use std::{
    convert::Infallible,
    future::poll_fn,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use axum::{body::Body, serve::Listener};
use bytes::Bytes;
use exoware_server::{
    ingest::{
        transport::{serve, terminate_unfinished_response, ConnectionControl},
        DecodeBuffers, PutConfig, PutMiddleware,
    },
    ingest_service, Ingest, IngestState, PutError, PutInput,
};
use http::{header, Request, Response, StatusCode, Version};
use http_body_util::BodyExt;
use socket2::SockRef;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::{sleep, timeout, timeout_at, Instant},
};
use tower::service_fn;

type Error = Box<dyn std::error::Error + Send + Sync>;
const DEADLINE: Duration = Duration::from_millis(240);
const SCHEDULING_SLACK: Duration = Duration::from_millis(80);
const LARGE: usize = 64 * 1024 * 1024;

#[derive(Default)]
struct Stats {
    request_started: Mutex<Option<Instant>>,
    io_dropped: Mutex<Option<Instant>>,
    io_drops: AtomicUsize,
    written: AtomicUsize,
    pending_writes: AtomicUsize,
    request_polls: AtomicUsize,
    body_polls: AtomicUsize,
    body_drops: AtomicUsize,
    stale_attempts: AtomicUsize,
    stale_disarms: AtomicUsize,
}

#[derive(Default)]
struct Gate {
    blocked: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

struct MeasuredIo {
    tcp: TcpStream,
    stats: Arc<Stats>,
    gate: Arc<Gate>,
}

impl Drop for MeasuredIo {
    fn drop(&mut self) {
        *self.stats.io_dropped.lock().unwrap() = Some(Instant::now());
        self.stats.io_drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl AsyncRead for MeasuredIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_read(cx, buf)
    }
}

impl AsyncWrite for MeasuredIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = if self.gate.blocked.load(Ordering::SeqCst) {
            *self.gate.waker.lock().unwrap() = Some(cx.waker().clone());
            Poll::Pending
        } else {
            Pin::new(&mut self.tcp).poll_write(cx, buf)
        };
        match result {
            Poll::Ready(Ok(count)) => {
                self.stats.written.fetch_add(count, Ordering::SeqCst);
            }
            Poll::Pending => {
                self.stats.pending_writes.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}

struct MeasuredListener {
    tcp: TcpListener,
    stats: Arc<Stats>,
    gate: Arc<Gate>,
}

impl Listener for MeasuredListener {
    type Io = MeasuredIo;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (tcp, addr) = self.tcp.accept().await.unwrap();
        SockRef::from(&tcp).set_send_buffer_size(4096).unwrap();
        tcp.set_nodelay(true).unwrap();
        (
            MeasuredIo {
                tcp,
                stats: self.stats.clone(),
                gate: self.gate.clone(),
            },
            addr,
        )
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp.local_addr()
    }
}

enum Kind {
    Small,
    Large,
}

struct ResponseBody {
    kind: Kind,
    sent: usize,
    stats: Arc<Stats>,
}

struct CountBody {
    inner: Body,
    stats: Arc<Stats>,
    response: bool,
}

impl http_body::Body for CountBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        if self.response {
            self.stats.body_polls.fetch_add(1, Ordering::SeqCst);
        } else {
            self.stats.request_polls.fetch_add(1, Ordering::SeqCst);
        }
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for ResponseBody {
    fn drop(&mut self) {
        self.stats.body_drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl http_body::Body for ResponseBody {
    type Data = Bytes;
    type Error = h2::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        self.stats.body_polls.fetch_add(1, Ordering::SeqCst);
        let total = if matches!(self.kind, Kind::Small) {
            9
        } else {
            LARGE
        };
        if self.sent >= total {
            return Poll::Ready(None);
        }
        let bytes = if matches!(self.kind, Kind::Small) {
            Bytes::from_static(b"rejected\n")
        } else {
            Bytes::from(vec![b'x'; 64 * 1024])
        };
        self.sent += bytes.len();
        Poll::Ready(Some(Ok(http_body::Frame::data(bytes))))
    }

    fn is_end_stream(&self) -> bool {
        match self.kind {
            Kind::Small => self.sent >= 9,
            Kind::Large => self.sent >= LARGE,
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let mut hint = http_body::SizeHint::new();
        match self.kind {
            Kind::Small => hint.set_exact((9 - self.sent) as u64),
            Kind::Large => hint.set_exact((LARGE - self.sent) as u64),
        }
        hint
    }
}

// These handlers isolate listener ownership from the ingest decoder and backend.
async fn handler(
    mut request: Request<Body>,
    stats: Arc<Stats>,
) -> Result<Response<Body>, Infallible> {
    let control = request
        .extensions()
        .get::<ConnectionControl>()
        .unwrap()
        .clone();
    let path = request.uri().path().to_owned();
    let version = request.version();
    if path == "/health" {
        assert_eq!(control.arm_http1(Version::HTTP_2, Instant::now()), None);
        return Ok(Response::new(Body::empty()));
    }
    if path == "/hold" {
        sleep(DEADLINE + SCHEDULING_SLACK).await;
        return Ok(Response::new(Body::from("ok")));
    }

    let started = Instant::now();
    *stats.request_started.lock().unwrap() = Some(started);
    let deadline = if path.contains("expired") {
        started - Duration::from_millis(1)
    } else {
        started + DEADLINE
    };
    if path.contains("delayed") {
        sleep(Duration::from_millis(160)).await;
    }
    let id = control.arm_http1(version, deadline);

    if path.starts_with("/complete") {
        while timeout_at(deadline, request.body_mut().frame())
            .await
            .unwrap()
            .is_some()
        {}
        assert!(control.disarm(id.unwrap()));
        if path == "/complete-stale" {
            let stats = stats.clone();
            tokio::spawn(async move {
                sleep(Duration::from_millis(40)).await;
                stats.stale_attempts.fetch_add(1, Ordering::SeqCst);
                if control.disarm(id.unwrap()) {
                    stats.stale_disarms.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
        return Ok(Response::new(Body::from("ok")));
    }

    let mut status = StatusCode::PAYLOAD_TOO_LARGE;
    if path == "/actual" || path == "/endless" {
        let mut bytes = 0;
        while Instant::now() < deadline {
            stats.request_polls.fetch_add(1, Ordering::SeqCst);
            match timeout_at(deadline, request.body_mut().frame()).await {
                Ok(Some(Ok(frame))) => {
                    bytes += frame.data_ref().map_or(0, Bytes::len);
                    if bytes > 4 {
                        break;
                    }
                }
                _ => break,
            }
        }
        if bytes <= 4 {
            status = StatusCode::REQUEST_TIMEOUT;
        }
    }
    if path.contains("expired") {
        status = StatusCode::REQUEST_TIMEOUT;
    }
    drop(request);

    let kind = if path.contains("large") {
        Kind::Large
    } else {
        Kind::Small
    };
    let mut response = Response::builder().status(status);
    if path.contains("head") {
        response = response.header("x-large-head", "x".repeat(1024 * 1024));
    }
    let response = response
        .body(Body::new(ResponseBody {
            kind,
            sent: 0,
            stats: stats.clone(),
        }))
        .unwrap();
    let response = terminate_unfinished_response(version, response);
    if version == Version::HTTP_2 {
        Ok(response.map(|inner| {
            Body::new(CountBody {
                inner,
                stats,
                response: true,
            })
        }))
    } else {
        Ok(response)
    }
}

struct Server {
    addr: SocketAddr,
    stats: Arc<Stats>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl Server {
    async fn open(blocked: bool) -> Result<Self, Error> {
        Self::start(blocked, false).await
    }

    async fn production(blocked: bool) -> Result<Self, Error> {
        Self::start(blocked, true).await
    }

    async fn start(blocked: bool, production: bool) -> Result<Self, Error> {
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let addr = tcp.local_addr()?;
        let stats = Arc::new(Stats::default());
        let gate = Arc::new(Gate::default());
        gate.blocked.store(blocked, Ordering::SeqCst);
        let listener = MeasuredListener {
            tcp,
            stats: stats.clone(),
            gate,
        };
        let config = PutConfig {
            max_wire_bytes: 4,
            timeout: DEADLINE,
            ..PutConfig::default()
        };
        let state = IngestState::new(Arc::new(ConsumeIngest)).with_put_config(config);
        let ingest = ingest_service(state).with_put_middleware(DelayMiddleware);
        let requests = stats.clone();
        let service = service_fn(move |request: Request<Body>| {
            let ingest = ingest.clone();
            let stats = requests.clone();
            async move {
                use tower::ServiceExt;

                if !production {
                    return handler(request, stats).await;
                }
                if request.uri().path() == "/health" {
                    return Ok(Response::new(Body::empty()));
                }
                *stats.request_started.lock().unwrap() = Some(Instant::now());
                let large_head = request.headers().contains_key("x-large-head");
                let request = request.map(|inner| {
                    Body::new(CountBody {
                        inner,
                        stats,
                        response: false,
                    })
                });
                let mut response = ingest.oneshot(request).await?;
                if large_head {
                    response
                        .headers_mut()
                        .insert("x-large-head", "x".repeat(1024 * 1024).parse().unwrap());
                }
                Ok::<_, Infallible>(response)
            }
        });
        let (shutdown, receive) = oneshot::channel();
        let task = tokio::spawn(async move {
            serve(listener, service, async {
                let _ = receive.await;
            })
            .await
            .unwrap();
        });
        Ok(Self {
            addr,
            stats,
            shutdown: Some(shutdown),
            task,
        })
    }

    async fn wait_drop(&self, count: usize) -> Result<(), Error> {
        timeout(Duration::from_secs(2), async {
            while self.stats.io_drops.load(Ordering::SeqCst) < count {
                sleep(Duration::from_millis(2)).await;
            }
        })
        .await?;
        Ok(())
    }

    fn assert_original_deadline(&self) {
        let started = self.stats.request_started.lock().unwrap().unwrap();
        let dropped = self.stats.io_dropped.lock().unwrap().unwrap();
        assert!(dropped <= started + DEADLINE + SCHEDULING_SLACK);
    }

    async fn close(&mut self) -> Result<(), Error> {
        self.shutdown.take().unwrap().send(()).unwrap();
        timeout(Duration::from_secs(2), &mut self.task).await??;
        Ok(())
    }
}

struct ConsumeIngest;

impl Ingest for ConsumeIngest {
    async fn put(&self, input: &mut PutInput) -> Result<u64, PutError> {
        while input.next_batch(DecodeBuffers::default()).await?.is_some() {}
        input.finish().await?;
        Ok(1)
    }
}

struct DelayMiddleware;

impl PutMiddleware for DelayMiddleware {
    fn call<'a>(
        &'a self,
        parts: &'a mut http::request::Parts,
    ) -> futures::future::BoxFuture<'a, Result<(), connectrpc::ConnectError>> {
        Box::pin(async move {
            if parts.headers.contains_key("x-delay") {
                sleep(Duration::from_millis(160)).await;
            }
            Ok(())
        })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn client(addr: SocketAddr) -> Result<TcpStream, Error> {
    let tcp = TcpStream::connect(addr).await?;
    SockRef::from(&tcp).set_recv_buffer_size(4096)?;
    tcp.set_nodelay(true)?;
    Ok(tcp)
}

struct Http2 {
    connection: h2::client::SendRequest<Bytes>,
    driver: JoinHandle<Result<(), h2::Error>>,
}

impl Http2 {
    async fn open(addr: SocketAddr) -> Result<Self, Error> {
        let (connection, driver) = h2::client::Builder::new()
            .initial_window_size(0)
            .handshake(TcpStream::connect(addr).await?)
            .await?;
        Ok(Self {
            connection,
            driver: tokio::spawn(driver),
        })
    }

    async fn assert_healthy(&mut self, addr: SocketAddr) -> Result<(), Error> {
        poll_fn(|cx| self.connection.poll_ready(cx)).await?;
        let (response, _) = self.connection.send_request(
            Request::get(format!("http://{addr}/health")).body(())?,
            true,
        )?;
        let response = timeout(Duration::from_secs(1), response).await??;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.body().is_end_stream());
        Ok(())
    }
}

impl Drop for Http2 {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

async fn unfinished(tcp: &mut TcpStream, path: &str) -> Result<(), Error> {
    let body = match path {
        "/actual" => "Transfer-Encoding: chunked\r\n\r\n8\r\nabcdefgh\r\n",
        "/endless" | "/expired" => "Transfer-Encoding: chunked\r\n\r\n1\r\nx\r\n",
        _ => "Content-Length: 32\r\n\r\nx",
    };
    tcp.write_all(format!("POST {path} HTTP/1.1\r\nHost: localhost\r\n{body}").as_bytes())
        .await?;
    Ok(())
}

async fn read_response(tcp: &mut TcpStream) -> Result<String, Error> {
    timeout(Duration::from_secs(2), async {
        let mut raw = Vec::new();
        let mut buf = [0; 1024];
        loop {
            let count = tcp.read(&mut buf).await?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing response",
                ));
            }
            raw.extend_from_slice(&buf[..count]);
            if let Some(end) = raw.windows(4).position(|part| part == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&raw[..end]).to_lowercase();
                let length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                if raw.len() >= end + 4 + length {
                    return Ok(String::from_utf8_lossy(&raw).into_owned());
                }
            }
        }
    })
    .await?
    .map_err(Into::into)
}

#[tokio::test]
async fn http1_synthetic_and_production_rejections_release_io() -> Result<(), Error> {
    for production in [false, true] {
        for case in ["declared", "actual", "endless", "expired"] {
            let mut server = Server::start(false, production).await?;
            let mut tcp = client(server.addr).await?;
            if production {
                unfinished_put(&mut tcp, case, false).await?;
            } else {
                unfinished(&mut tcp, &format!("/{case}")).await?;
                if matches!(case, "declared" | "actual") {
                    assert!(read_response(&mut tcp)
                        .await?
                        .contains("413 Payload Too Large"));
                }
            }
            server.wait_drop(1).await?;
            server.assert_original_deadline();
            if case == "expired" {
                assert_eq!(server.stats.request_polls.load(Ordering::SeqCst), 0);
            }
            server.close().await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn http1_blocked_writes_keep_the_original_absolute_deadline() -> Result<(), Error> {
    for (path, blocked, body_polled) in [
        ("/delayed-small", true, true),
        ("/delayed-head", true, false),
        ("/delayed-large", false, true),
    ] {
        let mut server = Server::open(blocked).await?;
        let mut tcp = client(server.addr).await?;
        unfinished(&mut tcp, path).await?;
        server.wait_drop(1).await?;
        server.assert_original_deadline();
        assert!(server.stats.pending_writes.load(Ordering::SeqCst) > 0);
        assert!(server.stats.written.load(Ordering::SeqCst) < LARGE);
        assert_eq!(
            server.stats.body_polls.load(Ordering::SeqCst) > 0,
            body_polled
        );
        assert_eq!(server.stats.body_drops.load(Ordering::SeqCst), 1);
        server.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn http1_successful_cleanup_allows_reuse_past_the_old_deadline() -> Result<(), Error> {
    let mut server = Server::open(false).await?;
    let mut tcp = client(server.addr).await?;
    tcp.write_all(b"POST /complete HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx")
        .await?;
    assert!(read_response(&mut tcp).await?.contains("200 OK"));
    tcp.write_all(b"GET /hold HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    assert!(read_response(&mut tcp).await?.contains("200 OK"));
    tcp.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    assert!(read_response(&mut tcp).await?.contains("200 OK"));
    assert_eq!(server.stats.io_drops.load(Ordering::SeqCst), 0);
    drop(tcp);
    server.close().await?;
    Ok(())
}

#[tokio::test]
async fn http1_stale_disarm_cannot_cancel_a_successor_timer() -> Result<(), Error> {
    let mut server = Server::open(false).await?;
    let mut tcp = client(server.addr).await?;
    tcp.write_all(
        b"POST /complete-stale HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx",
    )
    .await?;
    assert!(read_response(&mut tcp).await?.contains("200 OK"));
    unfinished(&mut tcp, "/large").await?;
    server.wait_drop(1).await?;
    server.assert_original_deadline();
    assert_eq!(server.stats.stale_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(server.stats.stale_disarms.load(Ordering::SeqCst), 0);
    server.close().await?;
    Ok(())
}

#[tokio::test]
async fn http2_synthetic_and_production_rejections_cancel_only_the_stream() -> Result<(), Error> {
    for production in [false, true] {
        for case in ["declared", "actual", "endless", "expired"] {
            let mut server = Server::start(false, production).await?;
            let mut h2 = Http2::open(server.addr).await?;
            let path = if production {
                PUT_PATH.to_owned()
            } else {
                format!("/{case}")
            };
            let mut request = Request::post(format!("http://{}{path}", server.addr));
            if production {
                request = request
                    .header(header::CONTENT_TYPE, "application/proto")
                    .header("connect-protocol-version", "1")
                    .header(
                        "connect-timeout-ms",
                        if case == "expired" { "0" } else { "240" },
                    );
                if case == "declared" {
                    request = request.header(header::CONTENT_LENGTH, "32");
                }
            }
            let started = Instant::now();
            let (response, mut upload) = h2.connection.send_request(request.body(())?, false)?;
            let wire: &'static [u8] = match (production, case) {
                (true, "actual") => TINY_PUT,
                (true, _) => b"\x0a",
                (false, "actual") => b"abcdefgh",
                (false, _) => b"x",
            };
            upload.send_data(Bytes::from_static(wire), false)?;
            let reason = timeout(
                DEADLINE + SCHEDULING_SLACK,
                poll_fn(|cx| upload.poll_reset(cx)),
            )
            .await??;
            assert_eq!(
                reason,
                h2::Reason::CANCEL,
                "production {production}, case {case}"
            );
            assert!(started.elapsed() <= DEADLINE + SCHEDULING_SLACK);
            if case == "expired" {
                assert_eq!(server.stats.request_polls.load(Ordering::SeqCst), 0);
            }
            if !production {
                assert_eq!(server.stats.body_polls.load(Ordering::SeqCst), 1);
                assert_eq!(server.stats.body_drops.load(Ordering::SeqCst), 1);
            }

            // Keep both halves of the rejected stream alive while another stream succeeds.
            h2.assert_healthy(server.addr).await?;
            assert_eq!(server.stats.io_drops.load(Ordering::SeqCst), 0);
            drop(response);
            drop(upload);
            drop(h2);
            server.close().await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_an_http1_connection_preserves_a_neighboring_http2_connection(
) -> Result<(), Error> {
    let mut server = Server::open(false).await?;
    let mut h2 = Http2::open(server.addr).await?;
    let mut tcp = client(server.addr).await?;
    unfinished(&mut tcp, "/large").await?;
    server.wait_drop(1).await?;
    h2.assert_healthy(server.addr).await?;
    assert_eq!(server.stats.io_drops.load(Ordering::SeqCst), 1);
    drop(h2);
    server.close().await?;
    Ok(())
}

#[tokio::test]
async fn graceful_shutdown_waits_for_an_active_disarmed_request() -> Result<(), Error> {
    let mut server = Server::open(false).await?;
    let mut tcp = client(server.addr).await?;
    tcp.write_all(b"POST /complete HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx")
        .await?;
    read_response(&mut tcp).await?;
    tcp.write_all(b"GET /hold HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    sleep(Duration::from_millis(20)).await;
    server.shutdown.take().unwrap().send(()).unwrap();
    assert!(read_response(&mut tcp).await?.contains("200 OK"));
    timeout(Duration::from_secs(2), &mut server.task).await??;
    assert_eq!(server.stats.io_drops.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn aborting_the_listener_task_releases_its_connections() -> Result<(), Error> {
    let mut server = Server::open(false).await?;
    let mut tcp = client(server.addr).await?;
    tcp.write_all(b"GET /hold HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    sleep(Duration::from_millis(20)).await;
    server.task.abort();
    assert!(timeout(Duration::from_secs(1), &mut server.task)
        .await?
        .unwrap_err()
        .is_cancelled());
    server.wait_drop(1).await?;
    Ok(())
}

async fn unfinished_put(tcp: &mut TcpStream, case: &str, delayed_head: bool) -> Result<(), Error> {
    let deadline = if case == "expired" { "0" } else { "240" };
    let length = if case == "declared" {
        "Content-Length: 32"
    } else {
        "Transfer-Encoding: chunked"
    };
    let extra = if delayed_head {
        "x-delay: 1\r\nx-large-head: 1\r\n"
    } else {
        ""
    };
    let head = format!(
        "POST /log.ingest.v1.Service/Put HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/proto\r\nconnect-protocol-version: 1\r\nconnect-timeout-ms: {deadline}\r\n{extra}{length}\r\n\r\n"
    );
    tcp.write_all(head.as_bytes()).await?;
    let wire = match case {
        "declared" => b"\x0a".as_slice(),
        "actual" => b"8\r\n\x0a\x06\x0a\x01k\x12\x01v\r\n".as_slice(),
        _ => b"1\r\n\x0a\r\n".as_slice(),
    };
    tcp.write_all(wire).await?;
    Ok(())
}

#[tokio::test]
async fn production_put_blocked_header_flush_uses_the_deadline_before_middleware(
) -> Result<(), Error> {
    let mut server = Server::production(true).await?;
    let mut tcp = client(server.addr).await?;
    unfinished_put(&mut tcp, "actual", true).await?;
    server.wait_drop(1).await?;
    server.assert_original_deadline();
    assert!(server.stats.pending_writes.load(Ordering::SeqCst) > 0);
    assert_eq!(server.stats.written.load(Ordering::SeqCst), 0);
    server.close().await?;
    Ok(())
}

const PUT_PATH: &str = "/log.ingest.v1.Service/Put";
const TINY_PUT: &[u8] = b"\x0a\x06\x0a\x01k\x12\x01v";

struct HeldIngest {
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}

impl Ingest for HeldIngest {
    async fn put(&self, input: &mut PutInput) -> Result<u64, PutError> {
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
        let mut rows = 0;
        while let Some(chunk) = input.next_batch(DecodeBuffers::new(64, 2)).await? {
            rows += chunk.entries().count();
        }
        input.finish().await?;
        assert_eq!(rows, 1);
        Ok(1)
    }
}

fn streaming_body(bytes: &'static [u8]) -> Body {
    Body::new(http_body_util::StreamBody::new(futures::stream::iter([
        Ok::<_, Infallible>(http_body::Frame::data(Bytes::from_static(bytes))),
    ])))
}

#[tokio::test]
async fn production_body_size_admission_and_declared_length_validation() {
    use exoware_server::ingest::{BudgetConfig, IngestBudget};
    use tower::ServiceExt;

    let maximum = PutConfig::default().max_wire_bytes;
    for (declared, exact, count, reserved, status) in [
        (
            Some(TINY_PUT.len()),
            false,
            4,
            4 * TINY_PUT.len(),
            StatusCode::OK,
        ),
        (None, true, 4, 4 * TINY_PUT.len(), StatusCode::OK),
        (None, false, 1, maximum, StatusCode::OK),
        (Some(32), true, 1, TINY_PUT.len(), StatusCode::BAD_REQUEST),
    ] {
        let ingest = Arc::new(HeldIngest {
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
        });
        let budget = IngestBudget::new(BudgetConfig::default());
        let service = ingest_service(IngestState::new(ingest.clone()).with_put_config(PutConfig {
            budget: budget.clone(),
            ..PutConfig::default()
        }));
        let mut tasks = Vec::new();
        for _ in 0..count {
            let mut request =
                Request::post(PUT_PATH).header(header::CONTENT_TYPE, "application/proto");
            if let Some(declared) = declared {
                request = request.header(header::CONTENT_LENGTH, declared);
            }
            let body = if exact {
                Body::from(Bytes::from_static(TINY_PUT))
            } else {
                streaming_body(TINY_PUT)
            };
            tasks.push(tokio::spawn(
                service.clone().oneshot(request.body(body).unwrap()),
            ));
        }
        timeout(
            Duration::from_secs(2),
            ingest.entered.acquire_many(count as u32),
        )
        .await
        .unwrap()
        .unwrap()
        .forget();

        // Holding every input exposes reservations before decoding starts.
        assert_eq!(budget.usage(), (count, reserved));
        ingest.release.add_permits(count);
        for task in tasks {
            let response = timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if status == StatusCode::BAD_REQUEST {
                assert_error(response, status, "invalid_argument").await;
            } else {
                assert_eq!(response.status(), status);
            }
        }
        assert_eq!(budget.usage(), (0, 0));
    }
}

async fn assert_error(response: Response<Body>, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["code"], code);
}

struct UnreachableIngest;

impl Ingest for UnreachableIngest {
    async fn put(&self, _: &mut PutInput) -> Result<u64, PutError> {
        panic!("metadata rejection must precede backend invocation")
    }
}

#[tokio::test]
async fn production_metadata_rejections_precede_exhausted_admission() {
    use exoware_server::ingest::{BudgetConfig, IngestBudget};
    use tower::ServiceExt;

    let cases = [
        (
            "application/json",
            None,
            None,
            None,
            StatusCode::NOT_IMPLEMENTED,
            "unimplemented",
        ),
        (
            "application/proto",
            Some("gzip"),
            None,
            None,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unknown",
        ),
        (
            "application/proto",
            None,
            Some("bad"),
            None,
            StatusCode::BAD_REQUEST,
            "invalid_argument",
        ),
        (
            "application/proto",
            None,
            None,
            Some("bad"),
            StatusCode::BAD_REQUEST,
            "invalid_argument",
        ),
        (
            "application/json",
            Some("gzip"),
            None,
            Some("bad"),
            StatusCode::NOT_IMPLEMENTED,
            "unimplemented",
        ),
    ];
    for (content_type, encoding, deadline, length, status, code) in cases {
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 0,
            max_bytes: 0,
        });
        let service = ingest_service(
            IngestState::new(Arc::new(UnreachableIngest)).with_put_config(PutConfig {
                budget: budget.clone(),
                ..PutConfig::default()
            }),
        );
        let mut request = Request::post(PUT_PATH).header(header::CONTENT_TYPE, content_type);
        if let Some(encoding) = encoding {
            request = request.header(header::CONTENT_ENCODING, encoding);
        }
        if let Some(deadline) = deadline {
            request = request.header("connect-timeout-ms", deadline);
        }
        if let Some(length) = length {
            request = request.header(header::CONTENT_LENGTH, length);
        }
        let response = service
            .oneshot(
                request
                    .body(Body::from(Bytes::from_static(TINY_PUT)))
                    .unwrap(),
            )
            .await
            .unwrap();
        let expected_encoding =
            (content_type == "application/proto" && encoding.is_some()).then_some("zstd");
        assert_eq!(
            response
                .headers()
                .get(header::ACCEPT_ENCODING)
                .map(|value| value.to_str().unwrap()),
            expected_encoding,
        );
        assert_error(response, status, code).await;
        assert_eq!(budget.usage(), (0, 0));
    }
}

#[derive(Clone)]
struct MethodTransport<T> {
    transport: T,
    method: http::Method,
}

impl<T: connectrpc::client::ClientTransport> connectrpc::client::ClientTransport
    for MethodTransport<T>
{
    type ResponseBody = T::ResponseBody;
    type Error = T::Error;

    fn send(
        &self,
        mut request: Request<connectrpc::client::ClientBody>,
    ) -> connectrpc::client::BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>>
    {
        *request.method_mut() = self.method.clone();
        self.transport.send(request)
    }
}

#[tokio::test]
async fn production_unsupported_methods_preserve_http_and_client_errors() {
    use connectrpc::client::{ClientConfig, ServiceTransport};
    use exoware_sdk::ingest::{PutRequest, ServiceClient};
    use tower::ServiceExt;

    for method in [
        http::Method::OPTIONS,
        http::Method::HEAD,
        http::Method::PUT,
        http::Method::PATCH,
        http::Method::DELETE,
        http::Method::GET,
    ] {
        let service = ingest_service(IngestState::new(Arc::new(UnreachableIngest)));
        let request = Request::builder()
            .method(method.clone())
            .uri(PUT_PATH)
            .body(Body::empty())
            .unwrap();
        let response = service.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        if method == http::Method::GET {
            assert!(response.headers().get(header::ALLOW).is_none());
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(error["code"], "unknown");
        } else {
            assert_eq!(response.headers().get(header::ALLOW).unwrap(), "POST");
            assert!(response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty());
        }
        let client = ServiceClient::new(
            MethodTransport {
                transport: ServiceTransport::new(service),
                method,
            },
            ClientConfig::new("http://store.test".parse().unwrap()),
        );
        let error = client.put(PutRequest::default()).await.unwrap_err();
        assert_eq!(error.code, connectrpc::ErrorCode::Unknown);
    }
}

#[tokio::test]
async fn production_known_bounds_are_enforced_and_maximum_still_validates() {
    use tower::ServiceExt;

    for (declared, maximum) in [(4, 32), (32, 4)] {
        let service = ingest_service(IngestState::new(Arc::new(ConsumeIngest)).with_put_config(
            PutConfig {
                max_wire_bytes: maximum,
                ..PutConfig::default()
            },
        ));
        let request = Request::post(PUT_PATH)
            .header(header::CONTENT_TYPE, "application/proto")
            .header(header::CONTENT_LENGTH, declared)
            .body(streaming_body(TINY_PUT))
            .unwrap();
        let response = service.oneshot(request).await.unwrap();
        assert_error(
            response,
            StatusCode::TOO_MANY_REQUESTS,
            "resource_exhausted",
        )
        .await;
    }
}

#[tokio::test]
async fn production_exact_length_exceeding_maximum_rejects_before_backend() {
    use tower::ServiceExt;

    for declared in [None, Some(1), Some(32)] {
        let service = ingest_service(
            IngestState::new(Arc::new(UnreachableIngest)).with_put_config(PutConfig {
                max_wire_bytes: 4,
                ..PutConfig::default()
            }),
        );
        let mut request = Request::post(PUT_PATH).header(header::CONTENT_TYPE, "application/proto");
        if let Some(declared) = declared {
            request = request.header(header::CONTENT_LENGTH, declared);
        }
        let response = service
            .oneshot(
                request
                    .body(Body::from(Bytes::from_static(TINY_PUT)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_error(
            response,
            StatusCode::TOO_MANY_REQUESTS,
            "resource_exhausted",
        )
        .await;
    }
}

struct WireCopyGate {
    calls: AtomicUsize,
    entered: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}

impl exoware_server::ingest::DecodeExecutor for WireCopyGate {
    fn execute(
        &self,
        state: exoware_server::ingest::DecodeState,
        buffers: DecodeBuffers,
    ) -> futures::future::BoxFuture<'static, Result<exoware_server::ingest::DecodeOutput, PutError>>
    {
        let hold = self.calls.fetch_add(1, Ordering::SeqCst) == 1;
        let entered = self.entered.clone();
        let release = self.release.clone();
        Box::pin(async move {
            if hold {
                entered.add_permits(1);
                release.acquire().await.unwrap().forget();
            }
            Ok(state.run(buffers))
        })
    }
}

struct CopyHeldIngest {
    entered: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}

impl Ingest for CopyHeldIngest {
    async fn put(&self, input: &mut PutInput) -> Result<u64, PutError> {
        input.set_executor(Arc::new(WireCopyGate {
            calls: AtomicUsize::new(0),
            entered: self.entered.clone(),
            release: self.release.clone(),
        }));
        while input.next_batch(DecodeBuffers::new(64, 2)).await?.is_some() {}
        input.finish().await?;
        Ok(1)
    }
}

#[tokio::test]
async fn production_known_body_copies_fit_without_another_full_wire_reservation() {
    use exoware_server::ingest::{BudgetConfig, IngestBudget};
    use tower::ServiceExt;

    let entered = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let budget = IngestBudget::new(BudgetConfig {
        max_requests: 4,
        max_bytes: 4096,
    });
    let service = ingest_service(
        IngestState::new(Arc::new(CopyHeldIngest {
            entered: entered.clone(),
            release: release.clone(),
        }))
        .with_put_config(PutConfig {
            budget: budget.clone(),
            ..PutConfig::default()
        }),
    );
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let request = Request::post(PUT_PATH)
            .header(header::CONTENT_TYPE, "application/proto")
            .header(header::CONTENT_LENGTH, TINY_PUT.len())
            .body(streaming_body(TINY_PUT))
            .unwrap();
        tasks.push(tokio::spawn(service.clone().oneshot(request)));
    }
    timeout(Duration::from_secs(2), entered.acquire_many(4))
        .await
        .unwrap()
        .unwrap()
        .forget();

    // Each paused worker owns the first copied frame before decoding resumes.
    let (requests, bytes) = budget.usage();
    assert_eq!(requests, 4);
    assert!(bytes >= 4 * TINY_PUT.len() * 2);
    assert!(bytes < 4096);
    release.add_permits(4);
    for task in tasks {
        assert_eq!(task.await.unwrap().unwrap().status(), StatusCode::OK);
    }
    assert_eq!(budget.usage(), (0, 0));
}

#[derive(Clone)]
struct CountedIngest(Arc<AtomicUsize>);

impl exoware_server::ingest::DecodeExecutor for CountedIngest {
    fn execute(
        &self,
        state: exoware_server::ingest::DecodeState,
        buffers: DecodeBuffers,
    ) -> futures::future::BoxFuture<'static, Result<exoware_server::ingest::DecodeOutput, PutError>>
    {
        self.0.fetch_add(1, Ordering::Relaxed);
        exoware_server::ingest::DecodeExecutor::execute(
            &exoware_server::ingest::BlockingDecodeExecutor,
            state,
            buffers,
        )
    }
}

impl Ingest for CountedIngest {
    async fn put(&self, input: &mut PutInput) -> Result<u64, PutError> {
        input.set_executor(Arc::new(self.clone()));
        let mut entries = 0;
        while let Some(chunk) = input.next_batch(DecodeBuffers::default()).await? {
            entries += chunk.entries().len();
        }
        input.finish().await?;
        assert_eq!(entries, 128);
        Ok(1)
    }
}

#[tokio::test]
async fn production_http1_fragmented_upload_amortizes_cpu_handoffs() -> Result<(), Error> {
    let jobs = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let service = ingest_service(IngestState::new(Arc::new(CountedIngest(jobs.clone()))));
    let (shutdown, stop) = oneshot::channel();
    let server = tokio::spawn(serve(listener, service, async {
        let _ = stop.await;
    }));
    let wire = TINY_PUT.repeat(128);
    let mut request = format!("POST {PUT_PATH} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/proto\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").into_bytes();
    for byte in &wire {
        request.extend_from_slice(&[b'1', b'\r', b'\n', *byte, b'\r', b'\n']);
    }
    request.extend_from_slice(b"0\r\n\r\n");
    let mut tcp = TcpStream::connect(addr).await?;
    tcp.write_all(&request).await?;
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), tcp.read_to_end(&mut response)).await??;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(jobs.load(Ordering::Relaxed) <= 2 * wire.len().div_ceil(64) + 8);
    shutdown.send(()).unwrap();
    server.await??;
    Ok(())
}

#[tokio::test]
async fn http2_completed_rejections_preserve_connect_errors() -> Result<(), Error> {
    use connectrpc::client::ClientConfig;
    use exoware_sdk::common::Entry;
    use exoware_sdk::ingest::{PutRequest, ServiceClient};

    for admission_exhausted in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let service = ingest_service(IngestState::new(Arc::new(ConsumeIngest)).with_put_config(
            PutConfig {
                max_wire_bytes: 4,
                budget: exoware_server::ingest::IngestBudget::new(
                    exoware_server::ingest::BudgetConfig {
                        max_requests: usize::from(!admission_exhausted),
                        max_bytes: 64 * 1024 * 1024,
                    },
                ),
                ..PutConfig::default()
            },
        ));
        let (shutdown, stop) = oneshot::channel();
        let server = tokio::spawn(serve(listener, service, async {
            let _ = stop.await;
        }));

        let uri: http::Uri = format!("http://{addr}").parse().unwrap();
        let transport = connectrpc::client::Http2Connection::connect_plaintext(uri.clone())
            .await?
            .shared(16);
        let client = ServiceClient::new(transport, ClientConfig::new(uri));
        let error = client
            .put(PutRequest {
                kvs: if admission_exhausted {
                    vec![]
                } else {
                    vec![Entry {
                        key: b"k".to_vec(),
                        value: Bytes::from_static(b"v"),
                        ..Default::default()
                    }]
                },
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(
            error.code,
            connectrpc::ErrorCode::ResourceExhausted,
            "client observed {error:?}"
        );
        assert_eq!(
            error.message.as_deref(),
            Some(if admission_exhausted {
                "ingest admission exhausted"
            } else {
                "request body exceeds wire limit"
            }),
            "client observed {error:?}"
        );
        shutdown.send(()).unwrap();
        server.await??;
    }
    Ok(())
}
