//! Bounded graceful shutdown of [serve] and [serve_with_config].

use axum::{routing::get, Router};
use bytes::Bytes;
use exoware_server::ingest::transport::{serve, serve_with_config, ServeConfig};
use http::{Request, StatusCode};
use socket2::SockRef;
use std::{
    future::poll_fn,
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{oneshot, Notify},
    task::JoinHandle,
    time::{sleep, timeout, Instant},
};

type Error = Box<dyn std::error::Error + Send + Sync>;

// Short enough to keep the tests fast, long enough that a request still
// running at it was clearly given the whole timeout.
const TIMEOUT: Duration = Duration::from_millis(500);
const SLACK: Duration = Duration::from_millis(1_500);
const LARGE: usize = 8 << 20;

struct Served {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<io::Result<()>>,
}

impl Served {
    async fn start(router: Router, timeout: Duration) -> Result<Self, Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (stop, stopped) = oneshot::channel::<()>();
        let config = ServeConfig {
            shutdown_timeout: timeout,
        };
        let task = tokio::spawn(serve_with_config(
            listener,
            router,
            async move {
                let _ = stopped.await;
            },
            config,
        ));
        Ok(Self {
            addr,
            stop: Some(stop),
            task,
        })
    }

    // Starts shutdown and returns how long serving took to end.
    async fn shut_down(mut self) -> Result<Duration, Error> {
        let started = Instant::now();
        let _ = self.stop.take().unwrap().send(());
        timeout(Duration::from_secs(10), &mut self.task)
            .await
            .map_err(|_| "serve did not finish after shutdown")???;
        Ok(started.elapsed())
    }
}

// A handler that never returns, recording when it starts and when it is dropped.
#[derive(Clone, Default)]
struct Hang {
    started: Arc<Notify>,
    dropped: Arc<AtomicBool>,
}

struct DropFlag(Arc<AtomicBool>);

// Dropping slowly gives serve time to return first if it did not wait for
// the task that owns the handler.
impl Drop for DropFlag {
    fn drop(&mut self) {
        std::thread::sleep(Duration::from_millis(200));
        self.0.store(true, Ordering::SeqCst);
    }
}

impl Hang {
    fn router(&self) -> Router {
        let hang = self.clone();
        Router::new()
            .route("/ok", get(|| async { StatusCode::NO_CONTENT }))
            .route("/large", get(|| async { vec![7_u8; LARGE] }))
            .route(
                "/hang",
                get(move || {
                    let hang = hang.clone();
                    async move {
                        let _flag = DropFlag(hang.dropped.clone());
                        hang.started.notify_one();
                        std::future::pending::<StatusCode>().await
                    }
                }),
            )
    }

    fn dropped(&self) -> bool {
        self.dropped.load(Ordering::SeqCst)
    }
}

struct Http2 {
    connection: h2::client::SendRequest<Bytes>,
    driver: JoinHandle<Result<(), h2::Error>>,
}

impl Http2 {
    async fn open(addr: SocketAddr, window: u32) -> Result<Self, Error> {
        let (connection, driver) = h2::client::Builder::new()
            .initial_window_size(window)
            .handshake(TcpStream::connect(addr).await?)
            .await?;
        Ok(Self {
            connection,
            driver: tokio::spawn(driver),
        })
    }

    async fn get(
        &mut self,
        addr: SocketAddr,
        path: &str,
    ) -> Result<h2::client::ResponseFuture, Error> {
        poll_fn(|cx| self.connection.poll_ready(cx)).await?;
        let request = Request::get(format!("http://{addr}{path}")).body(())?;
        let (response, _) = self.connection.send_request(request, true)?;
        Ok(response)
    }
}

impl Drop for Http2 {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

async fn http1_get(addr: SocketAddr, path: &str) -> Result<TcpStream, Error> {
    let mut tcp = TcpStream::connect(addr).await?;
    SockRef::from(&tcp).set_recv_buffer_size(4096)?;
    tcp.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .await?;
    Ok(tcp)
}

// Reads until the server closes the connection and returns the byte count.
async fn read_to_close(tcp: &mut TcpStream) -> Result<usize, Error> {
    let mut total = 0;
    let mut buf = vec![0; 16 * 1024];
    loop {
        match timeout(Duration::from_secs(5), tcp.read(&mut buf)).await? {
            Ok(0) | Err(_) => return Ok(total),
            Ok(count) => total += count,
        }
    }
}

// Gives the tasks that a clock advance woke turns to run before the next
// assertion. The current-thread runtime runs every ready task between
// yields, and the chain from the timer to the handler drop is short.
async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

// Handlers are dropped on their own tasks, so this waits briefly for it.
async fn dropped_soon(hang: &Hang) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !hang.dropped() {
        if Instant::now() > deadline {
            return false;
        }
        sleep(Duration::from_millis(10)).await;
    }
    true
}

#[tokio::test]
async fn shutdown_returns_at_once_when_nothing_is_in_flight() -> Result<(), Error> {
    for idle_connections in [false, true] {
        let hang = Hang::default();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (stop, stopped) = oneshot::channel::<()>();
        let server = tokio::spawn(serve(listener, hang.router(), async move {
            let _ = stopped.await;
        }));

        // Kept open, but idle, so the drain has nothing to wait for.
        let mut idle = None;
        if idle_connections {
            let mut tcp = http1_get(addr, "/ok").await?;
            let mut head = [0; 1024];
            let count = timeout(Duration::from_secs(2), tcp.read(&mut head)).await??;
            assert!(String::from_utf8_lossy(&head[..count]).contains("204"));

            let mut http2 = Http2::open(addr, 65_535).await?;
            let response = http2.get(addr, "/ok").await?;
            let response = timeout(Duration::from_secs(2), response).await??;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            idle = Some((tcp, http2));
        }

        let started = Instant::now();
        stop.send(()).unwrap();
        timeout(Duration::from_secs(2), server).await???;
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "shutdown took {elapsed:?}"
        );
        drop(idle);
    }
    Ok(())
}

// The default timeout applies without any configuration. Time is paused only
// after real I/O, so idle socket waits cannot advance it. The deadline was
// set between `before` and `after`, so the handler must survive until
// 30 seconds past the first and be gone 30 seconds past the second.
#[tokio::test]
async fn serve_closes_connections_after_the_default_timeout() -> Result<(), Error> {
    let hang = Hang::default();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (stop, stopped) = oneshot::channel::<()>();
    let (began, beginning) = oneshot::channel::<()>();
    let mut server = tokio::spawn(serve(listener, hang.router(), async move {
        let _ = stopped.await;
        let _ = began.send(());
    }));
    let mut tcp = http1_get(addr, "/hang").await?;
    timeout(Duration::from_secs(2), hang.started.notified()).await?;

    let before = Instant::now();
    stop.send(()).unwrap();
    timeout(Duration::from_secs(2), beginning).await??;
    let after = Instant::now();

    tokio::time::pause();
    tokio::time::advance(
        before + Duration::from_secs(30) - Duration::from_millis(1) - Instant::now(),
    )
    .await;
    settle().await;
    assert!(futures::poll!(&mut server).is_pending());
    assert!(!hang.dropped());

    tokio::time::advance(
        after + Duration::from_secs(30) + Duration::from_millis(1) - Instant::now(),
    )
    .await;
    settle().await;
    assert!(hang.dropped());
    tokio::time::resume();
    timeout(Duration::from_secs(2), server).await???;
    assert_eq!(read_to_close(&mut tcp).await?, 0);
    Ok(())
}

// Hyper runs each HTTP/2 stream on its own task. With several workers, that
// task can be dropped on one thread while serve finishes on another.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_handlers_that_never_return() -> Result<(), Error> {
    for http2 in [false, true] {
        let hang = Hang::default();
        let served = Served::start(hang.router(), TIMEOUT).await?;
        let addr = served.addr;
        let mut http1 = None;
        let mut pending = None;
        let mut connection = None;
        if http2 {
            let mut client = Http2::open(addr, 65_535).await?;
            pending = Some(client.get(addr, "/hang").await?);
            connection = Some(client);
        } else {
            http1 = Some(http1_get(addr, "/hang").await?);
        }
        timeout(Duration::from_secs(2), hang.started.notified()).await?;

        let elapsed = served.shut_down().await?;
        assert!(
            elapsed >= TIMEOUT && elapsed < TIMEOUT + SLACK,
            "shutdown took {elapsed:?}"
        );

        // The handler is gone by the time serving ends, along with its connection.
        assert!(hang.dropped(), "http2: {http2}");
        if let Some(response) = pending {
            assert!(timeout(Duration::from_secs(2), response).await?.is_err());
        }
        if let Some(mut tcp) = http1 {
            assert_eq!(read_to_close(&mut tcp).await?, 0);
        }
        drop(connection);
    }
    Ok(())
}

// A host that drops serve instead of signalling shutdown must not leave its
// connections and their handlers running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_serve_stops_its_connections() -> Result<(), Error> {
    for http2 in [false, true] {
        let hang = Hang::default();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(serve(listener, hang.router(), std::future::pending()));
        let mut http1 = None;
        let mut pending = None;
        let mut connection = None;
        if http2 {
            let mut client = Http2::open(addr, 65_535).await?;
            pending = Some(client.get(addr, "/hang").await?);
            connection = Some(client);
        } else {
            http1 = Some(http1_get(addr, "/hang").await?);
        }
        timeout(Duration::from_secs(2), hang.started.notified()).await?;

        server.abort();
        assert!(dropped_soon(&hang).await, "http2: {http2}");
        if let Some(response) = pending {
            assert!(timeout(Duration::from_secs(2), response).await?.is_err());
        }
        if let Some(mut tcp) = http1 {
            assert_eq!(read_to_close(&mut tcp).await?, 0);
        }
        drop(connection);
    }
    Ok(())
}

// A peer that keeps reading, however slowly, cannot extend the timeout.
#[tokio::test]
async fn shutdown_cuts_a_response_a_slow_peer_is_still_reading() -> Result<(), Error> {
    const CHUNK: usize = 1024;
    const PACE: Duration = Duration::from_millis(50);

    for http2 in [false, true] {
        let hang = Hang::default();
        let served = Served::start(hang.router(), TIMEOUT).await?;
        let addr = served.addr;
        let hurry = Arc::new(AtomicBool::new(false));
        let reading = hurry.clone();

        // Reads a chunk per pace until told to hurry, then drains whatever the
        // server sent before it closed the connection.
        let reader: JoinHandle<Result<usize, Error>> = if http2 {
            let mut client = Http2::open(addr, CHUNK as u32).await?;
            let response = client.get(addr, "/large").await?;
            let mut body = timeout(Duration::from_secs(2), response)
                .await??
                .into_body();
            tokio::spawn(async move {
                let _client = client;
                let mut received = 0;
                loop {
                    if !reading.load(Ordering::SeqCst) {
                        sleep(PACE).await;
                    }
                    match timeout(Duration::from_secs(5), body.data()).await? {
                        Some(Ok(chunk)) => {
                            received += chunk.len();
                            let _ = body.flow_control().release_capacity(chunk.len());
                        }
                        Some(Err(_)) | None => return Ok(received),
                    }
                }
            })
        } else {
            let mut tcp = http1_get(addr, "/large").await?;
            tokio::spawn(async move {
                let mut received = 0;
                let mut buf = [0; CHUNK];
                while !reading.load(Ordering::SeqCst) {
                    sleep(PACE).await;
                    match tcp.read(&mut buf).await {
                        Ok(0) | Err(_) => return Ok(received),
                        Ok(count) => received += count,
                    }
                }
                Ok(received + read_to_close(&mut tcp).await?)
            })
        };
        sleep(PACE * 4).await;

        let elapsed = served.shut_down().await?;
        assert!(
            elapsed >= TIMEOUT && elapsed < TIMEOUT + SLACK,
            "shutdown took {elapsed:?}"
        );
        hurry.store(true, Ordering::SeqCst);
        let received = timeout(Duration::from_secs(10), reader).await???;
        assert!(received < LARGE, "http2: {http2}, received {received}");
    }
    Ok(())
}
