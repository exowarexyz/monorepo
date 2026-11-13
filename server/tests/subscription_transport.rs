#![allow(refining_impl_trait)]

use bytes::Bytes;
use connectrpc::{ConnectError, ConnectRpcService, RequestContext, ServiceRequest};
use exoware_sdk::{
    common::kv::v1::Entry,
    log::stream::v1::{
        GetRequest, GetResponse, Service as StreamApi, ServiceServer as StreamServer,
        SubscribeRequest, SubscribeResponse,
    },
    selector::Selector,
    stream_filter::StreamFilter,
    ErrorCode, PrefixedStoreClient, StoreClient, SubscriptionRetryConfig,
};
use exoware_server::{
    bound_subscription,
    ingest::transport::{serve_with_config, ServeConfig, ShutdownSignal},
    stream_service, Log, LogBatch, Sequence, StreamHub, StreamState, SubscriptionLifetime,
    REASON_SERVER_SHUTDOWN,
};
use futures::{stream, Stream, StreamExt};
use http::{Request, StatusCode};
use socket2::SockRef;
use std::{
    future::poll_fn,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::{sleep, timeout, Instant},
};

type Error = Box<dyn std::error::Error + Send + Sync>;

// The transport cuts off a stalled response this long after its lifetime.
const GRACE: Duration = Duration::from_secs(2);
const SLACK: Duration = Duration::from_millis(1_500);

// Longer than the lifetime cutoff grace, so a close at the shutdown timeout
// cannot be mistaken for one at the grace, and still short enough to keep
// forced closes fast.
const SHUTDOWN: Duration = Duration::from_secs(3);
const SUBSCRIBE: &str = "/log.stream.v1.Service/Subscribe";

struct Served {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<io::Result<()>>,
}

impl Served {
    async fn start(app: axum::Router) -> Result<Self, Error> {
        Self::start_with(app, ServeConfig::default()).await
    }

    async fn start_with(app: axum::Router, config: ServeConfig) -> Result<Self, Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (shutdown, signal) = oneshot::channel::<()>();
        let task = tokio::spawn(serve_with_config(
            listener,
            app,
            async move {
                let _ = signal.await;
            },
            config,
        ));
        Ok(Self {
            addr,
            shutdown: Some(shutdown),
            task,
        })
    }

    // Starts shutdown and returns how long `serve` took to finish.
    async fn shut_down(mut self) -> Result<Duration, Error> {
        let started = Instant::now();
        let _ = self.shutdown.take().unwrap().send(());
        timeout(Duration::from_secs(40), &mut self.task)
            .await
            .map_err(|_| "serve did not finish after shutdown")???;
        Ok(started.elapsed())
    }
}

const fn short_shutdown() -> ServeConfig {
    ServeConfig {
        shutdown_timeout: SHUTDOWN,
    }
}

#[derive(Clone, Copy)]
enum Frames {
    // Sends one frame and then waits forever.
    Idle,
    // Sends one frame and ends cleanly.
    Finite,
    // Sends one frame and fails.
    Failing,
    // Sends large frames for as long as the peer reads them.
    Endless,
}

fn frame(sequence_number: u64, value: Bytes) -> Result<SubscribeResponse, ConnectError> {
    Ok(SubscribeResponse {
        sequence_number,
        entries: vec![Entry {
            key: vec![1],
            value,
            ..Default::default()
        }],
        ..Default::default()
    })
}

type Frame = Result<SubscribeResponse, ConnectError>;

fn frames(kind: Frames) -> Pin<Box<dyn Stream<Item = Frame> + Send>> {
    let first = stream::iter([frame(1, Bytes::from_static(b"v"))]);
    match kind {
        Frames::Idle => Box::pin(first.chain(stream::pending())),
        Frames::Finite => Box::pin(first),
        Frames::Failing => {
            Box::pin(first.chain(stream::iter([Err(ConnectError::internal("boom"))])))
        }
        Frames::Endless => {
            let value = Bytes::from(vec![7_u8; 256 * 1024]);
            Box::pin(stream::iter(1..).map(move |sequence| frame(sequence, value.clone())))
        }
    }
}

// Records when the server releases a subscription's backend stream.
struct Released(Arc<AtomicBool>);

impl Drop for Released {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

// A custom `Subscribe` handler that reuses the built-in lifetime and shutdown behavior.
struct Custom {
    kind: Frames,
    lifetime: SubscriptionLifetime,
    released: Arc<AtomicBool>,
}

impl StreamApi for Custom {
    async fn subscribe(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, SubscribeRequest>,
    ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<SubscribeResponse>> {
        let shutdown = ctx
            .extensions()
            .get::<ShutdownSignal>()
            .cloned()
            .expect("serve provides a shutdown signal");
        let released = Released(self.released.clone());
        let frames = frames(self.kind).map(move |frame| {
            let _ = &released;
            frame
        });
        Ok(connectrpc::Response::stream(Box::pin(bound_subscription(
            frames,
            self.lifetime,
            shutdown.closed(),
        ))))
    }

    async fn get(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetRequest>,
    ) -> connectrpc::ServiceResult<GetResponse> {
        Err(ConnectError::unimplemented("get"))
    }
}

async fn custom(kind: Frames, lifetime: SubscriptionLifetime) -> Result<Served, Error> {
    released(kind, lifetime, Arc::default()).await
}

async fn released(
    kind: Frames,
    lifetime: SubscriptionLifetime,
    released: Arc<AtomicBool>,
) -> Result<Served, Error> {
    let service = ConnectRpcService::new(StreamServer::new(Custom {
        kind,
        lifetime,
        released,
    }));
    Served::start_with(
        axum::Router::new().fallback_service(service),
        short_shutdown(),
    )
    .await
}

fn subscribe_body() -> Bytes {
    use buffa::Message as _;
    let message = SubscribeRequest::default().encode_to_bytes();
    let mut body = vec![0];
    body.extend_from_slice(&(message.len() as u32).to_be_bytes());
    body.extend_from_slice(&message);
    body.into()
}

// An HTTP/2 client whose streams start with `window` bytes of flow-control
// credit. With none, the server cannot send any response DATA.
struct Http2Client {
    connection: h2::client::SendRequest<Bytes>,
    driver: JoinHandle<Result<(), h2::Error>>,
}

impl Http2Client {
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

    async fn subscribe(&mut self, addr: SocketAddr) -> Result<h2::RecvStream, Error> {
        poll_fn(|cx| self.connection.poll_ready(cx)).await?;
        let request = Request::post(format!("http://{addr}{SUBSCRIBE}"))
            .header(http::header::CONTENT_TYPE, "application/connect+proto")
            .header("connect-protocol-version", "1")
            .body(())?;
        let (response, mut send) = self.connection.send_request(request, false)?;
        send.send_data(subscribe_body(), true)?;
        let response = timeout(Duration::from_secs(2), response).await??;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(response.into_body())
    }

    async fn assert_healthy(&mut self, addr: SocketAddr) -> Result<(), Error> {
        poll_fn(|cx| self.connection.poll_ready(cx)).await?;
        let request = Request::post(format!("http://{addr}/unknown")).body(())?;
        let (response, _) = self.connection.send_request(request, true)?;
        timeout(Duration::from_secs(2), response).await??;
        Ok(())
    }
}

impl Drop for Http2Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

// Sends an HTTP/1.1 subscription from a socket with a small receive buffer that is never read.
async fn stalled_http1(addr: SocketAddr) -> Result<TcpStream, Error> {
    let mut tcp = TcpStream::connect(addr).await?;
    SockRef::from(&tcp).set_recv_buffer_size(4096)?;
    let body = subscribe_body();
    let head = format!(
        "POST {SUBSCRIBE} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/connect+proto\r\nConnect-Protocol-Version: 1\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    tcp.write_all(head.as_bytes()).await?;
    tcp.write_all(&body).await?;
    Ok(tcp)
}

#[tokio::test]
async fn shutdown_ends_a_healthy_subscription_with_unavailable() -> Result<(), Error> {
    struct EmptyLog;

    impl Sequence for EmptyLog {
        fn current_sequence(&self) -> u64 {
            0
        }
    }

    impl Log for EmptyLog {
        async fn get_batch(&self, _sequence_number: u64) -> Result<Option<LogBatch>, String> {
            Ok(None)
        }

        async fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
            Ok(None)
        }
    }

    let state = StreamState::new(Arc::new(EmptyLog), Arc::new(StreamHub::new(0)));
    let served = Served::start(axum::Router::new().fallback_service(stream_service(state))).await?;
    let client = StoreClient::builder()
        .url(&format!("http://{}", served.addr))
        .subscription_retry(SubscriptionRetryConfig::disabled())
        .build()?;
    let filter = StreamFilter {
        selectors: vec![Selector {
            prefix: Bytes::from_static(&[1]),
            payload_regex: ".*".into(),
        }],
        value_filters: Vec::new(),
    };
    let mut subscription = PrefixedStoreClient::empty(client)
        .stream()
        .subscribe(filter, None)
        .await?;
    assert!(timeout(Duration::from_millis(200), subscription.next())
        .await
        .is_err());

    let shutdown = tokio::spawn(served.shut_down());
    let error = timeout(Duration::from_secs(2), subscription.next())
        .await?
        .expect_err("shutdown must end the subscription");
    let rpc = error.rpc_error().expect("rpc error");
    assert_eq!(rpc.code, ErrorCode::Unavailable);
    let decoded = error.decoded_rpc_error().unwrap().unwrap();
    assert_eq!(decoded.error_info.unwrap().reason, REASON_SERVER_SHUTDOWN);

    // The drain ends as soon as the subscription has, well before the default timeout.
    let elapsed = shutdown.await??;
    assert!(
        elapsed < Duration::from_secs(1),
        "shutdown took {elapsed:?}"
    );
    Ok(())
}

#[tokio::test]
async fn http2_stalled_subscription_is_reset_after_its_lifetime() -> Result<(), Error> {
    let lifetime = Duration::from_millis(500);
    let served = custom(
        Frames::Idle,
        SubscriptionLifetime::new(lifetime).with_jitter(0.0),
    )
    .await?;
    let mut client = Http2Client::open(served.addr, 0).await?;
    let started = Instant::now();
    let mut body = client.subscribe(served.addr).await?;

    let reset = timeout(lifetime + GRACE + SLACK, body.data())
        .await
        .map_err(|_| "a stalled subscription must be reset")?;
    assert!(matches!(reset, Some(Err(_)) | None));
    assert!(started.elapsed() >= lifetime + GRACE - Duration::from_millis(100));

    // Only the stalled stream is cut. Its connection keeps serving.
    client.assert_healthy(served.addr).await?;
    Ok(())
}

// A peer that grants no credit cannot receive the shutdown error, so the
// subscription and its backend stream last until the shutdown timeout.
#[tokio::test]
async fn http2_stalled_subscriptions_are_closed_at_the_shutdown_timeout() -> Result<(), Error> {
    let closes = [Frames::Idle, Frames::Finite, Frames::Failing].map(|kind| async move {
        let flag = Arc::new(AtomicBool::new(false));
        let served = released(kind, SubscriptionLifetime::unbounded(), flag.clone()).await?;
        let mut client = Http2Client::open(served.addr, 0).await?;
        let _body = client.subscribe(served.addr).await?;
        sleep(Duration::from_millis(100)).await;

        let elapsed = served.shut_down().await?;
        assert!(
            elapsed >= SHUTDOWN && elapsed < SHUTDOWN + SLACK,
            "shutdown took {elapsed:?}"
        );
        assert!(
            flag.load(Ordering::SeqCst),
            "serve returned before releasing the subscription"
        );
        Ok::<_, Error>(())
    });
    futures::future::try_join_all(closes).await?;
    Ok(())
}

#[tokio::test]
async fn http1_stalled_subscription_is_released_after_its_lifetime() -> Result<(), Error> {
    let lifetime = Duration::from_millis(500);
    let flag = Arc::new(AtomicBool::new(false));
    let served = released(
        Frames::Endless,
        SubscriptionLifetime::new(lifetime).with_jitter(0.0),
        flag.clone(),
    )
    .await?;

    // The peer never reads, so the response body stops being polled once the
    // socket fills and only the transport can end the subscription.
    let _tcp = stalled_http1(served.addr).await?;
    sleep(lifetime).await;
    assert!(!flag.load(Ordering::SeqCst));
    sleep(GRACE + SLACK).await;
    assert!(
        flag.load(Ordering::SeqCst),
        "the stalled subscription was not released"
    );
    Ok(())
}

#[tokio::test]
async fn http1_stalled_subscription_is_closed_at_the_shutdown_timeout() -> Result<(), Error> {
    let flag = Arc::new(AtomicBool::new(false));
    let served = released(
        Frames::Endless,
        SubscriptionLifetime::unbounded(),
        flag.clone(),
    )
    .await?;
    let _tcp = stalled_http1(served.addr).await?;
    sleep(Duration::from_millis(300)).await;

    let elapsed = served.shut_down().await?;
    assert!(
        elapsed >= SHUTDOWN && elapsed < SHUTDOWN + SLACK,
        "shutdown took {elapsed:?}"
    );
    assert!(
        flag.load(Ordering::SeqCst),
        "serve returned before releasing the subscription"
    );
    Ok(())
}

// A stalled subscription does not shorten the time an ordinary request on
// the same connection has to finish, so one that outlasts the lifetime
// cutoff grace still completes.
#[tokio::test]
async fn an_ordinary_request_beside_a_stalled_subscription_gets_the_whole_timeout(
) -> Result<(), Error> {
    const SLOW: Duration = Duration::from_secs(3);
    const TIMEOUT: Duration = Duration::from_secs(4);

    let service = ConnectRpcService::new(StreamServer::new(Custom {
        kind: Frames::Idle,
        lifetime: SubscriptionLifetime::unbounded(),
        released: Arc::default(),
    }));
    let router = axum::Router::new()
        .route(
            "/slow",
            axum::routing::get(|| async {
                sleep(SLOW).await;
                StatusCode::NO_CONTENT
            }),
        )
        .fallback_service(service);
    let served = Served::start_with(
        router,
        ServeConfig {
            shutdown_timeout: TIMEOUT,
        },
    )
    .await?;
    let mut client = Http2Client::open(served.addr, 0).await?;
    let _body = client.subscribe(served.addr).await?;

    poll_fn(|cx| client.connection.poll_ready(cx)).await?;
    let request = Request::get(format!("http://{}/slow", served.addr)).body(())?;
    let (response, _) = client.connection.send_request(request, true)?;
    sleep(Duration::from_millis(100)).await;

    let shutdown = tokio::spawn(served.shut_down());
    let response = timeout(TIMEOUT, response).await??;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // The stalled subscription still holds the connection until the timeout.
    let elapsed = shutdown.await??;
    assert!(
        elapsed >= TIMEOUT && elapsed < TIMEOUT + SLACK,
        "shutdown took {elapsed:?}"
    );
    Ok(())
}

const RESPONSE_LEN: usize = 256 * 1024;
const WINDOW: u32 = 1024;

fn large(router: axum::Router) -> axum::Router {
    router.route(
        "/large",
        axum::routing::get(|| async { vec![7_u8; RESPONSE_LEN] }),
    )
}

// Hyper hands a whole response chunk to h2 as soon as the peer grants any
// credit, so an ordinary response can be fully released by its handler while
// most of it still waits for the peer. Shutdown keeps draining it for longer
// than the subscription cutoff grace, and returns once it is done rather
// than at the default timeout.
async fn assert_slow_read_completes(
    served: Served,
    connection: &mut h2::client::SendRequest<Bytes>,
) -> Result<(), Error> {
    poll_fn(|cx| connection.poll_ready(cx)).await?;
    let request = Request::get(format!("http://{}/large", served.addr)).body(())?;
    let (response, _) = connection.send_request(request, true)?;
    let mut body = timeout(Duration::from_secs(2), response)
        .await??
        .into_body();

    let mut received = read_chunk(&mut body).await?.expect("first chunk");
    let shutdown = tokio::spawn(served.shut_down());
    let started = Instant::now();
    while started.elapsed() < GRACE + SLACK {
        sleep(Duration::from_millis(100)).await;
        let chunk = read_chunk(&mut body).await?;
        received += chunk.unwrap_or_else(|| panic!("the response ended after {received} bytes"));
    }
    assert!(
        !shutdown.is_finished(),
        "shutdown cut a response still being read"
    );

    while let Some(len) = read_chunk(&mut body).await? {
        received += len;
    }
    assert_eq!(received, RESPONSE_LEN);
    let elapsed = shutdown.await??;
    assert!(
        elapsed < ServeConfig::default().shutdown_timeout,
        "shutdown took {elapsed:?}"
    );
    Ok(())
}

#[tokio::test]
async fn shutdown_drains_an_ordinary_response_a_slow_peer_is_still_reading() -> Result<(), Error> {
    let served = Served::start(large(axum::Router::new())).await?;
    let mut client = Http2Client::open(served.addr, WINDOW).await?;
    assert_slow_read_completes(served, &mut client.connection).await
}

// A subscription that already ended on the connection does not shorten the
// time a later ordinary response has to drain.
#[tokio::test]
async fn shutdown_drains_an_ordinary_response_after_a_completed_subscription() -> Result<(), Error>
{
    let flag = Arc::new(AtomicBool::new(false));
    let service = ConnectRpcService::new(StreamServer::new(Custom {
        kind: Frames::Finite,
        lifetime: SubscriptionLifetime::new(Duration::from_secs(60)).with_jitter(0.0),
        released: flag.clone(),
    }));
    let served = Served::start(large(axum::Router::new()).fallback_service(service)).await?;
    let mut client = Http2Client::open(served.addr, WINDOW).await?;

    let request = Request::post(format!("http://{}{SUBSCRIBE}", served.addr))
        .header(http::header::CONTENT_TYPE, "application/connect+proto")
        .header("connect-protocol-version", "1")
        .body(())?;
    poll_fn(|cx| client.connection.poll_ready(cx)).await?;
    let (response, mut send) = client.connection.send_request(request, false)?;
    send.send_data(subscribe_body(), true)?;
    let response = timeout(Duration::from_secs(2), response).await??;
    assert_eq!(response.status(), StatusCode::OK);
    let mut subscription = response.into_body();
    while timeout(Duration::from_secs(2), read_chunk(&mut subscription))
        .await??
        .is_some()
    {}
    drop(subscription);
    assert!(flag.load(Ordering::SeqCst));

    assert_slow_read_completes(served, &mut client.connection).await
}

// Reads one chunk and grants the peer credit for the next.
async fn read_chunk(body: &mut h2::RecvStream) -> Result<Option<usize>, Error> {
    let Some(chunk) = body.data().await else {
        return Ok(None);
    };
    let chunk = chunk?;
    body.flow_control().release_capacity(chunk.len())?;
    Ok(Some(chunk.len()))
}
