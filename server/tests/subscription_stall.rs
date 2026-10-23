use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use buffa::Message;
use bytes::Bytes;
use exoware_sdk::{common::kv::v1::Selector as ProtoSelector, log::stream::v1::SubscribeRequest};
use exoware_server::{
    ingest::transport::serve, stream_service, CompiledMatchers, FilteredBatch, Log, LogBatch,
    Sequence, StreamNotification, StreamNotifier, StreamState, SubscriptionLifetime,
};
use http::{header, Request, StatusCode};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{oneshot, Notify},
    task::JoinHandle,
    time::{sleep, timeout, Instant},
};

type Error = Box<dyn std::error::Error + Send + Sync>;

const LIFETIME: Duration = Duration::from_millis(500);
const GRACE: Duration = Duration::from_secs(2);
const SLACK: Duration = Duration::from_millis(1_500);
const STALL_VALUE: usize = 16 * 1024;

struct CountingNotifier {
    sequence: AtomicU64,
    notify: Arc<Notify>,
}

impl StreamNotifier for CountingNotifier {
    fn subscribe(&self) -> StreamNotification {
        StreamNotification {
            current_sequence: self.sequence.load(Ordering::Acquire),
            notify: self.notify.clone(),
        }
    }

    fn current_sequence(&self) -> u64 {
        self.sequence.load(Ordering::Acquire)
    }

    fn advance(&self, seq: u64) {
        self.sequence.fetch_max(seq, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
}

struct MemoryLog {
    batches: Mutex<BTreeMap<u64, Bytes>>,
    notifier: Arc<CountingNotifier>,
    fail_at: AtomicU64,
}

impl MemoryLog {
    fn publish(&self, sequence_number: u64, value: Bytes) {
        self.batches.lock().unwrap().insert(sequence_number, value);
        self.notifier.advance(sequence_number);
    }
}

impl Sequence for MemoryLog {
    fn current_sequence(&self) -> u64 {
        self.notifier.current_sequence()
    }
}

impl Log for MemoryLog {
    async fn get_batch(&self, _: u64) -> Result<Option<LogBatch>, String> {
        Ok(None)
    }

    async fn get_batch_filtered(
        &self,
        sequence_number: u64,
        _: &CompiledMatchers,
    ) -> Result<Option<FilteredBatch>, String> {
        if self.fail_at.load(Ordering::SeqCst) == sequence_number {
            return Err("backend failure".into());
        }

        Ok(self
            .batches
            .lock()
            .unwrap()
            .get(&sequence_number)
            .cloned()
            .map(|value| FilteredBatch::from_kvs(vec![(Bytes::from_static(b"key"), value)])))
    }

    async fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
        Ok(self.batches.lock().unwrap().keys().next().copied())
    }
}

struct Server {
    addr: SocketAddr,
    log: Arc<MemoryLog>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<()>>,
}

async fn server(lifetime: SubscriptionLifetime) -> Result<Server, Error> {
    let notifier = Arc::new(CountingNotifier {
        sequence: AtomicU64::new(0),
        notify: Arc::new(Notify::new()),
    });
    let log = Arc::new(MemoryLog {
        batches: Mutex::default(),
        notifier: notifier.clone(),
        fail_at: AtomicU64::new(0),
    });
    let state = StreamState::new(log.clone(), notifier).with_subscription_lifetime(lifetime);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (shutdown, stop) = oneshot::channel();
    let task = tokio::spawn(serve(listener, stream_service(state), async {
        let _ = stop.await;
    }));
    Ok(Server {
        addr,
        log,
        shutdown,
        task,
    })
}

fn envelope(flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![flags];
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn subscribe_body() -> Vec<u8> {
    let request = SubscribeRequest {
        selectors: vec![ProtoSelector {
            payload_regex: "(?s).*".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    envelope(0, &request.encode_to_vec())
}

struct H2 {
    send: h2::client::SendRequest<Bytes>,
    driver: JoinHandle<Result<(), h2::Error>>,
    addr: SocketAddr,
}

impl H2 {
    async fn connect(addr: SocketAddr) -> Result<Self, Error> {
        let (send, driver) = h2::client::Builder::new()
            .initial_window_size(1024)
            .handshake(TcpStream::connect(addr).await?)
            .await?;
        Ok(Self {
            send,
            driver: tokio::spawn(driver),
            addr,
        })
    }

    async fn subscribe(&mut self) -> Result<h2::RecvStream, Error> {
        let request = Request::post(format!(
            "http://{}/log.stream.v1.Service/Subscribe",
            self.addr
        ))
        .header(header::CONTENT_TYPE, "application/connect+proto")
        .header("connect-protocol-version", "1")
        .body(())?;
        let mut send = self.send.clone().ready().await?;
        let (response, mut upload) = send.send_request(request, false)?;
        upload.send_data(Bytes::from(subscribe_body()), true)?;
        let response = response.await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(response.into_body())
    }
}

// Reads and releases every byte until the stream ends, then returns the
// Connect end-of-stream JSON.
async fn drain(mut body: h2::RecvStream) -> Result<serde_json::Value, Error> {
    let mut bytes = Vec::new();
    while let Some(data) = body.data().await {
        let data = data?;
        body.flow_control().release_capacity(data.len())?;
        bytes.extend_from_slice(&data);
    }
    let mut end = None;
    let mut rest = bytes.as_slice();
    while rest.len() >= 5 {
        let length = u32::from_be_bytes(rest[1..5].try_into().unwrap()) as usize;
        if rest[0] & 2 != 0 {
            end = Some(serde_json::from_slice(&rest[5..5 + length])?);
        }
        rest = &rest[5 + length..];
    }
    end.ok_or_else(|| "stream ended without an end-of-stream envelope".into())
}

// Receives frames without releasing capacity until the server resets the stream.
async fn stalled_until_reset(mut body: h2::RecvStream) -> Result<Instant, Error> {
    loop {
        match body.data().await {
            Some(Ok(_)) => {}
            Some(Err(error)) => {
                assert!(error.is_reset(), "unexpected stream error {error:?}");
                return Ok(Instant::now());
            }
            None => return Err("stalled stream ended cleanly".into()),
        }
    }
}

async fn first_frame(body: &mut h2::RecvStream) -> Result<(), Error> {
    let data = timeout(Duration::from_secs(5), body.data())
        .await?
        .ok_or("stream ended before the checkpoint")??;
    assert!(data.len() >= 5);
    Ok(())
}

async fn live_subscriptions(server: &Server) {
    let notify = &server.log.notifier.notify;
    for _ in 0..100 {
        if Arc::strong_count(notify) == 1 {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "subscription state leaked, {} references remain",
        Arc::strong_count(notify) - 1
    );
}

async fn stall(server: &Server, h2: &mut H2) -> Result<(h2::RecvStream, h2::RecvStream), Error> {
    let mut stalled = h2.subscribe().await?;
    first_frame(&mut stalled).await?;
    let mut responsive = h2.subscribe().await?;
    sleep(Duration::from_millis(50)).await;
    server.log.publish(1, Bytes::from(vec![7_u8; STALL_VALUE]));
    sleep(Duration::from_millis(50)).await;
    // The responsive stream still holds its checkpoint, which drain reads.
    let _ = &mut responsive;
    Ok((stalled, responsive))
}

#[tokio::test]
async fn h2_stalled_reader_is_reset_after_expiry_while_siblings_finish() -> Result<(), Error> {
    let server = server(SubscriptionLifetime::new(LIFETIME).with_jitter_fraction(0.0)).await?;
    let mut h2 = H2::connect(server.addr).await?;
    let started = Instant::now();
    let (stalled, responsive) = stall(&server, &mut h2).await?;
    let stalled = tokio::spawn(stalled_until_reset(stalled));

    let end = timeout(LIFETIME + SLACK, drain(responsive)).await??;
    let responsive_elapsed = started.elapsed();
    assert_eq!(end["error"]["code"], "unavailable");
    assert!(responsive_elapsed >= LIFETIME - Duration::from_millis(100));
    assert!(responsive_elapsed < LIFETIME + SLACK);

    let reset_at = timeout(LIFETIME + GRACE + SLACK + SLACK, stalled).await???;
    let stalled_elapsed = reset_at - started;
    assert!(
        stalled_elapsed >= GRACE - Duration::from_millis(300),
        "reset before the grace period {stalled_elapsed:?}"
    );

    live_subscriptions(&server).await;
    let mut sibling = h2.subscribe().await?;
    first_frame(&mut sibling).await?;
    assert!(!h2.driver.is_finished());

    drop(sibling);
    drop(h2);
    server.shutdown.send(()).unwrap();
    timeout(Duration::from_secs(5), server.task).await???;
    Ok(())
}

#[tokio::test]
async fn h2_stalled_reader_is_reset_during_shutdown_while_siblings_finish() -> Result<(), Error> {
    let server = server(SubscriptionLifetime::unbounded()).await?;
    let mut h2 = H2::connect(server.addr).await?;
    let (stalled, responsive) = stall(&server, &mut h2).await?;
    let stalled = tokio::spawn(stalled_until_reset(stalled));

    let started = Instant::now();
    server.shutdown.send(()).unwrap();
    let end = timeout(SLACK, drain(responsive)).await??;
    assert_eq!(end["error"]["code"], "unavailable");

    let reset_at = timeout(GRACE + SLACK, stalled).await???;
    assert!(reset_at - started >= GRACE - Duration::from_millis(300));
    timeout(GRACE + SLACK, server.task).await???;
    drop(h2);
    Ok(())
}

#[tokio::test]
async fn http1_stalled_reader_does_not_hold_the_shutdown_drain() -> Result<(), Error> {
    let server = server(SubscriptionLifetime::unbounded()).await?;
    let mut tcp = TcpStream::connect(server.addr).await?;
    let body = subscribe_body();
    let head = format!(
        "POST /log.stream.v1.Service/Subscribe HTTP/1.1\r\nhost: {}\r\ncontent-type: application/connect+proto\r\nconnect-protocol-version: 1\r\ncontent-length: {}\r\n\r\n",
        server.addr,
        body.len()
    );
    tcp.write_all(head.as_bytes()).await?;
    tcp.write_all(&body).await?;
    let mut first = [0_u8; 64];
    let read = timeout(Duration::from_secs(5), tcp.read(&mut first)).await??;
    assert!(read > 0);

    // The client stops reading, so these batches fill the socket buffers.
    for sequence in 1..=300 {
        server
            .log
            .publish(sequence, Bytes::from(vec![9_u8; 256 * 1024]));
        if sequence % 50 == 0 {
            sleep(Duration::from_millis(20)).await;
        }
    }
    sleep(Duration::from_millis(200)).await;

    let started = Instant::now();
    server.shutdown.send(()).unwrap();
    timeout(GRACE + SLACK, server.task).await???;
    assert!(started.elapsed() >= GRACE - Duration::from_millis(300));
    drop(tcp);
    Ok(())
}

#[tokio::test]
async fn h2_stalled_reader_is_reset_after_an_early_backend_error() -> Result<(), Error> {
    let server = server(SubscriptionLifetime::unbounded()).await?;
    let mut h2 = H2::connect(server.addr).await?;
    let mut stalled = h2.subscribe().await?;
    first_frame(&mut stalled).await?;
    sleep(Duration::from_millis(50)).await;
    server.log.publish(1, Bytes::from(vec![7_u8; STALL_VALUE]));
    sleep(Duration::from_millis(100)).await;

    // The failing batch ends the stream with no bound involved, so only the
    // terminal-path watchdog can cut the response off.
    server.log.fail_at.store(2, Ordering::SeqCst);
    let started = Instant::now();
    server.log.publish(2, Bytes::from_static(b"x"));
    let stalled = tokio::spawn(stalled_until_reset(stalled));
    let reset_at = timeout(GRACE + SLACK, stalled).await???;
    assert!(reset_at - started >= GRACE - Duration::from_millis(300));

    live_subscriptions(&server).await;
    drop(h2);
    server.shutdown.send(()).unwrap();
    timeout(Duration::from_secs(5), server.task).await???;
    Ok(())
}

fn raw_h2_subscribe(addr: SocketAddr) -> Vec<u8> {
    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        bytes.extend_from_slice(&[kind, flags]);
        bytes.extend_from_slice(&stream.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }
    fn literal(index: u8, value: &str) -> Vec<u8> {
        let mut bytes = vec![index, value.len() as u8];
        bytes.extend_from_slice(value.as_bytes());
        bytes
    }

    let mut settings = vec![0, 4];
    settings.extend_from_slice(&0x4000_0000_u32.to_be_bytes());
    let mut headers = vec![0x83, 0x86];
    headers.extend(literal(0x04, "/log.stream.v1.Service/Subscribe"));
    headers.extend(literal(0x01, &addr.to_string()));
    headers.extend([0x0f, 0x10, "application/connect+proto".len() as u8]);
    headers.extend_from_slice(b"application/connect+proto");

    let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    bytes.extend(frame(4, 0, 0, &settings));
    bytes.extend(frame(8, 0, 0, &0x3fff_0000_u32.to_be_bytes()));
    bytes.extend(frame(1, 0x4, 1, &headers));
    bytes.extend(frame(0, 0x1, 1, &subscribe_body()));
    bytes
}

// The peer advertises enormous HTTP/2 windows but never reads its socket, so
// output blocks in TCP after the stream task has nothing left to cancel.
#[tokio::test]
async fn h2_tcp_blocked_output_does_not_hold_the_shutdown_drain() -> Result<(), Error> {
    let server = server(SubscriptionLifetime::unbounded()).await?;
    let mut tcp = TcpStream::connect(server.addr).await?;
    tcp.write_all(&raw_h2_subscribe(server.addr)).await?;
    for _ in 0..100 {
        if Arc::strong_count(&server.log.notifier.notify) > 1 {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert!(Arc::strong_count(&server.log.notifier.notify) > 1);

    for sequence in 1..=300 {
        server
            .log
            .publish(sequence, Bytes::from(vec![9_u8; 256 * 1024]));
        if sequence % 50 == 0 {
            sleep(Duration::from_millis(20)).await;
        }
    }
    sleep(Duration::from_millis(300)).await;

    let started = Instant::now();
    server.shutdown.send(()).unwrap();
    timeout(GRACE + GRACE + SLACK, server.task).await???;
    let elapsed = started.elapsed();
    assert!(elapsed >= GRACE - Duration::from_millis(300), "{elapsed:?}");
    drop(tcp);
    Ok(())
}
