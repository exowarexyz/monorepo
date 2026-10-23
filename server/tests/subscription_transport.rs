use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use bytes::Bytes;
use connectrpc::{
    client::{ClientConfig, Http2Connection},
    ErrorCode,
};
use exoware_sdk::{
    common::kv::v1::Selector as ProtoSelector,
    decode_connect_error,
    log::stream::v1::{ServiceClient, SubscribeRequest, SubscribeResponse},
};
use exoware_server::{
    ingest::transport::serve, stream_service, FilteredBatch, Log, LogBatch, Sequence, StreamHub,
    StreamNotifier, StreamState, SubscriptionLifetime, REASON_SERVER_CLOSING,
    REASON_SUBSCRIPTION_EXPIRED,
};
use tokio::{
    net::TcpListener,
    sync::oneshot,
    task::JoinHandle,
    time::{timeout, Instant},
};

type Error = Box<dyn std::error::Error + Send + Sync>;

struct MemoryLog {
    batches: Mutex<BTreeMap<u64, Vec<(Bytes, Bytes)>>>,
    hub: Arc<StreamHub>,
    stall_reads: AtomicBool,
}

impl MemoryLog {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            batches: Mutex::default(),
            hub: Arc::new(StreamHub::new(0)),
            stall_reads: AtomicBool::new(false),
        })
    }

    fn publish(&self, sequence_number: u64, value: &'static [u8]) {
        self.batches.lock().unwrap().insert(
            sequence_number,
            vec![(Bytes::from_static(b"key"), Bytes::from_static(value))],
        );
        self.hub.publish(sequence_number);
    }
}

impl Sequence for MemoryLog {
    fn current_sequence(&self) -> u64 {
        self.hub.current_sequence()
    }
}

impl Log for MemoryLog {
    async fn get_batch(&self, _: u64) -> Result<Option<LogBatch>, String> {
        Ok(None)
    }

    async fn get_batch_filtered(
        &self,
        sequence_number: u64,
        _: &exoware_server::CompiledMatchers,
    ) -> Result<Option<FilteredBatch>, String> {
        if self.stall_reads.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }

        Ok(self
            .batches
            .lock()
            .unwrap()
            .get(&sequence_number)
            .cloned()
            .map(FilteredBatch::from_kvs))
    }

    async fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
        Ok(self.batches.lock().unwrap().keys().next().copied())
    }
}

struct Harness {
    log: Arc<MemoryLog>,
    client: ServiceClient<connectrpc::client::SharedHttp2Connection>,
    shutdown: oneshot::Sender<()>,
    server: JoinHandle<std::io::Result<()>>,
}

async fn harness(lifetime: SubscriptionLifetime) -> Result<Harness, Error> {
    let log = MemoryLog::new();
    let state = StreamState::new(log.clone(), log.hub.clone()).with_subscription_lifetime(lifetime);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (shutdown, stop) = oneshot::channel();
    let server = tokio::spawn(serve(listener, stream_service(state), async {
        let _ = stop.await;
    }));
    let uri: http::Uri = format!("http://{addr}").parse()?;
    let transport = Http2Connection::connect_plaintext(uri.clone())
        .await?
        .shared(16);
    let client = ServiceClient::new(transport, ClientConfig::new(uri));
    Ok(Harness {
        log,
        client,
        shutdown,
        server,
    })
}

fn request(since_sequence_number: Option<u64>) -> SubscribeRequest {
    SubscribeRequest {
        selectors: vec![ProtoSelector {
            prefix: Bytes::new(),
            payload_regex: "(?s).*".into(),
            ..Default::default()
        }],
        since_sequence_number,
        ..Default::default()
    }
}

#[derive(Debug)]
struct Frame {
    sequence_number: u64,
    entries: usize,
}

async fn next<B>(
    stream: &mut connectrpc::client::ServerStream<
        B,
        exoware_sdk::log::stream::v1::SubscribeResponseView<'static>,
    >,
) -> Result<Option<Frame>, connectrpc::ConnectError>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let message = timeout(
        Duration::from_secs(5),
        stream.message::<SubscribeResponse>(),
    )
    .await
    .expect("stream should make progress")?;
    Ok(message.map(|message| Frame {
        sequence_number: message.sequence_number(),
        entries: message.entries().len(),
    }))
}

fn reason(error: &connectrpc::ConnectError) -> String {
    decode_connect_error(error)
        .expect("decode connect error")
        .error_info
        .expect("error info")
        .reason
}

#[tokio::test]
async fn graceful_shutdown_ends_an_idle_live_subscription() -> Result<(), Error> {
    let Harness {
        log,
        client,
        shutdown,
        server,
    } = harness(SubscriptionLifetime::unbounded()).await?;
    log.publish(1, b"one");
    let mut stream = client.subscribe(request(None)).await?;

    let checkpoint = next(&mut stream).await?.expect("opening frame");
    assert_eq!(checkpoint.sequence_number, 1);
    assert_eq!(checkpoint.entries, 0);

    shutdown.send(()).unwrap();
    let error = next(&mut stream).await.expect_err("shutdown ends stream");
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert_eq!(reason(&error), REASON_SERVER_CLOSING);

    timeout(Duration::from_secs(5), server)
        .await
        .expect("graceful drain must finish")??;
    Ok(())
}

#[tokio::test]
async fn graceful_shutdown_ends_a_replaying_subscription_after_its_cursor() -> Result<(), Error> {
    let Harness {
        log,
        client,
        shutdown,
        server,
    } = harness(SubscriptionLifetime::unbounded()).await?;
    log.publish(1, b"one");
    log.publish(2, b"two");
    let mut stream = client.subscribe(request(Some(2))).await?;

    let checkpoint = next(&mut stream).await?.expect("opening frame");
    assert_eq!(checkpoint.sequence_number, 1);
    assert_eq!(checkpoint.entries, 0);
    let frame = next(&mut stream).await?.expect("replayed frame");
    assert_eq!(frame.sequence_number, 2);

    shutdown.send(()).unwrap();
    let error = next(&mut stream).await.expect_err("shutdown ends stream");
    assert_eq!(reason(&error), REASON_SERVER_CLOSING);
    timeout(Duration::from_secs(5), server)
        .await
        .expect("graceful drain must finish")??;
    Ok(())
}

#[tokio::test]
async fn lifetime_is_one_deadline_that_deliveries_do_not_reset() -> Result<(), Error> {
    let lifetime = SubscriptionLifetime::new(Duration::from_millis(600)).with_jitter_fraction(0.0);
    let Harness {
        log,
        client,
        shutdown,
        server,
    } = harness(lifetime).await?;
    let started = Instant::now();
    let mut stream = client.subscribe(request(None)).await?;
    let checkpoint = next(&mut stream).await?.expect("opening frame");
    assert_eq!(checkpoint.sequence_number, 0);

    tokio::time::sleep(Duration::from_millis(250)).await;
    log.publish(1, b"one");
    let frame = next(&mut stream).await?.expect("live frame");
    assert_eq!(frame.sequence_number, 1);

    tokio::time::sleep(Duration::from_millis(250)).await;
    log.publish(2, b"two");
    let frame = next(&mut stream).await?.expect("live frame");
    assert_eq!(frame.sequence_number, 2);

    let error = next(&mut stream).await.expect_err("lifetime ends stream");
    let elapsed = started.elapsed();
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert_eq!(reason(&error), REASON_SUBSCRIPTION_EXPIRED);
    assert!(
        elapsed >= Duration::from_millis(590),
        "ended early {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1_200),
        "deadline reset {elapsed:?}"
    );

    shutdown.send(()).unwrap();
    server.await??;
    Ok(())
}

#[tokio::test]
async fn graceful_shutdown_ends_a_subscription_whose_first_replay_read_is_stalled(
) -> Result<(), Error> {
    let Harness {
        log,
        client,
        shutdown,
        server,
    } = harness(SubscriptionLifetime::unbounded()).await?;
    log.publish(1, b"one");
    log.stall_reads.store(true, Ordering::SeqCst);
    let mut stream = client.subscribe(request(Some(1))).await?;

    let checkpoint = next(&mut stream).await?.expect("opening frame");
    assert_eq!(checkpoint.sequence_number, 0);
    assert_eq!(checkpoint.entries, 0);

    shutdown.send(()).unwrap();
    let error = next(&mut stream).await.expect_err("shutdown ends stream");
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert_eq!(reason(&error), REASON_SERVER_CLOSING);
    timeout(Duration::from_secs(5), server)
        .await
        .expect("graceful drain must finish")??;
    Ok(())
}
