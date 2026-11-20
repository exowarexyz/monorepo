//! A live subscriber keeps one continuous stream across server restarts and
//! server-enforced subscription lifetimes.

use bytes::Bytes;
use exoware_sdk::{
    keys::{Key, Prefix},
    kv_codec::Utf8,
    retention::RetentionPolicy,
    selector::Selector,
    stream_filter::StreamFilter,
    ErrorCode, PrefixedStoreClient, RetryConfig, StoreClient, StreamSubscription,
    SubscriptionRetryConfig,
};
use exoware_server::{SubscriptionLifetime, REASON_SUBSCRIPTION_EXPIRED};
use std::{net::SocketAddr, path::Path, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

type Error = Box<dyn std::error::Error + Send + Sync>;

// A simulator over a persistent directory that can stop and restart on the same address.
struct Server {
    addr: SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), Error>>,
}

impl Server {
    async fn start(
        directory: &Path,
        addr: SocketAddr,
        lifetime: SubscriptionLifetime,
    ) -> Result<Self, Error> {
        let listener = TcpListener::bind(addr).await?;
        let addr = listener.local_addr()?;
        let (shutdown, signal) = oneshot::channel::<()>();
        let directory = directory.to_path_buf();
        let task = tokio::spawn(async move {
            exoware_simulator::server::serve_until(&directory, listener, lifetime, async {
                let _ = signal.await;
            })
            .await
        });
        let server = Self {
            addr,
            shutdown,
            task,
        };
        server.wait_ready().await?;
        Ok(server)
    }

    async fn wait_ready(&self) -> Result<(), Error> {
        let health = format!("http://{}/health", self.addr);
        let client = reqwest::Client::new();
        for _ in 0..200 {
            if client.get(&health).send().await.is_ok() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Err("simulator did not become ready".into())
    }

    async fn stop(self) -> Result<SocketAddr, Error> {
        let _ = self.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(10), self.task).await???;
        Ok(self.addr)
    }

    fn client(&self, retry: SubscriptionRetryConfig) -> PrefixedStoreClient {
        let client = StoreClient::builder()
            .url(&format!("http://{}", self.addr))
            .retry_config(RetryConfig::disabled())
            .subscription_retry(retry)
            .build()
            .expect("build client");
        PrefixedStoreClient::empty(client)
    }
}

fn key(family: u8, payload: &[u8]) -> Key {
    Prefix::from_byte(family).encode(payload).expect("encode")
}

fn filter(family: u8) -> StreamFilter {
    StreamFilter {
        selectors: vec![Selector {
            prefix: Bytes::from(vec![family]),
            payload_regex: Utf8::from("(?s).*"),
        }],
        value_filters: vec![],
    }
}

// Writes one matching and one nonmatching batch, returning the matching sequence.
async fn write(client: &PrefixedStoreClient, label: u32) -> u64 {
    client
        .ingest()
        .put(&[(&key(2, &label.to_be_bytes()), b"skip")])
        .await
        .expect("put nonmatching");
    client
        .ingest()
        .put(&[(&key(1, &label.to_be_bytes()), b"keep")])
        .await
        .expect("put matching")
}

async fn collect(subscription: &mut StreamSubscription, count: usize) -> Vec<u64> {
    let mut delivered = Vec::with_capacity(count);
    while delivered.len() < count {
        let batch = tokio::time::timeout(Duration::from_secs(20), subscription.next())
            .await
            .expect("subscription stalled")
            .expect("subscription failed")
            .expect("subscription ended");
        delivered.push(batch.sequence_number);
    }
    delivered
}

// Keeps the subscription polled from its own task, so reconnects run while
// the server is down instead of waiting for the next call.
fn consume(mut subscription: StreamSubscription) -> mpsc::UnboundedReceiver<u64> {
    let (sender, receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(batch) = subscription.next().await.expect("subscription failed") {
            if sender.send(batch.sequence_number).is_err() {
                return;
            }
        }
    });
    receiver
}

async fn receive(delivered: &mut mpsc::UnboundedReceiver<u64>, count: usize) -> Vec<u64> {
    let mut sequences = Vec::with_capacity(count);
    while sequences.len() < count {
        let sequence = tokio::time::timeout(Duration::from_secs(20), delivered.recv())
            .await
            .expect("subscription stalled")
            .expect("subscription ended");
        sequences.push(sequence);
    }
    sequences
}

const fn resuming() -> SubscriptionRetryConfig {
    SubscriptionRetryConfig::standard()
        .with_initial_backoff(Duration::from_millis(200))
        .with_max_backoff(Duration::from_millis(400))
}

#[tokio::test]
async fn restarts_under_a_live_subscriber_keep_one_continuous_stream() -> Result<(), Error> {
    let directory = tempfile::tempdir()?;
    let addr: SocketAddr = "127.0.0.1:0".parse()?;
    let mut server =
        Server::start(directory.path(), addr, SubscriptionLifetime::unbounded()).await?;
    let subscription = server
        .client(resuming())
        .stream()
        .subscribe(filter(1), None)
        .await?;
    let mut delivered = consume(subscription);

    for round in 0..3_u32 {
        let writer = server.client(SubscriptionRetryConfig::disabled());
        let mut expected = Vec::new();
        for label in 0..3 {
            expected.push(write(&writer, round * 10 + label).await);
        }
        assert_eq!(receive(&mut delivered, expected.len()).await, expected);

        // The subscriber is refused while the server is down and must still
        // replay the writes made before it reconnects.
        let addr = server.stop().await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        server = Server::start(directory.path(), addr, SubscriptionLifetime::unbounded()).await?;
        let writer = server.client(SubscriptionRetryConfig::disabled());
        let mut expected = Vec::new();
        for label in 3..6 {
            expected.push(write(&writer, round * 10 + label).await);
        }
        assert_eq!(receive(&mut delivered, expected.len()).await, expected);
    }

    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn subscription_lifetime_closes_and_the_client_resumes_without_gaps() -> Result<(), Error> {
    let directory = tempfile::tempdir()?;
    let lifetime = SubscriptionLifetime::new(Duration::from_millis(300)).with_jitter(0.0);
    let server = Server::start(directory.path(), "127.0.0.1:0".parse()?, lifetime).await?;

    // Without resumption the forced close is visible.
    let mut plain = server
        .client(SubscriptionRetryConfig::disabled())
        .stream()
        .subscribe(filter(1), None)
        .await?;
    let error = tokio::time::timeout(Duration::from_secs(5), plain.next())
        .await?
        .expect_err("the lifetime must end the subscription");
    assert_eq!(error.rpc_error().unwrap().code, ErrorCode::Unavailable);
    let decoded = error.decoded_rpc_error().unwrap().unwrap();
    assert_eq!(
        decoded.error_info.unwrap().reason,
        REASON_SUBSCRIPTION_EXPIRED
    );

    let fast = SubscriptionRetryConfig::standard()
        .with_initial_backoff(Duration::from_millis(10))
        .with_max_backoff(Duration::from_millis(20));
    let mut subscription = server
        .client(fast)
        .stream()
        .subscribe(filter(1), None)
        .await?;
    let writer = server.client(SubscriptionRetryConfig::disabled());
    let mut expected = Vec::new();
    for label in 0..20 {
        expected.push(write(&writer, label).await);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(collect(&mut subscription, expected.len()).await, expected);
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn evicted_cursor_is_returned_without_retrying() -> Result<(), Error> {
    let directory = tempfile::tempdir()?;
    let server = Server::start(
        directory.path(),
        "127.0.0.1:0".parse()?,
        SubscriptionLifetime::unbounded(),
    )
    .await?;
    let client = server.client(resuming());
    for label in 0..20 {
        write(&client, label).await;
    }
    client
        .retention()
        .set_retention(Some(RetentionPolicy::KeepLatest { count: 10 }))
        .await?;

    let started = std::time::Instant::now();
    let error = match client.stream().subscribe(filter(1), Some(1)).await {
        Err(error) => error,
        Ok(mut subscription) => subscription
            .next()
            .await
            .expect_err("an evicted cursor must fail"),
    };
    assert_eq!(error.rpc_error().unwrap().code, ErrorCode::OutOfRange);
    let decoded = error.decoded_rpc_error().unwrap().unwrap();
    assert_eq!(decoded.error_info.unwrap().reason, "BATCH_EVICTED");
    assert!(started.elapsed() < Duration::from_secs(1));
    server.stop().await?;
    Ok(())
}
