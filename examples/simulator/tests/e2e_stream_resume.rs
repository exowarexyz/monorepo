use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::{extract::Request, Router};
use bytes::Bytes;
use exoware_sdk::kv_codec::Utf8;
use exoware_sdk::retention::RetentionPolicy;
use exoware_sdk::selector::Selector;
use exoware_sdk::stream_filter::StreamFilter;
use exoware_sdk::{PrefixedStoreClient, RetryConfig, StoreClient, StreamSubscription};
use exoware_server::{connect_stack, AppState, SubscriptionLifetime};
use exoware_simulator::RocksStore;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

struct Server {
    address: SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Server {
    async fn start(
        directory: &Path,
        address: SocketAddr,
        denied: Arc<AtomicBool>,
        subscriptions: Arc<AtomicUsize>,
    ) -> Self {
        Self::with_lifetime(
            directory,
            address,
            denied,
            subscriptions,
            SubscriptionLifetime::unbounded(),
        )
        .await
    }

    async fn with_lifetime(
        directory: &Path,
        address: SocketAddr,
        denied: Arc<AtomicBool>,
        subscriptions: Arc<AtomicUsize>,
        lifetime: SubscriptionLifetime,
    ) -> Self {
        let engine = Arc::new(RocksStore::open(directory, None).unwrap());
        let state = AppState::new(engine).with_subscription_lifetime(lifetime);
        let app = Router::new()
            .fallback_service(connect_stack(state))
            .layer(middleware::from_fn(move |request: Request, next: Next| {
                let denied = denied.clone();
                let subscriptions = subscriptions.clone();
                async move {
                    if request.uri().path() == "/log.stream.v1.Service/Subscribe" {
                        subscriptions.fetch_add(1, Ordering::SeqCst);
                        if denied.load(Ordering::SeqCst) {
                            return (
                                StatusCode::FORBIDDEN,
                                [(CONTENT_TYPE, "application/json")],
                                r#"{"code":"permission_denied","message":"subscription denied"}"#,
                            )
                                .into_response();
                        }
                    }
                    next.run(request).await
                }
            }));
        let listener = tokio::net::TcpListener::bind(address).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(async move {
            exoware_server::ingest::transport::serve(listener, app, async {
                let _ = signal.await;
            })
            .await
            .unwrap();
        });
        Self {
            address,
            shutdown,
            task,
        }
    }

    fn client(&self) -> PrefixedStoreClient {
        PrefixedStoreClient::empty(
            StoreClient::builder()
                .url(&format!("http://{}", self.address))
                .retry_config(RetryConfig::disabled())
                .build()
                .unwrap(),
        )
    }

    async fn stop(self) {
        self.shutdown.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), self.task)
            .await
            .expect("subscriptions must not prevent graceful shutdown")
            .unwrap();
    }
}

fn filter() -> StreamFilter {
    StreamFilter {
        selectors: vec![Selector {
            prefix: Bytes::from_static(&[1]),
            payload_regex: Utf8::from("(?s).*"),
        }],
        value_filters: vec![],
    }
}

fn ephemeral_address() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}

async fn put(client: &PrefixedStoreClient, value: u8) -> u64 {
    client
        .ingest()
        .put(&[(&Bytes::from_static(&[1, b'k']), &[value])])
        .await
        .unwrap()
}

async fn next(subscription: &mut StreamSubscription) -> exoware_sdk::StoreBatch {
    tokio::time::timeout(Duration::from_secs(3), subscription.next())
        .await
        .expect("subscription should resume")
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn restart_replays_writes_without_gaps_or_duplicates() {
    let directory = tempfile::tempdir().unwrap();
    let denied = Arc::new(AtomicBool::new(false));
    let subscriptions = Arc::new(AtomicUsize::new(0));
    let server = Server::start(
        directory.path(),
        ephemeral_address(),
        denied.clone(),
        subscriptions.clone(),
    )
    .await;
    let address = server.address;
    let client = server.client();
    let mut subscription = client.stream().subscribe(filter(), None).await.unwrap();
    let first = put(&client, 1).await;
    assert_eq!(next(&mut subscription).await.sequence_number, first);

    server.stop().await;
    let server = Server::start(directory.path(), address, denied, subscriptions.clone()).await;
    let second = put(&client, 2).await;
    let third = put(&client, 3).await;
    assert_eq!(next(&mut subscription).await.sequence_number, second);
    assert_eq!(next(&mut subscription).await.sequence_number, third);
    let fourth = put(&client, 4).await;
    assert_eq!(next(&mut subscription).await.sequence_number, fourth);
    assert_eq!(subscriptions.load(Ordering::SeqCst), 2);
    drop(subscription);
    server.stop().await;
}

#[tokio::test]
async fn initial_checkpoint_resumes_before_first_matching_batch() {
    let directory = tempfile::tempdir().unwrap();
    let denied = Arc::new(AtomicBool::new(false));
    let subscriptions = Arc::new(AtomicUsize::new(0));
    let server = Server::start(
        directory.path(),
        ephemeral_address(),
        denied.clone(),
        subscriptions.clone(),
    )
    .await;
    let address = server.address;
    let client = server.client();
    let mut subscription = client.stream().subscribe(filter(), None).await.unwrap();

    // Polling consumes the hidden checkpoint without requiring a matching write.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), subscription.next())
            .await
            .is_err()
    );
    server.stop().await;
    let server = Server::start(directory.path(), address, denied, subscriptions.clone()).await;
    let sequence = put(&client, 1).await;
    assert_eq!(next(&mut subscription).await.sequence_number, sequence);
    assert_eq!(subscriptions.load(Ordering::SeqCst), 2);
    drop(subscription);
    server.stop().await;
}

#[tokio::test]
async fn revoked_permission_on_reconnect_is_terminal() {
    let directory = tempfile::tempdir().unwrap();
    let denied = Arc::new(AtomicBool::new(false));
    let subscriptions = Arc::new(AtomicUsize::new(0));
    let server = Server::start(
        directory.path(),
        ephemeral_address(),
        denied.clone(),
        subscriptions.clone(),
    )
    .await;
    let address = server.address;
    let client = server.client();
    let mut subscription = client.stream().subscribe(filter(), None).await.unwrap();
    let first = put(&client, 1).await;
    assert_eq!(next(&mut subscription).await.sequence_number, first);
    server.stop().await;

    denied.store(true, Ordering::SeqCst);
    let server = Server::start(directory.path(), address, denied, subscriptions.clone()).await;
    let error = tokio::time::timeout(Duration::from_secs(3), subscription.next())
        .await
        .expect("permission failures must not exhaust the retry budget")
        .unwrap_err();
    assert_eq!(
        error.rpc_code(),
        Some(connectrpc::ErrorCode::PermissionDenied)
    );
    assert_eq!(subscriptions.load(Ordering::SeqCst), 2);
    drop(subscription);
    server.stop().await;
}

#[tokio::test]
async fn evicted_resume_cursor_is_terminal() {
    let directory = tempfile::tempdir().unwrap();
    let denied = Arc::new(AtomicBool::new(false));
    let subscriptions = Arc::new(AtomicUsize::new(0));
    let server = Server::start(
        directory.path(),
        ephemeral_address(),
        denied.clone(),
        subscriptions.clone(),
    )
    .await;
    let address = server.address;
    let client = server.client();
    let mut subscription = client.stream().subscribe(filter(), None).await.unwrap();
    let first = put(&client, 1).await;
    assert_eq!(next(&mut subscription).await.sequence_number, first);
    server.stop().await;

    let server = Server::start(directory.path(), address, denied, subscriptions.clone()).await;
    put(&client, 2).await;
    put(&client, 3).await;
    client
        .retention()
        .set_retention(Some(RetentionPolicy::KeepLatest { count: 1 }))
        .await
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(3), subscription.next())
        .await
        .expect("eviction must not exhaust the retry budget")
        .unwrap_err();
    assert_eq!(error.rpc_code(), Some(connectrpc::ErrorCode::OutOfRange));
    assert_eq!(
        error
            .decoded_rpc_error()
            .unwrap()
            .unwrap()
            .error_info
            .unwrap()
            .reason,
        "BATCH_EVICTED",
    );
    assert_eq!(subscriptions.load(Ordering::SeqCst), 2);
    drop(subscription);
    server.stop().await;
}

#[tokio::test]
async fn maximum_duration_resumes_repeatedly_without_losing_batches() {
    let directory = tempfile::tempdir().unwrap();
    let subscriptions = Arc::new(AtomicUsize::new(0));
    let server = Server::with_lifetime(
        directory.path(),
        ephemeral_address(),
        Arc::new(AtomicBool::new(false)),
        subscriptions.clone(),
        SubscriptionLifetime::new(Duration::from_millis(100)).with_jitter_fraction(0.0),
    )
    .await;
    let client = server.client();
    let mut subscription = client.stream().subscribe(filter(), None).await.unwrap();
    let first = put(&client, 1).await;
    assert_eq!(next(&mut subscription).await.sequence_number, first);

    for value in 2..=4 {
        let expected_requests = subscriptions.load(Ordering::SeqCst) + 1;
        let write = async {
            tokio::time::timeout(Duration::from_secs(3), async {
                while subscriptions.load(Ordering::SeqCst) < expected_requests {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("maximum lifetime should cause a reconnect");
            put(&client, value).await
        };
        let (sequence, batch) = tokio::join!(write, next(&mut subscription));
        assert_eq!(batch.sequence_number, sequence);
        assert_eq!(batch.entries[0].value.as_ref(), &[value]);
    }
    assert!(subscriptions.load(Ordering::SeqCst) >= 4);
    drop(subscription);
    server.stop().await;
}
