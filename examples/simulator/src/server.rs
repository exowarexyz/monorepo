//! HTTP server entrypoints.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, Router};
use bytes::Bytes;
use exoware_sdk::prune_policy::PrunePolicyDocument;
use exoware_server::{
    connect_stack, AppState, Ingest, Log, LogBatch, Prune, Query, QueryExtra, RangeScan,
    RangeScanBatch, Sequence,
};
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::rocks::RocksRangeScanCursor;
use crate::RocksStore;

pub const CMD: &str = "server";
pub const RUN_CMD: &str = "run";

async fn health() -> &'static str {
    "ok"
}

/// Run the store simulator until the process is interrupted.
pub async fn run(
    directory: &std::path::Path,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let engine = Arc::new(RocksStore::open(directory, None)?);
    let state = AppState::new(engine);
    let connect = connect_stack(state);

    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(connect)
        .layer(CorsLayer::very_permissive());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(%addr, directory = %directory.display(), "store simulator listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Store engine that keeps `guard` (the test's tempdir) alive until the engine — and every
/// range-scan cursor it hands out, which pins the DB independently — is dropped. Server and
/// connection tasks all hold engine clones and are torn down in arbitrary order when a test
/// runtime shuts down; owning the guard here (declared after the store, so it drops last, and
/// cloned into each cursor) keeps the data directory alive for as long as any store handle or
/// open cursor. Deleting the directory under a live store cannot corrupt anything, but it makes
/// the final close stall on RocksDB's background-error recovery loop.
struct GuardedStore<G> {
    store: RocksStore,
    _guard: Arc<G>,
}

/// Range-scan cursor that carries the tempdir guard: connection tasks hold the cursor (not the
/// engine) in their response streams, and the cursor's iterator pins the DB.
struct GuardedRangeScan<G> {
    inner: RocksRangeScanCursor,
    _guard: Arc<G>,
}

impl<G: Send + Sync + 'static> RangeScan for GuardedRangeScan<G> {
    async fn next_batch(&mut self, max_items: usize) -> Result<RangeScanBatch, String> {
        self.inner.next_batch(max_items).await
    }
}

impl<G: Send + Sync + 'static> Sequence for GuardedStore<G> {
    fn current_sequence(&self) -> u64 {
        self.store.current_sequence()
    }
}

impl<G: Send + Sync + 'static> Ingest for GuardedStore<G> {
    async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, String> {
        self.store.put_batch(kvs).await
    }
}

impl<G: Send + Sync + 'static> Query for GuardedStore<G> {
    type RangeScan = GuardedRangeScan<G>;

    async fn get(&self, key: Bytes) -> Result<(Option<Bytes>, QueryExtra), String> {
        self.store.get(key).await
    }

    async fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Result<Self::RangeScan, String> {
        Ok(GuardedRangeScan {
            inner: self.store.range_scan(start, end, limit, forward).await?,
            _guard: self._guard.clone(),
        })
    }

    async fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> Result<(Vec<(Bytes, Option<Bytes>)>, QueryExtra), String> {
        self.store.get_many(keys).await
    }
}

impl<G: Send + Sync + 'static> Prune for GuardedStore<G> {
    async fn apply_prune_policies(&self, document: PrunePolicyDocument) -> Result<(), String> {
        self.store.apply_prune_policies(document).await
    }
}

impl<G: Send + Sync + 'static> Log for GuardedStore<G> {
    async fn get_batch(&self, sequence_number: u64) -> Result<Option<LogBatch>, String> {
        self.store.get_batch(sequence_number).await
    }

    async fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
        self.store.oldest_retained_batch().await
    }
}

/// Used by integration tests: bind an ephemeral port and return the base URL.
///
/// `guard` (typically the `TempDir` owning `data_dir`) lives inside the engine and is dropped
/// after the store closes, so the data directory stays alive for as long as any engine handle
/// does — however the test runtime tears its tasks down.
pub async fn spawn_for_test(
    data_dir: &Path,
    guard: impl Send + Sync + 'static,
) -> Result<(tokio::task::JoinHandle<()>, String), Box<dyn std::error::Error + Send + Sync>> {
    let engine = Arc::new(GuardedStore {
        store: RocksStore::open(data_dir, None)?,
        _guard: Arc::new(guard),
    });
    let state = AppState::new(engine);
    let connect = connect_stack(state);
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(connect)
        .layer(CorsLayer::very_permissive());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let url = format!("http://127.0.0.1:{port}");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    wait_for_health(&url).await?;
    Ok((handle, url))
}

/// Poll until `GET {base}/health` succeeds (same contract as production query workers).
async fn wait_for_health(base: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let health = format!("{base}/health");
    let client = reqwest::Client::new();
    for _ in 0..200 {
        if client
            .get(&health)
            .send()
            .await
            .ok()
            .is_some_and(|r| r.status().is_success())
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err(format!("store simulator did not become ready at {health}").into())
}
