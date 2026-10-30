//! HTTP server entrypoints.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, Router};
use exoware_sdk::PreferZstdLayer;
use exoware_server::{connect_stack, AppState};
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::RocksStore;

pub const CMD: &str = "server";
pub const RUN_CMD: &str = "run";

async fn health() -> &'static str {
    "ok"
}

/// The simulator's routes, shared by [`run`] and [`open_temp`] so tests serve the same stack.
fn app(engine: RocksStore) -> Router {
    Router::new()
        .route("/health", get(health))
        .fallback_service(connect_stack(AppState::new(Arc::new(engine))))
        .layer(PreferZstdLayer)
        .layer(CorsLayer::very_permissive())
}

/// Run the store simulator until the process is interrupted.
pub async fn run(
    directory: &Path,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = app(RocksStore::open(directory, None)?);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(%addr, directory = %directory.display(), "store simulator listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    exoware_server::ingest::transport::serve(listener, app, std::future::pending()).await?;
    Ok(())
}

/// Used by integration tests: bind an ephemeral port and return the base URL.
///
/// The server runs on a temporary data directory owned by the store
/// ([`RocksStore::open_owned`]), deleted only after the database has fully closed.
pub async fn open_temp(
) -> Result<(tokio::task::JoinHandle<()>, String), Box<dyn std::error::Error + Send + Sync>> {
    let data_dir = tempfile::tempdir()?;
    let app = app(RocksStore::open_owned(data_dir, None)?);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let url = format!("http://127.0.0.1:{port}");
    let handle = tokio::spawn(async move {
        let _ =
            exoware_server::ingest::transport::serve(listener, app, std::future::pending()).await;
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
