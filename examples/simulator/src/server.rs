//! HTTP server entrypoints.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, Router};
use tower_http::cors::CorsLayer;
use tracing::info;

use exoware_server::{connect_stack, AppState};

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
    let engine = Arc::new(RocksStore::open(directory)?);
    let state = AppState::new(engine);
    let connect = connect_stack(state);

    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(connect)
        .layer(CorsLayer::very_permissive());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(%addr, "store simulator listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Used by integration tests: bind an ephemeral port and return the base URL.
pub async fn spawn_for_test(
    data_dir: &Path,
) -> Result<(tokio::task::JoinHandle<()>, String), Box<dyn std::error::Error + Send + Sync>> {
    let engine = Arc::new(RocksStore::open(data_dir)?);
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
