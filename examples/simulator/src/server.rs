//! HTTP server entrypoints.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, Router};
use exoware_server::{connect_stack, AppState};
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::{RocksConfig, RocksStore};

pub const CMD: &str = "server";
pub const RUN_CMD: &str = "run";

async fn health() -> &'static str {
    "ok"
}

/// Store options for the served simulator. Every commit ingests new SST files, and they pile
/// up while compaction catches up. Stock RocksDB sets `max_background_jobs` to 2, which runs
/// one compaction at a time across both column families. Four jobs let it run up to three
/// once level zero backs up. Stock RocksDB also keeps every table file open, so a backlog of
/// a thousand files exhausts the default descriptor limit of 1024. Capping open tables keeps
/// the simulator well below that limit.
fn store_config() -> RocksConfig {
    let mut config = RocksConfig::default();
    config.db_options.set_max_background_jobs(4);
    config.db_options.set_max_open_files(512);
    config
}

/// Run the store simulator until the process is interrupted.
pub async fn run(
    directory: &Path,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let engine = Arc::new(RocksStore::open(directory, Some(store_config()))?);
    let state = AppState::new(engine);
    let connect = connect_stack(state);

    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(connect)
        .layer(CorsLayer::very_permissive());

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
    let engine = Arc::new(RocksStore::open_owned(data_dir, Some(store_config()))?);
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
