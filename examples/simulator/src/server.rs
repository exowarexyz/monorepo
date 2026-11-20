//! HTTP server entrypoints.

use crate::{RocksConfig, RocksStore};
use axum::{
    routing::get,
    serve::{Listener, ListenerExt},
    Router,
};
use exoware_sdk::{transport::set_tcp_nodelay, PreferZstdLayer};
use exoware_server::{
    connect_stack, ingest::transport::ServeConfig, AppState, SubscriptionLifetime,
};
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

pub const CMD: &str = "server";
pub const RUN_CMD: &str = "run";

async fn health() -> &'static str {
    "ok"
}

/// Default for `--max-open-files`.
pub const DEFAULT_MAX_OPEN_FILES: i32 = 16_384;

/// Store options for the served simulator. Every commit group adds a log and a state SST and
/// log files are never merged, so RocksDB's open tables are capped at `max_open_files`. Under
/// pressure the table cache closes the log files, which nothing reads, and keeps the state
/// files every point read probes. The process open-file limit must cover the cap.
fn store_config(max_open_files: i32) -> RocksConfig {
    if let Ok(limit) = rlimit::Resource::NOFILE.get_soft() {
        if limit <= max_open_files as u64 {
            warn!(
                limit,
                max_open_files, "open-file limit is below the open-table cap, raise ulimit -n"
            );
        }
    }
    let mut config = RocksConfig::default();
    config.db_options.set_max_open_files(max_open_files);
    config
}

/// The simulator's routes, shared by [`run`] and [`open_temp`] so tests serve the same stack.
fn app(engine: RocksStore, lifetime: SubscriptionLifetime) -> Router {
    Router::new()
        .route("/health", get(health))
        .fallback_service(connect_stack(
            AppState::new(Arc::new(engine)).with_subscription_lifetime(lifetime),
        ))
        .layer(PreferZstdLayer)
        .layer(CorsLayer::very_permissive())
}

// Completes on SIGINT or SIGTERM.
async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                warn!(%error, "cannot listen for SIGTERM, only SIGINT stops the server");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

// The first signal drains gracefully. Listening replaces the default signal
// disposition for the rest of the process, so a second signal has to stop the
// process itself for an operator who will not wait for the shutdown timeout.
async fn shutdown_signal() {
    stop_signal().await;
    tokio::spawn(async {
        stop_signal().await;
        warn!("received a second signal, stopping without draining");
        std::process::exit(130);
    });
}

/// Run the store simulator until it receives SIGINT or SIGTERM.
///
/// Shutdown ends open subscriptions with a resumable `UNAVAILABLE` error and
/// gives other requests until `config.shutdown_timeout` to finish before
/// closing their connections. A second signal stops the process at once.
pub async fn run(
    directory: &Path,
    port: u16,
    max_open_files: i32,
    lifetime: SubscriptionLifetime,
    config: ServeConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = app(
        RocksStore::open(directory, Some(store_config(max_open_files)))?,
        lifetime,
    );

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(%addr, directory = %directory.display(), "store simulator listening");
    let listener = tokio::net::TcpListener::bind(addr)
        .await?
        .tap_io(set_tcp_nodelay);
    exoware_server::ingest::transport::serve_with_config(listener, app, shutdown_signal(), config)
        .await?;
    info!("store simulator stopped");
    Ok(())
}

/// Serve the store in `directory` on `listener` until `shutdown` completes.
///
/// Used by integration tests that stop and restart a server over the same store.
pub async fn serve_until(
    directory: &Path,
    listener: tokio::net::TcpListener,
    lifetime: SubscriptionLifetime,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = app(
        RocksStore::open(directory, Some(store_config(DEFAULT_MAX_OPEN_FILES)))?,
        lifetime,
    );
    exoware_server::ingest::transport::serve(listener.tap_io(set_tcp_nodelay), app, shutdown)
        .await?;
    Ok(())
}

/// Used by integration tests: bind an ephemeral port and return the base URL.
///
/// The server runs on a temporary data directory owned by the store
/// ([`RocksStore::open_owned`]), deleted only after the database has fully closed.
pub async fn open_temp(
) -> Result<(tokio::task::JoinHandle<()>, String), Box<dyn std::error::Error + Send + Sync>> {
    let data_dir = tempfile::tempdir()?;
    let app = app(
        RocksStore::open_owned(data_dir, Some(store_config(DEFAULT_MAX_OPEN_FILES)))?,
        SubscriptionLifetime::unbounded(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await?
        .tap_io(set_tcp_nodelay);
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
