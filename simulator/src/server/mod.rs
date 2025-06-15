use axum::{serve, Router};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::info;

mod auth;
mod store;
mod stream;

/// Subcommand for the server.
pub const CMD: &str = "server";

/// Run the simulator server.
pub const RUN_CMD: &str = "run";

/// The maximum size of any request body in bytes (21MB).
const MAX_REQUEST_BODY_SIZE: usize = 21 * 1024 * 1024;

/// Errors that can occur when running the simulator server.
#[derive(Error, Debug)]
pub enum Error {
    /// An I/O error occurred.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// An error occurred with the underlying RocksDB store.
    #[error("rocksdb error: {0}")]
    RocksDb(#[from] rocksdb::Error),
}

/// Runs the Exoware simulator server.
///
/// This function sets up and runs the HTTP server, which includes the store and stream endpoints.
///
/// # Arguments
///
/// * `directory` - The path to the directory for the persistent store.
/// * `port` - The port to bind the server to.
/// * `consistency_bound_min` - The minimum eventual consistency delay in milliseconds.
/// * `consistency_bound_max` - The maximum eventual consistency delay in milliseconds.
/// * `auth_token` - The token to use for bearer authentication.
/// * `allow_public_access` - A flag to allow unauthenticated access for read-only methods.
pub async fn run(
    directory: &Path,
    port: &u16,
    consistency_bound_min: u64,
    consistency_bound_max: u64,
    auth_token: String,
    allow_public_access: bool,
) -> Result<(), Error> {
    info!(
        directory = %directory.display(),
        port = port,
        consistency_bound_min = consistency_bound_min,
        consistency_bound_max = consistency_bound_max,
        allow_public_access = allow_public_access,
        "starting exoware simulator server"
    );

    // Create a listener for the server on the specified port.
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!(address = %listener.local_addr()?, "server listening");

    // Create a router for the server.
    let auth_token = Arc::new(auth_token);
    let store_router = store::router(
        directory,
        consistency_bound_min,
        consistency_bound_max,
        auth_token.clone(),
        allow_public_access,
    )?;
    let stream_router = stream::router(auth_token, allow_public_access);

    // Create a permissive CORS layer.
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any);

    let router = Router::new()
        .nest("/store", store_router)
        .nest("/stream", stream_router)
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_SIZE));

    info!("server routes configured, starting to serve requests");

    // Serve the server.
    serve(listener, router.into_make_service())
        .await
        .map_err(Error::Io)
}
