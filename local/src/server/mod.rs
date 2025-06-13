use axum::{serve, Router};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;

mod auth;
mod store;
mod stream;

/// Subcommand for the server.
pub const CMD: &str = "server";

/// Run the local server.
pub const RUN_CMD: &str = "run";

/// Errors that can occur when running the local server.
#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("rocksdb error: {0}")]
    RocksDb(#[from] rocksdb::Error),
}

pub async fn run(
    directory: &Path,
    port: &u16,
    consistency_bound_min: u64,
    consistency_bound_max: u64,
    auth_token: String,
    allow_public_access: bool,
) -> Result<(), Error> {
    // Create a listener for the server on the specified port.
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

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
    let router = Router::new()
        .nest("/store", store_router)
        .nest("/stream", stream_router);

    // Serve the server.
    serve(listener, router.into_make_service())
        .await
        .map_err(Error::Io)
}
