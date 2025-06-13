use axum::{serve, Router};
use std::path::PathBuf;
use thiserror::Error;
use tokio::net::TcpListener;

/// Subcommand for the server.
pub const CMD: &str = "server";

/// Run the local server.
pub const RUN_CMD: &str = "run";

/// Errors that can occur when running the local server.
#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub async fn run(directory: &PathBuf, port: &u16) -> Result<(), Error> {
    // Create a listener for the server on the specified port.
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

    // Create a router for the server.
    let router = Router::new();

    // Serve the server.
    serve(listener, router.into_make_service())
        .await
        .map_err(Error::Io)
}
