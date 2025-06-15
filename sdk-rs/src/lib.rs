//! Rust SDK for the Exoware API.

mod error;
pub use error::Error;
pub mod store;
pub mod stream;

use reqwest::Client as HttpClient;
use std::sync::Arc;

/// The client for interacting with the Exoware API.
#[derive(Clone)]
pub struct Client {
    http_client: HttpClient,
    base_url: String,
    token: Arc<String>,
}

impl Client {
    /// Creates a new [Client].
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the Exoware server (e.g., `http://localhost:8080`).
    /// * `token` - The token to use for bearer authentication.
    pub fn new(base_url: String, token: String) -> Self {
        Self {
            http_client: HttpClient::new(),
            base_url,
            token: Arc::new(token),
        }
    }

    /// Returns a [store::Client] for interacting with the key-value store.
    pub fn store(&self) -> store::Client {
        store::Client::new(self.clone())
    }

    /// Returns a [stream::Client] for interacting with realtime streams.
    pub fn stream(&self) -> stream::Client {
        stream::Client::new(self.clone())
    }

    /// Returns the base URL of the server.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}
