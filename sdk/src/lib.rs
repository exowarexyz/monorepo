#[cfg(feature = "testing")]
pub mod testing;

pub mod error;
pub mod store;
pub mod stream;

use reqwest::Client as HttpClient;
use std::sync::Arc;

/// The main client for interacting with an Exoware server.
#[derive(Clone)]
pub struct Client {
    http_client: HttpClient,
    base_url: String,
    auth_token: Arc<String>,
}

impl Client {
    /// Creates a new `Client`.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the Exoware server (e.g., `http://localhost:8080`).
    /// * `auth_token` - The token to use for bearer authentication.
    pub fn new(base_url: String, auth_token: String) -> Self {
        Self {
            http_client: HttpClient::new(),
            base_url,
            auth_token: Arc::new(auth_token),
        }
    }

    /// Returns a `StoreClient` for interacting with the key-value store.
    pub fn store(&self) -> store::StoreClient {
        store::StoreClient::new(self.clone())
    }

    /// Returns a `StreamClient` for interacting with real-time streams.
    pub fn stream(&self) -> stream::StreamClient {
        stream::StreamClient::new(self.clone())
    }

    /// Returns the base URL of the server.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}
