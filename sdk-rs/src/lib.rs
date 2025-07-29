//! Rust SDK for the Exoware API.

mod error;
pub use error::Error;
pub mod store;
pub mod stream;

use http::{header::AUTHORIZATION, HeaderMap};
use reqwest::{Client as HttpClient, Response};

/// The top-level client for interacting with Exoware APIs.
///
/// Provides authentication and other cross-cutting capabilities to its sub-clients.
#[derive(Clone)]
pub struct Client {
    http_client: HttpClient,
    base_url: String,
    token: String,
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
            token,
        }
    }

    /// Helper that adds the bearer authentication header to the provided `headers`.
    fn add_auth_header(&self, headers: &mut HeaderMap) {
        headers.insert(
            AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {}", self.token)).unwrap(),
        );
    }

    /// Helper that sends a get request to the provided `url` with the provided `headers` and
    /// returns the response.
    async fn get(&self, url: String, headers: HeaderMap) -> Result<Response, reqwest::Error> {
        self.http_client.get(&url).headers(headers).send().await
    }

    /// Helper that sends a get request to the provided `url` with the provided `headers` and
    /// `body` and returns the response.
    async fn post(
        &self,
        url: String,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<Response, reqwest::Error> {
        self.http_client
            .post(&url)
            .headers(headers)
            .body(body)
            .send()
            .await
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
