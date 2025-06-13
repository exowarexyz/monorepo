pub mod error;
pub mod store;
pub mod stream;

use reqwest::Client as HttpClient;
use std::sync::Arc;

#[derive(Clone)]
pub struct Client {
    http_client: HttpClient,
    base_url: String,
    auth_token: Arc<String>,
}

impl Client {
    pub fn new(base_url: String, auth_token: String) -> Self {
        Self {
            http_client: HttpClient::new(),
            base_url,
            auth_token: Arc::new(auth_token),
        }
    }

    pub fn store(&self) -> store::StoreClient {
        store::StoreClient::new(self.clone())
    }

    pub fn stream(&self) -> stream::StreamClient {
        stream::StreamClient::new(self.clone())
    }
}
