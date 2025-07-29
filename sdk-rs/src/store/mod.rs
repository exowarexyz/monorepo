//! Clients for interacting with Exoware stores.
//!
//! Current store APIs include:
//! - kv: an API offering raw access into the underlying kv database powering most other stores.
//! - adb: an API into authenticated data stores backed by a kv database.

use crate::Client as SdkClient;

pub mod adb;
pub mod kv;

pub const PATH: &str = "/store";

/// A client for interacting with exoware store APIs.
#[derive(Clone)]
pub struct Client {
    pub(super) base_url: String,
    pub(super) client: SdkClient,
}

impl Client {
    /// Creates a new [Client].
    pub fn new(client: SdkClient) -> Self {
        Self {
            base_url: format!("{}{}", client.base_url, PATH),
            client,
        }
    }

    pub fn kv(&self) -> kv::Client {
        kv::Client::new(self.client.clone(), &self.base_url)
    }

    pub fn adb(&self) -> adb::Client {
        adb::Client::new(self.client.clone(), &self.base_url)
    }
}
