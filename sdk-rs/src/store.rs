//! Persist and retrieve artifacts.

use crate::{error::Error, Client as SdkClient};
use base64::{engine::general_purpose, Engine as _};
use reqwest::header::{HeaderValue, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

/// The JSON payload for a `get` operation response.
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct GetResultPayload {
    #[serde_as(as = "Base64")]
    pub value: Vec<u8>,
}

/// An item in the result of a `query` operation.
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct QueryResultItemPayload {
    /// The key of the item.
    #[serde_as(as = "Base64")]
    pub key: Vec<u8>,
    /// The value of the item.
    #[serde_as(as = "Base64")]
    pub value: Vec<u8>,
}

/// The JSON payload for a `query` operation response.
#[derive(Serialize, Deserialize, Debug)]
pub struct QueryResultPayload {
    pub results: Vec<QueryResultItemPayload>,
}

/// A client for interacting with the key-value store.
#[derive(Clone)]
pub struct Client {
    client: SdkClient,
}

impl Client {
    /// Creates a new [Client].
    pub fn new(client: SdkClient) -> Self {
        Self { client }
    }

    /// Sets a key-value pair in the store.
    pub async fn set(&self, key: &[u8], value: Vec<u8>) -> Result<(), Error> {
        let key_b64 = general_purpose::STANDARD.encode(key);
        let url = format!("{}/store/{}", self.client.base_url, key_b64);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.client.token)).unwrap(),
        );

        let res = self
            .client
            .http_client
            .post(&url)
            .headers(headers)
            .body(value)
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(Error::Http(res.status()));
        }

        Ok(())
    }

    /// Retrieves a value from the store by its key.
    ///
    /// If the key does not exist, `Ok(None)` is returned.
    pub async fn get(&self, key: &[u8]) -> Result<Option<GetResultPayload>, Error> {
        let key_b64 = general_purpose::STANDARD.encode(key);
        let url = format!("{}/store/{}", self.client.base_url, key_b64);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.client.token)).unwrap(),
        );

        let res = self
            .client
            .http_client
            .get(&url)
            .headers(headers)
            .send()
            .await?;

        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !res.status().is_success() {
            return Err(Error::Http(res.status()));
        }

        Ok(Some(res.json().await?))
    }

    /// Queries for a range of key-value pairs.
    ///
    /// # Arguments
    ///
    /// * `start` - The key to start the query from (inclusive). If `None`, the query starts from the first key.
    /// * `end` - The key to end the query at (exclusive). If `None`, the query continues to the last key.
    /// * `limit` - The maximum number of results to return. If `None`, all results are returned.
    pub async fn query(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: Option<usize>,
    ) -> Result<QueryResultPayload, Error> {
        let mut url = format!("{}/store?", self.client.base_url);
        if let Some(start) = start {
            let start_b64 = general_purpose::STANDARD.encode(start);
            url.push_str(&format!("start={start_b64}&"));
        }
        if let Some(end) = end {
            let end_b64 = general_purpose::STANDARD.encode(end);
            url.push_str(&format!("end={end_b64}&"));
        }
        if let Some(limit) = limit {
            url.push_str(&format!("limit={limit}"));
        }

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.client.token)).unwrap(),
        );

        let res = self
            .client
            .http_client
            .get(&url)
            .headers(headers)
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(Error::Http(res.status()));
        }

        let payload: QueryResultPayload = res.json().await?;

        Ok(payload)
    }
}
