use crate::{error::Error, Client};
use base64::{engine::general_purpose, Engine as _};
use reqwest::header::{HeaderValue, AUTHORIZATION};
use serde::{Deserialize, Serialize};

/// The JSON payload for a `get` operation response.
#[derive(Serialize, Deserialize, Debug)]
pub struct GetResultPayload {
    pub value: String,
}

/// The result of a `get` operation.
#[derive(Debug)]
pub struct GetResult {
    /// The retrieved value.
    pub value: Vec<u8>,
}

/// An item in the result of a `query` operation. For internal use.
#[derive(Serialize, Deserialize, Debug)]
pub struct QueryResultItemPayload {
    pub key: String,
    pub value: String,
}

/// An item in the result of a `query` operation.
#[derive(Debug)]
pub struct QueryResultItem {
    /// The key of the item.
    pub key: String,
    /// The value of the item.
    pub value: Vec<u8>,
}

/// The JSON payload for a `query` operation response.
#[derive(Serialize, Deserialize, Debug)]
pub struct QueryResultPayload {
    pub results: Vec<QueryResultItemPayload>,
}

/// The result of a `query` operation.
#[derive(Debug)]
pub struct QueryResult {
    /// A list of key-value pairs.
    pub results: Vec<QueryResultItem>,
}

/// A client for interacting with the key-value store.
#[derive(Clone)]
pub struct StoreClient {
    client: Client,
}

impl StoreClient {
    /// Creates a new `StoreClient`.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Sets a key-value pair in the store.
    pub async fn set(&self, key: &str, value: Vec<u8>) -> Result<(), Error> {
        let url = format!("{}/store/{}", self.client.base_url, key);
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
    pub async fn get(&self, key: &str) -> Result<Option<GetResult>, Error> {
        let url = format!("{}/store/{}", self.client.base_url, key);
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

        let payload: GetResultPayload = res.json().await?;
        let value = general_purpose::STANDARD.decode(payload.value)?;

        Ok(Some(GetResult { value }))
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
        start: Option<&str>,
        end: Option<&str>,
        limit: Option<usize>,
    ) -> Result<QueryResult, Error> {
        let mut url = format!("{}/store?", self.client.base_url);
        if let Some(start) = start {
            url.push_str(&format!("start={}&", start));
        }
        if let Some(end) = end {
            url.push_str(&format!("end={}&", end));
        }
        if let Some(limit) = limit {
            url.push_str(&format!("limit={}", limit));
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
        let mut results = Vec::new();
        for item in payload.results {
            results.push(QueryResultItem {
                key: item.key,
                value: general_purpose::STANDARD.decode(item.value)?,
            });
        }

        Ok(QueryResult { results })
    }
}
