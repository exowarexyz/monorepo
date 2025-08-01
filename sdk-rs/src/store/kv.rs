use crate::{Client as SdkClient, Error};
use base64::{engine::general_purpose, Engine};
use http::HeaderMap;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

pub const PATH: &str = "/kv";

pub struct Client {
    client: SdkClient,
    base_url: String,
}

/// The JSON payload for a kv `get` operation response.
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct GetResultPayload {
    #[serde_as(as = "Base64")]
    pub value: Vec<u8>,
}

/// The JSON payload for a `query` operation response.
#[derive(Serialize, Deserialize, Debug)]
pub struct QueryResultPayload {
    pub results: Vec<QueryResultItemPayload>,
}

/// An item in the result of a `query` operation.
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct QueryResultItemPayload {
    /// The raw (kv store) key of the item.
    #[serde_as(as = "Base64")]
    pub key: Vec<u8>,
    /// The value of the item.
    #[serde_as(as = "Base64")]
    pub value: Vec<u8>,
}

impl Client {
    pub fn new(client: SdkClient, parent_url: &str) -> Self {
        Self {
            client,
            base_url: format!("{parent_url}{PATH}"),
        }
    }

    /// Retrieves a value from the kv store by its key.
    ///
    /// If the key does not exist, `Ok(None)` is returned.
    pub async fn get(&self, key: &[u8]) -> Result<Option<GetResultPayload>, Error> {
        let (url, headers) = self.get_request(key, HeaderMap::new());

        let res = self.client.get(url, headers).await?;

        Self::get_handle_response(res).await
    }

    /// Sets a key-value pair in the kv store.
    pub async fn set(&self, key: &[u8], value: Vec<u8>) -> Result<(), Error> {
        let (url, headers) = self.set_request(key, HeaderMap::new());

        let res = self.client.post(url, headers, value).await?;

        Self::set_handle_response(res).await
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
        let (url, headers) = self.query_request(start, end, limit, HeaderMap::new());

        let res = self.client.get(url, headers).await?;

        Self::query_handle_response(res).await
    }

    fn get_request(&self, key: &[u8], mut headers: HeaderMap) -> (String, HeaderMap) {
        let key_b64 = general_purpose::STANDARD.encode(key);
        let url = format!("{}/{}", self.base_url, key_b64);

        self.client.add_auth_header(&mut headers);

        (url, headers)
    }

    async fn get_handle_response(res: Response) -> Result<Option<GetResultPayload>, Error> {
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !res.status().is_success() {
            return Err(Error::Http(res.status()));
        }

        Ok(Some(res.json().await?))
    }

    pub fn set_request(&self, key: &[u8], mut headers: HeaderMap) -> (String, HeaderMap) {
        let key_b64 = general_purpose::STANDARD.encode(key);
        let url = format!("{}/{}", self.base_url, key_b64);

        self.client.add_auth_header(&mut headers);

        (url, headers)
    }

    pub async fn set_handle_response(res: Response) -> Result<(), Error> {
        if !res.status().is_success() {
            return Err(Error::Http(res.status()));
        }

        Ok(())
    }

    fn query_request(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: Option<usize>,
        mut headers: HeaderMap,
    ) -> (String, HeaderMap) {
        let mut url = format!("{}?", self.base_url);
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

        self.client.add_auth_header(&mut headers);

        (url, headers)
    }

    async fn query_handle_response(res: Response) -> Result<QueryResultPayload, Error> {
        if !res.status().is_success() {
            return Err(Error::Http(res.status()));
        }

        let payload: QueryResultPayload = res.json().await?;

        Ok(payload)
    }
}
