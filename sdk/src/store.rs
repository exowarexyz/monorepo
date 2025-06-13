use crate::{error::Error, Client};
use base64::{engine::general_purpose, Engine as _};
use reqwest::header::{HeaderValue, AUTHORIZATION};
use serde::Deserialize;

#[derive(Deserialize)]
struct GetResultPayload {
    value: String,
}

#[derive(Deserialize, Debug)]
pub struct GetResult {
    pub value: Vec<u8>,
}

#[derive(Deserialize)]
pub struct QueryResultItemPayload {
    key: String,
    value: String,
}

#[derive(Deserialize, Debug)]
pub struct QueryResultItem {
    pub key: String,
    pub value: Vec<u8>,
}

#[derive(Deserialize)]
struct QueryResultPayload {
    results: Vec<QueryResultItemPayload>,
}

#[derive(Deserialize, Debug)]
pub struct QueryResult {
    pub results: Vec<QueryResultItem>,
}

#[derive(Clone)]
pub struct StoreClient {
    client: Client,
}

impl StoreClient {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn set(&self, key: &str, value: Vec<u8>) -> Result<(), Error> {
        let url = format!("{}/store/{}", self.client.base_url, key);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.client.auth_token)).unwrap(),
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

    pub async fn get(&self, key: &str) -> Result<Option<GetResult>, Error> {
        let url = format!("{}/store/{}", self.client.base_url, key);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.client.auth_token)).unwrap(),
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
            HeaderValue::from_str(&format!("Bearer {}", self.client.auth_token)).unwrap(),
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
