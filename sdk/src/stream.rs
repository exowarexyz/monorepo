use crate::{error::Error, Client};
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use http::Request;
use reqwest::header::{HeaderValue, AUTHORIZATION};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream,
};

#[derive(Clone)]
pub struct StreamClient {
    client: Client,
}

pub struct Subscription {
    write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    pub read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
}

impl Subscription {
    pub async fn close(mut self) -> Result<(), Error> {
        self.write.close().await?;
        Ok(())
    }
}

impl StreamClient {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn publish(&self, name: &str, data: Vec<u8>) -> Result<(), Error> {
        let url = format!("{}/stream/{}", self.client.base_url, name);
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
            .body(data)
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(Error::Http(res.status()));
        }

        Ok(())
    }

    pub async fn subscribe(&self, name: &str) -> Result<Subscription, Error> {
        let url = format!("{}/stream/{}", self.client.base_url, name).replace("http", "ws");

        let request = Request::builder()
            .uri(&url)
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", self.client.auth_token)).unwrap(),
            )
            .body(())
            .unwrap();

        let (ws_stream, _) = connect_async(request).await?;
        let (write, read) = ws_stream.split();

        Ok(Subscription { write, read })
    }
}
