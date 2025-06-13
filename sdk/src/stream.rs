use crate::{error::Error, Client};
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use http::Request;
use reqwest::header::{HeaderValue, AUTHORIZATION, CONNECTION, UPGRADE};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{handshake::client::generate_key, protocol::Message},
    MaybeTlsStream, WebSocketStream,
};
use url::Url;

#[derive(Clone)]
pub struct StreamClient {
    client: Client,
}

#[derive(Debug)]
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
        let parsed_url = Url::parse(&url)?;

        let host = parsed_url
            .host_str()
            .ok_or_else(|| Error::Internal("Invalid URL: missing host".to_string()))?;

        let request = Request::builder()
            .method("GET")
            .uri(&url)
            .version(http::Version::HTTP_11)
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "Upgrade")
            .header("Sec-WebSocket-Key", generate_key())
            .header("Sec-WebSocket-Version", "13")
            .header("Host", host)
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
