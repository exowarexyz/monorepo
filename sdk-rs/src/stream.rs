use crate::{error::Error, Client};
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use http::Request;
use reqwest::header::{HeaderValue, AUTHORIZATION, CONNECTION, UPGRADE};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{
        handshake::client::generate_key,
        protocol::{Message, WebSocketConfig},
    },
    MaybeTlsStream, WebSocketStream,
};
use url::Url;

/// The maximum size of a message in bytes (20MB).
const MAX_MESSAGE_SIZE: usize = 20 * 1024 * 1024;

/// A client for interacting with realtime streams.
#[derive(Clone)]
pub struct StreamClient {
    client: Client,
}

/// A subscription to a realtime stream.
#[derive(Debug)]
pub struct Subscription {
    write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    /// The stream of incoming messages.
    pub read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
}

impl Subscription {
    /// Closes the WebSocket connection.
    pub async fn close(mut self) -> Result<(), Error> {
        self.write.close().await?;
        Ok(())
    }
}

impl StreamClient {
    /// Creates a new `StreamClient`.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Publishes a message to a stream.
    pub async fn publish(&self, name: &str, data: Vec<u8>) -> Result<(), Error> {
        let url = format!("{}/stream/{}", self.client.base_url, name);
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
            .body(data)
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(Error::Http(res.status()));
        }

        Ok(())
    }

    /// Subscribes to a stream.
    ///
    /// This function opens a WebSocket connection and returns a `Subscription` object,
    /// which can be used to read messages from the stream and close the connection.
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
                HeaderValue::from_str(&format!("Bearer {}", self.client.token)).unwrap(),
            )
            .body(())
            .unwrap();

        let (ws_stream, _) = connect_async_with_config(
            request,
            Some(WebSocketConfig {
                max_message_size: Some(MAX_MESSAGE_SIZE),
                max_frame_size: Some(MAX_MESSAGE_SIZE),
                ..Default::default()
            }),
            false,
        )
        .await?;
        let (write, read) = ws_stream.split();

        Ok(Subscription { write, read })
    }
}
