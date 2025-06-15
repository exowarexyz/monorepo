use reqwest::StatusCode;
use thiserror::Error;
use tokio_tungstenite::tungstenite;

/// Errors that can occur when interacting with the Exoware API.
#[derive(Error, Debug)]
pub enum Error {
    /// An error from the underlying `reqwest` HTTP client.
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    /// An error parsing a URL.
    #[error("url parse error: {0}")]
    Url(#[from] url::ParseError),
    /// An error from the underlying WebSocket client.
    #[error("websocket error: {0}")]
    WebSocket(#[from] tungstenite::Error),
    /// An error serializing or deserializing JSON.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// An error decoding a base64 string.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    /// An HTTP error response from the server.
    #[error("http error: {0}")]
    Http(StatusCode),
    /// An internal SDK error.
    #[error("internal error: {0}")]
    Internal(String),
}
