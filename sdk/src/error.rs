use reqwest::StatusCode;
use thiserror::Error;
use tokio_tungstenite::tungstenite;

#[derive(Error, Debug)]
pub enum Error {
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("url parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("websocket error: {0}")]
    WebSocket(#[from] tungstenite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("http error: {0}")]
    Http(StatusCode),
    #[error("internal error: {0}")]
    Internal(String),
}
