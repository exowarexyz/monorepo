use crate::server::stream::{StreamMap, StreamState};
use axum::{
    body::Bytes,
    extract::{ws::Message, ws::WebSocket, Path, Query, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures::stream::StreamExt;
use serde::Deserialize;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

/// Query parameters for authentication.
#[derive(Deserialize)]
pub(super) struct AuthParams {
    auth_token: Option<String>,
}

/// Publishes a message to a stream.
///
/// If the stream does not exist, it is created. Messages are broadcast to all
/// active subscribers.
pub async fn publish(
    State(state): State<StreamState>,
    Path(name): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    if let Some(tx) = state.streams.get(&name) {
        // Channel exists, send the message, ignoring errors if no subscribers are present.
        let _ = tx.send(body);
    } else {
        // Channel does not exist, create a new one and send the message.
        let (tx, _) = broadcast::channel(1024);
        let _ = tx.send(body);
        state.streams.insert(name, tx);
    }
}

/// Upgrades a connection to a WebSocket and subscribes to a stream.
///
/// This handler performs an authentication check before upgrading the connection.
/// If authentication is successful, the client is subscribed to the specified stream.
pub async fn subscribe(
    State(state): State<StreamState>,
    Path(name): Path<String>,
    Query(params): Query<AuthParams>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
) -> Response {
    let mut authorized = state.allow_public_access;

    if !authorized {
        if let Some(auth_header) = headers.get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(bearer_token) = auth_str.strip_prefix("Bearer ") {
                    if bearer_token == state.auth_token.as_str() {
                        authorized = true;
                    }
                }
            }
        } else if let Some(token) = params.auth_token {
            if token == *state.auth_token.as_str() {
                authorized = true;
            }
        }
    }

    if authorized {
        ws.on_upgrade(move |socket| handle_socket(socket, state.streams, name))
    } else {
        (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
    }
}

/// Handles an individual WebSocket connection.
///
/// This function listens for messages from a broadcast channel and forwards them
/// to the client. It also handles client-side close messages.
async fn handle_socket(mut socket: WebSocket, streams: StreamMap, name: String) {
    // Subscribe to the broadcast channel for the stream. If the channel does
    // not exist, it is created.
    let rx = {
        let tx = streams
            .entry(name.clone())
            .or_insert_with(|| broadcast::channel(1024).0)
            .clone();
        tx.subscribe()
    };

    let mut rx_stream = BroadcastStream::new(rx);

    loop {
        tokio::select! {
            // Forward messages from the broadcast channel to the WebSocket client.
            Some(Ok(msg)) = rx_stream.next() => {
                if socket.send(Message::Binary(msg)).await.is_err() {
                    break;
                }
            },
            // Handle messages from the client (e.g., close connection).
            Some(Ok(msg)) = socket.next() => {
                if let Message::Close(_) = msg {
                    break;
                }
            }
            else => { break; }
        }
    }
}
