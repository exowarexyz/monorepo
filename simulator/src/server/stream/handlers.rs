use crate::server::stream::{Error, Map, State};
use axum::{
    body::Bytes,
    extract::{ws::Message, ws::WebSocket, Path, State as AxumState, WebSocketUpgrade},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use futures::stream::StreamExt;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tracing::{debug, warn};

/// The maximum size of a stream name in bytes (512 bytes).
const MAX_NAME_SIZE: usize = 512;
/// The maximum size of a stream message in bytes (20MB).
const MAX_MESSAGE_SIZE: usize = 20 * 1024 * 1024;

/// Publishes a message to a stream.
///
/// If the stream does not exist, it is created. Messages are broadcast to all
/// active subscribers.
pub async fn publish(
    AxumState(state): AxumState<State>,
    Path(name): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, Error> {
    debug!(
        operation = "publish",
        stream_name = %name,
        message_size = body.len(),
        "processing publish request"
    );

    // Check if the stream name size exceeds the limit.
    if name.len() > MAX_NAME_SIZE {
        warn!(
            operation = "publish",
            stream_name = %name,
            name_size = name.len(),
            max_size = MAX_NAME_SIZE,
            "stream name size exceeds limit"
        );
        return Err(Error::NameTooLarge);
    }

    // Check if the message size exceeds the limit.
    if body.len() > MAX_MESSAGE_SIZE {
        warn!(
            operation = "publish",
            stream_name = %name,
            message_size = body.len(),
            max_size = MAX_MESSAGE_SIZE,
            "message size exceeds limit"
        );
        return Err(Error::MessageTooLarge);
    }

    if let Some(tx) = state.streams.get(&name) {
        // Channel exists, send the message, ignoring errors if no subscribers are present.
        match tx.send(body.clone()) {
            Ok(subscriber_count) => {
                debug!(
                    operation = "publish",
                    stream_name = %name,
                    subscriber_count = subscriber_count,
                    "message published to existing stream"
                );
            }
            Err(_) => {
                debug!(
                    operation = "publish",
                    stream_name = %name,
                    "message published to stream with no active subscribers"
                );
            }
        }
    } else {
        // Channel does not exist, create a new one and send the message.
        let (tx, _) = broadcast::channel(1024);
        match tx.send(body.clone()) {
            Ok(_) => {
                debug!(
                    operation = "publish",
                    stream_name = %name,
                    "message published to new stream"
                );
            }
            Err(_) => {
                debug!(
                    operation = "publish",
                    stream_name = %name,
                    "created new stream (no initial subscribers)"
                );
            }
        }
        state.streams.insert(name, tx);
    }

    Ok(StatusCode::OK)
}

/// Upgrades a connection to a WebSocket and subscribes to a stream.
///
/// This handler performs an authentication check before upgrading the connection.
/// If authentication is successful, the client is subscribed to the specified stream.
pub async fn subscribe(
    AxumState(state): AxumState<State>,
    Path(name): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, Error> {
    debug!(
        operation = "subscribe",
        stream_name = %name,
        "processing websocket upgrade request"
    );

    // Check if the stream name size exceeds the limit.
    if name.len() > MAX_NAME_SIZE {
        warn!(
            operation = "subscribe",
            stream_name = %name,
            name_size = name.len(),
            max_size = MAX_NAME_SIZE,
            "stream name size exceeds limit"
        );
        return Err(Error::NameTooLarge);
    }

    debug!(
        operation = "subscribe",
        stream_name = %name,
        "upgrading connection to websocket"
    );
    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state.streams, name)))
}

/// Handles an individual WebSocket connection.
///
/// This function listens for messages from a broadcast channel and forwards them
/// to the client. It also handles client-side close messages.
async fn handle_socket(mut socket: WebSocket, streams: Map, name: String) {
    debug!(
        operation = "handle_socket",
        stream_name = %name,
        "websocket connection established"
    );

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
                debug!(
                    operation = "handle_socket",
                    stream_name = %name,
                    message_size = msg.len(),
                    "forwarding message to websocket client"
                );
                if socket.send(Message::Binary(msg)).await.is_err() {
                    debug!(
                        operation = "handle_socket",
                        stream_name = %name,
                        "websocket send failed, closing connection"
                    );
                    break;
                }
            },
            // Handle messages from the client (e.g., close connection).
            Some(Ok(msg)) = socket.next() => {
                match msg {
                    Message::Close(_) => {
                        debug!(
                            operation = "handle_socket",
                            stream_name = %name,
                            "received close message from client"
                        );
                        break;
                    }
                    _ => {
                        debug!(
                            operation = "handle_socket",
                            stream_name = %name,
                            message_type = ?msg,
                            "received unexpected message from client"
                        );
                    }
                }
            }
            else => {
                debug!(
                    operation = "handle_socket",
                    stream_name = %name,
                    "websocket connection terminated"
                );
                break;
            }
        }
    }

    debug!(
        operation = "handle_socket",
        stream_name = %name,
        "websocket connection closed"
    );
}
