use crate::server::stream::StreamMap;
use axum::{
    body::Bytes,
    extract::{
        ws::{Message, WebSocket},
        Path, State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use futures::stream::StreamExt;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

pub async fn publish(
    State(streams): State<StreamMap>,
    Path(name): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    if let Some(tx) = streams.get(&name) {
        // Channel exists, send the message, ignoring errors if no subscribers are present.
        let _ = tx.send(body);
    } else {
        // Channel does not exist, create a new one and send the message.
        let (tx, _) = broadcast::channel(1024);
        let _ = tx.send(body);
        streams.insert(name, tx);
    }
}

pub async fn subscribe(
    State(streams): State<StreamMap>,
    Path(name): Path<String>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, streams, name))
}

async fn handle_socket(mut socket: WebSocket, streams: StreamMap, name: String) {
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
