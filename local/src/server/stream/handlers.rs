use crate::server::stream::{StreamMap, StreamState};
use axum::{
    body::{Body, Bytes},
    extract::FromRequest,
    extract::{ws::Message, ws::WebSocket, Path, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use futures::stream::StreamExt;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

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

pub async fn subscribe(
    State(state): State<StreamState>,
    Path(name): Path<String>,
    request: Request<Body>,
) -> Response {
    if !state.allow_public_access {
        let headers = request.headers();
        if let Some(auth_header) = headers.get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(bearer_token) = auth_str.strip_prefix("Bearer ") {
                    if bearer_token == state.auth_token.as_str() {
                        // continue
                    } else {
                        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
                    }
                } else {
                    return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
                }
            } else {
                return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
            }
        } else {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }
    }

    match axum::extract::WebSocketUpgrade::from_request(request, &state).await {
        Ok(ws) => ws.on_upgrade(move |socket| handle_socket(socket, state.streams, name)),
        Err(rejection) => rejection.into_response(),
    }
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
