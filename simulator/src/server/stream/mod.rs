use crate::server::auth;
use crate::server::stream::handlers::{publish, subscribe};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{body::Bytes, middleware::from_fn_with_state, routing::post, Router};
use dashmap::DashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::broadcast;
use tracing::info;

mod handlers;

/// Application-specific errors for the stream handler.
#[derive(Debug, Error)]
pub(super) enum Error {
    #[error("name too large")]
    NameTooLarge,
    #[error("message too large")]
    MessageTooLarge,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Error::NameTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, self.to_string()),
            Error::MessageTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, self.to_string()),
        };
        (status, message).into_response()
    }
}

/// A type alias for a map of stream names to their broadcast senders.
pub type StreamMap = Arc<DashMap<String, broadcast::Sender<Bytes>>>;

/// The state for the stream routes.
#[derive(Clone)]
pub struct StreamState {
    /// A map of active streams.
    pub streams: StreamMap,
    /// The authentication token.
    pub token: Arc<String>,
    /// A flag to allow unauthenticated access for read-only methods.
    pub allow_public_access: bool,
}

impl auth::Require for StreamState {
    fn token(&self) -> Arc<String> {
        self.token.clone()
    }

    fn allow_public_access(&self) -> bool {
        self.allow_public_access
    }
}

/// Creates a new `Router` for the stream endpoints.
///
/// This function initializes the `StreamState` and sets up the routes for
/// publishing to and subscribing to streams.
pub fn router(token: Arc<String>, allow_public_access: bool) -> Router {
    info!(
        allow_public_access = allow_public_access,
        "initializing stream module"
    );

    let state = StreamState {
        streams: StreamMap::new(DashMap::new()),
        token,
        allow_public_access,
    };

    let router = Router::new()
        .route("/{name}", post(publish).get(subscribe))
        .layer(from_fn_with_state(
            state.clone(),
            auth::middleware::<StreamState>,
        ))
        .with_state(state);

    info!("stream module initialized successfully");
    router
}
