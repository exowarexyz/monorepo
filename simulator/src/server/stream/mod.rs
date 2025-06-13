use crate::server::stream::handlers::{publish, subscribe};
use axum::{
    body::Bytes,
    middleware::from_fn_with_state,
    routing::{get, post},
    Router,
};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::server::auth;

mod handlers;

/// A type alias for a map of stream names to their broadcast senders.
pub type StreamMap = Arc<DashMap<String, broadcast::Sender<Bytes>>>;

/// The state for the stream routes.
#[derive(Clone)]
pub struct StreamState {
    /// A map of active streams.
    pub streams: StreamMap,
    /// The authentication token.
    pub auth_token: Arc<String>,
    /// A flag to allow unauthenticated access for read-only methods.
    pub allow_public_access: bool,
}

impl auth::RequireAuth for StreamState {
    fn auth_token(&self) -> Arc<String> {
        self.auth_token.clone()
    }

    fn allow_public_access(&self) -> bool {
        self.allow_public_access
    }
}

/// Creates a new `Router` for the stream endpoints.
///
/// This function initializes the `StreamState` and sets up the routes for
/// publishing to and subscribing to streams.
pub fn router(auth_token: Arc<String>, allow_public_access: bool) -> Router {
    let state = StreamState {
        streams: StreamMap::new(DashMap::new()),
        auth_token,
        allow_public_access,
    };

    let post_routes = Router::new()
        .route("/{name}", post(publish))
        .layer(from_fn_with_state(
            state.clone(),
            auth::middleware::<StreamState>,
        ));

    let get_routes = Router::new().route("/{name}", get(subscribe));

    post_routes.merge(get_routes).with_state(state)
}
