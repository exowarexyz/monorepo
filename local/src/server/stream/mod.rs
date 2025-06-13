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

pub type StreamMap = Arc<DashMap<String, broadcast::Sender<Bytes>>>;

#[derive(Clone)]
pub struct StreamState {
    pub streams: StreamMap,
    pub auth_token: Arc<String>,
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
