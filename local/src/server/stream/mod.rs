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

pub fn router(auth_token: Arc<String>, allow_public_access: bool) -> Router {
    let streams = StreamMap::new(DashMap::new());

    let post_routes = Router::new()
        .route("/:name", post(publish))
        .layer(from_fn_with_state(auth_token.clone(), auth::middleware));

    let get_routes = Router::new().route("/:name", get(subscribe));

    let router = if allow_public_access {
        post_routes.merge(get_routes)
    } else {
        post_routes.merge(get_routes.layer(from_fn_with_state(auth_token, auth::middleware)))
    };

    router.with_state(streams)
}
