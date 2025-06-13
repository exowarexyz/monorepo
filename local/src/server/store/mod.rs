use crate::server::auth;
use axum::{
    middleware::from_fn_with_state,
    routing::{get, post},
    Router,
};
use rocksdb::DB;
use std::path::Path;
use std::sync::Arc;

mod handlers;

#[derive(Clone)]
pub struct StoreState {
    pub db: Arc<DB>,
    pub consistency_bound: u64,
}

pub fn router(
    path: &Path,
    consistency_bound: u64,
    auth_token: Arc<String>,
    allow_public_access: bool,
) -> Result<Router, rocksdb::Error> {
    let db = Arc::new(DB::open_default(path)?);
    let state = StoreState {
        db,
        consistency_bound,
    };

    let post_routes = Router::new()
        .route("/:key", post(handlers::set))
        .layer(from_fn_with_state(auth_token.clone(), auth::middleware));

    let get_routes = Router::new()
        .route("/:key", get(handlers::get))
        .route("/", get(handlers::query));

    let router = if allow_public_access {
        post_routes.merge(get_routes)
    } else {
        post_routes.merge(get_routes.layer(from_fn_with_state(auth_token, auth::middleware)))
    };

    Ok(router.with_state(state))
}
