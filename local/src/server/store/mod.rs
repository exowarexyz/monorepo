use axum::{
    routing::{get, post},
    Router,
};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

mod handlers;

pub fn router() -> Router {
    let db = Arc::new(RwLock::new(BTreeMap::new()));
    Router::new()
        .route("/", get(handlers::query))
        .route("/:key", post(handlers::set).get(handlers::get))
        .with_state(db)
}
