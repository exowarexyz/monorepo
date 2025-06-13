use axum::{
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

pub fn router(path: &Path, consistency_bound: u64) -> Result<Router, rocksdb::Error> {
    let db = Arc::new(DB::open_default(path)?);
    let state = StoreState {
        db,
        consistency_bound,
    };
    let router = Router::new()
        .route("/", get(handlers::query))
        .route("/:key", post(handlers::set).get(handlers::get))
        .with_state(state);
    Ok(router)
}
