use axum::{
    routing::{get, post},
    Router,
};
use rocksdb::DB;
use std::path::Path;
use std::sync::Arc;

mod handlers;

pub fn router(path: &Path) -> Result<Router, rocksdb::Error> {
    let db = Arc::new(DB::open_default(path)?);
    let router = Router::new()
        .route("/", get(handlers::query))
        .route("/:key", post(handlers::set).get(handlers::get))
        .with_state(db);
    Ok(router)
}
