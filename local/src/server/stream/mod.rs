use crate::server::stream::handlers::{publish, subscribe};
use axum::{body::Bytes, routing::post, Router};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::broadcast;

mod handlers;

pub type StreamMap = Arc<DashMap<String, broadcast::Sender<Bytes>>>;

pub fn router() -> Router {
    let streams = StreamMap::new(DashMap::new());
    Router::new()
        .route("/:name", post(publish).get(subscribe))
        .with_state(streams)
}
