use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::{Arc, RwLock};

pub type Store = Arc<RwLock<BTreeMap<String, Bytes>>>;

#[derive(Deserialize)]
pub struct QueryParams {
    start: Option<String>,
    end: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
pub struct GetResult {
    value: String,
}

#[derive(Serialize)]
pub struct QueryResultItem {
    key: String,
    value: String,
}

#[derive(Serialize)]
pub struct QueryResults {
    results: Vec<QueryResultItem>,
}

pub async fn set(
    State(store): State<Store>,
    Path(key): Path<String>,
    value: Bytes,
) -> impl IntoResponse {
    store.write().unwrap().insert(key, value);
    (StatusCode::OK, "OK")
}

pub async fn get(
    State(store): State<Store>,
    Path(key): Path<String>,
) -> Result<Json<GetResult>, StatusCode> {
    let store = store.read().unwrap();
    match store.get(&key) {
        Some(value) => Ok(Json(GetResult {
            value: general_purpose::STANDARD.encode(value),
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

pub async fn query(
    State(store): State<Store>,
    Query(params): Query<QueryParams>,
) -> Result<Json<QueryResults>, StatusCode> {
    let store = store.read().unwrap();
    let limit = params.limit.unwrap_or(usize::MAX);

    let start_bound = params
        .start
        .as_ref()
        .map_or(Bound::Unbounded, |k| Bound::Included(k.clone()));

    let end_bound = params
        .end
        .as_ref()
        .map_or(Bound::Unbounded, |k| Bound::Excluded(k.clone()));

    let results = store
        .range((start_bound, end_bound))
        .take(limit)
        .map(|(k, v)| QueryResultItem {
            key: k.clone(),
            value: general_purpose::STANDARD.encode(v),
        })
        .collect();

    Ok(Json(QueryResults { results }))
}
