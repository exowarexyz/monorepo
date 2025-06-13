use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use rocksdb::{Direction, IteratorMode, DB};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub type Store = Arc<DB>;

#[derive(Debug)]
pub enum AppError {
    RocksDb(rocksdb::Error),
    NotFound,
}

impl From<rocksdb::Error> for AppError {
    fn from(err: rocksdb::Error) -> Self {
        AppError::RocksDb(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::RocksDb(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal server error: {}", err),
            ),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not Found".to_string()),
        };

        (status, error_message).into_response()
    }
}

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
    State(db): State<Store>,
    Path(key): Path<String>,
    value: Bytes,
) -> Result<impl IntoResponse, AppError> {
    db.put(key, value)?;
    Ok(StatusCode::OK)
}

pub async fn get(
    State(db): State<Store>,
    Path(key): Path<String>,
) -> Result<Json<GetResult>, AppError> {
    match db.get(key)? {
        Some(value) => Ok(Json(GetResult {
            value: general_purpose::STANDARD.encode(value),
        })),
        None => Err(AppError::NotFound),
    }
}

pub async fn query(
    State(db): State<Store>,
    Query(params): Query<QueryParams>,
) -> Result<Json<QueryResults>, AppError> {
    let limit = params.limit.unwrap_or(usize::MAX);

    let mode = params.start.as_ref().map_or(IteratorMode::Start, |key| {
        IteratorMode::From(key.as_bytes(), Direction::Forward)
    });

    let iter = db.iterator(mode);

    let mut results = Vec::new();
    for item in iter.take(limit) {
        let (key, value) = item?;
        let key_str = String::from_utf8(key.into()).unwrap();

        if let Some(end_key) = &params.end {
            if &key_str >= end_key {
                break;
            }
        }

        results.push(QueryResultItem {
            key: key_str,
            value: general_purpose::STANDARD.encode(value),
        });
    }

    Ok(Json(QueryResults { results }))
}
