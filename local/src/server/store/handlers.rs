use crate::server::store::StoreState;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use rocksdb::{Direction, IteratorMode};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_KEY_SIZE: usize = 512;
const MAX_VALUE_SIZE: usize = 20 * 1024 * 1024;

#[derive(Serialize, Deserialize, Debug)]
struct StoredValue {
    value: Vec<u8>,
    visible_at: u64,
    updated_at: u64,
}

#[derive(Debug)]
pub enum AppError {
    RocksDb(rocksdb::Error),
    Bincode(Box<bincode::ErrorKind>),
    NotFound,
    KeyTooLarge,
    ValueTooLarge,
    UpdateRateExceeded,
}

impl From<rocksdb::Error> for AppError {
    fn from(err: rocksdb::Error) -> Self {
        AppError::RocksDb(err)
    }
}

impl From<Box<bincode::ErrorKind>> for AppError {
    fn from(err: Box<bincode::ErrorKind>) -> Self {
        AppError::Bincode(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::RocksDb(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal server error: {}", err),
            ),
            AppError::Bincode(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal server error: {}", err),
            ),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not Found".to_string()),
            AppError::KeyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("Key size cannot exceed {} bytes", MAX_KEY_SIZE),
            ),
            AppError::ValueTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("Value size cannot exceed {} bytes", MAX_VALUE_SIZE),
            ),
            AppError::UpdateRateExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "Key can only be updated once per second".to_string(),
            ),
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
    State(state): State<StoreState>,
    Path(key): Path<String>,
    value: Bytes,
) -> Result<impl IntoResponse, AppError> {
    if key.len() > MAX_KEY_SIZE {
        return Err(AppError::KeyTooLarge);
    }
    if value.len() > MAX_VALUE_SIZE {
        return Err(AppError::ValueTooLarge);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if let Some(existing_value) = state.db.get(&key)? {
        let stored_value: StoredValue = bincode::deserialize(&existing_value)?;
        if now - stored_value.updated_at < 1 {
            return Err(AppError::UpdateRateExceeded);
        }
    }

    let delay_ms = rand::thread_rng().gen_range(0..=state.consistency_bound);
    let visible_at = now + (delay_ms / 1000);

    let stored_value = StoredValue {
        value: value.to_vec(),
        visible_at,
        updated_at: now,
    };

    let encoded_value = bincode::serialize(&stored_value)?;
    state.db.put(key, encoded_value)?;
    Ok(StatusCode::OK)
}

pub async fn get(
    State(state): State<StoreState>,
    Path(key): Path<String>,
) -> Result<Json<GetResult>, AppError> {
    let db_value = state.db.get(key)?;
    match db_value {
        Some(value) => {
            let stored_value: StoredValue = bincode::deserialize(&value)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if stored_value.visible_at <= now {
                Ok(Json(GetResult {
                    value: general_purpose::STANDARD.encode(&stored_value.value),
                }))
            } else {
                Err(AppError::NotFound)
            }
        }
        None => Err(AppError::NotFound),
    }
}

pub async fn query(
    State(state): State<StoreState>,
    Query(params): Query<QueryParams>,
) -> Result<Json<QueryResults>, AppError> {
    let limit = params.limit.unwrap_or(usize::MAX);

    let mode = params.start.as_ref().map_or(IteratorMode::Start, |key| {
        IteratorMode::From(key.as_bytes(), Direction::Forward)
    });

    let iter = state.db.iterator(mode);

    let mut results = Vec::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    for item in iter {
        if results.len() >= limit {
            break;
        }

        let (key, value) = item?;
        let stored_value: StoredValue = bincode::deserialize(&value)?;

        if stored_value.visible_at <= now {
            let key_str = String::from_utf8(key.into()).unwrap();

            if let Some(end_key) = &params.end {
                if &key_str >= end_key {
                    break;
                }
            }

            results.push(QueryResultItem {
                key: key_str,
                value: general_purpose::STANDARD.encode(&stored_value.value),
            });
        }
    }

    Ok(Json(QueryResults { results }))
}
