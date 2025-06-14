use crate::server::store::StoreState;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use exoware_sdk::api;
use rand::Rng;
use rocksdb::{Direction, IteratorMode};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// The maximum size of a key in bytes (512 bytes).
const MAX_KEY_SIZE: usize = 512;
/// The maximum size of a value in bytes (20 MB).
const MAX_VALUE_SIZE: usize = 20 * 1024 * 1024;

/// The structure of a value as it is stored in the database.
#[derive(Serialize, Deserialize, Debug)]
struct StoredValue {
    /// The raw value.
    value: Vec<u8>,
    /// The timestamp (in milliseconds) when the value becomes visible.
    visible_at: u128,
    /// The timestamp (in seconds) when the value was last updated.
    updated_at: u64,
}

/// Application-specific errors for the store handlers.
#[derive(Debug)]
pub enum AppError {
    /// An error from the underlying RocksDB database.
    RocksDb(rocksdb::Error),
    /// An error during serialization or deserialization.
    Bincode(Box<bincode::ErrorKind>),
    /// The requested key was not found.
    NotFound,
    /// The provided key is larger than `MAX_KEY_SIZE`.
    KeyTooLarge,
    /// The provided value is larger than `MAX_VALUE_SIZE`.
    ValueTooLarge,
    /// An attempt was made to update a key more than once per second.
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

/// Query parameters for the `query` endpoint.
#[derive(Deserialize)]
pub struct QueryParams {
    /// The key to start the query from (inclusive).
    start: Option<String>,
    /// The key to end the query at (exclusive).
    end: Option<String>,
    /// The maximum number of results to return.
    limit: Option<usize>,
}

/// Sets a key-value pair in the store.
///
/// This handler enforces key and value size limits. It also implements an eventual
/// consistency model by delaying the visibility of the new value based on the
/// `consistency_bound_min` and `consistency_bound_max` settings. A rate limit
/// of one update per second per key is also enforced.
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

    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let now_secs = (now_millis / 1000) as u64;

    if let Some(existing_value) = state.db.get(&key)? {
        let stored_value: StoredValue = bincode::deserialize(&existing_value)?;
        if now_secs - stored_value.updated_at < 1 {
            return Err(AppError::UpdateRateExceeded);
        }
    }

    let delay_ms = if state.consistency_bound_max > 0 {
        rand::thread_rng().gen_range(state.consistency_bound_min..=state.consistency_bound_max)
    } else {
        0
    };
    let visible_at = now_millis + delay_ms as u128;

    let stored_value = StoredValue {
        value: value.to_vec(),
        visible_at,
        updated_at: now_secs,
    };

    let encoded_value = bincode::serialize(&stored_value)?;
    state.db.put(key, encoded_value)?;
    Ok(StatusCode::OK)
}

/// Retrieves a value from the store by its key.
///
/// This handler respects the eventual consistency model. A value will not be returned
/// until the current time is after its `visible_at` timestamp. If the value is not
/// yet visible or does not exist, a `404 Not Found` error is returned.
pub async fn get(
    State(state): State<StoreState>,
    Path(key): Path<String>,
) -> Result<Json<api::GetResult>, AppError> {
    let db_value = state.db.get(key)?;
    match db_value {
        Some(value) => {
            let stored_value: StoredValue = bincode::deserialize(&value)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            if stored_value.visible_at <= now {
                Ok(Json(api::GetResult {
                    value: general_purpose::STANDARD.encode(&stored_value.value),
                }))
            } else {
                Err(AppError::NotFound)
            }
        }
        None => Err(AppError::NotFound),
    }
}

/// Queries for a range of key-value pairs.
///
/// This handler allows for paginated, range-based queries of the store. It respects
/// the eventual consistency model, only returning values that are currently visible.
pub async fn query(
    State(state): State<StoreState>,
    Query(params): Query<QueryParams>,
) -> Result<Json<api::QueryResult>, AppError> {
    let limit = params.limit.unwrap_or(usize::MAX);

    let mode = params.start.as_ref().map_or(IteratorMode::Start, |key| {
        IteratorMode::From(key.as_bytes(), Direction::Forward)
    });

    let iter = state.db.iterator(mode);

    let mut results = Vec::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();

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

            results.push(api::QueryResultItem {
                key: key_str,
                value: general_purpose::STANDARD.encode(&stored_value.value),
            });
        }
    }

    Ok(Json(api::QueryResult { results }))
}
