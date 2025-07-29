use crate::server::store::{Error, State};
use axum::{
    body::Bytes,
    extract::{Path, Query, State as AxumState},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use base64::{engine::general_purpose, Engine as _};
use exoware_sdk_rs::store::{GetResultPayload, QueryResultItemPayload, QueryResultPayload};
use rand::Rng;
use rocksdb::{Direction, IteratorMode};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

/// The maximum size of a key in bytes (512 bytes).
const MAX_KEY_SIZE: usize = 512;
/// The maximum size of a value in bytes (20MB).
const MAX_VALUE_SIZE: usize = 20 * 1024 * 1024;

/// A value stored in the database.
#[derive(Serialize, Deserialize)]
struct Entry {
    value: Vec<u8>,
    visible_at: u128,
    updated_at: u64,
}

/// Query parameters for the `query` endpoint.
#[derive(Deserialize)]
pub(super) struct QueryParams {
    /// The key to start the query from (inclusive).
    start: Option<String>,
    /// The key to end the query at (exclusive).
    end: Option<String>,
    /// The maximum number of results to return.
    limit: Option<usize>,
}

fn decode_base64_param(param: Option<&String>, param_name: &str) -> Result<Option<Vec<u8>>, Error> {
    param
        .map(|s| general_purpose::STANDARD.decode(s))
        .transpose()
        .map_err(|_| Error::InvalidParameter(format!("Invalid base64 in {param_name} parameter")))
}

/// Sets a key-value pair in the store.
pub(super) async fn set(
    AxumState(state): AxumState<State>,
    Path(key): Path<String>,
    value: Bytes,
) -> Result<impl IntoResponse, Error> {
    // Decode the base64 key
    let decoded_key = general_purpose::STANDARD
        .decode(&key)
        .map_err(|_| Error::InvalidParameter("Invalid base64 in key parameter".to_string()))?;

    debug!(
        operation = "set",
        key = %key,
        value_size = value.len(),
        "processing set request"
    );

    if decoded_key.len() > MAX_KEY_SIZE {
        return Err(Error::KeyTooLarge);
    }
    if value.len() > MAX_VALUE_SIZE {
        return Err(Error::ValueTooLarge);
    }

    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let now_secs = (now_millis / 1000) as u64;

    if let Some(existing_value) = state.db.get(&decoded_key)? {
        let stored_value: Entry = bincode::deserialize(&existing_value)?;
        if now_secs - stored_value.updated_at < 1 {
            return Err(Error::UpdateRateExceeded);
        }
    }

    let delay_ms = if state.consistency_bound_max > 0 {
        rand::thread_rng().gen_range(state.consistency_bound_min..=state.consistency_bound_max)
    } else {
        0
    };
    let visible_at = now_millis + delay_ms as u128;

    let stored_value = Entry {
        value: value.to_vec(),
        visible_at,
        updated_at: now_secs,
    };

    let encoded_value = bincode::serialize(&stored_value)?;
    state.db.put(decoded_key.clone(), encoded_value)?;

    debug!(
        operation = "set",
        key = %key,
        delay_ms = delay_ms,
        "set request completed successfully"
    );

    Ok(StatusCode::OK)
}

/// Retrieves a value from the store by its key.
pub(super) async fn get(
    AxumState(state): AxumState<State>,
    Path(key): Path<String>,
) -> Result<Json<GetResultPayload>, Error> {
    // Decode the base64 key
    let decoded_key = general_purpose::STANDARD
        .decode(&key)
        .map_err(|_| Error::InvalidParameter("Invalid base64 in key parameter".to_string()))?;

    debug!(
        operation = "get",
        key = %key,
        "processing get request"
    );

    let db_value = state.db.get(&decoded_key)?;
    match db_value {
        Some(value) => {
            let stored_value: Entry = bincode::deserialize(&value)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            if stored_value.visible_at <= now {
                debug!(
                    operation = "get",
                    key = %key,
                    value_size = stored_value.value.len(),
                    "get request completed successfully"
                );
                Ok(Json(GetResultPayload {
                    value: general_purpose::STANDARD.encode(&stored_value.value),
                }))
            } else {
                debug!(
                    operation = "get",
                    key = %key,
                    visible_at = stored_value.visible_at,
                    current_time = now,
                    "key not yet visible due to consistency bound"
                );
                Err(Error::NotFound)
            }
        }
        None => {
            debug!(
                operation = "get",
                key = %key,
                "key not found in database"
            );
            Err(Error::NotFound)
        }
    }
}

/// Queries for a range of key-value pairs.
pub(super) async fn query(
    AxumState(state): AxumState<State>,
    Query(params): Query<QueryParams>,
) -> Result<Json<QueryResultPayload>, Error> {
    debug!(
        operation = "query",
        start = ?params.start,
        end = ?params.end,
        limit = ?params.limit,
        "processing query request"
    );

    let limit = params.limit.unwrap_or(usize::MAX);

    let start_bytes = decode_base64_param(params.start.as_ref(), "start")?;
    let end_bytes = decode_base64_param(params.end.as_ref(), "end")?;

    let mode = start_bytes.as_ref().map_or(IteratorMode::Start, |key| {
        IteratorMode::From(key, Direction::Forward)
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
        let stored_value: Entry = bincode::deserialize(&value)?;

        if stored_value.visible_at <= now {
            if let Some(end_key) = &end_bytes {
                if key.as_ref() >= end_key.as_slice() {
                    break;
                }
            }

            results.push(QueryResultItemPayload {
                key: general_purpose::STANDARD.encode(&key),
                value: general_purpose::STANDARD.encode(&stored_value.value),
            });
        } else {
            warn!(
                operation = "query",
                key = %general_purpose::STANDARD.encode(&key),
                visible_at = stored_value.visible_at,
                current_time = now,
                "key not yet visible due to consistency bound"
            );
        }
    }

    debug!(
        operation = "query",
        result_count = results.len(),
        "query request completed successfully"
    );

    Ok(Json(QueryResultPayload { results }))
}
