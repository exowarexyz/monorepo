use crate::server::auth;
use axum::{
    http::StatusCode,
    middleware::from_fn_with_state,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose, Engine};
use exoware_sdk_rs::store;
use rocksdb::DB;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tracing::{info, warn};

mod adb;
mod kv;

/// Key prefixes for preventing conflicts between keys in the database.
/// the underlying KV db.
pub const KEY_NAMESPACE_PREFIX: u8 = 0x00;
pub const POS_NAMESPACE_PREFIX: u8 = 0x01;

/// The outer wrapper for any value written to the underlying database.
#[derive(Serialize, Deserialize, Debug)]
struct Entry {
    value: Vec<u8>,
    visible_at: u128,
    updated_at: u64,
}

impl Entry {
    fn new(value: Vec<u8>) -> Self {
        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let now_secs = (now_millis / 1000) as u64;
        Self {
            value,
            visible_at: 0,
            updated_at: now_secs,
        }
    }

    fn deserialize(value: &[u8]) -> Result<Entry, Error> {
        Ok(bincode::deserialize::<Entry>(value)?)
    }

    fn serialize(&self) -> Result<Vec<u8>, Error> {
        Ok(bincode::serialize(self)?)
    }

    fn write(&self, db: &DB, key: &[u8]) -> Result<(), Error> {
        let encoded_value = self.serialize()?;
        db.put(key, encoded_value)?;
        Ok(())
    }

    fn read(db: &DB, key: &[u8]) -> Result<Option<Entry>, Error> {
        match db.get(key)? {
            Some(value) => Ok(Some(Entry::deserialize(&value)?)),
            None => Ok(None),
        }
    }
}

/// Decodes a base64-encoded parameter. Returns `None` if the parameter is not present. Returns
/// [Error] if the parameter could not be decoded.
fn decode_base64_option(
    param: Option<&String>,
    param_name: &str,
) -> Result<Option<Vec<u8>>, Error> {
    param
        .map(|s| general_purpose::STANDARD.decode(s))
        .transpose()
        .map_err(|_| Error::InvalidParameter(format!("Invalid base64 in {param_name} parameter")))
}

/// Decodes a base64-encoded parameter. Returns [Error] if the parameter could not be decoded.
fn decode_base64_param(param: &String, param_name: &str) -> Result<Vec<u8>, Error> {
    general_purpose::STANDARD
        .decode(param)
        .map_err(|_| Error::InvalidParameter(format!("Invalid base64 in {param_name} parameter")))
}

/// Application-specific errors for the store handler.
#[derive(Debug, Error)]
pub(super) enum Error {
    #[error("key too large")]
    KeyTooLarge,
    #[error("value too large")]
    ValueTooLarge,
    #[error("update rate exceeded")]
    UpdateRateExceeded,
    #[error("not found")]
    NotFound,
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
    #[error("invalid body: {0}")]
    InvalidBody(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("missing data: {0}")]
    MissingData(String),
    #[error("database error: {0}")]
    Db(#[from] rocksdb::Error),
    #[error("deserialization error: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Error::KeyTooLarge => {
                warn!(error = %self, "request failed: key too large");
                (StatusCode::PAYLOAD_TOO_LARGE, self.to_string())
            }
            Error::ValueTooLarge => {
                warn!(error = %self, "request failed: value too large");
                (StatusCode::PAYLOAD_TOO_LARGE, self.to_string())
            }
            Error::UpdateRateExceeded => {
                warn!(error = %self, "request failed: update rate exceeded");
                (StatusCode::TOO_MANY_REQUESTS, self.to_string())
            }
            Error::NotFound => {
                warn!(error = %self, "request failed: key not found");
                (StatusCode::NOT_FOUND, self.to_string())
            }
            Error::InvalidParameter(_) => {
                warn!(error = %self, "request failed: invalid parameter");
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            Error::InvalidBody(_) => {
                warn!(error = %self, "request failed: invalid body");
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            Error::MissingData(_) => {
                warn!(error = %self, "request failed: missing data");
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            Error::Db(_) | Error::Bincode(_) => {
                warn!(error = %self, "request failed: internal db error");
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            Error::Internal(_) => {
                warn!(error = %self, "request failed: internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };
        (status, message).into_response()
    }
}

/// The state for the store routes.
#[derive(Clone)]
pub struct State {
    /// The RocksDB database instance.
    pub db: Arc<DB>,
    /// The minimum eventual consistency delay in milliseconds.
    pub consistency_bound_min: u64,
    /// The maximum eventual consistency delay in milliseconds.
    pub consistency_bound_max: u64,
    /// The authentication token.
    pub token: Arc<String>,
    /// A flag to allow unauthenticated access for read-only methods.
    pub allow_public_access: bool,
}

impl auth::Require for State {
    fn token(&self) -> Arc<String> {
        self.token.clone()
    }

    fn allow_public_access(&self) -> bool {
        self.allow_public_access
    }
}

/// Creates a new [Router] for the store endpoints.
///
/// This function initializes the [State] and sets up the routes for
/// setting, getting, and querying key-value pairs.
pub fn router(
    path: &Path,
    consistency_bound_min: u64,
    consistency_bound_max: u64,
    token: Arc<String>,
    allow_public_access: bool,
) -> Result<Router, rocksdb::Error> {
    info!(
        path = %path.display(),
        consistency_bound_min = consistency_bound_min,
        consistency_bound_max = consistency_bound_max,
        allow_public_access = allow_public_access,
        "initializing store module"
    );

    let db = Arc::new(DB::open_default(path)?);
    let state = State {
        db,
        consistency_bound_min,
        consistency_bound_max,
        token,
        allow_public_access,
    };

    // NOTE: All paths here must match the endpoint urls constructed by the sdk clients.
    let router = Router::new()
        .route(
            format!("{}/{}", store::kv::PATH, "{key}").as_str(),
            post(kv::set).get(kv::get),
        )
        .route(store::kv::PATH, get(kv::query))
        .route(store::adb::PATH, post(adb::get).get(adb::get))
        .route(
            format!("{}/{}", store::adb::PATH, "set_key").as_str(),
            post(adb::set_key),
        )
        .route(
            format!("{}/{}", store::adb::PATH, "set_node_digest").as_str(),
            post(adb::set_node_digest),
        )
        .layer(from_fn_with_state(state.clone(), auth::middleware::<State>))
        .with_state(state);

    info!("store module initialized successfully");
    Ok(router)
}
