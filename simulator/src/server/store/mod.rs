use crate::server::auth;
use axum::{
    http::StatusCode,
    middleware::from_fn_with_state,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use rocksdb::DB;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tracing::{info, warn};

mod handlers;

/// Application-specific errors for the store handlers.
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
            Error::Db(_) | Error::Bincode(_) => {
                warn!(error = %self, "request failed: internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };
        (status, message).into_response()
    }
}

/// The state for the store routes.
#[derive(Clone)]
pub struct StoreState {
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

impl auth::RequireAuth for StoreState {
    fn token(&self) -> Arc<String> {
        self.token.clone()
    }

    fn allow_public_access(&self) -> bool {
        self.allow_public_access
    }
}

/// Creates a new `Router` for the store endpoints.
///
/// This function initializes the `StoreState` and sets up the routes for
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
    let state = StoreState {
        db,
        consistency_bound_min,
        consistency_bound_max,
        token,
        allow_public_access,
    };

    let router = Router::new()
        .route("/{key}", post(handlers::set).get(handlers::get))
        .route("/", get(handlers::query))
        .layer(from_fn_with_state(
            state.clone(),
            auth::middleware::<StoreState>,
        ))
        .with_state(state);

    info!("store module initialized successfully");
    Ok(router)
}
