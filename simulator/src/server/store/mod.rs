use crate::server::auth;
use axum::{
    middleware::from_fn_with_state,
    routing::{get, post},
    Router,
};
use rocksdb::DB;
use std::path::Path;
use std::sync::Arc;
use tracing::info;

mod handlers;

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
    pub auth_token: Arc<String>,
    /// A flag to allow unauthenticated access for read-only methods.
    pub allow_public_access: bool,
}

impl auth::RequireAuth for StoreState {
    fn auth_token(&self) -> Arc<String> {
        self.auth_token.clone()
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
    auth_token: Arc<String>,
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
        auth_token,
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
