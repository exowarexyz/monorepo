use crate::server::auth;
use axum::{
    middleware::from_fn_with_state,
    routing::{get, post},
    Router,
};
use rocksdb::DB;
use std::path::Path;
use std::sync::Arc;

mod handlers;

#[derive(Clone)]
pub struct StoreState {
    pub db: Arc<DB>,
    pub consistency_bound_min: u64,
    pub consistency_bound_max: u64,
    pub auth_token: Arc<String>,
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

pub fn router(
    path: &Path,
    consistency_bound_min: u64,
    consistency_bound_max: u64,
    auth_token: Arc<String>,
    allow_public_access: bool,
) -> Result<Router, rocksdb::Error> {
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

    Ok(router)
}
