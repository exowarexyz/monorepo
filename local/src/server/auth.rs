use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

/// A trait for states that require authentication.
///
/// This trait provides access to the authentication token and the public access flag,
/// allowing the authentication middleware to be generic over different states.
pub trait RequireAuth: Clone + Send + Sync + 'static {
    /// Returns the authentication token.
    fn auth_token(&self) -> Arc<String>;
    /// Returns whether public access is allowed.
    fn allow_public_access(&self) -> bool;
}

/// Axum middleware for authentication.
///
/// This middleware checks for a bearer token in the `Authorization` header.
/// If the token is valid, the request is passed to the next handler.
/// If `allow_public_access` is true, GET requests are allowed without a token.
/// Otherwise, an `UNAUTHORIZED` status code is returned.
pub async fn middleware<S>(
    State(state): State<S>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode>
where
    S: RequireAuth,
{
    let headers = request.headers();
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(bearer_token) = auth_str.strip_prefix("Bearer ") {
                if bearer_token == state.auth_token().as_str() {
                    return Ok(next.run(request).await);
                }
            }
        }
    }

    if state.allow_public_access() && request.method() == "GET" {
        return Ok(next.run(request).await);
    }

    Err(StatusCode::UNAUTHORIZED)
}
