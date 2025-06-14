use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tracing::{debug, warn};

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
    let method = request.method().clone();
    let uri = request.uri().clone();

    debug!(
        method = %method,
        uri = %uri,
        "processing authentication for request"
    );

    let headers = request.headers();
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(bearer_token) = auth_str.strip_prefix("Bearer ") {
                if bearer_token == state.auth_token().as_str() {
                    debug!(
                        method = %method,
                        uri = %uri,
                        "authentication successful"
                    );
                    return Ok(next.run(request).await);
                } else {
                    warn!(
                        method = %method,
                        uri = %uri,
                        "authentication failed: invalid token"
                    );
                }
            } else {
                warn!(
                    method = %method,
                    uri = %uri,
                    "authentication failed: malformed authorization header"
                );
            }
        } else {
            warn!(
                method = %method,
                uri = %uri,
                "authentication failed: invalid authorization header encoding"
            );
        }
    }

    if state.allow_public_access() && request.method() == "GET" {
        debug!(
            method = %method,
            uri = %uri,
            "allowing public access for GET request"
        );
        return Ok(next.run(request).await);
    }

    warn!(
        method = %method,
        uri = %uri,
        "authentication failed: no valid credentials provided"
    );

    Err(StatusCode::UNAUTHORIZED)
}
