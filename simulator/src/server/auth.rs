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
pub trait Require: Clone + Send + Sync + 'static {
    /// Returns the authentication token.
    fn token(&self) -> Arc<String>;
    /// Returns whether public access is allowed.
    fn allow_public_access(&self) -> bool;
}

/// Axum middleware for authentication.
///
/// This middleware checks for a bearer token in the `Authorization` header
/// or a token in the query parameters.
///
/// If the token is valid, the request is passed to the next handler.
/// If `allow_public_access` is true, GET requests are allowed without a token.
/// Otherwise, an `UNAUTHORIZED` status code is returned.
pub async fn middleware<S>(
    State(state): State<S>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode>
where
    S: Require,
{
    let method = request.method().clone();
    let uri = request.uri().clone();

    debug!(
        method = %method,
        uri = %uri,
        "processing authentication for request"
    );

    let headers = request.headers();
    let mut authorized = false;

    // Check for token in Authorization header
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(bearer_token) = auth_str.strip_prefix("Bearer ") {
                if bearer_token == state.token().as_str() {
                    authorized = true;
                    debug!(
                        method = %method,
                        uri = %uri,
                        "authentication successful via header"
                    );
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

    // Check for token in query parameters if not already authorized
    if !authorized {
        if let Some(query) = request.uri().query() {
            if let Some(token_from_query) = url::form_urlencoded::parse(query.as_bytes())
                .find(|(key, _)| key == "token")
                .map(|(_, val)| val.into_owned())
            {
                if token_from_query == state.token().as_str() {
                    authorized = true;
                    debug!(
                        method = %method,
                        uri = %uri,
                        "authentication successful via query parameter"
                    );
                } else {
                    warn!(
                        method = %method,
                        uri = %uri,
                        "authentication failed: invalid query token"
                    );
                }
            }
        }
    }

    if authorized {
        return Ok(next.run(request).await);
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
