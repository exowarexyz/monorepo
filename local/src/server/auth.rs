use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

pub trait RequireAuth: Clone + Send + Sync + 'static {
    fn auth_token(&self) -> Arc<String>;
    fn allow_public_access(&self) -> bool;
}

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
