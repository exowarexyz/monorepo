use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

pub async fn middleware(
    State(token): State<Arc<String>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = request.headers();
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(bearer_token) = auth_str.strip_prefix("Bearer ") {
                if bearer_token == token.as_str() {
                    return Ok(next.run(request).await);
                }
            }
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}
