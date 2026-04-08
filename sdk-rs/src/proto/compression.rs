//! Wire compression for the store API.
//!
//! ## Registry
//!
//! Servers register **gzip** and **zstd** via [`connect_compression_registry`] (same as
//! [`connectrpc::compression::CompressionRegistry::default`]) so callers without zstd
//! (including typical browsers) can still negotiate gzip.
//!
//! ## Rust client transport
//!
//! HTTP transport that sets `Accept-Encoding: zstd, gzip` on every outbound request.
//!
//! [`connectrpc::compression::CompressionRegistry::default`] builds the header value in sorted
//! order (`gzip, zstd`), so servers negotiate **gzip** first. Replacing the header after
//! connectrpc builds the request lets clients **prefer zstd** while still advertising gzip.
//!
//! **Request bodies** (client -> server) use a single codec from connectrpc `compress_requests`.
//!
//! ## Edge upstream affinity (cookie)
//!
//! Deployments behind a load balancer or proxy may use HTTP sticky sessions: the edge sets
//! `Set-Cookie` for [`EXOWARE_AFFINITY_COOKIE`] so each client session sticks to one backend
//! (cache locality). This repo's Docker/Envoy example uses the stateful session filter for that.
//! [`PreferZstdHttpClient`] stores `Set-Cookie` from responses and sends `Cookie` on subsequent RPCs.

use std::sync::Arc;
use std::sync::Mutex;

use connectrpc::client::{BoxFuture, ClientBody, ClientTransport, HttpClient};
use connectrpc::compression::CompressionRegistry;
use connectrpc::ConnectError;
use http::header::{ACCEPT_ENCODING, COOKIE, SET_COOKIE};
use http::{Request, Response};

/// gzip + zstd - used for [`connectrpc::ConnectRpcService::with_compression`] and
/// [`connectrpc::client::ClientConfig::compression`].
#[must_use]
pub fn connect_compression_registry() -> CompressionRegistry {
    CompressionRegistry::default()
}

/// Sticky-session cookie name; must match whatever the edge emits in `Set-Cookie`.
pub const EXOWARE_AFFINITY_COOKIE: &str = "exoware_affinity_cookie";

/// Wraps [`HttpClient`] so every RPC sends `Accept-Encoding: zstd, gzip` (see module docs).
///
/// Also persists **HTTP sticky-session** behavior for [`EXOWARE_AFFINITY_COOKIE`]: when responses
/// include `Set-Cookie: exoware_affinity_cookie=...`, the value is stored and sent on later requests as
/// `Cookie: exoware_affinity_cookie=...` so the same client handle stays pinned to one upstream.
#[derive(Clone, Debug)]
pub struct PreferZstdHttpClient {
    inner: HttpClient,
    /// `Cookie` header line body (`name=value`) for [`EXOWARE_AFFINITY_COOKIE`], no `Cookie:` prefix.
    sticky_cookie: Arc<Mutex<Option<String>>>,
}

impl PreferZstdHttpClient {
    pub fn plaintext() -> Self {
        Self {
            inner: HttpClient::plaintext(),
            sticky_cookie: Arc::new(Mutex::new(None)),
        }
    }
}

impl ClientTransport for PreferZstdHttpClient {
    type ResponseBody = hyper::body::Incoming;
    type Error = ConnectError;

    fn send(
        &self,
        mut request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        if let Ok(guard) = self.sticky_cookie.lock() {
            if let Some(ref pair) = *guard {
                if let Ok(hv) = http::HeaderValue::from_str(pair) {
                    request.headers_mut().insert(COOKIE, hv);
                }
            }
        }
        request.headers_mut().insert(
            ACCEPT_ENCODING,
            http::HeaderValue::from_static("zstd, gzip"),
        );
        let inner = self.inner.clone();
        let sticky_cookie = Arc::clone(&self.sticky_cookie);
        Box::pin(async move {
            let response = inner.send(request).await?;
            let (parts, body) = response.into_parts();
            if let Ok(mut g) = sticky_cookie.lock() {
                for val in parts.headers.get_all(SET_COOKIE) {
                    if let Ok(s) = val.to_str() {
                        if let Some(pair) = parse_sticky_cookie_pair(s, EXOWARE_AFFINITY_COOKIE)
                        {
                            *g = Some(pair);
                            break;
                        }
                    }
                }
            }
            Ok(Response::from_parts(parts, body))
        })
    }
}

/// From one `Set-Cookie` header value, extract `name=value` for the affinity cookie.
fn parse_sticky_cookie_pair(set_cookie: &str, name: &str) -> Option<String> {
    let first = set_cookie.split(';').next()?.trim();
    let rest = first.strip_prefix(name)?.strip_prefix('=')?;
    let val = rest.trim().trim_matches('"');
    if val.is_empty() {
        return None;
    }
    Some(format!("{name}={val}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sticky_cookie_pair_handles_quoted_value() {
        let s = r#"exoware_affinity_cookie="Cg4xMjcuMC4wLjE6ODA4MQ=="; Path=/; HttpOnly"#;
        assert_eq!(
            parse_sticky_cookie_pair(s, EXOWARE_AFFINITY_COOKIE),
            Some("exoware_affinity_cookie=Cg4xMjcuMC4wLjE6ODA4MQ==".to_string())
        );
    }
}
