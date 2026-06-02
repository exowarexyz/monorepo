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
//! Deployments behind a load balancer or proxy may use HTTP sticky sessions: the edge sets a
//! `Set-Cookie` so each client session sticks to one backend (cache locality). The cookie name is
//! the edge's concern, not ours -- [`PreferZstdHttpClient`] keeps a small per-host cookie jar: it
//! stores every `Set-Cookie` from responses and replays them as `Cookie`, but only to the host
//! that set them. Host scoping means a single client targeting several upstreams (e.g. per-service
//! load balancers, each naming its cookie `AWSALB`) never sends one upstream's affinity token to
//! another.

use std::collections::BTreeMap;
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

/// Wraps [`HttpClient`] so every RPC sends `Accept-Encoding: zstd, gzip` (see module docs).
///
/// Also persists **HTTP sticky sessions** generically: it stores every `Set-Cookie` the edge
/// returns and replays them as `Cookie` on later requests to the same host, so the same client
/// handle stays pinned to one upstream -- regardless of the edge's cookie name, and without
/// leaking one host's cookie to another.
#[derive(Clone, Debug)]
pub struct PreferZstdHttpClient {
    inner: HttpClient,
    /// Per-host cookie jar: request authority (host[:port]) -> that host's cookies (name -> value).
    /// Host scoping keeps one upstream's sticky cookie from being replayed to a different host.
    cookies: Arc<Mutex<BTreeMap<String, BTreeMap<String, String>>>>,
}

impl PreferZstdHttpClient {
    pub fn plaintext() -> Self {
        Self {
            inner: HttpClient::plaintext(),
            cookies: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Render the `Cookie` header value for `authority` from the jar, or `None` if it holds none.
    fn cookie_header_for(&self, authority: &str) -> Option<String> {
        let jar = self.cookies.lock().ok()?;
        let origin = jar.get(authority)?;
        if origin.is_empty() {
            return None;
        }
        Some(
            origin
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    /// Store every `Set-Cookie` in `headers` under `authority`, so it is only replayed to that host.
    fn store_set_cookies(&self, authority: &str, headers: &http::HeaderMap) {
        let Ok(mut jar) = self.cookies.lock() else {
            return;
        };
        for val in headers.get_all(SET_COOKIE) {
            if let Ok(s) = val.to_str() {
                if let Some((name, value)) = parse_set_cookie(s) {
                    jar.entry(authority.to_string()).or_default().insert(name, value);
                }
            }
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
        // Scope cookies to the target host so one upstream's sticky cookie is never replayed to
        // another. Captured before `request` is moved into the future.
        let authority = request.uri().authority().map(|a| a.as_str().to_string());

        if let Some(ref authority) = authority {
            if let Some(header) = self.cookie_header_for(authority) {
                if let Ok(hv) = http::HeaderValue::from_str(&header) {
                    request.headers_mut().insert(COOKIE, hv);
                }
            }
        }

        request.headers_mut().insert(
            ACCEPT_ENCODING,
            http::HeaderValue::from_static("zstd, gzip"),
        );

        let this = self.clone();
        Box::pin(async move {
            let response = this.inner.send(request).await?;
            let (parts, body) = response.into_parts();
            if let Some(authority) = authority {
                this.store_set_cookies(&authority, &parts.headers);
            }
            Ok(Response::from_parts(parts, body))
        })
    }
}

/// From one `Set-Cookie` header value, extract the `(name, value)` pair, ignoring attributes
/// (`Path`, `Domain`, `Expires`, ...). The cookie is always the first `;`-separated segment.
fn parse_set_cookie(set_cookie: &str) -> Option<(String, String)> {
    let first = set_cookie.split(';').next()?.trim();
    let (name, value) = first.split_once('=')?;
    let name = name.trim();
    let value = value.trim().trim_matches('"');
    if name.is_empty() || value.is_empty() {
        return None;
    }
    Some((name.to_string(), value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_cookie_headers(values: &[&str]) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        for v in values {
            headers.append(SET_COOKIE, v.parse().unwrap());
        }
        headers
    }

    #[test]
    fn parse_set_cookie_extracts_name_value_ignoring_attrs() {
        // Quoted value with attributes.
        assert_eq!(
            parse_set_cookie(r#"affinity="Zm9vYmFy"; Path=/; HttpOnly"#),
            Some(("affinity".to_string(), "Zm9vYmFy".to_string()))
        );
        // A typical load-balancer stickiness cookie (e.g. AWS ALB).
        assert_eq!(
            parse_set_cookie("AWSALB=abc.def.ghi; Expires=Mon, 02 Jun 2026 00:00:00 GMT; Path=/"),
            Some(("AWSALB".to_string(), "abc.def.ghi".to_string()))
        );
        // Empty value -> ignored.
        assert_eq!(parse_set_cookie("AWSALB=; Path=/"), None);
    }

    #[test]
    fn cookies_are_scoped_per_host() {
        let client = PreferZstdHttpClient::plaintext();

        // Two hosts each set a cookie of the same name (`AWSALB`) with different values.
        client.store_set_cookies(
            "query.internal:80",
            &set_cookie_headers(&["AWSALB=hostA; Path=/"]),
        );
        client.store_set_cookies(
            "ingest.internal:80",
            &set_cookie_headers(&["AWSALB=hostB; Path=/"]),
        );

        // Each host replays only its own cookie -- no cross-host clobber or leak.
        assert_eq!(
            client.cookie_header_for("query.internal:80").as_deref(),
            Some("AWSALB=hostA")
        );
        assert_eq!(
            client.cookie_header_for("ingest.internal:80").as_deref(),
            Some("AWSALB=hostB")
        );
        // A host that set nothing replays nothing.
        assert_eq!(client.cookie_header_for("other.internal:80"), None);
    }

    #[test]
    fn multiple_cookies_for_one_host_are_merged() {
        let client = PreferZstdHttpClient::plaintext();
        client.store_set_cookies(
            "edge.internal:443",
            &set_cookie_headers(&["AWSALB=abc; Path=/", "AWSALBCORS=abc; Path=/; SameSite=None"]),
        );

        // BTreeMap keeps a deterministic, sorted `Cookie` line.
        assert_eq!(
            client.cookie_header_for("edge.internal:443").as_deref(),
            Some("AWSALB=abc; AWSALBCORS=abc")
        );
    }
}
