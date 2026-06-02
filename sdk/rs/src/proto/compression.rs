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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use connectrpc::client::{BoxFuture, ClientBody, ClientTransport, HttpClient};
use connectrpc::compression::CompressionRegistry;
use connectrpc::ConnectError;
use http::header::{ACCEPT_ENCODING, COOKIE, SET_COOKIE};
use http::{Request, Response};

// This jar exists for edge affinity, not general browser state. Keep it bounded so a broken or
// compromised edge cannot amplify memory usage or outbound request headers through Set-Cookie.
const MAX_COOKIES_PER_HOST: usize = 16;
const MAX_COOKIE_BYTES: usize = 4096;
const MAX_COOKIE_HEADER_BYTES: usize = 8192;

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
    /// Per-host cookie jar: request authority (`host` or `host:port`) -> that host's cookies (name -> value).
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
                match parse_set_cookie(s) {
                    Some(SetCookieUpdate::Store { name, value }) => {
                        store_cookie(&mut jar, authority, name, value);
                    }
                    Some(SetCookieUpdate::Delete { name }) => {
                        if let Some(origin) = jar.get_mut(authority) {
                            origin.remove(&name);
                            if origin.is_empty() {
                                jar.remove(authority);
                            }
                        }
                    }
                    None => {}
                }
            }
        }
    }
}

fn store_cookie(
    jar: &mut BTreeMap<String, BTreeMap<String, String>>,
    authority: &str,
    name: String,
    value: String,
) {
    if cookie_pair_len(&name, &value) > MAX_COOKIE_BYTES {
        return;
    }

    let origin = jar.entry(authority.to_string()).or_default();
    if !origin.contains_key(&name) && origin.len() >= MAX_COOKIES_PER_HOST {
        return;
    }

    let previous = origin.insert(name.clone(), value);
    if rendered_cookie_header_len(origin) > MAX_COOKIE_HEADER_BYTES {
        if let Some(previous) = previous {
            origin.insert(name, previous);
        } else {
            origin.remove(&name);
        }
    }
}

fn cookie_pair_len(name: &str, value: &str) -> usize {
    name.len() + 1 + value.len()
}

fn rendered_cookie_header_len(cookies: &BTreeMap<String, String>) -> usize {
    let pair_bytes = cookies
        .iter()
        .map(|(name, value)| cookie_pair_len(name, value))
        .sum::<usize>();
    pair_bytes + cookies.len().saturating_sub(1) * 2
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
                merge_cookie_header(request.headers_mut(), &header);
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum SetCookieUpdate {
    Store { name: String, value: String },
    Delete { name: String },
}

/// From one `Set-Cookie` header value, extract the cookie update, honoring expiry/deletion
/// attributes while ignoring non-lifetime attributes (`Path`, `Domain`, ...).
fn parse_set_cookie(set_cookie: &str) -> Option<SetCookieUpdate> {
    let mut segments = set_cookie.split(';');
    let first = segments.next()?.trim();
    let (name, value) = first.split_once('=')?;
    let name = name.trim();
    let value = value.trim().trim_matches('"');
    if name.is_empty() {
        return None;
    }

    if cookie_is_expired(segments) {
        return Some(SetCookieUpdate::Delete {
            name: name.to_string(),
        });
    }

    Some(SetCookieUpdate::Store {
        name: name.to_string(),
        value: value.to_string(),
    })
}

fn cookie_is_expired<'a>(attributes: impl IntoIterator<Item = &'a str>) -> bool {
    let mut expires = None;

    for attr in attributes {
        let Some((name, value)) = attr.trim().split_once('=') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();

        if name.eq_ignore_ascii_case("max-age") {
            if let Ok(seconds) = value.parse::<i64>() {
                return seconds <= 0;
            }
            continue;
        }

        if name.eq_ignore_ascii_case("expires") {
            expires = parse_cookie_expires(value);
        }
    }

    expires.is_some_and(|expiry| expiry <= Utc::now())
}

fn parse_cookie_expires(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(value)
        .map(|date| date.with_timezone(&Utc))
        .ok()
}

fn merge_cookie_header(headers: &mut http::HeaderMap, jar_header: &str) {
    let mut existing_values = Vec::new();
    for value in headers.get_all(COOKIE) {
        let Ok(value) = value.to_str() else {
            append_cookie_header(headers, jar_header);
            return;
        };
        existing_values.push(value.to_string());
    }

    if existing_values.is_empty() {
        insert_cookie_header(headers, jar_header);
        return;
    }

    let merged = merge_cookie_values(existing_values.iter().map(String::as_str), jar_header);
    if let Ok(value) = http::HeaderValue::from_str(&merged) {
        headers.insert(COOKIE, value);
    }
}

fn insert_cookie_header(headers: &mut http::HeaderMap, value: &str) {
    if let Ok(value) = http::HeaderValue::from_str(value) {
        headers.insert(COOKIE, value);
    }
}

fn append_cookie_header(headers: &mut http::HeaderMap, value: &str) {
    if let Ok(value) = http::HeaderValue::from_str(value) {
        headers.append(COOKIE, value);
    }
}

fn merge_cookie_values<'a>(
    existing_values: impl IntoIterator<Item = &'a str>,
    jar_header: &str,
) -> String {
    let mut merged = Vec::new();
    let mut existing_names = BTreeSet::new();

    for value in existing_values {
        for cookie in value.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            if let Some(name) = cookie_name(cookie) {
                existing_names.insert(name.to_string());
            }
            merged.push(cookie.to_string());
        }
    }

    for cookie in jar_header
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let should_append = match cookie_name(cookie) {
            Some(name) => !existing_names.contains(name),
            None => true,
        };
        if should_append {
            merged.push(cookie.to_string());
        }
    }

    merged.join("; ")
}

fn cookie_name(cookie: &str) -> Option<&str> {
    let (name, _) = cookie.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some(name)
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
            Some(SetCookieUpdate::Store {
                name: "affinity".to_string(),
                value: "Zm9vYmFy".to_string(),
            })
        );
        // A typical load-balancer stickiness cookie (e.g. AWS ALB).
        assert_eq!(
            parse_set_cookie("AWSALB=abc.def.ghi; Path=/"),
            Some(SetCookieUpdate::Store {
                name: "AWSALB".to_string(),
                value: "abc.def.ghi".to_string(),
            })
        );
        // Empty values are valid cookies; deletion is signaled by lifetime attributes below.
        assert_eq!(
            parse_set_cookie("AWSALB=; Path=/"),
            Some(SetCookieUpdate::Store {
                name: "AWSALB".to_string(),
                value: String::new(),
            })
        );
    }

    #[test]
    fn parse_set_cookie_marks_expired_cookies_for_deletion() {
        assert_eq!(
            parse_set_cookie("AWSALB=abc; Max-Age=0; Path=/"),
            Some(SetCookieUpdate::Delete {
                name: "AWSALB".to_string(),
            })
        );
        assert_eq!(
            parse_set_cookie("AWSALB=abc; Max-Age=-1; Path=/"),
            Some(SetCookieUpdate::Delete {
                name: "AWSALB".to_string(),
            })
        );
        assert_eq!(
            parse_set_cookie("AWSALB=abc; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/"),
            Some(SetCookieUpdate::Delete {
                name: "AWSALB".to_string(),
            })
        );
        assert_eq!(
            parse_set_cookie(
                "AWSALB=abc; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/"
            ),
            Some(SetCookieUpdate::Store {
                name: "AWSALB".to_string(),
                value: "abc".to_string(),
            })
        );
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
            &set_cookie_headers(&[
                "AWSALB=abc; Path=/",
                "AWSALBCORS=abc; Path=/; SameSite=None",
            ]),
        );

        // BTreeMap keeps a deterministic, sorted `Cookie` line.
        assert_eq!(
            client.cookie_header_for("edge.internal:443").as_deref(),
            Some("AWSALB=abc; AWSALBCORS=abc")
        );
    }

    #[test]
    fn oversized_cookie_is_not_stored() {
        let client = PreferZstdHttpClient::plaintext();
        let mut headers = http::HeaderMap::new();
        headers.append(
            SET_COOKIE,
            format!("AWSALB={}; Path=/", "x".repeat(MAX_COOKIE_BYTES))
                .parse()
                .unwrap(),
        );

        client.store_set_cookies("edge.internal:443", &headers);

        assert_eq!(client.cookie_header_for("edge.internal:443"), None);
    }

    #[test]
    fn cookie_count_cap_rejects_new_names_but_allows_replacement() {
        let client = PreferZstdHttpClient::plaintext();
        let mut headers = http::HeaderMap::new();
        for idx in 0..MAX_COOKIES_PER_HOST {
            headers.append(SET_COOKIE, format!("c{idx:02}=v; Path=/").parse().unwrap());
        }
        headers.append(SET_COOKIE, "extra=v; Path=/".parse().unwrap());

        client.store_set_cookies("edge.internal:443", &headers);

        let header = client
            .cookie_header_for("edge.internal:443")
            .expect("stored bounded cookies");
        assert_eq!(header.split("; ").count(), MAX_COOKIES_PER_HOST);
        assert!(!header.contains("extra="));

        client.store_set_cookies(
            "edge.internal:443",
            &set_cookie_headers(&["c00=rotated; Path=/"]),
        );

        let header = client
            .cookie_header_for("edge.internal:443")
            .expect("replacement should be stored");
        assert!(header.contains("c00=rotated"));
    }

    #[test]
    fn cookie_header_size_cap_rejects_insert_that_would_overflow_header() {
        let client = PreferZstdHttpClient::plaintext();
        let first = "a".repeat(MAX_COOKIE_BYTES - "a=".len());
        let second = "b".repeat(MAX_COOKIE_BYTES - "b=".len());
        let mut headers = http::HeaderMap::new();
        headers.append(SET_COOKIE, format!("a={first}; Path=/").parse().unwrap());
        headers.append(SET_COOKIE, format!("b={second}; Path=/").parse().unwrap());

        client.store_set_cookies("edge.internal:443", &headers);

        let header = client
            .cookie_header_for("edge.internal:443")
            .expect("first bounded cookie should be stored");
        assert!(header.len() <= MAX_COOKIE_HEADER_BYTES);
        assert_eq!(header.split("; ").count(), 1);
        assert!(header.starts_with("a="));
    }

    #[test]
    fn expired_set_cookie_removes_cookie_from_host_jar() {
        let client = PreferZstdHttpClient::plaintext();
        client.store_set_cookies(
            "edge.internal:443",
            &set_cookie_headers(&["AWSALB=abc; Path=/", "AWSALBCORS=def; Path=/"]),
        );
        client.store_set_cookies(
            "edge.internal:443",
            &set_cookie_headers(&["AWSALB=; Max-Age=0; Path=/"]),
        );

        assert_eq!(
            client.cookie_header_for("edge.internal:443").as_deref(),
            Some("AWSALBCORS=def")
        );
    }

    #[test]
    fn expired_set_cookie_clears_empty_host_jar() {
        let client = PreferZstdHttpClient::plaintext();
        client.store_set_cookies(
            "edge.internal:443",
            &set_cookie_headers(&["AWSALB=abc; Path=/"]),
        );
        client.store_set_cookies(
            "edge.internal:443",
            &set_cookie_headers(&["AWSALB=; Max-Age=0; Path=/"]),
        );

        assert_eq!(client.cookie_header_for("edge.internal:443"), None);
    }

    #[test]
    fn merge_cookie_values_appends_jar_cookies_to_existing_cookies() {
        assert_eq!(
            merge_cookie_values(["caller=token"].into_iter(), "AWSALB=abc; AWSALBCORS=def"),
            "caller=token; AWSALB=abc; AWSALBCORS=def"
        );
    }

    #[test]
    fn merge_cookie_values_keeps_existing_cookie_on_name_collision() {
        assert_eq!(
            merge_cookie_values(
                ["AWSALB=caller; app=session"].into_iter(),
                "AWSALB=jar; AWSALBCORS=jarcors"
            ),
            "AWSALB=caller; app=session; AWSALBCORS=jarcors"
        );
    }

    #[test]
    fn merge_cookie_header_preserves_existing_call_options_cookie() {
        let mut headers = http::HeaderMap::new();
        headers.append(COOKIE, "caller=token".parse().unwrap());
        headers.append(COOKIE, "app=session".parse().unwrap());

        merge_cookie_header(&mut headers, "AWSALB=abc");

        assert_eq!(
            headers.get(COOKIE).and_then(|v| v.to_str().ok()),
            Some("caller=token; app=session; AWSALB=abc")
        );
        assert_eq!(headers.get_all(COOKIE).iter().count(), 1);
    }
}
