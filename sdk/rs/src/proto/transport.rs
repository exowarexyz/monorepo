//! Connect transport helpers for the store API.
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
//! ## HTTP cookies
//!
//! [`PreferZstdHttpClient`] stores `Set-Cookie` response headers in an RFC6265 cookie store and
//! replays matching cookies on later requests. This covers edge affinity cookies as well as normal
//! domain, path, expiry, and deletion semantics.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;

use connectrpc::client::{BoxFuture, ClientBody, ClientTransport, HttpClient};
use connectrpc::compression::CompressionRegistry;
use connectrpc::ConnectError;
use cookie_store::{Cookie, CookieDomain, CookieStore};
use http::header::{ACCEPT_ENCODING, COOKIE, SET_COOKIE};
use http::{Request, Response};
use reqwest::Url;

/// gzip + zstd - used for [`connectrpc::ConnectRpcService::with_compression`] and
/// [`connectrpc::client::ClientConfig::compression`].
#[must_use]
pub fn connect_compression_registry() -> CompressionRegistry {
    CompressionRegistry::default()
}

/// Wraps [`HttpClient`] so every RPC sends `Accept-Encoding: zstd, gzip` (see module docs).
///
/// Also persists HTTP cookies: every `Set-Cookie` response header is stored in an RFC6265 jar and
/// replayed as `Cookie` when it matches a later request URL.
#[derive(Clone, Debug)]
pub struct PreferZstdHttpClient {
    inner: HttpClient,
    cookies: Arc<Mutex<CookieStore>>,
}

impl PreferZstdHttpClient {
    pub fn plaintext() -> Self {
        Self {
            inner: HttpClient::plaintext(),
            cookies: Arc::new(Mutex::new(CookieStore::new())),
        }
    }

    /// Render the `Cookie` header value for `url` from the jar, or `None` if it holds none.
    fn cookie_header_for(&self, url: &Url) -> Option<String> {
        let jar = self.cookies.lock().ok()?;
        let header = jar
            .get_request_values(url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        (!header.is_empty()).then_some(header)
    }

    /// Store every `Set-Cookie` in `headers` under `url`.
    fn store_set_cookies(&self, url: &Url, headers: &http::HeaderMap) {
        let Ok(mut jar) = self.cookies.lock() else {
            return;
        };
        for val in headers.get_all(SET_COOKIE) {
            if let Ok(s) = val.to_str() {
                if let Some(cookie) = parse_set_cookie(s, url) {
                    let _ = jar.insert(cookie, url);
                }
            }
        }
    }
}

/// Parse one `Set-Cookie` header and reject cookies scoped to a public suffix.
fn parse_set_cookie(set_cookie: &str, url: &Url) -> Option<Cookie<'static>> {
    let cookie = Cookie::parse(set_cookie, url).ok()?;
    if let CookieDomain::Suffix(domain) = &cookie.domain {
        // `cookie_store` needs a dynamic suffix list; `psl` supplies the compiled Mozilla list.
        if psl::suffix(domain.as_bytes())
            .is_some_and(|suffix| suffix.is_known() && suffix == domain.as_str())
        {
            return None;
        }
    }
    Some(cookie.into_owned())
}

fn request_url(uri: &http::Uri) -> Option<Url> {
    let scheme = uri.scheme_str()?;
    let authority = uri.authority()?;
    let path_and_query = uri.path_and_query().map_or("/", |pq| pq.as_str());
    Url::parse(&format!("{scheme}://{authority}{path_and_query}")).ok()
}

impl ClientTransport for PreferZstdHttpClient {
    type ResponseBody = hyper::body::Incoming;
    type Error = ConnectError;

    fn send(
        &self,
        mut request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        let url = request_url(request.uri());

        if let Some(ref url) = url {
            if let Some(header) = self.cookie_header_for(url) {
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
            if let Some(url) = url {
                this.store_set_cookies(&url, &parts.headers);
            }
            Ok(Response::from_parts(parts, body))
        })
    }
}

fn merge_cookie_header(headers: &mut http::HeaderMap, jar_header: &str) {
    let mut readable = Vec::new();
    let mut has_opaque = false;
    for value in headers.get_all(COOKIE) {
        match value.to_str() {
            Ok(value) => readable.push(value.to_string()),
            Err(_) => has_opaque = true,
        }
    }

    // All existing cookies are readable: merge into a single clean Cookie header.
    if !has_opaque {
        let merged = if readable.is_empty() {
            jar_header.to_string()
        } else {
            merge_cookie_values(readable.iter().map(String::as_str), jar_header)
        };
        insert_cookie_header(headers, &merged);
        return;
    }

    // Some existing cookies are opaque (non UTF-8) and cannot be merged into a string. Leave the
    // existing headers in place and append only the jar cookies whose names do not collide with the
    // readable existing ones, as an additional Cookie header.
    let existing_names = cookie_names(readable.iter().map(String::as_str));
    let additions = jar_cookies_excluding(&existing_names, jar_header);
    if !additions.is_empty() {
        append_cookie_header(headers, &additions);
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
        for cookie in split_cookies(value) {
            if let Some(name) = cookie_name(cookie) {
                existing_names.insert(name.to_string());
            }
            merged.push(cookie.to_string());
        }
    }

    let additions = jar_cookies_excluding(&existing_names, jar_header);
    if !additions.is_empty() {
        merged.push(additions);
    }

    merged.join("; ")
}

/// Jar cookies whose names are not already present in `existing_names`, rendered as a `Cookie` line.
/// Jar names never override caller-supplied ones.
fn jar_cookies_excluding(existing_names: &BTreeSet<String>, jar_header: &str) -> String {
    split_cookies(jar_header)
        .filter(|cookie| match cookie_name(cookie) {
            Some(name) => !existing_names.contains(name),
            None => true,
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn cookie_names<'a>(values: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for value in values {
        for cookie in split_cookies(value) {
            if let Some(name) = cookie_name(cookie) {
                names.insert(name.to_string());
            }
        }
    }
    names
}

fn split_cookies(value: &str) -> impl Iterator<Item = &str> {
    value.split(';').map(str::trim).filter(|s| !s.is_empty())
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

    fn url(value: &str) -> Url {
        Url::parse(value).unwrap()
    }

    fn set_cookie_headers(values: &[&str]) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        for v in values {
            headers.append(SET_COOKIE, v.parse().unwrap());
        }
        headers
    }

    #[test]
    fn host_only_cookies_are_scoped_per_host() {
        let client = PreferZstdHttpClient::plaintext();

        client.store_set_cookies(
            &url("https://query.internal:80/rpc"),
            &set_cookie_headers(&["AWSALB=hostA; Path=/"]),
        );
        client.store_set_cookies(
            &url("https://ingest.internal:80/rpc"),
            &set_cookie_headers(&["AWSALB=hostB; Path=/"]),
        );

        assert_eq!(
            client
                .cookie_header_for(&url("https://query.internal:80/rpc"))
                .as_deref(),
            Some("AWSALB=hostA")
        );
        assert_eq!(
            client
                .cookie_header_for(&url("https://ingest.internal:80/rpc"))
                .as_deref(),
            Some("AWSALB=hostB")
        );
        assert_eq!(
            client.cookie_header_for(&url("https://other.internal:80/rpc")),
            None
        );
    }

    #[test]
    fn cookie_hosts_are_case_insensitive() {
        let client = PreferZstdHttpClient::plaintext();

        client.store_set_cookies(
            &url("https://API.example.com/rpc"),
            &set_cookie_headers(&["AWSALB=stick; Path=/"]),
        );

        assert_eq!(
            client
                .cookie_header_for(&url("https://api.example.com/rpc"))
                .as_deref(),
            Some("AWSALB=stick")
        );
    }

    #[test]
    fn domain_and_path_matching_are_honored() {
        let client = PreferZstdHttpClient::plaintext();

        client.store_set_cookies(
            &url("https://api.example.com/rpc/create"),
            &set_cookie_headers(&["session=one; Domain=example.com; Path=/rpc"]),
        );

        assert_eq!(
            client
                .cookie_header_for(&url("https://query.example.com/rpc/read"))
                .as_deref(),
            Some("session=one")
        );
        assert_eq!(
            client.cookie_header_for(&url("https://query.example.com/other")),
            None
        );
    }

    #[test]
    fn public_suffix_domain_cookies_are_rejected() {
        let client = PreferZstdHttpClient::plaintext();

        client.store_set_cookies(
            &url("https://api.example.com/rpc"),
            &set_cookie_headers(&["leak=1; Domain=com; Path=/"]),
        );

        assert_eq!(
            client.cookie_header_for(&url("https://api.example.com/rpc")),
            None
        );
        assert_eq!(
            client.cookie_header_for(&url("https://other.com/rpc")),
            None
        );
    }

    #[test]
    fn expired_set_cookie_removes_cookie_from_jar() {
        let client = PreferZstdHttpClient::plaintext();

        client.store_set_cookies(
            &url("https://edge.internal/rpc"),
            &set_cookie_headers(&["AWSALB=abc; Path=/"]),
        );
        assert_eq!(
            client
                .cookie_header_for(&url("https://edge.internal/rpc"))
                .as_deref(),
            Some("AWSALB=abc")
        );

        client.store_set_cookies(
            &url("https://edge.internal/rpc"),
            &set_cookie_headers(&["AWSALB=; Max-Age=0; Path=/"]),
        );

        assert_eq!(
            client.cookie_header_for(&url("https://edge.internal/rpc")),
            None
        );
    }

    #[test]
    fn request_url_preserves_path_and_query() {
        assert_eq!(
            request_url(&"https://edge.internal/rpc?x=1".parse().unwrap()).as_ref(),
            Some(&url("https://edge.internal/rpc?x=1"))
        );
    }

    #[test]
    fn request_url_rejects_origin_form_uri() {
        assert_eq!(request_url(&"/rpc?x=1".parse().unwrap()), None);
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

    #[test]
    fn merge_cookie_header_preserves_opaque_cookie_and_appends_jar() {
        let mut headers = http::HeaderMap::new();
        // A non UTF-8 Cookie value cannot be merged into a string.
        headers.append(
            COOKIE,
            http::HeaderValue::from_bytes(b"opaque=\xff\xfe").unwrap(),
        );
        headers.append(COOKIE, "caller=token".parse().unwrap());

        merge_cookie_header(&mut headers, "AWSALB=abc; caller=jar");

        // The opaque and readable existing headers survive, and only the non-colliding jar cookie
        // is appended as a separate Cookie header.
        let values: Vec<_> = headers
            .get_all(COOKIE)
            .iter()
            .map(|v| v.as_bytes().to_vec())
            .collect();
        assert_eq!(values.len(), 3);
        assert!(values.contains(&b"opaque=\xff\xfe".to_vec()));
        assert!(values.contains(&b"caller=token".to_vec()));
        assert!(values.contains(&b"AWSALB=abc".to_vec()));
    }
}
