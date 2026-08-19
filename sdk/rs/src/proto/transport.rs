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
//! HTTP and HTTPS transport that sets `Accept-Encoding: zstd, gzip` on every outbound request.
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

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use connectrpc::client::{
    BoxFuture, ClientBody, ClientTransport, Http2Connection, HttpClient, ServiceTransport,
};
use connectrpc::compression::CompressionRegistry;
use connectrpc::rustls::ClientConfig;
use connectrpc::ConnectError;
use cookie_store::{Cookie, CookieDomain, CookieStore};
use http::header::{ACCEPT_ENCODING, AUTHORIZATION, COOKIE, SET_COOKIE};
use http::{Request, Response};
use http_body::Body;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::BodyExt;
use reqwest::Url;
use tower::balance::p2c::Balance;
use tower::discover::ServiceList;
use tower::load::completion::CompleteOnResponse;
use tower::load::PeakEwmaDiscover;
use tower::ServiceExt;

const DEFAULT_CONNECTIONS_PER_ORIGIN: usize = 4;
const DEFAULT_REQUEST_BUFFER_CAPACITY: usize = 64;
const DEFAULT_RTT: Duration = Duration::from_secs(1);
const DEFAULT_EWMA_DECAY: Duration = Duration::from_secs(10);

/// Configures an opt-in pool of independent HTTP/2 connections per RPC origin.
///
/// Requests wait in a bounded Tower buffer. Peak EWMA balancing favors connections with lower
/// observed response latency and fewer pending requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalancedHttp2Config {
    connections_per_origin: usize,
    request_buffer_capacity: usize,
    default_rtt: Duration,
    ewma_decay: Duration,
}

impl BalancedHttp2Config {
    /// Creates a configuration with the requested connection and buffer counts.
    pub const fn new(connections_per_origin: usize, request_buffer_capacity: usize) -> Self {
        Self {
            connections_per_origin,
            request_buffer_capacity,
            default_rtt: DEFAULT_RTT,
            ewma_decay: DEFAULT_EWMA_DECAY,
        }
    }

    /// Sets the initial latency estimate used before a connection completes a request.
    #[must_use]
    pub const fn with_default_rtt(mut self, default_rtt: Duration) -> Self {
        self.default_rtt = default_rtt;
        self
    }

    /// Sets how quickly an observed peak latency decays toward the moving average.
    #[must_use]
    pub const fn with_ewma_decay(mut self, ewma_decay: Duration) -> Self {
        self.ewma_decay = ewma_decay;
        self
    }

    /// Number of independent connections created for each distinct RPC origin.
    pub const fn connections_per_origin(&self) -> usize {
        self.connections_per_origin
    }

    /// Maximum number of requests waiting for a balanced connection.
    pub const fn request_buffer_capacity(&self) -> usize {
        self.request_buffer_capacity
    }
}

impl Default for BalancedHttp2Config {
    fn default() -> Self {
        Self::new(
            DEFAULT_CONNECTIONS_PER_ORIGIN,
            DEFAULT_REQUEST_BUFFER_CAPACITY,
        )
    }
}

/// Error returned while constructing the balanced HTTP/2 transport.
#[derive(Debug, thiserror::Error)]
pub enum BalancedHttp2TransportError {
    #[error("balanced HTTP/2 connections per origin must be nonzero")]
    ZeroConnections,
    #[error("balanced HTTP/2 request buffer capacity must be nonzero")]
    ZeroBufferCapacity,
    #[error("balanced HTTP/2 default RTT must be nonzero")]
    ZeroDefaultRtt,
    #[error("balanced HTTP/2 EWMA decay must be nonzero")]
    ZeroEwmaDecay,
    #[error("balanced HTTP/2 transport construction requires a running Tokio runtime")]
    MissingRuntime,
    #[error("balanced HTTP/2 HTTPS origins require a TLS configuration")]
    MissingTlsConfig,
}

/// Error type used after normalizing a consumer transport to the SDK's concrete body type.
#[derive(Debug)]
pub(crate) struct ErasedTransportError(String);

impl ErasedTransportError {
    fn new(error: impl fmt::Display) -> Self {
        Self(error.to_string())
    }
}

impl fmt::Display for ErasedTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ErasedTransportError {}

/// Response body used by the type-erased Store client transport.
pub(crate) type ErasedResponseBody = UnsyncBoxBody<Bytes, ErasedTransportError>;

trait DynClientTransport: Send + Sync {
    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<ErasedResponseBody>, ErasedTransportError>>;
}

struct ClientTransportAdapter<T> {
    inner: T,
}

impl<T> DynClientTransport for ClientTransportAdapter<T>
where
    T: ClientTransport,
    <T::ResponseBody as Body>::Error: fmt::Display,
{
    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<ErasedResponseBody>, ErasedTransportError>> {
        let future = self.inner.send(request);
        Box::pin(async move {
            let response = future.await.map_err(ErasedTransportError::new)?;
            Ok(response.map(|body| body.map_err(ErasedTransportError::new).boxed_unsync()))
        })
    }
}

/// Cloneable type erasure for a compatible connectrpc client transport.
#[derive(Clone)]
pub(crate) struct ErasedClientTransport {
    inner: Arc<dyn DynClientTransport>,
}

impl ErasedClientTransport {
    pub(crate) fn new<T>(transport: T) -> Self
    where
        T: ClientTransport,
        <T::ResponseBody as Body>::Error: fmt::Display,
    {
        Self {
            inner: Arc::new(ClientTransportAdapter { inner: transport }),
        }
    }
}

impl fmt::Debug for ErasedClientTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErasedClientTransport").finish()
    }
}

impl ClientTransport for ErasedClientTransport {
    type ResponseBody = ErasedResponseBody;
    type Error = ErasedTransportError;

    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        self.inner.send(request)
    }
}

#[derive(Clone, Debug)]
struct ClientMetadata {
    cookies: Arc<Mutex<CookieStore>>,
    authorization: Option<http::HeaderValue>,
}

impl ClientMetadata {
    fn new() -> Self {
        Self {
            cookies: Arc::new(Mutex::new(CookieStore::new())),
            authorization: None,
        }
    }

    fn with_authorization(mut self, value: http::HeaderValue) -> Self {
        self.authorization = Some(value);
        self
    }

    fn prepare_request(&self, request: &mut Request<ClientBody>) -> Option<Url> {
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

        if let Some(ref authorization) = self.authorization {
            apply_authorization(request.headers_mut(), authorization);
        }
        url
    }

    fn cookie_header_for(&self, url: &Url) -> Option<String> {
        let jar = self.cookies.lock().ok()?;
        let header = jar
            .get_request_values(url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        (!header.is_empty()).then_some(header)
    }

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

/// Applies SDK metadata policy around a consumer-supplied raw transport.
#[derive(Clone, Debug)]
pub(crate) struct MetadataClientTransport {
    inner: ErasedClientTransport,
    metadata: ClientMetadata,
}

impl MetadataClientTransport {
    pub(crate) fn new(inner: ErasedClientTransport) -> Self {
        Self {
            inner,
            metadata: ClientMetadata::new(),
        }
    }

    pub(crate) fn with_authorization(mut self, value: http::HeaderValue) -> Self {
        self.metadata = self.metadata.with_authorization(value);
        self
    }
}

impl ClientTransport for MetadataClientTransport {
    type ResponseBody = ErasedResponseBody;
    type Error = ErasedTransportError;

    fn send(
        &self,
        mut request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        let url = self.metadata.prepare_request(&mut request);
        let future = self.inner.send(request);
        let metadata = self.metadata.clone();
        Box::pin(async move {
            let response = future.await?;
            let (parts, body) = response.into_parts();
            if let Some(url) = url {
                metadata.store_set_cookies(&url, &parts.headers);
            }
            Ok(Response::from_parts(parts, body))
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RpcOrigin(String);

impl RpcOrigin {
    fn from_uri(uri: &http::Uri) -> Option<Self> {
        Some(Self(format!(
            "{}://{}",
            uri.scheme_str()?,
            uri.authority()?
        )))
    }

    fn uri(&self) -> http::Uri {
        self.0.parse().expect("validated RPC origin must be a URI")
    }
}

/// Routes requests to one balanced connection pool for each distinct RPC origin.
#[derive(Clone, Debug)]
pub(crate) struct BalancedHttp2Transport {
    origins: Arc<HashMap<RpcOrigin, ErasedClientTransport>>,
}

impl BalancedHttp2Transport {
    pub(crate) fn new(
        uris: impl IntoIterator<Item = http::Uri>,
        config: BalancedHttp2Config,
        tls_config: Option<Arc<ClientConfig>>,
    ) -> Result<Self, BalancedHttp2TransportError> {
        validate_balanced_config(config)?;
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| BalancedHttp2TransportError::MissingRuntime)?;
        let mut origins = HashMap::new();

        for uri in uris {
            let origin = RpcOrigin::from_uri(&uri)
                .expect("StoreClientBuilder validates RPC endpoint origins");
            if origins.contains_key(&origin) {
                continue;
            }

            let connection_uri = origin.uri();
            let connections = (0..config.connections_per_origin)
                .map(|_| match connection_uri.scheme_str() {
                    Some("http") => Ok(Http2Connection::lazy_plaintext(connection_uri.clone())),
                    Some("https") => tls_config
                        .clone()
                        .map(|tls| Http2Connection::lazy_tls(connection_uri.clone(), tls))
                        .ok_or(BalancedHttp2TransportError::MissingTlsConfig),
                    _ => unreachable!("StoreClientBuilder validates RPC endpoint schemes"),
                })
                .collect::<Result<Vec<_>, _>>()?;
            let discover = ServiceList::new(connections);
            let discover = PeakEwmaDiscover::new::<Request<ClientBody>>(
                discover,
                config.default_rtt,
                config.ewma_decay,
                CompleteOnResponse::default(),
            );
            let balance = Balance::new(discover);
            let (buffer, worker) =
                tower::buffer::Buffer::pair(balance, config.request_buffer_capacity);
            runtime.spawn(worker);
            let service = buffer.map_err(ErasedTransportError::new);
            let transport = ServiceTransport::new(service);
            origins.insert(origin, ErasedClientTransport::new(transport));
        }

        Ok(Self {
            origins: Arc::new(origins),
        })
    }

    #[cfg(test)]
    pub(crate) fn origin_count(&self) -> usize {
        self.origins.len()
    }
}

impl ClientTransport for BalancedHttp2Transport {
    type ResponseBody = ErasedResponseBody;
    type Error = ErasedTransportError;

    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        let Some(origin) = RpcOrigin::from_uri(request.uri()) else {
            return Box::pin(async {
                Err(ErasedTransportError::new(
                    "RPC request URI does not contain an origin",
                ))
            });
        };
        let Some(transport) = self.origins.get(&origin).cloned() else {
            return Box::pin(async move {
                Err(ErasedTransportError::new(format!(
                    "no balanced HTTP/2 pool configured for RPC origin {}",
                    origin.0
                )))
            });
        };
        transport.send(request)
    }
}

fn validate_balanced_config(
    config: BalancedHttp2Config,
) -> Result<(), BalancedHttp2TransportError> {
    if config.connections_per_origin == 0 {
        return Err(BalancedHttp2TransportError::ZeroConnections);
    }
    if config.request_buffer_capacity == 0 {
        return Err(BalancedHttp2TransportError::ZeroBufferCapacity);
    }
    if config.default_rtt.is_zero() {
        return Err(BalancedHttp2TransportError::ZeroDefaultRtt);
    }
    if config.ewma_decay.is_zero() {
        return Err(BalancedHttp2TransportError::ZeroEwmaDecay);
    }
    Ok(())
}

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
///
/// Carries the optional bearer credential too, so one place authenticates every RPC service
/// rather than each generated client doing it.
#[derive(Clone, Debug)]
pub struct PreferZstdHttpClient {
    plaintext: HttpClient,
    tls: Option<HttpClient>,
    metadata: ClientMetadata,
}

impl PreferZstdHttpClient {
    /// Creates a transport for HTTP endpoints.
    pub fn plaintext() -> Self {
        Self {
            plaintext: HttpClient::plaintext(),
            tls: None,
            metadata: ClientMetadata::new(),
        }
    }

    /// Creates a transport for HTTP and HTTPS endpoints using the provided TLS configuration.
    pub fn with_tls(tls_config: Arc<ClientConfig>) -> Self {
        Self {
            plaintext: HttpClient::plaintext(),
            tls: Some(HttpClient::with_tls(tls_config)),
            metadata: ClientMetadata::new(),
        }
    }

    /// Send `value` as `Authorization` on every RPC.
    ///
    /// Mark the value sensitive before passing it here so it stays redacted in `Debug` output.
    #[must_use]
    pub fn with_authorization(mut self, value: http::HeaderValue) -> Self {
        self.metadata = self.metadata.with_authorization(value);
        self
    }

    /// The `Authorization` value this client sends, if it has one.
    ///
    /// Only the crate's own tests read this back. Nothing on the request path needs it, because
    /// `send` uses the field directly.
    #[cfg(test)]
    pub(crate) fn authorization(&self) -> Option<&http::HeaderValue> {
        self.metadata.authorization.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn supports_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// Render the `Cookie` header value for `url` from the jar, or `None` if it holds none.
    #[cfg(test)]
    fn cookie_header_for(&self, url: &Url) -> Option<String> {
        self.metadata.cookie_header_for(url)
    }

    /// Store every `Set-Cookie` in `headers` under `url`.
    #[cfg(test)]
    fn store_set_cookies(&self, url: &Url, headers: &http::HeaderMap) {
        self.metadata.store_set_cookies(url, headers);
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

/// Convert an absolute HTTP URI into a URL usable by the cookie store.
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
        let transport = match request.uri().scheme_str() {
            Some("http") => self.plaintext.clone(),
            Some("https") => match &self.tls {
                Some(tls) => tls.clone(),
                None => {
                    return Box::pin(async {
                        Err(ConnectError::invalid_argument(
                            "HTTPS endpoint requires a TLS transport",
                        ))
                    });
                }
            },
            scheme => {
                let message = format!("unsupported endpoint URL scheme {scheme:?}");
                return Box::pin(async move { Err(ConnectError::invalid_argument(message)) });
            }
        };
        let url = self.metadata.prepare_request(&mut request);

        let this = self.clone();
        Box::pin(async move {
            let response = transport.send(request).await?;
            let (parts, body) = response.into_parts();
            if let Some(url) = url {
                this.metadata.store_set_cookies(&url, &parts.headers);
            }
            Ok(Response::from_parts(parts, body))
        })
    }
}

/// Set the client's credential as `Authorization`, leaving any caller-supplied one alone.
///
/// Deferring to the caller matches how jar cookies defer to caller-supplied cookie names, and it
/// is what lets one client reach a deployment that expects a different credential on a specific
/// call.
fn apply_authorization(headers: &mut http::HeaderMap, value: &http::HeaderValue) {
    if !headers.contains_key(AUTHORIZATION) {
        headers.insert(AUTHORIZATION, value.clone());
    }
}

/// Add jar cookies to existing `Cookie` headers without overriding caller-supplied names.
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

    // Some existing cookies have opaque values and cannot be merged into a string. Leave the
    // existing headers in place, but still read names from raw header bytes so jar cookies never
    // duplicate caller-supplied names.
    let existing_names = cookie_names_from_headers(headers);
    let additions = jar_cookies_excluding(&existing_names, jar_header);
    if !additions.is_empty() {
        append_cookie_header(headers, &additions);
    }
}

/// Replace all existing `Cookie` headers with one validated header value.
fn insert_cookie_header(headers: &mut http::HeaderMap, value: &str) {
    if let Ok(value) = http::HeaderValue::from_str(value) {
        headers.insert(COOKIE, value);
    }
}

/// Append one validated `Cookie` header value without disturbing existing headers.
fn append_cookie_header(headers: &mut http::HeaderMap, value: &str) {
    if let Ok(value) = http::HeaderValue::from_str(value) {
        headers.append(COOKIE, value);
    }
}

/// Merge readable caller cookie values with jar cookies, preserving caller values on name collision.
fn merge_cookie_values<'a>(
    existing_values: impl IntoIterator<Item = &'a str>,
    jar_header: &str,
) -> String {
    let mut merged = Vec::new();
    let mut existing_names = BTreeSet::new();

    for value in existing_values {
        for cookie in split_cookies(value) {
            if let Some(name) = cookie_name(cookie) {
                existing_names.insert(name.as_bytes().to_vec());
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
fn jar_cookies_excluding(existing_names: &BTreeSet<Vec<u8>>, jar_header: &str) -> String {
    split_cookies(jar_header)
        .filter(|cookie| match cookie_name(cookie) {
            Some(name) => !existing_names.contains(name.as_bytes()),
            None => true,
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Collect cookie names from raw `Cookie` headers, including ones with opaque values.
fn cookie_names_from_headers(headers: &http::HeaderMap) -> BTreeSet<Vec<u8>> {
    let mut names = BTreeSet::new();
    for value in headers.get_all(COOKIE) {
        for cookie in split_cookie_bytes(value.as_bytes()) {
            if let Some(name) = cookie_name_bytes(cookie) {
                names.insert(name.to_vec());
            }
        }
    }
    names
}

/// Split a `Cookie` header body into non-empty `name=value` fragments.
fn split_cookies(value: &str) -> impl Iterator<Item = &str> {
    value.split(';').map(str::trim).filter(|s| !s.is_empty())
}

/// Split a raw `Cookie` header body into non-empty `name=value` fragments.
fn split_cookie_bytes(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value
        .split(|b| *b == b';')
        .map(trim_cookie_bytes)
        .filter(|s| !s.is_empty())
}

/// Return the non-empty name before the first `=` in a cookie fragment.
fn cookie_name(cookie: &str) -> Option<&str> {
    let (name, _) = cookie.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some(name)
}

/// Return the non-empty raw name before the first `=` in a cookie fragment.
fn cookie_name_bytes(cookie: &[u8]) -> Option<&[u8]> {
    let eq = cookie.iter().position(|b| *b == b'=')?;
    let name = trim_cookie_bytes(&cookie[..eq]);
    if name.is_empty() {
        return None;
    }
    Some(name)
}

/// Trim HTTP optional whitespace around cookie fragments.
fn trim_cookie_bytes(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|b| !matches!(*b, b' ' | b'\t'))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| !matches!(*b, b' ' | b'\t'))
        .map_or(start, |i| i + 1);
    &value[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Debug, Default)]
    struct ScriptedTransport {
        calls: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<http::HeaderMap>>>,
    }

    impl ClientTransport for ScriptedTransport {
        type ResponseBody = http_body_util::Empty<Bytes>;
        type Error = ConnectError;

        fn send(
            &self,
            request: Request<ClientBody>,
        ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
            self.requests
                .lock()
                .unwrap()
                .push(request.headers().clone());
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let mut response = Response::new(http_body_util::Empty::new());
                if call == 0 {
                    response
                        .headers_mut()
                        .insert(SET_COOKIE, "AWSALB=sticky; Path=/".parse().unwrap());
                }
                Ok(response)
            })
        }
    }

    #[derive(Clone, Debug)]
    struct NamedTransport {
        name: &'static str,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl ClientTransport for NamedTransport {
        type ResponseBody = http_body_util::Empty<Bytes>;
        type Error = ConnectError;

        fn send(
            &self,
            _request: Request<ClientBody>,
        ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
            self.calls.lock().unwrap().push(self.name);
            Box::pin(async { Err(ConnectError::unavailable("recorded route")) })
        }
    }

    fn request(uri: &str) -> Request<ClientBody> {
        Request::post(uri)
            .body(connectrpc::client::full_body(Bytes::new()))
            .unwrap()
    }

    /// Parse a test URL literal.
    fn url(value: &str) -> Url {
        Url::parse(value).unwrap()
    }

    /// Build a header map containing the supplied `Set-Cookie` values.
    fn set_cookie_headers(values: &[&str]) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        for v in values {
            headers.append(SET_COOKIE, v.parse().unwrap());
        }
        headers
    }

    #[test]
    fn transport_modes_report_tls_support() {
        let plaintext = PreferZstdHttpClient::plaintext();
        assert!(!plaintext.supports_tls());

        let tls_config = ClientConfig::builder()
            .with_root_certificates(connectrpc::rustls::RootCertStore::empty())
            .with_no_client_auth();
        let tls = PreferZstdHttpClient::with_tls(Arc::new(tls_config));
        assert!(tls.supports_tls());
    }

    #[tokio::test]
    async fn metadata_wraps_a_supplied_transport_and_persists_cookies() {
        let raw = ScriptedTransport::default();
        let transport = MetadataClientTransport::new(ErasedClientTransport::new(raw.clone()))
            .with_authorization("Bearer token".parse().unwrap());

        transport
            .send(request("http://query.internal/rpc/first"))
            .await
            .unwrap();
        transport
            .send(request("http://query.internal/rpc/second"))
            .await
            .unwrap();

        let requests = raw.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for headers in requests.iter() {
            assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Bearer token");
            assert_eq!(headers.get(ACCEPT_ENCODING).unwrap(), "zstd, gzip");
        }
        assert_eq!(requests[1].get(COOKIE).unwrap(), "AWSALB=sticky");
    }

    #[tokio::test]
    async fn balanced_transport_builds_one_pool_per_distinct_origin() {
        let transport = BalancedHttp2Transport::new(
            [
                "http://one.internal/a".parse().unwrap(),
                "http://one.internal/b".parse().unwrap(),
                "http://two.internal/a".parse().unwrap(),
            ],
            BalancedHttp2Config::new(2, 32),
            None,
        )
        .unwrap();

        assert_eq!(transport.origin_count(), 2);
    }

    #[tokio::test]
    async fn balanced_transport_routes_by_request_origin() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let origins = HashMap::from([
            (
                RpcOrigin("http://ingest.internal".to_string()),
                ErasedClientTransport::new(NamedTransport {
                    name: "ingest",
                    calls: calls.clone(),
                }),
            ),
            (
                RpcOrigin("http://query.internal".to_string()),
                ErasedClientTransport::new(NamedTransport {
                    name: "query",
                    calls: calls.clone(),
                }),
            ),
        ]);
        let transport = BalancedHttp2Transport {
            origins: Arc::new(origins),
        };

        let _ = transport
            .send(request("http://query.internal/store.query.v1.Service/Get"))
            .await;
        let _ = transport
            .send(request("http://ingest.internal/log.ingest.v1.Service/Put"))
            .await;

        assert_eq!(*calls.lock().unwrap(), ["query", "ingest"]);
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
    fn merge_cookie_header_checks_opaque_cookie_names_before_appending_jar() {
        let mut headers = http::HeaderMap::new();
        // A Cookie value with an opaque value cannot be merged into a string, but its ASCII name is
        // still available from the raw header bytes.
        headers.append(
            COOKIE,
            http::HeaderValue::from_bytes(b"opaque=\xff\xfe").unwrap(),
        );
        headers.append(COOKIE, "caller=token".parse().unwrap());

        merge_cookie_header(&mut headers, "AWSALB=abc; opaque=jar; caller=jar");

        // The opaque and readable existing headers survive, and only the jar cookie that does not
        // collide with either existing name is appended as a separate Cookie header.
        let values: Vec<_> = headers
            .get_all(COOKIE)
            .iter()
            .map(|v| v.as_bytes().to_vec())
            .collect();
        assert_eq!(values.len(), 3);
        assert!(values.contains(&b"opaque=\xff\xfe".to_vec()));
        assert!(values.contains(&b"caller=token".to_vec()));
        assert!(values.contains(&b"AWSALB=abc".to_vec()));
        assert!(!values.contains(&b"opaque=jar".to_vec()));
    }

    #[test]
    fn authorization_is_set_when_absent() {
        let mut headers = http::HeaderMap::new();

        apply_authorization(&mut headers, &"Bearer client".parse().unwrap());

        assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Bearer client");
    }

    #[test]
    fn authorization_defers_to_the_caller() {
        let mut headers = http::HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer caller".parse().unwrap());

        apply_authorization(&mut headers, &"Bearer client".parse().unwrap());

        assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Bearer caller");
        assert_eq!(headers.get_all(AUTHORIZATION).iter().count(), 1);
    }

    #[test]
    fn no_credential_sends_no_authorization() {
        let client = PreferZstdHttpClient::plaintext();

        // A deployment with no load balancer in front of it must still be reachable.
        assert!(client.authorization().is_none());
    }
}
