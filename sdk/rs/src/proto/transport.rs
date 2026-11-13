//! Connect transport helpers for the store API.
//!
//! ## Registry
//!
//! Servers register **gzip** and **zstd** via [`connect_compression_registry`] (the codecs of
//! [`connectrpc::compression::CompressionRegistry::default`], with a faster zstd level and zstd
//! decompression sized from the frame header) so callers without zstd, such as Safari, can
//! still negotiate gzip.
//!
//! ## Server negotiation
//!
//! connectrpc answers in the first supported encoding the client lists. Browsers list gzip
//! before zstd, so [`PreferZstdLayer`] puts zstd first for any client that accepts it.
//!
//! ## Rust client transport
//!
//! HTTP and HTTPS transport that prefers zstd for the default response codecs.
//!
//! [`connectrpc::compression::CompressionRegistry::default`] builds the header value in sorted
//! order (`gzip, zstd`), so servers without [`PreferZstdLayer`] would negotiate **gzip** first.
//! [`PreferZstdHttpClient`] applies the same reordering as the layer to its own requests. Like
//! the layer, it only reorders encodings the client's registry listed, so a registry without
//! zstd never receives a zstd response.
//!
//! **Request bodies** (client -> server) use a single codec from connectrpc `compress_requests`.
//!
//! ## HTTP cookies
//!
//! [`PreferZstdHttpClient`] stores `Set-Cookie` response headers in an RFC6265 cookie store and
//! replays matching cookies on later requests. This covers edge affinity cookies as well as normal
//! domain, path, expiry, and deletion semantics.

use super::zstd_codec::ZstdCodec;
pub use bytes::Bytes;
use connectrpc::{compression::CompressionRegistry, Protocol};
use http::header::ACCEPT_ENCODING;
pub use http::{Request, Response};
pub use http_body::Body;
use std::task::{Context, Poll};

#[cfg(not(target_arch = "wasm32"))]
mod client;
#[cfg(not(target_arch = "wasm32"))]
pub use client::*;

/// zstd level for bodies this registry compresses, which are mostly query and stream
/// responses.
const ZSTD_LEVEL: i32 = -1;

/// gzip + zstd - used for [`connectrpc::ConnectRpcService::with_compression`] and
/// [`connectrpc::client::ClientConfig::compression`].
///
/// Its zstd codec decompresses into an exactly sized buffer. Registering connectrpc's own
/// `ZstdProvider` on top (to change the level, say) replaces that codec and its decompression.
#[must_use]
pub fn connect_compression_registry() -> CompressionRegistry {
    CompressionRegistry::default().register(ZstdCodec::with_level(ZSTD_LEVEL))
}

/// Makes a Connect server answer in zstd whenever the client accepts it.
///
/// connectrpc picks the first encoding in a request's `Accept-Encoding` (unary) or
/// `Connect-Accept-Encoding` (streaming) that the server supports. Browsers list gzip first, in
/// an order HTTP gives no meaning to and page scripts can't change, so they would get gzip even
/// when they also accept zstd. zstd is as small or smaller on our responses and far cheaper to
/// compress and decompress. This layer moves a bare `zstd` to the front of both headers so the
/// server's preference wins among the encodings the client accepts. The Connect protocol says
/// servers should follow the client's order, so this is a deliberate exception.
///
/// Requests that don't accept zstd, or already list a bare `zstd` first, pass through
/// unchanged. `Grpc-Accept-Encoding` is left alone: gRPC clients set it in code, so its order
/// is a real preference, and browsers can't speak plain gRPC.
///
/// Browsers decode zstd only with windows up to 8 MiB (RFC 9659).
/// [`connect_compression_registry`] compresses at zstd level -1, which keeps the window at or
/// below 512 KiB for any response size. Very high levels or long-distance matching would
/// exceed 8 MiB, and a test fails if the registry ever does.
#[derive(Clone, Copy, Debug, Default)]
pub struct PreferZstdLayer;

impl<S> tower::Layer<S> for PreferZstdLayer {
    type Service = PreferZstd<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PreferZstd { inner }
    }
}

/// Service produced by [`PreferZstdLayer`].
#[derive(Clone, Debug)]
pub struct PreferZstd<S> {
    inner: S,
}

impl<S, B> tower::Service<Request<B>> for PreferZstd<S>
where
    S: tower::Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        prefer_zstd_headers(request.headers_mut());
        self.inner.call(request)
    }
}

/// Puts an accepted zstd first in `Accept-Encoding` (unary) and `Connect-Accept-Encoding`
/// (streaming). Shared by [`PreferZstdLayer`] and [`PreferZstdHttpClient`].
fn prefer_zstd_headers(headers: &mut http::HeaderMap) {
    for name in [&ACCEPT_ENCODING, Protocol::Connect.accept_encoding_header()] {
        // connectrpc negotiates from the first value of each header.
        if let Some(value) = headers.get_mut(name) {
            if let Some(reordered) = prefer_zstd(value) {
                *value = reordered;
            }
        }
    }
}

/// `encodings` with a bare `zstd` first, or `None` when it already starts with one or doesn't
/// accept zstd. The other entries keep their order and parameters.
fn prefer_zstd(encodings: &http::HeaderValue) -> Option<http::HeaderValue> {
    let encodings = encodings.to_str().ok()?;
    let entries = encodings
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty());
    // Most requests need no change, so check before allocating.
    if entries.clone().next() == Some("zstd") || !entries.clone().any(accepts_zstd) {
        return None;
    }
    let mut reordered = String::with_capacity(encodings.len() + ", zstd".len());
    reordered.push_str("zstd");
    for entry in entries.filter(|entry| !is_zstd(entry)) {
        reordered.push_str(", ");
        reordered.push_str(entry);
    }
    http::HeaderValue::try_from(reordered).ok()
}

/// Whether one `Accept-Encoding` entry accepts zstd, at any weight except `q=0`.
fn accepts_zstd(entry: &str) -> bool {
    is_zstd(entry) && !entry.split(';').skip(1).any(is_zero_weight)
}

/// Whether one `Accept-Encoding` entry names zstd, whatever its parameters.
fn is_zstd(entry: &str) -> bool {
    coding(entry).eq_ignore_ascii_case("zstd")
}

/// Whether an `Accept-Encoding` parameter is `q=0`, which refuses its coding.
fn is_zero_weight(param: &str) -> bool {
    param.split_once('=').is_some_and(|(key, weight)| {
        key.trim().eq_ignore_ascii_case("q") && weight.trim().parse() == Ok(0.0_f32)
    })
}

/// The coding name of one `Accept-Encoding` entry, without its parameters.
fn coding(entry: &str) -> &str {
    entry.split(';').next().unwrap_or_default().trim()
}
