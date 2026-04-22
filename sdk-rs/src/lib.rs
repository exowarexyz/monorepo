//! Store Rust SDK Client.
//!
//! Provides typed access to the store put/get/query APIs plus
//! plain HTTP health/readiness probes.
//!
//! ## Errors
//!
//! RPC failures surface as [`ClientError::Rpc`] carrying a native [`ConnectError`]. Use
//! [`ClientError::decoded_rpc_error`] or [`StoreClient::decode_error_details`] to unpack
//! protobuf `google.rpc` details (and `store.query.v1.Detail` on query RPC errors), not string parsing.
//! Idempotent reads honor `google.rpc.RetryInfo` when deciding backoff (see `retry_delay_for_error`).

pub mod keys;
pub mod kv_codec;
pub mod match_key;
pub mod proto;
pub mod prune_policy;
pub mod stream_filter;
pub use keys::{Key, KeyCodec, KeyCodecError, KeyMut, KeyValidationError, Value, MAX_KEY_LEN};
pub use proto::*;
extern crate self as exoware_proto;

use bytes::Bytes;
use connectrpc::client::{ClientConfig, ServerStream as ConnectServerStream};
use connectrpc::{ConnectError, ErrorCode};
use exoware_proto::compact::ServiceClient as CompactServiceClient;
use exoware_proto::ingest::ServiceClient as IngestServiceClient;
use exoware_proto::query as proto_query;
use exoware_proto::query::ServiceClient as QueryServiceClient;
use exoware_proto::store::compact::v1::PruneRequest as ProtoPruneRequest;
use exoware_proto::store::ingest::v1::PutRequest as ProtoPutRequest;
use exoware_proto::store::query::v1::{
    GetManyRequest as ProtoGetManyRequest, GetRequest as ProtoGetRequest,
    RangeRequest as ProtoRangeRequest, ReduceRequest as ProtoWireReduceRequest,
};
use exoware_proto::RangeReduceRequest as DomainRangeReduceRequest;
use exoware_proto::{
    connect_compression_registry as proto_connect_compression_registry,
    decode_connect_error as proto_decode_connect_error,
    decode_query_detail_header_value as proto_decode_query_detail_header_value,
    to_domain_reduce_response as proto_to_domain_reduce_response,
    to_proto_reduce_params as proto_to_proto_reduce_params,
    PreferZstdHttpClient as ProtoPreferZstdHttpClient,
    QUERY_DETAIL_RESPONSE_HEADER as PROTO_QUERY_DETAIL_RESPONSE_HEADER,
};
use http::HeaderMap;
use keys::is_valid_key_size;
use kv_codec::KvReducedValue;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

const DEFAULT_RETRY_MAX_ATTEMPTS: usize = 3;
const DEFAULT_RETRY_INITIAL_BACKOFF_MS: u64 = 100;
const DEFAULT_RETRY_MAX_BACKOFF_MS: u64 = 2_000;

/// Codec used to compress **outgoing** RPC request bodies when compression applies.
///
/// connectrpc `ClientConfig::compress_requests` accepts a single encoding name; there is no
/// HTTP-style negotiation list for requests. Prefer [`Zstd`](Self::Zstd); use [`Gzip`](Self::Gzip)
/// when talking to a peer that only accepts gzip-compressed requests. Response decompression still
/// follows [`PreferZstdHttpClient`] and the shared [`connect_compression_registry`].
///
/// To drive this from configuration or environment variables, map your setting to this enum and
/// pass it to [`StoreClientBuilder::connect_request_compression`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConnectRequestCompression {
    /// `compress_requests("zstd")`.
    #[default]
    Zstd,
    /// `compress_requests("gzip")`.
    Gzip,
}

impl ConnectRequestCompression {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Zstd => "zstd",
            Self::Gzip => "gzip",
        }
    }
}

/// Default max decompressed RPC message size for client decode (matches the query worker).
///
/// The underlying client uses 4 MiB unless configured; large `Range` frames need headroom.
/// The store simulator uses the same 256 MiB cap for large `Range` frames.
const STORE_CLIENT_MAX_MESSAGE_BYTES: usize = 256 * 1024 * 1024;

/// Store client defaults: [`connect_compression_registry`] for codecs;
/// [`PreferZstdHttpClient`] sets `Accept-Encoding: zstd, gzip` on responses.
///
/// Request body compression uses [`ConnectRequestCompression`] (default zstd); connectrpc only
/// supports one request encoding per config (see [`ConnectRequestCompression`]).
fn store_connect_client_config(
    base_uri: http::Uri,
    request_compression: ConnectRequestCompression,
) -> ClientConfig {
    ClientConfig::new(base_uri)
        .compression(proto_connect_compression_registry())
        .compress_requests(request_compression.wire_name())
        .default_max_message_size(STORE_CLIENT_MAX_MESSAGE_BYTES)
}

/// Store client error.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("RPC error ({0})")]
    Rpc(Box<ConnectError>),
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("wire format error: {0}")]
    WireFormat(String),
}

impl ClientError {
    pub fn rpc_error(&self) -> Option<&ConnectError> {
        match self {
            Self::Rpc(err) => Some(err.as_ref()),
            _ => None,
        }
    }

    pub fn rpc_code(&self) -> Option<ErrorCode> {
        self.rpc_error().map(|err| err.code)
    }

    pub fn decoded_rpc_error(
        &self,
    ) -> Result<Option<exoware_proto::DecodedConnectError>, buffa::DecodeError> {
        self.rpc_error().map(proto_decode_connect_error).transpose()
    }
}

/// Traversal mode for range queries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeMode {
    Forward,
    Reverse,
}

/// Iterator-like async range stream.
pub struct RangeStream {
    stream:
        ConnectServerStream<hyper::body::Incoming, exoware_proto::query::RangeFrameView<'static>>,
    pending_frame: Option<exoware_proto::query::RangeFrame>,
    rows_seen: usize,
    final_count: Option<usize>,
    final_detail: Option<proto_query::Detail>,
    finished: bool,
    observed_sequence: Option<Arc<AtomicU64>>,
}

impl RangeStream {
    fn from_connect_stream(
        stream: ConnectServerStream<
            hyper::body::Incoming,
            exoware_proto::query::RangeFrameView<'static>,
        >,
        observed_sequence: Option<Arc<AtomicU64>>,
    ) -> Self {
        Self {
            stream,
            pending_frame: None,
            rows_seen: 0,
            final_count: None,
            final_detail: None,
            finished: false,
            observed_sequence,
        }
    }

    pub fn final_count(&self) -> Option<usize> {
        self.final_count
    }

    pub fn final_detail(&self) -> Option<proto_query::Detail> {
        self.final_detail.clone()
    }

    fn observe_detail_from_stream_trailers(&mut self) {
        self.final_detail = self
            .stream
            .trailers()
            .and_then(query_detail_from_header_map);
        if let (Some(sequence_store), Some(d)) =
            (&self.observed_sequence, self.final_detail.as_ref())
        {
            sequence_store.fetch_max(d.sequence_number, Ordering::SeqCst);
        }
    }

    async fn prefetch_first_frame(&mut self) -> Result<(), ConnectError> {
        if self.pending_frame.is_some() || self.finished {
            return Ok(());
        }
        match self.stream.message().await? {
            Some(frame) => {
                self.pending_frame = Some(frame.to_owned_message());
                Ok(())
            }
            None => {
                self.finished = true;
                if let Some(err) = self.stream.error() {
                    Err(err.clone())
                } else {
                    self.final_count = Some(self.rows_seen);
                    self.observe_detail_from_stream_trailers();
                    Ok(())
                }
            }
        }
    }

    pub async fn next_chunk(&mut self) -> Result<Option<Vec<(Key, Bytes)>>, ClientError> {
        if self.finished {
            return Ok(None);
        }

        let frame = if let Some(frame) = self.pending_frame.take() {
            frame
        } else {
            let Some(frame) = self
                .stream
                .message()
                .await
                .map_err(client_error_from_connect)?
            else {
                self.finished = true;
                if let Some(err) = self.stream.error() {
                    return Err(client_error_from_connect(err.clone()));
                }
                self.final_count = Some(self.rows_seen);
                self.observe_detail_from_stream_trailers();
                return Ok(None);
            };
            frame.to_owned_message()
        };

        let n = frame.results.len();
        self.rows_seen += n;
        Ok(Some(
            frame
                .results
                .iter()
                .map(|entry| {
                    (
                        Bytes::copy_from_slice(&entry.key),
                        Bytes::copy_from_slice(&entry.value),
                    )
                })
                .collect(),
        ))
    }

    pub async fn collect(mut self) -> Result<Vec<(Key, Bytes)>, ClientError> {
        let mut entries = Vec::new();
        while let Some(chunk) = self.next_chunk().await? {
            entries.extend(chunk);
        }
        Ok(entries)
    }
}

pub struct GetManyStream {
    stream:
        ConnectServerStream<hyper::body::Incoming, exoware_proto::query::GetManyFrameView<'static>>,
    pending_frame: Option<exoware_proto::query::GetManyFrame>,
    entries_seen: usize,
    final_detail: Option<proto_query::Detail>,
    finished: bool,
    observed_sequence: Option<Arc<AtomicU64>>,
}

impl GetManyStream {
    pub fn final_detail(&self) -> Option<proto_query::Detail> {
        self.final_detail.clone()
    }

    fn from_connect_stream(
        stream: ConnectServerStream<
            hyper::body::Incoming,
            exoware_proto::query::GetManyFrameView<'static>,
        >,
        observed_sequence: Option<Arc<AtomicU64>>,
    ) -> Self {
        Self {
            stream,
            pending_frame: None,
            entries_seen: 0,
            final_detail: None,
            finished: false,
            observed_sequence,
        }
    }

    fn observe_detail_from_stream_trailers(&mut self) {
        self.final_detail = self
            .stream
            .trailers()
            .and_then(query_detail_from_header_map);
        if let (Some(sequence_store), Some(d)) =
            (&self.observed_sequence, self.final_detail.as_ref())
        {
            sequence_store.fetch_max(d.sequence_number, Ordering::SeqCst);
        }
    }

    async fn prefetch_first_frame(&mut self) -> Result<(), ConnectError> {
        if self.pending_frame.is_some() || self.finished {
            return Ok(());
        }
        match self.stream.message().await? {
            Some(frame) => {
                self.pending_frame = Some(frame.to_owned_message());
                Ok(())
            }
            None => {
                self.finished = true;
                if let Some(err) = self.stream.error() {
                    Err(err.clone())
                } else {
                    self.observe_detail_from_stream_trailers();
                    Ok(())
                }
            }
        }
    }

    pub async fn next_chunk(&mut self) -> Result<Option<Vec<(Key, Option<Bytes>)>>, ClientError> {
        if self.finished {
            return Ok(None);
        }
        let frame = if let Some(frame) = self.pending_frame.take() {
            frame
        } else {
            let Some(frame) = self
                .stream
                .message()
                .await
                .map_err(client_error_from_connect)?
            else {
                self.finished = true;
                if let Some(err) = self.stream.error() {
                    return Err(client_error_from_connect(err.clone()));
                }
                self.observe_detail_from_stream_trailers();
                return Ok(None);
            };
            frame.to_owned_message()
        };

        self.entries_seen += frame.results.len();
        Ok(Some(
            frame
                .results
                .iter()
                .map(|entry| {
                    let key = Bytes::copy_from_slice(&entry.key);
                    let value = entry.value.as_ref().map(|v| Bytes::copy_from_slice(v));
                    (key, value)
                })
                .collect(),
        ))
    }

    pub async fn collect(mut self) -> Result<HashMap<Key, Bytes>, ClientError> {
        let mut map = HashMap::new();
        while let Some(chunk) = self.next_chunk().await? {
            for (key, value) in chunk {
                if let Some(v) = value {
                    map.insert(key, v);
                }
            }
        }
        Ok(map)
    }
}

impl RangeMode {
    fn to_proto(self) -> proto_query::TraversalMode {
        match self {
            Self::Forward => proto_query::TraversalMode::TRAVERSAL_MODE_FORWARD,
            Self::Reverse => proto_query::TraversalMode::TRAVERSAL_MODE_REVERSE,
        }
    }
}

/// One delivered (key, value) row from a stream subscription. The client
/// reapplies its own filter if it needs to know which match_key matched —
/// the wire frame doesn't carry the index.
#[derive(Clone, Debug)]
pub struct StreamSubscriptionEntry {
    pub key: Key,
    pub value: Bytes,
}

/// One atomic Put batch delivered to a subscriber.
#[derive(Clone, Debug)]
pub struct StreamSubscriptionFrame {
    pub sequence_number: u64,
    pub entries: Vec<StreamSubscriptionEntry>,
}

/// Async stream of `StreamSubscriptionFrame`. Backed by the generated
/// connectrpc server stream.
pub struct StreamSubscription {
    stream: ConnectServerStream<
        hyper::body::Incoming,
        exoware_proto::store::stream::v1::SubscribeResponseView<'static>,
    >,
}

impl std::fmt::Debug for StreamSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamSubscription").finish_non_exhaustive()
    }
}

impl StreamSubscription {
    /// Pull the next frame. `Ok(None)` = server closed the stream cleanly.
    pub async fn next(&mut self) -> Result<Option<StreamSubscriptionFrame>, ClientError> {
        match self
            .stream
            .message()
            .await
            .map_err(client_error_from_connect)?
        {
            Some(view) => {
                let owned = view.to_owned_message();
                let frame = StreamSubscriptionFrame {
                    sequence_number: owned.sequence_number,
                    entries: owned
                        .entries
                        .into_iter()
                        .map(|e| StreamSubscriptionEntry {
                            key: Bytes::from(e.key),
                            value: Bytes::from(e.value),
                        })
                        .collect(),
                };
                Ok(Some(frame))
            }
            None => {
                if let Some(err) = self.stream.error() {
                    Err(client_error_from_connect(err.clone()))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

/// Inspect a Connect error for `store.stream.BATCH_EVICTED` / `BATCH_NOT_FOUND`
/// `ErrorInfo` details. Used by `get_batch` to collapse both into `Ok(None)`.
fn is_batch_missing_error(err: &ConnectError) -> bool {
    match proto_decode_connect_error(err) {
        Ok(decoded) => decoded.error_info.is_some_and(|info| {
            info.domain == "store.stream"
                && matches!(info.reason.as_str(), "BATCH_EVICTED" | "BATCH_NOT_FOUND")
        }),
        Err(_) => false,
    }
}

/// Retry policy for idempotent read operations.
#[derive(Clone, Copy, Debug)]
pub struct RetryConfig {
    max_attempts: usize,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl RetryConfig {
    pub fn standard() -> Self {
        Self {
            max_attempts: DEFAULT_RETRY_MAX_ATTEMPTS,
            initial_backoff: Duration::from_millis(DEFAULT_RETRY_INITIAL_BACKOFF_MS),
            max_backoff: Duration::from_millis(DEFAULT_RETRY_MAX_BACKOFF_MS),
        }
    }

    pub fn disabled() -> Self {
        Self::standard().with_max_attempts(1)
    }

    pub fn with_max_attempts(mut self, max_attempts: usize) -> Self {
        self.max_attempts = max_attempts.max(1);
        self
    }

    pub fn with_initial_backoff(mut self, initial_backoff: Duration) -> Self {
        self.initial_backoff = initial_backoff;
        self
    }

    pub fn with_max_backoff(mut self, max_backoff: Duration) -> Self {
        self.max_backoff = max_backoff;
        self
    }

    pub(crate) fn sanitized(self) -> Self {
        let max_attempts = self.max_attempts.max(1);
        let max_backoff = self.max_backoff.max(self.initial_backoff);
        Self {
            max_attempts,
            initial_backoff: self.initial_backoff,
            max_backoff,
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self::standard()
    }
}

fn trim_connect_base(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

fn query_detail_from_header_map(map: &HeaderMap) -> Option<proto_query::Detail> {
    let v = map.get(PROTO_QUERY_DETAIL_RESPONSE_HEADER)?;
    let s = v.to_str().ok()?;
    proto_decode_query_detail_header_value(s).ok()
}

fn query_detail_from_unary_metadata(
    headers: &HeaderMap,
    trailers: &HeaderMap,
) -> Option<proto_query::Detail> {
    query_detail_from_header_map(headers).or_else(|| query_detail_from_header_map(trailers))
}

fn new_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .pool_max_idle_per_host(32)
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client")
}

/// Error returned when [`StoreClientBuilder`] is missing a required endpoint URL.
#[derive(Debug, thiserror::Error)]
pub enum ClientBuildError {
    #[error("StoreClientBuilder: missing health URL (set health_url or url)")]
    MissingHealthUrl,
    #[error("StoreClientBuilder: missing ingest URL (set ingest_url or url)")]
    MissingIngestUrl,
    #[error("StoreClientBuilder: missing query URL (set query_url or url)")]
    MissingQueryUrl,
    #[error("StoreClientBuilder: missing compact URL (set compact_url or url)")]
    MissingCompactUrl,
    #[error("StoreClientBuilder: invalid URL \"{url}\": {source}")]
    InvalidUrl {
        url: String,
        source: http::uri::InvalidUri,
    },
}

/// Configures a [`StoreClient`] with explicit bases for health probes and store services.
///
/// Use [`StoreClient::builder()`] to construct. Call [`Self::url`] to point health, ingest, and
/// query at the same origin, or set each base separately. Finish with [`Self::build`].
#[derive(Debug, Default)]
pub struct StoreClientBuilder {
    health_url: Option<String>,
    ingest_url: Option<String>,
    query_url: Option<String>,
    compact_url: Option<String>,
    stream_url: Option<String>,
    retry_config: RetryConfig,
    connect_request_compression: ConnectRequestCompression,
}

impl StoreClientBuilder {
    /// Sets the same base URL for all services (health, ingest, query, compact, stream).
    pub fn url(mut self, url: &str) -> Self {
        let u = trim_connect_base(url);
        self.health_url = Some(u.clone());
        self.ingest_url = Some(u.clone());
        self.query_url = Some(u.clone());
        self.compact_url = Some(u.clone());
        self.stream_url = Some(u);
        self
    }

    /// Base URL for plain HTTP `GET /health` and `GET /ready` (often the query worker).
    pub fn health_url(mut self, url: &str) -> Self {
        self.health_url = Some(trim_connect_base(url));
        self
    }

    /// Base URL for the ingest service (`store.ingest.v1.Service`).
    pub fn ingest_url(mut self, url: &str) -> Self {
        self.ingest_url = Some(trim_connect_base(url));
        self
    }

    /// Base URL for the query service (`store.query.v1.Service`).
    pub fn query_url(mut self, url: &str) -> Self {
        self.query_url = Some(trim_connect_base(url));
        self
    }

    /// Base URL for the compact service (`store.compact.v1.Service`).
    pub fn compact_url(mut self, url: &str) -> Self {
        self.compact_url = Some(trim_connect_base(url));
        self
    }

    /// Base URL for the stream service (`store.stream.v1.Service`). Defaults
    /// to the ingest base when not set explicitly.
    pub fn stream_url(mut self, url: &str) -> Self {
        self.stream_url = Some(trim_connect_base(url));
        self
    }

    /// Retry policy for idempotent read operations (get / range / reduce).
    pub fn retry_config(mut self, retry: RetryConfig) -> Self {
        self.retry_config = retry.sanitized();
        self
    }

    /// Codec for compressing **outgoing** RPC request bodies (default [`ConnectRequestCompression::Zstd`]).
    pub fn connect_request_compression(mut self, compression: ConnectRequestCompression) -> Self {
        self.connect_request_compression = compression;
        self
    }

    /// Build the client, or return an error if any required URL was not set.
    pub fn build(self) -> Result<StoreClient, ClientBuildError> {
        let health_url = self.health_url.ok_or(ClientBuildError::MissingHealthUrl)?;
        let ingest_url = self.ingest_url.ok_or(ClientBuildError::MissingIngestUrl)?;
        let query_url = self.query_url.ok_or(ClientBuildError::MissingQueryUrl)?;
        let compact_url = self
            .compact_url
            .ok_or(ClientBuildError::MissingCompactUrl)?;
        // Stream defaults to ingest when not explicitly configured; they
        // share the same origin in the reference simulator.
        let stream_url = self.stream_url.unwrap_or_else(|| ingest_url.clone());
        let ingest_uri: http::Uri =
            ingest_url
                .parse()
                .map_err(|e| ClientBuildError::InvalidUrl {
                    url: ingest_url.clone(),
                    source: e,
                })?;
        let query_uri: http::Uri = query_url
            .parse()
            .map_err(|e| ClientBuildError::InvalidUrl {
                url: query_url.clone(),
                source: e,
            })?;
        let compact_uri: http::Uri =
            compact_url
                .parse()
                .map_err(|e| ClientBuildError::InvalidUrl {
                    url: compact_url.clone(),
                    source: e,
                })?;
        let stream_uri: http::Uri =
            stream_url
                .parse()
                .map_err(|e| ClientBuildError::InvalidUrl {
                    url: stream_url.clone(),
                    source: e,
                })?;
        Ok(StoreClient {
            health_url,
            ingest_uri,
            query_uri,
            compact_uri,
            stream_uri,
            http: new_http_client(),
            connect_http: ProtoPreferZstdHttpClient::plaintext(),
            retry_config: self.retry_config,
            connect_request_compression: self.connect_request_compression,
        })
    }
}

/// Typed Rust client for Store.
#[derive(Clone, Debug)]
pub struct StoreClient {
    /// Base URL for `health()` / `ready()` (typically the query worker).
    pub(crate) health_url: String,
    ingest_uri: http::Uri,
    query_uri: http::Uri,
    compact_uri: http::Uri,
    stream_uri: http::Uri,
    http: reqwest::Client,
    connect_http: ProtoPreferZstdHttpClient,
    retry_config: RetryConfig,
    connect_request_compression: ConnectRequestCompression,
}

/// A session that enforces monotonic read consistency via a fixed `min_sequence_number` floor.
///
/// `StoreClient` itself does not retain any client-global observed sequence.
/// Plain query reads are stateless unless the caller passes an explicit
/// `min_sequence_number`.
///
/// A `SerializableReadSession` is the explicit consistency mechanism. The first
/// successful unary read seeds the session from the server-reported sequence,
/// and every later read passes that fixed floor so the server guarantees all
/// responses reflect at least that point in the write log.
///
/// Streamed query reads (`get_many`, `range_stream`) only expose their final
/// sequence in stream trailers, so if one of those is the first successful
/// read, the session is not pinned until that stream is fully drained.
#[derive(Clone, Debug)]
pub struct SerializableReadSession {
    client: StoreClient,
    state: Arc<SessionState>,
}

#[derive(Debug)]
struct SessionState {
    sequence: Arc<AtomicU64>,
    init_gate: tokio::sync::Mutex<()>,
}

impl SessionState {
    fn fixed_sequence(&self) -> Option<u64> {
        let sequence = self.sequence.load(Ordering::Acquire);
        (sequence > 0).then_some(sequence)
    }
}

#[derive(Default)]
struct RangeStreamReadOptions {
    min_sequence_number: Option<u64>,
    observed_sequence: Option<Arc<AtomicU64>>,
}

impl StoreClient {
    /// Start building a client with per-service base URLs.
    pub fn builder() -> StoreClientBuilder {
        StoreClientBuilder::default()
    }

    pub fn new(url: &str) -> Self {
        Self::with_retry_config(url, RetryConfig::standard())
    }

    pub fn with_retry_config(url: &str, retry_config: RetryConfig) -> Self {
        Self::builder()
            .url(url)
            .retry_config(retry_config)
            .build()
            .expect("url sets health, ingest, and query URLs")
    }

    /// Split endpoints for deployments where services run on different ports or hosts.
    pub fn with_split_urls(
        health_base: &str,
        ingest_base: &str,
        query_base: &str,
        compact_base: &str,
    ) -> Self {
        Self::with_split_urls_and_retry(
            health_base,
            ingest_base,
            query_base,
            compact_base,
            RetryConfig::standard(),
        )
    }

    pub fn with_split_urls_and_retry(
        health_base: &str,
        ingest_base: &str,
        query_base: &str,
        compact_base: &str,
        retry_config: RetryConfig,
    ) -> Self {
        Self::builder()
            .health_url(health_base)
            .ingest_url(ingest_base)
            .query_url(query_base)
            .compact_url(compact_base)
            .retry_config(retry_config)
            .build()
            .expect("all service URLs are set")
    }

    /// Outgoing Connect request body compression (see [`ConnectRequestCompression`]).
    pub fn connect_request_compression(&self) -> ConnectRequestCompression {
        self.connect_request_compression
    }

    pub fn decode_error_details(
        err: &ConnectError,
    ) -> Result<exoware_proto::DecodedConnectError, buffa::DecodeError> {
        proto_decode_connect_error(err)
    }

    /// Create an unseeded serializable read session.
    ///
    /// The first successful unary read fixes the session's sequence floor from
    /// the server response. Streamed query reads fix that floor only once their
    /// trailers arrive.
    pub fn create_session(&self) -> SerializableReadSession {
        self.create_session_with_sequence(0)
    }

    /// Create a serializable read session pinned to at least `sequence`.
    ///
    /// This is intended for stream-driven read paths that already observed a
    /// concrete store batch sequence and need follow-up query/proof reads to
    /// see at least that sequence.
    pub fn create_session_with_sequence(&self, sequence: u64) -> SerializableReadSession {
        SerializableReadSession {
            client: self.clone(),
            state: Arc::new(SessionState {
                sequence: Arc::new(AtomicU64::new(sequence)),
                init_gate: tokio::sync::Mutex::new(()),
            }),
        }
    }

    /// Typed access to the `store.ingest.v1` service.
    pub fn ingest(&self) -> Ingest<'_> {
        Ingest { c: self }
    }

    /// Typed access to the `store.query.v1` service.
    pub fn query(&self) -> Query<'_> {
        Query { c: self }
    }

    /// Typed access to the `store.compact.v1` service.
    pub fn compact(&self) -> Compact<'_> {
        Compact { c: self }
    }

    /// Typed access to the `store.stream.v1` service.
    pub fn stream(&self) -> Stream<'_> {
        Stream { c: self }
    }

    /// Submit a KV batch via Connect `Put`.
    ///
    /// On success returns the **store sequence number** from the response. Use it for immediate
    /// `get_with_min_sequence_number` / range calls or to seed
    /// [`Self::create_session_with_sequence`].
    /// If the request succeeds, the server accepts the full batch (count is `kvs.len()`).
    pub(crate) async fn put(&self, kvs: &[(&Key, &[u8])]) -> Result<u64, ClientError> {
        let mut proto_kvs = Vec::with_capacity(kvs.len());
        for (key, value) in kvs {
            if !is_valid_key_size(key.len()) {
                return Err(ClientError::WireFormat(format!(
                    "key length {} is outside valid store key range ({}..={})",
                    key.len(),
                    keys::MIN_KEY_LEN,
                    MAX_KEY_LEN
                )));
            }
            proto_kvs.push(exoware_proto::common::KvEntry {
                key: (*key).to_vec(),
                value: value.to_vec(),
                ..Default::default()
            });
        }

        let config =
            store_connect_client_config(self.ingest_uri.clone(), self.connect_request_compression);
        let client = IngestServiceClient::new(self.connect_http.clone(), config);
        let response = client
            .put(ProtoPutRequest {
                kvs: proto_kvs,
                ..Default::default()
            })
            .await
            .map_err(client_error_from_connect)?;
        Ok(response.into_owned().sequence_number)
    }

    pub(crate) async fn get(&self, key: &Key) -> Result<Option<Bytes>, ClientError> {
        self.get_internal(key, None).await
    }

    pub(crate) async fn get_with_min_sequence_number(
        &self,
        key: &Key,
        min_sequence_number: u64,
    ) -> Result<Option<Bytes>, ClientError> {
        self.get_internal(key, Some(min_sequence_number)).await
    }

    async fn get_internal(
        &self,
        key: &Key,
        min_sequence_number: Option<u64>,
    ) -> Result<Option<Bytes>, ClientError> {
        let (response, detail) = self
            .send_get(key, self.normalize_min_sequence_number(min_sequence_number))
            .await?;
        let _ = detail;
        Ok(response.value.map(Bytes::from))
    }

    pub(crate) async fn get_many(
        &self,
        keys: &[&Key],
        batch_size: u32,
    ) -> Result<GetManyStream, ClientError> {
        self.get_many_internal(keys, batch_size, None, None).await
    }

    pub(crate) async fn get_many_with_min_sequence_number(
        &self,
        keys: &[&Key],
        batch_size: u32,
        min_sequence_number: u64,
    ) -> Result<GetManyStream, ClientError> {
        self.get_many_internal(keys, batch_size, Some(min_sequence_number), None)
            .await
    }

    async fn get_many_internal(
        &self,
        keys: &[&Key],
        batch_size: u32,
        min_sequence_number: Option<u64>,
        observed_sequence: Option<Arc<AtomicU64>>,
    ) -> Result<GetManyStream, ClientError> {
        for key in keys {
            if !is_valid_key_size(key.len()) {
                return Err(ClientError::WireFormat(format!(
                    "key length {} is outside valid store key range ({}..={})",
                    key.len(),
                    keys::MIN_KEY_LEN,
                    MAX_KEY_LEN
                )));
            }
        }

        let config =
            store_connect_client_config(self.query_uri.clone(), self.connect_request_compression);
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
        let proto_keys: Vec<Vec<u8>> = keys.iter().map(|k| k.to_vec()).collect();
        let effective_min = self.normalize_min_sequence_number(min_sequence_number);
        let max_attempts = self.retry_config.max_attempts.max(1);
        let mut attempt = 1usize;
        loop {
            match client
                .get_many(ProtoGetManyRequest {
                    keys: proto_keys.clone(),
                    min_sequence_number: effective_min,
                    batch_size,
                    ..Default::default()
                })
                .await
            {
                Ok(stream) => {
                    let mut gms =
                        GetManyStream::from_connect_stream(stream, observed_sequence.clone());
                    if let Err(err) = gms.prefetch_first_frame().await {
                        if attempt < max_attempts && is_retryable_error(&err) {
                            let delay = retry_delay_for_error(&err, attempt, self.retry_config);
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        }
                        return Err(client_error_from_connect(err));
                    }
                    return Ok(gms);
                }
                Err(err) => {
                    if attempt < max_attempts && is_retryable_error(&err) {
                        let delay = retry_delay_for_error(&err, attempt, self.retry_config);
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(client_error_from_connect(err));
                }
            }
        }
    }

    /// Key range is inclusive: `start <= key <= end` when `end` is non-empty; empty `end` is
    /// unbounded above (matches `store.query.v1.RangeRequest`).
    pub(crate) async fn range(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_internal(start, end, limit, RangeMode::Forward, None)
            .await
    }

    /// See [`StoreClient::range`] for `end` semantics.
    pub(crate) async fn range_with_mode(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_internal(start, end, limit, mode, None).await
    }

    pub(crate) async fn range_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        min_sequence_number: u64,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_internal(
            start,
            end,
            limit,
            RangeMode::Forward,
            Some(min_sequence_number),
        )
        .await
    }

    pub(crate) async fn range_with_mode_and_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
        min_sequence_number: u64,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_internal(start, end, limit, mode, Some(min_sequence_number))
            .await
    }

    pub(crate) async fn range_stream(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
    ) -> Result<RangeStream, ClientError> {
        self.range_stream_internal(
            start,
            end,
            limit,
            batch_size,
            RangeMode::Forward,
            RangeStreamReadOptions::default(),
        )
        .await
    }

    pub(crate) async fn range_stream_with_mode(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        mode: RangeMode,
    ) -> Result<RangeStream, ClientError> {
        self.range_stream_internal(start, end, limit, batch_size, mode, Default::default())
            .await
    }

    pub(crate) async fn range_stream_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        min_sequence_number: u64,
    ) -> Result<RangeStream, ClientError> {
        self.range_stream_internal(
            start,
            end,
            limit,
            batch_size,
            RangeMode::Forward,
            RangeStreamReadOptions {
                min_sequence_number: Some(min_sequence_number),
                observed_sequence: None,
            },
        )
        .await
    }

    pub(crate) async fn range_stream_with_mode_and_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        mode: RangeMode,
        min_sequence_number: u64,
    ) -> Result<RangeStream, ClientError> {
        self.range_stream_internal(
            start,
            end,
            limit,
            batch_size,
            mode,
            RangeStreamReadOptions {
                min_sequence_number: Some(min_sequence_number),
                observed_sequence: None,
            },
        )
        .await
    }

    pub(crate) async fn range_reduce(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<Vec<Option<KvReducedValue>>, ClientError> {
        let (response, _) = self
            .range_reduce_response_internal(start, end, request, None)
            .await?;
        let decoded = proto_to_domain_reduce_response(response).map_err(ClientError::WireFormat)?;
        if !decoded.groups.is_empty() {
            return Err(ClientError::WireFormat(
                "grouped range reduction response returned for scalar request".to_string(),
            ));
        }
        Ok(decoded
            .results
            .iter()
            .map(|result| result.value.clone())
            .collect())
    }

    pub(crate) async fn range_reduce_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
        min_sequence_number: u64,
    ) -> Result<Vec<Option<KvReducedValue>>, ClientError> {
        let (response, _) = self
            .range_reduce_response_internal(start, end, request, Some(min_sequence_number))
            .await?;
        let decoded = proto_to_domain_reduce_response(response).map_err(ClientError::WireFormat)?;
        if !decoded.groups.is_empty() {
            return Err(ClientError::WireFormat(
                "grouped range reduction response returned for scalar request".to_string(),
            ));
        }
        Ok(decoded
            .results
            .iter()
            .map(|result| result.value.clone())
            .collect())
    }

    pub(crate) async fn range_reduce_response(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<exoware_proto::query::ReduceResponse, ClientError> {
        let (body, _) = self
            .range_reduce_response_internal(start, end, request, None)
            .await?;
        Ok(body)
    }

    pub(crate) async fn range_reduce_response_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
        min_sequence_number: u64,
    ) -> Result<exoware_proto::query::ReduceResponse, ClientError> {
        let (body, _) = self
            .range_reduce_response_internal(start, end, request, Some(min_sequence_number))
            .await?;
        Ok(body)
    }

    pub(crate) async fn prune(
        &self,
        policies: &[crate::prune_policy::PrunePolicy],
    ) -> Result<(), ClientError> {
        let config =
            store_connect_client_config(self.compact_uri.clone(), self.connect_request_compression);
        let client = CompactServiceClient::new(self.connect_http.clone(), config);
        client
            .prune(ProtoPruneRequest {
                policies: exoware_proto::prune_policies_to_proto(policies),
                ..Default::default()
            })
            .await
            .map_err(client_error_from_connect)?;
        Ok(())
    }

    pub async fn health(&self) -> Result<bool, ClientError> {
        let resp = self
            .http
            .get(format!("{}/health", self.health_url))
            .send()
            .await?;
        Ok(resp.status().is_success())
    }

    pub async fn ready(&self) -> Result<bool, ClientError> {
        let resp = self
            .http
            .get(format!("{}/ready", self.health_url))
            .send()
            .await?;
        Ok(resp.status().is_success())
    }

    fn normalize_min_sequence_number(&self, requested_sequence: Option<u64>) -> Option<u64> {
        requested_sequence.filter(|sequence| *sequence > 0)
    }

    async fn send_get(
        &self,
        key: &Key,
        min_sequence_number: Option<u64>,
    ) -> Result<
        (
            exoware_proto::query::GetResponse,
            Option<proto_query::Detail>,
        ),
        ClientError,
    > {
        if !is_valid_key_size(key.len()) {
            return Err(ClientError::WireFormat(format!(
                "key length {} is outside valid store key range ({}..={})",
                key.len(),
                keys::MIN_KEY_LEN,
                MAX_KEY_LEN
            )));
        }

        let config =
            store_connect_client_config(self.query_uri.clone(), self.connect_request_compression);
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
        let response = self
            .send_with_retry(|| async {
                client
                    .get(ProtoGetRequest {
                        key: key.to_vec(),
                        min_sequence_number,
                        ..Default::default()
                    })
                    .await
            })
            .await?;
        let detail = query_detail_from_unary_metadata(response.headers(), response.trailers());
        let owned = response.into_owned();
        Ok((owned, detail))
    }

    #[cfg(test)]
    pub async fn send_get_for_tests(
        &self,
        key: &Key,
        min_sequence_number: Option<u64>,
    ) -> Result<
        (
            exoware_proto::query::GetResponse,
            Option<proto_query::Detail>,
        ),
        ClientError,
    > {
        self.send_get(key, min_sequence_number).await
    }

    async fn range_internal(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
        min_sequence_number: Option<u64>,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        let stream = self
            .range_stream_internal(
                start,
                end,
                limit,
                limit.max(1),
                mode,
                RangeStreamReadOptions {
                    min_sequence_number,
                    observed_sequence: None,
                },
            )
            .await?;
        stream.collect().await
    }

    async fn range_stream_internal(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        mode: RangeMode,
        options: RangeStreamReadOptions,
    ) -> Result<RangeStream, ClientError> {
        if !is_valid_key_size(start.len()) || !is_valid_key_size(end.len()) {
            return Err(ClientError::WireFormat(
                "range start/end key length is outside valid store key range".to_string(),
            ));
        }
        if batch_size == 0 {
            return Err(ClientError::WireFormat(
                "batch_size must be positive".to_string(),
            ));
        }

        let config =
            store_connect_client_config(self.query_uri.clone(), self.connect_request_compression);
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
        let min_sequence_number = self.normalize_min_sequence_number(options.min_sequence_number);
        let max_attempts = self.retry_config.max_attempts.max(1);
        let mut attempt = 1usize;
        loop {
            // Server-streaming RPCs cannot transparently recover mid-stream failures,
            // but retrying a transient error while opening the stream or before the
            // first frame arrives is still safe. Treat both phases as a single
            // attempt budget so range opens do not multiply retries quadratically.
            let response = match client
                .range(ProtoRangeRequest {
                    start: start.to_vec(),
                    end: end.to_vec(),
                    limit: Some(u32::try_from(limit).unwrap_or(u32::MAX)),
                    batch_size: u32::try_from(batch_size).unwrap_or(u32::MAX),
                    mode: mode.to_proto().into(),
                    min_sequence_number,
                    ..Default::default()
                })
                .await
            {
                Ok(response) => response,
                Err(err) => {
                    if attempt < max_attempts && is_retryable_error(&err) {
                        let delay = retry_delay_for_error(&err, attempt, self.retry_config);
                        tracing::debug!(
                            attempt,
                            max_attempts,
                            code = err.code.as_str(),
                            delay_ms = delay.as_millis() as u64,
                            "store client retrying transient range-open error",
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(client_error_from_connect(err));
                }
            };

            let mut stream =
                RangeStream::from_connect_stream(response, options.observed_sequence.clone());
            if let Err(err) = stream.prefetch_first_frame().await {
                if attempt < max_attempts && is_retryable_error(&err) {
                    let delay = retry_delay_for_error(&err, attempt, self.retry_config);
                    tracing::debug!(
                        attempt,
                        max_attempts,
                        code = err.code.as_str(),
                        delay_ms = delay.as_millis() as u64,
                        "store client retrying transient stream-open error",
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                return Err(client_error_from_connect(err));
            }
            return Ok(stream);
        }
    }

    async fn range_reduce_response_internal(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
        min_sequence_number: Option<u64>,
    ) -> Result<
        (
            exoware_proto::query::ReduceResponse,
            Option<proto_query::Detail>,
        ),
        ClientError,
    > {
        let config =
            store_connect_client_config(self.query_uri.clone(), self.connect_request_compression);
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
        let proto_params = proto_to_proto_reduce_params(request.clone());
        let min_sequence_number = self.normalize_min_sequence_number(min_sequence_number);
        let response = self
            .send_with_retry(|| async {
                client
                    .reduce(ProtoWireReduceRequest {
                        start: start.to_vec(),
                        end: end.to_vec(),
                        params: Some(proto_params.clone()).into(),
                        min_sequence_number,
                        ..Default::default()
                    })
                    .await
            })
            .await?;
        let detail = query_detail_from_unary_metadata(response.headers(), response.trailers());
        let owned = response.into_owned();
        Ok((owned, detail))
    }

    async fn send_with_retry<F, Fut, T>(&self, mut make_request: F) -> Result<T, ClientError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, ConnectError>>,
    {
        let max_attempts = self.retry_config.max_attempts.max(1);
        let mut attempt = 1usize;
        loop {
            match make_request().await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    if attempt < max_attempts && is_retryable_error(&err) {
                        let delay = retry_delay_for_error(&err, attempt, self.retry_config);
                        tracing::debug!(
                            attempt,
                            max_attempts,
                            code = err.code.as_str(),
                            delay_ms = delay.as_millis() as u64,
                            "store client retrying transient RPC error",
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(client_error_from_connect(err));
                }
            }
        }
    }
}

// --- Service-grouped accessors ---------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Ingest<'a> {
    c: &'a StoreClient,
}

#[derive(Clone, Copy, Debug)]
pub struct Query<'a> {
    c: &'a StoreClient,
}

#[derive(Clone, Copy, Debug)]
pub struct Compact<'a> {
    c: &'a StoreClient,
}

#[derive(Clone, Copy, Debug)]
pub struct Stream<'a> {
    c: &'a StoreClient,
}

impl<'a> Ingest<'a> {
    pub async fn put(&self, kvs: &[(&Key, &[u8])]) -> Result<u64, ClientError> {
        self.c.put(kvs).await
    }
}

impl<'a> Query<'a> {
    pub async fn get(&self, key: &Key) -> Result<Option<Bytes>, ClientError> {
        self.c.get(key).await
    }

    pub async fn get_with_min_sequence_number(
        &self,
        key: &Key,
        min_sequence_number: u64,
    ) -> Result<Option<Bytes>, ClientError> {
        self.c
            .get_with_min_sequence_number(key, min_sequence_number)
            .await
    }

    pub async fn get_many(
        &self,
        keys: &[&Key],
        batch_size: u32,
    ) -> Result<GetManyStream, ClientError> {
        self.c.get_many(keys, batch_size).await
    }

    pub async fn get_many_with_min_sequence_number(
        &self,
        keys: &[&Key],
        batch_size: u32,
        min_sequence_number: u64,
    ) -> Result<GetManyStream, ClientError> {
        self.c
            .get_many_with_min_sequence_number(keys, batch_size, min_sequence_number)
            .await
    }

    /// Collect a `Range` into a `Vec`. Use `range_stream` for large scans.
    pub async fn range(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.c.range(start, end, limit).await
    }

    pub async fn range_with_mode(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.c.range_with_mode(start, end, limit, mode).await
    }

    pub async fn range_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        min_sequence_number: u64,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.c
            .range_with_min_sequence_number(start, end, limit, min_sequence_number)
            .await
    }

    pub async fn range_with_mode_and_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
        min_sequence_number: u64,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.c
            .range_with_mode_and_min_sequence_number(start, end, limit, mode, min_sequence_number)
            .await
    }

    pub async fn range_stream(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
    ) -> Result<RangeStream, ClientError> {
        self.c.range_stream(start, end, limit, batch_size).await
    }

    pub async fn range_stream_with_mode(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        mode: RangeMode,
    ) -> Result<RangeStream, ClientError> {
        self.c
            .range_stream_with_mode(start, end, limit, batch_size, mode)
            .await
    }

    pub async fn range_stream_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        min_sequence_number: u64,
    ) -> Result<RangeStream, ClientError> {
        self.c
            .range_stream_with_min_sequence_number(
                start,
                end,
                limit,
                batch_size,
                min_sequence_number,
            )
            .await
    }

    pub async fn range_stream_with_mode_and_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        mode: RangeMode,
        min_sequence_number: u64,
    ) -> Result<RangeStream, ClientError> {
        self.c
            .range_stream_with_mode_and_min_sequence_number(
                start,
                end,
                limit,
                batch_size,
                mode,
                min_sequence_number,
            )
            .await
    }

    pub async fn range_reduce(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<Vec<Option<KvReducedValue>>, ClientError> {
        self.c.range_reduce(start, end, request).await
    }

    pub async fn range_reduce_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
        min_sequence_number: u64,
    ) -> Result<Vec<Option<KvReducedValue>>, ClientError> {
        self.c
            .range_reduce_with_min_sequence_number(start, end, request, min_sequence_number)
            .await
    }

    pub async fn range_reduce_response(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<exoware_proto::query::ReduceResponse, ClientError> {
        self.c.range_reduce_response(start, end, request).await
    }

    pub async fn range_reduce_response_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
        min_sequence_number: u64,
    ) -> Result<exoware_proto::query::ReduceResponse, ClientError> {
        self.c
            .range_reduce_response_with_min_sequence_number(
                start,
                end,
                request,
                min_sequence_number,
            )
            .await
    }
}

impl<'a> Compact<'a> {
    pub async fn prune(
        &self,
        policies: &[crate::prune_policy::PrunePolicy],
    ) -> Result<(), ClientError> {
        self.c.prune(policies).await
    }
}

impl<'a> Stream<'a> {
    /// `store.stream.v1.Service.Subscribe` — see `StreamSubscription::next`
    /// for consuming delivered frames. `since_sequence_number = None` starts
    /// live from the next Put; `Some(N)` replays retained batches before
    /// transitioning to live. An evicted `since` returns a
    /// `ConnectError::out_of_range` carrying `ErrorInfo.reason = "BATCH_EVICTED"`.
    pub async fn subscribe(
        &self,
        filter: crate::stream_filter::StreamFilter,
        since_sequence_number: Option<u64>,
    ) -> Result<StreamSubscription, ClientError> {
        crate::stream_filter::validate_filter(&filter)
            .map_err(|e| ClientError::WireFormat(e.to_string()))?;
        let match_keys = filter
            .match_keys
            .into_iter()
            .map(|mk| exoware_proto::store::common::v1::MatchKey {
                reserved_bits: u32::from(mk.reserved_bits),
                prefix: u32::from(mk.prefix),
                payload_regex: mk.payload_regex.0,
                ..Default::default()
            })
            .collect();
        let request = exoware_proto::store::stream::v1::SubscribeRequest {
            match_keys,
            since_sequence_number,
            ..Default::default()
        };
        let config = store_connect_client_config(
            self.c.stream_uri.clone(),
            self.c.connect_request_compression,
        );
        let client = exoware_proto::store::stream::v1::ServiceClient::new(
            self.c.connect_http.clone(),
            config,
        );
        let stream = client
            .subscribe(request)
            .await
            .map_err(client_error_from_connect)?;
        Ok(StreamSubscription { stream })
    }

    /// `store.stream.v1.Service.Get` — `Ok(None)` collapses the server's
    /// `BATCH_EVICTED` / `BATCH_NOT_FOUND` error details.
    pub async fn get(
        &self,
        sequence_number: u64,
    ) -> Result<Option<Vec<(Key, Bytes)>>, ClientError> {
        let config = store_connect_client_config(
            self.c.stream_uri.clone(),
            self.c.connect_request_compression,
        );
        let client = exoware_proto::store::stream::v1::ServiceClient::new(
            self.c.connect_http.clone(),
            config,
        );
        match client
            .get(exoware_proto::store::stream::v1::GetRequest {
                sequence_number,
                ..Default::default()
            })
            .await
        {
            Ok(resp) => {
                let owned = resp.into_owned();
                let entries = owned
                    .entries
                    .into_iter()
                    .map(|e| (Bytes::from(e.key), Bytes::from(e.value)))
                    .collect();
                Ok(Some(entries))
            }
            Err(err) => {
                if is_batch_missing_error(&err) {
                    Ok(None)
                } else {
                    Err(client_error_from_connect(err))
                }
            }
        }
    }
}

impl SerializableReadSession {
    /// Fixed sequence floor for this session, if one has been established yet.
    ///
    /// Fresh sessions start with `None` unless created via
    /// [`StoreClient::create_session_with_sequence`]. A first streamed query
    /// read (`get_many`, `range_stream`) only sets this once the stream is
    /// fully drained and trailers are available.
    pub fn fixed_sequence(&self) -> Option<u64> {
        self.state.fixed_sequence()
    }

    pub async fn get(&self, key: &Key) -> Result<Option<Bytes>, ClientError> {
        let seeded_client = self.client.clone();
        let unseeded_client = self.client.clone();
        self.run_read(
            move |sequence| {
                let client = seeded_client.clone();
                async move { client.get_with_min_sequence_number(key, sequence).await }
            },
            move |observed_sequence| {
                let client = unseeded_client.clone();
                async move {
                    let (response, detail) = client.send_get(key, None).await?;
                    if let Some(detail) = detail {
                        observed_sequence.fetch_max(detail.sequence_number, Ordering::SeqCst);
                    }
                    Ok(response.value.map(Bytes::from))
                }
            },
        )
        .await
    }

    pub async fn get_many(
        &self,
        keys: &[&Key],
        batch_size: u32,
    ) -> Result<GetManyStream, ClientError> {
        let keys_owned: Vec<Key> = keys.iter().map(|k| Bytes::copy_from_slice(k)).collect();
        let seeded_client = self.client.clone();
        let unseeded_client = self.client.clone();
        let keys_seeded = keys_owned.clone();
        let keys_unseeded = keys_owned;
        self.run_read(
            move |sequence| {
                let client = seeded_client.clone();
                let keys = keys_seeded.clone();
                async move {
                    let refs: Vec<&Key> = keys.iter().collect();
                    client
                        .get_many_with_min_sequence_number(&refs, batch_size, sequence)
                        .await
                }
            },
            move |observed_sequence| {
                let client = unseeded_client.clone();
                let keys = keys_unseeded.clone();
                async move {
                    let refs: Vec<&Key> = keys.iter().collect();
                    client
                        .get_many_internal(&refs, batch_size, None, Some(observed_sequence))
                        .await
                }
            },
        )
        .await
    }

    pub async fn range(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_with_mode(start, end, limit, RangeMode::Forward)
            .await
    }

    pub async fn range_with_mode(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        let seeded_client = self.client.clone();
        let unseeded_client = self.client.clone();
        self.run_read(
            move |sequence| {
                let client = seeded_client.clone();
                async move {
                    client
                        .range_with_mode_and_min_sequence_number(start, end, limit, mode, sequence)
                        .await
                }
            },
            move |observed_sequence| {
                let client = unseeded_client.clone();
                async move {
                    let stream = client
                        .range_stream_internal(
                            start,
                            end,
                            limit,
                            limit.max(1),
                            mode,
                            RangeStreamReadOptions {
                                min_sequence_number: None,
                                observed_sequence: Some(observed_sequence),
                            },
                        )
                        .await;
                    stream?.collect().await
                }
            },
        )
        .await
    }

    pub async fn range_stream(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
    ) -> Result<RangeStream, ClientError> {
        self.range_stream_with_mode(start, end, limit, batch_size, RangeMode::Forward)
            .await
    }

    pub async fn range_stream_with_mode(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        mode: RangeMode,
    ) -> Result<RangeStream, ClientError> {
        let seeded_client = self.client.clone();
        let unseeded_client = self.client.clone();
        self.run_read(
            move |sequence| {
                let client = seeded_client.clone();
                async move {
                    client
                        .range_stream_with_mode_and_min_sequence_number(
                            start, end, limit, batch_size, mode, sequence,
                        )
                        .await
                }
            },
            move |observed_sequence| {
                let client = unseeded_client.clone();
                async move {
                    client
                        .range_stream_internal(
                            start,
                            end,
                            limit,
                            batch_size,
                            mode,
                            RangeStreamReadOptions {
                                min_sequence_number: None,
                                observed_sequence: Some(observed_sequence),
                            },
                        )
                        .await
                }
            },
        )
        .await
    }

    pub async fn range_reduce(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<Vec<Option<KvReducedValue>>, ClientError> {
        let seeded_client = self.client.clone();
        let unseeded_client = self.client.clone();
        let request_seeded = request.clone();
        let request_unseeded = request.clone();
        self.run_read(
            move |sequence| {
                let client = seeded_client.clone();
                let request = request_seeded.clone();
                async move {
                    client
                        .range_reduce_with_min_sequence_number(start, end, &request, sequence)
                        .await
                }
            },
            move |observed_sequence| {
                let client = unseeded_client.clone();
                let request = request_unseeded.clone();
                async move {
                    let (response, detail) = client
                        .range_reduce_response_internal(start, end, &request, None)
                        .await?;
                    if let Some(detail) = detail {
                        observed_sequence.fetch_max(detail.sequence_number, Ordering::SeqCst);
                    }
                    let decoded = proto_to_domain_reduce_response(response)
                        .map_err(ClientError::WireFormat)?;
                    if !decoded.groups.is_empty() {
                        return Err(ClientError::WireFormat(
                            "grouped range reduction response returned for scalar request"
                                .to_string(),
                        ));
                    }
                    Ok(decoded
                        .results
                        .iter()
                        .map(|result| result.value.clone())
                        .collect())
                }
            },
        )
        .await
    }

    pub async fn range_reduce_response(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<exoware_proto::query::ReduceResponse, ClientError> {
        let seeded_client = self.client.clone();
        let unseeded_client = self.client.clone();
        let request_seeded = request.clone();
        let request_unseeded = request.clone();
        self.run_read(
            move |sequence| {
                let client = seeded_client.clone();
                let request = request_seeded.clone();
                async move {
                    client
                        .range_reduce_response_with_min_sequence_number(
                            start, end, &request, sequence,
                        )
                        .await
                }
            },
            move |observed_sequence| {
                let client = unseeded_client.clone();
                let request = request_unseeded.clone();
                async move {
                    let (response, detail) = client
                        .range_reduce_response_internal(start, end, &request, None)
                        .await?;
                    if let Some(detail) = detail {
                        observed_sequence.fetch_max(detail.sequence_number, Ordering::SeqCst);
                    }
                    Ok(response)
                }
            },
        )
        .await
    }

    async fn run_read<T, SeededCall, SeededFut, UnseededCall, UnseededFut>(
        &self,
        seeded_call: SeededCall,
        unseeded_call: UnseededCall,
    ) -> Result<T, ClientError>
    where
        SeededCall: Fn(u64) -> SeededFut,
        SeededFut: std::future::Future<Output = Result<T, ClientError>>,
        UnseededCall: Fn(Arc<AtomicU64>) -> UnseededFut,
        UnseededFut: std::future::Future<Output = Result<T, ClientError>>,
    {
        if let Some(sequence) = self.fixed_sequence() {
            return seeded_call(sequence).await;
        }

        let gate = self.state.init_gate.lock().await;

        if let Some(sequence) = self.fixed_sequence() {
            drop(gate);
            return seeded_call(sequence).await;
        }

        let result = unseeded_call(self.state.sequence.clone()).await;
        drop(gate);
        result
    }
}

fn client_error_from_connect(err: ConnectError) -> ClientError {
    ClientError::Rpc(Box::new(err))
}

fn is_retryable_error(err: &ConnectError) -> bool {
    matches!(
        err.code,
        ErrorCode::Aborted
            | ErrorCode::ResourceExhausted
            | ErrorCode::Unavailable
            | ErrorCode::Unknown
            // Retrying `internal` is a trade-off: proxies and load balancers sometimes surface
            // transient faults this way; idempotent reads use a small attempt budget so we do not
            // spin forever. Prefer interpreting `google.rpc.RetryInfo` when present (see
            // `retry_delay_for_error`).
            | ErrorCode::Internal
    )
}

fn retry_delay_for_error(
    err: &ConnectError,
    attempt: usize,
    retry_config: RetryConfig,
) -> Duration {
    if let Ok(decoded) = proto_decode_connect_error(err) {
        if let Some(retry_info) = decoded.retry_info {
            if let Some(delay) = retry_info.retry_delay.as_option() {
                let secs = u64::try_from(delay.seconds).unwrap_or(0);
                let nanos = u32::try_from(delay.nanos.max(0)).unwrap_or(0);
                let hinted = Duration::new(secs, nanos);
                if !hinted.is_zero() {
                    return hinted.min(retry_config.max_backoff);
                }
            }
        }
    }
    retry_backoff_delay(attempt, retry_config)
}

fn retry_backoff_delay(attempt: usize, retry_config: RetryConfig) -> Duration {
    let exponent = (attempt.saturating_sub(1)).min(20) as u32;
    let factor = 1u128 << exponent;
    let base_ms = retry_config.initial_backoff.as_millis();
    let capped_ms = base_ms
        .saturating_mul(factor)
        .min(retry_config.max_backoff.as_millis());
    Duration::from_millis(capped_ms.min(u64::MAX as u128) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use exoware_proto::query::TraversalMode as ProtoTraversalMode;

    #[test]
    fn hex_round_trip() {
        let data = vec![0x00, 0x42, 0xFF, 0xAB];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "0042ffab");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn client_creation() {
        let client = StoreClient::new("http://localhost:10000");
        assert_eq!(client.health_url, "http://localhost:10000");
        assert_eq!(client.ingest_uri.to_string(), "http://localhost:10000/");
        assert_eq!(client.query_uri.to_string(), "http://localhost:10000/");
    }

    #[test]
    fn builder_matches_new_and_split_urls() {
        let single = StoreClient::new("http://localhost:9/");
        let built = StoreClient::builder()
            .url("http://localhost:9/")
            .build()
            .unwrap();
        assert_eq!(single.health_url, built.health_url);
        assert_eq!(single.ingest_uri.to_string(), built.ingest_uri.to_string());
        assert_eq!(single.query_uri.to_string(), built.query_uri.to_string());

        let split = StoreClient::with_split_urls("http://h", "http://i", "http://q", "http://c");
        let split_b = StoreClient::builder()
            .health_url("http://h")
            .ingest_url("http://i")
            .query_url("http://q")
            .compact_url("http://c")
            .build()
            .unwrap();
        assert_eq!(split.health_url, split_b.health_url);
        assert_eq!(split.ingest_uri.to_string(), split_b.ingest_uri.to_string());
        assert_eq!(split.query_uri.to_string(), split_b.query_uri.to_string());
        assert_eq!(
            split.compact_uri.to_string(),
            split_b.compact_uri.to_string()
        );
    }

    #[test]
    fn builder_fails_until_all_urls_set() {
        assert!(matches!(
            StoreClient::builder().health_url("http://h").build(),
            Err(ClientBuildError::MissingIngestUrl)
        ));
        assert!(matches!(
            StoreClient::builder()
                .health_url("http://h")
                .ingest_url("http://i")
                .build(),
            Err(ClientBuildError::MissingQueryUrl)
        ));
        assert!(matches!(
            StoreClient::builder()
                .health_url("http://h")
                .ingest_url("http://i")
                .query_url("http://q")
                .build(),
            Err(ClientBuildError::MissingCompactUrl)
        ));
    }

    #[test]
    fn client_trims_trailing_slash() {
        let client = StoreClient::new("http://localhost:10000/");
        assert_eq!(client.health_url, "http://localhost:10000");
    }

    #[test]
    fn create_session_starts_unseeded() {
        let client = StoreClient::new("http://localhost:10000/");
        let session = client.create_session();
        assert_eq!(session.fixed_sequence(), None);
    }

    #[test]
    fn range_mode_maps_to_proto_traversal() {
        assert_eq!(
            RangeMode::Forward.to_proto(),
            ProtoTraversalMode::TRAVERSAL_MODE_FORWARD
        );
        assert_eq!(
            RangeMode::Reverse.to_proto(),
            ProtoTraversalMode::TRAVERSAL_MODE_REVERSE
        );
    }

    #[test]
    fn retry_config_standard_defaults_match_expected() {
        let config = RetryConfig::standard();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_backoff, Duration::from_millis(100));
        assert_eq!(config.max_backoff, Duration::from_millis(2_000));
    }

    #[test]
    fn retry_config_clamps_attempts_and_backoff_bounds() {
        let config = RetryConfig::standard()
            .with_max_attempts(0)
            .with_initial_backoff(Duration::from_millis(250))
            .with_max_backoff(Duration::from_millis(50))
            .sanitized();
        assert_eq!(config.max_attempts, 1);
        assert_eq!(config.initial_backoff, Duration::from_millis(250));
        assert_eq!(config.max_backoff, Duration::from_millis(250));
    }

    #[test]
    fn retryable_codes_include_connect_transients() {
        assert!(is_retryable_error(&ConnectError::aborted("retry")));
        assert!(is_retryable_error(&ConnectError::resource_exhausted(
            "retry"
        )));
        assert!(is_retryable_error(&ConnectError::unavailable("retry")));
        assert!(is_retryable_error(&ConnectError::internal("retry")));
        assert!(!is_retryable_error(&ConnectError::invalid_argument(
            "no retry"
        )));
    }

    #[test]
    fn retry_backoff_delay_is_exponential_and_capped() {
        let config = RetryConfig::standard()
            .with_initial_backoff(Duration::from_millis(100))
            .with_max_backoff(Duration::from_millis(250));
        assert_eq!(retry_backoff_delay(1, config), Duration::from_millis(100));
        assert_eq!(retry_backoff_delay(2, config), Duration::from_millis(200));
        assert_eq!(retry_backoff_delay(3, config), Duration::from_millis(250));
        assert_eq!(retry_backoff_delay(4, config), Duration::from_millis(250));
    }

    #[test]
    fn create_session_with_sequence_pins_explicit_floor() {
        let client = StoreClient::new("http://localhost:10000/");
        let session = client.create_session_with_sequence(27);
        assert_eq!(session.fixed_sequence(), Some(27));
    }

    fn hex_encode(data: &[u8]) -> String {
        hex::encode(data)
    }

    fn hex_decode(s: &str) -> Option<Vec<u8>> {
        hex::decode(s).ok()
    }
}
