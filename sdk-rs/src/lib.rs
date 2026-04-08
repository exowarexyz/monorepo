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
//! Idempotent reads honor [`google.rpc.RetryInfo`] when deciding backoff (see `retry_delay_for_error`).

pub mod keys;
pub mod kv_codec;
pub mod proto;
pub mod prune_policy;
pub use keys::{Key, KeyCodec, KeyCodecError, KeyMut, KeyValidationError, Value, MAX_KEY_LEN};
pub use proto::*;
extern crate self as exoware_proto;

use bytes::Bytes;
use connectrpc::client::{ClientConfig, ServerStream as ConnectServerStream};
use connectrpc::{ConnectError, ErrorCode};
use keys::is_valid_key_size;
use kv_codec::KvReducedValue;
use exoware_proto::ingest::ServiceClient as IngestServiceClient;
use exoware_proto::query as proto_query;
use exoware_proto::query::ServiceClient as QueryServiceClient;
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
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
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
    sequence_number: Option<Arc<AtomicU64>>,
}

impl RangeStream {
    fn from_connect_stream(
        stream: ConnectServerStream<
            hyper::body::Incoming,
            exoware_proto::query::RangeFrameView<'static>,
        >,
        sequence_number: Arc<AtomicU64>,
    ) -> Self {
        Self {
            stream,
            pending_frame: None,
            rows_seen: 0,
            final_count: None,
            final_detail: None,
            finished: false,
            sequence_number: Some(sequence_number),
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
        if let (Some(token_store), Some(d)) = (&self.sequence_number, self.final_detail.as_ref()) {
            token_store.fetch_max(d.sequence_number, Ordering::SeqCst);
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
    stream: ConnectServerStream<
        hyper::body::Incoming,
        exoware_proto::query::GetManyFrameView<'static>,
    >,
    pending_frame: Option<exoware_proto::query::GetManyFrame>,
    entries_seen: usize,
    final_detail: Option<proto_query::Detail>,
    finished: bool,
    sequence_number: Option<Arc<AtomicU64>>,
}

impl GetManyStream {
    fn from_connect_stream(
        stream: ConnectServerStream<
            hyper::body::Incoming,
            exoware_proto::query::GetManyFrameView<'static>,
        >,
        sequence_number: Arc<AtomicU64>,
    ) -> Self {
        Self {
            stream,
            pending_frame: None,
            entries_seen: 0,
            final_detail: None,
            finished: false,
            sequence_number: Some(sequence_number),
        }
    }

    fn observe_detail_from_stream_trailers(&mut self) {
        self.final_detail = self
            .stream
            .trailers()
            .and_then(query_detail_from_header_map);
        if let (Some(token_store), Some(d)) = (&self.sequence_number, self.final_detail.as_ref()) {
            token_store.fetch_max(d.sequence_number, Ordering::SeqCst);
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
    retry_config: RetryConfig,
    connect_request_compression: ConnectRequestCompression,
}

impl StoreClientBuilder {
    /// Sets the same base URL for [`Self::health_url`], [`Self::ingest_url`], and [`Self::query_url`].
    pub fn url(mut self, url: &str) -> Self {
        let u = trim_connect_base(url);
        self.health_url = Some(u.clone());
        self.ingest_url = Some(u.clone());
        self.query_url = Some(u);
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
        let ingest_uri: http::Uri = ingest_url.parse().map_err(|e| ClientBuildError::InvalidUrl {
            url: ingest_url.clone(),
            source: e,
        })?;
        let query_uri: http::Uri = query_url.parse().map_err(|e| ClientBuildError::InvalidUrl {
            url: query_url.clone(),
            source: e,
        })?;
        Ok(StoreClient {
            health_url,
            ingest_uri,
            query_uri,
            http: new_http_client(),
            connect_http: ProtoPreferZstdHttpClient::plaintext(),
            sequence_number: Arc::new(AtomicU64::new(0)),
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
    http: reqwest::Client,
    connect_http: ProtoPreferZstdHttpClient,
    sequence_number: Arc<AtomicU64>,
    retry_config: RetryConfig,
    connect_request_compression: ConnectRequestCompression,
}

/// A session that enforces monotonic read consistency via a fixed `min_sequence_number` floor.
///
/// Every read in the session passes the same `min_sequence_number` so the server
/// guarantees all responses reflect at least that point in the write log. The first
/// read either inherits the parent `StoreClient`'s observed sequence number (if nonzero)
/// or issues an unseeded read and seeds from the response.
#[derive(Clone, Debug)]
pub struct SerializableReadSession {
    client: StoreClient,
    state: Arc<SessionState>,
}

#[derive(Debug)]
struct SessionState {
    token: AtomicU64,
    seeded: AtomicBool,
    init_gate: tokio::sync::Mutex<()>,
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

    /// Split endpoints for deployments where ingest and query run on different ports or hosts.
    ///
    /// Prefer [`StoreClient::builder`] for clarity. This is equivalent to
    /// `builder().health_url(health_base).ingest_url(ingest_base).query_url(query_base).build().unwrap()`.
    ///
    /// - `health_base`: used for plain HTTP `GET /health` and `GET /ready` (use the query worker URL).
    /// - `ingest_base`: base URL for `store.ingest.v1.Service`.
    /// - `query_base`: base URL for `store.query.v1.Service`.
    pub fn with_split_urls(health_base: &str, ingest_base: &str, query_base: &str) -> Self {
        Self::with_split_urls_and_retry(
            health_base,
            ingest_base,
            query_base,
            RetryConfig::standard(),
        )
    }

    pub fn with_split_urls_and_retry(
        health_base: &str,
        ingest_base: &str,
        query_base: &str,
        retry_config: RetryConfig,
    ) -> Self {
        Self::builder()
            .health_url(health_base)
            .ingest_url(ingest_base)
            .query_url(query_base)
            .retry_config(retry_config)
            .build()
            .expect("health, ingest, and query URLs are set")
    }

    pub fn sequence_number(&self) -> u64 {
        self.sequence_number.load(Ordering::Relaxed)
    }

    /// Outgoing Connect request body compression (see [`ConnectRequestCompression`]).
    pub fn connect_request_compression(&self) -> ConnectRequestCompression {
        self.connect_request_compression
    }

    pub fn observe_sequence_number(&self, token: u64) {
        self.sequence_number.fetch_max(token, Ordering::SeqCst);
    }

    pub fn decode_error_details(
        err: &ConnectError,
    ) -> Result<exoware_proto::DecodedConnectError, buffa::DecodeError> {
        proto_decode_connect_error(err)
    }

    pub fn create_session(&self) -> SerializableReadSession {
        let initial = self.sequence_number();
        SerializableReadSession {
            client: self.clone(),
            state: Arc::new(SessionState {
                token: AtomicU64::new(initial),
                seeded: AtomicBool::new(initial > 0),
                init_gate: tokio::sync::Mutex::new(()),
            }),
        }
    }

    /// Submit a KV batch via Connect `Put`.
    ///
    /// On success returns the **store sequence number** from the response (same value
    /// the client also records via [`Self::observe_sequence_number`]). Use it for immediate
    /// `get_with_min_sequence_number` / range calls without polling [`Self::sequence_number`].
    /// If the request succeeds, the server accepts the full batch (count is `kvs.len()`).
    pub async fn put(&self, kvs: &[(&Key, &[u8])]) -> Result<u64, ClientError> {
        let mut proto_kvs = Vec::with_capacity(kvs.len());
        for (key, value) in kvs {
            if !is_valid_key_size(key.len()) {
                return Err(ClientError::WireFormat(format!(
                    "key length {} is outside valid store key range ({}..={})",
                    key.len(), keys::MIN_KEY_LEN, MAX_KEY_LEN
                )));
            }
            proto_kvs.push(exoware_proto::ingest::KvPair {
                key: (*key).to_vec(),
                value: value.to_vec(),
                ..Default::default()
            });
        }

        let config = store_connect_client_config(
            self.ingest_uri.clone(),
            self.connect_request_compression,
        );
        let client = IngestServiceClient::new(self.connect_http.clone(), config);
        let response = client
            .put(ProtoPutRequest {
                kvs: proto_kvs,
                ..Default::default()
            })
            .await
            .map_err(client_error_from_connect)?;
        let owned = response.into_owned();
        let token = owned.sequence_number;
        self.observe_sequence_number(token);
        Ok(token)
    }

    pub async fn get(&self, key: &Key) -> Result<Option<Bytes>, ClientError> {
        self.get_internal(key, None).await
    }

    pub async fn get_with_min_sequence_number(
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
            .send_get(key, self.effective_min_sequence_number(min_sequence_number))
            .await?;
        if let Some(d) = detail {
            self.observe_sequence_number(d.sequence_number);
        }
        Ok(response.value.map(Bytes::from))
    }

    pub async fn get_many(
        &self,
        keys: &[&Key],
        batch_size: u32,
    ) -> Result<GetManyStream, ClientError> {
        self.get_many_internal(keys, batch_size, None).await
    }

    pub async fn get_many_with_min_sequence_number(
        &self,
        keys: &[&Key],
        batch_size: u32,
        min_sequence_number: u64,
    ) -> Result<GetManyStream, ClientError> {
        self.get_many_internal(keys, batch_size, Some(min_sequence_number))
            .await
    }

    async fn get_many_internal(
        &self,
        keys: &[&Key],
        batch_size: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<GetManyStream, ClientError> {
        for key in keys {
            if !is_valid_key_size(key.len()) {
                return Err(ClientError::WireFormat(format!(
                    "key length {} is outside valid store key range ({}..={})",
                    key.len(), keys::MIN_KEY_LEN, MAX_KEY_LEN
                )));
            }
        }

        let config = store_connect_client_config(
            self.query_uri.clone(),
            self.connect_request_compression,
        );
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
        let proto_keys: Vec<Vec<u8>> = keys.iter().map(|k| k.to_vec()).collect();
        let effective_min = self.effective_min_sequence_number(min_sequence_number);
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
                    let mut gms = GetManyStream::from_connect_stream(
                        stream,
                        self.sequence_number.clone(),
                    );
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
    pub async fn range(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_internal(start, end, limit, RangeMode::Forward, None)
            .await
    }

    /// See [`StoreClient::range`] for `end` semantics.
    pub async fn range_with_mode(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_internal(start, end, limit, mode, None).await
    }

    pub async fn range_with_min_sequence_number(
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

    pub async fn range_with_mode_and_min_sequence_number(
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

    pub async fn range_stream(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
    ) -> Result<RangeStream, ClientError> {
        self.range_stream_internal(start, end, limit, batch_size, RangeMode::Forward, None)
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
        self.range_stream_internal(start, end, limit, batch_size, mode, None)
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
        self.range_stream_internal(
            start,
            end,
            limit,
            batch_size,
            RangeMode::Forward,
            Some(min_sequence_number),
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
        self.range_stream_internal(
            start,
            end,
            limit,
            batch_size,
            mode,
            Some(min_sequence_number),
        )
        .await
    }

    pub async fn range_reduce(
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

    pub async fn range_reduce_with_min_sequence_number(
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

    pub async fn range_reduce_response(
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

    pub async fn range_reduce_response_with_min_sequence_number(
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

    #[cfg(test)]
    pub async fn range_reduce_response_for_tests(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<
        (
            exoware_proto::query::ReduceResponse,
            Option<proto_query::Detail>,
        ),
        ClientError,
    > {
        self.range_reduce_response_internal(start, end, request, None)
            .await
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

    fn effective_min_sequence_number(&self, override_token: Option<u64>) -> Option<u64> {
        let token = override_token.unwrap_or_else(|| self.sequence_number());
        (token > 0).then_some(token)
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
                key.len(), keys::MIN_KEY_LEN, MAX_KEY_LEN
            )));
        }

        let config = store_connect_client_config(
            self.query_uri.clone(),
            self.connect_request_compression,
        );
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
        let response = self
            .send_with_retry(
                || async {
                    client
                        .get(ProtoGetRequest {
                            key: key.to_vec(),
                            min_sequence_number,
                            ..Default::default()
                        })
                        .await
                },
            )
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
            .range_stream_internal(start, end, limit, limit.max(1), mode, min_sequence_number)
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
        min_sequence_number: Option<u64>,
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

        let config = store_connect_client_config(
            self.query_uri.clone(),
            self.connect_request_compression,
        );
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
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
                RangeStream::from_connect_stream(response, self.sequence_number.clone());
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
        let config = store_connect_client_config(
            self.query_uri.clone(),
            self.connect_request_compression,
        );
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
        let proto_params = proto_to_proto_reduce_params(request.clone());
        let response = self
            .send_with_retry(
                || async {
                    client
                        .reduce(ProtoWireReduceRequest {
                            start: start.to_vec(),
                            end: end.to_vec(),
                            params: Some(proto_params.clone()).into(),
                            min_sequence_number,
                            ..Default::default()
                        })
                        .await
                },
            )
            .await?;
        let detail = query_detail_from_unary_metadata(response.headers(), response.trailers());
        let owned = response.into_owned();
        if let Some(d) = detail.as_ref() {
            self.observe_sequence_number(d.sequence_number);
        }
        Ok((owned, detail))
    }

    async fn send_with_retry<F, Fut, T>(
        &self,
        mut make_request: F,
    ) -> Result<T, ClientError>
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

impl SerializableReadSession {
    pub fn fixed_token(&self) -> Option<u64> {
        if !self.state.seeded.load(Ordering::Acquire) {
            return None;
        }
        let token = self.state.token.load(Ordering::Acquire);
        (token > 0).then_some(token)
    }

    pub async fn get(&self, key: &Key) -> Result<Option<Bytes>, ClientError> {
        let seeded_client = self.client.clone();
        let unseeded_client = self.client.clone();
        self.run_read(
            move |token| {
                let client = seeded_client.clone();
                async move { client.get_with_min_sequence_number(key, token).await }
            },
            move || {
                let client = unseeded_client.clone();
                async move { client.get(key).await }
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
            move |token| {
                let client = seeded_client.clone();
                let keys = keys_seeded.clone();
                async move {
                    let refs: Vec<&Key> = keys.iter().collect();
                    client
                        .get_many_with_min_sequence_number(&refs, batch_size, token)
                        .await
                }
            },
            move || {
                let client = unseeded_client.clone();
                let keys = keys_unseeded.clone();
                async move {
                    let refs: Vec<&Key> = keys.iter().collect();
                    client.get_many(&refs, batch_size).await
                }
            },
        )
        .await
    }

    /// Same key-range semantics as [`StoreClient::range`].
    pub async fn range(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_with_mode(start, end, limit, RangeMode::Forward)
            .await
    }

    /// Same key-range semantics as [`StoreClient::range`].
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
            move |token| {
                let client = seeded_client.clone();
                async move {
                    client
                        .range_with_mode_and_min_sequence_number(start, end, limit, mode, token)
                        .await
                }
            },
            move || {
                let client = unseeded_client.clone();
                async move { client.range_internal(start, end, limit, mode, None).await }
            },
        )
        .await
    }

    /// Same key-range semantics as [`StoreClient::range`].
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

    /// Same key-range semantics as [`StoreClient::range`].
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
            move |token| {
                let client = seeded_client.clone();
                async move {
                    client
                        .range_stream_with_mode_and_min_sequence_number(
                            start, end, limit, batch_size, mode, token,
                        )
                        .await
                }
            },
            move || {
                let client = unseeded_client.clone();
                async move {
                    client
                        .range_stream_internal(start, end, limit, batch_size, mode, None)
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
            move |token| {
                let client = seeded_client.clone();
                let request = request_seeded.clone();
                async move {
                    client
                        .range_reduce_with_min_sequence_number(start, end, &request, token)
                        .await
                }
            },
            move || {
                let client = unseeded_client.clone();
                let request = request_unseeded.clone();
                async move { client.range_reduce(start, end, &request).await }
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
            move |token| {
                let client = seeded_client.clone();
                let request = request_seeded.clone();
                async move {
                    client
                        .range_reduce_response_with_min_sequence_number(start, end, &request, token)
                        .await
                }
            },
            move || {
                let client = unseeded_client.clone();
                let request = request_unseeded.clone();
                async move { client.range_reduce_response(start, end, &request).await }
            },
        )
        .await
    }

    fn try_seed_from_client_token(&self) -> Option<u64> {
        let token = self.client.sequence_number();
        if token == 0 {
            return None;
        }
        self.state.token.store(token, Ordering::Release);
        self.state.seeded.store(true, Ordering::Release);
        Some(token)
    }

    async fn run_read<T, SeededCall, SeededFut, UnseededCall, UnseededFut>(
        &self,
        seeded_call: SeededCall,
        unseeded_call: UnseededCall,
    ) -> Result<T, ClientError>
    where
        SeededCall: Fn(u64) -> SeededFut,
        SeededFut: std::future::Future<Output = Result<T, ClientError>>,
        UnseededCall: Fn() -> UnseededFut,
        UnseededFut: std::future::Future<Output = Result<T, ClientError>>,
    {
        if let Some(token) = self.fixed_token() {
            return seeded_call(token).await;
        }

        let gate = self.state.init_gate.lock().await;

        if let Some(token) = self
            .fixed_token()
            .or_else(|| self.try_seed_from_client_token())
        {
            drop(gate);
            return seeded_call(token).await;
        }

        let result = unseeded_call().await;
        if result.is_ok() {
            let _ = self.try_seed_from_client_token();
        }
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

        let split = StoreClient::with_split_urls("http://h", "http://i", "http://q");
        let split_b = StoreClient::builder()
            .health_url("http://h")
            .ingest_url("http://i")
            .query_url("http://q")
            .build()
            .unwrap();
        assert_eq!(split.health_url, split_b.health_url);
        assert_eq!(split.ingest_uri.to_string(), split_b.ingest_uri.to_string());
        assert_eq!(split.query_uri.to_string(), split_b.query_uri.to_string());
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
    }

    #[test]
    fn client_trims_trailing_slash() {
        let client = StoreClient::new("http://localhost:10000/");
        assert_eq!(client.health_url, "http://localhost:10000");
    }

    #[test]
    fn sequence_number_is_monotonic() {
        let client = StoreClient::new("http://localhost:10000/");
        assert_eq!(client.sequence_number(), 0);
        client.observe_sequence_number(7);
        client.observe_sequence_number(3);
        client.observe_sequence_number(9);
        assert_eq!(client.sequence_number(), 9);
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
    fn create_session_uses_existing_client_token() {
        let client = StoreClient::new("http://localhost:10000/");
        client.observe_sequence_number(11);
        let session = client.create_session();
        assert_eq!(session.fixed_token(), Some(11));
    }

    fn hex_encode(data: &[u8]) -> String {
        hex::encode(data)
    }

    fn hex_decode(s: &str) -> Option<Vec<u8>> {
        hex::decode(s).ok()
    }
}
