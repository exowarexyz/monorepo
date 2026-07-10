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
pub mod proto;
pub mod prune_policy;
pub mod selector;
pub mod stream_filter;
pub use keys::{Key, KeyMut, KeyValidationError, Prefix, PrefixError, Value, MAX_KEY_LEN};
pub use proto::*;
extern crate self as exoware_proto;

use bytes::Bytes;
use connectrpc::client::{ClientConfig, ServerStream as ConnectServerStream};
use connectrpc::{ConnectError, ErrorCode};
use exoware_proto::compact::ServiceClient as CompactServiceClient;
use exoware_proto::ingest::ServiceClient as IngestServiceClient;
use exoware_proto::log::ingest::v1::PutRequest as ProtoPutRequest;
use exoware_proto::query as proto_query;
use exoware_proto::query::ServiceClient as QueryServiceClient;
use exoware_proto::store::compact::v1::PruneRequest as ProtoPruneRequest;
use exoware_proto::store::query::v1::{
    GetManyRequest as ProtoGetManyRequest, GetRequest as ProtoGetRequest,
    RangeRequest as ProtoRangeRequest, ReduceRequest as ProtoWireReduceRequest,
};
use exoware_proto::RangeReduceRequest as DomainRangeReduceRequest;
use exoware_proto::{
    connect_compression_registry as proto_connect_compression_registry,
    decode_connect_error as proto_decode_connect_error,
    to_domain_reduce_response as proto_to_domain_reduce_response,
    to_proto_reduce_params as proto_to_proto_reduce_params,
    PreferZstdHttpClient as ProtoPreferZstdHttpClient,
};
use futures::future::BoxFuture;
use keys::is_valid_key_size;
use kv_codec::{KvExpr, KvFieldRef, KvReducedValue};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

const DEFAULT_RETRY_MAX_ATTEMPTS: usize = 3;
const DEFAULT_RETRY_INITIAL_BACKOFF_MS: u64 = 100;
const DEFAULT_RETRY_MAX_BACKOFF_MS: u64 = 2_000;

/// Converts caller-provided write values into the byte owner stored by
/// [`StoreWriteBatch`].
pub trait IntoStoreWriteValue {
    fn into_store_write_value(self) -> Bytes;
}

impl IntoStoreWriteValue for Bytes {
    fn into_store_write_value(self) -> Bytes {
        self
    }
}

impl IntoStoreWriteValue for &Bytes {
    fn into_store_write_value(self) -> Bytes {
        self.clone()
    }
}

impl IntoStoreWriteValue for Vec<u8> {
    fn into_store_write_value(self) -> Bytes {
        self.into()
    }
}

impl IntoStoreWriteValue for &Vec<u8> {
    fn into_store_write_value(self) -> Bytes {
        Bytes::copy_from_slice(self)
    }
}

impl IntoStoreWriteValue for &[u8] {
    fn into_store_write_value(self) -> Bytes {
        Bytes::copy_from_slice(self)
    }
}

impl<const N: usize> IntoStoreWriteValue for &[u8; N] {
    fn into_store_write_value(self) -> Bytes {
        Bytes::copy_from_slice(self)
    }
}

/// Codec used to compress **outgoing** RPC request bodies when compression applies.
///
/// Request compression is disabled by default because large ingest batches are
/// often CPU-bound before they are network-bound. Use [`Zstd`](Self::Zstd) when
/// upload bandwidth matters more than client CPU, or [`Gzip`](Self::Gzip) when
/// talking to a peer that only accepts gzip-compressed requests. Response
/// decompression still follows [`PreferZstdHttpClient`] and the shared
/// [`connect_compression_registry`].
///
/// To drive this from configuration or environment variables, map your setting to this enum and
/// pass it to [`StoreClientBuilder::connect_request_compression`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConnectRequestCompression {
    /// Do not compress outgoing request bodies.
    #[default]
    None,
    /// `compress_requests("zstd")`.
    Zstd,
    /// `compress_requests("gzip")`.
    Gzip,
}

impl ConnectRequestCompression {
    fn wire_name(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Zstd => Some("zstd"),
            Self::Gzip => Some("gzip"),
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
/// Request body compression uses [`ConnectRequestCompression`] (default none);
/// connectrpc only supports one request encoding per config (see
/// [`ConnectRequestCompression`]).
fn store_connect_client_config(
    base_uri: http::Uri,
    request_compression: ConnectRequestCompression,
) -> ClientConfig {
    let config = ClientConfig::new(base_uri)
        .with_compression(proto_connect_compression_registry())
        .with_default_max_message_size(STORE_CLIENT_MAX_MESSAGE_BYTES);
    match request_compression.wire_name() {
        Some(name) => config.compress_requests(name),
        None => config,
    }
}

/// Store client error.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("RPC error ({0})")]
    Rpc(Box<ConnectError>),
    #[error("store key prefix error: {0}")]
    Prefix(#[from] StoreKeyPrefixError),
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

/// Errors returned by [`StoreKeyPrefix`] when a logical key cannot be mapped
/// into the prefixed physical keyspace.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreKeyPrefixError {
    #[error("key does not belong to this store prefix")]
    PrefixMismatch,
    #[error("key offset {offset} plus store prefix shift {shift} exceeds u16")]
    KeyOffsetOverflow { offset: u16, shift: u16 },
    #[error("key prefix error: {0}")]
    Prefix(#[from] PrefixError),
}

/// A client-side namespace layered over raw Store keys.
///
/// The prefix prepends a fixed byte string to each physical Store key and
/// stores the caller's logical key in the remaining bytes. QMDB, SQL, and
/// other higher-level instances continue to build their own logical keys as
/// before; a prefixed [`StoreClient`] maps those keys on the wire and maps
/// returned keys back before callers see them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StoreKeyPrefix {
    inner: Prefix,
}

impl StoreKeyPrefix {
    pub fn new(prefix: impl Into<Bytes>) -> Result<Self, StoreKeyPrefixError> {
        Ok(Self {
            inner: Prefix::new(prefix)?,
        })
    }

    /// The zero-width identity prefix: maps every logical key to itself, so
    /// encode/decode/range/match are all no-ops and keys pass through
    /// un-namespaced.
    pub const fn identity() -> Self {
        Self {
            inner: Prefix::empty(),
        }
    }

    /// The raw prefix bytes.
    #[inline]
    pub fn prefix(&self) -> &Bytes {
        self.inner.as_bytes()
    }

    /// True when `key` starts with this prefix. The identity prefix matches
    /// every key.
    #[inline]
    pub fn matches(&self, key: &[u8]) -> bool {
        self.inner.matches(key)
    }

    /// Maximum logical key bytes available under this prefix.
    #[inline]
    pub fn max_logical_key_len(&self) -> usize {
        self.inner.max_payload_len()
    }

    /// Encode a logical key into the physical Store keyspace. The identity
    /// prefix returns a refcount-only clone of `key`.
    pub fn encode_key(&self, key: &Key) -> Result<Key, StoreKeyPrefixError> {
        Ok(self.inner.encode_key(key)?)
    }

    /// Decode a physical Store key back into the logical keyspace as a
    /// zero-copy slice of `key`'s backing storage.
    pub fn decode_key(&self, key: &Key) -> Result<Key, StoreKeyPrefixError> {
        self.inner
            .strip(key)
            .map_err(|_| StoreKeyPrefixError::PrefixMismatch)
    }

    /// Encode an inclusive logical range into the physical Store keyspace.
    ///
    /// Empty `end` means unbounded in the logical keyspace and is narrowed to
    /// this prefix's physical upper bound. Long logical upper bounds are
    /// clamped to the maximum logical key length representable under this
    /// prefix; this keeps scans over full-width prefix bounds (whose upper
    /// bound is intentionally `MAX_KEY_LEN` bytes) working.
    pub fn encode_range(&self, start: &Key, end: &Key) -> Result<(Key, Key), StoreKeyPrefixError> {
        let start = self.encode_key(start)?;
        let end = if end.is_empty() {
            self.inner.bounds().1
        } else {
            let max_len = self.max_logical_key_len();
            if end.len() > max_len {
                self.encode_key(&end.slice(..max_len))?
            } else {
                self.encode_key(end)?
            }
        };
        Ok((start, end))
    }

    fn prefix_selector(
        &self,
        selector: &crate::selector::Selector,
    ) -> Result<crate::selector::Selector, StoreKeyPrefixError> {
        let prefix = self.inner.join(&Prefix::new(selector.prefix.clone())?)?;
        Ok(crate::selector::Selector {
            prefix: prefix.as_bytes().clone(),
            payload_regex: selector.payload_regex.clone(),
        })
    }
}

/// A physical [`StoreClient`] paired with a [`StoreKeyPrefix`] that namespaces
/// every key on the wire. The prefix can be the zero-width
/// [`StoreKeyPrefix::identity`], representing the un-namespaced case.
#[derive(Clone, Debug)]
pub struct PrefixedStoreClient {
    client: StoreClient,
    prefix: StoreKeyPrefix,
}

impl PrefixedStoreClient {
    /// Pair a physical client with an explicit namespace prefix.
    pub fn new(client: StoreClient, prefix: StoreKeyPrefix) -> Self {
        Self { client, prefix }
    }

    /// Pair a physical client with the zero-width [`StoreKeyPrefix::identity`],
    /// so keys pass through untranslated.
    pub fn empty(client: StoreClient) -> Self {
        Self::new(client, StoreKeyPrefix::identity())
    }

    /// The configured key prefix.
    pub fn key_prefix(&self) -> &StoreKeyPrefix {
        &self.prefix
    }

    /// Borrow the underlying physical transport. Operations performed directly
    /// on it are *not* namespaced; prefer the methods on this type.
    pub fn client(&self) -> &StoreClient {
        &self.client
    }

    // --- key translation -----------------------------------------------------

    /// Encode a logical key as it will appear in the physical Store.
    pub fn encode_store_key(&self, key: &Key) -> Result<Key, ClientError> {
        Ok(self.prefix.encode_key(key)?)
    }

    /// Decode a physical Store key into this client's logical keyspace.
    pub fn decode_store_key(&self, key: &Key) -> Result<Key, ClientError> {
        Ok(self.prefix.decode_key(key)?)
    }

    fn encode_store_range(&self, start: &Key, end: &Key) -> Result<(Key, Key), ClientError> {
        Ok(self.prefix.encode_range(start, end)?)
    }

    fn prefix_prune_policies(
        &self,
        policies: &[crate::prune_policy::PrunePolicy],
    ) -> Result<Vec<crate::prune_policy::PrunePolicy>, ClientError> {
        policies
            .iter()
            .map(|policy| {
                use crate::prune_policy::{PolicyScope, PrunePolicy};
                let scope = match &policy.scope {
                    PolicyScope::Keys(scope) => {
                        let mut scope = scope.clone();
                        scope.selector = self.prefix.prefix_selector(&scope.selector)?;
                        PolicyScope::Keys(scope)
                    }
                    PolicyScope::Sequence => PolicyScope::Sequence,
                };
                Ok(PrunePolicy {
                    scope,
                    retain: policy.retain.clone(),
                })
            })
            .collect::<Result<Vec<_>, StoreKeyPrefixError>>()
            .map_err(ClientError::from)
    }

    fn prefix_stream_filter(
        &self,
        filter: crate::stream_filter::StreamFilter,
    ) -> Result<crate::stream_filter::StreamFilter, ClientError> {
        let selectors = filter
            .selectors
            .iter()
            .map(|mk| self.prefix.prefix_selector(mk))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(crate::stream_filter::StreamFilter {
            selectors,
            value_filters: filter.value_filters,
        })
    }

    fn prefix_reduce_request(
        &self,
        request: &DomainRangeReduceRequest,
    ) -> Result<DomainRangeReduceRequest, ClientError> {
        let mut request = request.clone();
        shift_reduce_request_key_offsets(self.prefix.prefix().len(), &mut request)?;
        Ok(request)
    }

    // --- service-grouped accessors -------------------------------------------

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

    /// Create an unseeded serializable read session over this namespace.
    pub fn create_session(&self) -> SerializableReadSession {
        self.create_session_with_sequence(0)
    }

    /// Create a serializable read session pinned to at least `sequence`.
    pub fn create_session_with_sequence(&self, sequence: u64) -> SerializableReadSession {
        SerializableReadSession {
            client: self.clone(),
            state: Arc::new(SessionState {
                sequence: Arc::new(AtomicU64::new(sequence)),
                init_gate: tokio::sync::Mutex::new(()),
            }),
        }
    }

    // --- writes --------------------------------------------------------------

    pub(crate) async fn put(&self, kvs: &[(&Key, &[u8])]) -> Result<u64, ClientError> {
        let keys = kvs
            .iter()
            .map(|(key, _)| self.encode_store_key(key))
            .collect::<Result<Vec<_>, _>>()?;
        let prefixed: Vec<(&Key, &[u8])> = keys
            .iter()
            .zip(kvs.iter())
            .map(|(key, (_, value))| (key, *value))
            .collect();
        self.client.put_physical(&prefixed).await
    }

    // --- reads ---------------------------------------------------------------

    pub(crate) async fn send_get(
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
        self.client
            .send_get(&self.encode_store_key(key)?, min_sequence_number)
            .await
    }

    pub(crate) async fn get(&self, key: &Key) -> Result<Option<Bytes>, ClientError> {
        self.client.get(&self.encode_store_key(key)?).await
    }

    pub(crate) async fn get_with_min_sequence_number(
        &self,
        key: &Key,
        min_sequence_number: u64,
    ) -> Result<Option<Bytes>, ClientError> {
        self.client
            .get_with_min_sequence_number(&self.encode_store_key(key)?, min_sequence_number)
            .await
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

    pub(crate) async fn get_many_internal(
        &self,
        keys: &[&Key],
        batch_size: u32,
        min_sequence_number: Option<u64>,
        observed_sequence: Option<Arc<AtomicU64>>,
    ) -> Result<GetManyStream, ClientError> {
        let mut proto_keys: Vec<Vec<u8>> = Vec::with_capacity(keys.len());
        for key in keys {
            let encoded = self.encode_store_key(key)?;
            if !is_valid_key_size(encoded.len()) {
                return Err(ClientError::WireFormat(format!(
                    "key length {} is outside valid store key range ({}..={})",
                    encoded.len(),
                    keys::MIN_KEY_LEN,
                    MAX_KEY_LEN
                )));
            }
            proto_keys.push(encoded.to_vec());
        }
        let mut stream = self
            .client
            .get_many_internal(
                proto_keys,
                batch_size,
                min_sequence_number,
                observed_sequence,
            )
            .await?;
        stream.key_prefix = Some(self.prefix.clone());
        Ok(stream)
    }

    pub(crate) async fn range(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_internal(start, end, limit, RangeMode::Forward, None)
            .await
    }

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

    async fn range_internal(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
        min_sequence_number: Option<u64>,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_stream_internal(
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
        .await?
        .collect()
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

    pub(crate) async fn range_stream_internal(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        mode: RangeMode,
        options: RangeStreamReadOptions,
    ) -> Result<RangeStream, ClientError> {
        let (start, end) = self.encode_store_range(start, end)?;
        let mut stream = self
            .client
            .range_stream_internal(&start, &end, limit, batch_size, mode, options)
            .await?;
        stream.key_prefix = Some(self.prefix.clone());
        Ok(stream)
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
        scalar_reduce_results(response)
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
        scalar_reduce_results(response)
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

    pub(crate) async fn range_reduce_response_internal(
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
        let (start, end) = self.encode_store_range(start, end)?;
        let request = self.prefix_reduce_request(request)?;
        self.client
            .range_reduce_response_internal(&start, &end, &request, min_sequence_number)
            .await
    }

    pub(crate) async fn prune(
        &self,
        policies: &[crate::prune_policy::PrunePolicy],
    ) -> Result<(), ClientError> {
        let policies = self.prefix_prune_policies(policies)?;
        self.client.prune(&policies).await
    }

    pub(crate) async fn subscribe(
        &self,
        filter: crate::stream_filter::StreamFilter,
        since_sequence_number: Option<u64>,
    ) -> Result<StreamSubscription, ClientError> {
        // Byte-aligned payloads let the server apply the caller's payload_regex
        // exactly against the post-prefix payload, so there is no client-side
        // re-filter: the prefix only namespaces keys on the wire.
        let filter = self.prefix_stream_filter(filter)?;
        let mut sub = self
            .client
            .subscribe_physical(filter, since_sequence_number)
            .await?;
        sub.key_prefix = Some(self.prefix.clone());
        Ok(sub)
    }

    pub(crate) async fn stream_get(
        &self,
        sequence_number: u64,
    ) -> Result<Option<Vec<(Key, Bytes)>>, ClientError> {
        let Some(owned) = self.client.stream_get_physical(sequence_number).await? else {
            return Ok(None);
        };
        let mut out = Vec::with_capacity(owned.entries.len());
        for entry in owned.entries {
            let key = Bytes::from(entry.key);
            if !self.prefix.matches(&key) {
                continue;
            }
            out.push((self.decode_store_key(&key)?, entry.value));
        }
        Ok(Some(out))
    }
}

/// Extract scalar (ungrouped) reduce results from a wire response.
fn scalar_reduce_results(
    response: exoware_proto::query::ReduceResponse,
) -> Result<Vec<Option<KvReducedValue>>, ClientError> {
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

/// A physical Store write batch assembled from one or more logical clients.
///
/// Use [`Self::push`] with the specific prefixed client that produced each
/// logical key, then [`Self::commit`] once to submit all rows in one atomic
/// Store `Put`.
#[derive(Clone, Debug, Default)]
pub struct StoreWriteBatch {
    entries: Vec<(Key, Bytes)>,
}

impl StoreWriteBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn reserve(&mut self, additional: usize) {
        self.entries.reserve(additional);
    }

    /// Stage a logical row under `client`'s namespace.
    ///
    /// The key is encoded as it is staged, so rows from several namespaces
    /// can share one batch; [`Self::commit`] writes the encoded rows
    /// verbatim through the physical client.
    pub fn push(
        &mut self,
        client: &PrefixedStoreClient,
        key: &Key,
        value: impl IntoStoreWriteValue,
    ) -> Result<&mut Self, ClientError> {
        self.entries.push((
            client.encode_store_key(key)?,
            value.into_store_write_value(),
        ));
        Ok(self)
    }

    /// The staged physical entries, in staging order.
    pub fn entries(&self) -> &[(Key, Bytes)] {
        &self.entries
    }

    pub async fn commit(&self, client: &StoreClient) -> Result<u64, ClientError> {
        client.put_prepared_physical(&self.entries).await
    }
}

/// A writer that can stage an already-prepared upload into a shared Store
/// write batch and then be notified of the batch outcome.
///
/// Implementations should keep `prepare_*` methods as inherent APIs because
/// each writer's input shape differs. Once a caller has a prepared handle,
/// this trait provides the common lifecycle:
///
/// 1. stage rows into a [`StoreWriteBatch`], consuming staged payloads if useful
/// 2. commit that batch
/// 3. mark the prepared handle persisted with the returned Store sequence
///    number, or failed if staging/commit does not complete
pub trait StoreBatchUpload {
    type Prepared: Send;
    type Receipt: Send;
    type Error: std::fmt::Display + Send;

    fn store_client(&self) -> &PrefixedStoreClient;

    fn stage_upload(
        &self,
        prepared: &mut Self::Prepared,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error>;

    fn commit_error(&self, error: ClientError) -> Self::Error;

    fn mark_upload_persisted<'a>(
        &'a self,
        prepared: Self::Prepared,
        sequence_number: u64,
    ) -> BoxFuture<'a, Self::Receipt>
    where
        Self: Sync + 'a,
        Self::Prepared: 'a;

    fn mark_upload_failed<'a>(
        &'a self,
        prepared: Self::Prepared,
        error: String,
    ) -> BoxFuture<'a, ()>
    where
        Self: Sync + 'a,
        Self::Prepared: 'a;

    fn commit_upload<'a>(
        &'a self,
        prepared: Self::Prepared,
    ) -> BoxFuture<'a, Result<Self::Receipt, Self::Error>>
    where
        Self: Sync + Sized + 'a,
        Self::Prepared: 'a,
        Self::Receipt: 'a,
        Self::Error: 'a,
    {
        Box::pin(async move {
            let mut prepared = prepared;
            let mut batch = StoreWriteBatch::new();
            if let Err(err) = self.stage_upload(&mut prepared, &mut batch) {
                let message = err.to_string();
                self.mark_upload_failed(prepared, message).await;
                return Err(err);
            }
            match batch.commit(self.store_client().client()).await {
                Ok(sequence_number) => {
                    Ok(self.mark_upload_persisted(prepared, sequence_number).await)
                }
                Err(err) => {
                    let message = err.to_string();
                    self.mark_upload_failed(prepared, message).await;
                    Err(self.commit_error(err))
                }
            }
        })
    }
}

/// A writer that can stage an already-prepared publication record into a
/// shared Store write batch and then be notified of the batch outcome.
///
/// This is the companion to [`StoreBatchUpload`] for metadata that publishes
/// already-staged data, such as QMDB watermarks. Implementations should keep
/// `prepare_*` methods as inherent APIs because each publisher decides when a
/// publication is needed.
pub trait StoreBatchPublication {
    type PreparedPublication: Send;
    type PublicationReceipt: Send;
    type Error: std::fmt::Display + Send;

    /// The namespaced client this writer stages and commits through. See
    /// [`StoreBatchUpload::store_client`].
    fn store_client(&self) -> &PrefixedStoreClient;

    fn stage_publication(
        &self,
        prepared: &Self::PreparedPublication,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error>;

    fn publication_commit_error(&self, error: ClientError) -> Self::Error;

    fn mark_publication_persisted<'a>(
        &'a self,
        prepared: Self::PreparedPublication,
        sequence_number: u64,
    ) -> BoxFuture<'a, Self::PublicationReceipt>
    where
        Self: Sync + 'a,
        Self::PreparedPublication: 'a;

    fn mark_publication_failed<'a>(
        &'a self,
        _prepared: Self::PreparedPublication,
        _error: String,
    ) -> BoxFuture<'a, ()>
    where
        Self: Sync + 'a,
        Self::PreparedPublication: 'a,
    {
        Box::pin(async {})
    }

    fn commit_publication<'a>(
        &'a self,
        prepared: Self::PreparedPublication,
    ) -> BoxFuture<'a, Result<Self::PublicationReceipt, Self::Error>>
    where
        Self: Sync + Sized + 'a,
        Self::PreparedPublication: 'a,
        Self::PublicationReceipt: 'a,
        Self::Error: 'a,
    {
        Box::pin(async move {
            let mut batch = StoreWriteBatch::new();
            if let Err(err) = self.stage_publication(&prepared, &mut batch) {
                let message = err.to_string();
                self.mark_publication_failed(prepared, message).await;
                return Err(err);
            }
            match batch.commit(self.store_client().client()).await {
                Ok(sequence_number) => Ok(self
                    .mark_publication_persisted(prepared, sequence_number)
                    .await),
                Err(err) => {
                    let message = err.to_string();
                    self.mark_publication_failed(prepared, message).await;
                    Err(self.publication_commit_error(err))
                }
            }
        })
    }
}

/// A stateful writer that owns a durable publication frontier.
///
/// This extends [`StoreBatchPublication`] with the pieces needed by writers
/// that can prepare a catch-up publication after pending uploads drain. The
/// associated prepared publication, receipt, and error types come from
/// [`StoreBatchPublication`], so databases can use this for watermarks,
/// checkpoints, catalog versions, or any similar publication record without
/// sharing QMDB-specific concepts.
pub trait StorePublicationFrontierWriter: StoreBatchPublication {
    fn latest_publication_receipt<'a>(&'a self) -> BoxFuture<'a, Option<Self::PublicationReceipt>>
    where
        Self: Sync + 'a,
        Self::PublicationReceipt: 'a;

    fn prepare_publication<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Option<Self::PreparedPublication>, Self::Error>>
    where
        Self: Sync + 'a,
        Self::PreparedPublication: 'a,
        Self::Error: 'a;

    fn flush_publication_with_receipt<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Option<Self::PublicationReceipt>, Self::Error>>
    where
        Self: Sync + 'a,
        Self::PublicationReceipt: 'a,
        Self::Error: 'a;

    fn flush_publication<'a>(&'a self) -> BoxFuture<'a, Result<(), Self::Error>>
    where
        Self: Sync + 'a,
        Self::PublicationReceipt: 'a,
        Self::Error: 'a,
    {
        Box::pin(async move { self.flush_publication_with_receipt().await.map(|_| ()) })
    }
}

/// Traversal mode for range queries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeMode {
    Forward,
    Reverse,
}

#[derive(Clone, Debug)]
pub struct RangeChunk {
    /// Rows returned in this stream frame.
    pub rows: Vec<(Key, Bytes)>,
    /// Query detail reported after reading this chunk.
    pub detail: Option<proto_query::Detail>,
}

#[derive(Clone, Debug)]
pub struct GetManyChunk {
    /// Lookup entries returned in this stream frame.
    pub entries: Vec<(Key, Option<Bytes>)>,
    /// Query detail reported after reading this chunk.
    pub detail: Option<proto_query::Detail>,
}

/// Iterator-like async range stream.
pub struct RangeStream {
    stream:
        ConnectServerStream<hyper::body::Incoming, exoware_proto::query::RangeFrameView<'static>>,
    pending_frame: Option<exoware_proto::query::RangeFrame>,
    rows_seen: usize,
    final_count: Option<usize>,
    finished: bool,
    observed_sequence: Option<Arc<AtomicU64>>,
    key_prefix: Option<StoreKeyPrefix>,
}

impl RangeStream {
    fn from_connect_stream(
        stream: ConnectServerStream<
            hyper::body::Incoming,
            exoware_proto::query::RangeFrameView<'static>,
        >,
        observed_sequence: Option<Arc<AtomicU64>>,
        key_prefix: Option<StoreKeyPrefix>,
    ) -> Self {
        Self {
            stream,
            pending_frame: None,
            rows_seen: 0,
            final_count: None,
            finished: false,
            observed_sequence,
            key_prefix,
        }
    }

    pub fn final_count(&self) -> Option<usize> {
        self.final_count
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
                    Ok(())
                }
            }
        }
    }

    pub async fn next_chunk(&mut self) -> Result<Option<RangeChunk>, ClientError> {
        loop {
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
                    return Ok(None);
                };
                frame.to_owned_message()
            };

            let detail = frame.detail.as_option().cloned();
            if let (Some(sequence_store), Some(detail)) = (&self.observed_sequence, detail.as_ref())
            {
                sequence_store.fetch_max(detail.sequence_number, Ordering::SeqCst);
            }
            let n = frame.results.len();

            // Hide default/empty wire frames from the SDK's semantic chunk stream.
            if n == 0 && detail.is_none() {
                continue;
            }

            let mut out = Vec::with_capacity(n);
            for entry in frame.results {
                let key = Bytes::from(entry.key);
                let key = match &self.key_prefix {
                    Some(prefix) => prefix.decode_key(&key)?,
                    None => key,
                };
                out.push((key, entry.value));
            }
            self.rows_seen += n;
            return Ok(Some(RangeChunk { rows: out, detail }));
        }
    }

    pub async fn collect(mut self) -> Result<Vec<(Key, Bytes)>, ClientError> {
        let mut entries = Vec::new();
        while let Some(chunk) = self.next_chunk().await? {
            entries.extend(chunk.rows);
        }
        Ok(entries)
    }
}

pub struct GetManyStream {
    stream:
        ConnectServerStream<hyper::body::Incoming, exoware_proto::query::GetManyFrameView<'static>>,
    pending_frame: Option<exoware_proto::query::GetManyFrame>,
    finished: bool,
    observed_sequence: Option<Arc<AtomicU64>>,
    key_prefix: Option<StoreKeyPrefix>,
}

impl GetManyStream {
    fn from_connect_stream(
        stream: ConnectServerStream<
            hyper::body::Incoming,
            exoware_proto::query::GetManyFrameView<'static>,
        >,
        observed_sequence: Option<Arc<AtomicU64>>,
        key_prefix: Option<StoreKeyPrefix>,
    ) -> Self {
        Self {
            stream,
            pending_frame: None,
            finished: false,
            observed_sequence,
            key_prefix,
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
                    Ok(())
                }
            }
        }
    }

    pub async fn next_chunk(&mut self) -> Result<Option<GetManyChunk>, ClientError> {
        loop {
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
                    return Ok(None);
                };
                frame.to_owned_message()
            };

            let detail = frame.detail.as_option().cloned();
            if let (Some(sequence_store), Some(detail)) = (&self.observed_sequence, detail.as_ref())
            {
                sequence_store.fetch_max(detail.sequence_number, Ordering::SeqCst);
            }
            let n = frame.results.len();

            // Hide default/empty wire frames from the SDK's semantic chunk stream.
            if n == 0 && detail.is_none() {
                continue;
            }

            let mut out = Vec::with_capacity(n);
            for entry in frame.results {
                let key = Bytes::from(entry.key);
                let key = match &self.key_prefix {
                    Some(prefix) => prefix.decode_key(&key)?,
                    None => key,
                };
                out.push((key, entry.value));
            }
            return Ok(Some(GetManyChunk {
                entries: out,
                detail,
            }));
        }
    }

    pub async fn collect(mut self) -> Result<HashMap<Key, Bytes>, ClientError> {
        let mut map = HashMap::new();
        while let Some(chunk) = self.next_chunk().await? {
            for (key, value) in chunk.entries {
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
/// reapplies its own filter if it needs to know which selector matched —
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
        exoware_proto::log::stream::v1::SubscribeResponseView<'static>,
    >,
    key_prefix: Option<StoreKeyPrefix>,
}

impl std::fmt::Debug for StreamSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamSubscription").finish_non_exhaustive()
    }
}

impl StreamSubscription {
    /// Pull the next frame. `Ok(None)` = server closed the stream cleanly.
    pub async fn next(&mut self) -> Result<Option<StreamSubscriptionFrame>, ClientError> {
        loop {
            match self
                .stream
                .message()
                .await
                .map_err(client_error_from_connect)?
            {
                Some(view) => {
                    let owned = view.to_owned_message();
                    let mut entries = Vec::with_capacity(owned.entries.len());
                    for entry in owned.entries {
                        let key = Bytes::from(entry.key);
                        let key = match &self.key_prefix {
                            Some(prefix) => prefix.decode_key(&key)?,
                            None => key,
                        };
                        entries.push(StreamSubscriptionEntry {
                            key,
                            value: entry.value,
                        });
                    }
                    if entries.is_empty() {
                        continue;
                    }
                    let frame = StreamSubscriptionFrame {
                        sequence_number: owned.sequence_number,
                        entries,
                    };
                    return Ok(Some(frame));
                }
                None => {
                    if let Some(err) = self.stream.error() {
                        return Err(client_error_from_connect(err.clone()));
                    } else {
                        return Ok(None);
                    }
                }
            }
        }
    }
}

/// Inspect a Connect error for `log.stream.BATCH_EVICTED` / `BATCH_NOT_FOUND`
/// `ErrorInfo` details. Used by `get_batch` to collapse both into `Ok(None)`.
fn is_batch_missing_error(err: &ConnectError) -> bool {
    match proto_decode_connect_error(err) {
        Ok(decoded) => decoded.error_info.is_some_and(|info| {
            info.domain == "log.stream"
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
    #[error("StoreClientBuilder: missing stream URL (set stream_url or url)")]
    MissingStreamUrl,
    #[error("StoreClientBuilder: invalid URL \"{url}\": {source}")]
    InvalidUrl {
        url: String,
        source: http::uri::InvalidUri,
    },
}

/// Configures a [`StoreClient`] with explicit bases for health probes and store services.
///
/// Use [`StoreClient::builder()`] to construct. Call [`Self::url`] to point every
/// service at the same origin, or set each base separately. Finish with [`Self::build`].
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

    /// Base URL for the ingest service (`log.ingest.v1.Service`).
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

    /// Base URL for the stream service (`log.stream.v1.Service`).
    pub fn stream_url(mut self, url: &str) -> Self {
        self.stream_url = Some(trim_connect_base(url));
        self
    }

    /// Retry policy for idempotent read operations (get / range / reduce).
    pub fn retry_config(mut self, retry: RetryConfig) -> Self {
        self.retry_config = retry.sanitized();
        self
    }

    /// Codec for compressing **outgoing** RPC request bodies (default [`ConnectRequestCompression::None`]).
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
        let stream_url = self.stream_url.ok_or(ClientBuildError::MissingStreamUrl)?;
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
/// Streamed query reads (`get_many`, `range_stream`) expose their sequence in
/// each returned chunk's detail, so if one of those is the first successful
/// read, the session is pinned once the first detail-bearing chunk is consumed.
#[derive(Clone, Debug)]
pub struct SerializableReadSession {
    client: PrefixedStoreClient,
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
            .expect("url sets all service URLs")
    }

    /// Pair this physical client with `prefix`, yielding the logical
    /// [`PrefixedStoreClient`] that namespaces every operation.
    pub fn prefixed(&self, prefix: StoreKeyPrefix) -> PrefixedStoreClient {
        PrefixedStoreClient::new(self.clone(), prefix)
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

    /// Submit a KV batch via Connect `Put`.
    ///
    /// On success returns the **store sequence number** from the response. Use it for immediate
    /// `get_with_min_sequence_number` / range calls or to seed
    /// [`PrefixedStoreClient::create_session_with_sequence`].
    /// If the request succeeds, the server accepts the full batch (count is `kvs.len()`).
    pub(crate) async fn put_physical(&self, kvs: &[(&Key, &[u8])]) -> Result<u64, ClientError> {
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
            proto_kvs.push(exoware_proto::common::Entry {
                key: key.to_vec(),
                value: Bytes::copy_from_slice(value),
                ..Default::default()
            });
        }
        self.send_put(proto_kvs).await
    }

    async fn put_prepared_physical(&self, kvs: &[(Key, Bytes)]) -> Result<u64, ClientError> {
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
            proto_kvs.push(exoware_proto::common::Entry {
                key: key.to_vec(),
                value: value.clone(),
                ..Default::default()
            });
        }
        self.send_put(proto_kvs).await
    }

    async fn send_put(&self, kvs: Vec<exoware_proto::common::Entry>) -> Result<u64, ClientError> {
        let config =
            store_connect_client_config(self.ingest_uri.clone(), self.connect_request_compression);
        let client = IngestServiceClient::new(self.connect_http.clone(), config);
        let response = client
            .put(ProtoPutRequest {
                kvs,
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
        let (response, _detail) = self
            .send_get(key, self.normalize_min_sequence_number(min_sequence_number))
            .await?;
        Ok(response.value)
    }

    /// Physical `get_many` over already-encoded wire keys. The
    /// [`PrefixedStoreClient`] wrapper encodes + validates and attaches the
    /// prefix to the returned stream for decoding.
    pub(crate) async fn get_many_internal(
        &self,
        proto_keys: Vec<Vec<u8>>,
        batch_size: u32,
        min_sequence_number: Option<u64>,
        observed_sequence: Option<Arc<AtomicU64>>,
    ) -> Result<GetManyStream, ClientError> {
        let config =
            store_connect_client_config(self.query_uri.clone(), self.connect_request_compression);
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
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
                        GetManyStream::from_connect_stream(stream, observed_sequence.clone(), None);
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

    /// Open a physical subscription over an already-encoded `filter`. The
    /// returned [`StreamSubscription`] carries no prefix; the logical
    /// [`PrefixedStoreClient`] wrapper attaches one for decoding.
    async fn subscribe_physical(
        &self,
        filter: crate::stream_filter::StreamFilter,
        since_sequence_number: Option<u64>,
    ) -> Result<StreamSubscription, ClientError> {
        crate::stream_filter::validate_filter(&filter)
            .map_err(|e| ClientError::WireFormat(e.to_string()))?;
        let selectors = filter
            .selectors
            .into_iter()
            .map(|mk| exoware_proto::common::kv::v1::Selector {
                prefix: mk.prefix,
                payload_regex: mk.payload_regex.0,
                ..Default::default()
            })
            .collect();
        let value_filters = filter
            .value_filters
            .into_iter()
            .map(|vf| {
                use crate::stream_filter::Filter;
                use exoware_proto::common::kv::v1::filter::Kind as ProtoKind;
                let kind = match vf {
                    Filter::Exact(bytes) => ProtoKind::Exact(bytes),
                    Filter::Prefix(bytes) => ProtoKind::Prefix(bytes),
                    Filter::Regex(pattern) => ProtoKind::Regex(pattern),
                };
                exoware_proto::common::kv::v1::Filter {
                    kind: Some(kind),
                    ..Default::default()
                }
            })
            .collect();
        let request = exoware_proto::log::stream::v1::SubscribeRequest {
            selectors,
            value_filters,
            since_sequence_number,
            ..Default::default()
        };
        let config =
            store_connect_client_config(self.stream_uri.clone(), self.connect_request_compression);
        let client =
            exoware_proto::log::stream::v1::ServiceClient::new(self.connect_http.clone(), config);
        let stream = client
            .subscribe(request)
            .await
            .map_err(client_error_from_connect)?;
        Ok(StreamSubscription {
            stream,
            key_prefix: None,
        })
    }

    /// Fetch a batch by sequence number, returning the raw owned response
    /// (physical keys, no decode). `None` collapses the server's
    /// `BATCH_EVICTED` / `BATCH_NOT_FOUND` errors. The [`PrefixedStoreClient`]
    /// wrapper consumes the entries in one pass to filter + decode.
    async fn stream_get_physical(
        &self,
        sequence_number: u64,
    ) -> Result<Option<exoware_proto::log::stream::v1::GetResponse>, ClientError> {
        let config =
            store_connect_client_config(self.stream_uri.clone(), self.connect_request_compression);
        let client =
            exoware_proto::log::stream::v1::ServiceClient::new(self.connect_http.clone(), config);
        match client
            .get(exoware_proto::log::stream::v1::GetRequest {
                sequence_number,
                ..Default::default()
            })
            .await
        {
            Ok(resp) => Ok(Some(resp.into_owned())),
            Err(err) => {
                if is_batch_missing_error(&err) {
                    Ok(None)
                } else {
                    Err(client_error_from_connect(err))
                }
            }
        }
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
                        key: key.clone().into(),
                        min_sequence_number,
                        ..Default::default()
                    })
                    .await
            })
            .await?;
        let owned = response.into_owned();
        let detail = owned.detail.as_option().cloned();
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
                    start: start.clone().into(),
                    end: end.clone().into(),
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
                RangeStream::from_connect_stream(response, options.observed_sequence.clone(), None);
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
                        start: start.clone().into(),
                        end: end.clone().into(),
                        params: Some(proto_params.clone()).into(),
                        min_sequence_number,
                        ..Default::default()
                    })
                    .await
            })
            .await?;
        let owned = response.into_owned();
        let detail = owned.detail.as_option().cloned();
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

fn shift_reduce_request_key_offsets(
    prefix_len: usize,
    request: &mut DomainRangeReduceRequest,
) -> Result<(), StoreKeyPrefixError> {
    // A byte-aligned store prefix shifts every key field past its bytes.
    // `KeyField` offsets are byte-granular, so they shift by the whole prefix
    // length in bytes; `ZOrderKey` offsets remain bit-granular, so they shift
    // by `prefix_len * 8` bits. `prefix_len` comes from a validated
    // `StoreKeyPrefix`, so both shifts fit u16 (`MAX_KEY_LEN * 8` = 2032).
    debug_assert!(prefix_len <= MAX_KEY_LEN);
    let shift_bytes = prefix_len as u16;
    let shift_bits = shift_bytes * 8;
    for reducer in &mut request.reducers {
        if let Some(expr) = &mut reducer.expr {
            shift_expr_key_offsets(shift_bytes, shift_bits, expr)?;
        }
    }
    for expr in &mut request.group_by {
        shift_expr_key_offsets(shift_bytes, shift_bits, expr)?;
    }
    if let Some(filter) = &mut request.filter {
        for check in &mut filter.checks {
            shift_field_ref_key_offset(shift_bytes, shift_bits, &mut check.field)?;
        }
    }
    Ok(())
}

fn shift_expr_key_offsets(
    shift_bytes: u16,
    shift_bits: u16,
    expr: &mut KvExpr,
) -> Result<(), StoreKeyPrefixError> {
    match expr {
        KvExpr::Field(field) => shift_field_ref_key_offset(shift_bytes, shift_bits, field),
        KvExpr::Literal(_) => Ok(()),
        KvExpr::Add(left, right)
        | KvExpr::Sub(left, right)
        | KvExpr::Mul(left, right)
        | KvExpr::Div(left, right) => {
            shift_expr_key_offsets(shift_bytes, shift_bits, left)?;
            shift_expr_key_offsets(shift_bytes, shift_bits, right)
        }
        KvExpr::Lower(inner) | KvExpr::DateTruncDay(inner) => {
            shift_expr_key_offsets(shift_bytes, shift_bits, inner)
        }
    }
}

fn shift_field_ref_key_offset(
    shift_bytes: u16,
    shift_bits: u16,
    field: &mut KvFieldRef,
) -> Result<(), StoreKeyPrefixError> {
    match field {
        KvFieldRef::Key { byte_offset, .. } => {
            *byte_offset = byte_offset.checked_add(shift_bytes).ok_or(
                StoreKeyPrefixError::KeyOffsetOverflow {
                    offset: *byte_offset,
                    shift: shift_bytes,
                },
            )?;
            Ok(())
        }
        KvFieldRef::ZOrderKey { bit_offset, .. } => {
            *bit_offset = bit_offset.checked_add(shift_bits).ok_or(
                StoreKeyPrefixError::KeyOffsetOverflow {
                    offset: *bit_offset,
                    shift: shift_bits,
                },
            )?;
            Ok(())
        }
        KvFieldRef::Value { .. } => Ok(()),
    }
}

// --- Service-grouped accessors ---------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Ingest<'a> {
    c: &'a PrefixedStoreClient,
}

#[derive(Clone, Copy, Debug)]
pub struct Query<'a> {
    c: &'a PrefixedStoreClient,
}

#[derive(Clone, Copy, Debug)]
pub struct Compact<'a> {
    c: &'a PrefixedStoreClient,
}

#[derive(Clone, Copy, Debug)]
pub struct Stream<'a> {
    c: &'a PrefixedStoreClient,
}

impl<'a> Ingest<'a> {
    pub async fn put(&self, kvs: &[(&Key, &[u8])]) -> Result<u64, ClientError> {
        self.c.put(kvs).await
    }

    /// Submit a [`StoreWriteBatch`] that has already been encoded into the
    /// physical Store keyspace.
    pub async fn put_prepared(&self, batch: &StoreWriteBatch) -> Result<u64, ClientError> {
        batch.commit(self.c.client()).await
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
    /// `log.stream.v1.Service.Subscribe` — see `StreamSubscription::next`
    /// for consuming delivered frames. `since_sequence_number = None` starts
    /// live from the next Put; `Some(N)` replays retained batches before
    /// transitioning to live. An evicted `since` returns a
    /// `ConnectError::out_of_range` carrying `ErrorInfo.reason = "BATCH_EVICTED"`.
    pub async fn subscribe(
        &self,
        filter: crate::stream_filter::StreamFilter,
        since_sequence_number: Option<u64>,
    ) -> Result<StreamSubscription, ClientError> {
        self.c.subscribe(filter, since_sequence_number).await
    }

    /// `log.stream.v1.Service.Get` — `Ok(None)` collapses the server's
    /// `BATCH_EVICTED` / `BATCH_NOT_FOUND` error details.
    pub async fn get(
        &self,
        sequence_number: u64,
    ) -> Result<Option<Vec<(Key, Bytes)>>, ClientError> {
        self.c.stream_get(sequence_number).await
    }
}

impl SerializableReadSession {
    /// Fixed sequence floor for this session, if one has been established yet.
    ///
    /// Fresh sessions start with `None` unless created via
    /// [`PrefixedStoreClient::create_session_with_sequence`]. A first streamed query
    /// read (`get_many`, `range_stream`) sets this once a detail-bearing chunk
    /// is consumed.
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
                    Ok(response.value)
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
        // `Key` is `Bytes`; cloning shares the backing buffer (refcount bump)
        // instead of deep-copying each key.
        let keys_owned: Vec<Key> = keys.iter().map(|k| (**k).clone()).collect();
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
    use crate::kv_codec::{KvFieldKind, KvPredicate, KvPredicateCheck, KvPredicateConstraint};
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
        assert_eq!(client.stream_uri.to_string(), "http://localhost:10000/");
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
        assert!(matches!(
            StoreClient::builder()
                .health_url("http://h")
                .ingest_url("http://i")
                .query_url("http://q")
                .compact_url("http://c")
                .build(),
            Err(ClientBuildError::MissingStreamUrl)
        ));
    }

    #[test]
    fn client_trims_trailing_slash() {
        let client = StoreClient::new("http://localhost:10000/");
        assert_eq!(client.health_url, "http://localhost:10000");
    }

    #[test]
    fn create_session_starts_unseeded() {
        let client = PrefixedStoreClient::empty(StoreClient::new("http://localhost:10000/"));
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
        let client = PrefixedStoreClient::empty(StoreClient::new("http://localhost:10000/"));
        let session = client.create_session_with_sequence(27);
        assert_eq!(session.fixed_sequence(), Some(27));
    }

    #[test]
    fn store_key_prefix_round_trips_logical_keys() {
        let prefix = StoreKeyPrefix::new(vec![0x0A]).unwrap();
        let logical = Bytes::from_static(b"hello");
        let physical = prefix.encode_key(&logical).unwrap();
        assert!(prefix.matches(&physical));
        assert_eq!(prefix.decode_key(&physical).unwrap(), logical);
    }

    #[test]
    fn identity_prefix_encode_decode_are_zero_copy() {
        let prefix = StoreKeyPrefix::identity();
        let logical = Bytes::from_static(b"passthrough-key");
        let physical = prefix.encode_key(&logical).unwrap();
        // The identity prefix copies no key bytes: encode/decode share backing.
        assert_eq!(physical.as_ptr(), logical.as_ptr());
        let decoded = prefix.decode_key(&physical).unwrap();
        assert_eq!(decoded.as_ptr(), logical.as_ptr());
        assert_eq!(decoded, logical);
    }

    #[test]
    fn uniform_width_prefixes_are_pairwise_disjoint() {
        // Six leaf prefixes sharing one uniform (1-byte) width.
        let all = [
            StoreKeyPrefix::new(vec![0]).unwrap(),
            StoreKeyPrefix::new(vec![1]).unwrap(),
            StoreKeyPrefix::new(vec![2]).unwrap(),
            StoreKeyPrefix::new(vec![3]).unwrap(),
            StoreKeyPrefix::new(vec![4]).unwrap(),
            StoreKeyPrefix::new(vec![5]).unwrap(),
        ];
        // A key encoded under one prefix never matches another's prefix, so a
        // prefix-bounded range scan in one can't observe another's keys (this is
        // the bug being fixed). Same-length prefixes are pairwise disjoint.
        let logical = Bytes::from_static(b"\x00\x10whatever-block-meta-or-op-log-key");
        for (i, pa) in all.iter().enumerate() {
            let physical = pa.encode_key(&logical).unwrap();
            assert!(pa.matches(&physical));
            assert_eq!(pa.decode_key(&physical).unwrap(), logical);
            for (j, pb) in all.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert!(
                    !pb.matches(&physical),
                    "prefix {j} matched a key encoded under prefix {i}",
                );
            }
        }
    }

    #[test]
    fn prefixed_store_client_always_carries_its_prefix() {
        let base = StoreClient::new("http://localhost:8090");
        let prefix = StoreKeyPrefix::new(vec![0]).unwrap();
        let client = base.prefixed(prefix.clone());
        assert_eq!(client.key_prefix(), &prefix);
        // The logical client encodes through its prefix.
        let logical = Bytes::from_static(b"row");
        assert_eq!(
            client.encode_store_key(&logical).unwrap(),
            prefix.encode_key(&logical).unwrap(),
        );
    }

    #[test]
    fn store_key_prefix_clamps_long_logical_range_upper_bound() {
        let prefix = StoreKeyPrefix::new(vec![0x02]).unwrap();
        // A full-width logical upper bound (MAX_KEY_LEN bytes of 0xFF), as an
        // un-prefixed scan's inclusive end would be.
        let logical_start = Bytes::new();
        let logical_end = Bytes::from(vec![0xFFu8; MAX_KEY_LEN]);
        assert_eq!(logical_end.len(), MAX_KEY_LEN);

        let (physical_start, physical_end) =
            prefix.encode_range(&logical_start, &logical_end).unwrap();
        assert!(prefix.matches(&physical_start));
        assert!(prefix.matches(&physical_end));
        // The logical end clamps to max_logical_key_len (253) before prefixing,
        // so the physical end is exactly MAX_KEY_LEN bytes.
        assert_eq!(prefix.max_logical_key_len(), MAX_KEY_LEN - 1);
        assert_eq!(physical_end.len(), MAX_KEY_LEN);
        assert_eq!(prefix.decode_key(&physical_start).unwrap(), logical_start);
    }

    #[test]
    fn store_key_prefix_rewrites_selector_family() {
        let prefix = StoreKeyPrefix::new(vec![0x05]).unwrap();
        let logical = crate::selector::Selector {
            prefix: Bytes::copy_from_slice(&[0x06]),
            payload_regex: crate::kv_codec::Utf8::from("(?s).*"),
        };
        let physical = prefix.prefix_selector(&logical).unwrap();
        assert_eq!(physical.prefix.as_ref(), &[0x05, 0x06]);
        assert_eq!(physical.payload_regex, logical.payload_regex);
    }

    #[test]
    fn store_key_prefix_composed_selector_reconstructs_and_strips_cleanly() {
        // Reproduces the selector-merge -> reconstruct-codec path that the old
        // bit-padding KeyCodec corrupted: a store namespace prefix is composed
        // onto a logical selector's prefix, and then a codec is rebuilt FROM the
        // merged selector prefix and used to strip keys. Under the old bit-packed
        // codec, composing two sub-byte prefixes and reconstructing a codec left a
        // spurious trailing 0x00 in the stripped payload; the byte-prefix design
        // must strip cleanly.

        // Multi-byte store namespace so the payload offset shift (= prefix length)
        // is genuinely exercised.
        let prefix = StoreKeyPrefix::new(vec![0x05, 0x06]).unwrap();
        let logical = crate::selector::Selector {
            prefix: Bytes::copy_from_slice(&[0x07]),
            payload_regex: crate::kv_codec::Utf8::from("(?s).*"),
        };

        // Compose via the real SDK merge path (byte-concatenates the store prefix
        // onto the selector prefix).
        let merged = prefix.prefix_selector(&logical).unwrap();
        assert_eq!(merged.prefix.as_ref(), &[0x05, 0x06, 0x07]);

        // Reconstruct the codec EXACTLY as apply_key_prune_policy does.
        let codec = Prefix::new(merged.prefix.clone()).unwrap();

        // Round-trip a real key through the reconstructed codec.
        let payload = [0xAA, 0xBB, 0xCC];
        let key = codec.encode(&payload).unwrap();
        assert_eq!(key.as_ref(), &[0x05, 0x06, 0x07, 0xAA, 0xBB, 0xCC]);
        assert!(codec.matches(&key));
        // The assertion the old codec would fail: the stripped payload is exactly
        // the original bytes, with no trailing spurious 0x00 from 8-bit padding.
        assert_eq!(
            codec.strip(&key).unwrap(),
            Bytes::copy_from_slice(&[0xAA, 0xBB, 0xCC])
        );

        // The scan bounds bracket the key. bounds() are inclusive on both ends:
        // start is the bare prefix, end is the prefix padded with 0xFF.
        let (start, end) = codec.bounds();
        assert!(start <= key && key <= end);

        // A key under a DIFFERENT merged prefix must not match this codec.
        let sibling = Prefix::new(vec![0x05, 0x06, 0x08])
            .unwrap()
            .encode(&[0x11])
            .unwrap();
        assert!(!codec.matches(&sibling));
    }

    #[test]
    fn store_key_prefix_stream_filter_passes_payload_regex_through() {
        // The stream path no longer broadens the payload regex: byte-aligned
        // payloads let the server apply the caller's real regex to the
        // post-prefix payload, so it must pass through unchanged.
        let client = StoreClient::builder()
            .url("http://localhost:10000")
            .build()
            .unwrap()
            .prefixed(StoreKeyPrefix::new(vec![0x05]).unwrap());
        let filter = crate::stream_filter::StreamFilter {
            selectors: vec![crate::selector::Selector {
                prefix: Bytes::copy_from_slice(&[0x06]),
                payload_regex: crate::kv_codec::Utf8::from("(?s)foo.*"),
            }],
            value_filters: vec![],
        };
        let physical = client.prefix_stream_filter(filter.clone()).unwrap();
        assert_eq!(physical.selectors[0].prefix.as_ref(), &[0x05, 0x06]);
        assert_eq!(
            physical.selectors[0].payload_regex,
            filter.selectors[0].payload_regex
        );
    }

    #[test]
    fn prefixed_reduce_request_shifts_key_field_offsets() {
        let client = StoreClient::builder()
            .url("http://localhost:10000")
            .build()
            .unwrap()
            .prefixed(StoreKeyPrefix::new(vec![0x01, 0x02, 0x03]).unwrap());
        let request = DomainRangeReduceRequest {
            reducers: vec![crate::RangeReducerSpec {
                op: crate::RangeReduceOp::SumField,
                expr: Some(KvExpr::Field(KvFieldRef::Key {
                    byte_offset: 9,
                    kind: KvFieldKind::UInt64,
                })),
            }],
            group_by: vec![KvExpr::Field(KvFieldRef::ZOrderKey {
                bit_offset: 12,
                field_position: 0,
                field_widths: vec![8],
                kind: KvFieldKind::UInt64,
            })],
            filter: Some(KvPredicate {
                checks: vec![KvPredicateCheck {
                    field: KvFieldRef::Value {
                        index: 0,
                        kind: KvFieldKind::UInt64,
                        nullable: false,
                    },
                    constraint: KvPredicateConstraint::UInt64Range {
                        min: Some(1),
                        max: Some(9),
                    },
                }],
                contradiction: false,
            }),
        };

        let shifted = client.prefix_reduce_request(&request).unwrap();
        let Some(KvExpr::Field(KvFieldRef::Key { byte_offset, .. })) =
            shifted.reducers[0].expr.as_ref()
        else {
            panic!("expected key field reducer");
        };
        // KeyField offsets are byte-granular: a 3-byte prefix shifts by 3 bytes,
        // so 9 -> 12.
        assert_eq!(*byte_offset, 12);
        let KvExpr::Field(KvFieldRef::ZOrderKey { bit_offset, .. }) = &shifted.group_by[0] else {
            panic!("expected z-order group field");
        };
        // Z-order offsets stay bit-granular: a 3-byte prefix shifts by 3*8 = 24
        // bits, so 12 -> 36.
        assert_eq!(*bit_offset, 36);
    }

    #[test]
    fn store_write_batch_uses_each_clients_prefix() {
        let base = StoreClient::new("http://localhost:10000");
        let a = base.prefixed(StoreKeyPrefix::new(vec![1]).unwrap());
        let b = base.prefixed(StoreKeyPrefix::new(vec![2]).unwrap());
        let key_a = Bytes::from_static(b"a");
        let key_b = Bytes::from_static(b"b");

        let mut batch = StoreWriteBatch::new();
        batch.push(&a, &key_a, b"va").unwrap();
        batch.push(&b, &key_b, b"vb").unwrap();

        assert_eq!(
            batch.entries[0].0,
            a.key_prefix().encode_key(&key_a).unwrap()
        );
        assert_eq!(
            batch.entries[1].0,
            b.key_prefix().encode_key(&key_b).unwrap()
        );
    }

    #[test]
    fn pushed_rows_round_trip_only_through_their_own_client() {
        let base = StoreClient::new("http://localhost:10000");
        let a = base.prefixed(StoreKeyPrefix::new(vec![1]).unwrap());
        let b = base.prefixed(StoreKeyPrefix::new(vec![2]).unwrap());
        let key = Bytes::from_static(b"shared-logical-key");

        let mut batch = StoreWriteBatch::new();
        batch.push(&a, &key, b"va").unwrap();
        batch.push(&b, &key, b"vb").unwrap();

        // The same logical key staged through two namespaces produces two
        // distinct physical rows, in staging order.
        let entries = batch.entries();
        assert_eq!(entries.len(), 2);
        assert_ne!(entries[0].0, entries[1].0);

        // Each physical key decodes back through its own namespace and is
        // rejected by the other.
        assert_eq!(a.decode_store_key(&entries[0].0).unwrap(), key);
        assert_eq!(b.decode_store_key(&entries[1].0).unwrap(), key);
        assert!(a.decode_store_key(&entries[1].0).is_err());
        assert!(b.decode_store_key(&entries[0].0).is_err());
    }

    #[test]
    fn identity_prefix_stages_keys_verbatim() {
        let base = StoreClient::new("http://localhost:10000");
        let plain = PrefixedStoreClient::empty(base);
        let key = Bytes::from_static(b"raw-key");

        let mut batch = StoreWriteBatch::new();
        batch.push(&plain, &key, b"v").unwrap();

        assert_eq!(batch.entries()[0].0, key);
    }

    #[test]
    fn push_rejects_keys_exceeding_prefixed_capacity() {
        let base = StoreClient::new("http://localhost:10000");
        let a = base.prefixed(StoreKeyPrefix::new(vec![1]).unwrap());
        let max = a.key_prefix().max_logical_key_len();

        let mut batch = StoreWriteBatch::new();
        let at_capacity = Key::from(vec![7u8; max]);
        batch.push(&a, &at_capacity, b"v").unwrap();

        let oversize = Key::from(vec![7u8; max + 1]);
        assert!(batch.push(&a, &oversize, b"v").is_err());
        assert_eq!(batch.len(), 1);
    }

    fn hex_encode(data: &[u8]) -> String {
        hex::encode(data)
    }

    fn hex_decode(s: &str) -> Option<Vec<u8>> {
        hex::decode(s).ok()
    }
}
