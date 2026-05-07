use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use commonware_codec::Encode;
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Family, Graftable, Location},
    qmdb::{
        any::{
            ordered::variable::Operation as QmdbOperation,
            unordered::variable::Operation as UnorderedQmdbOperation,
        },
        immutable::variable::Operation as ImmutableOperation,
        keyless::variable::Operation as KeylessOperation,
    },
};

use connectrpc::{Chain, ConnectError, ConnectRpcService, Context, ErrorCode, Limits};
use exoware_sdk::qmdb::v1::{
    current_key_lookup_result, CurrentKeyExclusionProof as ProtoCurrentKeyExclusionProof,
    CurrentKeyLookupResult as ProtoCurrentKeyLookupResult,
    CurrentKeyRangeEntry as ProtoCurrentKeyRangeEntry,
    CurrentKeyValueProof as ProtoCurrentKeyValueProof,
    CurrentOperationRangeProof as ProtoCurrentOperationRangeProof, CurrentOperationService,
    CurrentOperationServiceServer, GetCurrentOperationRangeRequestView,
    GetCurrentOperationRangeResponse, GetManyRequestView, GetManyResponse,
    GetOperationRangeRequestView, GetOperationRangeResponse, GetRangeRequestView, GetRangeResponse,
    GetRequestView, GetResponse, HistoricalMultiProof as ProtoHistoricalMultiProof,
    HistoricalOperationRangeProof as ProtoHistoricalOperationRangeProof, KeyLookupService,
    KeyLookupServiceServer, MultiProofOperation as ProtoMultiProofOperation, OperationLogService,
    OperationLogServiceServer, OrderedKeyRangeService, OrderedKeyRangeServiceServer,
    SubscribeRequestView, SubscribeResponse,
};
use exoware_sdk::store::common::v1::bytes_filter::KindView as ProtoBytesFilterKindView;
use exoware_sdk::stream_filter::{BytesFilter, CompiledBytesFilters};
use futures::future::BoxFuture;
use futures::{FutureExt, Stream};

use crate::auth::AuthenticatedBackendNamespace;
use crate::proof::{
    CurrentOperationRangeProofResult, OperationRangeCheckpoint, RawBatchMultiProof,
    RawKeyExclusionProof, RawKeyLookupProof, RawKeyRangeProof, RawKeyValueProof,
    RawUnorderedKeyValueProof,
};
use crate::subscription::{self as sub, RowClassifier};
use crate::{ImmutableClient, KeylessClient, OrderedClient, QmdbError, UnorderedClient};

const MAX_CONNECTRPC_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Decoded (key, value) payload for a QMDB operation. Either element is `None`
/// when the operation's logical key or value is absent (e.g. keyless ops).
pub struct OperationKv {
    pub key: Option<Vec<u8>>,
    pub value: Option<Vec<u8>>,
}

fn connect_limits() -> Limits {
    Limits::default()
        .max_request_body_size(MAX_CONNECTRPC_BODY_BYTES)
        .max_message_size(MAX_CONNECTRPC_BODY_BYTES)
}

fn qmdb_error_to_connect(err: QmdbError) -> ConnectError {
    match err {
        QmdbError::Client(client_err) => {
            if let Some(rpc) = client_err.rpc_error() {
                ConnectError::new(rpc.code, rpc.message.clone().unwrap_or_default())
            } else {
                ConnectError::internal(client_err.to_string())
            }
        }
        QmdbError::EmptyBatch
        | QmdbError::EmptyProofRequest
        | QmdbError::InvalidRangeLength
        | QmdbError::InvalidKeyRange { .. }
        | QmdbError::DuplicateRequestedKey { .. }
        | QmdbError::InvalidLocationRange { .. }
        | QmdbError::RangeStartOutOfBounds { .. }
        | QmdbError::EncodedValueTooLarge { .. }
        | QmdbError::SortableKeyTooLarge { .. } => ConnectError::invalid_argument(err.to_string()),
        QmdbError::WatermarkTooLow { .. } => ConnectError::out_of_range(err.to_string()),
        QmdbError::ProofKeyNotFound { .. } | QmdbError::KeyNotActive { .. } => {
            ConnectError::not_found(err.to_string())
        }
        QmdbError::CurrentProofRequiresBatchBoundary { .. }
        | QmdbError::CurrentBoundaryStateMissing { .. } => {
            ConnectError::failed_precondition(err.to_string())
        }
        QmdbError::Stream(_) => ConnectError::unavailable(err.to_string()),
        QmdbError::ProofVerification { .. }
        | QmdbError::CorruptData(_)
        | QmdbError::CommonwareMerkle(_)
        | QmdbError::WriterPoisoned(_) => ConnectError::internal(err.to_string()),
    }
}

fn raw_batch_multi_proof_to_proto<D: commonware_cryptography::Digest, F: Family>(
    proof: &RawBatchMultiProof<D, F>,
) -> ProtoHistoricalMultiProof {
    ProtoHistoricalMultiProof {
        proof: proof.proof.encode().to_vec(),
        operations: proof
            .operations
            .iter()
            .map(|(location, encoded_operation)| ProtoMultiProofOperation {
                location: location.as_u64(),
                encoded_operation: encoded_operation.clone(),
                ..Default::default()
            })
            .collect(),
        ops_root: proof
            .ops_root_witness
            .as_ref()
            .map(|_| proof.root.as_ref().to_vec())
            .unwrap_or_default(),
        ops_root_witness: proof
            .ops_root_witness
            .as_ref()
            .map(|witness| witness.encode().to_vec())
            .unwrap_or_default(),
        ..Default::default()
    }
}

fn operation_range_checkpoint_to_proto<D: commonware_cryptography::Digest, F: Family>(
    proof: &OperationRangeCheckpoint<D, F>,
) -> ProtoHistoricalOperationRangeProof {
    ProtoHistoricalOperationRangeProof {
        proof: proof.proof.encode().to_vec(),
        start_location: proof.start_location.as_u64(),
        encoded_operations: proof.encoded_operations.clone(),
        ops_root: proof
            .ops_root_witness
            .as_ref()
            .map(|_| proof.root.as_ref().to_vec())
            .unwrap_or_default(),
        ops_root_witness: proof
            .ops_root_witness
            .as_ref()
            .map(|witness| witness.encode().to_vec())
            .unwrap_or_default(),
        ..Default::default()
    }
}

fn current_operation_range_proof_to_proto<
    D: commonware_cryptography::Digest,
    Op: Encode,
    const N: usize,
    F: Family,
>(
    proof: &CurrentOperationRangeProofResult<D, Op, N, F>,
) -> ProtoCurrentOperationRangeProof {
    ProtoCurrentOperationRangeProof {
        proof: proof.proof.encode().to_vec(),
        start_location: proof.start_location.as_u64(),
        encoded_operations: proof
            .operations
            .iter()
            .map(|operation| operation.encode().to_vec())
            .collect(),
        chunks: proof.chunks.iter().map(|chunk| chunk.to_vec()).collect(),
        ..Default::default()
    }
}

fn raw_key_value_proof_to_proto<
    D: commonware_cryptography::Digest,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
>(
    proof: &RawKeyValueProof<D, K, V, N, F>,
) -> ProtoCurrentKeyValueProof
where
    QmdbOperation<F, K, V>: Encode,
{
    ProtoCurrentKeyValueProof {
        proof: proof.proof.encode().to_vec(),
        encoded_operation: proof.operation.encode().to_vec(),
        ..Default::default()
    }
}

fn raw_unordered_key_value_proof_to_proto<
    D: commonware_cryptography::Digest,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
>(
    proof: &RawUnorderedKeyValueProof<D, K, V, N, F>,
) -> ProtoCurrentKeyValueProof
where
    UnorderedQmdbOperation<F, K, V>: Encode,
{
    ProtoCurrentKeyValueProof {
        proof: proof.proof.encode().to_vec(),
        encoded_operation: proof.operation.encode().to_vec(),
        ..Default::default()
    }
}

fn raw_key_exclusion_proof_to_proto<
    D: commonware_cryptography::Digest,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
>(
    proof: &RawKeyExclusionProof<D, K, V, N, F>,
) -> ProtoCurrentKeyExclusionProof
where
    commonware_storage::qmdb::any::ordered::Update<
        K,
        commonware_storage::qmdb::any::value::VariableEncoding<V>,
    >: Encode,
{
    ProtoCurrentKeyExclusionProof {
        proof: proof.proof.encode().to_vec(),
        ..Default::default()
    }
}

fn raw_key_range_proof_to_proto<
    D: commonware_cryptography::Digest,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
>(
    proof: &RawKeyRangeProof<D, K, V, N, F>,
) -> GetRangeResponse
where
    QmdbOperation<F, K, V>: Encode,
    commonware_storage::qmdb::any::ordered::Update<
        K,
        commonware_storage::qmdb::any::value::VariableEncoding<V>,
    >: Encode,
{
    GetRangeResponse {
        entries: proof
            .entries
            .iter()
            .map(|entry| ProtoCurrentKeyRangeEntry {
                key: entry.key.clone(),
                proof: Some(raw_key_value_proof_to_proto(&entry.proof)).into(),
                ..Default::default()
            })
            .collect(),
        start_proof: proof
            .start_proof
            .as_ref()
            .map(raw_key_exclusion_proof_to_proto)
            .into(),
        end_proof: proof
            .end_proof
            .as_ref()
            .map(raw_key_exclusion_proof_to_proto)
            .into(),
        has_more: proof.has_more,
        next_start_key: proof.next_start_key.clone(),
        ..Default::default()
    }
}

#[derive(Clone)]
pub struct OrderedConnect<
    F: Graftable,
    H: Hasher,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
> {
    client: Arc<OrderedClient<F, H, K, V, N>>,
}

#[derive(Clone)]
pub struct UnorderedConnect<
    F: Graftable,
    H: Hasher,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
> {
    client: Arc<UnorderedClient<F, H, K, V>>,
}

impl<F, H, K, V, const N: usize> UnorderedConnect<F, H, K, V, N>
where
    F: Graftable,
    H: Hasher,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
{
    pub fn new(client: Arc<UnorderedClient<F, H, K, V>>) -> Self {
        Self { client }
    }
}

impl<F, H, K, V, const N: usize> OrderedConnect<F, H, K, V, N>
where
    F: Graftable,
    H: Hasher,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
{
    pub fn new(client: Arc<OrderedClient<F, H, K, V, N>>) -> Self {
        Self { client }
    }
}

/// Implemented by each QMDB backend client (`Arc<OrderedClient<...>>`,
/// `Arc<UnorderedClient<...>>`, etc.) to expose just the surface the generic
/// `OperationLogService` path needs.
trait OperationLogBackend: Clone + Send + Sync + 'static {
    type Family: commonware_storage::merkle::Family;
    type Digest: commonware_cryptography::Digest;
    /// Reject `key_filters` at subscribe time (set true for keyless, whose
    /// ops have no logical key).
    const REJECTS_KEY_FILTERS: bool = false;

    fn store_client(&self) -> &exoware_sdk::StoreClient;
    fn classify_and_filter(
        &self,
    ) -> (
        RowClassifier<Self::Family>,
        exoware_sdk::stream_filter::StreamFilter,
    );
    fn extract_operation_kv(
        &self,
        location: Location<Self::Family>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError>;
    fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location<Self::Family>,
        operations: Vec<(Location<Self::Family>, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, Self::Family>, QmdbError>> + Send;
    fn operation_range_checkpoint(
        &self,
        watermark: Location<Self::Family>,
        start_location: Location<Self::Family>,
        max_locations: u32,
    ) -> impl Future<Output = Result<OperationRangeCheckpoint<Self::Digest, Self::Family>, QmdbError>>
           + Send;
}

/// Wrapper that bridges any `OperationLogBackend` into a concrete
/// `OperationLogService` implementation usable with `OperationLogServiceServer`.
#[derive(Clone)]
struct OperationLogConnect<B: OperationLogBackend> {
    backend: B,
}

impl<B: OperationLogBackend> OperationLogConnect<B> {
    fn new(backend: B) -> Self {
        Self { backend }
    }
}

trait CurrentOperationRangeBackend<const N: usize>: Clone + Send + Sync + 'static {
    type Family: Graftable;
    type Digest: commonware_cryptography::Digest;
    type Operation: commonware_codec::Codec;

    fn current_operation_range_proof(
        &self,
        watermark: Location<Self::Family>,
        start_location: Location<Self::Family>,
        max_locations: u32,
    ) -> impl Future<
        Output = Result<
            CurrentOperationRangeProofResult<Self::Digest, Self::Operation, N, Self::Family>,
            QmdbError,
        >,
    > + Send;
}

#[derive(Clone)]
struct CurrentOperationConnect<B, const N: usize>
where
    B: CurrentOperationRangeBackend<N>,
{
    backend: B,
}

impl<B, const N: usize> CurrentOperationConnect<B, N>
where
    B: CurrentOperationRangeBackend<N>,
{
    fn new(backend: B) -> Self {
        Self { backend }
    }
}

impl<F, H, K, V, const N: usize> OperationLogBackend for Arc<OrderedClient<F, H, K, V, N>>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    QmdbOperation<F, K, V>: Encode + commonware_codec::Decode,
{
    type Family = F;
    type Digest = H::Digest;

    fn store_client(&self) -> &exoware_sdk::StoreClient {
        OrderedClient::store_client(self)
    }

    fn classify_and_filter(&self) -> (RowClassifier<F>, exoware_sdk::stream_filter::StreamFilter) {
        sub::classify_and_filter::<F>(None)
    }

    fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        OrderedClient::extract_operation_kv(self, location, bytes)
    }

    fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, F>, QmdbError>> + Send {
        OrderedClient::batch_multi_proof_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            operations,
        )
    }

    fn operation_range_checkpoint(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<Output = Result<OperationRangeCheckpoint<Self::Digest, F>, QmdbError>> + Send
    {
        OrderedClient::operation_range_checkpoint(self, watermark, start_location, max_locations)
    }
}

impl<F, H, K, V> OperationLogBackend for Arc<UnorderedClient<F, H, K, V>>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    V::Cfg: Clone,
    UnorderedQmdbOperation<F, K, V>: Encode + commonware_codec::Decode,
{
    type Family = F;
    type Digest = H::Digest;

    fn store_client(&self) -> &exoware_sdk::StoreClient {
        UnorderedClient::store_client(self)
    }

    fn classify_and_filter(&self) -> (RowClassifier<F>, exoware_sdk::stream_filter::StreamFilter) {
        sub::classify_and_filter::<F>(None)
    }

    fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        UnorderedClient::extract_operation_kv(self, location, bytes)
    }

    fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, F>, QmdbError>> + Send {
        UnorderedClient::batch_multi_proof_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            operations,
        )
    }

    fn operation_range_checkpoint(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<Output = Result<OperationRangeCheckpoint<Self::Digest, F>, QmdbError>> + Send
    {
        UnorderedClient::operation_range_checkpoint(self, watermark, start_location, max_locations)
    }
}

impl<F, H, K, V> OperationLogBackend for Arc<ImmutableClient<F, H, K, V>>
where
    F: Family,
    H: Hasher + Send + Sync + 'static,
    K: commonware_utils::Array
        + commonware_codec::Codec
        + Clone
        + AsRef<[u8]>
        + Send
        + Sync
        + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    V::Cfg: Clone,
    K::Cfg: Clone,
    ImmutableOperation<F, K, V>: Encode + commonware_codec::Decode<Cfg = (K::Cfg, V::Cfg)> + Clone,
{
    type Family = F;
    type Digest = H::Digest;

    fn store_client(&self) -> &exoware_sdk::StoreClient {
        ImmutableClient::store_client(self)
    }

    fn classify_and_filter(&self) -> (RowClassifier<F>, exoware_sdk::stream_filter::StreamFilter) {
        sub::classify_and_filter::<F>(Some(AuthenticatedBackendNamespace::Immutable))
    }

    fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        ImmutableClient::extract_operation_kv(self, location, bytes)
    }

    fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, F>, QmdbError>> + Send {
        ImmutableClient::batch_multi_proof_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            operations,
        )
    }

    fn operation_range_checkpoint(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<Output = Result<OperationRangeCheckpoint<Self::Digest, F>, QmdbError>> + Send
    {
        ImmutableClient::operation_range_checkpoint(self, watermark, start_location, max_locations)
    }
}

impl<F, H, V> OperationLogBackend for Arc<KeylessClient<F, H, V>>
where
    F: Family,
    H: Hasher + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    V::Cfg: Clone,
    KeylessOperation<F, V>: Encode + commonware_codec::Decode<Cfg = V::Cfg> + Clone,
{
    type Family = F;
    type Digest = H::Digest;
    const REJECTS_KEY_FILTERS: bool = true;

    fn store_client(&self) -> &exoware_sdk::StoreClient {
        KeylessClient::store_client(self)
    }

    fn classify_and_filter(&self) -> (RowClassifier<F>, exoware_sdk::stream_filter::StreamFilter) {
        sub::classify_and_filter::<F>(Some(AuthenticatedBackendNamespace::Keyless))
    }

    fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        KeylessClient::extract_operation_kv(self, location, bytes)
    }

    fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, F>, QmdbError>> + Send {
        KeylessClient::batch_multi_proof_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            operations,
        )
    }

    fn operation_range_checkpoint(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<Output = Result<OperationRangeCheckpoint<Self::Digest, F>, QmdbError>> + Send
    {
        KeylessClient::operation_range_checkpoint(self, watermark, start_location, max_locations)
    }
}

impl<F, H, K, V, const N: usize> CurrentOperationRangeBackend<N>
    for Arc<OrderedClient<F, H, K, V, N>>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    QmdbOperation<F, K, V>: Encode + commonware_codec::Decode,
{
    type Family = F;
    type Digest = H::Digest;
    type Operation = QmdbOperation<F, K, V>;

    fn current_operation_range_proof(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<
        Output = Result<
            CurrentOperationRangeProofResult<Self::Digest, Self::Operation, N, F>,
            QmdbError,
        >,
    > + Send {
        OrderedClient::current_operation_range_proof_raw_at(
            self,
            watermark,
            start_location,
            max_locations,
        )
    }
}

impl<F, H, K, V, const N: usize> CurrentOperationRangeBackend<N>
    for Arc<UnorderedClient<F, H, K, V>>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    V::Cfg: Clone,
    UnorderedQmdbOperation<F, K, V>: Encode + commonware_codec::Decode,
{
    type Family = F;
    type Digest = H::Digest;
    type Operation = UnorderedQmdbOperation<F, K, V>;

    fn current_operation_range_proof(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<
        Output = Result<
            CurrentOperationRangeProofResult<Self::Digest, Self::Operation, N, F>,
            QmdbError,
        >,
    > + Send {
        UnorderedClient::current_operation_range_proof_raw_at::<N>(
            self,
            watermark,
            start_location,
            max_locations,
        )
    }
}

#[derive(Clone, Debug)]
struct PendingBatch<F: Family> {
    sequence_number: u64,
    matched: Vec<(Location<F>, Vec<u8>)>,
}

#[derive(Clone, Debug)]
struct ReadyBatch<F: Family> {
    watermark: Location<F>,
    /// Store sequence of this batch's ops frame. Emitted as
    /// `resume_sequence_number`; unique per batch, so a client reconnecting
    /// at `resume + 1` skips only this batch. When multiple pending batches
    /// share a single authorizing watermark, each must carry its own
    /// per-batch sequence here or the reconnect cursor would jump past
    /// unread siblings.
    batch_sequence: u64,
    /// Minimum store sequence for the read session that builds the proof.
    /// Must be at least the watermark's publication sequence so the session
    /// observes the watermark row.
    read_floor_sequence: u64,
    matched: Vec<(Location<F>, Vec<u8>)>,
}

fn parse_bytes_filters<'a, 'b, I>(
    filters: I,
    label: &str,
) -> Result<Option<CompiledBytesFilters>, String>
where
    I: IntoIterator<Item = &'b exoware_sdk::store::common::v1::BytesFilterView<'a>>,
    'a: 'b,
{
    let mut domain = Vec::new();
    for filter in filters {
        domain.push(match filter.kind {
            Some(ProtoBytesFilterKindView::Exact(exact)) => BytesFilter::Exact(exact.to_vec()),
            Some(ProtoBytesFilterKindView::Prefix(prefix)) => BytesFilter::Prefix(prefix.to_vec()),
            Some(ProtoBytesFilterKindView::Regex(pattern)) => {
                BytesFilter::Regex(pattern.to_string())
            }
            None => {
                return Err(format!(
                    "each {label} filter must set exactly one of exact, prefix, or regex"
                ));
            }
        });
    }
    CompiledBytesFilters::compile(&domain).map_err(|e| format!("invalid {label} filter: {e}"))
}

fn matcher_passes(matcher: &Option<CompiledBytesFilters>, bytes: Option<&[u8]>) -> bool {
    match matcher {
        None => true,
        Some(m) => bytes.map(|b| m.matches(b)).unwrap_or(false),
    }
}

struct BatchSubscribeStream<D: commonware_cryptography::Digest, F: Family> {
    key_matcher: Option<CompiledBytesFilters>,
    value_matcher: Option<CompiledBytesFilters>,
    classify: RowClassifier<F>,
    extract_kv: Arc<
        dyn for<'a> Fn(Location<F>, &'a [u8]) -> Result<OperationKv, QmdbError>
            + Send
            + Sync
            + 'static,
    >,
    build_proof: Arc<
        dyn Fn(
                u64,
                Location<F>,
                Vec<(Location<F>, Vec<u8>)>,
            ) -> BoxFuture<'static, Result<RawBatchMultiProof<D, F>, QmdbError>>
            + Send
            + Sync
            + 'static,
    >,
    sub: exoware_sdk::StreamSubscription,
    pending: BTreeMap<Location<F>, PendingBatch<F>>,
    watermarks: BTreeMap<Location<F>, u64>,
    ready: VecDeque<ReadyBatch<F>>,
    building: Option<BoxFuture<'static, Result<SubscribeResponse, ConnectError>>>,
}

impl<D: commonware_cryptography::Digest, F: Family> Unpin for BatchSubscribeStream<D, F> {}

impl<D: commonware_cryptography::Digest, F: Family> BatchSubscribeStream<D, F> {
    fn new(
        key_matcher: Option<CompiledBytesFilters>,
        value_matcher: Option<CompiledBytesFilters>,
        classify: RowClassifier<F>,
        extract_kv: Arc<
            dyn for<'a> Fn(Location<F>, &'a [u8]) -> Result<OperationKv, QmdbError>
                + Send
                + Sync
                + 'static,
        >,
        build_proof: Arc<
            dyn Fn(
                    u64,
                    Location<F>,
                    Vec<(Location<F>, Vec<u8>)>,
                )
                    -> BoxFuture<'static, Result<RawBatchMultiProof<D, F>, QmdbError>>
                + Send
                + Sync
                + 'static,
        >,
        sub: exoware_sdk::StreamSubscription,
    ) -> Self {
        Self {
            key_matcher,
            value_matcher,
            classify,
            extract_kv,
            build_proof,
            sub,
            pending: BTreeMap::new(),
            watermarks: BTreeMap::new(),
            ready: VecDeque::new(),
            building: None,
        }
    }

    fn ingest_frame(
        &mut self,
        frame: &exoware_sdk::StreamSubscriptionFrame,
    ) -> Result<(), Box<ConnectError>> {
        let mut saw_operation = false;
        let mut latest: Option<Location<F>> = None;
        let mut matched: Vec<(Location<F>, Vec<u8>)> = Vec::new();
        let needs_decode = self.key_matcher.is_some() || self.value_matcher.is_some();

        for entry in &frame.entries {
            let Some((family, location)) = self.classify.classify(&entry.key, entry.value.as_ref())
            else {
                continue;
            };
            match family {
                sub::RowFamily::Op => {
                    saw_operation = true;
                    let include = if needs_decode {
                        let OperationKv { key, value } =
                            (self.extract_kv)(location, entry.value.as_ref())
                                .map_err(qmdb_error_to_connect)?;
                        matcher_passes(&self.key_matcher, key.as_deref())
                            && matcher_passes(&self.value_matcher, value.as_deref())
                    } else {
                        true
                    };
                    if include {
                        matched.push((location, entry.value.to_vec()));
                    }
                }
                sub::RowFamily::Presence => latest = Some(location),
                sub::RowFamily::Watermark => {
                    self.watermarks
                        .entry(location)
                        .or_insert(frame.sequence_number);
                }
            }
        }

        if saw_operation && !matched.is_empty() {
            let latest = latest.ok_or_else(|| {
                Box::new(ConnectError::internal("qmdb batch missing presence row"))
            })?;
            matched.sort_by_key(|(loc, _)| *loc);
            self.pending.insert(
                latest,
                PendingBatch {
                    sequence_number: frame.sequence_number,
                    matched,
                },
            );
        }

        self.drain_ready();
        Ok(())
    }

    fn drain_ready(&mut self) {
        drain_ready(&mut self.pending, &mut self.watermarks, &mut self.ready);
    }
}

fn drain_ready<F: Family>(
    pending: &mut BTreeMap<Location<F>, PendingBatch<F>>,
    watermarks: &mut BTreeMap<Location<F>, u64>,
    ready: &mut VecDeque<ReadyBatch<F>>,
) {
    while let Some((&latest, _)) = pending.iter().next() {
        let Some((&watermark, &watermark_sequence)) = watermarks.range(latest..).next() else {
            break;
        };
        let (_, batch) = pending.pop_first().expect("pending is not empty");
        ready.push_back(ReadyBatch {
            watermark,
            batch_sequence: batch.sequence_number,
            read_floor_sequence: batch.sequence_number.max(watermark_sequence),
            matched: batch.matched,
        });
    }

    if let Some(&floor) = pending
        .keys()
        .next()
        .or_else(|| watermarks.keys().next_back())
    {
        *watermarks = watermarks.split_off(&floor);
    }
}

impl<D: commonware_cryptography::Digest, F: Family> Stream for BatchSubscribeStream<D, F> {
    type Item = Result<SubscribeResponse, ConnectError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            if let Some(fut) = this.building.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(result) => {
                        this.building = None;
                        return Poll::Ready(Some(result));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            if let Some(batch) = this.ready.pop_front() {
                let build = this.build_proof.clone();
                let fut = async move {
                    let proof = (build)(batch.read_floor_sequence, batch.watermark, batch.matched)
                        .await
                        .map_err(qmdb_error_to_connect)?;
                    Ok(SubscribeResponse {
                        resume_sequence_number: batch.batch_sequence,
                        proof: Some(raw_batch_multi_proof_to_proto(&proof)).into(),
                        tip: proof.watermark.as_u64(),
                        ..Default::default()
                    })
                }
                .boxed();
                this.building = Some(fut);
                continue;
            }

            let frame = {
                let next_fut = this.sub.next();
                tokio::pin!(next_fut);
                match next_fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(Some(frame))) => frame,
                    Poll::Ready(Ok(None)) => return Poll::Ready(None),
                    Poll::Ready(Err(err)) => {
                        let connect = if let Some(rpc) = err.rpc_error() {
                            ConnectError::new(rpc.code, rpc.message.clone().unwrap_or_default())
                        } else {
                            ConnectError::new(ErrorCode::Internal, err.to_string())
                        };
                        return Poll::Ready(Some(Err(connect)));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            };

            if let Err(err) = this.ingest_frame(&frame) {
                return Poll::Ready(Some(Err(*err)));
            }
        }
    }
}

fn decode_since(since: Option<u64>) -> Option<u64> {
    match since {
        Some(0) | None => None,
        Some(value) => Some(value),
    }
}

impl<F, H, K, V, const N: usize> KeyLookupService for OrderedConnect<F, H, K, V, N>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    QmdbOperation<F, K, V>: Encode + commonware_codec::Decode,
    commonware_storage::qmdb::any::ordered::Update<
        K,
        commonware_storage::qmdb::any::value::VariableEncoding<V>,
    >: Encode,
{
    fn get(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<GetRequestView<'static>>,
    ) -> impl Future<Output = Result<(GetResponse, Context), ConnectError>> + Send {
        let client = self.client.clone();
        async move {
            let key = request.key.to_vec();
            let tip = Location::new(request.tip);
            let proof = client
                .key_value_proof_raw_at::<&[u8]>(tip, key.as_slice())
                .await
                .map_err(qmdb_error_to_connect)?;
            Ok((
                GetResponse {
                    proof: Some(raw_key_value_proof_to_proto(&proof)).into(),
                    ..Default::default()
                },
                ctx,
            ))
        }
    }

    fn get_many(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<GetManyRequestView<'static>>,
    ) -> impl Future<Output = Result<(GetManyResponse, Context), ConnectError>> + Send {
        let client = self.client.clone();
        async move {
            let tip = Location::new(request.tip);
            let keys: Vec<Vec<u8>> = request.keys.iter().map(|key| key.to_vec()).collect();
            let proofs = client
                .key_lookup_proofs_raw_at(tip, &keys)
                .await
                .map_err(qmdb_error_to_connect)?;
            let results = keys
                .into_iter()
                .zip(proofs.iter())
                .map(|(key, proof)| {
                    let result = match proof {
                        RawKeyLookupProof::Hit(proof) => current_key_lookup_result::Result::Hit(
                            Box::new(raw_key_value_proof_to_proto(proof)),
                        ),
                        RawKeyLookupProof::Miss(proof) => current_key_lookup_result::Result::Miss(
                            Box::new(raw_key_exclusion_proof_to_proto(proof)),
                        ),
                    };
                    ProtoCurrentKeyLookupResult {
                        key,
                        result: Some(result),
                        ..Default::default()
                    }
                })
                .collect();
            Ok((
                GetManyResponse {
                    results,
                    ..Default::default()
                },
                ctx,
            ))
        }
    }
}

impl<F, H, K, V, const N: usize> KeyLookupService for UnorderedConnect<F, H, K, V, N>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    V::Cfg: Clone,
    UnorderedQmdbOperation<F, K, V>: Encode + commonware_codec::Decode,
{
    fn get(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<GetRequestView<'static>>,
    ) -> impl Future<Output = Result<(GetResponse, Context), ConnectError>> + Send {
        let client = self.client.clone();
        async move {
            let key = request.key.to_vec();
            let tip = Location::new(request.tip);
            let proof = client
                .key_value_proof_raw_at::<N, _>(tip, key.as_slice())
                .await
                .map_err(qmdb_error_to_connect)?;
            Ok((
                GetResponse {
                    proof: Some(raw_unordered_key_value_proof_to_proto(&proof)).into(),
                    ..Default::default()
                },
                ctx,
            ))
        }
    }

    fn get_many(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<GetManyRequestView<'static>>,
    ) -> impl Future<Output = Result<(GetManyResponse, Context), ConnectError>> + Send {
        let client = self.client.clone();
        async move {
            let tip = Location::new(request.tip);
            let keys: Vec<Vec<u8>> = request.keys.iter().map(|key| key.to_vec()).collect();
            let proofs = client
                .key_lookup_proofs_raw_at::<N, _>(tip, &keys)
                .await
                .map_err(qmdb_error_to_connect)?;
            let results = proofs
                .iter()
                .map(|proof| ProtoCurrentKeyLookupResult {
                    key: match &proof.operation {
                        UnorderedQmdbOperation::Update(update) => update.0.as_ref().to_vec(),
                        _ => Vec::new(),
                    },
                    result: Some(current_key_lookup_result::Result::Hit(Box::new(
                        raw_unordered_key_value_proof_to_proto(proof),
                    ))),
                    ..Default::default()
                })
                .collect();
            Ok((
                GetManyResponse {
                    results,
                    ..Default::default()
                },
                ctx,
            ))
        }
    }
}

impl<F, H, K, V, const N: usize> OrderedKeyRangeService for OrderedConnect<F, H, K, V, N>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    QmdbOperation<F, K, V>: Encode + commonware_codec::Decode,
    commonware_storage::qmdb::any::ordered::Update<
        K,
        commonware_storage::qmdb::any::value::VariableEncoding<V>,
    >: Encode,
{
    fn get_range(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<GetRangeRequestView<'static>>,
    ) -> impl Future<Output = Result<(GetRangeResponse, Context), ConnectError>> + Send {
        let client = self.client.clone();
        async move {
            let tip = Location::new(request.tip);
            let end_key = request.end_key.as_deref();
            let proof = client
                .key_range_proof_raw_at(tip, request.start_key, end_key, request.limit)
                .await
                .map_err(qmdb_error_to_connect)?;
            Ok((raw_key_range_proof_to_proto(&proof), ctx))
        }
    }
}

impl<B: OperationLogBackend> OperationLogService for OperationLogConnect<B> {
    fn get_operation_range(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<GetOperationRangeRequestView<'static>>,
    ) -> impl Future<Output = Result<(GetOperationRangeResponse, Context), ConnectError>> + Send
    {
        let backend = self.backend.clone();
        async move {
            let proof = backend
                .operation_range_checkpoint(
                    Location::new(request.tip),
                    Location::new(request.start_location),
                    request.max_locations,
                )
                .await
                .map_err(qmdb_error_to_connect)?;
            Ok((
                GetOperationRangeResponse {
                    proof: Some(operation_range_checkpoint_to_proto(&proof)).into(),
                    ..Default::default()
                },
                ctx,
            ))
        }
    }

    fn subscribe(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<SubscribeRequestView<'static>>,
    ) -> impl Future<
        Output = Result<
            (
                Pin<Box<dyn Stream<Item = Result<SubscribeResponse, ConnectError>> + Send>>,
                Context,
            ),
            ConnectError,
        >,
    > + Send {
        let backend = self.backend.clone();
        async move {
            if B::REJECTS_KEY_FILTERS && !request.key_filters.is_empty() {
                return Err(ConnectError::invalid_argument(
                    "this OperationLogService endpoint does not accept key_filters",
                ));
            }
            let key_matcher = parse_bytes_filters(request.key_filters.iter(), "key")
                .map_err(ConnectError::invalid_argument)?;
            let value_matcher = parse_bytes_filters(request.value_filters.iter(), "value")
                .map_err(ConnectError::invalid_argument)?;
            let since = decode_since(request.since_sequence_number);
            let (classify, filter) = backend.classify_and_filter();
            let sub = sub::open_store_subscription(backend.store_client(), filter, since)
                .await
                .map_err(qmdb_error_to_connect)?;
            let extract_kv: Arc<
                dyn for<'a> Fn(Location<B::Family>, &'a [u8]) -> Result<OperationKv, QmdbError>
                    + Send
                    + Sync
                    + 'static,
            > = {
                let backend = backend.clone();
                Arc::new(move |location, bytes| backend.extract_operation_kv(location, bytes))
            };
            let build_proof = {
                let backend = backend.clone();
                Arc::new(move |seq, watermark, matched| {
                    let backend = backend.clone();
                    async move {
                        backend
                            .batch_multi_proof_with_read_floor(seq, watermark, matched)
                            .await
                    }
                    .boxed()
                })
            };
            let stream: Pin<
                Box<dyn Stream<Item = Result<SubscribeResponse, ConnectError>> + Send>,
            > = Box::pin(BatchSubscribeStream::new(
                key_matcher,
                value_matcher,
                classify,
                extract_kv,
                build_proof,
                sub,
            ));
            Ok((stream, ctx))
        }
    }
}

impl<B, const N: usize> CurrentOperationService for CurrentOperationConnect<B, N>
where
    B: CurrentOperationRangeBackend<N>,
    B::Operation: Encode,
{
    fn get_current_operation_range(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<GetCurrentOperationRangeRequestView<'static>>,
    ) -> impl Future<Output = Result<(GetCurrentOperationRangeResponse, Context), ConnectError>> + Send
    {
        let backend = self.backend.clone();
        async move {
            let proof = backend
                .current_operation_range_proof(
                    Location::new(request.tip),
                    Location::new(request.start_location),
                    request.max_locations,
                )
                .await
                .map_err(qmdb_error_to_connect)?;
            Ok((
                GetCurrentOperationRangeResponse {
                    proof: Some(current_operation_range_proof_to_proto(&proof)).into(),
                    ..Default::default()
                },
                ctx,
            ))
        }
    }
}

fn wrap_stack<D: ::connectrpc::Dispatcher>(dispatcher: D) -> ConnectRpcService<D> {
    ConnectRpcService::new(dispatcher)
        .with_limits(connect_limits())
        .with_compression(exoware_sdk::connect_compression_registry())
}

/// Mount key lookup, ordered key range, and operation subscription services on
/// one endpoint, so a single HTTP URL serves the full ordered-QMDB surface.
pub fn ordered_connect_stack<
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    const N: usize,
>(
    client: Arc<OrderedClient<F, H, K, V, N>>,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    QmdbOperation<F, K, V>: Encode + commonware_codec::Decode,
    commonware_storage::qmdb::any::ordered::Update<
        K,
        commonware_storage::qmdb::any::value::VariableEncoding<V>,
    >: Encode,
{
    wrap_stack(Chain(
        KeyLookupServiceServer::new(OrderedConnect::new(client.clone())),
        Chain(
            OrderedKeyRangeServiceServer::new(OrderedConnect::new(client.clone())),
            Chain(
                CurrentOperationServiceServer::new(CurrentOperationConnect::<_, N>::new(
                    client.clone(),
                )),
                OperationLogServiceServer::new(OperationLogConnect::new(client)),
            ),
        ),
    ))
}

/// Mount current key lookup and operation subscription services on one
/// unordered-QMDB endpoint. Unordered supports hit proofs for explicit keys
/// but does not expose key-space range or missing-key exclusion proofs.
pub fn unordered_connect_stack<
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    const N: usize,
>(
    client: Arc<UnorderedClient<F, H, K, V>>,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    V::Cfg: Clone,
    UnorderedQmdbOperation<F, K, V>: Encode + commonware_codec::Decode,
{
    wrap_stack(Chain(
        KeyLookupServiceServer::new(UnorderedConnect::<F, H, K, V, N>::new(client.clone())),
        Chain(
            CurrentOperationServiceServer::new(CurrentOperationConnect::<_, N>::new(
                client.clone(),
            )),
            OperationLogServiceServer::new(OperationLogConnect::new(client)),
        ),
    ))
}

pub fn unordered_operation_log_connect_stack<
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
>(
    client: Arc<UnorderedClient<F, H, K, V>>,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    V::Cfg: Clone,
    UnorderedQmdbOperation<F, K, V>: Encode + commonware_codec::Decode,
{
    wrap_stack(OperationLogServiceServer::new(OperationLogConnect::new(
        client,
    )))
}

pub fn immutable_operation_log_connect_stack<
    F: Family,
    H: Hasher + Send + Sync + 'static,
    K: commonware_utils::Array + commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
>(
    client: Arc<ImmutableClient<F, H, K, V>>,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    V::Cfg: Clone,
    K::Cfg: Clone,
    ImmutableOperation<F, K, V>: Encode + commonware_codec::Decode<Cfg = (K::Cfg, V::Cfg)> + Clone,
{
    wrap_stack(OperationLogServiceServer::new(OperationLogConnect::new(
        client,
    )))
}

pub fn keyless_operation_log_connect_stack<
    F: Family,
    H: Hasher + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
>(
    client: Arc<KeylessClient<F, H, V>>,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    V::Cfg: Clone,
    KeylessOperation<F, V>: Encode + commonware_codec::Decode<Cfg = V::Cfg> + Clone,
{
    wrap_stack(OperationLogServiceServer::new(OperationLogConnect::new(
        client,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(sequence_number: u64) -> PendingBatch<commonware_storage::merkle::mmr::Family> {
        PendingBatch {
            sequence_number,
            matched: vec![(
                Location::<commonware_storage::merkle::mmr::Family>::new(sequence_number),
                vec![sequence_number as u8],
            )],
        }
    }

    #[test]
    fn shared_watermark_preserves_per_batch_resume_cursor() {
        // Three batches (ops at locations 10, 11, 12) authorized by a single
        // watermark at location 12 (published at store seq 15). If they all
        // emitted the same resume cursor, a client that received only the
        // first batch and reconnected at resume+1 would skip the other two.
        let mut pending = BTreeMap::from([
            (
                Location::<commonware_storage::merkle::mmr::Family>::new(10),
                pending(10),
            ),
            (
                Location::<commonware_storage::merkle::mmr::Family>::new(11),
                pending(11),
            ),
            (
                Location::<commonware_storage::merkle::mmr::Family>::new(12),
                pending(12),
            ),
        ]);
        let mut watermarks = BTreeMap::from([(
            Location::<commonware_storage::merkle::mmr::Family>::new(12),
            15u64,
        )]);
        let mut ready = VecDeque::new();

        drain_ready(&mut pending, &mut watermarks, &mut ready);

        assert_eq!(ready.len(), 3);
        let cursors: Vec<u64> = ready.iter().map(|b| b.batch_sequence).collect();
        assert_eq!(cursors, vec![10, 11, 12]);
        for b in &ready {
            assert_eq!(b.read_floor_sequence, 15);
            assert_eq!(
                b.watermark,
                Location::<commonware_storage::merkle::mmr::Family>::new(12)
            );
        }

        // Simulate a reconnect after only the first batch was delivered:
        // the client would request since = cursors[0] + 1 = 11. After that
        // replay the server must still be able to hand the client batches 2
        // and 3 (their batch_sequence values 11 and 12 are both >= 11).
        let next_since = cursors[0] + 1;
        let not_yet_delivered: Vec<u64> = cursors
            .iter()
            .copied()
            .filter(|&seq| seq >= next_since)
            .collect();
        assert_eq!(not_yet_delivered, vec![11, 12]);
    }
}
