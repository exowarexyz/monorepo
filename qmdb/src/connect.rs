use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use commonware_codec::Encode;
use commonware_cryptography::Hasher;
use commonware_storage::{
    mmr::Location,
    qmdb::{
        any::{
            ordered::variable::Operation as QmdbOperation,
            unordered::variable::Operation as UnorderedQmdbOperation,
        },
        immutable::Operation as ImmutableOperation,
        keyless::Operation as KeylessOperation,
    },
};

use connectrpc::{Chain, ConnectError, ConnectRpcService, Context, ErrorCode, Limits};
use exoware_sdk_rs::store::common::v1::bytes_filter::KindView as ProtoBytesFilterKindView;
use exoware_sdk_rs::store::qmdb::v1::{
    CurrentKeyValueProof as ProtoCurrentKeyValueProof, CurrentRangeProof as ProtoCurrentRangeProof,
    GetManyRequestView, GetManyResponse, GetRequestView, GetResponse,
    HistoricalMultiProof as ProtoHistoricalMultiProof, MmrProof as ProtoMmrProof,
    MultiProofOperation as ProtoMultiProofOperation, OrderedService, OrderedServiceServer,
    RangeService, RangeServiceServer, SubscribeRequestView, SubscribeResponse,
};
use exoware_sdk_rs::stream_filter::{BytesFilter, CompiledBytesFilters};
use futures::future::BoxFuture;
use futures::{FutureExt, Stream};

use crate::auth::AuthenticatedBackendNamespace;
use crate::proof::{
    RawBatchMultiProof, RawCurrentRangeProof, RawKeyValueProof, RawMmrProof, RawMultiProof,
};
use crate::subscription::{self as sub, Classify, Family};
use crate::{ImmutableClient, KeylessClient, OrderedClient, QmdbError, UnorderedClient};

const MAX_CONNECTRPC_BODY_BYTES: usize = 256 * 1024 * 1024;
type BoxConnectError = Box<ConnectError>;

/// Decoded (key, value) payload for a QMDB operation. Either element is `None`
/// when the operation's logical key or value is absent (e.g. keyless ops).
pub type OperationKv = (Option<Vec<u8>>, Option<Vec<u8>>);

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
        | QmdbError::CommonwareMmr(_)
        | QmdbError::WriterPoisoned(_) => ConnectError::internal(err.to_string()),
    }
}

fn raw_mmr_proof_to_proto<D: commonware_cryptography::Digest>(
    proof: &RawMmrProof<D>,
) -> ProtoMmrProof {
    ProtoMmrProof {
        leaves: *proof.leaves,
        digests: proof
            .digests
            .iter()
            .map(|digest| digest.encode().to_vec())
            .collect(),
        ..Default::default()
    }
}

fn raw_current_range_proof_to_proto<D: commonware_cryptography::Digest>(
    proof: &RawCurrentRangeProof<D>,
) -> ProtoCurrentRangeProof {
    ProtoCurrentRangeProof {
        proof: Some(raw_mmr_proof_to_proto(&proof.proof)).into(),
        partial_chunk_digest: proof
            .partial_chunk_digest
            .as_ref()
            .map(|digest| digest.encode().to_vec()),
        ops_root: proof.ops_root.encode().to_vec(),
        ..Default::default()
    }
}

fn raw_multi_proof_to_proto<
    D: commonware_cryptography::Digest,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
>(
    proof: &RawMultiProof<D, K, V>,
) -> ProtoHistoricalMultiProof
where
    QmdbOperation<K, V>: Encode,
{
    ProtoHistoricalMultiProof {
        root: proof.root.encode().to_vec(),
        proof: Some(raw_mmr_proof_to_proto(&proof.proof)).into(),
        operations: proof
            .operations
            .iter()
            .map(|(location, operation)| ProtoMultiProofOperation {
                location: location.as_u64(),
                encoded_operation: operation.encode().to_vec(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

fn raw_batch_multi_proof_to_proto<D: commonware_cryptography::Digest>(
    proof: &RawBatchMultiProof<D>,
) -> ProtoHistoricalMultiProof {
    ProtoHistoricalMultiProof {
        root: proof.root.encode().to_vec(),
        proof: Some(raw_mmr_proof_to_proto(&proof.proof)).into(),
        operations: proof
            .operations
            .iter()
            .map(|(location, encoded_operation)| ProtoMultiProofOperation {
                location: location.as_u64(),
                encoded_operation: encoded_operation.clone(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

fn raw_key_value_proof_to_proto<
    D: commonware_cryptography::Digest,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
>(
    proof: &RawKeyValueProof<D, K, V, N>,
) -> ProtoCurrentKeyValueProof
where
    QmdbOperation<K, V>: Encode,
{
    ProtoCurrentKeyValueProof {
        root: proof.root.encode().to_vec(),
        location: *proof.location,
        chunk: proof.chunk.to_vec(),
        range_proof: Some(raw_current_range_proof_to_proto(&proof.range_proof)).into(),
        encoded_operation: proof.operation.encode().to_vec(),
        ..Default::default()
    }
}

#[derive(Clone)]
pub struct OrderedConnect<
    H: Hasher,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
> {
    client: Arc<OrderedClient<H, K, V, N>>,
}

impl<H, K, V, const N: usize> OrderedConnect<H, K, V, N>
where
    H: Hasher,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
{
    pub fn new(client: Arc<OrderedClient<H, K, V, N>>) -> Self {
        Self { client }
    }
}

/// Implemented by each QMDB backend client (`Arc<OrderedClient<...>>`,
/// `Arc<UnorderedClient<...>>`, etc.) to expose just the surface the generic
/// `RangeService` subscribe path needs. Callers instantiate via the
/// `RangeConnect<B>` type aliases + `*_range_connect_stack` helpers rather
/// than implementing this trait.
pub trait RangeBackend: Clone + Send + Sync + 'static {
    type Digest: commonware_cryptography::Digest;
    /// Reject `key_filters` at subscribe time (set true for keyless, whose
    /// ops have no logical key).
    const REJECTS_KEY_FILTERS: bool = false;

    fn store_client(&self) -> &exoware_sdk_rs::StoreClient;
    fn classify_and_filter(&self) -> (Classify, exoware_sdk_rs::stream_filter::StreamFilter);
    fn extract_operation_kv(
        &self,
        location: Location,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError>;
    fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location,
        operations: Vec<(Location, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest>, QmdbError>> + Send;
}

/// Wrapper that bridges any `RangeBackend` into a concrete `RangeService`
/// implementation usable with `RangeServiceServer`.
#[derive(Clone)]
pub struct RangeConnect<B: RangeBackend> {
    backend: B,
}

impl<B: RangeBackend> RangeConnect<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }
}

pub type OrderedRangeConnect<H, K, V, const N: usize> =
    RangeConnect<Arc<OrderedClient<H, K, V, N>>>;
pub type UnorderedRangeConnect<H, K, V> = RangeConnect<Arc<UnorderedClient<H, K, V>>>;
pub type ImmutableRangeConnect<H, K, V> = RangeConnect<Arc<ImmutableClient<H, K, V>>>;
pub type KeylessRangeConnect<H, V> = RangeConnect<Arc<KeylessClient<H, V>>>;

impl<H, K, V, const N: usize> RangeBackend for Arc<OrderedClient<H, K, V, N>>
where
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    QmdbOperation<K, V>: Encode + commonware_codec::Decode,
{
    type Digest = H::Digest;

    fn store_client(&self) -> &exoware_sdk_rs::StoreClient {
        OrderedClient::store_client(self)
    }

    fn classify_and_filter(&self) -> (Classify, exoware_sdk_rs::stream_filter::StreamFilter) {
        sub::classify_and_filter(None)
    }

    fn extract_operation_kv(
        &self,
        location: Location,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        OrderedClient::extract_operation_kv(self, location, bytes)
    }

    fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location,
        operations: Vec<(Location, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest>, QmdbError>> + Send {
        OrderedClient::batch_multi_proof_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            operations,
        )
    }
}

impl<H, K, V> RangeBackend for Arc<UnorderedClient<H, K, V>>
where
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    UnorderedQmdbOperation<K, V>: Encode + commonware_codec::Decode,
{
    type Digest = H::Digest;

    fn store_client(&self) -> &exoware_sdk_rs::StoreClient {
        UnorderedClient::store_client(self)
    }

    fn classify_and_filter(&self) -> (Classify, exoware_sdk_rs::stream_filter::StreamFilter) {
        sub::classify_and_filter(None)
    }

    fn extract_operation_kv(
        &self,
        location: Location,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        UnorderedClient::extract_operation_kv(self, location, bytes)
    }

    fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location,
        operations: Vec<(Location, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest>, QmdbError>> + Send {
        UnorderedClient::batch_multi_proof_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            operations,
        )
    }
}

impl<H, K, V> RangeBackend for Arc<ImmutableClient<H, K, V>>
where
    H: Hasher + Send + Sync + 'static,
    K: commonware_utils::Array
        + commonware_codec::Codec
        + Clone
        + AsRef<[u8]>
        + Send
        + Sync
        + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    ImmutableOperation<K, V>: Encode + commonware_codec::Decode<Cfg = V::Cfg> + Clone,
{
    type Digest = H::Digest;

    fn store_client(&self) -> &exoware_sdk_rs::StoreClient {
        ImmutableClient::store_client(self)
    }

    fn classify_and_filter(&self) -> (Classify, exoware_sdk_rs::stream_filter::StreamFilter) {
        sub::classify_and_filter(Some(AuthenticatedBackendNamespace::Immutable))
    }

    fn extract_operation_kv(
        &self,
        location: Location,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        ImmutableClient::extract_operation_kv(self, location, bytes)
    }

    fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location,
        operations: Vec<(Location, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest>, QmdbError>> + Send {
        ImmutableClient::batch_multi_proof_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            operations,
        )
    }
}

impl<H, V> RangeBackend for Arc<KeylessClient<H, V>>
where
    H: Hasher + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    KeylessOperation<V>: Encode + commonware_codec::Decode<Cfg = V::Cfg> + Clone,
{
    type Digest = H::Digest;
    const REJECTS_KEY_FILTERS: bool = true;

    fn store_client(&self) -> &exoware_sdk_rs::StoreClient {
        KeylessClient::store_client(self)
    }

    fn classify_and_filter(&self) -> (Classify, exoware_sdk_rs::stream_filter::StreamFilter) {
        sub::classify_and_filter(Some(AuthenticatedBackendNamespace::Keyless))
    }

    fn extract_operation_kv(
        &self,
        location: Location,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        KeylessClient::extract_operation_kv(self, location, bytes)
    }

    fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location,
        operations: Vec<(Location, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest>, QmdbError>> + Send {
        KeylessClient::batch_multi_proof_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            operations,
        )
    }
}

#[derive(Clone, Debug)]
struct PendingBatch {
    sequence_number: u64,
    matched: Vec<(Location, Vec<u8>)>,
}

#[derive(Clone, Debug)]
struct ReadyBatch {
    watermark: Location,
    read_floor_sequence: u64,
    matched: Vec<(Location, Vec<u8>)>,
}

fn parse_bytes_filters<'a, 'b, I>(
    filters: I,
    label: &str,
) -> Result<Option<CompiledBytesFilters>, String>
where
    I: IntoIterator<Item = &'b exoware_sdk_rs::store::common::v1::BytesFilterView<'a>>,
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

/// Decodes one streamed operation into its (optional key, optional value)
/// byte view. Combined so we decode the op once even when both filters are
/// active.
type ExtractKv =
    Arc<dyn Fn(Location, &[u8]) -> Result<OperationKv, QmdbError> + Send + Sync + 'static>;

type BuildBatchProof<D> = Arc<
    dyn Fn(
            u64,
            Location,
            Vec<(Location, Vec<u8>)>,
        ) -> BoxFuture<'static, Result<RawBatchMultiProof<D>, QmdbError>>
        + Send
        + Sync
        + 'static,
>;

fn matcher_passes(matcher: &Option<CompiledBytesFilters>, bytes: Option<&[u8]>) -> bool {
    match matcher {
        None => true,
        Some(m) => bytes.map(|b| m.matches(b)).unwrap_or(false),
    }
}

struct BatchSubscribeStream<D: commonware_cryptography::Digest> {
    key_matcher: Option<CompiledBytesFilters>,
    value_matcher: Option<CompiledBytesFilters>,
    classify: Classify,
    extract_kv: ExtractKv,
    build_proof: BuildBatchProof<D>,
    sub: exoware_sdk_rs::StreamSubscription,
    pending: BTreeMap<Location, PendingBatch>,
    watermarks: BTreeMap<Location, u64>,
    ready: VecDeque<ReadyBatch>,
    building: Option<BoxFuture<'static, Result<SubscribeResponse, ConnectError>>>,
}

impl<D: commonware_cryptography::Digest> BatchSubscribeStream<D> {
    fn new(
        key_matcher: Option<CompiledBytesFilters>,
        value_matcher: Option<CompiledBytesFilters>,
        classify: Classify,
        extract_kv: ExtractKv,
        build_proof: BuildBatchProof<D>,
        sub: exoware_sdk_rs::StreamSubscription,
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
        frame: &exoware_sdk_rs::StreamSubscriptionFrame,
    ) -> Result<(), BoxConnectError> {
        let mut saw_operation = false;
        let mut latest: Option<Location> = None;
        let mut matched: Vec<(Location, Vec<u8>)> = Vec::new();
        let needs_decode = self.key_matcher.is_some() || self.value_matcher.is_some();

        for entry in &frame.entries {
            let Some((family, location)) = (self.classify)(&entry.key, entry.value.as_ref()) else {
                continue;
            };
            match family {
                Family::Op => {
                    saw_operation = true;
                    let include = if needs_decode {
                        let (key, value) = (self.extract_kv)(location, entry.value.as_ref())
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
                Family::Presence => latest = Some(location),
                Family::Watermark => {
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
        while let Some((&latest, _)) = self.pending.iter().next() {
            let Some((&watermark, &watermark_sequence)) = self.watermarks.range(latest..).next()
            else {
                break;
            };
            let (_, batch) = self.pending.pop_first().expect("pending is not empty");
            self.ready.push_back(ReadyBatch {
                watermark,
                read_floor_sequence: batch.sequence_number.max(watermark_sequence),
                matched: batch.matched,
            });
        }

        if let Some(&floor) = self
            .pending
            .keys()
            .next()
            .or_else(|| self.watermarks.keys().next_back())
        {
            self.watermarks = self.watermarks.split_off(&floor);
        }
    }
}

impl<D: commonware_cryptography::Digest> Stream for BatchSubscribeStream<D> {
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
                        resume_sequence_number: batch.read_floor_sequence,
                        proof: Some(raw_batch_multi_proof_to_proto(&proof)).into(),
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

type SubscribeStream = Pin<Box<dyn Stream<Item = Result<SubscribeResponse, ConnectError>> + Send>>;

impl<H, K, V, const N: usize> OrderedService for OrderedConnect<H, K, V, N>
where
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    QmdbOperation<K, V>: Encode + commonware_codec::Decode,
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
            let proof = client
                .multi_proof_raw_at(tip, &keys)
                .await
                .map_err(qmdb_error_to_connect)?;
            Ok((
                GetManyResponse {
                    proof: Some(raw_multi_proof_to_proto(&proof)).into(),
                    ..Default::default()
                },
                ctx,
            ))
        }
    }
}

impl<B: RangeBackend> RangeService for RangeConnect<B> {
    fn subscribe(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<SubscribeRequestView<'static>>,
    ) -> impl Future<Output = Result<(SubscribeStream, Context), ConnectError>> + Send {
        let backend = self.backend.clone();
        async move {
            if B::REJECTS_KEY_FILTERS && !request.key_filters.is_empty() {
                return Err(ConnectError::invalid_argument(
                    "this RangeService endpoint does not accept key_filters",
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
            let extract_kv: ExtractKv = {
                let backend = backend.clone();
                Arc::new(move |location, bytes| backend.extract_operation_kv(location, bytes))
            };
            let build_proof: BuildBatchProof<B::Digest> = {
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
            let stream: SubscribeStream = Box::pin(BatchSubscribeStream::new(
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

fn wrap_stack<D: ::connectrpc::Dispatcher>(dispatcher: D) -> ConnectRpcService<D> {
    ConnectRpcService::new(dispatcher)
        .with_limits(connect_limits())
        .with_compression(exoware_sdk_rs::connect_compression_registry())
}

pub type OrderedConnectStack<H, K, V, const N: usize> = ConnectRpcService<
    Chain<
        OrderedServiceServer<OrderedConnect<H, K, V, N>>,
        RangeServiceServer<OrderedRangeConnect<H, K, V, N>>,
    >,
>;

/// Mount both `OrderedService` (Get/GetMany) and `RangeService` (Subscribe) on
/// one endpoint, so a single HTTP URL serves the full ordered-QMDB surface.
pub fn ordered_connect_stack<
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    const N: usize,
>(
    client: Arc<OrderedClient<H, K, V, N>>,
) -> OrderedConnectStack<H, K, V, N>
where
    QmdbOperation<K, V>: Encode + commonware_codec::Decode,
{
    wrap_stack(Chain(
        OrderedServiceServer::new(OrderedConnect::new(client.clone())),
        RangeServiceServer::new(OrderedRangeConnect::new(client)),
    ))
}

pub fn unordered_range_connect_stack<
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
>(
    client: Arc<UnorderedClient<H, K, V>>,
) -> ConnectRpcService<RangeServiceServer<UnorderedRangeConnect<H, K, V>>>
where
    UnorderedQmdbOperation<K, V>: Encode + commonware_codec::Decode,
{
    wrap_stack(RangeServiceServer::new(UnorderedRangeConnect::new(client)))
}

pub fn immutable_range_connect_stack<
    H: Hasher + Send + Sync + 'static,
    K: commonware_utils::Array + commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
>(
    client: Arc<ImmutableClient<H, K, V>>,
) -> ConnectRpcService<RangeServiceServer<ImmutableRangeConnect<H, K, V>>>
where
    ImmutableOperation<K, V>: Encode + commonware_codec::Decode<Cfg = V::Cfg> + Clone,
{
    wrap_stack(RangeServiceServer::new(ImmutableRangeConnect::new(client)))
}

pub fn keyless_range_connect_stack<
    H: Hasher + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
>(
    client: Arc<KeylessClient<H, V>>,
) -> ConnectRpcService<RangeServiceServer<KeylessRangeConnect<H, V>>>
where
    KeylessOperation<V>: Encode + commonware_codec::Decode<Cfg = V::Cfg> + Clone,
{
    wrap_stack(RangeServiceServer::new(KeylessRangeConnect::new(client)))
}
