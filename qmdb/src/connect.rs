use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
        operation::Operation as _,
    },
};
use connectrpc::{ConnectError, ConnectRpcService, Context, ErrorCode, Limits};
use exoware_sdk_rs::store::common::v1::bytes_match_key::KindView as ProtoBytesMatchKeyKindView;
use exoware_sdk_rs::store::qmdb::v1::{
    CurrentKeyValueProof as ProtoCurrentKeyValueProof, CurrentRangeProof as ProtoCurrentRangeProof,
    GetRequestView, GetResponse, HistoricalMultiProof as ProtoHistoricalMultiProof,
    HistoricalRangeProof as ProtoHistoricalRangeProof, ImmutableRangeService,
    ImmutableRangeServiceServer, KeylessRangeService, KeylessRangeServiceServer,
    MmrProof as ProtoMmrProof, MultiProofOperation as ProtoMultiProofOperation,
    OrderedRangeService, OrderedRangeServiceServer, OrderedService, OrderedServiceServer,
    RangeSubscribeRequestView, RangeSubscribeResponse, SubscribeRequestView, SubscribeResponse,
    UnorderedRangeService, UnorderedRangeServiceServer,
};
use futures::future::BoxFuture;
use futures::{FutureExt, Stream};
use regex::bytes::Regex;

use crate::proof::{
    OperationRangeCheckpoint, RawCurrentRangeProof, RawKeyValueProof, RawMmrProof, RawMultiProof,
};
use crate::subscription::{self as sub, Classify, Family};
use crate::{ImmutableClient, KeylessClient, OrderedClient, QmdbError, UnorderedClient};

const MAX_CONNECTRPC_BODY_BYTES: usize = 256 * 1024 * 1024;

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
        QmdbError::CorruptData(_) | QmdbError::CommonwareMmr(_) | QmdbError::WriterPoisoned(_) => {
            ConnectError::internal(err.to_string())
        }
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
        watermark: *proof.watermark,
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

fn operation_range_checkpoint_to_proto<D: commonware_cryptography::Digest>(
    checkpoint: &OperationRangeCheckpoint<D>,
) -> ProtoHistoricalRangeProof {
    ProtoHistoricalRangeProof {
        watermark: *checkpoint.watermark,
        root: checkpoint.root.encode().to_vec(),
        start_location: *checkpoint.start_location,
        proof: Some(raw_mmr_proof_to_proto(&checkpoint.proof)).into(),
        encoded_operations: checkpoint.encoded_operations.clone(),
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
        watermark: *proof.watermark,
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

#[derive(Clone)]
pub struct OrderedRangeConnect<
    H: Hasher,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
> {
    client: Arc<OrderedClient<H, K, V, N>>,
}

impl<H, K, V, const N: usize> OrderedRangeConnect<H, K, V, N>
where
    H: Hasher,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
{
    pub fn new(client: Arc<OrderedClient<H, K, V, N>>) -> Self {
        Self { client }
    }
}

#[derive(Clone)]
pub struct UnorderedRangeConnect<
    H: Hasher,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
> {
    client: Arc<UnorderedClient<H, K, V>>,
}

impl<H, K, V> UnorderedRangeConnect<H, K, V>
where
    H: Hasher,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
{
    pub fn new(client: Arc<UnorderedClient<H, K, V>>) -> Self {
        Self { client }
    }
}

#[derive(Clone)]
pub struct ImmutableRangeConnect<
    H: Hasher,
    K: AsRef<[u8]> + commonware_codec::Codec,
    V: commonware_codec::Codec + Send + Sync,
> {
    client: Arc<ImmutableClient<H, K, V>>,
}

impl<H, K, V> ImmutableRangeConnect<H, K, V>
where
    H: Hasher,
    K: AsRef<[u8]> + commonware_codec::Codec,
    V: commonware_codec::Codec + Send + Sync,
{
    pub fn new(client: Arc<ImmutableClient<H, K, V>>) -> Self {
        Self { client }
    }
}

#[derive(Clone)]
pub struct KeylessRangeConnect<H: Hasher, V: commonware_codec::Codec + Send + Sync> {
    client: Arc<KeylessClient<H, V>>,
}

impl<H, V> KeylessRangeConnect<H, V>
where
    H: Hasher,
    V: commonware_codec::Codec + Send + Sync,
{
    pub fn new(client: Arc<KeylessClient<H, V>>) -> Self {
        Self { client }
    }
}

#[derive(Clone, Debug)]
struct PendingRangeBatch {
    sequence_number: u64,
    start_location: Location,
    operation_count: u32,
}

#[derive(Clone, Debug)]
struct ReadyRangeBatch {
    watermark: Location,
    read_floor_sequence: u64,
    start_location: Location,
    operation_count: u32,
}

type BuildRangeResponse<Resp> =
    Arc<dyn Fn(ReadyRangeBatch) -> BoxFuture<'static, Result<Resp, ConnectError>> + Send + Sync>;

#[derive(Clone, Debug)]
struct PendingBatch {
    sequence_number: u64,
    matched_keys: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct ReadyBatch {
    watermark: Location,
    read_floor_sequence: u64,
    matched_keys: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct SubscriptionMatcher {
    exact_keys: BTreeSet<Vec<u8>>,
    prefixes: Vec<Vec<u8>>,
    regexes: Vec<Regex>,
}

impl SubscriptionMatcher {
    fn is_empty(&self) -> bool {
        self.exact_keys.is_empty() && self.prefixes.is_empty() && self.regexes.is_empty()
    }

    fn matches(&self, key: &[u8]) -> bool {
        self.exact_keys.contains(key)
            || self.prefixes.iter().any(|prefix| key.starts_with(prefix))
            || self.regexes.iter().any(|regex| regex.is_match(key))
    }
}

struct OrderedSubscribeStream<
    H: Hasher,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
> {
    client: Arc<OrderedClient<H, K, V, N>>,
    matcher: SubscriptionMatcher,
    classify: Classify,
    sub: exoware_sdk_rs::StreamSubscription,
    pending: BTreeMap<Location, PendingBatch>,
    watermarks: BTreeMap<Location, u64>,
    ready: VecDeque<ReadyBatch>,
    building: Option<BoxFuture<'static, Result<SubscribeResponse, ConnectError>>>,
}

impl<H, K, V, const N: usize> OrderedSubscribeStream<H, K, V, N>
where
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + Send + Sync + 'static,
    QmdbOperation<K, V>: Encode + commonware_codec::Decode,
{
    fn new(
        client: Arc<OrderedClient<H, K, V, N>>,
        matcher: SubscriptionMatcher,
        classify: Classify,
        sub: exoware_sdk_rs::StreamSubscription,
    ) -> Self {
        Self {
            client,
            matcher,
            classify,
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
    ) -> Result<(), ConnectError> {
        let mut saw_operation = false;
        let mut latest = None;
        let mut matched_keys = BTreeSet::<Vec<u8>>::new();

        for entry in &frame.entries {
            let Some((family, location)) = (self.classify)(&entry.key, entry.value.as_ref()) else {
                continue;
            };
            match family {
                Family::Op => {
                    saw_operation = true;
                    let operation = self
                        .client
                        .decode_operation_bytes(location, entry.value.as_ref())
                        .map_err(qmdb_error_to_connect)?;
                    if let Some(key) = operation.key() {
                        if self.matcher.matches(key.as_ref()) {
                            matched_keys.insert(key.as_ref().to_vec());
                        }
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

        if saw_operation {
            let latest = latest
                .ok_or_else(|| ConnectError::internal("ordered qmdb batch missing presence row"))?;
            if !matched_keys.is_empty() {
                self.pending.insert(
                    latest,
                    PendingBatch {
                        sequence_number: frame.sequence_number,
                        matched_keys: matched_keys.into_iter().collect(),
                    },
                );
            }
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
                matched_keys: batch.matched_keys,
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

impl<H, K, V, const N: usize> Stream for OrderedSubscribeStream<H, K, V, N>
where
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + Send + Sync + 'static,
    QmdbOperation<K, V>: Encode + commonware_codec::Decode,
{
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
                let client = this.client.clone();
                let keys = batch.matched_keys;
                let fut = async move {
                    let proof = client
                        .multi_proof_raw_with_read_floor(
                            batch.read_floor_sequence,
                            batch.watermark,
                            &keys,
                        )
                        .await
                        .map_err(qmdb_error_to_connect)?;
                    Ok(SubscribeResponse {
                        resume_sequence_number: batch.read_floor_sequence,
                        proof: Some(raw_multi_proof_to_proto(&proof)).into(),
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
                return Poll::Ready(Some(Err(err)));
            }
        }
    }
}

struct RangeSubscribeStream<Resp> {
    classify: Classify,
    sub: exoware_sdk_rs::StreamSubscription,
    pending: BTreeMap<Location, PendingRangeBatch>,
    watermarks: BTreeMap<Location, u64>,
    ready: VecDeque<ReadyRangeBatch>,
    building: Option<BoxFuture<'static, Result<Resp, ConnectError>>>,
    build_response: BuildRangeResponse<Resp>,
}

impl<Resp> RangeSubscribeStream<Resp>
where
    Resp: Send + 'static,
{
    fn new(
        classify: Classify,
        sub: exoware_sdk_rs::StreamSubscription,
        build_response: BuildRangeResponse<Resp>,
    ) -> Self {
        Self {
            classify,
            sub,
            pending: BTreeMap::new(),
            watermarks: BTreeMap::new(),
            ready: VecDeque::new(),
            building: None,
            build_response,
        }
    }

    fn ingest_frame(
        &mut self,
        frame: &exoware_sdk_rs::StreamSubscriptionFrame,
    ) -> Result<(), ConnectError> {
        let mut operation_count = 0u32;
        let mut min_operation: Option<Location> = None;
        let mut max_operation: Option<Location> = None;
        let mut latest = None;

        for entry in &frame.entries {
            let Some((family, location)) = (self.classify)(&entry.key, entry.value.as_ref()) else {
                continue;
            };
            match family {
                Family::Op => {
                    operation_count = operation_count.checked_add(1).ok_or_else(|| {
                        ConnectError::internal("operation count overflow in streamed qmdb batch")
                    })?;
                    min_operation = Some(min_operation.map_or(location, |min| min.min(location)));
                    max_operation = Some(max_operation.map_or(location, |max| max.max(location)));
                }
                Family::Presence => latest = Some(location),
                Family::Watermark => {
                    self.watermarks
                        .entry(location)
                        .or_insert(frame.sequence_number);
                }
            }
        }

        if operation_count > 0 {
            let latest =
                latest.ok_or_else(|| ConnectError::internal("qmdb batch missing presence row"))?;
            let start_location = latest
                .checked_add(1)
                .and_then(|next| next.checked_sub(operation_count as u64))
                .ok_or_else(|| ConnectError::internal("invalid streamed batch location range"))?;
            let min_operation = min_operation
                .ok_or_else(|| ConnectError::internal("streamed batch missing operation rows"))?;
            let max_operation = max_operation
                .ok_or_else(|| ConnectError::internal("streamed batch missing operation rows"))?;
            if min_operation != start_location || max_operation != latest {
                return Err(ConnectError::internal(format!(
                    "streamed qmdb batch locations are not contiguous: expected [{start_location}, {latest}], saw [{min_operation}, {max_operation}]"
                )));
            }
            self.pending.insert(
                latest,
                PendingRangeBatch {
                    sequence_number: frame.sequence_number,
                    start_location,
                    operation_count,
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
            self.ready.push_back(ReadyRangeBatch {
                watermark,
                read_floor_sequence: batch.sequence_number.max(watermark_sequence),
                start_location: batch.start_location,
                operation_count: batch.operation_count,
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

impl<Resp> Stream for RangeSubscribeStream<Resp>
where
    Resp: Send + 'static,
{
    type Item = Result<Resp, ConnectError>;

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
                this.building = Some((this.build_response)(batch));
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
                return Poll::Ready(Some(Err(err)));
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

impl<H, K, V, const N: usize> OrderedService for OrderedConnect<H, K, V, N>
where
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + Send + Sync + 'static,
    QmdbOperation<K, V>: Encode + commonware_codec::Decode,
{
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
        let client = self.client.clone();
        async move {
            let mut exact_keys = BTreeSet::<Vec<u8>>::new();
            let mut prefixes = Vec::new();
            let mut regexes = Vec::new();
            for match_key in request.match_keys.iter() {
                match match_key.kind {
                    Some(ProtoBytesMatchKeyKindView::Exact(exact)) => {
                        exact_keys.insert(exact.to_vec());
                    }
                    Some(ProtoBytesMatchKeyKindView::Prefix(prefix)) => {
                        prefixes.push(prefix.to_vec());
                    }
                    Some(ProtoBytesMatchKeyKindView::Regex(pattern)) => {
                        regexes.push(Regex::new(pattern).map_err(|err| {
                            ConnectError::invalid_argument(format!(
                                "invalid regex subscription filter `{pattern}`: {err}"
                            ))
                        })?);
                    }
                    None => {
                        return Err(ConnectError::invalid_argument(
                            "each match_key must set exactly one of exact, prefix, or regex",
                        ));
                    }
                }
            }
            let matcher = SubscriptionMatcher {
                exact_keys,
                prefixes,
                regexes,
            };
            if matcher.is_empty() {
                return Err(ConnectError::invalid_argument(
                    "subscribe must include at least one match_key",
                ));
            }

            let since = decode_since(request.since_sequence_number);
            let (classify, filter) = sub::ordered_classify_and_filter();
            let sub = sub::open_store_subscription(client.store_client(), filter, since)
                .await
                .map_err(qmdb_error_to_connect)?;
            let stream = OrderedSubscribeStream::new(client, matcher, classify, sub);
            let stream: Pin<
                Box<dyn Stream<Item = Result<SubscribeResponse, ConnectError>> + Send>,
            > = Box::pin(stream);
            Ok((stream, ctx))
        }
    }

    fn get(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<GetRequestView<'static>>,
    ) -> impl Future<Output = Result<(GetResponse, Context), ConnectError>> + Send {
        let client = self.client.clone();
        async move {
            let key = request.key.to_vec();
            let watermark = match request.watermark {
                Some(watermark) => Location::new(watermark),
                None => client
                    .writer_location_watermark()
                    .await
                    .map_err(qmdb_error_to_connect)?
                    .ok_or_else(|| {
                        ConnectError::failed_precondition("ordered qmdb has no published watermark")
                    })?,
            };
            let proof = client
                .key_value_proof_raw_at::<&[u8]>(watermark, key.as_slice())
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
}

impl<H, K, V, const N: usize> OrderedRangeService for OrderedRangeConnect<H, K, V, N>
where
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + Send + Sync + 'static,
    QmdbOperation<K, V>: Encode + commonware_codec::Decode,
{
    fn subscribe(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<RangeSubscribeRequestView<'static>>,
    ) -> impl Future<
        Output = Result<
            (
                Pin<Box<dyn Stream<Item = Result<RangeSubscribeResponse, ConnectError>> + Send>>,
                Context,
            ),
            ConnectError,
        >,
    > + Send {
        let client = self.client.clone();
        async move {
            let since = decode_since(request.since_sequence_number);
            let (classify, filter) = sub::ordered_classify_and_filter();
            let sub = sub::open_store_subscription(client.store_client(), filter, since)
                .await
                .map_err(qmdb_error_to_connect)?;
            let build_response: BuildRangeResponse<RangeSubscribeResponse> = Arc::new({
                let client = client.clone();
                move |batch| {
                    let client = client.clone();
                    async move {
                        let checkpoint = client
                            .operation_range_checkpoint_with_read_floor(
                                batch.read_floor_sequence,
                                batch.watermark,
                                batch.start_location,
                                batch.operation_count,
                            )
                            .await
                            .map_err(qmdb_error_to_connect)?;
                        Ok(RangeSubscribeResponse {
                            resume_sequence_number: batch.read_floor_sequence,
                            proof: Some(operation_range_checkpoint_to_proto(&checkpoint)).into(),
                            ..Default::default()
                        })
                    }
                    .boxed()
                }
            });
            let stream = RangeSubscribeStream::new(classify, sub, build_response);
            let stream: Pin<
                Box<dyn Stream<Item = Result<RangeSubscribeResponse, ConnectError>> + Send>,
            > = Box::pin(stream);
            Ok((stream, ctx))
        }
    }
}

impl<H, K, V> UnorderedRangeService for UnorderedRangeConnect<H, K, V>
where
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + Send + Sync + 'static,
    UnorderedQmdbOperation<K, V>: Encode + commonware_codec::Decode,
{
    fn subscribe(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<RangeSubscribeRequestView<'static>>,
    ) -> impl Future<
        Output = Result<
            (
                Pin<Box<dyn Stream<Item = Result<RangeSubscribeResponse, ConnectError>> + Send>>,
                Context,
            ),
            ConnectError,
        >,
    > + Send {
        let client = self.client.clone();
        async move {
            let since = decode_since(request.since_sequence_number);
            let (classify, filter) = sub::unordered_classify_and_filter();
            let sub = sub::open_store_subscription(client.store_client(), filter, since)
                .await
                .map_err(qmdb_error_to_connect)?;
            let build_response: BuildRangeResponse<RangeSubscribeResponse> = Arc::new({
                let client = client.clone();
                move |batch| {
                    let client = client.clone();
                    async move {
                        let checkpoint = client
                            .operation_range_checkpoint_with_read_floor(
                                batch.read_floor_sequence,
                                batch.watermark,
                                batch.start_location,
                                batch.operation_count,
                            )
                            .await
                            .map_err(qmdb_error_to_connect)?;
                        Ok(RangeSubscribeResponse {
                            resume_sequence_number: batch.read_floor_sequence,
                            proof: Some(operation_range_checkpoint_to_proto(&checkpoint)).into(),
                            ..Default::default()
                        })
                    }
                    .boxed()
                }
            });
            let stream = RangeSubscribeStream::new(classify, sub, build_response);
            let stream: Pin<
                Box<dyn Stream<Item = Result<RangeSubscribeResponse, ConnectError>> + Send>,
            > = Box::pin(stream);
            Ok((stream, ctx))
        }
    }
}

impl<H, K, V> ImmutableRangeService for ImmutableRangeConnect<H, K, V>
where
    H: Hasher + Send + Sync + 'static,
    K: commonware_utils::Array
        + commonware_codec::Codec
        + Clone
        + AsRef<[u8]>
        + Send
        + Sync
        + 'static,
    V: commonware_codec::Codec + Clone + Send + Sync + 'static,
    ImmutableOperation<K, V>: Encode + commonware_codec::Decode<Cfg = V::Cfg> + Clone,
{
    fn subscribe(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<RangeSubscribeRequestView<'static>>,
    ) -> impl Future<
        Output = Result<
            (
                Pin<Box<dyn Stream<Item = Result<RangeSubscribeResponse, ConnectError>> + Send>>,
                Context,
            ),
            ConnectError,
        >,
    > + Send {
        let client = self.client.clone();
        async move {
            let since = decode_since(request.since_sequence_number);
            let (classify, filter) = sub::immutable_classify_and_filter();
            let sub = sub::open_store_subscription(client.store_client(), filter, since)
                .await
                .map_err(qmdb_error_to_connect)?;
            let build_response: BuildRangeResponse<RangeSubscribeResponse> = Arc::new({
                let client = client.clone();
                move |batch| {
                    let client = client.clone();
                    async move {
                        let checkpoint = client
                            .operation_range_checkpoint_with_read_floor(
                                batch.read_floor_sequence,
                                batch.watermark,
                                batch.start_location,
                                batch.operation_count,
                            )
                            .await
                            .map_err(qmdb_error_to_connect)?;
                        Ok(RangeSubscribeResponse {
                            resume_sequence_number: batch.read_floor_sequence,
                            proof: Some(operation_range_checkpoint_to_proto(&checkpoint)).into(),
                            ..Default::default()
                        })
                    }
                    .boxed()
                }
            });
            let stream = RangeSubscribeStream::new(classify, sub, build_response);
            let stream: Pin<
                Box<dyn Stream<Item = Result<RangeSubscribeResponse, ConnectError>> + Send>,
            > = Box::pin(stream);
            Ok((stream, ctx))
        }
    }
}

impl<H, V> KeylessRangeService for KeylessRangeConnect<H, V>
where
    H: Hasher + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + Send + Sync + 'static,
    KeylessOperation<V>: Encode + commonware_codec::Decode<Cfg = V::Cfg> + Clone,
{
    fn subscribe(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<RangeSubscribeRequestView<'static>>,
    ) -> impl Future<
        Output = Result<
            (
                Pin<Box<dyn Stream<Item = Result<RangeSubscribeResponse, ConnectError>> + Send>>,
                Context,
            ),
            ConnectError,
        >,
    > + Send {
        let client = self.client.clone();
        async move {
            let since = decode_since(request.since_sequence_number);
            let (classify, filter) = sub::keyless_classify_and_filter();
            let sub = sub::open_store_subscription(client.store_client(), filter, since)
                .await
                .map_err(qmdb_error_to_connect)?;
            let build_response: BuildRangeResponse<RangeSubscribeResponse> = Arc::new({
                let client = client.clone();
                move |batch| {
                    let client = client.clone();
                    async move {
                        let checkpoint = client
                            .operation_range_checkpoint_with_read_floor(
                                batch.read_floor_sequence,
                                batch.watermark,
                                batch.start_location,
                                batch.operation_count,
                            )
                            .await
                            .map_err(qmdb_error_to_connect)?;
                        Ok(RangeSubscribeResponse {
                            resume_sequence_number: batch.read_floor_sequence,
                            proof: Some(operation_range_checkpoint_to_proto(&checkpoint)).into(),
                            ..Default::default()
                        })
                    }
                    .boxed()
                }
            });
            let stream = RangeSubscribeStream::new(classify, sub, build_response);
            let stream: Pin<
                Box<dyn Stream<Item = Result<RangeSubscribeResponse, ConnectError>> + Send>,
            > = Box::pin(stream);
            Ok((stream, ctx))
        }
    }
}

pub fn ordered_connect_stack<
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + Send + Sync + 'static,
    const N: usize,
>(
    client: Arc<OrderedClient<H, K, V, N>>,
) -> ConnectRpcService<OrderedServiceServer<OrderedConnect<H, K, V, N>>>
where
    QmdbOperation<K, V>: Encode + commonware_codec::Decode,
{
    ConnectRpcService::new(OrderedServiceServer::new(OrderedConnect::new(client)))
        .with_limits(connect_limits())
        .with_compression(exoware_sdk_rs::connect_compression_registry())
}

pub fn ordered_range_connect_stack<
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + Send + Sync + 'static,
    const N: usize,
>(
    client: Arc<OrderedClient<H, K, V, N>>,
) -> ConnectRpcService<OrderedRangeServiceServer<OrderedRangeConnect<H, K, V, N>>>
where
    QmdbOperation<K, V>: Encode + commonware_codec::Decode,
{
    ConnectRpcService::new(OrderedRangeServiceServer::new(OrderedRangeConnect::new(
        client,
    )))
    .with_limits(connect_limits())
    .with_compression(exoware_sdk_rs::connect_compression_registry())
}

pub fn unordered_range_connect_stack<
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + Send + Sync + 'static,
>(
    client: Arc<UnorderedClient<H, K, V>>,
) -> ConnectRpcService<UnorderedRangeServiceServer<UnorderedRangeConnect<H, K, V>>>
where
    UnorderedQmdbOperation<K, V>: Encode + commonware_codec::Decode,
{
    ConnectRpcService::new(UnorderedRangeServiceServer::new(
        UnorderedRangeConnect::new(client),
    ))
    .with_limits(connect_limits())
    .with_compression(exoware_sdk_rs::connect_compression_registry())
}

pub fn immutable_range_connect_stack<
    H: Hasher + Send + Sync + 'static,
    K: commonware_utils::Array + commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + Send + Sync + 'static,
>(
    client: Arc<ImmutableClient<H, K, V>>,
) -> ConnectRpcService<ImmutableRangeServiceServer<ImmutableRangeConnect<H, K, V>>>
where
    ImmutableOperation<K, V>: Encode + commonware_codec::Decode<Cfg = V::Cfg> + Clone,
{
    ConnectRpcService::new(ImmutableRangeServiceServer::new(
        ImmutableRangeConnect::new(client),
    ))
    .with_limits(connect_limits())
    .with_compression(exoware_sdk_rs::connect_compression_registry())
}

pub fn keyless_range_connect_stack<
    H: Hasher + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + Send + Sync + 'static,
>(
    client: Arc<KeylessClient<H, V>>,
) -> ConnectRpcService<KeylessRangeServiceServer<KeylessRangeConnect<H, V>>>
where
    KeylessOperation<V>: Encode + commonware_codec::Decode<Cfg = V::Cfg> + Clone,
{
    ConnectRpcService::new(KeylessRangeServiceServer::new(KeylessRangeConnect::new(
        client,
    )))
    .with_limits(connect_limits())
    .with_compression(exoware_sdk_rs::connect_compression_registry())
}
