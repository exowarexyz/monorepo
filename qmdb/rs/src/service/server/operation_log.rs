//! `qmdb.v1.OperationLogService`: historical operation ranges, multi-location
//! operation proofs, and proof-carrying subscriptions.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use commonware_storage::merkle::{Family, Graftable, Location};
use connectrpc::{ConnectError, ErrorCode, PreEncoded, RequestContext as Context, ServiceRequest};
use exoware_sdk::common::kv::v1::filter::KindView as ProtoFilterKindView;
use exoware_sdk::stream_filter::{CompiledFilters, Filter};
use exoware_sdk::PrefixedStoreClient;
use futures::future::BoxFuture;
use futures::{FutureExt, Stream};

// The subscribe stream still classifies raw Store rows itself.
use crate::adapter::subscription::{self as sub, RowClassifier};
use crate::proof::{OperationRangeCheckpoint, RawBatchMultiProof};
use crate::request::OperationLocations;
use crate::service::proto::qmdb::v1::{
    GetOperationRangeRequest, GetOperationRangeResponse, GetOperationsRequest,
    GetOperationsResponse, OperationLogService, SubscribeRequest, SubscribeResponse,
};
use crate::{OperationKv, PublishedWatermark, QmdbError};

use super::{encode, qmdb_error_to_connect};

/// Read capabilities needed by [`OperationLogServer`].
pub(crate) trait OperationLogReader: Send + Sync + 'static {
    type Family: Graftable;
    type Digest: commonware_cryptography::Digest;
    /// Reject `key_filters` at subscribe time (set true for keyless, whose
    /// ops have no logical key).
    const REJECTS_KEY_FILTERS: bool = false;

    fn extract_operation_kv(
        &self,
        location: Location<Self::Family>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError>;
    fn resolve_watermark(
        &self,
        watermark: Location<Self::Family>,
        min_sequence_number: Option<u64>,
    ) -> impl Future<Output = Result<PublishedWatermark<Self::Family>, QmdbError>> + Send;
    fn batch_multi_proof(
        &self,
        watermark: PublishedWatermark<Self::Family>,
        operations: Vec<(Location<Self::Family>, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, Self::Family>, QmdbError>> + Send;
    fn operation_range_checkpoint_at(
        &self,
        watermark: PublishedWatermark<Self::Family>,
        start_location: Location<Self::Family>,
        max_locations: u32,
    ) -> impl Future<Output = Result<OperationRangeCheckpoint<Self::Digest, Self::Family>, QmdbError>>
           + Send;
    fn operations_multi_proof_at(
        &self,
        watermark: PublishedWatermark<Self::Family>,
        locations: &[Location<Self::Family>],
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, Self::Family>, QmdbError>> + Send;
}

/// `OperationLogService` handler over any [`OperationLogReader`].
pub(crate) struct OperationLogServer<R: OperationLogReader> {
    reader: Arc<R>,
    raw_store: PrefixedStoreClient,
}

impl<R: OperationLogReader> Clone for OperationLogServer<R> {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            raw_store: self.raw_store.clone(),
        }
    }
}

impl<R: OperationLogReader> OperationLogServer<R> {
    pub(crate) fn new(reader: Arc<R>, raw_store: PrefixedStoreClient) -> Self {
        Self { reader, raw_store }
    }
}

#[derive(Clone, Debug)]
struct PendingBatch<F: Family> {
    latest: Location<F>,
    sequence_number: u64,
    matched: Vec<(Location<F>, Vec<u8>)>,
}

struct PendingBatches<F: Family> {
    batches: VecDeque<PendingBatch<F>>,

    // Tips can arrive out of order, but batches drain only from the front. Keep
    // each tip no greater than any later tip, including duplicates, so the next
    // minimum is available when the current one drains.
    minimums: VecDeque<Location<F>>,
}

impl<F: Family> PendingBatches<F> {
    fn new() -> Self {
        Self {
            batches: VecDeque::new(),
            minimums: VecDeque::new(),
        }
    }

    fn len(&self) -> usize {
        self.batches.len()
    }

    fn push_back(&mut self, batch: PendingBatch<F>) {
        while self.minimums.back().is_some_and(|&tip| tip > batch.latest) {
            self.minimums.pop_back();
        }
        self.minimums.push_back(batch.latest);
        self.batches.push_back(batch);
    }

    fn drain_ready(
        &mut self,
        watermarks: &mut BTreeMap<Location<F>, u64>,
        ready: &mut VecDeque<ReadyBatch<F>>,
    ) {
        // Preserve Store order so a resume cursor cannot skip an unpublished frame.
        while let Some(batch) = self.batches.front() {
            let Some((&watermark, &watermark_sequence)) = watermarks.range(batch.latest..).next()
            else {
                break;
            };
            let batch = self.batches.pop_front().expect("pending is not empty");
            if self.minimums.front() == Some(&batch.latest) {
                self.minimums.pop_front();
            }
            ready.push_back(ReadyBatch {
                watermark: PublishedWatermark {
                    location: watermark,
                    sequence_number: batch.sequence_number.max(watermark_sequence),
                },
                batch_sequence: batch.sequence_number,
                matched: batch.matched,
            });
        }

        if let Some(floor) = self
            .minimums
            .front()
            .copied()
            .or_else(|| watermarks.keys().next_back().copied())
        {
            *watermarks = watermarks.split_off(&floor);
        }
    }
}

#[derive(Clone, Debug)]
struct ReadyBatch<F: Family> {
    watermark: PublishedWatermark<F>,
    /// Store sequence of this batch's ops frame. Emitted as
    /// `resume_sequence_number`. It is unique per batch, so a client reconnecting
    /// at `resume + 1` skips only this batch. When multiple pending batches
    /// share a single authorizing watermark, each must carry its own
    /// per-batch sequence here or the reconnect cursor would jump past
    /// unread siblings.
    batch_sequence: u64,
    matched: Vec<(Location<F>, Vec<u8>)>,
}

fn parse_filters<'a, 'b, I>(filters: I, label: &str) -> Result<Option<CompiledFilters>, String>
where
    I: IntoIterator<Item = &'b exoware_sdk::common::kv::v1::FilterView<'a>>,
    'a: 'b,
{
    let mut domain = Vec::new();
    for filter in filters {
        domain.push(match filter.kind {
            Some(ProtoFilterKindView::Exact(exact)) => Filter::Exact(Bytes::copy_from_slice(exact)),
            Some(ProtoFilterKindView::Prefix(prefix)) => {
                Filter::Prefix(Bytes::copy_from_slice(prefix))
            }
            Some(ProtoFilterKindView::Regex(pattern)) => Filter::Regex(pattern.to_string()),
            None => {
                return Err(format!(
                    "each {label} filter must set exactly one of exact, prefix, or regex"
                ));
            }
        });
    }
    CompiledFilters::compile(&domain).map_err(|e| format!("invalid {label} filter: {e}"))
}

fn matcher_passes(matcher: &Option<CompiledFilters>, bytes: Option<&[u8]>) -> bool {
    match matcher {
        None => true,
        Some(m) => bytes.map(|b| m.matches(b)).unwrap_or(false),
    }
}

struct BatchSubscribeStream<D: commonware_cryptography::Digest, F: Graftable> {
    key_matcher: Option<CompiledFilters>,
    value_matcher: Option<CompiledFilters>,
    classify: RowClassifier<F>,
    extract_kv: Arc<
        dyn for<'a> Fn(Location<F>, &'a [u8]) -> Result<OperationKv, QmdbError>
            + Send
            + Sync
            + 'static,
    >,
    build_proof: Arc<
        dyn Fn(
                PublishedWatermark<F>,
                Vec<(Location<F>, Vec<u8>)>,
            ) -> BoxFuture<'static, Result<RawBatchMultiProof<D, F>, QmdbError>>
            + Send
            + Sync
            + 'static,
    >,
    sub: exoware_sdk::StreamSubscription,
    pending: PendingBatches<F>,
    watermarks: BTreeMap<Location<F>, u64>,
    ready: VecDeque<ReadyBatch<F>>,
    building: Option<BoxFuture<'static, Result<PreEncoded<SubscribeResponse>, ConnectError>>>,
    // Terminal upstream event observed while a proof was still building. It is
    // delivered after the staged batches drain.
    staged_terminal: Option<StagedTerminal>,
}

// Bound on batches staged (pending plus ready) while a proof builds. Staging
// keeps demand flowing to the store subscription so the server-side lookahead
// stays occupied during proof construction, and the bound keeps the staged
// queues finite when the subscriber outruns proof throughput.
const SUBSCRIBE_STAGED_BATCHES: usize = 8;

enum StagedTerminal {
    End,
    Error(ConnectError),
}

impl<D: commonware_cryptography::Digest, F: Graftable> Unpin for BatchSubscribeStream<D, F> {}

impl<D: commonware_cryptography::Digest, F: Graftable> BatchSubscribeStream<D, F> {
    fn new(
        key_matcher: Option<CompiledFilters>,
        value_matcher: Option<CompiledFilters>,
        classify: RowClassifier<F>,
        extract_kv: Arc<
            dyn for<'a> Fn(Location<F>, &'a [u8]) -> Result<OperationKv, QmdbError>
                + Send
                + Sync
                + 'static,
        >,
        build_proof: Arc<
            dyn Fn(
                    PublishedWatermark<F>,
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
            pending: PendingBatches::new(),
            watermarks: BTreeMap::new(),
            ready: VecDeque::new(),
            building: None,
            staged_terminal: None,
        }
    }

    fn poll_frame(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Option<exoware_sdk::StoreBatch>, ConnectError>> {
        let next_fut = self.sub.next();
        tokio::pin!(next_fut);
        next_fut.as_mut().poll(cx).map_err(|err| {
            if let Some(rpc) = err.rpc_error() {
                ConnectError::new(rpc.code, rpc.message.clone().unwrap_or_default())
            } else {
                ConnectError::new(ErrorCode::Internal, err.to_string())
            }
        })
    }

    fn ingest_frame(&mut self, frame: &exoware_sdk::StoreBatch) -> Result<(), Box<ConnectError>> {
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
                    latest = latest.max(Some(location));
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
                sub::RowFamily::Watermark => {
                    self.watermarks
                        .entry(location)
                        .or_insert(frame.sequence_number);
                }
            }
        }

        if !matched.is_empty() {
            let latest = latest.expect("matched operations determine the frame tip");
            matched.sort_by_key(|(loc, _)| *loc);
            if matched
                .windows(2)
                .any(|pair| pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1)
            {
                return Err(Box::new(ConnectError::internal(
                    "conflicting QMDB operations at one location",
                )));
            }
            matched.dedup();
            self.pending.push_back(PendingBatch {
                latest,
                sequence_number: frame.sequence_number,
                matched,
            });
        }

        self.pending
            .drain_ready(&mut self.watermarks, &mut self.ready);
        Ok(())
    }
}

impl<D: commonware_cryptography::Digest, F: Graftable> Stream for BatchSubscribeStream<D, F> {
    type Item = Result<PreEncoded<SubscribeResponse>, ConnectError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            if let Some(fut) = this.building.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(result) => {
                        this.building = None;
                        return Poll::Ready(Some(result));
                    }
                    Poll::Pending => {
                        // Keep pulling upstream frames while the proof builds
                        // so demand reaches the store subscription, up to the
                        // staged-batch bound.
                        while this.staged_terminal.is_none()
                            && this.pending.len() + this.ready.len() < SUBSCRIBE_STAGED_BATCHES
                        {
                            match this.poll_frame(cx) {
                                Poll::Ready(Ok(Some(frame))) => {
                                    if let Err(err) = this.ingest_frame(&frame) {
                                        this.staged_terminal = Some(StagedTerminal::Error(*err));
                                    }
                                }
                                Poll::Ready(Ok(None)) => {
                                    this.staged_terminal = Some(StagedTerminal::End);
                                }
                                Poll::Ready(Err(err)) => {
                                    this.staged_terminal = Some(StagedTerminal::Error(err));
                                }
                                Poll::Pending => break,
                            }
                        }
                        return Poll::Pending;
                    }
                }
            }

            if let Some(batch) = this.ready.pop_front() {
                let build = this.build_proof.clone();
                let fut = async move {
                    let proof = (build)(batch.watermark, batch.matched)
                        .await
                        .map_err(qmdb_error_to_connect)?;
                    Ok(encode::subscribe_response(batch.batch_sequence, &proof))
                }
                .boxed();
                this.building = Some(fut);
                continue;
            }

            if let Some(terminal) = this.staged_terminal.take() {
                return Poll::Ready(match terminal {
                    StagedTerminal::End => None,
                    StagedTerminal::Error(err) => Some(Err(err)),
                });
            }

            match this.poll_frame(cx) {
                Poll::Ready(Ok(Some(frame))) => {
                    if let Err(err) = this.ingest_frame(&frame) {
                        return Poll::Ready(Some(Err(*err)));
                    }
                }
                Poll::Ready(Ok(None)) => return Poll::Ready(None),
                Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err))),
                Poll::Pending => return Poll::Pending,
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

impl<R: OperationLogReader> OperationLogService for OperationLogServer<R> {
    fn get_operation_range(
        &self,
        _ctx: Context,
        request: ServiceRequest<'_, GetOperationRangeRequest>,
    ) -> impl Future<Output = connectrpc::ServiceResult<PreEncoded<GetOperationRangeResponse>>> + Send
    {
        let reader = self.reader.clone();
        async move {
            let watermark = reader
                .resolve_watermark(Location::new(request.tip), request.min_sequence_number)
                .await
                .map_err(qmdb_error_to_connect)?;
            let proof = reader
                .operation_range_checkpoint_at(
                    watermark,
                    Location::new(request.start_location),
                    request.max_locations,
                )
                .await
                .map_err(qmdb_error_to_connect)?;
            connectrpc::Response::ok(encode::get_operation_range_response(&proof))
        }
    }

    fn get_operations(
        &self,
        _ctx: Context,
        request: ServiceRequest<'_, GetOperationsRequest>,
    ) -> impl Future<Output = connectrpc::ServiceResult<PreEncoded<GetOperationsResponse>>> + Send
    {
        let reader = self.reader.clone();
        async move {
            let requested = request.locations.iter().copied().collect::<Vec<u64>>();
            OperationLocations::new(request.tip, &requested)
                .map_err(|err| qmdb_error_to_connect(err.into()))?;
            let watermark = reader
                .resolve_watermark(Location::new(request.tip), request.min_sequence_number)
                .await
                .map_err(qmdb_error_to_connect)?;
            let locations = requested
                .into_iter()
                .map(Location::new)
                .collect::<Vec<Location<R::Family>>>();
            let proof = reader
                .operations_multi_proof_at(watermark, &locations)
                .await
                .map_err(qmdb_error_to_connect)?;
            connectrpc::Response::ok(encode::get_operations_response(&proof))
        }
    }

    fn subscribe(
        &self,
        _ctx: Context,
        request: ServiceRequest<'_, SubscribeRequest>,
    ) -> impl Future<
        Output = connectrpc::ServiceResult<
            connectrpc::ServiceStream<PreEncoded<SubscribeResponse>>,
        >,
    > + Send {
        let raw_store = self.raw_store.clone();
        let reader = self.reader.clone();
        async move {
            if R::REJECTS_KEY_FILTERS && !request.key_filters.is_empty() {
                return Err(ConnectError::invalid_argument(
                    "this OperationLogService endpoint does not accept key_filters",
                ));
            }
            let key_matcher = parse_filters(request.key_filters.iter(), "key")
                .map_err(ConnectError::invalid_argument)?;
            let value_matcher = parse_filters(request.value_filters.iter(), "value")
                .map_err(ConnectError::invalid_argument)?;
            let since = decode_since(request.since_sequence_number);
            let (classify, filter) = sub::classify_and_filter::<R::Family>();
            let sub = sub::open_store_subscription(&raw_store, filter, since)
                .await
                .map_err(qmdb_error_to_connect)?;
            let extract_kv: Arc<
                dyn for<'a> Fn(Location<R::Family>, &'a [u8]) -> Result<OperationKv, QmdbError>
                    + Send
                    + Sync
                    + 'static,
            > = {
                let reader = reader.clone();
                Arc::new(move |location, bytes| reader.extract_operation_kv(location, bytes))
            };
            let build_proof = Arc::new(move |watermark, matched| {
                let reader = reader.clone();
                async move { reader.batch_multi_proof(watermark, matched).await }.boxed()
            });
            let stream: Pin<
                Box<dyn Stream<Item = Result<PreEncoded<SubscribeResponse>, ConnectError>> + Send>,
            > = Box::pin(BatchSubscribeStream::new(
                key_matcher,
                value_matcher,
                classify,
                extract_kv,
                build_proof,
                sub,
            ));
            Ok(connectrpc::Response::stream(stream))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fixed_request_sessions_do_not_share_observations_or_advance_floors() {
        let (_task, url) = exoware_simulator::open_temp().await.expect("simulator");
        let raw_store = PrefixedStoreClient::empty(exoware_sdk::StoreClient::new(&url));
        let first = exoware_sdk::ReadSession::fixed(raw_store.clone(), None);
        let second = exoware_sdk::ReadSession::fixed(raw_store.clone(), None);
        let explicit_zero = exoware_sdk::ReadSession::fixed(raw_store.clone(), Some(0));
        let key = Bytes::from_static(b"request-session-isolation");
        let sequence = raw_store
            .ingest()
            .put(&[(&key, b"value")])
            .await
            .expect("write fixture");

        assert_eq!(
            first.get(&key).await.expect("read fixture"),
            Some(Bytes::from_static(b"value"))
        );
        assert_eq!(first.evaluated_sequence(), Some(sequence));
        assert_eq!(first.min_sequence_number(), None);
        assert_eq!(second.evaluated_sequence(), None);
        assert_eq!(second.min_sequence_number(), None);
        assert_eq!(explicit_zero.min_sequence_number(), Some(0));
        assert_eq!(explicit_zero.evaluated_sequence(), None);
    }

    fn pending(
        latest: u64,
        sequence_number: u64,
    ) -> PendingBatch<commonware_storage::merkle::mmr::Family> {
        PendingBatch {
            latest: Location::new(latest),
            sequence_number,
            matched: vec![(
                Location::<commonware_storage::merkle::mmr::Family>::new(sequence_number),
                vec![sequence_number as u8],
            )],
        }
    }

    #[test]
    fn test_subscribe_multi_proof_proto_includes_ops_root_without_witness() {
        use buffa::Message as _;
        use commonware_codec::Encode as _;
        use commonware_cryptography::{sha256::Digest as Sha256Digest, Sha256};
        use commonware_storage::merkle::{mmr, Proof};
        use connectrpc::Encodable as _;

        let root = Sha256::fill(0x42);
        let raw = RawBatchMultiProof::<Sha256Digest, mmr::Family> {
            watermark: Location::new(0),
            ops_root: root,
            ops_root_witness: None,
            proof: Proof {
                leaves: Location::new(1),
                inactive_peaks: 0,
                digests: Vec::new(),
            },
            operations: vec![(Location::new(0), vec![0xAA])],
        };

        let encoded = encode::subscribe_response(0, &raw)
            .encode(connectrpc::CodecFormat::Proto)
            .expect("encode response");
        let proto = SubscribeResponse::decode_from_slice(&encoded).expect("decode response");
        let proof = proto.proof.as_option().expect("proof");

        assert_eq!(proof.ops_root, root.encode());
        assert!(proof.ops_root_witness.is_empty());
    }

    #[test]
    fn test_shared_watermark_preserves_per_batch_resume_cursor() {
        // Three batches (ops at locations 10, 11, 12) authorized by a single
        // watermark at location 12 (published at store seq 15). If they all
        // emitted the same resume cursor, a client that received only the
        // first batch and reconnected at resume+1 would skip the other two.
        let mut batches = PendingBatches::new();
        for sequence in 10..=12 {
            batches.push_back(pending(sequence, sequence));
        }
        let mut watermarks = BTreeMap::from([(
            Location::<commonware_storage::merkle::mmr::Family>::new(12),
            15u64,
        )]);
        let mut ready = VecDeque::new();

        batches.drain_ready(&mut watermarks, &mut ready);

        assert_eq!(ready.len(), 3);
        let cursors: Vec<u64> = ready.iter().map(|b| b.batch_sequence).collect();
        assert_eq!(cursors, vec![10, 11, 12]);
        for b in &ready {
            assert_eq!(b.watermark.sequence_number, 15);
            assert_eq!(
                b.watermark.location,
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

    #[test]
    fn test_out_of_order_uploads_preserve_subscription_replay_order() {
        type F = commonware_storage::merkle::mmr::Family;
        let mut batches = PendingBatches::new();
        batches.push_back(pending(20, 10));
        batches.push_back(pending(10, 11));
        let mut watermarks = BTreeMap::from([(Location::<F>::new(20), 12)]);
        let mut ready = VecDeque::new();
        batches.drain_ready(&mut watermarks, &mut ready);
        let cursors = ready
            .iter()
            .map(|batch| batch.batch_sequence)
            .collect::<Vec<_>>();
        assert_eq!(cursors, [10, 11]);
        let resume = cursors[0] + 1;
        assert!(cursors[1..].iter().all(|cursor| *cursor >= resume));
        assert!(ready
            .iter()
            .all(|batch| batch.watermark.sequence_number == 12));
    }

    #[test]
    fn test_subscription_waits_for_earlier_store_sequence_to_be_published() {
        type F = commonware_storage::merkle::mmr::Family;
        let mut batches = PendingBatches::new();
        batches.push_back(pending(20, 10));
        batches.push_back(pending(10, 11));
        let mut watermarks = BTreeMap::from([(Location::<F>::new(10), 11)]);
        let mut ready = VecDeque::new();
        batches.drain_ready(&mut watermarks, &mut ready);
        assert!(
            ready.is_empty(),
            "a cursor must not skip an unpublished earlier Store frame"
        );
        watermarks.insert(Location::new(20), 12);
        batches.drain_ready(&mut watermarks, &mut ready);
        assert_eq!(
            ready
                .iter()
                .map(|batch| batch.batch_sequence)
                .collect::<Vec<_>>(),
            [10, 11]
        );
    }

    #[test]
    fn test_subscription_prunes_watermarks_after_partial_drains() {
        type F = commonware_storage::merkle::mmr::Family;
        let mut batches = PendingBatches::new();
        for (sequence, latest) in [5, 20, 5, 30, 10, 10, 40].into_iter().enumerate() {
            batches.push_back(pending(latest, sequence as u64));
        }
        let mut watermarks = BTreeMap::from([
            (Location::<F>::new(4), 7),
            (Location::new(5), 8),
            (Location::new(10), 9),
        ]);
        let mut ready = VecDeque::new();

        // The later batch at tip 5 still needs its watermark after the first drains.
        batches.drain_ready(&mut watermarks, &mut ready);
        assert_eq!(batches.len(), 6);
        assert_eq!(
            watermarks.keys().copied().collect::<Vec<_>>(),
            [Location::new(5), Location::new(10)]
        );

        watermarks.insert(Location::new(20), 10);
        batches.drain_ready(&mut watermarks, &mut ready);
        assert_eq!(batches.len(), 4);
        assert_eq!(
            watermarks.keys().copied().collect::<Vec<_>>(),
            [Location::new(10), Location::new(20)]
        );

        watermarks.insert(Location::new(30), 11);
        batches.drain_ready(&mut watermarks, &mut ready);
        assert_eq!(batches.len(), 1);
        assert!(watermarks.is_empty());

        watermarks.insert(Location::new(40), 12);
        batches.drain_ready(&mut watermarks, &mut ready);
        assert_eq!(batches.len(), 0);
        assert_eq!(watermarks, BTreeMap::from([(Location::new(40), 12)]));
        assert_eq!(
            ready
                .iter()
                .map(|batch| (
                    batch.batch_sequence,
                    *batch.watermark.location,
                    batch.watermark.sequence_number
                ))
                .collect::<Vec<_>>(),
            [
                (0, 5, 8),
                (1, 20, 10),
                (2, 5, 8),
                (3, 30, 11),
                (4, 10, 9),
                (5, 10, 9),
                (6, 40, 12)
            ]
        );

        batches.push_back(pending(50, 13));
        batches.drain_ready(&mut watermarks, &mut ready);
        assert_eq!(batches.len(), 1);
        assert!(watermarks.is_empty());
    }
}

#[cfg(test)]
mod authenticated_upload_subscription_tests {
    use super::*;
    use commonware_cryptography::sha256::Digest;
    use commonware_storage::merkle::mmr;
    use exoware_sdk::{StoreBatch, StoreBatchEntry};

    type F = mmr::Family;

    async fn stream() -> BatchSubscribeStream<Digest, F> {
        let (_task, url) = exoware_simulator::open_temp().await.expect("simulator");
        let client = exoware_sdk::PrefixedStoreClient::empty(exoware_sdk::StoreClient::new(&url));
        let (classifier, filter) = sub::classify_and_filter::<F>();
        let subscription = client.stream().subscribe(filter, None).await.unwrap();
        BatchSubscribeStream::new(
            None,
            None,
            classifier,
            Arc::new(|_, bytes| {
                Ok(OperationKv {
                    key: None,
                    value: Some(bytes.to_vec()),
                })
            }),
            Arc::new(|_, _| async { unreachable!("ingestion does not build proofs") }.boxed()),
            subscription,
        )
    }

    fn operation(location: u64, value: &'static [u8]) -> StoreBatchEntry {
        StoreBatchEntry {
            key: crate::adapter::codec::encode_operation_key(Location::<F>::new(location)),
            value: Bytes::from_static(value),
        }
    }

    fn watermark(location: u64) -> StoreBatchEntry {
        StoreBatchEntry {
            key: crate::adapter::codec::encode_watermark_key(Location::<F>::new(location)),
            value: Bytes::new(),
        }
    }

    #[tokio::test]
    async fn test_data_only_frames_wait_for_publication_and_keep_store_order() {
        let mut stream = stream().await;
        stream
            .ingest_frame(&StoreBatch {
                sequence_number: 10,
                entries: vec![operation(4, b"four"), operation(5, b"five")],
            })
            .expect("authenticated data frames must not require a presence row");
        stream
            .ingest_frame(&StoreBatch {
                sequence_number: 11,
                entries: vec![operation(0, b"zero"), operation(1, b"one")],
            })
            .unwrap();
        assert_eq!(stream.pending.len(), 2);
        assert!(stream.ready.is_empty());

        stream
            .ingest_frame(&StoreBatch {
                sequence_number: 12,
                entries: vec![watermark(1)],
            })
            .unwrap();
        assert!(
            stream.ready.is_empty(),
            "an earlier Store frame must not be skipped"
        );
        stream
            .ingest_frame(&StoreBatch {
                sequence_number: 13,
                entries: vec![watermark(5)],
            })
            .unwrap();
        assert_eq!(stream.pending.len(), 0);
        assert_eq!(stream.ready.len(), 2);
        assert_eq!(
            stream
                .ready
                .iter()
                .map(|batch| (
                    batch.batch_sequence,
                    *batch.watermark.location,
                    batch.watermark.sequence_number
                ))
                .collect::<Vec<_>>(),
            [(10, 5, 13), (11, 1, 12)]
        );
        assert_eq!(
            stream.ready[0].matched,
            [
                (Location::new(4), b"four".to_vec()),
                (Location::new(5), b"five".to_vec())
            ]
        );
        assert_eq!(
            stream.ready[1].matched,
            [
                (Location::new(0), b"zero".to_vec()),
                (Location::new(1), b"one".to_vec())
            ]
        );
    }

    #[tokio::test]
    async fn test_filtered_out_operations_still_determine_the_data_frame_tip() {
        let mut stream = stream().await;
        stream.value_matcher =
            CompiledFilters::compile(&[Filter::Exact(Bytes::from_static(b"keep"))]).unwrap();
        stream
            .ingest_frame(&StoreBatch {
                sequence_number: 10,
                entries: vec![operation(4, b"keep"), operation(5, b"skip")],
            })
            .unwrap();
        stream
            .ingest_frame(&StoreBatch {
                sequence_number: 11,
                entries: vec![watermark(4)],
            })
            .unwrap();
        assert!(
            stream.ready.is_empty(),
            "filtering must not lower the required publication tip"
        );
        stream
            .ingest_frame(&StoreBatch {
                sequence_number: 12,
                entries: vec![watermark(5)],
            })
            .unwrap();
        assert_eq!(stream.ready.len(), 1);
        assert_eq!(
            stream.ready[0].matched,
            [(Location::new(4), b"keep".to_vec())]
        );
        assert_eq!(stream.ready[0].watermark.sequence_number, 12);
    }

    #[tokio::test]
    async fn test_overlapping_atomic_ranges_emit_each_operation_once() {
        let mut stream = stream().await;
        stream
            .ingest_frame(&StoreBatch {
                sequence_number: 10,
                entries: vec![
                    operation(0, b"zero"),
                    operation(1, b"one"),
                    operation(0, b"zero"),
                    watermark(1),
                ],
            })
            .unwrap();
        assert_eq!(stream.ready.len(), 1);
        assert_eq!(
            stream.ready[0].matched,
            [
                (Location::new(0), b"zero".to_vec()),
                (Location::new(1), b"one".to_vec())
            ]
        );
    }

    #[tokio::test]
    async fn test_conflicting_operation_rows_in_one_frame_are_rejected() {
        let mut stream = stream().await;
        assert!(stream
            .ingest_frame(&StoreBatch {
                sequence_number: 10,
                entries: vec![
                    operation(0, b"zero"),
                    operation(0, b"different"),
                    watermark(0)
                ],
            })
            .is_err());
    }
}
