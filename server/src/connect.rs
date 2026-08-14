//! Ingest, query, prune, retention, and stream services; storage is provided by capability
//! traits.

#![allow(refining_impl_trait)]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use connectrpc::{
    Chain, ConnectError, ConnectRpcService, Limits, PreEncoded, RequestContext as Context,
};
use exoware_proto::common::Entry;
use exoware_proto::google::rpc::{ErrorInfo, RetryInfo};
use exoware_proto::ingest::{
    PutResponse as ProtoPutResponse, Service as IngestApi, ServiceServer as IngestServiceServer,
};
use exoware_proto::log::retention::v1::{
    Service as RetentionApi, ServiceServer as RetentionServiceServer, SetRetentionRequestView,
    SetRetentionResponse,
};
use exoware_proto::log::stream::v1::{
    GetRequestView, GetResponse as StreamGetResponse, Service as StreamApi,
    ServiceServer as StreamServiceServer, SubscribeRequestView, SubscribeResponse,
};
use exoware_proto::prune::{
    PruneResponse, Service as PruneApi, ServiceServer as PruneServiceServer,
};
use exoware_proto::query::{
    Detail, GetManyEntry, GetManyFrame, GetResponse, RangeFrame, ReduceResponse,
    Service as QueryApi, ServiceServer as QueryServiceServer,
};
use exoware_proto::stream_filter::{Filter, StreamFilter};
use exoware_proto::{
    connect_compression_registry, parse_range_traversal_direction,
    to_domain_reduce_request_from_view, to_proto_optional_reduced_value, to_proto_reduced_value,
    with_error_info_detail, with_query_detail, with_retry_info_detail, RangeTraversalDirection,
};
use exoware_sdk as exoware_proto;
use exoware_sdk::common::kv::v1::filter::KindView as ProtoFilterKindView;
use exoware_sdk::keys::Key;
use exoware_sdk::selector::Selector;
use futures::{stream as stream_util, Stream, StreamExt};
use tokio::sync::Notify;

use crate::reduce::RangeReducer;
use crate::stream::{StreamHub, StreamNotifier};
use crate::validate::{self, IngestLimits};
use crate::{
    Ingest, IngestError, Log, LogBatch, Prune, Query, QueryExtra, RangeScan, Retention, StoreEngine,
};

// TODO (#57): Make limits configurable.
const MAX_CONNECTRPC_BODY_BYTES: usize = 256 * 1024 * 1024;
const RANGE_STREAM_MAX_FRAME_ROWS: usize = 4096;
const REDUCE_SCAN_BATCH_SIZE: usize = 4096;
// Per-subscription bound on concurrent subscribe log reads. Each slot can pin
// a fully materialized batch (in flight, or completed but held for in-order
// delivery), so server-wide memory and engine read pressure scale with this
// bound times the subscriber count. Engines stay responsible for protecting
// their own read path (for example via caching or request collapsing).
const SUBSCRIBE_GET_BATCH_LOOKAHEAD: usize = 8;

fn query_detail(sequence_number: u64, extra: QueryExtra) -> Detail {
    Detail {
        sequence_number,
        extra,
        ..Default::default()
    }
}

struct RangeStreamRequest {
    start_key: Key,
    end_key: Key,
    limit: usize,
    batch_size: usize,
    forward: bool,
    sequence_number: u64,
}

async fn range_stream<Q>(
    query: Arc<Q>,
    request: RangeStreamRequest,
) -> Result<Pin<Box<dyn Stream<Item = Result<RangeFrame, ConnectError>> + Send>>, ConnectError>
where
    Q: Query,
{
    let RangeStreamRequest {
        start_key,
        end_key,
        limit,
        batch_size,
        forward,
        sequence_number,
    } = request;
    let entries = query
        .range_scan(start_key, end_key, limit, forward)
        .await
        .map_err(ConnectError::internal)?;

    Ok(Box::pin(stream_util::unfold(
        Some((entries, false)),
        move |state| async move {
            let (mut entries, emitted_frame) = state?;
            let batch = match entries.next_batch(batch_size).await {
                Ok(batch) => batch,
                Err(e) => return Some((Err(ConnectError::internal(e)), None)),
            };
            let detail = query_detail(sequence_number, batch.extra);
            if batch.rows.is_empty() {
                if emitted_frame && detail.extra.is_empty() {
                    return None;
                }
                return Some((
                    Ok(RangeFrame {
                        detail: Some(detail).into(),
                        ..Default::default()
                    }),
                    None,
                ));
            }

            let mut chunk = Vec::with_capacity(batch.rows.len());
            for (key, value) in batch.rows {
                chunk.push(Entry {
                    key: key.into(),
                    value,
                    ..Default::default()
                });
            }
            Some((
                Ok(RangeFrame {
                    results: chunk,
                    detail: Some(detail).into(),
                    ..Default::default()
                }),
                Some((entries, true)),
            ))
        },
    )))
}

/// All-in-one single-process composition for a backend that serves every store capability.
/// Split deployments construct the narrower capability states directly.
pub struct AppState<E> {
    /// Backend that implements every store capability.
    pub engine: Arc<E>,
    /// Limits enforced by the ingest service before writing.
    pub ingest_limits: IngestLimits,
    /// Gates ingest (writes) only. The read and administrative services remain available during
    /// drains so that in-flight reads can complete while the worker sheds write traffic.
    pub ready: Arc<AtomicBool>,
    /// Shared fan-out hub for `log.stream.v1.Subscribe`.
    pub stream: Arc<StreamHub>,
}

impl<E> Clone for AppState<E> {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            ingest_limits: self.ingest_limits,
            ready: self.ready.clone(),
            stream: self.stream.clone(),
        }
    }
}

impl<E> AppState<E>
where
    E: StoreEngine,
{
    pub fn new(engine: Arc<E>) -> Self {
        let current_sequence = engine.current_sequence();
        Self {
            engine,
            ingest_limits: IngestLimits::default(),
            ready: Arc::new(AtomicBool::new(true)),
            stream: Arc::new(StreamHub::new(current_sequence)),
        }
    }

    pub fn with_ingest_limits(mut self, limits: IngestLimits) -> Self {
        self.ingest_limits = limits;
        self
    }
}

/// State for an ingest-only service.
pub struct IngestState<I> {
    /// Backend used for writes.
    pub ingest: Arc<I>,
    /// Limits enforced before writes reach the backend.
    pub limits: IngestLimits,
    /// Gates ingest writes only.
    pub ready: Arc<AtomicBool>,
    /// Optional live-stream notifier.
    pub notifier: Option<Arc<dyn StreamNotifier>>,
}

impl<I> Clone for IngestState<I> {
    fn clone(&self) -> Self {
        Self {
            ingest: self.ingest.clone(),
            limits: self.limits,
            ready: self.ready.clone(),
            notifier: self.notifier.clone(),
        }
    }
}

impl<I> IngestState<I>
where
    I: Ingest,
{
    pub fn new(ingest: Arc<I>) -> Self {
        Self {
            ingest,
            limits: IngestLimits::default(),
            ready: Arc::new(AtomicBool::new(true)),
            notifier: None,
        }
    }

    pub fn with_notifier(ingest: Arc<I>, notifier: Arc<dyn StreamNotifier>) -> Self {
        Self {
            ingest,
            limits: IngestLimits::default(),
            ready: Arc::new(AtomicBool::new(true)),
            notifier: Some(notifier),
        }
    }

    pub fn with_limits(mut self, limits: IngestLimits) -> Self {
        self.limits = limits;
        self
    }
}

impl<E> From<AppState<E>> for IngestState<E> {
    fn from(state: AppState<E>) -> Self {
        Self {
            ingest: state.engine,
            limits: state.ingest_limits,
            ready: state.ready,
            notifier: Some(state.stream),
        }
    }
}

/// State for a query-only service.
pub struct QueryState<Q> {
    /// Backend used for point and range reads.
    pub query: Arc<Q>,
}

impl<Q> Clone for QueryState<Q> {
    fn clone(&self) -> Self {
        Self {
            query: self.query.clone(),
        }
    }
}

impl<Q> QueryState<Q>
where
    Q: Query,
{
    pub fn new(query: Arc<Q>) -> Self {
        Self { query }
    }
}

impl<E> From<AppState<E>> for QueryState<E> {
    fn from(state: AppState<E>) -> Self {
        Self {
            query: state.engine,
        }
    }
}

/// State for a prune-only service.
pub struct PruneState<P> {
    /// Backend used for prune requests.
    pub prune: Arc<P>,
}

impl<P> Clone for PruneState<P> {
    fn clone(&self) -> Self {
        Self {
            prune: self.prune.clone(),
        }
    }
}

impl<P> PruneState<P>
where
    P: Prune,
{
    pub fn new(prune: Arc<P>) -> Self {
        Self { prune }
    }
}

impl<E> From<AppState<E>> for PruneState<E> {
    fn from(state: AppState<E>) -> Self {
        Self {
            prune: state.engine,
        }
    }
}

/// State for a retention-only service.
pub struct RetentionState<R> {
    /// Backend that owns the sequence-log retention rule.
    pub retention: Arc<R>,
}

impl<R> Clone for RetentionState<R> {
    fn clone(&self) -> Self {
        Self {
            retention: self.retention.clone(),
        }
    }
}

impl<R> RetentionState<R>
where
    R: Retention,
{
    pub fn new(retention: Arc<R>) -> Self {
        Self { retention }
    }
}

impl<E> From<AppState<E>> for RetentionState<E> {
    fn from(state: AppState<E>) -> Self {
        Self {
            retention: state.engine,
        }
    }
}

/// State for a stream-only service.
pub struct StreamState<L> {
    /// Backend used to load committed batches.
    pub log: Arc<L>,
    /// In-process notifier used to wake subscribers after new batches commit.
    pub notifier: Arc<dyn StreamNotifier>,
}

impl<L> Clone for StreamState<L> {
    fn clone(&self) -> Self {
        Self {
            log: self.log.clone(),
            notifier: self.notifier.clone(),
        }
    }
}

impl<L> StreamState<L>
where
    L: Log,
{
    pub fn new(log: Arc<L>, notifier: Arc<dyn StreamNotifier>) -> Self {
        Self { log, notifier }
    }
}

impl<E> From<AppState<E>> for StreamState<E> {
    fn from(state: AppState<E>) -> Self {
        Self {
            log: state.engine,
            notifier: state.stream,
        }
    }
}

pub struct IngestConnect<I> {
    state: IngestState<I>,
}

impl<I> Clone for IngestConnect<I> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<I> IngestConnect<I>
where
    I: Ingest,
{
    pub fn new(state: impl Into<IngestState<I>>) -> Self {
        Self {
            state: state.into(),
        }
    }
}

/// Backoff floor advertised to `RetryInfo`-aware clients for transient store conditions.
const RETRY_HINT_DELAY: std::time::Duration = std::time::Duration::from_secs(1);
/// `ErrorInfo.reason` when the ingest worker has not passed its readiness gate.
const REASON_WORKER_NOT_READY: &str = "WORKER_NOT_READY";
/// `ErrorInfo.reason` when the backend discovers a transient ingest write failure.
const REASON_INGEST_UNAVAILABLE: &str = "INGEST_UNAVAILABLE";

/// Attaches an explicit retry hint for "come back soon" responses.
fn with_retry_hint(err: ConnectError, retry_delay: std::time::Duration) -> ConnectError {
    with_retry_info_detail(
        err,
        RetryInfo {
            retry_delay: Some(buffa_types::google::protobuf::Duration::from(retry_delay)).into(),
            ..Default::default()
        },
    )
}

fn ingest_error_to_connect(err: IngestError) -> ConnectError {
    match err {
        IngestError::Unavailable { message } => with_retry_hint(
            with_error_info_detail(
                ConnectError::unavailable(message),
                ErrorInfo {
                    reason: REASON_INGEST_UNAVAILABLE.to_string(),
                    domain: crate::validate::INGEST_ERROR_DOMAIN.to_string(),
                    ..Default::default()
                },
            ),
            RETRY_HINT_DELAY,
        ),
        IngestError::Internal { message } => ConnectError::internal(message),
    }
}

impl<I> IngestApi for IngestConnect<I>
where
    I: Ingest,
{
    async fn put(
        &self,
        _ctx: Context,
        request: buffa::view::OwnedView<exoware_proto::log::ingest::v1::PutRequestView<'static>>,
    ) -> connectrpc::ServiceResult<ProtoPutResponse> {
        if !self.state.ready.load(Ordering::SeqCst) {
            return Err(with_retry_hint(
                with_error_info_detail(
                    ConnectError::unavailable("ingest is not ready"),
                    ErrorInfo {
                        reason: REASON_WORKER_NOT_READY.to_string(),
                        domain: crate::validate::INGEST_ERROR_DOMAIN.to_string(),
                        ..Default::default()
                    },
                ),
                RETRY_HINT_DELAY,
            ));
        }

        validate::validate_put_request(&request, self.state.limits)?;

        let wire = request.bytes();
        let mut batch = Vec::with_capacity(request.kvs.len());
        for kv in request.kvs.iter() {
            let key: Key = wire.slice_ref(kv.key);
            let value = wire.slice_ref(kv.value);
            batch.push((key, value));
        }

        let seq = self
            .state
            .ingest
            .put_batch(batch)
            .await
            .map_err(ingest_error_to_connect)?;

        // Advance any attached stream frontier after the write is committed.
        if let Some(notifier) = &self.state.notifier {
            notifier.advance(seq);
        }

        connectrpc::Response::ok(ProtoPutResponse {
            sequence_number: seq,
            ..Default::default()
        })
    }
}

pub struct QueryConnect<Q> {
    state: QueryState<Q>,
}

impl<Q> Clone for QueryConnect<Q> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<Q> QueryConnect<Q>
where
    Q: Query,
{
    pub fn new(state: impl Into<QueryState<Q>>) -> Self {
        Self {
            state: state.into(),
        }
    }

    fn current_sequence_number(&self) -> u64 {
        self.state.query.current_sequence()
    }

    fn error_detail(&self) -> Detail {
        Detail {
            sequence_number: self.current_sequence_number(),
            ..Default::default()
        }
    }

    fn consistency_not_ready_error(&self, required: u64, current: u64) -> ConnectError {
        let err = with_retry_hint(
            ConnectError::aborted("minimum consistency token is not yet visible"),
            RETRY_HINT_DELAY,
        );
        with_query_detail(
            with_error_info_detail(
                err,
                ErrorInfo {
                    reason: "CONSISTENCY_NOT_READY".to_string(),
                    domain: "store.query".to_string(),
                    metadata: [
                        ("required_sequence_number".to_string(), required.to_string()),
                        ("current_sequence_number".to_string(), current.to_string()),
                    ]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                },
            ),
            self.error_detail(),
        )
    }

    fn ensure_min_sequence_number(&self, required: Option<u64>) -> Result<u64, ConnectError> {
        let current = self.current_sequence_number();
        if let Some(required) = required {
            if current < required {
                return Err(self.consistency_not_ready_error(required, current));
            }
        }
        Ok(current)
    }
}

impl<Q> QueryApi for QueryConnect<Q>
where
    Q: Query,
{
    async fn get(
        &self,
        _ctx: Context,
        request: buffa::view::OwnedView<exoware_proto::store::query::v1::GetRequestView<'static>>,
    ) -> connectrpc::ServiceResult<GetResponse> {
        validate::validate_get_request(&request)?;
        let token = self.ensure_min_sequence_number(request.min_sequence_number)?;
        let wire = request.bytes();
        let key: Key = wire.slice_ref(request.key);
        let (value, extra) = self
            .state
            .query
            .get(key)
            .await
            .map_err(ConnectError::internal)?;
        let detail = query_detail(token, extra);
        connectrpc::Response::ok(GetResponse {
            value,
            detail: Some(detail).into(),
            ..Default::default()
        })
    }

    async fn get_many(
        &self,
        _ctx: Context,
        request: buffa::view::OwnedView<
            exoware_proto::store::query::v1::GetManyRequestView<'static>,
        >,
    ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<GetManyFrame>> {
        validate::validate_get_many_request(&request)?;
        let sequence_number = self.ensure_min_sequence_number(request.min_sequence_number)?;

        let wire = request.bytes();
        let keys: Vec<Key> = request.keys.iter().map(|key| wire.slice_ref(key)).collect();
        let (entries, extra) = self
            .state
            .query
            .get_many(keys)
            .await
            .map_err(ConnectError::internal)?;
        let detail = query_detail(sequence_number, extra);
        let batch_size = (request.batch_size as usize).min(RANGE_STREAM_MAX_FRAME_ROWS);
        let mut frames = Vec::new();
        let mut chunk = Vec::new();
        for (key, value) in entries {
            chunk.push(GetManyEntry {
                key: key.to_vec(),
                value,
                ..Default::default()
            });
            if chunk.len() >= batch_size {
                frames.push(Ok(GetManyFrame {
                    results: std::mem::take(&mut chunk),
                    detail: Some(detail.clone()).into(),
                    ..Default::default()
                }));
            }
        }
        if !chunk.is_empty() {
            frames.push(Ok(GetManyFrame {
                results: chunk,
                detail: Some(detail).into(),
                ..Default::default()
            }));
        } else if frames.is_empty() {
            frames.push(Ok(GetManyFrame {
                detail: Some(detail).into(),
                ..Default::default()
            }));
        }

        Ok(connectrpc::Response::stream(stream_util::iter(frames)))
    }

    async fn range(
        &self,
        _ctx: Context,
        request: buffa::view::OwnedView<exoware_proto::store::query::v1::RangeRequestView<'static>>,
    ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<RangeFrame>> {
        validate::validate_range_request(&request)?;
        let sequence_number = self.ensure_min_sequence_number(request.min_sequence_number)?;
        let wire = request.bytes();
        let start_key: Key = wire.slice_ref(request.start);
        let end_key: Key = wire.slice_ref(request.end);
        let limit = request.limit.map(|v| v as usize).unwrap_or(usize::MAX);
        let batch_size = (request.batch_size as usize).min(RANGE_STREAM_MAX_FRAME_ROWS);
        let forward = match parse_range_traversal_direction(request.mode) {
            Ok(RangeTraversalDirection::Forward) => true,
            Ok(RangeTraversalDirection::Reverse) => false,
            Err(e) => return Err(ConnectError::internal(format!("traversal mode: {e:?}"))),
        };
        Ok(connectrpc::Response::stream(
            range_stream(
                self.state.query.clone(),
                RangeStreamRequest {
                    start_key,
                    end_key,
                    limit,
                    batch_size,
                    forward,
                    sequence_number,
                },
            )
            .await?,
        ))
    }

    async fn reduce(
        &self,
        _ctx: Context,
        request: buffa::view::OwnedView<
            exoware_proto::store::query::v1::ReduceRequestView<'static>,
        >,
    ) -> connectrpc::ServiceResult<ReduceResponse> {
        validate::validate_reduce_request(&request)?;
        let token = self.ensure_min_sequence_number(request.min_sequence_number)?;
        let wire = request.bytes();
        let start_key: Key = wire.slice_ref(request.start);
        let end_key: Key = wire.slice_ref(request.end);
        let domain = to_domain_reduce_request_from_view(&request.params)
            .map_err(validate::reduce_params_error)?;

        let mut rows = self
            .state
            .query
            .range_scan(start_key, end_key, usize::MAX, true)
            .await
            .map_err(ConnectError::internal)?;

        let mut reducer = RangeReducer::new(&domain)
            .map_err(|e: crate::RangeError| ConnectError::internal(e.to_string()))?;
        let mut latest_extra = None;
        let final_extra = loop {
            let batch = rows
                .next_batch(REDUCE_SCAN_BATCH_SIZE)
                .await
                .map_err(ConnectError::internal)?;
            if batch.rows.is_empty() {
                break if batch.extra.is_empty() {
                    latest_extra.unwrap_or_default()
                } else {
                    batch.extra
                };
            }
            latest_extra = Some(batch.extra);
            for (key, value) in batch.rows {
                reducer
                    .update(&key, &value)
                    .map_err(|e: crate::RangeError| ConnectError::internal(e.to_string()))?;
            }
        };
        let response = reducer.finish();

        let detail = query_detail(token, final_extra);

        connectrpc::Response::ok(ReduceResponse {
            results: response
                .results
                .into_iter()
                .map(|result| exoware_proto::query::RangeReduceResult {
                    value: result.value.map(to_proto_reduced_value).into(),
                    ..Default::default()
                })
                .collect(),
            groups: response
                .groups
                .into_iter()
                .map(|group| {
                    let group_values_present =
                        group.group_values.iter().map(Option::is_some).collect();
                    exoware_proto::query::RangeReduceGroup {
                        group_values: group
                            .group_values
                            .into_iter()
                            .map(to_proto_optional_reduced_value)
                            .collect(),
                        group_values_present,
                        results: group
                            .results
                            .into_iter()
                            .map(|result| exoware_proto::query::RangeReduceResult {
                                value: result.value.map(to_proto_reduced_value).into(),
                                ..Default::default()
                            })
                            .collect(),
                        ..Default::default()
                    }
                })
                .collect(),
            detail: Some(detail).into(),
            ..Default::default()
        })
    }
}

pub struct PruneConnect<P> {
    state: PruneState<P>,
}

impl<P> Clone for PruneConnect<P> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<P> PruneConnect<P>
where
    P: Prune,
{
    pub fn new(state: impl Into<PruneState<P>>) -> Self {
        Self {
            state: state.into(),
        }
    }
}

impl<P> PruneApi for PruneConnect<P>
where
    P: Prune,
{
    async fn prune(
        &self,
        _ctx: Context,
        request: buffa::view::OwnedView<exoware_proto::store::prune::v1::PruneRequestView<'static>>,
    ) -> connectrpc::ServiceResult<PruneResponse> {
        validate::validate_prune_request(&request)?;
        let document = exoware_proto::parse_and_validate_policy_document(&request)
            .map_err(|e| ConnectError::invalid_argument(e.to_string()))?;

        self.state
            .prune
            .apply_prune_policies(document)
            .await
            .map_err(ConnectError::internal)?;
        connectrpc::Response::ok(PruneResponse::default())
    }
}

pub struct StreamConnect<B> {
    state: StreamState<B>,
}

impl<B> Clone for StreamConnect<B> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<B> StreamConnect<B>
where
    B: Log,
{
    pub fn new(state: impl Into<StreamState<B>>) -> Self {
        Self {
            state: state.into(),
        }
    }

    fn batch_evicted_connect_error(oldest_retained: Option<u64>) -> ConnectError {
        let mut metadata = HashMap::new();
        if let Some(v) = oldest_retained {
            metadata.insert(
                crate::stream::METADATA_OLDEST_RETAINED.to_string(),
                v.to_string(),
            );
        }
        with_error_info_detail(
            ConnectError::out_of_range("batch has been evicted from the log"),
            ErrorInfo {
                reason: crate::stream::REASON_BATCH_EVICTED.to_string(),
                domain: crate::stream::STREAM_ERROR_DOMAIN.to_string(),
                metadata,
                ..Default::default()
            },
        )
    }

    fn batch_evicted_error(&self, oldest_retained: Option<u64>) -> ConnectError {
        Self::batch_evicted_connect_error(oldest_retained)
    }

    fn batch_not_found_error(&self) -> ConnectError {
        with_error_info_detail(
            ConnectError::not_found("batch not found"),
            ErrorInfo {
                reason: crate::stream::REASON_BATCH_NOT_FOUND.to_string(),
                domain: crate::stream::STREAM_ERROR_DOMAIN.to_string(),
                ..Default::default()
            },
        )
    }
}

fn filtered_subscribe_response(
    batch: &LogBatch,
    matchers: &crate::stream::CompiledMatchers,
) -> Result<Option<SubscribeResponse>, ConnectError> {
    let response = batch.decode_response().map_err(ConnectError::internal)?;
    let entries = crate::stream::apply_filter(matchers, &response.entries);
    Ok((!entries.is_empty()).then_some(SubscribeResponse {
        sequence_number: batch.sequence_number(),
        entries,
        ..Default::default()
    }))
}

type OrderedBatchStream = Pin<Box<dyn Stream<Item = Result<Option<LogBatch>, String>> + Send>>;

fn ordered_batch_stream<B, S>(
    log: Arc<B>,
    sequences: S,
    mut first_batch: Option<LogBatch>,
) -> OrderedBatchStream
where
    B: Log,
    S: Stream<Item = u64> + Send + 'static,
{
    Box::pin(
        sequences
            .map(move |sequence_number| {
                let log = log.clone();
                // The sequence stream is consumed in order, so only the first
                // closure invocation observes the eagerly fetched batch and it
                // pairs with the first sequence.
                let first_batch = first_batch.take();
                async move {
                    match first_batch {
                        Some(batch) => Ok(Some(batch)),
                        None => log.get_batch(sequence_number).await,
                    }
                }
            })
            .buffered(SUBSCRIBE_GET_BATCH_LOOKAHEAD),
    )
}

// Live sequences are generated on demand and re-check the published frontier
// on every pull. The lookahead therefore keeps extending through new commits
// while earlier reads drain, instead of stopping at a frontier snapshot. When
// the subscriber is caught up the next pull parks on a publish notification,
// which keeps one live stream serving the whole subscription.
fn live_sequence_stream(
    notifier: Arc<dyn StreamNotifier>,
    notify: Arc<Notify>,
    start: Option<u64>,
) -> impl Stream<Item = u64> + Send {
    stream_util::unfold(start, move |next| {
        let notifier = notifier.clone();
        let notify = notify.clone();
        async move {
            let sequence_number = next?;
            // Re-check the frontier after arming the notifier so a publish
            // racing this pull is not lost.
            while sequence_number > notifier.current_sequence() {
                let notified = notify.clone().notified_owned();
                if sequence_number <= notifier.current_sequence() {
                    break;
                }
                notified.await;
            }
            Some((sequence_number, sequence_number.checked_add(1)))
        }
    })
}

struct ReplayState {
    batches: OrderedBatchStream,
}

enum ReplayProgress {
    Frame(SubscribeResponse),
    Advanced,
    Done,
}

struct SubscriptionState<B> {
    state: StreamState<B>,
    matchers: crate::stream::CompiledMatchers,
    // Both streams are dropped at termination so buffered batches free at the
    // failure boundary instead of when the client tears the stream down.
    replay: Option<ReplayState>,
    live: Option<OrderedBatchStream>,
    terminated: bool,
}

impl<B> SubscriptionState<B>
where
    B: Log,
{
    fn new(
        state: StreamState<B>,
        matchers: crate::stream::CompiledMatchers,
        replay: Option<ReplayState>,
        live: OrderedBatchStream,
    ) -> Self {
        Self {
            state,
            matchers,
            replay,
            live: Some(live),
            terminated: false,
        }
    }

    fn into_stream(
        self,
    ) -> Pin<Box<dyn Stream<Item = Result<SubscribeResponse, ConnectError>> + Send>> {
        Box::pin(stream_util::unfold(self, |mut state| async move {
            loop {
                if state.terminated {
                    return None;
                }

                if state.replay.is_some() {
                    match state.next_replay_frame().await {
                        Ok(ReplayProgress::Frame(frame)) => return Some((Ok(frame), state)),
                        Ok(ReplayProgress::Advanced) => continue,
                        Ok(ReplayProgress::Done) => {}
                        Err(err) => return Some((state.terminate(err), state)),
                    }
                }

                // The live sequence source only ends past u64::MAX, so an
                // exhausted live stream ends the subscription.
                let batch = state.live.as_mut()?.next().await?;
                match state.resolve_batch(batch).await {
                    Ok(Some(frame)) => return Some((Ok(frame), state)),
                    Ok(None) => continue,
                    Err(err) => return Some((state.terminate(err), state)),
                }
            }
        }))
    }

    fn terminate(&mut self, err: ConnectError) -> Result<SubscribeResponse, ConnectError> {
        self.terminated = true;
        self.replay = None;
        self.live = None;
        Err(err)
    }

    async fn next_replay_frame(&mut self) -> Result<ReplayProgress, ConnectError> {
        let Some(replay) = &mut self.replay else {
            return Ok(ReplayProgress::Done);
        };
        let Some(batch) = replay.batches.next().await else {
            self.replay = None;
            return Ok(ReplayProgress::Done);
        };
        Ok(match self.resolve_batch(batch).await? {
            Some(frame) => ReplayProgress::Frame(frame),
            None => ReplayProgress::Advanced,
        })
    }

    async fn resolve_batch(
        &mut self,
        batch: Result<Option<LogBatch>, String>,
    ) -> Result<Option<SubscribeResponse>, ConnectError> {
        let batch = batch.map_err(ConnectError::internal)?;
        let Some(batch) = batch else {
            let oldest = self
                .state
                .log
                .oldest_retained_batch()
                .await
                .map_err(ConnectError::internal)?;
            return Err(StreamConnect::<B>::batch_evicted_connect_error(oldest));
        };
        filtered_subscribe_response(&batch, &self.matchers)
    }
}

fn domain_filter_from_subscribe_view(
    req: &SubscribeRequestView<'_>,
) -> Result<StreamFilter, ConnectError> {
    let mut selectors = Vec::with_capacity(req.selectors.len());
    for mk in req.selectors.iter() {
        // Prefix length is validated when compile_matchers runs the shared
        // stream_filter::validate_filter over the assembled filter.
        selectors.push(Selector {
            prefix: Bytes::copy_from_slice(mk.prefix),
            payload_regex: exoware_sdk::kv_codec::Utf8::from(mk.payload_regex),
        });
    }
    let mut value_filters = Vec::with_capacity(req.value_filters.len());
    for vf in req.value_filters.iter() {
        value_filters.push(match vf.kind {
            Some(ProtoFilterKindView::Exact(bytes)) => Filter::Exact(Bytes::copy_from_slice(bytes)),
            Some(ProtoFilterKindView::Prefix(bytes)) => {
                Filter::Prefix(Bytes::copy_from_slice(bytes))
            }
            Some(ProtoFilterKindView::Regex(pattern)) => Filter::Regex(pattern.to_string()),
            None => {
                return Err(ConnectError::invalid_argument(
                    "each value_filter must set exactly one of exact, prefix, or regex",
                ))
            }
        });
    }
    Ok(StreamFilter {
        selectors,
        value_filters,
    })
}

impl<B> StreamApi for StreamConnect<B>
where
    B: Log,
{
    async fn subscribe(
        &self,
        _ctx: Context,
        request: buffa::view::OwnedView<SubscribeRequestView<'static>>,
    ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<SubscribeResponse>> {
        let filter = domain_filter_from_subscribe_view(&request)?;
        let since = request.since_sequence_number;

        // Snapshot the published frontier to bound replay and subscribe for
        // live wakeups. Bounded lookahead overlaps log reads while retaining
        // client-driven backpressure.
        let matchers = crate::stream::compile_matchers(&filter)?;
        let subscription = self.state.notifier.subscribe();
        let replay_bound = subscription.current_sequence;
        let live_notify = subscription.notify;

        // Optional replay. Validate the starting batch eagerly so an
        // already-evicted cursor fails the RPC immediately; later replay holes
        // are surfaced on the stream itself so callers reconnect from a safe
        // point instead of silently continuing.
        let replay = match since {
            Some(s) if s <= replay_bound && s > 0 => {
                let first_batch = self
                    .state
                    .log
                    .get_batch(s)
                    .await
                    .map_err(ConnectError::internal)?;
                let Some(first_batch) = first_batch else {
                    let oldest = self
                        .state
                        .log
                        .oldest_retained_batch()
                        .await
                        .map_err(ConnectError::internal)?;
                    return Err(self.batch_evicted_error(oldest));
                };
                Some(ReplayState {
                    batches: ordered_batch_stream(
                        self.state.log.clone(),
                        stream_util::iter(s..=replay_bound),
                        Some(first_batch),
                    ),
                })
            }
            _ => None,
        };
        let live = ordered_batch_stream(
            self.state.log.clone(),
            live_sequence_stream(
                self.state.notifier.clone(),
                live_notify,
                replay_bound.checked_add(1),
            ),
            None,
        );

        Ok(connectrpc::Response::stream(
            SubscriptionState::new(self.state.clone(), matchers, replay, live).into_stream(),
        ))
    }

    async fn get(
        &self,
        _ctx: Context,
        request: buffa::view::OwnedView<GetRequestView<'static>>,
    ) -> connectrpc::ServiceResult<PreEncoded<StreamGetResponse>> {
        let seq = request.sequence_number;
        match self
            .state
            .log
            .get_batch(seq)
            .await
            .map_err(ConnectError::internal)?
        {
            Some(batch) => connectrpc::Response::ok(PreEncoded::from_bytes_unchecked(
                batch.into_response_bytes(),
            )),
            None => {
                let current = self.state.log.current_sequence();
                // Distinguish "never existed" (seq > current) vs "evicted".
                if seq > current {
                    Err(self.batch_not_found_error())
                } else {
                    let oldest = self
                        .state
                        .log
                        .oldest_retained_batch()
                        .await
                        .map_err(ConnectError::internal)?;
                    Err(self.batch_evicted_error(oldest))
                }
            }
        }
    }
}

pub struct RetentionConnect<R> {
    state: RetentionState<R>,
}

impl<R> Clone for RetentionConnect<R> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<R> RetentionConnect<R>
where
    R: Retention,
{
    pub fn new(state: impl Into<RetentionState<R>>) -> Self {
        Self {
            state: state.into(),
        }
    }
}

impl<R> RetentionApi for RetentionConnect<R>
where
    R: Retention,
{
    async fn set_retention(
        &self,
        _ctx: Context,
        request: buffa::view::OwnedView<SetRetentionRequestView<'static>>,
    ) -> connectrpc::ServiceResult<SetRetentionResponse> {
        // Parse the wire shape, then authoritatively validate: buf.validate
        // annotations on the proto are documentation, so the handler enforces
        // the rule (e.g. keep_latest count > 0), mirroring the Prune handler.
        let policy = exoware_proto::parse_set_retention_request_view(&request)
            .map_err(ConnectError::invalid_argument)?;
        if let Some(policy) = policy.as_ref() {
            exoware_proto::validate_retention_policy(policy)
                .map_err(ConnectError::invalid_argument)?;
        }

        let oldest_retained_sequence = self
            .state
            .retention
            .set_retention(policy)
            .await
            .map_err(ConnectError::internal)?;
        connectrpc::Response::ok(SetRetentionResponse {
            oldest_retained_sequence,
            ..Default::default()
        })
    }
}

fn connect_limits() -> Limits {
    Limits::default()
        .max_request_body_size(MAX_CONNECTRPC_BODY_BYTES)
        .max_message_size(MAX_CONNECTRPC_BODY_BYTES)
}

pub(crate) type IngestService<I> = ConnectRpcService<IngestServiceServer<IngestConnect<I>>>;
pub(crate) type QueryService<Q> = ConnectRpcService<QueryServiceServer<QueryConnect<Q>>>;
pub(crate) type PruneService<P> = ConnectRpcService<PruneServiceServer<PruneConnect<P>>>;
pub(crate) type RetentionService<R> =
    ConnectRpcService<RetentionServiceServer<RetentionConnect<R>>>;
pub(crate) type StreamService<B> = ConnectRpcService<StreamServiceServer<StreamConnect<B>>>;
pub(crate) type QueryStack<Q, B> = ConnectRpcService<
    Chain<QueryServiceServer<QueryConnect<Q>>, StreamServiceServer<StreamConnect<B>>>,
>;
pub(crate) type ConnectStack<I, Q, P, R, B> = ConnectRpcService<
    Chain<
        IngestServiceServer<IngestConnect<I>>,
        Chain<
            QueryServiceServer<QueryConnect<Q>>,
            Chain<
                PruneServiceServer<PruneConnect<P>>,
                Chain<
                    RetentionServiceServer<RetentionConnect<R>>,
                    StreamServiceServer<StreamConnect<B>>,
                >,
            >,
        >,
    >,
>;

fn ingest_server<I>(state: IngestState<I>) -> IngestServiceServer<IngestConnect<I>>
where
    I: Ingest,
{
    IngestServiceServer::new(IngestConnect::new(state))
}

fn query_server<Q>(state: QueryState<Q>) -> QueryServiceServer<QueryConnect<Q>>
where
    Q: Query,
{
    QueryServiceServer::new(QueryConnect::new(state))
}

fn prune_server<P>(state: PruneState<P>) -> PruneServiceServer<PruneConnect<P>>
where
    P: Prune,
{
    PruneServiceServer::new(PruneConnect::new(state))
}

fn retention_server<R>(state: RetentionState<R>) -> RetentionServiceServer<RetentionConnect<R>>
where
    R: Retention,
{
    RetentionServiceServer::new(RetentionConnect::new(state))
}

fn stream_server<B>(state: StreamState<B>) -> StreamServiceServer<StreamConnect<B>>
where
    B: Log,
{
    StreamServiceServer::new(StreamConnect::new(state))
}

pub fn ingest_service<I>(state: IngestState<I>) -> IngestService<I>
where
    I: Ingest,
{
    ConnectRpcService::new(ingest_server(state))
        .with_limits(connect_limits())
        .with_compression(connect_compression_registry())
}

pub fn query_service<Q>(state: QueryState<Q>) -> QueryService<Q>
where
    Q: Query,
{
    ConnectRpcService::new(query_server(state))
        .with_limits(connect_limits())
        .with_compression(connect_compression_registry())
}

pub fn prune_service<P>(state: PruneState<P>) -> PruneService<P>
where
    P: Prune,
{
    ConnectRpcService::new(prune_server(state))
        .with_limits(connect_limits())
        .with_compression(connect_compression_registry())
}

pub fn retention_service<R>(state: RetentionState<R>) -> RetentionService<R>
where
    R: Retention,
{
    ConnectRpcService::new(retention_server(state))
        .with_limits(connect_limits())
        .with_compression(connect_compression_registry())
}

pub fn stream_service<B>(state: StreamState<B>) -> StreamService<B>
where
    B: Log,
{
    ConnectRpcService::new(stream_server(state))
        .with_limits(connect_limits())
        .with_compression(connect_compression_registry())
}

pub fn query_stack<Q, B>(
    query_state: QueryState<Q>,
    stream_state: StreamState<B>,
) -> QueryStack<Q, B>
where
    Q: Query,
    B: Log,
{
    ConnectRpcService::new(Chain(
        query_server(query_state),
        stream_server(stream_state),
    ))
    .with_limits(connect_limits())
    .with_compression(connect_compression_registry())
}

pub fn connect_stack<E>(state: AppState<E>) -> ConnectStack<E, E, E, E, E>
where
    E: StoreEngine,
{
    ConnectRpcService::new(Chain(
        ingest_server(state.clone().into()),
        Chain(
            query_server(state.clone().into()),
            Chain(
                prune_server(state.clone().into()),
                Chain(
                    retention_server(state.clone().into()),
                    stream_server(state.into()),
                ),
            ),
        ),
    ))
    .with_limits(connect_limits())
    .with_compression(connect_compression_registry())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::atomic::{AtomicU64, AtomicUsize};
    use std::sync::Mutex;
    use std::time::Duration;

    use buffa::Message;
    use exoware_proto::common::kv::v1::Selector as ProtoSelector;
    use exoware_proto::log::retention::v1::SetRetentionRequest;
    use exoware_proto::log::stream::v1::{SubscribeRequest, SubscribeRequestView};
    use exoware_proto::store::prune::v1::{
        policy_retain, KeysScope, Policy as ProtoPolicy, PolicyRetain, PruneRequest,
        PruneRequestView, RetainKeepLatest,
    };
    use exoware_sdk::keys::Prefix;
    use exoware_sdk::kv_codec::KvReducedValue;
    use exoware_sdk::prune_policy::{PrunePolicyDocument, PRUNE_POLICY_DOCUMENT_VERSION};
    use exoware_sdk::retention::RetentionPolicy;
    use exoware_sdk::{decode_connect_error, to_domain_reduce_response};
    use futures::StreamExt;

    use crate::{
        Ingest, IngestError, Log, Prune, Query, QueryExtra, RangeScan, RangeScanBatch, Retention,
        Sequence, StreamNotification, StreamNotifier,
    };

    const TEST_PREFIX: u8 = 1;

    #[derive(Clone)]
    struct PublishDuringReplay {
        hub: Arc<StreamHub>,
        sequence_offset: u64,
        kvs: Vec<(Bytes, Bytes)>,
    }

    #[derive(Default)]
    struct FakeEngineState {
        current_sequence: u64,
        batches: BTreeMap<u64, Option<Vec<(Bytes, Bytes)>>>,
        oldest_retained: Option<u64>,
        publish_on_get_batch: Option<PublishDuringReplay>,
        range_rows: Vec<(Bytes, Bytes)>,
        range_eof_extra: QueryExtra,
        range_next_count: usize,
        query_extra: QueryExtra,
        prune_policy_counts: Vec<usize>,
        put_error: Option<IngestError>,
        retention_calls: Vec<Option<RetentionPolicy>>,
        retention_floor: Option<u64>,
    }

    #[derive(Default)]
    struct FakeEngine {
        state: Arc<Mutex<FakeEngineState>>,
    }

    struct IteratorRangeScan {
        iter: Box<dyn Iterator<Item = Result<(Bytes, Bytes), String>> + Send + 'static>,
        eof_extra: Option<QueryExtra>,
    }

    impl RangeScan for IteratorRangeScan {
        async fn next_batch(&mut self, max_items: usize) -> Result<RangeScanBatch, String> {
            let mut rows = Vec::new();
            for row in self.iter.by_ref().take(max_items) {
                rows.push(row?);
            }
            let extra = if rows.is_empty() {
                self.eof_extra.take().unwrap_or_default()
            } else {
                QueryExtra::default()
            };
            Ok(RangeScanBatch { rows, extra })
        }
    }

    fn range_scan_from_iter<I>(iter: I) -> IteratorRangeScan
    where
        I: Iterator<Item = Result<(Bytes, Bytes), String>> + Send + 'static,
    {
        range_scan_from_iter_with_eof_extra(iter, QueryExtra::default())
    }

    fn range_scan_from_iter_with_eof_extra<I>(iter: I, eof_extra: QueryExtra) -> IteratorRangeScan
    where
        I: Iterator<Item = Result<(Bytes, Bytes), String>> + Send + 'static,
    {
        IteratorRangeScan {
            iter: Box::new(iter),
            eof_extra: Some(eof_extra),
        }
    }

    impl FakeEngine {
        fn set_current_sequence(&self, sequence_number: u64) {
            self.state.lock().expect("lock").current_sequence = sequence_number;
        }

        fn set_put_error(&self, err: IngestError) {
            self.state.lock().expect("lock").put_error = Some(err);
        }

        fn set_batch(&self, sequence_number: u64, kvs: Option<Vec<(Bytes, Bytes)>>) {
            self.state
                .lock()
                .expect("lock")
                .batches
                .insert(sequence_number, kvs);
        }

        fn set_oldest_retained(&self, oldest_retained: Option<u64>) {
            self.state.lock().expect("lock").oldest_retained = oldest_retained;
        }

        fn publish_live(
            &self,
            hub: Arc<StreamHub>,
            sequence_number: u64,
            kvs: Vec<(Bytes, Bytes)>,
        ) {
            let mut state = self.state.lock().expect("lock");
            state.current_sequence = state.current_sequence.max(sequence_number);
            state.batches.insert(sequence_number, Some(kvs.clone()));
            drop(state);
            hub.publish(sequence_number);
        }

        fn publish_on_every_get_batch(
            &self,
            hub: Arc<StreamHub>,
            sequence_offset: u64,
            kvs: Vec<(Bytes, Bytes)>,
        ) {
            self.state.lock().expect("lock").publish_on_get_batch = Some(PublishDuringReplay {
                hub,
                sequence_offset,
                kvs,
            });
        }

        fn set_range_rows(&self, rows: Vec<(Bytes, Bytes)>) {
            self.state.lock().expect("lock").range_rows = rows;
        }

        fn set_range_eof_extra(&self, extra: QueryExtra) {
            self.state.lock().expect("lock").range_eof_extra = extra;
        }

        fn range_next_count(&self) -> usize {
            self.state.lock().expect("lock").range_next_count
        }

        fn set_query_extra(&self, extra: QueryExtra) {
            self.state.lock().expect("lock").query_extra = extra;
        }

        fn set_retention_floor(&self, floor: Option<u64>) {
            self.state.lock().expect("lock").retention_floor = floor;
        }

        fn retention_calls(&self) -> Vec<Option<RetentionPolicy>> {
            self.state.lock().expect("lock").retention_calls.clone()
        }
    }

    impl Sequence for FakeEngine {
        fn current_sequence(&self) -> u64 {
            self.state.lock().expect("lock").current_sequence
        }
    }

    impl Ingest for FakeEngine {
        async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, IngestError> {
            let mut state = self.state.lock().map_err(|e| IngestError::Internal {
                message: e.to_string(),
            })?;
            if let Some(err) = state.put_error.take() {
                return Err(err);
            }
            state.current_sequence += 1;
            let seq = state.current_sequence;
            state.batches.insert(seq, Some(kvs));
            Ok(seq)
        }
    }

    impl Query for FakeEngine {
        type RangeScan = IteratorRangeScan;

        async fn get(&self, _key: Bytes) -> Result<(Option<Bytes>, QueryExtra), String> {
            self.state
                .lock()
                .map(|state| (None, state.query_extra.clone()))
                .map_err(|e| e.to_string())
        }

        async fn get_many(
            &self,
            keys: Vec<Bytes>,
        ) -> Result<(Vec<(Bytes, Option<Bytes>)>, QueryExtra), String> {
            self.state
                .lock()
                .map(|state| {
                    let entries = keys.into_iter().map(|key| (key, None)).collect();
                    (entries, state.query_extra.clone())
                })
                .map_err(|e| e.to_string())
        }

        async fn range_scan(
            &self,
            _start: Bytes,
            _end: Bytes,
            _limit: usize,
            _forward: bool,
        ) -> Result<Self::RangeScan, String> {
            let result = self
                .state
                .lock()
                .map(|state| (state.range_rows.clone(), state.range_eof_extra.clone()))
                .map_err(|e| e.to_string());
            let state = self.state.clone();
            let cursor = result.map(|(rows, eof_extra)| {
                range_scan_from_iter_with_eof_extra(
                    rows.into_iter().map(move |row| {
                        state.lock().expect("lock").range_next_count += 1;
                        Ok(row)
                    }),
                    eof_extra,
                )
            });
            cursor
        }
    }

    impl Prune for FakeEngine {
        async fn apply_prune_policies(&self, document: PrunePolicyDocument) -> Result<(), String> {
            self.state
                .lock()
                .map(|mut state| {
                    state.prune_policy_counts.push(document.policies.len());
                })
                .map_err(|e| e.to_string())
        }
    }

    impl Log for FakeEngine {
        async fn get_batch(&self, sequence_number: u64) -> Result<Option<LogBatch>, String> {
            let result: Result<_, String> = (|| {
                let mut state = self.state.lock().map_err(|e| e.to_string())?;
                let publish = state.publish_on_get_batch.clone();
                if let Some(publish) = publish.as_ref() {
                    let live_sequence = publish.sequence_offset + sequence_number;
                    state.current_sequence = state.current_sequence.max(live_sequence);
                    state
                        .batches
                        .entry(live_sequence)
                        .or_insert_with(|| Some(publish.kvs.clone()));
                }
                Ok((
                    publish,
                    state.batches.get(&sequence_number).cloned().unwrap_or(None),
                ))
            })();
            let (publish, batch) = result?;
            if let Some(publish) = publish {
                publish
                    .hub
                    .publish(publish.sequence_offset + sequence_number);
            }
            Ok(batch.map(|kvs| LogBatch::from_entries(sequence_number, kvs)))
        }

        async fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
            self.state
                .lock()
                .map(|state| state.oldest_retained)
                .map_err(|e| e.to_string())
        }
    }

    impl Retention for FakeEngine {
        async fn set_retention(
            &self,
            policy: Option<RetentionPolicy>,
        ) -> Result<Option<u64>, String> {
            self.state
                .lock()
                .map(|mut state| {
                    state.retention_calls.push(policy);
                    state.retention_floor
                })
                .map_err(|e| e.to_string())
        }
    }

    #[derive(Default)]
    struct BatchGate {
        released: AtomicBool,
        waits: AtomicUsize,
        notify: Notify,
    }

    impl BatchGate {
        async fn wait(&self) {
            loop {
                if self.released.load(Ordering::Acquire) {
                    return;
                }
                let notified = self.notify.notified();
                self.waits.fetch_add(1, Ordering::Release);
                if self.released.load(Ordering::Acquire) {
                    return;
                }
                notified.await;
            }
        }

        fn release(&self) {
            self.released.store(true, Ordering::Release);
            self.notify.notify_waiters();
        }

        fn wake(&self) {
            self.notify.notify_waiters();
        }

        fn wait_count(&self) -> usize {
            self.waits.load(Ordering::Acquire)
        }
    }

    #[derive(Default)]
    struct GatedLogState {
        batches: BTreeMap<u64, Vec<(Bytes, Bytes)>>,
        errors: HashMap<u64, String>,
        gates: HashMap<u64, Arc<BatchGate>>,
        started_sequences: Vec<u64>,
        get_counts: HashMap<u64, usize>,
        in_flight: usize,
        max_in_flight: usize,
    }

    #[derive(Default)]
    struct GatedLog {
        current_sequence: AtomicU64,
        state: Arc<Mutex<GatedLogState>>,
        started: Arc<Notify>,
    }

    impl GatedLog {
        fn set_batch(&self, sequence_number: u64, kvs: Vec<(Bytes, Bytes)>) {
            self.current_sequence
                .fetch_max(sequence_number, Ordering::Release);
            self.state
                .lock()
                .expect("lock")
                .batches
                .insert(sequence_number, kvs);
        }

        fn gate(&self, sequence_number: u64) {
            self.state
                .lock()
                .expect("lock")
                .gates
                .insert(sequence_number, Arc::new(BatchGate::default()));
        }

        fn set_error(&self, sequence_number: u64, error: impl Into<String>) {
            self.state
                .lock()
                .expect("lock")
                .errors
                .insert(sequence_number, error.into());
        }

        fn release(&self, sequence_number: u64) {
            self.state
                .lock()
                .expect("lock")
                .gates
                .get(&sequence_number)
                .expect("gate")
                .release();
        }

        fn wake(&self, sequence_number: u64) {
            self.state
                .lock()
                .expect("lock")
                .gates
                .get(&sequence_number)
                .expect("gate")
                .wake();
        }

        fn gate_wait_count(&self, sequence_number: u64) -> usize {
            self.state
                .lock()
                .expect("lock")
                .gates
                .get(&sequence_number)
                .expect("gate")
                .wait_count()
        }

        fn started_sequences(&self) -> Vec<u64> {
            self.state.lock().expect("lock").started_sequences.clone()
        }

        fn get_count(&self, sequence_number: u64) -> usize {
            self.state
                .lock()
                .expect("lock")
                .get_counts
                .get(&sequence_number)
                .copied()
                .unwrap_or_default()
        }

        fn in_flight(&self) -> usize {
            self.state.lock().expect("lock").in_flight
        }

        fn max_in_flight(&self) -> usize {
            self.state.lock().expect("lock").max_in_flight
        }

        async fn wait_for_started(&self, count: usize) {
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if self.started_sequences().len() >= count {
                        return;
                    }
                    let notified = self.started.notified();
                    if self.started_sequences().len() >= count {
                        return;
                    }
                    notified.await;
                }
            })
            .await
            .expect("batch reads should start");
        }

        async fn wait_for_gate_waits(&self, sequence_number: u64, count: usize) {
            tokio::time::timeout(Duration::from_secs(1), async {
                while self.gate_wait_count(sequence_number) < count {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("batch gate should be polled");
        }
    }

    struct InFlightGuard {
        state: Arc<Mutex<GatedLogState>>,
    }

    impl Drop for InFlightGuard {
        fn drop(&mut self) {
            self.state.lock().expect("lock").in_flight -= 1;
        }
    }

    impl Sequence for GatedLog {
        fn current_sequence(&self) -> u64 {
            self.current_sequence.load(Ordering::Acquire)
        }
    }

    impl Log for GatedLog {
        async fn get_batch(&self, sequence_number: u64) -> Result<Option<LogBatch>, String> {
            let (gate, batch, error) = {
                let mut state = self.state.lock().map_err(|err| err.to_string())?;
                state.started_sequences.push(sequence_number);
                *state.get_counts.entry(sequence_number).or_default() += 1;
                state.in_flight += 1;
                state.max_in_flight = state.max_in_flight.max(state.in_flight);
                (
                    state.gates.get(&sequence_number).cloned(),
                    state.batches.get(&sequence_number).cloned(),
                    state.errors.get(&sequence_number).cloned(),
                )
            };
            self.started.notify_waiters();
            let _guard = InFlightGuard {
                state: self.state.clone(),
            };
            if let Some(gate) = gate {
                gate.wait().await;
            }
            if let Some(error) = error {
                return Err(error);
            }
            Ok(batch.map(|kvs| LogBatch::from_entries(sequence_number, kvs)))
        }

        async fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
            Ok(self
                .state
                .lock()
                .map_err(|err| err.to_string())?
                .batches
                .first_key_value()
                .map(|(sequence_number, _)| *sequence_number))
        }
    }

    impl Retention for GatedLog {
        async fn set_retention(
            &self,
            _policy: Option<RetentionPolicy>,
        ) -> Result<Option<u64>, String> {
            self.oldest_retained_batch().await
        }
    }

    struct QueryOnlyEngine {
        sequence_number: u64,
        value: Option<Bytes>,
    }

    impl Sequence for QueryOnlyEngine {
        fn current_sequence(&self) -> u64 {
            self.sequence_number
        }
    }

    impl Query for QueryOnlyEngine {
        type RangeScan = IteratorRangeScan;

        async fn get(&self, _key: Bytes) -> Result<(Option<Bytes>, QueryExtra), String> {
            Ok((self.value.clone(), QueryExtra::default()))
        }

        async fn range_scan(
            &self,
            _start: Bytes,
            _end: Bytes,
            _limit: usize,
            _forward: bool,
        ) -> Result<Self::RangeScan, String> {
            Ok(range_scan_from_iter(std::iter::empty()))
        }

        async fn get_many(
            &self,
            keys: Vec<Bytes>,
        ) -> Result<(Vec<(Bytes, Option<Bytes>)>, QueryExtra), String> {
            Ok((
                keys.into_iter().map(|key| (key, None)).collect(),
                QueryExtra::default(),
            ))
        }
    }

    #[derive(Default)]
    struct PruneOnlyEngine {
        documents: Mutex<Vec<(u32, usize)>>,
    }

    impl PruneOnlyEngine {
        fn applied_count(&self) -> usize {
            self.documents.lock().expect("lock").len()
        }

        fn last_document(&self) -> Option<(u32, usize)> {
            self.documents.lock().expect("lock").last().copied()
        }
    }

    impl Prune for PruneOnlyEngine {
        async fn apply_prune_policies(&self, document: PrunePolicyDocument) -> Result<(), String> {
            self.documents
                .lock()
                .map(|mut documents| {
                    documents.push((document.version, document.policies.len()));
                })
                .map_err(|e| e.to_string())
        }
    }

    impl Retention for PruneOnlyEngine {
        async fn set_retention(
            &self,
            _policy: Option<RetentionPolicy>,
        ) -> Result<Option<u64>, String> {
            Ok(None)
        }
    }

    struct ManualNotifier {
        current_sequence: AtomicU64,
        notify: Arc<Notify>,
    }

    impl ManualNotifier {
        fn new(current_sequence: u64) -> Self {
            Self {
                current_sequence: AtomicU64::new(current_sequence),
                notify: Arc::new(Notify::new()),
            }
        }
    }

    impl StreamNotifier for ManualNotifier {
        fn subscribe(&self) -> StreamNotification {
            StreamNotification {
                current_sequence: self.current_sequence.load(Ordering::Acquire),
                notify: self.notify.clone(),
            }
        }

        fn current_sequence(&self) -> u64 {
            self.current_sequence.load(Ordering::Acquire)
        }

        fn advance(&self, seq: u64) {
            self.current_sequence.fetch_max(seq, Ordering::SeqCst);
            self.notify.notify_waiters();
        }
    }

    fn matching_kv(payload: &[u8], value: &[u8]) -> (Bytes, Bytes) {
        let key = Prefix::from_byte(TEST_PREFIX)
            .encode(payload)
            .expect("encode key");
        (key, Bytes::copy_from_slice(value))
    }

    fn nonmatching_kv(payload: &[u8], value: &[u8]) -> (Bytes, Bytes) {
        let key = Prefix::from_byte(TEST_PREFIX + 1)
            .encode(payload)
            .expect("encode key");
        (key, Bytes::copy_from_slice(value))
    }

    fn numeric_query_extra(name: &str, value: f64) -> QueryExtra {
        HashMap::from([(
            name.to_string(),
            buffa_types::google::protobuf::Value::from(value),
        )])
    }

    fn subscribe_request_bytes(since_sequence_number: Option<u64>) -> Vec<u8> {
        SubscribeRequest {
            selectors: vec![ProtoSelector {
                prefix: Bytes::from(vec![TEST_PREFIX]),
                payload_regex: "(?s).*".to_string(),
                ..Default::default()
            }],
            since_sequence_number,
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn put_request(
        value_len: usize,
    ) -> buffa::view::OwnedView<exoware_proto::log::ingest::v1::PutRequestView<'static>> {
        let bytes = exoware_proto::ingest::PutRequest {
            kvs: vec![exoware_proto::common::Entry {
                key: b"k".to_vec(),
                value: Bytes::from(vec![1u8; value_len]),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();
        buffa::view::OwnedView::<exoware_proto::log::ingest::v1::PutRequestView<'static>>::decode(
            bytes.into(),
        )
        .expect("decode put request")
    }

    fn keys_scope() -> KeysScope {
        KeysScope {
            selector: Some(ProtoSelector {
                prefix: Bytes::from(vec![TEST_PREFIX]),
                payload_regex: "(?s).*".to_string(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
    }

    fn keys_drop_all_policy() -> ProtoPolicy {
        ProtoPolicy {
            keys: Some(keys_scope()).into(),
            retain: Some(PolicyRetain {
                kind: Some(policy_retain::Kind::DropAll(Box::default())),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
    }

    fn keys_keep_latest_policy(count: u64) -> ProtoPolicy {
        ProtoPolicy {
            keys: Some(keys_scope()).into(),
            retain: Some(PolicyRetain {
                kind: Some(policy_retain::Kind::KeepLatest(Box::new(
                    RetainKeepLatest {
                        count,
                        ..Default::default()
                    },
                ))),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
    }

    fn prune_request(
        policies: Vec<ProtoPolicy>,
    ) -> buffa::view::OwnedView<PruneRequestView<'static>> {
        let bytes = PruneRequest {
            policies,
            ..Default::default()
        }
        .encode_to_vec();
        buffa::view::OwnedView::<PruneRequestView<'static>>::decode(bytes.into())
            .expect("decode prune request")
    }

    async fn subscribe_stream<B>(
        connect: &StreamConnect<B>,
        since_sequence_number: Option<u64>,
    ) -> Result<
        Pin<Box<dyn Stream<Item = Result<SubscribeResponse, ConnectError>> + Send>>,
        ConnectError,
    >
    where
        B: Log,
    {
        let bytes = subscribe_request_bytes(since_sequence_number);
        let request = buffa::view::OwnedView::<SubscribeRequestView<'static>>::decode(bytes.into())
            .expect("decode subscribe request");
        Ok(StreamApi::subscribe(connect, Context::default(), request)
            .await?
            .body)
    }

    async fn next_subscribe_frame(
        frames: &mut tokio::sync::mpsc::UnboundedReceiver<Result<SubscribeResponse, ConnectError>>,
    ) -> SubscribeResponse {
        tokio::time::timeout(Duration::from_secs(1), frames.recv())
            .await
            .expect("stream should yield")
            .expect("frame should exist")
            .expect("frame should be ok")
    }

    async fn set_retention<R>(
        connect: &RetentionConnect<R>,
        policy: Option<RetentionPolicy>,
    ) -> Result<SetRetentionResponse, ConnectError>
    where
        R: Retention,
    {
        let bytes = SetRetentionRequest {
            policy: policy
                .as_ref()
                .map(exoware_proto::retention_policy_to_proto)
                .into(),
            ..Default::default()
        }
        .encode_to_vec();
        let request =
            buffa::view::OwnedView::<SetRetentionRequestView<'static>>::decode(bytes.into())
                .expect("decode set_retention request");
        Ok(
            RetentionApi::set_retention(connect, Context::default(), request)
                .await?
                .body,
        )
    }

    #[tokio::test]
    async fn prune_connect_accepts_prune_only_engine() {
        let prune = Arc::new(PruneOnlyEngine::default());
        let connect = PruneConnect::new(PruneState::new(prune.clone()));
        let request = prune_request(vec![keys_drop_all_policy()]);

        PruneApi::prune(&connect, Context::default(), request)
            .await
            .expect("prune");

        assert_eq!(prune.applied_count(), 1);
        assert_eq!(
            prune.last_document(),
            Some((PRUNE_POLICY_DOCUMENT_VERSION, 1))
        );
    }

    #[tokio::test]
    async fn prune_rejects_unparseable_policy_before_engine_prune() {
        let prune = Arc::new(PruneOnlyEngine::default());
        let connect = PruneConnect::new(PruneState::new(prune.clone()));
        // A Keys scope without its required selector fails to parse into a
        // domain policy, so the handler rejects it before reaching the engine.
        let invalid_policy = ProtoPolicy {
            keys: Some(KeysScope::default()).into(),
            ..Default::default()
        };
        let request = prune_request(vec![invalid_policy]);

        let err = PruneApi::prune(&connect, Context::default(), request)
            .await
            .expect_err("invalid prune");

        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
        assert_eq!(prune.applied_count(), 0);
    }

    #[tokio::test]
    async fn prune_rejects_invalid_policy_before_engine_prune() {
        let prune = Arc::new(PruneOnlyEngine::default());
        let connect = PruneConnect::new(PruneState::new(prune.clone()));
        let request = prune_request(vec![keys_keep_latest_policy(0)]);

        let err = PruneApi::prune(&connect, Context::default(), request)
            .await
            .expect_err("invalid prune");

        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
        assert_eq!(prune.applied_count(), 0);
    }

    #[tokio::test]
    async fn set_retention_applies_policy_and_returns_floor() {
        let engine = Arc::new(FakeEngine::default());
        engine.set_current_sequence(5);
        engine.set_retention_floor(Some(4));
        let connect = RetentionConnect::new(RetentionState::new(engine.clone()));

        let response = set_retention(&connect, Some(RetentionPolicy::KeepLatest { count: 2 }))
            .await
            .expect("set_retention");

        // The floor is whatever the backend reports after one enforcement.
        assert_eq!(response.oldest_retained_sequence, Some(4));
        assert_eq!(
            engine.retention_calls(),
            vec![Some(RetentionPolicy::KeepLatest { count: 2 })]
        );
    }

    #[tokio::test]
    async fn set_retention_rejects_zero_keep_latest_before_engine() {
        let engine = Arc::new(FakeEngine::default());
        let connect = RetentionConnect::new(RetentionState::new(engine.clone()));

        let err = set_retention(&connect, Some(RetentionPolicy::KeepLatest { count: 0 }))
            .await
            .expect_err("count 0 rejected");

        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
        // Validation is authoritative, so the backend is never touched.
        assert!(engine.retention_calls().is_empty());
    }

    #[tokio::test]
    async fn set_retention_absent_policy_clears_rule() {
        let engine = Arc::new(FakeEngine::default());
        engine.set_retention_floor(None);
        let connect = RetentionConnect::new(RetentionState::new(engine.clone()));

        let response = set_retention(&connect, None)
            .await
            .expect("clear retention");

        // Clearing keeps enforcement off; no floor exists so none is returned.
        assert_eq!(response.oldest_retained_sequence, None);
        assert_eq!(engine.retention_calls(), vec![None]);
    }

    #[tokio::test]
    async fn query_connect_accepts_query_only_engine() {
        let query = Arc::new(QueryOnlyEngine {
            sequence_number: 9,
            value: Some(Bytes::from_static(b"value")),
        });
        let connect = QueryConnect::new(QueryState { query });
        let bytes = exoware_proto::query::GetRequest {
            key: b"k".to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let request = buffa::view::OwnedView::<
            exoware_proto::store::query::v1::GetRequestView<'static>,
        >::decode(bytes.into())
        .expect("decode get request");

        let response = QueryApi::get(&connect, Context::default(), request)
            .await
            .expect("get")
            .body;
        let detail = response.detail.as_option().expect("query detail");

        assert_eq!(response.value.as_deref(), Some(b"value".as_slice()));
        assert_eq!(detail.sequence_number, 9);
    }

    #[tokio::test]
    async fn get_includes_engine_query_extra() {
        let engine = Arc::new(FakeEngine::default());
        engine.set_current_sequence(5);
        engine.set_query_extra(HashMap::from([(
            "scanned_bytes".to_string(),
            buffa_types::google::protobuf::Value::from(123.0),
        )]));
        let connect = QueryConnect::new(AppState::new(engine));
        let bytes = exoware_proto::query::GetRequest {
            key: b"k".to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let request = buffa::view::OwnedView::<
            exoware_proto::store::query::v1::GetRequestView<'static>,
        >::decode(bytes.into())
        .expect("decode get request");

        let response = QueryApi::get(&connect, Context::default(), request)
            .await
            .expect("get")
            .body;
        let detail = response.detail.as_option().expect("query detail");

        assert_eq!(detail.sequence_number, 5);
        assert_eq!(
            detail
                .extra
                .get("scanned_bytes")
                .and_then(|v| v.as_number()),
            Some(123.0)
        );
    }

    #[test]
    fn split_service_constructors_build_independent_process_surfaces() {
        let engine = Arc::new(FakeEngine::default());
        let state = AppState::new(engine);

        let _ingest = ingest_service(state.clone().into());
        let _query = query_service(state.clone().into());
        let _prune = prune_service(state.clone().into());
        let _retention = retention_service(state.clone().into());
        let _stream = stream_service(state.clone().into());
        let _query_stack = query_stack(state.clone().into(), state.into());
    }

    #[tokio::test]
    async fn ingest_uses_configured_value_limit() {
        let engine = Arc::new(FakeEngine::default());
        let state = IngestState::new(engine).with_limits(IngestLimits { max_value_len: 4 });
        let connect = IngestConnect::new(state);

        let err = IngestApi::put(&connect, Context::default(), put_request(5))
            .await
            .expect_err("put should reject oversized value");

        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn ingest_unavailable_surfaces_as_unavailable_with_retry_info() {
        let engine = Arc::new(FakeEngine::default());
        engine.set_put_error(IngestError::Unavailable {
            message: "backend bouncing".to_string(),
        });
        let connect = IngestConnect::new(IngestState::new(engine));

        let err = IngestApi::put(&connect, Context::default(), put_request(1))
            .await
            .expect_err("transient put failure should surface");

        assert_eq!(err.code, connectrpc::ErrorCode::Unavailable);
        let decoded = decode_connect_error(&err).expect("decode details");
        assert_eq!(
            decoded.error_info.expect("error info").reason,
            REASON_INGEST_UNAVAILABLE
        );
        let retry_delay = decoded.retry_info.expect("retry info").retry_delay;
        let retry_delay = retry_delay.as_option().expect("retry delay");
        assert_eq!((retry_delay.seconds, retry_delay.nanos), (1, 0));
    }

    #[tokio::test]
    async fn ingest_internal_surfaces_as_internal_without_error_info() {
        let engine = Arc::new(FakeEngine::default());
        engine.set_put_error(IngestError::Internal {
            message: "invariant violated".to_string(),
        });
        let connect = IngestConnect::new(IngestState::new(engine));

        let err = IngestApi::put(&connect, Context::default(), put_request(1))
            .await
            .expect_err("fatal put failure should surface");

        assert_eq!(err.code, connectrpc::ErrorCode::Internal);
        let decoded = decode_connect_error(&err).expect("decode details");
        assert!(decoded.error_info.is_none());
    }

    #[tokio::test]
    async fn put_when_not_ready_keeps_worker_not_ready_reason() {
        let engine = Arc::new(FakeEngine::default());
        let state = IngestState::new(engine);
        state.ready.store(false, Ordering::SeqCst);
        let connect = IngestConnect::new(state);

        let err = IngestApi::put(&connect, Context::default(), put_request(1))
            .await
            .expect_err("not-ready gate should reject");

        // Both the gate and a backend-discovered outage surface `unavailable`; the reason string is
        // what keeps them distinguishable, so pin it against drift toward `INGEST_UNAVAILABLE`.
        assert_eq!(err.code, connectrpc::ErrorCode::Unavailable);
        let decoded = decode_connect_error(&err).expect("decode details");
        assert_eq!(
            decoded.error_info.expect("error info").reason,
            REASON_WORKER_NOT_READY
        );
    }

    #[tokio::test]
    async fn stream_can_be_advanced_by_external_notifier() {
        let engine = Arc::new(FakeEngine::default());
        let notifier = Arc::new(ManualNotifier::new(0));
        let connect = StreamConnect::new(StreamState::new(engine.clone(), notifier.clone()));
        let mut stream = subscribe_stream(&connect, None).await.expect("subscribe");

        engine.set_current_sequence(1);
        engine.set_batch(1, Some(vec![matching_kv(b"hit", b"v1")]));
        notifier.advance(1);

        let frame = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("stream should yield")
            .expect("frame should exist")
            .expect("frame should be ok");
        assert_eq!(frame.sequence_number, 1);
        assert_eq!(frame.entries.len(), 1);
        assert_eq!(frame.entries[0].value.as_ref(), b"v1");
    }

    #[tokio::test]
    async fn reduce_consumes_range_iterator_and_returns_detail() {
        let engine = Arc::new(FakeEngine::default());
        engine.set_current_sequence(7);
        engine.set_range_rows(vec![
            (Bytes::from_static(b"a"), Bytes::from_static(b"xx")),
            (Bytes::from_static(b"bb"), Bytes::from_static(b"yyy")),
        ]);
        let connect = QueryConnect::new(AppState::new(engine.clone()));
        let bytes = exoware_proto::query::ReduceRequest {
            start: b"a".to_vec(),
            end: b"z".to_vec(),
            params: Some(exoware_proto::query::ReduceParams {
                reducers: vec![exoware_proto::query::RangeReducerSpec {
                    op: exoware_proto::query::RangeReduceOp::RANGE_REDUCE_OP_COUNT_ALL.into(),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
        .encode_to_vec();
        let request = buffa::view::OwnedView::<
            exoware_proto::store::query::v1::ReduceRequestView<'static>,
        >::decode(bytes.into())
        .expect("decode reduce request");

        let response = QueryApi::reduce(&connect, Context::default(), request)
            .await
            .expect("reduce")
            .body;
        let detail = response.detail.as_option().expect("query detail").clone();
        let response = to_domain_reduce_response(response).expect("decode reduce response");

        assert_eq!(engine.range_next_count(), 2);
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].value, Some(KvReducedValue::UInt64(2)));
        assert_eq!(detail.sequence_number, 7);
        assert!(detail.extra.is_empty());
    }

    #[tokio::test]
    async fn reduce_uses_eof_query_extra() {
        let engine = Arc::new(FakeEngine::default());
        engine.set_current_sequence(8);
        engine.set_range_rows(vec![
            (Bytes::from_static(b"a"), Bytes::from_static(b"xx")),
            (Bytes::from_static(b"bb"), Bytes::from_static(b"yyy")),
        ]);
        engine.set_range_eof_extra(numeric_query_extra("final_rows", 2.0));
        let connect = QueryConnect::new(AppState::new(engine));
        let bytes = exoware_proto::query::ReduceRequest {
            start: b"a".to_vec(),
            end: b"z".to_vec(),
            params: Some(exoware_proto::query::ReduceParams {
                reducers: vec![exoware_proto::query::RangeReducerSpec {
                    op: exoware_proto::query::RangeReduceOp::RANGE_REDUCE_OP_COUNT_ALL.into(),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
        .encode_to_vec();
        let request = buffa::view::OwnedView::<
            exoware_proto::store::query::v1::ReduceRequestView<'static>,
        >::decode(bytes.into())
        .expect("decode reduce request");

        let response = QueryApi::reduce(&connect, Context::default(), request)
            .await
            .expect("reduce")
            .body;
        let detail = response.detail.as_option().expect("query detail");

        assert_eq!(detail.sequence_number, 8);
        assert_eq!(
            detail.extra.get("final_rows").and_then(|v| v.as_number()),
            Some(2.0)
        );
    }

    #[tokio::test]
    async fn get_many_populates_detail_on_each_frame() {
        let engine = Arc::new(FakeEngine::default());
        engine.set_current_sequence(11);
        let connect = QueryConnect::new(AppState::new(engine));
        let bytes = exoware_proto::query::GetManyRequest {
            keys: vec![b"a".to_vec(), b"bb".to_vec(), b"ccc".to_vec()],
            batch_size: 2,
            ..Default::default()
        }
        .encode_to_vec();
        let request = buffa::view::OwnedView::<
            exoware_proto::store::query::v1::GetManyRequestView<'static>,
        >::decode(bytes.into())
        .expect("decode get_many request");

        let mut stream = QueryApi::get_many(&connect, Context::default(), request)
            .await
            .expect("get_many")
            .body;
        let mut frame_sizes = Vec::new();
        let mut detail_frames = 0usize;
        while let Some(frame) = stream.next().await {
            let frame = frame.expect("get_many frame");
            frame_sizes.push(frame.results.len());
            let detail = frame.detail.as_option().expect("query detail");
            assert_eq!(detail.sequence_number, 11);
            assert!(detail.extra.is_empty());
            detail_frames += 1;
        }

        assert_eq!(frame_sizes, vec![2, 1]);
        assert_eq!(detail_frames, 2);
    }

    #[tokio::test]
    async fn range_returns_without_materializing_full_iterator() {
        let engine = Arc::new(FakeEngine::default());
        engine.set_current_sequence(9);
        engine.set_range_rows(
            (0..1000)
                .map(|i| {
                    (
                        Bytes::from(format!("key-{i:04}")),
                        Bytes::from_static(b"value"),
                    )
                })
                .collect(),
        );
        let connect = QueryConnect::new(AppState::new(engine.clone()));
        let bytes = exoware_proto::query::RangeRequest {
            start: b"a".to_vec(),
            end: b"z".to_vec(),
            limit: Some(1000),
            batch_size: 1,
            ..Default::default()
        }
        .encode_to_vec();
        let request = buffa::view::OwnedView::<
            exoware_proto::store::query::v1::RangeRequestView<'static>,
        >::decode(bytes.into())
        .expect("decode range request");

        let mut stream = QueryApi::range(&connect, Context::default(), request)
            .await
            .expect("range")
            .body;

        tokio::time::sleep(Duration::from_millis(50)).await;
        let consumed = engine.range_next_count();
        assert!(
            consumed < 1000,
            "range should not consume the full iterator before the response stream is read; consumed {consumed}",
        );

        let mut rows = 0;
        let mut latest_detail = None;
        let mut detail_frames = 0usize;
        while let Some(frame) = stream.next().await {
            let frame = frame.expect("range frame");
            rows += frame.results.len();
            if let Some(detail) = frame.detail.as_option() {
                detail_frames += 1;
                latest_detail = Some(detail.clone());
            }
        }

        assert_eq!(rows, 1000);
        assert_eq!(detail_frames, 1000);
        let detail = latest_detail.expect("query detail");
        assert_eq!(detail.sequence_number, 9);
        assert!(detail.extra.is_empty());
    }

    #[tokio::test]
    async fn range_emits_eof_query_extra_after_rows() {
        let engine = Arc::new(FakeEngine::default());
        engine.set_current_sequence(10);
        engine.set_range_rows(vec![
            (Bytes::from_static(b"a"), Bytes::from_static(b"1")),
            (Bytes::from_static(b"b"), Bytes::from_static(b"2")),
        ]);
        engine.set_range_eof_extra(numeric_query_extra("final_rows", 2.0));
        let connect = QueryConnect::new(AppState::new(engine));
        let bytes = exoware_proto::query::RangeRequest {
            start: b"a".to_vec(),
            end: b"z".to_vec(),
            limit: Some(2),
            batch_size: 2,
            ..Default::default()
        }
        .encode_to_vec();
        let request = buffa::view::OwnedView::<
            exoware_proto::store::query::v1::RangeRequestView<'static>,
        >::decode(bytes.into())
        .expect("decode range request");

        let mut stream = QueryApi::range(&connect, Context::default(), request)
            .await
            .expect("range")
            .body;
        let mut frames = Vec::new();
        while let Some(frame) = stream.next().await {
            frames.push(frame.expect("range frame"));
        }

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].results.len(), 2);
        let row_detail = frames[0].detail.as_option().expect("row detail");
        assert!(row_detail.extra.is_empty());

        assert!(frames[1].results.is_empty());
        let final_detail = frames[1].detail.as_option().expect("final detail");
        assert_eq!(final_detail.sequence_number, 10);
        assert_eq!(
            final_detail
                .extra
                .get("final_rows")
                .and_then(|v| v.as_number()),
            Some(2.0)
        );
    }

    #[tokio::test]
    async fn subscribe_without_replay_reads_the_next_live_batch() {
        let engine = Arc::new(FakeEngine::default());
        let state = AppState::new(engine.clone());
        let connect = StreamConnect::new(state.clone());
        let mut stream = subscribe_stream(&connect, None).await.expect("subscribe");
        engine.publish_live(state.stream.clone(), 1, vec![matching_kv(b"hit", b"v1")]);
        let frame = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("stream should yield")
            .expect("frame should exist")
            .expect("frame should be ok");
        assert_eq!(frame.sequence_number, 1);
        assert_eq!(frame.entries.len(), 1);
        assert_eq!(frame.entries[0].value.as_ref(), b"v1");
    }

    #[tokio::test]
    async fn dropping_subscription_cancels_in_flight_lookahead() {
        let last_sequence = SUBSCRIBE_GET_BATCH_LOOKAHEAD as u64 + 1;
        let engine = Arc::new(GatedLog::default());
        for sequence_number in 1..=last_sequence {
            engine.set_batch(
                sequence_number,
                vec![matching_kv(b"replay", &[sequence_number as u8])],
            );
        }
        for sequence_number in 2..=last_sequence {
            engine.gate(sequence_number);
        }

        let notifier = Arc::new(ManualNotifier::new(last_sequence));
        let connect = StreamConnect::new(StreamState::new(engine.clone(), notifier));
        let mut stream = subscribe_stream(&connect, Some(1))
            .await
            .expect("subscribe");

        let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("first frame")
            .expect("frame exists")
            .expect("frame ok");
        assert_eq!(first.sequence_number, 1);

        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.next())
                .await
                .is_err(),
            "gated batches must hold the stream pending",
        );
        engine.wait_for_started(last_sequence as usize).await;
        assert_eq!(engine.in_flight(), SUBSCRIBE_GET_BATCH_LOOKAHEAD);

        drop(stream);
        assert_eq!(engine.in_flight(), 0);
    }

    #[tokio::test]
    async fn replay_lookahead_is_bounded_and_emits_in_order() {
        let last_sequence = SUBSCRIBE_GET_BATCH_LOOKAHEAD as u64 + 1;
        let engine = Arc::new(GatedLog::default());
        for sequence_number in 1..=last_sequence {
            engine.set_batch(
                sequence_number,
                vec![matching_kv(b"replay", &[sequence_number as u8])],
            );
        }
        for sequence_number in 2..=last_sequence {
            engine.gate(sequence_number);
        }

        let notifier = Arc::new(ManualNotifier::new(last_sequence));
        let connect = StreamConnect::new(StreamState::new(engine.clone(), notifier));
        let mut stream = subscribe_stream(&connect, Some(1))
            .await
            .expect("subscribe");

        assert_eq!(engine.started_sequences(), vec![1]);

        let (sender, mut frames) = tokio::sync::mpsc::unbounded_channel();
        let reader = tokio::spawn(async move {
            while let Some(frame) = stream.next().await {
                if sender.send(frame).is_err() {
                    return;
                }
            }
        });

        assert_eq!(next_subscribe_frame(&mut frames).await.sequence_number, 1);
        engine.wait_for_started(last_sequence as usize).await;

        assert_eq!(engine.in_flight(), SUBSCRIBE_GET_BATCH_LOOKAHEAD);
        assert_eq!(engine.max_in_flight(), SUBSCRIBE_GET_BATCH_LOOKAHEAD);
        assert_eq!(
            engine.started_sequences(),
            (1..=last_sequence).collect::<Vec<_>>()
        );

        for sequence_number in (3..=last_sequence).rev() {
            engine.release(sequence_number);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), frames.recv())
                .await
                .is_err(),
            "later batches must wait for the first pending batch",
        );

        engine.release(2);
        for expected in 2..=last_sequence {
            assert_eq!(
                next_subscribe_frame(&mut frames).await.sequence_number,
                expected
            );
        }
        assert_eq!(engine.get_count(1), 1);

        reader.abort();
        let _ = reader.await;
    }

    #[tokio::test]
    async fn replay_lookahead_refills_after_filtered_batches() {
        let last_sequence = SUBSCRIBE_GET_BATCH_LOOKAHEAD as u64 + 2;
        let engine = Arc::new(GatedLog::default());
        for sequence_number in 1..=last_sequence {
            let kv = if sequence_number == 1 || sequence_number == last_sequence {
                matching_kv(b"match", &[sequence_number as u8])
            } else {
                nonmatching_kv(b"skip", &[sequence_number as u8])
            };
            engine.set_batch(sequence_number, vec![kv]);
        }

        let notifier = Arc::new(ManualNotifier::new(last_sequence));
        let connect = StreamConnect::new(StreamState::new(engine.clone(), notifier));
        let mut stream = subscribe_stream(&connect, Some(1))
            .await
            .expect("subscribe");

        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.sequence_number, 1);
        let last = stream.next().await.unwrap().unwrap();
        assert_eq!(last.sequence_number, last_sequence);

        for sequence_number in 1..=last_sequence {
            assert_eq!(engine.get_count(sequence_number), 1);
        }
    }

    #[tokio::test]
    async fn replay_lookahead_emits_earliest_error_and_terminates() {
        let engine = Arc::new(GatedLog::default());
        engine.set_batch(1, vec![matching_kv(b"first", b"v1")]);
        engine.set_batch(3, vec![matching_kv(b"later", b"v3")]);
        engine.set_error(2, "batch read failed");
        engine.gate(2);

        let notifier = Arc::new(ManualNotifier::new(3));
        let connect = StreamConnect::new(StreamState::new(engine.clone(), notifier));
        let mut stream = subscribe_stream(&connect, Some(1))
            .await
            .expect("subscribe");

        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.sequence_number, 1);
        let mut next = Box::pin(stream.next());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut next)
                .await
                .is_err(),
            "later successes must wait behind an earlier error",
        );
        engine.wait_for_started(3).await;
        assert_eq!(engine.get_count(3), 1);

        engine.release(2);
        let error = next.await.unwrap().expect_err("stream error");
        assert_eq!(error.code, connectrpc::ErrorCode::Internal);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn replay_to_live_catch_up_extends_bounded_lookahead() {
        const REPLAY_BOUND: u64 = 4;

        let first_live_bound = REPLAY_BOUND + SUBSCRIBE_GET_BATCH_LOOKAHEAD as u64;
        let second_live_bound = first_live_bound + SUBSCRIBE_GET_BATCH_LOOKAHEAD as u64;
        let engine = Arc::new(GatedLog::default());
        for sequence_number in 1..=second_live_bound {
            engine.set_batch(
                sequence_number,
                vec![matching_kv(b"batch", &[sequence_number as u8])],
            );
        }
        engine.gate(2);
        for sequence_number in (REPLAY_BOUND + 1)..=second_live_bound {
            engine.gate(sequence_number);
        }

        let notifier = Arc::new(ManualNotifier::new(REPLAY_BOUND));
        let connect = StreamConnect::new(StreamState::new(engine.clone(), notifier.clone()));
        let mut stream = subscribe_stream(&connect, Some(1))
            .await
            .expect("subscribe");
        let (sender, mut frames) = tokio::sync::mpsc::unbounded_channel();
        let reader = tokio::spawn(async move {
            while let Some(frame) = stream.next().await {
                if sender.send(frame).is_err() {
                    return;
                }
            }
        });

        assert_eq!(next_subscribe_frame(&mut frames).await.sequence_number, 1);
        engine.wait_for_started(REPLAY_BOUND as usize).await;
        engine.wait_for_gate_waits(2, 1).await;

        notifier.advance(first_live_bound);
        engine.wake(2);
        engine.wait_for_gate_waits(2, 2).await;
        assert_eq!(
            engine.started_sequences(),
            (1..=REPLAY_BOUND).collect::<Vec<_>>()
        );

        engine.release(2);
        for expected in 2..=REPLAY_BOUND {
            assert_eq!(
                next_subscribe_frame(&mut frames).await.sequence_number,
                expected
            );
        }

        engine.wait_for_started(first_live_bound as usize).await;
        assert_eq!(engine.in_flight(), SUBSCRIBE_GET_BATCH_LOOKAHEAD);

        notifier.advance(second_live_bound);
        for sequence_number in ((REPLAY_BOUND + 2)..=first_live_bound).rev() {
            engine.release(sequence_number);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), frames.recv())
                .await
                .is_err(),
            "live batches must remain ordered within the lookahead",
        );
        assert_eq!(engine.started_sequences().len(), first_live_bound as usize);

        engine.release(REPLAY_BOUND + 1);
        for expected in (REPLAY_BOUND + 1)..=first_live_bound {
            assert_eq!(
                next_subscribe_frame(&mut frames).await.sequence_number,
                expected
            );
        }

        engine.wait_for_started(second_live_bound as usize).await;
        assert_eq!(engine.in_flight(), SUBSCRIBE_GET_BATCH_LOOKAHEAD);
        assert_eq!(engine.max_in_flight(), SUBSCRIBE_GET_BATCH_LOOKAHEAD);

        for sequence_number in ((first_live_bound + 2)..=second_live_bound).rev() {
            engine.release(sequence_number);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), frames.recv())
                .await
                .is_err(),
            "batches read past the old frontier must preserve batch order",
        );

        engine.release(first_live_bound + 1);
        for expected in (first_live_bound + 1)..=second_live_bound {
            assert_eq!(
                next_subscribe_frame(&mut frames).await.sequence_number,
                expected
            );
        }

        reader.abort();
        let _ = reader.await;
    }

    #[tokio::test]
    async fn live_lookahead_extends_while_earlier_reads_are_in_flight() {
        let last_sequence = 12u64;
        let engine = Arc::new(GatedLog::default());
        for sequence_number in 3..=last_sequence {
            engine.set_batch(
                sequence_number,
                vec![matching_kv(b"live", &[sequence_number as u8])],
            );
            engine.gate(sequence_number);
        }

        let notifier = Arc::new(ManualNotifier::new(2));
        let connect = StreamConnect::new(StreamState::new(engine.clone(), notifier.clone()));
        let mut stream = subscribe_stream(&connect, None).await.expect("subscribe");
        let (sender, mut frames) = tokio::sync::mpsc::unbounded_channel();
        let reader = tokio::spawn(async move {
            while let Some(frame) = stream.next().await {
                if sender.send(frame).is_err() {
                    return;
                }
            }
        });

        notifier.advance(4);
        engine.wait_for_started(2).await;
        assert_eq!(engine.in_flight(), 2);

        // Reads past the old frontier must start while 3 and 4 are still in
        // flight, rather than after the pre-advance window fully drains.
        notifier.advance(last_sequence);
        engine.wait_for_started(SUBSCRIBE_GET_BATCH_LOOKAHEAD).await;
        assert_eq!(engine.in_flight(), SUBSCRIBE_GET_BATCH_LOOKAHEAD);
        assert_eq!(
            engine.started_sequences(),
            (3..=2 + SUBSCRIBE_GET_BATCH_LOOKAHEAD as u64).collect::<Vec<_>>()
        );

        for sequence_number in 3..=last_sequence {
            engine.release(sequence_number);
        }
        for expected in 3..=last_sequence {
            assert_eq!(
                next_subscribe_frame(&mut frames).await.sequence_number,
                expected
            );
        }
        assert_eq!(engine.max_in_flight(), SUBSCRIBE_GET_BATCH_LOOKAHEAD);

        reader.abort();
        let _ = reader.await;
    }

    #[tokio::test]
    async fn subscribe_past_end_reads_only_future_live_batches() {
        let engine = Arc::new(FakeEngine::default());
        engine.set_current_sequence(5);
        for seq in 1..=5 {
            engine.set_batch(seq, Some(vec![matching_kv(b"seed", b"v")]));
        }
        let state = AppState::new(engine.clone());
        let connect = StreamConnect::new(state.clone());
        let mut stream = subscribe_stream(&connect, Some(15))
            .await
            .expect("subscribe");

        assert!(
            tokio::time::timeout(Duration::from_millis(200), stream.next())
                .await
                .is_err(),
            "past-end cursor should not replay synthetic or historical frames",
        );

        engine.publish_live(state.stream.clone(), 6, vec![matching_kv(b"live", b"n")]);
        let frame = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("stream should yield")
            .expect("frame should exist")
            .expect("frame should be ok");
        assert_eq!(frame.sequence_number, 6);
        assert_eq!(frame.entries.len(), 1);
        assert_eq!(frame.entries[0].value.as_ref(), b"n");
    }

    #[tokio::test]
    async fn replay_hole_returns_batch_evicted_error_instead_of_empty_frame() {
        let engine = Arc::new(FakeEngine::default());
        engine.set_current_sequence(3);
        engine.set_oldest_retained(Some(2));
        engine.set_batch(2, Some(vec![matching_kv(b"replay", b"v2")]));

        let state = AppState::new(engine);
        let connect = StreamConnect::new(state);
        let mut stream = subscribe_stream(&connect, Some(2))
            .await
            .expect("subscribe");

        let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("stream should yield")
            .expect("first replay frame should exist")
            .expect("first replay frame should be ok");
        assert_eq!(first.sequence_number, 2);
        assert_eq!(first.entries.len(), 1);

        let err = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("stream should yield error")
            .expect("error item should exist")
            .expect_err("replay hole must be surfaced as an error");
        let decoded = decode_connect_error(&err).expect("decode connect error");
        assert_eq!(
            decoded.error_info.expect("error info").reason,
            crate::stream::REASON_BATCH_EVICTED,
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(1), stream.next())
                .await
                .expect("stream should terminate")
                .is_none(),
            "stream must terminate after surfacing the replay hole",
        );
    }

    #[tokio::test]
    async fn replay_with_live_burst_under_capacity_still_delivers_in_order() {
        const REPLAY_BATCHES: u64 = 100;

        let engine = Arc::new(FakeEngine::default());
        engine.set_current_sequence(REPLAY_BATCHES);
        engine.set_oldest_retained(Some(1));
        for seq in 1..=REPLAY_BATCHES {
            engine.set_batch(seq, Some(vec![matching_kv(b"replay", b"v")]));
        }

        let state = AppState::new(engine.clone());
        engine.publish_on_every_get_batch(
            state.stream.clone(),
            REPLAY_BATCHES,
            vec![matching_kv(b"live", b"tail")],
        );

        let connect = StreamConnect::new(state);
        let mut stream = subscribe_stream(&connect, Some(1))
            .await
            .expect("subscribe");
        let mut sequence_numbers = Vec::with_capacity((REPLAY_BATCHES * 2) as usize);
        while sequence_numbers.len() < (REPLAY_BATCHES * 2) as usize {
            let frame = tokio::time::timeout(Duration::from_secs(2), stream.next())
                .await
                .expect("stream should keep yielding")
                .expect("frame should exist")
                .expect("frame should be ok");
            sequence_numbers.push(frame.sequence_number);
        }

        let expected: Vec<u64> = (1..=(REPLAY_BATCHES * 2)).collect();
        assert_eq!(sequence_numbers, expected);
    }

    #[tokio::test]
    async fn replay_large_live_burst_is_paced_by_client_reads() {
        const REPLAY_BATCHES: u64 = 300;

        let engine = Arc::new(FakeEngine::default());
        engine.set_current_sequence(REPLAY_BATCHES);
        engine.set_oldest_retained(Some(1));
        for seq in 1..=REPLAY_BATCHES {
            engine.set_batch(seq, Some(vec![matching_kv(b"replay", b"v")]));
        }

        let state = AppState::new(engine.clone());
        engine.publish_on_every_get_batch(
            state.stream.clone(),
            REPLAY_BATCHES,
            vec![matching_kv(b"live", b"tail")],
        );

        let connect = StreamConnect::new(state);
        let mut stream = subscribe_stream(&connect, Some(1))
            .await
            .expect("subscribe");
        let mut sequence_numbers = Vec::with_capacity((REPLAY_BATCHES * 2) as usize);
        while sequence_numbers.len() < (REPLAY_BATCHES * 2) as usize {
            let frame = tokio::time::timeout(Duration::from_secs(2), stream.next())
                .await
                .expect("stream should keep yielding")
                .expect("frame should exist")
                .expect("frame should be ok");
            sequence_numbers.push(frame.sequence_number);
        }
        let expected: Vec<u64> = (1..=(REPLAY_BATCHES * 2)).collect();
        assert_eq!(sequence_numbers, expected);
    }
}
