//! Ingest, query, compact, and stream services; storage is provided by capability traits.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use buffa::MessageView;
use bytes::Bytes;
use connectrpc::{Chain, ConnectError, ConnectRpcService, Context, Limits};
use exoware_proto::common::KvEntry;
use exoware_proto::compact::{
    PruneResponse, Service as CompactApi, ServiceServer as CompactServiceServer,
};
use exoware_proto::google::rpc::{ErrorInfo, RetryInfo};
use exoware_proto::ingest::{
    PutResponse as ProtoPutResponse, Service as IngestApi, ServiceServer as IngestServiceServer,
};
use exoware_proto::query::{
    Detail, GetManyEntry, GetManyFrame, GetResponse, RangeFrame, ReduceResponse,
    Service as QueryApi, ServiceServer as QueryServiceServer,
};
use exoware_proto::store::stream::v1::{
    GetRequestView, GetResponse as StreamGetResponse, Service as StreamApi,
    ServiceServer as StreamServiceServer, SubscribeRequestView, SubscribeResponse,
};
use exoware_proto::stream_filter::{BytesFilter, StreamFilter};
use exoware_proto::{
    connect_compression_registry, parse_range_traversal_direction,
    to_domain_reduce_request_from_view, to_proto_optional_reduced_value, to_proto_reduced_value,
    with_error_info_detail, with_query_detail, with_retry_info_detail, RangeTraversalDirection,
};
use exoware_sdk as exoware_proto;
use exoware_sdk::keys::Key;
use exoware_sdk::match_key::MatchKey;
use exoware_sdk::store::common::v1::bytes_filter::KindView as ProtoBytesFilterKindView;
use futures::{stream as stream_util, Stream};
use tokio::sync::Notify;

use crate::reduce::RangeReducer;
use crate::stream::{StreamHub, StreamNotifier};
use crate::validate;
use crate::{BatchLog, Ingest, Prune, Query, QueryExtra, StoreEngine};

const MAX_CONNECTRPC_BODY_BYTES: usize = 256 * 1024 * 1024;
const RANGE_STREAM_MAX_FRAME_ROWS: usize = 4096;
const REDUCE_SCAN_BATCH_SIZE: usize = 4096;

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

async fn range_stream(
    query: Arc<dyn Query>,
    request: RangeStreamRequest,
) -> Result<Pin<Box<dyn Stream<Item = Result<RangeFrame, ConnectError>> + Send>>, ConnectError> {
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
                if emitted_frame {
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
                chunk.push(KvEntry {
                    key: key.into(),
                    value: value.into(),
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

#[derive(Clone)]
pub struct AppState {
    pub ingest: Arc<dyn Ingest>,
    pub query: Arc<dyn Query>,
    pub prune: Arc<dyn Prune>,
    pub batch_log: Arc<dyn BatchLog>,
    /// Gates ingest (writes) only. Query and compact remain available during drains so that
    /// in-flight reads can complete while the worker sheds write traffic.
    pub ready: Arc<AtomicBool>,
    /// Shared fan-out hub for `store.stream.v1.Subscribe`. `IngestConnect::put`
    /// calls `publish` on successful commit so subscribers receive exactly
    /// the rows that landed in the backend.
    pub stream: Arc<StreamHub>,
}

impl AppState {
    pub fn new(engine: Arc<dyn StoreEngine>) -> Self {
        let current_sequence = engine.current_sequence();
        Self::from_parts_with_sequence(
            engine.clone(),
            engine.clone(),
            engine.clone(),
            engine,
            current_sequence,
        )
    }

    pub fn from_parts(
        ingest: Arc<dyn Ingest>,
        query: Arc<dyn Query>,
        prune: Arc<dyn Prune>,
        batch_log: Arc<dyn BatchLog>,
    ) -> Self {
        let current_sequence = batch_log.current_sequence();
        Self::from_parts_with_sequence(ingest, query, prune, batch_log, current_sequence)
    }

    fn from_parts_with_sequence(
        ingest: Arc<dyn Ingest>,
        query: Arc<dyn Query>,
        prune: Arc<dyn Prune>,
        batch_log: Arc<dyn BatchLog>,
        current_sequence: u64,
    ) -> Self {
        Self {
            ingest,
            query,
            prune,
            batch_log,
            ready: Arc::new(AtomicBool::new(true)),
            stream: Arc::new(StreamHub::new(current_sequence)),
        }
    }
}

#[derive(Clone)]
pub struct IngestState {
    pub ingest: Arc<dyn Ingest>,
    /// Gates ingest writes only.
    pub ready: Arc<AtomicBool>,
    /// Optional live-stream notifier.
    pub notifier: Option<Arc<dyn StreamNotifier>>,
}

impl IngestState {
    pub fn new(ingest: Arc<dyn Ingest>) -> Self {
        Self {
            ingest,
            ready: Arc::new(AtomicBool::new(true)),
            notifier: None,
        }
    }

    pub fn with_notifier(ingest: Arc<dyn Ingest>, notifier: Arc<dyn StreamNotifier>) -> Self {
        Self {
            ingest,
            ready: Arc::new(AtomicBool::new(true)),
            notifier: Some(notifier),
        }
    }
}

impl From<AppState> for IngestState {
    fn from(state: AppState) -> Self {
        Self {
            ingest: state.ingest,
            ready: state.ready,
            notifier: Some(state.stream),
        }
    }
}

#[derive(Clone)]
pub struct QueryState {
    pub query: Arc<dyn Query>,
}

impl From<AppState> for QueryState {
    fn from(state: AppState) -> Self {
        Self { query: state.query }
    }
}

#[derive(Clone)]
pub struct CompactState {
    pub prune: Arc<dyn Prune>,
}

impl CompactState {
    pub fn new(prune: Arc<dyn Prune>) -> Self {
        Self { prune }
    }
}

impl From<AppState> for CompactState {
    fn from(state: AppState) -> Self {
        Self { prune: state.prune }
    }
}

#[derive(Clone)]
pub struct StreamState {
    pub batch_log: Arc<dyn BatchLog>,
    pub notifier: Arc<dyn StreamNotifier>,
}

impl StreamState {
    pub fn new(batch_log: Arc<dyn BatchLog>, notifier: Arc<dyn StreamNotifier>) -> Self {
        Self {
            batch_log,
            notifier,
        }
    }
}

impl From<AppState> for StreamState {
    fn from(state: AppState) -> Self {
        Self {
            batch_log: state.batch_log,
            notifier: state.stream,
        }
    }
}

#[derive(Clone)]
pub struct IngestConnect {
    state: IngestState,
}

impl IngestConnect {
    pub fn new(state: impl Into<IngestState>) -> Self {
        Self {
            state: state.into(),
        }
    }
}

impl IngestApi for IngestConnect {
    async fn put(
        &self,
        _ctx: Context,
        request: buffa::view::OwnedView<exoware_proto::store::ingest::v1::PutRequestView<'static>>,
    ) -> Result<(ProtoPutResponse, Context), ConnectError> {
        if !self.state.ready.load(Ordering::SeqCst) {
            return Err(with_error_info_detail(
                ConnectError::unavailable("ingest is not ready"),
                ErrorInfo {
                    reason: "WORKER_NOT_READY".to_string(),
                    domain: "store.ingest".to_string(),
                    ..Default::default()
                },
            ));
        }

        validate::validate_put_request(&request)?;

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
            .map_err(ConnectError::internal)?;

        // Single-process deployments can fan out the just-committed sequence
        // immediately. Split deployments let the serving process advance its
        // own stream notifier after observing durable state.
        if let Some(notifier) = &self.state.notifier {
            notifier.advance(seq);
        }

        Ok((
            ProtoPutResponse {
                sequence_number: seq,
                ..Default::default()
            },
            Context::default(),
        ))
    }
}

#[derive(Clone)]
pub struct QueryConnect {
    state: QueryState,
}

impl QueryConnect {
    pub fn new(state: impl Into<QueryState>) -> Self {
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
        let err = with_retry_info_detail(
            ConnectError::aborted("minimum consistency token is not yet visible"),
            RetryInfo {
                retry_delay: Some(buffa_types::google::protobuf::Duration::from(
                    std::time::Duration::from_secs(1),
                ))
                .into(),
                ..Default::default()
            },
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

impl QueryApi for QueryConnect {
    async fn get(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<exoware_proto::store::query::v1::GetRequestView<'static>>,
    ) -> Result<(GetResponse, Context), ConnectError> {
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
        Ok((
            GetResponse {
                value,
                detail: Some(detail).into(),
                ..Default::default()
            },
            ctx,
        ))
    }

    async fn get_many(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<
            exoware_proto::store::query::v1::GetManyRequestView<'static>,
        >,
    ) -> Result<
        (
            Pin<Box<dyn Stream<Item = Result<GetManyFrame, ConnectError>> + Send>>,
            Context,
        ),
        ConnectError,
    > {
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
                key,
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

        Ok((Box::pin(stream_util::iter(frames)), ctx))
    }

    async fn range(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<exoware_proto::store::query::v1::RangeRequestView<'static>>,
    ) -> Result<
        (
            Pin<Box<dyn Stream<Item = Result<RangeFrame, ConnectError>> + Send>>,
            Context,
        ),
        ConnectError,
    > {
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
        Ok((
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
            ctx,
        ))
    }

    async fn reduce(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<
            exoware_proto::store::query::v1::ReduceRequestView<'static>,
        >,
    ) -> Result<(ReduceResponse, Context), ConnectError> {
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
                break latest_extra.unwrap_or(batch.extra);
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

        Ok((
            ReduceResponse {
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
            },
            ctx,
        ))
    }
}

#[derive(Clone)]
pub struct CompactConnect {
    state: CompactState,
}

impl CompactConnect {
    pub fn new(state: impl Into<CompactState>) -> Self {
        Self {
            state: state.into(),
        }
    }
}

fn prune_error_to_connect_error(err: String) -> ConnectError {
    ConnectError::internal(err)
}

impl CompactApi for CompactConnect {
    async fn prune(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<
            exoware_proto::store::compact::v1::PruneRequestView<'static>,
        >,
    ) -> Result<(PruneResponse, Context), ConnectError> {
        validate::validate_prune_request(&request)?;
        let _document = exoware_proto::prune_policy_document_from_prune_request_view(&request)
            .map_err(|e| ConnectError::invalid_argument(e.to_string()))?;

        let policies = request
            .policies
            .iter()
            .map(|policy| policy.to_owned_message())
            .collect();
        self.state
            .prune
            .apply_prune_policies(policies)
            .await
            .map_err(prune_error_to_connect_error)?;
        Ok((PruneResponse::default(), ctx))
    }
}

#[derive(Clone)]
pub struct StreamConnect {
    state: StreamState,
}

impl StreamConnect {
    pub fn new(state: impl Into<StreamState>) -> Self {
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
    seq: u64,
    kvs: &[(Bytes, Bytes)],
    matchers: &crate::stream::CompiledMatchers,
) -> Option<SubscribeResponse> {
    let entries = crate::stream::apply_filter(matchers, kvs);
    (!entries.is_empty()).then_some(SubscribeResponse {
        sequence_number: seq,
        entries,
        ..Default::default()
    })
}

struct ReplayState {
    next_sequence: u64,
    bound: u64,
    first_batch: Option<Vec<(Bytes, Bytes)>>,
}

enum ReplayProgress {
    Frame(SubscribeResponse),
    Advanced,
    Done,
}

enum LiveProgress {
    Frame(SubscribeResponse),
    Advanced,
    NeedWait,
}

struct SubscriptionState {
    state: StreamState,
    matchers: crate::stream::CompiledMatchers,
    replay: Option<ReplayState>,
    next_live_sequence: u64,
    live_notify: Arc<Notify>,
    terminated: bool,
}

impl SubscriptionState {
    fn new(
        state: StreamState,
        matchers: crate::stream::CompiledMatchers,
        replay: Option<ReplayState>,
        next_live_sequence: u64,
        live_notify: Arc<Notify>,
    ) -> Self {
        Self {
            state,
            matchers,
            replay,
            next_live_sequence,
            live_notify,
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
                        Err(err) => {
                            state.terminated = true;
                            return Some((Err(err), state));
                        }
                    }
                }

                match state.next_live_frame().await {
                    Ok(LiveProgress::Frame(frame)) => return Some((Ok(frame), state)),
                    Ok(LiveProgress::Advanced) => continue,
                    Ok(LiveProgress::NeedWait) => {
                        state.wait_for_live().await;
                    }
                    Err(err) => {
                        state.terminated = true;
                        return Some((Err(err), state));
                    }
                }
            }
        }))
    }

    async fn next_replay_frame(&mut self) -> Result<ReplayProgress, ConnectError> {
        let Some(replay) = &mut self.replay else {
            return Ok(ReplayProgress::Done);
        };
        let seq = replay.next_sequence;
        let kvs = if let Some(first_batch) = replay.first_batch.take() {
            Some(first_batch)
        } else {
            self.state
                .batch_log
                .get_batch(seq)
                .await
                .map_err(ConnectError::internal)?
        };
        replay.next_sequence += 1;
        if replay.next_sequence > replay.bound {
            self.replay = None;
        }
        let Some(kvs) = kvs else {
            let oldest = self
                .state
                .batch_log
                .oldest_retained_batch()
                .await
                .map_err(ConnectError::internal)?;
            return Err(StreamConnect::batch_evicted_connect_error(oldest));
        };
        Ok(
            match filtered_subscribe_response(seq, &kvs, &self.matchers) {
                Some(frame) => ReplayProgress::Frame(frame),
                None => ReplayProgress::Advanced,
            },
        )
    }

    async fn next_live_frame(&mut self) -> Result<LiveProgress, ConnectError> {
        let current = self.state.notifier.current_sequence();
        if self.next_live_sequence > current {
            return Ok(LiveProgress::NeedWait);
        }
        let seq = self.next_live_sequence;
        self.next_live_sequence += 1;
        let kvs = self
            .state
            .batch_log
            .get_batch(seq)
            .await
            .map_err(ConnectError::internal)?;
        let Some(kvs) = kvs else {
            let oldest = self
                .state
                .batch_log
                .oldest_retained_batch()
                .await
                .map_err(ConnectError::internal)?;
            return Err(StreamConnect::batch_evicted_connect_error(oldest));
        };
        Ok(
            match filtered_subscribe_response(seq, &kvs, &self.matchers) {
                Some(frame) => LiveProgress::Frame(frame),
                None => LiveProgress::Advanced,
            },
        )
    }

    async fn wait_for_live(&self) {
        if self.next_live_sequence <= self.state.notifier.current_sequence() {
            return;
        }
        let notified = self.live_notify.clone().notified_owned();
        if self.next_live_sequence <= self.state.notifier.current_sequence() {
            return;
        }
        notified.await;
    }
}

fn domain_filter_from_subscribe_view(
    req: &SubscribeRequestView<'_>,
) -> Result<StreamFilter, ConnectError> {
    let mut match_keys = Vec::with_capacity(req.match_keys.len());
    for mk in req.match_keys.iter() {
        let reserved_bits = u8::try_from(mk.reserved_bits).map_err(|_| {
            ConnectError::invalid_argument(format!(
                "match_key.reserved_bits {} does not fit in u8",
                mk.reserved_bits
            ))
        })?;
        let prefix = u16::try_from(mk.prefix).map_err(|_| {
            ConnectError::invalid_argument(format!(
                "match_key.prefix {} does not fit in u16",
                mk.prefix
            ))
        })?;
        match_keys.push(MatchKey {
            reserved_bits,
            prefix,
            payload_regex: exoware_sdk::kv_codec::Utf8::from(mk.payload_regex),
        });
    }
    let mut value_filters = Vec::with_capacity(req.value_filters.len());
    for vf in req.value_filters.iter() {
        value_filters.push(match vf.kind {
            Some(ProtoBytesFilterKindView::Exact(bytes)) => BytesFilter::Exact(bytes.to_vec()),
            Some(ProtoBytesFilterKindView::Prefix(bytes)) => BytesFilter::Prefix(bytes.to_vec()),
            Some(ProtoBytesFilterKindView::Regex(pattern)) => {
                BytesFilter::Regex(pattern.to_string())
            }
            None => {
                return Err(ConnectError::invalid_argument(
                    "each value_filter must set exactly one of exact, prefix, or regex",
                ))
            }
        });
    }
    Ok(StreamFilter {
        match_keys,
        value_filters,
    })
}

impl StreamApi for StreamConnect {
    async fn subscribe(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<SubscribeRequestView<'static>>,
    ) -> Result<
        (
            Pin<Box<dyn Stream<Item = Result<SubscribeResponse, ConnectError>> + Send>>,
            Context,
        ),
        ConnectError,
    > {
        let filter = domain_filter_from_subscribe_view(&request)?;
        let since = request.since_sequence_number;

        // Snapshot the current published frontier and subscribe for future
        // wakeups. The stream then walks the batch log by sequence cursor, so
        // live delivery is paced by client reads instead of server-side
        // buffering.
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
                    .batch_log
                    .get_batch(s)
                    .await
                    .map_err(ConnectError::internal)?;
                let Some(first_batch) = first_batch else {
                    let oldest = self
                        .state
                        .batch_log
                        .oldest_retained_batch()
                        .await
                        .map_err(ConnectError::internal)?;
                    return Err(self.batch_evicted_error(oldest));
                };
                Some(ReplayState {
                    next_sequence: s,
                    bound: replay_bound,
                    first_batch: Some(first_batch),
                })
            }
            _ => None,
        };
        let next_live_sequence = replay_bound.saturating_add(1);

        Ok((
            SubscriptionState::new(
                self.state.clone(),
                matchers,
                replay,
                next_live_sequence,
                live_notify,
            )
            .into_stream(),
            ctx,
        ))
    }

    async fn get(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<GetRequestView<'static>>,
    ) -> Result<(StreamGetResponse, Context), ConnectError> {
        let seq = request.sequence_number;
        match self
            .state
            .batch_log
            .get_batch(seq)
            .await
            .map_err(ConnectError::internal)?
        {
            Some(kvs) => {
                let entries = kvs
                    .into_iter()
                    .map(|(k, v)| KvEntry {
                        key: k.to_vec(),
                        value: v.to_vec(),
                        ..Default::default()
                    })
                    .collect();
                Ok((
                    StreamGetResponse {
                        sequence_number: seq,
                        entries,
                        ..Default::default()
                    },
                    ctx,
                ))
            }
            None => {
                let current = self.state.batch_log.current_sequence();
                // Distinguish "never existed" (seq > current) vs "evicted".
                if seq > current {
                    Err(self.batch_not_found_error())
                } else {
                    let oldest = self
                        .state
                        .batch_log
                        .oldest_retained_batch()
                        .await
                        .map_err(ConnectError::internal)?;
                    Err(self.batch_evicted_error(oldest))
                }
            }
        }
    }
}

fn connect_limits() -> Limits {
    Limits::default()
        .max_request_body_size(MAX_CONNECTRPC_BODY_BYTES)
        .max_message_size(MAX_CONNECTRPC_BODY_BYTES)
}

pub type IngestService = ConnectRpcService<IngestServiceServer<IngestConnect>>;
pub type QueryService = ConnectRpcService<QueryServiceServer<QueryConnect>>;
pub type CompactService = ConnectRpcService<CompactServiceServer<CompactConnect>>;
pub type StreamService = ConnectRpcService<StreamServiceServer<StreamConnect>>;
pub type QueryStack =
    ConnectRpcService<Chain<QueryServiceServer<QueryConnect>, StreamServiceServer<StreamConnect>>>;
pub type ConnectStack = ConnectRpcService<
    Chain<
        IngestServiceServer<IngestConnect>,
        Chain<
            QueryServiceServer<QueryConnect>,
            Chain<CompactServiceServer<CompactConnect>, StreamServiceServer<StreamConnect>>,
        >,
    >,
>;

fn ingest_server(state: IngestState) -> IngestServiceServer<IngestConnect> {
    IngestServiceServer::new(IngestConnect::new(state))
}

fn query_server(state: QueryState) -> QueryServiceServer<QueryConnect> {
    QueryServiceServer::new(QueryConnect::new(state))
}

fn compact_server(state: CompactState) -> CompactServiceServer<CompactConnect> {
    CompactServiceServer::new(CompactConnect::new(state))
}

fn stream_server(state: StreamState) -> StreamServiceServer<StreamConnect> {
    StreamServiceServer::new(StreamConnect::new(state))
}

pub fn ingest_service(state: IngestState) -> IngestService {
    ConnectRpcService::new(ingest_server(state))
        .with_limits(connect_limits())
        .with_compression(connect_compression_registry())
}

pub fn query_service(state: QueryState) -> QueryService {
    ConnectRpcService::new(query_server(state))
        .with_limits(connect_limits())
        .with_compression(connect_compression_registry())
}

pub fn compact_service(state: CompactState) -> CompactService {
    ConnectRpcService::new(compact_server(state))
        .with_limits(connect_limits())
        .with_compression(connect_compression_registry())
}

pub fn stream_service(state: StreamState) -> StreamService {
    ConnectRpcService::new(stream_server(state))
        .with_limits(connect_limits())
        .with_compression(connect_compression_registry())
}

pub fn query_stack(query_state: QueryState, stream_state: StreamState) -> QueryStack {
    ConnectRpcService::new(Chain(
        query_server(query_state),
        stream_server(stream_state),
    ))
    .with_limits(connect_limits())
    .with_compression(connect_compression_registry())
}

pub fn connect_stack(state: AppState) -> ConnectStack {
    ConnectRpcService::new(Chain(
        ingest_server(state.clone().into()),
        Chain(
            query_server(state.clone().into()),
            Chain(
                compact_server(state.clone().into()),
                stream_server(state.into()),
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
    use std::sync::atomic::AtomicU64;
    use std::sync::Mutex;
    use std::time::Duration;

    use buffa::Message;
    use exoware_proto::store::common::v1::MatchKey as ProtoMatchKey;
    use exoware_proto::store::compact::v1::{
        policy, policy_retain, Policy as ProtoPolicy, PolicyRetain, PruneRequest, PruneRequestView,
        RetainDropAll,
    };
    use exoware_proto::store::stream::v1::{SubscribeRequest, SubscribeRequestView};
    use exoware_sdk::keys::KeyCodec;
    use exoware_sdk::kv_codec::KvReducedValue;
    use exoware_sdk::{decode_connect_error, to_domain_reduce_response};
    use futures::future::ready;
    use futures::StreamExt;

    use crate::{
        BatchLog, Ingest, Prune, Query, QueryExtra, RangeScan, RangeScanBatch, RangeScanCursor,
        RangeScanFuture, Sequence, StoreFuture, StreamNotification, StreamNotifier,
    };

    const TEST_RESERVED_BITS: u8 = 4;
    const TEST_PREFIX: u16 = 1;

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
        range_next_count: usize,
        query_extra: QueryExtra,
        prune_policy_counts: Vec<usize>,
    }

    #[derive(Default)]
    struct FakeEngine {
        state: Arc<Mutex<FakeEngineState>>,
    }

    struct IteratorRangeScan {
        iter: Box<dyn Iterator<Item = Result<(Bytes, Bytes), String>> + Send + 'static>,
    }

    impl RangeScan for IteratorRangeScan {
        fn next_batch<'a>(&'a mut self, max_items: usize) -> RangeScanFuture<'a, RangeScanBatch> {
            let mut rows = Vec::new();
            let result = (|| {
                for row in self.iter.by_ref().take(max_items) {
                    rows.push(row?);
                }
                Ok(RangeScanBatch {
                    rows,
                    extra: QueryExtra::default(),
                })
            })();
            Box::pin(ready(result))
        }
    }

    fn range_scan_from_iter<I>(iter: I) -> RangeScanCursor
    where
        I: Iterator<Item = Result<(Bytes, Bytes), String>> + Send + 'static,
    {
        Box::new(IteratorRangeScan {
            iter: Box::new(iter),
        })
    }

    impl FakeEngine {
        fn set_current_sequence(&self, sequence_number: u64) {
            self.state.lock().expect("lock").current_sequence = sequence_number;
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

        fn range_next_count(&self) -> usize {
            self.state.lock().expect("lock").range_next_count
        }

        fn set_query_extra(&self, extra: QueryExtra) {
            self.state.lock().expect("lock").query_extra = extra;
        }
    }

    impl Sequence for FakeEngine {
        fn current_sequence(&self) -> u64 {
            self.state.lock().expect("lock").current_sequence
        }
    }

    impl Ingest for FakeEngine {
        fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> StoreFuture<u64> {
            let result = (|| {
                let mut state = self.state.lock().map_err(|e| e.to_string())?;
                state.current_sequence += 1;
                let seq = state.current_sequence;
                state.batches.insert(seq, Some(kvs));
                Ok(seq)
            })();
            Box::pin(ready(result))
        }
    }

    impl Query for FakeEngine {
        fn get(&self, _key: Bytes) -> StoreFuture<(Option<Vec<u8>>, QueryExtra)> {
            let result = self
                .state
                .lock()
                .map(|state| (None, state.query_extra.clone()))
                .map_err(|e| e.to_string());
            Box::pin(ready(result))
        }

        fn get_many(
            &self,
            keys: Vec<Bytes>,
        ) -> StoreFuture<(Vec<(Vec<u8>, Option<Vec<u8>>)>, QueryExtra)> {
            let result = self
                .state
                .lock()
                .map(|state| {
                    let entries = keys.into_iter().map(|key| (key.to_vec(), None)).collect();
                    (entries, state.query_extra.clone())
                })
                .map_err(|e| e.to_string());
            Box::pin(ready(result))
        }

        fn range_scan(
            &self,
            _start: Bytes,
            _end: Bytes,
            _limit: usize,
            _forward: bool,
        ) -> StoreFuture<RangeScanCursor> {
            let result = self
                .state
                .lock()
                .map(|state| state.range_rows.clone())
                .map_err(|e| e.to_string());
            let state = self.state.clone();
            let cursor = result.map(|rows| {
                range_scan_from_iter(rows.into_iter().map(move |row| {
                    state.lock().expect("lock").range_next_count += 1;
                    Ok(row)
                }))
            });
            Box::pin(ready(cursor))
        }
    }

    impl Prune for FakeEngine {
        fn apply_prune_policies(&self, policies: Vec<ProtoPolicy>) -> StoreFuture<()> {
            let result = self
                .state
                .lock()
                .map(|mut state| {
                    state.prune_policy_counts.push(policies.len());
                })
                .map_err(|e| e.to_string());
            Box::pin(ready(result))
        }
    }

    impl BatchLog for FakeEngine {
        fn get_batch(&self, sequence_number: u64) -> StoreFuture<Option<Vec<(Bytes, Bytes)>>> {
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
            let (publish, batch) = match result {
                Ok(values) => values,
                Err(e) => return Box::pin(ready(Err(e))),
            };
            if let Some(publish) = publish {
                publish
                    .hub
                    .publish(publish.sequence_offset + sequence_number);
            }
            Box::pin(ready(Ok(batch)))
        }

        fn oldest_retained_batch(&self) -> StoreFuture<Option<u64>> {
            let result = self
                .state
                .lock()
                .map(|state| state.oldest_retained)
                .map_err(|e| e.to_string());
            Box::pin(ready(result))
        }
    }

    struct QueryOnlyEngine {
        sequence_number: u64,
        value: Option<Vec<u8>>,
    }

    impl Sequence for QueryOnlyEngine {
        fn current_sequence(&self) -> u64 {
            self.sequence_number
        }
    }

    impl Query for QueryOnlyEngine {
        fn get(&self, _key: Bytes) -> StoreFuture<(Option<Vec<u8>>, QueryExtra)> {
            Box::pin(ready(Ok((self.value.clone(), QueryExtra::default()))))
        }

        fn range_scan(
            &self,
            _start: Bytes,
            _end: Bytes,
            _limit: usize,
            _forward: bool,
        ) -> StoreFuture<RangeScanCursor> {
            Box::pin(ready(Ok(range_scan_from_iter(std::iter::empty()))))
        }

        fn get_many(
            &self,
            keys: Vec<Bytes>,
        ) -> StoreFuture<(Vec<(Vec<u8>, Option<Vec<u8>>)>, QueryExtra)> {
            Box::pin(ready(Ok((
                keys.into_iter().map(|key| (key.to_vec(), None)).collect(),
                QueryExtra::default(),
            ))))
        }
    }

    #[derive(Default)]
    struct PruneOnlyEngine {
        policy_counts: Mutex<Vec<usize>>,
    }

    impl PruneOnlyEngine {
        fn applied_count(&self) -> usize {
            self.policy_counts.lock().expect("lock").len()
        }
    }

    impl Prune for PruneOnlyEngine {
        fn apply_prune_policies(&self, policies: Vec<ProtoPolicy>) -> StoreFuture<()> {
            let result = self
                .policy_counts
                .lock()
                .map(|mut counts| {
                    counts.push(policies.len());
                })
                .map_err(|e| e.to_string());
            Box::pin(ready(result))
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
        let codec = KeyCodec::new(TEST_RESERVED_BITS, TEST_PREFIX);
        let key = codec.encode(payload).expect("encode key");
        (
            Bytes::copy_from_slice(key.as_ref()),
            Bytes::copy_from_slice(value),
        )
    }

    fn subscribe_request_bytes(since_sequence_number: Option<u64>) -> Vec<u8> {
        SubscribeRequest {
            match_keys: vec![ProtoMatchKey {
                reserved_bits: u32::from(TEST_RESERVED_BITS),
                prefix: u32::from(TEST_PREFIX),
                payload_regex: "(?s).*".to_string(),
                ..Default::default()
            }],
            since_sequence_number,
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn sequence_drop_all_policy() -> ProtoPolicy {
        ProtoPolicy {
            scope: Some(policy::Scope::Sequence(Box::default())),
            retain: Some(PolicyRetain {
                kind: Some(policy_retain::Kind::DropAll(Box::new(
                    RetainDropAll::default(),
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

    async fn subscribe_stream(
        connect: &StreamConnect,
        since_sequence_number: Option<u64>,
    ) -> Result<
        Pin<Box<dyn Stream<Item = Result<SubscribeResponse, ConnectError>> + Send>>,
        ConnectError,
    > {
        let bytes = subscribe_request_bytes(since_sequence_number);
        let request = buffa::view::OwnedView::<SubscribeRequestView<'static>>::decode(bytes.into())
            .expect("decode subscribe request");
        let (stream, _ctx) = StreamApi::subscribe(connect, Context::default(), request).await?;
        Ok(stream)
    }

    #[tokio::test]
    async fn compact_connect_accepts_prune_only_engine() {
        let prune = Arc::new(PruneOnlyEngine::default());
        let connect = CompactConnect::new(CompactState::new(prune.clone()));
        let request = prune_request(vec![sequence_drop_all_policy()]);

        CompactApi::prune(&connect, Context::default(), request)
            .await
            .expect("prune");

        assert_eq!(prune.applied_count(), 1);
    }

    #[tokio::test]
    async fn compact_validates_before_engine_prune() {
        let prune = Arc::new(PruneOnlyEngine::default());
        let connect = CompactConnect::new(CompactState::new(prune.clone()));
        let invalid_policy = ProtoPolicy {
            scope: Some(policy::Scope::Sequence(Box::default())),
            ..Default::default()
        };
        let request = prune_request(vec![invalid_policy]);

        let err = CompactApi::prune(&connect, Context::default(), request)
            .await
            .expect_err("invalid prune");

        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
        assert_eq!(prune.applied_count(), 0);
    }

    #[tokio::test]
    async fn query_connect_accepts_query_only_engine() {
        let query: Arc<dyn Query> = Arc::new(QueryOnlyEngine {
            sequence_number: 9,
            value: Some(b"value".to_vec()),
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

        let (response, _ctx) = QueryApi::get(&connect, Context::default(), request)
            .await
            .expect("get");
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

        let (response, _ctx) = QueryApi::get(&connect, Context::default(), request)
            .await
            .expect("get");
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
        let _compact = compact_service(state.clone().into());
        let _stream = stream_service(state.clone().into());
        let _query_stack = query_stack(state.clone().into(), state.into());
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
        assert_eq!(frame.entries[0].value.as_slice(), b"v1");
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

        let (response, _ctx) = QueryApi::reduce(&connect, Context::default(), request)
            .await
            .expect("reduce");
        let detail = response.detail.as_option().expect("query detail").clone();
        let response = to_domain_reduce_response(response).expect("decode reduce response");

        assert_eq!(engine.range_next_count(), 2);
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].value, Some(KvReducedValue::UInt64(2)));
        assert_eq!(detail.sequence_number, 7);
        assert!(detail.extra.is_empty());
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

        let (mut stream, _ctx) = QueryApi::get_many(&connect, Context::default(), request)
            .await
            .expect("get_many");
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

        let (mut stream, _ctx) = QueryApi::range(&connect, Context::default(), request)
            .await
            .expect("range");

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
        assert_eq!(frame.entries[0].value.as_slice(), b"v1");
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
        assert_eq!(frame.entries[0].value.as_slice(), b"n");
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
