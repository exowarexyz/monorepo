//! Ingest, query, and compact services; storage is provided by [`crate::StoreEngine`].

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

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
    connect_compression_registry, encode_query_detail_header_value,
    parse_range_traversal_direction, to_domain_reduce_request_from_view,
    to_proto_optional_reduced_value, to_proto_reduced_value, with_error_info_detail,
    with_query_detail, with_retry_info_detail, RangeTraversalDirection,
    QUERY_DETAIL_RESPONSE_HEADER,
};
use exoware_sdk as exoware_proto;
use exoware_sdk::keys::Key;
use exoware_sdk::match_key::MatchKey;
use exoware_sdk::store::common::v1::bytes_filter::KindView as ProtoBytesFilterKindView;
use futures::{stream as stream_util, Stream};
use http::header::HeaderValue;
use http::HeaderName;
use tokio::sync::futures::OwnedNotified;
use tokio::sync::Notify;

use crate::reduce::RangeReducer;
use crate::stream::StreamHub;
use crate::validate;
use crate::StoreEngine;

const MAX_CONNECTRPC_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Total bytes of keys plus values for entries read from the store (reference RocksDB engine).
fn read_bytes_for_kv<K: AsRef<[u8]>, V: AsRef<[u8]>>(key: &K, value: &V) -> u64 {
    key.as_ref().len() as u64 + value.as_ref().len() as u64
}

fn read_stats_read_bytes(read_bytes: u64) -> HashMap<String, u64> {
    [("read_bytes".to_string(), read_bytes)]
        .into_iter()
        .collect()
}

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<dyn StoreEngine>,
    /// Gates ingest (writes) only. Query and compact remain available during drains so that
    /// in-flight reads can complete while the worker sheds write traffic.
    pub ready: Arc<AtomicBool>,
    /// Shared fan-out hub for `store.stream.v1.Subscribe`. `IngestConnect::put`
    /// calls `publish` on successful commit so subscribers receive exactly
    /// the rows that landed in the engine.
    pub stream: Arc<StreamHub>,
}

impl AppState {
    pub fn new(engine: Arc<dyn StoreEngine>) -> Self {
        let current_sequence = engine.current_sequence();
        Self {
            engine,
            ready: Arc::new(AtomicBool::new(true)),
            stream: Arc::new(StreamHub::new(current_sequence)),
        }
    }
}

#[derive(Clone)]
pub struct IngestConnect {
    state: AppState,
}

impl IngestConnect {
    pub fn new(state: AppState) -> Self {
        Self { state }
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
        let mut batch = Vec::new();
        for kv in request.kvs.iter() {
            let key: Key = wire.slice_ref(kv.key);
            let value = wire.slice_ref(kv.value);
            batch.push((key, value));
        }

        let seq = self
            .state
            .engine
            .put_batch(&batch)
            .map_err(ConnectError::internal)?;

        // Fan out the just-committed batch to stream subscribers. `publish`
        // only announces the new sequence number; subscribers pull the batch
        // from the engine at their own pace.
        self.state.stream.publish(seq);

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
    state: AppState,
}

impl QueryConnect {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    fn current_sequence_number(&self) -> u64 {
        self.state.engine.current_sequence()
    }

    fn error_detail(&self) -> Detail {
        Detail {
            sequence_number: self.current_sequence_number(),
            read_stats: HashMap::new(),
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

    fn apply_query_detail_header(ctx: &mut Context, detail: &Detail) {
        if let Ok(value) = HeaderValue::from_str(&encode_query_detail_header_value(detail)) {
            if let Ok(name) = HeaderName::from_bytes(QUERY_DETAIL_RESPONSE_HEADER.as_bytes()) {
                ctx.response_headers.insert(name, value);
            }
        }
    }

    fn apply_query_detail_trailer(ctx: &mut Context, detail: &Detail) {
        if let Ok(value) = HeaderValue::from_str(&encode_query_detail_header_value(detail)) {
            if let Ok(name) = HeaderName::from_bytes(QUERY_DETAIL_RESPONSE_HEADER.as_bytes()) {
                ctx.set_trailer(name, value);
            }
        }
    }
}

impl QueryApi for QueryConnect {
    async fn get(
        &self,
        mut ctx: Context,
        request: buffa::view::OwnedView<exoware_proto::store::query::v1::GetRequestView<'static>>,
    ) -> Result<(GetResponse, Context), ConnectError> {
        validate::validate_get_request(&request)?;
        let token = self.ensure_min_sequence_number(request.min_sequence_number)?;
        let wire = request.bytes();
        let key: Key = wire.slice_ref(request.key);
        let value = self
            .state
            .engine
            .get(key.as_ref())
            .map_err(ConnectError::internal)?;
        let read_bytes =
            key.as_ref().len() as u64 + value.as_ref().map_or(0u64, |v| v.len() as u64);
        let detail = Detail {
            sequence_number: token,
            read_stats: [("read_bytes".to_string(), read_bytes)]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        Self::apply_query_detail_header(&mut ctx, &detail);
        Ok((
            GetResponse {
                value,
                ..Default::default()
            },
            ctx,
        ))
    }

    async fn get_many(
        &self,
        mut ctx: Context,
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

        let key_refs: Vec<&[u8]> = request.keys.iter().copied().collect();
        let entries = self
            .state
            .engine
            .get_many(&key_refs)
            .map_err(ConnectError::internal)?;
        let read_bytes: u64 = entries
            .iter()
            .map(|(k, v)| k.len() as u64 + v.as_ref().map_or(0u64, |v| v.len() as u64))
            .sum();
        let detail = Detail {
            sequence_number,
            read_stats: [("read_bytes".to_string(), read_bytes)]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        Self::apply_query_detail_trailer(&mut ctx, &detail);

        let batch_size = request.batch_size as usize;
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
                    ..Default::default()
                }));
            }
        }
        if !chunk.is_empty() {
            frames.push(Ok(GetManyFrame {
                results: chunk,
                ..Default::default()
            }));
        }

        Ok((Box::pin(stream_util::iter(frames)), ctx))
    }

    async fn range(
        &self,
        mut ctx: Context,
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
        let batch_size = request.batch_size as usize;
        let forward = match parse_range_traversal_direction(request.mode) {
            Ok(RangeTraversalDirection::Forward) => true,
            Ok(RangeTraversalDirection::Reverse) => false,
            Err(e) => return Err(ConnectError::internal(format!("traversal mode: {e:?}"))),
        };

        let entries = self
            .state
            .engine
            .range_scan(start_key.as_ref(), end_key.as_ref(), limit, forward)
            .map_err(ConnectError::internal)?;

        let mut read_bytes = 0u64;
        let mut frames = Vec::new();
        let mut chunk = Vec::new();
        for row in entries {
            let (key, value) = row.map_err(ConnectError::internal)?;
            read_bytes += read_bytes_for_kv(&key, &value);
            chunk.push(KvEntry {
                key: key.into(),
                value: value.into(),
                ..Default::default()
            });
            if chunk.len() >= batch_size {
                frames.push(Ok(RangeFrame {
                    results: std::mem::take(&mut chunk),
                    ..Default::default()
                }));
            }
        }
        if !chunk.is_empty() {
            frames.push(Ok(RangeFrame {
                results: chunk,
                ..Default::default()
            }));
        }

        let detail = Detail {
            sequence_number,
            read_stats: read_stats_read_bytes(read_bytes),
            ..Default::default()
        };
        Self::apply_query_detail_trailer(&mut ctx, &detail);

        Ok((Box::pin(stream_util::iter(frames)), ctx))
    }

    async fn reduce(
        &self,
        mut ctx: Context,
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

        let rows = self
            .state
            .engine
            .range_scan(start_key.as_ref(), end_key.as_ref(), usize::MAX, true)
            .map_err(ConnectError::internal)?;

        let mut reducer = RangeReducer::new(&domain)
            .map_err(|e: crate::RangeError| ConnectError::internal(e.to_string()))?;
        let mut read_bytes = 0u64;
        for row in rows {
            let (key, value) = row.map_err(ConnectError::internal)?;
            read_bytes += read_bytes_for_kv(&key, &value);
            reducer
                .update(&key, &value)
                .map_err(|e: crate::RangeError| ConnectError::internal(e.to_string()))?;
        }
        let response = reducer.finish();

        // Reduce is unary, so headers can include stats computed while consuming the iterator.
        let detail = Detail {
            sequence_number: token,
            read_stats: read_stats_read_bytes(read_bytes),
            ..Default::default()
        };
        Self::apply_query_detail_header(&mut ctx, &detail);

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
                ..Default::default()
            },
            ctx,
        ))
    }
}

#[derive(Clone)]
pub struct CompactConnect {
    state: AppState,
}

impl CompactConnect {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
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
        let document = exoware_proto::prune_policy_document_from_prune_request_view(&request)
            .map_err(|e| ConnectError::invalid_argument(e.to_string()))?;
        crate::prune::execute_prune(&self.state.engine, &document)
            .map_err(|e| ConnectError::internal(e.to_string()))?;
        Ok((PruneResponse::default(), ctx))
    }
}

#[derive(Clone)]
pub struct StreamConnect {
    state: AppState,
}

impl StreamConnect {
    pub fn new(state: AppState) -> Self {
        Self { state }
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

struct SubscriptionStream {
    state: AppState,
    matchers: crate::stream::CompiledMatchers,
    replay: Option<ReplayState>,
    next_live_sequence: u64,
    live_notify: Arc<Notify>,
    live_wait: Option<Pin<Box<OwnedNotified>>>,
    terminal_error: Option<ConnectError>,
    terminated: bool,
}

impl SubscriptionStream {
    fn new(
        state: AppState,
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
            live_wait: None,
            terminal_error: None,
            terminated: false,
        }
    }

    fn next_replay_frame(&mut self) -> Result<ReplayProgress, ConnectError> {
        let Some(replay) = &mut self.replay else {
            return Ok(ReplayProgress::Done);
        };
        let seq = replay.next_sequence;
        let kvs = if let Some(first_batch) = replay.first_batch.take() {
            Some(first_batch)
        } else {
            self.state
                .engine
                .get_batch(seq)
                .map_err(ConnectError::internal)?
        };
        replay.next_sequence += 1;
        if replay.next_sequence > replay.bound {
            self.replay = None;
        }
        let Some(kvs) = kvs else {
            let oldest = self
                .state
                .engine
                .oldest_retained_batch()
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

    fn next_live_frame(&mut self) -> Result<LiveProgress, ConnectError> {
        let current = self.state.stream.current_sequence();
        if self.next_live_sequence > current {
            return Ok(LiveProgress::NeedWait);
        }
        let seq = self.next_live_sequence;
        self.next_live_sequence += 1;
        let kvs = self
            .state
            .engine
            .get_batch(seq)
            .map_err(ConnectError::internal)?;
        let Some(kvs) = kvs else {
            let oldest = self
                .state
                .engine
                .oldest_retained_batch()
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
}

impl Stream for SubscriptionStream {
    type Item = Result<SubscribeResponse, ConnectError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(err) = self.terminal_error.take() {
                self.terminated = true;
                return Poll::Ready(Some(Err(err)));
            }
            if self.terminated {
                return Poll::Ready(None);
            }

            if self.replay.is_some() {
                match self.next_replay_frame() {
                    Ok(ReplayProgress::Frame(frame)) => return Poll::Ready(Some(Ok(frame))),
                    Ok(ReplayProgress::Advanced) => continue,
                    Ok(ReplayProgress::Done) => {}
                    Err(err) => {
                        self.terminal_error = Some(err);
                        continue;
                    }
                }
            }

            match self.next_live_frame() {
                Ok(LiveProgress::Frame(frame)) => return Poll::Ready(Some(Ok(frame))),
                Ok(LiveProgress::Advanced) => continue,
                Ok(LiveProgress::NeedWait) => {
                    if self.live_wait.is_none() {
                        self.live_wait = Some(Box::pin(self.live_notify.clone().notified_owned()));
                    }
                    if self.next_live_sequence <= self.state.stream.current_sequence() {
                        self.live_wait = None;
                        continue;
                    }
                    match self
                        .live_wait
                        .as_mut()
                        .expect("wait future")
                        .as_mut()
                        .poll(cx)
                    {
                        Poll::Ready(()) => {
                            self.live_wait = None;
                            continue;
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Err(err) => {
                    self.terminal_error = Some(err);
                    continue;
                }
            }
        }
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
        let (matchers, replay_bound, live_notify) = self.state.stream.subscribe(filter)?;

        // Optional replay. Validate the starting batch eagerly so an
        // already-evicted cursor fails the RPC immediately; later replay holes
        // are surfaced on the stream itself so callers reconnect from a safe
        // point instead of silently continuing.
        let replay = match since {
            Some(s) if s <= replay_bound && s > 0 => {
                let first_batch = self
                    .state
                    .engine
                    .get_batch(s)
                    .map_err(ConnectError::internal)?;
                let Some(first_batch) = first_batch else {
                    let oldest = self
                        .state
                        .engine
                        .oldest_retained_batch()
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
            Box::pin(SubscriptionStream::new(
                self.state.clone(),
                matchers,
                replay,
                next_live_sequence,
                live_notify,
            )),
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
            .engine
            .get_batch(seq)
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
                let current = self.state.engine.current_sequence();
                // Distinguish "never existed" (seq > current) vs "evicted".
                if seq > current {
                    Err(self.batch_not_found_error())
                } else {
                    let oldest = self
                        .state
                        .engine
                        .oldest_retained_batch()
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

pub fn connect_stack(
    state: AppState,
) -> ConnectRpcService<
    Chain<
        IngestServiceServer<IngestConnect>,
        Chain<
            QueryServiceServer<QueryConnect>,
            Chain<CompactServiceServer<CompactConnect>, StreamServiceServer<StreamConnect>>,
        >,
    >,
> {
    ConnectRpcService::new(Chain(
        IngestServiceServer::new(IngestConnect::new(state.clone())),
        Chain(
            QueryServiceServer::new(QueryConnect::new(state.clone())),
            Chain(
                CompactServiceServer::new(CompactConnect::new(state.clone())),
                StreamServiceServer::new(StreamConnect::new(state)),
            ),
        ),
    ))
    .with_limits(connect_limits())
    .with_compression(connect_compression_registry())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::time::Duration;

    use buffa::Message;
    use exoware_proto::store::common::v1::MatchKey as ProtoMatchKey;
    use exoware_proto::store::stream::v1::{SubscribeRequest, SubscribeRequestView};
    use exoware_sdk::keys::KeyCodec;
    use exoware_sdk::kv_codec::KvReducedValue;
    use exoware_sdk::{
        decode_connect_error, decode_query_detail_header_value, to_domain_reduce_response,
    };
    use futures::StreamExt;

    use crate::RangeScanIter;

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
    }

    #[derive(Default)]
    struct FakeEngine {
        state: Mutex<FakeEngineState>,
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
    }

    impl StoreEngine for FakeEngine {
        fn put_batch(&self, kvs: &[(Bytes, Bytes)]) -> Result<u64, String> {
            let mut state = self.state.lock().map_err(|e| e.to_string())?;
            state.current_sequence += 1;
            let seq = state.current_sequence;
            state.batches.insert(seq, Some(kvs.to_vec()));
            Ok(seq)
        }

        fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }

        fn range_scan(
            &self,
            _start: &[u8],
            _end: &[u8],
            _limit: usize,
            _forward: bool,
        ) -> Result<RangeScanIter<'_>, String> {
            let rows = self
                .state
                .lock()
                .map_err(|e| e.to_string())?
                .range_rows
                .clone();
            let state = &self.state;
            Ok(Box::new(rows.into_iter().map(move |row| {
                state.lock().expect("lock").range_next_count += 1;
                Ok(row)
            })))
        }

        fn delete_batch(&self, _keys: &[&[u8]]) -> Result<u64, String> {
            let mut state = self.state.lock().map_err(|e| e.to_string())?;
            state.current_sequence += 1;
            Ok(state.current_sequence)
        }

        fn current_sequence(&self) -> u64 {
            self.state.lock().expect("lock").current_sequence
        }

        fn get_batch(&self, sequence_number: u64) -> Result<Option<Vec<(Bytes, Bytes)>>, String> {
            let (publish, batch) = {
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
                (
                    publish,
                    state.batches.get(&sequence_number).cloned().unwrap_or(None),
                )
            };
            if let Some(publish) = publish {
                publish
                    .hub
                    .publish(publish.sequence_offset + sequence_number);
            }
            Ok(batch)
        }

        fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
            Ok(self
                .state
                .lock()
                .map_err(|e| e.to_string())?
                .oldest_retained)
        }

        fn prune_batch_log(&self, _cutoff_exclusive: u64) -> Result<u64, String> {
            Ok(0)
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
    async fn reduce_consumes_range_iterator_and_reports_read_bytes() {
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

        let (response, ctx) = QueryApi::reduce(&connect, Context::default(), request)
            .await
            .expect("reduce");
        let response = to_domain_reduce_response(response).expect("decode reduce response");

        assert_eq!(engine.range_next_count(), 2);
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].value, Some(KvReducedValue::UInt64(2)));

        let detail_value = ctx
            .response_headers
            .get(QUERY_DETAIL_RESPONSE_HEADER)
            .expect("query detail header")
            .to_str()
            .expect("query detail header string");
        let detail = decode_query_detail_header_value(detail_value).expect("decode detail");
        assert_eq!(detail.sequence_number, 7);
        assert_eq!(detail.read_stats.get("read_bytes"), Some(&8));
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
