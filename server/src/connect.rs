//! Ingest, query, and compact services; storage is provided by [`crate::StoreEngine`].

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use connectrpc::{Chain, ConnectError, ConnectRpcService, Context, Limits};
use exoware_proto::compact::{
    PruneResponse, Service as CompactApi, ServiceServer as CompactServiceServer,
};
use exoware_proto::google::rpc::{ErrorInfo, RetryInfo};
use exoware_proto::ingest::{
    PutResponse as ProtoPutResponse, Service as IngestApi, ServiceServer as IngestServiceServer,
};
use exoware_proto::query::{
    Detail, GetManyEntry, GetManyFrame, GetResponse, RangeEntry, RangeFrame, ReduceResponse,
    Service as QueryApi, ServiceServer as QueryServiceServer,
};
use exoware_proto::store::stream::v1::{
    GetBatchRequestView, Service as StreamApi, ServiceServer as StreamServiceServer, StreamEntry,
    StreamFrame, SubscribeRequestView,
};
use exoware_proto::stream_filter::StreamFilter;
use exoware_proto::{
    connect_compression_registry, encode_query_detail_header_value,
    parse_range_traversal_direction, to_domain_reduce_request_from_view,
    to_proto_optional_reduced_value, to_proto_reduced_value, with_error_info_detail,
    with_query_detail, with_retry_info_detail, RangeTraversalDirection,
    QUERY_DETAIL_RESPONSE_HEADER,
};
use exoware_sdk_rs as exoware_proto;
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::match_key::MatchKey;
use futures::{stream as stream_util, Stream, StreamExt};
use http::header::HeaderValue;
use http::HeaderName;
use tokio_stream::wrappers::ReceiverStream;

use crate::reduce::reduce_over_rows;
use crate::stream::StreamHub;
use crate::validate;
use crate::StoreEngine;

const MAX_CONNECTRPC_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Total bytes of keys plus values for entries read from the store (reference RocksDB engine).
fn read_bytes_for_kv_rows<K: AsRef<[u8]>, V: AsRef<[u8]>>(entries: &[(K, V)]) -> u64 {
    entries
        .iter()
        .map(|(k, v)| k.as_ref().len() as u64 + v.as_ref().len() as u64)
        .sum()
}

fn read_stats_read_bytes<K: AsRef<[u8]>, V: AsRef<[u8]>>(
    entries: &[(K, V)],
) -> HashMap<String, u64> {
    [("read_bytes".to_string(), read_bytes_for_kv_rows(entries))]
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
        Self {
            engine,
            ready: Arc::new(AtomicBool::new(true)),
            stream: Arc::new(StreamHub::new()),
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
        // short-circuits when there are no subscribers and uses `try_send`
        // internally so this never blocks ingest.
        self.state.stream.publish(seq, &batch);

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
        let detail = Detail {
            sequence_number,
            read_stats: read_stats_read_bytes(&entries),
            ..Default::default()
        };
        Self::apply_query_detail_trailer(&mut ctx, &detail);

        let mut frames = Vec::new();
        let mut chunk = Vec::new();
        for (key, value) in entries {
            chunk.push((key, value));
            if chunk.len() >= batch_size {
                frames.push(Ok(RangeFrame {
                    results: chunk
                        .drain(..)
                        .map(|(k, v)| RangeEntry {
                            key: k.into(),
                            value: v.into(),
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                }));
            }
        }
        if !chunk.is_empty() {
            frames.push(Ok(RangeFrame {
                results: chunk
                    .into_iter()
                    .map(|(k, v)| RangeEntry {
                        key: k.into(),
                        value: v.into(),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            }));
        }

        Ok((Box::pin(stream_util::iter(frames)), ctx))
    }

    async fn reduce(
        &self,
        mut ctx: Context,
        request: buffa::view::OwnedView<
            exoware_proto::store::query::v1::ReduceRequestView<'static>,
        >,
    ) -> Result<(ReduceResponse, Context), ConnectError> {
        validate::validate_reduce_request(&request)?; // proto-level; reduce_over_rows re-validates per-reducer constraints
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

        let response = reduce_over_rows(&rows, &domain)
            .map_err(|e: crate::RangeError| ConnectError::internal(e.to_string()))?;
        let detail = Detail {
            sequence_number: token,
            read_stats: read_stats_read_bytes(&rows),
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

    fn batch_evicted_error(&self, oldest_retained: Option<u64>) -> ConnectError {
        let mut metadata = HashMap::new();
        if let Some(v) = oldest_retained {
            metadata.insert("oldest_retained".to_string(), v.to_string());
        }
        with_error_info_detail(
            ConnectError::out_of_range("batch has been evicted from the log"),
            ErrorInfo {
                reason: "BATCH_EVICTED".to_string(),
                domain: "store.stream".to_string(),
                metadata,
                ..Default::default()
            },
        )
    }

    fn batch_not_found_error(&self) -> ConnectError {
        with_error_info_detail(
            ConnectError::not_found("batch not found"),
            ErrorInfo {
                reason: "BATCH_NOT_FOUND".to_string(),
                domain: "store.stream".to_string(),
                ..Default::default()
            },
        )
    }

    /// Build the replay portion of a `Subscribe` stream (seq in `since..=bound`).
    /// Applies the subscriber's own filter client-side-style on the server by
    /// running the compiled regexes against each `get_batch` row; returns a
    /// Vec of `StreamFrame`s ready to be prepended to the live channel.
    fn build_replay_frames(
        &self,
        since: u64,
        bound: u64,
        filter: &StreamFilter,
    ) -> Result<Vec<Result<StreamFrame, ConnectError>>, ConnectError> {
        let mut out = Vec::new();
        let compiled_matchers = compile_matchers(filter)?;
        for seq in since..=bound {
            match self
                .state
                .engine
                .get_batch(seq)
                .map_err(ConnectError::internal)?
            {
                Some(kvs) => {
                    let entries = filter_entries(&compiled_matchers, &kvs);
                    if !entries.is_empty() {
                        out.push(Ok(StreamFrame {
                            sequence_number: seq,
                            entries,
                            ..Default::default()
                        }));
                    }
                }
                None => {
                    // A gap inside [since, bound] is unexpected (those seq
                    // numbers were produced by THIS engine during replay).
                    // Emit EMPTY batches with no entries so we don't lie about
                    // sequence numbers, but keep strict monotonicity.
                    out.push(Ok(StreamFrame {
                        sequence_number: seq,
                        entries: Vec::new(),
                        ..Default::default()
                    }));
                }
            }
        }
        Ok(out)
    }
}

/// Small helper: compile a `StreamFilter` into `(KeyCodec, Regex)` pairs.
/// Used by `StreamConnect` replay so the same filter matching logic applies
/// to replayed frames as to live frames (which are handled inside `StreamHub`).
fn compile_matchers(
    filter: &StreamFilter,
) -> Result<Vec<(exoware_sdk_rs::keys::KeyCodec, regex::bytes::Regex)>, ConnectError> {
    let mut out = Vec::with_capacity(filter.match_keys.len());
    for mk in &filter.match_keys {
        let regex = exoware_sdk_rs::match_key::compile_payload_regex(&mk.payload_regex)
            .map_err(|e| ConnectError::invalid_argument(e.to_string()))?;
        let codec = exoware_sdk_rs::keys::KeyCodec::new(mk.reserved_bits, mk.prefix);
        out.push((codec, regex));
    }
    Ok(out)
}

fn filter_entries(
    matchers: &[(exoware_sdk_rs::keys::KeyCodec, regex::bytes::Regex)],
    kvs: &[(Bytes, Bytes)],
) -> Vec<StreamEntry> {
    let mut out = Vec::new();
    'outer: for (k, v) in kvs {
        for (codec, regex) in matchers {
            if !codec.matches(k) {
                continue;
            }
            let payload_len = codec.payload_capacity_bytes_for_key_len(k.len());
            let Ok(payload) = codec.read_payload(k, 0, payload_len) else {
                continue;
            };
            if regex.is_match(&payload) {
                out.push(StreamEntry {
                    key: k.to_vec(),
                    value: v.to_vec(),
                    ..Default::default()
                });
                continue 'outer;
            }
        }
    }
    out
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
            payload_regex: exoware_sdk_rs::kv_codec::Utf8::from(mk.payload_regex),
        });
    }
    Ok(StreamFilter { match_keys })
}

impl StreamApi for StreamConnect {
    async fn subscribe(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<SubscribeRequestView<'static>>,
    ) -> Result<
        (
            Pin<Box<dyn Stream<Item = Result<StreamFrame, ConnectError>> + Send>>,
            Context,
        ),
        ConnectError,
    > {
        let filter = domain_filter_from_subscribe_view(&request)?;
        let since = request.since_sequence_number;

        // Phase 1: register the subscriber FIRST so any live Put that lands
        // between now and the replay_bound snapshot is captured in the mpsc.
        let (sub_id, live_rx) = self.state.stream.subscribe(filter.clone())?;

        // Phase 2: snapshot the replay boundary atomically with respect to
        // future publishes (registration happened before this read).
        let replay_bound = self.state.engine.current_sequence();

        let filter_clone = filter.clone();
        let state = self.state.clone();
        let boundary = replay_bound;

        // Phase 3: optional replay.
        let replay_frames: Vec<Result<StreamFrame, ConnectError>> = match since {
            Some(s) if s <= boundary && s > 0 => {
                // Check the lower bound is still retained.
                if state
                    .engine
                    .get_batch(s)
                    .map_err(ConnectError::internal)?
                    .is_none()
                {
                    // Evicted → unsubscribe and surface the error.
                    state.stream.unsubscribe(sub_id);
                    let oldest = state
                        .engine
                        .oldest_retained_batch()
                        .map_err(ConnectError::internal)?;
                    return Err(self.batch_evicted_error(oldest));
                }
                self.build_replay_frames(s, boundary, &filter_clone)?
            }
            _ => Vec::new(),
        };

        // Phase 4: chain replay into live, filtering out any live frames
        // whose sequence number is <= replay_bound (those were already
        // delivered by replay — avoids double-emit for batches that landed
        // between registration and the boundary snapshot).
        let live_stream = ReceiverStream::new(live_rx).filter(move |frame| {
            let keep = match frame {
                Ok(f) => f.sequence_number > boundary,
                Err(_) => true,
            };
            async move { keep }
        });
        let replay_stream = stream_util::iter(replay_frames);
        let combined = replay_stream.chain(live_stream);

        Ok((Box::pin(combined), ctx))
    }

    async fn get_batch(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<GetBatchRequestView<'static>>,
    ) -> Result<(StreamFrame, Context), ConnectError> {
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
                    .map(|(k, v)| StreamEntry {
                        key: k.to_vec(),
                        value: v.to_vec(),
                        ..Default::default()
                    })
                    .collect();
                Ok((
                    StreamFrame {
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
