//! Ingest, query, and compact services; storage is provided by [`crate::StoreEngine`].

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use connectrpc::{Chain, ConnectError, ConnectRpcService, Context, Limits};
use exoware_common::keys::{validate_key_size, Key, MAX_KEY_LEN, MAX_VALUE_SIZE, MIN_VALUE_SIZE};
use exoware_sdk_rs as exoware_proto;
use exoware_proto::compact::{
    PruneResponse, Service as CompactApi, ServiceServer as CompactServiceServer,
};
use exoware_proto::google::rpc::{bad_request::FieldViolation, BadRequest, ErrorInfo, RetryInfo};
use exoware_proto::ingest::{
    PutResponse as ProtoPutResponse, Service as IngestApi, ServiceServer as IngestServiceServer,
};
use exoware_proto::query::{
    Detail, GetResponse, RangeEntry, RangeFrame, ReduceResponse, Service as QueryApi,
    ServiceServer as QueryServiceServer,
};
use exoware_proto::{
    connect_compression_registry, encode_query_detail_header_value,
    parse_range_traversal_direction, to_domain_reduce_request_from_view,
    to_proto_optional_reduced_value, to_proto_reduced_value, with_bad_request_detail,
    with_error_info_detail, with_query_detail, with_retry_info_detail, RangeTraversalDirection,
    RangeTraversalModeError, QUERY_DETAIL_RESPONSE_HEADER,
};
use futures::{stream, Stream};
use http::header::HeaderValue;
use http::HeaderName;

use crate::reduce::reduce_over_rows;
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
    pub ready: Arc<AtomicBool>,
}

impl AppState {
    pub fn new(engine: Arc<dyn StoreEngine>) -> Self {
        Self {
            engine,
            ready: Arc::new(AtomicBool::new(true)),
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

    fn invalid_argument_field_error(
        &self,
        field: impl Into<String>,
        description: impl Into<String>,
        reason: &'static str,
        message: impl Into<String>,
        metadata: impl IntoIterator<Item = (String, String)>,
    ) -> ConnectError {
        let description = description.into();
        let err = with_bad_request_detail(
            ConnectError::invalid_argument(message),
            BadRequest {
                field_violations: vec![FieldViolation {
                    field: field.into(),
                    description: description.clone(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        with_error_info_detail(
            err,
            ErrorInfo {
                reason: reason.to_string(),
                domain: "store.ingest".to_string(),
                metadata: metadata
                    .into_iter()
                    .chain(std::iter::once(("description".to_string(), description)))
                    .collect(),
                ..Default::default()
            },
        )
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

        let wire = request.bytes();
        let mut batch = Vec::new();
        for (index, kv) in request.kvs.iter().enumerate() {
            validate_key_size(kv.key.len()).map_err(|e| {
                self.invalid_argument_field_error(
                    format!("kvs[{index}].key"),
                    e.to_string(),
                    "INVALID_KEY_LENGTH",
                    "request key length is outside store limits",
                    [("max_key_len".to_string(), MAX_KEY_LEN.to_string())],
                )
            })?;
            if !(MIN_VALUE_SIZE..=MAX_VALUE_SIZE).contains(&kv.value.len()) {
                return Err(self.invalid_argument_field_error(
                    format!("kvs[{index}].value"),
                    format!(
                        "value size {} out of range [{}, {}]",
                        kv.value.len(),
                        MIN_VALUE_SIZE,
                        MAX_VALUE_SIZE
                    ),
                    "INVALID_VALUE_LENGTH",
                    "request value length is outside store limits",
                    [
                        ("min_value_len".to_string(), MIN_VALUE_SIZE.to_string()),
                        ("max_value_len".to_string(), MAX_VALUE_SIZE.to_string()),
                    ],
                ));
            }
            let key: Key = wire.slice_ref(kv.key);
            let value = wire.slice_ref(kv.value);
            batch.push((key, value));
        }

        let seq = self
            .state
            .engine
            .put_batch(&batch)
            .map_err(ConnectError::internal)?;

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

    fn invalid_argument_field_error(
        &self,
        field: impl Into<String>,
        description: impl Into<String>,
        reason: &'static str,
        message: impl Into<String>,
    ) -> ConnectError {
        let description = description.into();
        let err = with_bad_request_detail(
            ConnectError::invalid_argument(message),
            BadRequest {
                field_violations: vec![FieldViolation {
                    field: field.into(),
                    description: description.clone(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        with_error_info_detail(
            err,
            ErrorInfo {
                reason: reason.to_string(),
                domain: "store.query".to_string(),
                metadata: [("description".to_string(), description)]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
        )
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
        self.ensure_min_sequence_number(request.min_sequence_number)?;
        validate_key_size(request.key.len()).map_err(|e| {
            self.invalid_argument_field_error(
                "key",
                e.to_string(),
                "INVALID_KEY_LENGTH",
                "request key length is outside store limits",
            )
        })?;
        let wire = request.bytes();
        let key: Key = wire.slice_ref(request.key);
        let value = self
            .state
            .engine
            .get(key.as_ref())
            .map_err(ConnectError::internal)?;
        let token = self.current_sequence_number();
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
                found: value.is_some(),
                value: value.map(Into::into),
                ..Default::default()
            },
            ctx,
        ))
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
        self.ensure_min_sequence_number(request.min_sequence_number)?;
        validate_key_size(request.start.len()).map_err(|e| {
            self.invalid_argument_field_error(
                "start",
                e.to_string(),
                "INVALID_KEY_LENGTH",
                "range start key length is outside store limits",
            )
        })?;
        validate_key_size(request.end.len()).map_err(|e| {
            self.invalid_argument_field_error(
                "end",
                e.to_string(),
                "INVALID_KEY_LENGTH",
                "range end key length is outside store limits",
            )
        })?;
        let wire = request.bytes();
        let start_key: Key = wire.slice_ref(request.start);
        let end_key: Key = wire.slice_ref(request.end);
        let limit = request.limit.map(|v| v as usize).unwrap_or(usize::MAX);
        let batch_size = request.batch_size.max(1) as usize;
        let forward = match parse_range_traversal_direction(request.mode) {
            Ok(RangeTraversalDirection::Forward) => true,
            Ok(RangeTraversalDirection::Reverse) => false,
            Err(RangeTraversalModeError::UnknownWireValue(v)) => {
                return Err(self.invalid_argument_field_error(
                    "mode",
                    format!("unknown TraversalMode enum value {v}"),
                    "INVALID_TRAVERSAL_MODE",
                    "range mode must be TRAVERSAL_MODE_FORWARD (0) or TRAVERSAL_MODE_REVERSE (1)",
                ));
            }
        };

        let entries = self
            .state
            .engine
            .range_scan(start_key.as_ref(), end_key.as_ref(), limit, forward)
            .map_err(ConnectError::internal)?;

        let sequence_number = self.current_sequence_number();
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

        Ok((Box::pin(stream::iter(frames)), ctx))
    }

    async fn reduce(
        &self,
        mut ctx: Context,
        request: buffa::view::OwnedView<
            exoware_proto::store::query::v1::ReduceRequestView<'static>,
        >,
    ) -> Result<(ReduceResponse, Context), ConnectError> {
        self.ensure_min_sequence_number(request.min_sequence_number)?;
        validate_key_size(request.start.len()).map_err(|e| {
            self.invalid_argument_field_error(
                "start",
                e.to_string(),
                "INVALID_KEY_LENGTH",
                "reduce start key length is outside store limits",
            )
        })?;
        validate_key_size(request.end.len()).map_err(|e| {
            self.invalid_argument_field_error(
                "end",
                e.to_string(),
                "INVALID_KEY_LENGTH",
                "reduce end key length is outside store limits",
            )
        })?;
        let wire = request.bytes();
        let start_key: Key = wire.slice_ref(request.start);
        let end_key: Key = wire.slice_ref(request.end);
        let domain = to_domain_reduce_request_from_view(&request.params).map_err(|e| {
            self.invalid_argument_field_error(
                "params",
                e,
                "INVALID_REDUCE_PARAMS",
                "reduce params are invalid",
            )
        })?;

        let rows = self
            .state
            .engine
            .range_scan(start_key.as_ref(), end_key.as_ref(), usize::MAX, true)
            .map_err(ConnectError::internal)?;

        let response = reduce_over_rows(&rows, &domain)
            .map_err(|e: crate::RangeError| ConnectError::internal(e.to_string()))?;

        let token = self.current_sequence_number();
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
    _state: AppState,
}

impl CompactConnect {
    pub fn new(state: AppState) -> Self {
        Self { _state: state }
    }
}

impl CompactApi for CompactConnect {
    async fn prune(
        &self,
        ctx: Context,
        _request: buffa::view::OwnedView<
            exoware_proto::store::compact::v1::PruneRequestView<'static>,
        >,
    ) -> Result<(PruneResponse, Context), ConnectError> {
        Ok((PruneResponse::default(), ctx))
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
        Chain<QueryServiceServer<QueryConnect>, CompactServiceServer<CompactConnect>>,
    >,
> {
    ConnectRpcService::new(Chain(
        IngestServiceServer::new(IngestConnect::new(state.clone())),
        Chain(
            QueryServiceServer::new(QueryConnect::new(state.clone())),
            CompactServiceServer::new(CompactConnect::new(state)),
        ),
    ))
    .with_limits(connect_limits())
    .with_compression(connect_compression_registry())
}
