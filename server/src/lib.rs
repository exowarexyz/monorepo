#![allow(clippy::result_large_err, clippy::type_complexity)]
//! Store server for ingest/query/prune/retention/stream APIs.
//!
//! Use [`AppState`] with [`connect_stack`] for an all-in-one server, or the narrower
//! state and service constructors when capabilities are served separately.

mod connect;
mod engine;
mod put_wire;
mod reduce;
mod stream;
mod validate;

pub use connect::{
    connect_limits, connect_stack, consistency_not_ready_error, ingest_error_to_connect,
    ingest_service, prune_service, query_service, query_stack, retention_service, stream_service,
    worker_not_ready_error, AppState, IngestState, PruneState, QueryState, RetentionState,
    StreamState, MAX_CONNECTRPC_BODY_BYTES, MAX_CONNECTRPC_ELEMENT_MEMORY_BYTES,
    MAX_CONNECTRPC_MESSAGE_BYTES,
};
pub use engine::{
    FilteredBatch, Ingest, IngestError, Log, LogBatch, Prune, PutCodec, PutPlan, Query, QueryExtra,
    QueryResult, RangeScan, RangeScanBatch, RangeScanResult, Retention, Sequence, StoreEngine,
};
pub use put_wire::{decode_entry_with_budget, Field, PutEntryCursor, PutParseError, UnknownBudget};
pub use reduce::RangeError;
pub use stream::{
    CompiledMatchers, CompiledSelector, InvalidFilter, StreamHub, StreamNotification,
    StreamNotifier,
};
pub use validate::{
    put_too_large_error, validate_get_many_request, validate_put_count, validate_put_entry,
    IngestLimits,
};

/// Types used by filtered-batch and matcher APIs, re-exported so backends can
/// use the server API without a version-matched direct SDK dependency.
pub use exoware_sdk::{
    common::kv::v1::Entry,
    kv_codec::Utf8,
    selector::Selector,
    stream_filter::{Filter, StreamFilter},
};
