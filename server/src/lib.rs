#![allow(clippy::type_complexity)]
//! Store server for ingest/query/prune/retention/stream APIs.
//!
//! Use [`AppState`] with [`connect_stack`] for an all-in-one server, or the narrower
//! state and service constructors when capabilities are served separately.
//!
//! ## wasm32
//!
//! The crate builds for `wasm32-unknown-unknown` so a backend can serve the same stack inside a
//! browser page, called as a `tower` service with requests held in memory. That target has no
//! sockets, no threads and no Rust standard clock, and tokio drives no timers there. On wasm32:
//!
//! - `ingest::transport::serve` is absent.
//! - Put deadlines are `ingest::Instant` readings of the page's monotonic clock,
//!   `performance.now`. The crate arms no timer, so it notices a deadline only when the request
//!   is polled. A wait during a Put is not cut short at its deadline and lasts until something
//!   wakes it.
//! - The Put decode step runs in place.
//! - [`connect_stack`] and [`ingest_service`] remove the `connect-timeout-ms` and
//!   `grpc-timeout` headers from requests other than Put, because the Connect dispatcher reads
//!   the standard clock for them. The narrower service constructors pass requests to the
//!   dispatcher unchanged, so their caller must not send those headers.
//! - A panic ends the WebAssembly instance, even inside a Reduce kernel. Native builds report a
//!   Reduce kernel panic as an error.

mod connect;
mod engine;
pub mod ingest;
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
    FilteredBatch, Ingest, IngestError, Log, LogBatch, Prune, Query, QueryExtra, QueryResult,
    RangeScan, RangeScanBatch, RangeScanResult, Retention, Sequence, StoreEngine,
};
/// Types used by filtered-batch and matcher APIs, re-exported so backends can
/// use the server API without a version-matched direct SDK dependency.
pub use exoware_sdk::{
    common::kv::v1::Entry,
    kv_codec::Utf8,
    selector::Selector,
    stream_filter::{Filter, StreamFilter},
};
pub use ingest::{
    parser::{decode_entry_with_budget, Field, PutEntryCursor, PutParseError, UnknownBudget},
    service::{PutConfig, PutMiddleware, PutService},
    PutError, PutInput,
};
pub use reduce::RangeError;
pub use stream::{
    CompiledMatchers, CompiledSelector, InvalidFilter, StreamHub, StreamNotification,
    StreamNotifier,
};
pub use validate::{
    put_too_large_error, validate_get_many_request, validate_put_count, validate_put_entry,
    IngestLimits,
};
