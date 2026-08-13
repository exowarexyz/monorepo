#![allow(clippy::result_large_err, clippy::type_complexity)]
//! Store server for ingest/query/prune/retention/stream APIs.
//!
//! Use [`AppState`] with [`connect_stack`] for an all-in-one server, or the narrower
//! state and service constructors when capabilities are served separately.

mod connect;
mod engine;
mod reduce;
mod stream;
mod validate;

pub use connect::{
    connect_stack, ingest_service, prune_service, query_service, query_stack, retention_service,
    stream_service, AppState, IngestState, PruneState, QueryState, RetentionState, StreamState,
};
pub use engine::{
    FilteredBatch, Ingest, IngestError, Log, LogBatch, Prune, Query, QueryExtra, RangeScan,
    RangeScanBatch, Retention, Sequence, StoreEngine,
};
pub use reduce::RangeError;
pub use stream::{CompiledMatchers, StreamHub, StreamNotification, StreamNotifier};
pub use validate::{IngestLimits, DEFAULT_MAX_VALUE_LEN};
