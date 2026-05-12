#![allow(clippy::result_large_err, clippy::type_complexity)]
//! Store server for ingest/query/compact/stream APIs.
//!
//! Use [`AppState`] with [`connect_stack`] for an all-in-one server, or the narrower
//! state and service constructors when capabilities are served separately.

mod connect;
mod engine;
mod reduce;
mod stream;
mod validate;

pub use connect::{
    compact_service, connect_stack, ingest_service, query_service, query_stack, stream_service,
    AppState, CompactState, IngestState, QueryState, StreamState,
};
pub use engine::{
    Ingest, Log, Prune, Query, QueryExtra, RangeScan, RangeScanBatch, Sequence, StoreEngine,
};
pub use reduce::RangeError;
pub use stream::{StreamHub, StreamNotification, StreamNotifier};
pub use validate::{IngestLimits, DEFAULT_MAX_VALUE_LEN};
