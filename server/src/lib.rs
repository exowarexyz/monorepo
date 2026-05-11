#![allow(clippy::result_large_err, clippy::type_complexity)]
//! Store server for ingest/query/compact APIs.
//!
//! Provide store capability implementations and wrap them in [`AppState`], then call [`connect_stack`].

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
    BatchLog, Ingest, Prune, Query, QueryExtra, RangeScan, RangeScanBatch, Sequence, StoreEngine,
};
pub use reduce::RangeError;
pub use stream::{StreamHub, StreamNotification, StreamNotifier};
pub use validate::{IngestLimits, DEFAULT_MAX_VALUE_LEN};
