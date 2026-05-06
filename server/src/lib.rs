#![allow(clippy::result_large_err, clippy::type_complexity)]
//! Store server for ingest/query/compact APIs.
//!
//! Provide store capability implementations and wrap them in [`AppState`], then call [`connect_stack`].

mod connect;
mod engine;
mod prune;
mod reduce;
mod stream;
mod validate;

pub use connect::{
    compact_service, connect_stack, ingest_service, query_service, query_stack, stream_service,
    AppState, CompactConnect, CompactService, CompactState, ConnectStack, IngestConnect,
    IngestService, IngestState, QueryConnect, QueryService, QueryStack, QueryState, StreamConnect,
    StreamService, StreamState,
};
pub use engine::{BatchLog, Ingest, Prune, Query, RangeScanIter, Sequence, StoreEngine};
pub use prune::{execute_prune, PruneError};
pub use reduce::RangeError;
pub use stream::StreamHub;
