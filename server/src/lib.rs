#![allow(clippy::result_large_err, clippy::type_complexity)]
//! Store server for ingest/query/compact APIs.
//!
//! Provide an [`StoreEngine`] implementation and wrap it in [`AppState`], then call [`connect_stack`].

mod connect;
mod engine;
mod prune;
mod reduce;
mod stream;
mod validate;

pub use connect::{
    connect_stack, AppState, CompactConnect, IngestConnect, QueryConnect, StreamConnect,
};
pub use engine::{
    range_scan_cursor_from_iter, QueryExtra, RangeScan, RangeScanCursor, RangeScanIter, StoreEngine,
};
pub use prune::{execute_prune, PruneError};
pub use reduce::RangeError;
pub use stream::StreamHub;
