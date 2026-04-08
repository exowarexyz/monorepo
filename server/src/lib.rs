//! Store server for ingest/query/compact APIs.
//!
//! Provide an [`StoreEngine`] implementation and wrap it in [`AppState`], then call [`connect_stack`].

mod connect;
mod engine;
mod reduce;

pub use connect::{connect_stack, AppState, CompactConnect, IngestConnect, QueryConnect};
pub use engine::StoreEngine;
pub use reduce::{reduce_over_rows, RangeError};
