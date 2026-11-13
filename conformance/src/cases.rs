//! The conformance cases. Each takes the [`Backend`](crate::Backend) under test, opens its own
//! stores and closes them before it returns.

mod ingest;
mod log;
mod prune;
mod query;
mod reduce;

pub use ingest::*;
pub use log::*;
pub use prune::*;
pub use query::*;
pub use reduce::*;
