//! Store-backed Simplex read and upload clients.
//!
//! `exoware-simplex` stores Commonware Simplex artifacts in the Exoware Store
//! using a stable logical key layout. It is intentionally a client library, not
//! a consensus participant: callers still build and verify Commonware blocks and
//! certificates, then use this crate to persist the encoded artifacts.

mod error;
pub mod keys;
mod reader;
mod resolver;
mod types;
mod writer;

pub use error::SimplexError;
pub use reader::SimplexReader;
pub use resolver::init_marshal_resolver;
pub use types::{encode_block_data, BlockData, Finalized, Notarized, UploadReceipt, UploadSummary};
pub use writer::{PreparedEntry, PreparedUpload, SimplexWriter};
