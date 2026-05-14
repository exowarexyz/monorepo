//! Store-backed Simplex upload client.
//!
//! `exoware-simplex` stores Commonware Simplex artifacts in the Exoware Store
//! using a stable logical key layout. It is intentionally a client library, not
//! a consensus participant: callers still build and verify Commonware blocks and
//! certificates, then use this crate to persist the encoded artifacts.

mod client;
mod error;
pub mod keys;
mod types;

pub use client::{PreparedEntry, PreparedUpload, SimplexClient};
pub use error::SimplexError;
pub use types::{Finalized, Notarized, UploadReceipt, UploadSummary};
