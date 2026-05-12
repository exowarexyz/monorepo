//! In-process store API simulator (naive RocksDB).

mod kv_backend;
pub mod rocks;
#[cfg(feature = "commonware-runtime-backend")]
mod runtime_backend;
pub mod server;
mod store;

pub use exoware_server::{connect_stack, AppState, Ingest, Log, Prune, Query, Sequence};
pub use kv_backend::{Column, KvBackend, KvWrite, RowScan, ScanBounds, VecRowScan};
pub use rocks::{RocksBackend, RocksStore};
#[cfg(feature = "commonware-runtime-backend")]
pub use runtime_backend::{RuntimeKvBackend, RuntimeKvConfig};
pub use server::{run, spawn_for_test, CMD, RUN_CMD};
pub use store::Store;
