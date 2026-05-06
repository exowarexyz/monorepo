//! In-process store API simulator (naive RocksDB).

pub mod rocks;
pub mod server;

pub use exoware_server::{connect_stack, AppState, BatchLog, Ingest, Prune, Query, Sequence};
pub use rocks::RocksStore;
pub use server::{run, spawn_for_test, CMD, RUN_CMD};
