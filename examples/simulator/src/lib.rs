//! In-process store API simulator (naive RocksDB).
//!
//! The server (`run` / `spawn_for_test`) uses [`FlatFileRocksStore`]: uploads are made durable
//! as parallel checksummed flat files, sequence numbers are assigned by file renames committed
//! with one directory fsync per wave, and a WAL-less RocksDB instance is populated
//! asynchronously to serve reads (which gate on the applied frontier). The ordered
//! [`RocksStore`] pipeline and the experimental [`UnorderedRocksStore`] remain available as
//! library types.

pub mod flatfile;
pub mod rocks;
pub mod server;
pub mod unordered;

pub use exoware_server::{connect_stack, AppState, Ingest, Log, Prune, Query, Sequence};
pub use flatfile::{FlatFileConfig, FlatFileRocksStore};
pub use rocks::{CommitDurability, RocksConfig, RocksStore, RocksWritePipelineConfig};
pub use rocksdb;
pub use server::{run, spawn_for_test, CMD, RUN_CMD};
pub use unordered::{UnorderedRocksConfig, UnorderedRocksStore};
