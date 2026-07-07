//! In-process store API simulator (naive RocksDB).
//!
//! The server (`run` / `spawn_for_test`) uses [`UnorderedRocksStore`] with
//! [`CommitDurability::NoWalFlush`]: concurrent WAL-less data writes with sequence numbers
//! assigned after the fact, made durable per commit wave by one atomic memtable flush. The
//! ordered [`RocksStore`] pipeline remains available as a library type.

pub mod rocks;
pub mod server;
pub mod unordered;

pub use exoware_server::{connect_stack, AppState, Ingest, Log, Prune, Query, Sequence};
pub use rocks::{CommitDurability, RocksConfig, RocksStore, RocksWritePipelineConfig};
pub use rocksdb;
pub use server::{run, spawn_for_test, CMD, RUN_CMD};
pub use unordered::{UnorderedRocksConfig, UnorderedRocksStore};
