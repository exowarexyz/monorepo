# exoware-server

[![Crates.io](https://img.shields.io/crates/v/exoware-server.svg)](https://crates.io/crates/exoware-server)
[![Docs.rs](https://docs.rs/exoware-server/badge.svg)](https://docs.rs/exoware-server)

Serve the Exoware API.

## Status

`exoware-server` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Overview

`exoware-server` provides a backend-less ConnectRPC server for the Exoware API.
Implement the storage capability traits for your backend, wrap them in `AppState`,
and call `connect_stack` to get a ready-to-serve router with ingest, query,
compact, and stream services. Backends that implement every capability
automatically implement the `StoreEngine` compatibility facade.
Split deployments can instead mount `ingest_service`, `query_stack`,
`compact_service`, or `stream_service` with the narrower component state. The
stream service accepts a `StreamNotifier`; `StreamHub` is the in-process default.

```rust
use exoware_server::{
    AppState, BatchLog, Ingest, Prune, Query, RangeScanIter, Sequence, connect_stack,
};

// Implement the capabilities your component serves:
//   Sequence:
//   fn current_sequence(&self) -> u64;
//
//   Ingest:
//   fn put_batch(&self, kvs: &[(Bytes, Bytes)]) -> Result<u64, String>;
//
//   Query:
//   fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String>;
//   fn range_scan(&self, start: &[u8], end: &[u8], limit: usize, forward: bool) -> Result<RangeScanIter<'_>, String>;
//
//   Prune:
//   fn delete_batch(&self, keys: &[&[u8]]) -> Result<u64, String>;
//   fn prune_batch_log(&self, cutoff_exclusive: u64) -> Result<u64, String>;
//
//   BatchLog:
//   fn get_batch(&self, sequence_number: u64) -> Result<Option<Vec<(Bytes, Bytes)>>, String>;
//   fn oldest_retained_batch(&self) -> Result<Option<u64>, String>;
```
