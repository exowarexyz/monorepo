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
use bytes::Bytes;
use exoware_server::{
    AppState, BatchLog, Ingest, Prune, Query, QueryExtra, RangeScanCursor, Sequence,
    StoreEngine, StoreFuture, connect_stack,
};

// Implement the capabilities your component serves:
//   Sequence:
//   fn current_sequence(&self) -> u64;
//
//   Ingest:
//   fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> StoreFuture<u64>;
//
//   Query:
//   fn get(&self, key: Bytes) -> StoreFuture<(Option<Vec<u8>>, QueryExtra)>;
//   fn range_scan(&self, start: Bytes, end: Bytes, limit: usize, forward: bool) -> StoreFuture<RangeScanCursor>;
//   fn get_many(&self, keys: Vec<Bytes>) -> StoreFuture<(Vec<(Vec<u8>, Option<Vec<u8>>)>, QueryExtra)>;
//
//   Prune:
//   fn apply_prune_policies(
//       &self,
//       policies: Vec<exoware_sdk::store::compact::v1::Policy>,
//   ) -> StoreFuture<()>;
//
//   BatchLog:
//   fn get_batch(&self, sequence_number: u64) -> StoreFuture<Option<Vec<(Bytes, Bytes)>>>;
//   fn oldest_retained_batch(&self) -> StoreFuture<Option<u64>>;
```
