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
    AppState, BatchLog, Ingest, Prune, Query, QueryExtra, RangeScanCursor, Sequence,
    StoreEngine, StoreFuture, connect_stack,
};

// Implement the capabilities your component serves:
//   Sequence:
//   fn current_sequence(&self) -> u64;
//
//   Ingest:
//   fn put_batch<'a>(&'a self, kvs: &'a [(Bytes, Bytes)]) -> StoreFuture<'a, u64>;
//
//   Query:
//   fn get<'a>(&'a self, key: &'a [u8]) -> StoreFuture<'a, (Option<Vec<u8>>, QueryExtra)>;
//   fn range_scan<'a>(&'a self, start: Bytes, end: Bytes, limit: usize, forward: bool) -> StoreFuture<'a, RangeScanCursor>;
//   fn get_many<'a>(&'a self, keys: &'a [&'a [u8]]) -> StoreFuture<'a, (Vec<(Vec<u8>, Option<Vec<u8>>)>, QueryExtra)>;
//
//   Prune:
//   fn delete_batch<'a>(&'a self, keys: &'a [&'a [u8]]) -> StoreFuture<'a, u64>;
//   fn prune_batch_log<'a>(&'a self, cutoff_exclusive: u64) -> StoreFuture<'a, u64>;
//
//   BatchLog:
//   fn get_batch<'a>(&'a self, sequence_number: u64) -> StoreFuture<'a, Option<Vec<(Bytes, Bytes)>>>;
//   fn oldest_retained_batch<'a>(&'a self) -> StoreFuture<'a, Option<u64>>;
```
