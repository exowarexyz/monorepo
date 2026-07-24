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
stream service accepts an in-process `StreamNotifier`; `StreamHub` is the local
default.

```rust
use bytes::Bytes;
use exoware_sdk::prune_policy::PrunePolicyDocument;
use exoware_server::{
    AppState, Log, Ingest, Prune, Query, QueryExtra, RangeScan, RangeScanBatch, Retention,
    Sequence, StoreEngine, connect_stack,
};
use std::future::Future;

// Implement the capabilities your component serves:
//   Sequence:
//   fn current_sequence(&self) -> u64;
//
//   Ingest:
//   fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> impl Future<Output = Result<u64, String>> + Send + '_;
//
//   Query:
//   type RangeScan: RangeScan;
//   fn get(&self, key: Bytes) -> impl Future<Output = Result<(Option<Vec<u8>>, QueryExtra), String>> + Send + '_;
//   fn range_scan(&self, start: Bytes, end: Bytes, limit: usize, forward: bool) -> impl Future<Output = Result<Self::RangeScan, String>> + Send + '_;
//   fn get_many(&self, keys: Vec<Bytes>) -> impl Future<Output = Result<(Vec<(Vec<u8>, Option<Vec<u8>>)>, QueryExtra), String>> + Send + '_;
//
//   Prune:
//   fn apply_prune_policies(&self, document: PrunePolicyDocument) -> impl Future<Output = Result<(), String>> + Send + '_;
//
//   Log:
//   fn get_batch(&self, sequence_number: u64) -> impl Future<Output = Result<Option<Vec<(Bytes, Bytes)>>, String>> + Send + '_;
//   fn oldest_retained_batch(&self) -> impl Future<Output = Result<Option<u64>, String>> + Send + '_;
//
//   Retention:
//   fn set_retention(&self, policy: Option<RetentionPolicy>) -> impl Future<Output = Result<Option<u64>, String>> + Send + '_;
```
