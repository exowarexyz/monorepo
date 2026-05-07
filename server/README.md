# exoware-server

[![Crates.io](https://img.shields.io/crates/v/exoware-server.svg)](https://crates.io/crates/exoware-server)
[![Docs.rs](https://docs.rs/exoware-server/badge.svg)](https://docs.rs/exoware-server)

Serve the Exoware API.

## Status

`exoware-server` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Overview

`exoware-server` provides a backend-less ConnectRPC server for the Exoware API.
Implement the `StoreEngine` trait for your storage backend, wrap it in
`AppState`, and call `connect_stack` to get a ready-to-serve router with
ingest, query, and compact services.

```rust
use exoware_server::{AppState, QueryExtra, RangeScanCursor, StoreEngine, connect_stack};

// Implement StoreEngine for your backend:
//   fn put_batch(&self, kvs: &[(Bytes, Bytes)]) -> Result<u64, String>;
//   fn get(&self, key: &[u8]) -> Result<(Option<Vec<u8>>, QueryExtra), String>;
//   fn range_scan(&self, start: Bytes, end: Bytes, limit: usize, forward: bool) -> Result<RangeScanCursor, String>;
//   fn get_many(&self, keys: &[&[u8]]) -> Result<(Vec<(Vec<u8>, Option<Vec<u8>>)>, QueryExtra), String>;
//   fn delete_batch(&self, keys: &[&[u8]]) -> Result<u64, String>;
//   fn current_sequence(&self) -> u64;
```
