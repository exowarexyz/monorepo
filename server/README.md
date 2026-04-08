# exoware-server

[![Crates.io](https://img.shields.io/crates/v/exoware-server.svg)](https://crates.io/crates/exoware-server)
[![Docs.rs](https://docs.rs/exoware-server/badge.svg)](https://docs.rs/exoware-server)

Serve the Exoware API.

`exoware-server` provides a backend-less ConnectRPC server for the Exoware API.
Implement the `StoreEngine` trait for your storage backend, wrap it in
`AppState`, and call `connect_stack` to get a ready-to-serve router with
ingest, query, and compact services.

```rust
use exoware_server::{AppState, StoreEngine, connect_stack};

// Implement StoreEngine for your backend:
//   fn put_batch(&self, kvs: &[(Bytes, Bytes)]) -> Result<u64, String>;
//   fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String>;
//   fn range_scan(&self, start: &[u8], end: &[u8], limit: usize, forward: bool) -> Result<Vec<(Bytes, Bytes)>, String>;
//   fn delete_batch(&self, keys: &[&[u8]]) -> Result<u64, String>;
//   fn current_sequence(&self) -> u64;
```

## Status

`exoware-server` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.
