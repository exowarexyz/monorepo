# exoware-simulator

[![Crates.io](https://img.shields.io/crates/v/exoware-simulator.svg)](https://crates.io/crates/exoware-simulator)
[![Docs.rs](https://docs.rs/exoware-simulator/badge.svg)](https://docs.rs/exoware-simulator)

Run the Exoware API locally with a RocksDB backend. Use it to develop clients,
try the [browser sandbox](../sandbox/README.md), or run the
[validation tool](../../validation/README.md).

## Run locally

From the repository root:

```sh
cargo run -p exoware-simulator -- server run --port 8080
```

The server listens on all interfaces and stores data in
`$HOME/.exoware_store_simulator`. Pass `--directory /path/to/data` to use a different
RocksDB directory. Data persists between runs.
`GET /health` returns `ok` when the server is running.

Connect with the [Rust SDK](../../sdk/rs/README.md) or
[TypeScript SDK](../../sdk/ts/README.md). The simulator accepts requests without
credentials and enables permissive CORS for local browser development.

See the [server guide](../../server/README.md) for implementing a backend and
[`RocksStore`](src/rocks.rs) for this implementation.

## Status

`exoware-simulator` is **ALPHA** software and is not yet recommended for production
use. Developers should expect breaking changes and occasional instability.
