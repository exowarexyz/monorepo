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

The server listens on all interfaces, and `GET /health` returns `ok` while it
is running. It stores data in `$HOME/.exoware_store_simulator` and preserves
it between runs. Pass `--directory /path/to/data` to use a different RocksDB
directory.

RocksDB keeps up to `--max-open-files` table files open (default 16384) and
closes the least recently read ones beyond that, so run the server under an
open-file limit above it, for example `ulimit -n 65536`. The store merges its
log files in the background, so the file count grows with the bytes stored and
not with the number of writes. A cap below the state files a read probes makes
reads reopen tables.

Connect with the [Rust SDK](../../sdk/rs/README.md) or [TypeScript
SDK](../../sdk/ts/README.md). The simulator accepts requests without
credentials and enables permissive CORS for local browser development. To
build your own backend, start with the [server guide](../../server/README.md)
and use [`RocksStore`](src/rocks.rs) as an implementation reference.

## Status

`exoware-simulator` is **ALPHA** software and is not yet recommended for production
use. Developers should expect breaking changes and occasional instability.
