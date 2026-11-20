# exoware-indexeddb

Serve the Exoware Store from IndexedDB in a browser page. `IndexedDbStore`
implements the [backend traits](../../server/src/engine.rs) of
[exoware-server](../../server/README.md), so the server's own request handling
answers the complete Store API inside a page, without a network.

The database follows the [shared layout](../README.md). Every implementation
that follows it can open the same database, in the same page or in another
page of the origin.

## Serve the API in a page

```rust
use exoware_indexeddb::{Config, IndexedDbStore};
use exoware_server::{connect_stack, AppState};
use std::sync::Arc;

async fn serve() -> Result<(), String> {
    let store = IndexedDbStore::open("my-app", Config::default()).await?;
    let state = AppState::new(Arc::new(store.clone()));
    // Wake live subscribers for every batch committed to the database.
    store.watch(state.stream.clone());
    let api = connect_stack(state);
    // Call the tower service with requests held in memory.
    drop(api);
    Ok(())
}
```

Build for `wasm32-unknown-unknown`. The backend traits can also be called
directly, and `IndexedDbStore::put_batch` commits rows without a request.

## What to expect

- Every operation is one IndexedDB transaction. A write reports success only
  after its transaction completed with strict durability, and a write that
  reports a failure has written nothing. If the page goes away before a write
  reports, the write was committed in full or not at all.
- A query reads its whole answer inside one transaction and serves it from
  memory, because IndexedDB keeps a consistent view only while a transaction is
  live. `Config::max_query_bytes` (64 MiB by default) bounds that memory. It
  also bounds the rows a Reduce can read and what a prune holds for the keys
  it selects.
- A Put may carry at most `Config::max_batch_bytes` (64 MiB by default, 256 MiB
  at most). A Put writes its payload twice in one transaction, and Chrome fails
  a transaction that carries several hundred MiB.
- The store runs on the event loop of its page or worker. A long query or
  prune delays writers in every page that shares the database.
- A panic ends the WebAssembly instance, even inside a Reduce kernel. A native
  server reports a Reduce kernel panic as an error. Committed data is not
  affected.
- The request stack with Reduce links DataFusion and is a large WebAssembly
  module. A page that calls the traits directly links only what it uses.
- A commit from another page reaches this store through the layout's
  notification or when this store next runs an operation other than a prune.
  If the notification is lost, a query that asks for that sequence number is
  refused until this store hears of a later commit or runs such an operation.
- The Rust `StoreClient` does not build for `wasm32` yet. Rust code in a page
  reaches the store through the traits or the request stack.
- A browser can replace a damaged database with an empty one without an error.
  `IndexedDbStore::created` tells a page that expected data.

## Test

The tests run in headless Chrome through `wasm-bindgen-test`. Install
`wasm-bindgen-cli` at the `wasm-bindgen` version in `Cargo.lock` and a
`chromedriver` that matches your Chrome, then from the repository root:

```sh
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
    cargo test -p exoware-indexeddb --target wasm32-unknown-unknown
```

`tests/conformance.rs` runs the suite that the RocksDB
[simulator](../../examples/simulator/README.md) also passes, and
`tests/browser.rs` covers what is specific to IndexedDB.

## Status

`exoware-indexeddb` is **ALPHA** software and is not yet recommended for production
use. Developers should expect breaking changes and occasional instability.
