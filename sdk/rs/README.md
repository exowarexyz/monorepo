# exoware-sdk

[![Crates.io](https://img.shields.io/crates/v/exoware-sdk.svg)](https://crates.io/crates/exoware-sdk)
[![Docs.rs](https://docs.rs/exoware-sdk/badge.svg)](https://docs.rs/exoware-sdk)

Interact with the Exoware API in Rust.

## Status

`exoware-sdk` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Store Key Prefixes

Use `StoreKeyPrefix` when multiple logical QMDB, SQL, or raw KV instances share one Store database. The prefix is applied by the SDK, so higher-level clients keep using their normal logical keys:

```rust
use exoware_sdk::{StoreClient, StoreKeyPrefix};

let base = StoreClient::new("http://localhost:10000");
let orders = base.with_key_prefix(StoreKeyPrefix::new(4, 1)?);
let accounts = base.with_key_prefix(StoreKeyPrefix::new(4, 2)?);
```

For an atomic write spanning multiple prefixed clients, add each logical row through the client that owns it and commit once:

```rust
use exoware_sdk::StoreWriteBatch;

let mut batch = StoreWriteBatch::new();
batch.push(&orders, &order_key, order_value)?;
batch.push(&accounts, &account_key, account_value)?;
let sequence = batch.commit(&base).await?;
```
