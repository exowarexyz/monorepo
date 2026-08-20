# exoware-sdk

[![Crates.io](https://img.shields.io/crates/v/exoware-sdk.svg)](https://crates.io/crates/exoware-sdk)
[![Docs.rs](https://docs.rs/exoware-sdk/badge.svg)](https://docs.rs/exoware-sdk)

Interact with the Exoware API in Rust.

`StoreClient` supports HTTP and HTTPS endpoints. HTTPS connections verify certificates using the
platform trust configuration.

## Status

`exoware-sdk` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Store Key Prefixes

Use `StoreKeyPrefix` when multiple logical QMDB, SQL, or raw KV instances share one Store database. The prefix is applied by the SDK, so higher-level clients keep using their normal logical keys:

```rust
use exoware_sdk::{StoreClient, StoreKeyPrefix};

let base = StoreClient::new("http://localhost:10000");
let orders = base.prefixed(StoreKeyPrefix::new(vec![1])?);
let accounts = base.prefixed(StoreKeyPrefix::new(vec![2])?);
```

For an atomic write spanning multiple prefixed clients, add each logical row through the client that owns it and commit once:

```rust
use exoware_sdk::StoreWriteBatch;

let mut batch = StoreWriteBatch::new();
batch.push(&orders, &order_key, order_value)?;
batch.push(&accounts, &account_key, account_value)?;
let sequence = batch.commit(&base).await?;
```

## Examples

`remote` writes a batch to a deployed endpoint and reads it back, pinning each read to the sequence it just committed:

```bash
EXOWARE_URL=https://query.<deployment>.<domain> \
    EXOWARE_API_KEY=<token> \
    cargo run -p exoware-sdk --example remote
```

`EXOWARE_API_KEY` is the credential a public deployment requires, and the builder reads it from
the environment when `.api_key(...)` is not set. This example needs one covering both scopes.

Add `EXOWARE_WRITE_URL` to reach a deployment that serves its write path on a separate origin.

## RPC Transports

The default transport remains suitable for general use. High-throughput writers can opt into
independent HTTP clients per RPC origin.

```rust
use std::num::NonZeroUsize;
use std::time::Duration;

use exoware_sdk::{BalancedHttp2Config, StoreClient};

let transport = BalancedHttp2Config::default()
    .with_connections_per_origin(NonZeroUsize::new(4).unwrap())
    .with_request_timeout(Duration::from_secs(10));
let client = StoreClient::builder()
    .url("http://localhost:10000")
    .balanced_http2_transport(transport)
    .build()?;
```

Plain HTTP endpoints must accept prior-knowledge h2c. HTTPS endpoints require HTTP/2 through
ALPN and use platform trust by default. `with_tls_config` accepts custom roots or client
certificates. The request timeout bounds complete unary calls and streaming response headers. It
does not stop a streaming response after its headers arrive.

`StoreClientBuilder::client_transport` accepts a consumer transport built from the exact trait and
body types re-exported under `exoware_sdk::transport`. The SDK still owns bearer authentication,
cookies, and response compression preferences. Custom response bodies must be `Sync` so the public
SDK stream types remain `Sync`.

Tower services can use `exoware_sdk::transport::ServiceTransport`. Middleware that exposes
`tower::BoxError` must map it into a sized application error before constructing the transport.
