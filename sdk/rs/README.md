# exoware-sdk

[![Crates.io](https://img.shields.io/crates/v/exoware-sdk.svg)](https://crates.io/crates/exoware-sdk)
[![Docs.rs](https://docs.rs/exoware-sdk/badge.svg)](https://docs.rs/exoware-sdk)

Interact with the Exoware API in Rust.

`StoreClient` supports HTTP and HTTPS endpoints. HTTPS connections verify certificates using the
platform trust configuration.

## Status

`exoware-sdk` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Put limits and batching

The published limits are available under `exoware_sdk::limits`. See the
[language-independent protocol contract](../../proto/README.md) for the
application limits, transport byte limits, and size errors. The [server documentation](../../server/README.md#protocol-limits)
describes transport and response decode budgets.

`StoreWriteBatch::encoded_len` reports the exact uncompressed protobuf size of
the staged `PutRequest`. `StoreWriteBatch::split` creates ordered batches that
fit positive row and byte limits without copying or re-prefixing staged rows.
An empty batch produces no chunks. An entry that cannot fit alone returns an
error. Each chunk is atomic as one write, but splitting creates several writes.
Concurrent commits may be sequenced in a different order from the returned batches.
Exoware data is immutable. Applications own retry and publication coordination
across chunks.

## Request compression

Request compression is disabled by default. Select zstd and its compression level
on the client builder:

```rust
use exoware_sdk::{ConnectRequestCompression, StoreClient};

let client = StoreClient::builder()
    .url("http://localhost:10000")
    .connect_request_compression(ConnectRequestCompression::Zstd { level: -1 })
    .build()?;
```

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

## Read Sessions

`ReadSession::monotonic(client, floor)` advances its minimum sequence as reads
observe newer responses. `ReadSession::fixed(client, floor)` keeps that minimum
unchanged. Query responses will still be at the server's current sequence; neither session mode pins a historical snapshot.

```rust
use exoware_sdk::ReadSession;

let session = ReadSession::monotonic(orders.clone(), None);
let reader = ReadSession::fixed(orders.clone(), Some(publication_sequence));
```

`min_sequence_number()` reports the effective read floor, and `evaluated_sequence()`
reports the highest observed sequence. Clones share observations.
`None` means no requirement or observation; `Some(0)` is an explicit sequence zero.
`with_min_sequence_number(sequence)` derives a reader with a stronger floor when
needed, for either policy. It leaves the parent's configured floor unchanged and
does not count the requirement as an observation.

`create_session()` and `create_session_with_sequence(...)` create monotonic sessions.

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

High-throughput writers can opt into independent HTTP clients per RPC origin.

```rust
use std::num::NonZeroUsize;
use exoware_sdk::{transport::BalancedHttp2Config, StoreClient};

let client = StoreClient::builder()
    .url("http://localhost:10000")
    .balanced_http2_transport(
        BalancedHttp2Config::default()
            .with_connections_per_origin(NonZeroUsize::new(4).unwrap()),
    )
    .build()?;
```

HTTP uses prior-knowledge h2c. HTTPS requires HTTP/2 through ALPN and uses platform trust by
default. `with_tls_config` accepts custom roots and client certificates but replaces configured
ALPN protocols with HTTP/2. HTTP/2 PINGs detect dead peers on open and idle connections. The request
timeout bounds complete unary calls. It also bounds query streams through their first frame and
subscriptions through their response headers without stopping the streaming body after the call
returns.

`StoreClientBuilder::client_transport` accepts types re-exported under `exoware_sdk::transport`.
The SDK still owns authentication, cookies, and compression preferences. Tower services can use
`ServiceTransport`. A `tower::BoxError` must first be mapped into a concrete `std::error::Error`.
