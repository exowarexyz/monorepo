# exoware-sdk

[![Crates.io](https://img.shields.io/crates/v/exoware-sdk.svg)](https://crates.io/crates/exoware-sdk)
[![Docs.rs](https://docs.rs/exoware-sdk/badge.svg)](https://docs.rs/exoware-sdk)

Read and write Exoware's immutable key-value Store from Rust. The SDK also provides
range queries, reductions, log subscriptions, pruning, and log retention controls.

## Getting started

Add the SDK and the dependencies used by this example:

```sh
cargo add exoware-sdk bytes
cargo add tokio --features macros,rt-multi-thread
```

For local development, start the
[simulator](../../examples/simulator/README.md) on port 8080. Each Store write
returns a sequence number identifying its position in the Store's write order.
This example writes a batch, then uses that sequence to read data at least as
recent as the write:

```rust
use bytes::Bytes;
use exoware_sdk::{StoreClient, StoreKeyPrefix};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = StoreClient::builder()
        .url("http://localhost:8080")
        .build()?;
    let store = client.prefixed(StoreKeyPrefix::new(Bytes::from_static(b"example/"))?);
    let key = Bytes::from_static(b"greeting");

    let sequence = store.ingest().put(&[(&key, b"hello".as_slice())]).await?;
    let reader = store.create_session_with_sequence(sequence);
    let value = reader.get(&key).await?;
    assert_eq!(value.as_deref(), Some(b"hello".as_slice()));
    Ok(())
}
```

To connect to a deployment, use a credential with the scopes your operations
need. The builder reads `EXOWARE_API_KEY` unless you supply `.api_key(token)`.
It supports HTTP and HTTPS endpoints, with platform certificate trust for
HTTPS. If the deployment has separate read and write origins, set the service
URLs on
[`StoreClientBuilder`](https://docs.rs/exoware-sdk/latest/exoware_sdk/struct.StoreClientBuilder.html).
The [remote example](examples/remote.rs) uses separate origins and performs a
range scan. Run it from this repository with your deployment's URLs and token:

```sh
EXOWARE_URL=https://query.example.com \
    EXOWARE_WRITE_URL=https://write.example.com \
    EXOWARE_API_KEY=your-token \
    cargo run -p exoware-sdk --example remote
```

## Namespaces and atomic writes

`StoreKeyPrefix` adds a namespace to keys sent to the Store and removes it from
returned keys. Choose non-overlapping prefixes for logical stores that should be
independent. Prefix bytes count toward the physical key limit, so
`max_logical_key_len()` reports the remaining capacity. The same mechanism lets
[QMDB](../../qmdb/README.md) and [SQL](../../sql/README.md) instances share a Store.

To write across namespaces atomically, stage each row through its owning client
and commit the batch through the underlying `StoreClient`:

```rust
use exoware_sdk::StoreWriteBatch;

let orders = client.prefixed(StoreKeyPrefix::new(Bytes::from_static(b"orders/"))?);
let accounts = client.prefixed(StoreKeyPrefix::new(Bytes::from_static(b"accounts/"))?);
let mut batch = StoreWriteBatch::new();
batch.push(&orders, &Bytes::from_static(b"42"), b"created")?;
batch.push(&accounts, &Bytes::from_static(b"7"), b"active")?;
let sequence = batch.commit(&client).await?;
```

A commit sends one atomic Put. To plan a larger upload, use `encoded_len()` to
find its uncompressed protobuf size, including prefixes. Then use
`split(max_rows, max_encoded_bytes)` to consume the batch and return ordered
chunks within those limits. Each chunk is a separate write, so your
application must handle partial completion and coordinate publication.
Concurrent commits can be sequenced out of order.

The [Put contract](../../proto/README.md) defines limits, errors, and
splitting constraints. Rust exposes the published limits in
`exoware_sdk::limits`, but commits do not apply those size limits locally.
Compare the batch size with your deployment's limits before sending or use
those limits when splitting the batch.

## Read consistency

Query replicas may lag behind writes. A [`ReadSession`](https://docs.rs/exoware-sdk/latest/exoware_sdk/struct.ReadSession.html)
sets a minimum sequence, or floor, that each query must satisfy. Pass a write's
sequence to `create_session_with_sequence` when a read depends on that write.
The session is monotonic: as it observes newer query responses or log batches,
it raises the floor for subsequent requests. `create_session()` starts
without a floor.

`ReadSession::fixed(store, Some(sequence))` keeps the configured floor fixed as
responses arrive. A replica may already be ahead of the floor, so either
policy can return a later sequence. Neither pins a historical snapshot.

Clones share observations, and each query uses the floor known when it starts.
To require a higher minimum for one reader, use
`with_min_sequence_number(sequence)`. The derived reader shares observations
with its parent but leaves the parent's configured floor unchanged.

## Request options

Requests are uncompressed by default. To enable zstd, set
`.connect_request_compression(ConnectRequestCompression::Zstd { level: 3 })` on
the builder. Response decompression supports zstd and gzip.

`RetryConfig` controls retries, and `RetryConfig::disabled()` disables them.
Under the [admission retry contract](../../proto/README.md#admission-retries),
Put retries are limited to server rejections that confirm the batch was never
admitted. Generic errors, timeouts, and lost responses are not automatically
retried. A configured `request_timeout` covers all Put attempts and backoff.

The builder accepts a [custom transport](https://docs.rs/exoware-sdk/latest/exoware_sdk/transport/index.html)
or independent HTTP/2 connection pools through `balanced_http2_transport`.
Those pools require prior-knowledge h2c for HTTP, where the connection starts
with HTTP/2 without an upgrade, or HTTP/2 negotiated through ALPN for HTTPS.
Request timeouts bound unary calls and stream opening, not the lifetime of an
opened stream.

## Status

`exoware-sdk` is **ALPHA** software and is not yet recommended for production use.
Developers should expect breaking changes and occasional instability.
