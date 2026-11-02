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
[simulator](../../examples/simulator/README.md) on port 8080. This example writes
a batch and reads it at or after the returned sequence:

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

The builder reads `EXOWARE_API_KEY` unless you supply `.api_key(token)`. Use a
credential issued for the deployment with the scopes your operations need.
HTTP and HTTPS endpoints are supported. HTTPS uses platform certificate trust.
For separate read and write origins, set the service URLs on
[`StoreClientBuilder`](https://docs.rs/exoware-sdk/latest/exoware_sdk/struct.StoreClientBuilder.html).
The [remote example](examples/remote.rs) shows this configuration and a range scan:

```sh
EXOWARE_URL=https://query.example.com \
    EXOWARE_WRITE_URL=https://write.example.com \
    EXOWARE_API_KEY=your-token \
    cargo run -p exoware-sdk --example remote
```

Run that command from this repository, using your deployment's URLs and token.

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

A commit is one atomic Put. For larger uploads, `encoded_len()` reports the
uncompressed protobuf size, including prefixes. `split(max_rows, max_encoded_bytes)`
consumes the batch and returns ordered chunks within those limits. Committing
chunks creates separate writes. Handle partial completion and coordinate publication
yourself. Concurrent commits can be sequenced out of order.
See the [Put contract](../../proto/README.md) for limits, errors, and splitting
constraints. Rust exposes the published limits in `exoware_sdk::limits`. Commits
do not apply those size limits locally.

## Read consistency

A write's sequence is a minimum read position. Query replicas may lag, so pass
that sequence to `create_session_with_sequence` when a read depends on the write.
The resulting monotonic session raises its floor as it observes newer query
responses or log batches. `create_session()` starts without a floor.

`ReadSession::fixed(store, Some(sequence))` keeps the configured floor unchanged.
Neither policy pins a historical snapshot: reads may observe a later sequence.
Clones share observations, and each request uses the floor known when it starts.
`with_min_sequence_number(sequence)` derives a stronger reader without changing
the parent's configured floor. See
[`ReadSession`](https://docs.rs/exoware-sdk/latest/exoware_sdk/struct.ReadSession.html)
for observation tracking and log reads.

## Request options

Requests are uncompressed by default. To enable zstd, set
`.connect_request_compression(ConnectRequestCompression::Zstd { level: 3 })` on
the builder. Response decompression supports zstd and gzip.

`RetryConfig` controls retries. Put retries are limited to server rejections that
confirm the batch was never admitted. Generic errors, timeouts, and lost responses
are not automatically retried. `RetryConfig::disabled()` disables retries.
A configured `request_timeout` covers all Put attempts and backoff. See the
[admission retry contract](../../proto/README.md#admission-retries) before adding
application retries.

The builder also accepts a custom transport or independent HTTP/2 connection
pools through `balanced_http2_transport`. The latter requires prior-knowledge h2c
for HTTP and HTTP/2 through ALPN for HTTPS. Request timeouts bound unary calls and
stream opening, not the lifetime of an opened stream. See the
[builder reference](https://docs.rs/exoware-sdk/latest/exoware_sdk/struct.StoreClientBuilder.html)
and [transport types](https://docs.rs/exoware-sdk/latest/exoware_sdk/transport/index.html)
for configuration.

## Status

`exoware-sdk` is **ALPHA** software and is not yet recommended for production use.
Developers should expect breaking changes and occasional instability.
