# exoware-simplex

Store and retrieve typed Commonware Simplex artifacts through Exoware Store.
`SimplexWriter` publishes headers and full blocks by digest, notarizations and
finalizations by round (epoch and view), and finalizations by height.
`SimplexReader` decodes those records and checks their index bindings.

## Publish a finalization

Given a Commonware finalization and its matching header, construct a `Finalized`
record and upload it through a prefixed Store client:

```rust
use commonware_consensus::{simplex::types::Finalization, Block};
use commonware_cryptography::{certificate::Scheme, Digest};
use exoware_sdk::{StoreClient, StoreKeyPrefix};
use exoware_simplex::{Finalized, SimplexError, SimplexWriter, UploadReceipt};

async fn publish<B, S, D>(
    store_url: &str,
    prefix: StoreKeyPrefix,
    proof: Finalization<S, D>,
    header: B,
) -> Result<UploadReceipt, SimplexError>
where
    B: Block<Digest = D>,
    S: Scheme,
    D: Digest,
{
    let store = StoreClient::new(store_url).prefixed(prefix);
    let writer = SimplexWriter::new(store);
    let finalized = Finalized::new(proof, header)?;
    writer.upload_finalized(&finalized).await
}
```

The upload writes the header and both finalization indices in one Store Put.
Use the same Store prefix for readers and writers. To combine artifacts with
other writes, call the writer's `prepare_*` methods and stage the result in a
`StoreWriteBatch` through the SDK's `StoreBatchUpload` trait. See the
[SDK guide](../../sdk/rs/README.md) for batching and Store limits.

## Read and validate

`SimplexReader::new(store)` starts a monotonic read session with no initial
minimum. Clones share observed Store sequences. Use `with_session` to supply an
existing SDK `ReadSession`, or `with_min_sequence_number` to require reads at or
after a publication receipt's sequence. A fixed session sets a minimum sequence,
not a historical snapshot.

Typed reads take the decoded type's `Read::Cfg`. `get_header` and `get_block`
check the requested digest. Certificate reads check the requested round or
height, and `latest_finalized` selects the highest stored finalization height.
Missing records return `None`. Decoding or index mismatches return an error.
The `*_raw` methods return stored bytes without these checks. See
[`SimplexReader`](./src/reader.rs) for signatures and decoding configuration.

`Notarized` and `Finalized` check that the proof's payload equals the paired
header's `Block::digest()` during construction and decoding. These checks do
not verify signatures. Verify the proof with Commonware using the application's
trusted scheme, signing namespace and validator keys for the certificate's
epoch before treating it as certified. The Store prefix and signing namespace
serve different purposes and must both match the intended application.

A certificate record contains a proof and header. Store a body separately with
`upload_block` and fetch it with `get_block`. The application defines and checks
any body commitment in the header. The [`init_marshal_resolver`](./src/resolver.rs)
adapter supplies stored artifacts to Commonware Marshal for its verification
flow. Browser certificate verification is available through the
[TypeScript package](../ts/README.md).

## Local example data

With the [simulator](../../examples/simulator/README.md) running, seed demo
certificates from the repository root:

```bash
cargo run --package exoware-simplex --bin simplex -- \
  seed --store-url http://127.0.0.1:8080 --interval-secs 2
```

The command prints its signing scheme, namespace and encoded verification
material for the
[sandbox Simplex panel](../../examples/sandbox/README.md#simplex-panel).
It defaults to a time-based starting height. `--start-height` selects one
explicitly. These deterministic demo keys are for local examples.
