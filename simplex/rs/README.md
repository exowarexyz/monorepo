# exoware-simplex

Store and retrieve typed Commonware Simplex artifacts through Exoware Store.
`SimplexWriter` publishes headers and full blocks by digest, notarizations and
finalizations by round (epoch and view), and finalizations by height.
`SimplexReader` decodes those records and checks that they match the requested
digest, round, or height.

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

The upload writes the header and both finalization indices in one Store Put,
where readers using the same Store prefix can find them. To combine artifacts
with other writes, call the writer's `prepare_*` methods and stage the result in
a `StoreWriteBatch` through the SDK's `StoreBatchUpload` trait.

## Read and validate

Use `SimplexReader::new(store)` to start a monotonic read session with no initial
minimum. Clones share observed Store sequences, so the session's minimum
advances with their reads. To reuse an existing SDK `ReadSession`, call
`with_session`. To require reads at or after a publication receipt's sequence,
use `with_min_sequence_number`. A fixed session sets a minimum sequence, not a
historical snapshot.

Typed reads take the decoded type's `Read::Cfg`. `get_header` and `get_block`
check the requested digest, while certificate reads check the requested round
or height. Use `latest_finalized` to select the highest stored finalization
height. Missing records return `None`, and decoding or index mismatches return
an error. To read stored bytes without these checks, use the `*_raw` methods.

`Notarized` and `Finalized` check that the proof's payload equals the paired
header's `Block::digest()` during construction and decoding. To authenticate the
certificate's signatures as well, verify the proof with Commonware using the
application's trusted scheme, signing namespace and validator keys for the
certificate's epoch. The Store prefix selects where records are stored, while
the signing namespace is part of what validators sign. Both must match the
intended application.

A certificate record contains a proof and header. If the application also needs
a body, store it with `upload_block` and fetch it with `get_block`. The
application defines and checks any body commitment in the header. For
Commonware Marshal integrations, the
[`init_marshal_resolver`](./src/resolver.rs) adapter supplies stored artifacts to
Marshal's verification flow. The [TypeScript package](../ts/README.md) provides
browser certificate verification.

## Local example data

With the [simulator](../../examples/simulator/README.md) running, seed demo
certificates from the repository root:

```bash
cargo run --package exoware-simplex --bin simplex -- \
  seed --store-url http://127.0.0.1:8080 --store-prefix simplex --interval-secs 2
```

The command prints its signing scheme, namespace and encoded verification
material for the [sandbox Simplex panel](../../examples/sandbox/README.md#simplex-panel).
Set the panel's `VITE_SIMPLEX_STORE_PREFIX` to `simplex` to read these artifacts.
The seeder uses a time-based starting height unless you select one with `--start-height`.
The deterministic demo keys are for local examples.
