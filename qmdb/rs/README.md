# exoware-qmdb

Upload Commonware QMDB data to an Exoware Store, serve proof queries, and verify
responses against trusted roots. The crate supports ordered, unordered,
immutable, and keyless databases with MMR or MMB Merkle trees.

## Read and verify

Use an `adapter` reader to query uploaded data directly through a Store client.
Use a `service::client` to query a QMDB ConnectRPC endpoint and verify its
responses against roots supplied by your application.

This example reads a keyless operation log with variable-length byte values:

```rust
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_storage::{
    merkle::{mmr, Location},
    qmdb::keyless::variable::Operation,
};
use exoware_qmdb::{
    service::{client::rpc::OperationLogClient, proto::qmdb::v1::GetOperationRangeRequest},
    QmdbError,
};

type Op = Operation<mmr::Family, Vec<u8>>;

async fn read_prefix(
    endpoint: &str,
    tip: Location<mmr::Family>,
    trusted_root: &Digest,
) -> Result<Vec<Op>, QmdbError> {
    let client = OperationLogClient::<_, mmr::Family, Sha256, Op>::plaintext(
        endpoint,
        ((0..=4096).into(), ()),
    );
    let result = client
        .get_operation_range(
            GetOperationRangeRequest {
                tip: tip.as_u64(),
                start_location: 0,
                max_locations: 100,
                ..Default::default()
            },
            trusted_root,
        )
        .await?;
    Ok(result.operations)
}
```

The endpoint must serve that database and codec. The example allows values up to
4,096 bytes and returns up to the first 100 operations at `tip`. Use `new` with a
configured transport for HTTPS or authentication. Obtain the root and its tip
from authenticated application state before making the request.

### Proofs and roots

`OperationRangeProof` authenticates consecutive log entries.
`OperationMultiProof` authenticates entries at selected locations. These proofs
establish log membership. An included update need not still be active.
`Current*` proofs also authenticate the activity bitmap. Current key proofs
establish active values, and ordered key proofs can establish absence.
"Current" refers to state at the requested batch boundary, which may be older
than the latest published boundary.

For a database with current state, pass its trusted current root. The proof's
operation-root witness binds the operation log to that root. For an
operation-log-only database, pass its trusted operation-log root. A root received
with an untrusted response is not a trust anchor. Native adapter readers check
proofs against stored roots. Service clients check against caller-supplied roots.

Range verification binds the tip and the exact interval
`[start, min(start + max_locations, tip + 1))`. Multi-proof verification binds the
tip and the requested locations. `GetOperations` requires a nonempty, strictly
ascending list of at most 1,024 locations. The native
`Unordered::operation_multi_proof` and `Keyless::operation_multi_proof` helpers
support larger valid sets. The request cap belongs to the RPC API.

## Choose a reader and service

All four `adapter` readers expose operation roots and range proofs. Their
additional queries depend on the source database:

| Reader | Additional queries |
| --- | --- |
| `Ordered` | Indexed reads at a tip, current key hits, exclusions, and ordered key ranges |
| `Unordered` | Indexed reads at a tip and current key hits |
| `Immutable` | `get_at` by key |
| `Keyless` | `get_at` by operation location |

Current queries require uploaded current-boundary material. Unordered `get_many`
omits missing or inactive keys because unordered QMDB has no exclusion proofs.
Ordered keys must have the same `K::Ord` ordering as their raw bytes.

Readers take a `PrefixedStoreClient` and the source's codec configuration. Fixed
and variable encodings are supported. The default is `VariableEncoding<V>`.
Source index partitioning and full or compact storage do not change the upload
format. Keep each namespace to one operation history, Merkle family, hasher, and
codec. Use distinct SDK prefixes or Stores for separate instances.

[`service::server`](src/service/server/mod.rs) provides an
`*_operation_log_stack` for each kind, exposing operation queries and
subscriptions. `ordered_stack` adds current key queries, ordered key ranges, and
current operation ranges. `unordered_stack` adds current key queries and current
operation ranges. Each stack takes the same Store client and codec configuration
as its native reader.

The matching [`service::client`](src/service/client/mod.rs) types compose the
per-service clients in `service::client::rpc`. Native readers and service clients
share query names and `Verified*` results where they support the same operation.
Immutable and keyless logical `get_at` reads are native helpers. Their ConnectRPC
services expose the operation log.

`latest_published_watermark` reports the greatest published location observed by
a native reader. `root_at` returns the canonical root at a tip. Ordered and
unordered readers also expose the underlying log root through `ops_root_at`.
An optional `min_sequence_number` on proof requests sets the minimum Store
sequence for the publication lookup. The proof reads inherit that observed
sequence floor.

## Upload and publish

The [`adapter::upload`](src/adapter/upload/mod.rs) functions prepare Store rows
from captured Commonware operations and proof material. They are stateless: the
application owns capture, durable queuing, retries, and publication.

An `AuthenticatedOperationRange` contains every canonical encoded operation in
`[start_location, end_location)`, the prefix pins in `Family::nodes_to_pin` order,
and the inactive-peak count determined by the final commit's floor. The range
must end at a commit. It may contain earlier commits, overlap earlier uploads,
or begin at zero, where no pins are needed. Preserve the source's exact operation
order, including ordered QMDB's predecessor repairs and successor links.

`prepare_authenticated_range` checks the operations and pins against an
independently trusted operation-log root, then prepares operation, index, and
Merkle rows. Its codec configuration must match the source. For an
operation-log-only database with a complete prefix that fits in one atomic Store
Put, data and publication can be staged together. Here `F`, `H`, and `Op` are the
source's family, hasher, and operation type:

```rust,ignore
use commonware_parallel::Sequential;
use exoware_qmdb::adapter::upload::{
    prepare_authenticated_range, stage_authenticated_range, stage_watermark,
};
use exoware_sdk::StoreWriteBatch;

let prepared = prepare_authenticated_range::<F, H, Op, Sequential>(
    &range,
    &trusted_ops_root,
    &operation_cfg,
    &Sequential,
)?;
let latest = prepared.latest_location();
let mut batch = StoreWriteBatch::new();
stage_authenticated_range(&store, prepared, &mut batch)?;
stage_watermark::<F>(&store, latest, &mut batch)?;
let sequence = batch.commit(store.client()).await?;
```

For incremental or split uploads, publish location `W` only after every required
row in the contiguous prefix through `W` is durable. This includes pins, indices,
and any current-boundary rows inherited from earlier batches. If `[0, 100)` and
`[200, 300)` are durable, only the prefix through 99 can be published. Once
`[100, 200)` is durable, publication can advance to 299 without publishing each
intermediate commit.

Persist operations, proof material, trusted roots, and any current-boundary
material before allowing the source to discard them. Workers can prepare and
upload ranges independently and out of order. Repeated rows from the same
history have identical keys and values, so the same packet can be retried.
Coordinate publication after all required writes succeed. See the
[SDK batching guide](../../sdk/rs/README.md#namespaces-and-atomic-writes) for Put
limits and splitting.

### Current-state boundaries

For a current ordered or unordered database, attach a `CurrentBoundaryState`
before staging the prepared range:

```rust,ignore
let prepared = prepared.with_current_boundary::<H, N>(&boundary)?;
```

The boundary's root, operation-root witness, bitmap chunks, grafted nodes, and
`pruned_chunks` count must describe the range's final location. The family,
hasher, and chunk size `N` must match the source. `with_current_boundary` checks
the witness's binding to the prepared operation-log root. It does not authenticate
the supplied chunks, nodes, or pruning count.

Use [`recover_boundary_state`](src/adapter/upload/boundary.rs) to derive and
authenticate chunks and nodes from current range proofs. For an incremental
boundary, supply cumulative operation logs before and after one finalized batch
and proofs from that same applied state. With no previous log, it derives a
complete boundary for bootstrap or restart. The root, witness, and pruning count
must come from the same trusted source state.

Boundary rows are versioned by batch location. Unchanged chunks and nodes are
inherited from earlier boundaries. Retain the rows needed for every historical
tip you promise to serve. Source bitmap pruning does not delete Store rows or set
backend retention. The [`adapter::prune`](src/adapter/prune.rs) helpers construct
policies for update-index rows. Applications choose Store pruning and replay-log
retention separately.

### Pin omission

`stage_authenticated_range` includes all supplied prefix pins by default.
`prepared.without_pins_at(&positions)` omits supplied pins at exactly those
`BTreeSet<Position<F>>` positions. Preparation still authenticates every pin,
and reconstructed nodes and all other prepared rows are always staged.

Omit a pin only when the same authenticated digest in the same namespace and
history will be durable before publication and retained for serving proofs.
It may already be durable or depend on a pending predecessor upload. The
application must preserve that dependency through failures, retries, and
restarts. The library does not inspect Store or infer durability from range
bounds. Keep all pins for a nonzero bootstrap or restart when their availability
is not guaranteed.

## Subscriptions and synchronization

Rust subscriptions require `message_with_root` to obtain an independently trusted
root for each frame's tip. Filters match exact bytes, prefixes, or regexes over
logical keys and values. Reconnect from `resume_sequence_number + 1`.

Delivery follows Store write frames and waits for publication to cover each
frame's operations. A frame can contain only part of an uploaded range.
Overlapping locations within a frame are deduplicated, but retries in later
frames can repeat operations. Consumers must tolerate at-least-once delivery.

`OperationLogClient` implements Commonware's sync `Source`. Build its sync target
from a trusted operation-log root and retention range. For a current database,
`current_sync_target` derives the operation-log root from a witness checked
against the trusted current root.

## Development

From the repository root, run the Rust integration tests and the browser suite.
The latter requires installed package dependencies, a built TypeScript SDK,
Rust's `wasm32-unknown-unknown` target, `wasm-pack`, and `wasm-bindgen-cli`.
Use compatible tool versions from the
[TypeScript CI workflow](../../.github/workflows/typescript.yml):

```sh
cargo test -p exoware-qmdb --tests
npm --prefix qmdb/ts test
```

The [variant tests](tests/e2e_variants.rs) exercise Commonware source databases,
uploads, readers, and ConnectRPC clients across Merkle families and operation
encodings. Their fixtures are also verified by the browser WASM tests. The
[TypeScript guide](../ts/README.md) describes which codecs its typed APIs support.

After intentional fixture changes, regenerate all browser fixtures with one
command, then rerun the browser suite:

```sh
UPDATE_FIXTURES=1 cargo test -p exoware-qmdb --tests
```

## Status

`exoware-qmdb` is **ALPHA** software and is not yet recommended for production
use. Developers should expect breaking changes and occasional instability.
