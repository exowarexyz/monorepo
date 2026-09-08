# exoware-qmdb

Mirror authenticated Commonware QMDB operation ranges into an Exoware Store and
serve historical reads, proofs, and ConnectRPC APIs.

## Status

`exoware-qmdb` is **ALPHA** software and is not yet recommended for production
use. Developers should expect breaking changes and occasional instability.

## Native backends

All backends use the same stateless upload functions. Rust readers and proof
clients are generic over the Commonware Merkle family and operation codec.
Both MMR and MMB are supported.

| Commonware source | Rust reader | Operation encodings and keys | Source storage/index variants |
|---|---|---|---|
| `any::ordered`, `current::ordered` | `OrderedClient` | Fixed encoding with fixed keys; variable encoding with fixed or `Vec<u8>` keys | Plain and partitioned P1/P2/P3 |
| `any::unordered`, `current::unordered` | `UnorderedClient` | Fixed encoding with fixed keys; variable encoding with fixed or `Vec<u8>` keys | Plain and partitioned P1/P2/P3 |
| `immutable` | `ImmutableClient` | Fixed encoding with fixed keys; variable encoding with fixed or `Vec<u8>` keys | Full and compact |
| `keyless` | `KeylessClient` | Fixed or variable encoding | Full and compact |

Readers default to `VariableEncoding<V>`; select `FixedEncoding<V>` for fixed
operation codecs. Source indexing and compactness affect how Commonware retains
local state. They do not select a different Exoware uploader or row format.

Each Store namespace must contain one consistent QMDB operation history with
one family, hasher, and codec configuration. Use the SDK `StoreKeyPrefix` or a
separate Store to isolate instances. The row-family prefixes do not identify
QMDB instances or Merkle families.

## Authenticated upload contract

`AuthenticatedOperationRange` describes the half-open interval
`[start_location, proof.leaves)` using:

- a Commonware operation range proof
- pinned prefix nodes in `Family::nodes_to_pin(start_location)` order
- the exact canonical encoded operations in location order

`prepare_authenticated_range` takes that packet, an independently trusted
operation-log root, the originating operation codec configuration, and a hashing
strategy. It authenticates the range and pins, checks canonical operation
encodings and commit floors, and prepares operation, keyed-index, and Merkle
node rows, including a presence marker for the final location. It performs no
Store reads or writes and retains no state between calls.

The packet must contain every operation in its declared interval and end at the
proof's leaf count. Its final operation must be a commit whose inactivity floor
matches the proof's canonical inactive-peak count. Earlier commits are allowed,
so the same API accepts bootstrap packets, complete prefixes, incremental
suffixes, and overlapping ranges. A packet beginning at zero has no pinned
prefix nodes.

Use the source's exact operations. In particular, ordered operations include
Commonware's predecessor repairs and successor links; plain key/value writes
are not a substitute for that authenticated log.

`UploadOperation<F>` supplies the shared codec, commit-floor, and keyed-index
contract. Commonware ordered, unordered, immutable, and keyless operations
implement it. There is no per-source adapter to construct or recover.

Here `F`, `H`, and `Op` are the originating Commonware family, hasher, and
operation type:

```rust,ignore
use commonware_parallel::Sequential;
use exoware_qmdb::{
    prepare_authenticated_range, stage_authenticated_range, stage_watermark,
    AuthenticatedOperationRange,
};
use exoware_sdk::StoreWriteBatch;

let range = AuthenticatedOperationRange {
    start_location,
    proof: &proof,
    pinned_nodes: &pinned_nodes,
    encoded_operations: &encoded_operations,
};
let prepared = prepare_authenticated_range::<F, H, Op, Sequential>(
    &range,
    &expected_ops_root,
    &operation_cfg,
    &Sequential,
)?;
let latest = prepared.latest_location();

let mut data = StoreWriteBatch::new();
stage_authenticated_range(&client, prepared, &mut data)?;
data.commit(client.client()).await?;

// The caller's durable queue confirms that every required row through latest is durable
let mut publication = StoreWriteBatch::new();
stage_watermark::<F>(&client, latest, &mut publication)?;
publication.commit(client.client()).await?;
```

The expected root is a trust input, not a root accepted merely because it was
included in the proof response.

## Durable queue and publication

The caller owns packet durability, upload scheduling, retries, and publication.
Persist the source operations and proof material, together with their trusted
roots and any current-boundary material, before allowing the source to discard
what a retry needs. Preparation can then happen independently of source DB
mutation and independently of other packets.

Uploads may overlap and arrive concurrently or out of order. Repeating rows
from the same operation history produces the same keys and values. Retrying an
upload does not require reconstructing an Exoware writer or Merkle frontier.

Publish location `W` only when every required operation, index, and Merkle row
in the contiguous prefix through `W` is durable. For current QMDB, the required
current-boundary rows must also be durable. The queue must account for inherited
sparse boundary rows as well as the newest packet. Rows may instead be staged
alongside publication in the same atomic `StoreWriteBatch`.

`stage_watermark` stages only the watermark row. It does not read the Store,
check prefix completeness, calculate Merkle nodes, or maintain an upload queue.
A successful commit is the caller's durability event; preparation and staging
alone do not authorize advancing publication.

For example, if ranges `[0, 100)` and `[200, 300)` are durable, the contiguous
prefix ends at 99. After `[100, 200)` becomes durable, the caller may publish
299. It need not publish every intermediate commit location.

Readers fence requests at the latest published watermark. Historical roots and
proofs use the operation log at the requested valid commit location; current
proofs additionally require boundary material for that location. Retaining
older versioned rows preserves proofs at older boundaries after publication
advances.

## Current-state boundary material

Current ordered and unordered QMDBs authenticate both an operation log and an
activity bitmap. Attach the corresponding `CurrentBoundaryState` before staging:

```rust,ignore
let prepared = prepared.with_current_boundary::<H, N>(&boundary)?;
```

The boundary contains the trusted current root, an `OpsRootWitness`, bitmap
chunk deltas, grafted-node deltas, and `pruned_chunks` for the packet's final
location. Its family, hasher, and chunk size `N` must match the source DB.

`with_current_boundary` checks that the witness binds the authenticated
operation-log root to `boundary.root`. The caller must already have
authenticated the boundary's bitmap chunks and grafted nodes against its trusted
current root. The `pruned_chunks` count must also come from that trusted state.
The attachment method does not verify chunks, nodes, or that count by itself.

`recover_boundary_state` is the shared proof-based helper for deriving this
material from a Commonware current DB. For an incremental boundary it takes the
cumulative operation logs before and after one finalized batch, the trusted
current root, `pruned_chunks`, the operation-root witness, and current range
proofs from that same state. Passing no previous log derives a complete boundary
from the retained operation prefix, including bootstrap or restart material.
It verifies the supplied current proofs and derives the boundary rows without
reading the remote Store. It works for ordered and unordered logs.

Current rows are versioned by the final operation location of their batch.
Only changed chunks and grafted nodes need new rows; unchanged rows are inherited
from earlier boundaries. Current proof reads fetch those versioned rows and
persisted operation Merkle nodes instead of replaying the complete log.
Internal nodes absent from a sparse boundary can be reconstructed from their
authenticated children, including parents created by delayed MMB merges.

`pruned_chunks` counts the complete, all-zero bitmap chunks discarded from the
start of the source bitmap. A parent spans the pruning boundary when it covers
chunks on both sides of that boundary. This is expected during normal updates
and pruning. For example:

1. A parent covers bitmap chunks 0 and 1.
2. Updates make chunk 0 entirely inactive, so the source discards it.
3. Chunk 1 still contains active operations.
4. Their parent now spans the pruning boundary.

A proof for an active operation can still need that parent hash. The backend
computes it from chunk 0's operation-tree hash and chunk 1's current hash, using
the requested historical boundary. An all-zero bitmap chunk preserves its
operation-tree hash, so the discarded bitmap data is not needed to compute it.

The activity changes happen before pruning and can change the parent hash.
Pruning itself preserves the root. Since boundary deltas omit discarded chunks,
the backend recomputes parents spanning the boundary instead of relying on an
older stored parent hash. The `pruned_chunks` count does not delete backend rows
or configure retention.

Proof capture timing belongs to the source producer. Commonware `any`,
immutable, and keyless finalized batches expose operations, a root, a proof,
and pinned nodes before application. Current sources can capture
`ops_historical_proof`, pinned nodes, the operation-root witness, and current
range proofs from the applied DB state. Both routes feed the same packet and
preparation API; upload workers do not need access to a live source DB.

## Reads and ConnectRPC

All four readers expose historical operation roots and range proofs. Ordered
and unordered readers provide indexed historical key queries and multi-proofs;
immutable provides indexed `get_at`, and keyless provides location-based
`get_at`.

| Connect stack | Services |
|---|---|
| `ordered_operation_log_connect_stack`, `unordered_operation_log_connect_stack` | Historical operation ranges and subscriptions |
| `immutable_operation_log_connect_stack`, `keyless_operation_log_connect_stack` | Historical operation ranges and subscriptions |
| `ordered_connect_stack` | Historical operations, subscriptions, current operation ranges, current key hits and exclusions, ordered key ranges |
| `unordered_connect_stack` | Historical operations, subscriptions, current operation ranges, current key hits |

Full ordered and unordered stacks require uploaded current-boundary material.
Unordered QMDB has no authenticated key-exclusion semantics: missing keys are
omitted from its `GetMany` results. Immutable and keyless logical reads are Rust
helpers; their Connect stacks expose the operation log.

`OperationLogClient` verifies historical ranges against a caller-supplied root.
Without a current-root witness this is the operation-log root. When a response
contains that witness, verification binds the operation log to the supplied
current root. Native `root_at` always returns the operation-log root;
`current_root_at` returns the current root.

Unary range verification binds the exact requested
`[start, min(start + max_locations, tip + 1))` interval. Ordered key ranges
verify a linear interval and forward pagination over authenticated successor
links. Generic key ordering follows `K::Ord`.

Rust subscriptions use `message_with_root` to obtain an independently trusted
root for each frame tip. Subscription filters support exact bytes, prefixes,
and regexes over logical keys and values. Reconnect from
`resume_sequence_number + 1`.

Subscription delivery follows Store write frames and waits for the caller to
publish a watermark covering each frame's operations. Data rows may span Store
writes; a presence marker is not required in every frame. Overlapping operation
locations in one frame are deduplicated. Retries in separate frames can deliver
operations again, so consumers must tolerate at-least-once delivery.

`OperationLogClient` also implements Commonware's sync `Source`. Construct a
sync target from a trusted operation-log root and retention range, or use
`current_sync_target` to derive the operation-log root from a witness verified
against a trusted current root.

The update-row pruning helpers `prune::keep_latest_updates(count)` and
`prune::keep_positions_gte(min_location)` return SDK prune policies using the
actual prefix-free key layout. Applications explicitly choose Store-row pruning
and replay-log retention policies; source bitmap pruning does not trigger either.
Retain the rows needed to serve the application's promised historical reads and
proofs.

## Browser scope

The TypeScript/WASM API supports both MMR and MMB. `QmdbOperationLogClient`
authenticates historical operation ranges as raw bytes across backend and
encoding variants. It also exposes fixed keyless append and fixed unordered
update helpers that check the requested operation's semantics.

`OrderedQmdbClient` decodes variable-encoded ordered operations with `Vec<u8>`
keys and values. Its typed historical ranges, subscriptions, current operation
ranges, key lookups, and ordered key ranges use that codec. Raw historical range
support does not imply typed browser API parity for fixed ordered, immutable,
keyless, or unordered operations, or generic current proof support.

TypeScript subscription decoding checks internal proof consistency; callers
must compare each returned root with an independently trusted root for that
frame tip before using its operations. See the [TypeScript package](../ts/README.md)
for its transport and verification API.

## Variant tests

The `e2e_variants` suite covers 72 named source combinations:

| Module | Combinations |
|---|---:|
| `variants/ordered.rs` | 20: any/current × five encoding/key/value shapes × MMR/MMB |
| `variants/unordered.rs` | 20: any/current × five encoding/key/value shapes × MMR/MMB |
| `variants/append.rs` | 20 immutable + 12 keyless: encoding/key/value shapes × full/compact × MMR/MMB |

Fixed encoding uses fixed keys and values. Variable encoding covers fixed and
variable values with each supported key shape. Keyless variants omit keys.
Names follow the Commonware hierarchy and identify each dimension, for example
`test_current_ordered_variable_variable_keys_fixed_values_mmb`. Source
partitions derive from that name and their role (`merkle`, `log`, or `grafted`).

Partitioned indexes use the same operation codecs and proof types as plain
indexes. For the same authenticated history, partitioning does not affect proof
construction or verification. The matrix uses plain source indexes to cover
these shared interfaces; partitioned databases remain supported without
separate Exoware test cases.

These tests build roots and proof packets with public Commonware DB aliases,
then use the shared production preparation, Store staging, readers, and Connect
clients. They cover successive batches, keyed updates/deletes where applicable,
historical ranges, and independently trusted root checks. Current ordered cases
also cover bitmap activity, hits, exclusions, and paginated key ranges. Separate
current ordered tests exercise complete bitmap chunks, grafted nodes, pruning,
and proofs at older boundaries.

Every case checks its final Connect proof against a browser fixture. The browser
matrix independently enumerates all 72 names and verifies those raw historical
proofs with WASM, including current-root witnesses and rejection of tampered
roots, requests, and operations.

```sh
cargo test -p exoware-qmdb --test e2e_variants
cd qmdb/ts
npm run build:wasm
npm run build:ts
npm run test:client
```

After intentional fixture changes, regenerate them with
`UPDATE_FIXTURES=1 cargo test -p exoware-qmdb --test e2e_variants` and run the
browser matrix again.
