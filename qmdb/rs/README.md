# exoware-qmdb

Upload Commonware QMDB data to an Exoware Store, serve proof queries, and verify
responses against trusted roots. The crate supports ordered, unordered,
immutable, and keyless databases with MMR or MMB Merkle trees.

The application captures operations from its Commonware database and uses
`adapter::upload` to prepare Store rows. After writing those rows, the application
publishes a watermark identifying the durable prefix it is ready to serve.
`adapter` readers query that data directly, while `service::server` exposes it
through ConnectRPC and `service::client` verifies the responses.

## Read and verify

Queries identify a database state by its tip, the inclusive final operation
location, and its root, a hash commitment to that state. The following example
reads an already published keyless operation log through ConnectRPC. It uses
variable-length byte values and verifies the response against an
application-supplied root:

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

The endpoint must serve that database and codec, and the root and tip must come
from authenticated application state. The example allows values up to 4,096
bytes and returns up to the first 100 operations at `tip`. For HTTPS or
authentication, use `new` with a configured transport.

### Proofs and roots

`OperationRangeProof` authenticates consecutive log entries, and
`OperationMultiProof` authenticates entries at selected locations. Both establish
log membership, so an included update need not still be active.

For queries about active state, `Current*` proofs also authenticate the activity
bitmap at a batch boundary, the final commit location of an applied batch.
Current key proofs establish active values, and ordered key proofs can establish
absence. "Current" refers to that requested boundary, which may be older than
the latest published boundary.

For a database with current state, pass its trusted current root. The proof's
operation-root witness binds the operation log to that root. For an
operation-log-only database, pass its trusted operation-log root. Native adapter
readers check proofs against stored roots, while service clients check against
caller-supplied roots. A root received with an untrusted response is not a trust
anchor.

Range verification binds the tip and the exact interval
`[start, min(start + max_locations, tip + 1))`. Multi-proof verification binds the
tip and the requested locations. The `GetOperations` RPC requires a nonempty, strictly
ascending list of at most 1,024 locations. The native
`Unordered::operation_multi_proof` and `Keyless::operation_multi_proof` helpers
accept larger valid sets.

## Choose a reader and service

Choose the `adapter` reader that matches your source database. All four expose
operation roots and range proofs, with additional queries for each kind:

| Reader | Additional queries |
| --- | --- |
| `Ordered` | Indexed reads at a tip, current key hits, exclusions, and ordered key ranges |
| `Unordered` | Indexed reads at a tip and current key hits |
| `Immutable` | `get_at` by key |
| `Keyless` | `get_at` by operation location |

Current queries require uploaded current-boundary material. For unordered QMDB,
`get_many` omits missing or inactive keys because it has no exclusion proofs.
For ordered QMDB, keys must have the same `K::Ord` ordering as their raw bytes.

Readers take a `PrefixedStoreClient` and the source's codec configuration. They
support fixed and variable encodings, with `VariableEncoding<V>` as the default.
Source index partitioning and full or compact storage do not change the upload
format. Keep each namespace to a single operation history, Merkle family,
hasher, and codec by using distinct SDK prefixes or Stores for separate
instances.

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

To inspect publication state, use `latest_published_watermark` for the greatest
published location observed by a native reader and `root_at` for the canonical
root at a tip. Ordered and unordered readers also expose the underlying log root
through `ops_root_at`. On proof requests, an optional `min_sequence_number` sets
the minimum Store sequence for the publication lookup. Proof reads use the
sequence observed by that lookup as their minimum.

## Upload and publish

The [`adapter::upload`](src/adapter/upload/mod.rs) functions prepare Store rows
from captured Commonware operations and proof material. The application owns
capture, durable queuing, retries, and publication around these stateless
functions.

An `AuthenticatedOperationRange` contains every canonical encoded operation in
`[start_location, end_location)`, the prefix pins in `Family::nodes_to_pin` order,
and the inactive-peak count determined by the final commit's floor. The range
must end at a commit. It may contain earlier commits, overlap earlier uploads,
or begin at zero, where no pins are needed. Preserve the source's exact operation
order, including ordered QMDB's predecessor repairs and successor links.

Pass this range to `prepare_authenticated_range` with the source's codec
configuration and an independently trusted operation-log root. It checks the
operations and pins against that root, then prepares operation, index, and
Merkle rows. For an operation-log-only database with a complete prefix that fits
in one atomic Store Put, data and publication can be staged together. Here `F`,
`H`, and `Op` are the source's family, hasher, and operation type:

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

Workers can prepare and upload ranges independently and out of order, provided
the application coordinates publication after all required writes succeed.
Repeated rows from the same history have identical keys and values, so the same
packet can be retried. To make retries and recovery possible, persist operations,
proof material, trusted roots, and any current-boundary material before allowing
the source to discard them.

### Current-state boundaries

For a current ordered or unordered database, each uploaded batch also carries
its `Delta`: the batch's current root, the witness binding the operation-log
root to it, the bitmap chunks and grafted nodes the batch wrote, and the
source's `pruned_chunks` count. Read the batch's `Publication` before applying
the batch, then prepare its operations and delta against the trusted current
root:

```rust,ignore
use exoware_qmdb::adapter::upload::prepare_publication;

let publication = batch.publication(&db)?;
let prepared =
    prepare_publication::<F, H, U, Sequential, N>(&publication, &trusted_root, &Sequential)?;
```

To upload a range that was persisted as encoded operations, prepare it with
`prepare_authenticated_range` and attach the delta of the batch that ends it:

```rust,ignore
let prepared = prepared.with_current_boundary::<H, N>(&delta)?;
```

The delta must describe the range's final location, using the source's family,
hasher, and chunk size `N`. `with_current_boundary` checks the witness's binding
to the prepared operation-log root, but it does not authenticate the supplied
chunks, nodes, or pruning count. A delta holds only what its batch wrote, so
upload one for every batch since the source was created.

Boundary rows are versioned by batch location. Unchanged chunks and nodes are
inherited from earlier boundaries. Retain the rows needed for every historical
tip you promise to serve. Source bitmap pruning does not delete Store rows or set
backend retention. The [`adapter::prune`](src/adapter/prune.rs) helpers construct
policies for update-index rows. Applications choose Store pruning and replay-log
retention separately.

### Pin omission

Successive or overlapping uploads can share prefix pins, the Merkle digests
needed to authenticate the log before a range starts. When another upload
supplies those pins, you can avoid writing them again.
`stage_authenticated_range` includes all supplied prefix pins by default.
`prepared.without_pins_at(&positions)` omits supplied pins at exactly those
`BTreeSet<Position<F>>` positions. Preparation still authenticates every pin,
and reconstructed nodes and all other prepared rows are always staged.

Omit a pin only when the same authenticated digest in the same namespace and
history will be durable before publication and retained for serving proofs.
The pin may already be durable or depend on a pending predecessor upload. In
the latter case, the application must preserve that dependency through failures,
retries, and restarts. The library does not inspect Store or infer durability
from range bounds, so keep all pins for a nonzero bootstrap or restart when
their availability is not guaranteed.

## Subscriptions and synchronization

Read subscription frames with `message_with_root`, supplying a callback that
returns an independently trusted root for each frame's tip. Filters select
logical keys and values by exact bytes, prefixes, or regexes. To reconnect,
resume from `resume_sequence_number + 1`.

Delivery follows Store write frames and waits for publication to cover each
frame's operations. A frame can contain only part of an uploaded range.
Overlapping locations within a frame are deduplicated, but retries in later
frames can repeat operations. Consumers must tolerate at-least-once delivery.

To synchronize a local Commonware database from the uploaded log, use
`OperationLogClient` as a sync `Source`. Build its sync target from a trusted
operation-log root and retention range. For a current database,
`current_sync_target` derives the operation-log root from a witness checked
against the trusted current root.

## Status

`exoware-qmdb` is **ALPHA** software and is not yet recommended for production
use. Developers should expect breaking changes and occasional instability.
