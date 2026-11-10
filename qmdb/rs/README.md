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
location, and its root, a hash commitment to that state. A tip is a location at
or below the published watermark. Keyless and immutable roots and operation
proofs need a tip that is a commit, current-state reads need a commit whose
`Publication` was uploaded, and other reads accept any such tip. The following
example reads an already published keyless operation log through ConnectRPC. It
uses variable-length byte values and verifies the response against an
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
    expected_root: &Digest,
) -> Result<Vec<Op>, QmdbError> {
    let client = OperationLogClient::<_, mmr::Family, Sha256, Op>::plaintext(
        endpoint,
        ((0..=4096).into(), ()),
    );
    let result = client
        .operation_range(
            GetOperationRangeRequest {
                tip: tip.as_u64(),
                start_location: 0,
                max_locations: 100,
                ..Default::default()
            },
            expected_root,
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

For queries about active state, the current-state proofs (`KeyValueProof`,
`KeyExclusionProof`, and `CurrentOperationRangeProof`) also authenticate the
activity bitmap at the tip, which must be a commit whose `Publication` was
uploaded. Key-value proofs establish active values, and ordered key-exclusion
proofs can establish absence. "Current" means current as of that tip, which may
be older than the latest published watermark.

For a database with current state, pass its trusted current root. The proof's
operation-root witness binds the operation log to that root. For an
operation-log-only database, pass its trusted operation-log root. Native adapter
readers check proofs against stored roots, while service clients check against
caller-supplied roots. A root received with an untrusted response is not a trust
anchor.

Range verification binds the tip and the exact interval
`[start, min(start + max_locations, tip + 1))`. Multi-proof verification binds the
tip and the requested locations. The `GetOperations` RPC requires a nonempty, strictly
ascending list of at most 1,024 locations. Each native reader's
`operation_multi_proof` accepts larger valid sets.

## Choose a reader and service

Choose the `adapter` reader that matches your source database. All four expose
operation roots, range proofs, and reads at selected locations (`operations` and
`operation_multi_proof`), with additional queries for each kind:

| Reader | Additional queries |
| --- | --- |
| `Ordered` | `get_many_at` by key, current key hits, exclusions, and ordered key ranges |
| `Unordered` | `get_many_at` by key and current key hits |
| `Immutable` | `get_at` by key |
| `Keyless` | `get_at` by operation location |

The `get_at` and `get_many_at` reads return indexed values at a tip without a
proof.

Current queries require uploaded current-state publications. For unordered QMDB,
`get_hits` returns only active keys and omits the rest, because it has no
exclusion proofs. For ordered QMDB, keys must have the same `K::Ord` ordering as
their raw bytes.

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

To inspect the watermark, use `latest_published_watermark` for the greatest
published location observed by a native reader and `root_at` for the canonical
root at a tip. Ordered and unordered readers also expose the underlying log root
through `ops_root_at`. Every read at a tip takes an optional
`min_sequence_number`, the minimum Store sequence for the watermark lookup.
The read then uses the sequence observed by that lookup as its minimum.

## Upload and publish

The [`adapter::upload`](src/adapter/upload.rs) functions prepare Store rows
from captured Commonware operations and proof material. The application owns
capture, durable queuing, retries, and advancing the watermark around these
stateless functions.

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
in one atomic Store Put, data and the watermark can be staged together. Here `F`,
`H`, and `Op` are the source's family, hasher, and operation type:

```rust,ignore
use commonware_parallel::Sequential;
use exoware_qmdb::adapter::upload::{
    prepare_authenticated_range, stage_authenticated_range, stage_watermark,
};
use exoware_sdk::StoreWriteBatch;

let prepared = prepare_authenticated_range::<F, H, Op, Sequential>(
    &range,
    &expected_root,
    &op_cfg,
    &Sequential,
)?;
let latest = prepared.latest_location();
let mut batch = StoreWriteBatch::new();
stage_authenticated_range(&store, prepared, &mut batch)?;
stage_watermark::<F>(&store, latest, &mut batch)?;
let sequence = batch.commit(store.client()).await?;
```

For incremental or split uploads, publish watermark `W` only after every required
row in the contiguous prefix through `W` is durable. This includes pins, indices,
and any current-state rows inherited from earlier batches. If `[0, 100)` and
`[200, 300)` are durable, only the prefix through 99 can be published. Once
`[100, 200)` is durable, the watermark can advance to 299 without publishing each
intermediate commit.

Workers can prepare and upload ranges independently and out of order, provided
the application advances the watermark only after all required writes succeed.
Repeated rows from the same history have identical keys and values, so the same
packet can be retried. To make retries and recovery possible, persist operations,
proof material, trusted roots, and any current-state publications before
allowing the source to discard them.

### Current-state publications

A current ordered or unordered database uploads a `Publication` for every batch:
its operations and frontier plus the current-state rows (root, witness, bitmap
chunks, and grafted nodes) that current queries need. `prepare_publication`
checks the operations, frontier, and witness against an independently trusted
current root and prepares all of those rows. The bitmap chunks, grafted nodes,
and pruned chunk count are not authenticated and must come from the source of
the batch. Stage the rows with `stage_authenticated_range` as above, and the
same prefix rule governs when the watermark may advance past them.

If a chunk or grafted node is wrong or missing, or the pruned chunk count is
wrong, the upload still succeeds. A read that needs that value then returns an
error at that batch's tip, and at later tips until a later batch rewrites the
same chunk or node. To repair it, upload the batch's correct publication again
and create new readers, because a reader caches what it has loaded.

#### Initialization

A new database's commit at location 0 belongs to no batch, so upload its
publication once, before the first batch's. Staging its rows and then watermark 0
publishes location 0:

```rust,ignore
use exoware_qmdb::adapter::upload::{prepare_publication, Publication};

let initial = Publication::initial(&db)?;
let prepared =
    prepare_publication::<F, H, _, _, N>(&initial, &expected_root, &Sequential)?;
```

#### Updates

Build each batch's publication before applying the batch and while its
unapplied ancestors are still held. Its frontier is readable only until the
batch's changes are flushed:

```rust,ignore
let batch = batch.merkleize(&db).await?;
let publication = Publication::from_batch(&batch, &db)?;
let prepared =
    prepare_publication::<F, H, _, _, N>(&publication, &expected_root, &Sequential)?;
db = db.apply_batch(batch).await?;
```

To upload later, persist the publication with its codec and decode it with a
`PublicationCfg`. A persisted or uploaded publication commits the source to that
batch, so rebuild it identically after a restart.

Current-state rows are versioned by batch location. Unchanged chunks and nodes
are inherited from earlier batches. Retain the rows needed for every historical
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
history will be durable before the watermark covers it and retained for serving
proofs. The pin may already be durable or depend on a pending predecessor
upload. In the latter case, the application must preserve that dependency
through failures, retries, and restarts. The library does not inspect Store or
infer durability from range bounds, so keep all pins for a nonzero bootstrap or
restart when their availability is not guaranteed.

## Subscriptions and synchronization

Read subscription frames with `message_with_root`, supplying a callback that
returns an independently trusted root for each frame's tip. Filters select
logical keys and values by exact bytes, prefixes, or regexes. To reconnect,
resume from `resume_sequence_number + 1`.

Delivery follows Store write frames and waits for the watermark to cover each
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
