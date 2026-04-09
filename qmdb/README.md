# exoware-qmdb

QMDB instance backed by the Exoware API.

## Status

`exoware-qmdb` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Supported backends

The crate supports multiple Commonware authenticated backends:

- **Ordered QMDB** (`OrderedClient`): `qmdb::any` and `qmdb::current::ordered`
- **Unordered QMDB** (`UnorderedClient`): `qmdb::any::unordered::variable`
- **Immutable** (`ImmutableClient`): `qmdb::immutable`
- **Keyless** (`KeylessClient`): `qmdb::keyless`

All backends share the same upload -> publish watermark -> historical root /
range-proof flow. `OrderedClient` additionally supports current-state ordered
proofs at uploaded batch boundaries.

## Ordered QMDB

The ordered client stores:
- exact ordered QMDB operations by global `Location`
- per-key historical update rows for `key <= watermark` lookup
- historical ops-MMR nodes by global `Position`
- versioned current-state deltas:
  - bitmap chunks
  - grafted MMR nodes

### Why the ordered client exists

The application-facing query API wants store-style historical reads:
- "what was the latest value for key K at `location <= X`?"

But the proof system wants Commonware QMDB types:
- historical proofs over the ordered operation log
- current-state ordered proofs that include activity bitmap state

The ordered client keeps those two views aligned over one uploaded ordered
operation log.

For immutable reads, `ImmutableClient` also persists a keyed historical update
family so `ImmutableClient::get_at` can use the same reverse indexed lookup
pattern as the ordered QMDB path instead of replaying the whole operation prefix.

## Operation model

### OrderedClient

`OrderedClient` requires exact Commonware ordered-variable operations:

- `qmdb::any::ordered::variable::Operation<Vec<u8>, Vec<u8>>`

That is why plain key-value batch uploads are rejected for the ordered path:
the client cannot safely invent the predecessor-repair operations or `next_key`
links required by `qmdb::current::ordered`.

Use:

- `upload_operations(latest_location, operations)`
- `upload_current_boundary_state(latest_location, boundary_state)`

or, if the caller already has both pieces ready at once:

- `upload_operations_with_current_boundary(...)`

### UnorderedClient

`UnorderedClient` operates on unordered-variable operations:

- `qmdb::any::unordered::variable::Operation<K, V>`

It provides the same upload/publish/proof flow as the ordered client but
without current-state ordered proofs (no bitmap chunks or grafted nodes):

- `upload_operations(latest_location, operations)`
- `publish_writer_location_watermark(location)`
- `root_at(watermark)`
- `operation_range_proof(watermark, start_location, max_locations)`
- `query_many_at(keys, watermark)`

## Stored key families

The crate stores several store key families using `KeyCodec` prefixes:

- watermark rows
- presence rows
- operation rows
- keyed historical update rows
- historical ops-MMR node rows
- current bitmap chunk delta rows
- current grafted-node delta rows

 The update-row family is keyed by:

- ordered, prefix-free raw key bytes
- global operation location

This makes historical "latest update for key at or below watermark" lookups fast.

### Compaction prune-policy helpers

Callers do not need to hand-write generic prune-policy regexes for the standard
QMDB update-row family. `exoware-qmdb` exposes typed builders in `store_qmdb::prune`:

- `store_qmdb::prune::keep_latest_updates(count)`
- `store_qmdb::prune::keep_positions_gte(min_location)`

 These return `exoware_sdk_rs::prune_policy::PrunePolicy` values using the crate's
 actual update-key layout:

- ordered raw key bytes where:
  - raw `0x00` is escaped as `0x00 0xFF`
  - end-of-key is encoded as `0x00 0x00`
- trailing big-endian `Location`

Authenticated backends use separate namespaced families:

- `AUTH_OP_FAMILY`
- `AUTH_NODE_FAMILY`
- `AUTH_WATERMARK_FAMILY`
- `AUTH_INDEX_FAMILY`

For immutable keyed reads there is one additional family:

- `AUTH_IMMUTABLE_UPDATE_FAMILY`

The authenticated op/node/watermark/presence families reserve the first payload
byte for the backend namespace tag:

- `1` => immutable
- `2` => keyless

The immutable keyed-update family uses the same ordered prefix-free key /
location layout as the ordered QMDB update-row family, but under its own
authenticated prefix. This keeps immutable `get_at(key, watermark)` efficient:
read the latest keyed row with `location <= watermark`, then load exactly that
operation location to recover the typed value.

## Historical proof path

Historical helpers operate on the exact uploaded ordered operation log:

- `root_at(watermark)`
- `operation_range_proof(watermark, start_location, max_locations)`
- `multi_proof_at(watermark, keys)`
- or the generalized variant-selected helpers:
  - `root_for_variant(watermark, QmdbVariant::Any)`
  - `operation_range_proof_for_variant(watermark, QmdbVariant::Any, start_location, max_locations)`

These use persisted ops-MMR nodes keyed by global `Position`.

ASCII view:

```text
ordered operations log

loc:   0   1   2   3   4   5   6   7
       |   |   |   |   |   |   |   |
       v   v   v   v   v   v   v   v
ops:  op--op--op--op--op--op--op--op
         \_________________________/
             historical proofs
             root_at / range / multi
```

## Current ordered proof path

Current ordered helpers are:

- `current_root_at(watermark)`
- `current_operation_range_proof(watermark, start_location, max_locations)`
- `key_value_proof_at(watermark, key)`
- or the generalized variant-selected helpers:
  - `root_for_variant(watermark, QmdbVariant::Current)`
  - `operation_range_proof_for_variant(watermark, QmdbVariant::Current, start_location, max_locations)`

These are only available at uploaded batch locations, i.e. the
`latest_location` passed to an uploaded batch boundary state.

They do not replay the whole operation prefix on reads.

Instead, uploaded batch-boundary state persists versioned current-state rows
keyed by the uploaded batch location where that batch's final current state is
defined:

- bitmap chunk rows
- grafted-node rows

These uploads are sparse:

- include only changed chunks
- include only changed grafted nodes
- always include the boundary root

At proof time, the reader fetches:

- historical ops-MMR peaks from persisted global node rows
- the latest bitmap chunk rows at or below the requested watermark
- the latest grafted-node rows at or below the requested watermark

This preserves lower-watermark proofs below a later published low watermark
without requiring full-prefix replay during proof reads.

ASCII view:

```text
historical ops MMR rows             current-state rows at batch boundaries

Position -> digest                  (chunk, boundary)        -> chunk bytes
                                    (grafted_node, boundary) -> grafted digest

proof at boundary B reads:

  ops peaks at B
       +
  latest chunk rows with version <= B
       +
  latest grafted-node rows with version <= B
       =
  current::ordered root / proof at B
```

### What "keyed by batch location" means

The current-state rows are not keyed by every operation in the batch.
They are keyed by the batch boundary, i.e. the highest operation location in the
uploaded slice.

Concrete example:

- batch A covers locations 10..13
- batch A latest location is 13
- inside batch A:
  - location 10: `Update(alpha = v1)`
  - location 11: `Update(beta = v1)`
  - location 12: `Delete(alpha)`
  - location 13: `Update(gamma = v1)`

Suppose chunk 0 covers locations 0..255.

Then the boundary-state upload writes one versioned chunk row for the batch
boundary:

- `(chunk=0, version=13) -> bitmap after applying location 13`

and similarly for any grafted nodes whose digests changed by the end of that batch.

If the next uploaded batch ends at location 20 and touches the same chunk, then
another boundary-state upload writes:

- `(chunk=0, version=20) -> bitmap after applying location 20`

ASCII view:

```text
chunk 0 history

(chunk=0, version=13) ---> bitmap after batch ending at 13
(chunk=0, version=20) ---> bitmap after batch ending at 20
(chunk=0, version=35) ---> bitmap after batch ending at 35

query current proof at boundary 20:
  read latest row with version <= 20
  => use version 20

query current proof at boundary 13:
  read latest row with version <= 13
  => use version 13
```

When a reader asks for a current proof at watermark 13, it reads:

- the latest chunk row with `version <= 13`
- the latest grafted-node rows with `version <= 13`

When a reader asks for a current proof at watermark 20, it reads:

- the latest chunk row with `version <= 20`
- the latest grafted-node rows with `version <= 20`

So a later publication at watermark 20 does not destroy the ability to answer a
proof at watermark 13. The older state is still recoverable because the rows
were versioned by batch location, not overwritten by the latest watermark.

The trade-off is intentional:

- fewer current-state rows
- current proofs only at batch boundaries

Efficient example:

```text
batch A ends at 13
  touches chunk 0
  changes grafted leaves/ancestors on the path for chunk 0

upload:
  root@13
  chunk 0 @ 13
  changed grafted nodes @ 13

batch B ends at 20
  also touches chunk 0 only

upload:
  root@20
  chunk 0 @ 20
  changed grafted nodes @ 20

what is NOT uploaded:
  chunk 1 @ 20
  chunk 2 @ 20
  unchanged grafted nodes @ 20
```

## Two-phase upload and publication

The intended flow is now:

1. upload exact ordered operations for a batch boundary
2. upload the sparse current-state rows for that same batch boundary
3. later, publish a low watermark once you know which uploaded batch boundaries
   form the largest contiguous trusted prefix

The key point is that watermark publication no longer computes current-state
rows. It only:

- checks that the requested watermark is an uploaded batch boundary
- checks that current boundary state has already been uploaded for that boundary
- persists the historical ops-MMR node delta for the newly published suffix
- writes the watermark row that fences readers

So current-state work can be staged ahead of time with uploads, while watermark
publication remains the lightweight trust/fencing step.

ASCII flow:

```text
phase 1: stage data

  upload_operations(latest_location, ops)
                +
  upload_current_boundary_state(latest_location, boundary_state)

phase 2: trust the contiguous frontier

  publish_writer_location_watermark(W)

where W is the highest uploaded batch boundary such that every location in
[0, W] is known complete.
```

## Concurrent uploads vs watermark publication

Uploads do not have to become serial.

The model is:

- uploads may happen concurrently and out of order for disjoint ranges
- boundary-state uploads may also happen concurrently and out of order
- watermark publication advances one monotonic contiguous frontier

That frontier means:

- publishing watermark `W` asserts that every location in `[0, W]` is present
- readers and proof generation may trust any requested watermark `<= W`

This does not require publishing every intermediate watermark, and it does not
require upload order to match location order.

Example:

- worker A uploads locations `[0, 99]`
- worker C uploads locations `[200, 299]`
- worker B later uploads the missing middle `[100, 199]`

No reader trusts watermark 299 until the holes are filled and the publisher
advances the contiguous frontier to 299.

ASCII frontier:

```text
locations:

  0 ---------------- 99 100 --------------- 199 200 --------------- 299
  [ uploaded by A ]      [ uploaded by B ]      [ uploaded by C ]

possible arrival order:
  A, then C, then B

trusted low watermark:

  after A:  99
  after C:  still 99    (gap 100..199 not complete)
  after B:  299
```

Once that happens:

- uploads were still concurrent
- batch-boundary current state could have been staged before publication
- publication only processed the suffix's historical ops-MMR node delta and
  then advanced the trusted frontier
- current proofs can still be asked for lower uploaded batch boundaries like 199
  because the current-state rows were versioned by batch location

## Public query and proof fencing

All query and proof APIs are fenced by the latest published writer watermark.

That means:
- uploads may arrive out of order
- readers only trust watermarks that have been explicitly published
- proofs can still be requested at lower published watermarks

ASCII rule:

```text
uploaded boundaries:   99      199      299
                       |        |        |
staged current state:  yes      yes      yes
published watermark:            199

allowed:
  current_root_at(199)
  current_root_at(99)

not allowed:
  current_root_at(299)   // not yet published
  current_root_at(150)   // not a batch boundary
```

## Tests

The crate tests use real local Commonware databases as reference
implementations and check:

- ordered QMDB historical proof parity
- ordered QMDB current proof parity
- immutable historical root / query / range-proof parity
- keyless historical root / read / range-proof parity
- authenticated immutable indexed point-read behavior
- authenticated unpublished-watermark fencing
- authenticated partial-range and range-validation edge cases

There is also explicit coverage for current proofs below a later published low
watermark.
