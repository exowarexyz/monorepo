# exoware-server

[![Crates.io](https://img.shields.io/crates/v/exoware-server.svg)](https://crates.io/crates/exoware-server)
[![Docs.rs](https://docs.rs/exoware-server/badge.svg)](https://docs.rs/exoware-server)

Serve the Exoware API.

## Status

`exoware-server` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Overview

`exoware-server` provides a backend-less ConnectRPC server for the Exoware API.
Implement the storage capability traits for your backend, wrap them in `AppState`,
and call `connect_stack` to get a ready-to-serve router with ingest, query,
prune, retention, and stream services. Backends that implement every capability
automatically implement the `StoreEngine` compatibility facade.
Split deployments can instead mount `ingest_service`, `query_stack`,
`prune_service`, `retention_service`, or `stream_service` with the narrower
component state. The stream service accepts an in-process `StreamNotifier`;
`StreamHub` is the local default.

Custom GetMany handlers can call `validate_get_many_request(request.view())`
before opening a backend snapshot. Compare `min_sequence_number` with the
snapshot sequence before returning data. If the snapshot is below that floor,
return `consistency_not_ready_error(required, current)` to preserve the standard
error details and standard retry hint. Both helpers are exported from the crate root.

The shared Put adapter accepts Connect unary protobuf requests with identity or
bounded single-frame zstd encoding. It rejects Connect JSON, gzip request
compression, gRPC, gRPC-Web, and Connect streaming envelopes. Custom clients must
select the Connect unary protocol and binary protobuf. See
[Put client compatibility](../proto/README.md#put-client-compatibility) for the
format table, request headers, and zstd restrictions.

The adapter admits transport capacity before reading and lends `&mut PutInput`
to `Ingest::put`. Backends incrementally decode into
reserved preparation storage and call `finish().await` before publication.
Rejected input is drained separately within its wire bound and original deadline.
Encoding rejections advertise zstd through `Accept-Encoding`.
Other services continue through the ordinary ConnectRPC dispatcher and still
accept JSON and gzip requests.

Custom ingest handlers can reuse `PutEntryCursor`, `UnknownBudget`,
`decode_entry_with_budget`, and the validation and error helpers exported from
the crate root.

Call `message_bound().await` before sizing preparation memory. Identity requests
use their enforced wire and message limits. Zstd requests use the validated size
pledge. Inspection runs through the configured CPU executor and retains any
charged payload suffix without starting the decoder or allocating entry buffers.
The bound is cached. `finish().await` still verifies the complete request before
publication.

Admission ownership follows the allocations and work it protects. Detached CPU
jobs own decoding state and reservations. Accepted writer work retains its
reservations and advances the subscriber notifier after durable publication,
even when the requesting future has been cancelled.

Serve the combined service through the shared ingest listener to enforce HTTP/1.1
termination when unfinished requests reach their deadlines. Returning an error
response alone cannot bound connection lifetime when outbound writes are blocked.
HTTP/2 cleanup failure terminates the affected stream.

Put uses `connect-timeout-ms` when present and otherwise uses `PutConfig.timeout`,
which defaults to 30 seconds. Both are capped by `PutConfig.max_timeout`, which
defaults to five minutes. Clients can request more time than the fallback, but
cannot extend the host ceiling. Malformed timeout headers are rejected with
cleanup bounded by the smaller of the fallback and the host ceiling.

The same absolute deadline covers middleware, reception, decoding, backend work
and rejection cleanup. Stalled uploads cannot extend it during graceful shutdown.
Configure the fallback and ceiling for `max_wire_bytes` over the slowest supported
link, with room for processing and backend latency. Cancellation does not release
reservations still owned by detached decoding or accepted writer work. Those
reservations remain charged until the work releases its allocations.

`PutConfig.idle_timeout` defaults to `Some(Duration::from_secs(30))`. It bounds
waiting for the first body bytes, subsequent nonempty data, and HTTP EOF. Empty
frames and trailers do not reset it. Time spent decoding or processing batches
does not consume this allowance. Cancelled read attempts retain elapsed waiting
time, and rejection cleanup cannot restart an expired timer. Set it to `None`
to use only the absolute deadline. Clients that continually trickle bytes are
still bounded by the absolute deadline.

`AppState::with_put_config` and `IngestState::with_put_config` configure the host
budget, admitted wire bound, timeout, and observer. Memory upgrades fail immediately
while bootstrap admission is held. Known request lengths reserve their enforced
wire bound. Unknown lengths reserve the configured wire maximum before the first
body poll. Requests rejected from metadata retain only a request slot during raw
cleanup, which still enforces the wire bound and deadline. Hosts must leave room for decoder and backend reservations in addition
to transport admission. The byte budget accounts for admitted request allocations.
Fixed listener overhead and storage-engine memory have separate bounds.

Temporary initial-admission failures include a typed backoff hint. See the
[admission retry contract](../proto/README.md#admission-retries). Admission does
not queue requests while the budget is exhausted, and memory upgrades remain
fail-fast while existing reservations are held.

With the shared listener, initial-admission rejections send error details without
waiting for the upload body. HTTP/1 closes the connection and bounds blocked
error writes to one second. HTTP/2 allows up to one second for response flow
control and cancels only the rejected stream if that wait expires. Both bounds
respect the original request deadline. If delivery fails, the client may receive
a transport error instead of the retry details.

The simulator also needs a native SST staging allowance outside `IngestBudget`.
RocksDB copies the encoded log value while its Rust buffer is still live and
builds the state SST in parallel. Each `stage_workers` worker stages one wave.
Each wave is capped at 256 MiB of canonical Put encoding and 2,000,000 entries.
Allow native headroom per active worker for those buffers and table-building
overhead. `max_commit_batch_bytes` is a soft coalescing threshold, not a native
memory ceiling.

Direct simulator `RocksStore::put_batch` calls use a separate budget of 256
requests and 1 GiB. They do not consume the budget supplied through `PutConfig`.
Mixed direct and HTTP traffic can consume both budgets at once.

Use `ingest::maximum_reception_bytes(limits, &buffers)` when checking that a host
budget can admit one maximum Put. Pass the enforced `PutLimits` and the largest
`DecodeBuffers` capacities used by the backend. The checked estimate covers
transport admission and copies, decoding with one returned chunk still alive,
allocation replacement, entry ranges, and the maximum accepted zstd workspace.
Large fields can grow beyond
the requested byte capacity up to the message limit. Add backend preparation and
any additional retained chunk or slice allocations separately. Those owners retain
their full backing capacity.

Observers receive byte counts, HTTP EOF, validation and cleanup outcomes, and phase
elapsed times. Response timing ends when the adapter returns the response. It does
not measure the peer receiving the response.

## Protocol limits

See the [language-independent protocol contract](../proto/README.md) for the
portable Put limits and size error details. Default ingest validation uses the
published limits. A deployment can explicitly configure larger limits, but
requests above the published baseline are not portable.

Transport admission has separate backstops. Request bodies and decompressed
messages are capped at 256 MiB. The ordinary ConnectRPC dispatcher caps decoder
element memory at 192 MiB. Put uses the ingest validation limits and the configured
`IngestBudget` for allocation admission.
Stored stream responses and the Rust SDK response decoder allow 512 MiB messages
and 256 MiB of element memory. The response byte budget leaves room for metadata
and compression overhead when reading a full-size request back.
Element memory is counted across a message's decoded
elements. These limits do not describe total process memory or concurrent
request capacity.

The 2,000,000 entry baseline is an Exoware ingest contract. No sequence-row
cap is imposed by the Exoware server. A cap imposed downstream by a store
backend remains that backend's responsibility.

Reduce uses native DataFusion aggregation and streams completed groups in bounded
frames. Groups remain in memory by default. `QueryState::with_runtime` accepts a
DataFusion `RuntimeEnv` to configure its native memory pool and spill storage.
The pool accounts for worker aggregate state; backend buffers, transient input
batches, transport frames, and client results have separate memory ownership.
Unordered aggregation consumes its input before producing results.

```rust
use bytes::Bytes;
use exoware_sdk::prune_policy::PrunePolicyDocument;
use exoware_server::{
    AppState, Log, Ingest, PutInput, PutError, Prune, Query, QueryResult,
    RangeScan, RangeScanBatch, RangeScanResult, Retention, Sequence, StoreEngine, connect_stack,
};
use std::future::Future;

// Implement the capabilities your component serves:
//   Sequence:
//   fn current_sequence(&self) -> u64;
//
//   Ingest:
//   fn put(&self, input: &mut PutInput) -> impl Future<Output = Result<u64, PutError>> + Send;
//
//   Query:
//   type RangeScan: RangeScan;
//   fn get(&self, key: Bytes) -> impl Future<Output = Result<QueryResult<Option<Bytes>>, String>> + Send + '_;
//   fn range_scan(&self, start: Bytes, end: Bytes, limit: usize, forward: bool) -> impl Future<Output = Result<RangeScanResult<Self::RangeScan>, String>> + Send + '_;
//   fn get_many(&self, keys: Vec<Bytes>) -> impl Future<Output = Result<QueryResult<Vec<(Bytes, Option<Bytes>)>>, String>> + Send + '_;
//
//   RangeScan:
//   fn next_batch(&mut self, max_items: usize) -> impl Future<Output = Result<RangeScanBatch, String>> + Send;
//
//   Prune:
//   fn apply_prune_policies(&self, document: PrunePolicyDocument) -> impl Future<Output = Result<(), String>> + Send + '_;
//
//   Log:
//   fn get_batch(&self, sequence_number: u64) -> impl Future<Output = Result<Option<Vec<(Bytes, Bytes)>>, String>> + Send + '_;
//   fn oldest_retained_batch(&self) -> impl Future<Output = Result<Option<u64>, String>> + Send + '_;
//
//   Retention:
//   fn set_retention(&self, policy: Option<RetentionPolicy>) -> impl Future<Output = Result<Option<u64>, String>> + Send + '_;
```
