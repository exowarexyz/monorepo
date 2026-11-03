# exoware-server

[![Crates.io](https://img.shields.io/crates/v/exoware-server.svg)](https://crates.io/crates/exoware-server)
[![Docs.rs](https://docs.rs/exoware-server/badge.svg)](https://docs.rs/exoware-server)

Serve the Exoware API with your own storage backend, or run the
[simulator](../examples/simulator/README.md) for local development.

## Serve a backend

This crate adapts storage capabilities to Exoware's ConnectRPC services.
Implement the [backend traits](src/engine.rs) `Ingest`, `Query`, `Prune`, `Log`,
and `Retention` to serve the complete API. `Query` and `Log` also require
`Sequence` to report the local sequence frontier. Implementing these capability
traits also satisfies `StoreEngine`.

Once your backend implements those traits, this function serves it on localhost:

```rust
use exoware_server::{connect_stack, ingest::transport, AppState, StoreEngine};
use std::sync::Arc;
use tokio::net::TcpListener;

async fn serve<E: StoreEngine>(engine: Arc<E>) -> std::io::Result<()> {
    let service = connect_stack(AppState::new(engine));
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    transport::serve(listener, service, std::future::pending()).await
}
```

Call this function from a Tokio runtime. Replace `std::future::pending()` with
your shutdown future to stop accepting connections and drain active requests.
The [simulator](../examples/simulator/src/server.rs) shows a concrete backend
and an Axum router with a health endpoint.

Use `ingest::transport::serve` for services that accept Put requests. It supplies
the connection controls needed to terminate unfinished HTTP/1 uploads at their
deadline, even when response writes are blocked. HTTP/2 cleanup failure terminates
the affected stream. These bounds also apply while the listener drains requests
during shutdown.

To serve capabilities in separate components, construct the relevant
`IngestState`, `QueryState`, `PruneState`, `RetentionState`, or `StreamState`.

A query worker must be able to serve batches before announcing them, as required
by the [stream coordination contract](src/stream.rs). `AppState` shares a local
`StreamHub` between ingest and stream services. In a split deployment, provide
a remote notification path that advances the query worker's local
`StreamNotifier` only after that worker can serve the announced batches.

## Implement writes and reads

`Ingest::put` receives a borrowed `&mut PutInput`. Consume its batches into
preparation storage, then call `finish().await` and require success before
submitting anything for publication. Use `message_bound().await` to size
preparation allocations, but rely on `finish()` to validate the complete
request. Even when the backend rejects a batch through `input.reject(...)`,
continue consuming through EOF and call `finish()` so the adapter can apply
the [error precedence in the Ingest contract](src/engine.rs). The
[simulator's write path](../examples/simulator/src/rocks.rs) follows this
preparation, validation, and publication lifecycle.

Ownership must follow any work that outlives the request. Keep admission
reservations with the allocations and work they protect, so detached decoding
and accepted writer work retain their reservations if the requesting future is
cancelled. Accepted writes must also advance the supplied notifier after
durable publication. The [PutInput](src/ingest/input.rs) methods
`request_lease`, `reserve_bytes`, and `notifier` transfer that ownership through
the [admission leases](src/ingest/admission.rs) and notifier.

The [query and cursor contracts](src/engine.rs) require each query to return
data from one consistent state, together with the sequence number of that
state. A range cursor keeps that sequence fixed for its entire lifetime, and
`get_many` preserves input order. Those contracts also define range bounds
and end-of-stream behavior.

Custom GetMany handlers should call
`validate_get_many_request(request.view())` before opening a snapshot, then
check its sequence against `min_sequence_number`. Use
`consistency_not_ready_error(required, current)` when the snapshot is behind
to return the standard details and retry hint.

## Configure limits and resources

### Put limits and timeouts

Use `AppState::with_ingest_limits` to set validation limits and
`AppState::with_put_config` to configure transport admission, wire size, deadlines,
the clock, and observation. Ingest-only services expose the same controls through
`IngestState`. Custom clients must send Connect unary protobuf with identity or
bounded single-frame zstd encoding.

[PutConfig](src/ingest/service.rs) sets the absolute request deadline and upload
idle timeout, both of which default to 30 seconds. The absolute deadline covers
middleware, reception, decoding, backend work, and rejection cleanup. Clients
can override it with the `connect-timeout-ms` header, up to a five-minute ceiling.

The idle timeout includes waiting for HTTP EOF but excludes decoding and backend
processing time. Set it to `None` to rely only on the absolute deadline, and size
both timeouts for the maximum accepted request and the slowest supported link.

`PutConfig.clock` controls request deadlines, idle timeouts, and elapsed-time
measurements. It defaults to `TokioClock`. Deterministic tests can supply a
`PutClock` backed by their runtime. Use a monotonic clock in production.
Connection timers stay on Tokio. To run Put without a Tokio runtime, also replace
the default blocking decoder through `PutInput::set_executor`.

### Put admission and memory

The shared `IngestBudget` bounds admitted requests and charged allocations.
Requests with an unknown length reserve the configured wire maximum before
reception. If capacity is unavailable, admission and memory upgrades fail
immediately. Temporary initial-admission failures carry the [admission retry
hint](../proto/README.md#admission-retries), though a transport failure can
prevent its delivery.

Use [`maximum_reception_bytes`](src/ingest/reception.rs) with the enforced
`PutLimits` and largest backend `DecodeBuffers` capacities to estimate reception
memory for one request. Add preparation storage, extra retained chunks, listener
overhead, and storage-engine memory separately. The simulator's native SST staging
and direct `put_batch` calls have separate resource needs and budgets defined
by [its backend configuration](../examples/simulator/src/rocks.rs).

### Reduce memory

The Reduce RPC uses DataFusion aggregation. By default, group state stays in
memory, and unordered aggregation consumes its input before returning results.
To bound that state, use [QueryState::with_runtime](src/connect.rs) to supply
a `RuntimeEnv` with a bounded memory pool and spill storage. The pool excludes
backend, transient input, transport, and client buffers.

## Status

`exoware-server` is **ALPHA** software and is not yet recommended for production use.
Developers should expect breaking changes and occasional instability.
