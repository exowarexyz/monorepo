# exoware-server

[![Crates.io](https://img.shields.io/crates/v/exoware-server.svg)](https://crates.io/crates/exoware-server)
[![Docs.rs](https://docs.rs/exoware-server/badge.svg)](https://docs.rs/exoware-server)

Serve the Exoware API with your own storage backend.
For a local server, run the [simulator](../examples/simulator/README.md).

## Serve a backend

This crate adapts storage capabilities to Exoware's ConnectRPC services. Implement
`Ingest`, `Query`, `Prune`, `Log`, and `Retention` for your backend to serve the
complete API. `Query` and `Log` also require `Sequence` to report the local
sequence frontier. A backend with all five capabilities automatically implements
`StoreEngine`. The [backend traits](src/engine.rs) define the required methods
and their contracts.

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

For separate components, construct only the capabilities you serve with
`IngestState`, `QueryState`, `PruneState`, `RetentionState`, or `StreamState`.
The corresponding service constructors and `query_stack` are listed in the
[API reference](https://docs.rs/exoware-server). `AppState` shares a local
`StreamHub` between ingest and stream services. Split deployments need a remote
notification path that advances the query worker's local `StreamNotifier` only
after that worker can serve the announced batches. See the
[stream coordination contract](src/stream.rs).

## Implement writes and reads

`Ingest::put` receives a borrowed `&mut PutInput`. Consume its batches into
preparation storage, then successfully call `finish().await` before submitting
anything for publication. `message_bound().await` supplies a sizing bound for
preparation allocations, but does not validate the complete request. If the
backend rejects a batch through `input.reject(...)`, continue consuming through
EOF and call `finish()` so the adapter can select the correct error. The
[`Ingest` contract](src/engine.rs) specifies error precedence, and the
[simulator's implementation](../examples/simulator/src/rocks.rs) demonstrates
the write lifecycle.

Keep admission reservations with the allocations and work they protect.
Detached decoding and accepted writer work must retain their reservations when
the requesting future is cancelled. Accepted writes also retain responsibility
for advancing the supplied notifier after durable publication. Use
`PutInput::request_lease`, `reserve_bytes`, and `notifier` to transfer that
ownership. See [PutInput](src/ingest/input.rs) and the
[admission types](src/ingest/admission.rs).

Each query must return data from one consistent state, together with the sequence
number of that state. A range cursor keeps that sequence fixed for its entire
lifetime. `get_many` preserves input order. The [query and cursor
contracts](src/engine.rs) also define range bounds and end-of-stream behavior.
Custom GetMany handlers should call `validate_get_many_request(request.view())`
before opening a snapshot, then check its sequence against `min_sequence_number`.
Use `consistency_not_ready_error(required, current)` when the snapshot is behind
to return the standard details and retry hint.

## Configure limits and resources

Use `AppState::with_ingest_limits` to set validation limits and
`AppState::with_put_config` to configure transport admission, wire size, deadlines,
and observation. Ingest-only services expose the same controls through
`IngestState`. The [protocol contract](../proto/README.md) defines portable Put
limits and error details. Requests above that baseline depend on the deployment.
Put accepts Connect unary protobuf with identity or bounded single-frame zstd
encoding. See [client compatibility](../proto/README.md#put-client-compatibility)
before using a custom client.

`PutConfig` defaults to a 30-second request timeout, a five-minute ceiling, and a
30-second upload idle timeout. The `connect-timeout-ms` header can override the
fallback up to the ceiling. One absolute deadline covers middleware, reception,
decoding, backend work, and rejection cleanup. The idle timeout measures waiting for upload
progress, including HTTP EOF, and excludes decoding and backend processing time.
Set it to `None` to rely only on the absolute deadline. Size these timeouts for
the maximum accepted request and the slowest supported link. See
[PutConfig](src/ingest/service.rs).

The shared `IngestBudget` limits admitted requests and charged allocations.
Unknown-length requests reserve the configured wire maximum before reception.
Admission and memory upgrades fail immediately when capacity is unavailable.
Temporary initial-admission failures carry the [admission retry
hint](../proto/README.md#admission-retries), though a transport failure can prevent
its delivery.

Use [`maximum_reception_bytes`](src/ingest/reception.rs) with the enforced
`PutLimits` and largest backend `DecodeBuffers` capacities to estimate reception
memory for one request. Add preparation storage, extra retained chunks, listener
overhead, and storage-engine memory separately. The simulator's native SST staging
and direct `put_batch` calls have separate resource needs and budgets. Consult
[its backend configuration](../examples/simulator/src/rocks.rs) when sizing that
implementation.

The Reduce RPC uses DataFusion aggregation. Group state stays in memory by
default, and unordered aggregation consumes its input before returning results. Use
`QueryState::with_runtime` to supply a `RuntimeEnv` with a bounded memory pool and
spill storage. That pool excludes backend, transient input, transport, and client
buffers. The [query state documentation](src/connect.rs) describes this boundary.

## Status

`exoware-server` is **ALPHA** software and is not yet recommended for production use.
Developers should expect breaking changes and occasional instability.
