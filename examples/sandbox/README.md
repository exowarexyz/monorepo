# exoware-sandbox

Explore the Exoware API.

## Prerequisites

- Node.js and npm
- Rust and Cargo

## How to Run

1. **Start the simulator**

   From the monorepo root:

   ```bash
   cargo run --package exoware-simulator -- --verbose server run --port 8080
   ```

   Point the web app at this URL via `VITE_SIMULATOR_URL` (see below). The simulator does not require a bearer token; optional `VITE_TOKEN` is only used if your SDK client is configured with one.

2. **Install dependencies and run the web app**

   ```bash
   cd examples/sandbox
   npm install --include=dev
   npm run dev
   ```

   The app and local package build steps use dev dependencies (`vite`,
   `typescript`, and `wasm-pack`-driven build tooling). `--include=dev` keeps
   this working even if your shell or npm config omits dev dependencies by
   default.

3. **Open the web UI**

   Open the URL Vite prints (usually `http://localhost:5173`).

## Features

- **Store:** set and get key-value pairs, and run range queries.
- **Ordered QMDB** (optional, requires `VITE_QMDB_URL`): current/historical
  proofs and live subscribe streaming.
- **Simplex** (optional, requires `VITE_SIMPLEX_URL`): read and subscribe to
  seeded Commonware Simplex blocks, notarizations, and finalizations, with
  latest-finalization verification through the Simplex WASM verifier.
- **SQL** (optional, requires `VITE_SQL_URL`): run ad-hoc SQL queries and
  subscribe to a SQL WHERE predicate evaluated per ingested batch.

## Store namespace

The sandbox currently runs raw Store KV, Ordered QMDB, Simplex, and SQL against
the same unpartitioned simulator Store. QMDB, Simplex, and SQL each use their
own internal key families, but the demo binaries do not assign distinct SDK
`StoreKeyPrefix` values, and raw KV can write arbitrary Store keys. This means
the sandbox is useful for exercising the individual panels, but it should not be
treated as an example of isolated multi-instance Store partitioning.

## Ordered QMDB panel

The QMDB panel is only rendered when `VITE_QMDB_URL` is set, since it requires
a separate ConnectRPC server (not the simulator) running alongside the
simulator. The demo uses ordered QMDB over MMB. It verifies every `Get` /
`GetMany` proof against a **user-supplied
expected root**. Without the root the UI cannot anchor trust — the server
could return an internally-consistent but fabricated proof. Paste both the tip
(location) and the matching root (hex) into the UI per query.

In addition to the simulator running above:

1. **Start the QMDB server** on port 8081

   ```bash
   cargo run --package exoware-qmdb --bin qmdb -- \
     run --store-url http://127.0.0.1:8080
   ```

2. **Stream fresh batches** (keeps running; prints a `tip=N root=0x..` line
   every few seconds). Local ordered-QMDB MMB state
   persists under `$HOME/.exoware_qmdb_mmb_seed` so ctrl-c / restart resumes where
   the previous run left off; delete the directory to reset, or override the
   location with `--directory`.

   ```bash
   cargo run --package exoware-qmdb --bin qmdb -- \
     seed --store-url http://127.0.0.1:8080 --interval-secs 2
   ```

   Each line looks like:

   ```
   tip=14 root=0xb777..1064
   ```

3. **Point the web app at the QMDB server**:

   ```bash
   VITE_QMDB_URL=http://127.0.0.1:8081 npm run dev
   ```

4. **In the UI**, paste a `tip` + matching root pair from the `seed` stream,
   then pick a key (e.g. `k-00000000`):
   - **Get Proof** verifies against the pasted current root and reports proof size.
   - **Get Many** verifies current hit/miss lookup proofs against the same root and reports proof size.
   - **Get Range** verifies an ordered current range plus boundary proofs
     against the same root and reports proof size.
   - **Subscribe** verifies each emitted historical proof from the trusted
     current root for that emitted tip and reports proof size. Paste seed
     output lines into Trusted Roots when replaying or following multiple tips.

The client-side verifier rejects any proof whose recomputed root doesn't
match the pasted anchor.

## Simplex panel

The Simplex panel is only rendered when `VITE_SIMPLEX_URL` is set. It reads
Commonware Simplex artifacts written by the `simplex seed` process using the
same key layout as the Rust `exoware-simplex` crate. The panel configures the
Simplex WASM verifier from caller-supplied scheme, namespace, key material, and
artifact bytes.

With the simulator running above:

1. **Seed finalized Simplex blocks** (keeps running; every `--interval-secs` it
   uploads a dummy block, notarization, finalization-by-view, and
   finalization-by-height). The first lines print the threshold verifier
   material to paste into the Simplex panel. The default start height is
   time-based so restarts still advance the latest finalized height index.

   ```bash
   cargo run --package exoware-simplex --bin simplex -- \
     seed --store-url http://127.0.0.1:8080 --interval-secs 2
   ```

2. **Point the web app at the simulator**:

   ```bash
   VITE_SIMPLEX_URL=http://127.0.0.1:8080 npm run dev
   ```

3. **In the UI**:
   - **Connection** accepts the scheme, namespace, and verifier material printed
     by `simplex seed`.
   - **Read** fetches a block by digest or the latest finalized height index.
     Latest finalization uses verified reads, while block reads remain raw.
   - **Subscribe** streams notarizations and finalizations, verifying each
     certificate before display.

## SQL panel

The SQL panel is only rendered when `VITE_SQL_URL` is set. It hosts a thin
Connect client for `sql.v1.Service` served by a separate binary that
owns a `KvSchema` + DataFusion session.

In addition to the simulator running above:

1. **Start the SQL server** on port 8082

   ```bash
   cargo run --package exoware-sql --bin sql -- \
     run --store-url http://127.0.0.1:8080
   ```

2. **Seed rows** (keeps running; every `--interval-secs` it inserts 5 orders
   into `orders_kv` via `INSERT ... VALUES`). The server decodes each ingest
   batch and re-runs the subscriber's SQL WHERE predicate against just those
   rows, emitting one frame per matching batch.

   ```bash
   cargo run --package exoware-sql --bin sql -- \
     seed --store-url http://127.0.0.1:8080 --interval-secs 2
   ```

3. **Point the web app at the SQL server**:

   ```bash
   VITE_SQL_URL=http://127.0.0.1:8082 npm run dev
   ```

4. **In the UI**:
   - **Run Query** executes arbitrary SQL against the server's DataFusion
     session (e.g. aggregates over `orders_kv`).
   - **Start Subscribe** streams rows per ingest batch that satisfy the
     given WHERE predicate. Leave the predicate empty to emit every decoded
     row. Paste `SubscribeResponse.sequence_number + 1` into Since Sequence
     to resume.
