# exoware-sandbox

Explore the Exoware API in a browser. The Log and Store panels connect to a
local Store simulator. Optional panels let you inspect QMDB proofs, verify
Simplex certificates, and run SQL queries. Simplex also reads directly from
the simulator, while QMDB and SQL use their own servers backed by that Store.

## Prerequisites

- Node.js and npm
- Rust and Cargo, with the `wasm32-unknown-unknown` target installed
- wasm-pack

On macOS, use Homebrew LLVM for the WASM builds:

```bash
brew install llvm
export CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang"
export AR_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/llvm-ar"
```

## Run locally

1. **Start the simulator**

   From the monorepo root:

   ```bash
   cargo run --package exoware-simulator -- --verbose server run --port 8080
   ```

   Set `VITE_STORE_URL=http://localhost:8080` in
   `examples/sandbox/.env.local` to point the Store and Log panels at the
   simulator. The simulator accepts requests without a bearer token. For a
   deployment that requires one, set `VITE_TOKEN` to pass it to the SDK client.

2. **Install dependencies and run the web app**

   ```bash
   cd examples/sandbox
   npm install --include=dev
   npm run dev
   ```

   The app and local packages use development dependencies for Vite, TypeScript,
   and WASM builds. `--include=dev` installs them even when your shell or npm
   configuration omits development dependencies by default.

3. **Open the web UI**

   Open the URL Vite prints (usually `http://localhost:5173`).

## Features

- **Log:** Order and stream arbitrary data.
- **Store:** Query immutable data.
- **Ordered QMDB** (optional, requires `VITE_QMDB_URL`): operation-log and current-state
  proofs and live subscriptions.
- **Simplex** (optional, requires `VITE_SIMPLEX_STORE_URL`): read and subscribe to
  seeded Commonware Simplex blocks, notarizations, and finalizations, with
  latest-finalization verification through the Simplex WASM verifier.
- **SQL** (optional, requires `VITE_SQL_URL`): run ad-hoc SQL queries and
  subscribe to a SQL WHERE predicate evaluated per ingested batch.

## Store namespaces

Use `--store-prefix` to give each instance a non-overlapping namespace in the
shared Store. A server and its seeder must use the same prefix. The examples
below use `qmdb`, `simplex`, and `sql`; choose another prefix for each
additional instance. Omitting the option leaves keys unprefixed.

The Simplex panel reads the Store directly, so set `VITE_SIMPLEX_STORE_PREFIX`
to its seeder's prefix. The Log and Store panels access raw Store keys; use
other prefixes for manual writes.

## Ordered QMDB panel

The QMDB panel connects to a separate ConnectRPC server running alongside the
simulator. Set `VITE_QMDB_URL` to display it. The demo uses ordered QMDB over
MMB to prove operation-log ranges and current-state lookups.

For the Get actions, supply a tip (location) and its matching expected root in
hex. The verifier rejects a proof whose recomputed root does not match, so the
root must come from a source you trust independently of the query server. A
server can produce an internally consistent proof for fabricated data. The
local seeder below prints the tip and root pairs for this demo.

With the simulator running:

1. **Start the QMDB server** on port 8081

   ```bash
   cargo run --package exoware-qmdb --bin qmdb -- \
     run --store-url http://127.0.0.1:8080 --store-prefix qmdb
   ```

2. **Stream fresh batches.** Start the seeder in another terminal:

   ```bash
   cargo run --package exoware-qmdb --bin qmdb -- \
     seed --store-url http://127.0.0.1:8080 --store-prefix qmdb \
     --directory /tmp/exoware-qmdb-seed --interval-secs 2
   ```

   The seeder keeps running and prints a tip and root every few seconds:

   ```
   tip=14 root=0xb777..1064
   ```

   Its local ordered-QMDB MMB state persists under `--directory`, so restarting
   with the same directory resumes the same Store prefix. Use a fresh directory
   for a reset Store, a different `--store-prefix`, or another instance.

3. **Point the web app at the QMDB server**:

   ```bash
   VITE_QMDB_URL=http://127.0.0.1:8081 npm run dev
   ```

4. **Try a proof in the UI.** Paste a tip and matching root from the `seed`
   output, then choose an operation range or a key such as `k-00000000`:

   - **Get Operation Range** verifies a contiguous operation-log range against
     the supplied root.
   - **Subscribe** displays each streamed operation-log proof with its tip and
     decoded operations. These streamed proofs are not verified against a
     trusted root.
   - **Get** verifies a key's current value against the supplied root.
   - **Get Many** verifies current hit/miss lookup proofs against that root.
   - **Get Range** verifies an ordered current range and its start boundary
     proof against that root.

   Each action also displays the proof size.

## Simplex panel

Set `VITE_SIMPLEX_STORE_URL` to display the Simplex panel. It reads Commonware
Simplex artifacts written by `simplex seed`, using the same key layout as the
Rust `exoware-simplex` crate. Supply the scheme, namespace, and key material
printed by the seeder below to configure the Simplex WASM verifier for those
artifacts.

With the simulator running:

1. **Seed finalized Simplex blocks.** Start the seeder in another terminal:

   ```bash
   cargo run --package exoware-simplex --bin simplex -- \
     seed --store-url http://127.0.0.1:8080 --store-prefix simplex --interval-secs 2
   ```

   The seeder first prints the threshold verifier material to paste into the
   panel. At each `--interval-secs`, it uploads a dummy block and separate
   notarization/finalization records carrying the certified header. Its default
   start height is based on the current time so restarts can advance the latest
   finalized height index.

2. **Point the web app at the simulator**:

   ```bash
   VITE_SIMPLEX_STORE_URL=http://127.0.0.1:8080 VITE_SIMPLEX_STORE_PREFIX=simplex npm run dev
   ```

3. **Read and verify artifacts in the UI:**

   - **Connection** accepts the scheme, namespace, and verifier material printed
     by `simplex seed`.
   - **Read** fetches a block by digest, a notarization by round, a finalization
     by round or height, or the latest finalized height index. Round lookups
     require an epoch and view. The demo seeder uses epoch zero. Certificate reads
     are verified before display. From a verified certificate, use **Verify Full
     Block** to fetch the digest-indexed block, compare its header to the
     certified header, and verify the demo body commitment.
   - **Subscribe** streams notarizations and finalizations with their headers,
     verifying each certificate before display. Each streamed certificate can
     also fetch and verify its full block on demand.

## SQL panel

Set `VITE_SQL_URL` to display the SQL panel. It connects to a separate SQL
server that uses a `KvSchema` and DataFusion session to query Store data.

With the simulator running:

1. **Start the SQL server** on port 8082

   ```bash
   cargo run --package exoware-sql --bin sql -- \
     run --store-url http://127.0.0.1:8080 --store-prefix sql
   ```

2. **Seed rows.** Start the seeder in another terminal:

   ```bash
   cargo run --package exoware-sql --bin sql -- \
     seed --store-url http://127.0.0.1:8080 --store-prefix sql --interval-secs 2
   ```

   At each `--interval-secs`, the seeder inserts five orders into `orders_kv`
   with `INSERT ... VALUES`. For subscriptions, the server decodes each ingest
   batch and evaluates the subscriber's SQL WHERE predicate against those rows.
   Each matching batch produces one frame.

3. **Point the web app at the SQL server**:

   ```bash
   VITE_SQL_URL=http://127.0.0.1:8082 npm run dev
   ```

4. **Query or subscribe in the UI:**

   - **Run Query** executes arbitrary SQL against the server's DataFusion
     session (e.g. aggregates over `orders_kv`).
   - **Start Subscribe** streams rows per ingest batch that satisfy the
     given WHERE predicate. Leave the predicate empty to emit every decoded
     row. Paste `SubscribeResponse.sequence_number + 1` into Since Sequence
     to resume.
