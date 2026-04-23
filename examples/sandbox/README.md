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
   npm install
   npm run dev
   ```

3. **Open the web UI**

   Open the URL Vite prints (usually `http://localhost:5173`).

## Features

- **Store:** set and get key-value pairs, and run range queries.
- **Ordered QMDB** (optional, requires `VITE_QMDB_URL`): current/historical
  proofs and live subscribe streaming.

## Ordered QMDB panel

The QMDB panel is only rendered when `VITE_QMDB_URL` is set, since it requires
a separate ConnectRPC server (not the simulator) running alongside the
simulator. It verifies every `Get` / `GetMany` proof against a **user-supplied
expected root**. Without the root the UI cannot anchor trust — the server
could return an internally-consistent but fabricated proof. Paste both the tip
(location) and the matching root (hex) into the UI per query.

In addition to the simulator running above:

1. **Start the QMDB server** on port 8081

   ```bash
   cargo run --package exoware-qmdb --bin qmdb -- \
     run --store-url http://127.0.0.1:8080
   ```

2. **Stream fresh batches** (keeps running; prints a `watermark=N
   current_root=0x..` line every few seconds). The `--directory` holds the
   local ordered-QMDB state so ctrl-c / restart resumes where the previous run
   left off. Delete the directory to reset.

   ```bash
   cargo run --package exoware-qmdb --bin qmdb -- \
     seed-continuous \
     --store-url http://127.0.0.1:8080 \
     --interval-secs 2 \
     --directory ~/.exoware_qmdb_continuous
   ```

   Each line looks like:

   ```
   watermark=14 current_root=0xb777..1064 historical_root=0x1a3d..cd7b
   ```

   For a one-shot alternative, use `seed-demo` instead — it writes a single
   fixed batch (`alpha`, `beta`, `gamma`) and exits.

3. **Point the web app at the QMDB server**:

   ```bash
   VITE_QMDB_URL=http://127.0.0.1:8081 npm run dev
   ```

4. **In the UI**, paste a `watermark` + matching root pair from the
   `seed-continuous` stream, then pick a key (e.g. `k-00000000`):
   - **Get Proof** verifies against `current_root` (paste into Expected Current
     Root).
   - **Get Multi-Proof** verifies against `historical_root` (paste into
     Expected Historical Root).

   The client-side verifier rejects any proof whose recomputed root doesn't
   match the pasted anchor.

Subscribe streams live matches and does not require an expected root — each
batch's root is anchored by the stream's own `resumeSequenceNumber`.
