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
- **Ordered QMDB:** current/historical proofs and live subscribe streaming.

## Ordered QMDB panel

The QMDB panel talks to a separate ConnectRPC server (not the simulator). It
expects a published batch tip to anchor proofs against. Follow these steps in
addition to the simulator already running above:

1. **Seed the demo batch** (one-shot; prints the tip watermark)

   ```bash
   cargo run --package exoware-qmdb --bin qmdb -- \
     seed-demo --store-url http://127.0.0.1:8080
   ```

   Note the `watermark=<N>` line printed on stdout — that's the value to
   paste into the Tip field (and, optionally, set as `VITE_QMDB_TIP`).

2. **Start the QMDB server** on port 8081

   ```bash
   cargo run --package exoware-qmdb --bin qmdb -- \
     run --store-url http://127.0.0.1:8080
   ```

3. **Point the web app at both** — override the QMDB URL and the default tip
   in `.env.local` (or inline) before `npm run dev`:

   ```bash
   VITE_QMDB_URL=http://127.0.0.1:8081 VITE_QMDB_TIP=<watermark> npm run dev
   ```

The seeded demo writes `alpha`, `beta`, `gamma`. Get / GetMany proofs work
against the printed tip. Subscribe streams live matches — re-run `seed-demo`
or write your own batches via `OrderedWriter` to trigger more events.
