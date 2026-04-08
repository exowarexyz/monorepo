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
