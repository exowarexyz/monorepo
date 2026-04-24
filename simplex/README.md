# exoware-simplex

`exoware-simplex` stores Commonware Simplex activity and notarized/finalized
blocks in Exoware.

Activity is written through `exoware-sql` so votes, certificates, views, and
signers can be queried with SQL. Notarized and finalized blocks are stored in a
separate SQL table so consumers can subscribe to certificate/block rows and
verify them before accepting them.

## Run locally

Start the simulator Store:

```bash
cargo run --package exoware-simulator -- --verbose server run --port 8080
```

Start the Simplex SQL server, which registers `simplex_activity` and
`simplex_blocks` over that Store:

```bash
cargo run --package exoware-simplex --bin simplex -- \
  run --store-url http://127.0.0.1:8080 --port 8083
```

Seed demo Simplex activity plus notarized/finalized blocks:

```bash
cargo run --package exoware-simplex --bin simplex -- \
  seed --store-url http://127.0.0.1:8080 --interval-secs 2
```

The seed process prints:

```text
simplex_identity=0x...
simplex_namespace=_ALTO
```

Use that identity in the TypeScript verifier or the sandbox panel.
