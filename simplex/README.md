# exoware-simplex

`exoware-simplex` stores Commonware Simplex activity and notarized/finalized
blocks in Exoware.

Activity is written through `exoware-sql` so votes, certificates, views, and
signers can be queried with SQL. Signed activity is stored in
`simplex_signed_activity` with a non-null `signer` column for voting analytics.
Certificate activity is stored separately in `simplex_certificate_activity`.
Notarized and finalized blocks are stored in `simplex_blocks` so consumers can
subscribe to certificate/block rows and verify them before accepting them.

## Run locally

Start the simulator Store:

```bash
cargo run --package exoware-simulator -- --verbose server run --port 8080
```

Start the Simplex SQL server, which registers `simplex_signed_activity`,
`simplex_certificate_activity`, and `simplex_blocks` over that Store:

```bash
cargo run --package exoware-simplex --bin simplex -- \
  run --store-url http://127.0.0.1:8080 --port 8083
```

Seed demo Simplex activity plus notarized/finalized blocks:

```bash
cargo run --package exoware-simplex --bin simplex -- \
  seed --store-url http://127.0.0.1:8080 --interval-secs 2
```

The seed process generates a namespace for the run and prints it with the
committee identity:

```text
simplex_identity=0x...
simplex_namespace=simplex-demo-...
```

Use both values in the TypeScript verifier or the sandbox panel. To continue a
run with the same verifier namespace, pass it back explicitly:

```bash
cargo run --package exoware-simplex --bin simplex -- \
  seed --store-url http://127.0.0.1:8080 --namespace simplex-demo-...
```
