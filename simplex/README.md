# exoware-simplex

`exoware-simplex` streams Commonware Simplex notarized/finalized block
certificates into Exoware Store. Each certified block record is encoded with
the `store.simplex.v1.CertifiedBlock` proto and points at the raw Store KV
entry containing the native-encoded block bytes. The writer also maintains
Store index entries for certified blocks by view and finalized blocks by
height.

## Run locally

Start the simulator Store:

```bash
cargo run --package exoware-simulator -- --verbose server run --port 8080
```

Seed demo notarized/finalized blocks:

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

Use both values in the TypeScript verifier or the sandbox panel. The seed
process writes certified block records and raw blocks directly to the simulator
Store at `--store-url`. To continue a run with the same verifier namespace,
pass it back explicitly:

```bash
cargo run --package exoware-simplex --bin simplex -- \
  seed --store-url http://127.0.0.1:8080 --namespace simplex-demo-...
```
