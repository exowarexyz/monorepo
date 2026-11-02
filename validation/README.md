# exoware-validation

[![Crates.io](https://img.shields.io/crates/v/exoware-validation.svg)](https://crates.io/crates/exoware-validation)
[![Docs.rs](https://docs.rs/exoware-validation/badge.svg)](https://docs.rs/exoware-validation)

Validate an Exoware deployment.

## Run a correctness check

This workspace CLI writes deterministic records and exercises an Exoware-compatible
store. Run commands from the repository root against a development deployment.
For a local store, start the [simulator](../examples/simulator) in one terminal:

```bash
cargo run -p exoware-simulator --bin simulator -- server run --port 8080
```

In another terminal, write a small fixture and check its visibility, point reads,
missing keys, and sampled forward and reverse ranges:

```bash
cargo run -p exoware-validation -- validate --url http://localhost:8080 \
  --keys 100 --lookup-samples 25 --missing-samples 10 --range-samples 10
```

All commands default to `http://localhost:8080`. Use `--url` to select another
deployment. Requests use zstd compression by default. Pass
`--request-compression none` to disable it.

## Prepare and measure a workload

`load` writes a deterministic keyspace. `bench` measures a mix of point reads,
batched writes, and range scans. Load the fixture before benchmarking reads:

```bash
cargo run --release -p exoware-validation -- load --namespace 42 \
  --keys 10000 --value-size 256 --batch-size 100 --concurrency 4

cargo run --release -p exoware-validation -- bench --namespace 42 \
  --keys 10000 --value-size 256 --batch-size 100 --concurrency 8 \
  --ops 50000 --scenario balanced --output bench-report.json
```

Choose a fresh namespace for each independent fixture. By default, commands
choose separate run-specific namespaces, so an unconfigured `bench` will not
read the keys from an earlier `load`. To share a fixture, pass the same
`--namespace`, `--keys`, and `--key-len` to both commands. Match `--value-size`
so benchmark writes have the same size as loaded values. The key length and
value size defaults match between commands.

`--ops` counts benchmark operations, and `--batch-size` controls the number of
key/value pairs in each write. Use `bench --help` to select a workload scenario, key
distribution, or custom read/write/scan ratios.

## Interpret results

The commands use different success criteria:

- `validate` exits nonzero on a correctness failure or tool error. It waits for
  writes to become queryable within the configured visibility budget.
- `load` exits nonzero if it cannot complete the fixture. Transient ingest errors
  are retried with `--ingest-retry-attempts` and `--ingest-retry-backoff-ms`.
  Retries are logged, and the final summary includes the retry count.
- `bench` exits nonzero on tool errors such as invalid configuration or a failed
  report write. Backend operation failures increment `errors`, and successful
  reads with absent values increment `read_misses`. Both can occur with a zero
  exit status. Inspect them before accepting a result.

Benchmark reports contain the normalized configuration, seed, operation counters,
and separate read/write/scan latency histograms. Latencies include failed calls
and use fixed microsecond buckets. The text summary reports p50, p95, p99, and
maximum latency. See the [report types](src/report.rs) for the JSON fields.

Load and benchmark keys spread across the physical key range. Benchmark scans
start at a sampled key and stay within its leading-byte range, returning at most
`--scan-length` rows. They can return fewer rows at the end of that range, or
include rows from other namespaces. `scan_rows` counts all returned physical rows.
Compare scan latency and row counts against the same controlled fixture.
Standard validation uses a separate, contiguous key layout to bound its checks.

## Replay and extended validation

A saved benchmark report can supply the configuration and seed for another run:

```bash
cargo run --release -p exoware-validation -- bench \
  --manifest bench-report.json --output replay-report.json
```

Replay uses the report's endpoint, namespace, compression, and workload settings.
Workload flags cannot override a manifest. The CLI rejects incompatible key,
value, or workload-generator versions. Keep generated reports with the binary
revision used to produce them.

With the same manifest and acknowledged write outcomes, each worker repeats its
logical operations and appended-key allocation independently of task scheduling.
Replay does not restore the store. Start from the same store snapshot and
control other traffic when comparing results. Server state, write visibility,
hardware, and load affect observed latency and outcomes. Simulator reports are
useful for checking functionality, not for comparing deployment performance.

For larger correctness fixtures, `validate --full-range-verify` replaces sampled
checks with a paginated verification of every inserted record. The
`overlap-ledger-write` and `overlap-ledger-verify` modes split writing and checking
across processes for restart or outage tests. Select them with `validate --mode`
and supply `--ledger-path`. The writer records acknowledged writes and continues
appending until interrupted, retrying transient append failures. Stop it before
verification to include its final checkpoint. The verifier checks visibility,
forward and reverse ranges, and a reduction count against the ledger. See the
[validation implementation](src/validate.rs) for those checks and timing rules.

List all flags and defaults with:

```bash
cargo run -p exoware-validation -- --help
cargo run -p exoware-validation -- bench --help
cargo run -p exoware-validation -- validate --help
```

## Status

`exoware-validation` is **ALPHA** software and is not yet recommended for production use.
Developers should expect breaking changes and occasional instability.
