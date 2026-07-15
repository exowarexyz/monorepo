# exoware-workload

[![Crates.io](https://img.shields.io/crates/v/exoware-workload.svg)](https://crates.io/crates/exoware-workload)
[![Docs.rs](https://docs.rs/exoware-worload/badge.svg)](https://docs.rs/exoware-workload)

Validate an Exoware deployment.

## Status

`exoware-workload` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Overview

`exoware-workload` provides small CLI workloads for exercising Exoware-compatible stores. It is meant to support local development, deployment validation, and reproducible benchmark runs.

The tool has three modes:

- `load`: write a deterministic keyspace.
- `bench`: run a mixed read/write/scan workload and print a benchmark report.
- `validate`: write and query deterministic records to check correctness.

## Setup

Start a local simulator:

```bash
cargo run -p exoware-simulator --bin simulator -- server run --port 10000
```

Run workload commands from another terminal. The examples below use the default endpoint, `http://localhost:10000`.

## Examples

Load deterministic records:

```bash
cargo run -p exoware-workload -- load --namespace 2026052901 --keys 10000 --value-size 256 --batch-size 100 --concurrency 4
```

Run a benchmark:

```bash
cargo run -p exoware-workload -- bench --namespace 2026052901 --keys 10000 --value-size 256 --ops 50000 --batch-size 100 --concurrency 8 --scenario balanced --output bench-report.json
```

Replay a benchmark from a previous JSON report:

```bash
cargo run -p exoware-workload -- bench --manifest bench-report.json --output replay-report.json
```

Validate correctness:

```bash
cargo run -p exoware-workload -- validate --keys 100 --lookup-samples 25 --missing-samples 10 --range-samples 10
```

## Exit Semantics

Exit codes follow each command's purpose:

- `bench` is a measurement tool. It exits non-zero only when the tool itself fails (invalid configuration, a failed manifest read, or a failed JSON report write). Backend operation failures and absent reads are recorded as `errors` and `read_misses` in the report, not treated as failures; inspect both and apply your own policy.
- `load` prepares a complete keyspace for later benchmarking. It retries transient ingest failures (`--ingest-retry-attempts`, `--ingest-retry-backoff-ms`) so a complete fixture is far more likely, while still surfacing them: every retry is logged, the total retried count is reported in the final summary, and a persistent failure or any non-transient error still makes `load` exit non-zero rather than hand back an incomplete keyspace.
- `validate` is a correctness check. It exits non-zero when the tool fails or when any correctness check fails.

## Benchmark Reports

Benchmark JSON reports include the normalized config, seed, counters, and per-operation latency histograms for reads, writes, and scans. Histograms use fixed microsecond buckets; stdout and GitHub summaries show p50/p95/p99/max latency lines for readability.

`load` and `bench` use run-specific namespaces by default so independent runs do not reuse the same physical keys on persistent stores. Pass the same `--namespace` and `--keys` value to both commands when a benchmark should read from a keyspace written by `load`.

`bench --batch-size` controls the number of key/value pairs in each generated write operation. It defaults to 100, matching `load`; `--ops` still counts benchmark operations (requests), not individual keys in those write batches.

Generated load and benchmark keys open with a byte derived from the logical index, so a run's keys spread across the entire physical key range instead of sharing a fixed prefix. Standard validation instead uses its own contiguous key layout, keeping its whole-keyspace range checks bounded to the rows it owns.

`bench` reports `scan_rows` as every physical row returned by the store, including rows from other namespaces in the sampled interval. Compare scan latency and row counts only between runs against the same controlled fixture; the action's simulator reports are functionality artifacts, not cross-environment performance evidence.

`load`, `bench`, and `validate` accept `--value-size` (bytes, default 160) to control generated value size. Pass the same `--value-size` to `load` and a reading `bench` so writes appended during the benchmark match the loaded data.

## Benchmark Manifests

`workload bench --manifest <path>` accepts the normalized `config` and `seed` fields from a benchmark JSON report, so a run can be replayed without reconstructing CLI flags. For a fixed manifest, each worker repeats its logical operation stream and its appended-key allocation independent of task scheduling. A manifest whose key, value, or workload-generator version differs from the current binary is rejected rather than silently replayed with different data. A minimal manifest has this shape:

```json
{
  "schema_version": 1,
  "config": {
    "endpoint": "http://localhost:10000",
    "namespace": 2026052901,
    "key_space": 10000,
    "total_ops": 50000,
    "concurrency": 8,
    "scenario": "balanced",
    "workload": {
      "mix": { "read_ratio": 0.6, "write_ratio": 0.3, "scan_ratio": 0.1 },
      "scan_length": 25,
      "key_dist": "uniform",
      "latest_window": 5000,
      "latest_prob": 0.9,
      "zipf_theta": 0.99
    },
    "key_len": 48,
    "value_size": 256,
    "batch_size": 100,
    "keyspace_layout_version": 2,
    "value_generator_version": 1,
    "workload_generator_version": 3,
    "read_retry_attempts": 3
  },
  "seed": 1592639710
}
```

Use `--help` on the top-level command or any subcommand for all options:

```bash
cargo run -p exoware-workload -- --help
cargo run -p exoware-workload -- bench --help
```
