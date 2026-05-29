# exoware-workload

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
cargo run -p exoware-workload -- load --namespace 2026052901 --keys 10000 --batch-size 100 --concurrency 4
```

Run a benchmark:

```bash
cargo run -p exoware-workload -- bench --namespace 2026052901 --keys 10000 --ops 50000 --concurrency 8 --scenario balanced --output bench-report.json
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

`load` and `bench` exit non-zero when the tool itself fails, such as invalid configuration, a failed manifest read, or a failed JSON report write. Backend operation failures are logged and reported in counters, but do not make those commands fail by exit code. Automation should inspect the report counters, especially `errors`, and apply its own policy.

`validate` is a correctness check, so correctness failures return non-zero.

## Benchmark Reports

Benchmark JSON reports include the normalized config, seed, counters, and per-operation latency histograms for reads, writes, and scans. Histograms use fixed microsecond buckets; stdout and GitHub summaries show p50/p95/p99/max latency lines for readability.

`load` and `bench` use run-specific namespaces by default so independent runs do not reuse the same physical keys on persistent stores. Pass the same `--namespace` to both commands when a benchmark should read from a keyspace written by `load`.

## Benchmark Manifests

`workload bench --manifest <path>` accepts the normalized `config` and `seed` fields from a benchmark JSON report, so a run can be replayed without reconstructing CLI flags. A minimal manifest has this shape:

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
      "mix": { "read_ratio": 0.7, "write_ratio": 0.3, "scan_ratio": 0.0 },
      "scan_length": 25,
      "key_dist": "uniform",
      "latest_window": 5000,
      "latest_prob": 0.9,
      "zipf_theta": 0.99
    },
    "key_len": 48,
    "keyspace_layout_version": 1,
    "value_generator_version": 1,
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
