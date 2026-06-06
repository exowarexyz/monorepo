//! Exoware benchmark workload runner.
//!
//! Usage:
//!   workload bench --url http://localhost:10000 --keys 10000 --ops 50000 --scenario balanced
//!
//! Progress: `bench` emits `Benchmark progress` every `--progress-interval-secs` (default 10; 0 disables).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::ensure;
use chrono::Utc;
use tokio::time::MissedTickBehavior;

use crate::client::{build_client, ClientConfig};
use crate::keyspace::{default_run_namespace, Keyspace, DEFAULT_KEY_LEN, KEYSPACE_LAYOUT_VERSION};
use crate::report::{
    print_bench_report, read_bench_manifest_json, write_bench_report_json, BenchConfig,
    BenchManifest, BenchReport, LatencyHistogramsRecorder,
};
use crate::value::{value_for_index, DEFAULT_VALUE_SIZE, VALUE_GENERATOR_VERSION};
use crate::workload::{
    resolve_mix, worker_operation_count, KeyDistribution, Operation, Scenario, WorkerPlan,
    WorkloadSpec, DEFAULT_BENCH_RNG_SEED,
};

/// Run an Exoware benchmark scenario workload.
#[derive(clap::Args, Debug)]
pub struct Args {
    /// Read benchmark config and seed from a manifest or previous JSON report.
    #[arg(
        long,
        conflicts_with_all = [
            "url",
            "keys",
            "ops",
            "concurrency",
            "scenario",
            "scan_length",
            "key_dist",
            "latest_window",
            "latest_prob",
            "zipf_theta",
            "read_ratio",
            "write_ratio",
            "scan_ratio",
            "rng_seed",
            "read_retry_attempts",
            "key_len",
            "namespace",
            "value_size"
        ]
    )]
    manifest: Option<PathBuf>,
    #[arg(long, default_value = "http://localhost:10000")]
    url: String,
    #[arg(long, default_value_t = 10000)]
    keys: u64,
    #[arg(long, default_value_t = 50000)]
    ops: u64,
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    /// Exoware scenario selector.
    #[arg(long, value_enum, default_value_t = Scenario::Balanced)]
    scenario: Scenario,
    /// Range query length for scan-heavy workloads.
    #[arg(long, default_value_t = 25)]
    scan_length: usize,
    /// Key distribution strategy for read/scan operations.
    #[arg(long, value_enum, default_value_t = KeyDistribution::Uniform)]
    key_dist: KeyDistribution,
    /// Size of "latest" key window for recency-tuned workloads.
    #[arg(long, default_value_t = 5_000)]
    latest_window: u64,
    /// Probability of sampling from latest window when key-dist=latest.
    #[arg(long, default_value_t = 0.90)]
    latest_prob: f64,
    /// Zipfian skew parameter when key-dist=zipfian (must be in (0, 1)).
    #[arg(long, default_value_t = 0.99)]
    zipf_theta: f64,
    /// Optional custom read ratio override (must be used with write+scan).
    #[arg(long)]
    read_ratio: Option<f64>,
    /// Optional custom write ratio override (must be used with read+scan).
    #[arg(long)]
    write_ratio: Option<f64>,
    /// Optional custom scan ratio override (must be used with read+write).
    #[arg(long)]
    scan_ratio: Option<f64>,
    /// Deterministic RNG seed used for benchmark operation selection.
    #[arg(long, default_value_t = DEFAULT_BENCH_RNG_SEED)]
    rng_seed: u64,
    /// Max client read retry attempts for lookup/range calls.
    #[arg(long, default_value_t = 3)]
    read_retry_attempts: usize,
    /// Physical key length for generated workload keys.
    #[arg(long, default_value_t = DEFAULT_KEY_LEN)]
    key_len: usize,
    /// Key namespace; use the same value as load for a preloaded keyspace.
    #[arg(long)]
    namespace: Option<u64>,
    /// Size in bytes of generated values written by ingest operations.
    #[arg(long, default_value_t = DEFAULT_VALUE_SIZE)]
    value_size: usize,
    /// Emit periodic `Benchmark progress` logs every N seconds (0 = off).
    #[arg(long, default_value_t = 10)]
    progress_interval_secs: u64,
    /// Write a JSON benchmark report to this path.
    #[arg(long)]
    output: Option<PathBuf>,
}

/// Validated benchmark configuration used by the executor.
#[derive(Debug)]
pub struct Config {
    client: ClientConfig,
    namespace: u64,
    keyspace: Keyspace,
    initial_keys: u64,
    value_size: usize,
    total_ops: u64,
    concurrency: usize,
    scenario: Scenario,
    workload: WorkloadSpec,
    rng_seed: u64,
    progress_interval_secs: u64,
    output: Option<PathBuf>,
}

impl TryFrom<Args> for Config {
    type Error = anyhow::Error;

    fn try_from(args: Args) -> anyhow::Result<Self> {
        if let Some(path) = args.manifest {
            return Self::try_from_manifest(
                read_bench_manifest_json(&path)?,
                args.output,
                args.progress_interval_secs,
            );
        }

        let mix = resolve_mix(
            args.scenario,
            args.read_ratio,
            args.write_ratio,
            args.scan_ratio,
        )?;
        ensure!(args.concurrency > 0, "--concurrency must be > 0");
        ensure!(args.keys > 0, "--keys must be > 0");
        let namespace = args.namespace.unwrap_or_else(default_run_namespace);
        let workload = WorkloadSpec::new(
            mix,
            args.scan_length,
            args.key_dist,
            args.latest_window,
            args.latest_prob,
            args.zipf_theta,
        )?;

        Ok(Self {
            client: ClientConfig::new(args.url, args.read_retry_attempts)?,
            namespace,
            keyspace: Keyspace::from_u64_namespace(namespace, args.key_len)?,
            initial_keys: args.keys,
            value_size: args.value_size,
            total_ops: args.ops,
            concurrency: args.concurrency,
            scenario: args.scenario,
            workload,
            rng_seed: args.rng_seed,
            progress_interval_secs: args.progress_interval_secs,
            output: args.output,
        })
    }
}

impl Config {
    fn try_from_manifest(
        manifest: BenchManifest,
        output: Option<PathBuf>,
        progress_interval_secs: u64,
    ) -> anyhow::Result<Self> {
        ensure!(
            manifest.config.keyspace_layout_version == KEYSPACE_LAYOUT_VERSION,
            "manifest keyspace_layout_version {} does not match current version {}",
            manifest.config.keyspace_layout_version,
            KEYSPACE_LAYOUT_VERSION
        );
        ensure!(
            manifest.config.value_generator_version == VALUE_GENERATOR_VERSION,
            "manifest value_generator_version {} does not match current version {}",
            manifest.config.value_generator_version,
            VALUE_GENERATOR_VERSION
        );
        ensure!(
            manifest.config.key_space > 0,
            "manifest key_space must be > 0"
        );
        ensure!(
            manifest.config.concurrency > 0,
            "manifest concurrency must be > 0"
        );
        manifest.config.workload.validate()?;

        Ok(Self {
            client: ClientConfig::new(
                manifest.config.endpoint,
                manifest.config.read_retry_attempts,
            )?,
            namespace: manifest.config.namespace,
            keyspace: Keyspace::from_u64_namespace(
                manifest.config.namespace,
                manifest.config.key_len,
            )?,
            initial_keys: manifest.config.key_space,
            value_size: manifest.config.value_size,
            total_ops: manifest.config.total_ops,
            concurrency: manifest.config.concurrency,
            scenario: manifest.config.scenario,
            workload: manifest.config.workload,
            rng_seed: manifest.seed,
            progress_interval_secs,
            output,
        })
    }
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    run_workload(Config::try_from(args)?).await
}

async fn run_workload(config: Config) -> anyhow::Result<()> {
    let Config {
        client: client_config,
        namespace,
        keyspace,
        initial_keys,
        value_size,
        total_ops,
        concurrency,
        scenario,
        workload,
        rng_seed,
        progress_interval_secs,
        output,
    } = config;

    let client = Arc::new(build_client(&client_config)?);
    let report_config = BenchConfig {
        endpoint: client_config.endpoint.clone(),
        namespace,
        key_space: initial_keys,
        total_ops,
        concurrency,
        scenario,
        workload,
        key_len: keyspace.key_len,
        value_size,
        keyspace_layout_version: KEYSPACE_LAYOUT_VERSION,
        value_generator_version: VALUE_GENERATOR_VERSION,
        read_retry_attempts: client_config.read_retry_attempts,
    };
    let ops_done = Arc::new(AtomicU64::new(0));
    let reads_ok = Arc::new(AtomicU64::new(0));
    let reads_miss = Arc::new(AtomicU64::new(0));
    let writes_ok = Arc::new(AtomicU64::new(0));
    let scans_ok = Arc::new(AtomicU64::new(0));
    let scans_rows = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));

    // Latency is recorded for every SDK attempt, including failed backend
    // calls, so error-heavy runs still explain where time was spent.
    let latencies = Arc::new(LatencyHistogramsRecorder::default());
    let next_write_index = Arc::new(AtomicU64::new(initial_keys));
    let started_at = Utc::now();
    let start = Instant::now();

    tracing::info!(
        key_space = initial_keys,
        total_ops,
        concurrency,
        namespace,
        scenario = ?scenario,
        read_ratio = workload.mix.read_ratio,
        write_ratio = workload.mix.write_ratio,
        scan_ratio = workload.mix.scan_ratio,
        scan_length = workload.scan_length,
        key_dist = ?workload.key_dist,
        latest_window = workload.latest_window,
        latest_prob = workload.latest_prob,
        zipf_theta = workload.zipf_theta,
        rng_seed,
        progress_interval_secs,
        "Starting benchmark phase"
    );

    let mut handles = Vec::new();

    for worker in 0..concurrency {
        let client = client.clone();
        let keyspace = keyspace.clone();
        let ops_done = ops_done.clone();
        let reads_ok = reads_ok.clone();
        let reads_miss = reads_miss.clone();
        let writes_ok = writes_ok.clone();
        let scans_ok = scans_ok.clone();
        let scans_rows = scans_rows.clone();
        let errors = errors.clone();
        let latencies = latencies.clone();
        let next_write_index = next_write_index.clone();
        let worker_ops = worker_operation_count(total_ops, concurrency, worker)?;
        let worker_workload = workload;

        handles.push(tokio::spawn(async move {
            let mut plan = WorkerPlan::new(rng_seed, worker as u64, worker_workload);

            for _ in 0..worker_ops {
                let max_key_exclusive = next_write_index.load(Ordering::Relaxed).max(1);
                match plan.next_operation(max_key_exclusive) {
                    Operation::Read { index } => {
                        let key = keyspace.inserted_key(index)?;
                        let request_start = Instant::now();
                        let result = client.query().get(&key).await;
                        latencies.record_read(request_start.elapsed());
                        match result {
                            Ok(Some(_)) => {
                                reads_ok.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(None) => {
                                reads_miss.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => {
                                tracing::debug!("Lookup error: {e}");
                                errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Operation::Scan { start, end, limit } => {
                        let start_key = keyspace.inserted_key(start)?;
                        let end_key = keyspace.inserted_key(end)?;
                        let request_start = Instant::now();
                        let result = client.query().range(&start_key, &end_key, limit).await;
                        latencies.record_scan(request_start.elapsed());
                        match result {
                            Ok(rows) => {
                                scans_ok.fetch_add(1, Ordering::Relaxed);
                                scans_rows.fetch_add(rows.len() as u64, Ordering::Relaxed);
                            }
                            Err(e) => {
                                tracing::debug!("Range error: {e}");
                                errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Operation::Write => {
                        let write_idx = next_write_index.fetch_add(1, Ordering::Relaxed);
                        let key = keyspace.inserted_key(write_idx)?;
                        let value = value_for_index(namespace, write_idx, value_size);

                        let request_start = Instant::now();
                        let result = client.ingest().put(&[(&key, &value)]).await;
                        latencies.record_write(request_start.elapsed());
                        match result {
                            Ok(_) => {
                                writes_ok.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => {
                                tracing::debug!("Ingest error: {e}");
                                errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }

                ops_done.fetch_add(1, Ordering::Relaxed);
            }
            Ok::<(), anyhow::Error>(())
        }));
    }

    let progress_task = if progress_interval_secs > 0 {
        let ops_done = ops_done.clone();
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(progress_interval_secs));
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                let done = ops_done.load(Ordering::Relaxed);
                let elapsed = start.elapsed().as_secs_f64();
                if done >= total_ops {
                    break;
                }
                let rate = if elapsed > 0.0 {
                    done as f64 / elapsed
                } else {
                    0.0
                };
                let pct = (done as f64 / total_ops as f64 * 100.0).min(100.0);
                tracing::info!(
                    ops_done = done,
                    total_ops,
                    elapsed_secs = %format!("{:.1}", elapsed),
                    current_ops_per_sec = rate as u64,
                    percent_complete = %format!("{:.1}", pct),
                    "Benchmark progress"
                );
            }
        }))
    } else {
        None
    };

    for h in handles {
        h.await??;
    }

    if let Some(t) = progress_task {
        t.abort();
        let _ = t.await;
    }

    let elapsed = start.elapsed();
    let finished_at = Utc::now();
    let total = ops_done.load(Ordering::Relaxed);
    let read_misses = reads_miss.load(Ordering::Relaxed);
    let report = BenchReport {
        config: report_config,
        seed: rng_seed,
        elapsed_ms: elapsed.as_millis(),
        operations: total,
        reads: reads_ok.load(Ordering::Relaxed) + read_misses,
        writes: writes_ok.load(Ordering::Relaxed),
        errors: errors.load(Ordering::Relaxed),
        scans: scans_ok.load(Ordering::Relaxed),
        scan_rows: scans_rows.load(Ordering::Relaxed),
        read_misses,
        latency_histograms: latencies.snapshot(),
    };
    print_bench_report(&report);
    if let Some(path) = output {
        write_bench_report_json(&path, &report, started_at, finished_at)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> BenchManifest {
        BenchManifest::new(
            BenchConfig {
                endpoint: "http://localhost:10000/".to_string(),
                key_space: 1_000,
                namespace: 42,
                total_ops: 10_000,
                concurrency: 4,
                scenario: Scenario::ScanHeavy,
                workload: WorkloadSpec::new(
                    crate::workload::WorkloadMix {
                        read_ratio: 0.4,
                        write_ratio: 0.1,
                        scan_ratio: 0.5,
                    },
                    25,
                    KeyDistribution::Latest,
                    500,
                    0.8,
                    0.99,
                )
                .unwrap(),
                key_len: DEFAULT_KEY_LEN,
                value_size: DEFAULT_VALUE_SIZE,
                keyspace_layout_version: KEYSPACE_LAYOUT_VERSION,
                value_generator_version: VALUE_GENERATOR_VERSION,
                read_retry_attempts: 5,
            },
            123,
        )
    }

    fn sample_args() -> Args {
        Args {
            url: "http://localhost:10000/".to_string(),
            manifest: None,
            keys: 10_000,
            ops: 50_000,
            concurrency: 8,
            scenario: Scenario::Balanced,
            scan_length: 25,
            key_dist: KeyDistribution::Uniform,
            latest_window: 5_000,
            latest_prob: 0.90,
            zipf_theta: 0.99,
            read_ratio: None,
            write_ratio: None,
            scan_ratio: None,
            rng_seed: DEFAULT_BENCH_RNG_SEED,
            read_retry_attempts: 3,
            key_len: DEFAULT_KEY_LEN,
            namespace: Some(42),
            value_size: DEFAULT_VALUE_SIZE,
            progress_interval_secs: 10,
            output: None,
        }
    }

    #[test]
    fn config_normalizes_url() {
        let config = Config::try_from(sample_args()).expect("bench args should be valid");
        assert_eq!(config.client.endpoint, "http://localhost:10000");
    }

    #[test]
    fn config_uses_key_len() {
        let mut args = sample_args();
        args.key_len = 24;
        let config = Config::try_from(args).expect("bench args should be valid");
        assert_eq!(config.keyspace.key_len, 24);
    }

    #[test]
    fn config_uses_namespace() {
        let config = Config::try_from(sample_args()).expect("bench args should be valid");
        assert_eq!(config.namespace, 42);
        assert_eq!(
            config.keyspace.inserted_key(0).unwrap(),
            Keyspace::from_u64_namespace(42, DEFAULT_KEY_LEN)
                .unwrap()
                .inserted_key(0)
                .unwrap()
        );
    }

    #[test]
    fn config_resolves_custom_mix() {
        let mut args = sample_args();
        args.read_ratio = Some(0.1);
        args.write_ratio = Some(0.2);
        args.scan_ratio = Some(0.7);

        let config = Config::try_from(args).expect("custom mix should parse");
        assert_eq!(config.workload.mix.read_ratio, 0.1);
        assert_eq!(config.workload.mix.write_ratio, 0.2);
        assert_eq!(config.workload.mix.scan_ratio, 0.7);
    }

    #[test]
    fn config_rejects_zero_keys() {
        let mut args = sample_args();
        args.keys = 0;
        assert!(Config::try_from(args).is_err());
    }

    #[test]
    fn config_rejects_zero_concurrency() {
        let mut args = sample_args();
        args.concurrency = 0;
        assert!(Config::try_from(args).is_err());
    }

    #[test]
    fn config_rejects_invalid_latest_probability() {
        let mut args = sample_args();
        args.latest_prob = 1.1;
        assert!(Config::try_from(args).is_err());
    }

    #[test]
    fn config_rejects_invalid_zipf_theta() {
        let mut args = sample_args();
        args.zipf_theta = 1.0;
        assert!(Config::try_from(args).is_err());
    }

    #[test]
    fn config_from_manifest_uses_manifest_values() {
        let output = Some(PathBuf::from("report.json"));
        let config = Config::try_from_manifest(sample_manifest(), output.clone(), 0)
            .expect("manifest should parse");

        assert_eq!(config.client.endpoint, "http://localhost:10000");
        assert_eq!(config.namespace, 42);
        assert_eq!(config.initial_keys, 1_000);
        assert_eq!(config.total_ops, 10_000);
        assert_eq!(config.concurrency, 4);
        assert_eq!(config.scenario, Scenario::ScanHeavy);
        assert_eq!(config.workload.key_dist, KeyDistribution::Latest);
        assert_eq!(config.rng_seed, 123);
        assert_eq!(config.progress_interval_secs, 0);
        assert_eq!(config.output, output);
    }

    #[test]
    fn config_from_manifest_rejects_generator_version_mismatch() {
        let mut manifest = sample_manifest();
        manifest.config.value_generator_version += 1;

        let err = Config::try_from_manifest(manifest, None, 10)
            .expect_err("version mismatch should be rejected");
        assert!(err.to_string().contains("value_generator_version"));
    }
}
