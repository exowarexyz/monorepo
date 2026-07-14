use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{ensure, Context};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::workload::{Scenario, WorkloadSpec};

const BENCH_MANIFEST_SCHEMA_VERSION: u16 = 1;
const BENCH_REPORT_SCHEMA_VERSION: u16 = 1;
const LATENCY_UNIT: &str = "microseconds";

// Fixed buckets keep benchmark reports comparable across runs without needing
// to replay raw per-operation samples.
const LATENCY_BUCKET_UPPER_BOUNDS_US: [u64; 15] = [
    100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
    1_000_000, 2_500_000, 5_000_000,
];

// Reports and manifests written before `value_size` existed omit the field;
// default it to the generator default so they still parse and replay.
fn default_value_size() -> usize {
    crate::value::DEFAULT_VALUE_SIZE
}

// Older reports used the operation stream before Zipf sampling consumed one
// random draw per operation. Parse them so replay can reject the mismatch.
fn default_workload_generator_version() -> u16 {
    1
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BenchConfig {
    pub endpoint: String,
    pub namespace: u64,
    pub key_space: u64,
    pub total_ops: u64,
    pub concurrency: usize,
    pub scenario: Scenario,
    pub workload: WorkloadSpec,
    pub key_len: usize,
    #[serde(default = "default_value_size")]
    pub value_size: usize,
    pub keyspace_layout_version: u16,
    pub value_generator_version: u16,
    #[serde(default = "default_workload_generator_version")]
    pub workload_generator_version: u16,
    pub read_retry_attempts: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BenchReport {
    pub config: BenchConfig,
    pub seed: u64,
    pub elapsed_ms: u128,
    pub operations: u64,
    pub reads: u64,
    pub writes: u64,
    pub errors: u64,
    pub scans: u64,
    pub scan_rows: u64,
    pub read_misses: u64,
    pub latency_histograms: LatencyHistograms,
}

/// Benchmark manifests keep replay tied to the normalized runtime config and
/// seed, instead of requiring reconstruction of the original CLI flags.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BenchManifest {
    pub schema_version: u16,
    pub config: BenchConfig,
    pub seed: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LatencyHistograms {
    pub read: LatencyHistogram,
    pub write: LatencyHistogram,
    pub scan: LatencyHistogram,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LatencyHistogram {
    pub unit: String,
    pub count: u64,
    pub min_us: Option<u64>,
    pub max_us: Option<u64>,
    pub p50_us: Option<u64>,
    pub p95_us: Option<u64>,
    pub p99_us: Option<u64>,
    pub buckets: Vec<LatencyBucket>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LatencyBucket {
    pub upper_bound_us: Option<u64>,
    pub count: u64,
}

#[derive(Default)]
pub struct LatencyHistogramsRecorder {
    read: LatencyHistogramRecorder,
    write: LatencyHistogramRecorder,
    scan: LatencyHistogramRecorder,
}

struct LatencyHistogramRecorder {
    counts: Vec<AtomicU64>,
    min_us: AtomicU64,
    max_us: AtomicU64,
}

#[derive(Serialize)]
struct BenchReportJson<'a> {
    schema_version: u16,
    tool_version: &'static str,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    config: &'a BenchConfig,
    seed: u64,
    elapsed_ms: u128,
    ops_per_sec: f64,
    operations: u64,
    reads: u64,
    read_misses: u64,
    writes: u64,
    scans: u64,
    scan_rows: u64,
    errors: u64,
    latency_histograms: &'a LatencyHistograms,
}

impl BenchReport {
    pub fn ops_per_sec(&self) -> f64 {
        if self.elapsed_ms == 0 {
            return 0.0;
        }
        self.operations as f64 / (self.elapsed_ms as f64 / 1_000.0)
    }
}

impl BenchManifest {
    pub fn new(config: BenchConfig, seed: u64) -> Self {
        Self {
            schema_version: BENCH_MANIFEST_SCHEMA_VERSION,
            config,
            seed,
        }
    }
}

impl LatencyHistograms {
    pub fn empty() -> Self {
        LatencyHistogramsRecorder::default().snapshot()
    }
}

impl LatencyHistogramsRecorder {
    pub fn record_read(&self, duration: Duration) {
        self.read.record(duration);
    }

    pub fn record_write(&self, duration: Duration) {
        self.write.record(duration);
    }

    pub fn record_scan(&self, duration: Duration) {
        self.scan.record(duration);
    }

    pub fn snapshot(&self) -> LatencyHistograms {
        LatencyHistograms {
            read: self.read.snapshot(),
            write: self.write.snapshot(),
            scan: self.scan.snapshot(),
        }
    }
}

impl LatencyHistogramRecorder {
    fn record(&self, duration: Duration) {
        let micros = duration_to_micros(duration);
        let bucket = LATENCY_BUCKET_UPPER_BOUNDS_US
            .iter()
            .position(|bound| micros <= *bound)
            .unwrap_or(LATENCY_BUCKET_UPPER_BOUNDS_US.len());
        self.counts[bucket].fetch_add(1, Ordering::Relaxed);
        update_min(&self.min_us, micros);
        update_max(&self.max_us, micros);
    }

    fn snapshot(&self) -> LatencyHistogram {
        let counts = self
            .counts
            .iter()
            .map(|count| count.load(Ordering::Relaxed))
            .collect::<Vec<_>>();
        let count = counts.iter().sum();
        let max_us = self.max_us.load(Ordering::Relaxed);
        let min_us = self.min_us.load(Ordering::Relaxed);
        let max_us = if count == 0 { None } else { Some(max_us) };
        let min_us = if count == 0 { None } else { Some(min_us) };
        let buckets = counts
            .iter()
            .enumerate()
            .map(|(idx, count)| LatencyBucket {
                upper_bound_us: LATENCY_BUCKET_UPPER_BOUNDS_US.get(idx).copied(),
                count: *count,
            })
            .collect();

        LatencyHistogram {
            unit: LATENCY_UNIT.to_string(),
            count,
            min_us,
            max_us,
            p50_us: percentile_upper_bound_us(&counts, 0.50, max_us),
            p95_us: percentile_upper_bound_us(&counts, 0.95, max_us),
            p99_us: percentile_upper_bound_us(&counts, 0.99, max_us),
            buckets,
        }
    }
}

impl Default for LatencyHistogramRecorder {
    fn default() -> Self {
        Self {
            counts: (0..=LATENCY_BUCKET_UPPER_BOUNDS_US.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
            min_us: AtomicU64::new(u64::MAX),
            max_us: AtomicU64::new(0),
        }
    }
}

impl fmt::Display for BenchReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "benchmark report")?;
        writeln!(f, "  endpoint: {}", self.config.endpoint)?;
        writeln!(f, "  namespace: {}", self.config.namespace)?;
        writeln!(f, "  seed: {}", self.seed)?;
        writeln!(f, "  scenario: {:?}", self.config.scenario)?;
        writeln!(f, "  key_space: {}", self.config.key_space)?;
        writeln!(f, "  key_len: {}", self.config.key_len)?;
        writeln!(f, "  value_size: {}", self.config.value_size)?;
        writeln!(
            f,
            "  keyspace_layout_version: {}",
            self.config.keyspace_layout_version
        )?;
        writeln!(
            f,
            "  value_generator_version: {}",
            self.config.value_generator_version
        )?;
        writeln!(
            f,
            "  workload_generator_version: {}",
            self.config.workload_generator_version
        )?;
        writeln!(f, "  total_ops: {}", self.config.total_ops)?;
        writeln!(f, "  concurrency: {}", self.config.concurrency)?;
        writeln!(
            f,
            "  mix: read={:.4} write={:.4} scan={:.4}",
            self.config.workload.mix.read_ratio,
            self.config.workload.mix.write_ratio,
            self.config.workload.mix.scan_ratio
        )?;
        writeln!(
            f,
            "  distribution: {:?} latest_window={} latest_prob={:.4} zipf_theta={:.4}",
            self.config.workload.key_dist,
            self.config.workload.latest_window,
            self.config.workload.latest_prob,
            self.config.workload.zipf_theta
        )?;
        writeln!(f, "  scan_length: {}", self.config.workload.scan_length)?;
        writeln!(
            f,
            "  read_retry_attempts: {}",
            self.config.read_retry_attempts
        )?;
        writeln!(f, "  elapsed_ms: {}", self.elapsed_ms)?;
        writeln!(f, "  ops_per_sec: {:.2}", self.ops_per_sec())?;
        writeln!(f, "  operations: {}", self.operations)?;
        writeln!(f, "  reads: {}", self.reads)?;
        writeln!(f, "  read_misses: {}", self.read_misses)?;
        writeln!(f, "  writes: {}", self.writes)?;
        writeln!(f, "  scans: {}", self.scans)?;
        writeln!(f, "  scan_rows: {}", self.scan_rows)?;
        writeln!(f, "  errors: {}", self.errors)?;
        writeln!(
            f,
            "  read_latency_ms: {}",
            latency_summary_ms(&self.latency_histograms.read)
        )?;
        writeln!(
            f,
            "  write_latency_ms: {}",
            latency_summary_ms(&self.latency_histograms.write)
        )?;
        write!(
            f,
            "  scan_latency_ms: {}",
            latency_summary_ms(&self.latency_histograms.scan)
        )
    }
}

pub fn read_bench_manifest_json(path: &Path) -> anyhow::Result<BenchManifest> {
    let body = fs::read_to_string(path)
        .with_context(|| format!("failed to read benchmark manifest {path:?}"))?;
    let manifest: BenchManifest =
        serde_json::from_str(&body).context("failed to parse benchmark manifest")?;
    // A report JSON carries the same `config` and `seed` as a manifest, so reports are
    // intentionally replayable via `--manifest`. Accept either schema version so the manifest
    // and report schemas can evolve independently without silently breaking report replay.
    ensure!(
        manifest.schema_version == BENCH_MANIFEST_SCHEMA_VERSION
            || manifest.schema_version == BENCH_REPORT_SCHEMA_VERSION,
        "unsupported benchmark manifest schema_version {}",
        manifest.schema_version
    );
    Ok(manifest)
}

pub fn print_bench_report(report: &BenchReport) {
    tracing::info!(
        total_ops = report.operations,
        reads = report.reads,
        read_misses = report.read_misses,
        writes = report.writes,
        scans = report.scans,
        scan_rows = report.scan_rows,
        read_latency_p50_us = report.latency_histograms.read.p50_us,
        read_latency_p95_us = report.latency_histograms.read.p95_us,
        write_latency_p50_us = report.latency_histograms.write.p50_us,
        write_latency_p95_us = report.latency_histograms.write.p95_us,
        scan_latency_p50_us = report.latency_histograms.scan.p50_us,
        scan_latency_p95_us = report.latency_histograms.scan.p95_us,
        errors = report.errors,
        elapsed_ms = report.elapsed_ms,
        ops_per_sec = report.ops_per_sec(),
        seed = report.seed,
        "Benchmark phase complete"
    );
    println!("{report}");
}

pub fn write_bench_report_json(
    path: &Path,
    report: &BenchReport,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
) -> anyhow::Result<()> {
    let body = bench_report_json(report, started_at, finished_at)?;
    let temp_path = temporary_output_path(path);
    fs::write(&temp_path, body)
        .with_context(|| format!("failed to write temporary benchmark report {temp_path:?}"))?;
    fs::rename(&temp_path, path)
        .with_context(|| format!("failed to write benchmark report {path:?}"))?;
    Ok(())
}

fn bench_report_json(
    report: &BenchReport,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
) -> anyhow::Result<String> {
    let json = BenchReportJson {
        schema_version: BENCH_REPORT_SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION"),
        started_at,
        finished_at,
        config: &report.config,
        seed: report.seed,
        elapsed_ms: report.elapsed_ms,
        ops_per_sec: report.ops_per_sec(),
        operations: report.operations,
        reads: report.reads,
        read_misses: report.read_misses,
        writes: report.writes,
        scans: report.scans,
        scan_rows: report.scan_rows,
        errors: report.errors,
        latency_histograms: &report.latency_histograms,
    };
    serde_json::to_string_pretty(&json).context("failed to serialize benchmark report")
}

fn latency_summary_ms(histogram: &LatencyHistogram) -> String {
    if histogram.count == 0 {
        return "n/a".to_string();
    }
    format!(
        "p50={} p95={} p99={} max={}",
        format_us_as_ms(histogram.p50_us),
        format_us_as_ms(histogram.p95_us),
        format_us_as_ms(histogram.p99_us),
        format_us_as_ms(histogram.max_us)
    )
}

fn format_us_as_ms(value: Option<u64>) -> String {
    value
        .map(|value| format!("{:.3}ms", value as f64 / 1_000.0))
        .unwrap_or_else(|| "n/a".to_string())
}

fn duration_to_micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

fn percentile_upper_bound_us(counts: &[u64], percentile: f64, max_us: Option<u64>) -> Option<u64> {
    let total = counts.iter().sum::<u64>();
    if total == 0 {
        return None;
    }
    let target = ((total as f64) * percentile).ceil().max(1.0) as u64;
    let mut cumulative = 0u64;
    for (idx, count) in counts.iter().enumerate() {
        cumulative += *count;
        if cumulative >= target {
            return LATENCY_BUCKET_UPPER_BOUNDS_US.get(idx).copied().or(max_us);
        }
    }
    max_us
}

fn update_min(min: &AtomicU64, value: u64) {
    let mut current = min.load(Ordering::Relaxed);
    while value < current {
        match min.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(next) => current = next,
        }
    }
}

fn update_max(max: &AtomicU64, value: u64) {
    let mut current = max.load(Ordering::Relaxed);
    while value > current {
        match max.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(next) => current = next,
        }
    }
}

fn temporary_output_path(path: &Path) -> PathBuf {
    let mut filename = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "benchmark-report".into());
    filename.push(".tmp");
    path.with_file_name(filename)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload::{KeyDistribution, WorkloadMix};

    #[derive(Debug, Deserialize)]
    struct ParsedBenchReportJson {
        schema_version: u16,
        tool_version: String,
        started_at: DateTime<Utc>,
        finished_at: DateTime<Utc>,
        config: BenchConfig,
        seed: u64,
        elapsed_ms: u128,
        ops_per_sec: f64,
        operations: u64,
        reads: u64,
        read_misses: u64,
        writes: u64,
        scans: u64,
        scan_rows: u64,
        errors: u64,
        latency_histograms: LatencyHistograms,
    }

    fn sample_report() -> BenchReport {
        let latencies = LatencyHistogramsRecorder::default();
        latencies.record_read(Duration::from_micros(100));
        latencies.record_read(Duration::from_micros(2_000));
        latencies.record_write(Duration::from_micros(500));

        BenchReport {
            config: BenchConfig {
                endpoint: "http://localhost:10000".to_string(),
                namespace: 42,
                key_space: 1_000,
                total_ops: 10_000,
                concurrency: 4,
                scenario: Scenario::Balanced,
                workload: WorkloadSpec {
                    mix: WorkloadMix {
                        read_ratio: 0.7,
                        write_ratio: 0.3,
                        scan_ratio: 0.0,
                    },
                    scan_length: 25,
                    key_dist: KeyDistribution::Uniform,
                    latest_window: 5_000,
                    latest_prob: 0.9,
                    zipf_theta: 0.99,
                },
                key_len: 48,
                value_size: crate::value::DEFAULT_VALUE_SIZE,
                keyspace_layout_version: crate::keyspace::KEYSPACE_LAYOUT_VERSION,
                value_generator_version: crate::value::VALUE_GENERATOR_VERSION,
                workload_generator_version: crate::workload::WORKLOAD_GENERATOR_VERSION,
                read_retry_attempts: 3,
            },
            seed: 42,
            elapsed_ms: 2_000,
            operations: 10_000,
            reads: 7_000,
            writes: 3_000,
            errors: 0,
            scans: 0,
            scan_rows: 0,
            read_misses: 0,
            latency_histograms: latencies.snapshot(),
        }
    }

    #[test]
    fn bench_report_computes_ops_per_sec() {
        assert_eq!(sample_report().ops_per_sec(), 5_000.0);
    }

    #[test]
    fn bench_report_json_round_trips_metadata_config_and_counters() {
        let started_at = DateTime::parse_from_rfc3339("2026-05-28T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let finished_at = DateTime::parse_from_rfc3339("2026-05-28T12:00:02Z")
            .unwrap()
            .with_timezone(&Utc);
        let report = sample_report();
        let json =
            bench_report_json(&report, started_at, finished_at).expect("report should serialize");
        let parsed: ParsedBenchReportJson =
            serde_json::from_str(&json).expect("report JSON should deserialize");

        assert_eq!(parsed.schema_version, 1);
        assert_eq!(parsed.tool_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(parsed.started_at, started_at);
        assert_eq!(parsed.finished_at, finished_at);
        assert_eq!(parsed.config, report.config);
        assert_eq!(parsed.seed, report.seed);
        assert_eq!(parsed.elapsed_ms, report.elapsed_ms);
        assert_eq!(parsed.ops_per_sec, report.ops_per_sec());
        assert_eq!(parsed.operations, report.operations);
        assert_eq!(parsed.reads, report.reads);
        assert_eq!(parsed.read_misses, report.read_misses);
        assert_eq!(parsed.writes, report.writes);
        assert_eq!(parsed.scans, report.scans);
        assert_eq!(parsed.scan_rows, report.scan_rows);
        assert_eq!(parsed.errors, report.errors);
        assert_eq!(parsed.latency_histograms, report.latency_histograms);
        assert_eq!(parsed.latency_histograms.read.unit, "microseconds");
        assert_eq!(parsed.latency_histograms.read.count, 2);
        assert_eq!(parsed.latency_histograms.write.count, 1);
    }

    #[test]
    fn latency_histogram_uses_fixed_buckets_and_bucket_percentiles() {
        let latencies = LatencyHistogramsRecorder::default();
        latencies.record_read(Duration::from_micros(100));
        latencies.record_read(Duration::from_micros(2_000));
        latencies.record_read(Duration::from_micros(6_000_000));

        let histogram = latencies.snapshot().read;
        assert_eq!(histogram.count, 3);
        assert_eq!(histogram.min_us, Some(100));
        assert_eq!(histogram.max_us, Some(6_000_000));
        assert_eq!(histogram.p50_us, Some(2_500));
        assert_eq!(histogram.p95_us, Some(6_000_000));
        assert_eq!(histogram.buckets[0].upper_bound_us, Some(100));
        assert_eq!(histogram.buckets[0].count, 1);
        assert_eq!(histogram.buckets.last().unwrap().upper_bound_us, None);
        assert_eq!(histogram.buckets.last().unwrap().count, 1);
    }

    #[test]
    fn write_bench_report_json_overwrites_existing_file() {
        let started_at = DateTime::parse_from_rfc3339("2026-05-28T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let finished_at = DateTime::parse_from_rfc3339("2026-05-28T12:00:02Z")
            .unwrap()
            .with_timezone(&Utc);
        let path = std::env::temp_dir().join(format!(
            "exoware-workload-report-{}-{}.json",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&path, "old report").expect("seed existing report");

        write_bench_report_json(&path, &sample_report(), started_at, finished_at)
            .expect("report write should overwrite");
        let body = std::fs::read_to_string(&path).expect("report should be readable");
        let value: serde_json::Value =
            serde_json::from_str(&body).expect("report JSON should parse");
        std::fs::remove_file(&path).expect("temporary report should be removable");

        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["seed"], 42);
        assert_eq!(value["latency_histograms"]["read"]["count"], 2);
    }

    #[test]
    fn benchmark_report_json_can_be_read_as_manifest() {
        let started_at = DateTime::parse_from_rfc3339("2026-05-28T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let finished_at = DateTime::parse_from_rfc3339("2026-05-28T12:00:02Z")
            .unwrap()
            .with_timezone(&Utc);
        let report = sample_report();
        let json =
            bench_report_json(&report, started_at, finished_at).expect("report should serialize");
        let path = std::env::temp_dir().join(format!(
            "exoware-workload-manifest-{}-{}.json",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&path, json).expect("manifest fixture should write");

        let manifest = read_bench_manifest_json(&path).expect("report should parse as manifest");
        std::fs::remove_file(&path).expect("temporary manifest should be removable");

        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.config, report.config);
        assert_eq!(manifest.seed, report.seed);
    }

    #[test]
    fn read_manifest_accepts_report_schema_version_and_rejects_unknown() {
        let report = sample_report();
        let manifest = BenchManifest::new(report.config.clone(), report.seed);
        let mut value = serde_json::to_value(&manifest).expect("manifest should serialize");

        // A file stamped with the report schema version must still parse as a manifest, even
        // once that version diverges from the manifest schema version. Building the fixture from
        // the constant (rather than a literal) keeps this honest if the report schema is bumped.
        value["schema_version"] = serde_json::Value::from(BENCH_REPORT_SCHEMA_VERSION);
        let accepted_path = std::env::temp_dir().join(format!(
            "exoware-workload-manifest-report-version-{}-{}.json",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&accepted_path, value.to_string()).expect("manifest fixture should write");
        let parsed = read_bench_manifest_json(&accepted_path)
            .expect("report-versioned manifest should parse");
        std::fs::remove_file(&accepted_path).ok();
        assert_eq!(parsed.config, manifest.config);
        assert_eq!(parsed.seed, manifest.seed);

        // A schema version belonging to neither the manifest nor the report is still rejected.
        let unsupported = BENCH_MANIFEST_SCHEMA_VERSION.max(BENCH_REPORT_SCHEMA_VERSION) + 1;
        value["schema_version"] = serde_json::Value::from(unsupported);
        let rejected_path = std::env::temp_dir().join(format!(
            "exoware-workload-manifest-bad-version-{}-{}.json",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&rejected_path, value.to_string()).expect("manifest fixture should write");
        let err = read_bench_manifest_json(&rejected_path)
            .expect_err("unsupported manifest schema_version should be rejected");
        std::fs::remove_file(&rejected_path).ok();
        assert!(err
            .to_string()
            .contains("unsupported benchmark manifest schema_version"));
    }

    #[test]
    fn manifest_without_value_size_defaults_to_generator_default() {
        // Manifests predate `value_size`, so a config missing the field must still parse and
        // replay at the generator default rather than failing deserialization.
        let report = sample_report();
        let manifest = BenchManifest::new(report.config.clone(), report.seed);
        let mut value = serde_json::to_value(&manifest).expect("manifest should serialize");
        value["config"]
            .as_object_mut()
            .expect("config should be a JSON object")
            .remove("value_size");

        let path = std::env::temp_dir().join(format!(
            "exoware-workload-manifest-no-value-size-{}-{}.json",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&path, value.to_string()).expect("manifest fixture should write");
        let parsed = read_bench_manifest_json(&path).expect("legacy manifest should parse");
        std::fs::remove_file(&path).ok();
        assert_eq!(parsed.config.value_size, crate::value::DEFAULT_VALUE_SIZE);
    }

    #[test]
    fn manifest_without_workload_generator_version_is_marked_legacy() {
        let report = sample_report();
        let manifest = BenchManifest::new(report.config, report.seed);
        let mut value = serde_json::to_value(&manifest).expect("manifest should serialize");
        value["config"]
            .as_object_mut()
            .expect("config should be a JSON object")
            .remove("workload_generator_version");

        let path = std::env::temp_dir().join(format!(
            "exoware-workload-manifest-no-workload-generator-version-{}-{}.json",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&path, value.to_string()).expect("manifest fixture should write");
        let parsed = read_bench_manifest_json(&path).expect("legacy manifest should parse");
        std::fs::remove_file(&path).ok();

        assert_eq!(parsed.config.workload_generator_version, 1);
    }
}
