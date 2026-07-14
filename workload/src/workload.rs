use anyhow::{ensure, Context};
use clap::ValueEnum;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::ops::Range;
use std::sync::Arc;

use crate::deterministic::GOLDEN_RATIO_64;

/// Default seed used when the caller does not provide one.
pub const DEFAULT_BENCH_RNG_SEED: u64 = 0x5eed_c0de;

/// Version of the deterministic operation-stream generator used in manifests.
pub const WORKLOAD_GENERATOR_VERSION: u16 = 2;

/// Named workload mixes for benchmark operation selection.
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
#[allow(clippy::enum_variant_names)]
pub enum Scenario {
    ReadHeavy,
    Balanced,
    WriteHeavy,
    ScanHeavy,
    IngestBurst,
}

/// Key-index distribution for read and scan operations.
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lower")]
pub enum KeyDistribution {
    Uniform,
    Latest,
    Zipfian,
}

/// Ratios used to choose read, write, and scan operations.
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct WorkloadMix {
    /// Probability of issuing a point read.
    pub read_ratio: f64,
    /// Probability of issuing an ingest write.
    pub write_ratio: f64,
    /// Probability of issuing a range scan.
    pub scan_ratio: f64,
}

/// Validated logical workload description independent of command-line parsing.
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct WorkloadSpec {
    /// Operation mix used by every worker.
    pub mix: WorkloadMix,
    /// Requested row limit and maximum logical span for generated scans.
    pub scan_length: usize,
    /// Distribution used when selecting existing-key indexes.
    pub key_dist: KeyDistribution,
    /// Width of the recency window used by latest-biased sampling.
    pub latest_window: u64,
    /// Probability of sampling from the latest window.
    pub latest_prob: f64,
    /// Skew parameter used by Zipfian sampling.
    pub zipf_theta: f64,
}

/// Logical operation emitted by a reproducible worker plan.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Point read of an inserted logical key index.
    Read { index: u64 },
    /// Inclusive range scan between the keys of two inserted logical indexes;
    /// the executor orders the endpoint keys lexicographically.
    Scan { start: u64, end: u64, limit: usize },
    /// Ingest write; the executor assigns the next concrete write index.
    Write,
}

/// Deterministic per-worker operation stream.
pub struct WorkerPlan {
    rng: rand::rngs::StdRng,
    spec: WorkloadSpec,
    zipf_sampler: Option<Arc<ZipfSampler>>,
}

pub(crate) struct ZipfSampler {
    max_key_exclusive: u64,
    cdf: Vec<f64>,
}

impl Scenario {
    /// Returns the default operation mix for a named scenario.
    pub fn mix(self) -> WorkloadMix {
        match self {
            Scenario::ReadHeavy => WorkloadMix {
                read_ratio: 0.95,
                write_ratio: 0.05,
                scan_ratio: 0.00,
            },
            // Read-dominant with meaningful writes and a modest scan share, so the default mix
            // exercises every read path (point, ingest, range) rather than skipping scans.
            Scenario::Balanced => WorkloadMix {
                read_ratio: 0.67,
                write_ratio: 0.30,
                scan_ratio: 0.03,
            },
            Scenario::WriteHeavy => WorkloadMix {
                read_ratio: 0.20,
                write_ratio: 0.80,
                scan_ratio: 0.00,
            },
            Scenario::ScanHeavy => WorkloadMix {
                read_ratio: 0.40,
                write_ratio: 0.10,
                scan_ratio: 0.50,
            },
            Scenario::IngestBurst => WorkloadMix {
                read_ratio: 0.00,
                write_ratio: 1.00,
                scan_ratio: 0.00,
            },
        }
    }
}

impl WorkloadSpec {
    /// Constructs and validates a workload spec from normalized inputs.
    pub fn new(
        mix: WorkloadMix,
        scan_length: usize,
        key_dist: KeyDistribution,
        latest_window: u64,
        latest_prob: f64,
        zipf_theta: f64,
    ) -> anyhow::Result<Self> {
        let spec = Self {
            mix,
            scan_length,
            key_dist,
            latest_window,
            latest_prob,
            zipf_theta,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Validates ratios and distribution parameters before execution.
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            (0.0..=1.0).contains(&self.mix.read_ratio),
            "--read-ratio must be in [0, 1]"
        );
        ensure!(
            (0.0..=1.0).contains(&self.mix.write_ratio),
            "--write-ratio must be in [0, 1]"
        );
        ensure!(
            (0.0..=1.0).contains(&self.mix.scan_ratio),
            "--scan-ratio must be in [0, 1]"
        );
        ensure!(self.scan_length > 0, "--scan-length must be > 0");
        ensure!(
            (0.0..=1.0).contains(&self.latest_prob),
            "--latest-prob must be in [0, 1]"
        );
        ensure!(
            self.zipf_theta > 0.0 && self.zipf_theta < 1.0,
            "--zipf-theta must be in (0, 1)"
        );
        ensure!(self.latest_window > 0, "--latest-window must be > 0");
        ensure!(
            approx_eq(
                self.mix.read_ratio + self.mix.write_ratio + self.mix.scan_ratio,
                1.0,
                1e-9,
            ),
            "invalid workload ratios: read+write+scan must equal 1.0"
        );
        Ok(())
    }
}

impl WorkerPlan {
    /// Creates a replayable worker stream from the run seed and worker id.
    pub fn new(seed: u64, worker_id: u64, spec: WorkloadSpec) -> Self {
        Self::with_zipf_sampler(seed, worker_id, spec, None)
    }

    pub(crate) fn with_zipf_sampler(
        seed: u64,
        worker_id: u64,
        spec: WorkloadSpec,
        zipf_sampler: Option<Arc<ZipfSampler>>,
    ) -> Self {
        Self {
            rng: worker_rng(seed, worker_id),
            spec,
            zipf_sampler,
        }
    }

    /// Emits the next logical operation for the current visible key range.
    pub fn next_operation(&mut self, max_key_exclusive: u64) -> Operation {
        let p = self.rng.gen::<f64>();
        if p < self.spec.mix.read_ratio {
            return Operation::Read {
                index: self.sample_key_index(max_key_exclusive),
            };
        }

        if p < self.spec.mix.read_ratio + self.spec.mix.scan_ratio {
            let max_key_exclusive = max_key_exclusive.max(1);
            let start = self.sample_key_index(max_key_exclusive);
            let mut end = start.saturating_add(self.spec.scan_length.saturating_sub(1) as u64);
            if end >= max_key_exclusive {
                end = max_key_exclusive - 1;
            }

            return Operation::Scan {
                start,
                end,
                limit: self.spec.scan_length,
            };
        }

        Operation::Write
    }

    fn sample_key_index(&mut self, max_key_exclusive: u64) -> u64 {
        if self.spec.key_dist != KeyDistribution::Zipfian {
            return sample_key_index(&mut self.rng, max_key_exclusive, self.spec);
        }

        let replace_sampler = self
            .zipf_sampler
            .as_ref()
            .is_none_or(|sampler| sampler.max_key_exclusive != max_key_exclusive);
        if replace_sampler {
            self.zipf_sampler = Some(Arc::new(ZipfSampler::new(
                max_key_exclusive,
                self.spec.zipf_theta,
            )));
        }

        self.zipf_sampler
            .as_ref()
            .expect("zipf sampler is initialized")
            .sample(&mut self.rng)
    }
}

impl ZipfSampler {
    pub(crate) fn new(max_key_exclusive: u64, theta: f64) -> Self {
        if max_key_exclusive <= 1 {
            return Self {
                max_key_exclusive,
                cdf: vec![1.0],
            };
        }

        let mut cdf = Vec::with_capacity(max_key_exclusive as usize);
        let mut normalization = 0.0;
        for rank in 1..=max_key_exclusive {
            normalization += (rank as f64).powf(-theta);
            cdf.push(normalization);
        }
        for probability in &mut cdf {
            *probability /= normalization;
        }
        *cdf.last_mut().expect("non-empty zipf CDF") = 1.0;

        Self {
            max_key_exclusive,
            cdf,
        }
    }

    fn sample(&self, rng: &mut rand::rngs::StdRng) -> u64 {
        let draw = rng.gen();
        self.cdf.partition_point(|probability| *probability < draw) as u64
    }
}

/// Resolves scenario defaults and all-or-nothing custom ratio overrides.
pub fn resolve_mix(
    scenario: Scenario,
    read_ratio: Option<f64>,
    write_ratio: Option<f64>,
    scan_ratio: Option<f64>,
) -> anyhow::Result<WorkloadMix> {
    match (read_ratio, write_ratio, scan_ratio) {
        (None, None, None) => Ok(scenario.mix()),
        // Range and sum validation runs in `WorkloadSpec::validate` once the mix is built, so
        // only the all-or-nothing override shape is enforced here.
        (Some(read_ratio), Some(write_ratio), Some(scan_ratio)) => Ok(WorkloadMix {
            read_ratio,
            write_ratio,
            scan_ratio,
        }),
        _ => anyhow::bail!(
            "custom ratio override requires all of --read-ratio, --write-ratio, and --scan-ratio"
        ),
    }
}

/// Derives a stable RNG stream for a worker from the run seed.
pub fn worker_rng(base_seed: u64, worker_id: u64) -> rand::rngs::StdRng {
    let mixed = base_seed ^ worker_id.wrapping_mul(GOLDEN_RATIO_64);
    rand::rngs::StdRng::seed_from_u64(mixed)
}

/// Splits a total operation count across workers with deterministic remainder placement.
pub fn worker_operation_count(
    total_ops: u64,
    concurrency: usize,
    worker_id: usize,
) -> anyhow::Result<u64> {
    let range = worker_index_range(total_ops, concurrency, worker_id)?;
    Ok(range.end - range.start)
}

/// Splits a logical index range across workers with deterministic remainder placement.
pub fn worker_index_range(
    total_indices: u64,
    concurrency: usize,
    worker_id: usize,
) -> anyhow::Result<Range<u64>> {
    ensure!(concurrency > 0, "--concurrency must be > 0");
    ensure!(
        worker_id < concurrency,
        "worker_id must be less than concurrency"
    );

    let concurrency = concurrency as u64;
    let base = total_indices / concurrency;
    let remainder = total_indices % concurrency;
    let worker_id = worker_id as u64;
    let start = worker_id * base + worker_id.min(remainder);
    let end = start + base + u64::from(worker_id < remainder);
    Ok(start..end)
}

/// Returns the concrete key index for one worker's deterministic write sequence.
pub fn worker_write_index(
    initial_keys: u64,
    concurrency: usize,
    worker_id: usize,
    write_number: u64,
) -> anyhow::Result<u64> {
    ensure!(concurrency > 0, "--concurrency must be > 0");
    ensure!(
        worker_id < concurrency,
        "worker_id must be less than concurrency"
    );

    let offset = write_number
        .checked_mul(concurrency as u64)
        .and_then(|offset| offset.checked_add(worker_id as u64))
        .context("worker write index overflow")?;
    initial_keys
        .checked_add(offset)
        .context("worker write index overflow")
}

/// Samples an inserted logical key index according to the workload distribution.
pub fn sample_key_index(
    rng: &mut rand::rngs::StdRng,
    max_key_exclusive: u64,
    spec: WorkloadSpec,
) -> u64 {
    if max_key_exclusive <= 1 {
        return 0;
    }

    match spec.key_dist {
        KeyDistribution::Uniform => rng.gen_range(0..max_key_exclusive),
        KeyDistribution::Latest => {
            if rng.gen::<f64>() < spec.latest_prob {
                let window = spec.latest_window.max(1).min(max_key_exclusive);
                let start = max_key_exclusive - window;
                rng.gen_range(start..max_key_exclusive)
            } else {
                rng.gen_range(0..max_key_exclusive)
            }
        }
        KeyDistribution::Zipfian => sample_zipf_index(rng, max_key_exclusive, spec.zipf_theta),
    }
}

fn sample_zipf_index(rng: &mut rand::rngs::StdRng, max_key_exclusive: u64, theta: f64) -> u64 {
    ZipfSampler::new(max_key_exclusive, theta).sample(rng)
}

fn approx_eq(a: f64, b: f64, eps: f64) -> bool {
    (a - b).abs() <= eps
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    fn sample_spec() -> WorkloadSpec {
        WorkloadSpec::new(
            WorkloadMix {
                read_ratio: 0.4,
                write_ratio: 0.1,
                scan_ratio: 0.5,
            },
            25,
            KeyDistribution::Uniform,
            5_000,
            0.9,
            0.99,
        )
        .expect("sample workload spec should be valid")
    }

    fn worker_streams(
        seed: u64,
        spec: WorkloadSpec,
        total_ops: u64,
        concurrency: usize,
        max_key_exclusive: u64,
    ) -> Vec<Vec<Operation>> {
        (0..concurrency)
            .map(|worker| {
                let worker_ops = worker_operation_count(total_ops, concurrency, worker).unwrap();
                let mut plan = WorkerPlan::new(seed, worker as u64, spec);
                (0..worker_ops)
                    .map(|_| plan.next_operation(max_key_exclusive))
                    .collect()
            })
            .collect()
    }

    #[test]
    fn scenario_mixes_sum_to_one() {
        for scenario in [
            Scenario::ReadHeavy,
            Scenario::Balanced,
            Scenario::WriteHeavy,
            Scenario::ScanHeavy,
            Scenario::IngestBurst,
        ] {
            let mix = scenario.mix();
            assert!(approx_eq(
                mix.read_ratio + mix.write_ratio + mix.scan_ratio,
                1.0,
                1e-9
            ));
        }
    }

    #[test]
    fn resolve_mix_requires_all_custom_ratios() {
        let err = resolve_mix(Scenario::Balanced, Some(0.5), None, Some(0.5)).unwrap_err();
        assert!(err
            .to_string()
            .contains("requires all of --read-ratio, --write-ratio, and --scan-ratio"));
    }

    #[test]
    fn resolve_mix_custom_overrides_scenario() {
        let mix = resolve_mix(Scenario::ReadHeavy, Some(0.1), Some(0.2), Some(0.7))
            .expect("custom mix should parse");
        assert!(approx_eq(mix.read_ratio, 0.1, 1e-9));
        assert!(approx_eq(mix.write_ratio, 0.2, 1e-9));
        assert!(approx_eq(mix.scan_ratio, 0.7, 1e-9));
    }

    #[test]
    fn workload_spec_rejects_invalid_ratios() {
        let spec = WorkloadSpec {
            mix: WorkloadMix {
                read_ratio: 0.5,
                write_ratio: 0.5,
                scan_ratio: 0.5,
            },
            ..sample_spec()
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn workload_spec_rejects_ratio_outside_unit_interval() {
        let spec = WorkloadSpec {
            mix: WorkloadMix {
                read_ratio: -0.1,
                write_ratio: 0.6,
                scan_ratio: 0.5,
            },
            ..sample_spec()
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn latest_distribution_stays_in_window_when_prob_one() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let max = 10_000;
        let window = 100;
        let spec = WorkloadSpec {
            key_dist: KeyDistribution::Latest,
            latest_window: window,
            latest_prob: 1.0,
            ..sample_spec()
        };

        for _ in 0..1_000 {
            let idx = sample_key_index(&mut rng, max, spec);
            assert!(idx >= max - window);
            assert!(idx < max);
        }
    }

    #[test]
    fn all_distributions_respect_bounds() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        for key_dist in [
            KeyDistribution::Uniform,
            KeyDistribution::Latest,
            KeyDistribution::Zipfian,
        ] {
            let spec = WorkloadSpec {
                key_dist,
                ..sample_spec()
            };

            for _ in 0..1_000 {
                let idx = sample_key_index(&mut rng, 500, spec);
                assert!(idx < 500);
            }
        }
    }

    #[test]
    fn worker_rng_is_deterministic_per_seed_and_worker() {
        let mut a = worker_rng(42, 3);
        let mut b = worker_rng(42, 3);
        let seq_a: Vec<u64> = (0..8).map(|_| a.gen()).collect();
        let seq_b: Vec<u64> = (0..8).map(|_| b.gen()).collect();
        assert_eq!(seq_a, seq_b);
    }

    #[test]
    fn worker_rng_differs_across_workers() {
        let mut a = worker_rng(42, 3);
        let mut b = worker_rng(42, 4);
        let seq_a: Vec<u64> = (0..4).map(|_| a.gen()).collect();
        let seq_b: Vec<u64> = (0..4).map(|_| b.gen()).collect();
        assert_ne!(seq_a, seq_b);
    }

    #[test]
    fn zipfian_distribution_can_sample_the_last_key() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let spec = WorkloadSpec {
            key_dist: KeyDistribution::Zipfian,
            ..sample_spec()
        };

        assert!((0..10_000).any(|_| sample_key_index(&mut rng, 2, spec) == 1));
    }

    #[test]
    fn zipfian_distribution_matches_theoretical_head_probability() {
        let theta = 0.99;
        let keys = 4u64;
        let samples = 100_000u64;
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let sampler = ZipfSampler::new(keys, theta);

        let mut counts = [0u64; 4];
        for _ in 0..samples {
            counts[sampler.sample(&mut rng) as usize] += 1;
        }

        for pair in counts.windows(2) {
            assert!(
                pair[0] > pair[1],
                "zipfian counts must decrease by rank: {counts:?}"
            );
        }

        let normalization: f64 = (1..=keys).map(|rank| (rank as f64).powf(-theta)).sum();
        let expected_head = 1.0 / normalization;
        let actual_head = counts[0] as f64 / samples as f64;
        assert!(
            (actual_head - expected_head).abs() < 0.02,
            "head key frequency {actual_head:.4} deviates from zipf pmf {expected_head:.4}"
        );
    }

    #[test]
    fn worker_plans_share_a_supplied_zipf_sampler() {
        let spec = WorkloadSpec {
            key_dist: KeyDistribution::Zipfian,
            ..sample_spec()
        };
        let sampler = Arc::new(ZipfSampler::new(100, spec.zipf_theta));
        let first = WorkerPlan::with_zipf_sampler(1, 0, spec, Some(sampler.clone()));
        let second = WorkerPlan::with_zipf_sampler(1, 1, spec, Some(sampler));

        assert!(Arc::ptr_eq(
            first.zipf_sampler.as_ref().expect("sampler is set"),
            second.zipf_sampler.as_ref().expect("sampler is set")
        ));
    }

    #[test]
    fn zipfian_distribution_keeps_full_support_near_parameter_bounds() {
        for theta in [0.000_001, 0.999_999] {
            let mut rng = rand::rngs::StdRng::seed_from_u64(11);
            let spec = WorkloadSpec {
                key_dist: KeyDistribution::Zipfian,
                zipf_theta: theta,
                ..sample_spec()
            };
            assert!(
                (0..10_000).any(|_| sample_key_index(&mut rng, 4, spec) == 3),
                "last key was not sampled for theta={theta}"
            );
        }
    }

    #[test]
    fn worker_operation_count_distributes_remainder_to_first_workers() {
        let counts: Vec<u64> = (0..4)
            .map(|worker| worker_operation_count(10, 4, worker).unwrap())
            .collect();
        assert_eq!(counts, vec![3, 3, 2, 2]);
    }

    #[test]
    fn worker_index_ranges_balance_remainder() {
        let ranges: Vec<Range<u64>> = (0..4)
            .map(|worker| worker_index_range(7, 4, worker).unwrap())
            .collect();
        assert_eq!(ranges, vec![0..2, 2..4, 4..6, 6..7]);
    }

    #[test]
    fn worker_write_indexes_are_disjoint_and_replayable() {
        let indexes: Vec<u64> = (0..4)
            .flat_map(|worker| {
                (0..3).map(move |write_number| {
                    worker_write_index(100, 4, worker, write_number).unwrap()
                })
            })
            .collect();
        assert_eq!(
            indexes,
            vec![100, 104, 108, 101, 105, 109, 102, 106, 110, 103, 107, 111]
        );
    }

    #[test]
    fn worker_schedules_preserve_operation_streams_and_write_indexes() {
        fn run_schedule(schedule: &[usize], spec: WorkloadSpec) -> Vec<Vec<(Operation, u64)>> {
            let mut plans = [WorkerPlan::new(42, 0, spec), WorkerPlan::new(42, 1, spec)];
            let mut writes = [0u64; 2];
            let mut operations = vec![Vec::new(), Vec::new()];

            for &worker in schedule {
                let operation = plans[worker].next_operation(100);
                let write_index = match operation {
                    Operation::Write => {
                        let index = worker_write_index(100, 2, worker, writes[worker]).unwrap();
                        writes[worker] += 1;
                        index
                    }
                    _ => u64::MAX,
                };
                operations[worker].push((operation, write_index));
            }
            operations
        }

        let spec = WorkloadSpec::new(
            WorkloadMix {
                read_ratio: 0.5,
                write_ratio: 0.5,
                scan_ratio: 0.0,
            },
            1,
            KeyDistribution::Latest,
            10,
            1.0,
            0.99,
        )
        .unwrap();
        let serial = (0..64)
            .map(|_| 0)
            .chain((0..64).map(|_| 1))
            .collect::<Vec<_>>();
        let interleaved = (0..64).flat_map(|_| [0, 1]).collect::<Vec<_>>();

        assert_eq!(
            run_schedule(&serial, spec),
            run_schedule(&interleaved, spec)
        );
    }

    #[test]
    fn worker_plan_is_replayable_for_same_seed_and_worker() {
        let spec = sample_spec();
        let mut a = WorkerPlan::new(42, 0, spec);
        let mut b = WorkerPlan::new(42, 0, spec);
        let ops_a: Vec<Operation> = (0..32).map(|_| a.next_operation(1_000)).collect();
        let ops_b: Vec<Operation> = (0..32).map(|_| b.next_operation(1_000)).collect();
        assert_eq!(ops_a, ops_b);
    }

    #[test]
    fn same_workload_config_and_seed_replays_logical_operations() {
        let spec = WorkloadSpec::new(
            resolve_mix(Scenario::ScanHeavy, None, None, None).unwrap(),
            32,
            KeyDistribution::Latest,
            1_000,
            0.8,
            0.99,
        )
        .unwrap();
        let first = worker_streams(42, spec, 257, 8, 10_000);
        let second = worker_streams(42, spec, 257, 8, 10_000);
        let different_seed = worker_streams(43, spec, 257, 8, 10_000);

        assert_eq!(first, second);
        assert_ne!(first, different_seed);
    }

    #[test]
    fn worker_plan_differs_across_workers() {
        let spec = sample_spec();
        let mut a = WorkerPlan::new(42, 0, spec);
        let mut b = WorkerPlan::new(42, 1, spec);
        let ops_a: Vec<Operation> = (0..32).map(|_| a.next_operation(1_000)).collect();
        let ops_b: Vec<Operation> = (0..32).map(|_| b.next_operation(1_000)).collect();
        assert_ne!(ops_a, ops_b);
    }
}
