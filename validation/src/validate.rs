//! Exoware deployment validation CLI.
//!
//! This tool verifies end-to-end correctness against a deployed Exoware store:
//! - batched writes
//! - eventual point-read visibility
//! - sampled point lookups
//! - sampled not-found lookups
//! - sampled range query correctness
//!
//! Overlap-ledger appends retry transient failures until the process is
//! interrupted, so a chaos writer survives temporary outages.
//!
//! Example:
//!   cargo run --release -p exoware-validation -- validate \
//!     --url http://localhost:10000 \
//!     --keys 100

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context};
use clap::ValueEnum;
use exoware_sdk::keys::{next_key, Key, MAX_KEY_LEN};
use exoware_sdk::kv_codec::KvReducedValue;
use exoware_sdk::{PrefixedStoreClient, RangeMode};
use exoware_sdk::{RangeReduceOp, RangeReduceRequest, RangeReducerSpec};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{RngExt, SeedableRng};

use crate::client::{
    build_client, is_transient_ingest_error, is_transient_query_error, ClientArgs, ClientConfig,
};
use crate::deterministic::mix64;
use crate::ingest::{ingest_with_retry, retry_delay_for_error, IngestRetryArgs};
use crate::keyspace::{default_run_namespace, Keyspace, KeyspaceArgs};
use crate::ledger::{
    read_overlap_ledger, snapshot_interval, validate_overlap_ledger, OverlapLedgerWriter,
};
use crate::record::Record;
use crate::value::{
    overlap_value_for_index, validate_value_size, value_for_index, DEFAULT_MAX_VALUE_SIZE,
    DEFAULT_VALUE_SIZE,
};

const QUERY_RANGE_MAX_LIMIT: usize = 10_000;

// One streaming multi-get covers this many pending keys, bounding request
// size while replacing per-key round trips during visibility polling.
const VISIBILITY_KEYS_PER_CALL: usize = 1_024;

// Standard validation owns the full write-then-read lifecycle for one run.
// The overlap ledger modes split that lifecycle across processes so a chaos run
// can keep writing during restarts while a verifier checks only confirmed writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ValidateMode {
    Standard,
    OverlapLedgerWrite,
    OverlapLedgerVerify,
}

#[derive(clap::Args, Debug)]
#[command(about = "Exoware end-to-end correctness validator")]
pub struct Args {
    #[arg(long, value_enum, default_value_t = ValidateMode::Standard)]
    mode: ValidateMode,
    #[command(flatten)]
    client: ClientArgs,
    #[arg(long, default_value_t = 100)]
    keys: u64,
    #[arg(long, default_value_t = 25)]
    batch_size: usize,
    #[arg(long, default_value_t = 25)]
    lookup_samples: usize,
    #[arg(long, default_value_t = 10)]
    missing_samples: usize,
    #[arg(long, default_value_t = 10)]
    range_samples: usize,
    #[arg(long, default_value_t = 32)]
    max_range_limit: usize,
    #[arg(long, default_value_t = 30)]
    max_visibility_wait_secs: u64,
    #[arg(long, default_value_t = 250)]
    poll_interval_ms: u64,
    #[arg(long, default_value_t = 7)]
    seed: u64,
    #[arg(long, default_value_t = DEFAULT_VALUE_SIZE)]
    value_size: usize,
    /// Maximum generated value size accepted by this validation run.
    #[arg(long, default_value_t = DEFAULT_MAX_VALUE_SIZE)]
    max_value_size: usize,
    #[command(flatten)]
    ingest_retry: IngestRetryArgs,
    #[command(flatten)]
    keyspace: KeyspaceArgs,
    /// Validate eventual queryability by scanning the full inserted keyspace via
    /// paginated range queries (scales to very large key counts).
    #[arg(long, default_value_t = false)]
    full_range_verify: bool,
    /// Page size for full-range verification mode.
    #[arg(long, default_value_t = QUERY_RANGE_MAX_LIMIT)]
    range_page_size: usize,
    /// Path to the overlap-ledger state file used by overlap modes.
    #[arg(long)]
    ledger_path: Option<String>,
    /// Milliseconds to wait between steady-state overlap ledger writes.
    #[arg(long, default_value_t = 0)]
    overlap_write_interval_ms: u64,
    /// Minimum successful logical writes required before the overlap writer may exit cleanly.
    #[arg(long, default_value_t = 1)]
    overlap_min_writes: u64,
}

#[derive(Debug)]
pub struct Config {
    mode: ValidateMode,
    client: ClientConfig,
    keys: u64,
    batch_size: usize,
    lookup_samples: usize,
    missing_samples: usize,
    range_samples: usize,
    max_range_limit: usize,
    max_visibility_wait_secs: u64,
    poll_interval_ms: u64,
    seed: u64,
    value_size: usize,
    max_value_size: usize,
    ingest_retry: IngestRetryArgs,
    key_len: usize,
    namespace: Option<u64>,
    full_range_verify: bool,
    range_page_size: usize,
    ledger_path: Option<String>,
    overlap_write_interval_ms: u64,
    overlap_min_writes: u64,
}

impl TryFrom<Args> for Config {
    type Error = anyhow::Error;

    fn try_from(args: Args) -> anyhow::Result<Self> {
        let config = Self {
            mode: args.mode,
            client: args.client.into_config()?,
            keys: args.keys,
            batch_size: args.batch_size,
            lookup_samples: args.lookup_samples,
            missing_samples: args.missing_samples,
            range_samples: args.range_samples,
            max_range_limit: args.max_range_limit,
            max_visibility_wait_secs: args.max_visibility_wait_secs,
            poll_interval_ms: args.poll_interval_ms,
            seed: args.seed,
            value_size: args.value_size,
            max_value_size: args.max_value_size,
            ingest_retry: args.ingest_retry,
            key_len: args.keyspace.key_len,
            namespace: args.keyspace.namespace,
            full_range_verify: args.full_range_verify,
            range_page_size: args.range_page_size,
            ledger_path: args.ledger_path,
            overlap_write_interval_ms: args.overlap_write_interval_ms,
            overlap_min_writes: args.overlap_min_writes,
        };
        validate_config(&config)?;
        Ok(config)
    }
}

#[derive(Clone, Copy, Debug)]
struct RangePlan {
    start_idx: usize,
    end_idx: usize,
    page_size: usize,
}

#[derive(Debug)]
enum RangeScanError {
    /// Transient failures (network/409/503/etc) that may self-resolve on retry.
    Transient(anyhow::Error),
    /// Permanent correctness failures that should fail fast.
    Permanent(anyhow::Error),
}

/// Shared query-consistency settings for one bounded validation check.
struct ValidationCtx<'a> {
    client: &'a PrefixedStoreClient,
    query_url: &'a str,
    min_sequence_number: u64,
    deadline: Instant,
    poll_interval: Duration,
}

impl<'a> ValidationCtx<'a> {
    fn new(
        client: &'a PrefixedStoreClient,
        query_url: &'a str,
        min_sequence_number: u64,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Self {
        Self {
            client,
            query_url,
            min_sequence_number,
            deadline: Instant::now() + timeout,
            poll_interval,
        }
    }
}

enum PollOutcome<T> {
    Complete(T),
    Pending(String),
    Permanent(anyhow::Error),
}

/// Runs one eventual-consistency check until it completes, becomes permanent, or times out.
async fn poll_until<T, F, Fut>(
    ctx: &ValidationCtx<'_>,
    label: &str,
    mut operation: F,
) -> anyhow::Result<T>
where
    F: FnMut(u64) -> Fut,
    Fut: Future<Output = PollOutcome<T>>,
{
    let mut attempt = 0u64;
    let mut last_detail = "validation has not run yet".to_string();

    loop {
        if Instant::now() >= ctx.deadline {
            bail!(
                "{label} timeout on query {} after {attempt} attempts: {last_detail}",
                ctx.query_url
            );
        }

        attempt = attempt.saturating_add(1);
        match operation(attempt).await {
            PollOutcome::Complete(value) => return Ok(value),
            PollOutcome::Permanent(err) => return Err(err),
            PollOutcome::Pending(detail) => last_detail = detail,
        }

        if Instant::now() >= ctx.deadline {
            bail!(
                "{label} timeout on query {} after {attempt} attempts: {last_detail}",
                ctx.query_url
            );
        }

        tracing::info!(
            query_url = %ctx.query_url,
            validation = label,
            attempts = attempt,
            detail = %last_detail,
            "Validation retry"
        );
        tokio::time::sleep(ctx.poll_interval).await;
    }
}

fn range_scan_deadline_error(
    pages_scanned: u64,
    matched_rows: u64,
    expected_rows: u64,
    foreign_rows: u64,
    boundary: &Key,
) -> RangeScanError {
    RangeScanError::Permanent(anyhow!(
        "range scan deadline exceeded after {pages_scanned} pages: matched {matched_rows} of {expected_rows} expected rows, skipped {foreign_rows} foreign rows, next boundary {}",
        hex::encode(boundary)
    ))
}

/// Largest key strictly less than `key`: the reverse-pagination mirror of
/// [`next_key`]. Only the empty key has no predecessor.
fn prev_key(key: &Key) -> Option<Key> {
    let (&last, head) = key.as_ref().split_last()?;

    // A trailing 0x00 has an immediate predecessor in its own prefix; any other
    // last byte decrements and pads to the maximum key length with 0xFF.
    let mut prev = head.to_vec();
    if last != 0 {
        prev.push(last - 1);
        prev.resize(MAX_KEY_LEN, u8::MAX);
    }
    Some(Key::from(prev))
}

/// Pages through the inclusive window `[lo, hi]` in `mode` order and checks that
/// the rows selected by `is_own` are exactly `expected`, already in traversal
/// order.
///
/// Other data may lie inside a window on a shared store; rows this check does
/// not own are skipped rather than failing the match.
async fn scan_window_for_expected(
    ctx: &ValidationCtx<'_>,
    lo: &Key,
    hi: &Key,
    mode: RangeMode,
    page_size: usize,
    expected: &[&Record],
    is_own: impl Fn(&Key) -> bool,
) -> Result<(), RangeScanError> {
    let mut window_lo = lo.clone();
    let mut window_hi = hi.clone();
    let mut matched = 0usize;
    let mut pages_scanned = 0u64;
    let mut foreign_rows = 0u64;

    loop {
        let boundary = match mode {
            RangeMode::Forward => &window_lo,
            RangeMode::Reverse => &window_hi,
        };
        let remaining = ctx.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(range_scan_deadline_error(
                pages_scanned,
                matched as u64,
                expected.len() as u64,
                foreign_rows,
                boundary,
            ));
        }

        let query = ctx.client.query();
        let rows = match tokio::time::timeout(
            remaining,
            query.range_with_mode_and_min_sequence_number(
                &window_lo,
                &window_hi,
                page_size,
                mode,
                ctx.min_sequence_number,
            ),
        )
        .await
        {
            Ok(Ok(rows)) => rows,
            Ok(Err(err)) if is_transient_query_error(&err) => {
                return Err(RangeScanError::Transient(anyhow!(err)));
            }
            Ok(Err(err)) => return Err(RangeScanError::Permanent(anyhow!(err))),
            Err(_) => {
                return Err(range_scan_deadline_error(
                    pages_scanned,
                    matched as u64,
                    expected.len() as u64,
                    foreign_rows,
                    boundary,
                ));
            }
        };
        pages_scanned += 1;

        // Ordering must hold for every returned row, foreign rows included, and
        // equality in either direction means a duplicated key.
        let unsorted = match mode {
            RangeMode::Forward => rows.windows(2).any(|pair| pair[0].0 >= pair[1].0),
            RangeMode::Reverse => rows.windows(2).any(|pair| pair[0].0 <= pair[1].0),
        };
        if unsorted {
            return Err(RangeScanError::Permanent(anyhow!(
                "{mode:?} range page returned unsorted or duplicated keys"
            )));
        }

        for (key, value) in &rows {
            if !is_own(key) {
                foreign_rows += 1;
                continue;
            }
            let Some(record) = expected.get(matched) else {
                return Err(RangeScanError::Permanent(anyhow!(
                    "row mismatch: own key {} appeared after all {} expected rows matched",
                    hex::encode(key),
                    expected.len()
                )));
            };
            if *key != record.key {
                return Err(RangeScanError::Permanent(anyhow!(
                    "row mismatch at position {matched}: expected key {}, got {}",
                    hex::encode(&record.key),
                    hex::encode(key)
                )));
            }
            if value.as_ref() != record.value.as_slice() {
                return Err(RangeScanError::Permanent(anyhow!(
                    "value mismatch for key {}",
                    hex::encode(key)
                )));
            }
            matched += 1;
        }

        if matched >= expected.len() {
            return Ok(());
        }

        if rows.len() < page_size {
            return Err(RangeScanError::Permanent(anyhow!(
                "range window exhausted with {matched} of {} expected rows visible at sequence floor {}",
                expected.len(),
                ctx.min_sequence_number
            )));
        }

        // Advance past this page's extreme row; the page is non-empty because a
        // short page (including an empty one) returned above.
        let boundary = &rows.last().expect("page checked non-empty").0;
        let advanced = match mode {
            RangeMode::Forward => next_key(boundary).map(|next| window_lo = next),
            RangeMode::Reverse => prev_key(boundary).map(|prev| window_hi = prev),
        };
        if advanced.is_none() {
            return Err(RangeScanError::Permanent(anyhow!(
                "reached the edge of the key domain with {matched} of {} expected rows visible at sequence floor {}",
                expected.len(),
                ctx.min_sequence_number
            )));
        }
    }
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    let cli = Config::try_from(args)?;

    let client = build_client(&cli.client)?;

    let timeout = Duration::from_secs(cli.max_visibility_wait_secs);
    let poll_interval = Duration::from_millis(cli.poll_interval_ms);
    match cli.mode {
        ValidateMode::Standard => {
            run_standard_validation(&cli, &client, cli.client.endpoint(), timeout, poll_interval)
                .await
        }
        ValidateMode::OverlapLedgerWrite => {
            let namespace = cli
                .namespace
                .unwrap_or_else(|| default_run_namespace(cli.seed));
            run_overlap_ledger_write_mode(&cli, &client, cli.client.endpoint(), namespace).await
        }
        ValidateMode::OverlapLedgerVerify => {
            run_overlap_ledger_verify_mode(
                &cli,
                &client,
                cli.client.endpoint(),
                timeout,
                poll_interval,
            )
            .await
        }
    }
}

async fn run_standard_validation(
    cli: &Config,
    client: &PrefixedStoreClient,
    url: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> anyhow::Result<()> {
    let namespace = cli
        .namespace
        .unwrap_or_else(|| default_run_namespace(cli.seed));
    let keyspace = Keyspace::validation_from_u64_namespace(namespace, cli.key_len)?;
    let mut rng = StdRng::seed_from_u64(cli.seed ^ namespace.rotate_left(7));

    tracing::info!(
        url = %url,
        mode = "standard",
        keys = cli.keys,
        value_size = cli.value_size,
        max_value_size = cli.max_value_size,
        read_retry_attempts = cli.client.read_retry_attempts(),
        namespace,
        "Starting Exoware validation"
    );

    if cli.full_range_verify {
        let min_sequence_number = run_write_phase(
            client,
            cli.keys,
            cli.batch_size,
            namespace,
            &cli.ingest_retry,
            |index| {
                Ok(Record {
                    key: keyspace.inserted_key(index),
                    value: value_for_index(namespace, index, cli.value_size),
                })
            },
        )
        .await?;
        tracing::info!(
            query_url = %url,
            page_size = cli.range_page_size,
            "Validating full queryability with paginated range scan"
        );
        let ctx = ValidationCtx::new(client, url, min_sequence_number, timeout, poll_interval);
        wait_for_all_visible_via_range(
            &ctx,
            &keyspace,
            namespace,
            cli.keys,
            cli.value_size,
            cli.range_page_size,
        )
        .await?;
        tracing::info!(
            inserted_keys = cli.keys,
            mode = "full-range-verify",
            "Validation completed successfully"
        );
        return Ok(());
    }

    let records = build_records(&keyspace, cli.keys, |index| {
        value_for_index(namespace, index, cli.value_size)
    })?;
    // A sorted view over borrowed records; cloning the dataset for ordering
    // would double resident memory for the whole run.
    let mut sorted_records: Vec<&Record> = records.iter().collect();
    sorted_records.sort_by(|a, b| a.key.cmp(&b.key));

    let point_indices = sample_unique_indices(records.len(), cli.lookup_samples, &mut rng);
    let missing_indices = sample_missing_indices(cli.missing_samples, &mut rng);
    let range_plans = build_range_plans(
        sorted_records.len(),
        cli.range_samples,
        cli.max_range_limit,
        &mut rng,
    );

    let min_sequence_number = run_write_phase(
        client,
        u64::try_from(records.len()).context("record count does not fit in u64")?,
        cli.batch_size,
        namespace,
        &cli.ingest_retry,
        record_at(&records),
    )
    .await?;
    tracing::info!(query_url = %url, "Validating query endpoint");
    // Each validation phase polls against its own fresh deadline.
    let ctx = || ValidationCtx::new(client, url, min_sequence_number, timeout, poll_interval);
    wait_for_all_visible(&ctx(), &records).await?;
    run_point_samples(&ctx(), &records, &point_indices).await?;
    run_missing_samples(&ctx(), &keyspace, &missing_indices).await?;
    run_range_samples(&ctx(), &sorted_records, &range_plans).await?;

    tracing::info!(
        inserted_keys = records.len(),
        point_samples = point_indices.len(),
        missing_samples = missing_indices.len(),
        range_samples = range_plans.len(),
        "Validation completed successfully"
    );

    Ok(())
}

async fn run_overlap_ledger_write_mode(
    cli: &Config,
    client: &PrefixedStoreClient,
    url: &str,
    namespace: u64,
) -> anyhow::Result<()> {
    let ledger_path = cli
        .ledger_path
        .as_deref()
        .context("--ledger-path is required for overlap-ledger-write mode")?;
    tracing::info!(
        url = %url,
        mode = "overlap-ledger-write",
        namespace,
        hot_keys = cli.keys,
        ledger_path,
        "Starting overlap ledger writer"
    );
    let keyspace = Keyspace::validation_from_u64_namespace(namespace, cli.key_len)?;
    let mut records = build_records(&keyspace, cli.keys, |index| {
        overlap_value_for_index(namespace, index)
    })?;
    let mut sequence_number = run_write_phase(
        client,
        u64::try_from(records.len()).context("record count does not fit in u64")?,
        cli.batch_size,
        namespace,
        &cli.ingest_retry,
        record_at(&records),
    )
    .await?;

    let mut successful_writes = records.len() as u64;
    let mut ledger_writer = OverlapLedgerWriter::new(ledger_path);
    ledger_writer.checkpoint(namespace, successful_writes, sequence_number, &records)?;

    let mut next_index = records.len() as u64;
    let shutdown = overlap_shutdown_signal();
    tokio::pin!(shutdown);
    let write_interval = Duration::from_millis(cli.overlap_write_interval_ms);
    let mut writes_since_checkpoint = 0u64;

    // The initial fixture is bounded so setup failures surface promptly; the steady-state writer
    // stays alive through transient outages until it is explicitly stopped.
    'writer: loop {
        let record = Record {
            key: keyspace.inserted_key(next_index),
            value: overlap_value_for_index(namespace, next_index),
        };
        let label = format!("overlap-ledger append index {}", next_index);
        let mut attempt = 0u64;
        loop {
            let refs = [(&record.key, record.value.as_slice())];
            let ingest = client.ingest();
            let ingest_future = ingest.put(&refs);
            tokio::pin!(ingest_future);
            let put_result = tokio::select! {
                _ = &mut shutdown => break 'writer,
                result = &mut ingest_future => result,
            };
            match put_result {
                Ok(token) => {
                    sequence_number = token;
                    break;
                }
                Err(err) if is_transient_ingest_error(&err) => {
                    attempt = attempt.saturating_add(1);
                    tracing::warn!(
                        label,
                        attempt,
                        code = ?err.rpc_code(),
                        error = %err,
                        "transient ingest failure during overlap-ledger append; retrying"
                    );
                    let sleep = tokio::time::sleep(retry_delay_for_error(
                        &err,
                        cli.ingest_retry.backoff(),
                        attempt,
                    ));
                    tokio::pin!(sleep);
                    tokio::select! {
                        _ = &mut shutdown => break 'writer,
                        _ = &mut sleep => {}
                    }
                }
                Err(err) => {
                    return Err(anyhow!("ingest failed for {label}: {err}"));
                }
            }
        }

        successful_writes = successful_writes.saturating_add(1);
        ledger_writer.append(successful_writes, sequence_number, &record)?;
        records.push(record);
        writes_since_checkpoint = writes_since_checkpoint.saturating_add(1);
        if writes_since_checkpoint >= snapshot_interval(records.len()) {
            ledger_writer.checkpoint(namespace, successful_writes, sequence_number, &records)?;
            writes_since_checkpoint = 0;
        }
        next_index = next_index.saturating_add(1);

        if !write_interval.is_zero() {
            let sleep = tokio::time::sleep(write_interval);
            tokio::pin!(sleep);
            tokio::select! {
                _ = &mut shutdown => break 'writer,
                _ = &mut sleep => {}
            }
        }
    }

    ledger_writer.checkpoint(namespace, successful_writes, sequence_number, &records)?;
    ensure!(
        successful_writes >= cli.overlap_min_writes,
        "overlap-ledger writer recorded only {} logical writes (minimum required: {})",
        successful_writes,
        cli.overlap_min_writes
    );
    tracing::info!(
        namespace,
        successful_writes,
        ledger_path,
        "Overlap ledger writer completed successfully"
    );
    Ok(())
}

async fn run_overlap_ledger_verify_mode(
    cli: &Config,
    client: &PrefixedStoreClient,
    url: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> anyhow::Result<()> {
    let ledger_path = cli
        .ledger_path
        .as_deref()
        .context("--ledger-path is required for overlap-ledger-verify mode")?;
    let ledger = read_overlap_ledger(ledger_path)?;
    validate_overlap_ledger(&ledger)?;
    tracing::info!(
        url = %url,
        mode = "overlap-ledger-verify",
        namespace = ledger.namespace,
        expected_keys = ledger.records.len(),
        successful_writes = ledger.successful_writes,
        sequence_number = ledger.sequence_number,
        ledger_path,
        "Starting overlap ledger verification"
    );
    let mut sorted_records: Vec<&Record> = ledger.records.iter().collect();
    sorted_records.sort_by(|a, b| a.key.cmp(&b.key));
    // Each verification phase polls against its own fresh deadline.
    let ctx = || ValidationCtx::new(client, url, ledger.sequence_number, timeout, poll_interval);
    wait_for_all_visible(&ctx(), &ledger.records).await?;
    wait_for_exact_range_match(
        &ctx(),
        &sorted_records,
        RangeMode::Forward,
        cli.range_page_size,
    )
    .await?;
    wait_for_exact_range_match(
        &ctx(),
        &sorted_records,
        RangeMode::Reverse,
        cli.range_page_size,
    )
    .await?;
    wait_for_reduce_count_match(&ctx(), &sorted_records).await?;
    tracing::info!(
        namespace = ledger.namespace,
        expected_keys = sorted_records.len(),
        successful_writes = ledger.successful_writes,
        "Overlap ledger verification completed successfully"
    );
    Ok(())
}

fn validate_config(cli: &Config) -> anyhow::Result<()> {
    ensure!(cli.keys > 0, "--keys must be > 0");
    ensure!(cli.batch_size > 0, "--batch-size must be > 0");
    ensure!(
        cli.max_visibility_wait_secs > 0,
        "--max-visibility-wait-secs must be > 0"
    );
    ensure!(cli.poll_interval_ms > 0, "--poll-interval-ms must be > 0");
    ensure!(cli.max_range_limit > 0, "--max-range-limit must be > 0");
    cli.ingest_retry.validate()?;
    validate_value_size(cli.value_size, cli.max_value_size)?;
    ensure!(cli.range_page_size > 0, "--range-page-size must be > 0");
    ensure!(
        cli.range_page_size <= QUERY_RANGE_MAX_LIMIT,
        "--range-page-size must be <= {}",
        QUERY_RANGE_MAX_LIMIT
    );
    Keyspace::validation_from_u64_namespace(cli.namespace.unwrap_or(0), cli.key_len)?;
    match cli.mode {
        ValidateMode::Standard => {
            ensure!(
                cli.ledger_path.is_none(),
                "--ledger-path is only valid with overlap-ledger modes"
            );
        }
        ValidateMode::OverlapLedgerWrite | ValidateMode::OverlapLedgerVerify => {
            ensure!(
                cli.ledger_path.is_some(),
                "--ledger-path is required with overlap-ledger modes"
            );
            ensure!(
                cli.namespace.is_some() || cli.mode == ValidateMode::OverlapLedgerVerify,
                "--namespace is required for overlap-ledger-write mode"
            );
            ensure!(
                !cli.full_range_verify,
                "--full-range-verify is only supported in standard mode"
            );
        }
    }
    Ok(())
}

fn build_records(
    keyspace: &Keyspace,
    keys: u64,
    value_for: impl Fn(u64) -> Vec<u8>,
) -> anyhow::Result<Vec<Record>> {
    let key_count = usize::try_from(keys).context("--keys does not fit into usize")?;
    let mut records = Vec::with_capacity(key_count);
    for i in 0..keys {
        records.push(Record {
            key: keyspace.inserted_key(i),
            value: value_for(i),
        });
    }
    Ok(records)
}

/// Materializes write batches from a pre-built fixture for [`run_write_phase`].
fn record_at(records: &[Record]) -> impl FnMut(u64) -> anyhow::Result<Record> + '_ {
    move |index| {
        records
            .get(usize::try_from(index).context("record index does not fit in usize")?)
            .cloned()
            .context("write phase generated an out-of-bounds record index")
    }
}

async fn wait_for_exact_range_match(
    ctx: &ValidationCtx<'_>,
    expected_records: &[&Record],
    mode: RangeMode,
    page_size: usize,
) -> anyhow::Result<()> {
    let first = expected_records
        .first()
        .context("expected_records must not be empty for exact range match")?;
    let last = expected_records
        .last()
        .context("expected_records must not be empty for exact range match")?;
    // Reverse scans return rows highest-key-first, so compare against the reversed expectation.
    let expected_order = match mode {
        RangeMode::Forward => expected_records.to_vec(),
        RangeMode::Reverse => expected_records.iter().rev().copied().collect::<Vec<_>>(),
    };

    // Only rows carrying confirmed ledger keys participate in the match: the
    // window interleaves other namespaces' rows on a shared store, plus this
    // writer's final append when it landed without an acknowledgment before
    // shutdown.
    let own_keys = expected_records
        .iter()
        .map(|record| record.key.clone())
        .collect::<HashSet<Key>>();
    let label = format!("exact {mode:?} overlap-ledger range match");
    poll_until(ctx, &label, |attempt| {
        let expected_order = &expected_order;
        let own_keys = &own_keys;
        async move {
            match scan_window_for_expected(
                ctx,
                &first.key,
                &last.key,
                mode,
                page_size,
                expected_order,
                |key| own_keys.contains(key),
            )
            .await
            {
                Ok(()) => {
                    tracing::info!(
                        query_url = %ctx.query_url,
                        mode = ?mode,
                        attempts = attempt,
                        rows = expected_order.len(),
                        "Exact overlap-ledger range match succeeded"
                    );
                    PollOutcome::Complete(())
                }
                Err(RangeScanError::Transient(err)) => {
                    PollOutcome::Pending(format!("{mode:?} transient range error: {err}"))
                }
                Err(RangeScanError::Permanent(err)) => {
                    PollOutcome::Permanent(err.context(format!(
                        "exact {mode:?} overlap-ledger range query failed against {}",
                        ctx.query_url
                    )))
                }
            }
        }
    })
    .await
}

async fn wait_for_reduce_count_match(
    ctx: &ValidationCtx<'_>,
    expected_records: &[&Record],
) -> anyhow::Result<()> {
    let first = expected_records
        .first()
        .context("expected_records must not be empty for range reduction match")?;
    let last = expected_records
        .last()
        .context("expected_records must not be empty for range reduction match")?;
    let request = RangeReduceRequest {
        reducers: vec![RangeReducerSpec {
            op: RangeReduceOp::CountAll,
            expr: None,
        }],
        group_by: Vec::new(),
        filter: None,
    };
    let expected_count = expected_records.len() as u64;

    poll_until(ctx, "range reduce", |attempt| {
        let request = &request;
        async move {
            match ctx
            .client
            .query()
            .range_reduce_with_min_sequence_number(
                &first.key,
                &last.key,
                request,
                ctx.min_sequence_number,
            )
            .await
        {
            Ok(values) => {
                let actual = match values.as_slice() {
                    [Some(KvReducedValue::UInt64(v))] => *v,
                    [Some(KvReducedValue::Int64(v))] if *v >= 0 => *v as u64,
                    other => {
                        return PollOutcome::Permanent(anyhow!(
                            "unexpected range reduce count response on {}: {:?}",
                            ctx.query_url,
                            other
                        ));
                    }
                };
                if actual >= expected_count {
                    tracing::info!(
                        query_url = %ctx.query_url,
                        attempts = attempt,
                        actual_count = actual,
                        expected_count,
                        "Range reduction reached expected distinct-key floor"
                    );
                    PollOutcome::Complete(())
                } else {
                    PollOutcome::Permanent(anyhow!(
                        "confirmed range reduce count on {} returned {}, expected at least {} at sequence floor {}",
                        ctx.query_url,
                        actual,
                        expected_count,
                        ctx.min_sequence_number
                    ))
                }
            }
            Err(err) if is_transient_query_error(&err) => {
                PollOutcome::Pending(format!("range reduce transient failure: {err}"))
            }
            Err(err) => PollOutcome::Permanent(anyhow!(err).context(format!(
                "range reduction verification failed against {}",
                ctx.query_url
            ))),
            }
        }
    })
    .await
}

async fn overlap_shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for ctrl_c");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to listen for SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn run_write_phase(
    client: &PrefixedStoreClient,
    total_keys: u64,
    batch_size: usize,
    namespace: u64,
    ingest_retry: &IngestRetryArgs,
    mut materialize: impl FnMut(u64) -> anyhow::Result<Record>,
) -> anyhow::Result<u64> {
    tracing::info!(
        keys = total_keys,
        batch_size,
        namespace,
        "Starting write phase"
    );
    let batch_size = u64::try_from(batch_size).context("batch size does not fit in u64")?;
    let mut chunk_idx = 0u64;
    let mut start_idx = 0u64;
    let mut last_sequence_number = 0u64;
    while start_idx < total_keys {
        let end_idx = start_idx.saturating_add(batch_size).min(total_keys);
        let mut records = Vec::with_capacity(
            usize::try_from(end_idx - start_idx).context("write batch does not fit in usize")?,
        );
        for index in start_idx..end_idx {
            records.push(materialize(index)?);
        }
        last_sequence_number = ingest_with_retry(
            client,
            &records,
            ingest_retry.attempts,
            ingest_retry.backoff(),
            &format!("batch index {chunk_idx}"),
        )
        .await?
        .sequence_number;
        chunk_idx = chunk_idx.saturating_add(1);
        start_idx = end_idx;
    }
    tracing::info!("Write phase complete");
    Ok(last_sequence_number)
}

/// Record indexes a visibility batch could not resolve, plus the transient
/// error that left them unresolved.
struct PendingVisibility {
    indices: Vec<usize>,
    error: Option<String>,
}

/// Checks one batch of records with a single streaming multi-get.
///
/// A miss or value mismatch at the sequence floor is a permanent failure;
/// transient query errors leave the batch's unresolved keys pending.
async fn check_batch_visibility(
    ctx: &ValidationCtx<'_>,
    records: &[Record],
    batch: &[usize],
) -> Result<PendingVisibility, PollOutcome<()>> {
    let mut by_key: HashMap<&Key, usize> =
        batch.iter().map(|&idx| (&records[idx].key, idx)).collect();
    let keys: Vec<&Key> = batch.iter().map(|&idx| &records[idx].key).collect();
    let batch_size = u32::try_from(keys.len()).unwrap_or(u32::MAX);
    let permanent = |err: anyhow::Error| {
        PollOutcome::Permanent(err.context(format!(
            "point-read visibility query failed against {}",
            ctx.query_url
        )))
    };

    let mut stream = match ctx
        .client
        .query()
        .get_many_with_min_sequence_number(&keys, batch_size, ctx.min_sequence_number)
        .await
    {
        Ok(stream) => stream,
        Err(err) if is_transient_query_error(&err) => {
            return Ok(PendingVisibility {
                indices: by_key.into_values().collect(),
                error: Some(err.to_string()),
            });
        }
        Err(err) => return Err(permanent(anyhow!(err))),
    };
    loop {
        match stream.next_chunk().await {
            Ok(Some(chunk)) => {
                for (key, value) in chunk.entries {
                    let Some(idx) = by_key.remove(&key) else {
                        continue;
                    };
                    let record = &records[idx];
                    match value {
                        Some(value) => {
                            if value.as_ref() != record.value.as_slice() {
                                return Err(PollOutcome::Permanent(anyhow!(
                                    "value mismatch for key {} on query {}",
                                    hex::encode(&record.key),
                                    ctx.query_url
                                )));
                            }
                        }
                        None => {
                            return Err(PollOutcome::Permanent(anyhow!(
                                "confirmed key {} was missing on query {} at sequence floor {}",
                                hex::encode(&record.key),
                                ctx.query_url,
                                ctx.min_sequence_number
                            )));
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(err) if is_transient_query_error(&err) => {
                return Ok(PendingVisibility {
                    indices: by_key.into_values().collect(),
                    error: Some(err.to_string()),
                });
            }
            Err(err) => return Err(permanent(anyhow!(err))),
        }
    }
    // Keys the stream never reported stay pending for the next poll attempt.
    Ok(PendingVisibility {
        indices: by_key.into_values().collect(),
        error: None,
    })
}

async fn wait_for_all_visible(ctx: &ValidationCtx<'_>, records: &[Record]) -> anyhow::Result<()> {
    tracing::info!(
        query_url = %ctx.query_url,
        total_keys = records.len(),
        "Waiting for full point-read visibility"
    );
    let pending = Mutex::new((0..records.len()).collect::<Vec<_>>());

    poll_until(ctx, "point-read visibility", |attempt| {
        let pending = &pending;
        async move {
            let current_pending =
                std::mem::take(&mut *pending.lock().expect("visibility pending lock"));
            let mut remaining = Vec::new();
            let mut last_error: Option<String> = None;
            for batch in current_pending.chunks(VISIBILITY_KEYS_PER_CALL) {
                match check_batch_visibility(ctx, records, batch).await {
                    Ok(unresolved) => {
                        remaining.extend(unresolved.indices);
                        if unresolved.error.is_some() {
                            last_error = unresolved.error;
                        }
                    }
                    Err(outcome) => return outcome,
                }
            }
            if remaining.is_empty() {
                tracing::info!(
                    query_url = %ctx.query_url,
                    attempts = attempt,
                    "All keys visible and correct"
                );
                return PollOutcome::Complete(());
            }
            let sample = remaining
                .iter()
                .take(5)
                .map(|idx| hex::encode(&records[*idx].key))
                .collect::<Vec<_>>()
                .join(", ");
            let last_error_msg = last_error
                .as_deref()
                .unwrap_or("no lookup errors captured; keys remained missing");
            let pending_count = remaining.len();
            *pending.lock().expect("visibility pending lock") = remaining;
            PollOutcome::Pending(format!(
                "{pending_count} keys still missing; sample missing keys: [{sample}]; last error: {last_error_msg}"
            ))
        }
    })
    .await
}

async fn wait_for_all_visible_via_range(
    ctx: &ValidationCtx<'_>,
    keyspace: &Keyspace,
    namespace: u64,
    total_keys: u64,
    value_size: usize,
    page_size: usize,
) -> anyhow::Result<()> {
    tracing::info!(
        query_url = %ctx.query_url,
        total_keys,
        page_size,
        "Waiting for full range visibility"
    );
    poll_until(ctx, "full-range visibility", |attempt| async move {
        match scan_visible_prefix_via_range(
            ctx, keyspace, namespace, total_keys, value_size, page_size,
        )
        .await
        {
            Ok(pages_scanned) => {
                tracing::info!(
                    query_url = %ctx.query_url,
                    attempts = attempt,
                    pages_scanned,
                    total_keys,
                    "All keys visible and correct via full-range verification"
                );
                PollOutcome::Complete(())
            }
            Err(RangeScanError::Transient(err)) => {
                PollOutcome::Pending(format!("range scan transient failure: {err}"))
            }
            Err(RangeScanError::Permanent(err)) => PollOutcome::Permanent(err),
        }
    })
    .await
}

/// Scans the validator-owned range once, returning the pages scanned when
/// every inserted key is visible and correct; any shortfall is an error.
async fn scan_visible_prefix_via_range(
    ctx: &ValidationCtx<'_>,
    keyspace: &Keyspace,
    namespace: u64,
    total_keys: u64,
    value_size: usize,
    page_size: usize,
) -> Result<u64, RangeScanError> {
    if total_keys == 0 {
        return Ok(0);
    }

    let mut next_start = keyspace.inserted_key(0);
    let end = keyspace.inserted_key(total_keys - 1);
    // Validation keys are contiguous and ordered by their logical index, so
    // this scan stays within the validator-owned physical range.
    let mut expected_order = (0..total_keys).peekable();
    let mut visible = 0u64;
    let mut pages_scanned = 0u64;
    let mut foreign_rows = 0u64;
    let mut previous_key: Option<Key> = None;

    loop {
        let remaining = ctx.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(range_scan_deadline_error(
                pages_scanned,
                visible,
                total_keys,
                foreign_rows,
                &next_start,
            ));
        }

        let query = ctx.client.query();
        let rows = match tokio::time::timeout(
            remaining,
            query.range_with_min_sequence_number(
                &next_start,
                &end,
                page_size,
                ctx.min_sequence_number,
            ),
        )
        .await
        {
            Ok(Ok(rows)) => rows,
            Ok(Err(err)) if is_transient_query_error(&err) => {
                return Err(RangeScanError::Transient(anyhow!(err)));
            }
            Ok(Err(err)) => return Err(RangeScanError::Permanent(anyhow!(err))),
            Err(_) => {
                return Err(range_scan_deadline_error(
                    pages_scanned,
                    visible,
                    total_keys,
                    foreign_rows,
                    &next_start,
                ));
            }
        };
        pages_scanned += 1;

        if let Some(previous_key) = &previous_key {
            if rows
                .first()
                .is_some_and(|(first_key, _)| first_key <= previous_key)
            {
                return Err(RangeScanError::Permanent(anyhow!(
                    "range page repeated or reordered a key after {}",
                    hex::encode(previous_key)
                )));
            }
        }
        if rows.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(RangeScanError::Permanent(anyhow!(
                "range page returned unsorted or duplicated keys"
            )));
        }

        for (actual_key, actual_value) in &rows {
            let Some(index) = keyspace.inserted_index_of(actual_key) else {
                foreign_rows += 1;
                continue;
            };
            if index >= total_keys {
                continue;
            }
            let expected_index = expected_order.peek().copied().ok_or_else(|| {
                RangeScanError::Permanent(anyhow!(
                    "range returned an unexpected own key {} after all expected keys",
                    hex::encode(actual_key)
                ))
            })?;
            if index != expected_index {
                let expected_key = keyspace.inserted_key(expected_index);
                return Err(RangeScanError::Permanent(anyhow!(
                    "expected sorted key {} (index {}) before own row {} (index {})",
                    hex::encode(&expected_key),
                    expected_index,
                    hex::encode(actual_key),
                    index
                )));
            }
            let expected_value = value_for_index(namespace, index, value_size);
            if actual_value.as_ref() != expected_value.as_slice() {
                return Err(RangeScanError::Permanent(anyhow!(
                    "value mismatch at index {} for key {}",
                    index,
                    hex::encode(actual_key)
                )));
            }
            expected_order.next();
            visible += 1;
        }

        previous_key = rows.last().map(|(key, _)| key.clone());

        if visible >= total_keys {
            return Ok(pages_scanned);
        }

        if rows.len() < page_size {
            return Err(RangeScanError::Permanent(anyhow!(
                "range window exhausted with {} of {} sorted keys visible at sequence floor {}",
                visible,
                total_keys,
                ctx.min_sequence_number
            )));
        }

        let boundary = &rows.last().expect("page checked non-empty").0;
        let Some(advanced) = next_key(boundary) else {
            return Err(RangeScanError::Permanent(anyhow!(
                "reached the maximum possible key with {} of {} sorted keys visible at sequence floor {}",
                visible,
                total_keys,
                ctx.min_sequence_number
            )));
        };
        next_start = advanced;
    }
}

async fn run_point_samples(
    ctx: &ValidationCtx<'_>,
    records: &[Record],
    point_indices: &[usize],
) -> anyhow::Result<()> {
    tracing::info!(
        query_url = %ctx.query_url,
        samples = point_indices.len(),
        "Running point lookup samples"
    );
    for idx in point_indices {
        let record = &records[*idx];
        let label = format!("point lookup sample {}", hex::encode(&record.key));
        poll_until(ctx, &label, |_| async {
            match ctx
                .client
                .query()
                .get_with_min_sequence_number(&record.key, ctx.min_sequence_number)
                .await
            {
                Ok(Some(value)) => {
                    if value.as_ref() != record.value.as_slice() {
                        PollOutcome::Permanent(anyhow!(
                            "point lookup mismatch for key {} on {}",
                            hex::encode(&record.key),
                            ctx.query_url
                        ))
                    } else {
                        PollOutcome::Complete(())
                    }
                }
                Ok(None) => PollOutcome::Permanent(anyhow!(
                    "point lookup returned not found for inserted key {} on {}",
                    hex::encode(&record.key),
                    ctx.query_url
                )),
                Err(err) if is_transient_query_error(&err) => {
                    PollOutcome::Pending(format!("point lookup transient failure: {err}"))
                }
                Err(err) => PollOutcome::Permanent(anyhow!(err).context(format!(
                    "point lookup request failed for key {} on {}",
                    hex::encode(&record.key),
                    ctx.query_url
                ))),
            }
        })
        .await?;
    }
    Ok(())
}

async fn run_missing_samples(
    ctx: &ValidationCtx<'_>,
    keyspace: &Keyspace,
    missing_indices: &[u64],
) -> anyhow::Result<()> {
    tracing::info!(
        query_url = %ctx.query_url,
        samples = missing_indices.len(),
        "Running missing-key lookup samples"
    );
    for idx in missing_indices {
        let key = keyspace.missing_key(*idx);
        let label = format!("missing-key lookup sample {}", hex::encode(&key));
        poll_until(ctx, &label, |_| {
            let key = &key;
            async move {
                match ctx
                    .client
                    .query()
                    .get_with_min_sequence_number(key, ctx.min_sequence_number)
                    .await
                {
                    Ok(result) => {
                        if result.is_some() {
                            PollOutcome::Permanent(anyhow!(
                                "expected key {} to be missing on {}, but lookup returned a value",
                                hex::encode(key),
                                ctx.query_url
                            ))
                        } else {
                            PollOutcome::Complete(())
                        }
                    }
                    Err(err) if is_transient_query_error(&err) => {
                        PollOutcome::Pending(format!("missing-key lookup transient failure: {err}"))
                    }
                    Err(err) => PollOutcome::Permanent(anyhow!(err).context(format!(
                        "missing-key lookup request failed for key {} on {}",
                        hex::encode(key),
                        ctx.query_url
                    ))),
                }
            }
        })
        .await?;
    }
    Ok(())
}

async fn run_range_samples(
    ctx: &ValidationCtx<'_>,
    sorted_records: &[&Record],
    range_plans: &[RangePlan],
) -> anyhow::Result<()> {
    tracing::info!(
        query_url = %ctx.query_url,
        samples = range_plans.len(),
        "Running pseudorandomized forward/reverse range subsection samples"
    );
    // Every sampled window interleaves foreign rows on a shared store, so each
    // subsection is verified with a paginated scan that skips rows outside this
    // run instead of a single limit-bounded query.
    let own_keys: HashSet<Key> = sorted_records
        .iter()
        .map(|record| record.key.clone())
        .collect();
    for (sample_idx, plan) in range_plans.iter().enumerate() {
        let checks = build_range_subsection_checks(*plan, sample_idx as u64);
        let label = format!("range visibility sample {sample_idx}");
        poll_until(ctx, &label, |_| async {
            let mut pending_rows = 0usize;
            let mut pending_checks = 0usize;
            let mut pending_transient_errors = 0usize;
            let mut last_transient_error: Option<String> = None;
            for (check_idx, check) in checks.iter().enumerate() {
                let lo = &sorted_records[check.plan.start_idx].key;
                let hi = &sorted_records[check.plan.end_idx].key;
                let expected =
                    expected_range_slice_for_mode(sorted_records, check.plan, check.mode);
                let scan = scan_window_for_expected(
                    ctx,
                    lo,
                    hi,
                    check.mode,
                    check.plan.page_size,
                    &expected,
                    |key| own_keys.contains(key),
                )
                .await;
                match scan {
                    Ok(()) => {}
                    Err(RangeScanError::Transient(err)) => {
                        pending_checks += 1;
                        pending_rows += expected.len();
                        pending_transient_errors += 1;
                        last_transient_error = Some(format!(
                            "{:?} range sample {} subsection {} transient error: {}",
                            check.mode, sample_idx, check_idx, err
                        ));
                    }
                    Err(RangeScanError::Permanent(err)) => {
                        return PollOutcome::Permanent(err.context(format!(
                            "{:?} range request failed for sample {}, subsection {}",
                            check.mode, sample_idx, check_idx
                        )));
                    }
                }
            }

            if pending_checks == 0 {
                return PollOutcome::Complete(());
            }
            PollOutcome::Pending(format!(
                "sample {sample_idx}: {pending_checks} pending subsection checks, {pending_rows} rows still missing, transient_query_errors={pending_transient_errors}, last_transient_error={}",
                last_transient_error.as_deref().unwrap_or("none")
            ))
        })
        .await?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct RangeSubsectionCheck {
    plan: RangePlan,
    mode: RangeMode,
}

fn sample_unique_indices(total: usize, requested: usize, rng: &mut StdRng) -> Vec<usize> {
    if total == 0 || requested == 0 {
        return Vec::new();
    }
    rand::seq::index::sample(rng, total, requested.min(total)).into_vec()
}

fn sample_missing_indices(count: usize, rng: &mut StdRng) -> Vec<u64> {
    // Correctness comes from the keyspace's disjoint missing-key domain byte: these indexes never
    // collide with inserted keys regardless of value, so the high offset and lack of dedup are
    // only cosmetic.
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(1_000_000_000u64.wrapping_add(rng.random::<u64>() % 1_000_000));
    }
    values
}

fn build_range_plans(
    total_records: usize,
    range_samples: usize,
    max_range_limit: usize,
    rng: &mut StdRng,
) -> Vec<RangePlan> {
    if total_records == 0 || range_samples == 0 {
        return Vec::new();
    }
    let mut plans = Vec::with_capacity(range_samples);
    for _ in 0..range_samples {
        let start_idx = rng.random_range(0..total_records);
        let end_idx = rng.random_range(start_idx..total_records);
        let window = end_idx - start_idx + 1;
        // Varying the page size exercises limit truncation and pagination on
        // windows both smaller and larger than one page.
        let page_cap = window.min(max_range_limit.max(1));
        let page_size = rng.random_range(1..=page_cap);
        plans.push(RangePlan {
            start_idx,
            end_idx,
            page_size,
        });
    }
    plans
}

fn expected_range_slice_for_mode<'a>(
    records: &[&'a Record],
    plan: RangePlan,
    mode: RangeMode,
) -> Vec<&'a Record> {
    let window = records[plan.start_idx..=plan.end_idx].iter().copied();
    match mode {
        RangeMode::Forward => window.collect(),
        RangeMode::Reverse => window.rev().collect(),
    }
}

fn build_range_subsection_checks(plan: RangePlan, sample_seed: u64) -> Vec<RangeSubsectionCheck> {
    let window = plan.end_idx - plan.start_idx + 1;
    let subsection_count = if window <= 8 {
        1
    } else if window <= 32 {
        2
    } else {
        4
    };
    let step = window.div_ceil(subsection_count);

    let mut rng = StdRng::seed_from_u64(mix64(
        sample_seed
            ^ (plan.start_idx as u64)
            ^ ((plan.end_idx as u64) << 24)
            ^ (plan.page_size as u64),
    ));

    let mut subsections = Vec::new();
    let mut start_idx = plan.start_idx;
    while start_idx <= plan.end_idx {
        let end_idx = (start_idx + step - 1).min(plan.end_idx);
        let sub_window = end_idx - start_idx + 1;
        let page_size = rng.random_range(1..=sub_window.min(plan.page_size.max(1)));
        subsections.push(RangePlan {
            start_idx,
            end_idx,
            page_size,
        });
        if end_idx == plan.end_idx {
            break;
        }
        start_idx = end_idx + 1;
    }
    subsections.shuffle(&mut rng);

    let mut checks = Vec::with_capacity(subsections.len() * 2);
    for subsection in subsections {
        let mut modes = [RangeMode::Forward, RangeMode::Reverse];
        if rng.random_bool(0.5) {
            modes.reverse();
        }
        checks.extend(modes.map(|mode| RangeSubsectionCheck {
            plan: subsection,
            mode,
        }));
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyspace::DEFAULT_KEY_LEN;
    use axum::Router;
    use connectrpc::{ConnectError, ConnectRpcService, RequestContext};
    use exoware_sdk::common::kv::v1::Entry;
    use exoware_sdk::query::{
        GetManyEntry, GetManyFrame, GetResponse, OwnedGetManyRequestView, OwnedGetRequestView,
        OwnedRangeRequestView, OwnedReduceRequestView, RangeFrame, ReduceResponse,
        Service as QueryService, ServiceServer as QueryServiceServer,
    };
    use futures::stream;
    use std::collections::HashSet;

    #[derive(Clone)]
    enum RangeHarness {
        Duplicate { key: Key, value: Vec<u8> },
        Empty,
        MissingGet,
        PermanentError,
        Delayed { delay: Duration },
    }

    #[allow(refining_impl_trait)]
    impl QueryService for RangeHarness {
        async fn get(
            &self,
            _ctx: RequestContext,
            _request: OwnedGetRequestView,
        ) -> connectrpc::ServiceResult<GetResponse> {
            match self {
                Self::MissingGet => connectrpc::Response::ok(GetResponse::default()),
                _ => Err(ConnectError::unimplemented("test harness")),
            }
        }

        async fn get_many(
            &self,
            _ctx: RequestContext,
            request: OwnedGetManyRequestView,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<GetManyFrame>> {
            match self {
                Self::MissingGet => {
                    let results = request
                        .keys
                        .iter()
                        .map(|key| GetManyEntry {
                            key: key.to_vec(),
                            ..Default::default()
                        })
                        .collect();
                    Ok(connectrpc::Response::stream(stream::iter([Ok(
                        GetManyFrame {
                            results,
                            ..Default::default()
                        },
                    )])))
                }
                _ => Err(ConnectError::unimplemented("test harness")),
            }
        }

        async fn range(
            &self,
            _ctx: RequestContext,
            _request: OwnedRangeRequestView,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<RangeFrame>> {
            match self {
                Self::Duplicate { key, value } => {
                    let entry = Entry {
                        key: key.to_vec(),
                        value: value.clone().into(),
                        ..Default::default()
                    };
                    let frame = RangeFrame {
                        results: vec![entry.clone(), entry],
                        ..Default::default()
                    };
                    Ok(connectrpc::Response::stream(stream::iter([Ok(frame)])))
                }
                Self::Empty => Ok(connectrpc::Response::stream(stream::iter([Ok(
                    RangeFrame::default(),
                )]))),
                Self::MissingGet => Err(ConnectError::unimplemented("test harness")),
                Self::PermanentError => Err(ConnectError::invalid_argument("range rejected")),
                Self::Delayed { delay } => {
                    tokio::time::sleep(*delay).await;
                    Ok(connectrpc::Response::stream(stream::iter([Ok(
                        RangeFrame::default(),
                    )])))
                }
            }
        }

        async fn reduce(
            &self,
            _ctx: RequestContext,
            _request: OwnedReduceRequestView,
        ) -> connectrpc::ServiceResult<ReduceResponse> {
            Err(ConnectError::unimplemented("test harness"))
        }
    }

    async fn spawn_range_harness(harness: RangeHarness) -> PrefixedStoreClient {
        let connect = ConnectRpcService::new(QueryServiceServer::new(harness));
        let app = Router::new().fallback_service(connect);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });
        build_client(&ClientConfig::new(url, 1).expect("client config")).expect("client")
    }

    #[tokio::test]
    async fn full_range_scan_rejects_duplicate_own_row_after_expected_sequence() {
        let namespace = 42;
        let keyspace = Keyspace::validation_from_u64_namespace(namespace, DEFAULT_KEY_LEN).unwrap();
        let key = keyspace.inserted_key(0);
        let value = value_for_index(namespace, 0, DEFAULT_VALUE_SIZE);
        let client = spawn_range_harness(RangeHarness::Duplicate { key, value }).await;

        let ctx = ValidationCtx::new(
            &client,
            "test",
            1,
            Duration::from_secs(1),
            Duration::from_millis(1),
        );
        let result =
            scan_visible_prefix_via_range(&ctx, &keyspace, namespace, 1, DEFAULT_VALUE_SIZE, 2)
                .await;

        assert!(
            matches!(result, Err(RangeScanError::Permanent(_))),
            "duplicate own rows must be a permanent range correctness failure: {result:?}"
        );
    }

    #[tokio::test]
    async fn full_range_scan_does_not_retry_permanent_query_error_until_timeout() {
        let client = spawn_range_harness(RangeHarness::PermanentError).await;
        let keyspace = Keyspace::validation_from_u64_namespace(42, DEFAULT_KEY_LEN).unwrap();

        let ctx = ValidationCtx::new(
            &client,
            "test",
            1,
            Duration::from_millis(25),
            Duration::from_millis(1),
        );
        let err = wait_for_all_visible_via_range(&ctx, &keyspace, 42, 1, DEFAULT_VALUE_SIZE, 1)
            .await
            .expect_err("InvalidArgument must fail immediately");

        assert!(
            err.to_string().contains("range rejected"),
            "permanent query error was masked: {err:#}"
        );
        assert!(
            !err.to_string().contains("full-range visibility timeout"),
            "permanent query error was retried until timeout: {err:#}"
        );
    }

    #[tokio::test]
    async fn full_range_scan_does_not_retry_missing_rows_after_sequence_floor() {
        let client = spawn_range_harness(RangeHarness::Empty).await;
        let keyspace = Keyspace::validation_from_u64_namespace(42, DEFAULT_KEY_LEN).unwrap();

        let ctx = ValidationCtx::new(
            &client,
            "test",
            1,
            Duration::from_millis(25),
            Duration::from_millis(1),
        );
        let err = wait_for_all_visible_via_range(&ctx, &keyspace, 42, 1, DEFAULT_VALUE_SIZE, 1)
            .await
            .expect_err("a successful read at the write floor must include the written row");

        assert!(
            !err.to_string().contains("full-range visibility timeout"),
            "missing row after the sequence floor was retried until timeout: {err:#}"
        );
    }

    #[tokio::test]
    async fn point_read_does_not_retry_missing_key_after_sequence_floor() {
        let namespace = 42;
        let keyspace = Keyspace::validation_from_u64_namespace(namespace, DEFAULT_KEY_LEN).unwrap();
        let record = Record {
            key: keyspace.inserted_key(0),
            value: value_for_index(namespace, 0, DEFAULT_VALUE_SIZE),
        };
        let client = spawn_range_harness(RangeHarness::MissingGet).await;

        let ctx = ValidationCtx::new(
            &client,
            "test",
            1,
            Duration::from_millis(25),
            Duration::from_millis(1),
        );
        let err = wait_for_all_visible(&ctx, &[record])
            .await
            .expect_err("a missing key at the sequence floor must fail immediately");

        assert!(err.to_string().contains("confirmed key"));
        assert!(err.to_string().contains("was missing"));
        assert!(
            !err.to_string().contains("visibility timeout"),
            "a permanent missing-key result was retried until timeout: {err:#}"
        );
    }

    #[tokio::test]
    async fn range_scan_deadline_cancels_an_in_flight_page_request() {
        let namespace = 42;
        let keyspace = Keyspace::validation_from_u64_namespace(namespace, DEFAULT_KEY_LEN).unwrap();
        let record = Record {
            key: keyspace.inserted_key(0),
            value: value_for_index(namespace, 0, DEFAULT_VALUE_SIZE),
        };
        let client = spawn_range_harness(RangeHarness::Delayed {
            delay: Duration::from_millis(100),
        })
        .await;

        let ctx = ValidationCtx::new(
            &client,
            "test",
            1,
            Duration::from_millis(10),
            Duration::from_millis(1),
        );
        let err = scan_window_for_expected(
            &ctx,
            &record.key,
            &record.key,
            RangeMode::Forward,
            1,
            &[&record],
            |key| key == &record.key,
        )
        .await
        .expect_err("a range page that exceeds the validation deadline must fail");

        let detail = match err {
            RangeScanError::Permanent(err) => err.to_string(),
            other => panic!("deadline must be a permanent validation failure: {other:?}"),
        };
        assert!(detail.contains("range scan deadline exceeded"));
        assert!(detail.contains("matched 0 of 1 expected rows"));
    }

    #[test]
    fn sample_indices_are_unique_and_bounded() {
        let mut rng = StdRng::seed_from_u64(99);
        let sample = sample_unique_indices(20, 10, &mut rng);
        assert_eq!(sample.len(), 10);
        let unique: HashSet<usize> = sample.iter().copied().collect();
        assert_eq!(unique.len(), sample.len());
        assert!(sample.iter().all(|idx| *idx < 20));
    }

    #[test]
    fn range_plans_stay_in_bounds_and_cap_page_size() {
        let mut rng = StdRng::seed_from_u64(1);
        let plans = build_range_plans(50, 25, 7, &mut rng);
        assert_eq!(plans.len(), 25);
        for plan in plans {
            assert!(plan.start_idx <= plan.end_idx);
            assert!(plan.end_idx < 50);
            assert!(plan.page_size >= 1);
            assert!(plan.page_size <= 7);
            let window = plan.end_idx - plan.start_idx + 1;
            assert!(plan.page_size <= window);
        }
    }

    #[test]
    fn expected_range_slice_covers_full_window() {
        let keyspace = Keyspace::from_u64_namespace(55, DEFAULT_KEY_LEN).unwrap();
        let records = (0..10)
            .map(|i| Record {
                key: keyspace.inserted_key(i),
                value: value_for_index(55, i, 160),
            })
            .collect::<Vec<_>>();
        let record_refs: Vec<&Record> = records.iter().collect();
        let slice = expected_range_slice_for_mode(
            &record_refs,
            RangePlan {
                start_idx: 2,
                end_idx: 7,
                page_size: 3,
            },
            RangeMode::Forward,
        );
        assert_eq!(slice.len(), 6);
        assert_eq!(slice[0].key, records[2].key);
        assert_eq!(slice[5].key, records[7].key);
    }

    #[test]
    fn expected_reverse_range_slice_covers_full_window() {
        let keyspace = Keyspace::from_u64_namespace(55, DEFAULT_KEY_LEN).unwrap();
        let records = (0..10)
            .map(|i| Record {
                key: keyspace.inserted_key(i),
                value: value_for_index(55, i, 160),
            })
            .collect::<Vec<_>>();
        let record_refs: Vec<&Record> = records.iter().collect();
        let slice = expected_range_slice_for_mode(
            &record_refs,
            RangePlan {
                start_idx: 2,
                end_idx: 7,
                page_size: 3,
            },
            RangeMode::Reverse,
        );
        assert_eq!(slice.len(), 6);
        assert_eq!(slice[0].key, records[7].key);
        assert_eq!(slice[5].key, records[2].key);
    }

    #[test]
    fn prev_key_mirrors_next_key() {
        for bytes in [
            vec![0x12, 0x34],
            vec![0x12, 0x00],
            vec![0x00],
            vec![0xFF; MAX_KEY_LEN],
        ] {
            let key = Key::from(bytes);
            let prev = prev_key(&key).expect("non-empty keys have predecessors");
            assert!(prev < key);
            assert_eq!(next_key(&prev).expect("prev is below the maximum key"), key);
        }
        assert!(prev_key(&Key::new()).is_none());
    }

    #[test]
    fn subsection_checks_cover_both_modes_and_stay_in_bounds() {
        let plan = RangePlan {
            start_idx: 10,
            end_idx: 89,
            page_size: 25,
        };
        let checks = build_range_subsection_checks(plan, 42);
        assert!(checks.len() >= 4);
        assert_eq!(checks.len() % 2, 0);

        let has_forward = checks.iter().any(|c| c.mode == RangeMode::Forward);
        let has_reverse = checks.iter().any(|c| c.mode == RangeMode::Reverse);
        assert!(has_forward && has_reverse);
        assert!(checks.iter().all(|c| c.plan.start_idx >= plan.start_idx));
        assert!(checks.iter().all(|c| c.plan.end_idx <= plan.end_idx));
        assert!(checks.iter().all(|c| c.plan.start_idx <= c.plan.end_idx));
        assert!(checks.iter().all(|c| c.plan.page_size >= 1));
        assert!(checks
            .iter()
            .all(|c| c.plan.page_size <= (c.plan.end_idx - c.plan.start_idx + 1)));
    }

    fn sample_config(value_size: usize) -> Config {
        Config {
            mode: ValidateMode::Standard,
            client: ClientConfig::new("http://localhost:10000", 3).unwrap(),
            keys: 100,
            batch_size: 25,
            lookup_samples: 25,
            missing_samples: 10,
            range_samples: 10,
            max_range_limit: 32,
            max_visibility_wait_secs: 30,
            poll_interval_ms: 250,
            seed: 7,
            value_size,
            max_value_size: DEFAULT_MAX_VALUE_SIZE,
            ingest_retry: IngestRetryArgs {
                attempts: 150,
                backoff_ms: 200,
            },
            key_len: DEFAULT_KEY_LEN,
            namespace: None,
            full_range_verify: false,
            range_page_size: QUERY_RANGE_MAX_LIMIT,
            ledger_path: None,
            overlap_write_interval_ms: 0,
            overlap_min_writes: 1,
        }
    }

    #[test]
    fn validate_config_accepts_value_size_at_explicit_kv_mk1_limit() {
        let mut config = sample_config(crate::value::KV_MK1_COMPAT_MAX_VALUE_SIZE);
        config.max_value_size = crate::value::KV_MK1_COMPAT_MAX_VALUE_SIZE;
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_value_size_above_explicit_limit() {
        let mut config = sample_config(crate::value::KV_MK1_COMPAT_MAX_VALUE_SIZE + 1);
        config.max_value_size = crate::value::KV_MK1_COMPAT_MAX_VALUE_SIZE;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_accepts_zero_value_size() {
        let config = sample_config(0);
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_accepts_large_batch_size() {
        let mut config = sample_config(160);
        config.batch_size = 250_000;
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_requires_ledger_path_for_overlap_modes() {
        let mut config = sample_config(160);
        config.mode = ValidateMode::OverlapLedgerVerify;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_requires_namespace_for_overlap_writer() {
        let mut config = sample_config(160);
        config.mode = ValidateMode::OverlapLedgerWrite;
        config.ledger_path = Some("/tmp/overlap-ledger.txt".to_string());
        assert!(validate_config(&config).is_err());
        config.namespace = Some(42);
        assert!(validate_config(&config).is_ok());
    }
}
