//! Exoware deployment validation CLI.
//!
//! This tool verifies end-to-end correctness against a deployed Exoware store:
//! - batched writes
//! - eventual point-read visibility
//! - sampled point lookups
//! - sampled not-found lookups
//! - sampled range query correctness
//!
//! Example:
//!   cargo run --release -p exoware-workload -- validate \
//!     --url http://localhost:10000 \
//!     --keys 100

use std::collections::HashSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, ensure, Context};
use clap::ValueEnum;
use connectrpc::ErrorCode;
use exoware_sdk::keys::{next_key, Key, MAX_KEY_LEN};
use exoware_sdk::kv_codec::KvReducedValue;
use exoware_sdk::{ClientError, PrefixedStoreClient, RangeMode};
use exoware_sdk::{RangeReduceOp, RangeReduceRequest, RangeReducerSpec};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

use crate::client::{build_client, ClientConfig};
use crate::deterministic::mix64;
use crate::ingest::{ingest_with_retry, is_transient_ingest_error, retry_delay_for_error};
use crate::keyspace::{Keyspace, DEFAULT_KEY_LEN};
use crate::ledger::{
    hex_encode, read_overlap_ledger, validate_overlap_ledger, write_overlap_ledger,
};
use crate::record::Record;
use crate::value::{
    overlap_value_for_index, validate_value_size, value_for_index, DEFAULT_MAX_VALUE_SIZE,
    DEFAULT_VALUE_SIZE,
};

const QUERY_RANGE_MAX_LIMIT: usize = 10_000;

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
    #[arg(long, default_value = "http://localhost:10000")]
    url: String,
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
    /// Max attempts for each initial write batch. Continuous overlap-ledger appends retry until
    /// the process is interrupted so a chaos writer survives temporary outages.
    #[arg(long, default_value_t = 150)]
    ingest_retry_attempts: usize,
    #[arg(long, default_value_t = 200)]
    ingest_retry_backoff_ms: u64,
    /// Max client read retry attempts for lookup/range calls.
    #[arg(long, default_value_t = 3)]
    read_retry_attempts: usize,
    /// Physical key length for generated validation keys.
    #[arg(long, default_value_t = DEFAULT_KEY_LEN)]
    key_len: usize,
    /// Optional namespace override (defaults to timestamp-derived value).
    #[arg(long)]
    namespace: Option<u64>,
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
    ingest_retry_attempts: usize,
    ingest_retry_backoff_ms: u64,
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
            client: ClientConfig::new(args.url, args.read_retry_attempts)?,
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
            ingest_retry_attempts: args.ingest_retry_attempts,
            ingest_retry_backoff_ms: args.ingest_retry_backoff_ms,
            key_len: args.key_len,
            namespace: args.namespace,
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
struct RangeVisibilityScan {
    contiguous_visible: u64,
    pages_scanned: u64,
    complete: bool,
    detail: String,
}

#[derive(Debug)]
enum RangeScanError {
    /// Transient failures (network/409/503/etc) that may self-resolve on retry.
    Transient(anyhow::Error),
    /// Permanent correctness failures that should fail fast.
    Permanent(anyhow::Error),
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
        hex_encode(boundary)
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
#[allow(clippy::too_many_arguments)]
async fn scan_window_for_expected(
    client: &PrefixedStoreClient,
    lo: &Key,
    hi: &Key,
    mode: RangeMode,
    page_size: usize,
    min_sequence_number: u64,
    deadline: Instant,
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
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(range_scan_deadline_error(
                pages_scanned,
                matched as u64,
                expected.len() as u64,
                foreign_rows,
                boundary,
            ));
        }

        let query = client.query();
        let rows = match tokio::time::timeout(
            remaining,
            query.range_with_mode_and_min_sequence_number(
                &window_lo,
                &window_hi,
                page_size,
                mode,
                min_sequence_number,
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
                    hex_encode(key),
                    expected.len()
                )));
            };
            if *key != record.key {
                return Err(RangeScanError::Permanent(anyhow!(
                    "row mismatch at position {matched}: expected key {}, got {}",
                    hex_encode(&record.key),
                    hex_encode(key)
                )));
            }
            if value.as_ref() != record.value.as_slice() {
                return Err(RangeScanError::Permanent(anyhow!(
                    "value mismatch for key {}",
                    hex_encode(key)
                )));
            }
            matched += 1;
        }

        if matched >= expected.len() {
            return Ok(());
        }

        if rows.len() < page_size {
            return Err(RangeScanError::Permanent(anyhow!(
                "range window exhausted with {matched} of {} expected rows visible at sequence floor {min_sequence_number}",
                expected.len()
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
                "reached the edge of the key domain with {matched} of {} expected rows visible at sequence floor {min_sequence_number}",
                expected.len()
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
            let namespace = cli.namespace.unwrap_or_else(|| default_namespace(cli.seed));
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
    let namespace = cli.namespace.unwrap_or_else(|| default_namespace(cli.seed));
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
        let min_sequence_number = run_write_phase_generated(
            client,
            &keyspace,
            cli.keys,
            cli.batch_size,
            namespace,
            cli.value_size,
            cli.ingest_retry_attempts,
            Duration::from_millis(cli.ingest_retry_backoff_ms),
        )
        .await?;
        tracing::info!(
            query_url = %url,
            page_size = cli.range_page_size,
            "Validating full queryability with paginated range scan"
        );
        wait_for_all_visible_via_range(
            client,
            &keyspace,
            namespace,
            cli.keys,
            cli.value_size,
            cli.range_page_size,
            min_sequence_number,
            timeout,
            poll_interval,
            url,
        )
        .await?;
        tracing::info!(
            inserted_keys = cli.keys,
            mode = "full-range-verify",
            "Validation completed successfully"
        );
        return Ok(());
    }

    let records = build_records(&keyspace, namespace, cli.keys, cli.value_size)?;
    let mut sorted_records = records.clone();
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
        &records,
        cli.batch_size,
        namespace,
        cli.ingest_retry_attempts,
        Duration::from_millis(cli.ingest_retry_backoff_ms),
    )
    .await?;
    tracing::info!(query_url = %url, "Validating query endpoint");
    wait_for_all_visible(
        client,
        &records,
        min_sequence_number,
        timeout,
        poll_interval,
        url,
    )
    .await?;
    run_point_samples(
        client,
        &records,
        &point_indices,
        min_sequence_number,
        timeout,
        poll_interval,
        url,
    )
    .await?;
    run_missing_samples(
        client,
        &keyspace,
        &missing_indices,
        min_sequence_number,
        timeout,
        poll_interval,
        url,
    )
    .await?;
    run_range_samples(
        client,
        &sorted_records,
        &range_plans,
        min_sequence_number,
        timeout,
        poll_interval,
        url,
    )
    .await?;

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
    let mut records = build_overlap_records(&keyspace, namespace, cli.keys)?;
    let mut sequence_number = run_write_phase(
        client,
        &records,
        cli.batch_size,
        namespace,
        cli.ingest_retry_attempts,
        Duration::from_millis(cli.ingest_retry_backoff_ms),
    )
    .await?;

    let mut successful_writes = records.len() as u64;
    write_overlap_ledger(
        ledger_path,
        namespace,
        successful_writes,
        sequence_number,
        &records,
    )?;

    let mut next_index = records.len() as u64;
    let shutdown = overlap_shutdown_signal();
    tokio::pin!(shutdown);
    let write_interval = Duration::from_millis(cli.overlap_write_interval_ms);

    // The initial fixture is bounded so setup failures surface promptly; the steady-state writer
    // stays alive through transient outages until it is explicitly stopped.
    'writer: loop {
        let key = keyspace.inserted_key(next_index)?;
        let value = overlap_value_for_index(namespace, next_index);
        let ingest_value = value.clone();
        let refs = [(&key, ingest_value.as_slice())];
        let label = format!("overlap-ledger append index {}", next_index);
        let mut attempt = 0u64;
        loop {
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
                    records.push(Record {
                        key: key.clone(),
                        value,
                    });
                    successful_writes = successful_writes.saturating_add(1);
                    write_overlap_ledger(
                        ledger_path,
                        namespace,
                        successful_writes,
                        sequence_number,
                        &records,
                    )?;
                    next_index = next_index.saturating_add(1);
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
                        Duration::from_millis(cli.ingest_retry_backoff_ms),
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

        if !write_interval.is_zero() {
            let sleep = tokio::time::sleep(write_interval);
            tokio::pin!(sleep);
            tokio::select! {
                _ = &mut shutdown => break 'writer,
                _ = &mut sleep => {}
            }
        }
    }

    write_overlap_ledger(
        ledger_path,
        namespace,
        successful_writes,
        sequence_number,
        &records,
    )?;
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
    let mut sorted_records = ledger.records.clone();
    sorted_records.sort_by(|a, b| a.key.cmp(&b.key));
    wait_for_all_visible(
        client,
        &sorted_records,
        ledger.sequence_number,
        timeout,
        poll_interval,
        url,
    )
    .await?;
    wait_for_exact_range_match(
        client,
        &sorted_records,
        RangeMode::Forward,
        cli.range_page_size,
        ledger.sequence_number,
        timeout,
        poll_interval,
        url,
    )
    .await?;
    wait_for_exact_range_match(
        client,
        &sorted_records,
        RangeMode::Reverse,
        cli.range_page_size,
        ledger.sequence_number,
        timeout,
        poll_interval,
        url,
    )
    .await?;
    wait_for_reduce_count_match(
        client,
        &sorted_records,
        ledger.sequence_number,
        timeout,
        poll_interval,
        url,
    )
    .await?;
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
    ensure!(
        cli.ingest_retry_attempts > 0,
        "--ingest-retry-attempts must be > 0"
    );
    ensure!(
        cli.ingest_retry_backoff_ms > 0,
        "--ingest-retry-backoff-ms must be > 0"
    );
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

fn default_namespace(seed: u64) -> u64 {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    now_nanos ^ seed.rotate_left(13) ^ 0xA5A5_A5A5_A5A5_A5A5
}

fn build_records(
    keyspace: &Keyspace,
    namespace: u64,
    keys: u64,
    value_size: usize,
) -> anyhow::Result<Vec<Record>> {
    let key_count = usize::try_from(keys).context("--keys does not fit into usize")?;
    let mut records = Vec::with_capacity(key_count);
    for i in 0..keys {
        records.push(Record {
            key: keyspace.inserted_key(i)?,
            value: value_for_index(namespace, i, value_size),
        });
    }
    Ok(records)
}

fn build_overlap_records(
    keyspace: &Keyspace,
    namespace: u64,
    keys: u64,
) -> anyhow::Result<Vec<Record>> {
    let key_count = usize::try_from(keys).context("--keys does not fit into usize")?;
    let mut records = Vec::with_capacity(key_count);
    for i in 0..keys {
        records.push(Record {
            key: keyspace.inserted_key(i)?,
            value: overlap_value_for_index(namespace, i),
        });
    }
    Ok(records)
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_exact_range_match(
    client: &PrefixedStoreClient,
    expected_records: &[Record],
    mode: RangeMode,
    page_size: usize,
    min_sequence_number: u64,
    timeout: Duration,
    poll_interval: Duration,
    query_url: &str,
) -> anyhow::Result<()> {
    let first = expected_records
        .first()
        .context("expected_records must not be empty for exact range match")?;
    let last = expected_records
        .last()
        .context("expected_records must not be empty for exact range match")?;
    // Reverse scans return rows highest-key-first, so compare against the reversed expectation.
    let expected_order: Vec<&Record> = match mode {
        RangeMode::Forward => expected_records.iter().collect(),
        RangeMode::Reverse => expected_records.iter().rev().collect(),
    };

    // Only rows carrying confirmed ledger keys participate in the match: the
    // window interleaves other namespaces' rows on a shared store, plus this
    // writer's final append when it landed without an acknowledgment before
    // shutdown.
    let own_keys: HashSet<Key> = expected_records
        .iter()
        .map(|record| record.key.clone())
        .collect();
    let is_own = |key: &Key| own_keys.contains(key);
    let deadline = Instant::now() + timeout;
    let mut attempt = 0u64;

    loop {
        attempt = attempt.saturating_add(1);
        let scan = scan_window_for_expected(
            client,
            &first.key,
            &last.key,
            mode,
            page_size,
            min_sequence_number,
            deadline,
            &expected_order,
            is_own,
        )
        .await;
        let detail = match scan {
            Ok(()) => {
                tracing::info!(
                    query_url = %query_url,
                    mode = ?mode,
                    attempts = attempt,
                    rows = expected_order.len(),
                    "Exact overlap-ledger range match succeeded"
                );
                return Ok(());
            }
            Err(RangeScanError::Transient(err)) => {
                format!("{mode:?} transient range error: {err}")
            }
            Err(RangeScanError::Permanent(err)) => {
                return Err(err).with_context(|| {
                    format!("exact {mode:?} overlap-ledger range query failed against {query_url}")
                });
            }
        };

        if Instant::now() >= deadline {
            bail!(
                "exact {mode:?} overlap-ledger range match timed out on query {} after {} attempts: {}",
                query_url,
                attempt,
                detail
            );
        }
        tokio::time::sleep(poll_interval).await;
    }
}

async fn wait_for_reduce_count_match(
    client: &PrefixedStoreClient,
    expected_records: &[Record],
    min_sequence_number: u64,
    timeout: Duration,
    poll_interval: Duration,
    query_url: &str,
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
    let deadline = Instant::now() + timeout;
    let mut attempt = 0u64;
    let expected_count = expected_records.len() as u64;

    loop {
        attempt = attempt.saturating_add(1);
        let detail = match client
            .query()
            .range_reduce_with_min_sequence_number(
                &first.key,
                &last.key,
                &request,
                min_sequence_number,
            )
            .await
        {
            Ok(values) => {
                let actual = match values.as_slice() {
                    [Some(KvReducedValue::UInt64(v))] => *v,
                    [Some(KvReducedValue::Int64(v))] if *v >= 0 => *v as u64,
                    other => {
                        bail!(
                            "unexpected range reduce count response on {}: {:?}",
                            query_url,
                            other
                        );
                    }
                };
                if actual >= expected_count {
                    tracing::info!(
                        query_url = %query_url,
                        attempts = attempt,
                        actual_count = actual,
                        expected_count,
                        "Range reduction reached expected distinct-key floor"
                    );
                    return Ok(());
                }
                bail!(
                    "confirmed range reduce count on {} returned {}, expected at least {} at sequence floor {}",
                    query_url,
                    actual,
                    expected_count,
                    min_sequence_number
                )
            }
            Err(err) if is_transient_query_error(&err) => {
                format!("range reduce transient failure: {err}")
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("range reduction verification failed against {}", query_url)
                });
            }
        };
        if Instant::now() >= deadline {
            bail!(
                "range reduce timeout on {} after {} attempts: {}",
                query_url,
                attempt,
                detail
            );
        }
        tracing::info!(
            query_url = %query_url,
            attempts = attempt,
            detail = %detail,
            "Range reduction retry"
        );
        tokio::time::sleep(poll_interval).await;
    }
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
    records: &[Record],
    batch_size: usize,
    namespace: u64,
    ingest_retry_attempts: usize,
    ingest_retry_backoff: Duration,
) -> anyhow::Result<u64> {
    tracing::info!(
        keys = records.len(),
        batch_size,
        namespace,
        "Starting write phase"
    );
    let mut last_sequence_number = 0u64;
    for (chunk_idx, chunk) in records.chunks(batch_size).enumerate() {
        let refs: Vec<(&Key, &[u8])> = chunk
            .iter()
            .map(|record| (&record.key, record.value.as_slice()))
            .collect();
        last_sequence_number = ingest_with_retry(
            client,
            &refs,
            ingest_retry_attempts,
            ingest_retry_backoff,
            &format!("batch index {chunk_idx}"),
        )
        .await?
        .sequence_number;
    }
    tracing::info!("Write phase complete");
    Ok(last_sequence_number)
}

#[allow(clippy::too_many_arguments)]
async fn run_write_phase_generated(
    client: &PrefixedStoreClient,
    keyspace: &Keyspace,
    total_keys: u64,
    batch_size: usize,
    namespace: u64,
    value_size: usize,
    ingest_retry_attempts: usize,
    ingest_retry_backoff: Duration,
) -> anyhow::Result<u64> {
    tracing::info!(
        keys = total_keys,
        batch_size,
        namespace,
        value_size,
        "Starting generated write phase"
    );
    let mut chunk_idx = 0usize;
    let mut start_idx = 0u64;
    let mut last_sequence_number = 0u64;
    while start_idx < total_keys {
        let end_idx = start_idx.saturating_add(batch_size as u64).min(total_keys);
        let mut kvs = Vec::with_capacity((end_idx - start_idx) as usize);
        for idx in start_idx..end_idx {
            kvs.push((
                keyspace.inserted_key(idx)?,
                value_for_index(namespace, idx, value_size),
            ));
        }
        let refs: Vec<(&Key, &[u8])> = kvs.iter().map(|(k, v)| (k, v.as_slice())).collect();
        last_sequence_number = ingest_with_retry(
            client,
            &refs,
            ingest_retry_attempts,
            ingest_retry_backoff,
            &format!("generated batch index {chunk_idx}"),
        )
        .await?
        .sequence_number;
        chunk_idx += 1;
        start_idx = end_idx;
    }
    tracing::info!("Generated write phase complete");
    Ok(last_sequence_number)
}

fn is_transient_query_code(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::Aborted | ErrorCode::ResourceExhausted | ErrorCode::Unavailable
    )
}

fn is_transient_query_error(err: &ClientError) -> bool {
    match err {
        ClientError::Http(_) => true,
        _ => err.rpc_code().is_some_and(is_transient_query_code),
    }
}

async fn wait_for_all_visible(
    client: &PrefixedStoreClient,
    records: &[Record],
    min_sequence_number: u64,
    timeout: Duration,
    poll_interval: Duration,
    query_url: &str,
) -> anyhow::Result<()> {
    tracing::info!(
        query_url = %query_url,
        total_keys = records.len(),
        "Waiting for full point-read visibility"
    );
    let mut pending: Vec<usize> = (0..records.len()).collect();
    let mut attempt: u64 = 0;
    let mut last_error: Option<String> = None;
    let deadline = Instant::now() + timeout;

    while !pending.is_empty() {
        attempt += 1;
        let mut remaining = Vec::new();
        for idx in pending {
            let record = &records[idx];
            let get_result = client
                .query()
                .get_with_min_sequence_number(&record.key, min_sequence_number)
                .await;
            match get_result {
                Ok(Some(value)) => {
                    if value.as_ref() != record.value.as_slice() {
                        bail!(
                            "value mismatch for key {} on query {}",
                            hex_encode(&record.key),
                            query_url
                        );
                    }
                }
                Ok(None) => {
                    bail!(
                        "confirmed key {} was missing on query {} at sequence floor {}",
                        hex_encode(&record.key),
                        query_url,
                        min_sequence_number
                    );
                }
                Err(err) if is_transient_query_error(&err) => {
                    last_error = Some(err.to_string());
                    remaining.push(idx);
                }
                Err(err) => {
                    return Err(anyhow!(err)).with_context(|| {
                        format!("point-read visibility query failed against {query_url}")
                    });
                }
            }
        }
        if remaining.is_empty() {
            tracing::info!(
                query_url = %query_url,
                attempts = attempt,
                "All keys visible and correct"
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            let sample = remaining
                .iter()
                .take(5)
                .map(|idx| hex_encode(&records[*idx].key))
                .collect::<Vec<_>>()
                .join(", ");
            let last_error_msg = last_error
                .as_deref()
                .unwrap_or("no lookup errors captured; keys remained missing");
            bail!(
                "visibility timeout on query {}: {} keys still missing after {} attempts; sample missing keys: [{}]; last error: {}",
                query_url,
                remaining.len(),
                attempt,
                sample,
                last_error_msg
            );
        }
        tracing::info!(
            query_url = %query_url,
            attempts = attempt,
            pending = remaining.len(),
            "Visibility retry"
        );
        pending = remaining;
        tokio::time::sleep(poll_interval).await;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_all_visible_via_range(
    client: &PrefixedStoreClient,
    keyspace: &Keyspace,
    namespace: u64,
    total_keys: u64,
    value_size: usize,
    page_size: usize,
    min_sequence_number: u64,
    timeout: Duration,
    poll_interval: Duration,
    query_url: &str,
) -> anyhow::Result<()> {
    tracing::info!(
        query_url = %query_url,
        total_keys,
        page_size,
        "Waiting for full range visibility"
    );
    let mut attempt: u64 = 0;
    let mut best_visible: u64 = 0;
    let mut best_pages: u64 = 0;
    let mut last_detail = "range scan has not run yet".to_string();
    let deadline = Instant::now() + timeout;

    loop {
        if Instant::now() >= deadline {
            bail!(
                "full-range visibility timeout on query {} after {} attempts: visible_prefix={} of {}, best_pages_scanned={}, last_detail={}",
                query_url,
                attempt,
                best_visible,
                total_keys,
                best_pages,
                last_detail
            );
        }
        attempt += 1;
        match scan_visible_prefix_via_range(
            client,
            keyspace,
            namespace,
            total_keys,
            value_size,
            page_size,
            min_sequence_number,
            deadline,
        )
        .await
        {
            Ok(scan) => {
                best_visible = best_visible.max(scan.contiguous_visible);
                best_pages = best_pages.max(scan.pages_scanned);
                if scan.complete {
                    tracing::info!(
                        query_url = %query_url,
                        attempts = attempt,
                        pages_scanned = scan.pages_scanned,
                        total_keys,
                        "All keys visible and correct via full-range verification"
                    );
                    return Ok(());
                }
                last_detail = scan.detail;
            }
            Err(RangeScanError::Transient(err)) => {
                last_detail = format!("range scan transient failure: {err}");
            }
            Err(RangeScanError::Permanent(err)) => {
                return Err(err);
            }
        }
        tracing::info!(
            query_url = %query_url,
            attempts = attempt,
            visible_prefix = best_visible,
            total_keys,
            pending = total_keys.saturating_sub(best_visible),
            detail = %last_detail,
            "Full-range visibility retry"
        );
        tokio::time::sleep(poll_interval).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn scan_visible_prefix_via_range(
    client: &PrefixedStoreClient,
    keyspace: &Keyspace,
    namespace: u64,
    total_keys: u64,
    value_size: usize,
    page_size: usize,
    min_sequence_number: u64,
    deadline: Instant,
) -> Result<RangeVisibilityScan, RangeScanError> {
    if total_keys == 0 {
        return Ok(RangeVisibilityScan {
            contiguous_visible: 0,
            pages_scanned: 0,
            complete: true,
            detail: "no keys requested".to_string(),
        });
    }

    let mut next_start = keyspace
        .inserted_key(0)
        .map_err(RangeScanError::Permanent)?;
    let end = keyspace
        .inserted_key(total_keys - 1)
        .map_err(RangeScanError::Permanent)?;
    // Validation keys are contiguous and ordered by their logical index, so
    // this scan stays within the validator-owned physical range.
    let mut expected_order = (0..total_keys).peekable();
    let mut visible = 0u64;
    let mut pages_scanned = 0u64;
    let mut foreign_rows = 0u64;
    let mut previous_key: Option<Key> = None;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(range_scan_deadline_error(
                pages_scanned,
                visible,
                total_keys,
                foreign_rows,
                &next_start,
            ));
        }

        let query = client.query();
        let rows = match tokio::time::timeout(
            remaining,
            query.range_with_min_sequence_number(&next_start, &end, page_size, min_sequence_number),
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
                    hex_encode(previous_key)
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
                    hex_encode(actual_key)
                ))
            })?;
            if index != expected_index {
                let expected_key = keyspace
                    .inserted_key(expected_index)
                    .map_err(RangeScanError::Permanent)?;
                return Err(RangeScanError::Permanent(anyhow!(
                    "expected sorted key {} (index {}) before own row {} (index {})",
                    hex_encode(&expected_key),
                    expected_index,
                    hex_encode(actual_key),
                    index
                )));
            }
            let expected_value = value_for_index(namespace, index, value_size);
            if actual_value.as_ref() != expected_value.as_slice() {
                return Err(RangeScanError::Permanent(anyhow!(
                    "value mismatch at index {} for key {}",
                    index,
                    hex_encode(actual_key)
                )));
            }
            expected_order.next();
            visible += 1;
        }

        previous_key = rows.last().map(|(key, _)| key.clone());

        if visible >= total_keys {
            return Ok(RangeVisibilityScan {
                contiguous_visible: visible,
                pages_scanned,
                complete: true,
                detail: "full sorted key sequence verified".to_string(),
            });
        }

        if rows.len() < page_size {
            return Err(RangeScanError::Permanent(anyhow!(
                "range window exhausted with {} of {} sorted keys visible at sequence floor {}",
                visible,
                total_keys,
                min_sequence_number
            )));
        }

        let boundary = &rows.last().expect("page checked non-empty").0;
        let Some(advanced) = next_key(boundary) else {
            return Err(RangeScanError::Permanent(anyhow!(
                "reached the maximum possible key with {} of {} sorted keys visible at sequence floor {}",
                visible,
                total_keys,
                min_sequence_number
            )));
        };
        next_start = advanced;
    }
}

async fn run_point_samples(
    client: &PrefixedStoreClient,
    records: &[Record],
    point_indices: &[usize],
    min_sequence_number: u64,
    timeout: Duration,
    poll_interval: Duration,
    query_url: &str,
) -> anyhow::Result<()> {
    tracing::info!(
        query_url = %query_url,
        samples = point_indices.len(),
        "Running point lookup samples"
    );
    let deadline = Instant::now() + timeout;
    for idx in point_indices {
        let record = &records[*idx];
        loop {
            let get_result = client
                .query()
                .get_with_min_sequence_number(&record.key, min_sequence_number)
                .await;
            match get_result {
                Ok(Some(value)) => {
                    if value.as_ref() != record.value.as_slice() {
                        bail!(
                            "point lookup mismatch for key {} on {}",
                            hex_encode(&record.key),
                            query_url
                        );
                    }
                    break;
                }
                Ok(None) => {
                    bail!(
                        "point lookup returned not found for inserted key {} on {}",
                        hex_encode(&record.key),
                        query_url
                    );
                }
                Err(err) if is_transient_query_error(&err) => {
                    if Instant::now() >= deadline {
                        return Err(anyhow!(
                            "point lookup transient retry timeout for key {} on {}: {}",
                            hex_encode(&record.key),
                            query_url,
                            err
                        ));
                    }
                    tracing::info!(
                        query_url = %query_url,
                        key = %hex_encode(&record.key),
                        error = %err,
                        "Point lookup sample transient error; retrying"
                    );
                    tokio::time::sleep(poll_interval).await;
                }
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!(
                            "point lookup request failed for key {} on {}",
                            hex_encode(&record.key),
                            query_url
                        )
                    });
                }
            }
        }
    }
    Ok(())
}

async fn run_missing_samples(
    client: &PrefixedStoreClient,
    keyspace: &Keyspace,
    missing_indices: &[u64],
    min_sequence_number: u64,
    timeout: Duration,
    poll_interval: Duration,
    query_url: &str,
) -> anyhow::Result<()> {
    tracing::info!(
        query_url = %query_url,
        samples = missing_indices.len(),
        "Running missing-key lookup samples"
    );
    let deadline = Instant::now() + timeout;
    for idx in missing_indices {
        let key = keyspace.missing_key(*idx)?;
        loop {
            let get_result = client
                .query()
                .get_with_min_sequence_number(&key, min_sequence_number)
                .await;
            match get_result {
                Ok(result) => {
                    if result.is_some() {
                        bail!(
                            "expected key {} to be missing on {}, but lookup returned a value",
                            hex_encode(&key),
                            query_url
                        );
                    }
                    break;
                }
                Err(err) if is_transient_query_error(&err) => {
                    if Instant::now() >= deadline {
                        return Err(anyhow!(
                            "missing-key lookup transient retry timeout for key {} on {}: {}",
                            hex_encode(&key),
                            query_url,
                            err
                        ));
                    }
                    tracing::info!(
                        query_url = %query_url,
                        key = %hex_encode(&key),
                        error = %err,
                        "Missing-key lookup sample transient error; retrying"
                    );
                    tokio::time::sleep(poll_interval).await;
                }
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!(
                            "missing-key lookup request failed for key {} on {}",
                            hex_encode(&key),
                            query_url
                        )
                    });
                }
            }
        }
    }
    Ok(())
}

async fn run_range_samples(
    client: &PrefixedStoreClient,
    sorted_records: &[Record],
    range_plans: &[RangePlan],
    min_sequence_number: u64,
    timeout: Duration,
    poll_interval: Duration,
    query_url: &str,
) -> anyhow::Result<()> {
    tracing::info!(
        query_url = %query_url,
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
    let is_own = |key: &Key| own_keys.contains(key);
    let deadline = Instant::now() + timeout;
    for (sample_idx, plan) in range_plans.iter().enumerate() {
        let checks = build_range_subsection_checks(*plan, sample_idx as u64);
        loop {
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
                    client,
                    lo,
                    hi,
                    check.mode,
                    check.plan.page_size,
                    min_sequence_number,
                    deadline,
                    &expected,
                    is_own,
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
                        return Err(err).with_context(|| {
                            format!(
                                "{:?} range request failed for sample {}, subsection {}",
                                check.mode, sample_idx, check_idx
                            )
                        });
                    }
                }
            }

            if pending_checks == 0 {
                break;
            }

            if Instant::now() >= deadline {
                bail!(
                    "range visibility timeout on {} for sample {}: {} pending subsection checks, {} rows still missing, transient_query_errors={}, last_transient_error={}",
                    query_url,
                    sample_idx,
                    pending_checks,
                    pending_rows,
                    pending_transient_errors,
                    last_transient_error.as_deref().unwrap_or("none")
                );
            }
            tracing::info!(
                query_url = %query_url,
                sample_idx,
                pending_checks,
                pending_rows,
                pending_transient_errors,
                transient_error = %last_transient_error.as_deref().unwrap_or("none"),
                "Range visibility retry"
            );
            tokio::time::sleep(poll_interval).await;
        }
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
    let mut all_indices: Vec<usize> = (0..total).collect();
    all_indices.shuffle(rng);
    let sample_size = requested.min(total);
    all_indices.truncate(sample_size);
    all_indices
}

fn sample_missing_indices(count: usize, rng: &mut StdRng) -> Vec<u64> {
    // Correctness comes from the keyspace's disjoint missing-key domain byte: these indexes never
    // collide with inserted keys regardless of value, so the high offset and lack of dedup are
    // only cosmetic.
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(1_000_000_000u64.wrapping_add(rng.gen::<u64>() % 1_000_000));
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
        let start_idx = rng.gen_range(0..total_records);
        let end_idx = rng.gen_range(start_idx..total_records);
        let window = end_idx - start_idx + 1;
        // Varying the page size exercises limit truncation and pagination on
        // windows both smaller and larger than one page.
        let page_cap = window.min(max_range_limit.max(1));
        let page_size = rng.gen_range(1..=page_cap);
        plans.push(RangePlan {
            start_idx,
            end_idx,
            page_size,
        });
    }
    plans
}

fn expected_range_slice(records: &[Record], plan: RangePlan) -> Vec<&Record> {
    records[plan.start_idx..=plan.end_idx].iter().collect()
}

fn expected_reverse_range_slice(records: &[Record], plan: RangePlan) -> Vec<&Record> {
    records[plan.start_idx..=plan.end_idx]
        .iter()
        .rev()
        .collect()
}

fn expected_range_slice_for_mode(
    records: &[Record],
    plan: RangePlan,
    mode: RangeMode,
) -> Vec<&Record> {
    match mode {
        RangeMode::Forward => expected_range_slice(records, plan),
        RangeMode::Reverse => expected_reverse_range_slice(records, plan),
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
        let page_size = rng.gen_range(1..=sub_window.min(plan.page_size.max(1)));
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
        if rng.gen_bool(0.5) {
            checks.push(RangeSubsectionCheck {
                plan: subsection,
                mode: RangeMode::Forward,
            });
            checks.push(RangeSubsectionCheck {
                plan: subsection,
                mode: RangeMode::Reverse,
            });
        } else {
            checks.push(RangeSubsectionCheck {
                plan: subsection,
                mode: RangeMode::Reverse,
            });
            checks.push(RangeSubsectionCheck {
                plan: subsection,
                mode: RangeMode::Forward,
            });
        }
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use connectrpc::{ConnectError, ConnectRpcService, RequestContext};
    use exoware_sdk::common::kv::v1::Entry;
    use exoware_sdk::query::{
        GetManyFrame, GetResponse, OwnedGetManyRequestView, OwnedGetRequestView,
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
            _request: OwnedGetManyRequestView,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<GetManyFrame>> {
            Err(ConnectError::unimplemented("test harness"))
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
        let key = keyspace.inserted_key(0).unwrap();
        let value = value_for_index(namespace, 0, DEFAULT_VALUE_SIZE);
        let client = spawn_range_harness(RangeHarness::Duplicate { key, value }).await;

        let result = scan_visible_prefix_via_range(
            &client,
            &keyspace,
            namespace,
            1,
            DEFAULT_VALUE_SIZE,
            2,
            1,
            Instant::now() + Duration::from_secs(1),
        )
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

        let err = wait_for_all_visible_via_range(
            &client,
            &keyspace,
            42,
            1,
            DEFAULT_VALUE_SIZE,
            1,
            1,
            Duration::from_millis(25),
            Duration::from_millis(1),
            "test",
        )
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

        let err = wait_for_all_visible_via_range(
            &client,
            &keyspace,
            42,
            1,
            DEFAULT_VALUE_SIZE,
            1,
            1,
            Duration::from_millis(25),
            Duration::from_millis(1),
            "test",
        )
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
            key: keyspace.inserted_key(0).unwrap(),
            value: value_for_index(namespace, 0, DEFAULT_VALUE_SIZE),
        };
        let client = spawn_range_harness(RangeHarness::MissingGet).await;

        let err = wait_for_all_visible(
            &client,
            &[record],
            1,
            Duration::from_millis(25),
            Duration::from_millis(1),
            "test",
        )
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
            key: keyspace.inserted_key(0).unwrap(),
            value: value_for_index(namespace, 0, DEFAULT_VALUE_SIZE),
        };
        let client = spawn_range_harness(RangeHarness::Delayed {
            delay: Duration::from_millis(100),
        })
        .await;

        let err = scan_window_for_expected(
            &client,
            &record.key,
            &record.key,
            RangeMode::Forward,
            1,
            1,
            Instant::now() + Duration::from_millis(10),
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
                key: keyspace.inserted_key(i).unwrap(),
                value: value_for_index(55, i, 160),
            })
            .collect::<Vec<_>>();
        let slice = expected_range_slice(
            &records,
            RangePlan {
                start_idx: 2,
                end_idx: 7,
                page_size: 3,
            },
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
                key: keyspace.inserted_key(i).unwrap(),
                value: value_for_index(55, i, 160),
            })
            .collect::<Vec<_>>();
        let slice = expected_reverse_range_slice(
            &records,
            RangePlan {
                start_idx: 2,
                end_idx: 7,
                page_size: 3,
            },
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
            ingest_retry_attempts: 150,
            ingest_retry_backoff_ms: 200,
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
    fn transient_query_codes_cover_consistency_and_gateway_transients() {
        assert!(is_transient_query_code(ErrorCode::Aborted));
        assert!(is_transient_query_code(ErrorCode::ResourceExhausted));
        assert!(is_transient_query_code(ErrorCode::Unavailable));
        assert!(!is_transient_query_code(ErrorCode::InvalidArgument));
        assert!(!is_transient_query_code(ErrorCode::Internal));
    }

    #[test]
    fn transient_query_error_classifies_api_statuses() {
        assert!(is_transient_query_error(&ClientError::Rpc(Box::new(
            connectrpc::ConnectError::aborted("consistency not ready"),
        ))));
        assert!(is_transient_query_error(&ClientError::Rpc(Box::new(
            connectrpc::ConnectError::unavailable("load shed"),
        ))));
        assert!(!is_transient_query_error(&ClientError::Rpc(Box::new(
            connectrpc::ConnectError::invalid_argument("bad request"),
        ))));
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
