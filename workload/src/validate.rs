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

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, ensure, Context};
use clap::ValueEnum;
use connectrpc::ErrorCode;
use exoware_sdk::keys::Key;
use exoware_sdk::kv_codec::KvReducedValue;
use exoware_sdk::{ClientError, RangeMode, StoreClient};
use exoware_sdk::{RangeReduceOp, RangeReduceRequest, RangeReducerSpec};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

use crate::client::{build_client, ClientConfig};
use crate::deterministic::mix64;
use crate::keyspace::{Keyspace, DEFAULT_KEY_LEN};
use crate::ledger::{
    hex_encode, read_overlap_ledger, validate_overlap_ledger, write_overlap_ledger, OverlapLedger,
};
use crate::record::Record;
use crate::report;
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
    limit: usize,
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

pub async fn run(args: Args) -> anyhow::Result<()> {
    let cli = Config::try_from(args)?;

    let client = build_client(&cli.client)?;

    let timeout = Duration::from_secs(cli.max_visibility_wait_secs);
    let poll_interval = Duration::from_millis(cli.poll_interval_ms);
    match cli.mode {
        ValidateMode::Standard => {
            run_standard_validation(&cli, &client, &cli.client.endpoint, timeout, poll_interval)
                .await
        }
        ValidateMode::OverlapLedgerWrite => {
            let namespace = cli.namespace.unwrap_or_else(|| default_namespace(cli.seed));
            run_overlap_ledger_write_mode(&cli, &client, &cli.client.endpoint, namespace).await
        }
        ValidateMode::OverlapLedgerVerify => {
            run_overlap_ledger_verify_mode(
                &cli,
                &client,
                &cli.client.endpoint,
                timeout,
                poll_interval,
            )
            .await
        }
    }
}

async fn run_standard_validation(
    cli: &Config,
    client: &StoreClient,
    url: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> anyhow::Result<()> {
    let namespace = cli.namespace.unwrap_or_else(|| default_namespace(cli.seed));
    let keyspace = Keyspace::from_u64_namespace(namespace, cli.key_len)?;
    let mut rng = StdRng::seed_from_u64(cli.seed ^ namespace.rotate_left(7));

    tracing::info!(
        url = %url,
        mode = "standard",
        keys = cli.keys,
        value_size = cli.value_size,
        max_value_size = cli.max_value_size,
        read_retry_attempts = cli.client.read_retry_attempts,
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
            Some(min_sequence_number),
            timeout,
            poll_interval,
            url,
        )
        .await?;
        report::full_range_validation_complete(cli.keys);
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
        Some(min_sequence_number),
        timeout,
        poll_interval,
        url,
    )
    .await?;
    run_point_samples(
        client,
        &records,
        &point_indices,
        Some(min_sequence_number),
        timeout,
        poll_interval,
        url,
    )
    .await?;
    run_missing_samples(
        client,
        &keyspace,
        &missing_indices,
        Some(min_sequence_number),
        timeout,
        poll_interval,
        url,
    )
    .await?;
    run_range_samples(
        client,
        &sorted_records,
        &range_plans,
        Some(min_sequence_number),
        timeout,
        poll_interval,
        url,
    )
    .await?;

    report::standard_validation_complete(
        records.len(),
        point_indices.len(),
        missing_indices.len(),
        range_plans.len(),
    );

    Ok(())
}

async fn run_overlap_ledger_write_mode(
    cli: &Config,
    client: &StoreClient,
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
    let keyspace = Keyspace::from_u64_namespace(namespace, cli.key_len)?;
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
        &OverlapLedger {
            namespace,
            successful_writes,
            sequence_number,
            records: records.clone(),
        },
    )?;

    let mut next_index = records.len() as u64;
    let shutdown = overlap_shutdown_signal();
    tokio::pin!(shutdown);
    let write_interval = Duration::from_millis(cli.overlap_write_interval_ms);

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
                        &OverlapLedger {
                            namespace,
                            successful_writes,
                            sequence_number,
                            records: records.clone(),
                        },
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
                    let sleep =
                        tokio::time::sleep(Duration::from_millis(cli.ingest_retry_backoff_ms));
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
        &OverlapLedger {
            namespace,
            successful_writes,
            sequence_number,
            records,
        },
    )?;
    ensure!(
        successful_writes >= cli.overlap_min_writes,
        "overlap-ledger writer recorded only {} logical writes (minimum required: {})",
        successful_writes,
        cli.overlap_min_writes
    );
    report::overlap_ledger_writer_complete(namespace, successful_writes, ledger_path);
    Ok(())
}

async fn run_overlap_ledger_verify_mode(
    cli: &Config,
    client: &StoreClient,
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
        Some(ledger.sequence_number),
        timeout,
        poll_interval,
        url,
    )
    .await?;
    wait_for_exact_range_match(
        client,
        &sorted_records,
        Some(ledger.sequence_number),
        timeout,
        poll_interval,
        url,
    )
    .await?;
    wait_for_exact_reverse_range_match(
        client,
        &sorted_records,
        Some(ledger.sequence_number),
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
    report::overlap_ledger_verification_complete(
        ledger.namespace,
        sorted_records.len(),
        ledger.successful_writes,
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
    Keyspace::from_u64_namespace(cli.namespace.unwrap_or(0), cli.key_len)?;
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

async fn ingest_refs_with_retry(
    client: &StoreClient,
    refs: &[(&Key, &[u8])],
    ingest_retry_attempts: usize,
    ingest_retry_backoff: Duration,
    label: &str,
) -> anyhow::Result<u64> {
    let mut wal_seq = None;
    let mut last_err: Option<ClientError> = None;
    for attempt in 1..=ingest_retry_attempts {
        match client.ingest().put(refs).await {
            Ok(token) => {
                wal_seq = Some(token);
                break;
            }
            Err(err) if is_transient_ingest_error(&err) && attempt < ingest_retry_attempts => {
                tracing::warn!(
                    label,
                    attempt,
                    code = ?err.rpc_code(),
                    error = %err,
                    "transient ingest failure during validation; retrying"
                );
                tokio::time::sleep(ingest_retry_backoff).await;
            }
            Err(err) => {
                last_err = Some(err);
                break;
            }
        }
    }
    match wal_seq {
        Some(token) => Ok(token),
        None => {
            let err_text = last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "ingest exhausted retries without success".to_string());
            Err(anyhow!(
                "ingest failed for {label} after {} attempts: {err_text}",
                ingest_retry_attempts
            ))
        }
    }
}

async fn wait_for_exact_range_match(
    client: &StoreClient,
    expected_records: &[Record],
    min_sequence_number: Option<u64>,
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
    let limit = expected_records.len().saturating_add(1);
    let deadline = Instant::now() + timeout;
    let mut attempt = 0u64;

    loop {
        attempt = attempt.saturating_add(1);
        let range_result = match min_sequence_number {
            Some(sequence) => {
                client
                    .query()
                    .range_with_min_sequence_number(&first.key, &last.key, limit, sequence)
                    .await
            }
            None => client.query().range(&first.key, &last.key, limit).await,
        };
        let detail = match range_result {
            Ok(rows) => {
                if rows.len() != expected_records.len() {
                    format!(
                        "range returned {} rows, expected {}",
                        rows.len(),
                        expected_records.len()
                    )
                } else {
                    let mut mismatch = None;
                    for (idx, ((actual_key, actual_value), expected)) in
                        rows.iter().zip(expected_records.iter()).enumerate()
                    {
                        if actual_key != &expected.key {
                            mismatch = Some(format!(
                                "row {idx} key mismatch: expected {}, got {}",
                                hex_encode(&expected.key),
                                hex_encode(actual_key)
                            ));
                            break;
                        }
                        if actual_value.as_ref() != expected.value.as_slice() {
                            mismatch = Some(format!(
                                "row {idx} value mismatch for key {}",
                                hex_encode(&expected.key)
                            ));
                            break;
                        }
                    }
                    if let Some(detail) = mismatch {
                        detail
                    } else {
                        tracing::info!(
                            query_url = %query_url,
                            attempts = attempt,
                            rows = rows.len(),
                            "Exact overlap-ledger range match succeeded"
                        );
                        return Ok(());
                    }
                }
            }
            Err(err) if is_transient_query_error(&err) => format!("transient range error: {err}"),
            Err(err) => {
                return Err(anyhow!("exact overlap-ledger range query failed: {err}"));
            }
        };

        if Instant::now() >= deadline {
            bail!(
                "exact overlap-ledger range match timed out on query {} after {} attempts: {}",
                query_url,
                attempt,
                detail
            );
        }
        tokio::time::sleep(poll_interval).await;
    }
}

async fn wait_for_exact_reverse_range_match(
    client: &StoreClient,
    expected_records: &[Record],
    min_sequence_number: Option<u64>,
    timeout: Duration,
    poll_interval: Duration,
    query_url: &str,
) -> anyhow::Result<()> {
    let first = expected_records
        .first()
        .context("expected_records must not be empty for reverse range match")?;
    let last = expected_records
        .last()
        .context("expected_records must not be empty for reverse range match")?;
    let limit = expected_records.len().saturating_add(1);
    let deadline = Instant::now() + timeout;
    let mut attempt = 0u64;

    loop {
        attempt = attempt.saturating_add(1);
        let range_result = match min_sequence_number {
            Some(sequence) => {
                client
                    .query()
                    .range_with_mode_and_min_sequence_number(
                        &first.key,
                        &last.key,
                        limit,
                        RangeMode::Reverse,
                        sequence,
                    )
                    .await
            }
            None => {
                client
                    .query()
                    .range_with_mode(&first.key, &last.key, limit, RangeMode::Reverse)
                    .await
            }
        };
        let detail = match range_result {
            Ok(rows) => {
                if rows.len() != expected_records.len() {
                    format!(
                        "reverse range returned {} rows, expected {}",
                        rows.len(),
                        expected_records.len()
                    )
                } else {
                    let mut mismatch = None;
                    for (idx, ((actual_key, actual_value), expected)) in
                        rows.iter().zip(expected_records.iter().rev()).enumerate()
                    {
                        if actual_key != &expected.key {
                            mismatch = Some(format!(
                                "reverse row {} key mismatch: expected {}, got {}",
                                idx,
                                hex_encode(&expected.key),
                                hex_encode(actual_key)
                            ));
                            break;
                        }
                        if actual_value.as_ref() != expected.value.as_slice() {
                            mismatch = Some(format!(
                                "reverse row {} value mismatch for key {}",
                                idx,
                                hex_encode(&expected.key)
                            ));
                            break;
                        }
                    }
                    if let Some(mismatch) = mismatch {
                        mismatch
                    } else {
                        tracing::info!(
                            query_url = %query_url,
                            attempts = attempt,
                            rows = rows.len(),
                            "Reverse range matched exact expected record set"
                        );
                        return Ok(());
                    }
                }
            }
            Err(err) if is_transient_query_error(&err) => {
                format!("reverse range transient failure: {err}")
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "reverse exact-range verification failed against {}",
                        query_url
                    )
                });
            }
        };
        if Instant::now() >= deadline {
            bail!(
                "reverse exact-range timeout on {} after {} attempts: {}",
                query_url,
                attempt,
                detail
            );
        }
        tracing::info!(
            query_url = %query_url,
            attempts = attempt,
            detail = %detail,
            "Reverse exact-range retry"
        );
        tokio::time::sleep(poll_interval).await;
    }
}

async fn wait_for_reduce_count_match(
    client: &StoreClient,
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
                if actual == expected_count {
                    tracing::info!(
                        query_url = %query_url,
                        attempts = attempt,
                        expected_count,
                        "Range reduction matched expected distinct-key count"
                    );
                    return Ok(());
                }
                format!(
                    "range reduce count returned {}, expected {}",
                    actual, expected_count
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
    client: &StoreClient,
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
        last_sequence_number = ingest_refs_with_retry(
            client,
            &refs,
            ingest_retry_attempts,
            ingest_retry_backoff,
            &format!("batch index {chunk_idx}"),
        )
        .await?;
    }
    tracing::info!("Write phase complete");
    Ok(last_sequence_number)
}

#[allow(clippy::too_many_arguments)]
async fn run_write_phase_generated(
    client: &StoreClient,
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
        last_sequence_number = ingest_refs_with_retry(
            client,
            &refs,
            ingest_retry_attempts,
            ingest_retry_backoff,
            &format!("generated batch index {chunk_idx}"),
        )
        .await?;
        chunk_idx += 1;
        start_idx = end_idx;
    }
    tracing::info!("Generated write phase complete");
    Ok(last_sequence_number)
}

fn is_transient_ingest_code(code: ErrorCode) -> bool {
    matches!(code, ErrorCode::ResourceExhausted | ErrorCode::Unavailable)
}

fn is_transient_ingest_error(err: &ClientError) -> bool {
    err.rpc_code().is_some_and(is_transient_ingest_code)
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
    client: &StoreClient,
    records: &[Record],
    min_sequence_number: Option<u64>,
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
            let get_result = match min_sequence_number {
                Some(sequence) => {
                    client
                        .query()
                        .get_with_min_sequence_number(&record.key, sequence)
                        .await
                }
                None => client.query().get(&record.key).await,
            };
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
                Ok(None) => remaining.push(idx),
                Err(err) => {
                    last_error = Some(err.to_string());
                    remaining.push(idx);
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
    client: &StoreClient,
    keyspace: &Keyspace,
    namespace: u64,
    total_keys: u64,
    value_size: usize,
    page_size: usize,
    min_sequence_number: Option<u64>,
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

async fn scan_visible_prefix_via_range(
    client: &StoreClient,
    keyspace: &Keyspace,
    namespace: u64,
    total_keys: u64,
    value_size: usize,
    page_size: usize,
    min_sequence_number: Option<u64>,
) -> Result<RangeVisibilityScan, RangeScanError> {
    if total_keys == 0 {
        return Ok(RangeVisibilityScan {
            contiguous_visible: 0,
            pages_scanned: 0,
            complete: true,
            detail: "no keys requested".to_string(),
        });
    }
    let end_key = keyspace
        .inserted_key(total_keys - 1)
        .map_err(RangeScanError::Permanent)?;
    let mut next_start = keyspace
        .inserted_key(0)
        .map_err(RangeScanError::Permanent)?;
    let mut expected_index = 0u64;
    let mut pages_scanned = 0u64;

    loop {
        let rows = match min_sequence_number {
            Some(sequence) => {
                client
                    .query()
                    .range_with_min_sequence_number(&next_start, &end_key, page_size, sequence)
                    .await
            }
            None => client.query().range(&next_start, &end_key, page_size).await,
        }
        .map_err(|err| RangeScanError::Transient(anyhow!(err)))?;
        pages_scanned += 1;

        if rows.is_empty() {
            return Ok(RangeVisibilityScan {
                contiguous_visible: expected_index,
                pages_scanned,
                complete: false,
                detail: "range returned empty page before full visibility".to_string(),
            });
        }

        for (row_idx, (actual_key, actual_value)) in rows.iter().enumerate() {
            if expected_index >= total_keys {
                return Err(RangeScanError::Permanent(anyhow!(
                    "range returned extra rows beyond expected key count (pages_scanned={}, row_idx={})",
                    pages_scanned,
                    row_idx
                )));
            }
            let expected_key = keyspace
                .inserted_key(expected_index)
                .map_err(RangeScanError::Permanent)?;
            if actual_key != &expected_key {
                return Ok(RangeVisibilityScan {
                    contiguous_visible: expected_index,
                    pages_scanned,
                    complete: false,
                    detail: format!(
                        "first mismatch at expected index {}: expected key {}, got {}",
                        expected_index,
                        hex_encode(&expected_key),
                        hex_encode(actual_key)
                    ),
                });
            }
            let expected_value = value_for_index(namespace, expected_index, value_size);
            if actual_value.as_ref() != expected_value.as_slice() {
                return Err(RangeScanError::Permanent(anyhow!(
                    "value mismatch at index {} for key {}",
                    expected_index,
                    hex_encode(actual_key)
                )));
            }
            expected_index += 1;
        }

        if expected_index >= total_keys {
            return Ok(RangeVisibilityScan {
                contiguous_visible: expected_index,
                pages_scanned,
                complete: true,
                detail: "full sequence verified".to_string(),
            });
        }

        if rows.len() < page_size {
            return Ok(RangeVisibilityScan {
                contiguous_visible: expected_index,
                pages_scanned,
                complete: false,
                detail: format!(
                    "short range page (rows={}) before all keys visible",
                    rows.len()
                ),
            });
        }

        let Some(last_key) = rows.last().map(|(key, _)| key.clone()) else {
            return Err(RangeScanError::Permanent(anyhow!(
                "range page unexpectedly empty after non-empty check"
            )));
        };
        let Some(next_key) = Keyspace::next_lex_key(&last_key) else {
            return Ok(RangeVisibilityScan {
                contiguous_visible: expected_index,
                pages_scanned,
                complete: false,
                detail: "reached lexicographic key ceiling before full visibility".to_string(),
            });
        };
        next_start = next_key;
    }
}

async fn run_point_samples(
    client: &StoreClient,
    records: &[Record],
    point_indices: &[usize],
    min_sequence_number: Option<u64>,
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
            let get_result = match min_sequence_number {
                Some(sequence) => {
                    client
                        .query()
                        .get_with_min_sequence_number(&record.key, sequence)
                        .await
                }
                None => client.query().get(&record.key).await,
            };
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
    client: &StoreClient,
    keyspace: &Keyspace,
    missing_indices: &[u64],
    min_sequence_number: Option<u64>,
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
            let get_result = match min_sequence_number {
                Some(sequence) => {
                    client
                        .query()
                        .get_with_min_sequence_number(&key, sequence)
                        .await
                }
                None => client.query().get(&key).await,
            };
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
    client: &StoreClient,
    sorted_records: &[Record],
    range_plans: &[RangePlan],
    min_sequence_number: Option<u64>,
    timeout: Duration,
    poll_interval: Duration,
    query_url: &str,
) -> anyhow::Result<()> {
    tracing::info!(
        query_url = %query_url,
        samples = range_plans.len(),
        "Running pseudorandomized forward/reverse range subsection samples"
    );
    let deadline = Instant::now() + timeout;
    for (sample_idx, plan) in range_plans.iter().enumerate() {
        let checks = build_range_subsection_checks(*plan, sample_idx as u64);
        loop {
            let mut pending_rows = 0usize;
            let mut pending_checks = 0usize;
            let mut pending_transient_errors = 0usize;
            let mut last_transient_error: Option<String> = None;
            for (check_idx, check) in checks.iter().enumerate() {
                let start = &sorted_records[check.plan.start_idx].key;
                let end = &sorted_records[check.plan.end_idx].key;
                let expected =
                    expected_range_slice_for_mode(sorted_records, check.plan, check.mode);
                let range_result = match check.mode {
                    RangeMode::Forward => match min_sequence_number {
                        Some(sequence) => {
                            client
                                .query()
                                .range_with_min_sequence_number(
                                    start,
                                    end,
                                    check.plan.limit,
                                    sequence,
                                )
                                .await
                        }
                        None => client.query().range(start, end, check.plan.limit).await,
                    },
                    RangeMode::Reverse => match min_sequence_number {
                        Some(sequence) => {
                            client
                                .query()
                                .range_with_mode_and_min_sequence_number(
                                    start,
                                    end,
                                    check.plan.limit,
                                    RangeMode::Reverse,
                                    sequence,
                                )
                                .await
                        }
                        None => {
                            client
                                .query()
                                .range_with_mode(start, end, check.plan.limit, RangeMode::Reverse)
                                .await
                        }
                    },
                };
                let actual = match range_result {
                    Ok(rows) => rows,
                    Err(err) if is_transient_query_error(&err) => {
                        pending_checks += 1;
                        pending_rows += expected.len();
                        pending_transient_errors += 1;
                        last_transient_error = Some(format!(
                            "{:?} range sample {} subsection {} transient error: {}",
                            check.mode, sample_idx, check_idx, err
                        ));
                        continue;
                    }
                    Err(err) => {
                        return Err(err).with_context(|| {
                            format!(
                                "{:?} range request failed for sample {}, subsection {}",
                                check.mode, sample_idx, check_idx
                            )
                        });
                    }
                };

                if check.mode == RangeMode::Forward
                    && actual.windows(2).any(|window| window[0].0 > window[1].0)
                {
                    bail!(
                        "forward range sample {} subsection {} on {} returned unsorted keys",
                        sample_idx,
                        check_idx,
                        query_url
                    );
                }
                if check.mode == RangeMode::Reverse
                    && actual.windows(2).any(|window| window[0].0 < window[1].0)
                {
                    bail!(
                        "reverse range sample {} subsection {} on {} returned unsorted keys",
                        sample_idx,
                        check_idx,
                        query_url,
                    );
                }

                // These reads carry the write phase's sequence floor, so a conformant backend
                // already exposes every written key to range queries. A short page is tolerated
                // as retry headroom; a full page with the wrong rows is a real fault (handled below).
                if actual.len() < expected.len() {
                    pending_checks += 1;
                    pending_rows += expected.len() - actual.len();
                    continue;
                }

                if actual.len() != expected.len() {
                    bail!(
                        "{:?} range sample {} subsection {} on {} returned {} rows, expected {}",
                        check.mode,
                        sample_idx,
                        check_idx,
                        query_url,
                        actual.len(),
                        expected.len()
                    );
                }

                for (pos, (actual_pair, expected_record)) in
                    actual.iter().zip(expected.iter()).enumerate()
                {
                    if actual_pair.0 != expected_record.key {
                        bail!(
                            "{:?} range sample {} subsection {} on {} mismatched key at row {}",
                            check.mode,
                            sample_idx,
                            check_idx,
                            query_url,
                            pos
                        );
                    }
                    if actual_pair.1.as_ref() != expected_record.value.as_slice() {
                        bail!(
                            "{:?} range sample {} subsection {} on {} mismatched value for key {}",
                            check.mode,
                            sample_idx,
                            check_idx,
                            query_url,
                            hex_encode(&expected_record.key)
                        );
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
        let limit_cap = window.min(max_range_limit.max(1));
        let limit = rng.gen_range(1..=limit_cap);
        plans.push(RangePlan {
            start_idx,
            end_idx,
            limit,
        });
    }
    plans
}

fn expected_range_slice(records: &[Record], plan: RangePlan) -> Vec<&Record> {
    records[plan.start_idx..=plan.end_idx]
        .iter()
        .take(plan.limit)
        .collect()
}

fn expected_reverse_range_slice(records: &[Record], plan: RangePlan) -> Vec<&Record> {
    records[plan.start_idx..=plan.end_idx]
        .iter()
        .rev()
        .take(plan.limit)
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
        sample_seed ^ (plan.start_idx as u64) ^ ((plan.end_idx as u64) << 24) ^ (plan.limit as u64),
    ));

    let mut subsections = Vec::new();
    let mut start_idx = plan.start_idx;
    while start_idx <= plan.end_idx {
        let end_idx = (start_idx + step - 1).min(plan.end_idx);
        let sub_window = end_idx - start_idx + 1;
        let limit = rng.gen_range(1..=sub_window.min(plan.limit.max(1)));
        subsections.push(RangePlan {
            start_idx,
            end_idx,
            limit,
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
    use std::collections::HashSet;

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
    fn range_plans_stay_in_bounds_and_respect_limit() {
        let mut rng = StdRng::seed_from_u64(1);
        let plans = build_range_plans(50, 25, 7, &mut rng);
        assert_eq!(plans.len(), 25);
        for plan in plans {
            assert!(plan.start_idx <= plan.end_idx);
            assert!(plan.end_idx < 50);
            assert!(plan.limit >= 1);
            assert!(plan.limit <= 7);
            let window = plan.end_idx - plan.start_idx + 1;
            assert!(plan.limit <= window);
        }
    }

    #[test]
    fn expected_range_slice_applies_limit() {
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
                limit: 3,
            },
        );
        assert_eq!(slice.len(), 3);
        assert_eq!(slice[0].key, records[2].key);
        assert_eq!(slice[2].key, records[4].key);
    }

    #[test]
    fn expected_reverse_range_slice_applies_limit() {
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
                limit: 3,
            },
        );
        assert_eq!(slice.len(), 3);
        assert_eq!(slice[0].key, records[7].key);
        assert_eq!(slice[2].key, records[5].key);
    }

    #[test]
    fn subsection_checks_cover_both_modes_and_stay_in_bounds() {
        let plan = RangePlan {
            start_idx: 10,
            end_idx: 89,
            limit: 25,
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
        assert!(checks.iter().all(|c| c.plan.limit >= 1));
        assert!(checks
            .iter()
            .all(|c| c.plan.limit <= (c.plan.end_idx - c.plan.start_idx + 1)));
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
    fn transient_ingest_codes_cover_connect_transients() {
        assert!(is_transient_ingest_code(ErrorCode::ResourceExhausted));
        assert!(is_transient_ingest_code(ErrorCode::Unavailable));
        assert!(!is_transient_ingest_code(ErrorCode::InvalidArgument));
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
