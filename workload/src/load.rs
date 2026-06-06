//! Exoware load generator.
//!
//! Usage:
//!   workload load --url http://localhost:10000 --keys 10000

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::ensure;
use exoware_sdk::keys::Key;
use tokio::time::MissedTickBehavior;

use crate::client::{build_client, ClientConfig};
use crate::ingest::ingest_with_retry;
use crate::keyspace::{default_run_namespace, Keyspace, DEFAULT_KEY_LEN};
use crate::value::{value_for_index, DEFAULT_VALUE_SIZE};

/// Load phase: insert keys via ingest API.
#[derive(clap::Args, Debug)]
pub struct Args {
    #[arg(long, default_value = "http://localhost:10000")]
    url: String,
    #[arg(long, default_value_t = 10000)]
    keys: u64,
    #[arg(long, default_value_t = 100)]
    batch_size: usize,
    #[arg(long, default_value_t = 4)]
    concurrency: usize,
    /// Max client read retry attempts for lookup/range calls.
    #[arg(long, default_value_t = 3)]
    read_retry_attempts: usize,
    /// Physical key length for generated workload keys.
    #[arg(long, default_value_t = DEFAULT_KEY_LEN)]
    key_len: usize,
    /// Key namespace; pass the same value to bench to use this loaded keyspace.
    #[arg(long)]
    namespace: Option<u64>,
    /// Size in bytes of generated values.
    #[arg(long, default_value_t = DEFAULT_VALUE_SIZE)]
    value_size: usize,
    /// Emit periodic `Load progress` logs every N seconds (0 = off).
    #[arg(long, default_value_t = 10)]
    progress_interval_secs: u64,
    /// Max attempts per batch when ingest returns a transient error.
    #[arg(long, default_value_t = 150)]
    ingest_retry_attempts: usize,
    /// Backoff in milliseconds between transient ingest retries.
    #[arg(long, default_value_t = 200)]
    ingest_retry_backoff_ms: u64,
}

/// Validated load configuration independent of Clap.
#[derive(Debug)]
pub struct Config {
    client: ClientConfig,
    namespace: u64,
    keyspace: Keyspace,
    keys: u64,
    value_size: usize,
    batch_size: usize,
    concurrency: usize,
    progress_interval_secs: u64,
    ingest_retry_attempts: usize,
    ingest_retry_backoff_ms: u64,
}

impl TryFrom<Args> for Config {
    type Error = anyhow::Error;

    fn try_from(args: Args) -> anyhow::Result<Self> {
        ensure!(args.batch_size > 0, "--batch-size must be > 0");
        ensure!(args.concurrency > 0, "--concurrency must be > 0");
        ensure!(
            args.ingest_retry_attempts > 0,
            "--ingest-retry-attempts must be > 0"
        );
        ensure!(
            args.ingest_retry_backoff_ms > 0,
            "--ingest-retry-backoff-ms must be > 0"
        );
        let namespace = args.namespace.unwrap_or_else(default_run_namespace);

        Ok(Self {
            client: ClientConfig::new(args.url, args.read_retry_attempts)?,
            namespace,
            keyspace: Keyspace::from_u64_namespace(namespace, args.key_len)?,
            keys: args.keys,
            value_size: args.value_size,
            batch_size: args.batch_size,
            concurrency: args.concurrency,
            progress_interval_secs: args.progress_interval_secs,
            ingest_retry_attempts: args.ingest_retry_attempts,
            ingest_retry_backoff_ms: args.ingest_retry_backoff_ms,
        })
    }
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    run_load(Config::try_from(args)?).await
}

async fn run_load(config: Config) -> anyhow::Result<()> {
    let Config {
        client: client_config,
        namespace,
        keyspace,
        keys: total_keys,
        value_size,
        batch_size,
        concurrency,
        progress_interval_secs,
        ingest_retry_attempts,
        ingest_retry_backoff_ms,
    } = config;

    let client = Arc::new(build_client(&client_config)?);
    let keys_loaded = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let transient_retries = Arc::new(AtomicU64::new(0));
    let last_error = Arc::new(Mutex::new(None::<String>));
    let ingest_retry_backoff = Duration::from_millis(ingest_retry_backoff_ms);
    let start = Instant::now();

    tracing::info!(
        total_keys,
        batch_size,
        concurrency,
        namespace,
        "Starting load phase"
    );

    let mut handles = Vec::new();

    // Each worker owns a contiguous key range so generated keys stay disjoint without
    // coordination. When keys < concurrency the leading workers get empty ranges and the last
    // worker covers the remainder: correct, but not fully parallel for tiny key counts.
    let keys_per_worker = total_keys / concurrency as u64;

    for worker in 0..concurrency {
        let client = client.clone();
        let keyspace = keyspace.clone();
        let keys_loaded = keys_loaded.clone();
        let errors = errors.clone();
        let transient_retries = transient_retries.clone();
        let last_error = last_error.clone();
        let start_key = worker as u64 * keys_per_worker;
        let end_key = if worker == concurrency - 1 {
            total_keys
        } else {
            start_key + keys_per_worker
        };

        handles.push(tokio::spawn(async move {
            let mut i = start_key;
            while i < end_key {
                let batch_end = std::cmp::min(i + batch_size as u64, end_key);
                let mut kvs: Vec<(Key, Vec<u8>)> = Vec::new();
                for j in i..batch_end {
                    kvs.push((
                        keyspace.inserted_key(j)?,
                        value_for_index(namespace, j, value_size),
                    ));
                }

                let refs: Vec<(&Key, &[u8])> = kvs.iter().map(|(k, v)| (k, v.as_slice())).collect();
                let label = format!("worker {worker} batch [{i}, {batch_end})");
                match ingest_with_retry(
                    &client,
                    &refs,
                    ingest_retry_attempts,
                    ingest_retry_backoff,
                    &label,
                )
                .await
                {
                    Ok(outcome) => {
                        keys_loaded.fetch_add(refs.len() as u64, Ordering::Relaxed);
                        transient_retries.fetch_add(outcome.transient_retries, Ordering::Relaxed);
                    }
                    Err(e) => {
                        tracing::debug!("{e}");
                        errors.fetch_add(1, Ordering::Relaxed);
                        *last_error.lock().expect("last_error mutex poisoned") =
                            Some(e.to_string());
                    }
                }

                i = batch_end;
            }
            Ok::<(), anyhow::Error>(())
        }));
    }

    let progress_task = if progress_interval_secs > 0 {
        let keys_loaded = keys_loaded.clone();
        let errors = errors.clone();
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(progress_interval_secs));
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                let loaded = keys_loaded.load(Ordering::Relaxed);
                if loaded >= total_keys {
                    break;
                }
                let elapsed = start.elapsed().as_secs_f64();
                let rate = if elapsed > 0.0 {
                    loaded as f64 / elapsed
                } else {
                    0.0
                };
                let pct = (loaded as f64 / total_keys as f64 * 100.0).min(100.0);
                tracing::info!(
                    keys_loaded = loaded,
                    total_keys,
                    errors = errors.load(Ordering::Relaxed),
                    elapsed_secs = %format!("{:.1}", elapsed),
                    current_keys_per_sec = rate as u64,
                    percent_complete = %format!("{:.1}", pct),
                    "Load progress"
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
    let loaded = keys_loaded.load(Ordering::Relaxed);
    let errs = errors.load(Ordering::Relaxed);
    let retries = transient_retries.load(Ordering::Relaxed);
    let failed = total_keys.saturating_sub(loaded);
    let rate = loaded as f64 / elapsed.as_secs_f64();

    tracing::info!(
        requested = total_keys,
        loaded,
        failed,
        errors = errs,
        transient_retries = retries,
        elapsed_secs = elapsed.as_secs_f64(),
        keys_per_sec = rate as u64,
        "Load phase complete"
    );

    // `load` exists to produce a complete keyspace for later benchmarking, so a short write is a
    // failure of the command's purpose, not just a counter: surface it as a non-zero exit.
    if loaded < total_keys {
        let last_error = last_error
            .lock()
            .expect("last_error mutex poisoned")
            .clone();
        anyhow::bail!(
            "load incomplete: wrote {loaded} of {total_keys} requested keys ({failed} missing) across {errs} failed ingest batches; last error: {}",
            last_error.as_deref().unwrap_or("none captured")
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_args() -> Args {
        Args {
            url: "http://localhost:10000/".to_string(),
            keys: 100,
            batch_size: 25,
            concurrency: 4,
            read_retry_attempts: 3,
            key_len: DEFAULT_KEY_LEN,
            namespace: Some(42),
            value_size: DEFAULT_VALUE_SIZE,
            progress_interval_secs: 0,
            ingest_retry_attempts: 150,
            ingest_retry_backoff_ms: 200,
        }
    }

    #[test]
    fn config_normalizes_url() {
        let config = Config::try_from(sample_args()).expect("load args should be valid");
        assert_eq!(config.client.endpoint, "http://localhost:10000");
    }

    #[test]
    fn config_uses_key_len() {
        let mut args = sample_args();
        args.key_len = 24;
        let config = Config::try_from(args).expect("load args should be valid");
        assert_eq!(config.keyspace.key_len, 24);
    }

    #[test]
    fn config_uses_namespace() {
        let config = Config::try_from(sample_args()).expect("load args should be valid");
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
    fn config_rejects_zero_batch_size() {
        let mut args = sample_args();
        args.batch_size = 0;
        assert!(Config::try_from(args).is_err());
    }

    #[test]
    fn config_rejects_zero_concurrency() {
        let mut args = sample_args();
        args.concurrency = 0;
        assert!(Config::try_from(args).is_err());
    }

    #[test]
    fn config_rejects_zero_read_retry_attempts() {
        let mut args = sample_args();
        args.read_retry_attempts = 0;
        assert!(Config::try_from(args).is_err());
    }

    #[test]
    fn config_rejects_zero_ingest_retry_attempts() {
        let mut args = sample_args();
        args.ingest_retry_attempts = 0;
        assert!(Config::try_from(args).is_err());
    }

    #[test]
    fn config_rejects_zero_ingest_retry_backoff() {
        let mut args = sample_args();
        args.ingest_retry_backoff_ms = 0;
        assert!(Config::try_from(args).is_err());
    }
}
