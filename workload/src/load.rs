//! Exoware load generator.
//!
//! Usage:
//!   workload load --url http://localhost:10000 --keys 10000

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::ensure;
use exoware_sdk::keys::Key;

use crate::client::{build_client, ClientConfig};
use crate::keyspace::{Keyspace, DEFAULT_KEY_LEN};
use crate::value::default_value_for_index;

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
}

/// Validated load configuration independent of Clap.
#[derive(Debug)]
pub struct Config {
    client: ClientConfig,
    keyspace: Keyspace,
    keys: u64,
    batch_size: usize,
    concurrency: usize,
}

impl TryFrom<Args> for Config {
    type Error = anyhow::Error;

    fn try_from(args: Args) -> anyhow::Result<Self> {
        ensure!(args.batch_size > 0, "--batch-size must be > 0");
        ensure!(args.concurrency > 0, "--concurrency must be > 0");

        Ok(Self {
            client: ClientConfig::new(args.url, args.read_retry_attempts)?,
            keyspace: Keyspace::unnamespaced(args.key_len)?,
            keys: args.keys,
            batch_size: args.batch_size,
            concurrency: args.concurrency,
        })
    }
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    run_load(Config::try_from(args)?).await
}

async fn run_load(config: Config) -> anyhow::Result<()> {
    let Config {
        client: client_config,
        keyspace,
        keys: total_keys,
        batch_size,
        concurrency,
    } = config;

    let client = Arc::new(build_client(&client_config)?);
    let keys_loaded = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    tracing::info!(total_keys, batch_size, concurrency, "Starting load phase");

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
                    kvs.push((keyspace.inserted_key(j)?, default_value_for_index(j)));
                }

                let refs: Vec<(&Key, &[u8])> = kvs.iter().map(|(k, v)| (k, v.as_slice())).collect();
                match client.ingest().put(&refs).await {
                    Ok(_) => {
                        keys_loaded.fetch_add(refs.len() as u64, Ordering::Relaxed);
                    }
                    Err(e) => {
                        tracing::warn!("Ingest error: {e}");
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }

                i = batch_end;
            }
            Ok::<(), anyhow::Error>(())
        }));
    }

    for h in handles {
        h.await??;
    }

    let elapsed = start.elapsed();
    let loaded = keys_loaded.load(Ordering::Relaxed);
    let errs = errors.load(Ordering::Relaxed);
    let rate = loaded as f64 / elapsed.as_secs_f64();

    tracing::info!(
        loaded,
        errors = errs,
        elapsed_secs = elapsed.as_secs_f64(),
        keys_per_sec = rate as u64,
        "Load phase complete"
    );

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
}
