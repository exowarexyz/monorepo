//! Exoware load generator.
//!
//! Usage:
//!   validation load --url http://localhost:10000 --keys 10000

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::ensure;
use tokio::task::JoinSet;

use crate::client::{build_client, ClientArgs, ClientConfig};
use crate::exec::{join_all_or_abort, spawn_progress_task, stop_progress_task};
use crate::ingest::{ingest_with_retry, IngestRetryArgs, DEFAULT_INGEST_BATCH_SIZE};
use crate::keyspace::{default_run_namespace, Keyspace, KeyspaceArgs};
use crate::record::Record;
use crate::value::{value_for_index, DEFAULT_VALUE_SIZE};
use crate::workload::worker_index_range;

/// Load phase: insert keys via ingest API.
#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(flatten)]
    client: ClientArgs,
    #[arg(long, default_value_t = 10000)]
    keys: u64,
    #[arg(long, default_value_t = DEFAULT_INGEST_BATCH_SIZE)]
    batch_size: usize,
    #[arg(long, default_value_t = 4)]
    concurrency: usize,
    #[command(flatten)]
    keyspace: KeyspaceArgs,
    /// Size in bytes of generated values.
    #[arg(long, default_value_t = DEFAULT_VALUE_SIZE)]
    value_size: usize,
    /// Emit periodic `Load progress` logs every N seconds (0 = off).
    #[arg(long, default_value_t = 10)]
    progress_interval_secs: u64,
    #[command(flatten)]
    ingest_retry: IngestRetryArgs,
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
    ingest_retry: IngestRetryArgs,
}

impl TryFrom<Args> for Config {
    type Error = anyhow::Error;

    fn try_from(args: Args) -> anyhow::Result<Self> {
        ensure!(args.keys > 0, "--keys must be > 0");
        ensure!(args.batch_size > 0, "--batch-size must be > 0");
        ensure!(args.concurrency > 0, "--concurrency must be > 0");
        args.ingest_retry.validate()?;
        let namespace = args
            .keyspace
            .namespace
            .unwrap_or_else(|| default_run_namespace(0));

        Ok(Self {
            client: args.client.into_config()?,
            namespace,
            keyspace: Keyspace::from_u64_namespace(namespace, args.keyspace.key_len)?,
            keys: args.keys,
            value_size: args.value_size,
            batch_size: args.batch_size,
            concurrency: args.concurrency,
            progress_interval_secs: args.progress_interval_secs,
            ingest_retry: args.ingest_retry,
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
        ingest_retry,
    } = config;

    let client = Arc::new(build_client(&client_config)?);
    let keys_loaded = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let transient_retries = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    tracing::info!(
        total_keys,
        batch_size,
        concurrency,
        namespace,
        "Starting load phase"
    );

    let mut workers = JoinSet::new();

    for worker in 0..concurrency {
        let client = client.clone();
        let keyspace = keyspace.clone();
        let keys_loaded = keys_loaded.clone();
        let errors = errors.clone();
        let transient_retries = transient_retries.clone();
        let key_range = worker_index_range(total_keys, concurrency, worker)?;

        workers.spawn(async move {
            let mut last_error = None;
            let mut i = key_range.start;
            while i < key_range.end {
                let batch_end = std::cmp::min(i + batch_size as u64, key_range.end);
                let mut records = Vec::with_capacity(batch_size);
                for j in i..batch_end {
                    records.push(Record {
                        key: keyspace.inserted_key(j),
                        value: value_for_index(namespace, j, value_size),
                    });
                }

                let label = format!("worker {worker} batch [{i}, {batch_end})");
                match ingest_with_retry(
                    &client,
                    &records,
                    ingest_retry.attempts,
                    ingest_retry.backoff(),
                    &label,
                )
                .await
                {
                    Ok(outcome) => {
                        keys_loaded.fetch_add(records.len() as u64, Ordering::Relaxed);
                        transient_retries.fetch_add(outcome.transient_retries, Ordering::Relaxed);
                    }
                    Err(e) => {
                        tracing::debug!("{e}");
                        errors.fetch_add(1, Ordering::Relaxed);
                        last_error = Some(e.to_string());
                        break;
                    }
                }

                i = batch_end;
            }
            Ok::<Option<String>, anyhow::Error>(last_error)
        });
    }

    let progress_task = spawn_progress_task(
        keys_loaded.clone(),
        total_keys,
        progress_interval_secs,
        start,
        {
            let errors = errors.clone();
            move |progress| {
                tracing::info!(
                    keys_loaded = progress.done,
                    total_keys,
                    errors = errors.load(Ordering::Relaxed),
                    elapsed_secs = %format!("{:.1}", progress.elapsed_secs),
                    current_keys_per_sec = progress.per_sec as u64,
                    percent_complete = %format!("{:.1}", progress.percent),
                    "Load progress"
                );
            }
        },
    );

    let mut last_error = None;
    let workers_result = join_all_or_abort(&mut workers, "load worker", |worker_error| {
        if worker_error.is_some() {
            last_error = worker_error;
        }
    })
    .await;

    stop_progress_task(progress_task).await;
    workers_result?;

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
        anyhow::bail!(
            "load incomplete: wrote {loaded} of {total_keys} requested keys ({failed} missing) across {errs} failed ingest batches; last error: {}",
            last_error.as_deref().unwrap_or("none captured")
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::keyspace::DEFAULT_KEY_LEN;
    use axum::Router;
    use connectrpc::{ConnectError, ConnectRpcService, RequestContext};
    use exoware_sdk::ingest::{
        OwnedPutRequestView, PutResponse, Service as IngestService,
        ServiceServer as IngestServiceServer,
    };

    #[derive(Clone, Copy)]
    enum IngestFault {
        AlwaysInvalidArgument,
        AlwaysUnavailable,
        UnavailableFirst(u64),
    }

    #[derive(Clone)]
    struct IngestHarness {
        fault: IngestFault,
        puts: Arc<AtomicU64>,
    }

    #[allow(refining_impl_trait)]
    impl IngestService for IngestHarness {
        async fn put(
            &self,
            _ctx: RequestContext,
            _request: OwnedPutRequestView,
        ) -> connectrpc::ServiceResult<PutResponse> {
            let call = self.puts.fetch_add(1, Ordering::SeqCst) + 1;
            match self.fault {
                IngestFault::AlwaysInvalidArgument => {
                    Err(ConnectError::invalid_argument("put rejected"))
                }
                IngestFault::AlwaysUnavailable => Err(ConnectError::unavailable("store down")),
                IngestFault::UnavailableFirst(n) if call <= n => {
                    Err(ConnectError::unavailable("store warming up"))
                }
                IngestFault::UnavailableFirst(_) => connectrpc::Response::ok(PutResponse {
                    sequence_number: call,
                    ..Default::default()
                }),
            }
        }
    }

    async fn spawn_ingest_harness(fault: IngestFault) -> (String, Arc<AtomicU64>) {
        let puts = Arc::new(AtomicU64::new(0));
        let harness = IngestHarness {
            fault,
            puts: puts.clone(),
        };
        let connect = ConnectRpcService::new(IngestServiceServer::new(harness));
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
        (url, puts)
    }

    fn sample_args() -> Args {
        Args {
            client: ClientArgs {
                url: "http://localhost:10000/".to_string(),
                read_retry_attempts: 3,
            },
            keys: 100,
            batch_size: 25,
            concurrency: 4,
            keyspace: KeyspaceArgs {
                key_len: DEFAULT_KEY_LEN,
                namespace: Some(42),
            },
            value_size: DEFAULT_VALUE_SIZE,
            progress_interval_secs: 0,
            ingest_retry: IngestRetryArgs {
                attempts: 150,
                backoff_ms: 200,
            },
        }
    }

    #[test]
    fn config_normalizes_url() {
        let config = Config::try_from(sample_args()).expect("load args should be valid");
        assert_eq!(config.client.endpoint(), "http://localhost:10000");
    }

    #[test]
    fn config_uses_key_len() {
        let mut args = sample_args();
        args.keyspace.key_len = 24;
        let config = Config::try_from(args).expect("load args should be valid");
        assert_eq!(config.keyspace.key_len(), 24);
    }

    #[test]
    fn config_uses_namespace() {
        let config = Config::try_from(sample_args()).expect("load args should be valid");
        assert_eq!(config.namespace, 42);
        assert_eq!(
            config.keyspace.inserted_key(0),
            Keyspace::from_u64_namespace(42, DEFAULT_KEY_LEN)
                .unwrap()
                .inserted_key(0)
        );
    }

    #[test]
    fn config_rejects_zero_keys() {
        let mut args = sample_args();
        args.keys = 0;
        assert!(Config::try_from(args).is_err());
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
        args.client.read_retry_attempts = 0;
        assert!(Config::try_from(args).is_err());
    }

    #[test]
    fn config_rejects_zero_ingest_retry_attempts() {
        let mut args = sample_args();
        args.ingest_retry.attempts = 0;
        assert!(Config::try_from(args).is_err());
    }

    #[test]
    fn config_rejects_zero_ingest_retry_backoff() {
        let mut args = sample_args();
        args.ingest_retry.backoff_ms = 0;
        assert!(Config::try_from(args).is_err());
    }

    #[tokio::test]
    async fn load_reports_incomplete_without_retrying_permanent_ingest_errors() {
        let (url, puts) = spawn_ingest_harness(IngestFault::AlwaysInvalidArgument).await;
        let mut args = sample_args();
        args.client.url = url;
        args.keys = 4;
        args.batch_size = 2;
        args.concurrency = 2;
        args.ingest_retry.backoff_ms = 1;

        let err = run(args)
            .await
            .expect_err("permanent ingest failures must fail the load");
        let text = format!("{err:#}");
        assert!(text.contains("load incomplete: wrote 0 of 4"), "{text}");
        assert!(text.contains("after 1 attempt(s)"), "{text}");
        assert_eq!(
            puts.load(Ordering::SeqCst),
            2,
            "permanent errors must not be retried"
        );
    }

    #[tokio::test]
    async fn load_recovers_after_transient_ingest_failures() {
        let (url, puts) = spawn_ingest_harness(IngestFault::UnavailableFirst(3)).await;
        let mut args = sample_args();
        args.client.url = url;
        args.keys = 4;
        args.batch_size = 2;
        args.concurrency = 1;
        args.ingest_retry.attempts = 5;
        args.ingest_retry.backoff_ms = 1;

        run(args)
            .await
            .expect("load must complete after transient failures resolve");
        assert_eq!(puts.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn load_stops_after_an_exhausted_batch() {
        let (url, puts) = spawn_ingest_harness(IngestFault::AlwaysUnavailable).await;
        let mut args = sample_args();
        args.client.url = url;
        args.keys = 4;
        args.batch_size = 2;
        args.concurrency = 1;
        args.ingest_retry.attempts = 3;
        args.ingest_retry.backoff_ms = 1;

        let err = run(args)
            .await
            .expect_err("exhausted retries must fail the load");
        let text = format!("{err:#}");
        assert!(
            text.contains("after 3 attempt(s) (configured maximum: 3)"),
            "{text}"
        );
        assert_eq!(
            puts.load(Ordering::SeqCst),
            3,
            "the next batch must not start after retry exhaustion"
        );
    }
}
