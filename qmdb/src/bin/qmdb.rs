use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{routing::get, Router};
use clap::{Parser, Subcommand};
use commonware_codec::Encode;
use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::any::ordered::variable::Operation as QmdbOperation;
use commonware_storage::qmdb::{
    any::ordered::Update,
    current::{ordered::variable::Db as LocalQmdbDb, VariableConfig},
    store::LogStore as _,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_sdk_rs::StoreClient;
use store_qmdb::{
    ordered_full_connect_stack, recover_boundary_state, CurrentBoundaryState, OrderedClient,
    OrderedWriter, MAX_OPERATION_SIZE,
};
use tower_http::cors::CorsLayer;
use tracing::info;

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchOperation = QmdbOperation<Vec<u8>, Vec<u8>>;
type LocalDb = LocalQmdbDb<cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap, N>;

#[derive(Parser, Debug)]
#[command(
    name = "qmdb",
    version,
    about = "Ordered QMDB server over the store API."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Run {
        #[arg(long)]
        store_url: String,
        #[arg(long, default_value = "0.0.0.0")]
        host: IpAddr,
        #[arg(long, default_value_t = 8081)]
        port: u16,
    },
    SeedDemo {
        #[arg(long)]
        store_url: String,
    },
    SeedContinuous {
        #[arg(long)]
        store_url: String,
        #[arg(long, default_value_t = 2)]
        interval_secs: u64,
        /// Persistent directory for the local ordered-QMDB state. Reusing the
        /// same directory across restarts preserves the write log; deleting it
        /// resets the demo. Defaults to `$HOME/.exoware_qmdb_seed_continuous`.
        #[arg(long)]
        directory: Option<PathBuf>,
    },
}

struct LocalBatch {
    latest_location: Location,
    operations: Vec<BatchOperation>,
    current_boundary: CurrentBoundaryState<Digest, N>,
}

async fn health() -> &'static str {
    "ok"
}

fn op_cfg() -> <BatchOperation as commonware_codec::Read>::Cfg {
    (
        ((0..=MAX_OPERATION_SIZE).into(), ()),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    )
}

fn update_row_cfg() -> (
    <Vec<u8> as commonware_codec::Read>::Cfg,
    <Vec<u8> as commonware_codec::Read>::Cfg,
) {
    (
        ((0..=MAX_OPERATION_SIZE).into(), ()),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    )
}

async fn boundary_from_local_db(
    db: &LocalDb,
    previous_operations: Option<&[BatchOperation]>,
    operations: &[BatchOperation],
) -> CurrentBoundaryState<Digest, N> {
    recover_boundary_state::<Sha256, _, _, N, _, _>(
        previous_operations,
        operations,
        db.root(),
        |location| async move {
            let mut hasher = Sha256::default();
            let (proof, mut proof_ops, mut chunks) = db
                .range_proof(&mut hasher, location, NZU64!(1))
                .await
                .map_err(|error| {
                    store_qmdb::QmdbError::CorruptData(format!(
                        "local current range proof at {location}: {error}"
                    ))
                })?;
            proof_ops.pop().ok_or_else(|| {
                store_qmdb::QmdbError::CorruptData(format!(
                    "local current range proof at {location} returned no operations"
                ))
            })?;
            let chunk = chunks.pop().ok_or_else(|| {
                store_qmdb::QmdbError::CorruptData(format!(
                    "local current range proof at {location} returned no chunks"
                ))
            })?;
            Ok((proof.proof, chunk))
        },
    )
    .await
    .expect("recover boundary state")
}

async fn build_demo_batch() -> LocalBatch {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};

            let cfg = VariableConfig {
                mmr_journal_partition: "mmr-journal".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                mmr_metadata_partition: "mmr-metadata".into(),
                log_partition: "log".into(),
                log_write_buffer: NZUsize!(1024),
                log_compression: None,
                log_codec_config: (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                log_items_per_blob: NZU64!(8),
                grafted_mmr_metadata_partition: "grafted-metadata".into(),
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };
            let mut db: LocalDb = LocalDb::init(context.with_label("qmdb-demo"), cfg)
                .await
                .expect("init local ordered db");

            let finalized = {
                let mut batch = db.new_batch();
                batch.write(b"alpha".to_vec(), Some(b"one".to_vec()));
                batch.write(b"beta".to_vec(), Some(b"two".to_vec()));
                batch.write(b"gamma".to_vec(), Some(b"three".to_vec()));
                batch
                    .merkleize(None::<Vec<u8>>)
                    .await
                    .expect("merkleize demo batch")
            };
            db.apply_batch(finalized.finalize())
                .await
                .expect("apply demo batch");

            let latest = db.bounds().await.end - 1;
            let count = NonZeroU64::new(*latest + 1).expect("non-zero op count");
            let (_proof, ops) = db
                .ops_historical_proof(latest + 1, Location::new(0), count)
                .await
                .expect("historical proof");
            let boundary = boundary_from_local_db(&db, None, &ops).await;

            db.sync().await.expect("sync local ordered db");
            db.destroy().await.expect("destroy local ordered db");

            LocalBatch {
                latest_location: latest,
                operations: ops,
                current_boundary: boundary,
            }
        })
    })
    .await
    .expect("join demo batch task")
}

fn operation_summary(operation: &BatchOperation) -> String {
    match operation {
        BatchOperation::Update(Update {
            key,
            value,
            next_key,
        }) => format!(
            "update key={} value={} next_key={}",
            String::from_utf8_lossy(key),
            String::from_utf8_lossy(value),
            String::from_utf8_lossy(next_key),
        ),
        BatchOperation::Delete(key) => {
            format!("delete key={}", String::from_utf8_lossy(key))
        }
        other => format!("{other:?}"),
    }
}

async fn run(
    store_url: &str,
    host: IpAddr,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Arc::new(OrderedClient::<Sha256, Vec<u8>, Vec<u8>, N>::new(
        store_url,
        op_cfg(),
        update_row_cfg(),
    ));
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(ordered_full_connect_stack(client))
        .layer(CorsLayer::very_permissive());

    let addr = SocketAddr::from((host, port));
    info!(%addr, store_url, "ordered qmdb server listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn seed_demo(store_url: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let store = StoreClient::new(store_url);
    let writer = OrderedWriter::<Sha256, Vec<u8>, Vec<u8>, N>::empty(store.clone());
    let demo = build_demo_batch().await;

    writer
        .upload_and_publish(&demo.operations, &demo.current_boundary)
        .await?;

    let reader = OrderedClient::<Sha256, Vec<u8>, Vec<u8>, N>::from_client(
        store,
        op_cfg(),
        update_row_cfg(),
    );
    let historical_root = reader.root_at(demo.latest_location).await?;
    let current_root = reader.current_root_at(demo.latest_location).await?;

    println!("seeded ordered QMDB demo batch");
    println!("watermark={}", *demo.latest_location);
    println!(
        "historical_root=0x{}",
        hex::encode(historical_root.encode())
    );
    println!("current_root=0x{}", hex::encode(current_root.encode()));
    println!("operations:");
    for operation in &demo.operations {
        println!("  {}", operation_summary(operation));
    }
    Ok(())
}

fn default_seed_continuous_directory() -> PathBuf {
    let home = std::env::var("HOME").expect("$HOME is not configured");
    PathBuf::from(format!("{home}/.exoware_qmdb_seed_continuous"))
}

async fn seed_continuous(
    store_url: &str,
    interval_secs: u64,
    directory: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let directory = directory.unwrap_or_else(default_seed_continuous_directory);
    info!(
        directory = %directory.display(),
        store_url,
        interval_secs,
        "starting seed-continuous"
    );

    let store = StoreClient::new(store_url);
    let reader = OrderedClient::<Sha256, Vec<u8>, Vec<u8>, N>::from_client(
        store.clone(),
        op_cfg(),
        update_row_cfg(),
    );

    tokio::task::spawn_blocking(move || {
        let runner_cfg = cw_tokio::Config::new().with_storage_directory(directory);
        cw_tokio::Runner::new(runner_cfg).start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};

            let cfg = VariableConfig {
                mmr_journal_partition: "mmr-journal".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                mmr_metadata_partition: "mmr-metadata".into(),
                log_partition: "log".into(),
                log_write_buffer: NZUsize!(1024),
                log_compression: None,
                log_codec_config: (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                log_items_per_blob: NZU64!(8),
                grafted_mmr_metadata_partition: "grafted-metadata".into(),
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };
            let mut db: LocalDb = LocalDb::init(context.with_label("qmdb-continuous"), cfg)
                .await
                .expect("init local ordered db");

            let bounds = db.bounds().await;
            let (mut previous_ops, mut counter, writer) = if *bounds.end == 0 {
                info!("starting from empty local DB");
                let writer = OrderedWriter::<Sha256, Vec<u8>, Vec<u8>, N>::empty(store);
                (Vec::<BatchOperation>::new(), 0u64, writer)
            } else {
                let latest = bounds.end - 1;
                let count = NonZeroU64::new(*latest + 1).expect("non-zero op count");
                let (proof, cumulative) = db
                    .ops_historical_proof(latest + 1, Location::new(0), count)
                    .await
                    .expect(
                        "resume: failed to load cumulative ops from local DB; \
                             delete the directory to reset",
                    );
                let commit_count = cumulative
                    .iter()
                    .filter(|op| matches!(op, BatchOperation::CommitFloor(_, _)))
                    .count();
                let batches_so_far = (commit_count as u64).saturating_sub(1);
                let counter = batches_so_far * 3;
                let writer_state = store_qmdb::WriterState::from_proof::<Sha256, _>(
                    latest,
                    Location::new(0),
                    &proof,
                    &cumulative,
                )
                .expect("resume: reconstruct writer state");
                info!(
                    watermark = *latest,
                    batches = batches_so_far,
                    next_key_index = counter,
                    "resuming from persisted local DB",
                );
                let writer = OrderedWriter::<Sha256, Vec<u8>, Vec<u8>, N>::new(store, writer_state);
                (cumulative, counter, writer)
            };

            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    biased;
                    _ = tokio::signal::ctrl_c() => {
                        info!("ctrl-c received, shutting down");
                        break;
                    }
                    _ = ticker.tick() => {}
                }

                let finalized = {
                    let mut batch = db.new_batch();
                    for offset in 0..3u64 {
                        let key = format!("k-{:08x}", counter + offset).into_bytes();
                        let value = format!("v-{:08x}", counter + offset).into_bytes();
                        batch.write(key, Some(value));
                    }
                    if counter >= 3 {
                        let rewrite_key = format!("k-{:08x}", counter - 3).into_bytes();
                        let rewrite_value = format!("v-{:08x}-r", counter).into_bytes();
                        batch.write(rewrite_key, Some(rewrite_value));
                    }
                    if counter >= 6 && counter.is_multiple_of(12) {
                        let delete_key = format!("k-{:08x}", counter - 6).into_bytes();
                        batch.write(delete_key, None);
                    }
                    counter += 3;
                    batch.merkleize(None::<Vec<u8>>).await.expect("merkleize")
                };
                db.apply_batch(finalized.finalize())
                    .await
                    .expect("apply batch");

                let latest = db.bounds().await.end - 1;
                let count = NonZeroU64::new(*latest + 1).expect("non-zero op count");
                let (_proof, cumulative_ops) = db
                    .ops_historical_proof(latest + 1, Location::new(0), count)
                    .await
                    .expect("historical proof");
                let previous_slice = if previous_ops.is_empty() {
                    None
                } else {
                    Some(previous_ops.as_slice())
                };
                let boundary = boundary_from_local_db(&db, previous_slice, &cumulative_ops).await;
                let delta = &cumulative_ops[previous_ops.len()..];

                writer
                    .upload_and_publish(delta, &boundary)
                    .await
                    .expect("upload_and_publish");

                let historical_root = reader.root_at(latest).await.expect("historical root");
                let current_root = reader.current_root_at(latest).await.expect("current root");
                println!(
                    "watermark={} current_root=0x{} historical_root=0x{}",
                    *latest,
                    hex::encode(current_root.encode()),
                    hex::encode(historical_root.encode()),
                );

                previous_ops = cumulative_ops;
            }

            db.sync().await.expect("sync local ordered db");
        })
    })
    .await?;
    Ok(())
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    init_tracing();
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Run {
            store_url,
            host,
            port,
        } => run(&store_url, host, port).await,
        Command::SeedDemo { store_url } => seed_demo(&store_url).await,
        Command::SeedContinuous {
            store_url,
            interval_secs,
            directory,
        } => seed_continuous(&store_url, interval_secs, directory).await,
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("qmdb failed: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}
