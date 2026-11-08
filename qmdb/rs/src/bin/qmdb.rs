use axum::{routing::get, serve::ListenerExt, Router};
use clap::{Parser, Subcommand};
use commonware_codec::Encode;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_parallel::Sequential;
use commonware_runtime::{
    buffer::paged::CacheRef, tokio as cw_tokio, Runner as _, Supervisor as _,
};
use commonware_storage::{
    journal::contiguous::variable::Config as JournalConfig,
    merkle::{full::Config as MerkleConfig, mmb, Location},
    qmdb::{
        any::ordered::{variable::Operation as VariableOperation, Update},
        current::ordered::variable::{
            Config as CurrentOrderedVariableConfig, Db as CurrentOrderedVariableDb,
        },
        value::VariableEncoding,
    },
    translator::TwoCap,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::{
    adapter::upload::{
        prepare_publication, stage_authenticated_range, stage_watermark, Publication,
    },
    MAX_OPERATION_SIZE,
};
use exoware_sdk::{
    transport::set_tcp_nodelay, PreferZstdLayer, PrefixedStoreClient, StoreClient, StoreKeyPrefix,
    StoreWriteBatch,
};
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU64,
    path::PathBuf,
};
use tower_http::cors::CorsLayer;
use tracing::info;

const N: usize = 32;
type Family = mmb::Family;
type Operation = VariableOperation<Family, Vec<u8>, Vec<u8>>;
type Db = CurrentOrderedVariableDb<
    Family,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    N,
    Sequential,
>;

/// A publication of the seed's source database.
type SourcePublication = Publication<Family, Digest, Update<Vec<u8>, VariableEncoding<Vec<u8>>>, N>;

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
        #[arg(long, default_value = "")]
        store_prefix: String,
        #[arg(long, default_value = "0.0.0.0")]
        host: IpAddr,
        #[arg(long, default_value_t = 8081)]
        port: u16,
    },
    Seed {
        #[arg(long)]
        store_url: String,
        #[arg(long, default_value = "")]
        store_prefix: String,
        #[arg(long, default_value_t = 2)]
        interval_secs: u64,
        /// Directory for the local ordered-QMDB state. Reuse it to resume the
        /// same Store prefix after a restart, and use a fresh one for a reset
        /// Store or a different `--store-prefix`.
        #[arg(long)]
        directory: PathBuf,
    },
}

async fn health() -> &'static str {
    "ok"
}

/// Upload a publication of the source database and publish its final location.
async fn upload(
    store_client: &PrefixedStoreClient,
    publication: &SourcePublication,
    trusted_root: &Digest,
) -> Location<Family> {
    let prepared =
        prepare_publication::<Family, Sha256, _, _, N>(publication, trusted_root, &Sequential)
            .expect("publication must verify against the source root");
    let latest = prepared.latest_location();
    let mut rows = StoreWriteBatch::new();
    stage_authenticated_range(store_client, prepared, &mut rows)
        .expect("staging the publication must succeed");
    stage_watermark(store_client, latest, &mut rows).expect("staging the watermark must succeed");
    rows.commit(store_client.client())
        .await
        .expect("publication upload must succeed");
    latest
}

fn op_cfg() -> <Operation as commonware_codec::Read>::Cfg {
    (
        ((0..=MAX_OPERATION_SIZE).into(), ()),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    )
}

fn key_cfg() -> <Vec<u8> as commonware_codec::Read>::Cfg {
    ((0..=MAX_OPERATION_SIZE).into(), ())
}

async fn run(
    store_url: &str,
    store_prefix: String,
    host: IpAddr,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let store = StoreClient::new(store_url).prefixed(StoreKeyPrefix::new(store_prefix)?);
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(exoware_qmdb::service::server::ordered_stack::<
            Family,
            Sha256,
            Vec<u8>,
            Vec<u8>,
            N,
            VariableEncoding<Vec<u8>>,
        >(store, op_cfg(), key_cfg()))
        .layer(PreferZstdLayer)
        .layer(CorsLayer::very_permissive());

    let addr = SocketAddr::from((host, port));
    info!(%addr, store_url, "ordered qmdb server listening");
    let listener = tokio::net::TcpListener::bind(addr)
        .await?
        .tap_io(set_tcp_nodelay);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn seed(
    store_url: &str,
    store_prefix: String,
    interval_secs: u64,
    directory: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(
        directory = %directory.display(),
        store_url,
        interval_secs,
        "starting seed"
    );

    let store_client = StoreClient::new(store_url).prefixed(StoreKeyPrefix::new(store_prefix)?);

    tokio::task::spawn_blocking(move || {
        let runner_cfg = cw_tokio::Config::new().with_storage_directory(directory);
        cw_tokio::Runner::new(runner_cfg).start(|context| async move {
            let page_cache = CacheRef::new(NZU16!(64), NZUsize!(8));
            let cfg = CurrentOrderedVariableConfig {
                merkle: MerkleConfig {
                    journal_partition: "current-ordered-variable-mmb-seed-merkle-journal".into(),
                    metadata_partition: "current-ordered-variable-mmb-seed-merkle-metadata".into(),
                    items_per_blob: NZU64!(8),
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                    strategy: Sequential,
                    page_cache: page_cache.clone(),
                },
                log: JournalConfig {
                    partition: "current-ordered-variable-mmb-seed-log".into(),
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                    compression: None,
                    codec_config: (
                        ((0..=MAX_OPERATION_SIZE).into(), ()),
                        ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ),
                    items_per_section: NZU64!(8),
                    page_cache,
                },
                grafted_metadata_partition: "current-ordered-variable-mmb-seed-grafted-metadata"
                    .into(),
                translator: TwoCap,
                init_cache: None,
                init_buffer: NZUsize!(1 << 21),
                init_concurrency: (),
            };
            let mut source_db = Db::init(
                context.child("current_ordered_variable_mmb_seed"),
                cfg,
                None,
            )
            .await
            .expect("init local ordered db");

            // A new database's initial commit belongs to no batch, so upload its publication
            // before the first batch.
            let end = source_db.bounds().end;
            if end == Location::new(1) {
                let initial = Publication::initial(&source_db)
                    .expect("a new database must have an initial publication");
                upload(&store_client, &initial, &source_db.root()).await;
            }

            // Resume the key counter from the number of applied batches.
            let (_, operations) = source_db
                .ops_historical_proof(
                    end,
                    Location::new(0),
                    NonZeroU64::new(*end).expect("initial commit"),
                )
                .await
                .expect("read local operation history");
            let committed_batches = operations
                .iter()
                .filter(|operation| matches!(operation, Operation::CommitFloor(_, _)))
                .count()
                .saturating_sub(1) as u64;
            let mut counter = committed_batches * 3;
            info!(
                tip = *end - 1,
                batches = committed_batches,
                "local source opened"
            );

            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            // Keep the signal listener registered while each batch is written and uploaded.
            let shutdown = tokio::signal::ctrl_c();
            tokio::pin!(shutdown);
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown => {
                        info!("ctrl-c received, shutting down");
                        break;
                    }
                    _ = ticker.tick() => {}
                }

                let finalized = {
                    let mut batch = source_db.new_batch();
                    for offset in 0..3u64 {
                        let key = format!("k-{:08x}", counter + offset).into_bytes();
                        let value = format!("v-{:08x}", counter + offset).into_bytes();
                        batch = batch.write(key, Some(value));
                    }
                    if counter >= 3 {
                        let rewrite_key = format!("k-{:08x}", counter - 3).into_bytes();
                        let rewrite_value = format!("v-{:08x}-r", counter).into_bytes();
                        batch = batch.write(rewrite_key, Some(rewrite_value));
                    }
                    if counter >= 6 && counter.is_multiple_of(12) {
                        let delete_key = format!("k-{:08x}", counter - 6).into_bytes();
                        batch = batch.write(delete_key, None);
                    }
                    counter += 3;
                    batch.merkleize(&source_db).await.expect("merkleize")
                };

                // Upload each batch before applying it, so every applied batch is already
                // published. A batch depends only on how many batches came before it, so a batch
                // uploaded before an interrupted apply is rebuilt identically after a restart.
                let publication = Publication::read(&finalized, &source_db)
                    .expect("batch publication must be readable before apply");
                let latest = upload(&store_client, &publication, &finalized.root()).await;

                source_db = source_db.apply_batch(finalized).await.expect("apply batch");
                source_db = source_db.sync().await.expect("sync local ordered db");
                println!(
                    "tip={} root=0x{}",
                    *latest,
                    hex::encode(publication.root.encode())
                );
            }

            source_db.sync().await.expect("sync local ordered db");
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
            store_prefix,
            host,
            port,
        } => run(&store_url, store_prefix, host, port).await,
        Command::Seed {
            store_url,
            store_prefix,
            interval_secs,
            directory,
        } => seed(&store_url, store_prefix, interval_secs, directory).await,
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("qmdb failed: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}
