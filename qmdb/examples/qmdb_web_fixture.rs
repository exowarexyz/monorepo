use std::num::NonZeroU64;

use commonware_codec::FixedSize;
use commonware_cryptography::Sha256;
use commonware_runtime::{deterministic, tokio as cw_tokio, Runner as _};
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::{
    any::{
        ordered::variable::Operation as OrderedOperation,
        unordered::variable::{Db as LocalUnorderedDb, Operation as UnorderedOperation},
        VariableConfig as AnyVariableConfig,
    },
    current::{ordered::variable::Db as LocalOrderedDb, VariableConfig as OrderedVariableConfig},
    immutable::{Config as ImmutableConfig, Immutable, Operation as ImmutableOperation},
    keyless::{Config as KeylessConfig, Keyless, Operation as KeylessOperation},
    store::LogStore as _,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{sequence::FixedBytes, NZU16, NZU64, NZUsize};
use exoware_sdk_rs::StoreClient;
use store_qmdb::{
    recover_boundary_state, test_utils, CurrentBoundaryState, ImmutableClient, ImmutableWriter,
    KeylessWriter, OperationRangeCheckpoint, OrderedWriter, UnorderedWriter, MAX_OPERATION_SIZE,
};

const ORDERED_BOUNDARY_BYTES: usize = 32;

type Digest = commonware_cryptography::sha256::Digest;
type OrderedBatchOperation = OrderedOperation<Vec<u8>, Vec<u8>>;
type UnorderedBatchOperation = UnorderedOperation<Vec<u8>, Vec<u8>>;
type ImmutableBatchOperation = ImmutableOperation<FixedBytes<20>, Vec<u8>>;
type KeylessBatchOperation = KeylessOperation<Vec<u8>>;
type OrderedLocalDb =
    LocalOrderedDb<cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap, ORDERED_BOUNDARY_BYTES>;
type UnorderedLocalDb = LocalUnorderedDb<cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap>;
type ImmutableLocalDb =
    Immutable<deterministic::Context, FixedBytes<20>, Vec<u8>, Sha256, TwoCap>;
type KeylessLocalDb = Keyless<deterministic::Context, Vec<u8>, Sha256>;

struct OrderedBatch {
    latest_location: Location,
    operations: Vec<OrderedBatchOperation>,
    current_boundary: CurrentBoundaryState<Digest, ORDERED_BOUNDARY_BYTES>,
}

struct UnorderedBatch {
    latest_location: Location,
    operations: Vec<UnorderedBatchOperation>,
}

struct ImmutableBatch {
    latest_location: Location,
    operations: Vec<ImmutableBatchOperation>,
    primary_key: FixedBytes<20>,
}

struct KeylessBatch {
    latest_location: Location,
    operations: Vec<KeylessBatchOperation>,
}

fn parse_args() -> Result<(String, String), String> {
    let mut base_url = None;
    let mut command = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--base-url" => {
                base_url = args.next();
            }
            other => {
                if command.is_some() {
                    return Err(format!("unexpected extra argument: {other}"));
                }
                command = Some(other.to_string());
            }
        }
    }

    Ok((
        base_url.ok_or_else(|| "--base-url is required".to_string())?,
        command.ok_or_else(|| "command is required".to_string())?,
    ))
}

fn line(key: &str, value: impl std::fmt::Display) {
    println!("{key}={value}");
}

fn value_cfg() -> <Vec<u8> as commonware_codec::Read>::Cfg {
    ((0..=MAX_OPERATION_SIZE).into(), ())
}

fn kv_cfg() -> (
    <Vec<u8> as commonware_codec::Read>::Cfg,
    <Vec<u8> as commonware_codec::Read>::Cfg,
) {
    (
        ((0..=MAX_OPERATION_SIZE).into(), ()),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    )
}

async fn ordered_boundary_from_local_db(
    db: &OrderedLocalDb,
    operations: &[OrderedBatchOperation],
) -> CurrentBoundaryState<Digest, ORDERED_BOUNDARY_BYTES> {
    recover_boundary_state::<Sha256, _, _, ORDERED_BOUNDARY_BYTES, _, _>(
        None,
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
    .expect("recover_boundary_state")
}

async fn build_ordered_batch() -> OrderedBatch {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};

            let cfg = OrderedVariableConfig {
                mmr_journal_partition: "qmdb-web-ordered-mmr-journal".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                mmr_metadata_partition: "qmdb-web-ordered-mmr-metadata".into(),
                log_partition: "qmdb-web-ordered-log".into(),
                log_write_buffer: NZUsize!(1024),
                log_compression: None,
                log_codec_config: kv_cfg(),
                log_items_per_blob: NZU64!(8),
                grafted_mmr_metadata_partition: "qmdb-web-ordered-grafted-metadata".into(),
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };

            let mut db: OrderedLocalDb = OrderedLocalDb::init(context.with_label("ordered"), cfg)
                .await
                .expect("init");

            let finalized = {
                let mut batch = db.new_batch();
                batch.write(b"alpha".to_vec(), Some(b"one".to_vec()));
                batch.write(b"beta".to_vec(), Some(b"two".to_vec()));
                batch.merkleize(None::<Vec<u8>>).await.expect("merkleize")
            };
            db.apply_batch(finalized.finalize()).await.expect("apply");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .ops_historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");
            let current_boundary = ordered_boundary_from_local_db(&db, &ops).await;

            db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            OrderedBatch {
                latest_location: latest,
                operations: ops,
                current_boundary,
            }
        })
    })
    .await
    .expect("join")
}

async fn build_unordered_batch() -> UnorderedBatch {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};

            let cfg = AnyVariableConfig {
                mmr_journal_partition: "qmdb-web-unordered-mmr-journal".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                mmr_metadata_partition: "qmdb-web-unordered-mmr-metadata".into(),
                log_partition: "qmdb-web-unordered-log".into(),
                log_write_buffer: NZUsize!(1024),
                log_compression: None,
                log_codec_config: kv_cfg(),
                log_items_per_blob: NZU64!(8),
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };

            let mut db: UnorderedLocalDb = UnorderedLocalDb::init(context.with_label("unordered"), cfg)
                .await
                .expect("init");

            let finalized = {
                let mut batch = db.new_batch();
                batch.write(b"alpha".to_vec(), Some(b"one".to_vec()));
                batch.write(b"beta".to_vec(), Some(b"two".to_vec()));
                batch.merkleize(None::<Vec<u8>>).await.expect("merkleize")
            };
            db.apply_batch(finalized.finalize()).await.expect("apply");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");

            db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            UnorderedBatch {
                latest_location: latest,
                operations: ops,
            }
        })
    })
    .await
    .expect("join")
}

async fn build_immutable_batch() -> ImmutableBatch {
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};

            let cfg = ImmutableConfig {
                mmr_journal_partition: "qmdb-web-immutable-mmr-journal".into(),
                mmr_metadata_partition: "qmdb-web-immutable-mmr-metadata".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                log_partition: "qmdb-web-immutable-log".into(),
                log_items_per_section: NZU64!(5),
                log_compression: None,
                log_codec_config: value_cfg(),
                log_write_buffer: NZUsize!(1024),
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };

            let mut db: ImmutableLocalDb = ImmutableLocalDb::init(context.with_label("immutable"), cfg)
                .await
                .expect("init");

            let key_a = FixedBytes::new([0x11; 20]);
            let key_b = FixedBytes::new([0x22; 20]);
            let finalized = {
                let mut batch = db.new_batch();
                batch.set(key_a.clone(), b"alpha".to_vec());
                batch.set(key_b, b"beta".to_vec());
                batch.merkleize(None::<Vec<u8>>).finalize()
            };
            db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");

            db.destroy().await.expect("destroy");

            ImmutableBatch {
                latest_location: latest,
                operations: ops,
                primary_key: key_a,
            }
        })
    })
    .await
    .expect("join")
}

async fn build_tampered_immutable_batch() -> ImmutableBatch {
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};

            let cfg = ImmutableConfig {
                mmr_journal_partition: "qmdb-web-immutable-tampered-mmr-journal".into(),
                mmr_metadata_partition: "qmdb-web-immutable-tampered-mmr-metadata".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                log_partition: "qmdb-web-immutable-tampered-log".into(),
                log_items_per_section: NZU64!(5),
                log_compression: None,
                log_codec_config: value_cfg(),
                log_write_buffer: NZUsize!(1024),
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };

            let mut db: ImmutableLocalDb = ImmutableLocalDb::init(
                context.with_label("immutable_tampered"),
                cfg,
            )
            .await
            .expect("init");

            let key_a = FixedBytes::new([0x33; 20]);
            let key_b = FixedBytes::new([0x44; 20]);
            let finalized = {
                let mut batch = db.new_batch();
                batch.set(key_a.clone(), b"tampered-alpha".to_vec());
                batch.set(key_b, b"tampered-beta".to_vec());
                batch.merkleize(None::<Vec<u8>>).finalize()
            };
            db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");

            db.destroy().await.expect("destroy");

            ImmutableBatch {
                latest_location: latest,
                operations: ops,
                primary_key: key_a,
            }
        })
    })
    .await
    .expect("join")
}

async fn build_keyless_batch() -> KeylessBatch {
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};

            let cfg = KeylessConfig {
                mmr_journal_partition: "qmdb-web-keyless-mmr-journal".into(),
                mmr_metadata_partition: "qmdb-web-keyless-mmr-metadata".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                log_partition: "qmdb-web-keyless-log".into(),
                log_write_buffer: NZUsize!(1024),
                log_compression: None,
                log_codec_config: value_cfg(),
                log_items_per_section: NZU64!(7),
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };

            let mut db: KeylessLocalDb = KeylessLocalDb::init(context.with_label("keyless"), cfg)
                .await
                .expect("init");

            let finalized = {
                let mut batch = db.new_batch();
                batch.append(b"first-value".to_vec());
                batch.append(b"second-value".to_vec());
                batch.merkleize(None::<Vec<u8>>).finalize()
            };
            db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");

            db.destroy().await.expect("destroy");

            KeylessBatch {
                latest_location: latest,
                operations: ops,
            }
        })
    })
    .await
    .expect("join")
}

fn start_location(latest_location: Location, operation_count: usize) -> u64 {
    latest_location
        .as_u64()
        .checked_add(1)
        .expect("location overflow")
        .checked_sub(operation_count as u64)
        .expect("batch start underflow")
}

async fn seed_all(base_url: &str) {
    let client = StoreClient::with_split_urls(base_url, base_url, base_url, base_url);

    let ordered = build_ordered_batch().await;
    OrderedWriter::<Sha256, Vec<u8>, Vec<u8>, ORDERED_BOUNDARY_BYTES>::empty(client.clone())
        .upload_and_publish(&ordered.operations, &ordered.current_boundary)
        .await
        .expect("upload ordered");

    let unordered = build_unordered_batch().await;
    UnorderedWriter::<Sha256, Vec<u8>, Vec<u8>>::empty(client.clone())
        .upload_and_publish(&unordered.operations)
        .await
        .expect("upload unordered");

    let immutable = build_immutable_batch().await;
    ImmutableWriter::<Sha256, FixedBytes<20>, Vec<u8>>::empty(client.clone())
        .upload_and_publish(&immutable.operations)
        .await
        .expect("upload immutable");

    let keyless = build_keyless_batch().await;
    KeylessWriter::<Sha256, Vec<u8>>::empty(client.clone())
        .upload_and_publish(&keyless.operations)
        .await
        .expect("upload keyless");

    line(
        "ordered_watermark",
        ordered.latest_location.as_u64(),
    );
    line(
        "ordered_start_location",
        start_location(ordered.latest_location, ordered.operations.len()),
    );
    line(
        "unordered_watermark",
        unordered.latest_location.as_u64(),
    );
    line(
        "unordered_start_location",
        start_location(unordered.latest_location, unordered.operations.len()),
    );
    line(
        "immutable_watermark",
        immutable.latest_location.as_u64(),
    );
    line(
        "immutable_start_location",
        start_location(immutable.latest_location, immutable.operations.len()),
    );
    line("immutable_key_hex", hex::encode(immutable.primary_key.as_ref()));
    line(
        "keyless_watermark",
        keyless.latest_location.as_u64(),
    );
    line(
        "keyless_start_location",
        start_location(keyless.latest_location, keyless.operations.len()),
    );
}

async fn seed_ordered(base_url: &str) {
    let client = StoreClient::with_split_urls(base_url, base_url, base_url, base_url);
    let ordered = build_ordered_batch().await;
    OrderedWriter::<Sha256, Vec<u8>, Vec<u8>, ORDERED_BOUNDARY_BYTES>::empty(client)
        .upload_and_publish(&ordered.operations, &ordered.current_boundary)
        .await
        .expect("upload ordered");

    line("ordered_watermark", ordered.latest_location.as_u64());
    line(
        "ordered_start_location",
        start_location(ordered.latest_location, ordered.operations.len()),
    );
}

async fn seed_unordered(base_url: &str) {
    let client = StoreClient::with_split_urls(base_url, base_url, base_url, base_url);
    let unordered = build_unordered_batch().await;
    UnorderedWriter::<Sha256, Vec<u8>, Vec<u8>>::empty(client)
        .upload_and_publish(&unordered.operations)
        .await
        .expect("upload unordered");

    line("unordered_watermark", unordered.latest_location.as_u64());
    line(
        "unordered_start_location",
        start_location(unordered.latest_location, unordered.operations.len()),
    );
}

async fn seed_immutable(base_url: &str) {
    let client = StoreClient::with_split_urls(base_url, base_url, base_url, base_url);
    let immutable = build_immutable_batch().await;
    ImmutableWriter::<Sha256, FixedBytes<20>, Vec<u8>>::empty(client)
        .upload_and_publish(&immutable.operations)
        .await
        .expect("upload immutable");

    line("immutable_watermark", immutable.latest_location.as_u64());
    line(
        "immutable_start_location",
        start_location(immutable.latest_location, immutable.operations.len()),
    );
    line("immutable_key_hex", hex::encode(immutable.primary_key.as_ref()));
}

async fn seed_keyless(base_url: &str) {
    let client = StoreClient::with_split_urls(base_url, base_url, base_url, base_url);
    let keyless = build_keyless_batch().await;
    KeylessWriter::<Sha256, Vec<u8>>::empty(client)
        .upload_and_publish(&keyless.operations)
        .await
        .expect("upload keyless");

    line("keyless_watermark", keyless.latest_location.as_u64());
    line(
        "keyless_start_location",
        start_location(keyless.latest_location, keyless.operations.len()),
    );
}

async fn tamper_immutable(base_url: &str) {
    let client = StoreClient::with_split_urls(base_url, base_url, base_url, base_url);

    let immutable = build_tampered_immutable_batch().await;
    ImmutableWriter::<Sha256, FixedBytes<20>, Vec<u8>>::empty(client.clone())
        .upload_and_publish(&immutable.operations)
        .await
        .expect("upload immutable");

    let reader: ImmutableClient<Sha256, FixedBytes<20>, Vec<u8>> =
        ImmutableClient::from_client(client.clone(), value_cfg(), ((), value_cfg()));
    let watermark = reader
        .writer_location_watermark()
        .await
        .expect("writer watermark")
        .expect("published watermark");
    let batch_start = Location::new(start_location(watermark, immutable.operations.len()));
    let checkpoint: OperationRangeCheckpoint<Digest> = reader
        .operation_range_checkpoint(watermark, batch_start, immutable.operations.len() as u32)
        .await
        .expect("checkpoint");
    let (peak_pos, _, _) = checkpoint
        .reconstruct_peaks::<Sha256>()
        .expect("reconstruct peaks")
        .into_iter()
        .next()
        .expect("peak");
    let key = test_utils::encode_immutable_auth_node_key(peak_pos);
    let bad_value = vec![0xAA; Digest::SIZE];
    client
        .ingest()
        .put(&[(&key, bad_value.as_slice())])
        .await
        .expect("tamper put");

    line("immutable_watermark", watermark.as_u64());
    line("immutable_start_location", batch_start.as_u64());
    line("immutable_key_hex", hex::encode(immutable.primary_key.as_ref()));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (base_url, command) = parse_args().map_err(|e| format!("argument error: {e}"))?;

    match command.as_str() {
        "seed-all" => seed_all(&base_url).await,
        "seed-ordered" => seed_ordered(&base_url).await,
        "seed-unordered" => seed_unordered(&base_url).await,
        "seed-immutable" => seed_immutable(&base_url).await,
        "seed-keyless" => seed_keyless(&base_url).await,
        "tamper-immutable" => tamper_immutable(&base_url).await,
        other => return Err(format!("unknown command: {other}").into()),
    }

    Ok(())
}
