//! UnorderedWriter E2E: drive the single-writer helper against a live store
//! stack and verify the resulting roots + proofs against an independent local
//! Commonware Unordered DB fed the same ops.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::any::unordered::variable::Operation as UnorderedQmdbOperation;
use commonware_storage::qmdb::{
    any::{unordered::variable::Db as LocalUnorderedDb, VariableConfig},
    store::LogStore as _,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_sdk_rs::StoreClient;
use store_qmdb::{UnorderedClient, UnorderedWriter, MAX_OPERATION_SIZE};

use common::retry;

type Digest = commonware_cryptography::sha256::Digest;
type BatchProof = commonware_storage::mmr::Proof<Digest>;
type UnorderedBatchOperation = UnorderedQmdbOperation<Vec<u8>, Vec<u8>>;
type TestReader = UnorderedClient<Sha256, Vec<u8>, Vec<u8>>;
type TestWriter = UnorderedWriter<Sha256, Vec<u8>, Vec<u8>>;
type LocalDb = LocalUnorderedDb<cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap>;

fn op_cfg() -> <UnorderedBatchOperation as commonware_codec::Read>::Cfg {
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

fn fresh_reader(c: StoreClient) -> TestReader {
    TestReader::from_client(c, op_cfg(), update_row_cfg())
}

async fn fresh_writer(c: StoreClient) -> TestWriter {
    TestWriter::new(c).await.expect("writer")
}

struct LocalReference {
    latest_location: Location,
    root: Digest,
    operations: Vec<UnorderedBatchOperation>,
}

type WriteBatch = Vec<(Vec<u8>, Option<Vec<u8>>)>;

async fn build_local_reference(batches: Vec<WriteBatch>) -> LocalReference {
    tokio::task::spawn_blocking(move || {
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
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };
            let mut db: LocalDb = LocalDb::init(context.with_label("unordered"), cfg)
                .await
                .expect("init");
            for batch_writes in &batches {
                let finalized = {
                    let mut batch = db.new_batch();
                    for (k, v) in batch_writes {
                        batch.write(k.clone(), v.clone());
                    }
                    batch.merkleize(None::<Vec<u8>>).await.expect("merkleize")
                };
                db.apply_batch(finalized.finalize()).await.expect("apply");
            }
            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (BatchProof, Vec<UnorderedBatchOperation>) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");
            let root = db.root();
            db.destroy().await.expect("destroy");
            LocalReference {
                latest_location: latest,
                root,
                operations: ops,
            }
        })
    })
    .await
    .expect("join")
}

#[tokio::test]
async fn sequential_upload_matches_local_root() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_reference(vec![vec![
        (b"alpha".to_vec(), Some(b"one".to_vec())),
        (b"beta".to_vec(), Some(b"two".to_vec())),
    ]])
    .await;

    let writer = fresh_writer(client.clone()).await;
    let receipt = writer
        .upload_and_publish(&local.operations)
        .await
        .expect("upload");
    assert_eq!(receipt.latest_location, local.latest_location);
    assert_eq!(
        receipt.writer_location_watermark,
        Some(local.latest_location)
    );

    let got_root = retry(
        || {
            let r = fresh_reader(client.clone());
            let latest = local.latest_location;
            async move { r.root_at(latest).await }
        },
        "root_at",
    )
    .await;
    assert_eq!(got_root, local.root);
}

#[tokio::test]
async fn pipelined_batches_require_flush_to_catch_up_watermark() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_reference(vec![
        vec![(b"a".to_vec(), Some(b"1".to_vec()))],
        vec![(b"b".to_vec(), Some(b"2".to_vec()))],
        vec![(b"c".to_vec(), Some(b"3".to_vec()))],
    ])
    .await;

    let n = local.operations.len();
    let chunk = n / 3;
    let o1 = local.operations[..chunk].to_vec();
    let o2 = local.operations[chunk..2 * chunk].to_vec();
    let o3 = local.operations[2 * chunk..].to_vec();

    let writer = Arc::new(fresh_writer(client.clone()).await);

    let w1 = writer.clone();
    let w2 = writer.clone();
    let w3 = writer.clone();
    let (r1, r2, r3) = tokio::join!(
        async move { w1.upload_and_publish(&o1).await },
        async move { w2.upload_and_publish(&o2).await },
        async move { w3.upload_and_publish(&o3).await }
    );
    let _ = r1.expect("b1");
    let _ = r2.expect("b2");
    let _ = r3.expect("b3");

    writer.flush().await.expect("flush");
    let got_root = retry(
        || {
            let r = fresh_reader(client.clone());
            let latest = local.latest_location;
            async move { r.root_at(latest).await }
        },
        "root_at",
    )
    .await;
    assert_eq!(got_root, local.root);
}
