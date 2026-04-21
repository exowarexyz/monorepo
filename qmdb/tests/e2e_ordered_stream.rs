//! Ordered QMDB streaming e2e: upload a batch, publish watermark, observe
//! a `VerifiedOperationRange` emitted from `stream_batches`.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::any::ordered::variable::Operation as QmdbOperation;
use commonware_storage::qmdb::{
    current::{ordered::variable::Db as LocalQmdbDb, VariableConfig},
    store::LogStore as _,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_sdk_rs::StoreClient;
use futures::StreamExt;
use store_qmdb::{
    build_current_boundary_state, CurrentBoundaryState, OrderedClient, OrderedWriter,
    MAX_OPERATION_SIZE,
};

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchProof = commonware_storage::mmr::Proof<Digest>;
type BatchOperation = QmdbOperation<Vec<u8>, Vec<u8>>;
type TestOrderedClient = OrderedClient<Sha256, Vec<u8>, Vec<u8>, N>;
type LocalDb = LocalQmdbDb<cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap, N>;

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

struct LocalBatch {
    latest_location: Location,
    operations: Vec<BatchOperation>,
    current_boundary: CurrentBoundaryState<Digest, N>,
}

/// Build a local ordered DB with a two-key batch. Mirrors `e2e_ordered.rs`.
async fn build_local_batch() -> LocalBatch {
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
            let mut db: LocalDb = LocalDb::init(context.with_label("qmdb"), cfg)
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
            let (_proof, ops): (BatchProof, Vec<BatchOperation>) = db
                .ops_historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");

            let boundary = build_current_boundary_state::<Sha256, _, _, N>(None, &ops).await;

            db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            LocalBatch {
                latest_location: latest,
                operations: ops,
                current_boundary: boundary,
            }
        })
    })
    .await
    .expect("join")
}

/// Upload + publish `batch` via an OrderedWriter.
async fn upload_and_publish(client: &StoreClient, batch: &LocalBatch) {
    let writer: OrderedWriter<Sha256, Vec<u8>, Vec<u8>, N> = OrderedWriter::empty(client.clone());
    writer
        .upload_and_publish(&batch.operations, &batch.current_boundary)
        .await
        .expect("upload_and_publish");
}

#[tokio::test]
async fn stream_batches_emits_verifiable_range_proof_after_publish() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_batch().await;

    let oc = Arc::new(TestOrderedClient::from_client(
        client.clone(),
        op_cfg(),
        update_row_cfg(),
    ));
    let mut stream = oc
        .clone()
        .stream_batches(None)
        .await
        .expect("stream_batches");

    // Give the subscription time to register before ingest so the live path
    // captures our frames.
    tokio::time::sleep(Duration::from_millis(50)).await;

    upload_and_publish(&client, &local).await;

    let proof = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timeout")
        .expect("stream not closed")
        .expect("proof Ok");

    assert_eq!(proof.operations, local.operations);
    assert_eq!(proof.start_location, Location::new(0));
    assert_eq!(proof.watermark, local.latest_location);
}

#[tokio::test]
async fn stream_batches_replays_since_cursor() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_batch().await;

    let oc = Arc::new(TestOrderedClient::from_client(
        client.clone(),
        op_cfg(),
        update_row_cfg(),
    ));

    // First upload + publish the batch (no subscriber active).
    upload_and_publish(&client, &local).await;
    let seq_after = client.sequence_number();

    // Subscribe with since=1; the driver should replay the retained batch
    // (which is contained in sequence numbers 1..=seq_after) and produce a
    // proof.
    let mut stream = oc
        .clone()
        .stream_batches(Some(1))
        .await
        .expect("stream_batches");

    let proof = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timeout")
        .expect("stream not closed")
        .expect("proof Ok");

    assert_eq!(proof.operations, local.operations);
    // Ensure that the replay cursor landed within the retained log (sanity).
    assert!(seq_after > 0);
}
