//! Immutable QMDB streaming e2e.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::immutable::{
    Config as ImmutableConfig, Immutable, Operation as ImmutableOperation,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use exoware_sdk_rs::StoreClient;
use futures::StreamExt;
use store_qmdb::ImmutableClient;

use common::retry;

type Digest = commonware_cryptography::sha256::Digest;
type LocalDb = Immutable<
    deterministic::Context,
    FixedBytes<32>,
    Vec<u8>,
    commonware_cryptography::Sha256,
    TwoCap,
>;
type TestImmutableClient =
    ImmutableClient<commonware_cryptography::Sha256, FixedBytes<32>, Vec<u8>>;

fn fresh_immutable(c: StoreClient) -> TestImmutableClient {
    TestImmutableClient::from_client(c, ((0..=10000).into(), ()), ((), ((0..=10000).into(), ())))
}

struct LocalBatch {
    latest_location: Location,
    operations: Vec<ImmutableOperation<FixedBytes<32>, Vec<u8>>>,
    root: Digest,
}

async fn build_local_batch() -> LocalBatch {
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
            let cfg = ImmutableConfig {
                mmr_journal_partition: "immutable-mmr-journal".into(),
                mmr_metadata_partition: "immutable-mmr-metadata".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                log_partition: "immutable-log".into(),
                log_items_per_section: NZU64!(5),
                log_compression: None,
                log_codec_config: ((0..=10000).into(), ()),
                log_write_buffer: NZUsize!(1024),
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };
            let mut db: LocalDb = LocalDb::init(context.with_label("db"), cfg)
                .await
                .expect("init");

            let key_a = FixedBytes::new([0x11; 32]);
            let key_b = FixedBytes::new([0x22; 32]);
            let val_a = b"alpha".to_vec();
            let val_b = b"beta".to_vec();

            let finalized = {
                let mut batch = db.new_batch();
                batch.set(key_a, val_a);
                batch.set(key_b, val_b);
                batch.merkleize(None::<Vec<u8>>).finalize()
            };
            db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");
            let root = db.root();
            db.destroy().await.expect("destroy");

            LocalBatch {
                latest_location: latest,
                operations: ops,
                root,
            }
        })
    })
    .await
    .expect("join")
}

async fn upload_and_publish(client: &TestImmutableClient, batch: &LocalBatch) {
    retry(
        || {
            let ops = batch.operations.clone();
            let loc = batch.latest_location;
            async move { client.upload_operations(loc, &ops).await.map(|_| ()) }
        },
        "upload_operations",
    )
    .await;
    retry(
        || {
            let loc = batch.latest_location;
            async move {
                client
                    .publish_writer_location_watermark(loc)
                    .await
                    .map(|_| ())
            }
        },
        "publish_watermark",
    )
    .await;
}

#[tokio::test]
async fn stream_batches_emits_verifiable_immutable_range_proof() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_batch().await;

    let ic = Arc::new(fresh_immutable(client.clone()));
    let mut stream = ic
        .clone()
        .stream_batches(None)
        .await
        .expect("stream_batches");

    tokio::time::sleep(Duration::from_millis(50)).await;
    upload_and_publish(&ic, &local).await;

    let proof = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timeout")
        .expect("stream not closed")
        .expect("proof Ok");

    assert!(proof.verify::<commonware_cryptography::Sha256>());
    assert_eq!(proof.root, local.root);
    assert_eq!(proof.operations, local.operations);
    assert_eq!(proof.watermark, local.latest_location);
}
