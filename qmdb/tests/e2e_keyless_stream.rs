//! Keyless QMDB streaming e2e.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::{
    keyless::{Config as KeylessConfig, Keyless, Operation as KeylessOperation},
    store::LogStore as _,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_sdk_rs::StoreClient;
use futures::StreamExt;
use store_qmdb::{KeylessClient, KeylessWriter};

type Digest = commonware_cryptography::sha256::Digest;
type LocalDb = Keyless<deterministic::Context, Vec<u8>, commonware_cryptography::Sha256>;
type TestKeylessClient = KeylessClient<commonware_cryptography::Sha256, Vec<u8>>;

fn fresh_keyless(c: StoreClient) -> TestKeylessClient {
    TestKeylessClient::from_client(c, ((0..=10000).into(), ()))
}

struct LocalBatch {
    latest_location: Location,
    operations: Vec<KeylessOperation<Vec<u8>>>,
    root: Digest,
}

async fn build_local_batch() -> LocalBatch {
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
            let cfg = KeylessConfig {
                mmr_journal_partition: "keyless-mmr-journal".into(),
                mmr_metadata_partition: "keyless-mmr-metadata".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                log_partition: "keyless-log".into(),
                log_write_buffer: NZUsize!(1024),
                log_compression: None,
                log_codec_config: ((0..=10000).into(), ()),
                log_items_per_section: NZU64!(7),
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };
            let mut db: LocalDb = LocalDb::init(context.with_label("db"), cfg)
                .await
                .expect("init");

            let first = b"first-value".to_vec();
            let second = b"second-value".to_vec();
            let finalized = {
                let mut batch = db.new_batch();
                batch.append(first);
                batch.append(second);
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

async fn upload_and_publish(client: &StoreClient, batch: &LocalBatch) {
    let writer: KeylessWriter<commonware_cryptography::Sha256, Vec<u8>> =
        KeylessWriter::empty(client.clone());
    writer
        .upload_and_publish(&batch.operations)
        .await
        .expect("upload_and_publish");
}

#[tokio::test]
async fn stream_batches_emits_verifiable_keyless_range_proof() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_batch().await;

    let kc = Arc::new(fresh_keyless(client.clone()));
    let mut stream = kc
        .clone()
        .stream_batches(None)
        .await
        .expect("stream_batches");

    tokio::time::sleep(Duration::from_millis(50)).await;
    upload_and_publish(&client, &local).await;

    let proof = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timeout")
        .expect("stream not closed")
        .expect("proof Ok");

    assert_eq!(proof.root, local.root);
    assert_eq!(proof.operations, local.operations);
    assert_eq!(proof.watermark, local.latest_location);
}
