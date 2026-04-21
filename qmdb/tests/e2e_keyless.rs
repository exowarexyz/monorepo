//! Keyless QMDB E2E: run a local Commonware keyless DB, upload its
//! operations to a live store stack, then verify roots and proofs match.

mod common;

use std::num::NonZeroU64;

use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::{
    keyless::{Config as KeylessConfig, Keyless, Operation as KeylessOperation},
    store::LogStore as _,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_sdk_rs::StoreClient;
use store_qmdb::{KeylessClient, KeylessWriter};

use common::retry;

type Digest = commonware_cryptography::sha256::Digest;
type LocalDb = Keyless<deterministic::Context, Vec<u8>, commonware_cryptography::Sha256>;

type TestKeylessClient = KeylessClient<commonware_cryptography::Sha256, Vec<u8>>;
type TestKeylessWriter = KeylessWriter<commonware_cryptography::Sha256, Vec<u8>>;

fn fresh_keyless(c: StoreClient) -> TestKeylessClient {
    TestKeylessClient::from_client(c, ((0..=10000).into(), ()))
}

async fn fresh_writer(c: StoreClient) -> TestKeylessWriter {
    TestKeylessWriter::new(c).await.expect("writer")
}

struct LocalReference {
    latest_location: Location,
    root: Digest,
    operations: Vec<KeylessOperation<Vec<u8>>>,
    queried_location: Location,
    queried_value: Vec<u8>,
}

async fn build_local_db() -> LocalReference {
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
                batch.append(first.clone());
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
            let queried_location = ops
                .iter()
                .enumerate()
                .find_map(|(index, operation)| {
                    (operation.clone().into_value() == Some(first.clone()))
                        .then_some(Location::new(index as u64))
                })
                .expect("value location");

            LocalReference {
                latest_location: latest,
                root,
                operations: ops,
                queried_location,
                queried_value: first,
            }
        })
    })
    .await
    .expect("join")
}

#[tokio::test]
async fn keyless_round_trip() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db().await;

    let writer = fresh_writer(client.clone()).await;
    writer
        .upload_and_publish(&local.operations)
        .await
        .expect("upload_and_publish");

    let root = retry(
        || {
            let c = fresh_keyless(client.clone());
            let loc = local.latest_location;
            async move { c.root_at(loc).await }
        },
        "root_at",
    )
    .await;
    assert_eq!(root, local.root, "remote root must match local DB root");

    let c = fresh_keyless(client.clone());
    let got: Vec<u8> = c
        .get_at(local.queried_location, local.latest_location)
        .await
        .expect("get_at")
        .expect("present");
    assert_eq!(got, local.queried_value);

    let proof = c
        .operation_range_proof(
            local.latest_location,
            Location::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("proof");
    assert_eq!(proof.root, local.root);
    assert_eq!(proof.operations, local.operations);
}
