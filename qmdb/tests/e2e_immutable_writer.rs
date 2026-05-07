//! ImmutableWriter E2E: drive the single-writer helper against a live store
//! stack and verify the resulting roots + proofs against an independent local
//! Commonware Immutable DB fed the same ops.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;

use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::merkle::{mmr, Location};
use commonware_storage::qmdb::immutable::variable::{
    Db as Immutable, Operation as ImmutableOperation,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use exoware_qmdb::{ImmutableClient, ImmutableWriter};
use exoware_sdk::StoreClient;

use common::retry;

type Digest = commonware_cryptography::sha256::Digest;
type K = FixedBytes<32>;
type V = Vec<u8>;
type LocalDb =
    Immutable<mmr::Family, deterministic::Context, K, V, commonware_cryptography::Sha256, TwoCap>;
type TestReader = ImmutableClient<mmr::Family, commonware_cryptography::Sha256, K, V>;
type TestWriter = ImmutableWriter<mmr::Family, commonware_cryptography::Sha256, K, V>;

fn fresh_reader(c: StoreClient) -> TestReader {
    TestReader::from_client(
        c,
        ((), ((0..=10000).into(), ())),
        ((), ((0..=10000).into(), ())),
    )
}

fn fresh_writer(c: StoreClient) -> TestWriter {
    TestWriter::empty(c)
}

struct LocalReference {
    latest_location: Location<mmr::Family>,
    root: Digest,
    operations: Vec<ImmutableOperation<mmr::Family, K, V>>,
}

async fn build_local_reference(batches: Vec<Vec<(K, V)>>) -> LocalReference {
    tokio::task::spawn_blocking(move || {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::immutable_variable_config(
                "immutable-writer",
                page_cache,
                ((), ((0..=10000).into(), ())),
                NZU64!(5),
            );
            let mut db: LocalDb = LocalDb::init(context.with_label("db"), cfg)
                .await
                .expect("init");
            for batch_writes in &batches {
                let finalized = {
                    let mut batch = db.new_batch();
                    for (k, v) in batch_writes {
                        batch = batch.set(k.clone(), v.clone());
                    }
                    batch.merkleize(&db, None::<Vec<u8>>, db.inactivity_floor_loc())
                };
                db.apply_batch(finalized).await.expect("apply");
            }
            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::<mmr::Family>::new(0), n)
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
        (FixedBytes::new([0x11; 32]), b"alpha".to_vec()),
        (FixedBytes::new([0x22; 32]), b"beta".to_vec()),
    ]])
    .await;

    let writer = fresh_writer(client.clone());
    let receipt = common::commit_immutable_upload(&client, &writer, &local.operations)
        .await
        .expect("upload");
    assert_eq!(receipt.latest_location, local.latest_location);
    assert_eq!(
        receipt
            .writer_location_watermark
            .map(|checkpoint| checkpoint.location),
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
        vec![(FixedBytes::new([0x01; 32]), b"a".to_vec())],
        vec![(FixedBytes::new([0x02; 32]), b"b".to_vec())],
        vec![(FixedBytes::new([0x03; 32]), b"c".to_vec())],
    ])
    .await;

    let n = local.operations.len();
    let chunk = n / 3;
    let o1 = local.operations[..chunk].to_vec();
    let o2 = local.operations[chunk..2 * chunk].to_vec();
    let o3 = local.operations[2 * chunk..].to_vec();

    let writer = Arc::new(fresh_writer(client.clone()));

    let w1 = writer.clone();
    let w2 = writer.clone();
    let w3 = writer.clone();
    let c1 = client.clone();
    let c2 = client.clone();
    let c3 = client.clone();
    let (r1, r2, r3) = tokio::join!(
        async move { common::commit_immutable_upload(&c1, &w1, &o1).await },
        async move { common::commit_immutable_upload(&c2, &w2, &o2).await },
        async move { common::commit_immutable_upload(&c3, &w3, &o3).await }
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
