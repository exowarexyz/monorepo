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
use exoware_sdk::{PrefixedStoreClient, StoreClient};

use common::retry;

type Digest = commonware_cryptography::sha256::Digest;
type K = FixedBytes<32>;
type V = Vec<u8>;
type LocalDb = Immutable<
    mmr::Family,
    deterministic::Context,
    K,
    V,
    commonware_cryptography::Sha256,
    TwoCap,
    commonware_parallel::Sequential,
>;
type TestReader = ImmutableClient<mmr::Family, commonware_cryptography::Sha256, K, V>;
type TestWriter = ImmutableWriter<mmr::Family, commonware_cryptography::Sha256, K, V>;

fn fresh_reader(c: StoreClient) -> TestReader {
    TestReader::new(
        PrefixedStoreClient::empty(c),
        ((), ((0..=10000).into(), ())),
    )
}

fn fresh_writer(c: StoreClient) -> TestWriter {
    TestWriter::fresh(PrefixedStoreClient::empty(c))
}

struct LocalReference {
    latest_location: Location<mmr::Family>,
    root: Digest,
    operations: Vec<ImmutableOperation<mmr::Family, K, V>>,
}

async fn build_local_reference(batches: Vec<Vec<(K, V)>>) -> LocalReference {
    tokio::task::spawn_blocking(move || {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::immutable_variable_config(
                "immutable-writer",
                page_cache,
                ((), ((0..=10000).into(), ())),
                NZU64!(5),
            );
            let mut db: LocalDb = LocalDb::init(context.child("db"), cfg).await.expect("init");
            for batch_writes in &batches {
                let finalized = {
                    let mut batch = db.new_batch();
                    for (k, v) in batch_writes {
                        batch = batch.set(k.clone(), v.clone());
                    }
                    batch.merkleize(&db, None::<Vec<u8>>, db.bounds().end - 1)
                };
                db.apply_batch(finalized).await.expect("apply");
            }
            let latest = db.bounds().end - 1;
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

fn latest_inactivity_floor(ops: &[ImmutableOperation<mmr::Family, K, V>]) -> Location<mmr::Family> {
    match ops.last().expect("non-empty operations") {
        ImmutableOperation::Commit(_, floor) => *floor,
        ImmutableOperation::Set(_, _) => panic!("operations must end with Commit"),
    }
}

fn split_complete_batches(
    ops: &[ImmutableOperation<mmr::Family, K, V>],
) -> Vec<Vec<ImmutableOperation<mmr::Family, K, V>>> {
    let mut batches = Vec::new();
    let mut start = 0usize;
    for (index, operation) in ops.iter().enumerate() {
        if matches!(operation, ImmutableOperation::Commit(_, _)) {
            batches.push(ops[start..=index].to_vec());
            start = index + 1;
        }
    }
    assert_eq!(start, ops.len(), "operations must end at a batch boundary");
    batches
}

fn split_upload_batches(
    ops: &[ImmutableOperation<mmr::Family, K, V>],
) -> Vec<Vec<ImmutableOperation<mmr::Family, K, V>>> {
    let mut batches = split_complete_batches(ops);
    if batches.len() > 1
        && batches[0].len() == 1
        && matches!(batches[0][0], ImmutableOperation::Commit(_, _))
    {
        let mut first = batches.remove(0);
        first.extend(batches.remove(0));
        batches.insert(0, first);
    }
    batches
}

#[tokio::test]
async fn sequential_upload_matches_local_root() {
    let (_server, client) = common::local_store_client().await;
    let local = build_local_reference(vec![
        vec![(FixedBytes::new([0x11; 32]), b"alpha".to_vec())],
        vec![(FixedBytes::new([0x22; 32]), b"beta".to_vec())],
    ])
    .await;
    assert!(
        *latest_inactivity_floor(&local.operations) > 0,
        "test must not rely on inactivity_floor = 0"
    );

    let writer = fresh_writer(client.clone());
    let receipt = common::commit_immutable_upload(&writer, &local.operations)
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
    let (_server, client) = common::local_store_client().await;
    let local = build_local_reference(vec![
        vec![(FixedBytes::new([0x01; 32]), b"a".to_vec())],
        vec![(FixedBytes::new([0x02; 32]), b"b".to_vec())],
        vec![(FixedBytes::new([0x03; 32]), b"c".to_vec())],
    ])
    .await;
    assert!(
        *latest_inactivity_floor(&local.operations) > 0,
        "test must not rely on inactivity_floor = 0"
    );

    let batches = split_upload_batches(&local.operations);
    let o1 = batches[0].clone();
    let o2 = batches[1].clone();
    let o3 = batches[2].clone();

    let writer = Arc::new(fresh_writer(client.clone()));

    let w1 = writer.clone();
    let w2 = writer.clone();
    let w3 = writer.clone();
    let (r1, r2, r3) = tokio::join!(
        async move { common::commit_immutable_upload(&w1, &o1).await },
        async move { common::commit_immutable_upload(&w2, &o2).await },
        async move { common::commit_immutable_upload(&w3, &o3).await }
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
