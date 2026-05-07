//! Keyless QMDB E2E: run a local Commonware keyless DB, upload its
//! operations to a live store stack, then verify roots and proofs match.

mod common;

use std::num::NonZeroU64;

use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::merkle::{mmb, mmr, Family, Location};
use commonware_storage::qmdb::keyless::variable::{Db as Keyless, Operation as KeylessOperation};
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::{KeylessClient, KeylessWriter};
use exoware_sdk::StoreClient;

use common::retry;

type Digest = commonware_cryptography::sha256::Digest;
type LocalDb<F> = Keyless<F, deterministic::Context, Vec<u8>, commonware_cryptography::Sha256>;

type TestKeylessClient<F> = KeylessClient<F, commonware_cryptography::Sha256, Vec<u8>>;
type TestKeylessWriter<F> = KeylessWriter<F, commonware_cryptography::Sha256, Vec<u8>>;

fn fresh_keyless<F: Family>(c: StoreClient) -> TestKeylessClient<F> {
    TestKeylessClient::from_client(c, ((0..=10000).into(), ()))
}

fn fresh_writer<F: Family>(c: StoreClient) -> TestKeylessWriter<F> {
    TestKeylessWriter::empty(c)
}

struct LocalReference<F: Family> {
    latest_location: Location<F>,
    root: Digest,
    operations: Vec<KeylessOperation<F, Vec<u8>>>,
    queried_location: Location<F>,
    queried_value: Vec<u8>,
}

async fn build_local_db<F: Family>() -> LocalReference<F>
where
    KeylessOperation<F, Vec<u8>>:
        commonware_codec::Codec<Cfg = <Vec<u8> as commonware_codec::Read>::Cfg> + Clone,
{
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg =
                common::keyless_config("keyless", page_cache, ((0..=10000).into(), ()), NZU64!(7));
            let mut db: LocalDb<F> = LocalDb::init(context.with_label("db"), cfg)
                .await
                .expect("init");

            let first = b"first-value".to_vec();
            let second = b"second-value".to_vec();
            let finalized = {
                let batch = db.new_batch().append(first.clone()).append(second);
                batch.merkleize(&db, None::<Vec<u8>>, db.inactivity_floor_loc())
            };
            db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::<F>::new(0), n)
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

async fn keyless_round_trip_for_family<F: Family>()
where
    KeylessOperation<F, Vec<u8>>:
        commonware_codec::Codec<Cfg = <Vec<u8> as commonware_codec::Read>::Cfg> + Clone + PartialEq,
{
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db::<F>().await;

    let writer = fresh_writer::<F>(client.clone());
    common::commit_keyless_upload(&client, &writer, &local.operations)
        .await
        .expect("commit upload");

    let root = retry(
        || {
            let c = fresh_keyless::<F>(client.clone());
            let loc = local.latest_location;
            async move { c.root_at(loc).await }
        },
        "root_at",
    )
    .await;
    assert_eq!(root, local.root, "remote root must match local DB root");

    let c = fresh_keyless::<F>(client.clone());
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

    let checkpoint = c
        .operation_range_checkpoint(
            local.latest_location,
            Location::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("checkpoint");
    let peaks = checkpoint
        .reconstruct_peaks::<commonware_cryptography::Sha256>()
        .expect("reconstruct_peaks");
    let mut hasher = commonware_storage::qmdb::hasher::<commonware_cryptography::Sha256>();
    let reconstructed_root = commonware_storage::merkle::hasher::Hasher::<F>::root(
        &mut hasher,
        checkpoint.proof.leaves,
        0,
        peaks.iter().map(|(_, _, digest)| digest),
    )
    .expect("reconstruct root");
    assert_eq!(reconstructed_root, checkpoint.root);
}

#[tokio::test]
async fn keyless_round_trip() {
    keyless_round_trip_for_family::<mmr::Family>().await;
}

#[tokio::test]
async fn keyless_mmb_round_trip() {
    keyless_round_trip_for_family::<mmb::Family>().await;
}
