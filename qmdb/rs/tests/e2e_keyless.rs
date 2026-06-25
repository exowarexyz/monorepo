//! Keyless QMDB E2E: run a local Commonware keyless DB, upload its
//! operations to a live store stack, then verify roots and proofs match.

mod common;

use std::num::NonZeroU64;

use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::journal::contiguous::fixed::Config as FixedJournalConfig;
use commonware_storage::merkle::{mmb, mmr, Family, Graftable, Location};
use commonware_storage::qmdb::any::value::FixedEncoding;
use commonware_storage::qmdb::keyless::fixed::{
    Db as FixedKeyless, Operation as FixedKeylessOperation,
};
use commonware_storage::qmdb::keyless::variable::{Db as Keyless, Operation as KeylessOperation};
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::{KeylessClient, KeylessWriter};
use exoware_sdk::StoreClient;

use common::retry;

type Digest = commonware_cryptography::sha256::Digest;
type LocalDb<F> = Keyless<
    F,
    deterministic::Context,
    Vec<u8>,
    commonware_cryptography::Sha256,
    commonware_parallel::Sequential,
>;
type FixedLocalDb<F> = FixedKeyless<
    F,
    deterministic::Context,
    Digest,
    commonware_cryptography::Sha256,
    commonware_parallel::Sequential,
>;

type TestKeylessClient<F> = KeylessClient<F, commonware_cryptography::Sha256, Vec<u8>>;
type TestKeylessWriter<F> = KeylessWriter<F, commonware_cryptography::Sha256, Vec<u8>>;
type FixedTestKeylessClient<F> =
    KeylessClient<F, commonware_cryptography::Sha256, Digest, FixedEncoding<Digest>>;
type FixedTestKeylessWriter<F> =
    KeylessWriter<F, commonware_cryptography::Sha256, Digest, FixedEncoding<Digest>>;

fn fresh_keyless<F: Graftable>(c: StoreClient) -> TestKeylessClient<F> {
    TestKeylessClient::from_client(c, ((0..=10000).into(), ()))
}

fn fresh_writer<F: Family>(c: StoreClient) -> TestKeylessWriter<F> {
    TestKeylessWriter::fresh(c)
}

fn fresh_fixed_keyless<F: Graftable>(c: StoreClient) -> FixedTestKeylessClient<F>
where
    FixedKeylessOperation<F, Digest>: commonware_codec::Read<Cfg = ()>,
{
    FixedTestKeylessClient::from_client(c, ())
}

fn fresh_fixed_writer<F: Family>(c: StoreClient) -> FixedTestKeylessWriter<F> {
    FixedTestKeylessWriter::fresh(c)
}

struct LocalReference<F: Family> {
    latest_location: Location<F>,
    root: Digest,
    operations: Vec<KeylessOperation<F, Vec<u8>>>,
    queried_location: Location<F>,
    queried_value: Vec<u8>,
}

struct FixedLocalReference<F: Family> {
    latest_location: Location<F>,
    root: Digest,
    operations: Vec<FixedKeylessOperation<F, Digest>>,
    queried_location: Location<F>,
    queried_value: Digest,
}

async fn build_local_db<F: Family>() -> LocalReference<F>
where
    KeylessOperation<F, Vec<u8>>:
        commonware_codec::Codec<Cfg = <Vec<u8> as commonware_codec::Read>::Cfg> + Clone,
{
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg =
                common::keyless_config("keyless", page_cache, ((0..=10000).into(), ()), NZU64!(7));
            let mut db: LocalDb<F> = LocalDb::init(context.child("db"), cfg).await.expect("init");

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

async fn build_fixed_local_db<F: Family>() -> FixedLocalReference<F>
where
    FixedKeylessOperation<F, Digest>: commonware_codec::CodecFixed<Cfg = ()> + Clone,
{
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = commonware_storage::qmdb::keyless::Config {
                merkle: common::merkle_config("keyless_fixed", page_cache.clone()),
                log: FixedJournalConfig {
                    partition: "keyless_fixed_log".to_string(),
                    items_per_blob: NZU64!(7),
                    page_cache,
                    write_buffer: NZUsize!(1024),
                },
            };
            let mut db: FixedLocalDb<F> = FixedLocalDb::init(context.child("keyless_fixed"), cfg)
                .await
                .expect("init fixed");

            let first = commonware_cryptography::Sha256::fill(0x11);
            let second = commonware_cryptography::Sha256::fill(0x22);
            let finalized = {
                let batch = db.new_batch().append(first).append(second);
                batch.merkleize(&db, None::<Digest>, db.inactivity_floor_loc())
            };
            db.apply_batch(finalized).await.expect("apply fixed");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::<F>::new(0), n)
                .await
                .expect("fixed proof");
            let root = db.root();
            db.destroy().await.expect("destroy fixed");
            let queried_location = ops
                .iter()
                .enumerate()
                .find_map(|(index, operation)| {
                    (operation.clone().into_value() == Some(first))
                        .then_some(Location::new(index as u64))
                })
                .expect("fixed value location");

            FixedLocalReference {
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

async fn keyless_round_trip_for_family<F: Graftable>()
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
    assert!(checkpoint.verify::<commonware_cryptography::Sha256>());
    let mut malformed_checkpoint = checkpoint.clone();
    malformed_checkpoint
        .pinned_nodes
        .push(malformed_checkpoint.root);
    assert!(
        !malformed_checkpoint.verify::<commonware_cryptography::Sha256>(),
        "zero-start checkpoints must not verify with pinned nodes"
    );
    let peaks = checkpoint
        .reconstruct_peaks::<commonware_cryptography::Sha256>()
        .expect("reconstruct_peaks");
    let hasher = commonware_storage::qmdb::hasher::<commonware_cryptography::Sha256>();
    let reconstructed_root = commonware_storage::merkle::hasher::Hasher::<F>::root(
        &hasher,
        checkpoint.proof.leaves,
        0,
        peaks.iter().map(|(_, _, digest)| digest),
    )
    .expect("reconstruct root");
    assert_eq!(reconstructed_root, checkpoint.root);
}

#[tokio::test]
async fn keyless_fixed_round_trip() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_fixed_local_db::<mmr::Family>().await;

    let writer = fresh_fixed_writer::<mmr::Family>(client.clone());
    common::commit_keyless_upload(&client, &writer, &local.operations)
        .await
        .expect("commit fixed upload");

    let root = retry(
        || {
            let c = fresh_fixed_keyless::<mmr::Family>(client.clone());
            let loc = local.latest_location;
            async move { c.root_at(loc).await }
        },
        "fixed root_at",
    )
    .await;
    assert_eq!(
        root, local.root,
        "remote root must match local fixed DB root"
    );

    let c = fresh_fixed_keyless::<mmr::Family>(client.clone());
    let got: Digest = c
        .get_at(local.queried_location, local.latest_location)
        .await
        .expect("fixed get_at")
        .expect("present");
    assert_eq!(got, local.queried_value);

    let proof = c
        .operation_range_proof(
            local.latest_location,
            Location::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("fixed proof");
    assert_eq!(proof.root, local.root);
    assert_eq!(proof.operations, local.operations);
}

#[tokio::test]
async fn keyless_round_trip() {
    keyless_round_trip_for_family::<mmr::Family>().await;
}

#[tokio::test]
async fn keyless_mmb_round_trip() {
    keyless_round_trip_for_family::<mmb::Family>().await;
}
