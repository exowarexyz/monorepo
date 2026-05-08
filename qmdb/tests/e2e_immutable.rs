//! Immutable QMDB E2E: run a local Commonware immutable DB, upload its
//! operations to a live store stack, then verify roots and proofs match.

mod common;

use std::num::NonZeroU64;

use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::journal::contiguous::fixed::Config as FixedJournalConfig;
use commonware_storage::merkle::{mmr, Location};
use commonware_storage::qmdb::any::value::FixedEncoding;
use commonware_storage::qmdb::immutable::fixed::{
    Db as FixedImmutable, Operation as FixedImmutableOperation,
};
use commonware_storage::qmdb::immutable::variable::{
    Db as Immutable, Operation as ImmutableOperation,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use exoware_qmdb::{ImmutableClient, ImmutableWriter};
use exoware_sdk::StoreClient;

use common::retry;

type Digest = commonware_cryptography::sha256::Digest;
type LocalDb = Immutable<
    mmr::Family,
    deterministic::Context,
    FixedBytes<32>,
    Vec<u8>,
    commonware_cryptography::Sha256,
    TwoCap,
>;
type FixedLocalDb = FixedImmutable<
    mmr::Family,
    deterministic::Context,
    FixedBytes<32>,
    Digest,
    commonware_cryptography::Sha256,
    TwoCap,
>;

type TestImmutableClient =
    ImmutableClient<mmr::Family, commonware_cryptography::Sha256, FixedBytes<32>, Vec<u8>>;
type FixedTestImmutableClient = ImmutableClient<
    mmr::Family,
    commonware_cryptography::Sha256,
    FixedBytes<32>,
    Digest,
    FixedEncoding<Digest>,
>;

fn fresh_immutable(c: StoreClient) -> TestImmutableClient {
    TestImmutableClient::from_client(
        c,
        ((), ((0..=10000).into(), ())),
        ((), ((0..=10000).into(), ())),
    )
}

fn fresh_fixed_immutable(c: StoreClient) -> FixedTestImmutableClient {
    FixedTestImmutableClient::from_client(c, (), ((), ()))
}

type TestImmutableWriter =
    ImmutableWriter<mmr::Family, commonware_cryptography::Sha256, FixedBytes<32>, Vec<u8>>;
type FixedTestImmutableWriter = ImmutableWriter<
    mmr::Family,
    commonware_cryptography::Sha256,
    FixedBytes<32>,
    Digest,
    FixedEncoding<Digest>,
>;

fn fresh_writer(c: StoreClient) -> TestImmutableWriter {
    TestImmutableWriter::empty(c)
}

fn fresh_fixed_writer(c: StoreClient) -> FixedTestImmutableWriter {
    FixedTestImmutableWriter::empty(c)
}

struct LocalReference {
    latest_location: Location<mmr::Family>,
    root: Digest,
    operations: Vec<ImmutableOperation<mmr::Family, FixedBytes<32>, Vec<u8>>>,
    queried_key: FixedBytes<32>,
    queried_value: Vec<u8>,
}

struct FixedLocalReference {
    latest_location: Location<mmr::Family>,
    root: Digest,
    operations: Vec<FixedImmutableOperation<mmr::Family, FixedBytes<32>, Digest>>,
    queried_key: FixedBytes<32>,
    queried_value: Digest,
}

async fn build_local_db() -> LocalReference {
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::immutable_variable_config(
                "immutable",
                page_cache,
                ((), ((0..=10000).into(), ())),
                NZU64!(5),
            );
            let mut db: LocalDb = LocalDb::init(context.child("db"), cfg).await.expect("init");

            let key_a = FixedBytes::new([0x11; 32]);
            let key_b = FixedBytes::new([0x22; 32]);
            let val_a = b"alpha".to_vec();
            let val_b = b"beta".to_vec();

            let finalized = {
                let batch = db
                    .new_batch()
                    .set(key_a, val_a)
                    .set(key_b.clone(), val_b.clone());
                batch.merkleize(&db, None::<Vec<u8>>, db.inactivity_floor_loc())
            };
            db.apply_batch(finalized).await.expect("apply");

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
                queried_key: key_b,
                queried_value: val_b,
            }
        })
    })
    .await
    .expect("join")
}

async fn build_fixed_local_db() -> FixedLocalReference {
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = commonware_storage::qmdb::immutable::Config {
                merkle_config: common::merkle_config("immutable_fixed", page_cache.clone()),
                log: FixedJournalConfig {
                    partition: "immutable_fixed_log".to_string(),
                    items_per_blob: NZU64!(5),
                    page_cache,
                    write_buffer: NZUsize!(1024),
                },
                translator: TwoCap,
            };
            let mut db: FixedLocalDb = FixedLocalDb::init(context.child("immutable_fixed"), cfg)
                .await
                .expect("init fixed");

            let key_a = FixedBytes::new([0x11; 32]);
            let key_b = FixedBytes::new([0x22; 32]);
            let val_a = commonware_cryptography::Sha256::fill(0xA1);
            let val_b = commonware_cryptography::Sha256::fill(0xB2);

            let finalized = {
                let batch = db.new_batch().set(key_a, val_a).set(key_b.clone(), val_b);
                batch.merkleize(&db, None::<Digest>, db.inactivity_floor_loc())
            };
            db.apply_batch(finalized).await.expect("apply fixed");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::<mmr::Family>::new(0), n)
                .await
                .expect("fixed proof");
            let root = db.root();
            db.destroy().await.expect("destroy fixed");

            FixedLocalReference {
                latest_location: latest,
                root,
                operations: ops,
                queried_key: key_b,
                queried_value: val_b,
            }
        })
    })
    .await
    .expect("join")
}

#[tokio::test]
async fn immutable_round_trip() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db().await;

    let writer = fresh_writer(client.clone());
    common::commit_immutable_upload(&client, &writer, &local.operations)
        .await
        .expect("commit upload");

    let root = retry(
        || {
            let c = fresh_immutable(client.clone());
            let loc = local.latest_location;
            async move { c.root_at(loc).await }
        },
        "root_at",
    )
    .await;
    assert_eq!(root, local.root, "remote root must match local DB root");

    let c = fresh_immutable(client.clone());
    let got = c
        .get_at(&local.queried_key, local.latest_location)
        .await
        .expect("get_at")
        .expect("present");
    assert_eq!(got.key, local.queried_key);
    assert_eq!(got.value, Some(local.queried_value.clone()));

    let proof = c
        .operation_range_proof(
            local.latest_location,
            Location::<mmr::Family>::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("proof");
    assert_eq!(proof.root, local.root);
    assert_eq!(proof.operations, local.operations);
}

#[tokio::test]
async fn immutable_fixed_round_trip() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_fixed_local_db().await;

    let writer = fresh_fixed_writer(client.clone());
    common::commit_immutable_upload(&client, &writer, &local.operations)
        .await
        .expect("commit fixed upload");

    let root = retry(
        || {
            let c = fresh_fixed_immutable(client.clone());
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

    let c = fresh_fixed_immutable(client.clone());
    let got = c
        .get_at(&local.queried_key, local.latest_location)
        .await
        .expect("fixed get_at")
        .expect("present");
    assert_eq!(got.key, local.queried_key);
    assert_eq!(got.value, Some(local.queried_value));

    let proof = c
        .operation_range_proof(
            local.latest_location,
            Location::<mmr::Family>::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("fixed proof");
    assert_eq!(proof.root, local.root);
    assert_eq!(proof.operations, local.operations);
}
