//! Immutable QMDB E2E: run a local Commonware immutable DB, upload its
//! operations to a live store stack, then verify roots and proofs match.

mod common;

use std::num::NonZeroU64;

use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::mmr::Location;
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
    commonware_storage::mmr::Family,
    deterministic::Context,
    FixedBytes<32>,
    Vec<u8>,
    commonware_cryptography::Sha256,
    TwoCap,
>;

type TestImmutableClient =
    ImmutableClient<commonware_cryptography::Sha256, FixedBytes<32>, Vec<u8>>;

fn fresh_immutable(c: StoreClient) -> TestImmutableClient {
    TestImmutableClient::from_client(
        c,
        ((), ((0..=10000).into(), ())),
        ((), ((0..=10000).into(), ())),
    )
}

type TestImmutableWriter =
    ImmutableWriter<commonware_cryptography::Sha256, FixedBytes<32>, Vec<u8>>;

fn fresh_writer(c: StoreClient) -> TestImmutableWriter {
    TestImmutableWriter::empty(c)
}

struct LocalReference {
    latest_location: Location,
    root: Digest,
    operations: Vec<ImmutableOperation<commonware_storage::mmr::Family, FixedBytes<32>, Vec<u8>>>,
    queried_key: FixedBytes<32>,
    queried_value: Vec<u8>,
}

async fn build_local_db() -> LocalReference {
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::immutable_variable_config(
                "immutable",
                page_cache,
                ((), ((0..=10000).into(), ())),
                NZU64!(5),
            );
            let mut db: LocalDb = LocalDb::init(context.with_label("db"), cfg)
                .await
                .expect("init");

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
                .historical_proof(latest + 1, Location::new(0), n)
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
            Location::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("proof");
    assert_eq!(proof.root, local.root);
    assert_eq!(proof.operations, local.operations);
}
