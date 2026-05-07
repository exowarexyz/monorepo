//! Unordered QMDB E2E: run a local Commonware unordered DB, upload its
//! operations to a live store stack, then verify roots and proofs match.

mod common;

use std::num::NonZeroU64;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::merkle::{mmr, Location, Proof};
use commonware_storage::qmdb::any::unordered::variable::Db as LocalUnorderedDb;
use commonware_storage::qmdb::any::unordered::variable::Operation as UnorderedQmdbOperation;
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::{UnorderedClient, UnorderedWriter, MAX_OPERATION_SIZE};

type Digest = commonware_cryptography::sha256::Digest;
type BatchProof = Proof<mmr::Family, Digest>;
type UnorderedBatchOperation = UnorderedQmdbOperation<mmr::Family, Vec<u8>, Vec<u8>>;
type TestUnorderedClient = UnorderedClient<mmr::Family, Sha256, Vec<u8>, Vec<u8>>;
type LocalDb = LocalUnorderedDb<mmr::Family, cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap>;

fn op_cfg() -> <UnorderedBatchOperation as commonware_codec::Read>::Cfg {
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

struct LocalReference {
    latest_location: Location<mmr::Family>,
    operations: Vec<UnorderedBatchOperation>,
    values: std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

async fn build_local_db() -> LocalReference {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::unordered_variable_config(
                "unordered",
                page_cache,
                (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                NZU64!(8),
            );
            let mut db: LocalDb = LocalDb::init(context.with_label("unordered"), cfg)
                .await
                .expect("init");

            let finalized = {
                let batch = db
                    .new_batch()
                    .write(b"alpha".to_vec(), Some(b"one".to_vec()))
                    .write(b"beta".to_vec(), Some(b"two".to_vec()));
                batch
                    .merkleize(&db, None::<Vec<u8>>)
                    .await
                    .expect("merkleize")
            };
            db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (BatchProof, Vec<UnorderedBatchOperation>) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");

            let mut values = std::collections::BTreeMap::new();
            values.insert(
                b"alpha".to_vec(),
                db.get(&b"alpha".to_vec()).await.expect("get"),
            );
            values.insert(
                b"beta".to_vec(),
                db.get(&b"beta".to_vec()).await.expect("get"),
            );

            db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            LocalReference {
                latest_location: latest,
                operations: ops,
                values,
            }
        })
    })
    .await
    .expect("join")
}

#[tokio::test]
async fn unordered_round_trip() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db().await;

    let writer: UnorderedWriter<mmr::Family, Sha256, Vec<u8>, Vec<u8>> =
        UnorderedWriter::empty(client.clone());
    common::commit_unordered_upload(&client, &writer, &local.operations)
        .await
        .expect("commit upload");

    let c = TestUnorderedClient::from_client(client.clone(), op_cfg(), update_row_cfg());
    let watermark = c.writer_location_watermark().await.expect("watermark");
    assert_eq!(watermark, Some(local.latest_location));

    let queried = c
        .query_many_at(
            &[b"alpha".as_slice(), b"beta".as_slice()],
            local.latest_location,
        )
        .await
        .expect("query_many_at");
    assert_eq!(
        queried[0].as_ref().and_then(|v| v.value.clone()),
        local.values[b"alpha".as_slice()]
    );
    assert_eq!(
        queried[1].as_ref().and_then(|v| v.value.clone()),
        local.values[b"beta".as_slice()]
    );

    let proof = c
        .operation_range_proof(
            local.latest_location,
            Location::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("proof");
    assert_eq!(proof.operations, local.operations);
}
