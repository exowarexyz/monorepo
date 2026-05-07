//! Ordered QMDB E2E: run a local Commonware ordered DB, upload its
//! operations + current boundary state to a live store stack, then
//! verify roots and proofs match.

mod common;

use std::num::NonZeroU64;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::merkle::{mmb, mmr, Family, Graftable, Location, Proof};
use commonware_storage::qmdb::any::ordered::variable::Operation as QmdbOperation;
use commonware_storage::qmdb::current::ordered::variable::Db as LocalQmdbDb;
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::MAX_OPERATION_SIZE;
use exoware_qmdb::{recover_boundary_state, CurrentBoundaryState, OrderedClient, OrderedWriter};
use exoware_sdk::StoreClient;

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchOperation<F> = QmdbOperation<F, Vec<u8>, Vec<u8>>;
type TestOrderedClient<F> = OrderedClient<F, Sha256, Vec<u8>, Vec<u8>, N>;
type TestOrderedWriter<F> = OrderedWriter<F, Sha256, Vec<u8>, Vec<u8>, N>;
type LocalDb<F> = LocalQmdbDb<F, cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap, N>;

async fn boundary_from_local_db<F>(
    db: &LocalDb<F>,
    previous_operations: Option<&[BatchOperation<F>]>,
    operations: &[BatchOperation<F>],
) -> CurrentBoundaryState<Digest, N, F>
where
    F: Graftable,
    BatchOperation<F>: commonware_codec::Codec,
{
    let mut ops_root_hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let ops_root_witness = db
        .ops_root_witness(&mut ops_root_hasher)
        .await
        .expect("ops root witness");
    recover_boundary_state::<F, Sha256, _, N, _, _>(
        previous_operations,
        operations,
        db.root(),
        ops_root_witness,
        |location| async move {
            let mut hasher = Sha256::default();
            let (proof, mut proof_ops, mut chunks) = db
                .range_proof(&mut hasher, location, NZU64!(1))
                .await
                .map_err(|error| {
                    exoware_qmdb::QmdbError::CorruptData(format!(
                        "local current range proof at {location}: {error}"
                    ))
                })?;
            proof_ops.pop().ok_or_else(|| {
                exoware_qmdb::QmdbError::CorruptData(format!(
                    "local current range proof at {location} returned no operations"
                ))
            })?;
            let chunk = chunks.pop().ok_or_else(|| {
                exoware_qmdb::QmdbError::CorruptData(format!(
                    "local current range proof at {location} returned no chunks"
                ))
            })?;
            Ok((proof, chunk))
        },
    )
    .await
    .expect("recover_boundary_state")
}

async fn mirror_local<F>(client: &StoreClient, local: &LocalReference<F>)
where
    F: Graftable,
    BatchOperation<F>:
        commonware_codec::Codec + commonware_codec::Encode + commonware_codec::Decode,
{
    let writer: TestOrderedWriter<F> = TestOrderedWriter::empty(client.clone());
    common::commit_ordered_upload(client, &writer, &local.operations, &local.current_boundary)
        .await
        .expect("commit upload");
}

fn op_cfg<F: Family>() -> <BatchOperation<F> as commonware_codec::Read>::Cfg {
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

struct LocalReference<F: Family> {
    latest_location: Location<F>,
    operations: Vec<BatchOperation<F>>,
    current_boundary: CurrentBoundaryState<Digest, N, F>,
    values: std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

async fn build_local_db<F>() -> LocalReference<F>
where
    F: Graftable,
    BatchOperation<F>: commonware_codec::Codec + Clone,
{
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg =
                common::ordered_variable_config("ordered", page_cache, op_cfg::<F>(), NZU64!(8));
            let mut db: LocalDb<F> = LocalDb::init(context.with_label("qmdb"), cfg)
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
            let (_proof, ops): (Proof<F, Digest>, Vec<BatchOperation<F>>) = db
                .ops_historical_proof(latest + 1, Location::<F>::new(0), n)
                .await
                .expect("proof");

            let boundary = boundary_from_local_db(&db, None, &ops).await;

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
                current_boundary: boundary,
                values,
            }
        })
    })
    .await
    .expect("join")
}

#[tokio::test]
async fn ordered_round_trip() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db::<mmr::Family>().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::<mmr::Family>::from_client(
        client.clone(),
        op_cfg::<mmr::Family>(),
        update_row_cfg(),
    );
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
            Location::<mmr::Family>::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("proof");
    assert_eq!(proof.operations, local.operations);
}

#[tokio::test]
async fn ordered_mmb_round_trip() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db::<mmb::Family>().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::<mmb::Family>::from_client(
        client.clone(),
        op_cfg::<mmb::Family>(),
        update_row_cfg(),
    );
    let watermark = c.writer_location_watermark().await.expect("watermark");
    assert_eq!(watermark, Some(local.latest_location));

    let range = c
        .operation_range_proof(
            local.latest_location,
            Location::<mmb::Family>::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("operation range proof");
    assert_eq!(range.operations, local.operations);

    let current = c
        .current_operation_range_proof(
            local.latest_location,
            Location::<mmb::Family>::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("current operation range proof");
    assert_eq!(current.operations, local.operations);

    let key_proof = c
        .key_value_proof_at(local.latest_location, b"alpha".as_slice())
        .await
        .expect("key_value_proof_at");
    match &key_proof.operation {
        QmdbOperation::Update(update) => {
            assert_eq!(update.key, b"alpha".to_vec());
            assert_eq!(update.value, b"one".to_vec());
        }
        _ => panic!("expected Update operation"),
    }
}

#[tokio::test]
async fn current_root_at() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db::<mmr::Family>().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::<mmr::Family>::from_client(
        client.clone(),
        op_cfg::<mmr::Family>(),
        update_row_cfg(),
    );
    let root = c
        .current_root_at(local.latest_location)
        .await
        .expect("current_root_at");
    assert!(!root.as_ref().iter().all(|&b| b == 0));
}

#[tokio::test]
async fn current_operation_range_proof() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db::<mmr::Family>().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::<mmr::Family>::from_client(
        client.clone(),
        op_cfg::<mmr::Family>(),
        update_row_cfg(),
    );
    let proof = c
        .current_operation_range_proof(
            local.latest_location,
            Location::<mmr::Family>::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("current_operation_range_proof");
    assert_eq!(proof.operations, local.operations);
}

#[tokio::test]
async fn key_value_proof() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db::<mmr::Family>().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::<mmr::Family>::from_client(
        client.clone(),
        op_cfg::<mmr::Family>(),
        update_row_cfg(),
    );
    let result = c
        .key_value_proof_at(local.latest_location, b"alpha".as_slice())
        .await
        .expect("key_value_proof_at");
    match &result.operation {
        QmdbOperation::Update(u) => {
            assert_eq!(u.key, b"alpha".to_vec());
            assert_eq!(u.value, b"one".to_vec());
        }
        _ => panic!("expected Update operation"),
    }
}

#[tokio::test]
async fn multi_proof() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db::<mmr::Family>().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::<mmr::Family>::from_client(
        client.clone(),
        op_cfg::<mmr::Family>(),
        update_row_cfg(),
    );
    let result = c
        .multi_proof_at(
            local.latest_location,
            &[b"alpha".as_slice(), b"beta".as_slice()],
        )
        .await
        .expect("multi_proof_at");
    assert_eq!(result.operations.len(), 2);
}
