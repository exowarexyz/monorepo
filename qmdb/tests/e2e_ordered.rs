//! Ordered QMDB E2E: run a local Commonware ordered DB, upload its
//! operations + current boundary state to a live store stack, then
//! verify roots and proofs match.

mod common;

use std::num::NonZeroU64;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::any::ordered::variable::Operation as QmdbOperation;
use commonware_storage::qmdb::{
    current::{ordered::variable::Db as LocalQmdbDb, VariableConfig},
    store::LogStore as _,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_sdk_rs::StoreClient;
use store_qmdb::MAX_OPERATION_SIZE;
use store_qmdb::{recover_boundary_state, CurrentBoundaryState, OrderedClient, OrderedWriter};

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchProof = commonware_storage::mmr::Proof<Digest>;
type BatchOperation = QmdbOperation<Vec<u8>, Vec<u8>>;
type TestOrderedClient = OrderedClient<Sha256, Vec<u8>, Vec<u8>, N>;
type TestOrderedWriter = OrderedWriter<Sha256, Vec<u8>, Vec<u8>, N>;
type LocalDb = LocalQmdbDb<cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap, N>;

async fn boundary_from_local_db(
    db: &LocalDb,
    previous_operations: Option<&[BatchOperation]>,
    operations: &[BatchOperation],
) -> CurrentBoundaryState<Digest, N> {
    recover_boundary_state::<Sha256, _, _, N, _, _>(
        previous_operations,
        operations,
        db.root(),
        |location| async move {
            let mut hasher = Sha256::default();
            let (proof, mut proof_ops, mut chunks) = db
                .range_proof(&mut hasher, location, NZU64!(1))
                .await
                .map_err(|error| {
                    store_qmdb::QmdbError::CorruptData(format!(
                        "local current range proof at {location}: {error}"
                    ))
                })?;
            proof_ops.pop().ok_or_else(|| {
                store_qmdb::QmdbError::CorruptData(format!(
                    "local current range proof at {location} returned no operations"
                ))
            })?;
            let chunk = chunks.pop().ok_or_else(|| {
                store_qmdb::QmdbError::CorruptData(format!(
                    "local current range proof at {location} returned no chunks"
                ))
            })?;
            Ok((proof.proof, chunk))
        },
    )
    .await
    .expect("recover_boundary_state")
}

async fn mirror_local(client: &StoreClient, local: &LocalReference) {
    let writer: TestOrderedWriter = TestOrderedWriter::empty(client.clone());
    common::commit_ordered_upload(client, &writer, &local.operations, &local.current_boundary)
        .await
        .expect("commit upload");
}

fn op_cfg() -> <BatchOperation as commonware_codec::Read>::Cfg {
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
    latest_location: Location,
    operations: Vec<BatchOperation>,
    current_boundary: CurrentBoundaryState<Digest, N>,
    values: std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

async fn build_local_db() -> LocalReference {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
            let cfg = VariableConfig {
                mmr_journal_partition: "mmr-journal".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                mmr_metadata_partition: "mmr-metadata".into(),
                log_partition: "log".into(),
                log_write_buffer: NZUsize!(1024),
                log_compression: None,
                log_codec_config: (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                log_items_per_blob: NZU64!(8),
                grafted_mmr_metadata_partition: "grafted-metadata".into(),
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };
            let mut db: LocalDb = LocalDb::init(context.with_label("qmdb"), cfg)
                .await
                .expect("init");

            let finalized = {
                let mut batch = db.new_batch();
                batch.write(b"alpha".to_vec(), Some(b"one".to_vec()));
                batch.write(b"beta".to_vec(), Some(b"two".to_vec()));
                batch.merkleize(None::<Vec<u8>>).await.expect("merkleize")
            };
            db.apply_batch(finalized.finalize()).await.expect("apply");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (BatchProof, Vec<BatchOperation>) = db
                .ops_historical_proof(latest + 1, Location::new(0), n)
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
    let local = build_local_db().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::from_client(client.clone(), op_cfg(), update_row_cfg());
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

#[tokio::test]
async fn current_root_at() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::from_client(client.clone(), op_cfg(), update_row_cfg());
    let root = c
        .current_root_at(local.latest_location)
        .await
        .expect("current_root_at");
    assert!(!root.as_ref().iter().all(|&b| b == 0));
}

#[tokio::test]
async fn current_operation_range_proof() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::from_client(client.clone(), op_cfg(), update_row_cfg());
    let proof = c
        .current_operation_range_proof(
            local.latest_location,
            Location::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("current_operation_range_proof");
    assert_eq!(proof.operations, local.operations);
}

#[tokio::test]
async fn key_value_proof() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::from_client(client.clone(), op_cfg(), update_row_cfg());
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
    let local = build_local_db().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::from_client(client.clone(), op_cfg(), update_row_cfg());
    let result = c
        .multi_proof_at(
            local.latest_location,
            &[b"alpha".as_slice(), b"beta".as_slice()],
        )
        .await
        .expect("multi_proof_at");
    assert_eq!(result.operations.len(), 2);
}
