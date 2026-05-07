//! OrderedWriter E2E: drive the single-writer helper (with caller-supplied
//! CurrentBoundaryState per batch) against a live store stack and verify the
//! resulting roots + proofs against an independent local Commonware Ordered DB.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::any::ordered::variable::Operation as QmdbOperation;
use commonware_storage::qmdb::current::ordered::variable::Db as LocalQmdbDb;
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::{
    recover_boundary_state, CurrentBoundaryState, OrderedClient, OrderedWriter, MAX_OPERATION_SIZE,
};
use exoware_sdk::StoreClient;

use common::retry;

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchProof = commonware_storage::mmr::Proof<Digest>;
type BatchOperation = QmdbOperation<commonware_storage::mmr::Family, Vec<u8>, Vec<u8>>;
type TestReader = OrderedClient<Sha256, Vec<u8>, Vec<u8>, N>;
type TestWriter = OrderedWriter<Sha256, Vec<u8>, Vec<u8>, N>;
type LocalDb = LocalQmdbDb<
    commonware_storage::mmr::Family,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    N,
>;

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

fn fresh_reader(c: StoreClient) -> TestReader {
    TestReader::from_client(c, op_cfg(), update_row_cfg())
}

fn fresh_writer(c: StoreClient) -> TestWriter {
    TestWriter::empty(c)
}

struct LocalReference {
    latest_location: Location,
    root: Digest,
    operations: Vec<BatchOperation>,
    current_boundary: CurrentBoundaryState<Digest, N>,
}

type WriteBatch = Vec<(Vec<u8>, Option<Vec<u8>>)>;

async fn build_local_reference(
    batches: Vec<WriteBatch>,
    previous_operations: Option<Vec<BatchOperation>>,
) -> LocalReference {
    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::ordered_variable_config(
                "ordered-writer",
                page_cache,
                (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                NZU64!(8),
            );
            let mut db: LocalDb = LocalDb::init(context.with_label("qmdb"), cfg)
                .await
                .expect("init");
            for batch_writes in &batches {
                let finalized = {
                    let mut batch = db.new_batch();
                    for (k, v) in batch_writes {
                        batch = batch.write(k.clone(), v.clone());
                    }
                    batch
                        .merkleize(&db, None::<Vec<u8>>)
                        .await
                        .expect("merkleize")
                };
                db.apply_batch(finalized).await.expect("apply");
            }
            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (BatchProof, Vec<BatchOperation>) = db
                .ops_historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");
            let boundary = boundary_from_local_db(&db, previous_operations.as_deref(), &ops).await;
            db.sync().await.expect("sync");
            let root = db.root();
            db.destroy().await.expect("destroy");
            LocalReference {
                latest_location: latest,
                root,
                operations: ops,
                current_boundary: boundary,
            }
        })
    })
    .await
    .expect("join")
}

#[tokio::test]
async fn sequential_upload_matches_local_root() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_reference(
        vec![vec![
            (b"alpha".to_vec(), Some(b"one".to_vec())),
            (b"beta".to_vec(), Some(b"two".to_vec())),
        ]],
        None,
    )
    .await;

    let writer = fresh_writer(client.clone());
    let receipt =
        common::commit_ordered_upload(&client, &writer, &local.operations, &local.current_boundary)
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
            async move { r.current_root_at(latest).await }
        },
        "current_root_at",
    )
    .await;
    assert_eq!(got_root, local.root);
}

// Pipelined burst for ordered: each batch must carry its own current-boundary
// state corresponding to the cumulative state AFTER that batch. We drive three
// local DBs side-by-side to extract the per-batch CurrentBoundaryState.
#[tokio::test]
async fn pipelined_batches_require_flush_to_catch_up_watermark() {
    let (_dir, _server, client) = common::local_store_client().await;

    // Build three cumulative reference snapshots so we can pull a
    // current-boundary delta at each batch boundary from the local current DB.
    let b1 = vec![(b"p".to_vec(), Some(b"1".to_vec()))];
    let b2 = vec![(b"q".to_vec(), Some(b"2".to_vec()))];
    let b3 = vec![(b"r".to_vec(), Some(b"3".to_vec()))];
    let after1 = build_local_reference(vec![b1.clone()], None).await;
    let after2 = build_local_reference(
        vec![b1.clone(), b2.clone()],
        Some(after1.operations.clone()),
    )
    .await;
    let after3 = build_local_reference(vec![b1, b2, b3], Some(after2.operations.clone())).await;

    // Per-batch ops: slice the cumulative op list at boundaries.
    let ops1 = after1.operations.clone();
    let ops2 = after2.operations[after1.operations.len()..].to_vec();
    let ops3 = after3.operations[after2.operations.len()..].to_vec();

    let writer = Arc::new(fresh_writer(client.clone()));

    let w1 = writer.clone();
    let w2 = writer.clone();
    let w3 = writer.clone();
    let c1 = client.clone();
    let c2 = client.clone();
    let c3 = client.clone();
    let (r1, r2, r3) = tokio::join!(
        async move { common::commit_ordered_upload(&c1, &w1, &ops1, &after1.current_boundary).await },
        async move { common::commit_ordered_upload(&c2, &w2, &ops2, &after2.current_boundary).await },
        async move { common::commit_ordered_upload(&c3, &w3, &ops3, &after3.current_boundary).await }
    );
    let _ = r1.expect("b1");
    let _ = r2.expect("b2");
    let _ = r3.expect("b3");

    writer.flush().await.expect("flush");

    let got_root = retry(
        || {
            let r = fresh_reader(client.clone());
            let latest = after3.latest_location;
            async move { r.current_root_at(latest).await }
        },
        "current_root_at",
    )
    .await;
    assert_eq!(got_root, after3.root);
}
