//! Ordered QMDB range-stream ConnectRPC e2e: streamed historical checkpoints
//! plus client-side validation of tampered proofs.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use commonware_codec::Encode as _;
use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::merkle::{mmb, mmr, Location, Proof};
use commonware_storage::qmdb::any::ordered::variable::Operation as QmdbOperation;
use commonware_storage::qmdb::sync::resolver::Resolver as _;
use commonware_storage::qmdb::{
    any::ordered::{variable::Db as AnyOrderedQmdbDb, Update},
    current::ordered::variable::Db as LocalQmdbDb,
    sync as qmdb_sync,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{
    channel::{mpsc, oneshot},
    NZUsize, NZU16, NZU64,
};
use exoware_qmdb::proto::qmdb::v1::{
    GetCurrentOperationRangeRequest as ProtoGetCurrentOperationRangeRequest,
    GetOperationRangeRequest as ProtoGetOperationRangeRequest,
    SubscribeRequest as ProtoSubscribeRequest,
};
use exoware_qmdb::{
    ordered_connect_stack, recover_boundary_state, CurrentBoundaryState, CurrentOperationClient,
    CurrentSyncResolver, OperationLogClient, OperationLogSubscribeProof, OperationLogSyncResolver,
    OrderedClient, OrderedWriter, QmdbError, MAX_OPERATION_SIZE,
};
use exoware_sdk::common::kv::v1::{filter as proto_filter, Filter as ProtoFilter};
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::{PrefixedStoreClient, StoreClient};

const N: usize = 32;
const MIN_MMB_OPERATIONS: usize = 10;
type Digest = commonware_cryptography::sha256::Digest;
type BatchProof = Proof<mmr::Family, Digest>;
type BatchOperation = QmdbOperation<mmr::Family, Vec<u8>, Vec<u8>>;
type TestOrderedClient = OrderedClient<mmr::Family, Sha256, Vec<u8>, Vec<u8>, N>;
type LocalDb = LocalQmdbDb<
    mmr::Family,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    N,
    commonware_parallel::Sequential,
>;
type MmbBatchProof = Proof<mmb::Family, Digest>;
type MmbBatchOperation = QmdbOperation<mmb::Family, Vec<u8>, Vec<u8>>;
type MmbTestOrderedClient = OrderedClient<mmb::Family, Sha256, Vec<u8>, Vec<u8>, N>;
type MmbLocalDb = LocalQmdbDb<
    mmb::Family,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    N,
    commonware_parallel::Sequential,
>;
type MmbAnyLocalDb = AnyOrderedQmdbDb<
    mmb::Family,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    commonware_parallel::Sequential,
>;

async fn spawn_qmdb_server(
    client: Arc<TestOrderedClient>,
) -> (tokio::task::JoinHandle<()>, String) {
    common::spawn_operation_log_service(ordered_connect_stack(client)).await
}

fn validated_client(
    base: &str,
) -> OperationLogClient<PreferZstdHttpClient, mmr::Family, Sha256, BatchOperation> {
    OperationLogClient::plaintext(base, op_cfg())
}

fn current_operation_client(
    base: &str,
) -> CurrentOperationClient<PreferZstdHttpClient, mmr::Family, Sha256, BatchOperation, N> {
    CurrentOperationClient::plaintext(base, op_cfg())
}

async fn spawn_mmb_qmdb_server(
    client: Arc<MmbTestOrderedClient>,
) -> (tokio::task::JoinHandle<()>, String) {
    common::spawn_operation_log_service(ordered_connect_stack(client)).await
}

fn mmb_validated_client(
    base: &str,
) -> OperationLogClient<PreferZstdHttpClient, mmb::Family, Sha256, MmbBatchOperation> {
    OperationLogClient::plaintext(base, mmb_op_cfg())
}

async fn boundary_from_local_db(
    db: &LocalDb,
    previous_operations: Option<&[BatchOperation]>,
    operations: &[BatchOperation],
) -> CurrentBoundaryState<Digest, N, mmr::Family> {
    let ops_root_hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let ops_root_witness = db
        .ops_root_witness(&ops_root_hasher)
        .await
        .expect("ops root witness");
    recover_boundary_state::<mmr::Family, Sha256, _, N, _, _>(
        previous_operations,
        operations,
        db.root(),
        0,
        ops_root_witness,
        |location| async move {
            let hasher = commonware_storage::qmdb::hasher::<Sha256>();
            let (proof, mut proof_ops, mut chunks) = db
                .range_proof(&hasher, location, NZU64!(1))
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

fn mmb_op_cfg() -> <MmbBatchOperation as commonware_codec::Read>::Cfg {
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

struct LocalBatch {
    operations: Vec<BatchOperation>,
    current_boundary: CurrentBoundaryState<Digest, N, mmr::Family>,
    inactivity_floor: Location<mmr::Family>,
}

struct MmbLocalBatch {
    operations: Vec<MmbBatchOperation>,
    current_boundary: CurrentBoundaryState<Digest, N, mmb::Family>,
    inactivity_floor: Location<mmb::Family>,
}

struct MmbGrowingLocalBatch {
    initial: MmbLocalBatch,
    updated: MmbLocalBatch,
}

fn latest_inactivity_floor(operations: &[BatchOperation]) -> Location<mmr::Family> {
    operations
        .iter()
        .rev()
        .find_map(|operation| match operation {
            BatchOperation::CommitFloor(_, floor) => Some(*floor),
            _ => None,
        })
        .expect("batch has CommitFloor")
}

async fn build_local_batch() -> LocalBatch {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::ordered_variable_config(
                "ordered-range-connect",
                page_cache,
                (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                NZU64!(8),
            );
            let mut db: LocalDb = LocalDb::init(context.child("qmdb"), cfg)
                .await
                .expect("init");

            let mut ops = Vec::new();
            let mut inactivity_floor = Location::<mmr::Family>::new(0);
            for _ in 0..64u64 {
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
                let (_proof, cumulative): (BatchProof, Vec<BatchOperation>) = db
                    .ops_historical_proof(latest + 1, Location::new(0), n)
                    .await
                    .expect("proof");
                inactivity_floor = latest_inactivity_floor(&cumulative);
                ops = cumulative;
                if *inactivity_floor > 0 {
                    break;
                }
            }
            assert!(
                *inactivity_floor > 0,
                "MMR subscribe fixture must exercise nonzero inactivity floor"
            );
            let boundary = boundary_from_local_db(&db, None, &ops).await;
            db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            LocalBatch {
                operations: ops,
                current_boundary: boundary,
                inactivity_floor,
            }
        })
    })
    .await
    .expect("join")
}

async fn boundary_from_mmb_local_db(
    db: &MmbLocalDb,
    operations: &[MmbBatchOperation],
) -> CurrentBoundaryState<Digest, N, mmb::Family> {
    let ops_root_hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let ops_root_witness = db
        .ops_root_witness(&ops_root_hasher)
        .await
        .expect("ops root witness");
    recover_boundary_state::<mmb::Family, Sha256, _, N, _, _>(
        None,
        operations,
        db.root(),
        0,
        ops_root_witness,
        |location| async move {
            let hasher = commonware_storage::qmdb::hasher::<Sha256>();
            let (proof, mut proof_ops, mut chunks) = db
                .range_proof(&hasher, location, NZU64!(1))
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

fn latest_mmb_inactivity_floor(operations: &[MmbBatchOperation]) -> Location<mmb::Family> {
    operations
        .iter()
        .rev()
        .find_map(|operation| match operation {
            MmbBatchOperation::CommitFloor(_, floor) => Some(*floor),
            _ => None,
        })
        .expect("batch has CommitFloor")
}

async fn build_mmb_local_batch() -> MmbLocalBatch {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::ordered_variable_config(
                "ordered-range-connect-mmb",
                page_cache,
                (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                NZU64!(8),
            );
            let mut db: MmbLocalDb = MmbLocalDb::init(context.child("qmdb"), cfg)
                .await
                .expect("init");

            let mut ops = Vec::new();
            let mut inactivity_floor = Location::<mmb::Family>::new(0);
            for batch_index in 0..64u64 {
                let finalized = {
                    let alpha_value = format!("one-{batch_index}").into_bytes();
                    let key = format!("k-{batch_index:08x}").into_bytes();
                    let value = format!("v-{batch_index:08x}").into_bytes();
                    let batch = db
                        .new_batch()
                        .write(b"alpha".to_vec(), Some(alpha_value))
                        .write(key, Some(value));
                    batch
                        .merkleize(&db, None::<Vec<u8>>)
                        .await
                        .expect("merkleize")
                };
                db.apply_batch(finalized).await.expect("apply");

                let latest = db.bounds().await.end - 1;
                let n = NonZeroU64::new(*latest + 1).unwrap();
                let (_proof, cumulative): (MmbBatchProof, Vec<MmbBatchOperation>) = db
                    .ops_historical_proof(latest + 1, Location::new(0), n)
                    .await
                    .expect("proof");
                inactivity_floor = latest_mmb_inactivity_floor(&cumulative);
                ops = cumulative;
                if *inactivity_floor > 0 && ops.len() >= MIN_MMB_OPERATIONS {
                    break;
                }
            }
            assert!(
                *inactivity_floor > 0 && ops.len() >= MIN_MMB_OPERATIONS,
                "MMB fixture must exercise nonzero inactivity floor and multiple sync batches"
            );
            let boundary = boundary_from_mmb_local_db(&db, &ops).await;
            db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            MmbLocalBatch {
                operations: ops,
                current_boundary: boundary,
                inactivity_floor,
            }
        })
    })
    .await
    .expect("join")
}

async fn build_mmb_growing_local_batch() -> MmbGrowingLocalBatch {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::ordered_variable_config(
                "ordered-range-connect-mmb-growing",
                page_cache,
                (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                NZU64!(8),
            );
            let mut db: MmbLocalDb = MmbLocalDb::init(context.child("qmdb"), cfg)
                .await
                .expect("init");

            let mut ops = Vec::new();
            let mut inactivity_floor = Location::<mmb::Family>::new(0);
            let mut initial = None;
            let mut initial_len = None;
            for batch_index in 0..64u64 {
                let finalized = {
                    let alpha_value = format!("one-{batch_index}").into_bytes();
                    let key = format!("k-{batch_index:08x}").into_bytes();
                    let value = format!("v-{batch_index:08x}").into_bytes();
                    let batch = db
                        .new_batch()
                        .write(b"alpha".to_vec(), Some(alpha_value))
                        .write(key, Some(value));
                    batch
                        .merkleize(&db, None::<Vec<u8>>)
                        .await
                        .expect("merkleize")
                };
                db.apply_batch(finalized).await.expect("apply");

                let latest = db.bounds().await.end - 1;
                let n = NonZeroU64::new(*latest + 1).unwrap();
                let (_proof, cumulative): (MmbBatchProof, Vec<MmbBatchOperation>) = db
                    .ops_historical_proof(latest + 1, Location::new(0), n)
                    .await
                    .expect("proof");
                inactivity_floor = latest_mmb_inactivity_floor(&cumulative);
                ops = cumulative;

                if initial.is_none() && *inactivity_floor > 0 && ops.len() >= MIN_MMB_OPERATIONS {
                    let boundary = boundary_from_mmb_local_db(&db, &ops).await;
                    initial_len = Some(ops.len());
                    initial = Some(MmbLocalBatch {
                        operations: ops.clone(),
                        current_boundary: boundary,
                        inactivity_floor,
                    });
                    continue;
                }

                if initial_len
                    .map(|len| ops.len() >= len + MIN_MMB_OPERATIONS)
                    .unwrap_or(false)
                {
                    break;
                }
            }

            let initial = initial.expect("MMB growing fixture initial target");
            assert!(
                ops.len() >= initial.operations.len() + MIN_MMB_OPERATIONS,
                "MMB growing fixture must add enough operations for multiple updated sync fetches"
            );
            let boundary = boundary_from_mmb_local_db(&db, &ops).await;
            db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            MmbGrowingLocalBatch {
                initial,
                updated: MmbLocalBatch {
                    operations: ops,
                    current_boundary: boundary,
                    inactivity_floor,
                },
            }
        })
    })
    .await
    .expect("join")
}

async fn commit_upload(client: &StoreClient, batch: &LocalBatch) {
    let writer: OrderedWriter<mmr::Family, Sha256, Vec<u8>, Vec<u8>, N> =
        OrderedWriter::fresh(PrefixedStoreClient::empty(client.clone()));
    common::commit_ordered_upload(&writer, &batch.operations, &batch.current_boundary)
        .await
        .expect("commit upload");
}

async fn commit_mmb_upload(client: &StoreClient, batch: &MmbLocalBatch) {
    let writer: OrderedWriter<mmb::Family, Sha256, Vec<u8>, Vec<u8>, N> =
        OrderedWriter::fresh(PrefixedStoreClient::empty(client.clone()));
    common::commit_ordered_upload(&writer, &batch.operations, &batch.current_boundary)
        .await
        .expect("commit upload");
}

#[tokio::test]
async fn ordered_current_operation_range_connect_emits_verifiable_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    commit_upload(&store_client, &local).await;

    let ordered_client = Arc::new(TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client).await;
    let current = current_operation_client(&qmdb_url);
    let proof = current
        .get_current_operation_range(
            ProtoGetCurrentOperationRangeRequest {
                tip: (local.operations.len() - 1) as u64,
                start_location: 0,
                max_locations: local.operations.len() as u32,
                ..Default::default()
            },
            &local.current_boundary.root,
        )
        .await
        .expect("get current operation range");
    assert_eq!(proof.root, local.current_boundary.root);
    assert_eq!(proof.start_location, Location::new(0));
    assert_eq!(proof.chunks.len(), 1);
    assert_eq!(
        proof
            .operations
            .into_iter()
            .map(|(_, operation)| operation)
            .collect::<Vec<_>>(),
        local.operations
    );
}

#[tokio::test]
async fn ordered_current_state_sync_from_connect_api_reconstructs_current_db() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    commit_upload(&store_client, &local).await;

    let ordered_client = Arc::new(TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client).await;
    let resolver = CurrentSyncResolver::<_, mmr::Family, Sha256, BatchOperation>::plaintext(
        &qmdb_url,
        local.current_boundary.root,
        op_cfg(),
    );
    let op_count = Location::new(local.operations.len() as u64);
    let target = resolver.target(op_count).await.expect("api sync target");
    assert_eq!(target.range.start(), Location::new(0));
    assert_eq!(target.range.end(), op_count);

    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};

            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::ordered_variable_config(
                "ordered-current-sync-connect",
                page_cache,
                op_cfg(),
                NZU64!(8),
            );
            let db: LocalDb = qmdb_sync::sync(qmdb_sync::engine::Config {
                context: context.child("sync"),
                resolver,
                target,
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(7),
                apply_batch_size: 32,
                db_config: cfg,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 4,
            })
            .await
            .expect("sync current db from API");

            assert_eq!(db.root(), local.current_boundary.root);
            assert_eq!(
                db.get(&b"alpha".to_vec()).await.expect("get alpha"),
                Some(b"one".to_vec())
            );
            assert_eq!(
                db.get(&b"beta".to_vec()).await.expect("get beta"),
                Some(b"two".to_vec())
            );
            db.destroy().await.expect("destroy synced db");
        });
    })
    .await
    .expect("join sync runner");
}

#[tokio::test]
async fn ordered_mmb_current_state_sync_from_nonzero_connect_api_reconstructs_current_db() {
    const FETCH_BATCH_SIZE: u64 = 3;

    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_mmb_local_batch().await;
    let start = Location::<mmb::Family>::new(1);
    let start_index = usize::try_from(*start).expect("start fits usize");
    let remaining_ops = local
        .operations
        .len()
        .checked_sub(start_index)
        .expect("sync start is inside operation log");
    assert!(*start > 0, "MMB current-sync fixture must start after zero");
    assert!(
        start <= local.inactivity_floor,
        "MMB current-sync start must be within the safe sync boundary"
    );
    assert!(
        remaining_ops as u64 > FETCH_BATCH_SIZE * 2,
        "MMB current-sync fixture must require at least three nonzero-start fetches"
    );
    let expected_alpha = latest_mmb_value_for_key(&local.operations[start_index..], b"alpha");
    commit_mmb_upload(&store_client, &local).await;

    let ordered_client = Arc::new(MmbTestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        mmb_op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_mmb_qmdb_server(ordered_client).await;
    let resolver = CurrentSyncResolver::<_, mmb::Family, Sha256, MmbBatchOperation>::plaintext(
        &qmdb_url,
        local.current_boundary.root,
        mmb_op_cfg(),
    );
    let op_count = Location::new(local.operations.len() as u64);
    let target = resolver
        .target_range(start, op_count)
        .await
        .expect("api nonzero current sync target");
    let expected_current_root = local.current_boundary.root;

    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};

            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::ordered_variable_config(
                "ordered-mmb-current-sync-nonzero-connect",
                page_cache,
                mmb_op_cfg(),
                NZU64!(8),
            );
            let db: MmbLocalDb = qmdb_sync::sync(qmdb_sync::engine::Config {
                context: context.child("sync"),
                resolver,
                target,
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(3),
                apply_batch_size: 32,
                db_config: cfg,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 4,
            })
            .await
            .expect("sync current db from nonzero MMB API");

            assert_eq!(db.root(), expected_current_root);
            let bounds = db.bounds().await;
            assert_eq!(bounds.start, start);
            assert_eq!(bounds.end, op_count);
            assert_eq!(
                db.get(&b"alpha".to_vec()).await.expect("get alpha"),
                expected_alpha
            );
            db.destroy().await.expect("destroy synced db");
        });
    })
    .await
    .expect("join nonzero current sync runner");
}

#[tokio::test]
async fn ordered_mmb_sync_resolvers_return_pinned_nodes_for_nonzero_fetches() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_mmb_local_batch().await;
    let start = Location::<mmb::Family>::new(3);
    assert!(*start > 0, "regression must exercise a nonzero lower bound");
    assert!(
        local.operations.len() > usize::try_from(*start).expect("start fits usize"),
        "sync start is inside operation log"
    );
    commit_mmb_upload(&store_client, &local).await;

    let ordered_client = Arc::new(MmbTestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        mmb_op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_mmb_qmdb_server(ordered_client).await;
    let op_count = Location::new(local.operations.len() as u64);
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();

    let any_resolver =
        OperationLogSyncResolver::<_, mmb::Family, Sha256, MmbBatchOperation>::plaintext(
            &qmdb_url,
            mmb_op_cfg(),
        );
    let any_target = any_resolver
        .target_range(start, op_count)
        .await
        .expect("any nonzero sync target");
    let (_cancel_tx, cancel_rx) = oneshot::channel();
    let any_fetch = any_resolver
        .get_operations(op_count, start, NZU64!(1), true, cancel_rx)
        .await
        .expect("any resolver nonzero pinned fetch");
    let any_pinned_nodes = any_fetch
        .pinned_nodes
        .as_ref()
        .expect("any resolver returned pinned nodes");
    assert!(!any_pinned_nodes.is_empty());
    let any_elements = any_fetch
        .operations
        .iter()
        .map(|operation| operation.encode())
        .collect::<Vec<_>>();
    assert!(any_fetch.proof.verify_proof_and_pinned_nodes(
        &hasher,
        &any_elements,
        start,
        any_pinned_nodes,
        &any_target.root,
    ));

    let current_resolver =
        CurrentSyncResolver::<_, mmb::Family, Sha256, MmbBatchOperation>::plaintext(
            &qmdb_url,
            local.current_boundary.root,
            mmb_op_cfg(),
        );
    let current_target = current_resolver
        .target_range(start, op_count)
        .await
        .expect("current nonzero sync target");
    let (_cancel_tx, cancel_rx) = oneshot::channel();
    let current_fetch = current_resolver
        .get_operations(op_count, start, NZU64!(1), true, cancel_rx)
        .await
        .expect("current resolver nonzero pinned fetch");
    let current_pinned_nodes = current_fetch
        .pinned_nodes
        .as_ref()
        .expect("current resolver returned pinned nodes");
    assert!(!current_pinned_nodes.is_empty());
    let current_elements = current_fetch
        .operations
        .iter()
        .map(|operation| operation.encode())
        .collect::<Vec<_>>();
    assert!(current_fetch.proof.verify_proof_and_pinned_nodes(
        &hasher,
        &current_elements,
        start,
        current_pinned_nodes,
        &current_target.root,
    ));
}

#[tokio::test]
async fn ordered_mmb_operation_range_client_rejects_missing_nonzero_pinned_nodes() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_mmb_local_batch().await;
    let start = Location::<mmb::Family>::new(3);
    assert!(
        local.operations.len() > usize::try_from(*start).expect("start fits usize"),
        "sync start is inside operation log"
    );
    commit_mmb_upload(&store_client, &local).await;

    let ordered_client = Arc::new(MmbTestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        mmb_op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_mmb_qmdb_server(ordered_client).await;
    let request = ProtoGetOperationRangeRequest {
        tip: (local.operations.len() - 1) as u64,
        start_location: start.as_u64(),
        max_locations: 1,
        ..Default::default()
    };
    let mut response = common::operation_log_rpc_client(&qmdb_url)
        .get_operation_range(request.clone())
        .await
        .expect("raw get operation range")
        .into_view()
        .to_owned_message();
    let proof = mmb_validated_client(&qmdb_url)
        .get_operation_range(request.clone(), &local.current_boundary.root)
        .await
        .expect("nonzero operation range verifies with pinned nodes");
    assert_eq!(proof.start_location, start);
    assert_eq!(
        proof.operations,
        vec![(
            start,
            local.operations[usize::try_from(*start).expect("start fits usize")].clone()
        )]
    );
    let mut proof = response
        .proof
        .as_option()
        .cloned()
        .expect("operation range proof");
    assert!(!proof.pinned_nodes.is_empty());
    proof.pinned_nodes.clear();
    response.proof = Some(proof).into();

    let (_static_server, static_url) =
        common::spawn_static_operation_range_service(common::StaticOperationRangeService {
            operation_range_response: response,
        })
        .await;
    let client = mmb_validated_client(&static_url);
    let err = client
        .get_operation_range(request, &local.current_boundary.root)
        .await
        .expect_err("missing pinned nodes should fail nonzero operation range verification");
    assert!(matches!(
        err,
        QmdbError::ProofVerification {
            kind: exoware_qmdb::ProofKind::RangeCheckpoint
        }
    ));
}

#[tokio::test]
async fn ordered_mmb_operation_range_client_rejects_extra_nonzero_pinned_node() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_mmb_local_batch().await;
    let start = Location::<mmb::Family>::new(3);
    assert!(
        local.operations.len() > usize::try_from(*start).expect("start fits usize"),
        "sync start is inside operation log"
    );
    commit_mmb_upload(&store_client, &local).await;

    let ordered_client = Arc::new(MmbTestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        mmb_op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_mmb_qmdb_server(ordered_client).await;
    let request = ProtoGetOperationRangeRequest {
        tip: (local.operations.len() - 1) as u64,
        start_location: start.as_u64(),
        max_locations: 1,
        ..Default::default()
    };
    let mut response = common::operation_log_rpc_client(&qmdb_url)
        .get_operation_range(request.clone())
        .await
        .expect("raw get operation range")
        .into_view()
        .to_owned_message();
    let mut proof = response
        .proof
        .as_option()
        .cloned()
        .expect("operation range proof");
    assert!(!proof.pinned_nodes.is_empty());
    proof.pinned_nodes.push(proof.pinned_nodes[0].clone());
    response.proof = Some(proof).into();

    let (_static_server, static_url) =
        common::spawn_static_operation_range_service(common::StaticOperationRangeService {
            operation_range_response: response,
        })
        .await;
    let client = mmb_validated_client(&static_url);
    let err = client
        .get_operation_range(request, &local.current_boundary.root)
        .await
        .expect_err("extra pinned nodes should fail operation range verification");
    assert!(matches!(
        err,
        QmdbError::ProofVerification {
            kind: exoware_qmdb::ProofKind::RangeCheckpoint
        }
    ));
}

#[tokio::test]
async fn ordered_mmb_operation_range_client_rejects_zero_start_pinned_nodes() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_mmb_local_batch().await;
    commit_mmb_upload(&store_client, &local).await;

    let ordered_client = Arc::new(MmbTestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        mmb_op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_mmb_qmdb_server(ordered_client).await;
    let request = ProtoGetOperationRangeRequest {
        tip: (local.operations.len() - 1) as u64,
        start_location: 0,
        max_locations: 1,
        ..Default::default()
    };
    let mut response = common::operation_log_rpc_client(&qmdb_url)
        .get_operation_range(request.clone())
        .await
        .expect("raw get operation range")
        .into_view()
        .to_owned_message();
    let mut proof = response
        .proof
        .as_option()
        .cloned()
        .expect("operation range proof");
    assert!(proof.pinned_nodes.is_empty());
    proof
        .pinned_nodes
        .push(local.current_boundary.root.encode());
    response.proof = Some(proof).into();

    let (_static_server, static_url) =
        common::spawn_static_operation_range_service(common::StaticOperationRangeService {
            operation_range_response: response,
        })
        .await;
    let client = mmb_validated_client(&static_url);
    let err = client
        .get_operation_range(request, &local.current_boundary.root)
        .await
        .expect_err("zero-start pinned nodes should fail operation range verification");
    assert!(matches!(
        err,
        QmdbError::ProofVerification {
            kind: exoware_qmdb::ProofKind::RangeCheckpoint
        }
    ));
}

#[tokio::test]
async fn ordered_operation_range_connect_uses_current_root_witness() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    commit_upload(&store_client, &local).await;

    let ordered_client = Arc::new(TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client).await;
    let request = ProtoGetOperationRangeRequest {
        tip: (local.operations.len() - 1) as u64,
        start_location: 0,
        max_locations: local.operations.len() as u32,
        ..Default::default()
    };

    let raw_response = common::operation_log_rpc_client(&qmdb_url)
        .get_operation_range(request.clone())
        .await
        .expect("raw get operation range")
        .into_view()
        .to_owned_message();
    let raw_proof = raw_response
        .proof
        .as_option()
        .expect("operation range proof");
    assert!(!raw_proof.ops_root.is_empty());
    assert!(!raw_proof.ops_root_witness.is_empty());

    let client = validated_client(&qmdb_url);
    let proof = client
        .get_operation_range(request, &local.current_boundary.root)
        .await
        .expect("get operation range");
    assert_eq!(proof.root, local.current_boundary.root);
    assert_eq!(proof.start_location, Location::new(0));
    let expected: Vec<(Location<mmr::Family>, BatchOperation)> = local
        .operations
        .iter()
        .enumerate()
        .map(|(index, operation)| (Location::new(index as u64), operation.clone()))
        .collect();
    assert_eq!(proof.operations, expected);
}

fn match_exact(key: &[u8]) -> ProtoFilter {
    ProtoFilter {
        kind: Some(proto_filter::Kind::Exact(Bytes::copy_from_slice(key))),
        ..Default::default()
    }
}

fn match_prefix(prefix: &[u8]) -> ProtoFilter {
    ProtoFilter {
        kind: Some(proto_filter::Kind::Prefix(Bytes::copy_from_slice(prefix))),
        ..Default::default()
    }
}

fn match_regex(regex: &str) -> ProtoFilter {
    ProtoFilter {
        kind: Some(proto_filter::Kind::Regex(regex.to_string())),
        ..Default::default()
    }
}

fn all_operations_for_key(
    operations: &[BatchOperation],
    key: &[u8],
) -> Vec<(Location<mmr::Family>, BatchOperation)> {
    operations
        .iter()
        .enumerate()
        .filter_map(|(index, operation)| match operation {
            BatchOperation::Delete(found) if found.as_slice() == key => Some((
                Location::<mmr::Family>::new(index as u64),
                operation.clone(),
            )),
            BatchOperation::Update(Update { key: found, .. }) if found.as_slice() == key => Some((
                Location::<mmr::Family>::new(index as u64),
                operation.clone(),
            )),
            _ => None,
        })
        .collect()
}

fn all_mmb_operations_for_key(
    operations: &[MmbBatchOperation],
    key: &[u8],
) -> Vec<(Location<mmb::Family>, MmbBatchOperation)> {
    operations
        .iter()
        .enumerate()
        .filter_map(|(index, operation)| match operation {
            MmbBatchOperation::Delete(found) if found.as_slice() == key => Some((
                Location::<mmb::Family>::new(index as u64),
                operation.clone(),
            )),
            MmbBatchOperation::Update(Update { key: found, .. }) if found.as_slice() == key => {
                Some((
                    Location::<mmb::Family>::new(index as u64),
                    operation.clone(),
                ))
            }
            _ => None,
        })
        .collect()
}

fn latest_mmb_value_for_key(operations: &[MmbBatchOperation], key: &[u8]) -> Option<Vec<u8>> {
    operations
        .iter()
        .rev()
        .find_map(|operation| match operation {
            MmbBatchOperation::Delete(found) if found.as_slice() == key => Some(None),
            MmbBatchOperation::Update(Update {
                key: found, value, ..
            }) if found.as_slice() == key => Some(Some(value.clone())),
            _ => None,
        })
        .expect("key appears in operation log")
}

#[tokio::test]
async fn ordered_range_connect_subscribe_emits_verifiable_range_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    assert!(
        *local.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    let ordered_client = Arc::new(TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client).await;
    let client = validated_client(&qmdb_url);

    let mut stream = client
        .subscribe(ProtoSubscribeRequest::default())
        .await
        .expect("subscribe");

    tokio::time::sleep(Duration::from_millis(50)).await;
    commit_upload(&store_client, &local).await;

    let frame: OperationLogSubscribeProof<Digest, BatchOperation, mmr::Family> =
        tokio::time::timeout(
            Duration::from_secs(5),
            stream.message_with_root(common::trusted_root(local.current_boundary.root)),
        )
        .await
        .expect("timeout")
        .expect("stream result")
        .expect("stream frame");

    assert!(frame.resume_sequence_number > 0);
    let expected: Vec<(Location<mmr::Family>, BatchOperation)> = local
        .operations
        .iter()
        .enumerate()
        .map(|(i, op)| (Location::<mmr::Family>::new(i as u64), op.clone()))
        .collect();
    assert_eq!(frame.operations, expected);
}

#[tokio::test]
async fn ordered_range_connect_client_rejects_invalid_streamed_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    commit_upload(&store_client, &local).await;

    let ordered_client = Arc::new(TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client).await;
    let rpc = common::operation_log_rpc_client(&qmdb_url);
    let mut raw_stream = rpc
        .subscribe(ProtoSubscribeRequest {
            since_sequence_number: Some(1),
            ..Default::default()
        })
        .await
        .expect("subscribe");
    let raw_response = raw_stream
        .message()
        .await
        .expect("stream result")
        .expect("stream frame")
        .to_owned_message();

    let (_static_server, static_url) =
        common::spawn_static_operation_log_service(common::StaticOperationLogService {
            subscribe_response: common::tamper_subscribe_response(raw_response),
        })
        .await;
    let client = validated_client(&static_url);
    let mut stream = client
        .subscribe(ProtoSubscribeRequest::default())
        .await
        .expect("subscribe");

    let err = stream
        .message_with_root(common::trusted_root(local.current_boundary.root))
        .await
        .expect_err("tampered streamed proof should fail");
    assert!(matches!(
        err,
        QmdbError::ProofVerification {
            kind: exoware_qmdb::ProofKind::BatchMulti
        }
    ));
}

#[tokio::test]
async fn ordered_range_connect_subscribe_emits_multi_proof_for_matching_keys() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    let ordered_client = Arc::new(TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client.clone()).await;
    let client = validated_client(&qmdb_url);

    let mut stream = client
        .subscribe(ProtoSubscribeRequest {
            key_filters: vec![match_exact(b"alpha")],
            ..Default::default()
        })
        .await
        .expect("subscribe");

    tokio::time::sleep(Duration::from_millis(50)).await;
    commit_upload(&store_client, &local).await;

    let frame: OperationLogSubscribeProof<Digest, BatchOperation, mmr::Family> =
        tokio::time::timeout(
            Duration::from_secs(5),
            stream.message_with_root(common::trusted_root(local.current_boundary.root)),
        )
        .await
        .expect("timeout")
        .expect("stream result")
        .expect("stream frame");

    let expected = all_operations_for_key(&local.operations, b"alpha");
    assert!(!expected.is_empty());
    assert!(frame.resume_sequence_number > 0);
    assert_eq!(frame.operations, expected);
}

#[tokio::test]
async fn ordered_mmb_range_connect_subscribe_verifies_range_and_multi_proofs() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_mmb_local_batch().await;
    assert!(
        *local.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    let ordered_client = Arc::new(MmbTestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        mmb_op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_mmb_qmdb_server(ordered_client).await;
    let client = mmb_validated_client(&qmdb_url);

    let mut range_stream = client
        .subscribe(ProtoSubscribeRequest::default())
        .await
        .expect("range subscribe");

    tokio::time::sleep(Duration::from_millis(50)).await;
    commit_mmb_upload(&store_client, &local).await;

    let range_frame: OperationLogSubscribeProof<Digest, MmbBatchOperation, mmb::Family> =
        tokio::time::timeout(
            Duration::from_secs(5),
            range_stream.message_with_root(common::trusted_root(local.current_boundary.root)),
        )
        .await
        .expect("range timeout")
        .expect("range stream result")
        .expect("range stream frame");

    let expected_all: Vec<(Location<mmb::Family>, MmbBatchOperation)> = local
        .operations
        .iter()
        .enumerate()
        .map(|(i, op)| (Location::<mmb::Family>::new(i as u64), op.clone()))
        .collect();
    assert_eq!(range_frame.operations, expected_all);

    let mut multi_stream = client
        .subscribe(ProtoSubscribeRequest {
            key_filters: vec![match_exact(b"alpha")],
            since_sequence_number: Some(1),
            ..Default::default()
        })
        .await
        .expect("multi subscribe");

    let multi_frame: OperationLogSubscribeProof<Digest, MmbBatchOperation, mmb::Family> =
        tokio::time::timeout(
            Duration::from_secs(5),
            multi_stream.message_with_root(common::trusted_root(local.current_boundary.root)),
        )
        .await
        .expect("multi timeout")
        .expect("multi stream result")
        .expect("multi stream frame");

    let expected_filtered = all_mmb_operations_for_key(&local.operations, b"alpha");
    assert!(!expected_filtered.is_empty());
    assert_eq!(multi_frame.operations, expected_filtered);
}

#[tokio::test]
async fn ordered_mmb_operation_log_any_sync_from_connect_api_reconstructs_any_db() {
    const FETCH_BATCH_SIZE: u64 = 3;

    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_mmb_local_batch().await;
    assert!(
        local.operations.len() as u64 > FETCH_BATCH_SIZE * 2,
        "MMB any-sync fixture must require at least three fetches"
    );
    let expected_alpha = latest_mmb_value_for_key(&local.operations, b"alpha");
    commit_mmb_upload(&store_client, &local).await;

    let ordered_client = Arc::new(MmbTestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        mmb_op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_mmb_qmdb_server(ordered_client).await;
    let resolver = OperationLogSyncResolver::<_, mmb::Family, Sha256, MmbBatchOperation>::plaintext(
        &qmdb_url,
        mmb_op_cfg(),
    );
    let op_count = Location::new(local.operations.len() as u64);
    let target = resolver.target(op_count).await.expect("any sync target");
    let target_root = target.root;

    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};

            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::any_variable_config(
                "ordered-mmb-any-sync-connect",
                page_cache,
                mmb_op_cfg(),
                NZU64!(8),
            );
            let db: MmbAnyLocalDb = qmdb_sync::sync(qmdb_sync::engine::Config {
                context: context.child("sync"),
                resolver,
                target,
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(3),
                apply_batch_size: 32,
                db_config: cfg,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 4,
            })
            .await
            .expect("sync any db from MMB API");

            assert_eq!(db.root(), target_root);
            assert_eq!(
                db.get(&b"alpha".to_vec()).await.expect("get alpha"),
                expected_alpha
            );
            db.destroy().await.expect("destroy synced db");
        });
    })
    .await
    .expect("join any sync runner");
}

#[tokio::test]
async fn ordered_mmb_operation_log_any_sync_from_nonzero_connect_api_reconstructs_any_db() {
    const FETCH_BATCH_SIZE: u64 = 3;

    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_mmb_local_batch().await;
    let start = Location::<mmb::Family>::new(3);
    let start_index = usize::try_from(*start).expect("start fits usize");
    let remaining_ops = local
        .operations
        .len()
        .checked_sub(start_index)
        .expect("sync start is inside operation log");
    assert!(
        remaining_ops as u64 > FETCH_BATCH_SIZE * 2,
        "MMB any-sync fixture must require at least three nonzero-start fetches"
    );
    let expected_alpha = latest_mmb_value_for_key(&local.operations[start_index..], b"alpha");
    commit_mmb_upload(&store_client, &local).await;

    let ordered_client = Arc::new(MmbTestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        mmb_op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_mmb_qmdb_server(ordered_client).await;
    let resolver = OperationLogSyncResolver::<_, mmb::Family, Sha256, MmbBatchOperation>::plaintext(
        &qmdb_url,
        mmb_op_cfg(),
    );
    let op_count = Location::new(local.operations.len() as u64);
    let target = resolver
        .target_range(start, op_count)
        .await
        .expect("any nonzero sync target");
    let target_root = target.root;

    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};

            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::any_variable_config(
                "ordered-mmb-any-sync-nonzero-connect",
                page_cache,
                mmb_op_cfg(),
                NZU64!(8),
            );
            let db: MmbAnyLocalDb = qmdb_sync::sync(qmdb_sync::engine::Config {
                context: context.child("sync"),
                resolver,
                target,
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(3),
                apply_batch_size: 32,
                db_config: cfg,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 4,
            })
            .await
            .expect("sync any db from nonzero MMB API");

            assert_eq!(db.root(), target_root);
            let bounds = db.bounds().await;
            assert_eq!(bounds.start, start);
            assert_eq!(bounds.end, op_count);
            assert_eq!(
                db.get(&b"alpha".to_vec()).await.expect("get alpha"),
                expected_alpha
            );
            db.destroy().await.expect("destroy synced db");
        });
    })
    .await
    .expect("join nonzero any sync runner");
}

#[tokio::test]
async fn ordered_mmb_operation_log_any_sync_accepts_target_update_from_growing_backend() {
    const FETCH_BATCH_SIZE: u64 = 3;

    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_mmb_growing_local_batch().await;
    let start = Location::<mmb::Family>::new(1);
    let start_index = usize::try_from(*start).expect("start fits usize");
    let initial_remaining_ops = local
        .initial
        .operations
        .len()
        .checked_sub(start_index)
        .expect("sync start is inside initial operation log");
    assert!(*start > 0, "growing MMB sync must exercise a nonzero start");
    assert!(
        start <= local.initial.inactivity_floor,
        "growing MMB sync start must be within the safe sync boundary"
    );
    assert!(
        initial_remaining_ops as u64 > FETCH_BATCH_SIZE * 2,
        "initial MMB any-sync target must require at least three nonzero-start fetches"
    );
    let added_operations = local.updated.operations.len() - local.initial.operations.len();
    assert!(
        added_operations as u64 > FETCH_BATCH_SIZE * 2,
        "updated MMB any-sync target must add at least three fetches"
    );
    let expected_alpha =
        latest_mmb_value_for_key(&local.updated.operations[start_index..], b"alpha");
    commit_mmb_upload(&store_client, &local.initial).await;

    let ordered_client = Arc::new(MmbTestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        mmb_op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_mmb_qmdb_server(ordered_client).await;
    let resolver = OperationLogSyncResolver::<_, mmb::Family, Sha256, MmbBatchOperation>::plaintext(
        &qmdb_url,
        mmb_op_cfg(),
    );
    let target_resolver = resolver.clone();
    let initial_op_count = Location::new(local.initial.operations.len() as u64);
    let updated_op_count = Location::new(local.updated.operations.len() as u64);
    let initial_target = resolver
        .target_range(start, initial_op_count)
        .await
        .expect("initial nonzero any sync target");
    let expected_initial_target = initial_target.clone();

    let (update_tx, update_rx) = mpsc::channel(1);
    let (finish_tx, finish_rx) = mpsc::channel(1);
    let (reached_tx, mut reached_rx) = mpsc::channel(2);
    let sync_expected_alpha = expected_alpha;
    let sync_handle = tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};

            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::any_variable_config(
                "ordered-mmb-any-sync-growing-connect",
                page_cache,
                mmb_op_cfg(),
                NZU64!(8),
            );
            let db: MmbAnyLocalDb = qmdb_sync::sync(qmdb_sync::engine::Config {
                context: context.child("sync"),
                resolver,
                target: initial_target,
                max_outstanding_requests: 1,
                fetch_batch_size: NZU64!(3),
                apply_batch_size: 4,
                db_config: cfg,
                update_rx: Some(update_rx),
                finish_rx: Some(finish_rx),
                reached_target_tx: Some(reached_tx),
                max_retained_roots: 4,
            })
            .await
            .expect("sync any db from growing MMB API");

            assert_eq!(
                db.get(&b"alpha".to_vec()).await.expect("get alpha"),
                sync_expected_alpha
            );
            let bounds = db.bounds().await;
            assert_eq!(bounds.start, start);
            assert_eq!(bounds.end, updated_op_count);
            db.destroy().await.expect("destroy synced db");
        });
    });

    let reached_initial = tokio::time::timeout(Duration::from_secs(30), reached_rx.recv())
        .await
        .expect("timed out waiting for initial sync target")
        .expect("initial sync target channel closed");
    assert_eq!(reached_initial, expected_initial_target);

    commit_mmb_upload(&store_client, &local.updated).await;
    let updated_target = target_resolver
        .target_range(start, updated_op_count)
        .await
        .expect("updated nonzero any sync target");
    assert_ne!(updated_target, expected_initial_target);
    update_tx
        .send(updated_target.clone())
        .await
        .expect("send updated sync target");

    let reached_updated = tokio::time::timeout(Duration::from_secs(30), reached_rx.recv())
        .await
        .expect("timed out waiting for updated sync target")
        .expect("updated sync target channel closed");
    assert_eq!(reached_updated, updated_target);

    finish_tx.send(()).await.expect("send finish request");
    sync_handle.await.expect("join growing any sync runner");
}

#[tokio::test]
async fn ordered_range_connect_subscribe_replays_since_cursor() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    let ordered_client = Arc::new(TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client.clone()).await;
    let client = validated_client(&qmdb_url);

    commit_upload(&store_client, &local).await;

    let mut stream = client
        .subscribe(ProtoSubscribeRequest {
            key_filters: vec![match_exact(b"alpha")],
            since_sequence_number: Some(1),
            ..Default::default()
        })
        .await
        .expect("subscribe");

    let frame = tokio::time::timeout(
        Duration::from_secs(5),
        stream.message_with_root(common::trusted_root(local.current_boundary.root)),
    )
    .await
    .expect("timeout")
    .expect("stream result")
    .expect("stream frame");

    let expected = all_operations_for_key(&local.operations, b"alpha");
    assert!(!expected.is_empty());
    assert_eq!(frame.operations, expected);
}

#[tokio::test]
async fn ordered_range_connect_subscribe_matches_prefix_and_regex_filters() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    let ordered_client = Arc::new(TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client.clone()).await;
    let client = validated_client(&qmdb_url);

    let mut prefix_stream = client
        .subscribe(ProtoSubscribeRequest {
            key_filters: vec![match_prefix(b"alp")],
            ..Default::default()
        })
        .await
        .expect("prefix subscribe");
    let mut regex_stream = client
        .subscribe(ProtoSubscribeRequest {
            key_filters: vec![match_regex("^be.*$")],
            ..Default::default()
        })
        .await
        .expect("regex subscribe");

    tokio::time::sleep(Duration::from_millis(50)).await;
    commit_upload(&store_client, &local).await;

    let prefix_frame = tokio::time::timeout(
        Duration::from_secs(5),
        prefix_stream.message_with_root(common::trusted_root(local.current_boundary.root)),
    )
    .await
    .expect("prefix timeout")
    .expect("prefix stream result")
    .expect("prefix stream frame");
    let regex_frame = tokio::time::timeout(
        Duration::from_secs(5),
        regex_stream.message_with_root(common::trusted_root(local.current_boundary.root)),
    )
    .await
    .expect("regex timeout")
    .expect("regex stream result")
    .expect("regex stream frame");

    let alpha = all_operations_for_key(&local.operations, b"alpha");
    let beta = all_operations_for_key(&local.operations, b"beta");
    assert!(!alpha.is_empty());
    assert!(!beta.is_empty());

    assert_eq!(prefix_frame.operations, alpha);
    assert_eq!(regex_frame.operations, beta);
}

#[tokio::test]
async fn ordered_range_connect_subscribe_filters_by_value_regex_without_key() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    let ordered_client = Arc::new(TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client.clone()).await;
    let client = validated_client(&qmdb_url);

    // Regex matches the literal "one" — the value written for key "alpha" but
    // not for "beta". The client supplies no key filter.
    let mut stream = client
        .subscribe(ProtoSubscribeRequest {
            value_filters: vec![match_regex("^one$")],
            ..Default::default()
        })
        .await
        .expect("subscribe");

    tokio::time::sleep(Duration::from_millis(50)).await;
    commit_upload(&store_client, &local).await;

    let frame: OperationLogSubscribeProof<Digest, BatchOperation, mmr::Family> =
        tokio::time::timeout(
            Duration::from_secs(5),
            stream.message_with_root(common::trusted_root(local.current_boundary.root)),
        )
        .await
        .expect("timeout")
        .expect("stream result")
        .expect("stream frame");

    let expected = all_operations_for_key(&local.operations, b"alpha");
    assert!(!expected.is_empty());
    assert_eq!(frame.operations, expected);
}

#[tokio::test]
async fn ordered_range_connect_subscribe_intersects_key_and_value_filters() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    let ordered_client = Arc::new(TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client.clone()).await;
    let client = validated_client(&qmdb_url);

    // Key prefix matches alpha + beta; value regex excludes everything except
    // "two". Intersection should leave only beta's updates.
    let mut stream = client
        .subscribe(ProtoSubscribeRequest {
            key_filters: vec![match_prefix(b"")],
            value_filters: vec![match_regex("^two$")],
            ..Default::default()
        })
        .await
        .expect("subscribe");

    tokio::time::sleep(Duration::from_millis(50)).await;
    commit_upload(&store_client, &local).await;

    let frame = tokio::time::timeout(
        Duration::from_secs(5),
        stream.message_with_root(common::trusted_root(local.current_boundary.root)),
    )
    .await
    .expect("timeout")
    .expect("stream result")
    .expect("stream frame");

    let expected = all_operations_for_key(&local.operations, b"beta");
    assert!(!expected.is_empty());
    assert_eq!(frame.operations, expected);
}
