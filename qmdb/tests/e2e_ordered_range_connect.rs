//! Ordered QMDB range-stream ConnectRPC e2e: streamed historical checkpoints
//! plus client-side validation of tampered proofs.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::merkle::{mmr, Location, Proof};
use commonware_storage::qmdb::any::ordered::variable::Operation as QmdbOperation;
use commonware_storage::qmdb::{
    any::ordered::Update, current::ordered::variable::Db as LocalQmdbDb,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::{
    ordered_connect_stack, recover_boundary_state, CurrentBoundaryState, CurrentOperationClient,
    OperationLogClient, OperationLogSubscribeProof, OrderedClient, OrderedWriter, QmdbError,
    MAX_OPERATION_SIZE,
};
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::qmdb::v1::{
    GetCurrentOperationRangeRequest as ProtoGetCurrentOperationRangeRequest,
    SubscribeRequest as ProtoSubscribeRequest,
};
use exoware_sdk::store::common::v1::{
    bytes_filter as proto_bytes_filter, BytesFilter as ProtoBytesFilter,
};
use exoware_sdk::StoreClient;

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchProof = Proof<mmr::Family, Digest>;
type BatchOperation = QmdbOperation<mmr::Family, Vec<u8>, Vec<u8>>;
type TestOrderedClient = OrderedClient<mmr::Family, Sha256, Vec<u8>, Vec<u8>, N>;
type LocalDb = LocalQmdbDb<mmr::Family, cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap, N>;

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

async fn boundary_from_local_db(
    db: &LocalDb,
    previous_operations: Option<&[BatchOperation]>,
    operations: &[BatchOperation],
) -> CurrentBoundaryState<Digest, N, mmr::Family> {
    recover_boundary_state::<mmr::Family, Sha256, _, N, _, _>(
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

struct LocalBatch {
    operations: Vec<BatchOperation>,
    operation_root: Digest,
    current_boundary: CurrentBoundaryState<Digest, N, mmr::Family>,
}

async fn build_local_batch() -> LocalBatch {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
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
            let mut db: LocalDb = LocalDb::init(context.with_label("qmdb"), cfg)
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
            let (_proof, ops): (BatchProof, Vec<BatchOperation>) = db
                .ops_historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");
            let boundary = boundary_from_local_db(&db, None, &ops).await;
            let operation_root = db.ops_root();

            db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            LocalBatch {
                operations: ops,
                operation_root,
                current_boundary: boundary,
            }
        })
    })
    .await
    .expect("join")
}

async fn commit_upload(client: &StoreClient, batch: &LocalBatch) {
    let writer: OrderedWriter<mmr::Family, Sha256, Vec<u8>, Vec<u8>, N> =
        OrderedWriter::empty(client.clone());
    common::commit_ordered_upload(client, &writer, &batch.operations, &batch.current_boundary)
        .await
        .expect("commit upload");
}

#[tokio::test]
async fn ordered_current_operation_range_connect_emits_verifiable_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    commit_upload(&store_client, &local).await;

    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
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

fn match_exact(key: &[u8]) -> ProtoBytesFilter {
    ProtoBytesFilter {
        kind: Some(proto_bytes_filter::Kind::Exact(key.to_vec())),
        ..Default::default()
    }
}

fn match_prefix(prefix: &[u8]) -> ProtoBytesFilter {
    ProtoBytesFilter {
        kind: Some(proto_bytes_filter::Kind::Prefix(prefix.to_vec())),
        ..Default::default()
    }
}

fn match_regex(regex: &str) -> ProtoBytesFilter {
    ProtoBytesFilter {
        kind: Some(proto_bytes_filter::Kind::Regex(regex.to_string())),
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

#[tokio::test]
async fn ordered_range_connect_subscribe_emits_verifiable_range_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
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
            stream.message_with_root(common::trusted_root(local.operation_root)),
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

    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
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
        .message_with_root(common::trusted_root(local.operation_root))
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
    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
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
            stream.message_with_root(common::trusted_root(local.operation_root)),
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
async fn ordered_range_connect_subscribe_replays_since_cursor() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
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
        stream.message_with_root(common::trusted_root(local.operation_root)),
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
    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
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
        prefix_stream.message_with_root(common::trusted_root(local.operation_root)),
    )
    .await
    .expect("prefix timeout")
    .expect("prefix stream result")
    .expect("prefix stream frame");
    let regex_frame = tokio::time::timeout(
        Duration::from_secs(5),
        regex_stream.message_with_root(common::trusted_root(local.operation_root)),
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
    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
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
            stream.message_with_root(common::trusted_root(local.operation_root)),
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
    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
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
        stream.message_with_root(common::trusted_root(local.operation_root)),
    )
    .await
    .expect("timeout")
    .expect("stream result")
    .expect("stream frame");

    let expected = all_operations_for_key(&local.operations, b"beta");
    assert!(!expected.is_empty());
    assert_eq!(frame.operations, expected);
}
