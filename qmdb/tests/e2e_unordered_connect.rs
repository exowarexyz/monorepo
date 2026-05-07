//! Unordered QMDB ConnectRPC e2e: streamed range checkpoints plus client-side
//! validation of tampered proofs.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::merkle::{mmr, Location, Proof};
use commonware_storage::qmdb::any::unordered::variable::Db as LocalUnorderedDb;
use commonware_storage::qmdb::any::unordered::variable::Operation as UnorderedQmdbOperation;
use commonware_storage::qmdb::current::unordered::variable::Db as LocalCurrentUnorderedDb;
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use connectrpc::client::ClientConfig;
use connectrpc::ErrorCode;
use exoware_qmdb::{
    recover_boundary_state, unordered_connect_stack, unordered_operation_log_connect_stack,
    CurrentBoundaryState, OperationLogClient, OperationLogSubscribeProof, QmdbError,
    UnorderedClient, UnorderedConnectClient, UnorderedWriter, MAX_OPERATION_SIZE,
};
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::qmdb::v1::{
    GetManyRequest as ProtoGetManyRequest, GetRangeRequest as ProtoGetRangeRequest,
    GetRequest as ProtoGetRequest, KeyLookupServiceClient, OrderedKeyRangeServiceClient,
    SubscribeRequest as ProtoSubscribeRequest,
};
use exoware_sdk::StoreClient;

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchProof = Proof<mmr::Family, Digest>;
type BatchOperation = UnorderedQmdbOperation<mmr::Family, Vec<u8>, Vec<u8>>;
type FixedBatchOperation = UnorderedQmdbOperation<mmr::Family, Digest, Vec<u8>>;
type TestUnorderedClient = UnorderedClient<mmr::Family, Sha256, Vec<u8>, Vec<u8>>;
type FixedTestUnorderedClient = UnorderedClient<mmr::Family, Sha256, Digest, Vec<u8>>;
type LocalDb = LocalUnorderedDb<mmr::Family, cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap>;
type LocalCurrentDb =
    LocalCurrentUnorderedDb<mmr::Family, cw_tokio::Context, Digest, Vec<u8>, Sha256, TwoCap, N>;

async fn spawn_qmdb_range_server(
    client: Arc<TestUnorderedClient>,
) -> (tokio::task::JoinHandle<()>, String) {
    common::spawn_operation_log_service(unordered_operation_log_connect_stack(client)).await
}

async fn spawn_qmdb_full_server(
    client: Arc<FixedTestUnorderedClient>,
) -> (tokio::task::JoinHandle<()>, String) {
    common::spawn_operation_log_service(unordered_connect_stack::<
        mmr::Family,
        Sha256,
        Digest,
        Vec<u8>,
        N,
    >(client))
    .await
}

fn validated_client(
    base: &str,
) -> OperationLogClient<PreferZstdHttpClient, mmr::Family, Sha256, BatchOperation> {
    OperationLogClient::plaintext(base, op_cfg())
}

fn validated_key_client(
    base: &str,
) -> UnorderedConnectClient<PreferZstdHttpClient, mmr::Family, Sha256, Digest, Vec<u8>, N> {
    UnorderedConnectClient::plaintext(base, fixed_op_cfg())
}

fn key_lookup_rpc_client(base: &str) -> KeyLookupServiceClient<PreferZstdHttpClient> {
    KeyLookupServiceClient::new(
        PreferZstdHttpClient::plaintext(),
        ClientConfig::new(base.parse().expect("qmdb uri")),
    )
}

fn ordered_range_rpc_client(base: &str) -> OrderedKeyRangeServiceClient<PreferZstdHttpClient> {
    OrderedKeyRangeServiceClient::new(
        PreferZstdHttpClient::plaintext(),
        ClientConfig::new(base.parse().expect("qmdb uri")),
    )
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

fn fixed_op_cfg() -> <FixedBatchOperation as commonware_codec::Read>::Cfg {
    ((), ((0..=MAX_OPERATION_SIZE).into(), ()))
}

fn fixed_update_row_cfg() -> (
    <Digest as commonware_codec::Read>::Cfg,
    <Vec<u8> as commonware_codec::Read>::Cfg,
) {
    ((), ((0..=MAX_OPERATION_SIZE).into(), ()))
}

struct LocalBatch {
    operations: Vec<BatchOperation>,
    root: Digest,
}

struct FixedLocalBatch {
    latest_location: Location<mmr::Family>,
    alpha: Digest,
    beta: Digest,
    root: Digest,
    operations: Vec<FixedBatchOperation>,
    current_boundary: CurrentBoundaryState<Digest, N, mmr::Family>,
}

async fn boundary_from_local_current_db(
    db: &LocalCurrentDb,
    operations: &[FixedBatchOperation],
) -> CurrentBoundaryState<Digest, N, mmr::Family> {
    let mut ops_root_hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let ops_root_witness = db
        .ops_root_witness(&mut ops_root_hasher)
        .await
        .expect("ops root witness");
    recover_boundary_state::<mmr::Family, Sha256, _, N, _, _>(
        None,
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
                        "local current unordered range proof at {location}: {error}"
                    ))
                })?;
            proof_ops.pop().ok_or_else(|| {
                exoware_qmdb::QmdbError::CorruptData(format!(
                    "local current unordered range proof at {location} returned no operations"
                ))
            })?;
            let chunk = chunks.pop().ok_or_else(|| {
                exoware_qmdb::QmdbError::CorruptData(format!(
                    "local current unordered range proof at {location} returned no chunks"
                ))
            })?;
            Ok((proof, chunk))
        },
    )
    .await
    .expect("recover unordered current boundary")
}

async fn build_local_batch() -> LocalBatch {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::unordered_variable_config(
                "unordered-connect",
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
            let (_proof, ops): (BatchProof, Vec<BatchOperation>) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");
            let root = db.root();

            db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            LocalBatch {
                operations: ops,
                root,
            }
        })
    })
    .await
    .expect("join")
}

async fn build_fixed_local_batch() -> FixedLocalBatch {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::ordered_variable_config(
                "unordered-current-connect",
                page_cache,
                fixed_op_cfg(),
                NZU64!(8),
            );
            let mut db: LocalCurrentDb = LocalCurrentDb::init(context.with_label("current"), cfg)
                .await
                .expect("init");

            let alpha = Sha256::fill(0xA1);
            let beta = Sha256::fill(0xB2);
            let finalized = {
                let batch = db
                    .new_batch()
                    .write(alpha, Some(b"one".to_vec()))
                    .write(beta, Some(b"two".to_vec()));
                batch
                    .merkleize(&db, None::<Vec<u8>>)
                    .await
                    .expect("merkleize")
            };
            db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (BatchProof, Vec<FixedBatchOperation>) = db
                .ops_historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");
            let boundary = boundary_from_local_current_db(&db, &ops).await;

            db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            FixedLocalBatch {
                latest_location: latest,
                alpha,
                beta,
                root: boundary.root,
                operations: ops,
                current_boundary: boundary,
            }
        })
    })
    .await
    .expect("join")
}

async fn commit_upload(client: &StoreClient, batch: &LocalBatch) {
    let writer: UnorderedWriter<mmr::Family, Sha256, Vec<u8>, Vec<u8>> =
        UnorderedWriter::empty(client.clone());
    common::commit_unordered_upload(client, &writer, &batch.operations)
        .await
        .expect("commit upload");
}

async fn commit_fixed_upload(client: &StoreClient, batch: &FixedLocalBatch) {
    let writer: UnorderedWriter<mmr::Family, Sha256, Digest, Vec<u8>> =
        UnorderedWriter::empty(client.clone());
    common::commit_unordered_current_upload::<_, _, _, _, N>(
        client,
        &writer,
        &batch.operations,
        &batch.current_boundary,
    )
    .await
    .expect("commit current upload");
}

fn latest_fixed_operation_for_key(
    operations: &[FixedBatchOperation],
    key: &[u8],
) -> (Location<mmr::Family>, FixedBatchOperation) {
    operations
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, operation)| match operation {
            FixedBatchOperation::Update(update) if update.0.as_ref() == key => {
                Some((Location::new(index as u64), operation.clone()))
            }
            FixedBatchOperation::Delete(found) if found.as_ref() == key => {
                Some((Location::new(index as u64), operation.clone()))
            }
            _ => None,
        })
        .expect("matching operation")
}

#[tokio::test]
async fn unordered_range_stack_does_not_expose_key_lookup_or_ordered_range_services() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let unordered_client = Arc::new(TestUnorderedClient::from_client(
        store_client,
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_range_server(unordered_client).await;

    let err = key_lookup_rpc_client(&qmdb_url)
        .get_many(ProtoGetManyRequest {
            keys: vec![b"alpha".to_vec()],
            tip: 0,
            ..Default::default()
        })
        .await
        .expect_err("unordered stack should not expose KeyLookupService");
    assert_eq!(err.code, ErrorCode::Unimplemented);

    let err = ordered_range_rpc_client(&qmdb_url)
        .get_range(ProtoGetRangeRequest {
            start_key: b"a".to_vec(),
            limit: 1,
            tip: 0,
            ..Default::default()
        })
        .await
        .expect_err("unordered stack should not expose OrderedKeyRangeService");
    assert_eq!(err.code, ErrorCode::Unimplemented);
}

#[tokio::test]
async fn unordered_connect_get_many_returns_present_key_proofs() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_fixed_local_batch().await;
    commit_fixed_upload(&store_client, &local).await;

    let unordered_client = Arc::new(FixedTestUnorderedClient::from_client(
        store_client,
        fixed_op_cfg(),
        fixed_update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_full_server(unordered_client).await;
    let client = validated_key_client(&qmdb_url);

    let results = client
        .get_many(
            ProtoGetManyRequest {
                keys: vec![local.alpha.as_ref().to_vec(), local.beta.as_ref().to_vec()],
                tip: local.latest_location.as_u64(),
                ..Default::default()
            },
            &local.root,
        )
        .await
        .expect("get_many");

    let expected_alpha = latest_fixed_operation_for_key(&local.operations, local.alpha.as_ref());
    let expected_beta = latest_fixed_operation_for_key(&local.operations, local.beta.as_ref());
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].root, local.root);
    assert_eq!(results[0].location, expected_alpha.0);
    assert_eq!(results[0].operation, expected_alpha.1);
    assert_eq!(results[1].root, local.root);
    assert_eq!(results[1].location, expected_beta.0);
    assert_eq!(results[1].operation, expected_beta.1);

    let one = client
        .get(
            ProtoGetRequest {
                key: local.alpha.as_ref().to_vec(),
                tip: local.latest_location.as_u64(),
                ..Default::default()
            },
            &local.root,
        )
        .await
        .expect("get");
    assert_eq!(one.location, expected_alpha.0);
    assert_eq!(one.operation, expected_alpha.1);
}

#[tokio::test]
async fn unordered_connect_omits_missing_and_rejects_duplicate_range_and_stale_root() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_fixed_local_batch().await;
    commit_fixed_upload(&store_client, &local).await;

    let unordered_client = Arc::new(FixedTestUnorderedClient::from_client(
        store_client,
        fixed_op_cfg(),
        fixed_update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_full_server(unordered_client).await;

    let missing = Sha256::fill(0xCC);
    let client = validated_key_client(&qmdb_url);
    let existing = client
        .get_many(
            ProtoGetManyRequest {
                keys: vec![local.alpha.as_ref().to_vec(), missing.as_ref().to_vec()],
                tip: local.latest_location.as_u64(),
                ..Default::default()
            },
            &local.root,
        )
        .await
        .expect("unordered get_many with missing key");
    let expected_alpha = latest_fixed_operation_for_key(&local.operations, local.alpha.as_ref());
    assert_eq!(existing.len(), 1);
    assert_eq!(existing[0].location, expected_alpha.0);
    assert_eq!(existing[0].operation, expected_alpha.1);

    let err = key_lookup_rpc_client(&qmdb_url)
        .get_many(ProtoGetManyRequest {
            keys: vec![local.alpha.as_ref().to_vec(), local.alpha.as_ref().to_vec()],
            tip: local.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect_err("duplicate keys should be rejected");
    assert_eq!(err.code, ErrorCode::InvalidArgument);

    let err = ordered_range_rpc_client(&qmdb_url)
        .get_range(ProtoGetRangeRequest {
            start_key: local.alpha.as_ref().to_vec(),
            limit: 1,
            tip: local.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect_err("unordered stack should not expose OrderedKeyRangeService");
    assert_eq!(err.code, ErrorCode::Unimplemented);

    let stale_root = Sha256::fill(0xDD);
    let err = client
        .get_many(
            ProtoGetManyRequest {
                keys: vec![local.alpha.as_ref().to_vec()],
                tip: local.latest_location.as_u64(),
                ..Default::default()
            },
            &stale_root,
        )
        .await
        .expect_err("stale root should be rejected");
    assert!(matches!(
        err,
        QmdbError::ProofVerification {
            kind: exoware_qmdb::ProofKind::CurrentKeyValue
        }
    ));
}

#[tokio::test]
async fn unordered_connect_subscribe_emits_verifiable_range_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    let unordered_client = Arc::new(TestUnorderedClient::from_client(
        store_client.clone(),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_range_server(unordered_client).await;
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
            stream.message_with_root(common::trusted_root(local.root)),
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
        .map(|(i, op)| (Location::new(i as u64), op.clone()))
        .collect();
    assert_eq!(frame.operations, expected);
}

#[tokio::test]
async fn unordered_connect_client_rejects_invalid_streamed_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    commit_upload(&store_client, &local).await;

    let unordered_client = Arc::new(TestUnorderedClient::from_client(
        store_client.clone(),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_range_server(unordered_client).await;
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
        .message_with_root(common::trusted_root(local.root))
        .await
        .expect_err("tampered streamed proof should fail");
    assert!(matches!(
        err,
        QmdbError::ProofVerification {
            kind: exoware_qmdb::ProofKind::BatchMulti
        }
    ));
}
