//! Ordered QMDB range-stream ConnectRPC e2e: streamed historical checkpoints
//! plus client-side validation of tampered proofs.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::any::ordered::variable::Operation as QmdbOperation;
use commonware_storage::qmdb::{
    any::ordered::Update,
    current::{ordered::variable::Db as LocalQmdbDb, VariableConfig},
    store::LogStore as _,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::{
    ordered_connect_stack, recover_boundary_state, CurrentBoundaryState, OrderedClient,
    OrderedRangeConnectClient, OrderedWriter, QmdbError, RangeSubscribeProof, MAX_OPERATION_SIZE,
};
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::store::common::v1::{
    bytes_filter as proto_bytes_filter, BytesFilter as ProtoBytesFilter,
};
use exoware_sdk::store::qmdb::v1::SubscribeRequest as ProtoSubscribeRequest;
use exoware_sdk::StoreClient;

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchProof = commonware_storage::mmr::Proof<Digest>;
type BatchOperation = QmdbOperation<Vec<u8>, Vec<u8>>;
type TestOrderedClient = OrderedClient<Sha256, Vec<u8>, Vec<u8>, N>;
type LocalDb = LocalQmdbDb<cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap, N>;

async fn spawn_qmdb_server(
    client: Arc<TestOrderedClient>,
) -> (tokio::task::JoinHandle<()>, String) {
    common::spawn_range_service(ordered_connect_stack(client)).await
}

fn validated_client(
    base: &str,
) -> OrderedRangeConnectClient<PreferZstdHttpClient, Sha256, Vec<u8>, Vec<u8>> {
    OrderedRangeConnectClient::plaintext(base, op_cfg())
}

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
            Ok((proof.proof, chunk))
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
    current_boundary: CurrentBoundaryState<Digest, N>,
}

async fn build_local_batch() -> LocalBatch {
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

            db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            LocalBatch {
                operations: ops,
                current_boundary: boundary,
            }
        })
    })
    .await
    .expect("join")
}

async fn commit_upload(client: &StoreClient, batch: &LocalBatch) {
    let writer: OrderedWriter<Sha256, Vec<u8>, Vec<u8>, N> = OrderedWriter::empty(client.clone());
    common::commit_ordered_upload(client, &writer, &batch.operations, &batch.current_boundary)
        .await
        .expect("commit upload");
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
) -> Vec<(Location, BatchOperation)> {
    operations
        .iter()
        .enumerate()
        .filter_map(|(index, operation)| match operation {
            BatchOperation::Delete(found) if found.as_slice() == key => {
                Some((Location::new(index as u64), operation.clone()))
            }
            BatchOperation::Update(Update { key: found, .. }) if found.as_slice() == key => {
                Some((Location::new(index as u64), operation.clone()))
            }
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

    let frame: RangeSubscribeProof<Digest, BatchOperation> =
        tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .expect("timeout")
            .expect("stream result")
            .expect("stream frame");

    assert!(frame.resume_sequence_number > 0);
    let expected: Vec<(Location, BatchOperation)> = local
        .operations
        .iter()
        .enumerate()
        .map(|(i, op)| (Location::new(i as u64), op.clone()))
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
    let rpc = common::rpc_client(&qmdb_url);
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
        common::spawn_static_range_service(common::StaticRangeService {
            subscribe_response: common::tamper_subscribe_response(raw_response),
        })
        .await;
    let client = validated_client(&static_url);
    let mut stream = client
        .subscribe(ProtoSubscribeRequest::default())
        .await
        .expect("subscribe");

    let err = stream
        .message()
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

    let frame: RangeSubscribeProof<Digest, BatchOperation> =
        tokio::time::timeout(Duration::from_secs(5), stream.message())
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

    let frame = tokio::time::timeout(Duration::from_secs(5), stream.message())
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

    let prefix_frame = tokio::time::timeout(Duration::from_secs(5), prefix_stream.message())
        .await
        .expect("prefix timeout")
        .expect("prefix stream result")
        .expect("prefix stream frame");
    let regex_frame = tokio::time::timeout(Duration::from_secs(5), regex_stream.message())
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

    let frame: RangeSubscribeProof<Digest, BatchOperation> =
        tokio::time::timeout(Duration::from_secs(5), stream.message())
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

    let frame = tokio::time::timeout(Duration::from_secs(5), stream.message())
        .await
        .expect("timeout")
        .expect("stream result")
        .expect("stream frame");

    let expected = all_operations_for_key(&local.operations, b"beta");
    assert!(!expected.is_empty());
    assert_eq!(frame.operations, expected);
}
