//! Keyless QMDB ConnectRPC e2e: streamed range checkpoints plus client-side
//! validation of tampered proofs.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use commonware_codec::Encode;
use commonware_glue::stateful::db::{StateSyncDb, SyncEngineConfig};
use commonware_runtime::{deterministic, tokio as cw_tokio, Runner as _};
use commonware_storage::merkle::{mmr, Location};
use commonware_storage::qmdb::keyless::variable::{Db as Keyless, Operation as KeylessOperation};
use commonware_storage::qmdb::sync::resolver::Resolver as _;
use commonware_utils::channel::{mpsc, oneshot};
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::proto::qmdb::v1::{
    GetOperationRangeRequest as ProtoGetOperationRangeRequest,
    SubscribeRequest as ProtoSubscribeRequest,
};
use exoware_qmdb::{
    keyless_operation_log_connect_stack, KeylessClient, KeylessWriter, OperationLogClient,
    OperationLogSubscribeProof, OperationLogSyncResolver, QmdbError,
};
use exoware_sdk::common::kv::v1::{filter as proto_filter, Filter as ProtoFilter};
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::{PrefixedStoreClient, StoreClient};

type Digest = commonware_cryptography::sha256::Digest;
type LocalDb = Keyless<
    mmr::Family,
    deterministic::Context,
    Vec<u8>,
    commonware_cryptography::Sha256,
    commonware_parallel::Sequential,
>;
type SyncDb = Keyless<
    mmr::Family,
    cw_tokio::Context,
    Vec<u8>,
    commonware_cryptography::Sha256,
    commonware_parallel::Sequential,
>;
type TestKeylessClient = KeylessClient<mmr::Family, commonware_cryptography::Sha256, Vec<u8>>;
type BatchOperation = KeylessOperation<mmr::Family, Vec<u8>>;

async fn spawn_qmdb_server(
    client: Arc<TestKeylessClient>,
) -> (tokio::task::JoinHandle<()>, String) {
    common::spawn_operation_log_service(keyless_operation_log_connect_stack(client)).await
}

fn validated_client(
    base: &str,
) -> OperationLogClient<
    PreferZstdHttpClient,
    mmr::Family,
    commonware_cryptography::Sha256,
    BatchOperation,
> {
    OperationLogClient::plaintext(base, ((0..=10000).into(), ()))
}

struct LocalBatch {
    operations: Vec<BatchOperation>,
    root: Digest,
    inactivity_floor: Location<mmr::Family>,
}

async fn build_local_batch() -> LocalBatch {
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg =
                common::keyless_config("keyless", page_cache, ((0..=10000).into(), ()), NZU64!(7));
            let mut db: LocalDb = LocalDb::init(context.child("db"), cfg).await.expect("init");

            let finalized = {
                let batch = db
                    .new_batch()
                    .append(b"first-value".to_vec())
                    .append(b"second-value".to_vec());
                batch.merkleize(&db, None::<Vec<u8>>, db.inactivity_floor_loc())
            };
            db.apply_batch(finalized).await.expect("apply");
            let finalized = {
                let batch = db.new_batch().append(b"third-value".to_vec());
                batch.merkleize(&db, None::<Vec<u8>>, db.bounds().await.end - 1)
            };
            db.apply_batch(finalized).await.expect("apply second");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");
            let inactivity_floor = latest_inactivity_floor(&ops);
            let root = db.root();
            db.destroy().await.expect("destroy");

            LocalBatch {
                operations: ops,
                root,
                inactivity_floor,
            }
        })
    })
    .await
    .expect("join")
}

fn latest_inactivity_floor(ops: &[BatchOperation]) -> Location<mmr::Family> {
    match ops.last().expect("non-empty operations") {
        KeylessOperation::Commit(_, floor) => *floor,
        KeylessOperation::Append(_) => panic!("operations must end with Commit"),
    }
}

async fn commit_upload(client: &StoreClient, batch: &LocalBatch) {
    let writer: KeylessWriter<mmr::Family, commonware_cryptography::Sha256, Vec<u8>> =
        KeylessWriter::fresh(PrefixedStoreClient::empty(client.clone()));
    common::commit_keyless_upload(&writer, &batch.operations)
        .await
        .expect("commit upload");
}

#[tokio::test]
async fn keyless_connect_subscribe_emits_verifiable_multi_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    assert!(
        *local.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    let keyless_client = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((0..=10000).into(), ()),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(keyless_client).await;
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
    assert_eq!(frame.root, local.root);
    let expected: Vec<(Location<mmr::Family>, BatchOperation)> = local
        .operations
        .iter()
        .enumerate()
        .map(|(i, op)| (Location::new(i as u64), op.clone()))
        .collect();
    assert_eq!(frame.operations, expected);
}

#[tokio::test]
async fn keyless_connect_get_operation_range_returns_verifiable_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    assert!(
        *local.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    commit_upload(&store_client, &local).await;

    let keyless_client = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((0..=10000).into(), ()),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(keyless_client).await;
    let client = validated_client(&qmdb_url);

    let proof = client
        .get_operation_range(
            ProtoGetOperationRangeRequest {
                tip: u64::try_from(local.operations.len() - 1).expect("tip fits"),
                start_location: 1,
                max_locations: 1,
                ..Default::default()
            },
            &local.root,
        )
        .await
        .expect("get operation range");

    assert_eq!(proof.root, local.root);
    assert_eq!(proof.start_location, Location::new(1));
    assert_eq!(
        proof.operations,
        vec![(Location::new(1), local.operations[1].clone())]
    );
}

#[tokio::test]
async fn keyless_operation_log_sync_resolver_fetches_api_batches() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    commit_upload(&store_client, &local).await;

    let keyless_client = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((0..=10000).into(), ()),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(keyless_client).await;
    let resolver = OperationLogSyncResolver::<
        _,
        mmr::Family,
        commonware_cryptography::Sha256,
        BatchOperation,
    >::plaintext(&qmdb_url, ((0..=10000).into(), ()));
    let op_count = Location::new(local.operations.len() as u64);
    let target = resolver.target(op_count).await.expect("sync target");
    assert_eq!(target.root, local.root);

    let (_cancel_tx, cancel_rx) = oneshot::channel();
    let fetched = resolver
        .get_operations(op_count, Location::new(0), NZU64!(2), false, cancel_rx)
        .await
        .expect("fetch sync operations");
    assert_eq!(fetched.operations.as_slice(), &local.operations[..2]);

    let hasher = commonware_storage::qmdb::hasher::<commonware_cryptography::Sha256>();
    let elements = fetched
        .operations
        .iter()
        .map(|operation| operation.encode())
        .collect::<Vec<_>>();
    assert!(fetched.proof.verify_range_inclusion(
        &hasher,
        &elements,
        Location::new(0),
        &target.root
    ));
    assert!(
        fetched.callback.is_none(),
        "direct sync resolver fetches do not allocate an unused validation callback"
    );
}

#[tokio::test]
async fn keyless_commonware_glue_state_sync_uses_operation_log_resolver() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    assert!(
        *local.inactivity_floor > 0,
        "glue state-sync test must exercise a nonzero replay floor"
    );
    commit_upload(&store_client, &local).await;

    let keyless_client = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((0..=10000).into(), ()),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(keyless_client).await;
    let resolver = OperationLogSyncResolver::<
        _,
        mmr::Family,
        commonware_cryptography::Sha256,
        BatchOperation,
    >::plaintext(&qmdb_url, ((0..=10000).into(), ()));
    let op_count = Location::new(local.operations.len() as u64);
    let target = resolver
        .target_range(local.inactivity_floor, op_count)
        .await
        .expect("limited sync target");
    assert_eq!(target.root, local.root);
    assert_eq!(target.range.start(), local.inactivity_floor);
    assert_eq!(target.range.end(), op_count);

    let start = local.inactivity_floor;
    let start_index = usize::try_from(*start).expect("start fits usize");
    let expected_values = local
        .operations
        .iter()
        .enumerate()
        .skip(start_index)
        .filter_map(|(idx, operation)| match operation {
            KeylessOperation::Append(value) => Some((Location::new(idx as u64), value.clone())),
            KeylessOperation::Commit(Some(value), _) => {
                Some((Location::new(idx as u64), value.clone()))
            }
            KeylessOperation::Commit(None, _) => None,
        })
        .collect::<Vec<_>>();
    assert!(
        !expected_values.is_empty(),
        "fixture must leave readable values inside the limited sync range"
    );

    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(move |context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};

            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::keyless_config(
                "keyless-glue-state-sync",
                page_cache,
                ((0..=10000).into(), ()),
                NZU64!(7),
            );
            let (_update_tx, update_rx) = mpsc::channel(1);
            let synced: SyncDb = <SyncDb as StateSyncDb<_, _>>::sync_db(
                context.child("glue_sync"),
                cfg,
                resolver,
                target,
                update_rx,
                None,
                None,
                SyncEngineConfig {
                    fetch_batch_size: NZU64!(1),
                    apply_batch_size: 1,
                    max_outstanding_requests: 2,
                    update_channel_size: NZUsize!(1),
                    max_retained_roots: 4,
                },
            )
            .await
            .expect("commonware glue state sync");

            assert_eq!(synced.root(), local.root);
            let bounds = synced.bounds().await;
            assert_eq!(bounds.start, start);
            assert_eq!(bounds.end, op_count);
            for (location, expected) in expected_values {
                assert_eq!(
                    synced.get(location).await.expect("synced get"),
                    Some(expected)
                );
            }
            synced.destroy().await.expect("destroy synced db");
        });
    })
    .await
    .expect("join glue state sync runner");
}

#[tokio::test]
async fn keyless_operation_log_sync_resolver_observes_cancelled_fetch() {
    let resolver = OperationLogSyncResolver::<
        _,
        mmr::Family,
        commonware_cryptography::Sha256,
        BatchOperation,
    >::plaintext("http://127.0.0.1:1", ((0..=10000).into(), ()));
    let (cancel_tx, cancel_rx) = oneshot::channel();
    drop(cancel_tx);

    let err = resolver
        .get_operations(
            Location::new(1),
            Location::new(0),
            NZU64!(1),
            false,
            cancel_rx,
        )
        .await
        .expect_err("closed cancellation channel aborts fetch");
    assert!(matches!(err, QmdbError::SyncFetchCancelled));
}

#[tokio::test]
async fn keyless_connect_client_rejects_invalid_streamed_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    assert!(
        *local.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    commit_upload(&store_client, &local).await;

    let keyless_client = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((0..=10000).into(), ()),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(keyless_client).await;
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

fn match_exact(bytes: &[u8]) -> ProtoFilter {
    ProtoFilter {
        kind: Some(proto_filter::Kind::Exact(Bytes::copy_from_slice(bytes))),
        ..Default::default()
    }
}

fn match_regex(regex: &str) -> ProtoFilter {
    ProtoFilter {
        kind: Some(proto_filter::Kind::Regex(regex.to_string())),
        ..Default::default()
    }
}

#[tokio::test]
async fn keyless_connect_subscribe_filters_by_value_regex() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    assert!(
        *local.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    let keyless_client = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((0..=10000).into(), ()),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(keyless_client).await;
    let client = validated_client(&qmdb_url);

    // Only include ops whose value begins with "second".
    let mut stream = client
        .subscribe(ProtoSubscribeRequest {
            value_filters: vec![match_regex("^second.*$")],
            ..Default::default()
        })
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

    assert_eq!(frame.root, local.root);
    let expected: Vec<(Location<mmr::Family>, BatchOperation)> = local
        .operations
        .iter()
        .enumerate()
        .filter_map(|(i, op)| match op {
            KeylessOperation::Append(value) if value.starts_with(b"second") => {
                Some((Location::new(i as u64), op.clone()))
            }
            _ => None,
        })
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(frame.operations, expected);
}

#[tokio::test]
async fn keyless_connect_subscribe_rejects_key_filters() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    assert!(
        *local.inactivity_floor > 0,
        "test must not rely on inactivity_floor = 0"
    );
    let keyless_client = Arc::new(TestKeylessClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        ((0..=10000).into(), ()),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(keyless_client).await;

    let rpc = common::operation_log_rpc_client(&qmdb_url);
    let mut stream = rpc
        .subscribe(ProtoSubscribeRequest {
            key_filters: vec![match_exact(b"anything")],
            ..Default::default()
        })
        .await
        .expect("subscribe opens");

    // Even if we upload a batch that would otherwise match, the stream must
    // not emit a proof — keyless rejects key_filters server-side before it
    // opens the store subscription.
    commit_upload(&store_client, &local).await;

    match tokio::time::timeout(Duration::from_millis(500), stream.message()).await {
        Ok(Ok(Some(_))) => {
            panic!("keyless stream must not emit a proof when key_filters is set")
        }
        Ok(Ok(None)) => {}
        Ok(Err(err)) => {
            let msg = err.to_string();
            assert!(msg.contains("key_filters"), "unexpected error: {msg}");
        }
        Err(_) => panic!("stream hung instead of rejecting key_filters"),
    }
}
