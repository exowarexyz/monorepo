//! Ordered QMDB ConnectRPC e2e for the unary key-proof endpoints
//! (`OrderedService.Get` / `OrderedService.GetMany`).

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, Router};
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
use connectrpc::client::ClientConfig;
use connectrpc::{ConnectError, ConnectRpcService, Context};
use exoware_sdk_rs::proto::PreferZstdHttpClient;
use exoware_sdk_rs::store::qmdb::v1::{
    GetManyRequest as ProtoGetManyRequest, GetManyResponse as ProtoGetManyResponse,
    GetRequest as ProtoGetRequest, GetResponse as ProtoGetResponse, OrderedService,
    OrderedServiceClient, OrderedServiceServer,
};
use exoware_sdk_rs::StoreClient;
use store_qmdb::{
    ordered_connect_stack, recover_boundary_state, CurrentBoundaryState, OrderedClient,
    OrderedConnectClient, OrderedWriter, QmdbError, MAX_OPERATION_SIZE,
};

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchProof = commonware_storage::mmr::Proof<Digest>;
type BatchOperation = QmdbOperation<Vec<u8>, Vec<u8>>;
type TestOrderedClient = OrderedClient<Sha256, Vec<u8>, Vec<u8>, N>;
type LocalDb = LocalQmdbDb<cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap, N>;

async fn health() -> &'static str {
    "ok"
}

async fn wait_for_health(base: &str) {
    let url = format!("{base}/health");
    let client = reqwest::Client::new();
    for _ in 0..200 {
        if client
            .get(&url)
            .send()
            .await
            .ok()
            .is_some_and(|res| res.status().is_success())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("qmdb server did not become ready at {url}");
}

async fn spawn_qmdb_server(
    client: Arc<TestOrderedClient>,
) -> (tokio::task::JoinHandle<()>, String) {
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(ordered_connect_stack(client));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind qmdb server");
    let port = listener.local_addr().expect("local addr").port();
    let url = format!("http://127.0.0.1:{port}");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    wait_for_health(&url).await;
    (handle, url)
}

fn rpc_client(base: &str) -> OrderedServiceClient<PreferZstdHttpClient> {
    OrderedServiceClient::new(
        PreferZstdHttpClient::plaintext(),
        ClientConfig::new(base.parse().expect("qmdb uri")),
    )
}

fn validated_client(
    base: &str,
) -> OrderedConnectClient<PreferZstdHttpClient, Sha256, Vec<u8>, Vec<u8>, N> {
    OrderedConnectClient::plaintext(base, op_cfg())
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
    latest_location: Location,
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
                latest_location: latest,
                operations: ops,
                current_boundary: boundary,
            }
        })
    })
    .await
    .expect("join")
}

async fn upload_and_publish(client: &StoreClient, batch: &LocalBatch) {
    let writer: OrderedWriter<Sha256, Vec<u8>, Vec<u8>, N> = OrderedWriter::empty(client.clone());
    writer
        .upload_and_publish(&batch.operations, &batch.current_boundary)
        .await
        .expect("upload_and_publish");
}

fn latest_operation_for_key(
    operations: &[BatchOperation],
    key: &[u8],
) -> (Location, BatchOperation) {
    operations
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, operation)| match operation {
            BatchOperation::Delete(found) if found.as_slice() == key => {
                Some((Location::new(index as u64), operation.clone()))
            }
            BatchOperation::Update(Update { key: found, .. }) if found.as_slice() == key => {
                Some((Location::new(index as u64), operation.clone()))
            }
            _ => None,
        })
        .expect("matching operation")
}

#[derive(Clone)]
struct StaticOrderedService {
    get_response: ProtoGetResponse,
    get_many_response: ProtoGetManyResponse,
}

impl OrderedService for StaticOrderedService {
    fn get(
        &self,
        ctx: Context,
        _request: buffa::view::OwnedView<exoware_sdk_rs::store::qmdb::v1::GetRequestView<'static>>,
    ) -> impl std::future::Future<Output = Result<(ProtoGetResponse, Context), ConnectError>> + Send
    {
        let response = self.get_response.clone();
        async move { Ok((response, ctx)) }
    }

    fn get_many(
        &self,
        ctx: Context,
        _request: buffa::view::OwnedView<
            exoware_sdk_rs::store::qmdb::v1::GetManyRequestView<'static>,
        >,
    ) -> impl std::future::Future<Output = Result<(ProtoGetManyResponse, Context), ConnectError>> + Send
    {
        let response = self.get_many_response.clone();
        async move { Ok((response, ctx)) }
    }
}

async fn spawn_static_server(
    service: StaticOrderedService,
) -> (tokio::task::JoinHandle<()>, String) {
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(
            ConnectRpcService::new(OrderedServiceServer::new(service))
                .with_compression(exoware_sdk_rs::connect_compression_registry()),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind static qmdb server");
    let port = listener.local_addr().expect("local addr").port();
    let url = format!("http://127.0.0.1:{port}");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    wait_for_health(&url).await;
    (handle, url)
}

fn tamper_get_response(mut response: ProtoGetResponse) -> ProtoGetResponse {
    let mut proof = response.proof.as_option().cloned().expect("get proof");
    proof.root[0] ^= 0x01;
    response.proof = Some(proof).into();
    response
}

fn tamper_get_many_response(mut response: ProtoGetManyResponse) -> ProtoGetManyResponse {
    let mut proof = response.proof.as_option().cloned().expect("get_many proof");
    proof.root[0] ^= 0x01;
    response.proof = Some(proof).into();
    response
}

#[tokio::test]
async fn ordered_connect_get_returns_current_key_value_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
        op_cfg(),
        update_row_cfg(),
    ));
    upload_and_publish(&store_client, &local).await;
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client.clone()).await;
    let client = validated_client(&qmdb_url);

    let proof = client
        .get(ProtoGetRequest {
            key: b"alpha".to_vec(),
            tip: local.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get");

    let expected = latest_operation_for_key(&local.operations, b"alpha");
    assert_eq!(proof.root, local.current_boundary.root);
    assert_eq!(proof.location, expected.0);
    assert_eq!(proof.operation, expected.1);
}

#[tokio::test]
async fn ordered_connect_get_many_returns_historical_multi_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
        op_cfg(),
        update_row_cfg(),
    ));
    upload_and_publish(&store_client, &local).await;
    let historical_root = ordered_client
        .root_at(local.latest_location)
        .await
        .expect("historical root");
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client.clone()).await;
    let client = validated_client(&qmdb_url);

    let proof = client
        .get_many(ProtoGetManyRequest {
            keys: vec![b"alpha".to_vec(), b"beta".to_vec()],
            tip: local.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get_many");

    let alpha = latest_operation_for_key(&local.operations, b"alpha");
    let beta = latest_operation_for_key(&local.operations, b"beta");
    let mut expected = vec![alpha, beta];
    expected.sort_by_key(|(location, _)| *location);
    assert_eq!(proof.root, historical_root);
    assert_eq!(proof.operations, expected);
}

#[tokio::test]
async fn ordered_connect_client_rejects_invalid_get_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    upload_and_publish(&store_client, &local).await;

    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client.clone()).await;
    let rpc = rpc_client(&qmdb_url);

    let raw_get_response = rpc
        .get(ProtoGetRequest {
            key: b"alpha".to_vec(),
            tip: local.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get")
        .into_view()
        .to_owned_message();
    let raw_get_many_response = rpc
        .get_many(ProtoGetManyRequest {
            keys: vec![b"alpha".to_vec(), b"beta".to_vec()],
            tip: local.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get_many")
        .into_view()
        .to_owned_message();

    let (_static_server, static_url) = spawn_static_server(StaticOrderedService {
        get_response: tamper_get_response(raw_get_response),
        get_many_response: raw_get_many_response,
    })
    .await;
    let client = validated_client(&static_url);

    let err = client
        .get(ProtoGetRequest {
            key: b"alpha".to_vec(),
            tip: local.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect_err("tampered get proof should fail");
    assert!(matches!(
        err,
        QmdbError::ProofVerification {
            kind: store_qmdb::ProofKind::CurrentKeyValue
        }
    ));
}

#[tokio::test]
async fn ordered_connect_client_rejects_invalid_get_many_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    upload_and_publish(&store_client, &local).await;

    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client.clone()).await;
    let rpc = rpc_client(&qmdb_url);

    let raw_get_response = rpc
        .get(ProtoGetRequest {
            key: b"alpha".to_vec(),
            tip: local.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get")
        .into_view()
        .to_owned_message();
    let raw_get_many_response = rpc
        .get_many(ProtoGetManyRequest {
            keys: vec![b"alpha".to_vec(), b"beta".to_vec()],
            tip: local.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get_many")
        .into_view()
        .to_owned_message();

    let (_static_server, static_url) = spawn_static_server(StaticOrderedService {
        get_response: raw_get_response,
        get_many_response: tamper_get_many_response(raw_get_many_response),
    })
    .await;
    let client = validated_client(&static_url);

    let err = client
        .get_many(ProtoGetManyRequest {
            keys: vec![b"alpha".to_vec(), b"beta".to_vec()],
            tip: local.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect_err("tampered get_many proof should fail");
    assert!(matches!(
        err,
        QmdbError::ProofVerification {
            kind: store_qmdb::ProofKind::HistoricalMultiKey
        }
    ));
}
