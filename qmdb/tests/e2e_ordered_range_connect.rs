//! Ordered QMDB range-stream ConnectRPC e2e: streamed historical checkpoints
//! plus client-side validation of tampered proofs.

mod common;

use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, Router};
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
use connectrpc::client::ClientConfig;
use connectrpc::{ConnectError, ConnectRpcService, Context};
use exoware_sdk_rs::proto::PreferZstdHttpClient;
use exoware_sdk_rs::store::qmdb::v1::{
    OrderedRangeService, OrderedRangeServiceClient, OrderedRangeServiceServer,
    RangeSubscribeRequest as ProtoRangeSubscribeRequest,
    RangeSubscribeResponse as ProtoRangeSubscribeResponse,
};
use exoware_sdk_rs::StoreClient;
use store_qmdb::{
    ordered_range_connect_stack, recover_boundary_state, CurrentBoundaryState, OrderedClient,
    OrderedRangeConnectClient, OrderedWriter, QmdbError, RangeSubscribeProof, MAX_OPERATION_SIZE,
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
        .fallback_service(ordered_range_connect_stack(client));
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

fn rpc_client(base: &str) -> OrderedRangeServiceClient<PreferZstdHttpClient> {
    OrderedRangeServiceClient::new(
        PreferZstdHttpClient::plaintext(),
        ClientConfig::new(base.parse().expect("qmdb uri")),
    )
}

fn validated_client(
    base: &str,
) -> OrderedRangeConnectClient<PreferZstdHttpClient, Sha256, Vec<u8>, Vec<u8>, N> {
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

async fn upload_and_publish(client: &StoreClient, batch: &LocalBatch) {
    let writer: OrderedWriter<Sha256, Vec<u8>, Vec<u8>, N> = OrderedWriter::empty(client.clone());
    writer
        .upload_and_publish(&batch.operations, &batch.current_boundary)
        .await
        .expect("upload_and_publish");
}

#[derive(Clone)]
struct StaticOrderedRangeService {
    subscribe_response: ProtoRangeSubscribeResponse,
}

impl OrderedRangeService for StaticOrderedRangeService {
    fn subscribe(
        &self,
        ctx: Context,
        _request: buffa::view::OwnedView<
            exoware_sdk_rs::store::qmdb::v1::RangeSubscribeRequestView<'static>,
        >,
    ) -> impl std::future::Future<
        Output = Result<
            (
                Pin<
                    Box<
                        dyn futures::Stream<
                                Item = Result<ProtoRangeSubscribeResponse, ConnectError>,
                            > + Send,
                    >,
                >,
                Context,
            ),
            ConnectError,
        >,
    > + Send {
        let response = self.subscribe_response.clone();
        async move {
            let stream: Pin<
                Box<
                    dyn futures::Stream<Item = Result<ProtoRangeSubscribeResponse, ConnectError>>
                        + Send,
                >,
            > = Box::pin(futures::stream::iter([Ok(response)]));
            Ok((stream, ctx))
        }
    }
}

async fn spawn_static_server(
    service: StaticOrderedRangeService,
) -> (tokio::task::JoinHandle<()>, String) {
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(
            ConnectRpcService::new(OrderedRangeServiceServer::new(service))
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

fn tamper_range_response(mut response: ProtoRangeSubscribeResponse) -> ProtoRangeSubscribeResponse {
    let mut proof = response.proof.as_option().cloned().expect("range proof");
    proof.root[0] ^= 0x01;
    response.proof = Some(proof).into();
    response
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
        .subscribe(ProtoRangeSubscribeRequest::default())
        .await
        .expect("subscribe");

    tokio::time::sleep(Duration::from_millis(50)).await;
    upload_and_publish(&store_client, &local).await;

    let frame: RangeSubscribeProof<Digest, BatchOperation> =
        tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .expect("timeout")
            .expect("stream result")
            .expect("stream frame");

    assert!(frame.resume_sequence_number > 0);
    assert_eq!(frame.proof.start_location, Location::new(0));
    assert_eq!(frame.proof.operations, local.operations);
}

#[tokio::test]
async fn ordered_range_connect_client_rejects_invalid_streamed_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    upload_and_publish(&store_client, &local).await;

    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client).await;
    let rpc = rpc_client(&qmdb_url);
    let mut raw_stream = rpc
        .subscribe(ProtoRangeSubscribeRequest {
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

    let (_static_server, static_url) = spawn_static_server(StaticOrderedRangeService {
        subscribe_response: tamper_range_response(raw_response),
    })
    .await;
    let client = validated_client(&static_url);
    let mut stream = client
        .subscribe(ProtoRangeSubscribeRequest::default())
        .await
        .expect("subscribe");

    let err = stream
        .message()
        .await
        .expect_err("tampered streamed proof should fail");
    assert!(
        matches!(err, QmdbError::CorruptData(message) if message.contains("range checkpoint proof failed verification"))
    );
}
