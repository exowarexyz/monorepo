//! Ordered QMDB ConnectRPC e2e for current key lookup and range proof endpoints.

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
    any::ordered::Update, current::ordered::variable::Db as LocalQmdbDb,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use connectrpc::client::ClientConfig;
use connectrpc::{Chain, ConnectError, ConnectRpcService, Context};
use exoware_qmdb::{
    ordered_connect_stack, recover_boundary_state, CurrentBoundaryState, OrderedClient,
    OrderedConnectClient, OrderedWriter, QmdbError, VerifiedKeyLookup, MAX_OPERATION_SIZE,
};
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::qmdb::v1::{
    current_key_lookup_result, GetManyRequest as ProtoGetManyRequest,
    GetManyResponse as ProtoGetManyResponse, GetRangeRequest as ProtoGetRangeRequest,
    GetRangeResponse as ProtoGetRangeResponse, GetRequest as ProtoGetRequest,
    GetResponse as ProtoGetResponse, KeyLookupService, KeyLookupServiceClient,
    KeyLookupServiceServer, OrderedKeyRangeService, OrderedKeyRangeServiceClient,
    OrderedKeyRangeServiceServer,
};
use exoware_sdk::StoreClient;

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchProof = commonware_storage::mmr::Proof<Digest>;
type BatchOperation = QmdbOperation<commonware_storage::mmr::Family, Vec<u8>, Vec<u8>>;
type TestOrderedClient = OrderedClient<Sha256, Vec<u8>, Vec<u8>, N>;
type LocalDb = LocalQmdbDb<
    commonware_storage::mmr::Family,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    N,
>;

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

fn rpc_client(base: &str) -> KeyLookupServiceClient<PreferZstdHttpClient> {
    KeyLookupServiceClient::new(
        PreferZstdHttpClient::plaintext(),
        ClientConfig::new(base.parse().expect("qmdb uri")),
    )
}

fn range_rpc_client(base: &str) -> OrderedKeyRangeServiceClient<PreferZstdHttpClient> {
    OrderedKeyRangeServiceClient::new(
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
    recover_boundary_state::<Sha256, _, N, _, _>(
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
    latest_location: Location,
    operations: Vec<BatchOperation>,
    current_boundary: CurrentBoundaryState<Digest, N>,
}

async fn build_local_batch() -> LocalBatch {
    build_local_batch_with_writes(
        "ordered-connect",
        &[
            (b"alpha".to_vec(), b"one".to_vec()),
            (b"beta".to_vec(), b"two".to_vec()),
        ],
    )
    .await
}

async fn build_local_batch_with_writes(label: &str, writes: &[(Vec<u8>, Vec<u8>)]) -> LocalBatch {
    let label = label.to_string();
    let writes = writes.to_vec();
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::ordered_variable_config(
                &label,
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
                let mut batch = db.new_batch();
                for (key, value) in writes {
                    batch = batch.write(key, Some(value));
                }
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

async fn build_grafted_boundary_local_batch() -> LocalBatch {
    let writes = (0..1_100u64)
        .map(|index| {
            (
                format!("k-{index:08x}").into_bytes(),
                format!("v-{index:08x}").into_bytes(),
            )
        })
        .collect::<Vec<_>>();
    build_local_batch_with_writes("ordered-connect-grafted", &writes).await
}

async fn commit_upload(client: &StoreClient, batch: &LocalBatch) {
    let writer: OrderedWriter<Sha256, Vec<u8>, Vec<u8>, N> = OrderedWriter::empty(client.clone());
    common::commit_ordered_upload(client, &writer, &batch.operations, &batch.current_boundary)
        .await
        .expect("commit upload");
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
struct StaticQmdbService {
    get_response: ProtoGetResponse,
    get_many_response: ProtoGetManyResponse,
    get_range_response: ProtoGetRangeResponse,
}

impl KeyLookupService for StaticQmdbService {
    fn get(
        &self,
        ctx: Context,
        _request: buffa::view::OwnedView<exoware_sdk::qmdb::v1::GetRequestView<'static>>,
    ) -> impl std::future::Future<Output = Result<(ProtoGetResponse, Context), ConnectError>> + Send
    {
        let response = self.get_response.clone();
        async move { Ok((response, ctx)) }
    }

    fn get_many(
        &self,
        ctx: Context,
        _request: buffa::view::OwnedView<exoware_sdk::qmdb::v1::GetManyRequestView<'static>>,
    ) -> impl std::future::Future<Output = Result<(ProtoGetManyResponse, Context), ConnectError>> + Send
    {
        let response = self.get_many_response.clone();
        async move { Ok((response, ctx)) }
    }
}

impl OrderedKeyRangeService for StaticQmdbService {
    fn get_range(
        &self,
        ctx: Context,
        _request: buffa::view::OwnedView<exoware_sdk::qmdb::v1::GetRangeRequestView<'static>>,
    ) -> impl std::future::Future<Output = Result<(ProtoGetRangeResponse, Context), ConnectError>> + Send
    {
        let response = self.get_range_response.clone();
        async move { Ok((response, ctx)) }
    }
}

async fn spawn_static_server(service: StaticQmdbService) -> (tokio::task::JoinHandle<()>, String) {
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(
            ConnectRpcService::new(Chain(
                KeyLookupServiceServer::new(service.clone()),
                OrderedKeyRangeServiceServer::new(service),
            ))
            .with_compression(exoware_sdk::connect_compression_registry()),
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
    proof.proof[0] ^= 0x01;
    response.proof = Some(proof).into();
    response
}

fn tamper_get_many_response(mut response: ProtoGetManyResponse) -> ProtoGetManyResponse {
    let result = response.results.first_mut().expect("get_many result");
    match result.result.as_mut().expect("get_many hit/miss") {
        current_key_lookup_result::Result::Hit(proof) => proof.proof[0] ^= 0x01,
        current_key_lookup_result::Result::Miss(proof) => proof.proof[0] ^= 0x01,
    }
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
    commit_upload(&store_client, &local).await;
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client.clone()).await;
    let client = validated_client(&qmdb_url);

    let proof = client
        .get(
            ProtoGetRequest {
                key: b"alpha".to_vec(),
                tip: local.latest_location.as_u64(),
                ..Default::default()
            },
            &local.current_boundary.root,
        )
        .await
        .expect("get");

    let expected = latest_operation_for_key(&local.operations, b"alpha");
    assert_eq!(proof.root, local.current_boundary.root);
    assert_eq!(proof.location, expected.0);
    assert_eq!(proof.operation, expected.1);
}

#[tokio::test]
async fn ordered_get_after_grafted_boundary_returns_current_key_value_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_grafted_boundary_local_batch().await;
    let ordered_client =
        TestOrderedClient::from_client(store_client.clone(), op_cfg(), update_row_cfg());
    let writer: OrderedWriter<Sha256, Vec<u8>, Vec<u8>, N> =
        OrderedWriter::empty(store_client.clone());
    common::commit_ordered_upload(
        &store_client,
        &writer,
        &local.operations,
        &local.current_boundary,
    )
    .await
    .expect("commit upload");

    let key = b"k-00000400".to_vec();
    let proof = ordered_client
        .key_value_proof_at(local.latest_location, key.as_slice())
        .await
        .expect("get after grafted boundary");
    let expected = latest_operation_for_key(&local.operations, &key);
    assert_eq!(proof.root, local.current_boundary.root);
    assert_eq!(proof.location, expected.0);
    assert_eq!(proof.operation, expected.1);
}

#[tokio::test]
async fn ordered_connect_get_many_returns_current_key_lookup_proofs() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
        op_cfg(),
        update_row_cfg(),
    ));
    commit_upload(&store_client, &local).await;
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client.clone()).await;
    let client = validated_client(&qmdb_url);

    let proof = client
        .get_many(
            ProtoGetManyRequest {
                keys: vec![b"alpha".to_vec(), b"beta".to_vec()],
                tip: local.latest_location.as_u64(),
                ..Default::default()
            },
            &local.current_boundary.root,
        )
        .await
        .expect("get_many");

    let alpha = latest_operation_for_key(&local.operations, b"alpha");
    let beta = latest_operation_for_key(&local.operations, b"beta");
    assert_eq!(proof.len(), 2);
    match &proof[0] {
        VerifiedKeyLookup::Hit(hit) => {
            assert_eq!(hit.root, local.current_boundary.root);
            assert_eq!(hit.location, alpha.0);
            assert_eq!(hit.operation, alpha.1);
        }
        VerifiedKeyLookup::Miss { .. } => panic!("alpha should be a hit"),
    }
    match &proof[1] {
        VerifiedKeyLookup::Hit(hit) => {
            assert_eq!(hit.root, local.current_boundary.root);
            assert_eq!(hit.location, beta.0);
            assert_eq!(hit.operation, beta.1);
        }
        VerifiedKeyLookup::Miss { .. } => panic!("beta should be a hit"),
    }
}

#[tokio::test]
async fn ordered_connect_get_many_returns_miss_proofs_and_rejects_duplicates() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
        op_cfg(),
        update_row_cfg(),
    ));
    commit_upload(&store_client, &local).await;
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client.clone()).await;
    let client = validated_client(&qmdb_url);

    let proof = client
        .get_many(
            ProtoGetManyRequest {
                keys: vec![b"alpha".to_vec(), b"aardvark".to_vec()],
                tip: local.latest_location.as_u64(),
                ..Default::default()
            },
            &local.current_boundary.root,
        )
        .await
        .expect("get_many");
    assert_eq!(proof.len(), 2);
    assert!(matches!(proof[0], VerifiedKeyLookup::Hit(_)));
    assert!(matches!(
        &proof[1],
        VerifiedKeyLookup::Miss { key } if key == b"aardvark"
    ));

    let err = client
        .get_many(
            ProtoGetManyRequest {
                keys: vec![b"alpha".to_vec(), b"alpha".to_vec()],
                tip: local.latest_location.as_u64(),
                ..Default::default()
            },
            &local.current_boundary.root,
        )
        .await
        .expect_err("duplicate get_many keys should fail");
    assert!(err.to_string().contains("duplicate key"));
}

#[tokio::test]
async fn ordered_connect_get_range_verifies_complete_empty_and_partial_pages() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
        op_cfg(),
        update_row_cfg(),
    ));
    commit_upload(&store_client, &local).await;
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client.clone()).await;
    let client = validated_client(&qmdb_url);

    let complete = client
        .get_range(
            ProtoGetRangeRequest {
                start_key: b"a".to_vec(),
                end_key: Some(b"c".to_vec()),
                limit: 10,
                tip: local.latest_location.as_u64(),
                ..Default::default()
            },
            &local.current_boundary.root,
        )
        .await
        .expect("complete get_range");
    assert!(!complete.has_more);
    let complete_keys = complete
        .entries
        .iter()
        .map(|entry| match &entry.operation {
            BatchOperation::Update(update) => update.key.clone(),
            _ => unreachable!("range entry must be update"),
        })
        .collect::<Vec<_>>();
    assert_eq!(complete_keys, vec![b"alpha".to_vec(), b"beta".to_vec()]);

    let partial = client
        .get_range(
            ProtoGetRangeRequest {
                start_key: b"a".to_vec(),
                end_key: Some(b"z".to_vec()),
                limit: 1,
                tip: local.latest_location.as_u64(),
                ..Default::default()
            },
            &local.current_boundary.root,
        )
        .await
        .expect("partial get_range");
    assert!(partial.has_more);
    assert_eq!(partial.entries.len(), 1);
    assert_eq!(partial.next_start_key, b"beta".to_vec());

    let empty = client
        .get_range(
            ProtoGetRangeRequest {
                start_key: b"aardvark".to_vec(),
                end_key: Some(b"alpha".to_vec()),
                limit: 10,
                tip: local.latest_location.as_u64(),
                ..Default::default()
            },
            &local.current_boundary.root,
        )
        .await
        .expect("empty get_range");
    assert!(!empty.has_more);
    assert!(empty.entries.is_empty());
}

#[tokio::test]
async fn ordered_connect_client_rejects_get_range_boundary_omission() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    commit_upload(&store_client, &local).await;

    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client.clone()).await;
    let rpc = rpc_client(&qmdb_url);
    let range_rpc = range_rpc_client(&qmdb_url);

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
            keys: vec![b"alpha".to_vec()],
            tip: local.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get_many")
        .into_view()
        .to_owned_message();
    let mut raw_get_range_response = range_rpc
        .get_range(ProtoGetRangeRequest {
            start_key: b"a".to_vec(),
            end_key: Some(b"c".to_vec()),
            limit: 10,
            tip: local.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get_range")
        .into_view()
        .to_owned_message();
    raw_get_range_response.start_proof = None.into();

    let (_static_server, static_url) = spawn_static_server(StaticQmdbService {
        get_response: raw_get_response,
        get_many_response: raw_get_many_response,
        get_range_response: raw_get_range_response,
    })
    .await;
    let client = validated_client(&static_url);

    let err = client
        .get_range(
            ProtoGetRangeRequest {
                start_key: b"a".to_vec(),
                end_key: Some(b"c".to_vec()),
                limit: 10,
                tip: local.latest_location.as_u64(),
                ..Default::default()
            },
            &local.current_boundary.root,
        )
        .await
        .expect_err("omitted get_range start boundary should fail");
    assert!(err.to_string().contains("start boundary"));
}

#[tokio::test]
async fn ordered_connect_client_rejects_empty_unbounded_get_range_before_next_key() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    commit_upload(&store_client, &local).await;

    let ordered_client = Arc::new(TestOrderedClient::from_client(
        store_client.clone(),
        op_cfg(),
        update_row_cfg(),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(ordered_client.clone()).await;
    let rpc = rpc_client(&qmdb_url);
    let range_rpc = range_rpc_client(&qmdb_url);

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
            keys: vec![b"alpha".to_vec()],
            tip: local.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get_many")
        .into_view()
        .to_owned_message();
    let raw_get_range_response = range_rpc
        .get_range(ProtoGetRangeRequest {
            start_key: b"aardvark".to_vec(),
            end_key: Some(b"alpha".to_vec()),
            limit: 10,
            tip: local.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("bounded empty get_range")
        .into_view()
        .to_owned_message();
    assert!(raw_get_range_response.entries.is_empty());

    let (_static_server, static_url) = spawn_static_server(StaticQmdbService {
        get_response: raw_get_response,
        get_many_response: raw_get_many_response,
        get_range_response: raw_get_range_response,
    })
    .await;
    let client = validated_client(&static_url);

    let err = client
        .get_range(
            ProtoGetRangeRequest {
                start_key: b"aardvark".to_vec(),
                limit: 10,
                tip: local.latest_location.as_u64(),
                ..Default::default()
            },
            &local.current_boundary.root,
        )
        .await
        .expect_err("bounded empty proof must not verify an unbounded range");
    assert!(matches!(
        err,
        QmdbError::ProofVerification {
            kind: exoware_qmdb::ProofKind::CurrentKeyExclusion
        }
    ));
}

#[tokio::test]
async fn ordered_connect_client_rejects_invalid_get_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    commit_upload(&store_client, &local).await;

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

    let (_static_server, static_url) = spawn_static_server(StaticQmdbService {
        get_response: tamper_get_response(raw_get_response),
        get_many_response: raw_get_many_response,
        get_range_response: ProtoGetRangeResponse::default(),
    })
    .await;
    let client = validated_client(&static_url);

    let err = client
        .get(
            ProtoGetRequest {
                key: b"alpha".to_vec(),
                tip: local.latest_location.as_u64(),
                ..Default::default()
            },
            &local.current_boundary.root,
        )
        .await
        .expect_err("tampered get proof should fail");
    assert!(matches!(
        err,
        QmdbError::ProofVerification {
            kind: exoware_qmdb::ProofKind::CurrentKeyValue
        }
    ));
}

#[tokio::test]
async fn ordered_connect_client_rejects_invalid_get_many_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    commit_upload(&store_client, &local).await;

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

    let (_static_server, static_url) = spawn_static_server(StaticQmdbService {
        get_response: raw_get_response,
        get_many_response: tamper_get_many_response(raw_get_many_response),
        get_range_response: ProtoGetRangeResponse::default(),
    })
    .await;
    let client = validated_client(&static_url);

    let err = client
        .get_many(
            ProtoGetManyRequest {
                keys: vec![b"alpha".to_vec(), b"beta".to_vec()],
                tip: local.latest_location.as_u64(),
                ..Default::default()
            },
            &local.current_boundary.root,
        )
        .await
        .expect_err("tampered get_many proof should fail");
    assert!(matches!(
        err,
        QmdbError::ProofVerification {
            kind: exoware_qmdb::ProofKind::CurrentKeyValue
        }
    ));
}
