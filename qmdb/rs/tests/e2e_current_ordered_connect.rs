//! Ordered QMDB ConnectRPC e2e for current key lookup and range proof endpoints.

#![allow(refining_impl_trait)]

mod common;

use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::merkle::{mmr, Location, Proof};
use commonware_storage::qmdb::any::{
    ordered::variable::Operation as QmdbOperation, value::VariableEncoding,
};
use commonware_storage::qmdb::{
    any::ordered::Update, current::ordered::variable::Db as LocalQmdbDb,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use connectrpc::client::ClientConfig;
use connectrpc::{Chain, ConnectRpcService, RequestContext as Context, ServiceRequest};
use exoware_qmdb::proto::qmdb::v1::{
    current_key_lookup_result, CurrentOperationServiceClient,
    GetCurrentOperationRangeRequest as ProtoGetCurrentOperationRangeRequest,
    GetManyRequest as ProtoGetManyRequest, GetManyResponse as ProtoGetManyResponse,
    GetRangeRequest as ProtoGetRangeRequest, GetRangeResponse as ProtoGetRangeResponse,
    GetRequest as ProtoGetRequest, GetResponse as ProtoGetResponse, KeyLookupService,
    KeyLookupServiceClient, KeyLookupServiceServer, OrderedKeyRangeService,
    OrderedKeyRangeServiceClient, OrderedKeyRangeServiceServer,
};
use exoware_qmdb::{
    ordered_connect_stack, recover_boundary_state, CurrentBoundaryState, OrderedClient,
    OrderedConnectClient, QmdbError, VerifiedKeyLookup, MAX_OPERATION_SIZE,
};
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::{PrefixedStoreClient, RetryConfig, StoreClient, StoreWriteBatch};
use exoware_server::{
    Query, QueryExtra, QueryResult, RangeScan, RangeScanBatch, RangeScanResult, Sequence,
};

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchProof = Proof<mmr::Family, Digest>;
type BatchOperation = QmdbOperation<mmr::Family, Vec<u8>, Vec<u8>>;
type TestOrderedClient = OrderedClient<mmr::Family, Sha256, Vec<u8>, Vec<u8>, N>;
type Db = LocalQmdbDb<
    mmr::Family,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    N,
    commonware_parallel::Sequential,
>;

fn encoded_key(key: &[u8]) -> Vec<u8> {
    key.to_vec().encode().to_vec()
}

async fn spawn_qmdb_server(
    raw_store: PrefixedStoreClient,
) -> (tokio::task::JoinHandle<()>, String) {
    common::spawn_connect_service(ordered_connect_stack::<
        mmr::Family,
        Sha256,
        Vec<u8>,
        Vec<u8>,
        N,
        VariableEncoding<Vec<u8>>,
    >(raw_store, op_cfg(), key_cfg()))
    .await
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

fn current_operation_rpc_client(base: &str) -> CurrentOperationServiceClient<PreferZstdHttpClient> {
    CurrentOperationServiceClient::new(
        PreferZstdHttpClient::plaintext(),
        ClientConfig::new(base.parse().expect("qmdb uri")),
    )
}

fn key_lookup_client(
    base: &str,
) -> OrderedConnectClient<PreferZstdHttpClient, mmr::Family, Sha256, Vec<u8>, Vec<u8>, N> {
    let (key_cfg, value_cfg) = op_cfg();
    OrderedConnectClient::plaintext(base, op_cfg(), op_cfg(), key_cfg, value_cfg)
}

async fn boundary_from_source_db(
    db: &Db,
    previous_operations: Option<&[BatchOperation]>,
    operations: &[BatchOperation],
) -> CurrentBoundaryState<Digest, N, mmr::Family> {
    let ops_root_witness = db.ops_root_witness().await.expect("ops root witness");
    recover_boundary_state::<mmr::Family, Sha256, _, N, _, _>(
        previous_operations,
        operations,
        db.root(),
        0,
        ops_root_witness,
        |location| common::current_proof_chunk(db.range_proof(location, NZU64!(1))),
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

fn key_cfg() -> <Vec<u8> as commonware_codec::Read>::Cfg {
    ((0..=MAX_OPERATION_SIZE).into(), ())
}

struct SourceBatch {
    latest_location: Location<mmr::Family>,
    operations: Vec<BatchOperation>,
    current_boundary: CurrentBoundaryState<Digest, N, mmr::Family>,
}

async fn build_source_batch() -> SourceBatch {
    build_source_batch_with_writes(
        "current_ordered_variable_mmr_connect_source",
        &[
            (b"alpha".to_vec(), b"one".to_vec()),
            (b"beta".to_vec(), b"two".to_vec()),
        ],
    )
    .await
}

async fn build_source_batch_with_writes(
    partition_prefix: &'static str,
    writes: &[(Vec<u8>, Vec<u8>)],
) -> SourceBatch {
    let writes = writes.to_vec();
    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::current_variable_config(
                partition_prefix,
                page_cache,
                (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                NZU64!(8),
            );
            let mut db: Db = Db::init(context.child(partition_prefix), cfg)
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
            (db, _) = db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (BatchProof, Vec<BatchOperation>) = db
                .ops_historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");

            let boundary = boundary_from_source_db(&db, None, &ops).await;

            db = db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            SourceBatch {
                latest_location: latest,
                operations: ops,
                current_boundary: boundary,
            }
        })
    })
    .await
    .expect("join")
}

async fn build_grafted_boundary_source_batch() -> SourceBatch {
    let writes = (0..1_100u64)
        .map(|index| {
            (
                format!("k-{index:08x}").into_bytes(),
                format!("v-{index:08x}").into_bytes(),
            )
        })
        .collect::<Vec<_>>();
    build_source_batch_with_writes(
        "current_ordered_variable_mmr_grafted_connect_source",
        &writes,
    )
    .await
}

async fn commit_upload(store_client: &StoreClient, batch: &SourceBatch) {
    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_current_operations(
        &upload_client,
        &batch.operations,
        &op_cfg(),
        &batch.current_boundary,
    )
    .await
    .expect("commit upload");
}

fn current_snapshot_rows(source: &SourceBatch) -> BTreeMap<Bytes, Bytes> {
    let staging = PrefixedStoreClient::empty(StoreClient::new("http://127.0.0.1:1"));
    let (_, prepared) =
        common::prepare_operations::<mmr::Family, BatchOperation>(&source.operations, &op_cfg());
    let prepared = prepared
        .with_current_boundary::<Sha256, N>(&source.current_boundary)
        .expect("attach current boundary");
    let mut batch = StoreWriteBatch::new();
    exoware_qmdb::stage_authenticated_range(&staging, prepared, &mut batch)
        .expect("stage authenticated range");
    exoware_qmdb::stage_watermark(&staging, source.latest_location, &mut batch)
        .expect("stage watermark");
    batch.entries().iter().cloned().collect()
}

fn publication_key() -> Bytes {
    let staging = PrefixedStoreClient::empty(StoreClient::new("http://127.0.0.1:1"));
    let mut batch = StoreWriteBatch::new();
    exoware_qmdb::stage_watermark(&staging, Location::<mmr::Family>::new(0), &mut batch)
        .expect("stage watermark key");
    batch.entries()[0].0.clone()
}

struct RoutedCursor {
    rows: VecDeque<(Bytes, Bytes)>,
}

impl RangeScan for RoutedCursor {
    async fn next_batch(&mut self, max_items: usize) -> Result<RangeScanBatch, String> {
        Ok(RangeScanBatch {
            rows: (0..max_items)
                .map_while(|_| self.rows.pop_front())
                .collect(),
            extra: QueryExtra::default(),
        })
    }
}

struct RoutedCurrentQuery {
    rows: BTreeMap<Bytes, Bytes>,
    publication_key: Bytes,
    routes: Mutex<VecDeque<u64>>,
    reads: Mutex<Vec<u64>>,
    publication_reads: Mutex<usize>,
}

impl RoutedCurrentQuery {
    fn use_new_replica_for(&self, reads: usize) {
        let mut routes = self.routes.lock().unwrap();
        routes.clear();
        routes.extend(std::iter::repeat_n(101, reads));
    }

    fn use_late_replica(&self, reads: usize, sequence: u64) {
        assert!(reads > 0);
        let mut routes = self.routes.lock().unwrap();
        routes.clear();
        routes.extend(std::iter::repeat_n(101, reads - 1));
        routes.push_back(sequence);
    }

    fn route(&self) -> u64 {
        let sequence = self.routes.lock().unwrap().pop_front().unwrap_or(100);
        self.reads.lock().unwrap().push(sequence);
        sequence
    }

    fn read_count(&self) -> usize {
        self.reads.lock().unwrap().len()
    }
}

impl Sequence for RoutedCurrentQuery {
    fn current_sequence(&self) -> u64 {
        101
    }
}

impl Query for RoutedCurrentQuery {
    type RangeScan = RoutedCursor;

    async fn get(&self, key: Bytes) -> Result<QueryResult<Option<Bytes>>, String> {
        let sequence_number = self.route();
        Ok(QueryResult {
            value: self.rows.get(&key).cloned(),
            sequence_number,
            extra: QueryExtra::default(),
        })
    }

    async fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Result<RangeScanResult<Self::RangeScan>, String> {
        if start <= self.publication_key && self.publication_key <= end {
            *self.publication_reads.lock().unwrap() += 1;
        }
        let sequence_number = self.route();
        let mut rows = self
            .rows
            .range(start..)
            .take_while(|(key, _)| end.is_empty() || *key <= &end)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        if !forward {
            rows.reverse();
        }
        rows.truncate(limit);
        Ok(RangeScanResult {
            scan: RoutedCursor { rows: rows.into() },
            sequence_number,
        })
    }

    async fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> Result<QueryResult<Vec<(Bytes, Option<Bytes>)>>, String> {
        let sequence_number = self.route();
        Ok(QueryResult {
            value: keys
                .into_iter()
                .map(|key| {
                    let value = self.rows.get(&key).cloned();
                    (key, value)
                })
                .collect(),
            sequence_number,
            extra: QueryExtra::default(),
        })
    }
}

fn latest_operation_for_key(
    operations: &[BatchOperation],
    key: &[u8],
) -> (Location<mmr::Family>, BatchOperation) {
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
        _ctx: Context,
        _request: ServiceRequest<'_, ProtoGetRequest>,
    ) -> impl std::future::Future<Output = connectrpc::ServiceResult<ProtoGetResponse>> + Send {
        let response = self.get_response.clone();
        async move { connectrpc::Response::ok(response) }
    }

    fn get_many(
        &self,
        _ctx: Context,
        _request: ServiceRequest<'_, ProtoGetManyRequest>,
    ) -> impl std::future::Future<Output = connectrpc::ServiceResult<ProtoGetManyResponse>> + Send
    {
        let response = self.get_many_response.clone();
        async move { connectrpc::Response::ok(response) }
    }
}

impl OrderedKeyRangeService for StaticQmdbService {
    fn get_range(
        &self,
        _ctx: Context,
        _request: ServiceRequest<'_, ProtoGetRangeRequest>,
    ) -> impl std::future::Future<Output = connectrpc::ServiceResult<ProtoGetRangeResponse>> + Send
    {
        let response = self.get_range_response.clone();
        async move { connectrpc::Response::ok(response) }
    }
}

async fn spawn_static_server(service: StaticQmdbService) -> (tokio::task::JoinHandle<()>, String) {
    common::spawn_connect_service(
        ConnectRpcService::new(Chain(
            KeyLookupServiceServer::new(service.clone()),
            OrderedKeyRangeServiceServer::new(service),
        ))
        .with_compression(exoware_sdk::connect_compression_registry()),
    )
    .await
}

fn tamper_get_response(mut response: ProtoGetResponse) -> ProtoGetResponse {
    let mut proof = response.proof.as_option().cloned().expect("get proof");
    let mut bytes = proof.proof.to_vec();
    bytes[0] ^= 0x01;
    proof.proof = bytes.into();
    response.proof = Some(proof).into();
    response
}

fn tamper_get_many_response(mut response: ProtoGetManyResponse) -> ProtoGetManyResponse {
    let result = response.results.first_mut().expect("get_many result");
    match result.result.as_mut().expect("get_many hit/miss") {
        current_key_lookup_result::Result::Hit(proof) => {
            let mut bytes = proof.proof.to_vec();
            bytes[0] ^= 0x01;
            proof.proof = bytes.into();
        }
        current_key_lookup_result::Result::Miss(proof) => {
            let mut bytes = proof.proof.to_vec();
            bytes[0] ^= 0x01;
            proof.proof = bytes.into();
        }
    }
    response
}

#[tokio::test]
async fn test_ordered_connect_rejects_malformed_request_keys() {
    let raw_store = PrefixedStoreClient::empty(StoreClient::new("http://127.0.0.1:1"));
    let (server, url) = spawn_qmdb_server(raw_store).await;
    let lookup = rpc_client(&url);
    let ranges = range_rpc_client(&url);
    // A one-byte value length without its payload is invalid Vec key encoding
    let malformed = vec![1];
    let errors = [
        lookup
            .get(ProtoGetRequest {
                key: malformed.clone(),
                tip: 1,
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code,
        lookup
            .get_many(ProtoGetManyRequest {
                keys: vec![encoded_key(b"alpha"), malformed.clone()],
                tip: 1,
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code,
        ranges
            .get_range(ProtoGetRangeRequest {
                start_key: malformed.clone(),
                end_key: Some(encoded_key(b"omega")),
                limit: 1,
                tip: 1,
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code,
        ranges
            .get_range(ProtoGetRangeRequest {
                start_key: encoded_key(b"alpha"),
                end_key: Some(malformed),
                limit: 1,
                tip: 1,
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code,
    ];
    assert_eq!(errors, [connectrpc::ErrorCode::InvalidArgument; 4]);
    server.abort();
}

#[tokio::test]
async fn test_ordered_connect_get_returns_current_key_value_proof() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    commit_upload(&store_client, &source).await;
    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let connect_client = key_lookup_client(&qmdb_url);

    let proof = connect_client
        .get(
            ProtoGetRequest {
                key: encoded_key(b"alpha"),
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.current_boundary.root,
        )
        .await
        .expect("get");

    let expected = latest_operation_for_key(&source.operations, b"alpha");
    assert_eq!(proof.root, source.current_boundary.root);
    assert_eq!(proof.location, expected.0);
    assert_eq!(proof.operation, expected.1);
}

#[tokio::test]
async fn test_ordered_get_after_grafted_boundary_returns_current_key_value_proof() {
    let store_client = common::local_store_client().await;
    let source = build_grafted_boundary_source_batch().await;
    let ordered_client = TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        key_cfg(),
    );
    let upload_client = PrefixedStoreClient::empty(store_client.clone());
    common::commit_current_operations(
        &upload_client,
        &source.operations,
        &op_cfg(),
        &source.current_boundary,
    )
    .await
    .expect("commit upload");

    let key = b"k-00000400".to_vec();
    let proof = ordered_client
        .key_value_proof_at(source.latest_location, key.as_slice(), None)
        .await
        .expect("get after grafted boundary");
    let expected = latest_operation_for_key(&source.operations, &key);
    assert_eq!(proof.root, source.current_boundary.root);
    assert_eq!(proof.location, expected.0);
    assert_eq!(proof.operation, expected.1);
}

#[tokio::test]
async fn test_ordered_connect_get_many_returns_current_key_lookup_proofs() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    commit_upload(&store_client, &source).await;
    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let connect_client = key_lookup_client(&qmdb_url);

    let proof = connect_client
        .get_many(
            ProtoGetManyRequest {
                keys: vec![encoded_key(b"alpha"), encoded_key(b"beta")],
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.current_boundary.root,
        )
        .await
        .expect("get_many");

    let alpha = latest_operation_for_key(&source.operations, b"alpha");
    let beta = latest_operation_for_key(&source.operations, b"beta");
    assert_eq!(proof.len(), 2);
    match &proof[0] {
        VerifiedKeyLookup::Hit(hit) => {
            assert_eq!(hit.root, source.current_boundary.root);
            assert_eq!(hit.location, alpha.0);
            assert_eq!(hit.operation, alpha.1);
        }
        VerifiedKeyLookup::Miss { .. } => panic!("alpha should be a hit"),
    }
    match &proof[1] {
        VerifiedKeyLookup::Hit(hit) => {
            assert_eq!(hit.root, source.current_boundary.root);
            assert_eq!(hit.location, beta.0);
            assert_eq!(hit.operation, beta.1);
        }
        VerifiedKeyLookup::Miss { .. } => panic!("beta should be a hit"),
    }
}

#[tokio::test]
async fn test_ordered_connect_get_many_returns_miss_proofs_and_rejects_duplicates() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    commit_upload(&store_client, &source).await;
    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let connect_client = key_lookup_client(&qmdb_url);

    let proof = connect_client
        .get_many(
            ProtoGetManyRequest {
                keys: vec![encoded_key(b"alpha"), encoded_key(b"aardvark")],
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.current_boundary.root,
        )
        .await
        .expect("get_many");
    assert_eq!(proof.len(), 2);
    assert!(matches!(proof[0], VerifiedKeyLookup::Hit(_)));
    let aardvark = encoded_key(b"aardvark");
    assert!(matches!(
        &proof[1],
        VerifiedKeyLookup::Miss { key } if key == &aardvark
    ));

    let err = connect_client
        .get_many(
            ProtoGetManyRequest {
                keys: vec![encoded_key(b"alpha"), encoded_key(b"alpha")],
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.current_boundary.root,
        )
        .await
        .expect_err("duplicate get_many keys should fail");
    assert!(err.to_string().contains("duplicate key"));
}

#[tokio::test]
async fn test_ordered_connect_get_range_verifies_complete_empty_and_partial_pages() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    commit_upload(&store_client, &source).await;
    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let connect_client = key_lookup_client(&qmdb_url);

    let complete = connect_client
        .get_range(
            ProtoGetRangeRequest {
                start_key: encoded_key(b"a"),
                end_key: Some(encoded_key(b"c")),
                limit: 10,
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.current_boundary.root,
        )
        .await
        .expect("complete get_range");
    assert!(complete.next_start_key.is_none());
    let complete_keys = complete
        .entries
        .iter()
        .map(|entry| match &entry.operation {
            BatchOperation::Update(update) => update.key.clone(),
            _ => unreachable!("range entry must be update"),
        })
        .collect::<Vec<_>>();
    assert_eq!(complete_keys, vec![b"alpha".to_vec(), b"beta".to_vec()]);

    let partial = connect_client
        .get_range(
            ProtoGetRangeRequest {
                start_key: encoded_key(b"a"),
                end_key: Some(encoded_key(b"z")),
                limit: 1,
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.current_boundary.root,
        )
        .await
        .expect("partial get_range");
    assert_eq!(partial.entries.len(), 1);
    assert_eq!(partial.next_start_key, Some(encoded_key(b"beta").into()));

    let empty = connect_client
        .get_range(
            ProtoGetRangeRequest {
                start_key: encoded_key(b"aardvark"),
                end_key: Some(encoded_key(b"alpha")),
                limit: 10,
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.current_boundary.root,
        )
        .await
        .expect("empty get_range");
    assert!(empty.next_start_key.is_none());
    assert!(empty.entries.is_empty());
}

#[tokio::test]
async fn test_current_endpoints_enforce_cold_minimum_and_use_cached_publication() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    commit_upload(&store_client, &source).await;
    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let lookup = rpc_client(&qmdb_url);
    let ranges = range_rpc_client(&qmdb_url);
    let current_operations = current_operation_rpc_client(&qmdb_url);

    let cold_errors = [
        lookup
            .get(ProtoGetRequest {
                key: encoded_key(b"alpha"),
                tip: source.latest_location.as_u64() + 1,
                min_sequence_number: Some(u64::MAX),
                ..Default::default()
            })
            .await
            .expect_err("cold get publication lookup must enforce the sequence minimum")
            .code,
        lookup
            .get_many(ProtoGetManyRequest {
                keys: vec![encoded_key(b"alpha"), encoded_key(b"aardvark")],
                tip: source.latest_location.as_u64() + 1,
                min_sequence_number: Some(u64::MAX),
                ..Default::default()
            })
            .await
            .expect_err("cold get_many publication lookup must enforce the sequence minimum")
            .code,
        ranges
            .get_range(ProtoGetRangeRequest {
                start_key: encoded_key(b"aardvark"),
                end_key: Some(encoded_key(b"c")),
                limit: 10,
                tip: source.latest_location.as_u64() + 1,
                min_sequence_number: Some(u64::MAX),
                ..Default::default()
            })
            .await
            .expect_err("cold get_range publication lookup must enforce the sequence minimum")
            .code,
        current_operations
            .get_current_operation_range(ProtoGetCurrentOperationRangeRequest {
                tip: source.latest_location.as_u64() + 1,
                start_location: 0,
                max_locations: source.operations.len() as u32,
                min_sequence_number: Some(u64::MAX),
                ..Default::default()
            })
            .await
            .expect_err(
                "cold current operation publication lookup must enforce the sequence minimum",
            )
            .code,
    ];
    assert_eq!(cold_errors, [connectrpc::ErrorCode::Aborted; 4]);

    for min_sequence_number in [None, Some(0)] {
        lookup
            .get(ProtoGetRequest {
                key: encoded_key(b"alpha"),
                tip: source.latest_location.as_u64(),
                min_sequence_number,
                ..Default::default()
            })
            .await
            .expect("get at available sequence");
        lookup
            .get_many(ProtoGetManyRequest {
                keys: vec![encoded_key(b"alpha"), encoded_key(b"aardvark")],
                tip: source.latest_location.as_u64(),
                min_sequence_number,
                ..Default::default()
            })
            .await
            .expect("get_many at available sequence");
        ranges
            .get_range(ProtoGetRangeRequest {
                start_key: encoded_key(b"aardvark"),
                end_key: Some(encoded_key(b"c")),
                limit: 10,
                tip: source.latest_location.as_u64(),
                min_sequence_number,
                ..Default::default()
            })
            .await
            .expect("get_range at available sequence");
        current_operations
            .get_current_operation_range(ProtoGetCurrentOperationRangeRequest {
                tip: source.latest_location.as_u64(),
                start_location: 0,
                max_locations: source.operations.len() as u32,
                min_sequence_number,
                ..Default::default()
            })
            .await
            .expect("get_current_operation_range at available sequence");
    }

    lookup
        .get(ProtoGetRequest {
            key: encoded_key(b"alpha"),
            tip: source.latest_location.as_u64(),
            min_sequence_number: Some(u64::MAX),
            ..Default::default()
        })
        .await
        .expect("cached get uses the publication floor");
    lookup
        .get_many(ProtoGetManyRequest {
            keys: vec![encoded_key(b"alpha"), encoded_key(b"aardvark")],
            tip: source.latest_location.as_u64(),
            min_sequence_number: Some(u64::MAX),
            ..Default::default()
        })
        .await
        .expect("cached get_many uses the publication floor");
    ranges
        .get_range(ProtoGetRangeRequest {
            start_key: encoded_key(b"aardvark"),
            end_key: Some(encoded_key(b"c")),
            limit: 10,
            tip: source.latest_location.as_u64(),
            min_sequence_number: Some(u64::MAX),
            ..Default::default()
        })
        .await
        .expect("cached get_range uses the publication floor");
    current_operations
        .get_current_operation_range(ProtoGetCurrentOperationRangeRequest {
            tip: source.latest_location.as_u64(),
            start_location: 0,
            max_locations: source.operations.len() as u32,
            min_sequence_number: Some(u64::MAX),
            ..Default::default()
        })
        .await
        .expect("cached current operation range uses the publication floor");
}

#[tokio::test]
async fn test_current_endpoints_keep_floor_for_every_dependent_read() {
    let source = build_source_batch().await;
    let query = Arc::new(RoutedCurrentQuery {
        rows: current_snapshot_rows(&source),
        publication_key: publication_key(),
        routes: Mutex::new(VecDeque::new()),
        reads: Mutex::new(Vec::new()),
        publication_reads: Mutex::new(0),
    });
    let (store_server, query_url) = common::spawn_connect_service(exoware_server::query_service(
        exoware_server::QueryState::new(query.clone()),
    ))
    .await;
    let store = StoreClient::builder()
        .url(&query_url)
        .query_url(&query_url)
        .retry_config(RetryConfig::disabled())
        .build()
        .expect("routed Store client");
    let (qmdb_server, qmdb_url) = spawn_qmdb_server(PrefixedStoreClient::empty(store)).await;
    let lookup = rpc_client(&qmdb_url);
    let ranges = range_rpc_client(&qmdb_url);
    let current_operations = current_operation_rpc_client(&qmdb_url);

    lookup
        .get(ProtoGetRequest {
            key: encoded_key(b"alpha"),
            tip: source.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("warm publication cache at sequence 100");
    assert_eq!(*query.publication_reads.lock().unwrap(), 1);

    let get = ProtoGetRequest {
        key: encoded_key(b"alpha"),
        tip: source.latest_location.as_u64(),
        min_sequence_number: Some(101),
        ..Default::default()
    };
    query.use_new_replica_for(128);
    let before = query.read_count();
    lookup.get(get.clone()).await.expect("fresh get");
    let get_reads = query.read_count() - before;
    assert!(get_reads > 1);
    query.use_late_replica(get_reads, 100);
    lookup
        .get(get.clone())
        .await
        .expect("late get read at the publication floor");
    query.use_late_replica(get_reads, 99);
    let error = lookup
        .get(get)
        .await
        .expect_err("late get read below the publication floor");
    assert_eq!(error.code, connectrpc::ErrorCode::Aborted);

    let get_many = ProtoGetManyRequest {
        keys: vec![encoded_key(b"alpha"), encoded_key(b"aardvark")],
        tip: source.latest_location.as_u64(),
        min_sequence_number: Some(101),
        ..Default::default()
    };
    query.use_new_replica_for(128);
    let before = query.read_count();
    lookup
        .get_many(get_many.clone())
        .await
        .expect("fresh get_many with exclusion proof");
    let get_many_reads = query.read_count() - before;
    assert!(get_many_reads > 1);
    query.use_late_replica(get_many_reads, 100);
    lookup
        .get_many(get_many.clone())
        .await
        .expect("late get_many read at the publication floor");
    query.use_late_replica(get_many_reads, 99);
    let error = lookup
        .get_many(get_many)
        .await
        .expect_err("late get_many read below the publication floor");
    assert_eq!(error.code, connectrpc::ErrorCode::Aborted);

    let range = ProtoGetRangeRequest {
        start_key: encoded_key(b"aardvark"),
        end_key: Some(encoded_key(b"c")),
        limit: 10,
        tip: source.latest_location.as_u64(),
        min_sequence_number: Some(101),
        ..Default::default()
    };
    query.use_new_replica_for(128);
    let before = query.read_count();
    ranges
        .get_range(range.clone())
        .await
        .expect("fresh range with entries and start exclusion");
    let range_reads = query.read_count() - before;
    assert!(range_reads > 1);
    query.use_late_replica(range_reads, 100);
    ranges
        .get_range(range.clone())
        .await
        .expect("late range read at the publication floor");
    query.use_late_replica(range_reads, 99);
    let error = ranges
        .get_range(range)
        .await
        .expect_err("late range read below the publication floor");
    assert_eq!(error.code, connectrpc::ErrorCode::Aborted);

    let current = ProtoGetCurrentOperationRangeRequest {
        tip: source.latest_location.as_u64(),
        start_location: 0,
        max_locations: source.operations.len() as u32,
        min_sequence_number: Some(101),
        ..Default::default()
    };
    query.use_new_replica_for(128);
    let before = query.read_count();
    current_operations
        .get_current_operation_range(current.clone())
        .await
        .expect("fresh current operation range");
    let current_reads = query.read_count() - before;
    assert!(current_reads > 1);
    query.use_late_replica(current_reads, 100);
    current_operations
        .get_current_operation_range(current.clone())
        .await
        .expect("late current operation read at the publication floor");
    query.use_late_replica(current_reads, 99);
    let error = current_operations
        .get_current_operation_range(current)
        .await
        .expect_err("late current operation read below the publication floor");
    assert_eq!(error.code, connectrpc::ErrorCode::Aborted);

    assert_eq!(
        *query.publication_reads.lock().unwrap(),
        1,
        "caller floors must not alter or bypass cached publication evidence"
    );
    qmdb_server.abort();
    store_server.abort();
}

#[tokio::test]
async fn test_ordered_connect_client_rejects_get_range_boundary_omission() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    commit_upload(&store_client, &source).await;

    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let rpc = rpc_client(&qmdb_url);
    let range_rpc = range_rpc_client(&qmdb_url);

    let raw_get_response = rpc
        .get(ProtoGetRequest {
            key: encoded_key(b"alpha"),
            tip: source.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get")
        .into_view()
        .to_owned_message();
    let raw_get_many_response = rpc
        .get_many(ProtoGetManyRequest {
            keys: vec![encoded_key(b"alpha")],
            tip: source.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get_many")
        .into_view()
        .to_owned_message();
    let mut raw_get_range_response = range_rpc
        .get_range(ProtoGetRangeRequest {
            start_key: encoded_key(b"a"),
            end_key: Some(encoded_key(b"c")),
            limit: 10,
            tip: source.latest_location.as_u64(),
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
    let connect_client = key_lookup_client(&static_url);

    let err = connect_client
        .get_range(
            ProtoGetRangeRequest {
                start_key: encoded_key(b"a"),
                end_key: Some(encoded_key(b"c")),
                limit: 10,
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.current_boundary.root,
        )
        .await
        .expect_err("omitted get_range start boundary should fail");
    assert!(err.to_string().contains("start boundary"));
}

#[tokio::test]
async fn test_ordered_connect_client_rejects_empty_unbounded_get_range_before_next_key() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    commit_upload(&store_client, &source).await;

    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let rpc = rpc_client(&qmdb_url);
    let range_rpc = range_rpc_client(&qmdb_url);

    let raw_get_response = rpc
        .get(ProtoGetRequest {
            key: encoded_key(b"alpha"),
            tip: source.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get")
        .into_view()
        .to_owned_message();
    let raw_get_many_response = rpc
        .get_many(ProtoGetManyRequest {
            keys: vec![encoded_key(b"alpha")],
            tip: source.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get_many")
        .into_view()
        .to_owned_message();
    let raw_get_range_response = range_rpc
        .get_range(ProtoGetRangeRequest {
            start_key: encoded_key(b"aardvark"),
            end_key: Some(encoded_key(b"alpha")),
            limit: 10,
            tip: source.latest_location.as_u64(),
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
    let connect_client = key_lookup_client(&static_url);

    let err = connect_client
        .get_range(
            ProtoGetRangeRequest {
                start_key: encoded_key(b"aardvark"),
                limit: 10,
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.current_boundary.root,
        )
        .await
        .expect_err("bounded empty proof must not verify an unbounded range");
    assert!(matches!(err, QmdbError::RangeMismatch(_)), "{err}");
}

#[tokio::test]
async fn test_ordered_connect_client_rejects_invalid_get_proof() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    commit_upload(&store_client, &source).await;

    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let rpc = rpc_client(&qmdb_url);

    let raw_get_response = rpc
        .get(ProtoGetRequest {
            key: encoded_key(b"alpha"),
            tip: source.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get")
        .into_view()
        .to_owned_message();
    let raw_get_many_response = rpc
        .get_many(ProtoGetManyRequest {
            keys: vec![encoded_key(b"alpha"), encoded_key(b"beta")],
            tip: source.latest_location.as_u64(),
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
    let connect_client = key_lookup_client(&static_url);

    let err = connect_client
        .get(
            ProtoGetRequest {
                key: encoded_key(b"alpha"),
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.current_boundary.root,
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
async fn test_ordered_connect_client_rejects_invalid_get_many_proof() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    commit_upload(&store_client, &source).await;

    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let rpc = rpc_client(&qmdb_url);

    let raw_get_response = rpc
        .get(ProtoGetRequest {
            key: encoded_key(b"alpha"),
            tip: source.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get")
        .into_view()
        .to_owned_message();
    let raw_get_many_response = rpc
        .get_many(ProtoGetManyRequest {
            keys: vec![encoded_key(b"alpha"), encoded_key(b"beta")],
            tip: source.latest_location.as_u64(),
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
    let connect_client = key_lookup_client(&static_url);

    let err = connect_client
        .get_many(
            ProtoGetManyRequest {
                keys: vec![encoded_key(b"alpha"), encoded_key(b"beta")],
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.current_boundary.root,
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

#[tokio::test]
async fn test_ordered_connect_client_rejects_get_many_proof_for_different_key() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    commit_upload(&store_client, &source).await;

    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let rpc = rpc_client(&qmdb_url);

    let raw_get_many_response = rpc
        .get_many(ProtoGetManyRequest {
            keys: vec![encoded_key(b"beta")],
            tip: source.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get_many")
        .into_view()
        .to_owned_message();

    let (_static_server, static_url) = spawn_static_server(StaticQmdbService {
        get_response: ProtoGetResponse::default(),
        get_many_response: raw_get_many_response,
        get_range_response: ProtoGetRangeResponse::default(),
    })
    .await;
    let connect_client = key_lookup_client(&static_url);

    let err = connect_client
        .get_many(
            ProtoGetManyRequest {
                keys: vec![encoded_key(b"alpha")],
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.current_boundary.root,
        )
        .await
        .expect_err("get_many proof for a different key should fail");
    assert!(matches!(
        err,
        QmdbError::ProofVerification {
            kind: exoware_qmdb::ProofKind::CurrentKeyValue
        }
    ));
}

#[tokio::test]
async fn test_ordered_connect_client_rejects_get_range_page_shorter_than_limit() {
    let store_client = common::local_store_client().await;
    let source = build_source_batch().await;
    commit_upload(&store_client, &source).await;

    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let rpc = rpc_client(&qmdb_url);
    let range_rpc = range_rpc_client(&qmdb_url);

    let raw_get_response = rpc
        .get(ProtoGetRequest {
            key: encoded_key(b"alpha"),
            tip: source.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get")
        .into_view()
        .to_owned_message();
    let raw_get_many_response = rpc
        .get_many(ProtoGetManyRequest {
            keys: vec![encoded_key(b"alpha")],
            tip: source.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get_many")
        .into_view()
        .to_owned_message();
    // A one-entry page with a continuation is a valid answer for limit 1 only
    let raw_get_range_response = range_rpc
        .get_range(ProtoGetRangeRequest {
            start_key: encoded_key(b"a"),
            limit: 1,
            tip: source.latest_location.as_u64(),
            ..Default::default()
        })
        .await
        .expect("get_range")
        .into_view()
        .to_owned_message();
    assert_eq!(raw_get_range_response.entries.len(), 1);

    let (_static_server, static_url) = spawn_static_server(StaticQmdbService {
        get_response: raw_get_response,
        get_many_response: raw_get_many_response,
        get_range_response: raw_get_range_response,
    })
    .await;
    let connect_client = key_lookup_client(&static_url);

    let err = connect_client
        .get_range(
            ProtoGetRangeRequest {
                start_key: encoded_key(b"a"),
                limit: 2,
                tip: source.latest_location.as_u64(),
                ..Default::default()
            },
            &source.current_boundary.root,
        )
        .await
        .expect_err("a short page must not omit an in-range successor");
    assert!(matches!(err, QmdbError::RangeMismatch(_)), "{err}");
}
