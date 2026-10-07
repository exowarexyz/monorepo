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
    any::ordered::Update,
    current::ordered::{proof::constant::ExclusionProof, variable::Db as LocalQmdbDb},
    operation::Operation as _,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use connectrpc::client::ClientConfig;
use connectrpc::{Chain, ConnectRpcService, RequestContext as Context, ServiceRequest};
use exoware_qmdb::service::proto::qmdb::v1::{
    current_key_lookup_result, CurrentOperationServiceClient,
    GetCurrentOperationRangeRequest as ProtoGetCurrentOperationRangeRequest,
    GetManyRequest as ProtoGetManyRequest, GetManyResponse as ProtoGetManyResponse,
    GetRangeRequest as ProtoGetRangeRequest, GetRangeResponse as ProtoGetRangeResponse,
    GetRequest as ProtoGetRequest, GetResponse as ProtoGetResponse, KeyLookupService,
    KeyLookupServiceClient, KeyLookupServiceServer, OrderedKeyRangeService,
    OrderedKeyRangeServiceClient, OrderedKeyRangeServiceServer,
};
use exoware_qmdb::{
    adapter::upload::recover_boundary_state,
    proof::{RawKeyExclusionProof, RawKeyLookupProof, VerifiedKeyLookup},
    CurrentBoundaryState, QmdbError, MAX_OPERATION_SIZE,
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
type TestOrderedClient = exoware_qmdb::adapter::Ordered<mmr::Family, Sha256, Vec<u8>, Vec<u8>, N>;
type ConnectClient = exoware_qmdb::service::client::Ordered<
    PreferZstdHttpClient,
    mmr::Family,
    Sha256,
    Vec<u8>,
    Vec<u8>,
    N,
>;
/// One commit's writes, where `None` deletes the key.
type TipWrites = Vec<(Vec<u8>, Option<Vec<u8>>)>;
type KeyExclusionProof = RawKeyExclusionProof<Digest, Vec<u8>, Vec<u8>, N, mmr::Family>;
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
    common::spawn_connect_service(exoware_qmdb::service::server::ordered_stack::<
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

fn key_lookup_client(base: &str) -> ConnectClient {
    let (key_cfg, value_cfg) = op_cfg();
    exoware_qmdb::service::client::Ordered::plaintext(base, op_cfg(), op_cfg(), key_cfg, value_cfg)
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
    let writes = writes
        .iter()
        .map(|(key, value)| (key.clone(), Some(value.clone())))
        .collect();
    build_source_tips(partition_prefix, vec![writes])
        .await
        .pop()
        .expect("one tip")
}

/// Apply each batch of writes as its own commit, returning the
/// cumulative source state at every tip.
async fn build_source_tips(
    partition_prefix: &'static str,
    batches: Vec<TipWrites>,
) -> Vec<SourceBatch> {
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
            let mut db: Db = Db::init(context.child(partition_prefix), cfg, None)
                .await
                .expect("init");

            let mut tips = Vec::<SourceBatch>::new();
            for writes in batches {
                let finalized = {
                    let mut batch = db.new_batch();
                    for (key, value) in writes {
                        batch = batch.write(key, value);
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
                let previous = tips.last().map(|tip| tip.operations.as_slice());
                let boundary = boundary_from_source_db(&db, previous, &ops).await;
                tips.push(SourceBatch {
                    latest_location: latest,
                    operations: ops,
                    current_boundary: boundary,
                });
            }

            db = db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");
            tips
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
    exoware_qmdb::adapter::upload::stage_authenticated_range(&staging, prepared, &mut batch)
        .expect("stage authenticated range");
    exoware_qmdb::adapter::upload::stage_watermark(&staging, source.latest_location, &mut batch)
        .expect("stage watermark");
    batch.entries().iter().cloned().collect()
}

fn publication_key() -> Bytes {
    let staging = PrefixedStoreClient::empty(StoreClient::new("http://127.0.0.1:1"));
    let mut batch = StoreWriteBatch::new();
    exoware_qmdb::adapter::upload::stage_watermark(
        &staging,
        Location::<mmr::Family>::new(0),
        &mut batch,
    )
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

/// What an exclusion proof shows around the requested key.
#[derive(Debug, PartialEq)]
enum Cover {
    /// The covering active key and its successor.
    Span(String, String),
    /// No key is active, so the commit operation proves the miss.
    Commit,
}

fn span(key: &str, next_key: &str) -> Cover {
    Cover::Span(key.to_string(), next_key.to_string())
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("utf8 key")
}

fn cover(proof: &KeyExclusionProof) -> Cover {
    match &proof.proof {
        ExclusionProof::KeyValue(_, update) => {
            Cover::Span(text(&update.key), text(&update.next_key))
        }
        ExclusionProof::Commit(_, _) => Cover::Commit,
    }
}

fn tip_writes(writes: &[(&str, Option<&str>)]) -> TipWrites {
    writes
        .iter()
        .map(|(key, value)| {
            (
                key.as_bytes().to_vec(),
                value.map(|v| v.as_bytes().to_vec()),
            )
        })
        .collect()
}

/// Leaves `c`, `e`, `k`, `m` active at the second tip, with the deleted run
/// `a`, `b` below them, the run `g`, `h`, `i` and the single key `l` between them.
fn sparse_source_batches() -> Vec<TipWrites> {
    let keys = ["a", "b", "c", "e", "g", "h", "i", "k", "l", "m"];
    vec![
        tip_writes(&keys.map(|key| (key, Some(key)))),
        tip_writes(&["a", "b", "g", "h", "i", "l"].map(|key| (key, None))),
    ]
}

async fn upload_tips(store_client: &StoreClient, tips: &[SourceBatch]) {
    for tip in tips {
        commit_upload(store_client, tip).await;
    }
}

/// Miss proof for `key` at `tip`, checked against the tip's root both through
/// the adapter and over Connect.
async fn miss_proof(
    ordered: &TestOrderedClient,
    connect: &ConnectClient,
    tip: &SourceBatch,
    key: &str,
) -> KeyExclusionProof {
    let key = key.as_bytes().to_vec();
    let mut lookups = ordered
        .get_many_raw(tip.latest_location, std::slice::from_ref(&key), None)
        .await
        .expect("get_many_raw");
    let Some(RawKeyLookupProof::Miss(proof)) = lookups.pop() else {
        panic!("{} should be a miss", text(&key));
    };
    assert_eq!(proof.watermark, tip.latest_location);
    assert_eq!(proof.root, tip.current_boundary.root);
    assert_eq!(proof.requested_key, key);
    assert!(proof.verify::<Sha256>());

    let verified = connect
        .get_many(
            tip.latest_location,
            std::slice::from_ref(&key),
            None,
            &tip.current_boundary.root,
        )
        .await
        .expect("connect get_many");
    assert!(matches!(
        verified.as_slice(),
        [VerifiedKeyLookup::Miss { key: missed }] if missed == &key
    ));
    proof
}

async fn miss_cover(
    ordered: &TestOrderedClient,
    connect: &ConnectClient,
    tip: &SourceBatch,
    key: &str,
) -> Cover {
    cover(&miss_proof(ordered, connect, tip, key).await)
}

#[derive(Debug, PartialEq)]
struct RangePage {
    keys: Vec<String>,
    next_start_key: Option<String>,
    start_proof: Option<Cover>,
}

/// Range page at `tip`, checked against the tip's root both through the
/// adapter and over Connect.
async fn range_page(
    ordered: &TestOrderedClient,
    connect: &ConnectClient,
    tip: &SourceBatch,
    start: &str,
    end: Option<&str>,
    limit: u32,
) -> RangePage {
    let start = start.as_bytes().to_vec();
    let end = end.map(|end| end.as_bytes().to_vec());
    let raw = ordered
        .get_range_raw(tip.latest_location, start.clone(), end.clone(), limit, None)
        .await
        .expect("get_range_raw");
    for entry in &raw.entries {
        assert_eq!(entry.root, tip.current_boundary.root);
        assert!(entry.verify::<Sha256>());
    }
    if let Some(proof) = &raw.start_proof {
        assert_eq!(proof.root, tip.current_boundary.root);
        assert_eq!(proof.requested_key, start);
        assert!(proof.verify::<Sha256>());
    }
    let keys = raw
        .entries
        .iter()
        .map(|entry| text(entry.operation.key().expect("entry key")))
        .collect::<Vec<_>>();

    let verified = connect
        .get_range(
            tip.latest_location,
            start,
            end,
            limit,
            None,
            &tip.current_boundary.root,
        )
        .await
        .expect("connect get_range");
    let verified_keys = verified
        .entries
        .iter()
        .map(|entry| text(entry.operation.key().expect("entry key")))
        .collect::<Vec<_>>();
    assert_eq!(verified_keys, keys);

    RangePage {
        keys,
        next_start_key: verified.next_start_key.as_deref().map(text),
        start_proof: raw.start_proof.as_ref().map(cover),
    }
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
async fn test_ordered_connect_rejects_get_range_limit_above_maximum() {
    let raw_store = PrefixedStoreClient::empty(StoreClient::new("http://127.0.0.1:1"));
    let (server, url) = spawn_qmdb_server(raw_store).await;
    let ranges = range_rpc_client(&url);
    let request = |limit| ProtoGetRangeRequest {
        start_key: encoded_key(b"alpha"),
        limit,
        tip: 1,
        ..Default::default()
    };
    let too_large = ranges.get_range(request(1001)).await.unwrap_err();
    assert_eq!(too_large.code, connectrpc::ErrorCode::InvalidArgument);
    // The maximum passes validation and fails at the unreachable Store.
    let maximum = ranges.get_range(request(1000)).await.unwrap_err();
    assert_ne!(maximum.code, connectrpc::ErrorCode::InvalidArgument);
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
            source.latest_location,
            &b"alpha".to_vec(),
            None,
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
        .get(source.latest_location, &key, None)
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
            source.latest_location,
            &[b"alpha".to_vec(), b"beta".to_vec()],
            None,
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
            source.latest_location,
            &[b"alpha".to_vec(), b"aardvark".to_vec()],
            None,
            &source.current_boundary.root,
        )
        .await
        .expect("get_many");
    assert_eq!(proof.len(), 2);
    assert!(matches!(proof[0], VerifiedKeyLookup::Hit(_)));
    let aardvark = b"aardvark".to_vec();
    assert!(matches!(
        &proof[1],
        VerifiedKeyLookup::Miss { key } if key == &aardvark
    ));

    let err = connect_client
        .get_many(
            source.latest_location,
            &[b"alpha".to_vec(), b"alpha".to_vec()],
            None,
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
            source.latest_location,
            b"a".to_vec(),
            Some(b"c".to_vec()),
            10,
            None,
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
            source.latest_location,
            b"a".to_vec(),
            Some(b"z".to_vec()),
            1,
            None,
            &source.current_boundary.root,
        )
        .await
        .expect("partial get_range");
    assert_eq!(partial.entries.len(), 1);
    assert_eq!(partial.next_start_key, Some(b"beta".to_vec()));

    let empty = connect_client
        .get_range(
            source.latest_location,
            b"aardvark".to_vec(),
            Some(b"alpha".to_vec()),
            10,
            None,
            &source.current_boundary.root,
        )
        .await
        .expect("empty get_range");
    assert!(empty.next_start_key.is_none());
    assert!(empty.entries.is_empty());
}

#[tokio::test]
async fn test_ordered_connect_miss_proofs_cover_keys_below_between_and_above_active_keys() {
    let store_client = common::local_store_client().await;
    let tips = build_source_tips(
        "current_ordered_variable_mmr_connect_positioned_misses",
        vec![tip_writes(&[
            ("c", Some("c1")),
            ("e", Some("e1")),
            ("k", Some("k1")),
            ("m", Some("m1")),
        ])],
    )
    .await;
    upload_tips(&store_client, &tips).await;
    let ordered = TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        key_cfg(),
    );
    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let connect = key_lookup_client(&qmdb_url);
    let tip = &tips[0];

    // Keys outside the active range fall in the span that wraps from the greatest key
    assert_eq!(
        miss_cover(&ordered, &connect, tip, "a").await,
        span("m", "c")
    );
    assert_eq!(
        miss_cover(&ordered, &connect, tip, "z").await,
        span("m", "c")
    );
    assert_eq!(
        miss_cover(&ordered, &connect, tip, "d").await,
        span("c", "e")
    );
    assert_eq!(
        miss_cover(&ordered, &connect, tip, "ka").await,
        span("k", "m")
    );
}

#[tokio::test]
async fn test_ordered_connect_miss_proofs_skip_deleted_keys() {
    let store_client = common::local_store_client().await;
    let tips = build_source_tips(
        "current_ordered_variable_mmr_connect_deleted_misses",
        sparse_source_batches(),
    )
    .await;
    upload_tips(&store_client, &tips).await;
    let ordered = TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        key_cfg(),
    );
    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let connect = key_lookup_client(&qmdb_url);
    let tip = &tips[1];

    assert_eq!(
        miss_cover(&ordered, &connect, tip, "l").await,
        span("k", "m")
    );
    for key in ["g", "h", "i", "j"] {
        assert_eq!(
            miss_cover(&ordered, &connect, tip, key).await,
            span("e", "k")
        );
    }
    // Only deleted keys lie below these, so the walk wraps to the greatest key
    for key in ["a", "b", "bb"] {
        assert_eq!(
            miss_cover(&ordered, &connect, tip, key).await,
            span("m", "c")
        );
    }
}

#[tokio::test]
async fn test_ordered_connect_miss_proofs_ignore_versions_above_tip() {
    let store_client = common::local_store_client().await;
    let tips = build_source_tips(
        "current_ordered_variable_mmr_connect_tip_misses",
        vec![
            tip_writes(&[
                ("b", Some("b1")),
                ("d", Some("d1")),
                ("f", Some("f1")),
                ("h", Some("h1")),
            ]),
            tip_writes(&[
                ("d", None),
                ("e", Some("e2")),
                ("f", Some("f2")),
                ("h", None),
            ]),
        ],
    )
    .await;
    assert_ne!(tips[0].current_boundary.root, tips[1].current_boundary.root);
    upload_tips(&store_client, &tips).await;
    let ordered = TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        key_cfg(),
    );
    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let connect = key_lookup_client(&qmdb_url);
    let (earlier, later) = (&tips[0], &tips[1]);

    assert_eq!(
        miss_cover(&ordered, &connect, earlier, "c").await,
        span("b", "d")
    );
    assert_eq!(
        miss_cover(&ordered, &connect, earlier, "e").await,
        span("d", "f")
    );
    assert_eq!(
        miss_cover(&ordered, &connect, earlier, "z").await,
        span("h", "b")
    );
    let proof = miss_proof(&ordered, &connect, earlier, "g").await;
    assert_eq!(cover(&proof), span("f", "h"));
    let ExclusionProof::KeyValue(_, update) = &proof.proof else {
        unreachable!("span cover");
    };
    assert_eq!(update.value, b"f1".to_vec());
    assert_eq!(
        range_page(&ordered, &connect, earlier, "a", None, 10)
            .await
            .keys,
        ["b", "d", "f", "h"]
    );

    assert_eq!(
        miss_cover(&ordered, &connect, later, "c").await,
        span("b", "e")
    );
    assert_eq!(
        miss_cover(&ordered, &connect, later, "d").await,
        span("b", "e")
    );
    assert_eq!(
        miss_cover(&ordered, &connect, later, "h").await,
        span("f", "b")
    );
    let proof = miss_proof(&ordered, &connect, later, "g").await;
    assert_eq!(cover(&proof), span("f", "b"));
    let ExclusionProof::KeyValue(_, update) = &proof.proof else {
        unreachable!("span cover");
    };
    assert_eq!(update.value, b"f2".to_vec());
    assert_eq!(
        range_page(&ordered, &connect, later, "a", None, 10)
            .await
            .keys,
        ["b", "e", "f"]
    );
}

#[tokio::test]
async fn test_ordered_connect_miss_proofs_use_commit_when_every_key_is_deleted() {
    let store_client = common::local_store_client().await;
    let tips = build_source_tips(
        "current_ordered_variable_mmr_connect_empty_misses",
        vec![
            tip_writes(&[("a", Some("a1")), ("b", Some("b1"))]),
            tip_writes(&[("a", None), ("b", None)]),
        ],
    )
    .await;
    upload_tips(&store_client, &tips).await;
    let ordered = TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        key_cfg(),
    );
    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let connect = key_lookup_client(&qmdb_url);
    let (earlier, empty) = (&tips[0], &tips[1]);

    assert_eq!(
        miss_cover(&ordered, &connect, earlier, "c").await,
        span("b", "a")
    );
    for key in ["a", "b", "c"] {
        assert_eq!(
            miss_cover(&ordered, &connect, empty, key).await,
            Cover::Commit
        );
    }
    assert_eq!(
        range_page(&ordered, &connect, empty, "a", None, 10).await,
        RangePage {
            keys: Vec::new(),
            next_start_key: None,
            start_proof: Some(Cover::Commit),
        }
    );
}

#[tokio::test]
async fn test_ordered_connect_get_range_walks_past_deleted_keys() {
    let store_client = common::local_store_client().await;
    let tips = build_source_tips(
        "current_ordered_variable_mmr_connect_deleted_ranges",
        sparse_source_batches(),
    )
    .await;
    upload_tips(&store_client, &tips).await;
    let ordered = TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        key_cfg(),
    );
    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let connect = key_lookup_client(&qmdb_url);
    let tip = &tips[1];

    let between = range_page(&ordered, &connect, tip, "d", None, 10).await;
    assert_eq!(between.keys, ["e", "k", "m"]);
    assert_eq!(between.next_start_key, None);
    assert_eq!(between.start_proof, Some(span("c", "e")));

    let deleted_start = range_page(&ordered, &connect, tip, "h", None, 10).await;
    assert_eq!(deleted_start.keys, ["k", "m"]);
    assert_eq!(deleted_start.start_proof, Some(span("e", "k")));

    let across_runs = range_page(&ordered, &connect, tip, "a", Some("z"), 10).await;
    assert_eq!(across_runs.keys, ["c", "e", "k", "m"]);
    assert_eq!(across_runs.next_start_key, None);
    assert_eq!(across_runs.start_proof, Some(span("m", "c")));

    let limited = range_page(&ordered, &connect, tip, "c", None, 2).await;
    assert_eq!(limited.keys, ["c", "e"]);
    assert_eq!(limited.next_start_key.as_deref(), Some("k"));
    assert_eq!(limited.start_proof, None);

    let limited_after_run = range_page(&ordered, &connect, tip, "f", None, 1).await;
    assert_eq!(limited_after_run.keys, ["k"]);
    assert_eq!(limited_after_run.next_start_key.as_deref(), Some("m"));
    assert_eq!(limited_after_run.start_proof, Some(span("e", "k")));

    let bounded = range_page(&ordered, &connect, tip, "d", Some("l"), 10).await;
    assert_eq!(bounded.keys, ["e", "k"]);
    assert_eq!(bounded.next_start_key, None);
    let bounded_at_key = range_page(&ordered, &connect, tip, "d", Some("k"), 10).await;
    assert_eq!(bounded_at_key.keys, ["e"]);
    assert_eq!(bounded_at_key.next_start_key, None);

    let beyond_last = range_page(&ordered, &connect, tip, "n", None, 10).await;
    assert_eq!(
        beyond_last,
        RangePage {
            keys: Vec::new(),
            next_start_key: None,
            start_proof: Some(span("m", "c")),
        }
    );

    // The deleted keys are still active at the earlier tip
    let earlier = range_page(&ordered, &connect, &tips[0], "f", None, 3).await;
    assert_eq!(earlier.keys, ["g", "h", "i"]);
    assert_eq!(earlier.next_start_key.as_deref(), Some("k"));
    assert_eq!(earlier.start_proof, Some(span("e", "g")));
}

/// Keys in the deleted run of [`long_run_batches`].
const LONG_RUN: usize = 298;

fn long_run_key(index: usize) -> String {
    format!("k-{index:03}")
}

/// Writes `k-000` through `k-299`, then deletes every key between the two
/// ends, leaving a run of [`LONG_RUN`] deleted keys and twice as many update
/// rows, longer than the walk's first three pages.
fn long_run_batches() -> Vec<TipWrites> {
    let key = |index| long_run_key(index).into_bytes();
    vec![
        (0..LONG_RUN + 2)
            .map(|index| (key(index), Some(key(index))))
            .collect(),
        (1..=LONG_RUN).map(|index| (key(index), None)).collect(),
    ]
}

#[tokio::test]
async fn test_ordered_connect_miss_proofs_walk_long_deleted_runs_in_growing_pages() {
    let (query, store_client, _servers) = common::counting_store().await;
    let tips = build_source_tips(
        "current_ordered_variable_mmr_connect_long_run_misses",
        long_run_batches(),
    )
    .await;
    upload_tips(&store_client, &tips).await;
    let ordered = TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        key_cfg(),
    );
    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let connect = key_lookup_client(&qmdb_url);
    let tip = &tips[1];
    let (first, last) = (long_run_key(0), long_run_key(LONG_RUN + 1));
    let probe = format!("{}x", long_run_key(LONG_RUN));

    // One scan looks up the probe itself. The walk crosses the run in pages
    // of 128 and 1024 rows
    let (scans, rows) = miss_reads(&query, &ordered, tip, &probe).await;
    assert_eq!(scans, 1 + 2);
    assert!(
        (2 * LONG_RUN..=2 * LONG_RUN + 16).contains(&rows),
        "walk over {LONG_RUN} deleted keys read {rows} update rows"
    );

    assert_eq!(
        miss_cover(&ordered, &connect, tip, &probe).await,
        span(&first, &last)
    );
    for index in [1, 2, LONG_RUN / 2, LONG_RUN] {
        assert_eq!(
            miss_cover(&ordered, &connect, tip, &long_run_key(index)).await,
            span(&first, &last)
        );
    }
}

#[tokio::test]
async fn test_ordered_connect_get_range_spans_walk_pages() {
    let (query, store_client, _servers) = common::counting_store().await;
    let tips = build_source_tips(
        "current_ordered_variable_mmr_connect_long_run_ranges",
        long_run_batches(),
    )
    .await;
    upload_tips(&store_client, &tips).await;
    let ordered = TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        key_cfg(),
    );
    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let connect = key_lookup_client(&qmdb_url);
    let (first, last) = (long_run_key(0), long_run_key(LONG_RUN + 1));

    // Two active keys around the run, so the walk crosses every page size
    let across_run = range_page(&ordered, &connect, &tips[1], &first, None, 2).await;
    assert_eq!(across_run.keys, [first.clone(), last.clone()]);
    assert_eq!(across_run.next_start_key, None);
    assert_eq!(across_run.start_proof, None);
    let past_run = range_page(&ordered, &connect, &tips[1], &long_run_key(1), None, 10).await;
    assert_eq!(past_run.keys, [last.as_str()]);
    assert_eq!(past_run.start_proof, Some(span(&first, &last)));

    // Before the deletes every key is active but has a later delete row, so the
    // 128-row first page settles 64 keys. Entries are proven from the walk's
    // locations without reading the index again
    let limit = 40;
    query.reset_update_reads();
    let raw = ordered
        .get_range_raw(
            tips[0].latest_location,
            long_run_key(1).into_bytes(),
            None,
            limit,
            None,
        )
        .await
        .expect("get_range_raw");
    assert_eq!(raw.entries.len(), limit as usize);
    assert_eq!(query.update_reads(), (1, 128));
    let earlier = range_page(&ordered, &connect, &tips[0], &long_run_key(1), None, limit).await;
    assert_eq!(
        earlier.keys,
        (1..=limit as usize).map(long_run_key).collect::<Vec<_>>()
    );
    assert_eq!(
        earlier.next_start_key,
        Some(long_run_key(limit as usize + 1))
    );
    assert_eq!(earlier.start_proof, None);
}

/// Update-index `(scans, rows)` the adapter reads for a miss proof of `key`.
async fn miss_reads(
    query: &common::CountingQuery,
    ordered: &TestOrderedClient,
    tip: &SourceBatch,
    key: &str,
) -> (usize, usize) {
    query.reset_update_reads();
    ordered
        .get_many_raw(
            tip.latest_location,
            std::slice::from_ref(&key.as_bytes().to_vec()),
            None,
        )
        .await
        .expect("get_many_raw");
    query.update_reads()
}

#[tokio::test]
async fn test_ordered_connect_walks_settle_hot_keys_without_reading_every_version() {
    let (query, store_client, _servers) = common::counting_store().await;
    // `b` gets a version at every tip, more than a first page. The last tip
    // deletes it and writes `a`, so `a` has few versions below it
    let versions = 200;
    let mut batches = vec![tip_writes(&[
        ("b", Some("b0")),
        ("c", Some("c0")),
        ("d", Some("d0")),
    ])];
    for version in 1..versions - 1 {
        batches.push(tip_writes(&[("b", Some(&format!("b{version}")))]));
    }
    batches.push(tip_writes(&[("a", Some("a0")), ("b", None)]));
    let tips = build_source_tips("current_ordered_variable_mmr_connect_hot_key", batches).await;
    upload_tips(&store_client, &tips).await;
    let ordered = TestOrderedClient::new(
        PrefixedStoreClient::empty(store_client.clone()),
        op_cfg(),
        key_cfg(),
    );
    let (_qmdb_server, qmdb_url) =
        spawn_qmdb_server(PrefixedStoreClient::empty(store_client.clone())).await;
    let connect = key_lookup_client(&qmdb_url);
    let (active, deleted) = (&tips[versions - 2], &tips[versions - 1]);

    // Reverse walks settle `b` at its newest version at or below the tip, past
    // the delete above it, within the first page
    let proof = miss_proof(&ordered, &connect, active, "bb").await;
    assert_eq!(cover(&proof), span("b", "c"));
    let ExclusionProof::KeyValue(_, update) = &proof.proof else {
        unreachable!("span cover");
    };
    assert_eq!(update.value, format!("b{}", versions - 2).into_bytes());
    // One scan looks up the probe itself
    assert_eq!(
        miss_reads(&query, &ordered, active, "bb").await,
        (1 + 1, 128)
    );

    // A deleted `b` settles inactive, and the second page starts below its
    // older versions, reading only `a`
    assert_eq!(
        miss_cover(&ordered, &connect, deleted, "bb").await,
        span("a", "c")
    );
    let (scans, rows) = miss_reads(&query, &ordered, deleted, "bb").await;
    assert_eq!(scans, 1 + 2);
    assert!(
        rows < 128 + 16,
        "walk past a deleted key with {versions} versions read {rows} update rows"
    );

    // Forward walks read `b` oldest first across pages and settle it at the
    // version above the tip
    let page = range_page(&ordered, &connect, active, "b", None, 1).await;
    assert_eq!(page.keys, ["b"]);
    assert_eq!(page.next_start_key.as_deref(), Some("c"));
    let page = range_page(&ordered, &connect, deleted, "b", None, 1).await;
    assert_eq!(page.keys, ["c"]);
    assert_eq!(page.next_start_key.as_deref(), Some("d"));
    assert_eq!(page.start_proof, Some(span("a", "c")));
    // Earlier tips see `b` active with every later version above them
    let earliest = range_page(&ordered, &connect, &tips[0], "a", None, 4).await;
    assert_eq!(earliest.keys, ["b", "c", "d"]);
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
            source.latest_location,
            b"a".to_vec(),
            Some(b"c".to_vec()),
            10,
            None,
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
            source.latest_location,
            b"aardvark".to_vec(),
            None,
            10,
            None,
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
            source.latest_location,
            &b"alpha".to_vec(),
            None,
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
            source.latest_location,
            &[b"alpha".to_vec(), b"beta".to_vec()],
            None,
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
            source.latest_location,
            &[b"alpha".to_vec()],
            None,
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
            source.latest_location,
            b"a".to_vec(),
            None,
            2,
            None,
            &source.current_boundary.root,
        )
        .await
        .expect_err("a short page must not omit an in-range successor");
    assert!(matches!(err, QmdbError::RangeMismatch(_)), "{err}");
}
