#![allow(refining_impl_trait)]

#[allow(dead_code)]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_storage::merkle::{hasher::Hasher as _, mem::Mem, mmr, Family, Location, Position};
use commonware_storage::qmdb::any::unordered::variable::Operation as UnorderedOperation;
use commonware_storage::qmdb::keyless::variable::Operation as KeylessOperation;
use connectrpc::{ConnectError, ConnectRpcService, ErrorCode, RequestContext, ServiceRequest};
use exoware_qmdb::proto::qmdb::v1::GetOperationRangeRequest;
use exoware_qmdb::{
    keyless_operation_log_connect_stack, stage_authenticated_range, stage_watermark,
    unordered_operation_log_connect_stack, KeylessClient, OperationLogClient, UnorderedClient,
    UploadOperation, NODE_FAMILY,
};
use exoware_sdk::common::kv::v1::Entry;
use exoware_sdk::google::rpc::{ErrorInfo, RetryInfo};
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::proto::{
    decode_connect_error, with_error_info_detail, with_query_detail, with_retry_info_detail,
};
use exoware_sdk::query::{
    Detail, GetManyEntry, GetManyFrame, GetManyRequest, GetRequest, GetResponse, RangeFrame,
    RangeRequest, ReduceRequest, ReduceResponse, Service, ServiceServer, TraversalMode,
};
use exoware_sdk::{PrefixedStoreClient, RetryConfig, StoreClient, StoreKeyPrefix, StoreWriteBatch};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;

type Operation = KeylessOperation<mmr::Family, Vec<u8>>;
type UnorderedOp = UnorderedOperation<mmr::Family, Vec<u8>, Vec<u8>>;
type Keyless = KeylessClient<mmr::Family, Sha256, Vec<u8>>;
type Unordered = UnorderedClient<mmr::Family, Sha256, Vec<u8>, Vec<u8>>;
type ProofClient = OperationLogClient<PreferZstdHttpClient, mmr::Family, Sha256, Operation>;

#[derive(Clone, Debug)]
enum Call {
    Get(GetRequest),
    GetMany(GetManyRequest),
    Range(RangeRequest),
}

#[derive(Default)]
struct State {
    rows: BTreeMap<Vec<u8>, Bytes>,
    calls: Vec<Call>,
    get_sequence: u64,
    batch_sequences: Vec<u64>,
    range_sequence: u64,
    batch_error: Option<ConnectError>,
    batch_gate: Option<Arc<Gate>>,
    range_gate: Option<Arc<Gate>>,
}

struct Gate {
    entered: Semaphore,
    release: Semaphore,
}

impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        })
    }

    async fn hold(&self) {
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
    }

    async fn wait(&self) {
        tokio::time::timeout(Duration::from_secs(5), self.entered.acquire())
            .await
            .expect("request reached gate")
            .unwrap()
            .forget();
    }

    fn open(&self) {
        self.release.add_permits(1);
    }
}

#[derive(Clone, Default)]
struct Store {
    state: Arc<Mutex<State>>,
    changed: Arc<Notify>,
}

impl Store {
    fn calls(&self) -> Vec<Call> {
        self.state.lock().unwrap().calls.clone()
    }

    async fn wait_for_calls(&self, count: usize, predicate: impl Fn(&Call) -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.changed.notified();
                if self.calls().iter().filter(|call| predicate(call)).count() >= count {
                    return;
                }
                changed.await;
            }
        })
        .await
        .expect("expected Store calls arrived");
    }
}

impl Service for Store {
    async fn get(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, GetRequest>,
    ) -> connectrpc::ServiceResult<GetResponse> {
        let request = request.to_owned_message();
        let mut state = self.state.lock().unwrap();
        state.calls.push(Call::Get(request.clone()));
        self.changed.notify_one();
        require_floor(request.min_sequence_number, state.get_sequence)?;
        connectrpc::Response::ok(GetResponse {
            value: state.rows.get(request.key.as_slice()).cloned(),
            detail: detail(state.get_sequence).into(),
            ..Default::default()
        })
    }

    async fn get_many(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, GetManyRequest>,
    ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<GetManyFrame>> {
        let request = request.to_owned_message();
        let (gate, results, sequences, error) = {
            let mut state = self.state.lock().unwrap();
            state.calls.push(Call::GetMany(request.clone()));
            self.changed.notify_one();
            let results = request
                .keys
                .iter()
                .rev()
                .map(|key| GetManyEntry {
                    key: key.clone(),
                    value: state.rows.get(key.as_slice()).cloned(),
                    ..Default::default()
                })
                .collect::<Vec<_>>();
            let sequences = if state.batch_sequences.is_empty() {
                vec![0]
            } else {
                state.batch_sequences.clone()
            };
            (
                state.batch_gate.take(),
                results,
                sequences,
                state.batch_error.clone(),
            )
        };
        if let Some(gate) = gate {
            gate.hold().await;
        }
        let mut frames = Vec::new();
        let mut results = results;
        for sequence in sequences {
            if let Err(error) = require_floor(request.min_sequence_number, sequence) {
                frames.push(Err(error));
                break;
            }
            frames.push(Ok(GetManyFrame {
                results: std::mem::take(&mut results),
                detail: detail(sequence).into(),
                ..Default::default()
            }));
        }
        if let Some(error) = error {
            frames.push(Err(error));
        }
        Ok(connectrpc::Response::stream(futures::stream::iter(frames)))
    }

    async fn range(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, RangeRequest>,
    ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<RangeFrame>> {
        let request = request.to_owned_message();
        let (gate, results, sequence) = {
            let mut state = self.state.lock().unwrap();
            state.calls.push(Call::Range(request.clone()));
            let mut rows = state
                .rows
                .iter()
                .filter(|(key, _)| {
                    key.as_slice() >= request.start.as_slice()
                        && (request.end.is_empty() || key.as_slice() <= request.end.as_slice())
                })
                .map(|(key, value)| Entry {
                    key: key.clone(),
                    value: value.clone(),
                    ..Default::default()
                })
                .collect::<Vec<_>>();
            if request.mode == TraversalMode::Reverse {
                rows.reverse();
            }
            rows.truncate(request.limit.unwrap_or(u32::MAX) as usize);
            let gate = if request.mode == TraversalMode::Reverse {
                None
            } else {
                state.range_gate.take()
            };
            (gate, rows, state.range_sequence)
        };
        if let Some(gate) = gate {
            gate.hold().await;
        }
        require_floor(request.min_sequence_number, sequence)?;
        Ok(connectrpc::Response::stream(futures::stream::iter([Ok(
            RangeFrame {
                results,
                detail: detail(sequence).into(),
                ..Default::default()
            },
        )])))
    }

    async fn reduce(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, ReduceRequest>,
    ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<ReduceResponse>> {
        panic!("operation proofs must not reduce Store rows")
    }
}

fn detail(sequence_number: u64) -> Detail {
    Detail {
        sequence_number,
        ..Default::default()
    }
}

fn require_floor(floor: Option<u64>, sequence: u64) -> Result<(), ConnectError> {
    if sequence < floor.unwrap_or_default() {
        return Err(with_query_detail(
            ConnectError::new(ErrorCode::Aborted, "replica is behind the requested floor"),
            detail(sequence),
        ));
    }
    Ok(())
}

fn key(family: u8, location: u64) -> Vec<u8> {
    let mut key = vec![family];
    key.extend(location.to_be_bytes());
    key
}

fn operations() -> Vec<Operation> {
    (0..15)
        .map(|index| {
            if index == 3 || index == 14 {
                Operation::Commit(None, Location::new(0))
            } else {
                Operation::Append(vec![index])
            }
        })
        .collect()
}

fn request(tip: u64, start_location: u64, max_locations: u32) -> GetOperationRangeRequest {
    GetOperationRangeRequest {
        tip,
        start_location,
        max_locations,
        ..Default::default()
    }
}

fn proof_client(url: &str) -> ProofClient {
    ProofClient::plaintext(url, ((0..=10000).into(), ()))
}

struct Fixture {
    store: Store,
    client: StoreClient,
    servers: Vec<JoinHandle<()>>,
}

impl Fixture {
    async fn new() -> Self {
        let store = Store::default();
        let (server, url) = common::spawn_connect_service(
            ConnectRpcService::new(ServiceServer::new(store.clone()))
                .with_compression(exoware_sdk::connect_compression_registry()),
        )
        .await;
        let client = StoreClient::builder()
            .url(&url)
            .retry_config(RetryConfig::disabled())
            .build()
            .unwrap();
        Self {
            store,
            client,
            servers: vec![server],
        }
    }

    fn prefixed(&self, prefix: &[u8]) -> PrefixedStoreClient {
        self.client
            .prefixed(StoreKeyPrefix::new(Bytes::copy_from_slice(prefix)).unwrap())
    }

    fn stage<Op: UploadOperation<mmr::Family>>(
        &self,
        client: &PrefixedStoreClient,
        operations: &[Op],
        cfg: &Op::Cfg,
    ) -> Digest {
        let (root, prepared) = common::prepare_operations::<mmr::Family, Op>(operations, cfg);
        let mut batch = StoreWriteBatch::new();
        stage_authenticated_range(client, prepared, &mut batch).unwrap();
        stage_watermark(
            client,
            Location::<mmr::Family>::new(operations.len() as u64 - 1),
            &mut batch,
        )
        .unwrap();
        self.store.state.lock().unwrap().rows.extend(
            batch
                .entries()
                .iter()
                .map(|(key, value)| (key.to_vec(), value.clone())),
        );
        root
    }

    async fn keyless(&mut self, client: Keyless) -> String {
        let (server, url) =
            common::spawn_connect_service(keyless_operation_log_connect_stack(Arc::new(client)))
                .await;
        self.servers.push(server);
        url
    }

    async fn unordered(&mut self, client: Unordered) -> String {
        let (server, url) =
            common::spawn_connect_service(unordered_operation_log_connect_stack(Arc::new(client)))
                .await;
        self.servers.push(server);
        url
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for server in &self.servers {
            server.abort();
        }
    }
}

fn boundary_batch(calls: &[Call], tip: u64) -> &GetManyRequest {
    assert_eq!(calls.len(), 2, "one publication lookup and one proof batch");
    let Call::Get(publication) = &calls[0] else {
        panic!("publication must be first")
    };
    assert_eq!(publication.key.as_ref(), key(3, tip));
    let Call::GetMany(batch) = &calls[1] else {
        panic!("proof nodes must be batched")
    };
    let unique = batch.keys.iter().collect::<BTreeSet<_>>();
    assert_eq!(
        unique.len(),
        batch.keys.len(),
        "batch keys must be deduplicated"
    );
    batch
}

#[tokio::test]
async fn boundary_singletons_batch_nodes_and_preserve_response_floors() {
    for (floor, publication, batches, expected) in [(0, 0, vec![0], 0), (17, 23, vec![31, 47], 47)]
    {
        let mut fixture = Fixture::new().await;
        let store = fixture.prefixed(&[]);
        let operations = operations();
        let root = fixture.stage(&store, &operations, &((0..=10000).into(), ()));
        {
            let mut state = fixture.store.state.lock().unwrap();
            state.get_sequence = publication;
            state.batch_sequences = batches;
        }
        let url = fixture
            .keyless(Keyless::new(store, ((0..=10000).into(), ())))
            .await;
        let mut query = request(14, 14, 1);
        query.min_sequence_number = Some(floor);
        let proof = proof_client(&url)
            .get_operation_range(query, &root)
            .await
            .unwrap();
        assert_eq!(proof.operations, operations[14..]);
        assert_eq!(proof.sequence_number, expected);
        let calls = fixture.store.calls();
        let batch = boundary_batch(&calls, 14);
        assert_eq!(
            batch
                .keys
                .iter()
                .filter(|key| key.as_ref() == self::key(4, 14))
                .count(),
            1
        );
        let Call::Get(publication_request) = &calls[0] else {
            unreachable!()
        };
        assert_eq!(
            publication_request.min_sequence_number.unwrap_or_default(),
            floor
        );
        assert_eq!(batch.min_sequence_number.unwrap_or_default(), publication);
    }
}

#[tokio::test]
async fn historical_commit_without_marker_uses_reverse_publication_fallback() {
    let mut fixture = Fixture::new().await;
    let store = fixture.prefixed(&[]);
    let operations = operations();
    fixture.stage(&store, &operations, &((0..=10000).into(), ()));
    let (root, _) = common::prepare_operations::<mmr::Family, Operation>(
        &operations[..4],
        &((0..=10000).into(), ()),
    );
    let url = fixture
        .keyless(Keyless::new(store, ((0..=10000).into(), ())))
        .await;
    let proof = proof_client(&url)
        .get_operation_range(request(3, 1, 1), &root)
        .await
        .unwrap();
    assert_eq!(proof.operations, operations[1..2]);
    let calls = fixture.store.calls();
    assert_eq!(calls.len(), 3);
    assert!(matches!(&calls[0], Call::Get(get) if get.key.as_ref() == key(3, 3)));
    assert!(
        matches!(&calls[1], Call::Range(range) if range.mode == TraversalMode::Reverse && range.limit == Some(1))
    );
    assert!(matches!(&calls[2], Call::GetMany(_)));
}

#[tokio::test]
async fn unpublished_tip_precedes_bad_ranges_and_corrupt_rows_including_zero() {
    for tip in [0, 14] {
        let mut fixture = Fixture::new().await;
        let store = fixture.prefixed(&[]);
        fixture
            .store
            .state
            .lock()
            .unwrap()
            .rows
            .insert(key(4, tip), Bytes::from_static(b"corrupt"));
        let url = fixture
            .keyless(Keyless::new(store, ((0..=10000).into(), ())))
            .await;
        for start in [tip + 1, 0] {
            let error = common::operation_log_rpc_client(&url)
                .get_operation_range(request(tip, start, 1))
                .await
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::OutOfRange);
            assert!(error.message.unwrap().contains("watermark"));
        }
        assert!(fixture
            .store
            .calls()
            .iter()
            .all(|call| !matches!(call, Call::GetMany(_))));
    }

    let mut fixture = Fixture::new().await;
    let store = fixture.prefixed(&[]);
    let operations = vec![Operation::Commit(None, Location::new(0))];
    let root = fixture.stage(&store, &operations, &((0..=10000).into(), ()));
    let url = fixture
        .keyless(Keyless::new(store, ((0..=10000).into(), ())))
        .await;
    let proof = proof_client(&url)
        .get_operation_range(request(0, 0, 1), &root)
        .await
        .unwrap();
    assert_eq!(proof.operations, operations);
    boundary_batch(&fixture.store.calls(), 0);
}

#[tokio::test]
async fn operation_scan_overlaps_node_batch_and_preserves_order() {
    assert_operation_scan_overlap(10).await;
}

#[tokio::test]
async fn zero_sequence_publication_allows_parallel_operation_scan() {
    assert_operation_scan_overlap(0).await;
}

async fn assert_operation_scan_overlap(publication: u64) {
    let mut fixture = Fixture::new().await;
    let store = fixture.prefixed(&[]);
    let operations = operations();
    let root = fixture.stage(&store, &operations, &((0..=10000).into(), ()));
    let batch_gate = Gate::new();
    let range_gate = Gate::new();
    {
        let mut state = fixture.store.state.lock().unwrap();
        state.batch_gate = Some(batch_gate.clone());
        state.range_gate = Some(range_gate.clone());
        state.get_sequence = publication;
        state.batch_sequences = vec![20, 25];
        state.range_sequence = 30;
    }
    let url = fixture
        .keyless(Keyless::new(store, ((0..=10000).into(), ())))
        .await;
    let query = tokio::spawn(async move {
        proof_client(&url)
            .get_operation_range(request(14, 2, 9), &root)
            .await
    });
    batch_gate.wait().await;
    range_gate.wait().await;
    assert!(!query.is_finished());
    batch_gate.open();
    range_gate.open();
    let proof = query.await.unwrap().unwrap();
    assert_eq!(proof.operations, operations[2..11]);
    assert_eq!(proof.sequence_number, 30);
    let calls = fixture.store.calls();
    assert_eq!(calls.len(), 3);
    assert!(matches!(calls[0], Call::Get(_)));
    let range = calls
        .iter()
        .find_map(|call| match call {
            Call::Range(range) => Some(range),
            _ => None,
        })
        .unwrap();
    assert_eq!(range.start.as_ref(), key(4, 2));
    assert_eq!(range.end.as_ref(), key(4, 10));
    assert_eq!(range.min_sequence_number.unwrap_or_default(), publication);
    let batch = calls
        .iter()
        .find_map(|call| match call {
            Call::GetMany(batch) => Some(batch),
            _ => None,
        })
        .unwrap();
    assert_eq!(batch.min_sequence_number.unwrap_or_default(), publication);
}

#[tokio::test]
async fn cold_singleton_does_not_wait_for_another_proofs_operation_scan() {
    let mut fixture = Fixture::new().await;
    let store = fixture.prefixed(&[]);
    let operations = operations();
    let root = fixture.stage(&store, &operations, &((0..=10000).into(), ()));
    let range_gate = Gate::new();
    fixture.store.state.lock().unwrap().range_gate = Some(range_gate.clone());
    let url = fixture
        .keyless(Keyless::new(store, ((0..=10000).into(), ())))
        .await;
    let client = proof_client(&url);
    let range_client = client.clone();
    let range = tokio::spawn(async move {
        range_client
            .get_operation_range(request(14, 2, 9), &root)
            .await
    });
    range_gate.wait().await;
    let mut singleton =
        tokio::spawn(async move { client.get_operation_range(request(14, 14, 1), &root).await });
    fixture
        .store
        .wait_for_calls(2, |call| matches!(call, Call::Get(_)))
        .await;
    let result = tokio::time::timeout(Duration::from_secs(1), &mut singleton).await;
    assert!(!range.is_finished());
    range_gate.open();
    let proof = range.await.unwrap().unwrap();
    assert_eq!(proof.operations, operations[2..11]);
    if result.is_err() {
        singleton.await.unwrap().unwrap();
    }
    let proof = result
        .expect("a singleton must not wait for another proof's operation scan")
        .unwrap()
        .unwrap();
    assert_eq!(proof.operations, operations[14..15]);
}

#[tokio::test]
async fn failed_node_batch_returns_while_operation_scan_is_pending() {
    let mut fixture = Fixture::new().await;
    let store = fixture.prefixed(&[]);
    fixture.stage(&store, &operations(), &((0..=10000).into(), ()));
    let batch_gate = Gate::new();
    let range_gate = Gate::new();
    {
        let mut state = fixture.store.state.lock().unwrap();
        state.batch_gate = Some(batch_gate.clone());
        state.range_gate = Some(range_gate.clone());
        state.get_sequence = 23;
        state.batch_sequences = vec![19];
        state.range_sequence = 23;
    }
    let url = fixture
        .keyless(Keyless::new(store, ((0..=10000).into(), ())))
        .await;
    let mut query = tokio::spawn(async move {
        common::operation_log_rpc_client(&url)
            .get_operation_range(request(14, 2, 9))
            .await
    });
    batch_gate.wait().await;
    range_gate.wait().await;
    batch_gate.open();

    let result = tokio::time::timeout(Duration::from_secs(1), &mut query).await;
    query.abort();
    let error = result
        .expect("a failed node batch must not wait for the operation scan")
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Aborted);
    assert_eq!(
        decode_connect_error(&error).unwrap().query_detail,
        Some(detail(19))
    );
}

#[tokio::test]
async fn clones_share_successful_roots_and_nodes_but_recheck_publication() {
    let mut fixture = Fixture::new().await;
    let store = fixture.prefixed(&[]);
    let operations = operations();
    let root = fixture.stage(&store, &operations, &((0..=10000).into(), ()));
    let client = Keyless::new(store, ((0..=10000).into(), ()));
    let first_url = fixture.keyless(client.clone()).await;
    let second_url = fixture.keyless(client).await;
    proof_client(&first_url)
        .get_operation_range(request(14, 1, 1), &root)
        .await
        .unwrap();
    fixture.store.state.lock().unwrap().calls.clear();
    proof_client(&second_url)
        .get_operation_range(request(14, 1, 1), &root)
        .await
        .unwrap();
    let calls = fixture.store.calls();
    let batch = boundary_batch(&calls, 14);
    assert_eq!(batch.keys, vec![Bytes::from(key(4, 1))]);

    fixture.store.state.lock().unwrap().rows.remove(&key(3, 14));
    let error = common::operation_log_rpc_client(&second_url)
        .get_operation_range(request(14, 1, 1))
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::OutOfRange);
    assert_eq!(
        fixture
            .store
            .calls()
            .iter()
            .filter(|call| matches!(call, Call::Get(_)))
            .count(),
        2
    );
}

#[tokio::test]
async fn eleven_concurrent_singletons_fetch_each_node_once() {
    let mut fixture = Fixture::new().await;
    let store = fixture.prefixed(&[]);
    let operations = operations();
    let root = fixture.stage(&store, &operations, &((0..=10000).into(), ()));
    let gate = Gate::new();
    fixture.store.state.lock().unwrap().batch_gate = Some(gate.clone());
    let url = fixture
        .keyless(Keyless::new(store, ((0..=10000).into(), ())))
        .await;
    let client = proof_client(&url);
    let mut queries = Vec::new();
    let first = client.clone();
    queries.push(tokio::spawn(async move {
        first.get_operation_range(request(14, 0, 1), &root).await
    }));
    gate.wait().await;
    for location in 1..11 {
        let client = client.clone();
        queries.push(tokio::spawn(async move {
            client
                .get_operation_range(request(14, location, 1), &root)
                .await
        }));
    }
    fixture
        .store
        .wait_for_calls(11, |call| matches!(call, Call::Get(_)))
        .await;
    fixture
        .store
        .wait_for_calls(11, |call| matches!(call, Call::GetMany(_)))
        .await;
    assert!(queries.iter().all(|query| !query.is_finished()));
    gate.open();
    for (location, query) in queries.into_iter().enumerate() {
        let proof = tokio::time::timeout(Duration::from_secs(5), query)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(proof.operations, operations[location..location + 1]);
    }
    let calls = fixture.store.calls();
    assert_eq!(calls.len(), 22, "each proof needs one Get and one GetMany");
    let mut nodes = BTreeMap::new();
    for call in &calls {
        if let Call::GetMany(batch) = call {
            assert_eq!(
                batch.keys.len(),
                batch.keys.iter().collect::<BTreeSet<_>>().len()
            );
            for key in &batch.keys {
                if key[0] == NODE_FAMILY {
                    *nodes.entry(key.clone()).or_insert(0) += 1;
                }
            }
        }
    }
    assert!(!nodes.is_empty());
    assert!(
        nodes.values().all(|&count| count == 1),
        "node fetch counts {nodes:?}"
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, Call::Get(_)))
            .count(),
        11
    );
    assert!(calls.iter().all(|call| !matches!(call, Call::Range(_))));
}

#[tokio::test]
async fn separate_namespaces_do_not_share_cached_nodes_or_roots() {
    let mut fixture = Fixture::new().await;
    let mut roots = Vec::new();
    let mut urls = Vec::new();
    for prefix in [0xa1, 0xb2] {
        let store = fixture.prefixed(&[prefix]);
        let operations = vec![
            Operation::Append(vec![prefix]),
            Operation::Commit(None, Location::new(0)),
        ];
        roots.push(fixture.stage(&store, &operations, &((0..=10000).into(), ())));
        urls.push(
            fixture
                .keyless(Keyless::new(store, ((0..=10000).into(), ())))
                .await,
        );
    }
    assert_ne!(roots[0], roots[1]);
    for (index, prefix) in [0xa1, 0xb2].into_iter().enumerate() {
        let proof = proof_client(&urls[index])
            .get_operation_range(request(1, 0, 1), &roots[index])
            .await
            .unwrap();
        assert_eq!(proof.operations, vec![Operation::Append(vec![prefix])]);
    }
    let calls = fixture.store.calls();
    assert_eq!(calls.len(), 4);
    for (pair, prefix) in calls.as_chunks::<2>().0.iter().zip([0xa1, 0xb2]) {
        assert!(matches!(&pair[0], Call::Get(get) if get.key[0] == prefix));
        let Call::GetMany(batch) = &pair[1] else {
            panic!("namespace must fetch its proof rows")
        };
        assert!(batch.keys.iter().all(|key| key[0] == prefix));
        assert!(batch.keys.iter().any(|key| key[1] == NODE_FAMILY));
    }
}

fn prefix_root(operations: &[UnorderedOp], floor: u64) -> Digest {
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let base = Mem::<mmr::Family, Digest>::new();
    let digests = operations.iter().enumerate().map(|(index, operation)| {
        hasher.leaf_digest(
            Position::try_from(Location::<mmr::Family>::new(index as u64)).unwrap(),
            &operation.encode(),
        )
    });
    let inactive =
        mmr::Family::inactive_peaks(Location::new(operations.len() as u64), Location::new(floor));
    assert!(
        inactive > 0,
        "the fixture must authenticate a nonzero inactive prefix"
    );
    base.new_batch()
        .add_leaf_digests(digests)
        .merkleize(&base, &hasher)
        .root(&base, &hasher, inactive)
        .unwrap()
}

#[tokio::test]
async fn unordered_noncommit_tip_shares_floor_without_waiting_for_operation_scan() {
    let mut fixture = Fixture::new().await;
    let store = fixture.prefixed(&[]);
    let operations = vec![
        UnorderedOp::CommitFloor(None, Location::new(0)),
        UnorderedOp::Delete(b"first".to_vec()),
        UnorderedOp::Delete(b"second".to_vec()),
        UnorderedOp::Delete(b"third".to_vec()),
        UnorderedOp::CommitFloor(None, Location::new(4)),
        UnorderedOp::Delete(b"fourth".to_vec()),
        UnorderedOp::Delete(b"fifth".to_vec()),
        UnorderedOp::CommitFloor(None, Location::new(4)),
    ];
    let cfg = (((0..=10000).into(), ()), ((0..=10000).into(), ()));
    fixture.stage(&store, &operations, &cfg);
    let root = prefix_root(&operations[..7], 4);
    let range_gate = Gate::new();
    fixture.store.state.lock().unwrap().range_gate = Some(range_gate.clone());
    let url = fixture.unordered(Unordered::new(store, cfg)).await;
    let client = OperationLogClient::<_, mmr::Family, Sha256, UnorderedOp>::plaintext(&url, cfg);
    let range_client = client.clone();
    let range = tokio::spawn(async move {
        range_client
            .get_operation_range(request(6, 0, 2), &root)
            .await
    });
    range_gate.wait().await;
    let mut singleton =
        tokio::spawn(async move { client.get_operation_range(request(6, 6, 1), &root).await });
    let result = tokio::time::timeout(Duration::from_secs(1), &mut singleton).await;
    assert!(!range.is_finished());
    range_gate.open();
    assert_eq!(range.await.unwrap().unwrap().operations, operations[..2]);
    if result.is_err() {
        singleton.await.unwrap().unwrap();
    }
    let proof = result
        .expect("shared floor initialization must not wait for the operation scan")
        .unwrap()
        .unwrap();
    assert_eq!(proof.operations, operations[6..7]);
    let calls = fixture.store.calls();
    for location in [4, 5] {
        assert_eq!(
            calls
                .iter()
                .filter(|call| {
                    matches!(call, Call::Get(get) if get.key.as_ref() == key(4, location))
                })
                .count(),
            1,
            "the backward floor walk must be shared"
        );
    }
}

#[tokio::test]
async fn missing_witness_is_reloaded_after_a_successful_cached_proof() {
    let mut fixture = Fixture::new().await;
    let store = fixture.prefixed(&[]);
    let operations = vec![UnorderedOp::CommitFloor(None, Location::new(0))];
    let cfg = (((0..=10000).into(), ()), ((0..=10000).into(), ()));
    let root = fixture.stage(&store, &operations, &cfg);
    let url = fixture.unordered(Unordered::new(store, cfg)).await;
    let client = OperationLogClient::<_, mmr::Family, Sha256, UnorderedOp>::plaintext(&url, cfg);
    client
        .get_operation_range(request(0, 0, 1), &root)
        .await
        .unwrap();

    // A missing witness may be published later and must remain visible to this client.
    fixture
        .store
        .state
        .lock()
        .unwrap()
        .rows
        .insert(key(9, 0), Bytes::from_static(b"corrupt"));
    fixture.store.state.lock().unwrap().calls.clear();
    let error = common::operation_log_rpc_client(&url)
        .get_operation_range(request(0, 0, 1))
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
    assert!(error.message.unwrap().contains("witness"));
    let calls = fixture.store.calls();
    assert!(boundary_batch(&calls, 0).keys.contains(&key(9, 0)));
}

#[tokio::test]
async fn store_floor_rejections_survive_publication_and_late_batch_frames() {
    for (floor, publication, batches, expected_calls) in [
        (7, 0, vec![0], 1),
        (0, 23, vec![0], 2),
        (0, 23, vec![23, 19], 2),
    ] {
        let mut fixture = Fixture::new().await;
        let store = fixture.prefixed(&[]);
        fixture.stage(&store, &operations(), &((0..=10000).into(), ()));
        {
            let mut state = fixture.store.state.lock().unwrap();
            state.get_sequence = publication;
            state.batch_sequences = batches;
        }
        let url = fixture
            .keyless(Keyless::new(store, ((0..=10000).into(), ())))
            .await;
        let mut query = request(14, 1, 1);
        query.min_sequence_number = Some(floor);
        let error = common::operation_log_rpc_client(&url)
            .get_operation_range(query)
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Aborted);
        let calls = fixture.store.calls();
        assert_eq!(calls.len(), expected_calls);
        if expected_calls == 2 {
            assert_eq!(boundary_batch(&calls, 14).min_sequence_number, Some(23));
        }
    }
}

#[tokio::test]
async fn late_batch_abort_preserves_all_structured_details() {
    let mut fixture = Fixture::new().await;
    let store = fixture.prefixed(&[]);
    fixture.stage(&store, &operations(), &((0..=10000).into(), ()));
    let info = ErrorInfo {
        reason: "REPLICA_BEHIND".into(),
        domain: "operation-range-test".into(),
        ..Default::default()
    };
    let mut retry = RetryInfo::default();
    retry.retry_delay.get_or_insert_default().seconds = 3;
    let expected = with_query_detail(
        with_retry_info_detail(
            with_error_info_detail(
                ConnectError::new(ErrorCode::Aborted, "proof batch replica moved behind"),
                info.clone(),
            ),
            retry.clone(),
        ),
        detail(19),
    );
    {
        let mut state = fixture.store.state.lock().unwrap();
        state.get_sequence = 23;
        state.batch_sequences = vec![23];
        state.batch_error = Some(expected);
    }
    let url = fixture
        .keyless(Keyless::new(store, ((0..=10000).into(), ())))
        .await;
    let error = common::operation_log_rpc_client(&url)
        .get_operation_range(request(14, 1, 1))
        .await
        .unwrap_err();
    let decoded = decode_connect_error(&error).unwrap();
    assert_eq!(decoded.code, ErrorCode::Aborted);
    assert_eq!(
        decoded.message.as_deref(),
        Some("proof batch replica moved behind")
    );
    assert_eq!(decoded.error_info, Some(info));
    assert_eq!(decoded.retry_info, Some(retry));
    assert_eq!(decoded.query_detail, Some(detail(19)));
    assert_eq!(
        boundary_batch(&fixture.store.calls(), 14).min_sequence_number,
        Some(23)
    );
}
