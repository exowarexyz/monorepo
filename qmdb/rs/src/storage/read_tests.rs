#![allow(refining_impl_trait)]

use super::*;
use bytes::Bytes;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_storage::merkle::{mem::Mem, mmb, mmr, verification};
use connectrpc::{ConnectError, ConnectRpcService, RequestContext, ServiceRequest};
use exoware_sdk::{
    common::kv::v1::Entry,
    keys::Key,
    store::query::v1::{
        Detail, GetManyEntry, GetManyFrame, GetManyRequest, GetRequest, GetResponse, RangeFrame,
        RangeRequest, ReduceRequest, ReduceResponse, Service, ServiceServer,
    },
    PrefixedStoreClient, StoreClient, StoreKeyPrefix,
};
use futures::FutureExt as _;
use std::{
    collections::BTreeMap,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
struct NodeQueries {
    rows: BTreeMap<Key, Bytes>,
    calls: Arc<Mutex<Vec<(&'static str, usize)>>>,
    range_barrier: Option<Arc<tokio::sync::Barrier>>,
    requests: Arc<Mutex<Vec<GetManyRequest>>>,
    sequence: Option<u64>,
    fail_stream: bool,
}

impl Service for NodeQueries {
    async fn get(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, GetRequest>,
    ) -> connectrpc::ServiceResult<GetResponse> {
        self.calls.lock().unwrap().push(("get", 1));
        connectrpc::Response::ok(GetResponse {
            value: self.rows.get(request.key).cloned(),
            detail: Some(Detail {
                sequence_number: 1,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
    }

    async fn get_many(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, GetManyRequest>,
    ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<GetManyFrame>> {
        self.calls
            .lock()
            .unwrap()
            .push(("many", request.keys.len()));
        self.requests
            .lock()
            .unwrap()
            .push(request.to_owned_message());
        let sequence = self
            .sequence
            .map(|sequence| sequence.max(request.min_sequence_number.unwrap_or_default()));

        // Legal out-of-order frames require the adapter to recover requested slot order
        let mut frames = request
            .keys
            .iter()
            .rev()
            .enumerate()
            .map(|(index, key)| {
                Ok(GetManyFrame {
                    results: vec![GetManyEntry {
                        key: key.to_vec(),
                        value: self.rows.get(*key).cloned(),
                        ..Default::default()
                    }],
                    detail: Some(Detail {
                        sequence_number: sequence.map_or(1, |sequence| sequence + index as u64 + 1),
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                })
            })
            .collect::<Vec<_>>();
        if self.fail_stream {
            frames.push(Err(ConnectError::unavailable("test stream failure")));
        }
        Ok(connectrpc::Response::stream(futures::stream::iter(frames)))
    }

    async fn range(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, RangeRequest>,
    ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<RangeFrame>> {
        self.calls.lock().unwrap().push(("range", 1));
        if let Some(barrier) = &self.range_barrier {
            barrier.wait().await;
        }
        let results = self
            .rows
            .iter()
            .rev()
            .filter(|(key, _)| key.as_ref() >= request.start && key.as_ref() <= request.end)
            .take(1)
            .map(|(key, value)| Entry {
                key: key.to_vec(),
                value: value.clone(),
                ..Default::default()
            })
            .collect();
        Ok(connectrpc::Response::stream(futures::stream::iter([Ok(
            RangeFrame {
                results,
                detail: Some(Detail {
                    sequence_number: 1,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            },
        )])))
    }

    async fn reduce(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, ReduceRequest>,
    ) -> connectrpc::ServiceResult<ReduceResponse> {
        Err(ConnectError::unimplemented("node read test"))
    }
}

async fn serve(queries: NodeQueries) -> (PrefixedStoreClient, tokio::task::JoinHandle<()>) {
    let service = ConnectRpcService::new(ServiceServer::new(queries));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, axum::Router::new().fallback_service(service))
            .await
            .unwrap();
    });
    (PrefixedStoreClient::empty(StoreClient::new(&url)), task)
}

async fn assert_batched_proofs<F: Family + PartialEq>() {
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let mut memory = Mem::<F, Digest>::new();
    let operations = (0u64..64)
        .map(|index| index.to_be_bytes().to_vec())
        .collect::<Vec<_>>();
    let mut batch = memory.new_batch();
    for operation in &operations {
        batch = batch.add(&hasher, operation);
    }
    let batch = batch.merkleize(&memory, &hasher);
    memory.apply_batch(&batch).unwrap();
    let queries = NodeQueries {
        rows: (0..*memory.size())
            .map(|raw| {
                let position = Position::new(raw);
                (
                    encode_node_key(position),
                    Bytes::copy_from_slice(memory.get_node(position).unwrap().as_ref()),
                )
            })
            .collect(),
        ..Default::default()
    };
    let calls = queries.calls.clone();
    let (client, server) = serve(queries).await;
    let session = client.create_session_with_sequence(1);
    let storage = KvMerkleStorage::<F, Digest> {
        session: &session,
        size: memory.size(),
        _marker: PhantomData,
    };
    let range = Location::new(7)..Location::new(10);
    let proof = verification::historical_range_proof(
        &hasher,
        &storage,
        Location::new(64),
        range.clone(),
        0,
    )
    .await
    .unwrap();
    assert_eq!(proof, memory.range_proof(&hasher, range, 0).unwrap());
    let requested = calls.lock().unwrap().clone();
    assert_eq!(requested.len(), 1, "one bulk node request: {requested:?}");
    assert_eq!(requested[0].0, "many");
    assert!(requested[0].1 > 1);

    calls.lock().unwrap().clear();
    let locations = [Location::new(3), Location::new(19), Location::new(55)];
    let proof = verification::multi_proof(&storage, 0, hasher.root_bagging(), &locations)
        .await
        .unwrap();
    let expected = verification::multi_proof(&memory, 0, hasher.root_bagging(), &locations)
        .await
        .unwrap();
    assert_eq!(proof, expected);
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(calls.lock().unwrap()[0].0, "many");

    calls.lock().unwrap().clear();
    assert!(storage.get_nodes(&[]).await.unwrap().is_empty());
    assert!(calls.lock().unwrap().is_empty());
    let missing = memory.size();
    assert!(
        matches!(storage.get_nodes(&[Position::new(0), missing, missing + 1]).await,
        Err(merkle::Error::ElementPruned(position)) if position == missing)
    );
    server.abort();
}

#[tokio::test]
async fn test_merkle_proofs_batch_node_reads() {
    assert_batched_proofs::<mmr::Family>().await;
    assert_batched_proofs::<mmb::Family>().await;
}

async fn assert_current_nodes(positions: &[u64], expected_calls: &[(&str, usize)]) {
    let positions = positions
        .iter()
        .copied()
        .map(Position::<mmr::Family>::new)
        .collect::<Vec<_>>();
    let digests = positions
        .iter()
        .map(|position| Sha256::hash(&[&position.as_u64().to_be_bytes()]))
        .collect::<Vec<_>>();
    let watermark = Location::new(15);
    let queries = NodeQueries {
        rows: positions
            .iter()
            .zip(&digests)
            .map(|(&position, digest)| {
                let key = if mmr::Family::pos_to_height(position) < grafting::height::<1>() {
                    encode_node_key(position)
                } else {
                    encode_grafted_node_key(
                        grafting::ops_to_grafted_pos(position, grafting::height::<1>()),
                        watermark,
                    )
                };
                (key, Bytes::copy_from_slice(digest.as_ref()))
            })
            .collect(),
        range_barrier: Some(Arc::new(tokio::sync::Barrier::new(2))),
        ..Default::default()
    };
    let calls = queries.calls.clone();
    let (client, server) = serve(queries).await;
    let session = client.create_session_with_sequence(1);
    let storage = KvCurrentStorage::<mmr::Family, Sha256, 1> {
        session: &session,
        watermark,
        pruned_chunks: 0,
        size: Position::new(31),
        _marker: PhantomData,
    };
    // The watchdog reports a stalled sequential reader, without measuring request latency
    let nodes = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        storage.get_nodes(&positions),
    )
    .await
    .expect("grafted reads must reach the barrier concurrently")
    .unwrap();
    assert_eq!(nodes, digests);
    let mut requested = calls.lock().unwrap().clone();
    requested.sort();
    assert_eq!(requested, expected_calls);
    server.abort();
}

#[tokio::test]
async fn test_current_nodes_batch_operations_and_overlap_grafted_reads() {
    assert_current_nodes(&[0, 14, 15, 29], &[("many", 2), ("range", 1), ("range", 1)]).await;
    assert_current_nodes(&[14, 29], &[("range", 1), ("range", 1)]).await;
}

impl NodeQueries {
    fn prefix() -> StoreKeyPrefix {
        StoreKeyPrefix::new("proof/").unwrap()
    }

    fn key<F: Family>(position: u64) -> Key {
        Self::prefix()
            .encode_key(&encode_node_key(Position::<F>::new(position)))
            .unwrap()
    }

    async fn session(&self) -> (SerializableReadSession, tokio::task::JoinHandle<()>) {
        let (client, task) = serve(self.clone()).await;
        (
            client
                .client()
                .prefixed(Self::prefix())
                .create_session_with_sequence(17),
            task,
        )
    }
}

fn storage<F: Family>(session: &SerializableReadSession) -> KvMerkleStorage<'_, F, Digest> {
    KvMerkleStorage {
        session,
        size: Position::new(100),
        _marker: PhantomData,
    }
}

#[tokio::test]
async fn batches_nodes_in_order_and_tracks_the_observed_sequence() {
    let positions = [0, 3, 8].map(Position::<mmr::Family>::new);
    let digests = [1, 2, 3].map(|byte| Digest::decode(&[byte; 32][..]).unwrap());
    let store = NodeQueries {
        sequence: Some(40),
        rows: positions
            .iter()
            .zip(&digests)
            .map(|(position, digest)| {
                (
                    NodeQueries::key::<mmr::Family>(**position),
                    Bytes::copy_from_slice(digest.as_ref()),
                )
            })
            .collect(),
        ..Default::default()
    };
    let (session, server) = store.session().await;
    let storage = storage::<mmr::Family>(&session);

    assert_eq!(storage.get_nodes(&positions).await.unwrap(), digests);
    assert_eq!(session.evaluated_sequence(), Some(43));
    assert_eq!(session.fixed_sequence(), Some(43));
    {
        let requests = store.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].min_sequence_number, Some(17));
        assert_eq!(requests[0].batch_size, 3);
        assert_eq!(
            requests[0].keys,
            positions.map(|position| NodeQueries::key::<mmr::Family>(*position).to_vec())
        );
    }

    assert_eq!(
        storage.get_nodes(&positions[..1]).await.unwrap(),
        digests[..1]
    );
    assert_eq!(
        store.requests.lock().unwrap()[1].min_sequence_number,
        Some(43)
    );
    assert_eq!(session.evaluated_sequence(), Some(44));
    server.abort();
}

#[tokio::test]
async fn rejects_positions_that_are_not_strictly_increasing() {
    let store = NodeQueries::default();
    let (session, server) = store.session().await;
    let storage = storage::<mmr::Family>(&session);
    for positions in [[3, 0], [3, 3]] {
        let positions = positions.map(Position::new);
        assert!(AssertUnwindSafe(storage.get_nodes(&positions))
            .catch_unwind()
            .await
            .is_err());
    }
    assert!(store.requests.lock().unwrap().is_empty());
    server.abort();
}

#[tokio::test]
async fn reports_the_first_missing_or_malformed_node_in_request_order() {
    let positions = [0, 3, 8].map(Position::<mmr::Family>::new);
    for malformed in [None, Some(0), Some(3)] {
        let store = NodeQueries {
            rows: malformed
                .map(|position| {
                    (
                        NodeQueries::key::<mmr::Family>(position),
                        Bytes::from_static(b"invalid digest"),
                    )
                })
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let (session, server) = store.session().await;
        let error = storage::<mmr::Family>(&session)
            .get_nodes(&positions)
            .await
            .unwrap_err();
        if malformed == Some(0) {
            assert!(matches!(
                error,
                merkle::Error::DataCorrupted("exoware-qmdb node digest has invalid length")
            ));
        } else {
            assert!(
                matches!(error, merkle::Error::ElementPruned(position) if position == positions[0])
            );
        }
        assert_eq!(store.requests.lock().unwrap().len(), 1);
        server.abort();
    }
}

#[tokio::test]
async fn preserves_fetch_errors_after_streamed_results() {
    let store = NodeQueries {
        fail_stream: true,
        ..Default::default()
    };
    let (session, server) = store.session().await;
    let error = storage::<mmr::Family>(&session)
        .get_nodes(&[Position::new(0)])
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        merkle::Error::DataCorrupted("exoware-qmdb node fetch failed")
    ));
    assert_eq!(store.requests.lock().unwrap().len(), 1);
    server.abort();
}
