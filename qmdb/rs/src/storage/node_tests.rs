use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Request, Response},
};
use buffa::Message as _;
use bytes::Bytes;
use commonware_cryptography::{sha256::Digest as Sha256Digest, Sha256};
use commonware_storage::merkle::{mem::Mem, mmb, mmr};
use connectrpc::client::{BoxFuture, ClientBody, ClientTransport};
use exoware_sdk::{
    query::{Detail, GetManyEntry, GetManyFrame, GetManyRequest},
    ConnectError, Key, RetryConfig, StoreClient, StoreKeyPrefix,
};
use futures::FutureExt as _;
use std::{
    collections::HashMap,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
struct RecordingStore {
    rows: HashMap<Key, Bytes>,
    requests: Arc<Mutex<Vec<GetManyRequest>>>,
    fail_stream: bool,
}

impl RecordingStore {
    fn prefix() -> StoreKeyPrefix {
        StoreKeyPrefix::new("proof/").unwrap()
    }

    fn key<F: Family>(position: u64) -> Key {
        Self::prefix()
            .encode_key(&encode_node_key(Position::<F>::new(position)))
            .unwrap()
    }

    fn session(&self) -> SerializableReadSession {
        StoreClient::builder()
            .url("http://store.test")
            .retry_config(RetryConfig::disabled())
            .client_transport(self.clone())
            .build()
            .unwrap()
            .prefixed(Self::prefix())
            .create_session_with_sequence(17)
    }
}

impl ClientTransport for RecordingStore {
    type ResponseBody = Body;
    type Error = ConnectError;

    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Body>, ConnectError>> {
        let store = self.clone();
        Box::pin(async move {
            assert_eq!(request.uri().path(), "/store.query.v1.Service/GetMany");
            let body = to_bytes(Body::new(request.into_body()), usize::MAX)
                .await
                .unwrap();
            let request = GetManyRequest::decode_from_slice(&body[5..]).unwrap();
            store.requests.lock().unwrap().push(request.clone());
            let sequence = request.min_sequence_number.unwrap_or_default().max(40);
            let mut response = Vec::new();

            // Reverse the results and advance the sequence in every frame to exercise stream consumption.
            for (index, key) in request.keys.into_iter().rev().enumerate() {
                let value = store.rows.get(key.as_slice()).cloned();
                let frame = GetManyFrame {
                    results: vec![GetManyEntry {
                        key,
                        value,
                        ..Default::default()
                    }],
                    detail: Detail {
                        sequence_number: sequence + u64::try_from(index).unwrap() + 1,
                        ..Default::default()
                    }
                    .into(),
                    ..Default::default()
                };
                let payload = frame.encode_to_bytes();
                response.push(0);
                response.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
                response.extend_from_slice(&payload);
            }
            let trailer: &[u8] = if store.fail_stream {
                br#"{"error":{"code":"unavailable","message":"test stream failure"}}"#
            } else {
                b"{}"
            };
            response.push(2);
            response.extend_from_slice(&u32::try_from(trailer.len()).unwrap().to_be_bytes());
            response.extend_from_slice(trailer);
            Ok(Response::builder()
                .header("content-type", "application/connect+proto")
                .body(Body::from(response))
                .unwrap())
        })
    }
}

fn storage<F: Family>(session: &SerializableReadSession) -> KvMerkleStorage<'_, F, Sha256Digest> {
    KvMerkleStorage {
        session,
        size: Position::new(100),
        _marker: PhantomData,
    }
}

#[tokio::test]
async fn batches_nodes_in_order_and_tracks_the_observed_sequence() {
    let positions = [0, 3, 8].map(Position::<mmr::Family>::new);
    let digests = [1, 2, 3].map(|byte| Sha256Digest::decode(&[byte; 32][..]).unwrap());
    let store = RecordingStore {
        rows: positions
            .iter()
            .zip(&digests)
            .map(|(position, digest)| {
                (
                    RecordingStore::key::<mmr::Family>(**position),
                    Bytes::copy_from_slice(digest.as_ref()),
                )
            })
            .collect(),
        ..Default::default()
    };
    let session = store.session();
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
            positions.map(|position| RecordingStore::key::<mmr::Family>(*position).to_vec())
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
}

#[tokio::test]
async fn empty_nodes_do_not_read_or_advance_the_session() {
    let store = RecordingStore::default();
    let session = store.session();
    assert!(storage::<mmr::Family>(&session)
        .get_nodes(&[])
        .await
        .unwrap()
        .is_empty());
    assert!(store.requests.lock().unwrap().is_empty());
    assert_eq!(session.fixed_sequence(), Some(17));
    assert_eq!(session.evaluated_sequence(), None);
}

#[tokio::test]
async fn rejects_positions_that_are_not_strictly_increasing() {
    let store = RecordingStore::default();
    let session = store.session();
    let storage = storage::<mmr::Family>(&session);
    for positions in [[3, 0], [3, 3]] {
        let positions = positions.map(Position::new);
        assert!(AssertUnwindSafe(storage.get_nodes(&positions))
            .catch_unwind()
            .await
            .is_err());
    }
    assert!(store.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn reports_the_first_missing_or_malformed_node_in_request_order() {
    let positions = [0, 3, 8].map(Position::<mmr::Family>::new);
    for malformed in [None, Some(0), Some(3)] {
        let store = RecordingStore {
            rows: malformed
                .map(|position| {
                    (
                        RecordingStore::key::<mmr::Family>(position),
                        Bytes::from_static(b"invalid digest"),
                    )
                })
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let session = store.session();
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
    }
}

#[tokio::test]
async fn preserves_fetch_errors_after_streamed_results() {
    let store = RecordingStore {
        fail_stream: true,
        ..Default::default()
    };
    let session = store.session();
    let error = storage::<mmr::Family>(&session)
        .get_nodes(&[Position::new(0)])
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        merkle::Error::DataCorrupted("exoware-qmdb node fetch failed")
    ));
    assert_eq!(store.requests.lock().unwrap().len(), 1);
}

async fn assert_range_proof<F: Family>() {
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let mut mem = Mem::<F, Sha256Digest>::new();
    let mut batch = mem.new_batch();
    for index in 0u64..32 {
        batch = batch.add(&hasher, &hasher.digest(&index.to_be_bytes()));
    }
    mem.apply_batch(&batch.merkleize(&mem, &hasher)).unwrap();
    let store = RecordingStore {
        rows: (0..*mem.size())
            .map(|position| {
                (
                    RecordingStore::key::<F>(position),
                    Bytes::copy_from_slice(mem.get_node(Position::new(position)).unwrap().as_ref()),
                )
            })
            .collect(),
        ..Default::default()
    };
    let session = store.session();
    let mut storage = storage::<F>(&session);
    storage.size = mem.size();
    let range = Location::new(7)..Location::new(9);
    let expected = merkle::verification::range_proof(&hasher, &mem, range.clone(), 0)
        .await
        .unwrap();
    let actual = merkle::verification::range_proof(&hasher, &storage, range, 0)
        .await
        .unwrap();
    assert_eq!(actual, expected);
    let requests = store.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].keys.len() > 1);
}

#[tokio::test]
async fn range_proofs_match_memory_backed_proofs_in_one_store_request() {
    assert_range_proof::<mmr::Family>().await;
    assert_range_proof::<mmb::Family>().await;
}
