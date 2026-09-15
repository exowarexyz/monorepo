use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    sync::Mutex,
};

use bytes::Bytes;
use commonware_codec::DecodeExt;
use commonware_cryptography::Digest;
use commonware_storage::merkle::{
    self, storage::Storage as MerkleStorage, Family, Location, Position,
};
use exoware_sdk::{ClientError, SerializableReadSession};

use crate::{
    codec::{encode_node_key, merkle_size_for_watermark, op_count_for_watermark},
    QmdbError,
};

pub(crate) fn range_positions<F: Family>(
    watermark: Location<F>,
    start: Location<F>,
    end: Location<F>,
) -> Result<Vec<Position<F>>, QmdbError> {
    let leaves = op_count_for_watermark(watermark)?;
    let size = merkle_size_for_watermark(watermark)?;
    if start >= end || end > leaves {
        return Err(QmdbError::CorruptData(
            "invalid Merkle prefetch range".into(),
        ));
    }

    // Canonical peak order describes leaf coverage even when node positions are not sorted.
    let mut positions = BTreeSet::new();
    let mut leaf_start = 0u64;
    for (position, height) in F::peaks(size) {
        let capacity = 1u64
            .checked_shl(height)
            .ok_or_else(|| QmdbError::CorruptData("Merkle peak height overflow".into()))?;
        let leaf_end = leaf_start
            .checked_add(capacity)
            .ok_or_else(|| QmdbError::CorruptData("Merkle peak leaf range overflow".into()))?;
        positions.insert(position);
        let mut pending = vec![(position, height, leaf_start, leaf_end)];
        while let Some((position, height, left, right)) = pending.pop() {
            if right <= *start || left >= *end {
                positions.insert(position);
                continue;
            }
            if *start <= left && right <= *end {
                continue;
            }
            if height == 0 {
                continue;
            }
            let middle = left + (right - left) / 2;
            let (left_child, right_child) = F::children(position, height);
            pending.push((right_child, height - 1, middle, right));
            pending.push((left_child, height - 1, left, middle));
        }
        leaf_start = leaf_end;
    }
    positions.extend(F::nodes_to_pin(start));
    Ok(positions.into_iter().collect())
}

pub(crate) struct PrefetchedMerkleStorage<'a, F: Family, D: Digest> {
    session: &'a SerializableReadSession,
    size: Position<F>,
    nodes: Mutex<BTreeMap<Position<F>, Option<Bytes>>>,
    error: Mutex<Option<ClientError>>,
    marker: PhantomData<D>,
}

impl<'a, F: Family, D: Digest> PrefetchedMerkleStorage<'a, F, D> {
    pub(crate) fn new(
        session: &'a SerializableReadSession,
        size: Position<F>,
        nodes: BTreeMap<Position<F>, Option<Bytes>>,
    ) -> Self {
        Self {
            session,
            size,
            nodes: Mutex::new(nodes),
            error: Mutex::new(None),
            marker: PhantomData,
        }
    }

    pub(crate) fn take_error(&self) -> Option<ClientError> {
        self.error.lock().unwrap().take()
    }

    pub(crate) fn node_rows(&self) -> Vec<(Position<F>, Bytes)> {
        self.nodes
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(&position, bytes)| bytes.clone().map(|bytes| (position, bytes)))
            .collect()
    }

    fn fetch_error(&self, error: ClientError) -> merkle::Error<F> {
        self.error.lock().unwrap().get_or_insert(error);
        merkle::Error::DataCorrupted("exoware-qmdb prefetched node fetch failed")
    }

    fn decode_node(bytes: &[u8]) -> Result<D, merkle::Error<F>> {
        if bytes.len() != D::SIZE {
            return Err(merkle::Error::DataCorrupted(
                "exoware-qmdb node digest has invalid length",
            ));
        }
        D::decode(bytes)
            .map_err(|_| merkle::Error::DataCorrupted("exoware-qmdb node digest decode failed"))
    }

    async fn load_nodes(&self, positions: &[Position<F>]) -> Result<(), merkle::Error<F>> {
        let missing = {
            let nodes = self.nodes.lock().unwrap();
            positions
                .iter()
                .copied()
                .filter(|position| !nodes.contains_key(position))
                .collect::<Vec<_>>()
        };
        if missing.is_empty() {
            return Ok(());
        }
        let keys = missing
            .iter()
            .copied()
            .map(encode_node_key)
            .collect::<Vec<_>>();
        let refs = keys.iter().collect::<Vec<_>>();
        let mut stream = self
            .session
            .get_many(&refs, u32::try_from(keys.len()).unwrap_or(u32::MAX))
            .await
            .map_err(|error| self.fetch_error(error))?;
        let mut rows = BTreeMap::new();
        while let Some(chunk) = stream
            .next_chunk()
            .await
            .map_err(|error| self.fetch_error(error))?
        {
            rows.extend(chunk.entries);
        }

        // Preserve absent rows and defer decoding so errors follow requested position order.
        let mut nodes = self.nodes.lock().unwrap();
        for (position, key) in missing.into_iter().zip(keys) {
            nodes
                .entry(position)
                .or_insert_with(|| rows.remove(&key).flatten());
        }
        Ok(())
    }
}

impl<F: Family, D: Digest> MerkleStorage<F> for PrefetchedMerkleStorage<'_, F, D> {
    type Digest = D;

    fn size(&self) -> Position<F> {
        self.size
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<D>, merkle::Error<F>> {
        self.load_nodes(&[position]).await?;
        self.nodes.lock().unwrap()[&position]
            .as_ref()
            .map(|bytes| Self::decode_node(bytes))
            .transpose()
    }

    async fn get_nodes(&self, positions: &[Position<F>]) -> Result<Vec<D>, merkle::Error<F>> {
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        self.load_nodes(positions).await?;
        let nodes = self.nodes.lock().unwrap();
        positions
            .iter()
            .map(|&position| {
                let bytes = nodes[&position]
                    .as_ref()
                    .ok_or(merkle::Error::ElementPruned(position))?;
                Self::decode_node(bytes)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_storage::merkle::{hasher::Standard, mem::Mem, mmb, mmr, verification, Bagging};
    use connectrpc::{ConnectError, ConnectRpcService, ErrorCode, RequestContext, ServiceRequest};
    use exoware_sdk::{
        keys::Key,
        store::query::v1::{
            Detail, GetManyEntry, GetManyFrame, GetManyRequest, GetRequest, GetResponse,
            RangeFrame, RangeRequest, ReduceRequest, ReduceResponse, Service, ServiceServer,
        },
        PrefixedStoreClient, StoreClient,
    };
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct NodeQueries {
        rows: BTreeMap<Key, Bytes>,
        requests: Arc<Mutex<Vec<GetManyRequest>>>,
        failure: Option<ErrorCode>,
    }

    #[allow(refining_impl_trait)]
    impl Service for NodeQueries {
        async fn get(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, GetRequest>,
        ) -> connectrpc::ServiceResult<GetResponse> {
            panic!("prefetch fallback must use GetMany")
        }

        async fn get_many(
            &self,
            _: RequestContext,
            request: ServiceRequest<'_, GetManyRequest>,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<GetManyFrame>> {
            self.requests
                .lock()
                .unwrap()
                .push(request.to_owned_message());
            let mut frames = request
                .keys
                .iter()
                .rev()
                .map(|key| {
                    Ok(GetManyFrame {
                        results: vec![GetManyEntry {
                            key: key.to_vec(),
                            value: self.rows.get(*key).cloned(),
                            ..Default::default()
                        }],
                        detail: Some(Detail {
                            sequence_number: 1,
                            ..Default::default()
                        })
                        .into(),
                        ..Default::default()
                    })
                })
                .collect::<Vec<_>>();
            if let Some(code) = self.failure {
                frames.push(Err(ConnectError::new(
                    code,
                    "prefetch structured stream failure",
                )));
            }
            Ok(connectrpc::Response::stream(futures::stream::iter(frames)))
        }

        async fn range(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, RangeRequest>,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<RangeFrame>> {
            panic!("prefetch fallback must use GetMany")
        }

        async fn reduce(
            &self,
            _: RequestContext,
            _: ServiceRequest<'_, ReduceRequest>,
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<ReduceResponse>> {
            panic!("prefetch fallback must use GetMany")
        }
    }

    async fn serve(queries: NodeQueries) -> (SerializableReadSession, tokio::task::JoinHandle<()>) {
        let service = ConnectRpcService::new(ServiceServer::new(queries));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, axum::Router::new().fallback_service(service))
                .await
                .unwrap();
        });
        let client = PrefixedStoreClient::empty(StoreClient::new(&url));
        (client.create_session_with_sequence(1), task)
    }

    async fn assert_range_plans<F: Family + PartialEq>() {
        let queries = NodeQueries::default();
        let requests = queries.requests.clone();
        let (session, server) = serve(queries).await;
        for bagging in [Bagging::ForwardFold, Bagging::BackwardFold] {
            let hasher = Standard::<Sha256>::new(bagging);
            for leaves in 1..=24 {
                let mut memory = Mem::<F, Digest>::new();
                let mut batch = memory.new_batch();
                for leaf in 0u64..leaves {
                    batch = batch.add(&hasher, &leaf.to_be_bytes());
                }
                memory
                    .apply_batch(&batch.merkleize(&memory, &hasher))
                    .unwrap();
                let peaks = F::peaks(memory.size())
                    .map(|(position, _)| position)
                    .collect::<Vec<_>>();
                for start in 0..leaves {
                    for end in start + 1..=leaves {
                        let plan = range_positions::<F>(
                            Location::new(leaves - 1),
                            Location::new(start),
                            Location::new(end),
                        )
                        .unwrap();
                        assert!(plan.is_sorted_by(|a, b| a < b));
                        assert!(peaks.iter().all(|peak| plan.contains(peak)));
                        assert!(
                            F::nodes_to_pin(Location::new(start)).all(|pin| plan.contains(&pin))
                        );
                        let nodes = plan
                            .iter()
                            .map(|&position| {
                                (
                                    position,
                                    Some(Bytes::copy_from_slice(
                                        memory.get_node(position).unwrap().as_ref(),
                                    )),
                                )
                            })
                            .collect();
                        let storage = PrefetchedMerkleStorage::<F, Digest>::new(
                            &session,
                            memory.size(),
                            nodes,
                        );
                        for inactive in 0..=peaks.len() {
                            let range = Location::new(start)..Location::new(end);
                            let actual = verification::historical_range_proof(
                                &hasher,
                                &storage,
                                Location::new(leaves),
                                range.clone(),
                                inactive,
                            )
                            .await
                            .unwrap();
                            let expected = memory.range_proof(&hasher, range, inactive).unwrap();
                            assert_eq!(
                                actual, expected,
                                "leaves={leaves}, range={start}..{end}, inactive={inactive}"
                            );
                        }
                    }
                }
            }
        }
        assert!(requests.lock().unwrap().is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn range_plans_match_memory_proofs_for_both_families() {
        assert_range_plans::<mmr::Family>().await;
        assert_range_plans::<mmb::Family>().await;
    }

    #[test]
    fn plan_keeps_all_peaks_and_handles_unsorted_canonical_mmb_order() {
        let size = Position::<mmb::Family>::try_from(Location::new(5)).unwrap();
        let peaks = mmb::Family::peaks(size)
            .map(|(position, _)| position)
            .collect::<Vec<_>>();
        assert!(!peaks.is_sorted());
        let plan =
            range_positions::<mmb::Family>(Location::new(4), Location::new(4), Location::new(5))
                .unwrap();
        assert!(plan.is_sorted_by(|a, b| a < b));
        assert!(peaks.iter().all(|peak| plan.contains(peak)));
    }

    #[test]
    fn plan_rejects_invalid_ranges_and_overflow() {
        for (watermark, start, end) in [(4, 2, 2), (4, 4, 6), (u64::MAX, 0, 1)] {
            assert!(range_positions::<mmr::Family>(
                Location::new(watermark),
                Location::new(start),
                Location::new(end)
            )
            .is_err());
        }
        assert!(range_positions::<mmb::Family>(
            mmb::Family::MAX_LEAVES,
            Location::new(0),
            Location::new(1)
        )
        .is_err());
    }

    #[tokio::test]
    async fn fallback_batches_only_unplanned_nodes_and_retains_absences() {
        let positions = [0, 3, 8, 9].map(Position::<mmr::Family>::new);
        let digests = [1, 2, 3].map(|byte| Digest::decode(&[byte; 32][..]).unwrap());
        let queries = NodeQueries {
            rows: positions[..3]
                .iter()
                .zip(&digests)
                .map(|(&position, digest)| {
                    (
                        encode_node_key(position),
                        Bytes::copy_from_slice(digest.as_ref()),
                    )
                })
                .collect(),
            ..Default::default()
        };
        let requests = queries.requests.clone();
        let (session, server) = serve(queries).await;
        let storage = PrefetchedMerkleStorage::<mmr::Family, Digest>::new(
            &session,
            Position::new(10),
            BTreeMap::from([(
                positions[0],
                Some(Bytes::copy_from_slice(digests[0].as_ref())),
            )]),
        );
        assert_eq!(storage.get_nodes(&positions[..3]).await.unwrap(), digests);
        assert_eq!(storage.get_nodes(&positions[..3]).await.unwrap(), digests);
        assert_eq!(requests.lock().unwrap().len(), 1);
        assert_eq!(
            requests.lock().unwrap()[0].keys,
            positions[1..3]
                .iter()
                .copied()
                .map(encode_node_key)
                .map(|key| key.to_vec())
                .collect::<Vec<_>>()
        );
        assert_eq!(storage.node_rows().len(), 3);
        assert!(storage.get_node(positions[3]).await.unwrap().is_none());
        assert!(storage.get_node(positions[3]).await.unwrap().is_none());
        assert_eq!(requests.lock().unwrap().len(), 2);
        assert_eq!(requests.lock().unwrap()[1].batch_size, 1);

        let absent = PrefetchedMerkleStorage::<mmr::Family, Digest>::new(
            &session,
            Position::new(10),
            BTreeMap::from([(positions[0], None)]),
        );
        assert!(absent.get_node(positions[0]).await.unwrap().is_none());
        assert!(
            matches!(absent.get_nodes(&positions[..1]).await, Err(merkle::Error::ElementPruned(position)) if position == positions[0])
        );
        assert!(absent.node_rows().is_empty());
        assert_eq!(requests.lock().unwrap().len(), 2);
        assert!(absent.get_nodes(&[]).await.unwrap().is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn fallback_defers_decode_errors_until_requested_order_is_known() {
        let positions = [0, 3].map(Position::<mmr::Family>::new);
        for malformed in positions {
            let queries = NodeQueries {
                rows: BTreeMap::from([(
                    encode_node_key(malformed),
                    Bytes::from_static(b"invalid"),
                )]),
                ..Default::default()
            };
            let (session, server) = serve(queries).await;
            let storage = PrefetchedMerkleStorage::<mmr::Family, Digest>::new(
                &session,
                Position::new(10),
                BTreeMap::new(),
            );
            let error = storage.get_nodes(&positions).await.unwrap_err();
            if malformed == positions[0] {
                assert!(matches!(
                    error,
                    merkle::Error::DataCorrupted("exoware-qmdb node digest has invalid length")
                ));
            } else {
                assert!(
                    matches!(error, merkle::Error::ElementPruned(position) if position == positions[0])
                );
            }
            assert!(storage.take_error().is_none());
            server.abort();
        }
    }

    #[tokio::test]
    async fn fallback_preserves_structured_stream_failures() {
        for code in [
            ErrorCode::Aborted,
            ErrorCode::Unavailable,
            ErrorCode::Internal,
        ] {
            let (session, server) = serve(NodeQueries {
                failure: Some(code),
                ..Default::default()
            })
            .await;
            let storage = PrefetchedMerkleStorage::<mmr::Family, Digest>::new(
                &session,
                Position::new(10),
                BTreeMap::new(),
            );
            assert!(matches!(
                storage.get_nodes(&[Position::new(0)]).await,
                Err(merkle::Error::DataCorrupted(
                    "exoware-qmdb prefetched node fetch failed"
                ))
            ));
            let error = storage.take_error().unwrap();
            assert_eq!(error.rpc_code(), Some(code));
            assert!(error
                .to_string()
                .contains("prefetch structured stream failure"));
            assert!(storage.take_error().is_none());
            assert!(storage.node_rows().is_empty());
            server.abort();
        }
    }

    #[tokio::test]
    #[should_panic(expected = "positions must be strictly increasing")]
    async fn requires_strictly_increasing_positions() {
        let client = PrefixedStoreClient::empty(StoreClient::new("http://127.0.0.1:1"));
        let session = client.create_session_with_sequence(1);
        let storage = PrefetchedMerkleStorage::<mmr::Family, Digest>::new(
            &session,
            Position::new(10),
            BTreeMap::new(),
        );
        let _ = storage
            .get_nodes(&[Position::new(3), Position::new(0)])
            .await;
    }
}
