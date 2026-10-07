use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use bytes::Bytes;
use commonware_codec::{Copying, DecodeExt, FixedSize};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::merkle::{
    self, hasher::Hasher as _, storage::Storage as MerkleStorage, Family, Graftable, Location,
    Position,
};
use commonware_storage::qmdb::current::grafting;
use exoware_sdk::{RangeMode, ReadSession};

use crate::adapter::codec::{chunk_index_for_location, encode_grafted_node_key, encode_node_key};

pub(crate) struct KvMerkleStorage<'a, F: Family, D: Digest> {
    pub(crate) session: &'a ReadSession,
    pub(crate) size: Position<F>,
    pub(crate) _marker: PhantomData<D>,
}

impl<F: Family, D: Digest> MerkleStorage<F> for KvMerkleStorage<'_, F, D> {
    type Digest = D;

    fn size(&self) -> Position<F> {
        self.size
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<D>, merkle::Error<F>> {
        let key = encode_node_key(position);
        let bytes = self.session.get(&key).await.map_err(|error| {
            crate::error::store_read_error(error, "exoware-qmdb node fetch failed")
        })?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        Self::decode_node(bytes.as_ref()).map(Some)
    }

    async fn get_nodes(&self, positions: &[Position<F>]) -> Result<Vec<D>, merkle::Error<F>> {
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        let nodes = self.load_nodes(positions).await?;
        positions
            .iter()
            .zip(nodes)
            .map(|(&position, node)| {
                let bytes = node.ok_or(merkle::Error::ElementPruned(position))?;
                Self::decode_node(bytes.as_ref())
            })
            .collect()
    }
}

impl<F: Family, D: Digest> KvMerkleStorage<'_, F, D> {
    fn decode_node(bytes: &[u8]) -> Result<D, merkle::Error<F>> {
        if bytes.len() != D::SIZE {
            return Err(merkle::Error::DataCorrupted(
                "exoware-qmdb node digest has invalid length",
            ));
        }
        D::decode(Copying(bytes))
            .map_err(|_| merkle::Error::DataCorrupted("exoware-qmdb node digest decode failed"))
    }

    async fn load_nodes(
        &self,
        positions: &[Position<F>],
    ) -> Result<Vec<Option<Bytes>>, merkle::Error<F>> {
        load_node_rows(self.session, positions).await
    }
}

/// Operation-tree node rows at `positions` in one batched read, `None` where a
/// row is absent. Decoding is left to callers so a later malformed node cannot
/// mask an earlier missing node.
async fn load_node_rows<F: Family>(
    session: &ReadSession,
    positions: &[Position<F>],
) -> Result<Vec<Option<Bytes>>, merkle::Error<F>> {
    if positions.is_empty() {
        return Ok(Vec::new());
    }
    let keys = positions
        .iter()
        .map(|&position| encode_node_key(position))
        .collect::<Vec<_>>();
    let refs = keys.iter().collect::<Vec<_>>();
    let rows = session
        .get_many(&refs, u32::try_from(keys.len()).unwrap_or(u32::MAX))
        .await
        .map_err(|error| crate::error::store_read_error(error, "exoware-qmdb node fetch failed"))?
        .collect()
        .await
        .map_err(|error| crate::error::store_read_error(error, "exoware-qmdb node fetch failed"))?;
    Ok(keys.iter().map(|key| rows.get(key).cloned()).collect())
}

/// Where a current proof reads the node at an operation-tree position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NodeSource<F: Family> {
    /// The operation-tree node: below the grafting height, or covering only
    /// pruned chunks, whose bits are all zero.
    Ops,
    /// The stored grafted node at this grafted-tree position, latest version at
    /// or below the watermark. An absent parent is rebuilt from its children.
    Grafted(Position<F>),
    /// Rebuilt from its children: the node spans the pruning boundary.
    Rebuilt,
}

/// The [`NodeSource`] of the node at `position` when `pruned_chunks` bitmap
/// chunks are pruned.
pub(crate) fn node_source<F: Graftable, const N: usize>(
    position: Position<F>,
    pruned_chunks: u64,
) -> Result<NodeSource<F>, merkle::Error<F>> {
    let grafting_height = grafting::height::<N>();
    if F::pos_to_height(position) < grafting_height {
        return Ok(NodeSource::Ops);
    }
    let grafted_position = grafting::ops_to_grafted_pos::<F>(position, grafting_height);
    let grafted_height = F::pos_to_height(grafted_position);
    let leftmost = F::leftmost_leaf(grafted_position, grafted_height);
    let covered_chunks = 1u64.checked_shl(grafted_height).ok_or_else(|| {
        merkle::Error::DataCorrupted("exoware-qmdb current grafted height overflow")
    })?;
    if (*leftmost).saturating_add(covered_chunks) <= pruned_chunks {
        return Ok(NodeSource::Ops);
    }
    // A parent can cover both discarded all-zero chunks and retained chunks with active bits
    // Activity changes before pruning can change its hash
    // Pruning itself preserves the root
    // Boundary deltas omit discarded chunks, so only wholly retained nodes reuse stored current hashes
    if *leftmost >= pruned_chunks {
        return Ok(NodeSource::Grafted(grafted_position));
    }
    Ok(NodeSource::Rebuilt)
}

/// Node rows a current proof reads, all read by [`load_proof_nodes`] before
/// the proof is built.
#[derive(Default)]
pub(crate) struct ProofNodes<F: Family> {
    /// Operation-tree nodes by position.
    ops: BTreeMap<Position<F>, Bytes>,
    /// Grafted nodes by grafted-tree position, `None` where the row is absent
    /// and the node is rebuilt from its children.
    grafted: BTreeMap<Position<F>, Option<Bytes>>,
}

/// Read every node a current proof needs at `watermark`, given the
/// operation-tree `positions` it requests. Each round reads operation-tree
/// nodes in one batch alongside one range read per grafted node. A node rebuilt
/// from its children adds them to the next round: before reading when it spans
/// the pruning boundary, after reading when its stored grafted row is absent.
pub(crate) async fn load_proof_nodes<F: Graftable, const N: usize>(
    session: &ReadSession,
    watermark: Location<F>,
    pruned_chunks: u64,
    positions: impl IntoIterator<Item = Position<F>>,
) -> Result<ProofNodes<F>, crate::QmdbError> {
    let merkle_error = crate::error::merkle_error::<F>;
    let mut nodes = ProofNodes::default();
    let mut pending = positions.into_iter().collect::<Vec<_>>();
    while !pending.is_empty() {
        let mut ops = BTreeSet::new();
        // Grafted position to the operation-tree position it stands for
        let mut grafted = BTreeMap::new();
        while let Some(position) = pending.pop() {
            match node_source::<F, N>(position, pruned_chunks).map_err(merkle_error)? {
                NodeSource::Ops if !nodes.ops.contains_key(&position) => {
                    ops.insert(position);
                }
                NodeSource::Grafted(grafted_position)
                    if !nodes.grafted.contains_key(&grafted_position) =>
                {
                    grafted.insert(grafted_position, position);
                }
                NodeSource::Rebuilt => pending.extend(children(position)),
                NodeSource::Ops | NodeSource::Grafted(_) => {}
            }
        }
        let ops = ops.into_iter().collect::<Vec<_>>();
        let (ops_rows, grafted_rows) = futures::try_join!(
            async { load_node_rows(session, &ops).await.map_err(merkle_error) },
            futures::future::try_join_all(grafted.keys().map(|&grafted_position| async move {
                Ok::<_, crate::QmdbError>(
                    load_grafted_node(session, watermark, grafted_position).await?,
                )
            })),
        )?;
        for (position, row) in ops.into_iter().zip(ops_rows) {
            let row = row.ok_or_else(|| merkle_error(merkle::Error::ElementPruned(position)))?;
            nodes.ops.insert(position, row);
        }
        for ((grafted_position, position), row) in grafted.into_iter().zip(grafted_rows) {
            // Grafted leaves require bitmap data and cannot be rebuilt from operation children
            if row.is_none() && F::pos_to_height(grafted_position) > 0 {
                pending.extend(children(position));
            }
            nodes.grafted.insert(grafted_position, row);
        }
    }
    Ok(nodes)
}

fn children<F: Family>(position: Position<F>) -> [Position<F>; 2] {
    let (left, right) = F::children(position, F::pos_to_height(position));
    [left, right]
}

/// The stored grafted node at `grafted_position`, latest version at or below
/// `watermark`.
async fn load_grafted_node<F: Family>(
    session: &ReadSession,
    watermark: Location<F>,
    grafted_position: Position<F>,
) -> Result<Option<Bytes>, exoware_sdk::ClientError> {
    let start = encode_grafted_node_key(grafted_position, Location::new(0));
    let end = encode_grafted_node_key(grafted_position, watermark);
    let rows = session
        .range_with_mode(&start, &end, 1, RangeMode::Reverse)
        .await?;
    Ok(rows.into_iter().next().map(|(_, bytes)| bytes))
}

/// A current proof's operation tree, served from the [`ProofNodes`] read for
/// it. A node that was not read is an error, never a Store read.
pub(crate) struct CurrentProofStorage<'a, F: Graftable, H: Hasher, const N: usize> {
    pub(crate) nodes: &'a ProofNodes<F>,
    pub(crate) pruned_chunks: u64,
    pub(crate) size: Position<F>,
    pub(crate) _marker: PhantomData<H>,
}

impl<F: Graftable, H: Hasher, const N: usize> MerkleStorage<F>
    for CurrentProofStorage<'_, F, H, N>
{
    type Digest = H::Digest;

    fn size(&self) -> Position<F> {
        self.size
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<H::Digest>, merkle::Error<F>> {
        self.node(position)
    }

    async fn get_nodes(
        &self,
        positions: &[Position<F>],
    ) -> Result<Vec<H::Digest>, merkle::Error<F>> {
        positions
            .iter()
            .map(|&position| {
                self.node(position)?
                    .ok_or(merkle::Error::ElementPruned(position))
            })
            .collect()
    }
}

impl<F: Graftable, H: Hasher, const N: usize> CurrentProofStorage<'_, F, H, N> {
    fn node(&self, position: Position<F>) -> Result<Option<H::Digest>, merkle::Error<F>> {
        let unread = merkle::Error::DataCorrupted("exoware-qmdb current proof node was not read");
        match node_source::<F, N>(position, self.pruned_chunks)? {
            NodeSource::Ops => self
                .nodes
                .ops
                .get(&position)
                .ok_or(unread)
                .and_then(|bytes| KvMerkleStorage::<F, H::Digest>::decode_node(bytes.as_ref()))
                .map(Some),
            NodeSource::Grafted(grafted_position) => {
                match self.nodes.grafted.get(&grafted_position).ok_or(unread)? {
                    Some(bytes) => {
                        if bytes.len() != H::Digest::SIZE {
                            return Err(merkle::Error::DataCorrupted(
                                "exoware-qmdb current grafted node has invalid length",
                            ));
                        }
                        H::Digest::decode(Copying(bytes.as_ref()))
                            .map(Some)
                            .map_err(|_| {
                                merkle::Error::DataCorrupted(
                                    "exoware-qmdb current grafted node decode failed",
                                )
                            })
                    }
                    None if F::pos_to_height(grafted_position) == 0 => Ok(None),
                    None => self.rebuild(position),
                }
            }
            NodeSource::Rebuilt => self.rebuild(position),
        }
    }

    /// Rebuild parents spanning the pruning boundary and absent delayed-merge
    /// parents from their children.
    fn rebuild(&self, position: Position<F>) -> Result<Option<H::Digest>, merkle::Error<F>> {
        let [left, right] = children(position);
        let Some(left) = self.node(left)? else {
            return Ok(None);
        };
        let Some(right) = self.node(right)? else {
            return Ok(None);
        };
        let hasher = commonware_storage::qmdb::hasher::<H>();
        Ok(Some(hasher.node_digest(position, &left, &right)))
    }
}

/// Indices of the [`BitmapTail`] chunks at a watermark.
pub(crate) struct TailIndices {
    pub(crate) pending: Option<u64>,
    pub(crate) last: Option<u64>,
}

impl TailIndices {
    pub(crate) fn at<F: Graftable, const N: usize>(
        watermark: Location<F>,
    ) -> Result<Self, crate::QmdbError> {
        let len = crate::adapter::codec::op_count_for_watermark(watermark)?.as_u64();
        let chunk_bits = crate::adapter::codec::bitmap_chunk_bits::<N>();
        let complete = len / chunk_bits;
        let graftable = grafting::graftable_chunks::<F>(len, grafting::height::<N>()).min(complete);
        Ok(Self {
            pending: (complete > graftable).then_some(graftable),
            last: (len % chunk_bits != 0).then(|| chunk_index_for_location::<F, N>(watermark)),
        })
    }
}

/// The bitmap chunks at a watermark that no grafted node covers, which every
/// current proof reads, cleared below the inactivity floor.
#[derive(Clone, Default)]
pub(crate) struct BitmapTail {
    /// The complete chunk not yet grafted, if any.
    pub(crate) pending: Option<Bytes>,
    /// The partial last chunk, when the length is not chunk-aligned.
    pub(crate) last: Option<Bytes>,
}

/// Decode a [`BitmapTail`] chunk.
pub(crate) fn tail_chunk<const N: usize>(bytes: &Bytes) -> Result<[u8; N], crate::QmdbError> {
    bytes.as_ref().try_into().map_err(|_| {
        crate::QmdbError::CorruptData("current bitmap tail chunk has invalid length".into())
    })
}

/// Bitmap metadata and the chunks consumed by one native current proof
pub(crate) struct ProofBitmap<const N: usize> {
    len: u64,
    complete_chunks: usize,
    last_chunk: usize,
    pub(crate) pruned_chunks: usize,
    chunks: std::collections::BTreeMap<usize, [u8; N]>,
}

impl<const N: usize> ProofBitmap<N> {
    /// Bitmap at `watermark` holding its `tail`, whose chunks must be present
    /// exactly when the watermark has them. A proof of one location adds its
    /// [`Self::chunk_to_prove`].
    pub(crate) fn new<F: Graftable>(
        watermark: Location<F>,
        pruned_chunks: u64,
        tail: &BitmapTail,
    ) -> Result<Self, crate::QmdbError> {
        let len = crate::adapter::codec::op_count_for_watermark(watermark)?.as_u64();
        let chunk_bits = crate::adapter::codec::bitmap_chunk_bits::<N>();
        let complete = len / chunk_bits;
        let graftable = grafting::graftable_chunks::<F>(len, grafting::height::<N>()).min(complete);
        if pruned_chunks > graftable || complete - graftable > 1 {
            return Err(crate::QmdbError::CorruptData(
                "invalid current bitmap window".into(),
            ));
        }
        let indices = TailIndices::at::<F, N>(watermark)?;
        if indices.pending.is_some() != tail.pending.is_some()
            || indices.last.is_some() != tail.last.is_some()
        {
            return Err(crate::QmdbError::CorruptData(
                "current bitmap tail does not match its watermark".into(),
            ));
        }
        let mut bitmap = Self {
            len,
            complete_chunks: chunk_slot(complete)?,
            last_chunk: chunk_slot(chunk_index_for_location::<F, N>(watermark))?,
            pruned_chunks: chunk_slot(pruned_chunks)?,
            chunks: std::collections::BTreeMap::new(),
        };
        for (index, chunk) in indices
            .pending
            .zip(tail.pending.as_ref())
            .into_iter()
            .chain(indices.last.zip(tail.last.as_ref()))
        {
            bitmap.insert(index, tail_chunk(chunk)?)?;
        }
        Ok(bitmap)
    }

    /// The chunk a proof of `location` reads that the bitmap lacks. Upstream
    /// rejects a location in a pruned chunk before reading it.
    pub(crate) fn chunk_to_prove<F: Graftable>(
        &self,
        location: Location<F>,
    ) -> Result<Option<u64>, crate::QmdbError> {
        if location.as_u64() >= self.len {
            return Err(crate::QmdbError::CorruptData(
                "current proof location exceeds watermark".into(),
            ));
        }
        let index = chunk_index_for_location::<F, N>(location);
        let slot = chunk_slot(index)?;
        Ok((slot >= self.pruned_chunks && !self.chunks.contains_key(&slot)).then_some(index))
    }

    pub(crate) fn insert(&mut self, index: u64, chunk: [u8; N]) -> Result<(), crate::QmdbError> {
        self.chunks.insert(chunk_slot(index)?, chunk);
        Ok(())
    }
}

fn chunk_slot(index: u64) -> Result<usize, crate::QmdbError> {
    usize::try_from(index).map_err(|_| {
        crate::QmdbError::CorruptData("current bitmap chunk index exceeds usize".into())
    })
}

impl<const N: usize> commonware_utils::bitmap::Readable<N> for ProofBitmap<N> {
    fn complete_chunks(&self) -> usize {
        self.complete_chunks
    }

    fn get_chunk(&self, chunk: usize) -> [u8; N] {
        *self
            .chunks
            .get(&chunk)
            .expect("current proof requested an unloaded bitmap chunk")
    }

    fn last_chunk(&self) -> ([u8; N], u64) {
        let bits = (self.len - 1) % crate::adapter::codec::bitmap_chunk_bits::<N>() + 1;
        (self.get_chunk(self.last_chunk), bits)
    }

    fn pruned_chunks(&self) -> usize {
        self.pruned_chunks
    }

    fn len(&self) -> u64 {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_storage::merkle::{mem::Mem, mmb, mmr, verification};
    use connectrpc::{ConnectError, ConnectRpcService, RequestContext, ServiceRequest};
    use exoware_sdk::{
        common::kv::v1::Entry,
        keys::Key,
        store::query::v1::{
            Detail, GetManyEntry, GetManyFrame, GetManyRequest, GetRequest, GetResponse,
            RangeFrame, RangeRequest, ReduceRequest, ReduceResponse, Service, ServiceServer,
        },
        PrefixedStoreClient, StoreClient, StoreKeyPrefix,
    };
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    use commonware_utils::bitmap::Readable as _;

    // N = 1 gives eight-bit chunks (grafting height 3). Each chunk's byte is its index.
    fn load<F: Graftable>(
        watermark: u64,
        pruned_chunks: u64,
        location: Option<u64>,
    ) -> Result<(ProofBitmap<1>, Vec<u64>), crate::QmdbError> {
        let watermark = Location::<F>::new(watermark);
        let indices = TailIndices::at::<F, 1>(watermark)?;
        let mut requested = indices
            .pending
            .into_iter()
            .chain(indices.last)
            .collect::<Vec<_>>();
        let chunk = |index: Option<u64>| index.map(|index| Bytes::from(vec![index as u8]));
        let tail = BitmapTail {
            pending: chunk(indices.pending),
            last: chunk(indices.last),
        };
        let mut bitmap = ProofBitmap::<1>::new(watermark, pruned_chunks, &tail)?;
        if let Some(location) = location {
            if let Some(index) = bitmap.chunk_to_prove(Location::<F>::new(location))? {
                bitmap.insert(index, [index as u8])?;
                requested.push(index);
            }
        }
        requested.sort();
        Ok((bitmap, requested))
    }

    #[test]
    fn test_loads_last_chunk_only_for_partial_lengths() {
        let (bitmap, requested) = load::<mmr::Family>(12, 0, None).unwrap();
        assert_eq!(requested, [1]);
        assert_eq!(bitmap.last_chunk(), ([1], 5));
        assert_eq!(bitmap.complete_chunks(), 1);

        // An aligned MMR bitmap has neither a partial nor a pending chunk
        let (bitmap, requested) = load::<mmr::Family>(15, 0, None).unwrap();
        assert!(requested.is_empty());
        assert_eq!(bitmap.complete_chunks(), 2);
        assert_eq!(bitmap.len(), 16);

        // Pruning every complete chunk of an aligned bitmap leaves nothing to read
        let (bitmap, requested) = load::<mmr::Family>(15, 2, None).unwrap();
        assert!(requested.is_empty());
        assert_eq!(bitmap.pruned_chunks(), 2);
    }

    #[test]
    fn test_loads_queried_chunk_and_skips_pruned_locations() {
        let (bitmap, requested) = load::<mmr::Family>(20, 0, Some(3)).unwrap();
        assert_eq!(requested, [0, 2]);
        assert_eq!(bitmap.get_chunk(0), [0]);
        assert_eq!(bitmap.get_chunk(2), [2]);

        // Upstream rejects a pruned location before reading its chunk
        let (bitmap, requested) = load::<mmr::Family>(20, 1, Some(3)).unwrap();
        assert_eq!(requested, [2]);
        assert_eq!(bitmap.pruned_chunks(), 1);

        // The queried chunk and the partial chunk coincide
        let (_, requested) = load::<mmr::Family>(20, 0, Some(19)).unwrap();
        assert_eq!(requested, [2]);
    }

    #[test]
    fn test_loads_pending_chunk_for_mmb() {
        // Chunk 0 of an MMB is graftable once 11 leaves exist, so 17 leaves leave chunk 1 pending
        let (bitmap, requested) = load::<mmb::Family>(16, 0, None).unwrap();
        assert_eq!(requested, [1, 2]);
        assert_eq!(bitmap.get_chunk(1), [1]);
        assert_eq!(bitmap.last_chunk(), ([2], 1));

        // An aligned MMB bitmap still needs its pending chunk
        let (bitmap, requested) = load::<mmb::Family>(15, 0, None).unwrap();
        assert_eq!(requested, [1]);
        assert_eq!(bitmap.get_chunk(1), [1]);

        // A queried location inside the pending chunk does not load it twice
        let (_, requested) = load::<mmb::Family>(16, 0, Some(8)).unwrap();
        assert_eq!(requested, [1, 2]);
    }

    #[test]
    fn test_rejects_a_tail_that_does_not_match_the_watermark() {
        // 17 MMB leaves have a pending chunk and a partial last chunk
        let watermark = Location::<mmb::Family>::new(16);
        let chunk = |byte: u8| Some(Bytes::from(vec![byte]));
        let tail = |pending, last| BitmapTail { pending, last };
        for wrong in [
            tail(None, chunk(2)),
            tail(chunk(1), None),
            tail(None, None),
            tail(chunk(1), Some(Bytes::from(vec![2, 2]))),
        ] {
            assert!(matches!(
                ProofBitmap::<1>::new(watermark, 0, &wrong),
                Err(crate::QmdbError::CorruptData(_))
            ));
        }
        assert!(ProofBitmap::<1>::new(watermark, 0, &tail(chunk(1), chunk(2))).is_ok());
    }

    #[test]
    fn test_readable_view_matches_commonware_prunable_bitmap() {
        use commonware_utils::bitmap::{Prunable, Readable};
        for (watermark, pruned) in [(12u64, 0usize), (15, 0), (20, 1), (23, 2)] {
            let mut prunable = Prunable::<1>::new_with_pruned_chunks(pruned).unwrap();
            while Readable::len(&prunable) <= watermark {
                prunable.push(false);
            }
            let (bitmap, _) = load::<mmr::Family>(watermark, pruned as u64, None).unwrap();
            assert_eq!(bitmap.len(), Readable::len(&prunable));
            assert_eq!(
                bitmap.complete_chunks(),
                Readable::complete_chunks(&prunable)
            );
            assert_eq!(bitmap.pruned_chunks(), Readable::pruned_chunks(&prunable));
            if !prunable.is_chunk_aligned() {
                assert_eq!(bitmap.last_chunk().1, Readable::last_chunk(&prunable).1);
            }
        }
    }

    #[test]
    fn test_rejects_invalid_windows() {
        assert!(load::<mmr::Family>(12, 2, None).is_err());
        assert!(load::<mmr::Family>(12, 0, Some(13)).is_err());
        assert!(load::<mmb::Family>(9, 1, None).is_err());
    }

    #[derive(Clone, Default)]
    struct NodeQueries {
        rows: BTreeMap<Key, Bytes>,
        calls: Arc<Mutex<Vec<(&'static str, usize)>>>,
        range_barrier: Option<Arc<tokio::sync::Barrier>>,
        requests: Arc<Mutex<Vec<GetManyRequest>>>,
        sequence: Option<u64>,
        fail_stream: bool,
    }

    #[allow(refining_impl_trait)]
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
            let sequence = self.sequence.unwrap_or(1);
            if let Some(required) = request.min_sequence_number {
                if sequence < required {
                    return Err(ConnectError::aborted(format!(
                        "snapshot sequence {sequence} is below requested {required}"
                    )));
                }
            }

            // Legal out-of-order frames require the adapter to recover requested slot order
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
                            sequence_number: sequence,
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
        ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<ReduceResponse>> {
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
        // The watchdog reports a stalled sequential reader, without measuring request latency
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            load_proof_nodes::<mmr::Family, 1>(&session, watermark, 0, positions.iter().copied()),
        )
        .await
        .expect("grafted reads must reach the barrier concurrently")
        .unwrap();
        let storage = CurrentProofStorage::<mmr::Family, Sha256, 1> {
            nodes: &read,
            pruned_chunks: 0,
            size: Position::new(31),
            _marker: PhantomData,
        };
        let nodes = storage.get_nodes(&positions).await.unwrap();
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

    #[tokio::test]
    async fn test_absent_grafted_parent_is_rebuilt_from_children_read_ahead() {
        // With one-byte chunks (grafting height 3), the 16-leaf MMR's root (30)
        // is a grafted parent over the grafted leaves 14 and 29.
        let watermark = Location::<mmr::Family>::new(15);
        let height = grafting::height::<1>();
        let child = |position: u64| {
            let position = Position::<mmr::Family>::new(position);
            let digest = Sha256::hash(&[&position.as_u64().to_be_bytes()]);
            (position, digest)
        };
        let (left, right) = (child(14), child(29));
        let queries = NodeQueries {
            rows: [left, right]
                .iter()
                .map(|&(position, digest)| {
                    (
                        encode_grafted_node_key(
                            grafting::ops_to_grafted_pos(position, height),
                            watermark,
                        ),
                        Bytes::copy_from_slice(digest.as_ref()),
                    )
                })
                .collect(),
            ..Default::default()
        };
        let calls = queries.calls.clone();
        let (client, server) = serve(queries).await;
        let session = client.create_session_with_sequence(1);
        let root = Position::<mmr::Family>::new(30);
        let read = load_proof_nodes::<mmr::Family, 1>(&session, watermark, 0, [root])
            .await
            .unwrap();
        // The absent parent's row, then both children in a second round
        assert_eq!(*calls.lock().unwrap(), [("range", 1); 3]);

        let storage = CurrentProofStorage::<mmr::Family, Sha256, 1> {
            nodes: &read,
            pruned_chunks: 0,
            size: Position::new(31),
            _marker: PhantomData,
        };
        let expected =
            commonware_storage::qmdb::hasher::<Sha256>().node_digest(root, &left.1, &right.1);
        assert_eq!(storage.get_nodes(&[root]).await.unwrap(), [expected]);
        assert_eq!(calls.lock().unwrap().len(), 3, "building reads nothing");
        server.abort();
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

        async fn session(&self) -> (ReadSession, tokio::task::JoinHandle<()>) {
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

    fn storage<F: Family>(session: &ReadSession) -> KvMerkleStorage<'_, F, Digest> {
        KvMerkleStorage {
            session,
            size: Position::new(100),
            _marker: PhantomData,
        }
    }

    #[tokio::test]
    async fn reported_snapshot_sequence_gates_following_reads() {
        let positions = [0, 3, 8].map(Position::<mmr::Family>::new);
        let digests = [1, 2, 3].map(|byte| Digest::decode(Copying(&[byte; 32][..])).unwrap());
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
        assert_eq!(session.evaluated_sequence(), Some(40));
        assert_eq!(session.min_sequence_number(), Some(40));
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
            Some(40)
        );
        assert_eq!(session.evaluated_sequence(), Some(40));
        server.abort();
    }

    #[tokio::test]
    async fn reports_the_first_missing_or_malformed_node_in_request_order() {
        let positions = [0, 3, 8].map(Position::<mmr::Family>::new);
        for malformed in [None, Some(0), Some(3)] {
            let store = NodeQueries {
                sequence: Some(17),
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
            sequence: Some(17),
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
}
