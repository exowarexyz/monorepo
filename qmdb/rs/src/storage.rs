use std::marker::PhantomData;

use bytes::Bytes;
use commonware_codec::{DecodeExt, FixedSize};
use commonware_cryptography::{Digest, Hasher};
use commonware_macros::boxed;
use commonware_storage::merkle::{
    self, hasher::Hasher as _, storage::Storage as MerkleStorage, Family, Graftable, Location,
    Position,
};
use commonware_storage::qmdb::current::grafting;
use exoware_sdk::{RangeMode, SerializableReadSession};

use crate::codec::{chunk_index_for_location, encode_grafted_node_key, encode_node_key};

#[cfg(test)]
#[path = "storage/read_tests.rs"]
mod read_tests;

pub(crate) struct KvMerkleStorage<'a, F: Family, D: Digest> {
    pub(crate) session: &'a SerializableReadSession,
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
        let bytes = self
            .session
            .get(&key)
            .await
            .map_err(|_| merkle::Error::DataCorrupted("exoware-qmdb node fetch failed"))?;
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
        D::decode(bytes)
            .map_err(|_| merkle::Error::DataCorrupted("exoware-qmdb node digest decode failed"))
    }

    async fn load_nodes(
        &self,
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
        let rows = self
            .session
            .get_many(&refs, u32::try_from(keys.len()).unwrap_or(u32::MAX))
            .await
            .map_err(|_| merkle::Error::DataCorrupted("exoware-qmdb node fetch failed"))?
            .collect()
            .await
            .map_err(|_| merkle::Error::DataCorrupted("exoware-qmdb node fetch failed"))?;

        // Decode in request order so a later malformed node cannot mask an earlier missing node.
        Ok(keys.iter().map(|key| rows.get(key).cloned()).collect())
    }
}

pub(crate) struct KvCurrentStorage<'a, F: Graftable, H: Hasher, const N: usize> {
    pub(crate) session: &'a SerializableReadSession,
    pub(crate) watermark: Location<F>,
    pub(crate) pruned_chunks: u64,
    pub(crate) size: Position<F>,
    pub(crate) _marker: PhantomData<H>,
}

impl<F: Graftable, H: Hasher, const N: usize> MerkleStorage<F> for KvCurrentStorage<'_, F, H, N> {
    type Digest = H::Digest;

    fn size(&self) -> Position<F> {
        self.size
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<H::Digest>, merkle::Error<F>> {
        self.get_node_inner(position).await
    }

    async fn get_nodes(
        &self,
        positions: &[Position<F>],
    ) -> Result<Vec<H::Digest>, merkle::Error<F>> {
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        let grafting_height = grafting::height::<N>();
        let (ops_positions, current_positions): (Vec<_>, Vec<_>) = positions
            .iter()
            .copied()
            .partition(|position| F::pos_to_height(*position) < grafting_height);
        let ops = KvMerkleStorage::<F, H::Digest> {
            session: self.session,
            size: self.size,
            _marker: PhantomData,
        };
        let (ops_nodes, current_nodes) = futures::try_join!(
            ops.load_nodes(&ops_positions),
            futures::future::try_join_all(
                current_positions
                    .iter()
                    .map(|&position| self.get_node_inner(position))
            ),
        )?;
        let mut ops_nodes = ops_nodes.into_iter().map(|bytes| {
            bytes
                .map(|bytes| KvMerkleStorage::<F, H::Digest>::decode_node(bytes.as_ref()))
                .transpose()
        });
        let mut current_nodes = current_nodes.into_iter().map(Ok);

        // Resolve absent nodes in request order after all independent reads complete
        positions
            .iter()
            .map(|&position| {
                let node = if F::pos_to_height(position) < grafting_height {
                    ops_nodes.next()
                } else {
                    current_nodes.next()
                }
                .expect("one result per requested position")?;
                node.ok_or(merkle::Error::ElementPruned(position))
            })
            .collect()
    }
}

impl<F: Graftable, H: Hasher, const N: usize> KvCurrentStorage<'_, F, H, N> {
    #[boxed]
    async fn get_node_inner(
        &self,
        position: Position<F>,
    ) -> Result<Option<H::Digest>, merkle::Error<F>> {
        let ops = KvMerkleStorage::<F, H::Digest> {
            session: self.session,
            size: self.size,
            _marker: PhantomData,
        };
        let grafting_height = grafting::height::<N>();
        let ops_height = F::pos_to_height(position);
        if ops_height < grafting_height {
            return ops.get_node(position).await;
        }

        let grafted_position = grafting::ops_to_grafted_pos::<F>(position, grafting_height);
        let grafted_height = F::pos_to_height(grafted_position);
        let leftmost = F::leftmost_leaf(grafted_position, grafted_height);
        let covered_chunks = 1u64.checked_shl(grafted_height).ok_or_else(|| {
            merkle::Error::DataCorrupted("exoware-qmdb current grafted height overflow")
        })?;
        if (*leftmost).saturating_add(covered_chunks) <= self.pruned_chunks {
            return ops.get_node(position).await;
        }

        // A parent can cover both discarded all-zero chunks and retained chunks with active bits
        // Activity changes before pruning can change its hash
        // Pruning itself preserves the root
        // Boundary deltas omit discarded chunks, so only wholly retained nodes reuse stored current hashes
        if *leftmost >= self.pruned_chunks {
            let start = encode_grafted_node_key(grafted_position, Location::new(0));
            let end = encode_grafted_node_key(grafted_position, self.watermark);
            let rows = self
                .session
                .range_with_mode(&start, &end, 1, RangeMode::Reverse)
                .await
                .map_err(|_| {
                    merkle::Error::DataCorrupted("exoware-qmdb current grafted node fetch failed")
                })?;
            if let Some((_, bytes)) = rows.into_iter().next() {
                if bytes.len() != H::Digest::SIZE {
                    return Err(merkle::Error::DataCorrupted(
                        "exoware-qmdb current grafted node has invalid length",
                    ));
                }
                return H::Digest::decode(bytes.as_ref()).map(Some).map_err(|_| {
                    merkle::Error::DataCorrupted("exoware-qmdb current grafted node decode failed")
                });
            }
        }

        // Grafted leaves require bitmap data and cannot be reconstructed from operation children
        if grafted_height == 0 {
            return Ok(None);
        }

        // Rebuild parents spanning the pruning boundary and absent delayed-merge parents from children
        let (left, right) = F::children(position, ops_height);
        let Some(left) = self.get_node_inner(left).await? else {
            return Ok(None);
        };
        let Some(right) = self.get_node_inner(right).await? else {
            return Ok(None);
        };
        let hasher = commonware_storage::qmdb::hasher::<H>();
        Ok(Some(hasher.node_digest(position, &left, &right)))
    }
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
    pub(crate) async fn load<F, Load, Fut>(
        watermark: Location<F>,
        pruned_chunks: u64,
        location: Option<Location<F>>,
        mut load: Load,
    ) -> Result<Self, crate::QmdbError>
    where
        F: Graftable,
        Load: FnMut(u64) -> Fut,
        Fut: std::future::Future<Output = Result<[u8; N], crate::QmdbError>>,
    {
        let len = crate::codec::op_count_for_watermark(watermark)?.as_u64();
        let chunk_bits = crate::codec::bitmap_chunk_bits::<N>();
        let complete = len / chunk_bits;
        let graftable = grafting::graftable_chunks::<F>(len, grafting::height::<N>()).min(complete);
        if pruned_chunks > graftable || complete - graftable > 1 {
            return Err(crate::QmdbError::CorruptData(
                "invalid current bitmap window".into(),
            ));
        }
        let index = |value| {
            usize::try_from(value).map_err(|_| {
                crate::QmdbError::CorruptData("current bitmap chunk index exceeds usize".into())
            })
        };
        // Current proof construction reads the partial trailing chunk (`last_chunk`, only when
        // the length is not chunk-aligned), the pending chunk (if any) and the queried chunk
        // (`get_chunk`). Upstream rejects a queried location in a pruned chunk before reading it.
        let last = chunk_index_for_location::<F, N>(watermark);
        let mut required = std::collections::BTreeSet::new();
        if len % chunk_bits != 0 {
            required.insert(last);
        }
        if complete > graftable {
            required.insert(graftable);
        }
        if let Some(location) = location {
            if location > watermark {
                return Err(crate::QmdbError::CorruptData(
                    "current proof location exceeds watermark".into(),
                ));
            }
            let chunk = chunk_index_for_location::<F, N>(location);
            if chunk >= pruned_chunks {
                required.insert(chunk);
            }
        }
        let required = required.into_iter().collect::<Vec<_>>();
        let loaded =
            futures::future::try_join_all(required.iter().map(|chunk| load(*chunk))).await?;
        let chunks = required
            .into_iter()
            .zip(loaded)
            .map(|(chunk, data)| Ok((index(chunk)?, data)))
            .collect::<Result<_, crate::QmdbError>>()?;
        Ok(Self {
            len,
            complete_chunks: index(complete)?,
            last_chunk: index(last)?,
            pruned_chunks: index(pruned_chunks)?,
            chunks,
        })
    }
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
        let bits = (self.len - 1) % crate::codec::bitmap_chunk_bits::<N>() + 1;
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
    use commonware_storage::merkle::{mmb, mmr};
    use commonware_utils::bitmap::Readable as _;

    // N = 1 gives eight-bit chunks (grafting height 3)
    fn load<F: Graftable>(
        watermark: u64,
        pruned_chunks: u64,
        location: Option<u64>,
    ) -> Result<(ProofBitmap<1>, Vec<u64>), crate::QmdbError> {
        let mut requested = Vec::new();
        let bitmap = futures::executor::block_on(ProofBitmap::<1>::load(
            Location::<F>::new(watermark),
            pruned_chunks,
            location.map(Location::<F>::new),
            |chunk| {
                requested.push(chunk);
                async move { Ok([chunk as u8]) }
            },
        ))?;
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
}

#[cfg(test)]
mod node_tests;
