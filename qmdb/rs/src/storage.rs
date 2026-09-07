use std::marker::PhantomData;

use commonware_codec::DecodeExt;
use commonware_cryptography::Digest;
use commonware_storage::merkle::{
    self, storage::Storage as MerkleStorage, Family, Graftable, Location, Position,
};
use commonware_storage::qmdb::current::grafting;
use exoware_sdk::{RangeMode, SerializableReadSession};

use crate::codec::{chunk_index_for_location, encode_grafted_node_key, encode_node_key};

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
        if bytes.len() != D::SIZE {
            return Err(merkle::Error::DataCorrupted(
                "exoware-qmdb node digest has invalid length",
            ));
        }
        D::decode(bytes.as_ref())
            .map(Some)
            .map_err(|_| merkle::Error::DataCorrupted("exoware-qmdb node digest decode failed"))
    }
}

pub(crate) struct KvCurrentStorage<'a, F: Graftable, D: Digest, const N: usize> {
    pub(crate) session: &'a SerializableReadSession,
    pub(crate) watermark: Location<F>,
    pub(crate) pruned_chunks: u64,
    pub(crate) size: Position<F>,
    pub(crate) _marker: PhantomData<D>,
}

impl<F: Graftable, D: Digest, const N: usize> MerkleStorage<F> for KvCurrentStorage<'_, F, D, N> {
    type Digest = D;

    fn size(&self) -> Position<F> {
        self.size
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<D>, merkle::Error<F>> {
        let grafting_height = grafting::height::<N>();
        if F::pos_to_height(position) < grafting_height {
            let key = encode_node_key(position);
            let bytes = self.session.get(&key).await.map_err(|_| {
                merkle::Error::DataCorrupted("exoware-qmdb current ops node fetch failed")
            })?;
            let Some(bytes) = bytes else {
                return Ok(None);
            };
            if bytes.len() != D::SIZE {
                return Err(merkle::Error::DataCorrupted(
                    "exoware-qmdb current ops node has invalid length",
                ));
            }
            return D::decode(bytes.as_ref()).map(Some).map_err(|_| {
                merkle::Error::DataCorrupted("exoware-qmdb current ops node decode failed")
            });
        }

        let grafted_position = grafting::ops_to_grafted_pos::<F>(position, grafting_height);
        let grafted_height = F::pos_to_height(grafted_position);
        let leftmost = F::leftmost_leaf(grafted_position, grafted_height);
        let covered_chunks = 1u64.checked_shl(grafted_height).ok_or_else(|| {
            merkle::Error::DataCorrupted("exoware-qmdb current grafted height overflow")
        })?;
        if (*leftmost).saturating_add(covered_chunks) <= self.pruned_chunks {
            let key = encode_node_key(position);
            let bytes = self.session.get(&key).await.map_err(|_| {
                merkle::Error::DataCorrupted("exoware-qmdb current pruned ops node fetch failed")
            })?;
            let Some(bytes) = bytes else {
                return Ok(None);
            };
            if bytes.len() != D::SIZE {
                return Err(merkle::Error::DataCorrupted(
                    "exoware-qmdb current pruned ops node has invalid length",
                ));
            }
            return D::decode(bytes.as_ref()).map(Some).map_err(|_| {
                merkle::Error::DataCorrupted("exoware-qmdb current pruned ops node decode failed")
            });
        }

        let start = encode_grafted_node_key(grafted_position, Location::new(0));
        let end = encode_grafted_node_key(grafted_position, self.watermark);
        let rows = self
            .session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await
            .map_err(|_| {
                merkle::Error::DataCorrupted("exoware-qmdb current grafted node fetch failed")
            })?;
        let Some((_, bytes)) = rows.into_iter().next() else {
            return Ok(None);
        };
        if bytes.len() != D::SIZE {
            return Err(merkle::Error::DataCorrupted(
                "exoware-qmdb current grafted node has invalid length",
            ));
        }
        D::decode(bytes.as_ref()).map(Some).map_err(|_| {
            merkle::Error::DataCorrupted("exoware-qmdb current grafted node decode failed")
        })
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
    fn loads_last_chunk_only_for_partial_lengths() {
        let (bitmap, requested) = load::<mmr::Family>(12, 0, None).unwrap();
        assert_eq!(requested, [1]);
        assert_eq!(bitmap.last_chunk(), ([1], 5));
        assert_eq!(bitmap.complete_chunks(), 1);

        // An aligned MMR bitmap has neither a partial nor a pending chunk
        let (bitmap, requested) = load::<mmr::Family>(15, 0, None).unwrap();
        assert!(requested.is_empty());
        assert_eq!(bitmap.complete_chunks(), 2);
        assert_eq!(bitmap.len(), 16);
    }

    #[test]
    fn loads_queried_chunk_and_skips_pruned_locations() {
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
    fn loads_pending_chunk_for_mmb() {
        // Chunk 0 of an MMB is graftable once 11 leaves exist, so 17 leaves leave chunk 1 pending
        let (bitmap, requested) = load::<mmb::Family>(16, 0, None).unwrap();
        assert_eq!(requested, [1, 2]);
        assert_eq!(bitmap.get_chunk(1), [1]);
        assert_eq!(bitmap.last_chunk(), ([2], 1));

        // An aligned MMB bitmap still needs its pending chunk
        let (bitmap, requested) = load::<mmb::Family>(15, 0, None).unwrap();
        assert_eq!(requested, [1]);
        assert_eq!(bitmap.get_chunk(1), [1]);
    }

    #[test]
    fn rejects_invalid_windows() {
        assert!(load::<mmr::Family>(12, 2, None).is_err());
        assert!(load::<mmr::Family>(12, 0, Some(13)).is_err());
        assert!(load::<mmb::Family>(9, 1, None).is_err());
    }
}
