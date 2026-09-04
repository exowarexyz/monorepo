use std::marker::PhantomData;

use commonware_codec::DecodeExt;
use commonware_cryptography::Digest;
use commonware_storage::merkle::{
    self, storage::Storage as MerkleStorage, Family, Graftable, Location, Position,
};
use commonware_storage::qmdb::current::grafting;
use exoware_sdk::{RangeMode, SerializableReadSession};

use crate::codec::{encode_grafted_node_key, encode_node_key};

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
        let complete_chunks = index(complete)?;
        let mut required = std::collections::BTreeSet::new();
        if len % chunk_bits != 0 {
            required.insert(complete);
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
            required.insert(location.as_u64() / chunk_bits);
        }
        let mut chunks = std::collections::BTreeMap::new();
        for chunk in required.into_iter().filter(|chunk| *chunk >= pruned_chunks) {
            chunks.insert(index(chunk)?, load(chunk).await?);
        }
        Ok(Self {
            len,
            complete_chunks,
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
        if chunk < self.pruned_chunks {
            [0; N]
        } else {
            *self
                .chunks
                .get(&chunk)
                .expect("current proof requested an unloaded bitmap chunk")
        }
    }

    fn last_chunk(&self) -> ([u8; N], u64) {
        let bits = self.len % crate::codec::bitmap_chunk_bits::<N>();
        let (index, bits) = if bits == 0 {
            (
                self.complete_chunks - 1,
                crate::codec::bitmap_chunk_bits::<N>(),
            )
        } else {
            (self.complete_chunks, bits)
        };
        (self.get_chunk(index), bits)
    }

    fn pruned_chunks(&self) -> usize {
        self.pruned_chunks
    }
    fn len(&self) -> u64 {
        self.len
    }
}
