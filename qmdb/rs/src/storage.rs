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

