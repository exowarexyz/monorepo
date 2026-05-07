use std::marker::PhantomData;

use commonware_codec::DecodeExt;
use commonware_cryptography::Digest;
use commonware_storage::merkle::{
    self, storage::Storage as MerkleStorage, Family, Graftable, Location, Position,
};
use exoware_sdk::{RangeMode, SerializableReadSession};

use crate::auth::encode_auth_node_key;
use crate::auth::AuthenticatedBackendNamespace;
use crate::codec::{
    encode_grafted_node_key, encode_node_key, grafting_height_for, ops_to_grafted_pos,
};

pub(crate) struct KvMerkleStorage<'a, F: Family, D: Digest> {
    pub(crate) session: &'a SerializableReadSession,
    pub(crate) size: Position<F>,
    pub(crate) _marker: PhantomData<D>,
}

impl<F: Family, D: Digest> MerkleStorage<F> for KvMerkleStorage<'_, F, D> {
    type Digest = D;

    async fn size(&self) -> Position<F> {
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
    pub(crate) size: Position<F>,
    pub(crate) _marker: PhantomData<D>,
}

impl<F: Graftable, D: Digest, const N: usize> MerkleStorage<F> for KvCurrentStorage<'_, F, D, N> {
    type Digest = D;

    async fn size(&self) -> Position<F> {
        self.size
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<D>, merkle::Error<F>> {
        if F::pos_to_height(position) < grafting_height_for::<N>() {
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

        let grafted_position = ops_to_grafted_pos::<F>(position, grafting_height_for::<N>());
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

pub(crate) struct AuthKvMerkleStorage<'a, F: Family, D: Digest> {
    pub(crate) session: &'a SerializableReadSession,
    pub(crate) namespace: AuthenticatedBackendNamespace,
    pub(crate) size: Position<F>,
    pub(crate) _marker: PhantomData<D>,
}

impl<F: Family, D: Digest> MerkleStorage<F> for AuthKvMerkleStorage<'_, F, D> {
    type Digest = D;

    async fn size(&self) -> Position<F> {
        self.size
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<D>, merkle::Error<F>> {
        let key = encode_auth_node_key(self.namespace, position);
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
        let digest = D::decode(bytes.as_ref())
            .map_err(|_| merkle::Error::DataCorrupted("exoware-qmdb node digest decode failed"))?;
        Ok(Some(digest))
    }
}
