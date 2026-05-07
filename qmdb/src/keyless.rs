use std::marker::PhantomData;

use commonware_codec::{Codec, Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Family, Location},
    qmdb::keyless::variable::Operation as KeylessOperation,
};
use exoware_sdk::{SerializableReadSession, StoreClient};

use crate::auth::AuthenticatedBackendNamespace;
use crate::auth::{
    compute_auth_root, load_auth_operation_at, load_auth_operation_bytes_range,
    read_latest_auth_watermark, require_published_auth_watermark,
};
use crate::codec::merkle_size_for_watermark;
use crate::connect::OperationKv;
use crate::core::retry_transient_post_ingest_query;
use crate::error::QmdbError;
use crate::proof::{OperationRangeCheckpoint, RawBatchMultiProof, VerifiedOperationRange};
use crate::storage::AuthKvMerkleStorage;

#[derive(Clone, Debug)]
pub struct KeylessClient<F: Family, H: Hasher, V: Codec + Send + Sync> {
    client: StoreClient,
    value_cfg: V::Cfg,
    _marker: PhantomData<(F, H)>,
}

impl<F, H, V> KeylessClient<F, H, V>
where
    F: Family,
    H: Hasher,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    KeylessOperation<F, V>: Encode + Decode<Cfg = V::Cfg> + Clone,
{
    pub fn new(url: &str, value_cfg: V::Cfg) -> Self {
        Self::from_client(StoreClient::new(url), value_cfg)
    }

    pub fn from_client(client: StoreClient, value_cfg: V::Cfg) -> Self {
        Self {
            client,
            value_cfg,
            _marker: PhantomData,
        }
    }

    pub(crate) fn store_client(&self) -> &StoreClient {
        &self.client
    }

    pub(crate) fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError>
    where
        V: AsRef<[u8]>,
    {
        let op = KeylessOperation::<F, V>::decode_cfg(bytes, &self.value_cfg).map_err(|e| {
            QmdbError::CorruptData(format!(
                "failed to decode keyless operation at location {location}: {e}"
            ))
        })?;
        let value = match &op {
            KeylessOperation::Append(value) => Some(value.as_ref().to_vec()),
            KeylessOperation::Commit(Some(value), _) => Some(value.as_ref().to_vec()),
            KeylessOperation::Commit(None, _) => None,
        };
        Ok(OperationKv { key: None, value })
    }

    pub async fn writer_location_watermark(&self) -> Result<Option<Location<F>>, QmdbError> {
        retry_transient_post_ingest_query(|| {
            let session = self.client.create_session();
            async move {
                read_latest_auth_watermark::<F>(&session, AuthenticatedBackendNamespace::Keyless)
                    .await
            }
        })
        .await
    }

    pub async fn root_at(&self, watermark: Location<F>) -> Result<H::Digest, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Keyless;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        compute_auth_root::<F, H>(&session, namespace, watermark).await
    }

    pub async fn get_at(
        &self,
        location: Location<F>,
        watermark: Location<F>,
    ) -> Result<Option<V>, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Keyless;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        let count = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        if location >= count {
            return Err(QmdbError::RangeStartOutOfBounds {
                start: location.as_u64(),
                count: count.as_u64(),
            });
        }
        let operation = load_auth_operation_at::<F, KeylessOperation<F, V>>(
            &session,
            namespace,
            location,
            &self.value_cfg,
        )
        .await?;
        Ok(operation.into_value())
    }

    pub async fn operation_range_checkpoint(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<OperationRangeCheckpoint<H::Digest, F>, QmdbError> {
        let session = self.client.create_session();
        self.operation_range_checkpoint_in_session(
            &session,
            watermark,
            start_location,
            max_locations,
        )
        .await
    }

    pub(crate) async fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> Result<RawBatchMultiProof<H::Digest, F>, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Keyless;
        let session = self
            .client
            .create_session_with_sequence(read_floor_sequence);
        require_published_auth_watermark(&session, namespace, watermark).await?;
        let storage = AuthKvMerkleStorage::<F, H::Digest> {
            session: &session,
            namespace,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData::<H::Digest>,
        };
        let root = compute_auth_root::<F, H>(&session, namespace, watermark).await?;
        crate::proof::build_batch_multi_proof::<F, H, _>(&storage, watermark, root, operations)
            .await
    }

    async fn operation_range_checkpoint_in_session(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<OperationRangeCheckpoint<H::Digest, F>, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Keyless;
        require_published_auth_watermark(session, namespace, watermark).await?;
        let end = crate::proof::resolve_range_bounds(watermark, start_location, max_locations)?;
        let storage = AuthKvMerkleStorage::<F, H::Digest> {
            session,
            namespace,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData::<H::Digest>,
        };
        let root = compute_auth_root::<F, H>(session, namespace, watermark).await?;
        let encoded_operations =
            load_auth_operation_bytes_range(session, namespace, start_location, end).await?;
        crate::proof::build_operation_range_checkpoint::<F, H, _>(
            &storage,
            watermark,
            start_location,
            end,
            root,
            encoded_operations,
        )
        .await
    }

    /// Verified contiguous range of operations.
    pub async fn operation_range_proof(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<VerifiedOperationRange<H::Digest, KeylessOperation<F, V>, F>, QmdbError> {
        let checkpoint = self
            .operation_range_checkpoint(watermark, start_location, max_locations)
            .await?;
        let operations = checkpoint
            .encoded_operations
            .iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = checkpoint.start_location + offset as u64;
                KeylessOperation::<F, V>::decode_cfg(bytes.as_slice(), &self.value_cfg).map_err(
                    |e| {
                        QmdbError::CorruptData(format!(
                            "failed to decode authenticated operation at location {location}: {e}"
                        ))
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VerifiedOperationRange {
            root: checkpoint.root,
            start_location: checkpoint.start_location,
            operations,
        })
    }
}
