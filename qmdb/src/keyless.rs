use std::marker::PhantomData;
use std::sync::Arc;

use commonware_codec::{Codec, Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::{
    mmr::{verification, Location},
    qmdb::keyless::Operation as KeylessOperation,
};
use exoware_sdk_rs::StoreClient;

use crate::auth::AuthenticatedBackendNamespace;
use crate::auth::{
    compute_auth_root, load_auth_operation_at, load_auth_operation_range,
    read_latest_auth_watermark, require_published_auth_watermark,
};
use crate::codec::mmr_size_for_watermark;
use crate::core::retry_transient_post_ingest_query;
use crate::error::QmdbError;
use crate::proof::{RangeProof, VerifiedOperationRange};
use crate::storage::AuthKvMmrStorage;

#[derive(Clone, Debug)]
pub struct KeylessClient<H: Hasher, V: Codec + Send + Sync> {
    client: StoreClient,
    value_cfg: V::Cfg,
    _marker: PhantomData<H>,
}

impl<H, V> KeylessClient<H, V>
where
    H: Hasher,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    KeylessOperation<V>: Encode + Decode<Cfg = V::Cfg> + Clone,
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

    pub fn sequence_number(&self) -> u64 {
        self.client.sequence_number()
    }

    pub async fn writer_location_watermark(&self) -> Result<Option<Location>, QmdbError> {
        retry_transient_post_ingest_query(|| {
            let session = self.client.create_session();
            async move {
                read_latest_auth_watermark(&session, AuthenticatedBackendNamespace::Keyless).await
            }
        })
        .await
    }

    pub async fn root_at(&self, watermark: Location) -> Result<H::Digest, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Keyless;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        compute_auth_root::<H>(&session, namespace, watermark).await
    }

    pub async fn get_at(
        &self,
        location: Location,
        watermark: Location,
    ) -> Result<Option<V>, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Keyless;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        let count = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        if location >= count {
            return Err(QmdbError::RangeStartOutOfBounds {
                start: location,
                count,
            });
        }
        let operation = load_auth_operation_at::<KeylessOperation<V>>(
            &session,
            namespace,
            location,
            &self.value_cfg,
        )
        .await?;
        Ok(operation.into_value())
    }

    /// Verified contiguous range of operations.
    pub async fn operation_range_proof(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<VerifiedOperationRange<H::Digest, KeylessOperation<V>>, QmdbError> {
        if max_locations == 0 {
            return Err(QmdbError::InvalidRangeLength);
        }
        let namespace = AuthenticatedBackendNamespace::Keyless;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        let count = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        if start_location >= count {
            return Err(QmdbError::RangeStartOutOfBounds {
                start: start_location,
                count,
            });
        }
        let end = start_location
            .saturating_add(max_locations as u64)
            .min(count);
        let storage = AuthKvMmrStorage {
            session: &session,
            namespace,
            mmr_size: mmr_size_for_watermark(watermark)?,
            _marker: PhantomData::<H::Digest>,
        };
        let proof = verification::range_proof(&storage, start_location..end)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
        let raw: RangeProof<H::Digest, KeylessOperation<V>> = RangeProof {
            watermark,
            root: compute_auth_root::<H>(&session, namespace, watermark).await?,
            start_location,
            proof,
            operations: load_auth_operation_range::<KeylessOperation<V>>(
                &session,
                namespace,
                start_location,
                end,
                &self.value_cfg,
            )
            .await?,
        };
        if !raw.verify::<H>() {
            return Err(QmdbError::CorruptData(
                "keyless range proof failed verification".to_string(),
            ));
        }
        Ok(VerifiedOperationRange {
            watermark: raw.watermark,
            root: raw.root,
            start_location: raw.start_location,
            operations: raw.operations,
        })
    }

    /// Open a stream of verified keyless operation ranges, one per uploaded
    /// batch. See [`OrderedClient::stream_batches`](crate::OrderedClient::stream_batches)
    /// for the full contract. The operation type is `KeylessOperation<V>`,
    /// and the subscription filter is restricted to the Keyless namespace tag.
    pub async fn stream_batches(
        self: Arc<Self>,
        since: Option<u64>,
    ) -> Result<KeylessBatchStream<H, V>, QmdbError>
    where
        Self: 'static,
        H: Send + Sync + 'static,
        V: Send + Sync + 'static,
        V::Cfg: Send + Sync,
    {
        use crate::stream::driver::{self as drv, BatchProofStream};
        use futures::FutureExt;

        let (classify, filter) =
            drv::authenticated_classify_and_filter(AuthenticatedBackendNamespace::Keyless);
        let sub = drv::open_subscription(&self.client, filter, since).await?;

        let build_proof: drv::BuildProof<VerifiedOperationRange<H::Digest, KeylessOperation<V>>> =
            Arc::new(move |watermark: Location, start: Location, count: u32| {
                let me = self.clone();
                async move { me.operation_range_proof(watermark, start, count).await }.boxed()
            });

        Ok(BatchProofStream::new(sub, classify, build_proof))
    }
}

/// Async stream of verified keyless operation ranges, one per batch.
pub type KeylessBatchStream<H, V> = crate::stream::driver::BatchProofStream<
    VerifiedOperationRange<<H as Hasher>::Digest, KeylessOperation<V>>,
>;
