use std::marker::PhantomData;
use std::sync::{atomic::AtomicU64, Arc};

use commonware_codec::{Codec, Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::{
    mmr::{verification, Location, Position},
    qmdb::keyless::Operation as KeylessOperation,
};
use exoware_sdk_rs::StoreClient;

use crate::auth::AuthenticatedBackendNamespace;
use crate::auth::{
    append_auth_nodes_incrementally, build_auth_upload_rows, compute_auth_root,
    encode_auth_presence_key, encode_auth_watermark_key, load_auth_operation_at,
    load_auth_operation_bytes_range, load_auth_operation_range, read_latest_auth_watermark,
    require_auth_uploaded_boundary, require_published_auth_watermark,
};
use crate::codec::{ensure_encoded_value_size, mmr_size_for_watermark};
use crate::core::{retry_transient_post_ingest_query, wait_until_query_visible_sequence};
use crate::error::QmdbError;
use crate::proof::AuthenticatedOperationRangeProof;
use crate::storage::AuthKvMmrStorage;
use crate::UploadReceipt;

#[derive(Clone, Debug)]
pub struct KeylessClient<H: Hasher, V: Codec + Send + Sync> {
    client: StoreClient,
    value_cfg: V::Cfg,
    query_visible_sequence: Option<Arc<AtomicU64>>,
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
            query_visible_sequence: None,
            _marker: PhantomData,
        }
    }

    pub fn with_query_visible_sequence(mut self, seq: Arc<AtomicU64>) -> Self {
        self.query_visible_sequence = Some(seq);
        self
    }

    pub fn inner(&self) -> &StoreClient {
        &self.client
    }

    pub fn sequence_number(&self) -> u64 {
        self.client.sequence_number()
    }

    async fn sync_after_ingest(&self) -> Result<(), QmdbError> {
        let token = self.client.sequence_number();
        wait_until_query_visible_sequence(self.query_visible_sequence.as_ref(), token).await
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

    pub async fn upload_operations(
        &self,
        latest_location: Location,
        operations: &[KeylessOperation<V>],
    ) -> Result<UploadReceipt, QmdbError> {
        if operations.is_empty() {
            return Err(QmdbError::EmptyBatch);
        }
        let namespace = AuthenticatedBackendNamespace::Keyless;
        if self
            .client
            .get(&encode_auth_presence_key(namespace, latest_location))
            .await?
            .is_some()
        {
            return Err(QmdbError::DuplicateBatchWatermark { latest_location });
        }
        let encoded = operations
            .iter()
            .map(|operation| {
                let bytes = operation.encode().to_vec();
                ensure_encoded_value_size(bytes.len())?;
                Ok(bytes)
            })
            .collect::<Result<Vec<_>, QmdbError>>()?;
        let (_, rows) = build_auth_upload_rows(namespace, latest_location, &encoded)?;
        let refs = rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;

        Ok(UploadReceipt {
            latest_location,
            operation_count: Location::new(operations.len() as u64),
            keyed_operation_count: 0,
            writer_location_watermark: self.writer_location_watermark().await?,
            sequence_number: self.client.sequence_number(),
        })
    }

    pub async fn publish_writer_location_watermark(
        &self,
        location: Location,
    ) -> Result<Location, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Keyless;
        let session = self.client.create_session();
        let latest = read_latest_auth_watermark(&session, namespace).await?;
        if let Some(watermark) = latest {
            if watermark >= location {
                return Ok(watermark);
            }
        }
        require_auth_uploaded_boundary(&session, namespace, location).await?;
        let previous_ops_size = match latest {
            Some(previous) => mmr_size_for_watermark(previous)?,
            None => Position::new(0),
        };
        let delta_start = latest.map_or(Location::new(0), |watermark| watermark + 1);
        let end_exclusive = location
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        let encoded =
            load_auth_operation_bytes_range(&session, namespace, delta_start, end_exclusive)
                .await?;
        let mut rows = Vec::new();
        append_auth_nodes_incrementally::<H>(
            &session,
            namespace,
            previous_ops_size,
            &encoded,
            &mut rows,
        )
        .await?;
        rows.push((encode_auth_watermark_key(namespace, location), Vec::new()));
        let refs = rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;
        let visible = self.writer_location_watermark().await?;
        if visible < Some(location) {
            return Err(QmdbError::CorruptData(format!(
                "keyless watermark publish did not become query-visible: requested={location}, visible={visible:?}"
            )));
        }
        Ok(location)
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

    pub async fn operation_range_proof(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<AuthenticatedOperationRangeProof<H::Digest, KeylessOperation<V>>, QmdbError> {
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
        Ok(AuthenticatedOperationRangeProof {
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
        })
    }

    /// Open a stream of `AuthenticatedOperationRangeProof<KeylessOperation>`
    /// per uploaded batch. See `OrderedClient::stream_batches` for semantics.
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
        use crate::auth::{
            auth_payload_regex_for_namespace, decode_auth_operation_location,
            decode_auth_presence_location, decode_auth_watermark_location,
            AUTH_FAMILY_RESERVED_BITS, AUTH_OP_FAMILY_PREFIX, AUTH_PRESENCE_FAMILY_PREFIX,
            AUTH_WATERMARK_FAMILY_PREFIX,
        };
        use crate::stream::driver::{self as drv, BatchProofStream, Classify, Family};
        use exoware_sdk_rs::keys::{Key, KeyCodec};
        use futures::FutureExt;

        let namespace = AuthenticatedBackendNamespace::Keyless;
        let op_codec = KeyCodec::new(AUTH_FAMILY_RESERVED_BITS, AUTH_OP_FAMILY_PREFIX);
        let presence_codec = KeyCodec::new(AUTH_FAMILY_RESERVED_BITS, AUTH_PRESENCE_FAMILY_PREFIX);
        let watermark_codec = KeyCodec::new(AUTH_FAMILY_RESERVED_BITS, AUTH_WATERMARK_FAMILY_PREFIX);

        let classify: Classify = Arc::new(move |key: &Key, _value: &[u8]| {
            if op_codec.matches(key) {
                return decode_auth_operation_location(namespace, key)
                    .ok()
                    .map(|l| (Family::Op, l));
            }
            if presence_codec.matches(key) {
                return decode_auth_presence_location(namespace, key)
                    .ok()
                    .map(|l| (Family::Presence, l));
            }
            if watermark_codec.matches(key) {
                return decode_auth_watermark_location(namespace, key)
                    .ok()
                    .map(|l| (Family::Watermark, l));
            }
            None
        });

        let payload_regex = auth_payload_regex_for_namespace(namespace);
        let filter = drv::build_filter(
            AUTH_FAMILY_RESERVED_BITS,
            AUTH_OP_FAMILY_PREFIX,
            AUTH_PRESENCE_FAMILY_PREFIX,
            AUTH_WATERMARK_FAMILY_PREFIX,
            &payload_regex,
        );
        let sub = drv::open_subscription(&self.client, filter, since).await?;

        let build_proof: drv::BuildProof<
            AuthenticatedOperationRangeProof<H::Digest, KeylessOperation<V>>,
        > = Arc::new(
            move |watermark: Location, start: Location, count: u32| {
                let me = self.clone();
                async move { me.operation_range_proof(watermark, start, count).await }.boxed()
            },
        );

        Ok(KeylessBatchStream {
            inner: BatchProofStream::new(sub, classify, build_proof),
        })
    }
}

/// Async stream of authenticated keyless range proofs, one per batch.
pub struct KeylessBatchStream<H: Hasher, V: Codec + Clone + Send + Sync> {
    inner: crate::stream::driver::BatchProofStream<
        AuthenticatedOperationRangeProof<H::Digest, KeylessOperation<V>>,
    >,
}

impl<H, V> futures::Stream for KeylessBatchStream<H, V>
where
    H: Hasher,
    V: Codec + Clone + Send + Sync,
    KeylessOperation<V>: Encode,
    AuthenticatedOperationRangeProof<H::Digest, KeylessOperation<V>>: Send + 'static,
{
    type Item =
        Result<AuthenticatedOperationRangeProof<H::Digest, KeylessOperation<V>>, QmdbError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.inner).poll_next(cx)
    }
}
