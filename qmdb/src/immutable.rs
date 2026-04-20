use std::marker::PhantomData;
use std::sync::{atomic::AtomicU64, Arc};

use commonware_codec::{Codec, Decode, Encode, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_storage::{
    mmr::{verification, Location, Position},
    qmdb::immutable::Operation as ImmutableOperation,
};
use commonware_utils::Array;
use exoware_sdk_rs::StoreClient;

use crate::auth::AuthenticatedBackendNamespace;
use crate::auth::{
    append_auth_nodes_incrementally, build_auth_immutable_upload_rows, compute_auth_root,
    decode_auth_immutable_update_location, encode_auth_presence_key, encode_auth_watermark_key,
    load_auth_operation_at, load_auth_operation_range, load_latest_auth_immutable_update_row,
    read_latest_auth_watermark, require_auth_uploaded_boundary, require_published_auth_watermark,
};
use crate::codec::{mmr_size_for_watermark, UpdateRow};
use crate::core::{retry_transient_post_ingest_query, wait_until_query_visible_sequence};
use crate::error::QmdbError;
use crate::proof::AuthenticatedOperationRangeProof;
use crate::storage::AuthKvMmrStorage;
use crate::{UploadReceipt, VersionedValue};

#[derive(Clone, Debug)]
pub struct ImmutableClient<H: Hasher, K: AsRef<[u8]> + Codec, V: Codec + Send + Sync> {
    client: StoreClient,
    value_cfg: V::Cfg,
    update_row_cfg: (K::Cfg, V::Cfg),
    query_visible_sequence: Option<Arc<AtomicU64>>,
    _marker: PhantomData<(H, K)>,
}

impl<H, K, V> ImmutableClient<H, K, V>
where
    H: Hasher,
    K: Array + Codec + Clone + AsRef<[u8]>,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    K::Cfg: Clone,
    ImmutableOperation<K, V>: Encode + Decode<Cfg = V::Cfg> + Clone,
{
    pub fn new(url: &str, value_cfg: V::Cfg, update_row_cfg: (K::Cfg, V::Cfg)) -> Self {
        Self::from_client(StoreClient::new(url), value_cfg, update_row_cfg)
    }

    pub fn from_client(
        client: StoreClient,
        value_cfg: V::Cfg,
        update_row_cfg: (K::Cfg, V::Cfg),
    ) -> Self {
        Self {
            client,
            value_cfg,
            update_row_cfg,
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
                read_latest_auth_watermark(&session, AuthenticatedBackendNamespace::Immutable).await
            }
        })
        .await
    }

    pub async fn upload_operations(
        &self,
        latest_location: Location,
        operations: &[ImmutableOperation<K, V>],
    ) -> Result<UploadReceipt, QmdbError> {
        if operations.is_empty() {
            return Err(QmdbError::EmptyBatch);
        }
        let namespace = AuthenticatedBackendNamespace::Immutable;
        if self
            .client
            .query()
            .get(&encode_auth_presence_key(namespace, latest_location))
            .await?
            .is_some()
        {
            return Err(QmdbError::DuplicateBatchWatermark { latest_location });
        }
        let (keyed_operation_count, rows) =
            build_auth_immutable_upload_rows(latest_location, operations)?;
        let refs = rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.ingest().put(&refs).await?;
        self.sync_after_ingest().await?;
        Ok(UploadReceipt {
            latest_location,
            operation_count: Location::new(operations.len() as u64),
            keyed_operation_count,
            writer_location_watermark: self.writer_location_watermark().await?,
            sequence_number: self.client.sequence_number(),
        })
    }

    pub async fn publish_writer_location_watermark(
        &self,
        location: Location,
    ) -> Result<Location, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Immutable;
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
        let encoded = crate::auth::load_auth_operation_bytes_range(
            &session,
            namespace,
            delta_start,
            end_exclusive,
        )
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
        self.client.ingest().put(&refs).await?;
        self.sync_after_ingest().await?;
        let visible = self.writer_location_watermark().await?;
        if visible < Some(location) {
            return Err(QmdbError::CorruptData(format!(
                "immutable watermark publish did not become query-visible: requested={location}, visible={visible:?}"
            )));
        }
        Ok(location)
    }

    pub async fn root_at(&self, watermark: Location) -> Result<H::Digest, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Immutable;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        compute_auth_root::<H>(&session, namespace, watermark).await
    }

    pub async fn get_at(
        &self,
        key: &K,
        watermark: Location,
    ) -> Result<Option<VersionedValue<K, V>>, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Immutable;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        let Some((row_key, row_value)) =
            load_latest_auth_immutable_update_row(&session, watermark, key.as_ref()).await?
        else {
            return Ok(None);
        };
        let location = decode_auth_immutable_update_location(&row_key)?;
        let decoded =
            <UpdateRow<K, V> as CodecRead>::read_cfg(&mut row_value.as_ref(), &self.update_row_cfg)
                .map_err(|e| QmdbError::CorruptData(format!("update row decode: {e}")))?;
        if <K as AsRef<[u8]>>::as_ref(&decoded.key) != key.as_ref() {
            return Err(QmdbError::CorruptData(format!(
                "authenticated immutable update row key mismatch at location {location}"
            )));
        }
        let operation = load_auth_operation_at::<ImmutableOperation<K, V>>(
            &session,
            namespace,
            location,
            &self.value_cfg,
        )
        .await?;
        match operation {
            ImmutableOperation::Set(operation_key, value) if operation_key == *key => {
                Ok(Some(VersionedValue {
                    key: operation_key,
                    location,
                    value: Some(value),
                }))
            }
            ImmutableOperation::Set(_, _) => Err(QmdbError::CorruptData(format!(
                "authenticated immutable update row does not match operation key at location {location}"
            ))),
            ImmutableOperation::Commit(_) => Err(QmdbError::CorruptData(format!(
                "authenticated immutable update row points at commit location {location}"
            ))),
        }
    }

    pub async fn operation_range_proof(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<AuthenticatedOperationRangeProof<H::Digest, ImmutableOperation<K, V>>, QmdbError>
    {
        if max_locations == 0 {
            return Err(QmdbError::InvalidRangeLength);
        }
        let namespace = AuthenticatedBackendNamespace::Immutable;
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
            operations: load_auth_operation_range::<ImmutableOperation<K, V>>(
                &session,
                namespace,
                start_location,
                end,
                &self.value_cfg,
            )
            .await?,
        })
    }

    /// Open a stream of `AuthenticatedOperationRangeProof<ImmutableOperation>`
    /// per uploaded batch. See `OrderedClient::stream_batches` for semantics.
    ///
    /// The filter is restricted to the Immutable namespace tag so Immutable
    /// and Keyless clients can share a store without cross-talk.
    pub async fn stream_batches(
        self: Arc<Self>,
        since: Option<u64>,
    ) -> Result<ImmutableBatchStream<H, K, V>, QmdbError>
    where
        Self: 'static,
        H: Send + Sync + 'static,
        K: Send + Sync + 'static,
        V: Send + Sync + 'static,
        K::Cfg: Send + Sync,
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

        let namespace = AuthenticatedBackendNamespace::Immutable;
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
            AuthenticatedOperationRangeProof<H::Digest, ImmutableOperation<K, V>>,
        > = Arc::new(
            move |watermark: Location, start: Location, count: u32| {
                let me = self.clone();
                async move { me.operation_range_proof(watermark, start, count).await }.boxed()
            },
        );

        Ok(ImmutableBatchStream {
            inner: BatchProofStream::new(sub, classify, build_proof),
        })
    }
}

/// Async stream of authenticated immutable range proofs, one per batch.
pub struct ImmutableBatchStream<H: Hasher, K: Array + Codec, V: Codec + Clone + Send + Sync> {
    inner: crate::stream::driver::BatchProofStream<
        AuthenticatedOperationRangeProof<H::Digest, ImmutableOperation<K, V>>,
    >,
}

impl<H, K, V> futures::Stream for ImmutableBatchStream<H, K, V>
where
    H: Hasher,
    K: Array + Codec + Clone + AsRef<[u8]>,
    V: Codec + Clone + Send + Sync,
    ImmutableOperation<K, V>: Encode,
    AuthenticatedOperationRangeProof<H::Digest, ImmutableOperation<K, V>>: Send + 'static,
{
    type Item =
        Result<AuthenticatedOperationRangeProof<H::Digest, ImmutableOperation<K, V>>, QmdbError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.inner).poll_next(cx)
    }
}
