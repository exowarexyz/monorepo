use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::sync::{atomic::AtomicU64, Arc};

use commonware_codec::{Codec, Decode, Encode, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_storage::{
    mmr::{verification, Location, Position},
    qmdb::{
        any::ordered::variable::Operation as QmdbOperation,
        current::{
            ordered::db::KeyValueProof as CurrentKeyValueProof,
            proof::{OperationProof as CurrentOperationProof, RangeProof as CurrentRangeProof},
        },
        operation::Key as QmdbKey,
    },
};
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::{RangeMode, SerializableReadSession, StoreClient};

use crate::codec::{
    bitmap_chunk_bits, chunk_index_for_location, decode_digest, decode_update_location,
    encode_chunk_key, encode_current_meta_key, encode_presence_key, encode_update_key,
    ensure_encoded_value_size, mmr_size_for_watermark, UpdateRow, NO_PARTIAL_CHUNK,
};
use crate::core::{HistoricalOpsClientCore, PreparedCurrentBoundaryUpload, PreparedUpload};
use crate::error::QmdbError;
use crate::proof::{
    CurrentOperationRangeProofResult, KeyValueProofResult, MultiProofResult, OperationRangeProof,
    VariantOperationRangeProof, VariantRoot,
};
use crate::storage::{KvCurrentStorage, KvMmrStorage};
use crate::{CurrentBoundaryState, QmdbVariant, UploadReceipt, VersionedValue};

#[derive(Clone)]
pub struct OrderedClient<
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
> {
    client: StoreClient,
    op_cfg: <QmdbOperation<K, V> as commonware_codec::Read>::Cfg,
    update_row_cfg: (K::Cfg, V::Cfg),
    query_visible_sequence: Option<Arc<AtomicU64>>,
    _marker: PhantomData<(H, K)>,
}

impl<H: Hasher, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, const N: usize> std::fmt::Debug
    for OrderedClient<H, K, V, N>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderedClient").finish_non_exhaustive()
    }
}

impl<H, K, V, const N: usize> OrderedClient<H, K, V, N>
where
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    QmdbOperation<K, V>: Encode + Decode,
{
    fn core(&self) -> HistoricalOpsClientCore<'_, H::Digest, K, V> {
        HistoricalOpsClientCore {
            client: &self.client,
            query_visible_sequence: self.query_visible_sequence.as_ref(),
            update_row_cfg: self.update_row_cfg.clone(),
            _marker: PhantomData,
        }
    }

    pub fn new(
        url: &str,
        op_cfg: <QmdbOperation<K, V> as commonware_codec::Read>::Cfg,
        update_row_cfg: (K::Cfg, V::Cfg),
    ) -> Self {
        Self::from_client(StoreClient::new(url), op_cfg, update_row_cfg)
    }

    pub fn from_client(
        client: StoreClient,
        op_cfg: <QmdbOperation<K, V> as commonware_codec::Read>::Cfg,
        update_row_cfg: (K::Cfg, V::Cfg),
    ) -> Self {
        Self {
            client,
            op_cfg,
            update_row_cfg,
            query_visible_sequence: None,
            _marker: PhantomData,
        }
    }

    pub fn with_query_visible_sequence(mut self, seq: Arc<AtomicU64>) -> Self {
        self.query_visible_sequence = Some(seq);
        self
    }

    pub(crate) async fn sync_after_ingest(&self) -> Result<(), QmdbError> {
        self.core().sync_after_ingest().await
    }

    pub fn inner(&self) -> &StoreClient {
        &self.client
    }

    pub fn sequence_number(&self) -> u64 {
        self.client.sequence_number()
    }

    pub async fn writer_location_watermark(&self) -> Result<Option<Location>, QmdbError> {
        self.core().writer_location_watermark().await
    }

    pub async fn publish_writer_location_watermark(
        &self,
        location: Location,
    ) -> Result<Location, QmdbError> {
        let session = self.client.create_session();
        let latest_watermark = self.core().read_latest_watermark(&session).await?;
        if let Some(watermark) = latest_watermark {
            if watermark >= location {
                return Ok(watermark);
            }
        }
        self.core()
            .require_batch_boundary(&session, location)
            .await?;
        self.require_current_boundary_state(&session, location)
            .await?;
        let previous_watermark = latest_watermark;
        let previous_ops_size = match previous_watermark {
            Some(previous) => mmr_size_for_watermark(previous)?,
            None => Position::new(0),
        };
        let delta_start_location = previous_watermark.map_or(Location::new(0), |w| w + 1);
        let end_location_exclusive = location
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        let delta_operations = self
            .load_operation_range(&session, delta_start_location, end_location_exclusive)
            .await?;
        let mut rows = Vec::<(Key, Vec<u8>)>::new();
        self.append_ops_nodes_incrementally(
            &session,
            previous_ops_size,
            &delta_operations,
            &mut rows,
        )
        .await?;
        rows.push((crate::codec::encode_watermark_key(location), Vec::new()));
        let refs = rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;
        let visible = self.writer_location_watermark().await?;
        if visible < Some(location) {
            return Err(QmdbError::CorruptData(format!(
                "ordered watermark publish did not become query-visible: requested={location}, visible={visible:?}"
            )));
        }
        Ok(location)
    }

    pub async fn upload_operations(
        &self,
        latest_location: Location,
        operations: &[QmdbOperation<K, V>],
    ) -> Result<UploadReceipt, QmdbError> {
        if operations.is_empty() {
            return Err(QmdbError::EmptyBatch);
        }
        if self
            .client
            .get(&encode_presence_key(latest_location))
            .await?
            .is_some()
        {
            return Err(QmdbError::DuplicateBatchWatermark { latest_location });
        }

        let prepared = PreparedUpload::build(latest_location, operations)?;
        let refs = prepared
            .rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;

        let writer_location_watermark = self.writer_location_watermark().await?;
        Ok(UploadReceipt {
            latest_location,
            operation_count: Location::from(prepared.operation_count as u64),
            keyed_operation_count: prepared.keyed_operation_count,
            writer_location_watermark,
            sequence_number: self.client.sequence_number(),
        })
    }

    pub async fn upload_operations_with_current_boundary(
        &self,
        latest_location: Location,
        operations: &[QmdbOperation<K, V>],
        current_boundary: &CurrentBoundaryState<H::Digest, N>,
    ) -> Result<UploadReceipt, QmdbError> {
        if operations.is_empty() {
            return Err(QmdbError::EmptyBatch);
        }
        if self
            .client
            .get(&encode_presence_key(latest_location))
            .await?
            .is_some()
        {
            return Err(QmdbError::DuplicateBatchWatermark { latest_location });
        }

        let prepared_ops = PreparedUpload::build(latest_location, operations)?;
        let prepared_current =
            PreparedCurrentBoundaryUpload::build(latest_location, current_boundary)?;
        let refs = prepared_ops
            .rows
            .iter()
            .chain(prepared_current.rows.iter())
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;

        let writer_location_watermark = self.writer_location_watermark().await?;
        Ok(UploadReceipt {
            latest_location,
            operation_count: Location::from(prepared_ops.operation_count as u64),
            keyed_operation_count: prepared_ops.keyed_operation_count,
            writer_location_watermark,
            sequence_number: self.client.sequence_number(),
        })
    }

    pub async fn upload_current_boundary_state(
        &self,
        latest_location: Location,
        current_boundary: &CurrentBoundaryState<H::Digest, N>,
    ) -> Result<(), QmdbError> {
        let prepared = PreparedCurrentBoundaryUpload::build(latest_location, current_boundary)?;
        let refs = prepared
            .rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;
        Ok(())
    }

    pub async fn root_at(&self, watermark: Location) -> Result<H::Digest, QmdbError> {
        Ok(self
            .root_for_variant(watermark, QmdbVariant::Any)
            .await?
            .root)
    }

    pub async fn current_root_at(&self, watermark: Location) -> Result<H::Digest, QmdbError> {
        Ok(self
            .root_for_variant(watermark, QmdbVariant::Current)
            .await?
            .root)
    }

    pub async fn root_for_variant(
        &self,
        watermark: Location,
        variant: QmdbVariant,
    ) -> Result<VariantRoot<H::Digest>, QmdbError> {
        let session = self.client.create_session();
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        let root = match variant {
            QmdbVariant::Any => self.compute_ops_root(&session, watermark).await?,
            QmdbVariant::Current => {
                self.core()
                    .require_batch_boundary(&session, watermark)
                    .await?;
                self.load_current_boundary_root(&session, watermark).await?
            }
        };
        Ok(VariantRoot {
            watermark,
            variant,
            root,
        })
    }

    pub async fn query_many_at<Q: AsRef<[u8]>>(
        &self,
        keys: &[Q],
        max_location: Location,
    ) -> Result<Vec<Option<VersionedValue<K, V>>>, QmdbError> {
        self.core().query_many_at(keys, max_location).await
    }

    pub async fn multi_proof_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location,
        keys: &[Q],
    ) -> Result<MultiProofResult<H::Digest, K, V>, QmdbError> {
        if keys.is_empty() {
            return Err(QmdbError::EmptyProofRequest);
        }

        let session = self.client.create_session();
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        let storage = KvMmrStorage::<H::Digest> {
            session: &session,
            mmr_size: mmr_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        let root = self.compute_ops_root(&session, watermark).await?;

        let mut seen = BTreeSet::<Vec<u8>>::new();
        let mut locations = Vec::<Location>::with_capacity(keys.len());
        let mut operations = Vec::<(Location, QmdbOperation<K, V>)>::with_capacity(keys.len());
        for key in keys {
            let key_bytes = key.as_ref().to_vec();
            if !seen.insert(key_bytes.clone()) {
                return Err(QmdbError::DuplicateRequestedKey { key: key_bytes });
            }
            let start = encode_update_key(key.as_ref(), Location::new(0))?;
            let end = encode_update_key(key.as_ref(), watermark)?;
            let rows = session
                .range_with_mode(&start, &end, 1, RangeMode::Reverse)
                .await?;
            let Some((row_key, row_value)) = rows.into_iter().next() else {
                return Err(QmdbError::ProofKeyNotFound {
                    watermark,
                    key: key.as_ref().to_vec(),
                });
            };
            let global_loc = decode_update_location(&row_key)?;
            let decoded = <UpdateRow<K, V> as CodecRead>::read_cfg(
                &mut row_value.as_ref(),
                &self.update_row_cfg,
            )
            .map_err(|e| QmdbError::CorruptData(format!("update row decode: {e}")))?;
            if <K as AsRef<[u8]>>::as_ref(&decoded.key) != key.as_ref() {
                return Err(QmdbError::ProofKeyNotFound {
                    watermark,
                    key: key.as_ref().to_vec(),
                });
            }
            let operation = self.load_operation_at(&session, global_loc).await?;
            locations.push(global_loc);
            operations.push((global_loc, operation));
        }
        operations.sort_by_key(|(loc, _)| *loc);
        locations.sort();

        let proof = verification::multi_proof(&storage, &locations)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
        Ok(MultiProofResult {
            watermark,
            root,
            proof,
            operations,
        })
    }

    pub async fn operation_range_proof(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<OperationRangeProof<H::Digest, K, V>, QmdbError> {
        match self
            .operation_range_proof_for_variant(
                watermark,
                QmdbVariant::Any,
                start_location,
                max_locations,
            )
            .await?
        {
            VariantOperationRangeProof::Any(proof) => Ok(proof),
            VariantOperationRangeProof::Current(_) => Err(QmdbError::CorruptData(
                "unexpected current proof returned for any variant request".to_string(),
            )),
        }
    }

    /// Open a stream of `OperationRangeProof` per uploaded batch.
    ///
    /// The returned stream yields one proof per batch whose presence marker
    /// AND watermark have both landed in the store. `since = None` starts live
    /// from the next batch; `Some(N)` replays retained batches with
    /// sequence_number >= N before transitioning to live. Caller must verify
    /// each emitted proof with `verify::<H>()` before trusting its contents.
    ///
    /// On transport errors (slow-client eviction, connection closed) the
    /// stream yields `Err(QmdbError::Stream(..))`; resubscribe with
    /// `since = last_seen_batch_seq + 1` to replay the gap via the batch log.
    pub async fn stream_batches(
        self: std::sync::Arc<Self>,
        since: Option<u64>,
    ) -> Result<OrderedBatchStream<H, K, V, N>, QmdbError>
    where
        Self: 'static,
        H: Send + Sync + 'static,
        K: Send + Sync + 'static,
        V: Send + Sync + 'static,
        K::Cfg: Send + Sync,
        V::Cfg: Send + Sync,
    {
        use crate::codec::{decode_operation_location_key, decode_presence_location};
        use crate::codec::{OP_FAMILY, PRESENCE_FAMILY, RESERVED_BITS, WATERMARK_FAMILY};
        use crate::stream::driver::{
            self as drv, BatchProofStream, Classify, Family,
        };
        use commonware_storage::mmr::Location;
        use exoware_sdk_rs::keys::{Key, KeyCodec};
        use futures::FutureExt;
        use std::sync::Arc;

        let op_codec = KeyCodec::new(RESERVED_BITS, OP_FAMILY);
        let presence_codec = KeyCodec::new(RESERVED_BITS, PRESENCE_FAMILY);
        let watermark_codec = KeyCodec::new(RESERVED_BITS, WATERMARK_FAMILY);

        let classify: Classify = Arc::new(move |key: &Key, _value: &[u8]| {
            if op_codec.matches(key) {
                return decode_operation_location_key(key)
                    .ok()
                    .map(|l| (Family::Op, l));
            }
            if presence_codec.matches(key) {
                return decode_presence_location(key)
                    .ok()
                    .map(|l| (Family::Presence, l));
            }
            if watermark_codec.matches(key) {
                return crate::codec::decode_watermark_location(key)
                    .ok()
                    .map(|l| (Family::Watermark, l));
            }
            None
        });

        let filter = drv::build_filter(
            RESERVED_BITS,
            OP_FAMILY,
            PRESENCE_FAMILY,
            WATERMARK_FAMILY,
            "(?s-u)^.{8}$",
        );
        let sub = drv::open_subscription(&self.client, filter, since).await?;

        let build_proof: drv::BuildProof<OperationRangeProof<H::Digest, K, V>> = Arc::new(
            move |watermark: Location, start: Location, count: u32| {
                let me = self.clone();
                async move { me.operation_range_proof(watermark, start, count).await }.boxed()
            },
        );

        Ok(OrderedBatchStream {
            inner: BatchProofStream::new(sub, classify, build_proof),
        })
    }

    pub async fn operation_range_proof_for_variant(
        &self,
        watermark: Location,
        variant: QmdbVariant,
        start_location: Location,
        max_locations: u32,
    ) -> Result<VariantOperationRangeProof<H::Digest, K, V, N>, QmdbError> {
        if max_locations == 0 {
            return Err(QmdbError::InvalidRangeLength);
        }

        let session = self.client.create_session();
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
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
        match variant {
            QmdbVariant::Any => {
                let storage = KvMmrStorage::<H::Digest> {
                    session: &session,
                    mmr_size: mmr_size_for_watermark(watermark)?,
                    _marker: PhantomData,
                };
                let proof = verification::range_proof(&storage, start_location..end)
                    .await
                    .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
                let root = self.compute_ops_root(&session, watermark).await?;
                let operations = self
                    .load_operation_range(&session, start_location, end)
                    .await?;

                Ok(VariantOperationRangeProof::Any(OperationRangeProof {
                    watermark,
                    root,
                    start_location,
                    proof,
                    operations,
                }))
            }
            QmdbVariant::Current => {
                self.core()
                    .require_batch_boundary(&session, watermark)
                    .await?;
                let proof = self
                    .build_current_range_proof(&session, watermark, start_location, end)
                    .await?;
                let root = self.load_current_boundary_root(&session, watermark).await?;
                let operations = self
                    .load_operation_range(&session, start_location, end)
                    .await?;
                let chunks = self
                    .load_bitmap_chunks(&session, watermark, start_location, end)
                    .await?;

                Ok(VariantOperationRangeProof::Current(
                    CurrentOperationRangeProofResult {
                        watermark,
                        root,
                        start_location,
                        proof,
                        operations,
                        chunks,
                    },
                ))
            }
        }
    }

    pub async fn current_operation_range_proof(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<CurrentOperationRangeProofResult<H::Digest, K, V, N>, QmdbError> {
        match self
            .operation_range_proof_for_variant(
                watermark,
                QmdbVariant::Current,
                start_location,
                max_locations,
            )
            .await?
        {
            VariantOperationRangeProof::Current(proof) => Ok(proof),
            VariantOperationRangeProof::Any(_) => Err(QmdbError::CorruptData(
                "unexpected any proof returned for current variant request".to_string(),
            )),
        }
    }

    pub async fn key_value_proof_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location,
        key: Q,
    ) -> Result<KeyValueProofResult<H::Digest, K, V, N>, QmdbError> {
        let session = self.client.create_session();
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        self.core()
            .require_batch_boundary(&session, watermark)
            .await?;

        let key_bytes = key.as_ref().to_vec();
        let Some((row_key, row_value)) = self
            .load_latest_update_row(&session, watermark, key.as_ref())
            .await?
        else {
            return Err(QmdbError::ProofKeyNotFound {
                watermark,
                key: key_bytes,
            });
        };
        let location = decode_update_location(&row_key)?;
        let decoded =
            <UpdateRow<K, V> as CodecRead>::read_cfg(&mut row_value.as_ref(), &self.update_row_cfg)
                .map_err(|e| QmdbError::CorruptData(format!("update row decode: {e}")))?;
        if <K as AsRef<[u8]>>::as_ref(&decoded.key) != key.as_ref() {
            return Err(QmdbError::ProofKeyNotFound {
                watermark,
                key: key.as_ref().to_vec(),
            });
        }
        if decoded.value.is_none() {
            return Err(QmdbError::KeyNotActive {
                watermark,
                key: key.as_ref().to_vec(),
            });
        }

        let operation = self.load_operation_at(&session, location).await?;
        let QmdbOperation::Update(update) = &operation else {
            return Err(QmdbError::KeyNotActive {
                watermark,
                key: key.as_ref().to_vec(),
            });
        };
        let range_proof = self
            .build_current_range_proof(&session, watermark, location, location + 1)
            .await?;
        let chunk = self
            .load_bitmap_chunk(&session, watermark, chunk_index_for_location::<N>(location))
            .await?;
        let root = self.load_current_boundary_root(&session, watermark).await?;

        Ok(KeyValueProofResult {
            watermark,
            root,
            proof: CurrentKeyValueProof {
                proof: CurrentOperationProof {
                    loc: location,
                    chunk,
                    range_proof,
                },
                next_key: update.next_key.clone(),
            },
            operation,
        })
    }

    async fn require_current_boundary_state(
        &self,
        session: &SerializableReadSession,
        location: Location,
    ) -> Result<(), QmdbError> {
        if session
            .get(&encode_current_meta_key(location))
            .await?
            .is_some()
        {
            Ok(())
        } else {
            Err(QmdbError::CurrentBoundaryStateMissing { location })
        }
    }

    async fn load_current_boundary_root(
        &self,
        session: &SerializableReadSession,
        location: Location,
    ) -> Result<H::Digest, QmdbError> {
        let Some(bytes) = session.get(&encode_current_meta_key(location)).await? else {
            return Err(QmdbError::CurrentBoundaryStateMissing { location });
        };
        decode_digest(
            bytes.as_ref(),
            format!("current boundary root at {location}"),
        )
    }

    async fn append_ops_nodes_incrementally<Op: Encode>(
        &self,
        session: &SerializableReadSession,
        previous_ops_size: Position,
        delta_operations: &[Op],
        rows: &mut Vec<(Key, Vec<u8>)>,
    ) -> Result<(Position, BTreeMap<Position, H::Digest>, H::Digest), QmdbError> {
        let encoded = delta_operations
            .iter()
            .map(|operation| {
                let bytes = operation.encode().to_vec();
                ensure_encoded_value_size(bytes.len())?;
                Ok(bytes)
            })
            .collect::<Result<Vec<_>, QmdbError>>()?;
        self.core()
            .append_encoded_ops_nodes_incrementally::<H>(session, previous_ops_size, &encoded, rows)
            .await
    }

    pub(crate) async fn compute_ops_root(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
    ) -> Result<H::Digest, QmdbError> {
        self.core().compute_ops_root::<H>(session, watermark).await
    }

    async fn build_current_range_proof(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        start_location: Location,
        end_location_exclusive: Location,
    ) -> Result<CurrentRangeProof<H::Digest>, QmdbError> {
        let storage = KvCurrentStorage::<H::Digest, N> {
            session,
            watermark,
            mmr_size: mmr_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        let proof = verification::range_proof(&storage, start_location..end_location_exclusive)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
        Ok(CurrentRangeProof {
            proof,
            partial_chunk_digest: self
                .load_partial_chunk_digest(session, watermark)
                .await?
                .map(|(_, digest)| digest),
            ops_root: self.compute_ops_root(session, watermark).await?,
        })
    }

    async fn load_bitmap_chunk(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        chunk_index: u64,
    ) -> Result<[u8; N], QmdbError> {
        let start = encode_chunk_key(chunk_index, Location::new(0));
        let end = encode_chunk_key(chunk_index, watermark);
        let rows = session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        let Some((_, bytes)) = rows.into_iter().next() else {
            return Err(QmdbError::CorruptData(format!(
                "missing bitmap chunk {chunk_index} at watermark {watermark}"
            )));
        };
        if bytes.len() != N {
            return Err(QmdbError::CorruptData(format!(
                "bitmap chunk {chunk_index} has invalid length {}",
                bytes.len()
            )));
        }
        let mut chunk = [0u8; N];
        chunk.copy_from_slice(bytes.as_ref());
        Ok(chunk)
    }

    async fn load_bitmap_chunks(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        start_location: Location,
        end_location_exclusive: Location,
    ) -> Result<Vec<[u8; N]>, QmdbError> {
        let start_chunk = chunk_index_for_location::<N>(start_location);
        let end_chunk = chunk_index_for_location::<N>(end_location_exclusive - 1);
        let mut chunks = Vec::with_capacity((end_chunk - start_chunk + 1) as usize);
        for chunk_index in start_chunk..=end_chunk {
            chunks.push(
                self.load_bitmap_chunk(session, watermark, chunk_index)
                    .await?,
            );
        }
        Ok(chunks)
    }

    async fn load_partial_chunk_digest(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
    ) -> Result<Option<(u64, H::Digest)>, QmdbError> {
        let leaves = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        let next_bit = *leaves % bitmap_chunk_bits::<N>();
        if next_bit == NO_PARTIAL_CHUNK {
            return Ok(None);
        }
        let chunk_index = *leaves / bitmap_chunk_bits::<N>();
        let chunk = self
            .load_bitmap_chunk(session, watermark, chunk_index)
            .await?;
        let mut hasher = H::default();
        hasher.update(&chunk);
        Ok(Some((next_bit, hasher.finalize())))
    }

    async fn load_operation_at(
        &self,
        session: &SerializableReadSession,
        location: Location,
    ) -> Result<QmdbOperation<K, V>, QmdbError> {
        let bytes = self
            .core()
            .load_operation_bytes_at(session, location)
            .await?;
        QmdbOperation::<K, V>::decode_cfg(bytes.as_slice(), &self.op_cfg).map_err(|e| {
            QmdbError::CorruptData(format!(
                "failed to decode qmdb operation at location {location}: {e}"
            ))
        })
    }

    async fn load_operation_range(
        &self,
        session: &SerializableReadSession,
        start_location: Location,
        end_location_exclusive: Location,
    ) -> Result<Vec<QmdbOperation<K, V>>, QmdbError> {
        let rows = self
            .core()
            .load_operation_bytes_range(session, start_location, end_location_exclusive)
            .await?;
        rows.into_iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = start_location + offset as u64;
                QmdbOperation::<K, V>::decode_cfg(bytes.as_slice(), &self.op_cfg).map_err(|e| {
                    QmdbError::CorruptData(format!(
                        "failed to decode qmdb operation at location {location}: {e}"
                    ))
                })
            })
            .collect()
    }

    async fn load_latest_update_row(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        key: &[u8],
    ) -> Result<Option<(Key, Vec<u8>)>, QmdbError> {
        self.core()
            .load_latest_update_row(session, watermark, key)
            .await
    }
}

/// Async stream of `OperationRangeProof`s, one per uploaded batch observed
/// via the store's stream service. See `OrderedClient::stream_batches`.
pub struct OrderedBatchStream<H: Hasher, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, const N: usize>
{
    inner: crate::stream::driver::BatchProofStream<OperationRangeProof<H::Digest, K, V>>,
}

impl<H, K, V, const N: usize> futures::Stream for OrderedBatchStream<H, K, V, N>
where
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    QmdbOperation<K, V>: Encode,
    OperationRangeProof<H::Digest, K, V>: Send + 'static,
{
    type Item = Result<OperationRangeProof<H::Digest, K, V>, QmdbError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.inner).poll_next(cx)
    }
}
