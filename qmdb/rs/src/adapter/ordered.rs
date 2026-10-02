use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::sync::Arc;

use commonware_codec::{Codec, Copying, Decode, DecodeExt, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Graftable, Location},
    qmdb::{
        any::{
            ordered,
            value::{ValueEncoding, VariableEncoding},
        },
        current::{
            ordered::proof::constant::ExclusionProof,
            proof::{constant::OperationProof, OpsRootWitness, RangeProof},
        },
        operation::{Key as QmdbKey, Operation as _},
    },
};
use exoware_sdk::{keys::Key, PrefixedStoreClient, RangeMode, ReadSession};

use crate::adapter::codec::{
    chunk_index_for_location, clear_below_floor, decode_current_boundary_metadata,
    decode_update_index_value_present, decode_update_location, decode_update_raw_key,
    encode_chunk_key, encode_current_meta_key, encode_operation_key, encode_ops_root_witness_key,
    encode_update_key, merkle_size_for_watermark, CurrentBoundaryMetadata, UPDATE_PREFIX,
};
use crate::adapter::core;
use crate::adapter::operation_range::{
    load_operation_range_checkpoint, load_operations_multi_proof,
};
use crate::adapter::read_cache::ReadCache;
use crate::adapter::storage::{KvCurrentStorage, ProofBitmap};
use crate::error::{error_key, QmdbError};
use crate::proof::{
    CurrentOperationRangeProofResult, MultiProofOperations, OperationRangeCheckpoint,
    RawBatchMultiProof, RawKeyExclusionProof, RawKeyLookupProof, RawKeyRangeProof,
    RawKeyValueProof, VerifiedCurrentRange, VerifiedKeyLookup, VerifiedKeyRange, VerifiedKeyValue,
    VerifiedOperationRange,
};
use crate::request::{span_contains, validate_key_range};
use crate::OperationKv;
use crate::PublishedWatermark;
use crate::VersionedValue;

const ACTIVE_OPERATION_GET_MANY_BATCH: usize = 1024;
/// Update-index rows in a walk's first request. An exclusion walk usually
/// reads the probed key's own overwritten or deleted versions and stops at
/// its neighbour's newest one.
const UPDATE_WALK_FIRST_PAGE_ROWS: usize = 128;
/// Factor by which each further request grows, so a long run of inactive keys
/// costs round trips logarithmic in its length.
const UPDATE_WALK_PAGE_GROWTH: usize = 8;
/// Largest walk request, the Store's row limit for one range frame.
const UPDATE_WALK_MAX_PAGE_ROWS: usize = 4096;

pub struct Ordered<
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    ordered::Operation<F, K, E>: commonware_codec::Read,
{
    store: PrefixedStoreClient,
    publication: Arc<core::PublicationCache<F>>,
    op_cfg: <ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    key_cfg: K::Cfg,
    read_cache: Arc<ReadCache<F, H::Digest>>,
    _marker: PhantomData<(F, H, K, E)>,
}

impl<
        F: Graftable,
        H: Hasher,
        K: QmdbKey + Codec,
        V: Codec + Clone + Send + Sync,
        const N: usize,
        E: ValueEncoding<Value = V>,
    > Clone for Ordered<F, H, K, V, N, E>
where
    ordered::Operation<F, K, E>: commonware_codec::Read,
{
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            publication: self.publication.clone(),
            op_cfg: self.op_cfg.clone(),
            key_cfg: self.key_cfg.clone(),
            read_cache: self.read_cache.clone(),
            _marker: PhantomData,
        }
    }
}

impl<
        F: Graftable,
        H: Hasher,
        K: QmdbKey + Codec,
        V: Codec + Clone + Send + Sync,
        const N: usize,
        E: ValueEncoding<Value = V>,
    > std::fmt::Debug for Ordered<F, H, K, V, N, E>
where
    ordered::Operation<F, K, E>: commonware_codec::Read,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ordered").finish_non_exhaustive()
    }
}

impl<F, H, K, V, const N: usize, E> crate::adapter::core::LatestValueResolver<F, K, V>
    for Ordered<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Encode + Decode,
{
    fn resolve_latest_value(
        &self,
        location: Location<F>,
        requested_key: &[u8],
        op_bytes: Vec<u8>,
    ) -> Result<VersionedValue<K, V, F>, QmdbError> {
        let (key, value) = match Self::decode_operation(&self.op_cfg, location, &op_bytes)? {
            ordered::Operation::Update(update) => (update.key, Some(update.value)),
            ordered::Operation::Delete(key) => (key, None),
            ordered::Operation::CommitFloor(_, _) => {
                return Err(QmdbError::CorruptData(format!(
                    "latest update row at {location} points to a commit operation"
                )));
            }
        };
        if key.as_ref() != requested_key {
            return Err(QmdbError::CorruptData(format!(
                "latest update row at {location} points to a different key"
            )));
        }
        Ok(VersionedValue {
            key,
            location,
            value,
        })
    }
}

impl<F, H, K, V, const N: usize, E> Ordered<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: commonware_codec::Read,
{
    /// Read client for the Store namespace.
    pub fn new(
        store: PrefixedStoreClient,
        op_cfg: <ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        key_cfg: K::Cfg,
    ) -> Self {
        Self {
            store,
            publication: Arc::new(core::PublicationCache::default()),
            op_cfg,
            key_cfg,
            read_cache: Arc::new(ReadCache::new()),
            _marker: PhantomData,
        }
    }
}

impl<F, H, K, V, const N: usize, E> Ordered<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Encode + Decode,
{
    /// Refresh publication evidence and return the greatest watermark observed by this client.
    pub async fn latest_published_watermark(&self) -> Result<Option<Location<F>>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), None);
        self.publication.refresh(&session).await
    }

    /// Record a watermark published at `sequence`, as seen by a subscription.
    pub(crate) fn observe_published(&self, location: Location<F>, sequence: u64) {
        self.publication.observe(location, sequence);
    }

    pub(crate) async fn resolve_watermark(
        &self,
        watermark: Location<F>,
        min_sequence_number: Option<u64>,
    ) -> Result<PublishedWatermark<F>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), min_sequence_number);
        self.publication.require(&session, watermark).await
    }

    /// Canonical root at `watermark`, as the source database's `root()` returns
    /// it: the current root when current-state rows were uploaded for this
    /// boundary, otherwise the operations-log root.
    pub async fn root_at(&self, watermark: Location<F>) -> Result<H::Digest, QmdbError> {
        let watermark = self.resolve_watermark(watermark, None).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        if Self::load_ops_root_witness(&session, watermark.location)
            .await?
            .is_some()
        {
            return Self::load_current_boundary_root(&session, watermark.location).await;
        }
        Self::compute_ops_root(&session, &self.op_cfg, watermark.location).await
    }

    /// Operations-log root at `watermark`, as the source database's `ops_root()`
    /// returns it.
    pub async fn ops_root_at(&self, watermark: Location<F>) -> Result<H::Digest, QmdbError> {
        let watermark = self.resolve_watermark(watermark, None).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        Self::compute_ops_root(&session, &self.op_cfg, watermark.location).await
    }

    pub async fn query_many_at<Q: AsRef<[u8]>>(
        &self,
        keys: &[Q],
        max_location: Location<F>,
    ) -> Result<Vec<Option<VersionedValue<K, V, F>>>, QmdbError> {
        let watermark = self.resolve_watermark(max_location, None).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        core::query_many_at(&session, keys, watermark.location, self).await
    }

    fn decode_operation(
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<ordered::Operation<F, K, E>, QmdbError> {
        ordered::Operation::<F, K, E>::decode_cfg(Copying(bytes), op_cfg).map_err(|e| {
            QmdbError::CorruptData(format!(
                "failed to decode qmdb operation at location {location}: {e}"
            ))
        })
    }

    pub(crate) fn decode_operation_bytes(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<ordered::Operation<F, K, E>, QmdbError> {
        Self::decode_operation(&self.op_cfg, location, bytes)
    }

    pub(crate) fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError>
    where
        V: AsRef<[u8]>,
    {
        let op = Self::decode_operation(&self.op_cfg, location, bytes)?;
        let key = op.key().map(|k| <K as AsRef<[u8]>>::as_ref(k).to_vec());
        let value = match &op {
            ordered::Operation::Update(update) => Some(update.value.as_ref().to_vec()),
            ordered::Operation::CommitFloor(Some(value), _) => Some(value.as_ref().to_vec()),
            ordered::Operation::Delete(_) | ordered::Operation::CommitFloor(None, _) => None,
        };
        Ok(OperationKv { key, value })
    }

    /// Verified contiguous range of operations.
    pub async fn operation_range(
        &self,
        tip: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<VerifiedOperationRange<H::Digest, ordered::Operation<F, K, E>, F>, QmdbError> {
        let checkpoint = self
            .operation_range_checkpoint(tip, start_location, max_locations, min_sequence_number)
            .await?;
        let operations = checkpoint
            .encoded_operations
            .iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = checkpoint.start_location + offset as u64;
                self.decode_operation_bytes(location, bytes)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VerifiedOperationRange {
            tip: checkpoint.watermark,
            root: checkpoint.canonical_root::<H>(),
            start_location: checkpoint.start_location,
            operations,
        })
    }

    /// Operation-range checkpoint: the proof, pinned nodes, and encoded operations.
    pub async fn operation_range_checkpoint(
        &self,
        tip: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<OperationRangeCheckpoint<H::Digest, F>, QmdbError> {
        let watermark = self.resolve_watermark(tip, min_sequence_number).await?;
        self.operation_range_checkpoint_at(watermark, start_location, max_locations)
            .await
    }

    pub(crate) async fn operation_range_checkpoint_at(
        &self,
        watermark: PublishedWatermark<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<OperationRangeCheckpoint<H::Digest, F>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        let watermark = watermark.location;
        let end = crate::proof::resolve_range_bounds(watermark, start_location, max_locations)?;
        let session = &session;
        let checkpoint = load_operation_range_checkpoint::<F, H, _>(
            session,
            &self.read_cache,
            watermark,
            start_location,
            end,
            true,
            |bytes| async move {
                let operation = Self::decode_operation(&self.op_cfg, watermark, bytes.as_ref())?;
                let floor = Self::load_ops_inactivity_floor_from(
                    session,
                    &self.op_cfg,
                    watermark,
                    operation,
                )
                .await?;
                core::inactive_peaks(watermark, floor)
            },
        )
        .await?;
        Ok(checkpoint)
    }

    /// Multi-proof at a published watermark, built from the same cached reads
    /// as [`Self::operation_range_checkpoint_at`].
    pub(crate) async fn multi_proof_at(
        &self,
        watermark: PublishedWatermark<F>,
        operations: MultiProofOperations<'_, F>,
    ) -> Result<RawBatchMultiProof<H::Digest, F>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        let watermark = watermark.location;
        let session = &session;
        load_operations_multi_proof::<F, H, _>(
            session,
            &self.read_cache,
            watermark,
            operations,
            true,
            |bytes| async move {
                let operation = Self::decode_operation(&self.op_cfg, watermark, bytes.as_ref())?;
                let floor = Self::load_ops_inactivity_floor_from(
                    session,
                    &self.op_cfg,
                    watermark,
                    operation,
                )
                .await?;
                core::inactive_peaks(watermark, floor)
            },
        )
        .await
    }

    /// Verified raw current-state proof for a contiguous operation range.
    pub async fn current_operation_range_raw(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<
        CurrentOperationRangeProofResult<H::Digest, ordered::Operation<F, K, E>, N, F>,
        QmdbError,
    > {
        let watermark = self
            .resolve_watermark(watermark, min_sequence_number)
            .await?;
        let end =
            crate::proof::resolve_range_bounds(watermark.location, start_location, max_locations)?;
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        core::require_batch_boundary(&session, watermark.location).await?;
        let proof = Self::build_current_range_proof(
            &session,
            &self.op_cfg,
            watermark.location,
            start_location,
            end,
        )
        .await?;
        let root = Self::load_current_boundary_root(&session, watermark.location).await?;
        let operations =
            Self::load_operation_range(&session, &self.op_cfg, start_location, end).await?;
        let chunks = Self::load_bitmap_chunks(
            &session,
            &self.op_cfg,
            watermark.location,
            start_location,
            end,
        )
        .await?;
        let raw = CurrentOperationRangeProofResult {
            watermark: watermark.location,
            root,
            start_location,
            proof,
            operations,
            chunks,
        };
        if !raw.verify::<H>() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentRange,
            });
        }
        Ok(raw)
    }

    /// Verified contiguous range from the current-state variant (with bitmap chunks).
    pub async fn current_operation_range(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<VerifiedCurrentRange<H::Digest, ordered::Operation<F, K, E>, N, F>, QmdbError> {
        let raw = self
            .current_operation_range_raw(
                watermark,
                start_location,
                max_locations,
                min_sequence_number,
            )
            .await?;
        Ok(VerifiedCurrentRange {
            tip: raw.watermark,
            root: raw.root,
            start_location: raw.start_location,
            operations: raw.operations,
            chunks: raw.chunks,
        })
    }

    async fn key_value_proof_raw<Q: AsRef<[u8]>>(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
        key: Q,
    ) -> Result<RawKeyValueProof<H::Digest, ordered::Operation<F, K, E>, N, F>, QmdbError> {
        core::require_batch_boundary(session, watermark).await?;
        let key_bytes = error_key(&key);
        let Some((row_key, row_value)) =
            core::load_latest_update_row(session, watermark, key.as_ref()).await?
        else {
            return Err(QmdbError::ProofKeyNotFound {
                watermark: watermark.as_u64(),
                key: key_bytes,
            });
        };
        let location = decode_update_location(&row_key)?;
        let inactivity_floor = Self::load_inactivity_floor_at(session, op_cfg, watermark).await?;
        if location < inactivity_floor || !decode_update_index_value_present(row_value.as_ref())? {
            return Err(QmdbError::KeyNotActive {
                watermark: watermark.as_u64(),
                key: key_bytes,
            });
        }

        let operation = Self::load_operation_at(session, op_cfg, location).await?;
        let ordered::Operation::Update(update) = &operation else {
            return Err(QmdbError::KeyNotActive {
                watermark: watermark.as_u64(),
                key: key_bytes,
            });
        };
        if update.key.as_ref() != key.as_ref() {
            return Err(QmdbError::CorruptData(format!(
                "latest active ordered key row at {location} points to a different key"
            )));
        }
        let root = Self::load_current_boundary_root(session, watermark).await?;
        let proof =
            Self::build_current_operation_proof(session, op_cfg, watermark, location).await?;
        let raw = RawKeyValueProof {
            watermark,
            root,
            proof,
            operation,
        };
        if !raw.verify::<H>() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
        Ok(raw)
    }

    async fn key_value_proof_raw_at_watermark<Q: AsRef<[u8]>>(
        &self,
        watermark: PublishedWatermark<F>,
        key: Q,
    ) -> Result<RawKeyValueProof<H::Digest, ordered::Operation<F, K, E>, N, F>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        Self::key_value_proof_raw(&session, &self.op_cfg, watermark.location, key).await
    }

    /// Verified raw current-state proof for a single key.
    pub async fn get_raw<Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        key: Q,
        min_sequence_number: Option<u64>,
    ) -> Result<RawKeyValueProof<H::Digest, ordered::Operation<F, K, E>, N, F>, QmdbError> {
        let watermark = self
            .resolve_watermark(watermark, min_sequence_number)
            .await?;
        self.key_value_proof_raw_at_watermark(watermark, key).await
    }

    /// Verified current-state proof for a single key. The returned
    /// `operation` is the matching `Update`. Its `next_key` is the value
    /// the proof was verified against.
    pub async fn get(
        &self,
        tip: Location<F>,
        key: &K,
        min_sequence_number: Option<u64>,
    ) -> Result<VerifiedKeyValue<H::Digest, ordered::Operation<F, K, E>, F>, QmdbError> {
        let raw = self.get_raw(tip, key.as_ref(), min_sequence_number).await?;
        Ok(verified_key_value(raw))
    }

    /// Verified current-state lookups for `keys`: a hit with its value proof,
    /// or a miss proven by exclusion, in request order.
    pub async fn get_many(
        &self,
        tip: Location<F>,
        keys: &[K],
        min_sequence_number: Option<u64>,
    ) -> Result<Vec<VerifiedKeyLookup<H::Digest, K, V, F, E>>, QmdbError> {
        let raw = self.get_many_raw(tip, keys, min_sequence_number).await?;
        Ok(raw
            .into_iter()
            .map(|lookup| match lookup {
                RawKeyLookupProof::Hit(proof) => VerifiedKeyLookup::Hit(verified_key_value(proof)),
                RawKeyLookupProof::Miss(proof) => VerifiedKeyLookup::Miss {
                    key: proof.requested_key,
                },
            })
            .collect())
    }

    /// Verified ordered current-state range for `[start_key, end_key)`, at most
    /// `limit` entries.
    pub async fn get_range(
        &self,
        tip: Location<F>,
        start_key: K,
        end_key: Option<K>,
        limit: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<VerifiedKeyRange<H::Digest, K, V, F, E>, QmdbError> {
        let raw = self
            .get_range_raw(
                tip,
                start_key.clone(),
                end_key.clone(),
                limit,
                min_sequence_number,
            )
            .await?;
        let start_successor = raw.start_proof.map(|proof| match proof.proof {
            ExclusionProof::KeyValue(_, update) => Some(update.next_key),
            ExclusionProof::Commit(_, _) => None,
        });
        let entries = raw
            .entries
            .into_iter()
            .map(verified_key_value)
            .collect::<Vec<_>>();
        let keys = entries
            .iter()
            .map(|entry| match &entry.operation {
                ordered::Operation::Update(update) => Ok((&update.key, &update.next_key)),
                _ => Err(QmdbError::CorruptData(
                    "key range entry is not an update".to_string(),
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let next_start_key = validate_key_range(
            &start_key,
            end_key.as_ref(),
            limit,
            &keys,
            start_successor.flatten().as_ref(),
        )
        .map_err(QmdbError::RangeMismatch)?
        .cloned();
        Ok(VerifiedKeyRange {
            entries,
            next_start_key,
        })
    }

    /// Visit keys of the key-ordered update index in `[start, end]`, in `mode`
    /// order, with each key's latest version at or below `watermark` as
    /// `(raw key, location, value present)`. Stops when `visit` returns
    /// `false`, so a walk reads only up to the keys its caller needs. Index
    /// order is raw key byte order, which matches `K`'s order as commonware's
    /// ordered index already requires of ordered QMDB keys.
    ///
    /// A key is visited as soon as its rows settle it: in reverse at its newest
    /// version at or below `watermark`, and forward at the first version above
    /// `watermark` or the next key. Later requests skip the rest of a settled
    /// key's rows. Reads pages of at least `first_page_rows` rows, each later page
    /// [`UPDATE_WALK_PAGE_GROWTH`] times larger up to [`UPDATE_WALK_MAX_PAGE_ROWS`],
    /// so the Store reads little past the row where `visit` stops.
    async fn walk_latest_updates(
        session: &ReadSession,
        start: &Key,
        end: &Key,
        mode: RangeMode,
        watermark: Location<F>,
        first_page_rows: usize,
        mut visit: impl FnMut(Vec<u8>, Location<F>, bool) -> Result<bool, QmdbError>,
    ) -> Result<(), QmdbError> {
        let (mut start, mut end) = (start.clone(), end.clone());
        let mut page_rows =
            first_page_rows.clamp(UPDATE_WALK_FIRST_PAGE_ROWS, UPDATE_WALK_MAX_PAGE_ROWS);
        let mut last_row_key: Option<Key> = None;
        // Rows arrive grouped by key; versions oldest first forward, newest first reverse.
        // A key's versions may span pages, so the settled and pending keys carry across them.
        let mut settled_raw_key: Option<Vec<u8>> = None;
        // Forward, the newest version at or below `watermark` so far of the current key.
        let mut pending: Option<(Vec<u8>, Location<F>, bool)> = None;
        loop {
            let rows = session
                .range_with_mode(&start, &end, page_rows, mode)
                .await?;
            let exhausted = rows.len() < page_rows;
            // Each page after the first restarts at the previous page's last row, inclusive.
            let repeats_last_row = rows
                .first()
                .is_some_and(|(row_key, _)| last_row_key.as_ref() == Some(row_key));
            for (row_key, row_value) in rows.into_iter().skip(usize::from(repeats_last_row)) {
                let raw_key = decode_update_raw_key(&row_key)?;
                last_row_key = Some(row_key.clone());
                if settled_raw_key.as_ref() == Some(&raw_key) {
                    continue;
                }
                // Forward, a new key settles the pending one
                if let Some((pending_raw_key, location, value_present)) =
                    pending.take_if(|(pending_raw_key, _, _)| *pending_raw_key != raw_key)
                {
                    if !visit(pending_raw_key, location, value_present)? {
                        return Ok(());
                    }
                }
                let location = decode_update_location(&row_key)?;
                if location > watermark {
                    // Forward, versions above `watermark` follow every eligible one
                    if mode == RangeMode::Forward {
                        settled_raw_key = Some(raw_key);
                        if let Some((pending_raw_key, location, value_present)) = pending.take() {
                            if !visit(pending_raw_key, location, value_present)? {
                                return Ok(());
                            }
                        }
                    }
                    continue;
                }
                let value_present = decode_update_index_value_present(&row_value)?;
                match mode {
                    RangeMode::Forward => pending = Some((raw_key, location, value_present)),
                    RangeMode::Reverse => {
                        settled_raw_key = Some(raw_key.clone());
                        if !visit(raw_key, location, value_present)? {
                            return Ok(());
                        }
                    }
                }
            }
            let Some(last_row_key) = last_row_key.clone().filter(|_| !exhausted) else {
                break;
            };
            // Past a settled key, resume beyond its remaining versions
            let last_raw_key = decode_update_raw_key(&last_row_key)?;
            let last_key_settled = settled_raw_key.as_ref() == Some(&last_raw_key);
            match mode {
                RangeMode::Forward => {
                    start = if last_key_settled {
                        encode_update_key(&last_raw_key, Location::<F>::new(u64::MAX))?
                    } else {
                        last_row_key
                    };
                    if start > end {
                        break;
                    }
                }
                RangeMode::Reverse => {
                    end = if last_key_settled {
                        encode_update_key(&last_raw_key, Location::<F>::new(0))?
                    } else {
                        last_row_key
                    };
                    if end < start {
                        break;
                    }
                }
            }
            page_rows = page_rows
                .saturating_mul(UPDATE_WALK_PAGE_GROWTH)
                .min(UPDATE_WALK_MAX_PAGE_ROWS);
        }
        if let Some((pending_raw_key, location, value_present)) = pending {
            visit(pending_raw_key, location, value_present)?;
        }
        Ok(())
    }

    /// Greatest key active at `watermark` in `[start, end]`, as `(raw key, location)`.
    /// Fails if `absent_key` is active, since an exclusion proof requires it not to be.
    async fn greatest_active_key(
        session: &ReadSession,
        start: &Key,
        end: &Key,
        watermark: Location<F>,
        inactivity_floor: Location<F>,
        absent_key: &[u8],
    ) -> Result<Option<(Vec<u8>, Location<F>)>, QmdbError> {
        let mut found = None;
        Self::walk_latest_updates(
            session,
            start,
            end,
            RangeMode::Reverse,
            watermark,
            UPDATE_WALK_FIRST_PAGE_ROWS,
            |raw_key, location, value_present| {
                if !value_present || location < inactivity_floor {
                    return Ok(true);
                }
                if raw_key == absent_key {
                    return Err(QmdbError::CorruptData(
                        "cannot build exclusion proof for active key".to_string(),
                    ));
                }
                found = Some((raw_key, location));
                Ok(false)
            },
        )
        .await?;
        Ok(found)
    }

    /// The active update whose span covers the inactive `key`: the greatest
    /// active key below it or, when none is, the greatest active key overall,
    /// whose span wraps. `None` when no key is active.
    async fn covering_update(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
        inactivity_floor: Location<F>,
        key: &K,
    ) -> Result<Option<(Location<F>, ordered::Update<K, E>)>, QmdbError> {
        let (index_start, index_end) = UPDATE_PREFIX.bounds();
        let through_key = encode_update_key(key.as_ref(), watermark)?;
        let mut found = Self::greatest_active_key(
            session,
            &index_start,
            &through_key,
            watermark,
            inactivity_floor,
            key.as_ref(),
        )
        .await?;
        if found.is_none() {
            // Nothing below `key` is active, so only keys above it can cover the wrap.
            let after_key = encode_update_key(key.as_ref(), Location::<F>::new(u64::MAX))?;
            found = Self::greatest_active_key(
                session,
                &after_key,
                &index_end,
                watermark,
                inactivity_floor,
                key.as_ref(),
            )
            .await?;
        }
        let Some((active_key, location)) = found else {
            return Ok(None);
        };
        let mut updates =
            Self::load_active_updates(session, op_cfg, &[(active_key, location)]).await?;
        Ok(updates.pop())
    }

    /// Load the update operations behind active `(key, location)` index entries.
    async fn load_active_updates(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        entries: &[(Vec<u8>, Location<F>)],
    ) -> Result<Vec<(Location<F>, ordered::Update<K, E>)>, QmdbError> {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let operation_keys = entries
            .iter()
            .map(|(_, location)| encode_operation_key(*location))
            .collect::<Vec<_>>();
        let operation_key_refs = operation_keys.iter().collect::<Vec<_>>();
        let batch_size = u32::try_from(
            operation_key_refs
                .len()
                .min(ACTIVE_OPERATION_GET_MANY_BATCH),
        )
        .expect("batch bound fits u32");
        let mut loaded = session
            .get_many(&operation_key_refs, batch_size)
            .await?
            .collect()
            .await?;
        entries
            .iter()
            .zip(&operation_keys)
            .map(|((key, location), operation_key)| {
                let Some(encoded) = loaded.remove(operation_key) else {
                    return Err(QmdbError::CorruptData(format!(
                        "missing operation row at location {location}"
                    )));
                };
                let operation = Self::decode_operation(op_cfg, *location, encoded.as_ref())?;
                let ordered::Operation::Update(update) = operation else {
                    return Err(QmdbError::CorruptData(format!(
                        "latest active key row at {location} does not point to an update operation"
                    )));
                };
                if update.key.as_ref() != key.as_slice() {
                    return Err(QmdbError::CorruptData(format!(
                        "active update key mismatch at {location}"
                    )));
                }
                Ok((*location, update))
            })
            .collect()
    }

    async fn key_exclusion_proof(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
        key: &K,
    ) -> Result<RawKeyExclusionProof<H::Digest, K, V, N, F, E>, QmdbError> {
        core::require_batch_boundary(session, watermark).await?;
        let root = Self::load_current_boundary_root(session, watermark).await?;
        let inactivity_floor = Self::load_inactivity_floor_at(session, op_cfg, watermark).await?;
        let covering =
            Self::covering_update(session, op_cfg, watermark, inactivity_floor, key).await?;

        let proof = if let Some((location, update)) = covering {
            if !span_contains(&update.key, &update.next_key, key) {
                return Err(QmdbError::CorruptData(format!(
                    "no ordered active-key span contains requested key {key:?}"
                )));
            }
            let op_proof =
                Self::build_current_operation_proof(session, op_cfg, watermark, location).await?;
            ExclusionProof::KeyValue(op_proof, update)
        } else {
            let operation = Self::load_operation_at(session, op_cfg, watermark).await?;
            let ordered::Operation::CommitFloor(value, floor) = operation else {
                return Err(QmdbError::CorruptData(format!(
                    "empty ordered exclusion proof expected CommitFloor at watermark {watermark}"
                )));
            };
            if floor != watermark {
                return Err(QmdbError::CorruptData(format!(
                    "empty ordered exclusion proof expected floor {watermark}, got {floor}"
                )));
            }
            let op_proof =
                Self::build_current_operation_proof(session, op_cfg, watermark, watermark).await?;
            ExclusionProof::Commit(op_proof, value)
        };

        let raw = RawKeyExclusionProof {
            watermark,
            root,
            requested_key: key.clone(),
            proof,
        };
        if !raw.verify::<H>() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyExclusion,
            });
        }
        Ok(raw)
    }

    async fn key_exclusion_proof_at_watermark(
        &self,
        watermark: PublishedWatermark<F>,
        key: &K,
    ) -> Result<RawKeyExclusionProof<H::Digest, K, V, N, F, E>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        Self::key_exclusion_proof(&session, &self.op_cfg, watermark.location, key).await
    }

    /// Verified current-state lookup proofs for explicit keys, preserving request order.
    pub async fn get_many_raw(
        &self,
        watermark: Location<F>,
        keys: &[K],
        min_sequence_number: Option<u64>,
    ) -> Result<Vec<RawKeyLookupProof<H::Digest, K, V, N, F, E>>, QmdbError> {
        if keys.is_empty() {
            return Err(QmdbError::EmptyProofRequest);
        }

        let watermark = self
            .resolve_watermark(watermark, min_sequence_number)
            .await?;
        let mut seen = BTreeSet::<Vec<u8>>::new();
        let mut proofs = Vec::with_capacity(keys.len());
        for key in keys {
            let key_bytes = error_key(key);
            if !seen.insert(key_bytes.clone()) {
                return Err(QmdbError::DuplicateRequestedKey { key: key_bytes });
            }
            match self
                .key_value_proof_raw_at_watermark(watermark, key.as_ref())
                .await
            {
                Ok(proof) => proofs.push(RawKeyLookupProof::Hit(proof)),
                Err(QmdbError::ProofKeyNotFound { .. } | QmdbError::KeyNotActive { .. }) => {
                    let proof = self
                        .key_exclusion_proof_at_watermark(watermark, key)
                        .await?;
                    proofs.push(RawKeyLookupProof::Miss(proof));
                }
                Err(err) => return Err(err),
            }
        }
        Ok(proofs)
    }

    /// Verified ordered current-state range proof for `[start_key, end_key)`.
    pub async fn get_range_raw(
        &self,
        watermark: Location<F>,
        start_key: K,
        end_key: Option<K>,
        limit: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<RawKeyRangeProof<H::Digest, K, V, N, F, E>, QmdbError> {
        if limit == 0 {
            return Err(QmdbError::InvalidRangeLength);
        }
        if let Some(end) = end_key.as_ref() {
            if end <= &start_key {
                return Err(QmdbError::InvalidKeyRange {
                    start_key: error_key(&start_key),
                    end_key: error_key(end),
                });
            }
        }

        let watermark = self
            .resolve_watermark(watermark, min_sequence_number)
            .await?;

        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        let inactivity_floor =
            Self::load_inactivity_floor_at(&session, &self.op_cfg, watermark.location).await?;
        let start = encode_update_key(start_key.as_ref(), Location::<F>::new(0))?;
        let (_, index_end) = UPDATE_PREFIX.bounds();
        let mut active = Vec::new();
        // Settling the `limit`th active key can take a row of the key after it.
        let first_page_rows = (limit as usize).saturating_add(1);
        Self::walk_latest_updates(
            &session,
            &start,
            &index_end,
            RangeMode::Forward,
            watermark.location,
            first_page_rows,
            |raw_key, location, value_present| {
                if end_key
                    .as_ref()
                    .is_some_and(|end| raw_key.as_slice() >= end.as_ref())
                {
                    return Ok(false);
                }
                if value_present && location >= inactivity_floor {
                    active.push((raw_key, location));
                }
                Ok(active.len() < limit as usize)
            },
        )
        .await?;
        // Each entry's proof loads and checks its own operation.
        let mut entries = Vec::with_capacity(active.len());
        for (key, _) in &active {
            let proof = self
                .key_value_proof_raw_at_watermark(watermark, key.as_slice())
                .await?;
            entries.push(proof);
        }

        let start_proof = if entries
            .first()
            .is_some_and(|entry| entry.operation.key() == Some(&start_key))
        {
            None
        } else {
            Some(
                self.key_exclusion_proof_at_watermark(watermark, &start_key)
                    .await?,
            )
        };

        Ok(RawKeyRangeProof {
            watermark: watermark.location,
            entries,
            start_proof,
        })
    }

    async fn load_current_boundary_metadata(
        session: &ReadSession,
        location: Location<F>,
    ) -> Result<CurrentBoundaryMetadata<H::Digest>, QmdbError> {
        let Some(bytes) = session.get(&encode_current_meta_key(location)).await? else {
            return Err(QmdbError::CurrentBoundaryStateMissing {
                location: location.as_u64(),
            });
        };
        decode_current_boundary_metadata::<H::Digest>(
            bytes.as_ref(),
            format!("current boundary metadata at {location}"),
        )
    }

    async fn load_current_boundary_root(
        session: &ReadSession,
        location: Location<F>,
    ) -> Result<H::Digest, QmdbError> {
        Ok(Self::load_current_boundary_metadata(session, location)
            .await?
            .root)
    }

    async fn load_ops_root_witness(
        session: &ReadSession,
        location: Location<F>,
    ) -> Result<Option<OpsRootWitness<F, H::Digest>>, QmdbError> {
        let Some(bytes) = session.get(&encode_ops_root_witness_key(location)).await? else {
            return Ok(None);
        };
        OpsRootWitness::<F, H::Digest>::decode(Copying(bytes.as_ref()))
            .map(Some)
            .map_err(|e| {
                QmdbError::CorruptData(format!(
                    "current ops-root witness at {location} decode error: {e}"
                ))
            })
    }

    async fn compute_ops_root(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
    ) -> Result<H::Digest, QmdbError> {
        let inactive_peaks = Self::ops_inactive_peaks_at(session, op_cfg, watermark).await?;
        core::compute_ops_root::<F, H>(session, watermark, inactive_peaks).await
    }

    async fn proof_bitmap(
        session: &ReadSession,
        watermark: Location<F>,
        inactivity_floor: Location<F>,
        location: Option<Location<F>>,
    ) -> Result<ProofBitmap<N>, QmdbError> {
        let metadata = Self::load_current_boundary_metadata(session, watermark).await?;
        ProofBitmap::load(watermark, metadata.pruned_chunks, location, |chunk| {
            Self::load_bitmap_chunk_with_floor(session, watermark, inactivity_floor, chunk)
        })
        .await
    }

    async fn build_current_range_proof(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
        start_location: Location<F>,
        end_location_exclusive: Location<F>,
    ) -> Result<RangeProof<F, H::Digest>, QmdbError> {
        let inactivity_floor = Self::load_inactivity_floor_at(session, op_cfg, watermark).await?;
        let status = Self::proof_bitmap(session, watermark, inactivity_floor, None).await?;
        let storage = KvCurrentStorage::<F, H, N> {
            session,
            watermark,
            pruned_chunks: status.pruned_chunks as u64,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        RangeProof::new::<H, _, N>(
            &status,
            &storage,
            inactivity_floor,
            start_location..end_location_exclusive,
            Self::compute_ops_root(session, op_cfg, watermark).await?,
        )
        .await
        .map_err(crate::error::current_proof_error)
    }

    async fn build_current_operation_proof(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
        location: Location<F>,
    ) -> Result<OperationProof<F, H::Digest, N>, QmdbError> {
        core::require_batch_boundary(session, watermark).await?;
        let inactivity_floor = Self::load_inactivity_floor_at(session, op_cfg, watermark).await?;
        let status =
            Self::proof_bitmap(session, watermark, inactivity_floor, Some(location)).await?;
        let storage = KvCurrentStorage::<F, H, N> {
            session,
            watermark,
            pruned_chunks: status.pruned_chunks as u64,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        OperationProof::new::<H, _>(
            &status,
            &storage,
            inactivity_floor,
            location,
            Self::compute_ops_root(session, op_cfg, watermark).await?,
        )
        .await
        .map_err(crate::error::current_proof_error)
    }

    async fn load_inactivity_floor_at(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
    ) -> Result<Location<F>, QmdbError> {
        match Self::load_operation_at(session, op_cfg, watermark).await? {
            ordered::Operation::CommitFloor(_, floor) => Ok(floor),
            _ => Err(QmdbError::CorruptData(format!(
                "expected CommitFloor at watermark {watermark}"
            ))),
        }
    }

    async fn load_ops_inactivity_floor_at(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
    ) -> Result<Location<F>, QmdbError> {
        let operation = Self::load_operation_at(session, op_cfg, watermark).await?;
        Self::load_ops_inactivity_floor_from(session, op_cfg, watermark, operation).await
    }

    async fn load_ops_inactivity_floor_from(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
        mut operation: ordered::Operation<F, K, E>,
    ) -> Result<Location<F>, QmdbError> {
        let mut location = watermark;
        loop {
            if let ordered::Operation::CommitFloor(_, floor) = operation {
                return Ok(floor);
            }
            if *location == 0 {
                return Err(QmdbError::CorruptData(format!(
                    "no CommitFloor found at or before watermark {watermark}"
                )));
            }
            location -= 1;
            operation = Self::load_operation_at(session, op_cfg, location).await?;
        }
    }

    async fn ops_inactive_peaks_at(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
    ) -> Result<usize, QmdbError> {
        let inactivity_floor =
            Self::load_ops_inactivity_floor_at(session, op_cfg, watermark).await?;
        core::inactive_peaks(watermark, inactivity_floor)
    }

    async fn load_bitmap_chunk_with_floor(
        session: &ReadSession,
        watermark: Location<F>,
        inactivity_floor: Location<F>,
        chunk_index: u64,
    ) -> Result<[u8; N], QmdbError> {
        let start = encode_chunk_key(chunk_index, Location::<F>::new(0));
        let end = encode_chunk_key(chunk_index, watermark);
        let rows = session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        let mut chunk = match rows.into_iter().next() {
            Some((_, bytes)) => <[u8; N]>::decode(Copying(bytes.as_ref())).map_err(|e| {
                QmdbError::CorruptData(format!("bitmap chunk {chunk_index} decode error: {e}"))
            })?,
            None => {
                return Err(QmdbError::CorruptData(format!(
                    "missing bitmap chunk {chunk_index} at watermark {watermark}"
                )));
            }
        };
        clear_below_floor::<F, N>(&mut chunk, chunk_index, inactivity_floor);
        Ok(chunk)
    }

    async fn load_bitmap_chunks(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
        start_location: Location<F>,
        end_location_exclusive: Location<F>,
    ) -> Result<Vec<[u8; N]>, QmdbError> {
        let floor = Self::load_inactivity_floor_at(session, op_cfg, watermark).await?;
        let start_chunk = chunk_index_for_location::<F, N>(start_location);
        let end_chunk = chunk_index_for_location::<F, N>(end_location_exclusive - 1);
        futures::future::try_join_all((start_chunk..=end_chunk).map(|chunk_index| {
            Self::load_bitmap_chunk_with_floor(session, watermark, floor, chunk_index)
        }))
        .await
    }

    async fn load_operation_at(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        location: Location<F>,
    ) -> Result<ordered::Operation<F, K, E>, QmdbError> {
        let bytes = core::load_operation_bytes_at(session, location).await?;
        Self::decode_operation(op_cfg, location, &bytes)
    }

    async fn load_operation_range(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        start_location: Location<F>,
        end_location_exclusive: Location<F>,
    ) -> Result<Vec<ordered::Operation<F, K, E>>, QmdbError> {
        core::load_operation_bytes_range(session, start_location, end_location_exclusive)
            .await?
            .into_iter()
            .enumerate()
            .map(|(offset, bytes)| {
                Self::decode_operation(op_cfg, start_location + offset as u64, &bytes)
            })
            .collect()
    }
}

fn verified_key_value<D: commonware_cryptography::Digest, Op, F: Graftable, const N: usize>(
    raw: RawKeyValueProof<D, Op, N, F>,
) -> VerifiedKeyValue<D, Op, F> {
    VerifiedKeyValue {
        root: raw.root,
        location: raw.proof.loc,
        operation: raw.operation,
    }
}
