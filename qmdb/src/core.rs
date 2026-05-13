use std::marker::PhantomData;
use std::time::Duration;

use commonware_codec::{Codec, Encode, Read as CodecRead};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::merkle::{
    hasher::Hasher as MerkleHasher, mem::Mem, Family, Graftable, Location, Position,
};
use commonware_storage::qmdb::{
    any::{ordered, unordered, value::ValueEncoding},
    current::grafting,
    operation::Key as QmdbKey,
};
use exoware_sdk::keys::Key;
use exoware_sdk::{ClientError, RangeMode, SerializableReadSession, StoreClient};

use crate::codec::{
    decode_digest, decode_operation_location_key, decode_update_location,
    decode_watermark_location, encode_chunk_key, encode_current_meta_key, encode_grafted_node_key,
    encode_node_key, encode_operation_key, encode_ops_root_witness_key, encode_presence_key,
    encode_update_key, encode_watermark_key, ensure_encoded_value_size, merkle_size_for_watermark,
    CurrentBoundaryMetadata, UpdateRow, WATERMARK_CODEC,
};
use crate::error::QmdbError;
use crate::VersionedValue;

const POST_INGEST_QUERY_RETRY_MAX_ATTEMPTS: usize = 6;
const POST_INGEST_QUERY_RETRY_INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const POST_INGEST_QUERY_RETRY_MAX_BACKOFF: Duration = Duration::from_millis(1_000);

pub(crate) fn is_transient_post_ingest_query_error(err: &QmdbError) -> bool {
    match err {
        QmdbError::Client(ClientError::Http(_)) => true,
        QmdbError::Client(err) => err.rpc_code().is_some_and(|code| {
            matches!(
                code,
                connectrpc::ErrorCode::Aborted
                    | connectrpc::ErrorCode::ResourceExhausted
                    | connectrpc::ErrorCode::Unavailable
            )
        }),
        _ => false,
    }
}

pub(crate) fn post_ingest_query_retry_backoff(attempt: usize) -> Duration {
    let exponent = (attempt.saturating_sub(1)).min(20) as u32;
    let factor = 1u128 << exponent;
    let base_ms = POST_INGEST_QUERY_RETRY_INITIAL_BACKOFF.as_millis();
    let capped_ms = base_ms
        .saturating_mul(factor)
        .min(POST_INGEST_QUERY_RETRY_MAX_BACKOFF.as_millis());
    Duration::from_millis(capped_ms.min(u64::MAX as u128) as u64)
}

pub(crate) async fn retry_transient_post_ingest_query<F, Fut, T>(mut op: F) -> Result<T, QmdbError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, QmdbError>>,
{
    let mut attempt = 1usize;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err)
                if attempt < POST_INGEST_QUERY_RETRY_MAX_ATTEMPTS
                    && is_transient_post_ingest_query_error(&err) =>
            {
                tokio::time::sleep(post_ingest_query_retry_backoff(attempt)).await;
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HistoricalOpsClientCore<'a, F: Family, D: Digest, K: Codec, V: Codec> {
    pub(crate) client: &'a StoreClient,
    pub(crate) update_row_cfg: (K::Cfg, V::Cfg),
    pub(crate) _marker: PhantomData<(F, D, K, V)>,
}

impl<'a, F: Family, D: Digest, K: Codec, V: Codec> HistoricalOpsClientCore<'a, F, D, K, V> {
    pub(crate) async fn writer_location_watermark(&self) -> Result<Option<Location<F>>, QmdbError> {
        retry_transient_post_ingest_query(|| {
            let session = self.client.create_session();
            async move { self.read_latest_watermark(&session).await }
        })
        .await
    }

    pub(crate) async fn read_latest_watermark(
        &self,
        session: &SerializableReadSession,
    ) -> Result<Option<Location<F>>, QmdbError> {
        let (start, end) = WATERMARK_CODEC.prefix_bounds();
        let rows = session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        match rows.into_iter().next() {
            Some((key, _)) => Ok(Some(decode_watermark_location(&key)?)),
            None => Ok(None),
        }
    }

    pub(crate) async fn require_published_watermark(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
    ) -> Result<(), QmdbError> {
        let available = self
            .read_latest_watermark(session)
            .await?
            .unwrap_or(Location::new(0));
        let watermark_exists = session
            .get(&encode_watermark_key(watermark))
            .await?
            .is_some();
        if available < watermark
            || (!watermark_exists && available == Location::new(0) && watermark == Location::new(0))
        {
            return Err(QmdbError::WatermarkTooLow {
                requested: watermark.as_u64(),
                available: available.as_u64(),
            });
        }
        Ok(())
    }

    pub(crate) async fn require_batch_boundary(
        &self,
        session: &SerializableReadSession,
        location: Location<F>,
    ) -> Result<(), QmdbError> {
        if session.get(&encode_presence_key(location)).await?.is_some() {
            Ok(())
        } else {
            Err(QmdbError::CurrentProofRequiresBatchBoundary {
                location: location.as_u64(),
            })
        }
    }

    pub(crate) async fn load_latest_update_row(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        key: &[u8],
    ) -> Result<Option<(Key, Vec<u8>)>, QmdbError> {
        let start = encode_update_key(key, Location::<F>::new(0))?;
        let end = encode_update_key(key, watermark)?;
        let rows = session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        Ok(rows
            .into_iter()
            .next()
            .map(|(key, value)| (key, value.to_vec())))
    }

    pub(crate) async fn compute_ops_root<H: Hasher<Digest = D>>(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
    ) -> Result<D, QmdbError> {
        let size = merkle_size_for_watermark(watermark)?;
        let leaves = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        let peak_positions: Vec<(Position<F>, u32)> = F::peaks(size).collect();
        let fetched = if peak_positions.is_empty() {
            std::collections::HashMap::new()
        } else {
            let peak_keys: Vec<Key> = peak_positions
                .iter()
                .map(|(pos, _)| encode_node_key(*pos))
                .collect();
            let peak_key_refs: Vec<&Key> = peak_keys.iter().collect();
            session
                .get_many(&peak_key_refs, peak_key_refs.len() as u32)
                .await?
                .collect()
                .await?
        };
        let mut peaks = Vec::with_capacity(peak_positions.len());
        for (peak_pos, _) in &peak_positions {
            let Some(bytes) = fetched.get(&encode_node_key(*peak_pos)) else {
                return Err(QmdbError::CorruptData(format!(
                    "missing Merkle peak node at position {peak_pos}"
                )));
            };
            peaks.push(decode_digest(
                bytes.as_ref(),
                format!("Merkle peak node at position {peak_pos}"),
            )?);
        }
        let hasher = commonware_storage::qmdb::hasher::<H>();
        hasher
            .root(leaves, 0, peaks.iter())
            .map_err(|e| QmdbError::CommonwareMerkle(e.to_string()))
    }

    pub(crate) async fn load_operation_bytes_at(
        &self,
        session: &SerializableReadSession,
        location: Location<F>,
    ) -> Result<Vec<u8>, QmdbError> {
        let Some(bytes) = session.get(&encode_operation_key(location)).await? else {
            return Err(QmdbError::CorruptData(format!(
                "missing operation row at location {location}"
            )));
        };
        Ok(bytes.to_vec())
    }

    pub(crate) async fn load_operation_bytes_range(
        &self,
        session: &SerializableReadSession,
        start_location: Location<F>,
        end_location_exclusive: Location<F>,
    ) -> Result<Vec<Vec<u8>>, QmdbError> {
        if start_location >= end_location_exclusive {
            return Ok(Vec::new());
        }
        let start = encode_operation_key(start_location);
        let end = encode_operation_key(end_location_exclusive - 1);
        let rows = session
            .range(
                &start,
                &end,
                (*end_location_exclusive - *start_location) as usize,
            )
            .await?;
        if rows.len() != (*end_location_exclusive - *start_location) as usize {
            return Err(QmdbError::CorruptData(format!(
                "expected {} operation rows in location range [{start_location}, {end_location_exclusive}), found {}",
                *end_location_exclusive - *start_location,
                rows.len()
            )));
        }
        let mut encoded = Vec::with_capacity(rows.len());
        for (offset, (key, value)) in rows.into_iter().enumerate() {
            let expected_location = start_location + offset as u64;
            let location = decode_operation_location_key(&key)?;
            if location != expected_location {
                return Err(QmdbError::CorruptData(format!(
                    "operation row order mismatch: expected {expected_location}, got {location}"
                )));
            }
            encoded.push(value.to_vec());
        }
        Ok(encoded)
    }

    pub(crate) async fn query_many_at<Q: AsRef<[u8]>>(
        &self,
        keys: &[Q],
        max_location: Location<F>,
    ) -> Result<Vec<Option<VersionedValue<K, V, F>>>, QmdbError> {
        let session = self.client.create_session();
        self.require_published_watermark(&session, max_location)
            .await?;

        let futs = keys.iter().map(|key| {
            let key_bytes = key.as_ref();
            async {
                let Some((row_key, row_value)) = self
                    .load_latest_update_row(&session, max_location, key_bytes)
                    .await?
                else {
                    return Ok(None);
                };
                let location = decode_update_location(&row_key)?;
                let decoded = <UpdateRow<K, V> as CodecRead>::read_cfg(
                    &mut row_value.as_ref(),
                    &self.update_row_cfg,
                )
                .map_err(|e| QmdbError::CorruptData(format!("update row decode: {e}")))?;
                Ok(Some(VersionedValue {
                    key: decoded.key,
                    location,
                    value: decoded.value,
                }))
            }
        });
        futures::future::join_all(futs).await.into_iter().collect()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedUpload {
    pub(crate) operation_count: u32,
    pub(crate) keyed_operation_count: u32,
    /// Op rows in location order. Values are canonical encoded bytes; writers
    /// feed references from here to `extend_merkle_from_peaks` without cloning.
    pub(crate) op_rows: Vec<(Key, Vec<u8>)>,
    /// Update-index rows (for keyed ops) plus the presence row. Order is
    /// opaque to the store — rows are indexed by key, not position.
    pub(crate) aux_rows: Vec<(Key, Vec<u8>)>,
}

impl PreparedUpload {
    /// Byte-slice view over the op rows for feeding to `extend_merkle_from_peaks`.
    pub(crate) fn op_bytes(&self) -> impl Iterator<Item = &[u8]> {
        self.op_rows.iter().map(|(_, v)| v.as_slice())
    }

    /// Consume the two row vectors into a single `Vec` for dispatch.
    pub(crate) fn into_all_rows(self) -> Vec<(Key, Vec<u8>)> {
        let mut rows = self.op_rows;
        rows.extend(self.aux_rows);
        rows
    }
}

impl PreparedUpload {
    pub(crate) fn build<
        F: Family,
        K: QmdbKey + Codec,
        V: Codec + Clone + Send + Sync,
        E: ValueEncoding<Value = V>,
    >(
        latest_location: Location<F>,
        operations: &[ordered::Operation<F, K, E>],
    ) -> Result<Self, QmdbError>
    where
        ordered::Operation<F, K, E>: Encode,
    {
        Self::build_from_ops(latest_location, operations, |op| match op {
            ordered::Operation::Update(ordered::Update {
                key,
                value,
                next_key: _,
            }) => Some((key, Some(value))),
            ordered::Operation::Delete(key) => Some((key, None)),
            ordered::Operation::CommitFloor(_, _) => None,
        })
    }

    pub(crate) fn build_unordered<
        F: Family,
        K: QmdbKey + Codec,
        V: Codec + Clone + Send + Sync,
        E: ValueEncoding<Value = V>,
    >(
        latest_location: Location<F>,
        operations: &[unordered::Operation<F, K, E>],
    ) -> Result<Self, QmdbError>
    where
        unordered::Operation<F, K, E>: Encode,
    {
        Self::build_from_ops(latest_location, operations, |op| match op {
            unordered::Operation::Update(unordered::Update(key, value)) => Some((key, Some(value))),
            unordered::Operation::Delete(key) => Some((key, None)),
            unordered::Operation::CommitFloor(_, _) => None,
        })
    }

    fn build_from_ops<F: Family, Op: Encode, K: AsRef<[u8]> + Encode + Clone, V: Encode + Clone>(
        latest_location: Location<F>,
        operations: &[Op],
        extract_keyed: impl Fn(&Op) -> Option<(&K, Option<&V>)>,
    ) -> Result<Self, QmdbError> {
        let mut op_rows = Vec::<(Key, Vec<u8>)>::with_capacity(operations.len());
        let mut aux_rows = Vec::<(Key, Vec<u8>)>::with_capacity(operations.len() + 1);
        let mut keyed_operation_count = 0u32;
        let count_u64 = operations.len() as u64;
        let Some(start_location) = latest_location
            .checked_add(1)
            .and_then(|n| n.checked_sub(count_u64))
        else {
            return Err(QmdbError::InvalidLocationRange {
                start_location: 0,
                latest_location: latest_location.as_u64(),
                count: operations.len(),
            });
        };

        for (index, op) in operations.iter().enumerate() {
            let location = start_location + index as u64;
            let encoded = op.encode().to_vec();
            ensure_encoded_value_size(encoded.len())?;
            op_rows.push((encode_operation_key(location), encoded));

            if let Some((key, value)) = extract_keyed(op) {
                keyed_operation_count += 1;
                let update_row = UpdateRow {
                    key: key.clone(),
                    value: value.cloned(),
                };
                aux_rows.push((
                    encode_update_key(key.as_ref(), location)?,
                    update_row.encode().to_vec(),
                ));
            }
        }

        let operation_count = u32::try_from(operations.len()).map_err(|_| {
            QmdbError::CorruptData("operation count does not fit in u32".to_string())
        })?;
        aux_rows.push((encode_presence_key(latest_location), Vec::new()));

        Ok(Self {
            operation_count,
            keyed_operation_count,
            op_rows,
            aux_rows,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedCurrentBoundaryUpload {
    pub(crate) rows: Vec<(Key, Vec<u8>)>,
}

impl PreparedCurrentBoundaryUpload {
    pub(crate) fn build<F: Graftable, D: Digest, const N: usize>(
        latest_location: Location<F>,
        current_boundary: &crate::CurrentBoundaryState<D, N, F>,
    ) -> Result<Self, QmdbError> {
        let mut rows = Vec::with_capacity(
            2 + current_boundary.chunks.len() + current_boundary.grafted_nodes.len(),
        );
        rows.push((
            encode_current_meta_key(latest_location),
            CurrentBoundaryMetadata {
                root: current_boundary.root,
                pruned_chunks: current_boundary.pruned_chunks,
            }
            .encode()
            .to_vec(),
        ));
        rows.push((
            encode_ops_root_witness_key(latest_location),
            current_boundary.ops_root_witness.encode().to_vec(),
        ));
        for &(chunk_index, chunk) in &current_boundary.chunks {
            rows.push((
                encode_chunk_key(chunk_index, latest_location),
                chunk.encode().to_vec(),
            ));
        }
        for &(ops_position, digest) in &current_boundary.grafted_nodes {
            let grafted_position =
                grafting::ops_to_grafted_pos::<F>(ops_position, grafting::height::<N>());
            rows.push((
                encode_grafted_node_key(grafted_position, latest_location),
                digest.encode().to_vec(),
            ));
        }
        Ok(Self { rows })
    }
}

/// Pure Merkle-family extension: from existing peaks + size, fold
/// `encoded_operations` into new leaves and compute the resulting peaks, size,
/// root, and the full list of newly-created nodes the caller can persist.
pub(crate) struct MerkleExtension<F: Family, D: Digest> {
    pub(crate) size: Position<F>,
    pub(crate) peaks: Vec<(Position<F>, u32, D)>,
    pub(crate) root: D,
    pub(crate) new_nodes: Vec<(Position<F>, D)>,
}

pub(crate) fn extend_merkle_from_peaks<F: Family, H: Hasher, Op: AsRef<[u8]>>(
    peaks: Vec<(Position<F>, u32, H::Digest)>,
    previous_size: Position<F>,
    encoded_operations: impl IntoIterator<Item = Op>,
) -> Result<MerkleExtension<F, H::Digest>, QmdbError> {
    let previous_leaves = Location::<F>::try_from(previous_size)
        .map_err(|e| QmdbError::CorruptData(format!("invalid incremental ops size: {e}")))?;
    let mut peak_map: std::collections::BTreeMap<Position<F>, (u32, H::Digest)> = peaks
        .into_iter()
        .map(|(pos, height, digest)| (pos, (height, digest)))
        .collect();
    let pinned_nodes = F::peaks(previous_size)
        .map(|(pos, height)| {
            let (actual_height, digest) = peak_map.remove(&pos).ok_or_else(|| {
                QmdbError::CorruptData(format!(
                    "missing peak {pos} while extending merkle tree"
                ))
            })?;
            if actual_height != height {
                return Err(QmdbError::CorruptData(format!(
                    "peak {pos} height mismatch while extending merkle tree: expected {height}, got {actual_height}"
                )));
            }
            Ok(digest)
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    if let Some((extra_pos, _)) = peak_map.first_key_value() {
        return Err(QmdbError::CorruptData(format!(
            "unexpected peak {extra_pos} while extending merkle tree"
        )));
    }

    let hasher = commonware_storage::qmdb::hasher::<H>();
    let mem = Mem::<F, H::Digest>::from_components(Vec::new(), previous_leaves, pinned_nodes)
        .map_err(|e| QmdbError::CommonwareMerkle(e.to_string()))?;
    let mut batch = mem.new_batch();
    for encoded in encoded_operations {
        let encoded = encoded.as_ref();
        ensure_encoded_value_size(encoded.len())?;
        batch = batch.add(&hasher, encoded);
    }

    let batch = batch.merkleize(&mem, &hasher);
    let size = batch.size();
    let new_nodes = (*previous_size..*size)
        .map(|raw_pos| {
            let pos = Position::new(raw_pos);
            let digest = batch.get_node(pos).ok_or_else(|| {
                QmdbError::CorruptData(format!("missing node {pos} after merkle extension"))
            })?;
            Ok((pos, digest))
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    let peaks = F::peaks(size)
        .map(|(pos, height)| {
            let digest = batch
                .get_node(pos)
                .or_else(|| mem.get_node(pos))
                .ok_or_else(|| {
                    QmdbError::CorruptData(format!("missing peak {pos} after merkle extension"))
                })?;
            Ok((pos, height, digest))
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    let root = batch
        .root(&mem, &hasher, 0)
        .map_err(|e| QmdbError::CommonwareMerkle(e.to_string()))?;
    Ok(MerkleExtension {
        size,
        peaks,
        root,
        new_nodes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Sha256;
    use commonware_storage::merkle::mmr;

    #[test]
    fn current_boundary_upload_keys_grafted_nodes_by_grafted_space_position() {
        let mut hasher = Sha256::default();
        hasher.update(b"grafted-node");
        let digest = hasher.finalize();

        let ops_position = Position::new(2046);
        let latest_location = Location::new(1024);
        let boundary = crate::CurrentBoundaryState::<_, 32, mmr::Family> {
            root: digest,
            pruned_chunks: 0,
            ops_root_witness: commonware_storage::qmdb::current::proof::OpsRootWitness {
                grafted_root: digest,
                pending_chunk_digest:
                    <mmr::Family as commonware_storage::merkle::Graftable>::PendingChunk::<
                        commonware_cryptography::sha256::Digest,
                    >::try_from(None::<commonware_cryptography::sha256::Digest>)
                    .expect("MMR has no pending chunk"),
                partial_chunk: None,
            },
            chunks: Vec::new(),
            grafted_nodes: vec![(ops_position, digest)],
        };

        let upload =
            PreparedCurrentBoundaryUpload::build(latest_location, &boundary).expect("upload");
        let grafted_position = grafting::ops_to_grafted_pos(ops_position, grafting::height::<32>());
        let expected_key = encode_grafted_node_key(grafted_position, latest_location);
        let stale_ops_key = encode_grafted_node_key(ops_position, latest_location);

        assert!(upload
            .rows
            .iter()
            .any(|(key, value)| key == &expected_key && value.as_slice() == digest.as_ref()));
        assert!(!upload.rows.iter().any(|(key, _)| key == &stale_ops_key));
    }
}
