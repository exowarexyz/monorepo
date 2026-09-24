#[cfg(test)]
mod tests;

use commonware_codec::{Codec, Decode};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_storage::merkle::{
    hasher::Hasher as MerkleHasher, mem::Mem, Family, Location, Position,
};
use crossbeam_utils::atomic::AtomicCell;
use exoware_sdk::keys::Key;
use exoware_sdk::{RangeMode, ReadSession};

use crate::codec::{
    decode_digest, decode_operation_location_key, decode_update_location,
    decode_watermark_location, encode_node_key, encode_operation_key, encode_presence_key,
    encode_update_key, ensure_encoded_value_size, merkle_size_for_watermark,
    op_count_for_watermark, WATERMARK_PREFIX,
};
use crate::error::QmdbError;
use crate::VersionedValue;

pub(crate) async fn read_latest_watermark_with_sequence<F: Family>(
    session: &ReadSession,
) -> Result<(Option<Location<F>>, u64), QmdbError> {
    let (start, end) = WATERMARK_PREFIX.bounds();
    let mut stream = session
        .range_stream_with_mode(&start, &end, 1, 1, RangeMode::Reverse)
        .await?;
    let chunk = stream.next_chunk().await?.ok_or_else(|| {
        QmdbError::CorruptData("watermark query returned no response frame".to_string())
    })?;
    stream.collect().await?;
    let sequence = chunk
        .detail
        .map(|detail| detail.sequence_number)
        .ok_or_else(|| {
            QmdbError::CorruptData("watermark query omitted Store sequence metadata".to_string())
        })?;
    let watermark = chunk
        .rows
        .into_iter()
        .next()
        .map(|(key, _)| decode_watermark_location(&key))
        .transpose()?;
    Ok((watermark, sequence))
}

/// Decodes a loaded operation and verifies that it matches the requested key.
pub(crate) trait LatestValueResolver<F: Family, K: Codec, V: Codec> {
    fn resolve_latest_value(
        &self,
        location: Location<F>,
        requested_key: &[u8],
        op_bytes: Vec<u8>,
    ) -> Result<VersionedValue<K, V, F>, QmdbError>;
}

/// A requested watermark and the minimum Store sequence that makes it readable.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PublishedWatermark<F: Family> {
    pub(crate) location: Location<F>,
    pub(crate) sequence_number: u64,
}

/// Caches the greatest published QMDB watermark and the store sequence returned
/// by the publication lookup that observed it.
///
/// Reads at that watermark or an earlier one can skip publication lookup, given
/// their data and proof reads must require at least the cached sequence as `min_sequence_number`.
///
/// Share a cache only between clients for the same store and namespace.
#[derive(Debug)]
pub(crate) struct PublicationCache<F: Family> {
    published: AtomicCell<Option<PublishedWatermark<F>>>,
    refresh_gate: tokio::sync::Mutex<()>,
}

impl<F: Family> Default for PublicationCache<F> {
    fn default() -> Self {
        Self {
            published: AtomicCell::new(None),
            refresh_gate: tokio::sync::Mutex::new(()),
        }
    }
}

impl<F: Family> PublicationCache<F> {
    // Callers must hold refresh_gate so concurrent refreshes cannot overwrite newer evidence.
    fn remember(&self, available: Option<Location<F>>, sequence: u64) {
        let Some(location) = available else {
            return;
        };
        let published = self.published.load();
        if published.as_ref().is_none_or(|known| {
            location > known.location
                || (location == known.location && sequence < known.sequence_number)
        }) {
            self.published.store(Some(PublishedWatermark {
                location,
                sequence_number: sequence,
            }));
        }
    }

    fn published_sequence(&self, watermark: Location<F>) -> Option<u64> {
        self.published
            .load()
            .filter(|known| known.location >= watermark)
            .map(|known| known.sequence_number)
    }

    pub(crate) async fn refresh(
        &self,
        session: &ReadSession,
    ) -> Result<Option<Location<F>>, QmdbError> {
        let _gate = self.refresh_gate.lock().await;
        let (available, sequence) = read_latest_watermark_with_sequence(session).await?;
        self.remember(available, sequence);
        Ok(self.published.load().map(|known| known.location))
    }

    pub(crate) async fn require(
        &self,
        session: &ReadSession,
        watermark: Location<F>,
    ) -> Result<PublishedWatermark<F>, QmdbError> {
        if let Some(sequence) = self.published_sequence(watermark) {
            return Ok(PublishedWatermark {
                location: watermark,
                sequence_number: sequence,
            });
        }

        let _gate = self.refresh_gate.lock().await;
        if let Some(sequence) = self.published_sequence(watermark) {
            return Ok(PublishedWatermark {
                location: watermark,
                sequence_number: sequence,
            });
        }

        let (available, sequence) = read_latest_watermark_with_sequence(session).await?;
        self.remember(available, sequence);
        let published = self.published.load();
        match published.as_ref() {
            Some(known) if known.location >= watermark => Ok(PublishedWatermark {
                location: watermark,
                sequence_number: known.sequence_number,
            }),
            _ => Err(QmdbError::WatermarkTooLow {
                requested: watermark.as_u64(),
                available: published
                    .as_ref()
                    .map_or(0, |known| known.location.as_u64()),
            }),
        }
    }
}

pub(crate) async fn require_batch_boundary<F: Family>(
    session: &ReadSession,
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

pub(crate) async fn load_latest_update_row<F: Family>(
    session: &ReadSession,
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

/// Loads each key's latest operation at `watermark` and decodes it with `resolver`.
/// The session must require the publication sequence.
pub(crate) async fn query_many_at<F, K, V, Q, R>(
    session: &ReadSession,
    keys: &[Q],
    watermark: Location<F>,
    resolver: &R,
) -> Result<Vec<Option<VersionedValue<K, V, F>>>, QmdbError>
where
    F: Family,
    K: Codec,
    V: Codec,
    Q: AsRef<[u8]>,
    R: LatestValueResolver<F, K, V>,
{
    let futs = keys.iter().map(|key| {
        let key_bytes = key.as_ref();
        async move {
            let Some((row_key, _row_value)) =
                load_latest_update_row(session, watermark, key_bytes).await?
            else {
                return Ok(None);
            };
            let location = decode_update_location(&row_key)?;
            let op_bytes = load_operation_bytes_at(session, location).await?;
            Ok(Some(
                resolver.resolve_latest_value(location, key_bytes, op_bytes)?,
            ))
        }
    });
    futures::future::join_all(futs).await.into_iter().collect()
}

pub(crate) async fn compute_ops_root<F: Family, H: Hasher>(
    session: &ReadSession,
    watermark: Location<F>,
    inactive_peaks: usize,
) -> Result<H::Digest, QmdbError> {
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
        .root(leaves, inactive_peaks, peaks.iter())
        .map_err(|e| QmdbError::CommonwareMerkle(e.to_string()))
}

pub(crate) fn inactive_peaks<F: Family>(
    watermark: Location<F>,
    inactivity_floor: Location<F>,
) -> Result<usize, QmdbError> {
    Ok(F::inactive_peaks(
        op_count_for_watermark(watermark)?,
        inactivity_floor,
    ))
}

pub(crate) async fn load_operation_at<F: Family, Op>(
    session: &ReadSession,
    location: Location<F>,
    cfg: &Op::Cfg,
) -> Result<Op, QmdbError>
where
    Op: Decode,
{
    let bytes = load_operation_bytes_at(session, location).await?;
    decode_operation_at::<F, Op>(&bytes, location, cfg)
}

pub(crate) fn decode_operation_at<F: Family, Op: Decode>(
    bytes: &[u8],
    location: Location<F>,
    cfg: &Op::Cfg,
) -> Result<Op, QmdbError> {
    Op::decode_cfg(bytes, cfg).map_err(|e| {
        QmdbError::CorruptData(format!(
            "failed to decode authenticated operation at location {location}: {e}"
        ))
    })
}

pub(crate) async fn load_operation_bytes_at<F: Family>(
    session: &ReadSession,
    location: Location<F>,
) -> Result<Vec<u8>, QmdbError> {
    let Some(bytes) = session.get(&encode_operation_key(location)).await? else {
        return Err(QmdbError::CorruptData(format!(
            "missing operation row at location {location}"
        )));
    };
    Ok(bytes.to_vec())
}

pub(crate) async fn load_operation_bytes_range<F: Family>(
    session: &ReadSession,
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

/// Extend a pinned prefix with encoded operations, returning the root, frontier,
/// and every new node needed to serve proofs.
pub(crate) struct MerkleExtension<F: Family, D: Digest> {
    pub(crate) size: Position<F>,
    pub(crate) peaks: Vec<(Position<F>, u32, D)>,
    pub(crate) root: D,
    pub(crate) new_nodes: Vec<(Position<F>, D)>,
}

pub(crate) fn extend_merkle_from_pinned_nodes<F, H, S, I>(
    pinned_nodes: Vec<H::Digest>,
    pruning_boundary: Location<F>,
    encoded_operations: I,
    inactive_peaks: usize,
    strategy: &S,
) -> Result<MerkleExtension<F, H::Digest>, QmdbError>
where
    F: Family,
    H: Hasher,
    S: Strategy,
    I: IntoIterator + Send,
    I::Item: AsRef<[u8]> + Send,
    I::IntoIter: Send,
{
    let previous_size = Position::try_from(pruning_boundary)
        .map_err(|e| QmdbError::CorruptData(format!("invalid incremental ops size {e}")))?;

    let hasher = commonware_storage::qmdb::hasher::<H>();
    let mem = Mem::<F, H::Digest>::from_components(Vec::new(), pruning_boundary, pinned_nodes)
        .map_err(|e| QmdbError::CommonwareMerkle(e.to_string()))?;
    let leaf_digests = strategy.try_map_collect_vec(
        encoded_operations.into_iter().enumerate(),
        |(offset, encoded)| {
            let encoded = encoded.as_ref();
            ensure_encoded_value_size(encoded.len())?;
            let offset = u64::try_from(offset)
                .map_err(|_| QmdbError::CorruptData("operation offset exceeds u64".into()))?;
            let location = pruning_boundary
                .checked_add(offset)
                .ok_or_else(|| QmdbError::CorruptData("operation location overflow".into()))?;
            let position = Position::try_from(location).map_err(|e| {
                QmdbError::CorruptData(format!("invalid operation location {location}. {e}"))
            })?;
            Ok::<_, QmdbError>(hasher.leaf_digest(position, encoded))
        },
    )?;

    let batch = mem
        .new_batch_with_strategy(strategy.clone())
        .add_leaf_digests(leaf_digests);
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
        .root(&mem, &hasher, inactive_peaks)
        .map_err(|e| QmdbError::CommonwareMerkle(e.to_string()))?;
    Ok(MerkleExtension {
        size,
        peaks,
        root,
        new_nodes,
    })
}
