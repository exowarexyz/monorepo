use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use commonware_codec::{Codec, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::mmr::{
    self,
    iterator::{PathIterator, PeakIterator},
    Location, Position, StandardHasher,
};
use commonware_storage::qmdb::{
    any::ordered::variable::Operation as QmdbOperation, operation::Key as QmdbKey,
};

use crate::codec::{
    bitmap_chunk_bits, chunk_index_for_location, grafting_height_for, ops_to_grafted_pos,
    position_height,
};
use crate::error::QmdbError;
use crate::CurrentBoundaryState;

fn chunk_idx_to_ops_pos(chunk_idx: u64, grafting_height: u32) -> Position {
    let first_leaf_loc = Location::new(chunk_idx << grafting_height);
    let first_leaf_pos = Position::try_from(first_leaf_loc).expect("chunk_idx_to_ops_pos overflow");
    Position::new(*first_leaf_pos + (1u64 << (grafting_height + 1)) - 2)
}

fn grafted_to_ops_pos(grafted_pos: Position, grafting_height: u32) -> Position {
    let grafted_height = position_height(grafted_pos);
    let leftmost_grafted_leaf_pos = grafted_pos + 2 - (1u64 << (grafted_height + 1));
    let chunk_idx = *Location::try_from(leftmost_grafted_leaf_pos)
        .expect("leftmost leaf is not a valid grafted leaf");
    let ops_leaf_loc = chunk_idx << grafting_height;
    let ops_leaf_pos =
        Position::try_from(Location::new(ops_leaf_loc)).expect("ops leaf loc overflow");
    let ops_height = grafted_height + grafting_height;
    Position::new(*ops_leaf_pos + (1u64 << (ops_height + 1)) - 2)
}

/// Recover the ordered current-boundary delta for one batch from local proof
/// material emitted by a Commonware `current::ordered::Db`.
///
/// This is the bridge between a caller-owned local Commonware current DB and
/// [`crate::OrderedWriter`]. Callers apply a batch locally, then use this
/// function to recover the exact versioned current-state rows that must be
/// uploaded for that batch boundary:
///
/// - `root`: the local current DB root after applying `operations`
/// - `chunks`: only the bitmap chunks whose contents changed at this boundary
/// - `grafted_nodes`: only the complete-chunk grafted nodes whose digests
///   changed at this boundary
///
/// `previous_operations` and `operations` are the cumulative ordered-op logs
/// before and after one finalized local batch respectively, not just the delta
/// batch itself. In the intended flow `operations` therefore includes the
/// new batch's appended `CommitFloor`, and `previous_operations` is the exact
/// cumulative prefix immediately before that batch was applied.
///
/// This function is not meant for arbitrary diffs between unrelated op slices;
/// it assumes the caller is recovering the boundary rows for exactly one newly
/// applied local batch.
///
/// `prove_at(location)` must return a current range proof plus the bitmap
/// chunk for that exact `location`, taken from the same local DB state as
/// `root`.
///
/// The returned [`CurrentBoundaryState`] can be passed directly to
/// [`crate::OrderedWriter::prepare_upload`].
///
/// TODO: replace this proof-driven recovery path with a thin adapter over
/// `commonware_storage::qmdb::current::batch::MerkleizedBatch` once upstream
/// exposes the bitmap-chunk and grafted-subtree deltas needed to publish one
/// batch boundary directly.
pub async fn recover_boundary_state<H, K, V, const N: usize, F, Fut>(
    previous_operations: Option<&[QmdbOperation<K, V>]>,
    operations: &[QmdbOperation<K, V>],
    root: H::Digest,
    mut prove_at: F,
) -> Result<CurrentBoundaryState<H::Digest, N>, QmdbError>
where
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    QmdbOperation<K, V>: Encode,
    F: FnMut(Location) -> Fut,
    Fut: Future<Output = Result<(mmr::Proof<H::Digest>, [u8; N]), QmdbError>>,
{
    if operations.is_empty() {
        return Err(QmdbError::EmptyBatch);
    }

    let previous_len = previous_operations.map_or(0usize, |ops| ops.len());
    if previous_len >= operations.len() {
        return Err(QmdbError::CorruptData(format!(
            "current operations length {} must exceed previous length {}",
            operations.len(),
            previous_len
        )));
    }
    validate_recovery_input(previous_operations, operations)?;

    let changed_chunks = changed_chunk_representatives::<K, V, N>(previous_operations, operations);
    let complete_chunks = operations.len() / bitmap_chunk_bits::<N>() as usize;
    let mmr_size = Position::try_from(Location::new(operations.len() as u64))
        .map_err(|e| QmdbError::CorruptData(format!("invalid current proof leaf count: {e}")))?;
    let grafting_height = grafting_height_for::<N>();

    let mut chunks = BTreeMap::<u64, [u8; N]>::new();
    let mut grafted_nodes = BTreeMap::<Position, H::Digest>::new();

    for (chunk_index, location) in changed_chunks {
        let (proof, chunk) = prove_at(location).await?;
        chunks.entry(chunk_index).or_insert(chunk);

        if chunk_index as usize >= complete_chunks {
            continue;
        }

        let operation = operations.get(*location as usize).ok_or_else(|| {
            QmdbError::CorruptData(format!(
                "missing operation at location {location} in current boundary input"
            ))
        })?;
        let elements = [operation.encode().to_vec()];
        let chunk_refs = vec![chunk.as_ref()];
        let mut verifier = ProofVerifier::<H>::new(grafting_height, chunk_index, chunk_refs);
        let mut collected = Vec::new();
        proof
            .reconstruct_peak_digests(&mut verifier, &elements, location, Some(&mut collected))
            .map_err(|e| {
                QmdbError::CorruptData(format!(
                    "failed to reconstruct current proof digests for location {location}: {e}"
                ))
            })?;
        let digest_map: BTreeMap<Position, H::Digest> = collected.into_iter().collect();

        for position in changed_grafted_positions_for_chunk(chunk_index, mmr_size, grafting_height)?
        {
            let Some(digest) = digest_map.get(&position).copied() else {
                return Err(QmdbError::CorruptData(format!(
                    "missing grafted digest at position {position} for chunk {chunk_index}"
                )));
            };
            grafted_nodes.insert(position, digest);
        }
    }

    Ok(CurrentBoundaryState {
        root,
        chunks: chunks.into_iter().collect(),
        grafted_nodes: grafted_nodes.into_iter().collect(),
    })
}

fn validate_recovery_input<K, V>(
    previous_operations: Option<&[QmdbOperation<K, V>]>,
    operations: &[QmdbOperation<K, V>],
) -> Result<(), QmdbError>
where
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    QmdbOperation<K, V>: Encode,
{
    if !matches!(operations.last(), Some(QmdbOperation::CommitFloor(_, _))) {
        return Err(QmdbError::CorruptData(
            "recover_boundary_state requires operations to end with CommitFloor".into(),
        ));
    }

    let Some(previous) = previous_operations else {
        return Ok(());
    };

    for (index, (expected, actual)) in previous.iter().zip(operations.iter()).enumerate() {
        if expected.encode() != actual.encode() {
            return Err(QmdbError::CorruptData(format!(
                "recover_boundary_state requires previous_operations to be an exact prefix of operations; mismatch at location {index}"
            )));
        }
    }

    let delta = &operations[previous.len()..];
    let commit_count = delta
        .iter()
        .filter(|operation| matches!(operation, QmdbOperation::CommitFloor(_, _)))
        .count();
    if commit_count != 1 {
        return Err(QmdbError::CorruptData(format!(
            "recover_boundary_state requires exactly one CommitFloor in the appended batch delta, found {commit_count}"
        )));
    }

    if !matches!(delta.last(), Some(QmdbOperation::CommitFloor(_, _))) {
        return Err(QmdbError::CorruptData(
            "recover_boundary_state requires the appended batch delta to end with CommitFloor"
                .into(),
        ));
    }

    Ok(())
}

fn changed_chunk_representatives<K, V, const N: usize>(
    previous_operations: Option<&[QmdbOperation<K, V>]>,
    operations: &[QmdbOperation<K, V>],
) -> BTreeMap<u64, Location>
where
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
{
    // The inactivity floor of the batch being recovered lives in the trailing
    // CommitFloor op. Chunks whose entire bit range is below this floor are
    // fully pruned by `current::Db` after `apply_batch`; we cannot serve a
    // proof for them and we do not need to -- `load_bitmap_chunk` folds all
    // below-floor bits to 0 deterministically at read time. Skip those chunks
    // here so we do not ask the local DB to prove a location it has discarded.
    let floor = match operations.last() {
        Some(QmdbOperation::CommitFloor(_, floor)) => *floor,
        _ => Location::new(0),
    };
    let chunk_bits = bitmap_chunk_bits::<N>();
    let floor_chunk = *floor / chunk_bits;
    let first_alive_location = floor_chunk.saturating_mul(chunk_bits);

    let previous_len = previous_operations.map_or(0usize, |ops| ops.len());
    let mut changed = BTreeMap::<u64, Location>::new();

    for raw_location in previous_len..operations.len() {
        let location = Location::new(raw_location as u64);
        if raw_location as u64 >= first_alive_location {
            changed
                .entry(chunk_index_for_location::<N>(location))
                .or_insert(location);
        }
    }

    let Some(previous) = previous_operations else {
        return changed;
    };

    // The previous batch's CommitFloor bit, floor-raise move clears, and
    // base-diff clears of still-present-but-below-floor locations are all
    // handled at read time via `load_bitmap_chunk`'s below-floor masking.
    // We only track touched-key representatives in chunks the server does
    // not already know how to fold (chunks straddling or above the floor).
    let mut touched_keys = operations[previous_len..]
        .iter()
        .filter_map(|operation| match operation {
            QmdbOperation::Update(update) => Some(update.key.as_ref().to_vec()),
            QmdbOperation::Delete(key) => Some(key.as_ref().to_vec()),
            QmdbOperation::CommitFloor(_, _) => None,
        })
        .collect::<BTreeSet<_>>();

    // Walk backwards only as far as the first alive chunk. Anything below
    // that is fully pruned locally and contributes nothing to the boundary,
    // so iterating it just wastes work on unmatchable brand-new keys still
    // sitting in `touched_keys`.
    for index in (0..previous.len()).rev() {
        if touched_keys.is_empty() || (index as u64) < first_alive_location {
            break;
        }
        let location = Location::new(index as u64);
        match &previous[index] {
            QmdbOperation::Update(update) => {
                if touched_keys.remove(update.key.as_ref()) {
                    changed
                        .entry(chunk_index_for_location::<N>(location))
                        .or_insert(location);
                }
            }
            QmdbOperation::Delete(key) => {
                touched_keys.remove(key.as_ref());
            }
            QmdbOperation::CommitFloor(_, _) => {}
        }
    }

    changed
}

fn changed_grafted_positions_for_chunk(
    chunk_index: u64,
    mmr_size: Position,
    grafting_height: u32,
) -> Result<Vec<Position>, QmdbError> {
    let leaf_ops_pos = chunk_idx_to_ops_pos(chunk_index, grafting_height);
    let (peak_pos, peak_height) = containing_peak(mmr_size, leaf_ops_pos).ok_or_else(|| {
        QmdbError::CorruptData(format!(
            "missing containing peak for chunk {chunk_index} at ops position {leaf_ops_pos}"
        ))
    })?;

    if peak_height < grafting_height {
        return Ok(Vec::new());
    }

    let grafted_leaf_pos = Position::try_from(Location::new(chunk_index))
        .expect("chunk index is a valid leaf location");
    let grafted_peak_pos = ops_to_grafted_pos(peak_pos, grafting_height);
    let grafted_peak_height = peak_height - grafting_height;

    let mut positions = vec![leaf_ops_pos];
    for (parent_grafted_pos, _) in
        PathIterator::new(grafted_leaf_pos, grafted_peak_pos, grafted_peak_height)
    {
        positions.push(grafted_to_ops_pos(parent_grafted_pos, grafting_height));
    }
    Ok(positions)
}

fn containing_peak(mmr_size: Position, position: Position) -> Option<(Position, u32)> {
    PeakIterator::new(mmr_size).find(|(peak_pos, height)| {
        let leftmost = *peak_pos + 2 - (1u64 << (height + 1));
        leftmost <= position && position <= *peak_pos
    })
}

fn ops_pos_to_chunk_idx(ops_pos: Position, grafting_height: u32) -> u64 {
    let leftmost_leaf_pos = *ops_pos + 2 - (1u64 << (grafting_height + 1));
    let location = Location::try_from(Position::new(leftmost_leaf_pos))
        .expect("ops_pos_to_chunk_idx expects a grafting-height position");
    *location >> grafting_height
}

// TODO: replace this local mirror with
// `commonware_storage::qmdb::current::grafting::Verifier` once upstream makes
// that verifier public (it is still `pub(super)` in commonware-storage
// v2026.3.0).
struct ProofVerifier<'a, H: Hasher> {
    inner: StandardHasher<H>,
    grafting_height: u32,
    chunks: Vec<&'a [u8]>,
    start_chunk_index: u64,
}

impl<'a, H: Hasher> ProofVerifier<'a, H> {
    fn new(grafting_height: u32, start_chunk_index: u64, chunks: Vec<&'a [u8]>) -> Self {
        Self {
            inner: StandardHasher::<H>::new(),
            grafting_height,
            chunks,
            start_chunk_index,
        }
    }
}

impl<H: Hasher> mmr::hasher::Hasher for ProofVerifier<'_, H> {
    type Digest = H::Digest;
    type Inner = H;

    fn leaf_digest(&mut self, pos: Position, element: &[u8]) -> Self::Digest {
        self.inner.leaf_digest(pos, element)
    }

    fn node_digest(
        &mut self,
        pos: Position,
        left: &Self::Digest,
        right: &Self::Digest,
    ) -> Self::Digest {
        match position_height(pos).cmp(&self.grafting_height) {
            std::cmp::Ordering::Less | std::cmp::Ordering::Greater => {
                self.inner.node_digest(pos, left, right)
            }
            std::cmp::Ordering::Equal => {
                let ops_subtree_root = self.inner.node_digest(pos, left, right);
                let chunk_idx = ops_pos_to_chunk_idx(pos, self.grafting_height);
                let Some(local_idx) = chunk_idx
                    .checked_sub(self.start_chunk_index)
                    .filter(|index| *index < self.chunks.len() as u64)
                    .map(|index| index as usize)
                else {
                    return ops_subtree_root;
                };
                let chunk = self.chunks[local_idx];
                if chunk.iter().all(|&byte| byte == 0) {
                    ops_subtree_root
                } else {
                    self.inner.inner().update(chunk);
                    self.inner.inner().update(&ops_subtree_root);
                    self.inner.inner().finalize()
                }
            }
        }
    }

    fn root<'a>(
        &mut self,
        leaves: Location,
        peak_digests: impl Iterator<Item = &'a Self::Digest>,
    ) -> Self::Digest {
        self.inner.root(leaves, peak_digests)
    }

    fn digest(&mut self, data: &[u8]) -> Self::Digest {
        self.inner.digest(data)
    }

    fn inner(&mut self) -> &mut Self::Inner {
        self.inner.inner()
    }

    fn fork(&self) -> impl mmr::hasher::Hasher<Digest = Self::Digest> {
        Self {
            inner: StandardHasher::<H>::new(),
            grafting_height: self.grafting_height,
            chunks: self.chunks.clone(),
            start_chunk_index: self.start_chunk_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::changed_chunk_representatives;
    use commonware_storage::mmr::Location;
    use commonware_storage::qmdb::any::ordered::{
        variable::Operation as TestOperation, Update as OrderedUpdate,
    };
    use std::collections::BTreeMap;

    fn update(key: &[u8], value: &[u8]) -> TestOperation<Vec<u8>, Vec<u8>> {
        TestOperation::Update(OrderedUpdate {
            key: key.to_vec(),
            value: value.to_vec(),
            next_key: Vec::new(),
        })
    }

    fn commit(floor: u64) -> TestOperation<Vec<u8>, Vec<u8>> {
        TestOperation::CommitFloor(None, Location::new(floor))
    }

    fn previous_ops() -> Vec<TestOperation<Vec<u8>, Vec<u8>>> {
        let mut ops = vec![commit(0)];
        for index in 1..8 {
            ops.push(update(
                format!("fill-{index}").as_bytes(),
                format!("value-{index}").as_bytes(),
            ));
        }
        ops.push(update(b"target", b"old"));
        for index in 9..16 {
            ops.push(update(
                format!("fill-{index}").as_bytes(),
                format!("value-{index}").as_bytes(),
            ));
        }
        ops
    }

    #[test]
    fn rewrite_pulls_in_old_update_chunk_when_floor_preserves_it() {
        // No trailing CommitFloor -> floor defaults to 0 -> no filtering.
        // The rewrite of "target" pulls in its old-location chunk.
        let previous = previous_ops();
        let mut operations = previous.clone();
        operations.push(update(b"target", b"new"));

        let changed =
            changed_chunk_representatives::<Vec<u8>, Vec<u8>, 1>(Some(&previous), &operations);

        assert_eq!(
            changed,
            BTreeMap::from([(1u64, Location::new(8)), (2u64, Location::new(16)),])
        );
    }

    #[test]
    fn chunks_fully_below_new_floor_are_skipped() {
        // Trailing CommitFloor(floor=16) means chunks 0 and 1 (covering
        // locations 0..15) are fully below the floor and handled by read-time
        // masking; they must not appear in the changed-chunks map. Only chunk
        // 2 (straddling / above the floor) is tracked, and crucially the
        // representative for that chunk is an above-floor location so the
        // local DB can still serve a proof for it.
        let previous = previous_ops();
        let mut operations = previous.clone();
        operations.push(update(b"target", b"new"));
        operations.push(commit(16));

        let changed =
            changed_chunk_representatives::<Vec<u8>, Vec<u8>, 1>(Some(&previous), &operations);

        assert_eq!(changed, BTreeMap::from([(2u64, Location::new(16))]));
    }

    #[test]
    fn straddling_chunk_keeps_first_new_representative() {
        // With floor=18, chunks 0 and 1 (locations 0..15) are fully below and
        // skipped; chunk 2 (locations 16..23) straddles -- locations 16-17 are
        // below the floor, locations 18-23 are at/above. The local DB still
        // has chunk 2 intact (it is not fully pruned), so the filter operates
        // at chunk granularity and keeps chunk 2 with the first new-location
        // representative.
        let previous = previous_ops();
        let mut operations = previous.clone();
        operations.push(update(b"neighbor1", b"v"));
        operations.push(update(b"neighbor2", b"v"));
        operations.push(update(b"neighbor3", b"v"));
        operations.push(commit(18));

        let changed =
            changed_chunk_representatives::<Vec<u8>, Vec<u8>, 1>(Some(&previous), &operations);

        assert_eq!(changed, BTreeMap::from([(2u64, Location::new(16))]));
    }

    #[test]
    fn rejects_inputs_that_do_not_end_with_commit_floor() {
        let previous = previous_ops();
        let mut operations = previous.clone();
        operations.push(update(b"target", b"new"));

        let err =
            super::validate_recovery_input(Some(&previous), &operations).expect_err("must reject");
        assert!(
            err.to_string().contains("end with CommitFloor"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_delta_with_multiple_commit_floors() {
        let previous = previous_ops();
        let mut operations = previous.clone();
        operations.push(commit(16));
        operations.push(commit(17));

        let err =
            super::validate_recovery_input(Some(&previous), &operations).expect_err("must reject");
        assert!(
            err.to_string().contains("exactly one CommitFloor"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_non_prefix_previous_operations() {
        let previous = previous_ops();
        let mut operations = previous.clone();
        operations[3] = update(b"mutated", b"value");
        operations.push(commit(16));

        let err =
            super::validate_recovery_input(Some(&previous), &operations).expect_err("must reject");
        assert!(
            err.to_string().contains("exact prefix"),
            "unexpected error: {err}"
        );
    }
}
