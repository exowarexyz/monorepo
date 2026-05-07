use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use commonware_codec::{Codec, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::merkle::{
    hasher::{Hasher as MerkleHasher, Standard as StandardHasher},
    Family, Graftable, Location, Position,
};
use commonware_storage::qmdb::{
    current::proof::RangeProof as CurrentRangeProof, operation::Operation as QmdbOperation,
};

use crate::codec::{
    bitmap_chunk_bits, chunk_index_for_location, grafting_height_for, ops_to_grafted_pos,
};
use crate::error::QmdbError;
use crate::CurrentBoundaryState;

fn chunk_idx_to_ops_pos<F: Graftable>(chunk_idx: u64, grafting_height: u32) -> Position<F> {
    F::subtree_root_position(Location::new(chunk_idx << grafting_height), grafting_height)
}

fn grafted_to_ops_pos<F: Graftable>(grafted_pos: Position<F>, grafting_height: u32) -> Position<F> {
    let grafted_height = F::pos_to_height(grafted_pos);
    let chunk_idx = *F::leftmost_leaf(grafted_pos, grafted_height);
    let ops_leaf_loc = chunk_idx << grafting_height;
    let ops_height = grafted_height + grafting_height;
    F::subtree_root_position(Location::new(ops_leaf_loc), ops_height)
}

/// Recover the current-boundary delta for one batch from local proof material
/// emitted by a Commonware `current` QMDB.
///
/// This is the bridge between a caller-owned local Commonware current DB and a
/// writer that publishes current-state rows. Callers apply a batch locally,
/// then use this function to recover the exact versioned current-state rows
/// that must be uploaded for that batch boundary:
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
/// The returned [`CurrentBoundaryState`] can be passed directly to ordered or
/// unordered writer APIs that accept current-boundary state.
///
/// TODO: replace this proof-driven recovery path with a thin adapter over
/// `commonware_storage::qmdb::current::batch::MerkleizedBatch` once upstream
/// exposes the bitmap-chunk and grafted-subtree deltas needed to publish one
/// batch boundary directly.
pub async fn recover_boundary_state<M, H, Op, const N: usize, Prove, Fut>(
    previous_operations: Option<&[Op]>,
    operations: &[Op],
    root: H::Digest,
    mut prove_at: Prove,
) -> Result<CurrentBoundaryState<H::Digest, N, M>, QmdbError>
where
    M: Graftable,
    H: Hasher,
    Op: QmdbOperation<M> + Codec,
    Op::Key: AsRef<[u8]>,
    Prove: FnMut(Location<M>) -> Fut,
    Fut: Future<Output = Result<(CurrentRangeProof<M, H::Digest>, [u8; N]), QmdbError>>,
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
    validate_recovery_input::<M, Op>(previous_operations, operations)?;

    let changed_chunks = changed_chunk_representatives::<M, Op, N>(previous_operations, operations);
    let complete_chunks = operations.len() / bitmap_chunk_bits::<N>() as usize;
    let merkle_size = Position::try_from(Location::new(operations.len() as u64))
        .map_err(|e| QmdbError::CorruptData(format!("invalid current proof leaf count: {e}")))?;
    let grafting_height = grafting_height_for::<N>();

    let mut chunks = BTreeMap::<u64, [u8; N]>::new();
    let mut grafted_nodes = BTreeMap::<Position<M>, H::Digest>::new();

    for (chunk_index, location) in changed_chunks {
        let (proof, chunk) = prove_at(location).await?;
        chunks.entry(chunk_index).or_insert(chunk);

        let operation = operations.get(*location as usize).ok_or_else(|| {
            QmdbError::CorruptData(format!(
                "missing operation at location {location} in current boundary input"
            ))
        })?;
        let mut hasher = H::default();
        if !proof.verify(
            &mut hasher,
            location,
            std::slice::from_ref(operation),
            std::slice::from_ref(&chunk),
            &root,
        ) {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentRange,
            });
        }

        if chunk_index as usize >= complete_chunks {
            continue;
        }

        let elements = [operation.encode().to_vec()];
        let chunk_refs = vec![chunk.as_ref()];
        let verifier = ProofVerifier::<M, H>::new(grafting_height, chunk_index, chunk_refs);
        let inner_root = proof
            .proof
            .reconstruct_root(&verifier, &elements, location)
            .map_err(|e| {
                QmdbError::CorruptData(format!(
                    "failed to reconstruct current proof root for location {location}: {e}"
                ))
            })?;
        let collected = proof
            .proof
            .verify_range_inclusion_and_extract_digests(&verifier, &elements, location, &inner_root)
            .map_err(|e| {
                QmdbError::CorruptData(format!(
                    "failed to reconstruct current proof digests for location {location}: {e}"
                ))
            })?;
        let digest_map: BTreeMap<Position<M>, H::Digest> = collected.into_iter().collect();

        for position in
            changed_grafted_positions_for_chunk::<M>(chunk_index, merkle_size, grafting_height)?
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

fn validate_recovery_input<F: Family, Op>(
    previous_operations: Option<&[Op]>,
    operations: &[Op],
) -> Result<(), QmdbError>
where
    Op: QmdbOperation<F> + Encode,
{
    if !operations.last().is_some_and(|op| op.has_floor().is_some()) {
        return Err(QmdbError::CorruptData(
            "recover_boundary_state requires operations to end with a commit floor".into(),
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
        .filter(|operation| operation.has_floor().is_some())
        .count();
    if commit_count != 1 {
        return Err(QmdbError::CorruptData(format!(
            "recover_boundary_state requires exactly one commit floor in the appended batch delta, found {commit_count}"
        )));
    }

    if !delta.last().is_some_and(|op| op.has_floor().is_some()) {
        return Err(QmdbError::CorruptData(
            "recover_boundary_state requires the appended batch delta to end with a commit floor"
                .into(),
        ));
    }

    Ok(())
}

fn changed_chunk_representatives<F: Family, Op, const N: usize>(
    previous_operations: Option<&[Op]>,
    operations: &[Op],
) -> BTreeMap<u64, Location<F>>
where
    Op: QmdbOperation<F>,
    Op::Key: AsRef<[u8]>,
{
    // The inactivity floor of the batch being recovered lives in the trailing
    // CommitFloor op. Chunks whose entire bit range is below this floor are
    // fully pruned by `current::Db` after `apply_batch`; we cannot serve a
    // proof for them and we do not need to -- `load_bitmap_chunk` folds all
    // below-floor bits to 0 deterministically at read time. Skip those chunks
    // here so we do not ask the local DB to prove a location it has discarded.
    let floor = operations
        .last()
        .and_then(QmdbOperation::has_floor)
        .unwrap_or(Location::new(0));
    let chunk_bits = bitmap_chunk_bits::<N>();
    let floor_chunk = *floor / chunk_bits;
    let first_alive_location = floor_chunk.saturating_mul(chunk_bits);

    let previous_len = previous_operations.map_or(0usize, |ops| ops.len());
    let mut changed = BTreeMap::<u64, Location<F>>::new();

    for raw_location in previous_len..operations.len() {
        let location = Location::new(raw_location as u64);
        if raw_location as u64 >= first_alive_location {
            changed
                .entry(chunk_index_for_location::<F, N>(location))
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
        .filter_map(|operation| operation.key().map(|key| key.as_ref().to_vec()))
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
        if let Some(key) = previous[index].key() {
            if touched_keys.remove(key.as_ref()) && previous[index].is_update() {
                changed
                    .entry(chunk_index_for_location::<F, N>(location))
                    .or_insert(location);
            }
        }
    }

    changed
}

fn changed_grafted_positions_for_chunk<F: Graftable>(
    chunk_index: u64,
    merkle_size: Position<F>,
    grafting_height: u32,
) -> Result<Vec<Position<F>>, QmdbError> {
    let leaf_ops_pos = chunk_idx_to_ops_pos::<F>(chunk_index, grafting_height);
    let (peak_pos, peak_height) =
        containing_peak::<F>(merkle_size, leaf_ops_pos).ok_or_else(|| {
            QmdbError::CorruptData(format!(
                "missing containing peak for chunk {chunk_index} at ops position {leaf_ops_pos}"
            ))
        })?;

    if peak_height < grafting_height {
        return Ok(Vec::new());
    }

    let grafted_leaf_pos = Position::<F>::try_from(Location::new(chunk_index))
        .expect("chunk index is a valid leaf location");
    let grafted_peak_pos = ops_to_grafted_pos::<F>(peak_pos, grafting_height);
    let grafted_peak_height = peak_height - grafting_height;

    let mut positions = vec![leaf_ops_pos];
    for parent_grafted_pos in
        grafted_path_parent_positions(grafted_leaf_pos, grafted_peak_pos, grafted_peak_height)
    {
        positions.push(grafted_to_ops_pos::<F>(parent_grafted_pos, grafting_height));
    }
    Ok(positions)
}

fn grafted_path_parent_positions<F: Family>(
    leaf_pos: Position<F>,
    peak_pos: Position<F>,
    peak_height: u32,
) -> Vec<Position<F>> {
    let mut positions = Vec::with_capacity(peak_height as usize);
    let mut node_pos = peak_pos;
    let mut two_h = 1u64 << peak_height;
    while two_h > 1 {
        positions.push(node_pos);
        let left_pos = node_pos - two_h;
        let right_pos = node_pos - 1;
        two_h >>= 1;
        node_pos = if left_pos < leaf_pos {
            right_pos
        } else {
            left_pos
        };
    }
    positions
}

fn containing_peak<F: Graftable>(
    merkle_size: Position<F>,
    position: Position<F>,
) -> Option<(Position<F>, u32)> {
    F::peaks(merkle_size).find(|(peak_pos, height)| {
        let leftmost = F::leftmost_leaf(*peak_pos, *height);
        let rightmost = leftmost + ((1u64 << *height) - 1);
        let position_leaf = F::leftmost_leaf(position, F::pos_to_height(position));
        leftmost <= position_leaf && position_leaf <= rightmost
    })
}

fn ops_pos_to_chunk_idx<F: Graftable>(ops_pos: Position<F>, grafting_height: u32) -> u64 {
    let location = F::leftmost_leaf(ops_pos, grafting_height);
    *location >> grafting_height
}

// TODO: replace this local mirror with
// `commonware_storage::qmdb::current::grafting::Verifier` once upstream exposes
// it; the verifier is still private in the pinned Commonware revision.
#[derive(Clone)]
struct ProofVerifier<'a, F: Graftable, H: Hasher> {
    inner: StandardHasher<H>,
    grafting_height: u32,
    chunks: Vec<&'a [u8]>,
    start_chunk_index: u64,
    _marker: std::marker::PhantomData<F>,
}

impl<'a, F: Graftable, H: Hasher> ProofVerifier<'a, F, H> {
    fn new(grafting_height: u32, start_chunk_index: u64, chunks: Vec<&'a [u8]>) -> Self {
        Self {
            inner: commonware_storage::qmdb::hasher::<H>(),
            grafting_height,
            chunks,
            start_chunk_index,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: Graftable, H: Hasher> MerkleHasher<F> for ProofVerifier<'_, F, H> {
    type Digest = H::Digest;

    fn hash<'a>(&self, parts: impl IntoIterator<Item = &'a [u8]>) -> Self::Digest {
        self.inner.hash(parts)
    }

    fn root_bagging(&self) -> commonware_storage::merkle::Bagging {
        self.inner.root_bagging()
    }

    fn leaf_digest(&self, pos: Position<F>, element: &[u8]) -> Self::Digest {
        self.inner.leaf_digest(pos, element)
    }

    fn node_digest(
        &self,
        pos: Position<F>,
        left: &Self::Digest,
        right: &Self::Digest,
    ) -> Self::Digest {
        match F::pos_to_height(pos).cmp(&self.grafting_height) {
            std::cmp::Ordering::Less | std::cmp::Ordering::Greater => {
                self.inner.node_digest(pos, left, right)
            }
            std::cmp::Ordering::Equal => {
                let ops_subtree_root = self.inner.node_digest(pos, left, right);
                let chunk_idx = ops_pos_to_chunk_idx::<F>(pos, self.grafting_height);
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
                    self.inner.hash([chunk, ops_subtree_root.as_ref()])
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::changed_chunk_representatives;
    use commonware_storage::merkle::{mmr, Location};
    use commonware_storage::qmdb::any::ordered::{
        variable::Operation as TestOperation, Update as OrderedUpdate,
    };
    use std::collections::BTreeMap;

    fn update(key: &[u8], value: &[u8]) -> TestOperation<mmr::Family, Vec<u8>, Vec<u8>> {
        TestOperation::Update(OrderedUpdate {
            key: key.to_vec(),
            value: value.to_vec(),
            next_key: Vec::new(),
        })
    }

    fn commit(floor: u64) -> TestOperation<mmr::Family, Vec<u8>, Vec<u8>> {
        TestOperation::CommitFloor(None, Location::new(floor))
    }

    fn previous_ops() -> Vec<TestOperation<mmr::Family, Vec<u8>, Vec<u8>>> {
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

        let changed = changed_chunk_representatives::<mmr::Family, TestOperation<_, _, _>, 1>(
            Some(&previous),
            &operations,
        );

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

        let changed = changed_chunk_representatives::<mmr::Family, TestOperation<_, _, _>, 1>(
            Some(&previous),
            &operations,
        );

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

        let changed = changed_chunk_representatives::<mmr::Family, TestOperation<_, _, _>, 1>(
            Some(&previous),
            &operations,
        );

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
            err.to_string().contains("end with a commit floor"),
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
            err.to_string().contains("exactly one commit floor"),
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
