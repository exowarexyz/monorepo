use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use commonware_codec::{Codec, Encode};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Sequential;
use commonware_storage::merkle::{
    self,
    hasher::{Hasher as MerkleHasher, Standard as StandardHasher},
    path,
    storage::Storage as MerkleStorage,
    Family, Graftable, Location, Position,
};
use commonware_storage::qmdb::{
    current::{
        db::compute_grafted_leaves,
        grafting,
        proof::{OpsRootWitness, RangeProof},
    },
    operation::Operation as QmdbOperation,
};

use crate::codec::{bitmap_chunk_bits, chunk_index_for_location};
use crate::error::QmdbError;
use crate::CurrentBoundaryState;

/// Recover the current-boundary delta for one batch from local proof material
/// emitted by a Commonware `current` QMDB.
///
/// This is the bridge between a caller-owned local Commonware current DB and a
/// writer that publishes current-state rows. Callers apply a batch locally,
/// then use this function to recover the exact versioned current-state rows
/// that must be uploaded for that batch boundary:
///
/// - `root`: the local current DB root after applying `operations`
/// - `ops_root_witness`: the local proof that the operation-log root is
///   committed by `root`
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
pub async fn recover_boundary_state<M, H, Op, const N: usize, Prove, Fut>(
    previous_operations: Option<&[Op]>,
    operations: &[Op],
    root: H::Digest,
    ops_root_witness: OpsRootWitness<H::Digest>,
    mut prove_at: Prove,
) -> Result<CurrentBoundaryState<H::Digest, N, M>, QmdbError>
where
    M: Graftable,
    H: Hasher,
    Op: QmdbOperation<M> + Codec,
    Op::Key: AsRef<[u8]>,
    Prove: FnMut(Location<M>) -> Fut,
    Fut: Future<Output = Result<(RangeProof<M, H::Digest>, [u8; N]), QmdbError>>,
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
    let grafting_height = grafting::height::<N>();

    let mut chunks = BTreeMap::<u64, [u8; N]>::new();
    let mut grafted_digests = BTreeMap::<Position<M>, H::Digest>::new();

    for (chunk_index, location) in changed_chunks {
        let (proof, chunk) = prove_at(location).await?;
        chunks.entry(chunk_index).or_insert(chunk);

        let operation = operations.get(*location as usize).ok_or_else(|| {
            QmdbError::CorruptData(format!(
                "missing operation at location {location} in current boundary input"
            ))
        })?;
        let digest_map = proof
            .extract_digests::<H, _, N>(
                location,
                std::slice::from_ref(operation),
                std::slice::from_ref(&chunk),
            )
            .ok_or(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentRange,
            })?;

        if chunk_index as usize >= complete_chunks {
            continue;
        }

        let (leaf_grafted_pos, leaf_digest) = changed_grafted_leaf_digest_for_chunk::<M, H, N>(
            chunk_index,
            &chunk,
            merkle_size,
            grafting_height,
            &digest_map,
        )
        .await?;
        grafted_digests.insert(leaf_grafted_pos, leaf_digest);

        for (position, digest) in changed_grafted_ancestor_digests_for_chunk::<M, H>(
            chunk_index,
            complete_chunks,
            grafting_height,
            &digest_map,
            &mut grafted_digests,
        )? {
            grafted_digests.insert(position, digest);
        }
    }

    Ok(CurrentBoundaryState {
        root,
        ops_root_witness,
        chunks: chunks.into_iter().collect(),
        grafted_nodes: grafted_digests
            .into_iter()
            .map(|(grafted_position, digest)| {
                (
                    grafting::grafted_to_ops_pos::<M>(grafted_position, grafting_height),
                    digest,
                )
            })
            .collect(),
    })
}

fn validate_recovery_input<F: Family, Op>(
    previous_operations: Option<&[Op]>,
    operations: &[Op],
) -> Result<(), QmdbError>
where
    Op: QmdbOperation<F> + Encode,
{
    if operations.last().is_none_or(|op| op.has_floor().is_none()) {
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

    if delta.last().is_none_or(|op| op.has_floor().is_none()) {
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
    // proof for them and we do not need to. `load_bitmap_chunk` folds all
    // below-floor bits to 0 deterministically at read time.
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

    let mut touched_keys = operations[previous_len..]
        .iter()
        .filter_map(|operation| operation.key().map(|key| key.as_ref().to_vec()))
        .collect::<BTreeSet<_>>();

    // Walk backwards only as far as the first alive chunk. Anything below
    // that is fully pruned locally and contributes nothing to the boundary.
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

async fn changed_grafted_leaf_digest_for_chunk<F, H, const N: usize>(
    chunk_index: u64,
    chunk: &[u8; N],
    merkle_size: Position<F>,
    grafting_height: u32,
    digest_map: &BTreeMap<Position<F>, H::Digest>,
) -> Result<(Position<F>, H::Digest), QmdbError>
where
    F: Graftable,
    H: Hasher,
{
    let grafted_pos = Position::<F>::try_from(Location::new(chunk_index))
        .expect("chunk index is a valid grafted leaf location");
    let ops_pos = grafting::grafted_to_ops_pos::<F>(grafted_pos, grafting_height);
    if let Some(digest) = digest_map.get(&ops_pos).copied() {
        return Ok((grafted_pos, digest));
    }

    let chunk_index_usize = usize::try_from(chunk_index)
        .map_err(|_| QmdbError::CorruptData("current chunk index does not fit in usize".into()))?;
    let storage = ProofDigestStorage {
        size: merkle_size,
        digests: digest_map,
    };
    let hasher = commonware_storage::qmdb::hasher::<H>();
    let mut leaves = compute_grafted_leaves::<F, H, Sequential, N>(
        &hasher,
        &storage,
        [(chunk_index_usize, *chunk)],
        &Sequential,
    )
    .await
    .map_err(|e| QmdbError::CommonwareMerkle(e.to_string()))?;
    let (_chunk_index, digest) = leaves
        .pop()
        .ok_or_else(|| QmdbError::CorruptData("missing computed grafted leaf".into()))?;
    Ok((grafted_pos, digest))
}

fn changed_grafted_ancestor_digests_for_chunk<F, H>(
    chunk_index: u64,
    complete_chunks: usize,
    grafting_height: u32,
    digest_map: &BTreeMap<Position<F>, H::Digest>,
    computed: &mut BTreeMap<Position<F>, H::Digest>,
) -> Result<Vec<(Position<F>, H::Digest)>, QmdbError>
where
    F: Graftable,
    H: Hasher,
{
    let complete_chunks = u64::try_from(complete_chunks).map_err(|_| {
        QmdbError::CorruptData("complete current chunk count does not fit in u64".into())
    })?;
    if chunk_index >= complete_chunks {
        return Ok(Vec::new());
    }

    let grafted_size = Position::<F>::try_from(Location::new(complete_chunks))
        .map_err(|e| QmdbError::CorruptData(format!("invalid grafted current size: {e}")))?;
    let grafted_leaf_pos = Position::<F>::try_from(Location::new(chunk_index))
        .expect("chunk index is a valid grafted leaf location");
    let (grafted_peak_pos, grafted_peak_height) =
        containing_peak::<F>(grafted_size, grafted_leaf_pos).ok_or_else(|| {
            QmdbError::CorruptData(format!(
                "missing containing grafted peak for chunk {chunk_index} at grafted position {grafted_leaf_pos}"
            ))
        })?;

    let first_leaf = F::leftmost_leaf(grafted_peak_pos, grafted_peak_height);
    let parents = path::Iterator::<F>::new(
        grafted_peak_pos,
        grafted_peak_height,
        first_leaf,
        Location::new(chunk_index),
    )
    .map(|(parent, _sibling, _height)| parent)
    .collect::<Vec<_>>();

    let hasher = commonware_storage::qmdb::hasher::<H>();
    let bagging = <StandardHasher<H> as MerkleHasher<F>>::root_bagging(&hasher);
    let verifier = grafting::Verifier::<F, H>::new(grafting_height, 0, Vec::new(), bagging);

    let mut out = Vec::with_capacity(parents.len());
    for parent_grafted_pos in parents.into_iter().rev() {
        if let Some(digest) = computed.get(&parent_grafted_pos).copied() {
            out.push((parent_grafted_pos, digest));
            continue;
        }

        let parent_ops_pos = grafting::grafted_to_ops_pos::<F>(parent_grafted_pos, grafting_height);
        let parent_digest = if let Some(digest) = digest_map.get(&parent_ops_pos).copied() {
            digest
        } else {
            let parent_height = F::pos_to_height(parent_grafted_pos);
            let (left_pos, right_pos) = F::children(parent_grafted_pos, parent_height);
            let left_digest =
                grafted_digest::<F, H>(left_pos, grafting_height, digest_map, computed)?;
            let right_digest =
                grafted_digest::<F, H>(right_pos, grafting_height, digest_map, computed)?;
            verifier.node_digest(parent_ops_pos, &left_digest, &right_digest)
        };
        computed.insert(parent_grafted_pos, parent_digest);
        out.push((parent_grafted_pos, parent_digest));
    }
    Ok(out)
}

fn grafted_digest<F, H>(
    grafted_pos: Position<F>,
    grafting_height: u32,
    digest_map: &BTreeMap<Position<F>, H::Digest>,
    computed: &BTreeMap<Position<F>, H::Digest>,
) -> Result<H::Digest, QmdbError>
where
    F: Graftable,
    H: Hasher,
{
    if let Some(digest) = computed.get(&grafted_pos).copied() {
        return Ok(digest);
    }

    let ops_pos = grafting::grafted_to_ops_pos::<F>(grafted_pos, grafting_height);
    digest_map.get(&ops_pos).copied().ok_or_else(|| {
        QmdbError::CorruptData(format!(
            "missing grafted sibling digest at ops position {ops_pos}"
        ))
    })
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

struct ProofDigestStorage<'a, F: Family, D: Digest> {
    size: Position<F>,
    digests: &'a BTreeMap<Position<F>, D>,
}

impl<F: Family, D: Digest> MerkleStorage<F> for ProofDigestStorage<'_, F, D> {
    type Digest = D;

    async fn size(&self) -> Position<F> {
        self.size
    }

    async fn get_node(&self, pos: Position<F>) -> Result<Option<D>, merkle::Error<F>> {
        Ok(self.digests.get(&pos).copied())
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
