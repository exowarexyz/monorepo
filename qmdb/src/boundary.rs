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

fn changed_chunk_representatives<K, V, const N: usize>(
    previous_operations: Option<&[QmdbOperation<K, V>]>,
    operations: &[QmdbOperation<K, V>],
) -> BTreeMap<u64, Location>
where
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
{
    let previous_len = previous_operations.map_or(0usize, |ops| ops.len());
    let mut changed = BTreeMap::<u64, Location>::new();

    for raw_location in previous_len..operations.len() {
        let location = Location::new(raw_location as u64);
        changed
            .entry(chunk_index_for_location::<N>(location))
            .or_insert(location);
    }

    let Some(previous) = previous_operations else {
        return changed;
    };

    let mut touched_keys = operations[previous_len..]
        .iter()
        .filter_map(|operation| match operation {
            QmdbOperation::Update(update) => Some(update.key.as_ref().to_vec()),
            QmdbOperation::Delete(key) => Some(key.as_ref().to_vec()),
            QmdbOperation::CommitFloor(_, _) => None,
        })
        .collect::<BTreeSet<_>>();
    let mut needs_previous_commit = previous_len > 0;

    for index in (0..previous.len()).rev() {
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
            QmdbOperation::CommitFloor(_, _) => {
                if needs_previous_commit {
                    changed
                        .entry(chunk_index_for_location::<N>(location))
                        .or_insert(location);
                    needs_previous_commit = false;
                }
            }
        }

        if touched_keys.is_empty() && !needs_previous_commit {
            break;
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
