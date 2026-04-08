use std::collections::BTreeMap;
use std::marker::PhantomData;

use commonware_codec::{Codec, Encode};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::mmr::{
    self, iterator::PeakIterator, mem::Mmr, storage::Storage as MmrStorage, Location, Position,
    StandardHasher, UnmerkleizedBatch,
};
use commonware_storage::qmdb::{
    any::ordered::variable::Operation as QmdbOperation, operation::Key as QmdbKey,
};

use crate::codec::{
    bitmap_chunk_bits, ensure_encoded_value_size, grafting_height_for, position_height,
};
use crate::error::QmdbError;
use crate::CurrentBoundaryState;

pub(crate) struct RebuiltCurrentState<H: Hasher, K, V, const N: usize> {
    pub(crate) ops_mmr: Mmr<H::Digest>,
    pub(crate) ops_root: H::Digest,
    pub(crate) chunks: Vec<[u8; N]>,
    pub(crate) grafted_mmr: Mmr<H::Digest>,
    pub(crate) partial_chunk_digest: Option<(u64, H::Digest)>,
    _marker: PhantomData<(K, V)>,
}

impl<H, K, V, const N: usize> RebuiltCurrentState<H, K, V, N>
where
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    QmdbOperation<K, V>: Encode,
{
    pub(crate) fn build(operations: Vec<QmdbOperation<K, V>>) -> Result<Self, QmdbError> {
        let encoded_operations = operations
            .iter()
            .map(|operation| {
                let encoded = operation.encode().to_vec();
                ensure_encoded_value_size(encoded.len())?;
                Ok(encoded)
            })
            .collect::<Result<Vec<_>, QmdbError>>()?;
        let ops_mmr = build_operation_mmr::<H>(&encoded_operations)?;
        let ops_root = *ops_mmr.root();
        let chunks = build_bitmap_chunks::<K, V, N>(&operations);
        let complete_chunks = operations.len() / bitmap_chunk_bits::<N>() as usize;
        let grafted_mmr = build_grafted_mmr::<H, N>(&ops_mmr, &chunks[..complete_chunks])?;
        let partial_chunk_digest = if operations
            .len()
            .is_multiple_of(bitmap_chunk_bits::<N>() as usize)
            || chunks.is_empty()
        {
            None
        } else {
            let next_bit = (operations.len() % bitmap_chunk_bits::<N>() as usize) as u64;
            let mut hasher = H::default();
            hasher.update(&chunks[chunks.len() - 1]);
            Some((next_bit, hasher.finalize()))
        };
        Ok(Self {
            ops_mmr,
            ops_root,
            chunks,
            grafted_mmr,
            partial_chunk_digest,
            _marker: PhantomData,
        })
    }
}

pub(crate) struct RebuiltCurrentStorage<'a, D: Digest, const N: usize> {
    pub(crate) ops_mmr: &'a Mmr<D>,
    pub(crate) grafted_mmr: &'a Mmr<D>,
}

impl<D: Digest, const N: usize> MmrStorage<D> for RebuiltCurrentStorage<'_, D, N> {
    async fn size(&self) -> Position {
        self.ops_mmr.size()
    }

    async fn get_node(&self, position: Position) -> Result<Option<D>, mmr::Error> {
        if position_height(position) < grafting_height_for::<N>() {
            return Ok(self.ops_mmr.get_node(position));
        }
        let grafted_position =
            crate::codec::ops_to_grafted_pos(position, grafting_height_for::<N>());
        Ok(self.grafted_mmr.get_node(grafted_position))
    }
}

pub(crate) fn build_operation_mmr<H: Hasher>(
    encoded_operations: &[Vec<u8>],
) -> Result<Mmr<H::Digest>, QmdbError> {
    let mut hasher = StandardHasher::<H>::new();
    let mut mmr = Mmr::new(&mut hasher);
    let changeset = {
        let mut batch = UnmerkleizedBatch::new(&mmr);
        for op in encoded_operations {
            batch.add(&mut hasher, op);
        }
        batch.merkleize(&mut hasher).finalize()
    };
    mmr.apply(changeset)
        .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
    Ok(mmr)
}

pub(crate) fn build_bitmap_chunks<K, V, const N: usize>(
    operations: &[QmdbOperation<K, V>],
) -> Vec<[u8; N]>
where
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
{
    let mut latest_active = BTreeMap::<Vec<u8>, usize>::new();
    let mut latest_commit = None::<usize>;
    let mut bits = vec![false; operations.len()];

    for (index, operation) in operations.iter().enumerate() {
        match operation {
            QmdbOperation::Update(update) => {
                bits[index] = true;
                if let Some(previous) = latest_active.insert(update.key.as_ref().to_vec(), index) {
                    bits[previous] = false;
                }
            }
            QmdbOperation::Delete(key) => {
                if let Some(previous) = latest_active.remove(key.as_ref()) {
                    bits[previous] = false;
                }
            }
            QmdbOperation::CommitFloor(_, _) => {
                bits[index] = true;
                if let Some(previous) = latest_commit.replace(index) {
                    bits[previous] = false;
                }
            }
        }
    }

    let chunk_count = operations.len().div_ceil(bitmap_chunk_bits::<N>() as usize);
    let mut chunks = vec![[0u8; N]; chunk_count];
    for (bit_index, is_set) in bits.into_iter().enumerate() {
        if !is_set {
            continue;
        }
        let chunk_index = bit_index / bitmap_chunk_bits::<N>() as usize;
        let bit_in_chunk = bit_index % bitmap_chunk_bits::<N>() as usize;
        chunks[chunk_index][bit_in_chunk / 8] |= 1 << (bit_in_chunk % 8);
    }
    chunks
}

pub(crate) fn build_grafted_mmr<H: Hasher, const N: usize>(
    ops_mmr: &Mmr<H::Digest>,
    complete_chunks: &[[u8; N]],
) -> Result<Mmr<H::Digest>, QmdbError> {
    let mut grafted_hasher =
        GraftedHasher::new(StandardHasher::<H>::new(), grafting_height_for::<N>());
    let mut grafted_mmr = Mmr::new(&mut grafted_hasher);
    if complete_chunks.is_empty() {
        return Ok(grafted_mmr);
    }

    let zero_chunk = [0u8; N];
    let changeset = {
        let mut batch = grafted_mmr.new_batch();
        for (chunk_index, chunk) in complete_chunks.iter().enumerate() {
            let ops_position =
                chunk_idx_to_ops_pos(chunk_index as u64, grafting_height_for::<N>());
            let ops_digest = ops_mmr.get_node(ops_position).ok_or_else(|| {
                QmdbError::CorruptData(format!(
                    "missing ops subtree root at position {ops_position} for chunk {chunk_index}"
                ))
            })?;
            let digest = if *chunk == zero_chunk {
                ops_digest
            } else {
                let mut hasher = H::default();
                hasher.update(chunk);
                hasher.update(&ops_digest);
                hasher.finalize()
            };
            batch.add_leaf_digest(digest);
        }
        batch.merkleize(&mut grafted_hasher).finalize()
    };
    grafted_mmr
        .apply(changeset)
        .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
    Ok(grafted_mmr)
}

pub(crate) async fn compute_storage_root<H: Hasher>(
    storage: &impl MmrStorage<H::Digest>,
) -> Result<H::Digest, QmdbError> {
    let size = storage.size().await;
    let leaves = Location::try_from(size)
        .map_err(|e| QmdbError::CorruptData(format!("invalid storage size: {e}")))?;
    let mut peaks = Vec::new();
    for (peak_pos, _) in PeakIterator::new(size) {
        let digest = storage
            .get_node(peak_pos)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?
            .ok_or_else(|| {
                QmdbError::CorruptData(format!("missing peak node at position {peak_pos}"))
            })?;
        peaks.push(digest);
    }
    let mut hasher = StandardHasher::<H>::new();
    Ok(mmr::hasher::Hasher::root(&mut hasher, leaves, peaks.iter()))
}

pub(crate) fn combine_current_roots<H: Hasher>(
    ops_root: &H::Digest,
    grafted_root: &H::Digest,
    partial_chunk: Option<(u64, &H::Digest)>,
) -> H::Digest {
    let mut hasher = H::default();
    hasher.update(ops_root);
    hasher.update(grafted_root);
    if let Some((next_bit, digest)) = partial_chunk {
        hasher.update(&next_bit.to_be_bytes());
        hasher.update(digest);
    }
    hasher.finalize()
}

pub(crate) fn chunk_idx_to_ops_pos(chunk_idx: u64, grafting_height: u32) -> Position {
    let first_leaf_loc = Location::new(chunk_idx << grafting_height);
    let first_leaf_pos =
        Position::try_from(first_leaf_loc).expect("chunk_idx_to_ops_pos overflow");
    Position::new(*first_leaf_pos + (1u64 << (grafting_height + 1)) - 2)
}

pub(crate) fn grafted_to_ops_pos(grafted_pos: Position, grafting_height: u32) -> Position {
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

pub(crate) struct GraftedHasher<H: Hasher> {
    inner: StandardHasher<H>,
    grafting_height: u32,
}

impl<H: Hasher> GraftedHasher<H> {
    pub(crate) const fn new(inner: StandardHasher<H>, grafting_height: u32) -> Self {
        Self {
            inner,
            grafting_height,
        }
    }
}

impl<H: Hasher> mmr::hasher::Hasher for GraftedHasher<H> {
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
        let ops_pos = grafted_to_ops_pos(pos, self.grafting_height);
        self.inner.node_digest(ops_pos, left, right)
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
        }
    }
}

pub async fn build_current_boundary_state<H, K, V, const N: usize>(
    previous_operations: Option<&[QmdbOperation<K, V>]>,
    operations: &[QmdbOperation<K, V>],
) -> CurrentBoundaryState<H::Digest, N>
where
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    QmdbOperation<K, V>: Encode,
{
    let state = RebuiltCurrentState::<H, K, V, N>::build(operations.to_vec())
        .expect("rebuild current state");

    let storage = RebuiltCurrentStorage::<H::Digest, N> {
        ops_mmr: &state.ops_mmr,
        grafted_mmr: &state.grafted_mmr,
    };
    let grafted_root = compute_storage_root::<H>(&storage)
        .await
        .expect("compute rebuilt grafted root");
    let root = combine_current_roots::<H>(
        &state.ops_root,
        &grafted_root,
        state
            .partial_chunk_digest
            .as_ref()
            .map(|(next_bit, digest)| (*next_bit, digest)),
    );

    let previous_state = previous_operations.map(|ops| {
        RebuiltCurrentState::<H, K, V, N>::build(ops.to_vec())
            .expect("rebuild previous current state")
    });

    let chunks = state
        .chunks
        .iter()
        .enumerate()
        .filter_map(|(chunk_index, chunk)| {
            let changed = previous_state
                .as_ref()
                .and_then(|previous| previous.chunks.get(chunk_index))
                .is_none_or(|previous| previous != chunk);
            changed.then_some((chunk_index as u64, *chunk))
        })
        .collect::<Vec<_>>();
    let grafted_nodes = (0..*state.grafted_mmr.size())
        .filter_map(|raw_position| {
            let position = Position::new(raw_position);
            let digest = state
                .grafted_mmr
                .get_node(position)
                .expect("rebuilt grafted node exists");
            let changed = previous_state
                .as_ref()
                .and_then(|previous| previous.grafted_mmr.get_node(position))
                .is_none_or(|previous| previous != digest);
            changed.then_some((position, digest))
        })
        .collect::<Vec<_>>();
    CurrentBoundaryState {
        root,
        chunks,
        grafted_nodes,
    }
}
