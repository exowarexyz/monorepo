use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

use bytes::Bytes;
use commonware_codec::DecodeExt;
use commonware_cryptography::Digest;
use commonware_storage::merkle::{
    self, storage::Storage as MerkleStorage, Family, Location, Position,
};

use crate::{
    codec::{merkle_size_for_watermark, op_count_for_watermark},
    QmdbError,
};

pub(crate) fn range_positions<F: Family>(
    watermark: Location<F>,
    start: Location<F>,
    end: Location<F>,
) -> Result<Vec<Position<F>>, QmdbError> {
    let leaves = op_count_for_watermark(watermark)?;
    let size = merkle_size_for_watermark(watermark)?;
    if start >= end || end > leaves {
        return Err(QmdbError::CorruptData(
            "invalid Merkle prefetch range".into(),
        ));
    }

    // Canonical peak order describes leaf coverage even when node positions are not sorted.
    let mut positions = BTreeSet::new();
    let mut leaf_start = 0u64;
    for (position, height) in F::peaks(size) {
        let capacity = 1u64
            .checked_shl(height)
            .ok_or_else(|| QmdbError::CorruptData("Merkle peak height overflow".into()))?;
        let leaf_end = leaf_start
            .checked_add(capacity)
            .ok_or_else(|| QmdbError::CorruptData("Merkle peak leaf range overflow".into()))?;
        positions.insert(position);
        let mut pending = vec![(position, height, leaf_start, leaf_end)];
        while let Some((position, height, left, right)) = pending.pop() {
            if right <= *start || left >= *end {
                positions.insert(position);
                continue;
            }
            if *start <= left && right <= *end {
                continue;
            }
            if height == 0 {
                continue;
            }
            let middle = left + (right - left) / 2;
            let (left_child, right_child) = F::children(position, height);
            pending.push((right_child, height - 1, middle, right));
            pending.push((left_child, height - 1, left, middle));
        }
        leaf_start = leaf_end;
    }
    positions.extend(F::nodes_to_pin(start));
    Ok(positions.into_iter().collect())
}

// The range plan includes every proof node and checkpoint pin before construction starts.
pub(crate) struct PrefetchedMerkleStorage<F: Family, D: Digest> {
    size: Position<F>,
    nodes: BTreeMap<Position<F>, Option<Bytes>>,
    marker: PhantomData<D>,
}

impl<F: Family, D: Digest> PrefetchedMerkleStorage<F, D> {
    pub(crate) fn new(size: Position<F>, nodes: BTreeMap<Position<F>, Option<Bytes>>) -> Self {
        Self {
            size,
            nodes,
            marker: PhantomData,
        }
    }

    fn decode_node(bytes: &[u8]) -> Result<D, merkle::Error<F>> {
        if bytes.len() != D::SIZE {
            return Err(merkle::Error::DataCorrupted(
                "exoware-qmdb node digest has invalid length",
            ));
        }
        D::decode(bytes)
            .map_err(|_| merkle::Error::DataCorrupted("exoware-qmdb node digest decode failed"))
    }
}

impl<F: Family, D: Digest> MerkleStorage<F> for PrefetchedMerkleStorage<F, D> {
    type Digest = D;

    fn size(&self) -> Position<F> {
        self.size
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<D>, merkle::Error<F>> {
        self.nodes
            .get(&position)
            .and_then(Option::as_ref)
            .map(|bytes| Self::decode_node(bytes))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_storage::merkle::{hasher::Standard, mem::Mem, mmb, mmr, verification, Bagging};

    async fn assert_range_plans<F: Family + PartialEq>() {
        for bagging in [Bagging::ForwardFold, Bagging::BackwardFold] {
            let hasher = Standard::<Sha256>::new(bagging);
            for leaves in 1..=24 {
                let mut memory = Mem::<F, Digest>::new();
                let mut batch = memory.new_batch();
                for leaf in 0u64..leaves {
                    batch = batch.add(&hasher, &leaf.to_be_bytes());
                }
                memory
                    .apply_batch(&batch.merkleize(&memory, &hasher))
                    .unwrap();
                let peaks = F::peaks(memory.size())
                    .map(|(position, _)| position)
                    .collect::<Vec<_>>();
                for start in 0..leaves {
                    for end in start + 1..=leaves {
                        let plan = range_positions::<F>(
                            Location::new(leaves - 1),
                            Location::new(start),
                            Location::new(end),
                        )
                        .unwrap();
                        assert!(plan.is_sorted_by(|a, b| a < b));
                        assert!(peaks.iter().all(|peak| plan.contains(peak)));
                        assert!(
                            F::nodes_to_pin(Location::new(start)).all(|pin| plan.contains(&pin))
                        );
                        let nodes = plan
                            .iter()
                            .map(|&position| {
                                (
                                    position,
                                    Some(Bytes::copy_from_slice(
                                        memory.get_node(position).unwrap().as_ref(),
                                    )),
                                )
                            })
                            .collect();
                        let storage =
                            PrefetchedMerkleStorage::<F, Digest>::new(memory.size(), nodes);
                        for inactive in 0..=peaks.len() {
                            let range = Location::new(start)..Location::new(end);
                            let actual = verification::historical_range_proof(
                                &hasher,
                                &storage,
                                Location::new(leaves),
                                range.clone(),
                                inactive,
                            )
                            .await
                            .unwrap();
                            let expected = memory.range_proof(&hasher, range, inactive).unwrap();
                            assert_eq!(
                                actual, expected,
                                "leaves={leaves}, range={start}..{end}, inactive={inactive}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn range_plans_match_memory_proofs_for_both_families() {
        assert_range_plans::<mmr::Family>().await;
        assert_range_plans::<mmb::Family>().await;
    }

    async fn assert_large_range_plans<F: Family>() {
        let maximum = *F::MAX_LEAVES;
        let mut sizes = BTreeSet::from([maximum - 1, maximum]);
        for height in 1..=62 {
            let boundary = 1u64 << height;
            sizes.extend(
                [boundary - 1, boundary, boundary + 1]
                    .into_iter()
                    .filter(|size| *size <= maximum),
            );
        }
        for leaves in sizes {
            let size = Position::<F>::try_from(Location::new(leaves)).unwrap();
            let peaks = F::peaks(size).count();
            for (start, end) in [
                (0, leaves),
                (0, 1),
                (leaves - 1, leaves),
                (leaves / 2, leaves),
            ] {
                let start = Location::new(start);
                let end = Location::new(end);
                let plan = range_positions::<F>(Location::new(leaves - 1), start, end).unwrap();
                assert!(F::nodes_to_pin(start).all(|pin| plan.contains(&pin)));

                // Synthetic digests check the proof builder's read set without allocating leaves.
                let nodes = plan
                    .into_iter()
                    .map(|position| (position, Some(Bytes::from_static(&[0; 32]))))
                    .collect();
                let storage = PrefetchedMerkleStorage::<F, Digest>::new(size, nodes);
                for bagging in [Bagging::ForwardFold, Bagging::BackwardFold] {
                    let hasher = Standard::<Sha256>::new(bagging);
                    for inactive in [0, peaks] {
                        verification::range_proof(&hasher, &storage, start..end, inactive)
                            .await
                            .unwrap();
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn range_plans_cover_large_topology_boundaries() {
        assert_large_range_plans::<mmr::Family>().await;
        assert_large_range_plans::<mmb::Family>().await;
    }

    #[test]
    fn plan_rejects_invalid_ranges_and_overflow() {
        for (watermark, start, end) in [(4, 2, 2), (4, 4, 6), (u64::MAX, 0, 1)] {
            assert!(range_positions::<mmr::Family>(
                Location::new(watermark),
                Location::new(start),
                Location::new(end)
            )
            .is_err());
        }
        assert!(range_positions::<mmb::Family>(
            mmb::Family::MAX_LEAVES,
            Location::new(0),
            Location::new(1)
        )
        .is_err());
    }

    #[tokio::test]
    async fn missing_and_malformed_nodes_follow_requested_order() {
        let positions = [0, 3, 8].map(Position::<mmr::Family>::new);
        for malformed in positions[..2].iter().copied() {
            let mut nodes = BTreeMap::from([
                (positions[0], None),
                (positions[1], None),
                (positions[2], Some(Bytes::from_static(&[0; 32]))),
            ]);
            nodes.insert(malformed, Some(Bytes::from_static(b"invalid")));
            let storage =
                PrefetchedMerkleStorage::<mmr::Family, Digest>::new(Position::new(10), nodes);
            assert_eq!(
                storage.get_node(positions[2]).await.unwrap(),
                Some(Digest([0; 32]))
            );
            assert!(storage.get_nodes(&[]).await.unwrap().is_empty());
            let error = storage.get_nodes(&positions[..2]).await.unwrap_err();
            if malformed == positions[0] {
                assert!(matches!(
                    error,
                    merkle::Error::DataCorrupted("exoware-qmdb node digest has invalid length")
                ));
            } else {
                assert!(
                    matches!(error, merkle::Error::ElementPruned(position) if position == positions[0])
                );
            }
        }
    }
}
