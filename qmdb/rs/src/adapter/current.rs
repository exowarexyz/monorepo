//! Current-state proof reads shared by the ordered and unordered adapters.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

use bytes::Bytes;
use commonware_codec::{Copying, DecodeExt};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::merkle::{Family, Graftable, Location, Position};
use commonware_storage::qmdb::current::proof::{constant::OperationProof, RangeProof};
use exoware_sdk::{RangeMode, ReadSession};

use crate::adapter::codec::{
    chunk_index_for_location, clear_below_floor, decode_current_boundary_metadata,
    encode_chunk_key, encode_current_meta_key, encode_node_key, encode_operation_key,
    encode_presence_key, merkle_size_for_watermark,
};
use crate::adapter::core;
use crate::adapter::operation_range::root;
use crate::adapter::read_cache::{ReadCache, RootContext};
use crate::adapter::storage::{tail_chunks, KvCurrentStorage, ProofBitmap};
use crate::QmdbError;

/// Current-state values fixed by one published batch boundary.
#[derive(Clone)]
pub(crate) struct CurrentTip<F: Family, D: Digest> {
    pub watermark: Location<F>,
    /// Canonical current root.
    pub root: D,
    /// Bitmap chunks pruned at this tip.
    pub pruned_chunks: u64,
    /// Floor of the tip's commit, below which no operation is active.
    pub inactivity_floor: Location<F>,
    /// Operations-log root and its inactive peaks.
    pub ops: RootContext<D>,
    /// The [`tail_chunks`] as `(index, chunk)`, cleared below the floor.
    pub tail_chunks: Vec<(u64, Bytes)>,
}

impl<F: Family, D: Digest> CurrentTip<F, D> {
    fn tail_chunk<const N: usize>(&self, index: u64) -> Option<[u8; N]> {
        self.tail_chunks
            .iter()
            .find(|(tail, _)| *tail == index)
            .map(|(_, chunk)| chunk.as_ref().try_into().expect("tail chunks are N bytes"))
    }
}

/// The [`CurrentTip`] at `watermark`, from `cache` or else loaded and cached.
/// Concurrent callers for one watermark share a single load. `commit_floor`
/// decodes the operation at `watermark`, which must be a commit, and returns
/// its inactivity floor.
pub(crate) async fn current_tip<F: Graftable, H: Hasher, const N: usize>(
    session: &ReadSession,
    cache: &Arc<ReadCache<F, H::Digest>>,
    watermark: Location<F>,
    commit_floor: impl FnOnce(&[u8]) -> Result<Location<F>, QmdbError>,
) -> Result<CurrentTip<F, H::Digest>, QmdbError> {
    let (tip, _guard) = cache.current(watermark).await;
    if let Some(tip) = tip {
        return Ok(tip);
    }
    let ops = cache.cached_context(watermark);
    let tip = load_current_tip::<F, H, N>(session, watermark, ops, commit_floor).await?;
    cache.put_current(tip.clone());
    Ok(tip)
}

/// Load the [`CurrentTip`] at `watermark` in one round of concurrent reads,
/// reading the ops root peaks only when `ops` is unknown.
async fn load_current_tip<F: Graftable, H: Hasher, const N: usize>(
    session: &ReadSession,
    watermark: Location<F>,
    ops: Option<RootContext<H::Digest>>,
    commit_floor: impl FnOnce(&[u8]) -> Result<Location<F>, QmdbError>,
) -> Result<CurrentTip<F, H::Digest>, QmdbError> {
    let presence_key = encode_presence_key(watermark);
    let meta_key = encode_current_meta_key(watermark);
    let commit_key = encode_operation_key(watermark);
    let peaks = match ops {
        Some(_) => Vec::new(),
        None => F::peaks(merkle_size_for_watermark(watermark)?)
            .map(|(position, _)| position)
            .collect::<Vec<_>>(),
    };
    let peak_keys = peaks
        .iter()
        .map(|&position| encode_node_key(position))
        .collect::<Vec<_>>();
    let keys = [&presence_key, &meta_key, &commit_key]
        .into_iter()
        .chain(&peak_keys)
        .collect::<Vec<_>>();
    let batch_size = u32::try_from(keys.len()).expect("peak count fits u32");
    let tail = tail_chunks::<F, N>(watermark)?;
    let (mut rows, tail) = futures::try_join!(
        async { Ok::<_, QmdbError>(session.get_many(&keys, batch_size).await?.collect().await?) },
        futures::future::try_join_all(tail.into_iter().map(|index| async move {
            let chunk = load_chunk_row::<F, N>(session, watermark, index).await?;
            Ok::<_, QmdbError>((index, chunk))
        })),
    )?;

    if !rows.contains_key(&presence_key) {
        return Err(QmdbError::CurrentProofRequiresBatchBoundary {
            location: watermark.as_u64(),
        });
    }
    let Some(meta) = rows.get(&meta_key) else {
        return Err(QmdbError::CurrentBoundaryStateMissing {
            location: watermark.as_u64(),
        });
    };
    let meta = decode_current_boundary_metadata::<H::Digest>(
        meta.as_ref(),
        format_args!("current boundary metadata at {watermark}"),
    )?;
    let Some(commit) = rows.get(&commit_key) else {
        return Err(QmdbError::CorruptData(format!(
            "missing operation row at location {watermark}"
        )));
    };
    let inactivity_floor = commit_floor(commit.as_ref())?;
    let ops = match ops {
        Some(ops) => ops,
        None => {
            let inactive_peaks = core::inactive_peaks(watermark, inactivity_floor)?;
            let nodes = peaks
                .iter()
                .zip(&peak_keys)
                .map(|(&position, key)| (position, rows.remove(key)))
                .collect::<BTreeMap<Position<F>, Option<Bytes>>>();
            RootContext {
                root: root::<F, H>(&nodes, watermark, inactive_peaks)?,
                inactive_peaks,
            }
        }
    };
    let tail_chunks = tail
        .into_iter()
        .map(|(index, mut chunk)| {
            clear_below_floor::<F, N>(&mut chunk, index, inactivity_floor);
            (index, Bytes::copy_from_slice(&chunk))
        })
        .collect();
    Ok(CurrentTip {
        watermark,
        root: meta.root,
        pruned_chunks: meta.pruned_chunks,
        inactivity_floor,
        ops,
        tail_chunks,
    })
}

/// Bitmap chunk `index` at the tip, as its latest version at or below the
/// watermark with bits below the floor cleared.
async fn load_chunk<F: Graftable, D: Digest, const N: usize>(
    session: &ReadSession,
    tip: &CurrentTip<F, D>,
    index: u64,
) -> Result<[u8; N], QmdbError> {
    if let Some(chunk) = tip.tail_chunk::<N>(index) {
        return Ok(chunk);
    }
    let mut chunk = load_chunk_row::<F, N>(session, tip.watermark, index).await?;
    clear_below_floor::<F, N>(&mut chunk, index, tip.inactivity_floor);
    Ok(chunk)
}

async fn load_chunk_row<F: Graftable, const N: usize>(
    session: &ReadSession,
    watermark: Location<F>,
    index: u64,
) -> Result<[u8; N], QmdbError> {
    let start = encode_chunk_key(index, Location::<F>::new(0));
    let end = encode_chunk_key(index, watermark);
    let rows = session
        .range_with_mode(&start, &end, 1, RangeMode::Reverse)
        .await?;
    let Some((_, bytes)) = rows.into_iter().next() else {
        return Err(QmdbError::CorruptData(format!(
            "missing bitmap chunk {index} at watermark {watermark}"
        )));
    };
    <[u8; N]>::decode(Copying(bytes.as_ref()))
        .map_err(|e| QmdbError::CorruptData(format!("bitmap chunk {index} decode error: {e}")))
}

/// Bitmap chunks covering `[start, end)`.
pub(crate) async fn load_chunks<F: Graftable, D: Digest, const N: usize>(
    session: &ReadSession,
    tip: &CurrentTip<F, D>,
    start: Location<F>,
    end: Location<F>,
) -> Result<Vec<[u8; N]>, QmdbError> {
    let first = chunk_index_for_location::<F, N>(start);
    let last = chunk_index_for_location::<F, N>(end - 1);
    futures::future::try_join_all(
        (first..=last).map(|index| load_chunk::<F, D, N>(session, tip, index)),
    )
    .await
}

async fn proof_bitmap<F: Graftable, D: Digest, const N: usize>(
    session: &ReadSession,
    tip: &CurrentTip<F, D>,
    location: Option<Location<F>>,
) -> Result<ProofBitmap<N>, QmdbError> {
    ProofBitmap::load(tip.watermark, tip.pruned_chunks, location, |index| {
        load_chunk::<F, D, N>(session, tip, index)
    })
    .await
}

fn storage<'a, F: Graftable, H: Hasher, const N: usize>(
    session: &'a ReadSession,
    tip: &CurrentTip<F, H::Digest>,
) -> Result<KvCurrentStorage<'a, F, H, N>, QmdbError> {
    Ok(KvCurrentStorage {
        session,
        watermark: tip.watermark,
        pruned_chunks: tip.pruned_chunks,
        size: merkle_size_for_watermark(tip.watermark)?,
        _marker: PhantomData,
    })
}

/// Current-state proof for the operation at `location`.
pub(crate) async fn operation_proof<F: Graftable, H: Hasher, const N: usize>(
    session: &ReadSession,
    tip: &CurrentTip<F, H::Digest>,
    location: Location<F>,
) -> Result<OperationProof<F, H::Digest, N>, QmdbError> {
    let status = proof_bitmap::<F, H::Digest, N>(session, tip, Some(location)).await?;
    OperationProof::new::<H, _>(
        &status,
        &storage::<F, H, N>(session, tip)?,
        tip.inactivity_floor,
        location,
        tip.ops.root,
    )
    .await
    .map_err(crate::error::current_proof_error)
}

/// Current-state proof for the operations in `[start, end)`.
pub(crate) async fn range_proof<F: Graftable, H: Hasher, const N: usize>(
    session: &ReadSession,
    tip: &CurrentTip<F, H::Digest>,
    start: Location<F>,
    end: Location<F>,
) -> Result<RangeProof<F, H::Digest>, QmdbError> {
    let status = proof_bitmap::<F, H::Digest, N>(session, tip, None).await?;
    RangeProof::new::<H, _, N>(
        &status,
        &storage::<F, H, N>(session, tip)?,
        tip.inactivity_floor,
        start..end,
        tip.ops.root,
    )
    .await
    .map_err(crate::error::current_proof_error)
}
