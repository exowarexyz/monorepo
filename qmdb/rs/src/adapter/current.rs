//! Current-state proof reads shared by the ordered and unordered adapters.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

use bytes::Bytes;
use commonware_codec::{Copying, DecodeExt};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::merkle::{Family, Graftable, Location, Position};
use commonware_storage::qmdb::current::proof::{
    constant::OperationProof, operation_proof_positions, range_proof_positions, RangeProof,
};
use exoware_sdk::{RangeMode, ReadSession};
use futures::FutureExt;

use crate::adapter::codec::{
    chunk_index_for_location, clear_below_floor, decode_current_boundary_metadata,
    encode_chunk_key, encode_current_meta_key, encode_node_key, encode_operation_key,
    encode_presence_key, merkle_size_for_watermark, op_count_for_watermark,
};
use crate::adapter::core;
use crate::adapter::operation_range::root;
use crate::adapter::read_cache::{ReadCache, RootContext};
use crate::adapter::storage::{
    load_proof_nodes, tail_chunk, BitmapTail, CurrentProofStorage, ProofBitmap, ProofNodes,
    TailIndices,
};
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
    /// Bitmap chunks every proof at this tip reads.
    pub tail: BitmapTail,
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
    let indices = TailIndices::at::<F, N>(watermark)?;
    let load_tail = |index: Option<u64>| async move {
        let Some(index) = index else {
            return Ok(None);
        };
        let chunk = load_chunk_row::<F, N>(session, watermark, index).await?;
        Ok::<_, QmdbError>(Some(chunk))
    };
    let (mut rows, pending_chunk, last_chunk) = futures::try_join!(
        async { Ok::<_, QmdbError>(session.get_many(&keys, batch_size).await?.collect().await?) },
        load_tail(indices.pending),
        load_tail(indices.last),
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
    let keep = |index: Option<u64>, chunk: Option<[u8; N]>| {
        index.zip(chunk).map(|(index, mut chunk)| {
            clear_below_floor::<F, N>(&mut chunk, index, inactivity_floor);
            Bytes::copy_from_slice(&chunk)
        })
    };
    Ok(CurrentTip {
        watermark,
        root: meta.root,
        pruned_chunks: meta.pruned_chunks,
        inactivity_floor,
        ops,
        tail: BitmapTail {
            pending: keep(indices.pending, pending_chunk),
            last: keep(indices.last, last_chunk),
        },
    })
}

/// Bitmap chunk `index` at the tip, with bits below the floor cleared: the
/// cached tail chunk when it is one, else its latest version at or below the
/// watermark.
async fn load_chunk<F: Graftable, D: Digest, const N: usize>(
    session: &ReadSession,
    tip: &CurrentTip<F, D>,
    index: u64,
) -> Result<[u8; N], QmdbError> {
    let indices = TailIndices::at::<F, N>(tip.watermark)?;
    let cached = if indices.pending == Some(index) {
        tip.tail.pending.as_ref()
    } else if indices.last == Some(index) {
        tip.tail.last.as_ref()
    } else {
        None
    };
    if let Some(chunk) = cached {
        return tail_chunk(chunk);
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
    let mut bitmap = ProofBitmap::new(tip.watermark, tip.pruned_chunks, &tip.tail)?;
    if let Some(location) = location {
        if let Some(index) = bitmap.chunk_to_prove(location)? {
            bitmap.insert(index, load_chunk::<F, D, N>(session, tip, index).await?)?;
        }
    }
    Ok(bitmap)
}

/// Proof construction reads only [`ProofNodes`] already in memory, so it
/// completes without waiting; waiting would mean it reached for the Store.
fn construction_awaited() -> QmdbError {
    QmdbError::CommonwareMerkle("current proof construction waited on unread nodes".into())
}

fn storage<'a, F: Graftable, H: Hasher, const N: usize>(
    tip: &CurrentTip<F, H::Digest>,
    nodes: &'a ProofNodes<F>,
) -> Result<CurrentProofStorage<'a, F, H, N>, QmdbError> {
    Ok(CurrentProofStorage {
        nodes,
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
    let leaves = op_count_for_watermark(tip.watermark)?;
    let positions = operation_proof_positions::<F, N>(leaves, tip.inactivity_floor, location)
        .map_err(crate::error::current_proof_error)?;
    let nodes =
        load_proof_nodes::<F, N>(session, tip.watermark, tip.pruned_chunks, positions).await?;
    OperationProof::new::<H, _>(
        &status,
        &storage::<F, H, N>(tip, &nodes)?,
        tip.inactivity_floor,
        location,
        tip.ops.root,
    )
    .now_or_never()
    .ok_or_else(construction_awaited)?
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
    let leaves = op_count_for_watermark(tip.watermark)?;
    let positions = range_proof_positions::<F, N>(leaves, tip.inactivity_floor, start..end)
        .map_err(crate::error::current_proof_error)?;
    let nodes =
        load_proof_nodes::<F, N>(session, tip.watermark, tip.pruned_chunks, positions).await?;
    RangeProof::new::<H, _, N>(
        &status,
        &storage::<F, H, N>(tip, &nodes)?,
        tip.inactivity_floor,
        start..end,
        tip.ops.root,
    )
    .now_or_never()
    .ok_or_else(construction_awaited)?
    .map_err(crate::error::current_proof_error)
}
