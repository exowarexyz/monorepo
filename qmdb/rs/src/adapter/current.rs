//! Current-state proof reads shared by the ordered and unordered adapters.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bytes::Bytes;
use commonware_codec::{Copying, DecodeExt};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::merkle::{ElementPlan, Family, Graftable, Location, Position, RangePlan};
use commonware_storage::qmdb::current::proof::{constant::OperationProof, RangeProof};
use exoware_sdk::{RangeMode, ReadSession};

use crate::adapter::codec::{
    chunk_index_for_location, clear_below_floor, decode_current_boundary_metadata,
    decode_update_index_value_present, decode_update_location, encode_chunk_key,
    encode_current_meta_key, encode_node_key, encode_operation_key, encode_presence_key,
    merkle_size_for_watermark, op_count_for_watermark,
};
use crate::adapter::core;
use crate::adapter::operation_range::root;
use crate::adapter::read_cache::{ReadCache, RootContext};
use crate::adapter::storage::{
    load_proof_nodes, tail_chunk, BitmapTail, ProofBitmap, ProofNodes, TailIndices,
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

/// The operation row, bitmap chunk and proof nodes for a current proof of one
/// operation, read together by [`load_proof_reads`].
pub(crate) struct ProofReads<F: Family, const N: usize> {
    /// The proof's plan, which the reads cover and its build consumes.
    plan: ElementPlan<F>,
    /// The encoded operation at the plan's location.
    pub(crate) operation: Bytes,
    /// The operation's bitmap chunk, unless the chunk is pruned.
    chunk: Option<[u8; N]>,
    nodes: ProofNodes<F>,
}

/// Location of `key`'s latest update at the tip, which must hold a value.
/// An update that holds a value below the inactivity floor contradicts the
/// tip, so the index is corrupt.
pub(crate) async fn locate_active_key<F: Family, D: Digest>(
    session: &ReadSession,
    tip: &CurrentTip<F, D>,
    key: &[u8],
) -> Result<Location<F>, QmdbError> {
    let watermark = tip.watermark;
    let Some((row_key, row_value)) = core::load_latest_update_row(session, watermark, key).await?
    else {
        return Err(QmdbError::ProofKeyNotFound {
            watermark: watermark.as_u64(),
            key: key.to_vec(),
        });
    };
    let location = decode_update_location(&row_key)?;
    if !decode_update_index_value_present(row_value.as_ref())? {
        return Err(QmdbError::KeyNotActive {
            watermark: watermark.as_u64(),
            key: key.to_vec(),
        });
    }
    if location < tip.inactivity_floor {
        return Err(QmdbError::CorruptData(format!(
            "latest update at {location} holds a value below inactivity floor {}",
            tip.inactivity_floor
        )));
    }
    Ok(location)
}

/// Read everything a current proof of the operation at `location` needs in one
/// phase: its proof nodes as planned by commonware, with the operation row in
/// the first node batch, alongside its bitmap chunk (unless a tail chunk).
pub(crate) async fn load_proof_reads<F: Graftable, H: Hasher, const N: usize>(
    session: &ReadSession,
    cache: &Arc<ReadCache<F, H::Digest>>,
    tip: &CurrentTip<F, H::Digest>,
    location: Location<F>,
) -> Result<ProofReads<F, N>, QmdbError> {
    let leaves = op_count_for_watermark(tip.watermark)?;
    let plan = ElementPlan::new(leaves, location).map_err(crate::error::merkle_error)?;
    let positions = plan.positions();
    let chunk_index = chunk_index_for_location::<F, N>(location);
    let operation_key = encode_operation_key(location);
    let ((mut rows, nodes), chunk) = futures::try_join!(
        load_proof_nodes::<F, H::Digest, N>(
            session,
            cache,
            tip.watermark,
            tip.pruned_chunks,
            positions,
            BTreeSet::from([operation_key.clone()]),
        ),
        async {
            if chunk_index < tip.pruned_chunks {
                return Ok(None);
            }
            load_chunk::<F, H::Digest, N>(session, tip, chunk_index)
                .await
                .map(Some)
        },
    )?;
    let Some(operation) = rows.remove(&operation_key) else {
        return Err(QmdbError::CorruptData(format!(
            "missing operation row at location {location}"
        )));
    };
    Ok(ProofReads {
        plan,
        operation,
        chunk,
        nodes,
    })
}

/// The plan and proof nodes for a current range proof, read together by
/// [`load_range_reads`].
pub(crate) struct RangeReads<F: Family> {
    plan: RangePlan<F>,
    nodes: ProofNodes<F>,
}

/// The plan and proof nodes for the current range proof of `[start, end)`.
pub(crate) async fn load_range_reads<F: Graftable, H: Hasher, const N: usize>(
    session: &ReadSession,
    cache: &Arc<ReadCache<F, H::Digest>>,
    tip: &CurrentTip<F, H::Digest>,
    start: Location<F>,
    end: Location<F>,
) -> Result<RangeReads<F>, QmdbError> {
    let leaves = op_count_for_watermark(tip.watermark)?;
    let plan = RangePlan::new(leaves, start..end).map_err(crate::error::merkle_error)?;
    let (_, nodes) = load_proof_nodes::<F, H::Digest, N>(
        session,
        cache,
        tip.watermark,
        tip.pruned_chunks,
        plan.positions(),
        BTreeSet::new(),
    )
    .await?;
    Ok(RangeReads { plan, nodes })
}

/// Current-state proof for the operation `reads` was loaded for, built from
/// `reads` alone.
pub(crate) fn operation_proof<F: Graftable, H: Hasher, const N: usize>(
    tip: &CurrentTip<F, H::Digest>,
    reads: ProofReads<F, N>,
) -> Result<OperationProof<F, H::Digest, N>, QmdbError> {
    let mut status = ProofBitmap::new(tip.watermark, tip.pruned_chunks, &tip.tail)?;
    if let Some(index) = status.chunk_to_prove(reads.plan.location())? {
        let chunk = reads.chunk.ok_or_else(|| {
            QmdbError::CorruptData(format!("current proof chunk {index} was not read"))
        })?;
        status.insert(index, chunk)?;
    }
    let digests = reads
        .nodes
        .digests::<H, N>(tip.pruned_chunks, &reads.plan.positions())
        .map_err(crate::error::merkle_error)?;
    OperationProof::build::<H>(
        &status,
        reads.plan,
        |position| digests.get(&position).copied(),
        tip.inactivity_floor,
        tip.ops.root,
    )
    .map_err(crate::error::current_proof_error)
}

/// Current-state range proof built from [`load_range_reads`].
pub(crate) fn range_proof<F: Graftable, H: Hasher, const N: usize>(
    tip: &CurrentTip<F, H::Digest>,
    reads: RangeReads<F>,
) -> Result<RangeProof<F, H::Digest>, QmdbError> {
    let status = ProofBitmap::new(tip.watermark, tip.pruned_chunks, &tip.tail)?;
    let digests = reads
        .nodes
        .digests::<H, N>(tip.pruned_chunks, &reads.plan.positions())
        .map_err(crate::error::merkle_error)?;
    RangeProof::build::<H, N>(
        &status,
        reads.plan,
        |position| digests.get(&position).copied(),
        tip.inactivity_floor,
        tip.ops.root,
    )
    .map_err(crate::error::current_proof_error)
}
