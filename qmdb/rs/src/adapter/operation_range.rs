use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use commonware_codec::{Copying, DecodeExt};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::merkle::{hasher::Hasher as _, Family, Graftable, Location, Position};
use commonware_storage::qmdb::current::proof::OpsRootWitness;
use exoware_sdk::{keys::Key, ReadSession};

use crate::adapter::codec::{
    encode_node_key, encode_operation_key, encode_ops_root_witness_key, merkle_size_for_watermark,
    op_count_for_watermark,
};
use crate::adapter::core::load_operation_bytes_range;
use crate::adapter::prefetch::{multi_positions, range_positions, PrefetchedMerkleStorage};
use crate::adapter::read_cache::{ReadCache, RootContext};
use crate::proof::{
    build_batch_multi_proof, build_operation_range_checkpoint, MultiProofOperations,
    OperationRangeCheckpoint, RawBatchMultiProof,
};
use crate::{decode_digest, QmdbError};

pub(crate) async fn load_operation_range_checkpoint<F, H, Fut>(
    session: &ReadSession,
    cache: &Arc<ReadCache<F, H::Digest>>,
    watermark: Location<F>,
    start: Location<F>,
    end: Location<F>,
    with_witness: bool,
    resolve_inactive_peaks: impl FnOnce(Bytes) -> Fut,
) -> Result<OperationRangeCheckpoint<H::Digest, F>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    Fut: Future<Output = Result<usize, QmdbError>>,
{
    let size = merkle_size_for_watermark(watermark)?;
    let positions = range_positions(watermark, start, end)?;
    let mut keys = BTreeSet::new();
    if *end - *start == 1 {
        keys.insert(encode_operation_key(start));
    }
    let metadata = load_published_reads::<F, H, _>(
        session,
        cache,
        watermark,
        &positions,
        keys,
        with_witness,
        resolve_inactive_peaks,
    );

    // Both reads inherit the publication check's observed floor. Interpret range errors
    // after inactivity metadata and root peaks, regardless of completion order.
    let (mut reads, operations) = futures::try_join!(metadata, async {
        let operations = if *end - *start > 1 {
            load_operation_bytes_range(session, start, end).await
        } else {
            Ok(Vec::new())
        };
        Ok::<_, QmdbError>(operations)
    })?;
    let operations = if *end - *start == 1 {
        vec![reads
            .rows
            .remove(&encode_operation_key(start))
            .ok_or_else(|| {
                QmdbError::CorruptData(format!("missing operation row at location {start}"))
            })?
            .to_vec()]
    } else {
        operations?
    };
    let storage = PrefetchedMerkleStorage::<F, H::Digest>::new(size, reads.nodes);
    let mut checkpoint = build_operation_range_checkpoint::<F, H, _>(
        &storage,
        watermark,
        start,
        end,
        reads.context.root,
        reads.context.inactive_peaks,
        operations,
    )
    .await?;
    checkpoint.ops_root_witness = reads.witness?;
    Ok(checkpoint)
}

/// Build a multi-proof with one batched read of any operation rows still to
/// read and every planned node, reusing cached root context, witness, and nodes
/// like range reads.
pub(crate) async fn load_operations_multi_proof<F, H, Fut>(
    session: &ReadSession,
    cache: &Arc<ReadCache<F, H::Digest>>,
    watermark: Location<F>,
    operations: MultiProofOperations<'_, F>,
    with_witness: bool,
    resolve_inactive_peaks: impl FnOnce(Bytes) -> Fut,
) -> Result<RawBatchMultiProof<H::Digest, F>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    Fut: Future<Output = Result<usize, QmdbError>>,
{
    let size = merkle_size_for_watermark(watermark)?;
    let locations = match &operations {
        MultiProofOperations::Read(locations) => locations.to_vec(),
        MultiProofOperations::Given(operations) => {
            operations.iter().map(|(location, _)| *location).collect()
        }
    };
    let positions = multi_positions(watermark, &locations)?;
    let keys = match &operations {
        MultiProofOperations::Read(locations) => locations
            .iter()
            .map(|&location| encode_operation_key(location))
            .collect(),
        MultiProofOperations::Given(_) => BTreeSet::new(),
    };
    let mut reads = load_published_reads::<F, H, _>(
        session,
        cache,
        watermark,
        &positions,
        keys,
        with_witness,
        resolve_inactive_peaks,
    )
    .await?;
    let operations = match operations {
        MultiProofOperations::Read(locations) => locations
            .iter()
            .map(|&location| {
                let bytes = reads
                    .rows
                    .remove(&encode_operation_key(location))
                    .ok_or_else(|| {
                        QmdbError::CorruptData(format!(
                            "missing operation row at location {location}"
                        ))
                    })?;
                Ok((location, bytes.to_vec()))
            })
            .collect::<Result<Vec<_>, QmdbError>>()?,
        MultiProofOperations::Given(operations) => operations,
    };
    let storage = PrefetchedMerkleStorage::<F, H::Digest>::new(size, reads.nodes);
    let mut proof = build_batch_multi_proof::<F, H, _>(
        &storage,
        watermark,
        reads.context.root,
        reads.context.inactive_peaks,
        operations,
    )
    .await?;
    proof.ops_root_witness = reads.witness?;
    Ok(proof)
}

/// Rows, nodes, root context, and ops-root witness for one published watermark.
struct PublishedReads<F: Graftable, D: Digest> {
    rows: HashMap<Key, Bytes>,
    nodes: BTreeMap<Position<F>, Option<Bytes>>,
    context: RootContext<D>,
    /// Decode errors surface after the proof is built, matching range reads.
    witness: Result<Option<OpsRootWitness<F, D>>, QmdbError>,
}

/// Read `keys` and the planned `positions` in one batched request, adding the
/// watermark operation and witness rows only when the cache lacks them.
async fn load_published_reads<F, H, Fut>(
    session: &ReadSession,
    cache: &Arc<ReadCache<F, H::Digest>>,
    watermark: Location<F>,
    positions: &[Position<F>],
    mut keys: BTreeSet<Key>,
    with_witness: bool,
    resolve_inactive_peaks: impl FnOnce(Bytes) -> Fut,
) -> Result<PublishedReads<F, H::Digest>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    Fut: Future<Output = Result<usize, QmdbError>>,
{
    let context = cache.cached_context(watermark);
    let witness = with_witness.then(|| cache.witness(watermark)).flatten();
    if context.is_none() {
        keys.insert(encode_operation_key(watermark));
    }
    if with_witness && witness.is_none() {
        keys.insert(encode_ops_root_witness_key(watermark));
    }
    let (rows, nodes) = fetch_rows(session, cache, positions, keys).await?;

    // Fetch each request's rows before coalescing metadata work so a cold watermark
    // does not add another network phase for followers.
    // The gate shares the floor walk. After failure, followers retry in their own sessions.
    let (context, context_guard) = match context {
        Some(context) => (Some(context), None),
        None => cache.context(watermark).await,
    };
    let context = match context {
        Some(context) => context,
        None => {
            let operation = rows.get(&encode_operation_key(watermark)).ok_or_else(|| {
                QmdbError::CorruptData(format!("missing operation row at location {watermark}"))
            })?;
            let inactive_peaks = resolve_inactive_peaks(operation.clone()).await?;
            RootContext {
                root: root::<F, H>(&nodes, watermark, inactive_peaks)?,
                inactive_peaks,
            }
        }
    };
    let witness_cached = witness.is_some();
    let witness = witness
        .or_else(|| rows.get(&encode_ops_root_witness_key(watermark)).cloned())
        .map(|bytes| {
            let witness = OpsRootWitness::<F, H::Digest>::decode(Copying(bytes.as_ref())).map_err(
                |error| {
                    QmdbError::CorruptData(format!(
                        "current ops-root witness at {watermark} decode error: {error}"
                    ))
                },
            )?;
            if !witness_cached {
                cache.put_witness(watermark, bytes);
            }
            Ok::<_, QmdbError>(witness)
        })
        .transpose();

    // Published metadata is immutable. Share it without waiting for this request's
    // operation scan or proof, which each caller still verifies independently.
    cache.put_context(watermark, context);
    drop(context_guard);
    Ok(PublishedReads {
        rows,
        nodes,
        context,
        witness,
    })
}

fn root<F: Family, H: Hasher>(
    nodes: &BTreeMap<Position<F>, Option<Bytes>>,
    watermark: Location<F>,
    inactive_peaks: usize,
) -> Result<H::Digest, QmdbError> {
    let size = merkle_size_for_watermark(watermark)?;
    let mut peaks = Vec::new();
    for (position, _) in F::peaks(size) {
        let bytes = nodes
            .get(&position)
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                QmdbError::CorruptData(format!("missing Merkle peak node at position {position}"))
            })?;
        peaks.push(decode_digest::<H::Digest>(
            bytes,
            format_args!("Merkle peak node at position {position}"),
        )?);
    }
    commonware_storage::qmdb::hasher::<H>()
        .root(
            op_count_for_watermark(watermark)?,
            inactive_peaks,
            peaks.iter(),
        )
        .map_err(|error| QmdbError::CommonwareMerkle(error.to_string()))
}

async fn fetch_rows<F: Family, D: Digest>(
    session: &ReadSession,
    cache: &Arc<ReadCache<F, D>>,
    positions: &[Position<F>],
    mut keys: BTreeSet<Key>,
) -> Result<(HashMap<Key, Bytes>, BTreeMap<Position<F>, Option<Bytes>>), QmdbError> {
    let mut nodes = BTreeMap::new();
    let mut rows = HashMap::new();
    let reservation = cache.reserve(positions);
    nodes.extend(
        reservation
            .hits
            .iter()
            .map(|(&position, bytes)| (position, Some(bytes.clone()))),
    );
    for &position in &reservation.owned {
        keys.insert(encode_node_key(position));
    }
    let keys = keys.into_iter().collect::<Vec<_>>();
    if !keys.is_empty() {
        let refs = keys.iter().collect::<Vec<_>>();
        rows.extend(
            session
                .get_many(&refs, u32::try_from(keys.len()).unwrap_or(u32::MAX))
                .await?
                .collect()
                .await?,
        );
    }
    let mut positive = Vec::new();
    for &position in &reservation.owned {
        let bytes = rows.remove(&encode_node_key(position));
        if let Some(bytes) = &bytes {
            positive.push((position, bytes.clone()));
        }
        nodes.insert(position, bytes);
    }
    let pending = reservation.complete(positive);
    nodes.extend(
        pending
            .wait()
            .await
            .into_iter()
            .map(|(position, bytes)| (position, Some(bytes))),
    );

    // Read unresolved followers directly so replacement flights cannot keep delaying this request.
    let remaining = positions
        .iter()
        .copied()
        .filter(|position| !nodes.contains_key(position))
        .collect::<Vec<_>>();
    if !remaining.is_empty() {
        let keys = remaining
            .iter()
            .map(|&position| encode_node_key(position))
            .collect::<Vec<_>>();
        let refs = keys.iter().collect::<Vec<_>>();
        let mut fetched = session
            .get_many(&refs, u32::try_from(keys.len()).unwrap_or(u32::MAX))
            .await?
            .collect()
            .await?;
        for (position, key) in remaining.into_iter().zip(keys) {
            nodes.insert(position, fetched.remove(&key));
        }
    }
    Ok((rows, nodes))
}
