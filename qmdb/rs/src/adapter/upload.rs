//! Prepare Store rows for Commonware QMDB uploads.
//!
//! [`prepare_authenticated_range`] and [`prepare_publication`] each check their input against a
//! trusted root before they prepare any row, and [`prepare_publication`] adds the batch's
//! current-state rows. [`stage_authenticated_range`] adds prepared rows to a Store write batch,
//! and [`stage_watermark`] adds the watermark that makes the durable prefix visible to readers.
//! Nothing here reads the Store or keeps state between calls.
//!
//! ```text
//!     AuthenticatedOperationRange                           Publication
//!   and a trusted operation-log root                 and a trusted current root
//!                  |                                             |
//!     prepare_authenticated_range                       prepare_publication
//!                  |                                             |
//!                  '--------> PreparedAuthenticatedRange <-------'
//!                                         |
//!                             stage_authenticated_range                      watermark
//!                                         |                                      |
//!                                         v                               stage_watermark
//!                                  StoreWriteBatch <-----------------------------'
//! ```
//!
//! Ranges may overlap and contain several commits, and every upload to a namespace must belong
//! to the same operation history, so repeated operation and Merkle node keys carry identical
//! values and any upload can be retried.

use crate::{
    adapter::{
        codec::{
            encode_chunk_key, encode_current_meta_key, encode_grafted_node_key, encode_node_key,
            encode_operation_key, encode_ops_root_witness_key, encode_presence_key,
            encode_update_index_value, encode_update_key, encode_watermark_key,
            ensure_encoded_value_size, CurrentBoundaryMetadata,
        },
        core::{extend_merkle_from_pinned_nodes, MerkleExtension},
    },
    error::current_proof_error,
    ProofKind, QmdbError,
};
use bytes::BufMut;
use commonware_codec::{Buf, Codec, Copying, Encode, EncodeSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_storage::{
    index::Unordered as UnorderedIndex,
    journal::contiguous::Contiguous,
    merkle::{Family, Graftable, Location, Position},
    qmdb::{
        any::operation::{Operation as AnyOperation, Update},
        current::{batch::MerkleizedBatch, db::Db, grafting, proof::OpsRootWitness},
        immutable, keyless,
        operation::{Committable, Floored, Key as QmdbKey},
        value::ValueEncoding,
    },
    Context,
};
use commonware_utils::{bitmap::Readable as _, iter::zip_eq};
use exoware_sdk::{keys::Key, PrefixedStoreClient, StoreWriteBatch};
use std::{collections::BTreeSet, sync::Arc};

/// An operation range and prefix frontier for authentication against a trusted root.
#[derive(Clone, Copy, Debug, PartialEq)]
#[must_use]
pub struct AuthenticatedOperationRange<'a, D: Digest, F: Family> {
    /// Inclusive operation location where the range starts.
    pub start_location: Location<F>,
    /// Exclusive operation location committed by the expected root.
    pub end_location: Location<F>,
    /// Canonical inactive peak count determined by the final commit floor.
    pub inactive_peaks: usize,
    /// Prefix frontier in [`Family::nodes_to_pin`] order.
    pub pinned_nodes: &'a [D],
    /// Canonical operation encodings in location order.
    pub encoded_operations: &'a [Vec<u8>],
}

/// A QMDB operation whose keyed changes can be indexed for historical queries.
pub trait UploadOperation<F: Family>: Codec + Floored<F> {
    /// Return the affected key and whether its value is present after this operation.
    ///
    /// Commits and keyless operations return `None`. Deletions return `Some((key, false))`.
    fn indexed_key(&self) -> Option<(&[u8], bool)>;
}

impl<F: Family, U: Update> UploadOperation<F> for AnyOperation<F, U>
where
    Self: Codec,
{
    fn indexed_key(&self) -> Option<(&[u8], bool)> {
        match self {
            Self::Delete(key) => Some((key.as_ref(), false)),
            Self::Update(update) => Some((update.key().as_ref(), true)),
            Self::CommitFloor(_, _) => None,
        }
    }
}

impl<F: Family, K: QmdbKey, E: ValueEncoding> UploadOperation<F> for immutable::Operation<F, K, E>
where
    Self: Codec,
{
    fn indexed_key(&self) -> Option<(&[u8], bool)> {
        match self {
            Self::Set(key, _) => Some((key.as_ref(), true)),
            Self::Commit(_, _) => None,
        }
    }
}

impl<F: Family, E: ValueEncoding> UploadOperation<F> for keyless::Operation<F, E>
where
    Self: Codec,
{
    fn indexed_key(&self) -> Option<(&[u8], bool)> {
        None
    }
}

/// Deterministic logical Store rows prepared by [`prepare_authenticated_range`] or
/// [`prepare_publication`].
#[derive(Debug, PartialEq)]
#[must_use]
pub struct PreparedAuthenticatedRange<D: Digest, F: Family> {
    rows: Vec<(Key, Vec<u8>)>,
    pinned_nodes: Vec<(Position<F>, D)>,
    start_location: Location<F>,
    latest_location: Location<F>,
}

impl<D: Digest, F: Family> PreparedAuthenticatedRange<D, F> {
    /// Exclude supplied pins at these positions from staging, without omitting reconstructed nodes.
    /// Omitted pins must be durable before the watermark covers them and retained for proofs, as
    /// described under [pin omission].
    ///
    /// [pin omission]: https://github.com/exowarexyz/monorepo/tree/main/qmdb/rs#pin-omission
    pub fn without_pins_at(mut self, positions: &BTreeSet<Position<F>>) -> Self {
        self.pinned_nodes
            .retain(|(position, _)| !positions.contains(position));
        self
    }

    /// Inclusive first operation location in this range.
    pub const fn start_location(&self) -> Location<F> {
        self.start_location
    }

    /// Inclusive final operation location in this range.
    pub const fn latest_location(&self) -> Location<F> {
        self.latest_location
    }
}

/// Verify an operation range and prepare its operation, index, and Merkle node rows.
///
/// `expected_root` must be trusted independently of the supplied range and pins. The range
/// must end at a commit whose floor determines the canonical inactive peak count. Earlier
/// commits are accepted, allowing bootstrap, prefixes, and overlapping uploads to use this API.
/// The operation codec configuration must match the originating QMDB variant.
/// Reconstruction authenticates the range and pins before operation decoding.
pub fn prepare_authenticated_range<F, H, Op, S>(
    authenticated: &AuthenticatedOperationRange<'_, H::Digest, F>,
    expected_root: &H::Digest,
    op_cfg: &Op::Cfg,
    strategy: &S,
) -> Result<PreparedAuthenticatedRange<H::Digest, F>, QmdbError>
where
    F: Family,
    H: Hasher,
    Op: UploadOperation<F>,
    S: Strategy,
{
    let extension = reconstruct_range::<F, H, _>(authenticated, strategy)?;
    if extension.root != *expected_root {
        return Err(QmdbError::ProofVerification {
            kind: ProofKind::OperationRange,
        });
    }

    // Decode only once the range authenticates, and accept only canonical encodings.
    let operations = authenticated
        .encoded_operations
        .iter()
        .enumerate()
        .map(|(offset, encoded)| {
            let location = authenticated.start_location + offset as u64;
            let operation = Op::decode_cfg(Copying(encoded), op_cfg).map_err(|error| {
                QmdbError::CorruptData(format!(
                    "failed to decode authenticated operation at {location}: {error}"
                ))
            })?;
            if operation.encode().as_ref() != encoded {
                return Err(QmdbError::CorruptData(format!(
                    "authenticated operation at {location} is not canonically encoded"
                )));
            }
            Ok(operation)
        })
        .collect::<Result<Vec<_>, _>>()?;
    prepare_rows(authenticated, extension, &operations)
}

/// What an Exoware writer stores for one current QMDB batch. Replaying `operations` onto
/// `pinned_nodes` under the final commit's floor rebuilds the operation-log root, and
/// `ops_root_witness` binds that root to `root`.
#[derive(Clone)]
#[must_use]
pub struct Publication<F: Graftable, D: Digest, U: Update, const N: usize> {
    /// Location of the first operation.
    pub start_location: Location<F>,
    /// Operation-log frontier at `start_location`, in [`Family::nodes_to_pin`] order.
    pub pinned_nodes: Vec<D>,
    /// Operations the batch appends from `start_location`, ending with its commit.
    pub operations: Arc<Vec<AnyOperation<F, U>>>,
    /// Canonical current root after the batch.
    pub root: D,
    /// Witness binding the operation-log root after the batch to `root`.
    pub ops_root_witness: OpsRootWitness<F, D>,
    /// Bitmap chunks below this index were pruned when the batch was merkleized.
    pub pruned_chunks: u64,
    /// Bitmap chunks the batch wrote, by ascending index.
    pub chunks: Vec<(u64, [u8; N])>,
    /// Grafted nodes the batch appended or overwrote, by ascending operation-log position.
    pub grafted_nodes: Vec<(Position<F>, D)>,
}

impl<F: Graftable, D: Digest, U: Update, const N: usize> Publication<F, D, U, N>
where
    AnyOperation<F, U>: Codec,
{
    /// Build `batch`'s publication from the batch and `db`. Call this before applying `batch`,
    /// because its frontier is readable only until the batch's changes are flushed. The frontier
    /// reads through `batch`'s unapplied ancestors, so they must still be held.
    pub fn from_batch<E, C, I, H, S>(
        batch: &MerkleizedBatch<F, D, U, N, S>,
        db: &Db<F, E, C, I, H, U, N, S>,
    ) -> Result<Self, QmdbError>
    where
        E: Context,
        C: Contiguous<Item = AnyOperation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        let pinned_nodes = batch.ops_pinned_nodes(db).map_err(current_proof_error)?;
        let (start_location, operations) = batch.operations();
        Ok(Self {
            start_location,
            pinned_nodes,
            operations,
            root: batch.root(),
            ops_root_witness: batch.ops_root_witness().clone(),
            pruned_chunks: batch.pruned_chunks(),
            chunks: batch.chunks(),
            grafted_nodes: batch.grafted_nodes(),
        })
    }

    /// Build the publication of a new database's initial commit. No batch includes that commit,
    /// so upload this publication before the one of the database's first batch.
    pub fn initial<E, C, I, H, S>(db: &Db<F, E, C, I, H, U, N, S>) -> Result<Self, QmdbError>
    where
        E: Context,
        C: Contiguous<Item = AnyOperation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        if db.bounds().end != Location::new(1) {
            return Err(QmdbError::CorruptData(
                "initial publication must come from a database holding only its initial commit"
                    .into(),
            ));
        }
        let bitmap = db.bitmap();
        Ok(Self {
            start_location: Location::new(0),
            pinned_nodes: Vec::new(),
            operations: Arc::new(vec![AnyOperation::CommitFloor(None, Location::new(0))]),
            root: db.root(),
            ops_root_witness: db.ops_root_witness().clone(),
            pruned_chunks: bitmap.pruned_chunks() as u64,
            chunks: vec![(0, bitmap.get_chunk(0))],
            grafted_nodes: Vec::new(),
        })
    }
}

/// Decoding limits for a [`Publication`].
#[derive(Clone, Debug)]
pub struct PublicationCfg<C> {
    /// Configuration of each operation.
    pub operation: C,
    /// Accepted number of operations.
    pub operations: RangeCfg<usize>,
    /// Accepted number of bitmap chunks.
    pub chunks: RangeCfg<usize>,
    /// Accepted number of grafted nodes.
    pub grafted_nodes: RangeCfg<usize>,
}

impl<F: Graftable, D: Digest, U: Update, const N: usize> Write for Publication<F, D, U, N>
where
    AnyOperation<F, U>: Write,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.start_location.write(buf);
        self.pinned_nodes.write(buf);
        self.operations.write(buf);
        self.root.write(buf);
        self.ops_root_witness.write(buf);
        self.pruned_chunks.write(buf);
        self.chunks.write(buf);
        self.grafted_nodes.write(buf);
    }
}

impl<F: Graftable, D: Digest, U: Update, const N: usize> EncodeSize for Publication<F, D, U, N>
where
    AnyOperation<F, U>: EncodeSize,
{
    fn encode_size(&self) -> usize {
        self.start_location.encode_size()
            + self.pinned_nodes.encode_size()
            + self.operations.encode_size()
            + self.root.encode_size()
            + self.ops_root_witness.encode_size()
            + self.pruned_chunks.encode_size()
            + self.chunks.encode_size()
            + self.grafted_nodes.encode_size()
    }
}

impl<F: Graftable, D: Digest, U: Update, const N: usize> Read for Publication<F, D, U, N>
where
    AnyOperation<F, U>: Read,
{
    type Cfg = PublicationCfg<<AnyOperation<F, U> as Read>::Cfg>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        // The frontier at `start_location` has a fixed number of nodes.
        let start_location = Location::<F>::read(buf)?;
        let pins = F::nodes_to_pin(start_location).count();
        Ok(Self {
            start_location,
            pinned_nodes: Vec::read_cfg(buf, &(RangeCfg::exact(pins), ()))?,
            operations: Arc::read_cfg(buf, &(cfg.operations, cfg.operation.clone()))?,
            root: D::read(buf)?,
            ops_root_witness: OpsRootWitness::read(buf)?,
            pruned_chunks: u64::read(buf)?,
            chunks: Vec::read_cfg(buf, &(cfg.chunks, ((), ())))?,
            grafted_nodes: Vec::read_cfg(buf, &(cfg.grafted_nodes, ((), ())))?,
        })
    }
}

/// Verify a current QMDB batch's [`Publication`] against `expected_root` and prepare its
/// operation rows and current-state rows. The root must be trusted independently of the
/// publication. The bitmap chunks, grafted nodes, and pruned chunk count are not authenticated
/// and must come from the source of the batch.
pub fn prepare_publication<F, H, U, S, const N: usize>(
    publication: &Publication<F, H::Digest, U, N>,
    expected_root: &H::Digest,
    strategy: &S,
) -> Result<PreparedAuthenticatedRange<H::Digest, F>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    U: Update,
    AnyOperation<F, U>: UploadOperation<F>,
    S: Strategy,
{
    // Anchor the publication to the trusted root before hashing any operations.
    if publication.root != *expected_root {
        return Err(QmdbError::ProofVerification {
            kind: ProofKind::Publication,
        });
    }

    // Rebuild the authenticated range from the publication. A publication holds one batch, so
    // its last operation must be its only commit. The floor of that commit fixes the canonical
    // inactive peak count.
    let operations = publication.operations.as_slice();
    let (floor, earlier) = operations
        .split_last()
        .and_then(|(last, earlier)| Some((last.inactivity_floor()?, earlier)))
        .ok_or_else(|| QmdbError::CorruptData("publication must end at a commit".into()))?;
    if earlier.iter().any(Committable::is_commit) {
        return Err(QmdbError::CorruptData(
            "publication must not contain a commit before its last operation".into(),
        ));
    }
    let end = publication
        .start_location
        .checked_add(operations.len() as u64)
        .ok_or_else(|| {
            QmdbError::CorruptData("publication end location must not overflow".into())
        })?;
    let encoded_operations = operations
        .iter()
        .map(|operation| operation.encode().to_vec())
        .collect::<Vec<_>>();
    let authenticated = AuthenticatedOperationRange {
        start_location: publication.start_location,
        end_location: end,
        inactive_peaks: F::inactive_peaks(end, floor),
        pinned_nodes: &publication.pinned_nodes,
        encoded_operations: &encoded_operations,
    };

    // The range authenticates only if the witness binds its rebuilt operation-log root to the
    // trusted root.
    let extension = reconstruct_range::<F, H, _>(&authenticated, strategy)?;
    if !publication
        .ops_root_witness
        .verify::<H>(&extension.root, expected_root)
    {
        return Err(QmdbError::ProofVerification {
            kind: ProofKind::Publication,
        });
    }
    let mut prepared = prepare_rows(&authenticated, extension, operations)?;

    // Add the current-state rows at the range's final location.
    let latest_location = prepared.latest_location;
    let rows = &mut prepared.rows;
    rows.reserve(2 + publication.chunks.len() + publication.grafted_nodes.len());
    rows.push((
        encode_current_meta_key(latest_location),
        CurrentBoundaryMetadata {
            root: publication.root,
            pruned_chunks: publication.pruned_chunks,
        }
        .encode()
        .to_vec(),
    ));
    rows.push((
        encode_ops_root_witness_key(latest_location),
        publication.ops_root_witness.encode().to_vec(),
    ));
    for &(chunk_index, chunk) in &publication.chunks {
        rows.push((
            encode_chunk_key(chunk_index, latest_location),
            chunk.encode().to_vec(),
        ));
    }

    // `grafting::ops_to_grafted_pos` panics for a node below the grafting height and, in an MMR,
    // for a position that exceeds the node limit once two is added, so both are rejected first.
    let grafting_height = grafting::height::<N>();
    for &(ops_position, digest) in &publication.grafted_nodes {
        if ops_position.checked_add(2).is_none() {
            return Err(QmdbError::CorruptData(format!(
                "grafted node at {ops_position} must not overflow"
            )));
        }
        if F::pos_to_height(ops_position) < grafting_height {
            return Err(QmdbError::CorruptData(format!(
                "grafted node at {ops_position} must be at or above the grafting height"
            )));
        }
        let grafted_position = grafting::ops_to_grafted_pos::<F>(ops_position, grafting_height);
        rows.push((
            encode_grafted_node_key(grafted_position, latest_location),
            digest.encode().to_vec(),
        ));
    }
    Ok(prepared)
}

/// Validate the shape of `authenticated` and rebuild its operation-log root and new Merkle nodes
/// from its pins and encoded operations. The caller must check the rebuilt root against its
/// trusted root before decoding or preparing anything from the range.
fn reconstruct_range<F, H, S>(
    authenticated: &AuthenticatedOperationRange<'_, H::Digest, F>,
    strategy: &S,
) -> Result<MerkleExtension<F, H::Digest>, QmdbError>
where
    F: Family,
    H: Hasher,
    S: Strategy,
{
    let start = authenticated.start_location;
    let end = authenticated.end_location;
    if !start.is_valid_index() || !end.is_valid() || start >= end {
        return Err(QmdbError::CorruptData(format!(
            "invalid authenticated operation range [{start}, {end})"
        )));
    }
    let expected_count = usize::try_from(*end - *start).map_err(|_| {
        QmdbError::CorruptData("authenticated operation count exceeds usize".into())
    })?;
    if authenticated.encoded_operations.len() != expected_count {
        return Err(QmdbError::CorruptData(format!(
            "authenticated range [{start}, {end}) contains {} operations",
            authenticated.encoded_operations.len()
        )));
    }

    // Reject oversized input before reconstruction hashes any operations.
    for encoded in authenticated.encoded_operations {
        ensure_encoded_value_size(encoded.len())?;
    }

    let pins = F::nodes_to_pin(start).count();
    if authenticated.pinned_nodes.len() != pins {
        return Err(QmdbError::CorruptData(format!(
            "authenticated range has {} pins, expected {}",
            authenticated.pinned_nodes.len(),
            pins
        )));
    }

    // Reconstruction also creates delayed MMB parents hidden by folded proof prefixes.
    extend_merkle_from_pinned_nodes::<F, H, S, _>(
        authenticated.pinned_nodes.to_vec(),
        start,
        authenticated.encoded_operations.iter().map(Vec::as_slice),
        authenticated.inactive_peaks,
        strategy,
    )
}

/// Prepare the operation, index, and Merkle node rows of a range whose rebuilt root the caller
/// has checked against its trusted root. `operations` are the range's canonical encodings,
/// decoded, in order. The range's shape was validated when it was reconstructed.
fn prepare_rows<F, D, Op>(
    authenticated: &AuthenticatedOperationRange<'_, D, F>,
    extension: MerkleExtension<F, D>,
    operations: &[Op],
) -> Result<PreparedAuthenticatedRange<D, F>, QmdbError>
where
    F: Family,
    D: Digest,
    Op: UploadOperation<F>,
{
    let start = authenticated.start_location;
    let end = authenticated.end_location;
    let latest_location = end - 1;
    let mut operation_rows = Vec::with_capacity(operations.len());
    let mut index_rows = Vec::new();
    let mut final_floor = None;
    for (offset, (operation, encoded)) in
        zip_eq(operations, authenticated.encoded_operations).enumerate()
    {
        let location = start + offset as u64;
        final_floor = operation.inactivity_floor();
        if let Some(floor) = final_floor {
            if !floor.is_valid() || floor > location {
                return Err(QmdbError::CorruptData(format!(
                    "authenticated commit floor {floor} exceeds commit location {location}"
                )));
            }
        }
        if let Some((key, value_present)) = operation.indexed_key() {
            index_rows.push((
                encode_update_key(key, location)?,
                encode_update_index_value(value_present),
            ));
        }
        operation_rows.push((encode_operation_key(location), encoded.clone()));
    }
    let floor = final_floor
        .ok_or_else(|| QmdbError::CorruptData("authenticated range must end at a commit".into()))?;
    if authenticated.inactive_peaks != F::inactive_peaks(end, floor) {
        return Err(QmdbError::CorruptData(
            "authenticated range has a noncanonical inactive peak count".into(),
        ));
    }

    let mut rows = operation_rows;
    rows.extend(index_rows);
    let pinned_nodes = zip_eq(
        F::nodes_to_pin(start),
        authenticated.pinned_nodes.iter().copied(),
    )
    .collect();
    rows.extend(
        extension
            .new_nodes
            .into_iter()
            .map(|(position, digest)| (encode_node_key(position), digest.encode().to_vec())),
    );
    rows.push((encode_presence_key(latest_location), Vec::new()));
    Ok(PreparedAuthenticatedRange {
        rows,
        pinned_nodes,
        start_location: start,
        latest_location,
    })
}

/// Stage the prepared rows and remaining supplied pins under the store's key prefix.
pub fn stage_authenticated_range<D: Digest, F: Family>(
    store: &PrefixedStoreClient,
    prepared: PreparedAuthenticatedRange<D, F>,
    batch: &mut StoreWriteBatch,
) -> Result<(), QmdbError> {
    batch.reserve(prepared.rows.len() + prepared.pinned_nodes.len());
    for (key, value) in prepared.rows {
        batch.push(store, &key, value)?;
    }
    for (position, digest) in prepared.pinned_nodes {
        batch.push(store, &encode_node_key(position), digest.encode())?;
    }
    Ok(())
}

/// Stage the watermark, the commit location that publishes the durable prefix, under the
/// store's key prefix.
///
/// The caller must only advance this location after every required row in the contiguous prefix
/// is durable, or when those rows are staged in the same atomic Store batch. For current QMDBs,
/// the current-state rows of every batch through this location must also be durable or staged.
pub fn stage_watermark<F: Family>(
    store: &PrefixedStoreClient,
    watermark: Location<F>,
    batch: &mut StoreWriteBatch,
) -> Result<(), QmdbError> {
    if !watermark.is_valid_index() {
        return Err(QmdbError::CorruptData(format!(
            "invalid published operation watermark {watermark}"
        )));
    }
    batch.push(store, &encode_watermark_key(watermark), Vec::new())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, DecodeExt, FixedSize};
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Sha256};
    use commonware_parallel::{mocks::Explorer, rayon::ThreadPoolBuilder, Rayon, Sequential};
    use commonware_storage::{
        merkle::{mem::Mem, mmb, mmr},
        qmdb::{
            any::{ordered, unordered},
            value::{FixedEncoding, VariableEncoding},
        },
    };
    use commonware_utils::sequence::FixedBytes;
    use exoware_sdk::{StoreClient, StoreKeyPrefix};
    use std::{
        collections::BTreeMap,
        num::NonZeroUsize,
        sync::atomic::{AtomicUsize, Ordering},
    };

    type FixedValueEncoding = FixedEncoding<FixedBytes<8>>;
    type FixedKeylessOperation<F> = keyless::Operation<F, FixedValueEncoding>;
    type CodecUpdate = unordered::Update<FixedBytes<8>, FixedValueEncoding>;
    type CodecPublication<F> = Publication<F, Sha256Digest, CodecUpdate, 32>;

    #[derive(Clone)]
    struct AuthenticatedRangeFixture<F: Family> {
        start_location: Location<F>,
        root: Sha256Digest,
        end_location: Location<F>,
        inactive_peaks: usize,
        pinned_nodes: Vec<Sha256Digest>,
        encoded_operations: Vec<Vec<u8>>,
        merkle_nodes: BTreeMap<Position<F>, Sha256Digest>,
    }

    impl<F: Family> AuthenticatedRangeFixture<F> {
        fn view(&self) -> AuthenticatedOperationRange<'_, Sha256Digest, F> {
            AuthenticatedOperationRange {
                start_location: self.start_location,
                end_location: self.end_location,
                inactive_peaks: self.inactive_peaks,
                pinned_nodes: &self.pinned_nodes,
                encoded_operations: &self.encoded_operations,
            }
        }

        fn prepare(&self) -> Result<PreparedAuthenticatedRange<Sha256Digest, F>, QmdbError> {
            prepare_authenticated_range::<F, Sha256, FixedKeylessOperation<F>, _>(
                &self.view(),
                &self.root,
                &(),
                &Sequential,
            )
        }
    }

    fn authenticated_range_fixture<F: Family>(
        encoded_history: &[Vec<u8>],
        start_location: u64,
        inactive_peaks: usize,
    ) -> AuthenticatedRangeFixture<F> {
        let hasher = commonware_storage::qmdb::hasher::<Sha256>();
        let mut memory = Mem::<F, _>::new();
        let mut batch = memory.new_batch();
        for operation in encoded_history {
            batch = batch.add(&hasher, operation);
        }
        let batch = batch.merkleize(&memory, &hasher);
        memory.apply_batch(&batch).expect("apply test operations");
        let start_location = Location::new(start_location);
        let end = Location::new(encoded_history.len() as u64);
        let size = Position::try_from(end).expect("valid size");
        AuthenticatedRangeFixture {
            start_location,
            root: memory.root(&hasher, inactive_peaks).expect("test root"),
            end_location: end,
            inactive_peaks,
            pinned_nodes: F::nodes_to_pin(start_location)
                .map(|position| memory.get_node(position).expect("test pin"))
                .collect(),
            encoded_operations: encoded_history[*start_location as usize..].to_vec(),
            merkle_nodes: (0..*size)
                .map(|position| {
                    let position = Position::new(position);
                    (position, memory.get_node(position).expect("test node"))
                })
                .collect(),
        }
    }

    fn encode<Op: Encode>(operations: &[Op]) -> Vec<Vec<u8>> {
        operations.iter().map(|op| op.encode().to_vec()).collect()
    }

    fn staged_rows<F: Family>(
        prepared: PreparedAuthenticatedRange<Sha256Digest, F>,
    ) -> BTreeMap<Key, Vec<u8>> {
        let client = StoreClient::new("http://127.0.0.1:1")
            .prefixed(StoreKeyPrefix::new(b"authenticated-range/".to_vec()).expect("prefix"));
        let mut batch = StoreWriteBatch::new();
        stage_authenticated_range(&client, prepared, &mut batch).expect("stage range");
        batch
            .entries()
            .iter()
            .map(|(key, value)| {
                (
                    client.decode_store_key(key).expect("client namespace"),
                    value.to_vec(),
                )
            })
            .collect()
    }

    fn committed_encoded_operations<F: Family>() -> Vec<Vec<u8>> {
        encode(&[
            FixedKeylessOperation::<F>::Commit(None, Location::new(0)),
            FixedKeylessOperation::<F>::Append(FixedBytes::new([1; 8])),
            FixedKeylessOperation::<F>::Commit(None, Location::new(0)),
            FixedKeylessOperation::<F>::Append(FixedBytes::new([2; 8])),
            FixedKeylessOperation::<F>::Commit(None, Location::new(2)),
        ])
    }

    fn reject_tampering<F: Family>() {
        let operations = committed_encoded_operations::<F>();
        let original = authenticated_range_fixture::<F>(&operations, 3, 0);
        let _ = original.prepare().expect("valid authenticated range");
        let changed_digest = Sha256::hash(&[b"changed digest"]);

        assert!(!original.pinned_nodes.is_empty());
        for index in 0..original.pinned_nodes.len() {
            let mut changed = original.clone();
            changed.pinned_nodes[index] = changed_digest;
            assert!(matches!(
                changed.prepare(),
                Err(QmdbError::ProofVerification { .. })
            ));
        }

        for index in 0..original.encoded_operations.len() {
            let mut changed = original.clone();
            changed.encoded_operations[index][1] ^= 1;
            assert!(matches!(
                changed.prepare(),
                Err(QmdbError::ProofVerification { .. })
            ));
        }

        let mut changed = original.clone();
        changed.inactive_peaks = 1;
        assert!(matches!(
            changed.prepare(),
            Err(QmdbError::ProofVerification { .. })
        ));

        let mut changed = original.clone();
        changed.start_location += 1;
        assert!(matches!(changed.prepare(), Err(QmdbError::CorruptData(_))));

        let mut changed = original.clone();
        changed.end_location += 1;
        assert!(matches!(changed.prepare(), Err(QmdbError::CorruptData(_))));

        let mut changed = original.clone();
        changed.start_location += 1;
        changed.end_location += 1;

        // Keep the pin count valid so relocation reaches root authentication.
        changed.pinned_nodes.resize(
            F::nodes_to_pin(changed.start_location).count(),
            changed_digest,
        );
        assert!(matches!(
            changed.prepare(),
            Err(QmdbError::ProofVerification { .. })
        ));

        let mut changed = original.clone();
        changed.encoded_operations.swap(0, 1);
        assert!(matches!(
            changed.prepare(),
            Err(QmdbError::ProofVerification { .. })
        ));

        let mut changed = original.clone();
        changed.inactive_peaks = usize::MAX;
        assert!(matches!(
            changed.prepare(),
            Err(QmdbError::CommonwareMerkle(_))
        ));

        let mut changed = original.clone();
        changed.pinned_nodes.push(changed_digest);
        assert!(matches!(changed.prepare(), Err(QmdbError::CorruptData(_))));

        assert!(matches!(
            prepare_authenticated_range::<F, Sha256, FixedKeylessOperation<F>, _>(
                &original.view(),
                &changed_digest,
                &(),
                &Sequential,
            ),
            Err(QmdbError::ProofVerification { .. })
        ));

        let mut changed = original.clone();
        changed.encoded_operations.pop();
        assert!(matches!(changed.prepare(), Err(QmdbError::CorruptData(_))));

        let mut changed = original;
        changed.pinned_nodes.pop();
        assert!(matches!(changed.prepare(), Err(QmdbError::CorruptData(_))));
    }

    #[test]
    fn test_rejects_tampered_range_pins_operations_and_trusted_root() {
        reject_tampering::<mmr::Family>();
        reject_tampering::<mmb::Family>();
    }

    fn authenticate_frontier_pins<F: Family>() {
        for (start, end) in [(4, 5), (10, 11), (8, 13), (16, 19), (31, 34)] {
            for floor in [0, start] {
                let mut operations = (0u64..end - 1)
                    .map(|index| {
                        FixedKeylessOperation::<F>::Append(FixedBytes::new(index.to_be_bytes()))
                    })
                    .collect::<Vec<_>>();
                operations.push(FixedKeylessOperation::Commit(None, Location::new(floor)));
                let inactive_peaks = F::inactive_peaks(Location::new(end), Location::new(floor));
                let original =
                    authenticated_range_fixture::<F>(&encode(&operations), start, inactive_peaks);
                let _ = original.prepare().expect("valid frontier");
                assert!(!original.pinned_nodes.is_empty());
                for index in 0..original.pinned_nodes.len() {
                    let mut changed = original.clone();
                    changed.pinned_nodes[index] = Sha256::hash(&[b"changed pin"]);
                    assert!(matches!(
                        changed.prepare(),
                        Err(QmdbError::ProofVerification { .. })
                    ));
                }
            }
        }
    }

    #[test]
    fn test_authenticates_pins_across_folded_and_delayed_merges() {
        authenticate_frontier_pins::<mmr::Family>();
        authenticate_frontier_pins::<mmb::Family>();
    }

    // This decoder accepts aliases so the tests exercise canonical encoding validation.
    struct AliasedCommit(u8);

    impl Write for AliasedCommit {
        fn write(&self, buf: &mut impl BufMut) {
            self.0.write(buf);
        }
    }

    impl FixedSize for AliasedCommit {
        const SIZE: usize = 1;
    }

    impl Read for AliasedCommit {
        type Cfg = Arc<AtomicUsize>;

        fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
            cfg.fetch_add(1, Ordering::Relaxed);
            Ok(Self(u8::read_cfg(buf, &())? & 1))
        }
    }

    impl<F: Family> Floored<F> for AliasedCommit {
        fn inactivity_floor(&self) -> Option<Location<F>> {
            Some(Location::new(0))
        }
    }

    impl<F: Family> UploadOperation<F> for AliasedCommit {
        fn indexed_key(&self) -> Option<(&[u8], bool)> {
            None
        }
    }

    fn authenticate_before_decode<F: Family>() {
        let authenticated = authenticated_range_fixture::<F>(&[vec![2]], 0, 0);
        let decoded = Arc::new(AtomicUsize::new(0));
        let wrong_root = Sha256::hash(&[b"wrong root"]);
        let error = prepare_authenticated_range::<F, Sha256, AliasedCommit, _>(
            &authenticated.view(),
            &wrong_root,
            &decoded,
            &Sequential,
        )
        .unwrap_err();
        assert!(matches!(error, QmdbError::ProofVerification { .. }));
        assert_eq!(decoded.load(Ordering::Relaxed), 0);

        let error = prepare_authenticated_range::<F, Sha256, AliasedCommit, _>(
            &authenticated.view(),
            &authenticated.root,
            &decoded,
            &Sequential,
        )
        .expect_err("noncanonical authenticated bytes must fail");
        assert!(
            matches!(error, QmdbError::CorruptData(message) if message.contains("not canonically encoded"))
        );
        assert_eq!(decoded.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_authenticates_before_decoding_and_rejects_noncanonical_encoding() {
        authenticate_before_decode::<mmr::Family>();
        authenticate_before_decode::<mmb::Family>();
    }

    fn reject_invalid_commit_contract<F: Family>() {
        let mut operations = committed_encoded_operations::<F>();

        operations[0] = FixedKeylessOperation::<F>::Commit(None, Location::new(1))
            .encode()
            .to_vec();
        let error = authenticated_range_fixture::<F>(&operations, 0, 0)
            .prepare()
            .expect_err("invalid earlier floor");
        assert!(
            matches!(error, QmdbError::CorruptData(message) if message.contains("exceeds commit location"))
        );

        operations = committed_encoded_operations::<F>();
        operations[4] = FixedKeylessOperation::<F>::Commit(None, Location::new(5))
            .encode()
            .to_vec();
        let error = authenticated_range_fixture::<F>(&operations, 0, 0)
            .prepare()
            .expect_err("invalid final floor");
        assert!(
            matches!(error, QmdbError::CorruptData(message) if message.contains("exceeds commit location"))
        );

        operations[4] = FixedKeylessOperation::<F>::Append(FixedBytes::new([3; 8]))
            .encode()
            .to_vec();
        let error = authenticated_range_fixture::<F>(&operations, 0, 0)
            .prepare()
            .expect_err("missing final commit");
        assert!(
            matches!(error, QmdbError::CorruptData(message) if message.contains("must end at a commit"))
        );

        operations = committed_encoded_operations::<F>();
        let error = authenticated_range_fixture::<F>(&operations, 0, 1)
            .prepare()
            .expect_err("noncanonical inactive peaks");
        assert!(
            matches!(error, QmdbError::CorruptData(message) if message.contains("noncanonical inactive peak count"))
        );
    }

    #[test]
    fn test_rejects_invalid_commit_floors_and_inactive_peak_count() {
        reject_invalid_commit_contract::<mmr::Family>();
        reject_invalid_commit_contract::<mmb::Family>();
    }

    fn accept_overlap<F: Family>() {
        let operations = committed_encoded_operations::<F>();
        let bootstrap = authenticated_range_fixture::<F>(&operations[..1], 0, 0)
            .prepare()
            .expect("bootstrap commit");
        assert_eq!(bootstrap.start_location(), Location::new(0));
        assert_eq!(bootstrap.latest_location(), Location::new(0));

        let prefix = authenticated_range_fixture::<F>(&operations[..3], 0, 0)
            .prepare()
            .expect("prefix with two commits");
        let overlap = authenticated_range_fixture::<F>(&operations, 1, 0)
            .prepare()
            .expect("overlap with two commits");
        let full = authenticated_range_fixture::<F>(&operations, 0, 0)
            .prepare()
            .expect("full history with three commits");
        let mut expected = staged_rows(full);
        let mut combined = staged_rows(prefix);
        let mut repeated_rows = 0;
        for (key, value) in staged_rows(overlap) {
            if let Some(previous) = combined.insert(key, value.clone()) {
                repeated_rows += 1;
                assert_eq!(previous, value, "overlapping rows must be identical");
            }
        }
        assert!(repeated_rows > 0);
        // Overlapping ranges can advertise additional intermediate batch boundaries
        expected.retain(|key, _| !crate::adapter::codec::PRESENCE_PREFIX.matches(key));
        combined.retain(|key, _| !crate::adapter::codec::PRESENCE_PREFIX.matches(key));
        assert_eq!(combined, expected);
    }

    #[test]
    fn test_bootstrap_and_overlapping_ranges_with_multiple_commits_are_accepted() {
        accept_overlap::<mmr::Family>();
        accept_overlap::<mmb::Family>();
    }

    fn omit_existing_pins<F: Family>() {
        let operations = (0..13)
            .map(|_| FixedKeylessOperation::<F>::Commit(None, Location::new(0)))
            .collect::<Vec<_>>();
        let encoded = encode(&operations);
        let ranges = [(3, 6), (6, 10), (7, 13), (5, 11)]
            .into_iter()
            .map(|(start, end)| authenticated_range_fixture::<F>(&encoded[..end], start, 0))
            .collect::<Vec<_>>();
        let defaults = ranges
            .iter()
            .map(|range| staged_rows(range.prepare().expect("prepare default")))
            .collect::<Vec<_>>();
        let expected = defaults
            .iter()
            .flat_map(|rows| rows.clone())
            .collect::<BTreeMap<_, _>>();
        let bootstrap = &ranges[0];
        let empty = BTreeSet::new();
        assert_eq!(
            staged_rows(
                bootstrap
                    .prepare()
                    .expect("prepare bootstrap")
                    .without_pins_at(&empty)
            ),
            defaults[0]
        );
        for (position, digest) in
            F::nodes_to_pin(bootstrap.start_location).zip(&bootstrap.pinned_nodes)
        {
            assert_eq!(
                defaults[0].get(&encode_node_key(position)),
                Some(&digest.encode().to_vec())
            );
        }

        for omit_all in [false, true] {
            let mut admitted = defaults[0].clone();
            let mut batches = vec![defaults[0].clone()];
            for (index, range) in ranges.iter().enumerate().skip(1) {
                let pins = F::nodes_to_pin(range.start_location).collect::<Vec<_>>();
                assert!(pins.len() > 1);
                let existing = pins
                    .iter()
                    .copied()
                    .enumerate()
                    .filter_map(|(index, position)| {
                        (omit_all || index % 2 == 0).then_some(position)
                    })
                    .collect::<BTreeSet<_>>();
                assert!(!existing.is_empty());
                assert_eq!(existing.len() == pins.len(), omit_all);
                for position in &existing {
                    assert!(admitted.contains_key(&encode_node_key(*position)));
                }
                let staged = staged_rows(
                    range
                        .prepare()
                        .expect("prepare omission")
                        .without_pins_at(&existing),
                );
                assert_eq!(staged.len() + existing.len(), defaults[index].len());
                for (position, digest) in pins.iter().zip(&range.pinned_nodes) {
                    let value = staged.get(&encode_node_key(*position));
                    if existing.contains(position) {
                        assert!(value.is_none());
                    } else {
                        assert_eq!(value, Some(&digest.encode().to_vec()));
                    }
                }
                admitted.extend(staged.clone());
                batches.push(staged);
            }

            // Admitted predecessors can finish last, so the watermark waits for all prefix data
            let client = StoreClient::new("http://127.0.0.1:1").unprefixed();
            let latest = Location::<F>::new(12);
            let mut durable = BTreeMap::new();
            for index in [2, 3, 1, 0] {
                durable.extend(batches[index].clone());
                assert!(!durable.contains_key(&encode_watermark_key(latest)));
            }
            assert_eq!(durable, expected);
            let mut watermark = StoreWriteBatch::new();
            stage_watermark(&client, latest, &mut watermark).expect("publish complete prefix");
            for (key, value) in watermark.entries() {
                durable.insert(client.decode_store_key(key).unwrap(), value.to_vec());
            }
            assert!(durable.contains_key(&encode_watermark_key(latest)));

            // Reconstruct the retained Store frontier to serve a proof after the watermark
            let end = Location::new(encoded.len() as u64);
            let start_size = Position::try_from(bootstrap.start_location).unwrap();
            let end_size = Position::try_from(end).unwrap();
            let nodes = (*start_size..*end_size)
                .map(|position| {
                    Sha256Digest::decode(Copying(
                        durable[&encode_node_key(Position::<F>::new(position))].as_slice(),
                    ))
                    .expect("stored Merkle node")
                })
                .collect();
            let pins = F::nodes_to_pin(bootstrap.start_location)
                .map(|position| {
                    Sha256Digest::decode(Copying(durable[&encode_node_key(position)].as_slice()))
                        .expect("stored bootstrap pin")
                })
                .collect();
            let memory =
                Mem::<F, Sha256Digest>::from_components(nodes, bootstrap.start_location, pins)
                    .expect("retained Store frontier");
            let hasher = commonware_storage::qmdb::hasher::<Sha256>();
            assert_eq!(memory.root(&hasher, 0).unwrap(), ranges[2].root);
            for position in F::nodes_to_pin(end) {
                assert_eq!(
                    memory.get_node(position),
                    Some(ranges[2].merkle_nodes[&position])
                );
            }
            let proof = memory
                .range_proof(&hasher, bootstrap.start_location..end, 0)
                .expect("served proof");
            assert!(proof.verify_range_inclusion_with_pinned_nodes(
                &hasher,
                bootstrap.start_location,
                &encoded[*bootstrap.start_location as usize..],
                &bootstrap.pinned_nodes,
                &ranges[2].root,
            ));
        }
    }

    #[test]
    fn test_existing_pins_preserve_mmr_rows_and_served_frontier() {
        omit_existing_pins::<mmr::Family>();
    }

    #[test]
    fn test_existing_pins_preserve_mmb_rows_and_served_frontier() {
        omit_existing_pins::<mmb::Family>();
    }

    #[test]
    fn test_indexed_keys_distinguish_updates_deletions_and_commits() {
        type Unordered = unordered::Operation<mmr::Family, FixedBytes<8>, FixedValueEncoding>;
        type Ordered = ordered::Operation<mmr::Family, FixedBytes<8>, FixedValueEncoding>;
        type Immutable = immutable::Operation<mmr::Family, Vec<u8>, VariableEncoding<Vec<u8>>>;
        let key = FixedBytes::new([1; 8]);
        let value = FixedBytes::new([2; 8]);
        let unordered_update = Unordered::Update(unordered::Update(key.clone(), value.clone()));
        let ordered_update = Ordered::Update(ordered::Update {
            key: key.clone(),
            value: value.clone(),
            next_key: FixedBytes::new([3; 8]),
        });
        assert_eq!(unordered_update.indexed_key(), Some((key.as_ref(), true)));
        assert_eq!(ordered_update.indexed_key(), Some((key.as_ref(), true)));
        assert_eq!(
            Unordered::Delete(key.clone()).indexed_key(),
            Some((key.as_ref(), false))
        );
        assert_eq!(
            Ordered::Delete(key.clone()).indexed_key(),
            Some((key.as_ref(), false))
        );
        assert_eq!(
            Unordered::CommitFloor(None, Location::new(0)).indexed_key(),
            None
        );
        assert_eq!(
            Ordered::CommitFloor(None, Location::new(0)).indexed_key(),
            None
        );
        let immutable = Immutable::Set(vec![1, 0, 2], vec![3, 4]);
        assert_eq!(immutable.indexed_key(), Some(([1, 0, 2].as_slice(), true)));
        assert_eq!(
            Immutable::Commit(None, Location::new(0)).indexed_key(),
            None
        );
        assert_eq!(
            FixedKeylessOperation::<mmr::Family>::Append(value).indexed_key(),
            None
        );
    }

    fn assert_parallel_preparation<F: Family + PartialEq>() {
        // Force parallel work even for this small fixture
        let strategy = Explorer::parallel(
            &Rayon::new(ThreadPoolBuilder::new(NonZeroUsize::new(2).unwrap()))
                .expect("Rayon strategy"),
        );
        for floor in [0, 512] {
            let mut operations = vec![FixedKeylessOperation::<F>::Commit(None, Location::new(0))];
            operations.extend(
                (1u64..769).map(|index| {
                    FixedKeylessOperation::Append(FixedBytes::new(index.to_be_bytes()))
                }),
            );
            operations.push(FixedKeylessOperation::Commit(None, Location::new(floor)));
            let inactive_peaks =
                F::inactive_peaks(Location::new(operations.len() as u64), Location::new(floor));
            assert_eq!(inactive_peaks == 0, floor == 0);
            let authenticated =
                authenticated_range_fixture::<F>(&encode(&operations), 513, inactive_peaks);
            assert!(!authenticated.pinned_nodes.is_empty());
            let sequential = authenticated.prepare().expect("sequential preparation");
            let parallel = prepare_authenticated_range::<F, Sha256, FixedKeylessOperation<F>, _>(
                &authenticated.view(),
                &authenticated.root,
                &(),
                &strategy,
            )
            .expect("parallel preparation");
            assert_eq!(parallel, sequential);
        }
    }

    #[test]
    fn test_parallel_preparation_mmr() {
        assert_parallel_preparation::<mmr::Family>();
    }

    #[test]
    fn test_parallel_preparation_mmb() {
        assert_parallel_preparation::<mmb::Family>();
    }

    fn codec_publication<F: Graftable>() -> CodecPublication<F>
    where
        F::PendingChunk<Sha256Digest>: Default,
    {
        let start_location = Location::new(3);
        CodecPublication {
            start_location,
            pinned_nodes: F::nodes_to_pin(start_location)
                .map(|position| Sha256::hash(&[&position.to_be_bytes()]))
                .collect(),
            operations: Arc::new(vec![
                AnyOperation::Update(unordered::Update(
                    FixedBytes::new([1; 8]),
                    FixedBytes::new([2; 8]),
                )),
                AnyOperation::Delete(FixedBytes::new([3; 8])),
                AnyOperation::CommitFloor(Some(FixedBytes::new([4; 8])), Location::new(2)),
            ]),
            root: Sha256::hash(&[b"root"]),
            ops_root_witness: OpsRootWitness {
                grafted_root: Sha256::hash(&[b"grafted root"]),
                pending_chunk_digest: Default::default(),
                partial_chunk: Some((5, Sha256::hash(&[b"partial chunk"]))),
            },
            pruned_chunks: 1,
            chunks: vec![(1, [6; 32]), (2, [7; 32])],
            grafted_nodes: vec![(Position::new(510), Sha256::hash(&[b"grafted node"]))],
        }
    }

    fn codec_cfg() -> PublicationCfg<()> {
        PublicationCfg {
            operation: (),
            operations: (0..=3).into(),
            chunks: (0..=2).into(),
            grafted_nodes: (0..=1).into(),
        }
    }

    fn publication_codec_round_trips_and_enforces_limits<F: Graftable>()
    where
        F::PendingChunk<Sha256Digest>: Default,
    {
        // A publication within the configured limits round-trips.
        let publication = codec_publication::<F>();
        let encoded = publication.encode();
        let decoded = CodecPublication::<F>::decode_cfg(encoded.clone(), &codec_cfg())
            .expect("encoded publication must decode");
        assert_eq!(decoded.encode(), encoded);

        // Each vector longer than its configured limit is rejected.
        for cfg in [
            PublicationCfg {
                operations: (0..=2).into(),
                ..codec_cfg()
            },
            PublicationCfg {
                chunks: (0..=1).into(),
                ..codec_cfg()
            },
            PublicationCfg {
                grafted_nodes: (0..=0).into(),
                ..codec_cfg()
            },
        ] {
            assert!(matches!(
                CodecPublication::<F>::decode_cfg(encoded.clone(), &cfg),
                Err(commonware_codec::Error::InvalidLength(_))
            ));
        }

        // A frontier whose length does not match the start location is rejected.
        let mut extra_pin = publication;
        extra_pin.pinned_nodes.push(Sha256::hash(&[b"extra pin"]));
        assert!(matches!(
            CodecPublication::<F>::decode_cfg(extra_pin.encode(), &codec_cfg()),
            Err(commonware_codec::Error::InvalidLength(_))
        ));
    }

    #[test]
    fn test_publication_codec_round_trips_and_enforces_limits() {
        publication_codec_round_trips_and_enforces_limits::<mmr::Family>();
        publication_codec_round_trips_and_enforces_limits::<mmb::Family>();
    }

    #[test]
    fn test_mmb_replays_delayed_parent_hidden_by_inactive_prefix() {
        let operations = encode(&[
            FixedKeylessOperation::<mmb::Family>::Commit(None, Location::new(0)),
            FixedKeylessOperation::<mmb::Family>::Append(FixedBytes::new([1; 8])),
            FixedKeylessOperation::<mmb::Family>::Append(FixedBytes::new([2; 8])),
            FixedKeylessOperation::<mmb::Family>::Commit(None, Location::new(0)),
            FixedKeylessOperation::<mmb::Family>::Commit(None, Location::new(4)),
        ]);
        let authenticated = authenticated_range_fixture::<mmb::Family>(&operations, 4, 1);
        let parent = Position::new(7);
        let hasher = commonware_storage::qmdb::hasher::<Sha256>();
        let memory = Mem::<mmb::Family, Sha256Digest>::from_components(
            authenticated.merkle_nodes.values().copied().collect(),
            Location::new(0),
            Vec::new(),
        )
        .expect("source Merkle tree");
        let proof = memory
            .range_proof(
                &hasher,
                authenticated.start_location..authenticated.end_location,
                authenticated.inactive_peaks,
            )
            .expect("source proof with an inactive prefix");
        let extracted = proof
            .verify_range_inclusion_and_extract_digests(
                &hasher,
                authenticated.start_location,
                &authenticated.encoded_operations,
                &authenticated.root,
            )
            .expect("verify source proof");
        assert!(!extracted.iter().any(|(position, _)| *position == parent));

        let prepared = authenticated
            .prepare()
            .expect("replay authenticated MMB pins");
        let rows = staged_rows(prepared);
        assert_eq!(
            rows.get(&encode_node_key(parent)),
            Some(&authenticated.merkle_nodes[&parent].encode().to_vec()),
        );
        for (position, digest) in
            mmb::Family::nodes_to_pin(authenticated.start_location).zip(&authenticated.pinned_nodes)
        {
            assert_eq!(
                rows.get(&encode_node_key(position)),
                Some(&digest.encode().to_vec())
            );
        }

        // Even an overbroad omission set cannot suppress the delayed parent or other new nodes
        let existing_nodes = authenticated.merkle_nodes.keys().copied().collect();
        let prepared = authenticated.prepare().expect("prepare with omitted pins");
        let mandatory = prepared.rows.iter().cloned().collect::<BTreeMap<_, _>>();
        let omitted = staged_rows(prepared.without_pins_at(&existing_nodes));
        assert_eq!(omitted, mandatory);
        assert_eq!(
            omitted.get(&encode_node_key(parent)),
            rows.get(&encode_node_key(parent))
        );
    }

    #[test]
    fn test_staging_keeps_watermark_explicit_and_uses_the_client_namespace() {
        let operations = committed_encoded_operations::<mmr::Family>();
        let prepared = authenticated_range_fixture::<mmr::Family>(&operations, 0, 0)
            .prepare()
            .expect("prepare range");
        let latest = prepared.latest_location();
        let client = StoreClient::new("http://127.0.0.1:1")
            .prefixed(StoreKeyPrefix::new(b"authenticated-range/".to_vec()).expect("prefix"));

        // Staging the range writes its presence row under the client's prefix and no watermark.
        let mut batch = StoreWriteBatch::new();
        stage_authenticated_range(&client, prepared, &mut batch).expect("stage range");
        let mut has_boundary = false;
        for (physical, _) in batch.entries() {
            let logical = client.decode_store_key(physical).expect("client namespace");
            has_boundary |= logical == encode_presence_key(latest);
            assert_ne!(logical, encode_watermark_key(latest));
        }
        assert!(has_boundary);

        // Staging the watermark adds exactly one empty row after the data rows.
        let data_rows = batch.len();
        stage_watermark(&client, latest, &mut batch).expect("stage watermark");
        let watermark = &batch.entries()[data_rows..];
        assert_eq!(watermark.len(), 1);
        assert_eq!(
            client.decode_store_key(&watermark[0].0).unwrap(),
            encode_watermark_key(latest)
        );
        assert!(watermark.iter().all(|(_, value)| value.is_empty()));

        // An invalid watermark location fails and stages nothing.
        let staged = batch.len();
        assert!(stage_watermark(&client, mmr::Family::MAX_LEAVES, &mut batch).is_err());
        assert_eq!(batch.len(), staged);
    }
}
