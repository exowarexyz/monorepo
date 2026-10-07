#![allow(clippy::type_complexity)]

//! Read and verify Commonware QMDB proofs from Exoware.
//!
//! Supports ordered, unordered, immutable, and keyless QMDB.
//!
//! Writes go directly to the store service, with this crate offering helpers such as
//! [`adapter::upload::prepare_authenticated_range`], [`adapter::upload::stage_authenticated_range`]
//! and [`adapter::upload::stage_watermark`].
//!
//! Reads take one of two paths. The adapters ([`adapter::Ordered`], [`adapter::Unordered`],
//! [`adapter::Immutable`], and [`adapter::Keyless`]) query the store service directly. The
//! clients under [`service::client`] query the QMDB ConnectRPC service and verify each
//! response against a trusted root.
//!
//! # Crate map
//!
//! - [`adapter`]: Commonware QMDB on the Exoware Store. One reader per kind
//!   (e.g. [`adapter::Ordered`]), plus upload staging in [`adapter::upload`].
//! - [`service`]: the `qmdb.v1` ConnectRPC services.
//!   - [`service::proto`]: generated request, response, and proof messages.
//!   - [`service::server`]: one Connect stack function per kind.
//!   - [`service::client`]: one verifying client per kind (e.g. [`service::client::Ordered`]),
//!     built from the per-service clients in [`service::client::rpc`].
//! - [`proof`]: raw and verified proof types shared by readers and clients.
//! - [`error`]: [`QmdbError`] and [`ProofKind`].
//!
//! # Uploads and publication
//!
//! Callers provide authenticated Commonware operation ranges and stage their Store rows
//! without constructing an uploader or reading remote state. An application-owned durable
//! queue publishes the watermark after the whole contiguous prefix is durable.
//!
//! Uploads may still happen concurrently and out of order. Current batch-boundary
//! state may also be uploaded ahead of publication. Only watermark publication is
//! monotonic: publishing watermark `W` means the whole contiguous prefix
//! `[0, W]` is available and may now be trusted by readers.
//!
//! Readers fence historical queries against that low watermark. Historical proofs
//! use the global ops Merkle nodes stored by `Position`.
//!
//! Current QMDB proofs use versioned current-state deltas:
//! - bitmap chunk rows
//! - grafted-node rows
//!
//! Those rows are versioned by uploaded batch boundary `Location`, not by the
//! final published watermark. That is what preserves lower-boundary current
//! proofs below a later published low watermark.

pub mod adapter;
pub mod error;
pub mod proof;
mod request;
pub mod service;

#[cfg(feature = "test-utils")]
pub use adapter::codec::{CHUNK_FAMILY, NODE_FAMILY};
pub use error::{ProofKind, QmdbError};

use commonware_codec::DecodeExt;
use commonware_cryptography::Digest;
use commonware_storage::merkle::{self, Family, Graftable, Location};
use commonware_storage::qmdb::current::proof::OpsRootWitness;

/// Maximum encoded operation size for QMDB key and value payloads (u16 length on the wire).
pub const MAX_OPERATION_SIZE: usize = u16::MAX as usize;

/// Historical value resolved for one logical key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedValue<K, V, F: Family> {
    pub key: K,
    pub location: Location<F>,
    pub value: Option<V>,
}

/// Current-state rows for one uploaded current batch boundary.
///
/// Current QMDB uploads carry more than the historical op log: each published
/// batch boundary also stores the current-state root, op-root witness, and the
/// subset of bitmap chunks and grafted nodes that changed at that boundary.
/// This struct is that versioned delta payload.
///
/// Callers typically obtain it from [`adapter::upload::recover_boundary_state`], using a local
/// Commonware current DB, then attach it with
/// [`adapter::upload::PreparedAuthenticatedRange::with_current_boundary`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentBoundaryState<D: Digest, const N: usize, F: Graftable> {
    /// Canonical current-state root at this batch boundary.
    pub root: D,
    /// Number of complete, all-zero chunks discarded from the start of the source bitmap.
    /// Source pruning preserves the root. This count does not delete backend rows.
    pub pruned_chunks: u64,
    /// Proof that the raw operation-log root is committed by `root`.
    pub ops_root_witness: OpsRootWitness<F, D>,
    /// Changed bitmap chunks keyed by chunk index.
    pub chunks: Vec<(u64, [u8; N])>,
    /// Changed grafted digests keyed by ops-space Merkle position.
    pub grafted_nodes: Vec<(merkle::Position<F>, D)>,
}

/// Decoded (key, value) payload for a QMDB operation. Either element is `None`
/// when the operation's logical key or value is absent (e.g. keyless ops).
pub(crate) struct OperationKv {
    pub(crate) key: Option<Vec<u8>>,
    pub(crate) value: Option<Vec<u8>>,
}

/// A requested watermark and the minimum Store sequence that makes it readable.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PublishedWatermark<F: Family> {
    pub(crate) location: Location<F>,
    pub(crate) sequence_number: u64,
}

pub(crate) fn decode_digest<D: Digest>(
    bytes: &[u8],
    label: impl std::fmt::Display,
) -> Result<D, QmdbError> {
    D::decode(bytes).map_err(|e| QmdbError::CorruptData(format!("{label} decode error: {e}")))
}

// The native crate owns tests for request constraints shared with the WASM verifier.
#[cfg(test)]
mod tests {
    use crate::request::{span_contains, validate_key_range, InvalidWindow, OperationWindow};

    #[test]
    fn test_spans_wrap_past_the_greatest_key() {
        assert!(span_contains(&2, &6, &2));
        assert!(span_contains(&2, &6, &5));
        assert!(!span_contains(&2, &6, &6));
        assert!(!span_contains(&2, &6, &1));
        assert!(span_contains(&6, &2, &7));
        assert!(span_contains(&6, &2, &1));
        assert!(!span_contains(&6, &2, &2));
        assert!(!span_contains(&6, &2, &4));
        assert!(span_contains(&3, &3, &9));
    }

    #[test]
    fn test_operation_windows_preserve_large_absolute_positions() {
        for start in [u32::MAX as u64 - 1, u32::MAX as u64 + 1, (1u64 << 53) + 1] {
            let window = OperationWindow::new(start + 2, start, 10).unwrap();
            assert!(window.validate(start, 3, start + 3).is_ok());
            assert!(window.validate(start + 1, 3, start + 3).is_err());
            assert!(window.validate(start, 2, start + 3).is_err());
            assert!(window.validate(start, 3, start + 4).is_err());
        }
        assert!(matches!(
            OperationWindow::new(u64::MAX, 0, 1),
            Err(InvalidWindow::TipOverflow)
        ));
        assert!(matches!(
            OperationWindow::new(10, 11, 1),
            Err(InvalidWindow::StartOutOfBounds {
                start: 11,
                count: 11
            })
        ));
        assert!(matches!(
            OperationWindow::new(10, 0, 0),
            Err(InvalidWindow::ZeroMaximum)
        ));
    }

    #[test]
    fn test_linear_key_ranges_match_sorted_map_pages() {
        let keys = [2, 4, 6];
        for start in 0..9 {
            for end in (start + 1)..10 {
                for limit in 1..5 {
                    let matching = keys
                        .iter()
                        .filter(|key| **key >= start && **key < end)
                        .collect::<Vec<_>>();
                    let selected = matching
                        .iter()
                        .take(limit as usize)
                        .map(|key| {
                            let index =
                                keys.iter().position(|candidate| candidate == *key).unwrap();
                            (*key, &keys[(index + 1) % keys.len()])
                        })
                        .collect::<Vec<_>>();
                    let successor = keys.iter().find(|key| **key > start).or(keys.first());
                    let next = matching.get(limit as usize).copied();
                    assert_eq!(
                        validate_key_range(&start, Some(&end), limit, &selected, successor)
                            .unwrap(),
                        next,
                    );
                }
            }
        }
    }

    #[test]
    fn test_key_ranges_reject_wraparound_and_incomplete_pages() {
        assert!(validate_key_range(&1, Some(&7), 3, &[], Some(&2)).is_err());
        assert!(validate_key_range(&1, Some(&7), 3, &[(&2, &4)], Some(&2)).is_err());
        assert!(validate_key_range(&4, None, 3, &[(&4, &6), (&6, &2), (&2, &4)], None).is_err());
        assert!(validate_key_range(&1, Some(&7), 1, &[(&2, &4), (&4, &6)], Some(&2)).is_err());
        // An empty-database start proof cannot precede entries
        assert!(validate_key_range(&1, Some(&7), 3, &[(&2, &4)], None).is_err());
        // Entries must chain through their authenticated successors
        assert!(validate_key_range(&1, Some(&7), 3, &[(&2, &4), (&6, &2)], Some(&2)).is_err());
        assert!(validate_key_range(&1, Some(&7), 0, &[], Some(&2)).is_err());
        assert!(validate_key_range(&7, Some(&7), 3, &[], None).is_err());
    }

    #[test]
    fn test_single_key_databases_accept_self_successors() {
        assert_eq!(
            validate_key_range(&0, None, 5, &[(&3, &3)], Some(&3)),
            Ok(None)
        );
        assert_eq!(validate_key_range(&3, None, 5, &[(&3, &3)], None), Ok(None));
        // A start above the only key wraps to it, so an empty page is complete
        assert_eq!(validate_key_range(&4, None, 5, &[], Some(&3)), Ok(None));
    }
}
