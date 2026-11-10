#![allow(clippy::type_complexity)]

//! Upload Commonware QMDB data to an Exoware Store, serve proof queries, and verify responses
//! against trusted roots. Ordered, unordered, immutable, and keyless databases are supported,
//! with MMR or MMB Merkle trees.
//!
//! [`adapter::upload`] verifies and stages upload rows, and the application commits them to the
//! Store. A current QMDB uploads each batch as an [`adapter::upload::Publication`] that also
//! carries the batch's current-state changes.
//!
//! Reads take one of two paths. The adapters ([`adapter::Ordered`], [`adapter::Unordered`],
//! [`adapter::Immutable`], and [`adapter::Keyless`]) query the Store directly. The clients
//! under [`service::client`] query the `qmdb.v1` ConnectRPC service that [`service::server`]
//! serves from the same rows, and verify each response against a trusted root.
//!
//! # Crate map
//!
//! - [`adapter`]: Commonware QMDB on the Exoware Store. One reader per kind
//!   (e.g. [`adapter::Ordered`]), plus upload staging in [`adapter::upload`].
//! - [`service`]: the `qmdb.v1` ConnectRPC services.
//!   - [`service::proto`]: generated request, response, and proof messages.
//!   - [`service::server`]: a full stack and an operation-log-only stack per kind. Immutable
//!     and keyless have only the latter.
//!   - [`service::client`]: one verifying client per kind (e.g. [`service::client::Ordered`]),
//!     built from the per-service clients in [`service::client::rpc`].
//! - [`proof`]: proof results and verified payloads shared by readers and clients.
//! - [`error`]: [`QmdbError`] and [`ProofKind`].
//!
//! # Uploads and watermarks
//!
//! Preparation reads no remote state, so ranges may be uploaded concurrently and out of order,
//! and a current batch's publication may be uploaded before the watermark reaches it. Only the
//! watermark is monotonic. Publishing watermark `W` means the whole contiguous prefix `[0, W]`
//! is durable and may be trusted by readers, which fence historical queries against it.
//! Historical proofs use the operation-log Merkle nodes, which are stored once by `Position`.
//!
//! ```text
//!  durable     [0 ........ 99]              [200 ...... 299]
//!  watermark               99
//!
//!  durable     [0 ........ 99][100 .... 199][200 ...... 299]
//!  watermark                                            299
//! ```
//!
//! A gap holds the watermark at the end of the prefix below it. Once the gap is durable, the
//! watermark can move past every commit up to the next gap in one step.
//!
//! A publication's current-state rows (metadata, witness, bitmap chunks, and grafted nodes)
//! are versioned by the batch's final location rather than by the watermark, so current proofs
//! at earlier batches stay available after a later watermark is published.

pub mod adapter;
pub mod error;
pub mod proof;
mod request;
pub mod service;

#[cfg(feature = "test-utils")]
pub use adapter::codec::{CHUNK_FAMILY, NODE_FAMILY};
use commonware_codec::{Copying, DecodeExt};
use commonware_cryptography::Digest;
use commonware_storage::merkle::{Family, Location};
pub use error::{ProofKind, QmdbError};

/// Maximum encoded operation size for QMDB key and value payloads (u16 length on the wire).
pub const MAX_OPERATION_SIZE: usize = u16::MAX as usize;

/// Historical value resolved for one logical key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedValue<K, V, F: Family> {
    pub key: K,
    pub location: Location<F>,
    pub value: Option<V>,
}

/// A requested tip and the minimum Store sequence at which a published watermark covers it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ResolvedTip<F: Family> {
    pub(crate) tip: Location<F>,
    pub(crate) sequence_number: u64,
}

pub(crate) fn decode_digest<D: Digest>(
    bytes: &[u8],
    label: impl std::fmt::Display,
) -> Result<D, QmdbError> {
    D::decode(Copying(bytes))
        .map_err(|e| QmdbError::CorruptData(format!("{label} decode error: {e}")))
}

// The native crate owns tests for request constraints shared with the WASM verifier.
#[cfg(test)]
mod tests {
    use crate::{
        request::{
            validate_key_range, InvalidLocations, InvalidWindow, OperationLocations,
            OperationWindow,
        },
        service::{validate_operations_request, MAX_REQUESTED_LOCATIONS},
    };

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
    fn test_operation_locations_require_ascending_locations_within_tip() {
        assert!(OperationLocations::new(10, &[0, 4, 10]).is_ok());
        assert!(matches!(
            OperationLocations::new(u64::MAX, &[0]),
            Err(InvalidLocations::TipOverflow)
        ));
        assert!(matches!(
            OperationLocations::new(10, &[]),
            Err(InvalidLocations::Empty)
        ));
        assert!(matches!(
            OperationLocations::new(10, &[3, 3]),
            Err(InvalidLocations::NotAscending { location: 3 })
        ));
        assert!(matches!(
            OperationLocations::new(10, &[4, 2]),
            Err(InvalidLocations::NotAscending { location: 2 })
        ));
        assert!(matches!(
            OperationLocations::new(10, &[0, 11]),
            Err(InvalidLocations::OutOfBounds {
                location: 11,
                count: 11
            })
        ));
        let many = (0..=MAX_REQUESTED_LOCATIONS as u64).collect::<Vec<_>>();
        assert!(OperationLocations::new(u64::MAX - 1, &many).is_ok());
    }

    #[test]
    fn test_operations_rpc_limits_locations() {
        let many = (0..=MAX_REQUESTED_LOCATIONS as u64).collect::<Vec<_>>();
        assert!(matches!(
            validate_operations_request(u64::MAX - 1, &many),
            Err(crate::QmdbError::InvalidRequestedLocations(_))
        ));
        assert!(
            validate_operations_request(u64::MAX - 1, &many[..MAX_REQUESTED_LOCATIONS]).is_ok()
        );
    }

    #[test]
    fn test_operation_locations_match_responses_exactly() {
        let start = (1u64 << 53) + 1;
        let requested = [start, start + 7];
        let locations = OperationLocations::new(start + 9, &requested).unwrap();
        assert!(locations
            .validate(requested.into_iter(), start + 10)
            .is_ok());
        assert!(locations
            .validate(requested.into_iter(), start + 11)
            .is_err());
        assert!(locations.validate([start].into_iter(), start + 10).is_err());
        assert!(locations
            .validate([start, start + 7, start + 8].into_iter(), start + 10)
            .is_err());
        assert!(locations
            .validate([start + 7, start].into_iter(), start + 10)
            .is_err());
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
