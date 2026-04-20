//! Client-side streaming of uploaded QMDB batches.
//!
//! Each variant's `stream_batches()` method subscribes to the store's
//! `store.stream.v1.Service.Subscribe` RPC with a filter that selects exactly
//! the row families the variant's codec writes (operation rows, batch-boundary
//! presence markers, and published watermark rows). As those frames arrive
//! the driver accumulates operations, and once a watermark advances past a
//! closed batch it calls the variant's existing `operation_range_proof` to
//! produce a verifiable range proof over that batch's contiguous locations.
//!
//! Filter and decoder layouts:
//! - `ordered` / `unordered` (unnamed namespace): OP_FAMILY=0x4,
//!   PRESENCE_FAMILY=0x2, WATERMARK_FAMILY=0x3 — 8-byte location payload each.
//! - `immutable` / `keyless` (authenticated, `AuthenticatedBackendNamespace`):
//!   AUTH_OP_FAMILY=0x9, AUTH_INDEX_FAMILY=0xC (presence), AUTH_WATERMARK_FAMILY=0xB
//!   — 1-byte namespace tag + 8-byte location payload each. The namespace tag
//!   lets ordered+unordered vs immutable+keyless coexist in one store without
//!   cross-talk.
//!
//! Transport drops (slow-client eviction) surface as `QmdbError::Stream`; the
//! caller should resubscribe with `since = last_observed_seq + 1` to replay
//! the missed batches.

pub(crate) mod driver;
