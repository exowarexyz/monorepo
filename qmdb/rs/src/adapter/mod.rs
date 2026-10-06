//! Commonware QMDB mapped onto the Exoware Store.
//!
//! Writers stage authenticated operation ranges and watermarks as Store rows with
//! [`upload`].
//! Readers ([`Ordered`], [`Unordered`], [`Immutable`], [`Keyless`]) serve
//! historical and current proofs from those rows.
//!
//! Each proven read has a raw variant (`*_raw`, or `operation_range_checkpoint`
//! for `operation_range`) that returns the proof alongside the payload. Both are
//! checked against the root stored with the proof.

pub(crate) mod codec;
pub(crate) mod core;
mod current;
mod immutable;
mod keyless;
mod operation_range;
mod ordered;
mod prefetch;
pub mod prune;
mod read_cache;
pub(crate) mod storage;
pub(crate) mod subscription;
mod unordered;
pub mod upload;

pub use immutable::Immutable;
pub use keyless::Keyless;
pub use ordered::Ordered;
pub use unordered::Unordered;
