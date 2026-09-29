//! Commonware QMDB mapped onto the Exoware Store.
//!
//! Writers stage authenticated operation ranges and watermarks as Store rows with
//! [`upload`].
//! Readers ([`Ordered`], [`Unordered`], [`Immutable`], [`Keyless`]) serve
//! historical and current proofs from those rows.

pub(crate) mod codec;
pub(crate) mod core;
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
