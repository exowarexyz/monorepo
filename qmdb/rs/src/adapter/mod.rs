//! Commonware QMDB on the Exoware Store.
//!
//! [`upload`] prepares and stages what a writer uploads: authenticated operation ranges, current
//! batch publications, and the watermarks that publish them. The readers ([`Ordered`],
//! [`Unordered`], [`Immutable`], and [`Keyless`]) query the uploaded rows at a tip, a location at
//! or below the published watermark, and build historical and current proofs from them. Keyless and
//! immutable roots and operation proofs need a tip that is a commit, current-state reads need a
//! commit whose publication was uploaded, and other reads accept any such tip. A read verifies its
//! proof against the root the rows determine at that tip and returns the payload with that root,
//! for the caller to compare with a root it trusts. The `*_proof` reads return the verified proof
//! itself, which the ConnectRPC server forwards to clients that verify it against their own trusted
//! root. The `get_at` and `get_many_at` reads return indexed values without a proof.

pub(crate) mod codec;
pub(crate) mod core;
mod current;
mod immutable;
mod keyless;
mod operation_range;
mod ordered;
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
