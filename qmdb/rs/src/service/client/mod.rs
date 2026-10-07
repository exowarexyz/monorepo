//! Verifying ConnectRPC clients.
//!
//! [`Ordered`], [`Unordered`], [`Immutable`], and [`Keyless`] each cover every
//! service the matching server stack mounts. [`rpc`] holds the per-service
//! clients they are built from.

mod immutable;
mod keyless;
mod ordered;
pub mod rpc;
mod unordered;

pub use immutable::Immutable;
pub use keyless::Keyless;
pub use ordered::Ordered;
pub use unordered::Unordered;
