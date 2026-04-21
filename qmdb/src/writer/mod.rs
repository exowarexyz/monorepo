//! Single-writer helpers that push QMDB state into the store without reading
//! the store in the hot loop.
//!
//! Each variant exposes a pure `build_*_upload` function that deterministically
//! turns (MMR peaks, ops) into the full set of store rows, plus a stateful
//! `*Writer` wrapper around [`core::WriterCore`] that starts from caller-supplied
//! frontier state, pipelines PUTs, gates in-band watermark emission on pipeline
//! emptiness, and exposes a `flush()` to publish a catch-up watermark after bursts.
//!
//! Callers own durability. On any PUT error the writer poisons; the caller must
//! construct a fresh writer from a caller-owned committed frontier. Since PUT rows are
//! content-addressed and MMR math is deterministic, retries are idempotent.

mod core;
mod immutable;
mod keyless;
mod ordered;
mod unordered;

pub use immutable::{build_immutable_upload, BuiltImmutableUpload, ImmutableWriter};
pub use keyless::{build_keyless_upload, BuiltKeylessUpload, KeylessWriter};
pub use ordered::{build_ordered_upload, BuiltOrderedUpload, OrderedWriter};
pub use unordered::{build_unordered_upload, BuiltUnorderedUpload, UnorderedWriter};
