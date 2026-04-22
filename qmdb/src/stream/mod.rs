//! Client-side streaming of uploaded QMDB batches.
//!
//! Transport drops (slow-client eviction) surface as `QmdbError::Stream`; the
//! caller should resubscribe with `since = last_observed_seq + 1` to replay
//! the missed batches via the batch log.

pub(crate) mod driver;
