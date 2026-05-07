//! Storage callbacks for the store services.
//!
//! Implement this trait for your backend. Errors are surfaced to clients as internal RPC failures
//! (string message only; keep messages safe to expose if you rely on that).

use std::collections::HashMap;

use bytes::Bytes;
use futures::future::BoxFuture;

pub type QueryExtra = HashMap<String, buffa_types::google::protobuf::Value>;
pub type RangeScanCursor = Box<dyn RangeScan + Send + 'static>;

#[derive(Clone, Debug, Default)]
pub struct RangeScanBatch {
    /// Rows read by this cursor pull.
    pub rows: Vec<(Bytes, Bytes)>,
    /// Backend-specific query metadata after reading these rows.
    pub extra: QueryExtra,
}

/// Owned pull-based range cursor for query RPCs.
///
/// Implementations own any state needed to produce batches, allowing query
/// handlers to pull rows lazily without borrowing the engine.
pub trait RangeScan: Send {
    /// Pull up to `max_items` rows. Returning an empty `rows` batch marks EOF.
    /// `extra` is emitted with the response frame built from the same batch.
    fn next_batch<'a>(
        &'a mut self,
        max_items: usize,
    ) -> BoxFuture<'a, Result<RangeScanBatch, String>>;
}

/// Implement these operations for your store. All methods must be thread-safe.
pub trait StoreEngine: Send + Sync + 'static {
    /// Persist key-value pairs atomically and return the new global sequence number for this write.
    fn put_batch(&self, kvs: &[(Bytes, Bytes)]) -> Result<u64, String>;

    /// Fetch the value for a single key plus backend-specific query metadata.
    /// Returns `None` when the key does not exist.
    fn get(&self, key: &[u8]) -> Result<(Option<Vec<u8>>, QueryExtra), String>;

    /// Cursor over keys in `[start, end]` (inclusive) when `end` is non-empty;
    /// empty `end` means unbounded above. Matches `store.query.v1.RangeRequest`
    /// / `ReduceRequest` on the wire. `limit` caps rows yielded.
    fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Result<RangeScanCursor, String>;

    /// Batch-get plus backend-specific query metadata. Returns `(key, Option<value>)`
    /// for each input key, preserving order.
    fn get_many(
        &self,
        keys: &[&[u8]],
    ) -> Result<(Vec<(Vec<u8>, Option<Vec<u8>>)>, QueryExtra), String>;

    /// Delete a batch of keys atomically. Returns the new global sequence number.
    fn delete_batch(&self, keys: &[&[u8]]) -> Result<u64, String>;

    /// Current sequence number visible to readers (used for `min_sequence_number` checks).
    fn current_sequence(&self) -> u64;

    /// Return the (key, value) pairs written by the `put_batch` call that was
    /// assigned `sequence_number`. `Ok(None)` = the batch has been pruned or
    /// was never written (the store.stream.v1 service maps `None` to NOT_FOUND
    /// with a `BATCH_EVICTED` detail).
    ///
    /// Engines that don't retain a batch log return `Ok(None)` unconditionally,
    /// which disables `GetBatch` and since-cursored `Subscribe` for that
    /// deployment.
    fn get_batch(&self, sequence_number: u64) -> Result<Option<Vec<(Bytes, Bytes)>>, String>;

    /// Lowest retained batch sequence number, or `None` when the batch log is
    /// empty. Surfaced in `BATCH_EVICTED` error details so clients know where
    /// to resume from.
    fn oldest_retained_batch(&self) -> Result<Option<u64>, String>;

    /// Delete all batch-log entries with `sequence_number < cutoff_exclusive`.
    /// Returns the number of entries deleted. Invoked only by the compact
    /// service's batch-log policy scope — never by ingest.
    fn prune_batch_log(&self, cutoff_exclusive: u64) -> Result<u64, String>;
}
