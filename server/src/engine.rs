//! Storage callbacks for the store services.
//!
//! Implement this trait for your backend. Errors are surfaced to clients as internal RPC failures
//! (string message only; keep messages safe to expose if you rely on that).

use bytes::Bytes;

/// Implement these operations for your store. All methods must be thread-safe.
pub trait StoreEngine: Send + Sync + 'static {
    /// Persist key-value pairs atomically and return the new global sequence number for this write.
    fn put_batch(&self, kvs: &[(Bytes, Bytes)]) -> Result<u64, String>;

    /// Fetch the value for a single key. Returns `None` when the key does not exist.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String>;

    /// Keys in `[start, end]` (inclusive) when `end` is non-empty; empty `end` means unbounded
    /// above. Matches `store.query.v1.RangeRequest` / `ReduceRequest` on the wire. `limit` caps
    /// rows returned.
    fn range_scan(
        &self,
        start: &[u8],
        end: &[u8],
        limit: usize,
        forward: bool,
    ) -> Result<Vec<(Bytes, Bytes)>, String>;

    /// Batch-get: returns `(key, Option<value>)` for each input key, preserving order.
    fn get_many(&self, keys: &[&[u8]]) -> Result<Vec<(Vec<u8>, Option<Vec<u8>>)>, String> {
        keys.iter()
            .map(|k| Ok((k.to_vec(), self.get(k)?)))
            .collect()
    }

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
