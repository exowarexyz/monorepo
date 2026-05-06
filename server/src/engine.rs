//! Storage callbacks for the store services.
//!
//! Implement the capability traits your component serves. Errors are surfaced to clients as
//! internal RPC failures (string message only; keep messages safe to expose if you rely on that).

use bytes::Bytes;

pub type RangeScanIter<'a> = Box<dyn Iterator<Item = Result<(Bytes, Bytes), String>> + Send + 'a>;

/// Current sequence frontier shared by query, pruning, and batch-log consumers.
pub trait Sequence: Send + Sync + 'static {
    /// Current sequence number visible to readers (used for `min_sequence_number` checks).
    fn current_sequence(&self) -> u64;
}

/// Ingest write capability.
pub trait Ingest: Send + Sync + 'static {
    /// Persist key-value pairs atomically and return the new global sequence number for this write.
    fn put_batch(&self, kvs: &[(Bytes, Bytes)]) -> Result<u64, String>;
}

/// Query read capability.
pub trait Query: Sequence {
    /// Fetch the value for a single key. Returns `None` when the key does not exist.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String>;

    /// Keys in `[start, end]` (inclusive) when `end` is non-empty; empty `end` means unbounded
    /// above. Matches `store.query.v1.RangeRequest` / `ReduceRequest` on the wire. `limit` caps
    /// rows yielded.
    fn range_scan(
        &self,
        start: &[u8],
        end: &[u8],
        limit: usize,
        forward: bool,
    ) -> Result<RangeScanIter<'_>, String>;

    /// Batch-get: returns `(key, Option<value>)` for each input key, preserving order.
    fn get_many(&self, keys: &[&[u8]]) -> Result<Vec<(Vec<u8>, Option<Vec<u8>>)>, String> {
        keys.iter()
            .map(|k| Ok((k.to_vec(), self.get(k)?)))
            .collect()
    }
}

/// Prune mutation capability.
pub trait Prune: Sequence {
    /// Delete a batch of keys atomically. Returns the new global sequence number.
    fn delete_batch(&self, keys: &[&[u8]]) -> Result<u64, String>;

    /// Delete all batch-log entries with `sequence_number < cutoff_exclusive`.
    /// Returns the number of entries deleted. Invoked only by the compact
    /// service's batch-log policy scope — never by ingest.
    fn prune_batch_log(&self, cutoff_exclusive: u64) -> Result<u64, String>;
}

/// Retained per-sequence batch-log access for stream replay and lookups.
pub trait BatchLog: Sequence {
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
}

/// Compatibility facade for backends that serve every store capability.
pub trait StoreEngine: Ingest + Query + Prune + BatchLog {}

impl<T: Ingest + Query + Prune + BatchLog + ?Sized> StoreEngine for T {}
