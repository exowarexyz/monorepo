//! Storage callbacks for the store services.
//!
//! Implement this trait for your backend. Errors are surfaced to clients as internal RPC failures
//! (string message only; keep messages safe to expose if you rely on that).

use bytes::Bytes;

/// Implement these operations for your store. All methods must be thread-safe.
pub trait StoreEngine: Send + Sync + 'static {
    /// Persist key-value pairs atomically and return the new global sequence number for this write.
    fn put_batch(&self, kvs: &[(Bytes, Bytes)]) -> Result<u64, String>;

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

    /// Current sequence number visible to readers (used for `min_sequence_number` checks).
    fn current_sequence(&self) -> u64;
}
