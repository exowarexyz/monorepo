//! Storage callbacks for the store services.
//!
//! Implement the capability traits your component serves. Errors are surfaced to clients as
//! internal RPC failures (string message only; keep messages safe to expose if you rely on that).

use std::collections::HashMap;

use bytes::Bytes;
use futures::future::BoxFuture;

pub type QueryExtra = HashMap<String, buffa_types::google::protobuf::Value>;
pub type RangeScanCursor = Box<dyn RangeScan + Send + 'static>;
pub type StoreFuture<'a, T> = BoxFuture<'a, Result<T, String>>;

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
    fn next_batch<'a>(&'a mut self, max_items: usize) -> StoreFuture<'a, RangeScanBatch>;
}

/// Local sequence frontier visible to this process.
pub trait Sequence: Send + Sync + 'static {
    /// Highest sequence number this process can currently serve.
    fn current_sequence(&self) -> u64;
}

/// Ingest write capability.
pub trait Ingest: Send + Sync + 'static {
    /// Persist key-value pairs atomically and return the new global sequence number for this write.
    fn put_batch<'a>(&'a self, kvs: &'a [(Bytes, Bytes)]) -> StoreFuture<'a, u64>;
}

/// Query read capability.
pub trait Query: Sequence {
    /// Fetch the value for a single key plus backend-specific query metadata.
    /// Returns `None` when the key does not exist.
    fn get<'a>(&'a self, key: &'a [u8]) -> StoreFuture<'a, (Option<Vec<u8>>, QueryExtra)>;

    /// Cursor over keys in `[start, end]` (inclusive) when `end` is non-empty;
    /// empty `end` means unbounded above. Matches `store.query.v1.RangeRequest`
    /// / `ReduceRequest` on the wire. `limit` caps rows yielded.
    fn range_scan<'a>(
        &'a self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> StoreFuture<'a, RangeScanCursor>;

    /// Batch-get plus backend-specific query metadata. Returns `(key, Option<value>)`
    /// for each input key, preserving order.
    fn get_many<'a>(
        &'a self,
        keys: &'a [&'a [u8]],
    ) -> StoreFuture<'a, (Vec<(Vec<u8>, Option<Vec<u8>>)>, QueryExtra)>;
}

/// Prune mutation capability.
pub trait Prune: Sequence {
    /// Delete a batch of keys atomically. Returns the new global sequence number.
    fn delete_batch<'a>(&'a self, keys: &'a [&'a [u8]]) -> StoreFuture<'a, u64>;

    /// Delete all batch-log entries with `sequence_number < cutoff_exclusive`.
    /// Returns the number of entries deleted. Invoked only by the compact
    /// service's batch-log policy scope — never by ingest.
    fn prune_batch_log<'a>(&'a self, cutoff_exclusive: u64) -> StoreFuture<'a, u64>;
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
    fn get_batch<'a>(
        &'a self,
        sequence_number: u64,
    ) -> StoreFuture<'a, Option<Vec<(Bytes, Bytes)>>>;

    /// Lowest retained batch sequence number, or `None` when the batch log is
    /// empty. Surfaced in `BATCH_EVICTED` error details so clients know where
    /// to resume from.
    fn oldest_retained_batch<'a>(&'a self) -> StoreFuture<'a, Option<u64>>;
}

/// Compatibility facade for backends that serve every store capability.
pub trait StoreEngine: Ingest + Query + Prune + BatchLog {}

impl<T: Ingest + Query + Prune + BatchLog + ?Sized> StoreEngine for T {}
