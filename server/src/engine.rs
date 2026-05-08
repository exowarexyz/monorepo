//! Storage callbacks for the store services.
//!
//! Implement the capability traits your component serves. Errors are surfaced to clients as
//! internal RPC failures (string message only; keep messages safe to expose if you rely on that).

use std::collections::HashMap;

use bytes::Bytes;
use exoware_sdk::prune_policy::PrunePolicyDocument;
use futures::future::BoxFuture;

/// Backend-defined query metadata.
///
/// Keep this lightweight: streaming query RPCs may emit detail on every frame.
pub type QueryExtra = HashMap<String, buffa_types::google::protobuf::Value>;
pub type RangeScanCursor = Box<dyn RangeScan + Send + 'static>;

/// Owned async operation result returned by store capability methods.
///
/// The boxed future is `'static` so service handlers can poll it after the `&self` method call
/// has returned.
pub type StoreFuture<T> = BoxFuture<'static, Result<T, String>>;
pub type RangeScanFuture<'a, T> = BoxFuture<'a, Result<T, String>>;

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
    /// EOF may carry non-empty `extra` with final query metadata.
    /// `extra` is emitted with the response frame built from the same batch.
    fn next_batch<'a>(&'a mut self, max_items: usize) -> RangeScanFuture<'a, RangeScanBatch>;
}

/// Local sequence frontier visible to this process.
///
/// This is a standalone capability so split deployments can advertise a frontier without serving
/// full query or batch-log reads.
pub trait Sequence: Send + Sync + 'static {
    /// Highest sequence number this process can currently serve.
    fn current_sequence(&self) -> u64;
}

/// Ingest write capability.
pub trait Ingest: Send + Sync + 'static {
    /// Persist key-value pairs atomically and return the new global sequence number for this write.
    fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> StoreFuture<u64>;
}

/// Query read capability.
pub trait Query: Sequence {
    /// Fetch the value for a single key plus backend-specific query metadata.
    /// Returns `None` when the key does not exist.
    fn get(&self, key: Bytes) -> StoreFuture<(Option<Vec<u8>>, QueryExtra)>;

    /// Cursor over keys in `[start, end]` (inclusive) when `end` is non-empty;
    /// empty `end` means unbounded above. Matches `store.query.v1.RangeRequest`
    /// / `ReduceRequest` on the wire. `limit` caps rows yielded.
    fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> StoreFuture<RangeScanCursor>;

    /// Batch-get plus backend-specific query metadata. Returns `(key, Option<value>)`
    /// for each input key, preserving order.
    fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> StoreFuture<(Vec<(Vec<u8>, Option<Vec<u8>>)>, QueryExtra)>;
}

/// Prune mutation capability.
///
/// Public point deletes are intentionally not exposed as a separate capability; engines may delete
/// keys as an internal effect of applying prune policies.
pub trait Prune: Send + Sync + 'static {
    /// Apply prune policies sequentially.
    fn apply_prune_policies(&self, document: PrunePolicyDocument) -> StoreFuture<()>;
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
    fn get_batch(&self, sequence_number: u64) -> StoreFuture<Option<Vec<(Bytes, Bytes)>>>;

    /// Lowest retained batch sequence number, or `None` when the batch log is
    /// empty. Surfaced in `BATCH_EVICTED` error details so clients know where
    /// to resume from.
    fn oldest_retained_batch(&self) -> StoreFuture<Option<u64>>;
}

/// Compatibility facade for backends that serve every store capability.
pub trait StoreEngine: Ingest + Query + Prune + BatchLog {}

impl<T: Ingest + Query + Prune + BatchLog + ?Sized> StoreEngine for T {}
