//! Storage callbacks for the store services.
//!
//! Implement the capability traits your component serves. String errors are surfaced to clients as
//! internal RPC failures (message only; keep messages safe to expose if you rely on that). `Ingest`
//! additionally lets a backend mark a write failure transient via [`IngestError`].

use std::collections::HashMap;
use std::future::Future;

use buffa::Message;
use bytes::Bytes;
use exoware_sdk::common::kv::v1::Entry;
use exoware_sdk::log::stream::v1::GetResponse as StreamGetResponse;
use exoware_sdk::prune_policy::PrunePolicyDocument;
use exoware_sdk::retention::RetentionPolicy;

use crate::stream::{apply_filter, CompiledMatchers};

/// Backend-defined query metadata.
///
/// Keep this lightweight: streaming query RPCs may emit detail on every frame.
pub type QueryExtra = HashMap<String, buffa_types::google::protobuf::Value>;

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
    fn next_batch(
        &mut self,
        max_items: usize,
    ) -> impl Future<Output = Result<RangeScanBatch, String>> + Send;
}

/// Local sequence frontier visible to this process.
pub trait Sequence: Send + Sync + 'static {
    /// Highest sequence number this process can currently serve.
    fn current_sequence(&self) -> u64;
}

/// Why an ingest write was not accepted.
///
/// Backends choose the variant; the Connect layer maps it to the wire code and retry details.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IngestError {
    /// The write cannot currently be accepted; clients may retry with backoff.
    #[error("unavailable: {message}")]
    Unavailable { message: String },

    /// The write failed in a way retries will not fix.
    #[error("internal: {message}")]
    Internal { message: String },
}

/// Ingest write capability.
pub trait Ingest: Send + Sync + 'static {
    /// Persist key-value pairs atomically and return the global sequence number that includes this
    /// write. Backends may coalesce concurrent writes and return the same sequence number to each
    /// coalesced caller.
    fn put_batch(
        &self,
        kvs: Vec<(Bytes, Bytes)>,
    ) -> impl Future<Output = Result<u64, IngestError>> + Send;
}

/// Query read capability.
pub trait Query: Sequence {
    type RangeScan: RangeScan + 'static;

    /// Fetch the value for a single key plus backend-specific query metadata.
    /// Returns `None` when the key does not exist.
    fn get(
        &self,
        key: Bytes,
    ) -> impl Future<Output = Result<(Option<Bytes>, QueryExtra), String>> + Send;

    /// Cursor over keys in `[start, end]` (inclusive) when `end` is non-empty;
    /// empty `end` means unbounded above. Matches `store.query.v1.RangeRequest`
    /// / `ReduceRequest` on the wire. `limit` caps rows yielded.
    fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> impl Future<Output = Result<Self::RangeScan, String>> + Send;

    /// Batch-get plus backend-specific query metadata. Returns `(key, Option<value>)`
    /// for each input key, preserving order.
    fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> impl Future<Output = Result<(Vec<(Bytes, Option<Bytes>)>, QueryExtra), String>> + Send;
}

/// Prune mutation capability.
pub trait Prune: Send + Sync + 'static {
    /// Apply a validated prune policy document sequentially.
    fn apply_prune_policies(
        &self,
        document: PrunePolicyDocument,
    ) -> impl Future<Output = Result<(), String>> + Send;
}

/// Pre-encoded `log.stream.v1.GetResponse` stored for a retained sequence batch.
#[derive(Clone, Debug)]
pub struct LogBatch {
    sequence_number: u64,
    response_bytes: Bytes,
}

impl LogBatch {
    /// Wrap protobuf bytes already encoded as `log.stream.v1.GetResponse`.
    pub fn from_response_bytes(sequence_number: u64, response_bytes: impl Into<Bytes>) -> Self {
        Self {
            sequence_number,
            response_bytes: response_bytes.into(),
        }
    }

    /// Build a log batch from key-value pairs.
    pub fn from_entries(sequence_number: u64, kvs: Vec<(Bytes, Bytes)>) -> Self {
        Self::from_response(StreamGetResponse {
            sequence_number,
            entries: kvs
                .into_iter()
                .map(|(key, value)| Entry {
                    key: key.to_vec(),
                    value,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }

    /// Build a log batch from an owned response.
    pub fn from_response(response: StreamGetResponse) -> Self {
        Self {
            sequence_number: response.sequence_number,
            response_bytes: Bytes::from(response.encode_to_vec()),
        }
    }

    /// Sequence number under which this batch was loaded.
    pub fn sequence_number(&self) -> u64 {
        self.sequence_number
    }

    /// Consume the batch into its pre-encoded response bytes.
    pub fn into_response_bytes(self) -> Bytes {
        self.response_bytes
    }

    /// Decode the stored response for paths that need to inspect entries.
    pub fn decode_response(&self) -> Result<StreamGetResponse, String> {
        StreamGetResponse::decode_from_slice(&self.response_bytes)
            .map_err(|err| format!("failed to decode sequence log value: {err}"))
    }
}

/// Filtered and fully resolved entries from a retained sequence batch.
///
/// An empty entry list represents a retained batch with no matches. Subscribe
/// frames are stamped with the sequence number the read was requested under,
/// so a filtered batch carries no sequence number a backend could misstamp.
#[derive(Clone, Debug)]
pub struct FilteredBatch {
    entries: Vec<Entry>,
}

impl FilteredBatch {
    /// Build a filtered batch from owned caller-visible entries.
    ///
    /// Values must contain resolved payload bytes.
    pub fn from_entries(entries: Vec<Entry>) -> Self {
        Self { entries }
    }

    /// Build a filtered batch from resolved key-value pairs.
    pub fn from_kvs(kvs: Vec<(Bytes, Bytes)>) -> Self {
        Self {
            entries: kvs
                .into_iter()
                .map(|(key, value)| Entry {
                    key: key.to_vec(),
                    value,
                    ..Default::default()
                })
                .collect(),
        }
    }

    /// Consume the batch into its entries.
    pub fn into_entries(self) -> Vec<Entry> {
        self.entries
    }
}

/// Retained per-sequence batch-log access for stream replay and lookups.
pub trait Log: Sequence {
    /// Return the pre-encoded `GetResponse` for the `put_batch` call that was
    /// assigned `sequence_number`. Return `Ok(None)` when the batch is not
    /// available from this log.
    ///
    /// Engines that don't retain a log return `Ok(None)` unconditionally,
    /// which disables `GetBatch` and since-cursored `Subscribe` for that
    /// deployment.
    ///
    /// The stream service maps unavailable batches to `BATCH_NOT_FOUND` when
    /// they are beyond the visible sequence frontier and `BATCH_EVICTED`
    /// otherwise.
    fn get_batch(
        &self,
        sequence_number: u64,
    ) -> impl Future<Output = Result<Option<LogBatch>, String>> + Send;

    /// Return fully resolved matching entries from the batch assigned
    /// `sequence_number`.
    ///
    /// Return `Some` with no entries when the batch is retained but no entries
    /// match. Return `None` only when the batch is unavailable.
    ///
    /// An entry matches only when [`CompiledMatchers::matches_key`] accepts its
    /// key and [`CompiledMatchers::matches_value`] accepts its resolved value.
    /// Matching entries must keep their original batch order and multiplicity
    /// without truncation, so subscribers observe the same frames the default
    /// implementation would produce. Subscribe frames are stamped with the
    /// requested `sequence_number`, so entries taken from any other batch would
    /// be delivered under the wrong resume cursor.
    ///
    /// Optimized implementations must call `matches_key` before resolving a
    /// value and `matches_value` afterward. Failures confined to key-excluded
    /// values do not fail the filtered read.
    fn get_batch_filtered(
        &self,
        sequence_number: u64,
        matchers: &CompiledMatchers,
    ) -> impl Future<Output = Result<Option<FilteredBatch>, String>> + Send {
        async move {
            let Some(batch) = self.get_batch(sequence_number).await? else {
                return Ok(None);
            };
            let response = batch.decode_response()?;
            let entries = apply_filter(matchers, response.entries);
            Ok(Some(FilteredBatch::from_entries(entries)))
        }
    }

    /// Lowest retained batch sequence number, or `None` when the log is
    /// empty. Surfaced in `BATCH_EVICTED` error details so clients know where
    /// to resume from.
    fn oldest_retained_batch(&self) -> impl Future<Output = Result<Option<u64>, String>> + Send;
}

/// Sequence-log retention capability (`log.stream.v1` SetRetention).
pub trait Retention: Send + Sync + 'static {
    /// Persist and apply the retention rule; `None` clears it. Returns the oldest retained
    /// sequence after one synchronous enforcement (`None` when the log is empty / no floor).
    fn set_retention(
        &self,
        policy: Option<RetentionPolicy>,
    ) -> impl Future<Output = Result<Option<u64>, String>> + Send;
}

/// Compatibility facade for backends that serve every store capability.
pub trait StoreEngine: Ingest + Query + Prune + Log + Retention {}

impl<T: Ingest + Query + Prune + Log + Retention> StoreEngine for T {}

#[cfg(test)]
mod tests {
    use std::future::ready;

    use super::*;
    use exoware_sdk::kv_codec::Utf8;
    use exoware_sdk::selector::Selector;
    use exoware_sdk::stream_filter::StreamFilter;

    #[derive(Clone)]
    struct TestLog {
        batch: Option<LogBatch>,
    }

    impl Sequence for TestLog {
        fn current_sequence(&self) -> u64 {
            u64::from(self.batch.is_some())
        }
    }

    impl Log for TestLog {
        fn get_batch(
            &self,
            sequence_number: u64,
        ) -> impl Future<Output = Result<Option<LogBatch>, String>> + Send {
            ready(Ok((sequence_number == 1)
                .then(|| self.batch.clone())
                .flatten()))
        }

        fn oldest_retained_batch(
            &self,
        ) -> impl Future<Output = Result<Option<u64>, String>> + Send {
            ready(Ok(self.batch.as_ref().map(|_| 1)))
        }
    }

    fn matchers() -> CompiledMatchers {
        crate::stream::compile_matchers(&StreamFilter {
            selectors: vec![Selector {
                prefix: Bytes::from_static(&[1]),
                payload_regex: Utf8::from("^keep$"),
            }],
            value_filters: vec![],
        })
        .unwrap()
    }

    #[test]
    fn default_filtered_batch_preserves_retained_and_missing_states() {
        let matching = (
            Bytes::from_static(&[1, b'k', b'e', b'e', b'p']),
            Bytes::from_static(b"one"),
        );
        let excluded = (
            Bytes::from_static(&[2, b'k', b'e', b'e', b'p']),
            Bytes::from_static(b"two"),
        );
        let log = TestLog {
            batch: Some(LogBatch::from_entries(1, vec![matching, excluded])),
        };
        let filtered = futures::executor::block_on(log.get_batch_filtered(1, &matchers()))
            .unwrap()
            .unwrap();
        let entries = filtered.into_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value.as_ref(), b"one");

        let retained_without_matches = TestLog {
            batch: Some(LogBatch::from_entries(
                1,
                vec![(Bytes::from_static(&[2]), Bytes::from_static(b"value"))],
            )),
        };
        let filtered = futures::executor::block_on(
            retained_without_matches.get_batch_filtered(1, &matchers()),
        )
        .unwrap()
        .unwrap();
        assert!(filtered.into_entries().is_empty());

        let missing = TestLog { batch: None };
        let filtered =
            futures::executor::block_on(missing.get_batch_filtered(1, &matchers())).unwrap();
        assert!(filtered.is_none());
    }
}
