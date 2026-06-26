//! Live stream coordination for `log.stream.v1`.
//!
//! A [`StreamNotifier`] tracks the highest published batch sequence and wakes
//! subscribers. Each subscriber then pulls batches from the log at its own
//! pace, so live delivery is naturally paced by client reads instead of an
//! internal per-subscriber backlog.
//!
//! `StreamNotifier` is an in-process coordination primitive. Split deployments
//! need a separate remote notification path that advances a local notifier after
//! the query worker can serve the announced batches.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use connectrpc::ConnectError;
use exoware_sdk::common::Entry;
use exoware_sdk::keys::KeyCodec;
use exoware_sdk::selector::compile_payload_regex;
use exoware_sdk::stream_filter::{validate_filter, CompiledFilters, StreamFilter};
use regex::bytes::Regex;
use tokio::sync::Notify;

/// `ErrorInfo.domain` used for all stream-service errors.
pub const STREAM_ERROR_DOMAIN: &str = "log.stream";
/// `ErrorInfo.reason` when a `since_sequence_number` or `Get(seq)` references a
/// batch that has been pruned from the log.
pub const REASON_BATCH_EVICTED: &str = "BATCH_EVICTED";
/// `ErrorInfo.reason` when a `Get(seq)` references a sequence number greater
/// than any that has ever been issued.
pub const REASON_BATCH_NOT_FOUND: &str = "BATCH_NOT_FOUND";
/// Metadata key on `BATCH_EVICTED` errors carrying the lowest retained seq.
pub const METADATA_OLDEST_RETAINED: &str = "oldest_retained";

#[derive(Clone)]
pub(crate) struct CompiledKeyMatcher {
    codec: KeyCodec,
    regex: Regex,
}

#[derive(Clone)]
pub(crate) struct CompiledMatchers {
    pub keys: Vec<CompiledKeyMatcher>,
    pub values: Option<CompiledFilters>,
}

/// Validate and compile a `StreamFilter`. Shared between replay and live
/// delivery so both paths match identically and regexes are compiled once per
/// subscribe.
pub(crate) fn compile_matchers(filter: &StreamFilter) -> Result<CompiledMatchers, ConnectError> {
    validate_filter(filter).map_err(|e| ConnectError::invalid_argument(e.to_string()))?;
    let keys = filter
        .selectors
        .iter()
        .map(|mk| {
            let regex = compile_payload_regex(&mk.payload_regex)
                .map_err(|e| ConnectError::invalid_argument(e.to_string()))?;
            Ok(CompiledKeyMatcher {
                codec: KeyCodec::new(mk.reserved_bits, mk.prefix),
                regex,
            })
        })
        .collect::<Result<Vec<_>, ConnectError>>()?;
    let values = CompiledFilters::compile(&filter.value_filters)
        .map_err(|e| ConnectError::invalid_argument(format!("invalid value_filter: {e}")))?;
    Ok(CompiledMatchers { keys, values })
}

/// Apply a compiled filter to a batch. First-match-wins per entry.
pub(crate) fn apply_filter(matchers: &CompiledMatchers, kvs: &[Entry]) -> Vec<Entry> {
    let mut out = Vec::with_capacity(kvs.len());
    'outer: for kv in kvs {
        let v = kv.value.as_ref();
        let value_ok = matchers.values.as_ref().is_none_or(|m| m.matches(v));
        if !value_ok {
            continue;
        }
        let k = Bytes::copy_from_slice(&kv.key);
        for matcher in &matchers.keys {
            if !matcher.codec.matches(&k) {
                continue;
            }
            let payload_len = matcher.codec.payload_capacity_bytes_for_key_len(k.len());
            let Ok(payload) = matcher.codec.read_payload(&k, 0, payload_len) else {
                continue;
            };
            if matcher.regex.is_match(&payload) {
                out.push(kv.clone());
                continue 'outer;
            }
        }
    }
    out
}

#[derive(Clone)]
pub struct StreamNotification {
    pub current_sequence: u64,
    pub notify: Arc<Notify>,
}

// TODO (#56): Add a separate remote stream notification abstraction for split deployments.
/// In-process notification capability for stream subscribers.
pub trait StreamNotifier: Send + Sync + 'static {
    /// Atomically snapshot the visible batch frontier and return a notifier
    /// that wakes when the frontier may have advanced.
    fn subscribe(&self) -> StreamNotification;

    /// Highest batch sequence currently visible to live subscribers.
    fn current_sequence(&self) -> u64;

    /// Announce that batches through `seq` may now be visible.
    fn advance(&self, seq: u64);
}

pub struct StreamHub {
    published_sequence: AtomicU64,
    notify: Arc<Notify>,
}

impl StreamHub {
    pub fn new(initial_sequence: u64) -> Self {
        Self {
            published_sequence: AtomicU64::new(initial_sequence),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Announce a newly committed batch sequence to subscribers.
    pub fn publish(&self, seq: u64) {
        self.advance(seq);
    }
}

impl StreamNotifier for StreamHub {
    fn subscribe(&self) -> StreamNotification {
        StreamNotification {
            current_sequence: self.published_sequence.load(Ordering::Acquire),
            notify: self.notify.clone(),
        }
    }

    fn current_sequence(&self) -> u64 {
        self.published_sequence.load(Ordering::Acquire)
    }

    fn advance(&self, seq: u64) {
        self.published_sequence.fetch_max(seq, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exoware_sdk::kv_codec::Utf8;
    use exoware_sdk::selector::Selector;
    use exoware_sdk::stream_filter::Filter;

    fn filter(prefix: u16, regex: &str) -> StreamFilter {
        StreamFilter {
            selectors: vec![Selector {
                reserved_bits: 4,
                prefix,
                payload_regex: Utf8::from(regex),
            }],
            value_filters: vec![],
        }
    }

    fn filter_with_values(prefix: u16, regex: &str, value_filters: Vec<Filter>) -> StreamFilter {
        StreamFilter {
            selectors: vec![Selector {
                reserved_bits: 4,
                prefix,
                payload_regex: Utf8::from(regex),
            }],
            value_filters,
        }
    }

    fn key(family: u8, payload: &[u8]) -> Bytes {
        let codec = KeyCodec::new(4, u16::from(family));
        let key = codec.encode(payload).unwrap();
        Bytes::copy_from_slice(key.as_ref())
    }

    fn kv(family: u8, payload: &[u8], value: &'static [u8]) -> Entry {
        Entry {
            key: key(family, payload).to_vec(),
            value: Bytes::from_static(value),
            ..Default::default()
        }
    }

    #[test]
    fn publish_sequence_is_monotonic() {
        let hub = StreamHub::new(7);
        assert_eq!(hub.current_sequence(), 7);
        hub.publish(3);
        assert_eq!(hub.current_sequence(), 7);
        hub.publish(9);
        assert_eq!(hub.current_sequence(), 9);
    }

    #[test]
    fn subscribe_snapshots_current_sequence() {
        let hub = StreamHub::new(11);
        let subscription = hub.subscribe();
        assert_eq!(subscription.current_sequence, 11);
    }

    #[test]
    fn apply_filter_still_selects_matching_entries() {
        let matchers = compile_matchers(&filter(1, "(?s).*")).unwrap();
        let kvs = vec![kv(1, b"hit", b"v1"), kv(2, b"miss", b"v2")];
        let entries = apply_filter(&matchers, &kvs);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value.as_ref(), b"v1");
    }

    #[test]
    fn subscribe_rejects_invalid_filter() {
        let bad = StreamFilter {
            selectors: vec![],
            value_filters: vec![],
        };
        assert!(compile_matchers(&bad).is_err());
    }

    #[test]
    fn value_filter_intersects_with_key_filter() {
        let matchers = compile_matchers(&filter_with_values(
            1,
            "(?s).*",
            vec![Filter::Regex("^keep$".into())],
        ))
        .unwrap();
        let kvs = vec![kv(1, b"a", b"keep"), kv(1, b"b", b"drop")];
        let entries = apply_filter(&matchers, &kvs);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value.as_ref(), b"keep");
    }

    #[test]
    fn value_filter_exact_match() {
        let matchers = compile_matchers(&filter_with_values(
            1,
            "(?s).*",
            vec![Filter::Exact(Bytes::from_static(b"target"))],
        ))
        .unwrap();
        let kvs = vec![kv(1, b"a", b"target"), kv(1, b"b", b"other")];
        let entries = apply_filter(&matchers, &kvs);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value.as_ref(), b"target");
    }

    #[test]
    fn value_filter_empty_accepts_all_matching_keys() {
        let matchers = compile_matchers(&filter(1, "(?s).*")).unwrap();
        let kvs = vec![kv(1, b"a", b"one"), kv(1, b"b", b"two")];
        let entries = apply_filter(&matchers, &kvs);
        assert_eq!(entries.len(), 2);
    }
}
