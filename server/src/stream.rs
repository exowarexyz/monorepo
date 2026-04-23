//! Live stream coordination for `store.stream.v1`.
//!
//! `StreamHub::publish` is called synchronously after `StoreEngine::put_batch`
//! returns `Ok`. The hub only tracks the highest published batch sequence and
//! wakes subscribers; each subscriber then pulls batches from the engine at its
//! own pace, so live delivery is naturally paced by client reads instead of an
//! internal per-subscriber backlog.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use connectrpc::ConnectError;
use exoware_sdk_rs::common::KvEntry;
use exoware_sdk_rs::keys::KeyCodec;
use exoware_sdk_rs::match_key::compile_payload_regex;
use exoware_sdk_rs::stream_filter::{validate_filter, CompiledBytesFilters, StreamFilter};
use regex::bytes::Regex;
use tokio::sync::Notify;

/// `ErrorInfo.domain` used for all stream-service errors.
pub const STREAM_ERROR_DOMAIN: &str = "store.stream";
/// `ErrorInfo.reason` when a `since_sequence_number` or `Get(seq)` references a
/// batch that has been pruned from the batch log.
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
    pub values: Option<CompiledBytesFilters>,
}

/// Validate and compile a `StreamFilter`. Shared between replay and live
/// delivery so both paths match identically and regexes are compiled once per
/// subscribe.
pub(crate) fn compile_matchers(filter: &StreamFilter) -> Result<CompiledMatchers, ConnectError> {
    validate_filter(filter).map_err(|e| ConnectError::invalid_argument(e.to_string()))?;
    let keys = filter
        .match_keys
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
    let values = CompiledBytesFilters::compile(&filter.value_filters)
        .map_err(|e| ConnectError::invalid_argument(format!("invalid value_filter: {e}")))?;
    Ok(CompiledMatchers { keys, values })
}

/// Apply a compiled filter to a batch. First-match-wins per `(key, value)`.
pub(crate) fn apply_filter(matchers: &CompiledMatchers, kvs: &[(Bytes, Bytes)]) -> Vec<KvEntry> {
    let mut out = Vec::with_capacity(kvs.len());
    'outer: for (k, v) in kvs {
        let value_ok = matchers.values.as_ref().is_none_or(|m| m.matches(v));
        if !value_ok {
            continue;
        }
        for matcher in &matchers.keys {
            if !matcher.codec.matches(k) {
                continue;
            }
            let payload_len = matcher.codec.payload_capacity_bytes_for_key_len(k.len());
            let Ok(payload) = matcher.codec.read_payload(k, 0, payload_len) else {
                continue;
            };
            if matcher.regex.is_match(&payload) {
                out.push(KvEntry {
                    key: k.to_vec(),
                    value: v.to_vec(),
                    ..Default::default()
                });
                continue 'outer;
            }
        }
    }
    out
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

    /// Compile the filter and atomically snapshot the highest published batch
    /// sequence that should be considered "already visible" to this
    /// subscription. Later publishes wake the returned notifier.
    pub(crate) fn subscribe(
        &self,
        filter: StreamFilter,
    ) -> Result<(CompiledMatchers, u64, Arc<Notify>), ConnectError> {
        let matchers = compile_matchers(&filter)?;
        let floor = self.published_sequence.load(Ordering::Acquire);
        Ok((matchers, floor, self.notify.clone()))
    }

    /// Announce a newly committed batch sequence to subscribers.
    pub fn publish(&self, seq: u64) {
        self.published_sequence.fetch_max(seq, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub(crate) fn current_sequence(&self) -> u64 {
        self.published_sequence.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exoware_sdk_rs::kv_codec::Utf8;
    use exoware_sdk_rs::match_key::MatchKey;
    use exoware_sdk_rs::stream_filter::BytesFilter;

    fn filter(prefix: u16, regex: &str) -> StreamFilter {
        StreamFilter {
            match_keys: vec![MatchKey {
                reserved_bits: 4,
                prefix,
                payload_regex: Utf8::from(regex),
            }],
            value_filters: vec![],
        }
    }

    fn filter_with_values(
        prefix: u16,
        regex: &str,
        value_filters: Vec<BytesFilter>,
    ) -> StreamFilter {
        StreamFilter {
            match_keys: vec![MatchKey {
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
        let (_matchers, floor, _notify) = hub.subscribe(filter(1, "(?s).*")).unwrap();
        assert_eq!(floor, 11);
    }

    #[test]
    fn apply_filter_still_selects_matching_entries() {
        let matchers = compile_matchers(&filter(1, "(?s).*")).unwrap();
        let kvs = vec![
            (key(1, b"hit"), Bytes::from_static(b"v1")),
            (key(2, b"miss"), Bytes::from_static(b"v2")),
        ];
        let entries = apply_filter(&matchers, &kvs);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value.as_slice(), b"v1");
    }

    #[test]
    fn subscribe_rejects_invalid_filter() {
        let hub = StreamHub::new(0);
        let bad = StreamFilter {
            match_keys: vec![],
            value_filters: vec![],
        };
        assert!(hub.subscribe(bad).is_err());
    }

    #[test]
    fn value_filter_intersects_with_key_filter() {
        let matchers = compile_matchers(&filter_with_values(
            1,
            "(?s).*",
            vec![BytesFilter::Regex("^keep$".into())],
        ))
        .unwrap();
        let kvs = vec![
            (key(1, b"a"), Bytes::from_static(b"keep")),
            (key(1, b"b"), Bytes::from_static(b"drop")),
        ];
        let entries = apply_filter(&matchers, &kvs);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value.as_slice(), b"keep");
    }

    #[test]
    fn value_filter_exact_match() {
        let matchers = compile_matchers(&filter_with_values(
            1,
            "(?s).*",
            vec![BytesFilter::Exact(b"target".to_vec())],
        ))
        .unwrap();
        let kvs = vec![
            (key(1, b"a"), Bytes::from_static(b"target")),
            (key(1, b"b"), Bytes::from_static(b"other")),
        ];
        let entries = apply_filter(&matchers, &kvs);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value.as_slice(), b"target");
    }

    #[test]
    fn value_filter_empty_accepts_all_matching_keys() {
        let matchers = compile_matchers(&filter(1, "(?s).*")).unwrap();
        let kvs = vec![
            (key(1, b"a"), Bytes::from_static(b"one")),
            (key(1, b"b"), Bytes::from_static(b"two")),
        ];
        let entries = apply_filter(&matchers, &kvs);
        assert_eq!(entries.len(), 2);
    }
}
