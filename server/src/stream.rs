//! Live stream coordination for `log.stream.v1`.
//!
//! A [`StreamNotifier`] tracks the highest published batch sequence and wakes
//! subscribers. Each subscriber pulls batches from the log at its own pace.
//! A small ordered lookahead overlaps log reads without allowing an unbounded
//! per-subscriber backlog.
//!
//! `StreamNotifier` is an in-process coordination primitive. Split deployments
//! need a separate remote notification path that advances a local notifier after
//! the query worker can serve the announced batches.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use connectrpc::ConnectError;
use exoware_sdk::common::Entry;
use exoware_sdk::keys::Prefix;
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

#[derive(Clone, Debug)]
struct CompiledKeyMatcher {
    prefix: Prefix,
    regex: Regex,
}

/// A stream filter rejected during validation or compilation.
///
/// Messages describe the invalid selector or value filter and are safe to
/// surface to clients.
#[derive(Clone, Debug, thiserror::Error)]
#[error("{0}")]
pub struct InvalidFilter(String);

/// Validated stream matchers compiled for repeated evaluation.
#[derive(Clone, Debug)]
pub struct CompiledMatchers {
    keys: Vec<CompiledKeyMatcher>,
    values: Option<CompiledFilters>,
}

impl CompiledMatchers {
    /// Validate and compile a `StreamFilter`.
    pub fn compile(filter: &StreamFilter) -> Result<Self, InvalidFilter> {
        validate_filter(filter).map_err(|e| InvalidFilter(e.to_string()))?;
        let keys = filter
            .selectors
            .iter()
            .map(|mk| {
                let regex = compile_payload_regex(&mk.payload_regex)
                    .map_err(|e| InvalidFilter(e.to_string()))?;
                let prefix =
                    Prefix::new(mk.prefix.clone()).map_err(|e| InvalidFilter(e.to_string()))?;
                Ok(CompiledKeyMatcher { prefix, regex })
            })
            .collect::<Result<Vec<_>, InvalidFilter>>()?;
        let values = CompiledFilters::compile(&filter.value_filters)
            .map_err(|e| InvalidFilter(format!("invalid value_filter: {e}")))?;
        Ok(Self { keys, values })
    }

    /// Return whether both predicates accept an already-resolved entry.
    ///
    /// The key predicate runs first, so key-excluded entries avoid the
    /// value-filter scan. Implementations that resolve values lazily must call
    /// [`Self::matches_key`] before resolving the value and
    /// [`Self::matches_value`] afterward.
    pub fn matches(&self, key: &[u8], value: &[u8]) -> bool {
        self.matches_key(key) && self.matches_value(value)
    }

    /// Return whether any selector matches the key.
    ///
    /// Selector regular expressions evaluate bytes after the matching prefix.
    pub fn matches_key(&self, key: &[u8]) -> bool {
        self.keys.iter().any(|matcher| {
            matcher
                .prefix
                .strip_slice(key)
                .is_some_and(|payload| matcher.regex.is_match(payload))
        })
    }

    /// Return whether the configured value filters match the value.
    ///
    /// Values pass when no value filter is configured.
    pub fn matches_value(&self, value: &[u8]) -> bool {
        self.values
            .as_ref()
            .is_none_or(|matcher| matcher.matches(value))
    }
}

/// Validate and compile a `StreamFilter`. Shared between replay and live
/// delivery so both paths match identically and regexes are compiled once per
/// subscribe.
pub(crate) fn compile_matchers(filter: &StreamFilter) -> Result<CompiledMatchers, ConnectError> {
    CompiledMatchers::compile(filter).map_err(|e| ConnectError::invalid_argument(e.to_string()))
}

/// Apply compiled matchers while consuming the source entries.
pub(crate) fn apply_filter(matchers: &CompiledMatchers, kvs: Vec<Entry>) -> Vec<Entry> {
    kvs.into_iter()
        .filter(|kv| matchers.matches(kv.key.as_ref(), kv.value.as_ref()))
        .collect()
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
    use crate::{Filter, Selector, StreamFilter, Utf8};
    use bytes::Bytes;
    use exoware_sdk::keys::Key;

    fn filter(prefix: u8, regex: &str) -> StreamFilter {
        StreamFilter {
            selectors: vec![Selector {
                prefix: Bytes::from(vec![prefix]),
                payload_regex: Utf8::from(regex),
            }],
            value_filters: vec![],
        }
    }

    fn filter_with_values(prefix: u8, regex: &str, value_filters: Vec<Filter>) -> StreamFilter {
        StreamFilter {
            selectors: vec![Selector {
                prefix: Bytes::from(vec![prefix]),
                payload_regex: Utf8::from(regex),
            }],
            value_filters,
        }
    }

    fn key(family: u8, payload: &[u8]) -> Key {
        Prefix::from_byte(family).encode(payload).unwrap()
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
        let entries = apply_filter(&matchers, kvs);
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
        let entries = apply_filter(&matchers, kvs);
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
        let entries = apply_filter(&matchers, kvs);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value.as_ref(), b"target");
    }

    #[test]
    fn value_filter_empty_accepts_all_matching_keys() {
        let matchers = compile_matchers(&filter(1, "(?s).*")).unwrap();
        let kvs = vec![kv(1, b"a", b"one"), kv(1, b"b", b"two")];
        let entries = apply_filter(&matchers, kvs);
        assert_eq!(entries.len(), 2);
    }

    // Verbatim copy of the pre-refactor apply_filter loop. The differential
    // test below pins the rewrite to the old first-match-wins semantics.
    fn apply_filter_reference(matchers: &CompiledMatchers, kvs: &[Entry]) -> Vec<Entry> {
        let mut out = Vec::with_capacity(kvs.len());
        'outer: for kv in kvs {
            let v = kv.value.as_ref();
            let value_ok = matchers.values.as_ref().is_none_or(|m| m.matches(v));
            if !value_ok {
                continue;
            }
            for matcher in &matchers.keys {
                let Some(payload) = matcher.prefix.strip_slice(&kv.key) else {
                    continue;
                };
                if matcher.regex.is_match(payload) {
                    out.push(kv.clone());
                    continue 'outer;
                }
            }
        }
        out
    }

    #[test]
    fn apply_filter_matches_reference_implementation() {
        let overlapping = StreamFilter {
            selectors: vec![
                Selector {
                    prefix: Bytes::from_static(&[1]),
                    payload_regex: Utf8::from("^a"),
                },
                Selector {
                    prefix: Bytes::from_static(&[1]),
                    payload_regex: Utf8::from("b$"),
                },
                Selector {
                    prefix: Bytes::from_static(&[2]),
                    payload_regex: Utf8::from("(?s).*"),
                },
            ],
            value_filters: vec![],
        };
        let with_values = StreamFilter {
            value_filters: vec![
                Filter::Prefix(Bytes::from_static(b"keep")),
                Filter::Exact(Bytes::from_static(b"exact")),
                Filter::Regex("^regex$".into()),
            ],
            ..overlapping.clone()
        };
        let entries = vec![
            // Matches both prefix-1 selectors and must appear exactly once.
            kv(1, b"ab", b"keep-anything"),
            kv(1, b"aX", b"exact"),
            kv(1, b"Xb", b"regex"),
            kv(1, b"XX", b"keep"),
            kv(1, b"", b"keep"),
            kv(2, b"", b"exact"),
            kv(2, b"anything", b"drop"),
            kv(3, b"ab", b"keep"),
            // Duplicate entry preserves multiplicity.
            kv(1, b"ab", b"keep-anything"),
            kv(1, b"ab", b"nope"),
        ];

        for filter in [overlapping, with_values] {
            let matchers = compile_matchers(&filter).unwrap();
            let expected = apply_filter_reference(&matchers, &entries);
            let actual = apply_filter(&matchers, entries.clone());
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn public_compile_builds_usable_matchers_and_rejects_invalid_filters() {
        let matchers = CompiledMatchers::compile(&filter_with_values(
            1,
            "^hit$",
            vec![Filter::Exact(Bytes::from_static(b"v"))],
        ))
        .expect("compile");
        assert!(matchers.matches(key(1, b"hit").as_ref(), b"v"));
        assert!(!matchers.matches(key(1, b"miss").as_ref(), b"v"));
        assert!(!matchers.matches(key(1, b"hit").as_ref(), b"other"));

        let invalid = StreamFilter {
            selectors: vec![],
            value_filters: vec![],
        };
        assert!(CompiledMatchers::compile(&invalid).is_err());
    }

    #[test]
    fn matcher_methods_preserve_key_and_value_semantics() {
        let matchers = compile_matchers(&filter_with_values(
            1,
            "^hit$",
            vec![
                Filter::Prefix(Bytes::from_static(b"keep")),
                Filter::Exact(Bytes::from_static(b"exact")),
                Filter::Regex("^regex$".into()),
            ],
        ))
        .unwrap();

        assert!(matchers.matches_key(key(1, b"hit").as_ref()));
        assert!(!matchers.matches_key(key(1, b"miss").as_ref()));
        assert!(!matchers.matches_key(key(2, b"hit").as_ref()));
        assert!(matchers.matches_value(b"keep-suffix"));
        assert!(matchers.matches_value(b"exact"));
        assert!(matchers.matches_value(b"regex"));
        assert!(!matchers.matches_value(b"drop"));

        let without_value_filters = compile_matchers(&filter(1, "(?s).*")).unwrap();
        assert!(without_value_filters.matches_value(b"anything"));
    }
}
