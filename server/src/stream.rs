//! Live subscriber registry + post-commit fan-out for `store.stream.v1`.
//!
//! `StreamHub::publish` is called synchronously after `StoreEngine::put_batch`
//! returns `Ok`. Slow subscribers (full mpsc) are dropped on the next non-empty
//! fan-out so a wedged client can't hold up ingest.

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use connectrpc::ConnectError;
use dashmap::DashMap;
use exoware_sdk_rs::keys::KeyCodec;
use exoware_sdk_rs::match_key::compile_payload_regex;
use exoware_sdk_rs::store::stream::v1::{StreamEntry, SubscribeResponse};
use exoware_sdk_rs::stream_filter::{validate_filter, StreamFilter};
use regex::bytes::Regex;
use tokio::sync::mpsc;

/// Bounded queue depth per subscriber. 256 frames is enough to absorb bursts
/// without letting one subscriber hold megabytes of in-flight payload; beyond
/// that the subscriber is dropped (reconnect via since-cursor to catch up).
const SUBSCRIBER_CHANNEL_CAPACITY: usize = 256;

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
pub(crate) struct CompiledMatcher {
    codec: KeyCodec,
    regex: Regex,
}

/// Validate and compile a `StreamFilter` into ready-to-use `(KeyCodec, Regex)`
/// pairs. Shared between the hub (live fan-out) and `StreamConnect` (replay)
/// so both paths match identically and regexes are compiled once per subscribe.
pub(crate) fn compile_matchers(
    filter: &StreamFilter,
) -> Result<Vec<CompiledMatcher>, ConnectError> {
    validate_filter(filter).map_err(|e| ConnectError::invalid_argument(e.to_string()))?;
    filter
        .match_keys
        .iter()
        .map(|mk| {
            let regex = compile_payload_regex(&mk.payload_regex)
                .map_err(|e| ConnectError::invalid_argument(e.to_string()))?;
            Ok(CompiledMatcher {
                codec: KeyCodec::new(mk.reserved_bits, mk.prefix),
                regex,
            })
        })
        .collect()
}

/// Apply a compiled filter to a batch. First-match-wins per `(key, value)`.
pub(crate) fn apply_filter(
    matchers: &[CompiledMatcher],
    kvs: &[(Bytes, Bytes)],
) -> Vec<StreamEntry> {
    // Upper bound is `kvs.len()` (first-match-wins caps 1 entry per kv).
    let mut out = Vec::with_capacity(kvs.len());
    'outer: for (k, v) in kvs {
        for matcher in matchers {
            if !matcher.codec.matches(k) {
                continue;
            }
            let payload_len = matcher.codec.payload_capacity_bytes_for_key_len(k.len());
            let Ok(payload) = matcher.codec.read_payload(k, 0, payload_len) else {
                continue;
            };
            if matcher.regex.is_match(&payload) {
                out.push(StreamEntry {
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

struct Subscriber {
    matchers: Vec<CompiledMatcher>,
    tx: mpsc::Sender<Result<SubscribeResponse, ConnectError>>,
}

#[derive(Default)]
pub struct StreamHub {
    subs: DashMap<u64, Subscriber>,
    next_id: AtomicU64,
}

impl StreamHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a subscriber. Returns `(id, pre-compiled matchers, rx)` — the
    /// matchers are handed back so the replay path can reuse them instead of
    /// compiling every regex a second time.
    pub(crate) fn subscribe(
        &self,
        filter: StreamFilter,
    ) -> Result<
        (
            u64,
            Vec<CompiledMatcher>,
            mpsc::Receiver<Result<SubscribeResponse, ConnectError>>,
        ),
        ConnectError,
    > {
        let matchers = compile_matchers(&filter)?;
        let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.subs.insert(
            id,
            Subscriber {
                matchers: matchers.clone(),
                tx,
            },
        );
        Ok((id, matchers, rx))
    }

    /// Remove a subscriber by id (idempotent; no-op if already gone).
    pub fn unsubscribe(&self, id: u64) {
        self.subs.remove(&id);
    }

    /// Fan out a committed batch. A subscriber whose mpsc is full or closed is
    /// dropped on the same pass.
    pub fn publish(&self, seq: u64, kvs: &[(Bytes, Bytes)]) {
        if self.subs.is_empty() {
            return;
        }
        self.subs.retain(|_, sub| {
            let entries = apply_filter(&sub.matchers, kvs);
            if entries.is_empty() {
                // Retain idle subscribers. Drop only on actual send failure, so
                // a filter that never matches doesn't evict the client.
                return !sub.tx.is_closed();
            }
            let frame = SubscribeResponse {
                sequence_number: seq,
                entries,
                ..Default::default()
            };
            sub.tx.try_send(Ok(frame)).is_ok()
        });
    }

    #[cfg(test)]
    pub(crate) fn subscriber_count(&self) -> usize {
        self.subs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exoware_sdk_rs::kv_codec::Utf8;
    use exoware_sdk_rs::match_key::MatchKey;

    fn filter(prefix: u16, regex: &str) -> StreamFilter {
        StreamFilter {
            match_keys: vec![MatchKey {
                reserved_bits: 4,
                prefix,
                payload_regex: Utf8::from(regex),
            }],
        }
    }

    fn key(family: u8, payload: &[u8]) -> Bytes {
        let codec = KeyCodec::new(4, u16::from(family));
        let key = codec.encode(payload).unwrap();
        Bytes::copy_from_slice(key.as_ref())
    }

    #[test]
    fn publish_delivers_only_matching_entries() {
        let hub = StreamHub::new();
        let (_id, _m, mut rx) = hub.subscribe(filter(1, "(?s).*")).unwrap();
        let kvs = vec![
            (key(1, b"hit"), Bytes::from_static(b"v1")),
            (key(2, b"miss"), Bytes::from_static(b"v2")),
        ];
        hub.publish(42, &kvs);
        let frame = rx.try_recv().unwrap().unwrap();
        assert_eq!(frame.sequence_number, 42);
        assert_eq!(frame.entries.len(), 1);
        assert_eq!(frame.entries[0].value.as_slice(), b"v1");
    }

    #[test]
    fn non_matching_publish_yields_no_frame_but_retains_subscriber() {
        let hub = StreamHub::new();
        let (_id, _m, mut rx) = hub.subscribe(filter(1, "(?s).*")).unwrap();
        hub.publish(1, &[(key(2, b"nope"), Bytes::from_static(b"x"))]);
        assert!(rx.try_recv().is_err());
        assert_eq!(hub.subscriber_count(), 1);
    }

    #[test]
    fn subscriber_drops_on_closed_channel() {
        let hub = StreamHub::new();
        let (_id, _m, rx) = hub.subscribe(filter(1, "(?s).*")).unwrap();
        drop(rx);
        // Non-matching publish retains idle subs; `is_closed()` makes us drop.
        hub.publish(1, &[(key(2, b"x"), Bytes::new())]);
        assert_eq!(hub.subscriber_count(), 0);
    }

    #[test]
    fn subscribe_rejects_invalid_filter() {
        let hub = StreamHub::new();
        let bad = StreamFilter { match_keys: vec![] };
        assert!(hub.subscribe(bad).is_err());
    }
}
