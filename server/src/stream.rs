//! Live subscriber registry + post-commit fan-out for `store.stream.v1`.
//!
//! `StreamHub` holds the active subscribers. `StreamHub::publish` is called
//! synchronously after `StoreEngine::put_batch` returns `Ok`. Each subscriber
//! carries a precompiled regex-bytes match list; we run it against each `(key,
//! value)` of the batch and `try_send` a `StreamFrame` over a bounded mpsc. A
//! slow subscriber whose channel fills is dropped on the next non-empty frame
//! — we don't block ingest to wait for it.

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use connectrpc::ConnectError;
use dashmap::DashMap;
use exoware_sdk_rs::keys::KeyCodec;
use exoware_sdk_rs::match_key::compile_payload_regex;
use exoware_sdk_rs::store::stream::v1::{StreamEntry, StreamFrame};
use exoware_sdk_rs::stream_filter::{validate_filter, StreamFilter};
use regex::bytes::Regex;
use tokio::sync::mpsc;

/// Bounded queue depth per subscriber. 256 frames is enough to absorb bursts
/// without letting one subscriber hold megabytes of in-flight payload; beyond
/// that, the subscriber is dropped (reconnect via since-cursor to catch up).
const SUBSCRIBER_CHANNEL_CAPACITY: usize = 256;

#[derive(Clone)]
struct CompiledMatcher {
    codec: KeyCodec,
    regex: Regex,
}

struct Subscriber {
    matchers: Vec<CompiledMatcher>,
    tx: mpsc::Sender<Result<StreamFrame, ConnectError>>,
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

    /// Register a subscriber. Returns the subscriber id (for later
    /// `unsubscribe`) and the receive half of the channel feeding its stream.
    /// The filter is validated and compiled here so invalid input fails
    /// before we touch ingest.
    pub fn subscribe(
        &self,
        filter: StreamFilter,
    ) -> Result<(u64, mpsc::Receiver<Result<StreamFrame, ConnectError>>), ConnectError> {
        validate_filter(&filter).map_err(|e| ConnectError::invalid_argument(e.to_string()))?;
        let mut matchers = Vec::with_capacity(filter.match_keys.len());
        for mk in &filter.match_keys {
            let regex = compile_payload_regex(&mk.payload_regex)
                .map_err(|e| ConnectError::invalid_argument(e.to_string()))?;
            let codec = KeyCodec::new(mk.reserved_bits, mk.prefix);
            matchers.push(CompiledMatcher { codec, regex });
        }
        let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.subs.insert(id, Subscriber { matchers, tx });
        Ok((id, rx))
    }

    /// Remove a subscriber by id (idempotent; no-op if already gone).
    pub fn unsubscribe(&self, id: u64) {
        self.subs.remove(&id);
    }

    /// Fan out a committed batch. Called synchronously after
    /// `StoreEngine::put_batch` returns `Ok(seq)`. Subscribers whose mpsc is
    /// full or closed are dropped on the same pass so a chronically slow
    /// client can't wedge ingest.
    pub fn publish(&self, seq: u64, kvs: &[(Bytes, Bytes)]) {
        // Short-circuit the common no-subscribers case.
        if self.subs.is_empty() {
            return;
        }
        self.subs.retain(|_, sub| {
            let entries = apply_filter(&sub.matchers, kvs);
            if entries.is_empty() {
                // Keep idle subscribers. Drop only on actual send failure, so
                // that a filter which never matches doesn't evict the client.
                return !sub.tx.is_closed();
            }
            let frame = StreamFrame {
                sequence_number: seq,
                entries,
                ..Default::default()
            };
            sub.tx.try_send(Ok(frame)).is_ok()
        });
    }

    /// Current subscriber count. Tests/diagnostics only.
    pub fn subscriber_count(&self) -> usize {
        self.subs.len()
    }
}

/// Apply a subscriber's matchers to a batch. First-match-wins per `(k, v)`.
/// Returns owned `StreamEntry` vec — the key/value are refcount-cloned.
fn apply_filter(matchers: &[CompiledMatcher], kvs: &[(Bytes, Bytes)]) -> Vec<StreamEntry> {
    let mut out = Vec::new();
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
        let (_id, mut rx) = hub.subscribe(filter(1, "(?s).*")).unwrap();
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
        let (_id, mut rx) = hub.subscribe(filter(1, "(?s).*")).unwrap();
        hub.publish(1, &[(key(2, b"nope"), Bytes::from_static(b"x"))]);
        assert!(rx.try_recv().is_err()); // no frame
        assert_eq!(hub.subscriber_count(), 1); // still subscribed
    }

    #[test]
    fn subscriber_drops_on_closed_channel() {
        let hub = StreamHub::new();
        let (_id, rx) = hub.subscribe(filter(1, "(?s).*")).unwrap();
        drop(rx);
        // First publish won't match our prefix → we still retain, but
        // `is_closed()` will be true so we drop.
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
