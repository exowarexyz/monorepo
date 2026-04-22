//! Shared batch accumulator + Stream adapter for all four QMDB variants.
//!
//! Variants plug in via `(Classify, BuildProof)` pairs; the three-state
//! pipeline (OP → PRESENCE → WATERMARK → drain) is otherwise identical.
//! Verification happens inside each variant's `BuildProof`, so items emitted
//! from the stream are already verified against the store's root.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use commonware_storage::mmr::Location;
use exoware_qmdb_core::stream::{Accumulator, ClosedBatch, Family};
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::match_key::MatchKey;
use exoware_sdk_rs::stream_filter::StreamFilter;
use exoware_sdk_rs::ClientError;
use futures::future::BoxFuture;
use futures::Stream;

use crate::error::QmdbError;
use crate::{ReadSubscription, SubscriptionEntry, SubscriptionFrame};

/// Closure that classifies a `(key, value)` pair into a known family and
/// decodes the sequence-number-agnostic `Location` from it. Implemented per
/// variant (ordered/unordered use OP_FAMILY=0x4 etc.; immutable/keyless use
/// AUTH_* + a namespace byte).
pub(crate) type Classify =
    Arc<dyn Fn(&Key, &[u8]) -> Option<(Family, Location)> + Send + Sync + 'static>;

/// Async factory that builds a variant's verified range (typically
/// `VerifiedOperationRange` for one of the four QMDB variants).
///
/// The leading `u64` is the store batch sequence that must be used as the
/// read floor for any follow-up query/proof session. This is how
/// `stream_batches()` avoids a visibility race where subscribe delivery can
/// outrun ordinary query visibility.
pub(crate) type BuildProof<Out> = Arc<
    dyn Fn(
            u64,      /* read floor store sequence number */
            Location, /* watermark */
            Location, /* start */
            u32,      /* count */
        ) -> BoxFuture<'static, Result<Out, QmdbError>>
        + Send
        + Sync
        + 'static,
>;

/// Build the three-family filter shared across all variants: OP + PRESENCE +
/// WATERMARK, each a `(reserved_bits, prefix, payload_regex)` tuple.
pub(crate) fn build_filter(
    reserved_bits: u8,
    op_prefix: u16,
    presence_prefix: u16,
    watermark_prefix: u16,
    payload_regex: &str,
) -> StreamFilter {
    use exoware_sdk_rs::kv_codec::Utf8;
    StreamFilter {
        match_keys: vec![
            MatchKey {
                reserved_bits,
                prefix: op_prefix,
                payload_regex: Utf8::from(payload_regex),
            },
            MatchKey {
                reserved_bits,
                prefix: presence_prefix,
                payload_regex: Utf8::from(payload_regex),
            },
            MatchKey {
                reserved_bits,
                prefix: watermark_prefix,
                payload_regex: Utf8::from(payload_regex),
            },
        ],
    }
}

/// Per-family decoder callback used by `classify_and_filter`. Returns `None`
/// when the key doesn't belong to this family/namespace (e.g. a keyless row
/// sneaked onto an immutable subscriber's filter).
type DecodeLocation = Arc<dyn Fn(&exoware_sdk_rs::keys::Key) -> Option<Location> + Send + Sync>;

/// Build a `(Classify, StreamFilter)` from three (Op, Presence, Watermark)
/// family entries. Each entry is `(prefix, decoder)`; `reserved_bits` and
/// `payload_regex` are shared. This is the one place the driver understands
/// how QMDB row families look on the wire.
fn classify_and_filter(
    reserved_bits: u8,
    payload_regex: &str,
    families: [(u16, Family, DecodeLocation); 3],
) -> (Classify, StreamFilter) {
    use exoware_sdk_rs::keys::{Key as StoreKey, KeyCodec};

    let compiled: [(KeyCodec, Family, DecodeLocation); 3] = [
        (
            KeyCodec::new(reserved_bits, families[0].0),
            families[0].1,
            families[0].2.clone(),
        ),
        (
            KeyCodec::new(reserved_bits, families[1].0),
            families[1].1,
            families[1].2.clone(),
        ),
        (
            KeyCodec::new(reserved_bits, families[2].0),
            families[2].1,
            families[2].2.clone(),
        ),
    ];

    let classify: Classify = Arc::new(move |key: &StoreKey, _value: &[u8]| {
        for (codec, family, decode) in &compiled {
            if codec.matches(key) {
                return decode(key).map(|l| (*family, l));
            }
        }
        None
    });

    let filter = build_filter(
        reserved_bits,
        families[0].0,
        families[1].0,
        families[2].0,
        payload_regex,
    );
    (classify, filter)
}

/// Classifier + filter for the unauthenticated (Op=0x4, Presence=0x2,
/// Watermark=0x3) layout used by `ordered` and `unordered`.
pub(crate) fn unauthenticated_classify_and_filter() -> (Classify, StreamFilter) {
    use crate::codec::{
        decode_operation_location_key, decode_presence_location, decode_watermark_location,
        OP_FAMILY, PRESENCE_FAMILY, RESERVED_BITS, WATERMARK_FAMILY,
    };
    classify_and_filter(
        RESERVED_BITS,
        "(?s-u)^.{8}$",
        [
            (
                OP_FAMILY,
                Family::Op,
                Arc::new(|k| decode_operation_location_key(k).ok()),
            ),
            (
                PRESENCE_FAMILY,
                Family::Presence,
                Arc::new(|k| decode_presence_location(k).ok()),
            ),
            (
                WATERMARK_FAMILY,
                Family::Watermark,
                Arc::new(|k| decode_watermark_location(k).ok()),
            ),
        ],
    )
}

/// Classifier + filter for the authenticated (AUTH_OP=0x9, AUTH_INDEX=0xC,
/// AUTH_WATERMARK=0xB) layout used by `immutable` and `keyless`. The 1-byte
/// namespace tag in each key's payload gates cross-variant leakage.
pub(crate) fn authenticated_classify_and_filter(
    namespace: crate::auth::AuthenticatedBackendNamespace,
) -> (Classify, StreamFilter) {
    use crate::auth::{
        auth_payload_regex_for_namespace, decode_auth_operation_location,
        decode_auth_presence_location, decode_auth_watermark_location, AUTH_FAMILY_RESERVED_BITS,
        AUTH_OP_FAMILY_PREFIX, AUTH_PRESENCE_FAMILY_PREFIX, AUTH_WATERMARK_FAMILY_PREFIX,
    };
    let ns = namespace;
    classify_and_filter(
        AUTH_FAMILY_RESERVED_BITS,
        &auth_payload_regex_for_namespace(ns),
        [
            (
                AUTH_OP_FAMILY_PREFIX,
                Family::Op,
                Arc::new(move |k| decode_auth_operation_location(ns, k).ok()),
            ),
            (
                AUTH_PRESENCE_FAMILY_PREFIX,
                Family::Presence,
                Arc::new(move |k| decode_auth_presence_location(ns, k).ok()),
            ),
            (
                AUTH_WATERMARK_FAMILY_PREFIX,
                Family::Watermark,
                Arc::new(move |k| decode_auth_watermark_location(ns, k).ok()),
            ),
        ],
    )
}

pin_project_lite::pin_project! {
    // Generic stream of per-batch proofs. `Out` is whatever the variant's
    // `operation_range_proof` returns.
    pub struct BatchProofStream<Out> {
        sub: Option<Box<dyn ReadSubscription>>,
        classify: Classify,
        build_proof: BuildProof<Out>,
        acc: Accumulator,
        // Queued ready batches awaiting proof construction. Pulled one per
        // poll_next call so we don't starve the transport.
        ready: VecDeque<ClosedBatch>,
        // Currently-building proof future, if any.
        #[pin]
        building: Option<BoxFuture<'static, Result<Out, QmdbError>>>,
        // In-flight upstream subscription read. This must persist across polls,
        // especially for JS/WASM subscriptions whose `next()` resolves later.
        #[pin]
        pulling: Option<PullNext>,
    }
}

type PullNext = BoxFuture<
    'static,
    (
        Box<dyn ReadSubscription>,
        Result<Option<SubscriptionFrame>, ClientError>,
    ),
>;

fn pull_next(mut sub: Box<dyn ReadSubscription>) -> PullNext {
    Box::pin(async move {
        let next = sub.next().await;
        (sub, next)
    })
}

impl<Out> BatchProofStream<Out> {
    pub(crate) fn new(
        sub: Box<dyn ReadSubscription>,
        classify: Classify,
        build_proof: BuildProof<Out>,
    ) -> Self {
        Self {
            sub: Some(sub),
            classify,
            build_proof,
            acc: Accumulator::new(),
            ready: VecDeque::new(),
            building: None,
            pulling: None,
        }
    }
}

impl<Out: Send + 'static> Stream for BatchProofStream<Out> {
    type Item = Result<Out, QmdbError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            // 1. If a proof is already being built, drive it to completion.
            if let Some(fut) = this.building.as_mut().as_pin_mut() {
                match fut.poll(cx) {
                    Poll::Ready(Ok(out)) => {
                        this.building.set(None);
                        return Poll::Ready(Some(Ok(out)));
                    }
                    Poll::Ready(Err(e)) => {
                        this.building.set(None);
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            // 2. If there's a ready batch and no proof in flight, kick one off.
            if let Some(batch) = this.ready.pop_front() {
                let count = u32::try_from(*(batch.latest - batch.start) + 1)
                    .expect("batch length fits u32");
                let fut = (this.build_proof)(
                    batch.read_floor_sequence,
                    batch.watermark,
                    batch.start,
                    count,
                );
                this.building.set(Some(fut));
                continue;
            }

            // 3. Pull the next frame from the upstream subscription.
            if this.pulling.as_mut().as_pin_mut().is_none() {
                let sub = this
                    .sub
                    .take()
                    .expect("subscription is only absent while a pull is in flight");
                this.pulling.set(Some(pull_next(sub)));
            }

            let (sub, next) = match this
                .pulling
                .as_mut()
                .as_pin_mut()
                .expect("pulling must be set before poll")
                .poll(cx)
            {
                Poll::Ready(result) => result,
                Poll::Pending => return Poll::Pending,
            };
            *this.sub = Some(sub);
            this.pulling.set(None);

            let frame = match next {
                Ok(Some(frame)) => frame,
                Ok(None) => return Poll::Ready(None),
                Err(err) => {
                    return Poll::Ready(Some(Err(QmdbError::Stream(err.to_string()))));
                }
            };

            // 4. Classify every entry in the frame and feed the accumulator.
            for entry in &frame.entries {
                let SubscriptionEntry { key, value } = entry;
                if let Some((family, location)) = (this.classify)(key, value.as_ref()) {
                    this.acc
                        .ingest_entry(family, location, frame.sequence_number);
                }
            }

            // 5. Drain any batches that are now ready. Enqueue them.
            let ready = this.acc.drain_ready();
            for r in ready {
                this.ready.push_back(r);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Accumulator, Family};
    use commonware_storage::mmr::Location;

    fn loc(n: u64) -> Location {
        Location::new(n)
    }

    // Two batches pending when both watermarks arrive in the same drain pass
    // must each be stamped with the watermark that actually authorized them,
    // not the single latest. Regression test for per-batch watermark mixing.
    #[test]
    fn drain_stamps_each_batch_with_its_own_watermark() {
        let mut acc = Accumulator::new();
        // Batch A: ops at 0..=5, presence at 5.
        for i in 0..=5 {
            acc.ingest_entry(Family::Op, loc(i), 11);
        }
        acc.ingest_entry(Family::Presence, loc(5), 11);
        // Batch B: ops at 6..=10, presence at 10.
        for i in 6..=10 {
            acc.ingest_entry(Family::Op, loc(i), 19);
        }
        acc.ingest_entry(Family::Presence, loc(10), 19);
        // Both watermarks land before any drain.
        acc.ingest_entry(Family::Watermark, loc(5), 13);
        acc.ingest_entry(Family::Watermark, loc(10), 23);

        let ready = acc.drain_ready();
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0].latest, loc(5));
        assert_eq!(ready[0].watermark, loc(5), "batch A must drain at wm=5");
        assert_eq!(ready[0].read_floor_sequence, 13);
        assert_eq!(ready[1].latest, loc(10));
        assert_eq!(ready[1].watermark, loc(10), "batch B must drain at wm=10");
        assert_eq!(ready[1].read_floor_sequence, 23);
    }

    // A batch stays pending until a watermark large enough to cover its
    // latest location arrives; later batches drain immediately once their
    // watermark lands.
    #[test]
    fn drain_waits_for_authorizing_watermark() {
        let mut acc = Accumulator::new();
        for i in 0..=5 {
            acc.ingest_entry(Family::Op, loc(i), 5);
        }
        acc.ingest_entry(Family::Presence, loc(5), 5);
        assert!(acc.drain_ready().is_empty());

        acc.ingest_entry(Family::Watermark, loc(4), 4);
        assert!(
            acc.drain_ready().is_empty(),
            "wm=4 does not authorize batch with latest=5"
        );

        acc.ingest_entry(Family::Watermark, loc(7), 9);
        let ready = acc.drain_ready();
        assert_eq!(ready.len(), 1);
        assert_eq!(
            ready[0].watermark,
            loc(7),
            "smallest wm >= latest is 7 (4 was GC'd)"
        );
        assert_eq!(ready[0].read_floor_sequence, 9);
    }

    // Cross-batch op interleaving inside a single ingest pass: disjoint
    // location ranges mean each batch advances its own in-progress entry
    // unambiguously. (Not a case our transport actually produces — frames are
    // per-PUT — but the entry-level accumulator handles it correctly and this
    // test pins that behavior against the bugbot "fragmentation" claim.)
    #[test]
    fn interleaved_cross_batch_ops_do_not_fragment() {
        let mut acc = Accumulator::new();
        // A: ops 0..=4, presence 4. B: ops 5..=9, presence 9.
        // Interleave in a way that stresses find_map matching.
        acc.ingest_entry(Family::Op, loc(0), 10);
        acc.ingest_entry(Family::Op, loc(5), 20);
        acc.ingest_entry(Family::Op, loc(1), 10);
        acc.ingest_entry(Family::Op, loc(6), 20);
        acc.ingest_entry(Family::Op, loc(2), 10);
        acc.ingest_entry(Family::Op, loc(3), 10);
        acc.ingest_entry(Family::Op, loc(4), 10);
        acc.ingest_entry(Family::Presence, loc(4), 10);
        acc.ingest_entry(Family::Op, loc(7), 20);
        acc.ingest_entry(Family::Op, loc(8), 20);
        acc.ingest_entry(Family::Op, loc(9), 20);
        acc.ingest_entry(Family::Presence, loc(9), 20);
        acc.ingest_entry(Family::Watermark, loc(4), 12);
        acc.ingest_entry(Family::Watermark, loc(9), 22);

        let ready = acc.drain_ready();
        assert_eq!(ready.len(), 2);
        assert_eq!((ready[0].start, ready[0].latest), (loc(0), loc(4)));
        assert_eq!(ready[0].watermark, loc(4));
        assert_eq!(ready[0].read_floor_sequence, 12);
        assert_eq!((ready[1].start, ready[1].latest), (loc(5), loc(9)));
        assert_eq!(ready[1].watermark, loc(9));
        assert_eq!(ready[1].read_floor_sequence, 22);
    }

    // GC must not discard a watermark that still authorizes a pending batch.
    // Per invariant 3 (monotonic batch `latest` on the wire) a late batch
    // with latest=3 after an earlier drain of latest=7 doesn't actually occur
    // in production — but the GC rule must still be safe if it did: the
    // smallest-pending-latest floor never drops a covering wm.
    #[test]
    fn gc_preserves_watermarks_needed_by_pending_batches() {
        let mut acc = Accumulator::new();
        // Idle drain with wm=7 seen but no pending: the fallback floor
        // (largest wm) retains wm=7 rather than emptying the set.
        acc.ingest_entry(Family::Watermark, loc(7), 7);
        let ready = acc.drain_ready();
        assert!(ready.is_empty());
        assert!(
            acc.has_watermark(loc(7)),
            "idle GC must retain the largest wm as a floor"
        );

        // Now a batch with latest=3 arrives (hypothetically late) plus its
        // own wm=3. Both wm=3 and wm=7 are in the set; drain picks the
        // smallest wm >= latest = 3, which is the authoritative one.
        for i in 0..=3 {
            acc.ingest_entry(Family::Op, loc(i), 3);
        }
        acc.ingest_entry(Family::Presence, loc(3), 3);
        acc.ingest_entry(Family::Watermark, loc(3), 3);
        let ready = acc.drain_ready();
        assert_eq!(ready.len(), 1);
        assert_eq!(
            ready[0].watermark,
            loc(3),
            "drain picks own wm=3, not later wm=7"
        );
        assert_eq!(ready[0].read_floor_sequence, 3);
    }

    #[test]
    fn drain_uses_later_of_batch_and_watermark_sequences_as_read_floor() {
        let mut acc = Accumulator::new();

        acc.ingest_entry(Family::Op, loc(0), 40);
        acc.ingest_entry(Family::Presence, loc(0), 40);
        acc.ingest_entry(Family::Watermark, loc(0), 35);

        acc.ingest_entry(Family::Op, loc(1), 50);
        acc.ingest_entry(Family::Presence, loc(1), 50);
        acc.ingest_entry(Family::Watermark, loc(1), 60);

        let ready = acc.drain_ready();
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0].latest, loc(0));
        assert_eq!(ready[0].read_floor_sequence, 40);
        assert_eq!(ready[1].latest, loc(1));
        assert_eq!(ready[1].read_floor_sequence, 60);
    }
}
