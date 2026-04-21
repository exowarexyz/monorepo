//! Shared batch accumulator + Stream adapter for all four QMDB variants.
//!
//! Variants plug in via `(Classify, BuildProof)` pairs; the three-state
//! pipeline (OP → PRESENCE → WATERMARK → drain) is otherwise identical.
//! Verification happens inside each variant's `BuildProof`, so items emitted
//! from the stream are already verified against the store's root.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use commonware_storage::mmr::Location;
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::match_key::MatchKey;
use exoware_sdk_rs::stream_filter::StreamFilter;
use exoware_sdk_rs::{StoreClient, StreamSubscription, StreamSubscriptionEntry};
use futures::future::BoxFuture;
use futures::Stream;

use crate::error::QmdbError;

/// Family an incoming key belongs to. `None` → the row is unrelated / we
/// should ignore it (for example, if the subscriber's filter were ever
/// widened to include other families).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Family {
    Op,
    Presence,
    Watermark,
}

/// Closure that classifies a `(key, value)` pair into a known family and
/// decodes the sequence-number-agnostic `Location` from it. Implemented per
/// variant (ordered/unordered use OP_FAMILY=0x4 etc.; immutable/keyless use
/// AUTH_* + a namespace byte).
pub(crate) type Classify =
    Arc<dyn Fn(&Key, &[u8]) -> Option<(Family, Location)> + Send + Sync + 'static>;

/// Async factory that builds a variant's verified range (typically
/// `VerifiedOperationRange` for one of the four QMDB variants).
pub(crate) type BuildProof<Out> = Arc<
    dyn Fn(
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

/// Open a subscription with no replay (live from the next batch).
pub(crate) async fn open_subscription(
    client: &StoreClient,
    filter: StreamFilter,
    since: Option<u64>,
) -> Result<StreamSubscription, QmdbError> {
    client
        .stream()
        .subscribe(filter, since)
        .await
        .map_err(|e| QmdbError::Stream(e.to_string()))
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

/// State machine for one stream.
struct Accumulator {
    in_progress: BTreeMap<Location /* start */, InProgressBatch>,
    pending: BTreeMap<Location /* latest */, ClosedBatch>,
    watermark: Option<Location>,
}

struct InProgressBatch {
    start: Location,
    next_expected: Location,
}

struct ClosedBatch {
    start: Location,
    latest: Location,
    /// Snapshot of the watermark in force at drain time; used by `poll_next`
    /// to feed `operation_range_proof`. Carrying it here avoids a stale-state
    /// race if the upstream advances the watermark between drain and poll.
    watermark: Location,
}

impl Accumulator {
    fn new() -> Self {
        Self {
            in_progress: BTreeMap::new(),
            pending: BTreeMap::new(),
            watermark: None,
        }
    }

    fn ingest_entry(&mut self, family: Family, location: Location) {
        match family {
            Family::Op => {
                let key = self
                    .in_progress
                    .iter()
                    .find_map(|(start, b)| (b.next_expected == location).then_some(*start));
                match key {
                    Some(start) => {
                        self.in_progress.get_mut(&start).unwrap().next_expected += 1;
                    }
                    None => {
                        self.in_progress.insert(
                            location,
                            InProgressBatch {
                                start: location,
                                next_expected: location + 1,
                            },
                        );
                    }
                }
            }
            Family::Presence => {
                // `location` is the batch's `latest_location` (inclusive max);
                // close the in-progress batch whose next_expected == latest+1.
                let key = self
                    .in_progress
                    .iter()
                    .find_map(|(start, b)| (b.next_expected == location + 1).then_some(*start));
                if let Some(start) = key {
                    let in_prog = self.in_progress.remove(&start).unwrap();
                    self.pending.insert(
                        location,
                        ClosedBatch {
                            start: in_prog.start,
                            latest: location,
                            watermark: Location::new(0),
                        },
                    );
                }
            }
            Family::Watermark => {
                if self.watermark.is_none_or(|w| w < location) {
                    self.watermark = Some(location);
                }
            }
        }
    }

    /// Drain every pending batch whose latest <= watermark, in ascending order.
    fn drain_ready(&mut self) -> Vec<ClosedBatch> {
        let Some(w) = self.watermark else {
            return Vec::new();
        };
        let mut ready = Vec::new();
        while let Some((&latest, _)) = self.pending.iter().next() {
            if latest > w {
                break;
            }
            let (_, mut batch) = self.pending.pop_first().unwrap();
            batch.watermark = w;
            ready.push(batch);
        }
        ready
    }
}

pin_project_lite::pin_project! {
    // Generic stream of per-batch proofs. `Out` is whatever the variant's
    // `operation_range_proof` returns.
    pub struct BatchProofStream<Out> {
        sub: StreamSubscription,
        classify: Classify,
        build_proof: BuildProof<Out>,
        acc: Accumulator,
        // Queued ready batches awaiting proof construction. Pulled one per
        // poll_next call so we don't starve the transport.
        ready: std::collections::VecDeque<ClosedBatch>,
        // Currently-building proof future, if any.
        #[pin]
        building: Option<BoxFuture<'static, Result<Out, QmdbError>>>,
    }
}

impl<Out> BatchProofStream<Out> {
    pub(crate) fn new(
        sub: StreamSubscription,
        classify: Classify,
        build_proof: BuildProof<Out>,
    ) -> Self {
        Self {
            sub,
            classify,
            build_proof,
            acc: Accumulator::new(),
            ready: std::collections::VecDeque::new(),
            building: None,
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
                let fut = (this.build_proof)(batch.watermark, batch.start, count);
                this.building.set(Some(fut));
                continue;
            }

            // 3. Pull the next frame from the upstream subscription.
            let next_fut = this.sub.next();
            tokio::pin!(next_fut);
            let frame = match next_fut.as_mut().poll(cx) {
                Poll::Ready(Ok(Some(frame))) => frame,
                Poll::Ready(Ok(None)) => return Poll::Ready(None),
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Some(Err(QmdbError::Stream(e.to_string()))));
                }
                Poll::Pending => return Poll::Pending,
            };

            // 4. Classify every entry in the frame and feed the accumulator.
            for entry in &frame.entries {
                let StreamSubscriptionEntry { key, value } = entry;
                if let Some((family, location)) = (this.classify)(key, value.as_ref()) {
                    this.acc.ingest_entry(family, location);
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
