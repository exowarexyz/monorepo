//! Shared batch accumulator + Stream adapter for all four QMDB variants.
//!
//! The accumulator consumes `StreamSubscriptionFrame`s from the store's stream
//! service and drives a state machine:
//! 1. OP row -> stash the location in the current in-progress batch.
//! 2. PRESENCE -> close the in-progress batch at `latest_location`, move to
//!    `pending`.
//! 3. WATERMARK -> for every pending batch whose `latest_location <= watermark`,
//!    call `build_proof(...)` and emit the proof on the output stream.
//!
//! The variant-specific pieces (family classification, `build_proof`) are
//! passed in; everything else is shared. Drivers do NOT verify proofs — the
//! caller is expected to call `verify::<H>()` on the emitted item.

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

/// Async factory that builds a variant's proof (OperationRangeProof,
/// UnorderedOperationRangeProof, or AuthenticatedOperationRangeProof<_>).
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

/// Classifier + filter pair for the shared (Op, Presence, Watermark) family
/// layout used by `ordered`/`unordered` (which share OP_FAMILY=0x4 /
/// PRESENCE_FAMILY=0x2 / WATERMARK_FAMILY=0x3) and `immutable`/`keyless`
/// (which share AUTH_OP/AUTH_INDEX/AUTH_WATERMARK, distinguished only by a
/// 1-byte namespace tag). Prevents drift across the four variant call sites.
pub(crate) fn unauthenticated_classify_and_filter() -> (Classify, StreamFilter) {
    use crate::codec::{
        decode_operation_location_key, decode_presence_location, decode_watermark_location,
        OP_FAMILY, PRESENCE_FAMILY, RESERVED_BITS, WATERMARK_FAMILY,
    };
    use exoware_sdk_rs::keys::{Key as StoreKey, KeyCodec};

    let op_codec = KeyCodec::new(RESERVED_BITS, OP_FAMILY);
    let presence_codec = KeyCodec::new(RESERVED_BITS, PRESENCE_FAMILY);
    let watermark_codec = KeyCodec::new(RESERVED_BITS, WATERMARK_FAMILY);

    let classify: Classify = Arc::new(move |key: &StoreKey, _value: &[u8]| {
        if op_codec.matches(key) {
            return decode_operation_location_key(key)
                .ok()
                .map(|l| (Family::Op, l));
        }
        if presence_codec.matches(key) {
            return decode_presence_location(key)
                .ok()
                .map(|l| (Family::Presence, l));
        }
        if watermark_codec.matches(key) {
            return decode_watermark_location(key)
                .ok()
                .map(|l| (Family::Watermark, l));
        }
        None
    });

    let filter = build_filter(
        RESERVED_BITS,
        OP_FAMILY,
        PRESENCE_FAMILY,
        WATERMARK_FAMILY,
        "(?s-u)^.{8}$",
    );
    (classify, filter)
}

/// Classifier + filter for the authenticated families (immutable / keyless).
/// The 1-byte namespace tag in the payload distinguishes the two within the
/// same family prefixes, so `auth_classify_and_filter(namespace)` must be
/// called separately per variant.
pub(crate) fn authenticated_classify_and_filter(
    namespace: crate::auth::AuthenticatedBackendNamespace,
) -> (Classify, StreamFilter) {
    use crate::auth::{
        auth_payload_regex_for_namespace, decode_auth_operation_location,
        decode_auth_presence_location, decode_auth_watermark_location,
        AUTH_FAMILY_RESERVED_BITS, AUTH_OP_FAMILY_PREFIX, AUTH_PRESENCE_FAMILY_PREFIX,
        AUTH_WATERMARK_FAMILY_PREFIX,
    };
    use exoware_sdk_rs::keys::{Key as StoreKey, KeyCodec};

    let op_codec = KeyCodec::new(AUTH_FAMILY_RESERVED_BITS, AUTH_OP_FAMILY_PREFIX);
    let presence_codec = KeyCodec::new(AUTH_FAMILY_RESERVED_BITS, AUTH_PRESENCE_FAMILY_PREFIX);
    let watermark_codec = KeyCodec::new(AUTH_FAMILY_RESERVED_BITS, AUTH_WATERMARK_FAMILY_PREFIX);

    let classify: Classify = Arc::new(move |key: &StoreKey, _value: &[u8]| {
        if op_codec.matches(key) {
            return decode_auth_operation_location(namespace, key)
                .ok()
                .map(|l| (Family::Op, l));
        }
        if presence_codec.matches(key) {
            return decode_auth_presence_location(namespace, key)
                .ok()
                .map(|l| (Family::Presence, l));
        }
        if watermark_codec.matches(key) {
            return decode_auth_watermark_location(namespace, key)
                .ok()
                .map(|l| (Family::Watermark, l));
        }
        None
    });

    let payload_regex = auth_payload_regex_for_namespace(namespace);
    let filter = build_filter(
        AUTH_FAMILY_RESERVED_BITS,
        AUTH_OP_FAMILY_PREFIX,
        AUTH_PRESENCE_FAMILY_PREFIX,
        AUTH_WATERMARK_FAMILY_PREFIX,
        &payload_regex,
    );
    (classify, filter)
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
    // Intentionally storing raw encoded op bytes is not necessary — the variant's
    // `operation_range_proof` re-reads ops from the store. We only need the batch
    // boundary (start/latest locations) to make the call.
    _count: u32,
}

struct ClosedBatch {
    start: Location,
    latest: Location,
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
                // Find or open an in-progress batch whose next_expected == location.
                let key = self
                    .in_progress
                    .iter()
                    .find_map(|(start, b)| (b.next_expected == location).then_some(*start));
                match key {
                    Some(start) => {
                        let b = self.in_progress.get_mut(&start).unwrap();
                        b.next_expected += 1;
                        b._count += 1;
                    }
                    None => {
                        self.in_progress.insert(
                            location,
                            InProgressBatch {
                                start: location,
                                next_expected: location + 1,
                                _count: 1,
                            },
                        );
                    }
                }
            }
            Family::Presence => {
                // `location` is the batch's `latest_location` (inclusive max).
                // Close the in-progress batch whose next_expected == latest+1.
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
                        },
                    );
                }
            }
            Family::Watermark => {
                match self.watermark {
                    Some(w) if w >= location => {}
                    _ => self.watermark = Some(location),
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
            let (_, batch) = self.pending.pop_first().unwrap();
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
                let watermark = this.acc.watermark.expect("ready implies watermark set");
                let count = u32::try_from(*(batch.latest - batch.start) + 1)
                    .expect("batch length fits u32");
                let fut = (this.build_proof)(watermark, batch.start, count);
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
