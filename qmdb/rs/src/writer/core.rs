//! Shared pipeline machinery for single-writer helpers.
//!
//! Every variant writer tracks the same thing: Merkle peaks, the next Location,
//! a last-published watermark, and a per-dispatched-batch queue so each new
//! PUT can ride a watermark at the latest **safe** location — the highest
//! `latest_location` whose entire predecessor prefix has ACKd.
//!
//! Pipelining rule (same for all four writers):
//!
//! - Pipeline empty at dispatch → include watermark at **this batch's own
//!   latest_location**. That is safe because no concurrent PUT precedes us.
//! - Pipeline non-empty at dispatch → include watermark at the
//!   **latest-contiguous-acked location** (`latest_contiguous_acked`), i.e.
//!   the last location for which every preceding batch has already returned
//!   an ACK. That is strictly behind our own `latest_location` but strictly
//!   ahead of (or equal to) `latest_published`.
//! - Nothing in the contiguous-acked prefix is new → omit the watermark row.
//!
//! Under sustained saturation this keeps the published watermark lagging the
//! dispatch frontier by ~pipeline depth — not unbounded. `flush()` is only
//! needed for the tail after the last dispatch.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use commonware_storage::merkle::{Family, Location, Position};
use tokio::sync::{Mutex, Notify};

use crate::error::QmdbError;
use crate::{PublishedCheckpoint, WriterState};

/// Merkle/pipeline state held in memory by a single-writer helper.
#[derive(Debug)]
pub(crate) struct Cache<D: Digest, F: Family> {
    pub peaks: Vec<(Position<F>, u32, D)>,
    pub ops_size: Position<F>,
    pub next_location: Location<F>,
    /// Highest watermark location already included in some prepared or
    /// committed PUT by this writer instance. This suppresses duplicate
    /// watermark rows while batches are still in flight.
    pub latest_published: Option<Location<F>>,
    /// Highest watermark location definitely committed by an ACKed PUT (or a
    /// successful `flush()` watermark PUT). Recovery helpers must report this
    /// value, not the speculative `latest_published`.
    pub latest_committed_published: Option<PublishedCheckpoint<F>>,
    pub latest_dispatched: Option<Location<F>>,
    /// Dispatched-but-not-yet-ACKd batches, in dispatch order. Per-batch
    /// `acked` lets us handle out-of-order ACKs correctly: we only advance
    /// `latest_contiguous_acked` when the FRONT of the queue has ACKd (and
    /// then keep popping while the new front is also ACKd).
    pub pending: VecDeque<PendingBatch<F>>,
    /// Highest `latest_location` of a batch in the contiguous-acked prefix
    /// from the start. Monotonic — never moves backward.
    pub latest_contiguous_acked: Option<Location<F>>,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingBatch<F: Family> {
    pub id: u64,
    pub latest: Location<F>,
    pub watermark_at: Option<Location<F>>,
    pub acked: bool,
}

#[derive(Debug)]
pub(crate) enum State<D: Digest, F: Family> {
    /// Transient sentinel used while moving a poisoned cache out of the enum.
    Uninit,
    Ready(Cache<D, F>),
    Poisoned {
        msg: String,
        cache: Cache<D, F>,
    },
}

pub(crate) struct WriterCore<D: Digest, F: Family, S: Strategy> {
    state: Mutex<State<D, F>>,
    /// Serializes live frontier builds so each starts from its predecessor's
    /// peaks. A cancelled CPU job may finish later but cannot mutate state.
    build_gate: Mutex<()>,
    strategy: S,
    /// Monotonic counter of `advance` calls — also the next dispatch_id.
    dispatched: AtomicU64,
    /// Monotonic counter of `ack_success` + `ack_failure` calls. Used only
    /// for drain detection (`await_drain`); watermark logic uses the
    /// per-batch `pending` queue.
    acked: AtomicU64,
    ack_notify: Notify,
}

/// Snapshot of cache state handed to the variant-specific build closure inside
/// [`WriterCore::prepare`]. `peaks` is cloned from the live cache so the
/// closure can build the next Merkle frontier while the cache keeps its last
/// committed snapshot until the build result is accepted.
pub(crate) struct BuildContext<D: Digest, F: Family> {
    pub peaks: Vec<(Position<F>, u32, D)>,
    pub ops_size: Position<F>,
    pub latest_location: Location<F>,
    /// Location to emit the watermark row at for this batch's PUT, or `None`
    /// if no safe location is available.
    pub watermark_at: Option<Location<F>>,
}

/// What the build closure returns: updated Merkle state plus variant-specific
/// output (the row list the writer will PUT).
pub(crate) struct BuildResult<D: Digest, F: Family, R> {
    pub new_peaks: Vec<(Position<F>, u32, D)>,
    pub new_ops_size: Position<F>,
    pub output: R,
}

/// What [`WriterCore::prepare`] returns: the variant's build output plus the
/// dispatch metadata the writer needs to dispatch + ACK the PUT.
pub(crate) struct PreparedDispatch<F: Family, R> {
    pub output: R,
    pub dispatch_id: u64,
    pub watermark_at: Option<Location<F>>,
    pub latest_location: Location<F>,
}

fn newest_checkpoint<F: Family>(
    current: Option<PublishedCheckpoint<F>>,
    candidate: PublishedCheckpoint<F>,
) -> PublishedCheckpoint<F> {
    match current {
        Some(current)
            if current.location > candidate.location
                || (current.location == candidate.location
                    && current.sequence_number >= candidate.sequence_number) =>
        {
            current
        }
        _ => candidate,
    }
}

impl<D: Digest, F: Family, S: Strategy> WriterCore<D, F, S> {
    pub(crate) fn from_cache(cache: Cache<D, F>, strategy: S) -> Self {
        Self {
            state: Mutex::new(State::Ready(cache)),
            build_gate: Mutex::new(()),
            strategy,
            dispatched: AtomicU64::new(0),
            acked: AtomicU64::new(0),
            ack_notify: Notify::new(),
        }
    }

    /// Serialize frontier builds without holding the state mutex during CPU
    /// work. State changes only after a successful build, so cancellation or
    /// poisoning leaves the previous frontier intact.
    pub(crate) async fn prepare<R>(
        &self,
        ops_len: u64,
        build: impl FnOnce(BuildContext<D, F>, S) -> Result<BuildResult<D, F, R>, QmdbError>
            + Send
            + 'static,
    ) -> Result<PreparedDispatch<F, R>, QmdbError>
    where
        R: Send + 'static,
    {
        if ops_len == 0 {
            return Err(QmdbError::EmptyBatch);
        }

        let _build_slot = self.build_gate.lock().await;

        let ctx = {
            let mut state = self.state.lock().await;
            let cache = match &mut *state {
                State::Ready(c) => c,
                State::Uninit => unreachable!("writer core is always constructed with state"),
                State::Poisoned { msg, .. } => return Err(QmdbError::WriterPoisoned(msg.clone())),
            };
            let latest_location = cache
                .next_location
                .checked_add(ops_len - 1)
                .ok_or_else(|| QmdbError::CorruptData("next_location overflow".to_string()))?;

            // Safe watermark:
            // - Pipeline empty: our own latest_location (we're the only in-flight PUT).
            // - Pipeline non-empty: latest_contiguous_acked (last fully-acked prefix location).
            // - Don't re-publish what's already out.
            let candidate = if cache.pending.is_empty() {
                Some(latest_location)
            } else {
                cache.latest_contiguous_acked
            };
            let watermark_at = candidate.filter(|c| cache.latest_published.is_none_or(|p| *c > p));

            BuildContext {
                peaks: cache.peaks.clone(),
                ops_size: cache.ops_size,
                latest_location,
                watermark_at,
            }
        };
        let latest_location = ctx.latest_location;
        let watermark_at = ctx.watermark_at;

        let result = self
            .strategy
            .spawn(move |strategy| build(ctx, strategy))
            .await?;

        let mut state = self.state.lock().await;
        let cache = match &mut *state {
            State::Ready(c) => c,
            State::Uninit => unreachable!("writer core is always constructed with state"),
            State::Poisoned { msg, .. } => return Err(QmdbError::WriterPoisoned(msg.clone())),
        };
        let dispatch_id = self.dispatched.fetch_add(1, Ordering::SeqCst);
        cache.peaks = result.new_peaks;
        cache.ops_size = result.new_ops_size;
        cache.next_location = latest_location + 1;
        cache.latest_dispatched = Some(latest_location);

        // Flush can advance the watermark while the build runs.
        if let Some(wm) = watermark_at {
            if cache.latest_published.is_none_or(|p| wm > p) {
                cache.latest_published = Some(wm);
            }
        }
        cache.pending.push_back(PendingBatch {
            id: dispatch_id,
            latest: latest_location,
            watermark_at,
            acked: false,
        });

        Ok(PreparedDispatch {
            output: result.output,
            dispatch_id,
            watermark_at,
            latest_location,
        })
    }

    /// Record a PUT success for the batch with this `dispatch_id`. Marks it
    /// ACKd in `pending`, then advances `latest_contiguous_acked` by popping
    /// any contiguous-acked prefix off the front.
    pub(crate) async fn ack_success(&self, dispatch_id: u64, sequence_number: u64) {
        let mut matched = false;
        {
            let mut state = self.state.lock().await;
            let cache = match &mut *state {
                State::Ready(c) => c,
                State::Poisoned { cache, .. } => cache,
                State::Uninit => unreachable!("writer core is never externally uninitialized"),
            };
            match cache.pending.iter_mut().find(|p| p.id == dispatch_id) {
                Some(p) => {
                    p.acked = true;
                    if let Some(wm) = p.watermark_at {
                        let checkpoint = PublishedCheckpoint {
                            location: wm,
                            sequence_number,
                        };
                        cache.latest_committed_published = Some(newest_checkpoint(
                            cache.latest_committed_published,
                            checkpoint,
                        ));
                    }
                    matched = true;
                }
                None => {
                    debug_assert!(false, "ack_success for unknown dispatch_id {dispatch_id}");
                }
            }
            while cache.pending.front().is_some_and(|p| p.acked) {
                let popped = cache.pending.pop_front().expect("front exists");
                cache.latest_contiguous_acked = Some(popped.latest);
            }
        }
        if !matched {
            return;
        }
        self.acked.fetch_add(1, Ordering::SeqCst);
        self.ack_notify.notify_waiters();
    }

    /// Record a PUT failure. Poisons the writer — the caller must construct a
    /// fresh writer from caller-owned committed frontier state before
    /// resuming. (Rolling back cleanly with other batches in flight is
    /// ambiguous; resuming from explicit caller state is always correct.)
    pub(crate) async fn ack_failure(&self, msg: String) {
        {
            let mut state = self.state.lock().await;
            let replacement = match std::mem::replace(&mut *state, State::Uninit) {
                State::Ready(cache) => State::Poisoned { msg, cache },
                State::Poisoned {
                    msg: existing,
                    cache,
                } => State::Poisoned {
                    msg: existing,
                    cache,
                },
                State::Uninit => State::Uninit,
            };
            *state = replacement;
        }
        self.acked.fetch_add(1, Ordering::SeqCst);
        self.ack_notify.notify_waiters();
    }

    /// Wait until every dispatched batch has ACKd (successfully or not).
    ///
    /// Register the `Notified` future BEFORE the counter load: `Notify` does
    /// not buffer wakes, so a naive `if !done { notified.await }` races
    /// against ACKs firing between the load and the await.
    pub(crate) async fn await_drain(&self) {
        loop {
            let notified = self.ack_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let d = self.dispatched.load(Ordering::SeqCst);
            let a = self.acked.load(Ordering::SeqCst);
            if a >= d {
                return;
            }
            notified.await;
        }
    }

    /// If the latest contiguous ACKed batch's `latest_location` is ahead of the
    /// currently published watermark, return that location so the caller can
    /// issue a catch-up watermark PUT.
    pub(crate) async fn pending_watermark(&self) -> Result<Option<Location<F>>, QmdbError> {
        let state = self.state.lock().await;
        match &*state {
            State::Ready(c) => Ok(match c.latest_contiguous_acked {
                Some(d) if c.latest_published.is_some_and(|p| p >= d) => None,
                Some(d) => Some(d),
                _ => None,
            }),
            State::Uninit => unreachable!("writer core is always constructed with state"),
            State::Poisoned { msg, .. } => Err(QmdbError::WriterPoisoned(msg.clone())),
        }
    }

    /// Return the watermark that can be published by a Store batch containing
    /// `uploads`. This treats the provided dispatch IDs as committed
    /// atomically with the watermark row, but still stops at the first pending
    /// prefix hole not covered by those uploads.
    pub(crate) async fn pending_watermark_for_uploads(
        &self,
        uploads: &[(u64, Location<F>)],
    ) -> Result<Option<Location<F>>, QmdbError> {
        let state = self.state.lock().await;
        let cache = match &*state {
            State::Ready(c) => c,
            State::Uninit => unreachable!("writer core is always constructed with state"),
            State::Poisoned { msg, .. } => return Err(QmdbError::WriterPoisoned(msg.clone())),
        };
        let mut candidate = cache.latest_contiguous_acked;
        for pending in &cache.pending {
            if pending.acked
                || uploads.iter().any(|&(dispatch_id, latest)| {
                    dispatch_id == pending.id && latest == pending.latest
                })
            {
                candidate = Some(pending.latest);
                continue;
            }
            break;
        }
        Ok(match candidate {
            Some(d) if cache.latest_published.is_some_and(|p| p >= d) => None,
            Some(d) => Some(d),
            _ => None,
        })
    }

    /// Mark a catch-up watermark (emitted by `flush()`) as published.
    pub(crate) async fn mark_watermark_published(
        &self,
        location: Location<F>,
        sequence_number: u64,
    ) {
        let mut state = self.state.lock().await;
        if let State::Ready(c) = &mut *state {
            if c.latest_published.is_none_or(|current| location > current) {
                c.latest_published = Some(location);
            }
            let checkpoint = PublishedCheckpoint {
                location,
                sequence_number,
            };
            c.latest_committed_published =
                Some(newest_checkpoint(c.latest_committed_published, checkpoint));
        }
    }

    /// Snapshot of the latest published watermark from local state.
    pub(crate) async fn latest_published(&self) -> Option<Location<F>> {
        self.latest_published_checkpoint()
            .await
            .map(|checkpoint| checkpoint.location)
    }

    /// Snapshot of the latest published checkpoint from local state.
    pub(crate) async fn latest_published_checkpoint(&self) -> Option<PublishedCheckpoint<F>> {
        match &*self.state.lock().await {
            State::Ready(c) => c.latest_committed_published,
            State::Poisoned { cache, .. } => cache.latest_committed_published,
            _ => None,
        }
    }
}

impl<D: Digest, F: Family> Cache<D, F> {
    pub(crate) fn from_writer_state(state: WriterState<D, F>) -> Self {
        let latest_committed = state.latest_committed_location();
        let latest_committed_published = latest_committed.map(|location| PublishedCheckpoint {
            location,
            sequence_number: 0,
        });
        Self {
            peaks: state.peaks,
            ops_size: state.ops_size,
            next_location: state.next_location,
            latest_published: latest_committed,
            latest_committed_published,
            latest_dispatched: None,
            pending: VecDeque::new(),
            latest_contiguous_acked: latest_committed,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    use super::*;
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_parallel::{Rayon, Sequential};
    use commonware_storage::merkle::mmr;

    fn fresh_core() -> WriterCore<Sha256Digest, mmr::Family, Sequential> {
        WriterCore::from_cache(
            Cache {
                peaks: Vec::new(),
                ops_size: Position::new(0),
                next_location: Location::new(0),
                latest_published: None,
                latest_committed_published: None,
                latest_dispatched: None,
                pending: VecDeque::new(),
                latest_contiguous_acked: None,
            },
            Sequential,
        )
    }

    // `await_drain` must complete once `acked >= dispatched`, even when the
    // ACK bump and its wake fire after the counter is first read but before
    // the waiter has been registered. The implementation uses
    // `tokio::pin!(notified); notified.as_mut().enable()` BEFORE the load so
    // the intervening wake is captured. This test drives exactly that
    // interleaving: bump counters + notify BEFORE polling, so the first
    // poll inside `await_drain` must still return Ready.
    #[tokio::test]
    async fn await_drain_completes_even_with_pre_poll_ack() {
        let core = fresh_core();
        core.dispatched.fetch_add(1, Ordering::SeqCst);
        // ACK lands before any poll of the drain future.
        core.acked.fetch_add(1, Ordering::SeqCst);
        core.ack_notify.notify_waiters();

        tokio::time::timeout(std::time::Duration::from_millis(100), core.await_drain())
            .await
            .expect("await_drain must complete when acked >= dispatched");
    }

    fn loc(n: u64) -> Location<mmr::Family> {
        Location::new(n)
    }

    fn ready_cache(
        next_location: Location<mmr::Family>,
        latest_published: Option<Location<mmr::Family>>,
    ) -> Cache<Sha256Digest, mmr::Family> {
        Cache {
            peaks: Vec::new(),
            ops_size: Position::new(0),
            next_location,
            latest_published,
            latest_committed_published: latest_published.map(|location| PublishedCheckpoint {
                location,
                sequence_number: 0,
            }),
            latest_dispatched: latest_published,
            pending: VecDeque::new(),
            latest_contiguous_acked: latest_published,
        }
    }

    fn passthrough_build(
        ctx: BuildContext<Sha256Digest, mmr::Family>,
        _strategy: Sequential,
    ) -> Result<BuildResult<Sha256Digest, mmr::Family, ()>, QmdbError> {
        Ok(BuildResult {
            new_peaks: ctx.peaks,
            new_ops_size: ctx.ops_size,
            output: (),
        })
    }

    fn rayon_core() -> WriterCore<Sha256Digest, mmr::Family, Rayon> {
        let strategy =
            Rayon::new(NonZeroUsize::new(2).expect("non-zero")).expect("construct Rayon strategy");
        WriterCore::from_cache(ready_cache(loc(0), None), strategy)
    }

    fn rayon_passthrough_build(
        ctx: BuildContext<Sha256Digest, mmr::Family>,
        _strategy: Rayon,
    ) -> Result<BuildResult<Sha256Digest, mmr::Family, ()>, QmdbError> {
        Ok(BuildResult {
            new_peaks: ctx.peaks,
            new_ops_size: ctx.ops_size,
            output: (),
        })
    }

    #[tokio::test]
    async fn restored_writer_state_reports_committed_watermark_immediately() {
        let core = WriterCore::from_cache(
            Cache::from_writer_state(WriterState::<Sha256Digest, mmr::Family> {
                peaks: Vec::new(),
                ops_size: Position::new(8),
                next_location: loc(8),
            }),
            Sequential,
        );
        assert_eq!(core.latest_published().await, Some(loc(7)));
    }

    #[tokio::test]
    async fn out_of_order_acks_only_advance_the_contiguous_prefix() {
        let core = fresh_core();

        let first = core
            .prepare(1, passthrough_build)
            .await
            .expect("prepare first");
        let second = core
            .prepare(1, passthrough_build)
            .await
            .expect("prepare second");
        let third = core
            .prepare(1, passthrough_build)
            .await
            .expect("prepare third");
        assert_eq!(first.watermark_at, Some(loc(0)));
        assert_eq!(second.watermark_at, None);
        assert_eq!(third.watermark_at, None);

        // Later batches ACK first, but the prefix still has a hole at batch 0.
        core.ack_success(third.dispatch_id, 30).await;
        core.ack_success(second.dispatch_id, 20).await;
        assert_eq!(
            core.latest_published().await,
            None,
            "committed watermark must not advance past an unacked prefix hole",
        );
        assert_eq!(
            core.pending_watermark().await.expect("pending watermark"),
            None,
            "flush must not publish past an unacked prefix hole",
        );
        {
            let state = core.state.lock().await;
            let cache = match &*state {
                State::Ready(cache) => cache,
                other => panic!("unexpected writer state: {other:?}"),
            };
            assert_eq!(cache.latest_contiguous_acked, None);
            assert_eq!(cache.latest_committed_published, None);
        }

        // A new batch dispatched while the hole remains must still omit the
        // watermark row.
        let fourth = core
            .prepare(1, passthrough_build)
            .await
            .expect("prepare fourth");
        let fourth_upload = (fourth.dispatch_id, fourth.latest_location);
        assert_eq!(fourth.watermark_at, None);
        assert_eq!(
            core.pending_watermark().await.expect("pending watermark"),
            None,
            "flush must stay blocked while the prefix hole remains",
        );
        assert_eq!(
            core.pending_watermark_for_uploads(std::slice::from_ref(&fourth_upload))
                .await
                .expect("batch watermark"),
            None,
            "an atomic Store batch cannot publish through an uncovered prefix hole",
        );

        // Once the missing first batch ACKs, the contiguous frontier jumps to
        // the highest already-acked predecessor (batch 2 / location 2).
        core.ack_success(first.dispatch_id, 10).await;
        assert_eq!(
            core.pending_watermark().await.expect("pending watermark"),
            Some(loc(2)),
            "flush may publish the contiguous ACKed prefix, but not the in-flight tail",
        );
        assert_eq!(
            core.pending_watermark_for_uploads(std::slice::from_ref(&fourth_upload))
                .await
                .expect("batch watermark"),
            Some(loc(3)),
            "an atomic Store batch may publish the tail it contains",
        );
        {
            let state = core.state.lock().await;
            let cache = match &*state {
                State::Ready(cache) => cache,
                other => panic!("unexpected writer state: {other:?}"),
            };
            assert_eq!(cache.latest_contiguous_acked, Some(loc(2)));
            assert_eq!(
                cache
                    .latest_committed_published
                    .map(|checkpoint| checkpoint.location),
                Some(loc(0))
            );
            assert_eq!(
                cache
                    .latest_committed_published
                    .map(|checkpoint| checkpoint.sequence_number),
                Some(10)
            );
        }

        // With batch 3 still in flight, the next dispatch should publish the
        // contiguous prefix watermark, not its own latest location.
        let fifth = core
            .prepare(1, passthrough_build)
            .await
            .expect("prepare fifth");
        assert_eq!(fifth.watermark_at, Some(loc(2)));
    }

    #[tokio::test]
    async fn seeded_state_flush_path_only_needs_one_tail_publication() {
        let core = WriterCore::from_cache(
            Cache::from_writer_state(WriterState::<Sha256Digest, mmr::Family> {
                peaks: Vec::new(),
                ops_size: Position::new(8),
                next_location: loc(8),
            }),
            Sequential,
        );

        let first = core
            .prepare(1, passthrough_build)
            .await
            .expect("prepare first");
        let second = core
            .prepare(1, passthrough_build)
            .await
            .expect("prepare second");
        assert_eq!(first.watermark_at, Some(loc(8)));
        assert_eq!(second.watermark_at, None);

        core.ack_success(first.dispatch_id, 11).await;
        core.ack_success(second.dispatch_id, 12).await;
        core.await_drain().await;

        assert_eq!(
            core.pending_watermark().await.expect("pending watermark"),
            Some(loc(9)),
            "flush should publish exactly the trailing batch boundary",
        );

        core.mark_watermark_published(loc(9), 13).await;
        assert_eq!(core.latest_published().await, Some(loc(9)));
        assert_eq!(
            core.latest_published_checkpoint()
                .await
                .map(|checkpoint| checkpoint.sequence_number),
            Some(13)
        );
        assert_eq!(
            core.pending_watermark().await.expect("pending watermark"),
            None,
            "after publishing the tail once, a second flush should be a no-op",
        );
    }

    #[tokio::test]
    async fn stale_flush_completion_does_not_regress_published_checkpoint() {
        let core = fresh_core();
        let first = core
            .prepare(1, passthrough_build)
            .await
            .expect("prepare first");
        let second = core
            .prepare(1, passthrough_build)
            .await
            .expect("prepare second");
        let third = core
            .prepare(1, passthrough_build)
            .await
            .expect("prepare third");

        core.ack_success(first.dispatch_id, 10).await;
        core.ack_success(second.dispatch_id, 11).await;
        let stale_flush = core
            .pending_watermark()
            .await
            .expect("prepare stale flush")
            .expect("stale flush target");
        assert_eq!(stale_flush, loc(1));

        core.ack_success(third.dispatch_id, 12).await;
        let fourth = core
            .prepare(1, passthrough_build)
            .await
            .expect("prepare fourth");
        assert_eq!(fourth.watermark_at, Some(loc(3)));
        core.ack_success(fourth.dispatch_id, 13).await;

        core.mark_watermark_published(stale_flush, 14).await;
        assert_eq!(core.latest_published().await, Some(loc(3)));
        assert_eq!(
            core.latest_published_checkpoint().await,
            Some(PublishedCheckpoint {
                location: loc(3),
                sequence_number: 13,
            })
        );

        core.mark_watermark_published(loc(3), 12).await;
        assert_eq!(
            core.latest_published_checkpoint()
                .await
                .map(|checkpoint| checkpoint.sequence_number),
            Some(13)
        );

        core.mark_watermark_published(loc(3), 15).await;
        assert_eq!(
            core.latest_published_checkpoint()
                .await
                .map(|checkpoint| checkpoint.sequence_number),
            Some(15)
        );
    }

    #[tokio::test]
    async fn poisoned_writer_reports_last_committed_not_speculative_watermark() {
        let core = WriterCore::from_cache(ready_cache(loc(8), Some(loc(7))), Sequential);

        let prepared = core.prepare(1, passthrough_build).await.expect("prepare");
        assert_eq!(
            prepared.watermark_at,
            Some(loc(8)),
            "the batch still schedules an in-band watermark"
        );
        assert_eq!(
            core.latest_published().await,
            Some(loc(7)),
            "recovery helper must stay on the committed watermark while the PUT is in flight",
        );

        core.ack_failure("boom".to_string()).await;
        assert_eq!(
            core.latest_published().await,
            Some(loc(7)),
            "poisoned recovery helper must not expose the speculative watermark from the failed PUT",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_build_does_not_reserve_frontier_state() {
        let core = Arc::new(rayon_core());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();

        let build_core = core.clone();
        let build = tokio::spawn(async move {
            build_core
                .prepare(1, move |ctx, _strategy| {
                    started_tx.send(()).expect("report build start");
                    release_rx.recv().expect("release cancelled build");
                    finished_tx.send(()).expect("report build completion");
                    Ok(BuildResult {
                        new_peaks: ctx.peaks,
                        new_ops_size: ctx.ops_size,
                        output: (),
                    })
                })
                .await
        });

        started_rx.await.expect("build started");
        let watermark = tokio::time::timeout(Duration::from_secs(1), core.latest_published())
            .await
            .expect("watermark read waited for CPU work");
        assert_eq!(watermark, None);

        build.abort();
        let join_error = match build.await {
            Ok(_) => panic!("build task was not cancelled"),
            Err(error) => error,
        };
        assert!(join_error.is_cancelled());

        let prepared = tokio::time::timeout(
            Duration::from_secs(1),
            core.prepare(1, rayon_passthrough_build),
        )
        .await
        .expect("replacement prepare waited for cancelled CPU work")
        .expect("prepare replacement");
        assert_eq!(prepared.dispatch_id, 0);
        assert_eq!(prepared.latest_location, loc(0));

        release_tx.send(()).expect("release cancelled build");
        finished_rx.await.expect("cancelled CPU work finished");

        let state = core.state.lock().await;
        let cache = match &*state {
            State::Ready(cache) => cache,
            other => panic!("unexpected writer state: {other:?}"),
        };
        assert_eq!(cache.next_location, loc(1));
        assert_eq!(cache.pending.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_builds_commit_frontiers_in_prepare_order() {
        let core = Arc::new(rayon_core());
        let (first_started_tx, first_started_rx) = tokio::sync::oneshot::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();

        let first_core = core.clone();
        let first = tokio::spawn(async move {
            first_core
                .prepare(1, move |ctx, _strategy| {
                    first_started_tx.send(()).expect("report first start");
                    release_first_rx.recv().expect("release first build");
                    let latest_location = ctx.latest_location;
                    Ok(BuildResult {
                        new_peaks: ctx.peaks,
                        new_ops_size: ctx.ops_size,
                        output: latest_location,
                    })
                })
                .await
        });
        first_started_rx.await.expect("first build started");

        let (second_entered_tx, second_entered_rx) = tokio::sync::oneshot::channel();
        let (second_started_tx, mut second_started_rx) = tokio::sync::oneshot::channel();
        let second_core = core.clone();
        let second = tokio::spawn(async move {
            second_entered_tx.send(()).expect("report second prepare");
            second_core
                .prepare(1, move |ctx, _strategy| {
                    second_started_tx.send(()).expect("report second start");
                    let latest_location = ctx.latest_location;
                    Ok(BuildResult {
                        new_peaks: ctx.peaks,
                        new_ops_size: ctx.ops_size,
                        output: latest_location,
                    })
                })
                .await
        });
        second_entered_rx.await.expect("second prepare started");

        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut second_started_rx)
                .await
                .is_err(),
            "second build started from an uncommitted frontier"
        );

        release_first_tx.send(()).expect("release first build");
        tokio::time::timeout(Duration::from_secs(1), &mut second_started_rx)
            .await
            .expect("second build did not start")
            .expect("report second start");

        let first = first
            .await
            .expect("first task")
            .expect("prepare first batch");
        let second = second
            .await
            .expect("second task")
            .expect("prepare second batch");
        assert_eq!(first.dispatch_id, 0);
        assert_eq!(first.latest_location, loc(0));
        assert_eq!(first.output, loc(0));
        assert_eq!(second.dispatch_id, 1);
        assert_eq!(second.latest_location, loc(1));
        assert_eq!(second.output, loc(1));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn poisoned_writer_discards_inflight_build() {
        let core = Arc::new(rayon_core());
        let first = core
            .prepare(1, rayon_passthrough_build)
            .await
            .expect("prepare first batch");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let build_core = core.clone();
        let build = tokio::spawn(async move {
            build_core
                .prepare(1, move |ctx, _strategy| {
                    started_tx.send(()).expect("report build start");
                    release_rx.recv().expect("release build");
                    Ok(BuildResult {
                        new_peaks: ctx.peaks,
                        new_ops_size: ctx.ops_size,
                        output: (),
                    })
                })
                .await
        });

        started_rx.await.expect("build started");
        core.ack_failure("first upload failed".to_string()).await;
        release_tx.send(()).expect("release build");

        let error = match build.await.expect("build task") {
            Ok(_) => panic!("poisoned build committed"),
            Err(error) => error,
        };
        assert!(matches!(error, QmdbError::WriterPoisoned(_)));
        assert_eq!(core.dispatched.load(Ordering::SeqCst), 1);

        let state = core.state.lock().await;
        let cache = match &*state {
            State::Poisoned { cache, .. } => cache,
            other => panic!("unexpected writer state: {other:?}"),
        };
        assert_eq!(cache.next_location, loc(1));
        assert_eq!(cache.pending.len(), 1);
        assert_eq!(
            cache.pending.front().map(|pending| pending.id),
            Some(first.dispatch_id)
        );
    }
}
