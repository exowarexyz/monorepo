//! Shared pipeline machinery for single-writer helpers.
//!
//! Every variant writer tracks the same thing: MMR peaks, the next Location,
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
use commonware_storage::mmr::{Location, Position};
use tokio::sync::{Mutex, Notify};

use crate::error::QmdbError;
use crate::WriterState;

/// MMR/pipeline state held in memory by a single-writer helper.
#[derive(Debug)]
pub(crate) struct Cache<D: Digest> {
    pub peaks: Vec<(Position, u32, D)>,
    pub ops_size: Position,
    pub next_location: Location,
    /// Highest watermark location already included in some prepared or
    /// committed PUT by this writer instance. This suppresses duplicate
    /// watermark rows while batches are still in flight.
    pub latest_published: Option<Location>,
    /// Highest watermark location definitely committed by an ACKed PUT (or a
    /// successful `flush()` watermark PUT). Recovery helpers must report this
    /// value, not the speculative `latest_published`.
    pub latest_committed_published: Option<Location>,
    pub latest_dispatched: Option<Location>,
    /// Dispatched-but-not-yet-ACKd batches, in dispatch order. Per-batch
    /// `acked` lets us handle out-of-order ACKs correctly: we only advance
    /// `latest_contiguous_acked` when the FRONT of the queue has ACKd (and
    /// then keep popping while the new front is also ACKd).
    pub pending: VecDeque<PendingBatch>,
    /// Highest `latest_location` of a batch in the contiguous-acked prefix
    /// from the start. Monotonic — never moves backward.
    pub latest_contiguous_acked: Option<Location>,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingBatch {
    pub id: u64,
    pub latest: Location,
    pub watermark_at: Option<Location>,
    pub acked: bool,
}

#[derive(Debug)]
pub(crate) enum State<D: Digest> {
    /// Transient sentinel used while moving a poisoned cache out of the enum.
    Uninit,
    Ready(Cache<D>),
    Poisoned {
        msg: String,
        cache: Cache<D>,
    },
}

pub(crate) struct WriterCore<D: Digest> {
    state: Mutex<State<D>>,
    /// Monotonic counter of `advance` calls — also the next dispatch_id.
    dispatched: AtomicU64,
    /// Monotonic counter of `ack_success` + `ack_failure` calls. Used only
    /// for drain detection (`await_drain`); watermark logic uses the
    /// per-batch `pending` queue.
    acked: AtomicU64,
    ack_notify: Notify,
}

/// Snapshot of cache state handed to the variant-specific build closure
/// inside [`WriterCore::prepare`]. Ownership of `peaks` transfers so the
/// closure can feed them directly to `extend_mmr_from_peaks` without cloning.
pub(crate) struct BuildContext<D: Digest> {
    pub peaks: Vec<(Position, u32, D)>,
    pub ops_size: Position,
    pub latest_location: Location,
    /// Location to emit the watermark row at for this batch's PUT, or `None`
    /// if no safe location is available.
    pub watermark_at: Option<Location>,
}

/// What the build closure returns: updated MMR state plus variant-specific
/// output (the row list the writer will PUT).
pub(crate) struct BuildResult<D: Digest, R> {
    pub new_peaks: Vec<(Position, u32, D)>,
    pub new_ops_size: Position,
    pub output: R,
}

/// What [`WriterCore::prepare`] returns: the variant's build output plus the
/// dispatch metadata the writer needs to dispatch + ACK the PUT.
pub(crate) struct PreparedDispatch<R> {
    pub output: R,
    pub dispatch_id: u64,
    pub watermark_at: Option<Location>,
    pub latest_location: Location,
}

impl<D: Digest> WriterCore<D> {
    pub(crate) fn from_cache(cache: Cache<D>) -> Self {
        Self {
            state: Mutex::new(State::Ready(cache)),
            dispatched: AtomicU64::new(0),
            acked: AtomicU64::new(0),
            ack_notify: Notify::new(),
        }
    }

    /// Atomically reserve a batch slot, run the variant-specific `build`
    /// closure under the state mutex, and commit the resulting MMR delta to
    /// the cache — all in one locked step. This is what prevents the
    /// `dispatch_id` race: because the cache (peaks, size, next_location,
    /// pending) is updated inside the same lock that `build` runs under, no
    /// concurrent `prepare` call can observe stale pre-batch state.
    ///
    /// Build phase is therefore serialized across pipelined uploads, but the
    /// PUT dispatch itself happens AFTER `prepare` returns (i.e. outside the
    /// lock), so network round-trips still pipeline freely.
    pub(crate) async fn prepare<R>(
        &self,
        ops_len: u64,
        build: impl FnOnce(BuildContext<D>) -> Result<BuildResult<D, R>, QmdbError>,
    ) -> Result<PreparedDispatch<R>, QmdbError> {
        let mut state = self.state.lock().await;
        let cache = match &mut *state {
            State::Ready(c) => c,
            State::Uninit => unreachable!("writer core is always constructed with state"),
            State::Poisoned { msg, .. } => return Err(QmdbError::WriterPoisoned(msg.clone())),
        };
        if ops_len == 0 {
            return Err(QmdbError::EmptyBatch);
        }
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

        let ctx = BuildContext {
            peaks: cache.peaks.clone(),
            ops_size: cache.ops_size,
            latest_location,
            watermark_at,
        };
        let result = build(ctx)?;

        let dispatch_id = self.dispatched.fetch_add(1, Ordering::SeqCst);
        cache.peaks = result.new_peaks;
        cache.ops_size = result.new_ops_size;
        cache.next_location = latest_location + 1;
        cache.latest_dispatched = Some(latest_location);
        if let Some(wm) = watermark_at {
            cache.latest_published = Some(wm);
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
    pub(crate) async fn ack_success(&self, dispatch_id: u64) {
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
                        cache.latest_committed_published = Some(
                            cache
                                .latest_committed_published
                                .map_or(wm, |cur| cur.max(wm)),
                        );
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

    /// If the latest dispatched batch's `latest_location` is ahead of the
    /// currently published watermark, return that location so the caller can
    /// issue a catch-up watermark PUT.
    pub(crate) async fn pending_watermark(&self) -> Result<Option<Location>, QmdbError> {
        let state = self.state.lock().await;
        match &*state {
            State::Ready(c) => Ok(match (c.latest_committed_published, c.latest_dispatched) {
                (Some(p), Some(d)) if p >= d => None,
                (_, Some(d)) => Some(d),
                _ => None,
            }),
            State::Uninit => unreachable!("writer core is always constructed with state"),
            State::Poisoned { msg, .. } => Err(QmdbError::WriterPoisoned(msg.clone())),
        }
    }

    /// Mark a catch-up watermark (emitted by `flush()`) as published.
    pub(crate) async fn mark_watermark_published(&self, location: Location) {
        let mut state = self.state.lock().await;
        if let State::Ready(c) = &mut *state {
            c.latest_published = Some(location);
            c.latest_committed_published = Some(location);
        }
    }

    /// Snapshot of the latest published watermark from local state.
    pub(crate) async fn latest_published(&self) -> Option<Location> {
        match &*self.state.lock().await {
            State::Ready(c) => c.latest_committed_published,
            State::Poisoned { cache, .. } => cache.latest_committed_published,
            _ => None,
        }
    }
}

impl<D: Digest> Cache<D> {
    pub(crate) fn from_writer_state(state: WriterState<D>) -> Self {
        let latest_committed = state.latest_committed_location();
        Self {
            peaks: state.peaks,
            ops_size: state.ops_size,
            next_location: state.next_location,
            latest_published: latest_committed,
            latest_committed_published: latest_committed,
            latest_dispatched: None,
            pending: VecDeque::new(),
            latest_contiguous_acked: latest_committed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256::Digest as Sha256Digest;

    fn fresh_core() -> WriterCore<Sha256Digest> {
        WriterCore::from_cache(Cache {
            peaks: Vec::new(),
            ops_size: Position::new(0),
            next_location: Location::new(0),
            latest_published: None,
            latest_committed_published: None,
            latest_dispatched: None,
            pending: VecDeque::new(),
            latest_contiguous_acked: None,
        })
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

    fn loc(n: u64) -> Location {
        Location::new(n)
    }

    fn ready_cache(
        next_location: Location,
        latest_published: Option<Location>,
    ) -> Cache<Sha256Digest> {
        Cache {
            peaks: Vec::new(),
            ops_size: Position::new(0),
            next_location,
            latest_published,
            latest_committed_published: latest_published,
            latest_dispatched: latest_published,
            pending: VecDeque::new(),
            latest_contiguous_acked: latest_published,
        }
    }

    fn passthrough_build(
        ctx: BuildContext<Sha256Digest>,
    ) -> Result<BuildResult<Sha256Digest, ()>, QmdbError> {
        Ok(BuildResult {
            new_peaks: ctx.peaks,
            new_ops_size: ctx.ops_size,
            output: (),
        })
    }

    #[tokio::test]
    async fn restored_writer_state_reports_committed_watermark_immediately() {
        let core = WriterCore::from_cache(Cache::from_writer_state(WriterState::<Sha256Digest> {
            peaks: Vec::new(),
            ops_size: Position::new(8),
            next_location: loc(8),
        }));
        assert_eq!(core.latest_published().await, Some(loc(7)));
    }

    #[tokio::test]
    async fn out_of_order_acks_only_advance_the_contiguous_prefix() {
        let core = fresh_core();

        let first = core.prepare(1, passthrough_build).await.expect("prepare first");
        let second = core
            .prepare(1, passthrough_build)
            .await
            .expect("prepare second");
        let third = core.prepare(1, passthrough_build).await.expect("prepare third");
        assert_eq!(first.watermark_at, Some(loc(0)));
        assert_eq!(second.watermark_at, None);
        assert_eq!(third.watermark_at, None);

        // Later batches ACK first, but the prefix still has a hole at batch 0.
        core.ack_success(third.dispatch_id).await;
        core.ack_success(second.dispatch_id).await;
        assert_eq!(
            core.latest_published().await,
            None,
            "committed watermark must not advance past an unacked prefix hole",
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
        assert_eq!(fourth.watermark_at, None);

        // Once the missing first batch ACKs, the contiguous frontier jumps to
        // the highest already-acked predecessor (batch 2 / location 2).
        core.ack_success(first.dispatch_id).await;
        {
            let state = core.state.lock().await;
            let cache = match &*state {
                State::Ready(cache) => cache,
                other => panic!("unexpected writer state: {other:?}"),
            };
            assert_eq!(cache.latest_contiguous_acked, Some(loc(2)));
            assert_eq!(cache.latest_committed_published, Some(loc(0)));
        }

        // With batch 3 still in flight, the next dispatch should publish the
        // contiguous prefix watermark, not its own latest location.
        let fifth = core.prepare(1, passthrough_build).await.expect("prepare fifth");
        assert_eq!(fifth.watermark_at, Some(loc(2)));
    }

    #[tokio::test]
    async fn seeded_state_flush_path_only_needs_one_tail_publication() {
        let core = WriterCore::from_cache(Cache::from_writer_state(WriterState::<Sha256Digest> {
            peaks: Vec::new(),
            ops_size: Position::new(8),
            next_location: loc(8),
        }));

        let first = core.prepare(1, passthrough_build).await.expect("prepare first");
        let second = core
            .prepare(1, passthrough_build)
            .await
            .expect("prepare second");
        assert_eq!(first.watermark_at, Some(loc(8)));
        assert_eq!(second.watermark_at, None);

        core.ack_success(first.dispatch_id).await;
        core.ack_success(second.dispatch_id).await;
        core.await_drain().await;

        assert_eq!(
            core.pending_watermark().await.expect("pending watermark"),
            Some(loc(9)),
            "flush should publish exactly the trailing batch boundary",
        );

        core.mark_watermark_published(loc(9)).await;
        assert_eq!(core.latest_published().await, Some(loc(9)));
        assert_eq!(
            core.pending_watermark().await.expect("pending watermark"),
            None,
            "after publishing the tail once, a second flush should be a no-op",
        );
    }

    #[tokio::test]
    async fn poisoned_writer_reports_last_committed_not_speculative_watermark() {
        let core = WriterCore::from_cache(ready_cache(loc(8), Some(loc(7))));

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
}
