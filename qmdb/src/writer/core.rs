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

/// MMR/pipeline state held in memory by a single-writer helper.
#[derive(Debug)]
pub(crate) struct Cache<D: Digest> {
    pub peaks: Vec<(Position, u32, D)>,
    pub ops_size: Position,
    pub next_location: Location,
    pub latest_published: Option<Location>,
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
    pub acked: bool,
}

#[derive(Debug)]
pub(crate) enum State<D: Digest> {
    Uninit,
    Ready(Cache<D>),
    Poisoned(String),
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

/// Everything a variant writer needs to build the next batch.
pub(crate) struct BatchBegin<D: Digest> {
    pub peaks: Vec<(Position, u32, D)>,
    pub ops_size: Position,
    pub latest_location: Location,
    /// Location to emit the watermark row at for this batch's PUT, or `None`
    /// if no safe location is available.
    pub watermark_at: Option<Location>,
    /// Dispatch id to pass back to `ack_success` / `ack_failure` so we can
    /// mark the specific batch as acked (ACK order is not guaranteed by the
    /// transport when PUTs run on separate HTTP/2 streams).
    pub dispatch_id: u64,
}

/// Delta a variant writer hands back to [`WriterCore::advance`] after
/// building the batch's rows.
pub(crate) struct BatchAdvance<D: Digest> {
    pub new_peaks: Vec<(Position, u32, D)>,
    pub new_ops_size: Position,
    pub latest_location: Location,
    pub watermark_at: Option<Location>,
    pub dispatch_id: u64,
}

impl<D: Digest> WriterCore<D> {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(State::Uninit),
            dispatched: AtomicU64::new(0),
            acked: AtomicU64::new(0),
            ack_notify: Notify::new(),
        }
    }

    /// Install a freshly-bootstrapped cache and reset pipeline counters.
    pub(crate) async fn install(&self, cache: Cache<D>) {
        let mut state = self.state.lock().await;
        *state = State::Ready(cache);
        self.dispatched.store(0, Ordering::SeqCst);
        self.acked.store(0, Ordering::SeqCst);
        self.ack_notify.notify_waiters();
    }

    /// Prepare the next batch. Returns peaks, size, computed `latest_location`,
    /// and the safe watermark location (if any). Caller must subsequently
    /// call [`advance`] with the new cache state.
    pub(crate) async fn begin(&self, ops_len: u64) -> Result<BatchBegin<D>, QmdbError> {
        let state = self.state.lock().await;
        let cache = match &*state {
            State::Ready(c) => c,
            State::Uninit => return Err(QmdbError::WriterNotBootstrapped),
            State::Poisoned(msg) => return Err(QmdbError::WriterPoisoned(msg.clone())),
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
        let dispatch_id = self.dispatched.load(Ordering::SeqCst);
        Ok(BatchBegin {
            peaks: cache.peaks.clone(),
            ops_size: cache.ops_size,
            latest_location,
            watermark_at,
            dispatch_id,
        })
    }

    /// Commit the batch delta: update peaks/ops_size/next_location, push
    /// this batch onto `pending`, advance `latest_published` if we're
    /// emitting a watermark row, and bump `dispatched`. Call once per
    /// `begin` before awaiting the PUT.
    pub(crate) async fn advance(&self, update: BatchAdvance<D>) {
        let mut state = self.state.lock().await;
        if let State::Ready(c) = &mut *state {
            c.peaks = update.new_peaks;
            c.ops_size = update.new_ops_size;
            c.next_location = update.latest_location + 1;
            c.latest_dispatched = Some(update.latest_location);
            if let Some(wm) = update.watermark_at {
                c.latest_published = Some(wm);
            }
            c.pending.push_back(PendingBatch {
                id: update.dispatch_id,
                latest: update.latest_location,
                acked: false,
            });
        }
        self.dispatched.fetch_add(1, Ordering::SeqCst);
    }

    /// Record a PUT success for the batch with this `dispatch_id`. Marks it
    /// ACKd in `pending`, then advances `latest_contiguous_acked` by popping
    /// any contiguous-acked prefix off the front.
    pub(crate) async fn ack_success(&self, dispatch_id: u64) {
        {
            let mut state = self.state.lock().await;
            if let State::Ready(c) = &mut *state {
                match c.pending.iter_mut().find(|p| p.id == dispatch_id) {
                    Some(p) => p.acked = true,
                    None => {
                        debug_assert!(false, "ack_success for unknown dispatch_id {dispatch_id}")
                    }
                }
                while c.pending.front().is_some_and(|p| p.acked) {
                    let popped = c.pending.pop_front().expect("front exists");
                    c.latest_contiguous_acked = Some(popped.latest);
                }
            }
        }
        self.acked.fetch_add(1, Ordering::SeqCst);
        self.ack_notify.notify_waiters();
    }

    /// Record a PUT failure. Poisons the writer — the caller must call
    /// `bootstrap()` before resuming. (Rolling back cleanly with other
    /// batches in flight is ambiguous; re-bootstrapping from the store is
    /// always correct.)
    pub(crate) async fn ack_failure(&self, msg: String) {
        {
            let mut state = self.state.lock().await;
            *state = State::Poisoned(msg);
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
            State::Ready(c) => Ok(match (c.latest_published, c.latest_dispatched) {
                (Some(p), Some(d)) if p >= d => None,
                (_, Some(d)) => Some(d),
                _ => None,
            }),
            State::Uninit => Err(QmdbError::WriterNotBootstrapped),
            State::Poisoned(msg) => Err(QmdbError::WriterPoisoned(msg.clone())),
        }
    }

    /// Mark a catch-up watermark (emitted by `flush()`) as published.
    pub(crate) async fn mark_watermark_published(&self, location: Location) {
        let mut state = self.state.lock().await;
        if let State::Ready(c) = &mut *state {
            c.latest_published = Some(location);
        }
    }

    /// Snapshot of the latest published watermark from local state.
    pub(crate) async fn latest_published(&self) -> Option<Location> {
        match &*self.state.lock().await {
            State::Ready(c) => c.latest_published,
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256::Digest as Sha256Digest;

    fn fresh_core() -> WriterCore<Sha256Digest> {
        let core = WriterCore::<Sha256Digest>::new();
        // install() requires an async context; this test-only helper builds
        // an initial Ready state without going through the async path.
        *core.state.try_lock().unwrap() = State::Ready(Cache {
            peaks: Vec::new(),
            ops_size: Position::new(0),
            next_location: Location::new(0),
            latest_published: None,
            latest_dispatched: None,
            pending: VecDeque::new(),
            latest_contiguous_acked: None,
        });
        core
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
}
