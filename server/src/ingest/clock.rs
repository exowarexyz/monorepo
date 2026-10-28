use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

use connectrpc::ConnectError;
use futures::future::{BoxFuture, Either};

/// Source of time for Put deadlines and timings.
///
/// The default reads Tokio's clock. A backend can substitute another clock, such
/// as a deterministic runtime's simulated one, so Put timeouts follow that clock.
///
/// `now` and `sleep_until` must share one timeline. A sleep until `t` finishes
/// once `now()` reaches `t`, and finishes promptly if `t` has already passed.
/// Deadlines are also checked by comparing `now()` with them, so `now` should not
/// move backward. A step back delays every pending timeout by the same amount.
/// Dropping a `sleep_until` future cancels it.
///
/// Only Put request handling reads this clock. Connection deadlines in
/// [`transport`](super::transport) stay on Tokio. The default
/// [`BlockingDecodeExecutor`](super::BlockingDecodeExecutor) also needs a Tokio
/// runtime, so a backend that runs without one supplies its own
/// [`DecodeExecutor`](super::DecodeExecutor).
pub trait PutClock: Send + Sync + 'static {
    fn now(&self) -> SystemTime;

    fn sleep_until(&self, deadline: SystemTime) -> BoxFuture<'static, ()>;

    fn elapsed(&self, since: SystemTime) -> Duration {
        self.now().duration_since(since).unwrap_or_default()
    }
}

/// Tokio's monotonic clock, reported as wall time measured from construction.
///
/// Reading Tokio rather than the system clock keeps deadlines immune to wall
/// clock steps and lets tests that pause Tokio time drive Put timeouts. The
/// reported times drift from the system clock over time, so compare them only
/// with times from the same clock.
#[derive(Clone, Copy, Debug)]
pub struct TokioClock {
    system: SystemTime,
    tokio: tokio::time::Instant,
}

impl TokioClock {
    pub fn new() -> Self {
        Self {
            system: SystemTime::now(),
            tokio: tokio::time::Instant::now(),
        }
    }

    fn to_system(self, instant: tokio::time::Instant) -> SystemTime {
        match instant.checked_duration_since(self.tokio) {
            Some(after) => self.system + after,
            None => self.system - self.tokio.duration_since(instant),
        }
    }

    fn to_tokio(self, time: SystemTime) -> tokio::time::Instant {
        match time.duration_since(self.system) {
            Ok(after) => self.tokio + after,
            Err(error) => self
                .tokio
                .checked_sub(error.duration())
                .unwrap_or(self.tokio),
        }
    }
}

impl Default for TokioClock {
    fn default() -> Self {
        Self::new()
    }
}

impl PutClock for TokioClock {
    fn now(&self) -> SystemTime {
        self.to_system(tokio::time::Instant::now())
    }

    fn sleep_until(&self, deadline: SystemTime) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep_until(self.to_tokio(deadline)))
    }
}

/// The error for a Put that ran past its request deadline.
pub(crate) fn deadline_exceeded() -> ConnectError {
    ConnectError::deadline_exceeded("ingest deadline exceeded")
}

/// An absolute Put deadline and the clock that measures it.
#[derive(Clone)]
pub struct PutDeadline {
    clock: Arc<dyn PutClock>,
    at: SystemTime,
}

impl PutDeadline {
    pub fn new(clock: Arc<dyn PutClock>, at: SystemTime) -> Self {
        Self { clock, at }
    }

    pub fn after(clock: Arc<dyn PutClock>, timeout: Duration) -> Self {
        let at = clock.now() + timeout;
        Self { clock, at }
    }

    pub fn at(&self) -> SystemTime {
        self.at
    }

    pub fn clock(&self) -> &dyn PutClock {
        &*self.clock
    }

    pub fn remaining(&self) -> Duration {
        self.at.duration_since(self.clock.now()).unwrap_or_default()
    }

    pub fn expired(&self) -> bool {
        self.clock.now() >= self.at
    }

    /// Polls `future` until it finishes or the deadline passes. Like
    /// `tokio::time::timeout_at`, the future is polled before the deadline.
    pub(crate) async fn timeout<F: Future>(&self, future: F) -> Result<F::Output, ConnectError> {
        let expiry = Expiry::new(self.clock(), self.at);
        match futures::future::select(std::pin::pin!(future), expiry).await {
            Either::Left((output, _)) => Ok(output),
            Either::Right(((), _)) => Err(deadline_exceeded()),
        }
    }
}

impl fmt::Debug for PutDeadline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PutDeadline")
            .field("at", &self.at)
            .finish_non_exhaustive()
    }
}

// Callers that run on Tokio can keep passing Tokio instants.
impl From<tokio::time::Instant> for PutDeadline {
    fn from(instant: tokio::time::Instant) -> Self {
        let clock = TokioClock::new();
        Self::new(Arc::new(clock), clock.to_system(instant))
    }
}

/// Resolves once `clock` reaches `at`.
///
/// Each poll reads the clock before touching the timer. A Tokio timer polled
/// after its task spent Tokio's cooperative budget reports Pending even past its
/// deadline, and work that keeps finding ready channels can spend that budget on
/// every poll. The timer is created on the first poll that has to wait, so work
/// that finishes right away never allocates one.
pub(crate) struct Expiry<'a> {
    clock: &'a dyn PutClock,
    at: SystemTime,
    sleep: Option<BoxFuture<'static, ()>>,
}

impl<'a> Expiry<'a> {
    pub(crate) fn new(clock: &'a dyn PutClock, at: SystemTime) -> Self {
        Self {
            clock,
            at,
            sleep: None,
        }
    }
}

impl Future for Expiry<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let Self { clock, at, sleep } = self.get_mut();
        if clock.now() >= *at {
            return Poll::Ready(());
        }
        sleep
            .get_or_insert_with(|| clock.sleep_until(*at))
            .as_mut()
            .poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deadline_fires_after_the_future_spends_the_coop_budget() {
        let deadline = PutDeadline::after(Arc::new(TokioClock::new()), Duration::from_millis(10));
        // Every poll spends Tokio's cooperative budget, which makes a Tokio timer
        // polled afterwards return Pending.
        let busy = async {
            loop {
                tokio::task::consume_budget().await;
            }
        };
        let error = tokio::time::timeout(Duration::from_secs(1), deadline.timeout(busy))
            .await
            .expect("deadline did not fire")
            .expect_err("the busy work never finishes");

        assert_eq!(error.code, connectrpc::ErrorCode::DeadlineExceeded);
    }
}
