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

/// Clock used for Put deadlines and elapsed-time measurements.
///
/// `now` and `sleep_until` must use the same timeline. A sleep completes when
/// `now() >= deadline`, including when the deadline has already passed. Dropping
/// the sleep future cancels the wait.
///
/// `now` should not move backward. Use a monotonic clock in production so wall
/// clock adjustments cannot move request deadlines relative to Tokio's
/// connection deadlines.
///
/// Running without Tokio also requires a custom [`DecodeExecutor`](super::DecodeExecutor);
/// the default [`BlockingDecodeExecutor`](super::BlockingDecodeExecutor) uses
/// Tokio's blocking pool.
pub trait PutClock: Send + Sync + 'static {
    fn now(&self) -> SystemTime;

    fn sleep_until(&self, deadline: SystemTime) -> BoxFuture<'static, ()>;

    fn elapsed(&self, since: SystemTime) -> Duration {
        self.now().duration_since(since).unwrap_or_default()
    }
}

/// Tokio's monotonic clock mapped to [`SystemTime`].
///
/// Anchored to system time at construction, then advanced by Tokio time. This
/// follows paused Tokio time and ignores later wall clock adjustments. Compare
/// timestamps only with others from the same clock.
#[derive(Clone, Copy, Debug)]
pub struct TokioClock {
    system_origin: SystemTime,
    tokio_origin: tokio::time::Instant,
}

impl TokioClock {
    pub fn new() -> Self {
        Self {
            system_origin: SystemTime::now(),
            tokio_origin: tokio::time::Instant::now(),
        }
    }

    fn to_system(self, instant: tokio::time::Instant) -> SystemTime {
        match instant.checked_duration_since(self.tokio_origin) {
            Some(after) => self.system_origin + after,
            None => self.system_origin - self.tokio_origin.duration_since(instant),
        }
    }

    fn to_tokio(self, time: SystemTime) -> tokio::time::Instant {
        match time.duration_since(self.system_origin) {
            Ok(after) => self.tokio_origin + after,
            Err(error) => self
                .tokio_origin
                .checked_sub(error.duration())
                .unwrap_or(self.tokio_origin),
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

pub(crate) fn deadline_error() -> ConnectError {
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

    /// A ready result wins over an expired deadline, matching `tokio::time::timeout_at`.
    pub(crate) async fn timeout<F: Future>(&self, future: F) -> Result<F::Output, ConnectError> {
        let expiry = Expiry::new(self.clock(), self.at);
        match futures::future::select(std::pin::pin!(future), expiry).await {
            Either::Left((output, _)) => Ok(output),
            Either::Right(((), _)) => Err(deadline_error()),
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

/// Waits for a deadline, creating the timer only when needed.
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
        // Tokio timers can return Pending after the task exhausts its cooperative
        // budget, even when overdue. Check the clock so busy work cannot starve expiry.
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
pub(crate) mod testing {
    use super::*;

    use commonware_runtime::{deterministic, Clock as _};

    pub(crate) fn tokio_deadline(timeout: Duration) -> PutDeadline {
        PutDeadline::after(Arc::new(TokioClock::new()), timeout)
    }

    pub(crate) struct SimulatedClock(pub(crate) deterministic::Context);

    impl PutClock for SimulatedClock {
        fn now(&self) -> SystemTime {
            self.0.current()
        }

        fn sleep_until(&self, deadline: SystemTime) -> BoxFuture<'static, ()> {
            Box::pin(self.0.sleep_until(deadline))
        }
    }
}

#[cfg(test)]
mod tests {
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};

    use super::testing::{tokio_deadline, SimulatedClock};
    use super::*;

    async fn assert_contract(clock: &dyn PutClock) {
        // Include a deadline from before the clock was created.
        let started = clock.now();
        clock.sleep_until(started - Duration::from_secs(1)).await;
        assert!(clock.elapsed(started) < Duration::from_millis(100));

        let deadline = clock.now() + Duration::from_millis(50);
        clock.sleep_until(deadline).await;
        let woke = clock.now();
        assert!(woke >= deadline);
        assert!(clock.now() >= woke);

        // Future timestamps have zero elapsed time.
        assert_eq!(clock.elapsed(woke + Duration::from_secs(1)), Duration::ZERO);
    }

    #[tokio::test]
    async fn tokio_clock_meets_the_contract() {
        assert_contract(&TokioClock::new()).await;
    }

    #[tokio::test(start_paused = true)]
    async fn tokio_clock_meets_the_contract_on_paused_time() {
        assert_contract(&TokioClock::new()).await;
    }

    #[test]
    fn simulated_clock_meets_the_contract() {
        deterministic::Runner::default().start(|context| async move {
            assert_contract(&SimulatedClock(context.child("clock"))).await;
        });
    }

    #[tokio::test(start_paused = true)]
    async fn tokio_clock_follows_paused_time() {
        let clock = TokioClock::new();
        let started = clock.now();
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(clock.elapsed(started), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn deadline_fires_with_exhausted_coop_budget() {
        let deadline = tokio_deadline(Duration::from_millis(10));
        // Leave no budget for the timer on any poll.
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
