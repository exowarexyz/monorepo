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
/// Prefer a monotonic clock in production. The connection layer measures the
/// same request timeout on Tokio's monotonic clock, so a clock that jumps, such
/// as the system clock after an NTP step, makes the two deadlines disagree.
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

    /// Polls `future` until it finishes or the deadline passes. Like
    /// `tokio::time::timeout_at`, the future is polled before the deadline.
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
pub(crate) mod testing {
    use super::*;

    use commonware_runtime::{deterministic, Clock as _};

    /// A deadline `timeout` from now on a fresh Tokio clock.
    pub(crate) fn tokio_deadline(timeout: Duration) -> PutDeadline {
        PutDeadline::after(Arc::new(TokioClock::new()), timeout)
    }

    /// Reads time from Commonware's deterministic runtime, which simulates it.
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

    /// Checks the documented `PutClock` contract on `clock`, from inside the
    /// runtime it belongs to.
    async fn assert_contract(clock: &dyn PutClock) {
        // A deadline that already passed finishes promptly, including one from
        // before the clock was created.
        let started = clock.now();
        clock.sleep_until(started - Duration::from_secs(1)).await;
        assert!(clock.elapsed(started) < Duration::from_millis(100));

        // A sleep finishes once `now` reaches its deadline, and `now` never moves
        // backward across it.
        let deadline = clock.now() + Duration::from_millis(50);
        clock.sleep_until(deadline).await;
        let woke = clock.now();
        assert!(woke >= deadline);
        assert!(clock.now() >= woke);

        // `elapsed` saturates at zero for times that have not happened yet.
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
    async fn deadline_fires_after_the_future_spends_the_coop_budget() {
        let deadline = tokio_deadline(Duration::from_millis(10));
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
