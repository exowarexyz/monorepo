use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

use futures::future::{BoxFuture, Either};

/// A monotonic timeline shared by deadlines and elapsed-time measurements.
///
/// `now` and `sleep_until` must use the same timeline. Sleeps at or before
/// `now` complete immediately. Dropping a sleep cancels the wait.
pub trait Clock: Send + Sync + 'static {
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

impl Clock for TokioClock {
    fn now(&self) -> SystemTime {
        self.to_system(tokio::time::Instant::now())
    }

    fn sleep_until(&self, deadline: SystemTime) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep_until(self.to_tokio(deadline)))
    }
}

/// A deadline elapsed before the operation completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("deadline exceeded")]
pub struct Elapsed;

/// An absolute deadline and the clock that measures it.
#[derive(Clone)]
pub struct Deadline {
    clock: Arc<dyn Clock>,
    at: SystemTime,
}

impl Deadline {
    pub fn new(clock: Arc<dyn Clock>, at: SystemTime) -> Self {
        Self { clock, at }
    }

    pub fn after(clock: Arc<dyn Clock>, timeout: Duration) -> Self {
        let at = clock.now() + timeout;
        Self { clock, at }
    }

    /// Shorten this deadline without changing its clock.
    pub fn capped(&self, duration: Duration) -> Self {
        Self::new(self.clock.clone(), self.at.min(self.clock.now() + duration))
    }

    pub async fn wait(&self) {
        Expiry::new(self.clock(), self.at).await;
    }

    pub fn at(&self) -> SystemTime {
        self.at
    }

    pub fn clock(&self) -> &dyn Clock {
        &*self.clock
    }

    pub fn remaining(&self) -> Duration {
        self.at.duration_since(self.clock.now()).unwrap_or_default()
    }

    pub fn expired(&self) -> bool {
        self.clock.now() >= self.at
    }

    /// A ready result wins over an expired deadline, matching `tokio::time::timeout_at`.
    pub async fn timeout<F: Future>(&self, future: F) -> Result<F::Output, Elapsed> {
        let expiry = Expiry::new(self.clock(), self.at);
        match futures::future::select(std::pin::pin!(future), expiry).await {
            Either::Left((output, _)) => Ok(output),
            Either::Right(((), _)) => Err(Elapsed),
        }
    }
}

impl fmt::Debug for Deadline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Deadline")
            .field("at", &self.at)
            .finish_non_exhaustive()
    }
}

/// Waits for a deadline, creating the timer only when needed.
pub(crate) struct Expiry<'a> {
    clock: &'a dyn Clock,
    at: SystemTime,
    sleep: Option<BoxFuture<'static, ()>>,
}

impl<'a> Expiry<'a> {
    pub(crate) fn new(clock: &'a dyn Clock, at: SystemTime) -> Self {
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

    pub(crate) fn tokio_deadline(timeout: Duration) -> Deadline {
        Deadline::after(Arc::new(TokioClock::new()), timeout)
    }

    pub(crate) struct SimulatedRuntime(pub(crate) deterministic::Context);

    impl crate::runtime::Runtime for SimulatedRuntime {
        fn clock(&self) -> Arc<dyn Clock> {
            use commonware_runtime::Supervisor as _;
            Arc::new(SimulatedClock(self.0.child("clock")))
        }
        fn spawn(&self, name: &'static str, task: crate::runtime::TaskFn) -> crate::runtime::Task {
            use commonware_runtime::{Spawner as _, Supervisor as _};
            let handle = self
                .0
                .child(name)
                .spawn(move |context| task(Arc::new(Self(context))));
            let handle = Arc::new(std::sync::Mutex::new(handle));
            let abort = handle.clone();
            crate::runtime::Task::new(
                Box::pin(std::future::poll_fn(move |cx| {
                    Pin::new(&mut *handle.lock().unwrap())
                        .poll(cx)
                        .map_err(|e| crate::runtime::TaskError(e.to_string()))
                })),
                move || abort.lock().unwrap().abort(),
            )
        }
        fn execute_cpu(
            &self,
            job: Box<dyn FnOnce() + Send>,
        ) -> BoxFuture<'static, Result<(), crate::runtime::TaskError>> {
            use commonware_runtime::{Spawner as _, Supervisor as _};
            let context = self.0.child("cpu");
            Box::pin(async move {
                context
                    .shared(true)
                    .spawn(move |_| async move { job() })
                    .await
                    .map_err(|e| crate::runtime::TaskError(e.to_string()))
            })
        }
    }

    pub(crate) struct SimulatedClock(pub(crate) deterministic::Context);

    impl Clock for SimulatedClock {
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

    #[test]
    fn deadline_allocates_only_when_waiting_and_cancels_its_sleep() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct ClockProbe(Arc<AtomicUsize>);
        struct PendingSleep(Arc<AtomicUsize>);

        impl Future for PendingSleep {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }
        impl Drop for PendingSleep {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        impl Clock for ClockProbe {
            fn now(&self) -> SystemTime {
                SystemTime::UNIX_EPOCH
            }
            fn sleep_until(&self, _: SystemTime) -> BoxFuture<'static, ()> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Box::pin(PendingSleep(self.0.clone()))
            }
        }

        let active = Arc::new(AtomicUsize::new(0));
        let deadline =
            Deadline::after(Arc::new(ClockProbe(active.clone())), Duration::from_secs(1));
        assert_eq!(
            futures::executor::block_on(deadline.timeout(std::future::ready(42))).unwrap(),
            42
        );
        assert_eq!(active.load(Ordering::SeqCst), 0);
        let mut wait = Box::pin(deadline.timeout(std::future::pending::<()>()));
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        assert_eq!(active.load(Ordering::SeqCst), 1);
        drop(wait);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    async fn assert_contract(clock: &dyn Clock) {
        // Include a deadline from before the clock was created.
        let started = clock.now();
        clock.sleep_until(started - Duration::from_secs(1)).await;

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

        assert_eq!(error, Elapsed);
    }
}
