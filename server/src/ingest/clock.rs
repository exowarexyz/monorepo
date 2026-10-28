use std::{
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime},
};

use futures::future::{BoxFuture, Either};

/// Source of time for Put deadlines and timings.
///
/// The default reads Tokio's clock. A backend can substitute another clock, such
/// as a deterministic runtime's simulated one, so Put timeouts follow that clock.
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
/// clock steps and lets tests that pause Tokio time drive Put timeouts.
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
}

// Callers that run on Tokio can keep passing Tokio instants.
impl From<tokio::time::Instant> for PutDeadline {
    fn from(instant: tokio::time::Instant) -> Self {
        let clock = TokioClock::new();
        Self::new(Arc::new(clock), clock.to_system(instant))
    }
}

pub(crate) struct Elapsed;

/// Polls `future` until it finishes or `clock` reaches `deadline`. Like
/// `tokio::time::timeout_at`, the future is polled before the deadline.
pub(crate) async fn timeout_at<F: Future>(
    clock: &dyn PutClock,
    deadline: SystemTime,
    future: F,
) -> Result<F::Output, Elapsed> {
    let future = std::pin::pin!(future);
    match futures::future::select(future, clock.sleep_until(deadline)).await {
        Either::Left((output, _)) => Ok(output),
        Either::Right(((), _)) => Err(Elapsed),
    }
}
