//! Lifetime bounds for server-streaming subscriptions.
//!
//! [bound_subscription] wraps any response stream so that an elapsed
//! lifetime or an external close signal ends it with an `UNAVAILABLE` error.
//! Clients treat that status as a transient condition and resume from their
//! last cursor, so rolling restarts and load rebalancing do not lose data.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use connectrpc::ConnectError;
use exoware_sdk::google::rpc::ErrorInfo;
use exoware_sdk::with_error_info_detail;
use futures::future::Shared;
use futures::{FutureExt as _, Stream};
use rand::RngExt as _;
use tokio::task::JoinHandle;
use tokio::time::{Instant, Sleep};

use crate::ingest::transport::StreamWatchdog;
use crate::stream::STREAM_ERROR_DOMAIN;

/// `ErrorInfo.reason` when a subscription reached its maximum lifetime.
pub const REASON_SUBSCRIPTION_EXPIRED: &str = "SUBSCRIPTION_EXPIRED";
/// `ErrorInfo.reason` when the server is shutting down or the caller closed the subscription.
pub const REASON_SERVER_CLOSING: &str = "SERVER_CLOSING";

const DEFAULT_JITTER_FRACTION: f64 = 0.2;

/// A boxed server-streaming response body.
pub type SubscriptionStream<T> = Pin<Box<dyn Stream<Item = Result<T, ConnectError>> + Send>>;

/// Optional upper bound on how long one subscription may stay open.
///
/// Each subscription ends at a deadline drawn uniformly from
/// `max_duration * (1 - jitter_fraction)` through `max_duration`, so the
/// configured maximum is never exceeded and reconnect storms are spread out.
/// The default is unbounded.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SubscriptionLifetime {
    max_duration: Option<Duration>,
    jitter_fraction: f64,
}

impl Default for SubscriptionLifetime {
    fn default() -> Self {
        Self::unbounded()
    }
}

impl SubscriptionLifetime {
    /// Subscriptions stay open until the client or the server shuts down.
    pub const fn unbounded() -> Self {
        Self {
            max_duration: None,
            jitter_fraction: DEFAULT_JITTER_FRACTION,
        }
    }

    /// Ends each subscription no later than `max_duration` after it opens.
    pub const fn new(max_duration: Duration) -> Self {
        Self {
            max_duration: Some(max_duration),
            jitter_fraction: DEFAULT_JITTER_FRACTION,
        }
    }

    /// Sets the fraction of `max_duration` that jitter may remove.
    ///
    /// Values are clamped to `0.0..=1.0` and non-finite values disable jitter,
    /// which makes the maximum strict.
    pub fn with_jitter_fraction(mut self, fraction: f64) -> Self {
        self.jitter_fraction = if fraction.is_finite() {
            fraction.clamp(0.0, 1.0)
        } else {
            0.0
        };
        self
    }

    /// The configured maximum duration, if any.
    pub const fn max_duration(&self) -> Option<Duration> {
        self.max_duration
    }

    /// The configured jitter fraction.
    pub const fn jitter_fraction(&self) -> f64 {
        self.jitter_fraction
    }

    /// Draws a deadline for a subscription that opened at `start`.
    pub fn deadline_from(&self, start: Instant) -> Option<Instant> {
        let max = self.max_duration?;
        let removed = if self.jitter_fraction > 0.0 {
            rand::rng().random_range(0.0..=self.jitter_fraction)
        } else {
            0.0
        };

        Some(start + max.mul_f64(1.0 - removed))
    }
}

fn unavailable(reason: &str, message: &str) -> ConnectError {
    with_error_info_detail(
        ConnectError::unavailable(message),
        ErrorInfo {
            reason: reason.to_string(),
            domain: STREAM_ERROR_DOMAIN.to_string(),
            ..Default::default()
        },
    )
}

type SharedClose = Shared<Pin<Box<dyn Future<Output = ()> + Send>>>;

#[derive(Clone, Copy)]
enum Ended {
    Closing,
    Expired,
}

impl Ended {
    fn error(self) -> ConnectError {
        match self {
            Self::Closing => unavailable(
                REASON_SERVER_CLOSING,
                "subscription closed, resume from the last cursor",
            ),
            Self::Expired => unavailable(
                REASON_SUBSCRIPTION_EXPIRED,
                "subscription reached its maximum lifetime, resume from the last cursor",
            ),
        }
    }
}

// The inner stream lives behind a short synchronous lock so the supervisor can
// drop it at the bound even while Hyper is not polling the body. The body then
// only has the terminal error left to deliver.
struct Core<T> {
    state: Mutex<CoreState<T>>,
}

struct CoreState<T> {
    inner: Option<SubscriptionStream<T>>,
    ended: Option<Ended>,
}

impl<T> Core<T> {
    fn lock(&self) -> MutexGuard<'_, CoreState<T>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // Backend resources drop outside the lock because their destructors are
    // arbitrary code.
    fn end(&self, ended: Ended) {
        let inner = {
            let mut state = self.lock();
            state.ended.get_or_insert(ended);
            state.inner.take()
        };
        drop(inner);
    }
}

// Aborting on drop ties the supervisor to the response body, so a completed
// or abandoned subscription never leaves a timer or signal reference behind.
struct Supervisor(JoinHandle<()>);

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// Hyper stops polling a response body while the peer withholds output
// capacity, so the stream itself cannot notice a bound that fires then. This
// task runs independently of body polling. It releases the subscription at the
// bound, so the sampled lifetime is strict for backend resources, and tells
// the transport to cut the response off if the peer has not drained the
// terminal error within the flush grace period.
async fn supervise<T>(
    core: Arc<Core<T>>,
    watchdog: Option<StreamWatchdog>,
    deadline: Option<Instant>,
    close: SharedClose,
) {
    let expired = async {
        match deadline {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending().await,
        }
    };
    let ended = tokio::select! {
        _ = close => Ended::Closing,
        _ = expired => Ended::Expired,
    };

    core.end(ended);
    if let Some(watchdog) = watchdog {
        watchdog.cancel_after_grace();
    }
}

struct BoundedStream<T> {
    core: Arc<Core<T>>,
    deadline: Option<Pin<Box<Sleep>>>,
    close: SharedClose,
    finished: bool,
    watchdog: Option<StreamWatchdog>,
    _supervisor: Supervisor,
}

impl<T> Drop for BoundedStream<T> {
    // A body dropped for any reason is ending its response, so the flush must
    // be bounded even when no bound fired. The supervisor also shares the
    // inner stream, so it is released here instead of when that task is reaped.
    fn drop(&mut self) {
        self.core.end(Ended::Closing);
        if let Some(watchdog) = &self.watchdog {
            watchdog.cancel_after_grace();
        }
    }
}

impl<T: Send + 'static> BoundedStream<T> {
    fn terminate(
        &mut self,
        item: Option<Result<T, ConnectError>>,
    ) -> Poll<Option<Result<T, ConnectError>>> {
        self.finished = true;
        self.deadline = None;
        if let Some(watchdog) = &self.watchdog {
            watchdog.cancel_after_grace();
        }
        Poll::Ready(item)
    }

    // Takes the bound fields directly so it can run while the core lock is held.
    fn poll_bounds(
        close: &mut SharedClose,
        deadline: &mut Option<Pin<Box<Sleep>>>,
        cx: &mut Context<'_>,
    ) -> Option<Ended> {
        if Pin::new(close).poll(cx).is_ready() {
            return Some(Ended::Closing);
        }

        // The clock is compared as well because a deadline that elapsed during a
        // long inner poll may not have been fired by the timer driver yet.
        if let Some(deadline) = deadline {
            if deadline.as_mut().poll(cx).is_ready() || Instant::now() >= deadline.deadline() {
                return Some(Ended::Expired);
            }
        }
        None
    }
}

impl<T: Send + 'static> Stream for BoundedStream<T> {
    type Item = Result<T, ConnectError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }

        // Bounds are checked before and after every inner poll so a ready or
        // busy stream can never report anything but the bound after the maximum
        // lifetime or a close signal, even when one inner poll spans the bound.
        if let Some(ended) = Self::poll_bounds(&mut this.close, &mut this.deadline, cx) {
            this.core.end(ended);
        }

        let mut state = this.core.lock();
        if let Some(ended) = state.ended {
            drop(state);
            return this.terminate(Some(Err(ended.error())));
        }
        let Some(inner) = state.inner.as_mut() else {
            drop(state);
            return this.terminate(None);
        };
        let Poll::Ready(item) = inner.as_mut().poll_next(cx) else {
            return Poll::Pending;
        };
        let ended = Self::poll_bounds(&mut this.close, &mut this.deadline, cx);
        if ended.is_none() {
            if let Some(Ok(item)) = item {
                return Poll::Ready(Some(Ok(item)));
            }
        }
        let inner = state.inner.take();
        drop(state);
        drop(inner);
        match ended {
            Some(ended) => {
                this.core.end(ended);
                this.terminate(Some(Err(ended.error())))
            }
            None => this.terminate(item),
        }
    }
}

/// Ends `stream` with `UNAVAILABLE` when its lifetime elapses or `close` completes.
///
/// The deadline is drawn once, when this function is called, and is never
/// extended by frame delivery. A supervisor task drops the wrapped stream at the
/// bound even when the response body is not being polled, so the sampled
/// lifetime is strict for backend resources. The body still has to carry the
/// terminal error to the peer. Under `transport::serve` a peer that does not
/// accept it within a fixed flush grace period has its response reset, so the
/// physical disconnect of a stalled peer can trail the bound by that period.
/// Handlers that implement their own `Subscribe` can wrap their response
/// stream with this function to share the behavior of the built-in service.
/// Call it on the task that runs the handler, because the transport finds the
/// response to cut off through a task-local. A stream wrapped on a spawned
/// task still ends at its bound but cannot be cut off while the peer stalls.
pub fn bound_subscription<T, C>(
    stream: impl Stream<Item = Result<T, ConnectError>> + Send + 'static,
    lifetime: SubscriptionLifetime,
    close: C,
) -> SubscriptionStream<T>
where
    T: Send + 'static,
    C: Future<Output = ()> + Send + 'static,
{
    let deadline = lifetime.deadline_from(Instant::now());
    let close: SharedClose = (Box::pin(close) as Pin<Box<dyn Future<Output = ()> + Send>>).shared();
    let watchdog = StreamWatchdog::current();
    if let Some(watchdog) = &watchdog {
        watchdog.mark_supervised();
    }
    let core = Arc::new(Core {
        state: Mutex::new(CoreState {
            inner: Some(Box::pin(stream)),
            ended: None,
        }),
    });
    let supervisor = Supervisor(tokio::spawn(supervise(
        core.clone(),
        watchdog.clone(),
        deadline,
        close.clone(),
    )));

    Box::pin(BoundedStream {
        core,
        deadline: deadline.map(|deadline| Box::pin(tokio::time::sleep_until(deadline))),
        close,
        finished: false,
        watchdog,
        _supervisor: supervisor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{stream, StreamExt};
    use tokio::sync::Notify;

    fn reason(error: &ConnectError) -> String {
        exoware_sdk::decode_connect_error(error)
            .expect("decode connect error")
            .error_info
            .expect("error info")
            .reason
    }

    #[test]
    fn deadline_never_exceeds_max_and_stays_within_jitter() {
        let start = Instant::now();
        let lifetime = SubscriptionLifetime::new(Duration::from_secs(100));
        for _ in 0..1_000 {
            let deadline = lifetime.deadline_from(start).unwrap();
            assert!(deadline <= start + Duration::from_secs(100));
            assert!(deadline >= start + Duration::from_secs(80));
        }

        let strict = lifetime.with_jitter_fraction(0.0);
        assert_eq!(
            strict.deadline_from(start),
            Some(start + Duration::from_secs(100))
        );
        assert_eq!(SubscriptionLifetime::default().deadline_from(start), None);
    }

    #[test]
    fn jitter_fraction_is_clamped() {
        let lifetime = SubscriptionLifetime::unbounded();
        assert_eq!(lifetime.with_jitter_fraction(7.0).jitter_fraction(), 1.0);
        assert_eq!(lifetime.with_jitter_fraction(-1.0).jitter_fraction(), 0.0);
        assert_eq!(
            lifetime.with_jitter_fraction(f64::NAN).jitter_fraction(),
            0.0
        );
    }

    #[tokio::test(start_paused = true)]
    async fn idle_stream_ends_at_one_deadline_without_reset() {
        let lifetime = SubscriptionLifetime::new(Duration::from_secs(10)).with_jitter_fraction(0.0);
        let frames = stream::iter([Ok(1_u32), Ok(2)]).chain(stream::pending());
        let mut bounded = bound_subscription(frames, lifetime, std::future::pending());

        assert_eq!(bounded.next().await.unwrap().unwrap(), 1);
        tokio::time::advance(Duration::from_secs(6)).await;
        assert_eq!(bounded.next().await.unwrap().unwrap(), 2);

        let started = Instant::now();
        let error = bounded.next().await.unwrap().unwrap_err();
        assert_eq!(started.elapsed(), Duration::from_secs(4));
        assert_eq!(error.code, connectrpc::ErrorCode::Unavailable);
        assert_eq!(reason(&error), REASON_SUBSCRIPTION_EXPIRED);
        assert!(bounded.next().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn busy_stream_cannot_outlive_its_deadline() {
        let lifetime = SubscriptionLifetime::new(Duration::from_secs(1)).with_jitter_fraction(0.0);
        let frames = stream::unfold(0_u32, |next| async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            Some((Ok(next), next + 1))
        });
        let mut bounded = bound_subscription(frames, lifetime, std::future::pending());

        let mut delivered = 0;
        let error = loop {
            match bounded.next().await.unwrap() {
                Ok(_) => delivered += 1,
                Err(error) => break error,
            }
        };
        assert_eq!(delivered, 3);
        assert_eq!(reason(&error), REASON_SUBSCRIPTION_EXPIRED);
    }

    #[tokio::test]
    async fn close_signal_ends_an_idle_stream() {
        let close = std::sync::Arc::new(Notify::new());
        let waiter = close.clone();
        let mut bounded = bound_subscription(
            stream::pending::<Result<u32, ConnectError>>(),
            SubscriptionLifetime::unbounded(),
            async move { waiter.notified().await },
        );

        let pending = tokio::time::timeout(Duration::from_millis(20), bounded.next()).await;
        assert!(pending.is_err());

        close.notify_one();
        let error = bounded.next().await.unwrap().unwrap_err();
        assert_eq!(error.code, connectrpc::ErrorCode::Unavailable);
        assert_eq!(reason(&error), REASON_SERVER_CLOSING);
        assert!(bounded.next().await.is_none());
    }

    #[tokio::test]
    async fn closed_before_first_poll_delivers_no_ready_frame() {
        let frames = stream::iter([Ok(7_u32), Ok(8)]);
        let mut bounded = bound_subscription(frames, SubscriptionLifetime::unbounded(), async {});

        let error = bounded.next().await.unwrap().unwrap_err();
        assert_eq!(reason(&error), REASON_SERVER_CLOSING);
        assert!(bounded.next().await.is_none());
    }

    #[tokio::test]
    async fn closed_before_first_poll_ends_a_stream_with_no_ready_frame() {
        let mut bounded = bound_subscription(
            stream::pending::<Result<u32, ConnectError>>(),
            SubscriptionLifetime::unbounded(),
            async {},
        );

        let error = bounded.next().await.unwrap().unwrap_err();
        assert_eq!(reason(&error), REASON_SERVER_CLOSING);
    }

    #[tokio::test]
    async fn inner_errors_and_end_pass_through_and_terminate() {
        let frames = stream::iter([Err::<u32, _>(ConnectError::internal("boom"))]);
        let mut bounded = bound_subscription(
            frames,
            SubscriptionLifetime::unbounded(),
            std::future::pending(),
        );

        let error = bounded.next().await.unwrap().unwrap_err();
        assert_eq!(error.code, connectrpc::ErrorCode::Internal);
        assert!(bounded.next().await.is_none());
    }

    struct ReleaseProbe(Arc<std::sync::atomic::AtomicBool>);

    impl Stream for ReleaseProbe {
        type Item = Result<u32, ConnectError>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Drop for ReleaseProbe {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn bound_releases_the_stream_without_the_body_being_polled() {
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let lifetime = SubscriptionLifetime::new(Duration::from_secs(10)).with_jitter_fraction(0.0);
        let mut bounded = bound_subscription(
            ReleaseProbe(released.clone()),
            lifetime,
            std::future::pending(),
        );

        tokio::time::sleep(Duration::from_secs(9)).await;
        assert!(!released.load(std::sync::atomic::Ordering::SeqCst));
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(released.load(std::sync::atomic::Ordering::SeqCst));

        let error = bounded.next().await.unwrap().unwrap_err();
        assert_eq!(reason(&error), REASON_SUBSCRIPTION_EXPIRED);
    }

    #[tokio::test]
    async fn close_releases_the_stream_without_the_body_being_polled() {
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let close = Arc::new(Notify::new());
        let waiter = close.clone();
        let bounded = bound_subscription(
            ReleaseProbe(released.clone()),
            SubscriptionLifetime::unbounded(),
            async move { waiter.notified().await },
        );

        tokio::task::yield_now().await;
        close.notify_one();
        for _ in 0..50 {
            if released.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(released.load(std::sync::atomic::Ordering::SeqCst));
        drop(bounded);
    }
}
