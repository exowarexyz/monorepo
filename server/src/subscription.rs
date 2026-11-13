//! Lifetime bounds for server-streaming subscriptions.
//!
//! [bound_subscription] ends a response stream with `UNAVAILABLE` when its
//! sampled lifetime elapses or an external close signal fires. Resuming
//! clients treat that status as transient and reconnect from their cursor, so
//! rolling restarts and rebalancing do not lose or repeat batches.

use crate::{ingest::transport, stream::STREAM_ERROR_DOMAIN};
use connectrpc::ConnectError;
use exoware_sdk::{google::rpc::ErrorInfo, with_error_info_detail};
use futures::Stream;
use rand::RngExt as _;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

/// `ErrorInfo.reason` when a subscription reached its maximum lifetime.
pub const REASON_SUBSCRIPTION_EXPIRED: &str = "SUBSCRIPTION_EXPIRED";

/// `ErrorInfo.reason` when the server closed a subscription because it is shutting down.
pub const REASON_SERVER_SHUTDOWN: &str = "SERVER_SHUTDOWN";

const DEFAULT_JITTER: f64 = 0.2;

/// Optional upper bound on how long one subscription stays open.
///
/// Each subscription samples its lifetime uniformly from
/// `max_duration * (1 - jitter)` through `max_duration`. The maximum is never
/// exceeded, and jitter spreads the reconnects of subscriptions that opened
/// together. Subscriptions are unbounded by default, because clients without
/// automatic resume would see each forced close as the end of their stream.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SubscriptionLifetime {
    max_duration: Option<Duration>,
    jitter: f64,
}

impl Default for SubscriptionLifetime {
    fn default() -> Self {
        Self::unbounded()
    }
}

impl SubscriptionLifetime {
    /// Subscriptions stay open until the client leaves, the stream fails, or the server shuts down.
    pub const fn unbounded() -> Self {
        Self {
            max_duration: None,
            jitter: DEFAULT_JITTER,
        }
    }

    /// Ends each subscription no later than `max_duration` after it opens.
    ///
    /// The default jitter samples lifetimes from 80% through 100% of `max_duration`.
    pub const fn new(max_duration: Duration) -> Self {
        Self {
            max_duration: Some(max_duration),
            jitter: DEFAULT_JITTER,
        }
    }

    /// Sets the fraction of `max_duration` that jitter may remove.
    ///
    /// Values are clamped to `0.0..=1.0`. A non-finite value disables jitter,
    /// so every subscription lives exactly `max_duration`.
    pub const fn with_jitter(mut self, fraction: f64) -> Self {
        self.jitter = if fraction.is_finite() {
            fraction.clamp(0.0, 1.0)
        } else {
            0.0
        };
        self
    }

    /// The configured jitter fraction.
    pub const fn jitter(&self) -> f64 {
        self.jitter
    }

    fn sample(&self) -> Option<Duration> {
        let max = self.max_duration?;
        if self.jitter == 0.0 {
            return Some(max);
        }
        let removed = rand::rng().random_range(0.0..=self.jitter);
        Some(max.mul_f64(1.0 - removed))
    }
}

// Both ends are the same resumable status. Only the reason tells them apart.
fn ended(reason: &str, message: &str) -> ConnectError {
    with_error_info_detail(
        ConnectError::unavailable(message),
        ErrorInfo {
            reason: reason.to_string(),
            domain: STREAM_ERROR_DOMAIN.to_string(),
            ..Default::default()
        },
    )
}

/// A subscription stream ended by its lifetime or a close signal.
///
/// Created by [bound_subscription].
pub struct BoundedSubscription<S, C> {
    // Dropped as soon as the subscription ends, so backend resources are
    // released then rather than when the transport drops the response body.
    active: Option<Active<S, C>>,
}

// Every field is boxed, so the wrapper is `Unpin` and can be borrowed
// mutably without pin projection.
struct Active<S, C> {
    inner: Pin<Box<S>>,
    close: Pin<Box<C>>,
    deadline: Option<Pin<Box<Sleep>>>,
}

impl<S, C> Active<S, C>
where
    C: Future<Output = ()>,
{
    fn poll_bounds(&mut self, cx: &mut Context<'_>) -> Option<ConnectError> {
        if self.close.as_mut().poll(cx).is_ready() {
            return Some(ended(
                REASON_SERVER_SHUTDOWN,
                "server is shutting down, resume from the last received sequence",
            ));
        }

        // The clock is checked as well because a sleep can stay pending past its
        // deadline when the task has exhausted its cooperative budget.
        let deadline = self.deadline.as_mut()?;
        if deadline.as_mut().poll(cx).is_ready() || Instant::now() >= deadline.deadline() {
            return Some(ended(
                REASON_SUBSCRIPTION_EXPIRED,
                "subscription reached its maximum lifetime, resume from the last received sequence",
            ));
        }
        None
    }
}

impl<S, C, T> Stream for BoundedSubscription<S, C>
where
    S: Stream<Item = Result<T, ConnectError>>,
    C: Future<Output = ()>,
{
    type Item = Result<T, ConnectError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let Some(active) = this.active.as_mut() else {
            return Poll::Ready(None);
        };
        if let Some(error) = active.poll_bounds(cx) {
            this.active = None;
            return Poll::Ready(Some(Err(error)));
        }

        // Bounds are checked again after a ready item, so a frame produced
        // after the bound by one long inner poll is never delivered.
        let item = std::task::ready!(active.inner.as_mut().poll_next(cx));
        let item = match item {
            Some(Ok(item)) => match active.poll_bounds(cx) {
                Some(error) => Some(Err(error)),
                None => return Poll::Ready(Some(Ok(item))),
            },
            item => item,
        };
        this.active = None;
        Poll::Ready(item)
    }
}

/// Ends `stream` with `UNAVAILABLE` when its sampled lifetime elapses or `close` completes.
///
/// The lifetime is sampled once, when this function is called, and frame
/// delivery never extends it. Inner errors and the end of `stream` pass
/// through and end the subscription. Nothing from `stream` is delivered once
/// a bound has been reached, so emit an opening checkpoint ahead of the
/// returned stream rather than from inside it.
///
/// Under [transport::serve], a response is also cut off shortly after its
/// lifetime when the client has stopped reading it. That requires calling this
/// from the request handler before it returns the response. Output that the
/// transport has already taken in full is bounded only by the shutdown
/// timeout. Elsewhere, the lifetime only takes effect while the client keeps
/// reading.
///
/// Built-in `log.stream.v1.Subscribe` handlers use this with
/// [transport::ShutdownSignal::closed] as `close`. Backends that implement
/// their own `Subscribe` handler can do the same to share that behavior.
pub fn bound_subscription<S, C>(
    stream: S,
    lifetime: SubscriptionLifetime,
    close: C,
) -> BoundedSubscription<S, C>
where
    C: Future<Output = ()>,
{
    let deadline = lifetime
        .sample()
        .and_then(|lifetime| Instant::now().checked_add(lifetime));
    if let Some(deadline) = deadline {
        transport::arm_subscription_cutoff(deadline);
    }

    BoundedSubscription {
        active: Some(Active {
            inner: Box::pin(stream),
            close: Box::pin(close),
            deadline: deadline.map(|deadline| Box::pin(tokio::time::sleep_until(deadline))),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{stream, StreamExt};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use tokio::sync::Notify;

    fn reason(error: &ConnectError) -> String {
        exoware_sdk::decode_connect_error(error)
            .expect("decode connect error")
            .error_info
            .expect("error info")
            .reason
    }

    #[test]
    fn sampled_lifetimes_stay_within_the_jitter_window() {
        let lifetime = SubscriptionLifetime::new(Duration::from_secs(100));
        for _ in 0..1_000 {
            let sampled = lifetime.sample().unwrap();
            assert!(sampled <= Duration::from_secs(100));
            assert!(sampled >= Duration::from_secs(80));
        }

        let strict = lifetime.with_jitter(0.0);
        assert_eq!(strict.sample(), Some(Duration::from_secs(100)));
        assert_eq!(SubscriptionLifetime::default().sample(), None);
    }

    #[test]
    fn jitter_is_clamped() {
        let lifetime = SubscriptionLifetime::unbounded();
        assert_eq!(lifetime.with_jitter(7.0).jitter(), 1.0);
        assert_eq!(lifetime.with_jitter(-1.0).jitter(), 0.0);
        assert_eq!(lifetime.with_jitter(f64::NAN).jitter(), 0.0);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_stream_ends_at_its_lifetime_despite_frames() {
        let lifetime = SubscriptionLifetime::new(Duration::from_secs(10)).with_jitter(0.0);
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
    async fn busy_stream_delivers_nothing_after_its_lifetime() {
        let lifetime = SubscriptionLifetime::new(Duration::from_secs(1)).with_jitter(0.0);
        let frames = stream::unfold(0_u32, |next| async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            Some((Ok(next), next + 1))
        });
        let mut bounded = bound_subscription(frames, lifetime, std::future::pending());

        let mut delivered = Vec::new();
        let error = loop {
            match bounded.next().await.unwrap() {
                Ok(frame) => delivered.push(frame),
                Err(error) => break error,
            }
        };
        assert_eq!(delivered, vec![0, 1, 2]);
        assert_eq!(reason(&error), REASON_SUBSCRIPTION_EXPIRED);
    }

    #[tokio::test(start_paused = true)]
    async fn close_signal_ends_an_idle_stream() {
        let close = Arc::new(Notify::new());
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
        assert_eq!(reason(&error), REASON_SERVER_SHUTDOWN);
        assert!(bounded.next().await.is_none());
    }

    #[tokio::test]
    async fn closed_signal_wins_over_ready_frames() {
        let frames = stream::iter([Ok(7_u32), Ok(8)]);
        let mut bounded = bound_subscription(frames, SubscriptionLifetime::unbounded(), async {});

        let error = bounded.next().await.unwrap().unwrap_err();
        assert_eq!(reason(&error), REASON_SERVER_SHUTDOWN);
        assert!(bounded.next().await.is_none());
    }

    #[tokio::test]
    async fn inner_errors_and_end_pass_through() {
        let frames = stream::iter([Ok(1_u32), Err(ConnectError::internal("boom")), Ok(2)]);
        let mut bounded = bound_subscription(
            frames,
            SubscriptionLifetime::unbounded(),
            std::future::pending(),
        );
        assert_eq!(bounded.next().await.unwrap().unwrap(), 1);
        let error = bounded.next().await.unwrap().unwrap_err();
        assert_eq!(error.code, connectrpc::ErrorCode::Internal);
        assert!(bounded.next().await.is_none());

        let mut ended = bound_subscription(
            stream::iter([Ok::<_, ConnectError>(3_u32)]),
            SubscriptionLifetime::unbounded(),
            std::future::pending(),
        );
        assert_eq!(ended.next().await.unwrap().unwrap(), 3);
        assert!(ended.next().await.is_none());
    }

    struct ReleaseProbe(Arc<AtomicBool>);

    impl Stream for ReleaseProbe {
        type Item = Result<u32, ConnectError>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Drop for ReleaseProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn ending_releases_the_inner_stream_before_the_wrapper_drops() {
        let released = Arc::new(AtomicBool::new(false));
        let lifetime = SubscriptionLifetime::new(Duration::from_secs(1)).with_jitter(0.0);
        let mut bounded = bound_subscription(
            ReleaseProbe(released.clone()),
            lifetime,
            std::future::pending(),
        );

        let error = bounded.next().await.unwrap().unwrap_err();
        assert_eq!(reason(&error), REASON_SUBSCRIPTION_EXPIRED);
        assert!(released.load(Ordering::SeqCst));
    }
}
