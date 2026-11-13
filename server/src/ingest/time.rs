//! Deadline clock used by ingest.
//!
//! Native builds use the tokio clock and timers. On wasm32 the Rust standard clock is not
//! available and tokio drives no timers, so those builds read the page's monotonic clock and
//! check a deadline whenever the guarded future is polled.

#[cfg(target_arch = "wasm32")]
pub(crate) use browser::timeout_at;
#[cfg(target_arch = "wasm32")]
pub use browser::Instant;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use tokio::time::{timeout_at, Instant};

#[cfg(target_arch = "wasm32")]
mod browser {
    use std::{future::Future, ops::Add, pin::pin, task::Poll, time::Duration};
    use wasm_bindgen::prelude::wasm_bindgen;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = performance, js_name = now)]
        fn performance_now() -> f64;
    }

    /// A reading of the page's monotonic clock (`performance.now()`).
    ///
    /// It stands in for `tokio::time::Instant` in the ingest API on wasm32.
    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Instant(Duration);

    impl Instant {
        /// The current reading.
        pub fn now() -> Self {
            // The clock reports milliseconds since the page's time origin. A reading that
            // `Duration` cannot hold, such as NaN or a negative value, becomes zero.
            let millis = performance_now();
            Self(Duration::try_from_secs_f64(millis / 1000.0).unwrap_or_default())
        }

        /// Time passed since this reading.
        pub fn elapsed(&self) -> Duration {
            Self::now().0.saturating_sub(self.0)
        }
    }

    impl Add<Duration> for Instant {
        type Output = Self;

        fn add(self, duration: Duration) -> Self {
            Self(self.0.saturating_add(duration))
        }
    }

    /// The deadline passed before the future finished.
    pub(crate) struct Elapsed;

    /// Resolves with the output of `future`, or with [`Elapsed`] when a poll finds `future`
    /// still pending after the deadline.
    ///
    /// No timer is armed, so the deadline is noticed only when this future is polled. A wait
    /// inside `future` that nothing wakes before the deadline lasts until something wakes it.
    pub(crate) async fn timeout_at<F: Future>(
        deadline: Instant,
        future: F,
    ) -> Result<F::Output, Elapsed> {
        let mut future = pin!(future);
        std::future::poll_fn(|cx| {
            if let Poll::Ready(output) = future.as_mut().poll(cx) {
                return Poll::Ready(Ok(output));
            }
            if Instant::now() >= deadline {
                return Poll::Ready(Err(Elapsed));
            }
            Poll::Pending
        })
        .await
    }
}
