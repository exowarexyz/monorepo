//! Execution and time supplied by the application hosting the server.

mod clock;
mod hyper;
pub mod simulated;

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{channel::oneshot, future::BoxFuture};

#[cfg(test)]
pub(crate) use clock::testing;
pub(crate) use clock::Expiry;
pub use clock::{Clock, Deadline, Elapsed, TokioClock};
pub use hyper::{Executor, TaskSet, TaskSpawner, Timer};

/// A task failed or was cancelled before producing its result.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TaskError(pub String);

/// An asynchronous task owned by its caller. Dropping it requests cancellation.
pub struct Task {
    completion: BoxFuture<'static, Result<(), TaskError>>,
    abort: Box<dyn Fn() + Send + Sync>,
    finished: bool,
}

impl Task {
    pub fn new(
        completion: BoxFuture<'static, Result<(), TaskError>>,
        abort: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        Self {
            completion,
            abort: Box::new(abort),
            finished: false,
        }
    }

    pub fn abort(&self) {
        (self.abort)();
    }
}

impl Future for Task {
    type Output = Result<(), TaskError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = self.completion.as_mut().poll(cx);
        self.finished |= result.is_ready();
        result
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        if !self.finished {
            self.abort();
        }
    }
}

/// The runtime passed to a spawned task belongs to that task's scope.
pub type TaskFn = Box<dyn FnOnce(Arc<dyn Runtime>) -> BoxFuture<'static, ()> + Send>;

/// Time, asynchronous tasks, and CPU execution for ingestion.
///
/// CPU jobs start when their returned future is polled. Once running, a job
/// keeps ownership of its captures until it finishes, even if the future is dropped.
pub trait Runtime: Send + Sync + 'static {
    fn clock(&self) -> Arc<dyn Clock>;
    fn spawn(&self, name: &'static str, task: TaskFn) -> Task;
    fn execute_cpu(
        &self,
        job: Box<dyn FnOnce() + Send>,
    ) -> BoxFuture<'static, Result<(), TaskError>>;
}

/// Execute a typed CPU job without exposing its result type in the runtime interface.
pub async fn run_cpu<T: Send + 'static>(
    runtime: Arc<dyn Runtime>,
    job: impl FnOnce() -> T + Send + 'static,
) -> Result<T, TaskError> {
    let (sender, receiver) = oneshot::channel();
    runtime
        .execute_cpu(Box::new(move || {
            let _ = sender.send(job());
        }))
        .await?;
    receiver
        .await
        .map_err(|_| TaskError("CPU worker exited without a result".into()))
}

/// Tokio execution with a shared monotonic clock.
#[derive(Clone)]
pub struct TokioRuntime {
    handle: tokio::runtime::Handle,
    clock: Arc<dyn Clock>,
}

impl TokioRuntime {
    /// Select the currently entered Tokio runtime explicitly.
    pub fn current() -> Arc<Self> {
        Arc::new(Self {
            handle: tokio::runtime::Handle::current(),
            clock: Arc::new(TokioClock::new()),
        })
    }
}

impl Runtime for TokioRuntime {
    fn clock(&self) -> Arc<dyn Clock> {
        self.clock.clone()
    }

    fn spawn(&self, _: &'static str, task: TaskFn) -> Task {
        let runtime = Arc::new(self.clone());
        let handle = self.handle.spawn(async move { task(runtime).await });
        let abort = handle.abort_handle();
        Task::new(
            Box::pin(async move { handle.await.map_err(|error| TaskError(error.to_string())) }),
            move || abort.abort(),
        )
    }

    fn execute_cpu(
        &self,
        job: Box<dyn FnOnce() + Send>,
    ) -> BoxFuture<'static, Result<(), TaskError>> {
        let handle = self.handle.clone();
        Box::pin(async move {
            handle
                .spawn_blocking(job)
                .await
                .map_err(|error| TaskError(error.to_string()))
        })
    }
}

/// Yield once without requiring an executor-specific task context.
pub async fn yield_now() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await
}

#[cfg(test)]
mod tests;
