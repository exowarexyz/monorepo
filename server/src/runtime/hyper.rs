use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};

use futures::{
    future::BoxFuture,
    stream::{FuturesUnordered, StreamExt},
    task::AtomicWaker,
    FutureExt,
};

use super::{Clock, Deadline, Runtime, Task, TaskError};

struct Tasks {
    pending: Mutex<FuturesUnordered<Task>>,
    changed: AtomicWaker,
}

/// Owns spawned tasks and cancels them when the owner is dropped.
pub struct TaskSet(Arc<Tasks>);

/// A registration handle that cannot keep its task owner alive.
#[derive(Clone)]
pub struct TaskSpawner(Weak<Tasks>);

impl Default for TaskSet {
    fn default() -> Self {
        Self(Arc::new(Tasks {
            pending: Mutex::new(FuturesUnordered::new()),
            changed: AtomicWaker::new(),
        }))
    }
}

impl TaskSet {
    pub fn spawner(&self) -> TaskSpawner {
        TaskSpawner(Arc::downgrade(&self.0))
    }
    pub fn is_empty(&self) -> bool {
        self.0.pending.lock().unwrap().is_empty()
    }
    pub async fn next(&self) -> Option<Result<(), TaskError>> {
        std::future::poll_fn(|cx| {
            self.0.changed.register(cx.waker());
            self.0.pending.lock().unwrap().poll_next_unpin(cx)
        })
        .await
    }
}

impl Drop for TaskSet {
    fn drop(&mut self) {
        self.0.pending.lock().unwrap().clear();
    }
}

impl TaskSpawner {
    pub fn push(&self, task: Task) {
        if let Some(tasks) = self.0.upgrade() {
            let mut pending = tasks.pending.lock().unwrap();
            while let Some(Some(_)) = pending.next().now_or_never() {}
            pending.push(task);
            drop(pending);
            tasks.changed.wake();
        }
    }
}

/// Hyper task execution tied to a connection or client owner.
#[derive(Clone)]
pub struct Executor {
    runtime: Arc<dyn Runtime>,
    tasks: TaskSpawner,
}

impl Executor {
    pub fn new(runtime: Arc<dyn Runtime>, tasks: TaskSpawner) -> Self {
        Self { runtime, tasks }
    }
}

impl<F> hyper::rt::Executor<F> for Executor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        self.tasks.push(self.runtime.spawn(
            "http",
            Box::new(move |_| {
                Box::pin(async move {
                    let _ = future.await;
                })
            }),
        ));
    }
}

/// Maps Hyper's instant type onto the selected clock, including simulated time.
#[derive(Clone)]
pub struct Timer {
    clock: Arc<dyn Clock>,
    instant_origin: Instant,
    clock_origin: SystemTime,
}

impl Timer {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            instant_origin: Instant::now(),
            clock_origin: clock.now(),
            clock,
        }
    }
}

struct Sleep(Mutex<BoxFuture<'static, ()>>);

impl Future for Sleep {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.0.get_mut().unwrap().as_mut().poll(cx)
    }
}

impl hyper::rt::Sleep for Sleep {}

impl hyper::rt::Timer for Timer {
    fn now(&self) -> Instant {
        match self.clock.now().duration_since(self.clock_origin) {
            Ok(elapsed) => self.instant_origin + elapsed,
            Err(before) => self
                .instant_origin
                .checked_sub(before.duration())
                .unwrap_or(self.instant_origin),
        }
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn hyper::rt::Sleep>> {
        let deadline = Deadline::after(self.clock.clone(), duration);
        Box::pin(Sleep(Mutex::new(Box::pin(
            async move { deadline.wait().await },
        ))))
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
        let at = match deadline.checked_duration_since(self.instant_origin) {
            Some(after) => self.clock_origin + after,
            None => self.clock_origin - self.instant_origin.duration_since(deadline),
        };
        let deadline = Deadline::new(self.clock.clone(), at);
        Box::pin(Sleep(Mutex::new(Box::pin(
            async move { deadline.wait().await },
        ))))
    }

    fn reset(&self, sleep: &mut Pin<Box<dyn hyper::rt::Sleep>>, deadline: Instant) {
        *sleep = self.sleep_until(deadline);
    }
}
