//! Shared execution scaffolding for multi-worker commands.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::MissedTickBehavior;

/// Point-in-time completion numbers handed to a command's progress logger.
pub(crate) struct Progress {
    pub done: u64,
    pub elapsed_secs: f64,
    pub per_sec: f64,
    pub percent: f64,
}

/// Spawns a periodic progress logger over a completion counter (`interval_secs == 0` disables).
///
/// The immediate first tick is swallowed so the first log lands one full interval into the
/// run, and missed ticks are skipped so a stalled runtime does not burst logs on recovery.
pub(crate) fn spawn_progress_task(
    counter: Arc<AtomicU64>,
    total: u64,
    interval_secs: u64,
    start: Instant,
    log: impl Fn(&Progress) + Send + 'static,
) -> Option<JoinHandle<()>> {
    if interval_secs == 0 {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            let done = counter.load(Ordering::Relaxed);
            if done >= total {
                break;
            }
            let elapsed_secs = start.elapsed().as_secs_f64();
            let per_sec = if elapsed_secs > 0.0 {
                done as f64 / elapsed_secs
            } else {
                0.0
            };
            let percent = (done as f64 / total as f64 * 100.0).min(100.0);
            log(&Progress {
                done,
                elapsed_secs,
                per_sec,
                percent,
            });
        }
    }))
}

pub(crate) async fn stop_progress_task(task: Option<JoinHandle<()>>) {
    if let Some(task) = task {
        task.abort();
        let _ = task.await;
    }
}

/// Drains a worker set, aborting and reaping every remaining worker after the
/// first failure so no task outlives its run.
pub(crate) async fn join_all_or_abort<T: 'static>(
    workers: &mut JoinSet<anyhow::Result<T>>,
    context: &str,
    mut on_ok: impl FnMut(T),
) -> anyhow::Result<()> {
    while let Some(result) = workers.join_next().await {
        let result = result
            .map_err(|err| anyhow!("{context} task failed: {err}"))
            .and_then(|worker_result| worker_result);
        match result {
            Ok(value) => on_ok(value),
            Err(err) => {
                workers.abort_all();
                while workers.join_next().await.is_some() {}
                return Err(err);
            }
        }
    }
    Ok(())
}
