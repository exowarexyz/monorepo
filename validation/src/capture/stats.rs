use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

/// A shared view of recorder progress that survives recorder completion or drop.
#[derive(Clone, Debug, Default)]
pub struct Statistics {
    inner: Arc<Mutex<StatisticsSnapshot>>,
}

#[derive(Clone, Debug, Default)]
pub struct StatisticsSnapshot {
    /// Accepted batches whose processing has not started, including receive handoff.
    pub queued_batches: u64,
    /// Whether the writer holds an accepted batch.
    pub writer_active: bool,
    /// Logical bytes retained by accepted queued and writer-held batches.
    pub outstanding_bytes: u64,
    pub peak_queued_batches: u64,
    pub peak_outstanding_bytes: u64,
    pub accepted_batches: u64,
    pub queue_overflows: u64,
    /// Rejections caused by the queued logical byte budget.
    pub byte_budget_overflows: u64,
    pub writer_failures: u64,
    pub publication_failures: u64,
    pub processed_batches: u64,
    pub processed_rows: u64,
    /// Successfully processed row records, excluding event metadata.
    pub processed_bytes: u64,
    /// Elapsed batch processing, including failed attempts.
    pub processing_ns: u64,
    /// Elapsed final buffer flushes for the row and event payload files.
    pub final_flush_ns: u64,
    /// Elapsed final syncs for the row and event payload files.
    pub final_sync_ns: u64,
    /// Elapsed publication attempts, including failures.
    pub publication_ns: u64,
    pub published: bool,
}

impl Statistics {
    pub fn snapshot(&self) -> StatisticsSnapshot {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(super) fn update<T>(&self, f: impl FnOnce(&mut StatisticsSnapshot) -> T) -> T {
        let mut snapshot = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut snapshot)
    }
}

pub(super) fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}
