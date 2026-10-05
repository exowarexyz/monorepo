use super::{bundle, stats::elapsed_ns, Batch, Profile, Row, Statistics};
use anyhow::{anyhow, ensure, Result};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Budget for binary row records and 16 bytes per accepted event.
    pub max_bytes: u64,
    /// Logical bytes retained by queued and writer-held batches.
    /// Includes `Vec<Row>` capacity times `size_of::<Row>()` and key/value lengths.
    /// Shared Bytes backing allocations can be larger, so this does not bound RSS.
    pub max_queued_bytes: u64,
    /// Maximum queued whole batches. The writer may hold one additional batch.
    pub queue_batches: usize,
}

#[derive(Debug)]
struct Reservation {
    outstanding: Arc<AtomicU64>,
    bytes: u64,
}

impl Reservation {
    fn acquire(outstanding: &Arc<AtomicU64>, bytes: u64, limit: u64) -> Option<Self> {
        let mut current = outstanding.load(Ordering::Relaxed);
        loop {
            let total = current.checked_add(bytes).filter(|total| *total <= limit)?;
            match outstanding.compare_exchange_weak(
                current,
                total,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        Some(Self {
            outstanding: Arc::clone(outstanding),
            bytes,
        })
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.outstanding.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct QueuedBatch {
    // Release payloads before gauges, then return capacity so new admissions cannot inflate peaks.
    batch: Batch,
    tracking: BatchTracking,
    _reservation: Reservation,
}

#[derive(Debug)]
struct BatchTracking {
    statistics: Statistics,
    bytes: u64,
    registered: bool,
    started: bool,
}

impl BatchTracking {
    fn start(&mut self) {
        self.statistics.update(|snapshot| {
            snapshot.queued_batches -= 1;
            snapshot.writer_active = true;
        });
        self.started = true;
    }
}

impl Drop for BatchTracking {
    fn drop(&mut self) {
        if self.registered {
            self.statistics.update(|snapshot| {
                if self.started {
                    snapshot.writer_active = false;
                } else {
                    snapshot.queued_batches -= 1;
                }
                snapshot.outstanding_bytes -= self.bytes;
            });
        }
    }
}

struct WriterLifecycle {
    statistics: Statistics,
    succeeded: bool,
}

impl Drop for WriterLifecycle {
    fn drop(&mut self) {
        self.statistics.update(|snapshot| {
            snapshot.writer_active = false;
            if !self.succeeded {
                snapshot.writer_failures = snapshot.writer_failures.saturating_add(1);
            }
        });
    }
}

fn queued_size(rows: &Vec<Row>) -> Result<u64> {
    let container = rows
        .capacity()
        .checked_mul(std::mem::size_of::<Row>())
        .ok_or_else(|| anyhow!("capture queue size overflow"))?;
    rows.iter()
        .try_fold(u64::try_from(container)?, |total, row| {
            let key = u64::try_from(row.key.len())?;
            let value = u64::try_from(row.value.len())?;
            total
                .checked_add(key)
                .and_then(|size| size.checked_add(value))
                .ok_or_else(|| anyhow!("capture queue size overflow"))
        })
}

fn write_batches(
    receiver: Receiver<QueuedBatch>,
    mut writer: bundle::RowWriter,
    statistics: Statistics,
) -> Result<bundle::Spool> {
    let mut lifecycle = WriterLifecycle {
        statistics,
        succeeded: false,
    };
    for mut queued in receiver {
        queued.tracking.start();
        writer.batch(&queued.batch)?;
    }
    let spool = writer.finish()?;
    lifecycle.succeeded = true;
    Ok(spool)
}

pub struct Recorder {
    path: PathBuf,
    profile: Profile,
    source: BTreeMap<String, String>,
    limits: Limits,
    start: Instant,
    accepted_bytes: u64,
    stopped: bool,
    failure: Option<String>,
    outstanding: Arc<AtomicU64>,
    statistics: Statistics,
    sender: SyncSender<QueuedBatch>,
    worker: JoinHandle<Result<bundle::Spool>>,
}

impl Recorder {
    pub fn start(
        path: impl AsRef<Path>,
        profile: Profile,
        source: BTreeMap<String, String>,
        limits: Limits,
    ) -> Result<Self> {
        ensure!(limits.max_bytes > 0, "capture byte budget must be positive");
        ensure!(
            limits.max_queued_bytes > 0,
            "capture queued byte budget must be positive"
        );
        ensure!(limits.queue_batches > 0, "capture queue must be positive");
        profile.validate()?;

        let path = path.as_ref().to_owned();
        let statistics = Statistics::default();
        let writer = bundle::RowWriter::with_statistics(&path, statistics.clone())?;
        let (sender, receiver) = mpsc::sync_channel(limits.queue_batches);
        let worker_statistics = statistics.clone();
        let worker = thread::Builder::new()
            .name("capture-recorder".into())
            .spawn(move || write_batches(receiver, writer, worker_statistics))?;
        Ok(Self {
            path,
            profile,
            source,
            limits,
            start: Instant::now(),
            accepted_bytes: 0,
            stopped: false,
            failure: None,
            outstanding: Arc::new(AtomicU64::new(0)),
            statistics,
            sender,
            worker,
        })
    }

    pub fn statistics(&self) -> Statistics {
        self.statistics.clone()
    }

    fn invalidate<T>(&mut self, error: impl std::fmt::Display) -> Result<T> {
        let message = error.to_string();
        self.failure = Some(message.clone());
        Err(anyhow!(message))
    }

    /// Records one whole logical issue before any request retries.
    pub fn record(&mut self, rows: Vec<Row>) -> Result<bool> {
        if let Some(failure) = &self.failure {
            return Err(anyhow!(failure.clone()));
        }
        if self.stopped {
            return Ok(false);
        }
        let offset_ns = match u64::try_from(self.start.elapsed().as_nanos()) {
            Ok(offset) => offset,
            Err(error) => return self.invalidate(error),
        };
        let size = match bundle::encoded_size(&rows) {
            Ok(size) => size,
            Err(error) => return self.invalidate(error),
        };
        if size > self.limits.max_bytes {
            return self.invalidate("capture batch exceeds byte budget");
        }
        if size > self.limits.max_bytes - self.accepted_bytes {
            self.stopped = true;
            return Ok(false);
        }
        let queued_bytes = match queued_size(&rows) {
            Ok(size) => size,
            Err(error) => return self.invalidate(error),
        };
        let Some(reservation) = Reservation::acquire(
            &self.outstanding,
            queued_bytes,
            self.limits.max_queued_bytes,
        ) else {
            self.statistics.update(|snapshot| {
                snapshot.byte_budget_overflows = snapshot.byte_budget_overflows.saturating_add(1);
            });
            return self.invalidate("capture queued byte budget exceeded");
        };
        let queued = QueuedBatch {
            batch: Batch { offset_ns, rows },
            _reservation: reservation,
            tracking: BatchTracking {
                statistics: self.statistics.clone(),
                bytes: queued_bytes,
                registered: true,
                started: false,
            },
        };

        // Registration and receive handoff share a lock so teardown cannot run first.
        let result = self.statistics.update(|snapshot| {
            let sent = self.sender.try_send(queued);
            if sent.is_ok() {
                snapshot.queued_batches += 1;
                snapshot.outstanding_bytes += queued_bytes;
                snapshot.accepted_batches = snapshot.accepted_batches.saturating_add(1);
                snapshot.peak_queued_batches =
                    snapshot.peak_queued_batches.max(snapshot.queued_batches);
                snapshot.peak_outstanding_bytes = snapshot
                    .peak_outstanding_bytes
                    .max(snapshot.outstanding_bytes);
            } else if matches!(&sent, Err(TrySendError::Full(_))) {
                snapshot.queue_overflows = snapshot.queue_overflows.saturating_add(1);
            }
            sent
        });
        match result {
            Ok(()) => {
                self.accepted_bytes += size;
                Ok(true)
            }
            Err(TrySendError::Full(mut queued)) => {
                queued.tracking.registered = false;
                drop(queued);
                self.invalidate("capture queue is full")
            }
            Err(TrySendError::Disconnected(mut queued)) => {
                queued.tracking.registered = false;
                drop(queued);
                self.invalidate("capture writer stopped")
            }
        }
    }

    pub fn finish(self, repeat_period: Duration) -> Result<()> {
        drop(self.sender);
        let spool = self
            .worker
            .join()
            .map_err(|_| anyhow!("capture writer panicked"))??;
        if let Some(failure) = self.failure {
            return Err(anyhow!(failure));
        }
        let repeat_period_ns = match u64::try_from(repeat_period.as_nanos()) {
            Ok(period) => period,
            Err(error) => {
                self.statistics.update(|snapshot| {
                    snapshot.publication_failures = snapshot.publication_failures.saturating_add(1);
                });
                return Err(error.into());
            }
        };
        let started = Instant::now();
        let published = bundle::publish(
            &self.path,
            &self.profile,
            self.source,
            repeat_period_ns,
            spool,
        );
        let publication_ns = elapsed_ns(started);
        self.statistics.update(|snapshot| {
            snapshot.publication_ns = snapshot.publication_ns.saturating_add(publication_ns);
            if published.is_ok() {
                snapshot.published = true;
            } else {
                snapshot.publication_failures = snapshot.publication_failures.saturating_add(1);
            }
        });
        published
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{
        bundle::tests::row, Bundle, Domain, Endian, Family, Offset, Patch, Target,
    };
    use bytes::Bytes;
    use std::{fs, sync::atomic::AtomicBool};
    use tempfile::tempdir;

    fn profile() -> Profile {
        Profile {
            version: 1,
            domains: BTreeMap::from([("id".into(), Domain::Numeric { width: 1 })]),
            families: vec![Family {
                id: 7,
                name: "rows".into(),
                key_prefix_hex: "aa".into(),
                fresh_key: 0,
                patches: vec![Patch {
                    target: Target::Key,
                    offset: Offset::Start(1),
                    domain: "id".into(),
                    endian: Endian::Big,
                }],
            }],
        }
    }

    fn limits() -> Limits {
        Limits {
            max_bytes: 1024,
            max_queued_bytes: 4096,
            queue_batches: 8,
        }
    }

    fn queued(batch: Batch, outstanding: &Arc<AtomicU64>, limit: u64) -> QueuedBatch {
        queued_with_statistics(batch, outstanding, limit, Statistics::default())
    }

    fn queued_with_statistics(
        batch: Batch,
        outstanding: &Arc<AtomicU64>,
        limit: u64,
        statistics: Statistics,
    ) -> QueuedBatch {
        let bytes = queued_size(&batch.rows).unwrap();
        let reservation = Reservation::acquire(outstanding, bytes, limit).unwrap();
        statistics.update(|snapshot| {
            snapshot.queued_batches += 1;
            snapshot.outstanding_bytes += bytes;
            snapshot.accepted_batches += 1;
            snapshot.peak_queued_batches =
                snapshot.peak_queued_batches.max(snapshot.queued_batches);
            snapshot.peak_outstanding_bytes = snapshot
                .peak_outstanding_bytes
                .max(snapshot.outstanding_bytes);
        });
        QueuedBatch {
            batch,
            _reservation: reservation,
            tracking: BatchTracking {
                statistics,
                bytes,
                registered: true,
                started: false,
            },
        }
    }

    struct TrackedPayload {
        bytes: Vec<u8>,
        outstanding: Arc<AtomicU64>,
        statistics: Statistics,
        dropped: Arc<AtomicBool>,
    }

    impl AsRef<[u8]> for TrackedPayload {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for TrackedPayload {
        fn drop(&mut self) {
            assert!(self.outstanding.load(Ordering::Relaxed) > 0);
            assert!(self.statistics.snapshot().outstanding_bytes > 0);
            self.dropped.store(true, Ordering::Relaxed);
        }
    }

    #[test]
    fn queue_accounting_includes_spare_row_capacity_and_logical_slices() {
        let backing = Bytes::from(vec![0; 1024]);
        let mut rows = Vec::with_capacity(32);
        rows.push(Row {
            family: 7,
            key: backing.slice(..1),
            value: backing.slice(1..6),
        });
        assert_eq!(
            queued_size(&rows).unwrap(),
            (rows.capacity() * std::mem::size_of::<Row>()) as u64 + 6
        );
        let outstanding = Arc::new(AtomicU64::new(0));
        assert!(Reservation::acquire(&outstanding, u64::MAX, u64::MAX).is_some());
        let held = Reservation::acquire(&outstanding, u64::MAX, u64::MAX).unwrap();
        assert!(Reservation::acquire(&outstanding, 1, u64::MAX).is_none());
        drop(held);
        assert_eq!(outstanding.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn writer_held_bytes_remain_reserved_until_payload_references_drop() {
        let temp = tempdir().unwrap();
        let outstanding = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let statistics = Statistics::default();
        let tracked = Row {
            family: 7,
            key: Bytes::from_static(b"key"),
            value: Bytes::from_owner(TrackedPayload {
                bytes: b"value".to_vec(),
                outstanding: Arc::clone(&outstanding),
                statistics: statistics.clone(),
                dropped: Arc::clone(&dropped),
            }),
        };
        let batch = Batch {
            offset_ns: 0,
            rows: vec![tracked],
        };
        let limit = queued_size(&batch.rows).unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .try_send(queued_with_statistics(
                batch,
                &outstanding,
                limit,
                statistics.clone(),
            ))
            .unwrap();
        let mut held = receiver.recv().unwrap();
        assert_eq!(statistics.snapshot().queued_batches, 1);
        held.tracking.start();
        assert_eq!(statistics.snapshot().queued_batches, 0);
        assert!(statistics.snapshot().writer_active);
        assert_eq!(statistics.snapshot().outstanding_bytes, limit);
        assert_eq!(outstanding.load(Ordering::Relaxed), limit);
        assert!(Reservation::acquire(&outstanding, limit, limit).is_none());

        let path = temp.path().join("capture");
        let mut writer = bundle::RowWriter::with_statistics(&path, statistics.clone()).unwrap();
        writer.batch(&held.batch).unwrap();
        assert_eq!(outstanding.load(Ordering::Relaxed), limit);
        assert!(!dropped.load(Ordering::Relaxed));
        drop(held);
        assert!(dropped.load(Ordering::Relaxed));
        assert_eq!(outstanding.load(Ordering::Relaxed), 0);
        assert_eq!(statistics.snapshot().outstanding_bytes, 0);
        assert!(!statistics.snapshot().writer_active);
        let batch = Batch {
            offset_ns: 1,
            rows: vec![row(2)],
        };
        sender
            .try_send(queued_with_statistics(
                batch,
                &outstanding,
                limit,
                statistics.clone(),
            ))
            .unwrap();
        let mut held = receiver.recv().unwrap();
        held.tracking.start();
        writer.batch(&held.batch).unwrap();
        drop(held);
        assert_eq!(outstanding.load(Ordering::Relaxed), 0);
        bundle::publish(
            &path,
            &profile(),
            BTreeMap::new(),
            2,
            writer.finish().unwrap(),
        )
        .unwrap();
        assert_eq!(Bundle::read(&path).unwrap().batches.len(), 2);
    }

    #[test]
    fn receiver_cleanup_preserves_the_writer_held_batch() {
        let outstanding = Arc::new(AtomicU64::new(0));
        let statistics = Statistics::default();
        let (sender, receiver) = mpsc::sync_channel(1);
        let batch = Batch {
            offset_ns: 0,
            rows: vec![row(1)],
        };
        let bytes = queued_size(&batch.rows).unwrap();
        sender
            .try_send(queued_with_statistics(
                batch.clone(),
                &outstanding,
                4096,
                statistics.clone(),
            ))
            .unwrap();
        let mut held = receiver.recv().unwrap();
        held.tracking.start();
        sender
            .try_send(queued_with_statistics(
                batch,
                &outstanding,
                4096,
                statistics.clone(),
            ))
            .unwrap();
        let snapshot = statistics.snapshot();
        assert_eq!(snapshot.accepted_batches, 2);
        assert_eq!(snapshot.queued_batches, 1);
        assert!(snapshot.writer_active);
        assert_eq!(snapshot.outstanding_bytes, 2 * bytes);
        assert_eq!(snapshot.peak_queued_batches, 1);
        assert_eq!(snapshot.peak_outstanding_bytes, 2 * bytes);
        drop(receiver);
        let snapshot = statistics.snapshot();
        assert_eq!(snapshot.queued_batches, 0);
        assert!(snapshot.writer_active);
        assert_eq!(snapshot.outstanding_bytes, bytes);
        assert_eq!(outstanding.load(Ordering::Relaxed), bytes);
        drop(held);
        let snapshot = statistics.snapshot();
        assert_eq!(snapshot.outstanding_bytes, 0);
        assert!(!snapshot.writer_active);
        assert_eq!(outstanding.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn recorder_byte_limit_includes_the_background_writer_batch() {
        struct HeldPayload {
            entered: SyncSender<()>,
            release: Receiver<()>,
        }

        impl AsRef<[u8]> for HeldPayload {
            fn as_ref(&self) -> &[u8] {
                b"value"
            }
        }

        impl Drop for HeldPayload {
            fn drop(&mut self) {
                self.entered.send(()).unwrap();
                self.release.recv_timeout(Duration::from_secs(10)).unwrap();
            }
        }

        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let mut held = row(1);
        held.value = Bytes::from_owner(HeldPayload {
            entered: entered_sender,
            release: release_receiver,
        });
        let rows = vec![held];
        let limit = queued_size(&rows).unwrap();
        let mut limits = limits();
        limits.max_queued_bytes = limit;
        let mut recorder = Recorder::start(&path, profile(), BTreeMap::new(), limits).unwrap();
        let outstanding = Arc::clone(&recorder.outstanding);
        let statistics = recorder.statistics();
        assert!(recorder.record(rows).unwrap());
        entered_receiver
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
        assert_eq!(outstanding.load(Ordering::Relaxed), limit);
        let snapshot = statistics.snapshot();
        assert_eq!(snapshot.queued_batches, 0);
        assert!(snapshot.writer_active);
        assert_eq!(snapshot.outstanding_bytes, limit);
        assert!(recorder.record(vec![row(2)]).is_err());
        release_sender.send(()).unwrap();
        assert!(recorder.finish(Duration::from_secs(60)).is_err());
        assert_eq!(outstanding.load(Ordering::Relaxed), 0);
        let snapshot = statistics.snapshot();
        assert_eq!(snapshot.byte_budget_overflows, 1);
        assert_eq!(snapshot.accepted_batches, 1);
        assert_eq!(snapshot.peak_outstanding_bytes, limit);
        assert_eq!(snapshot.queued_batches, 0);
        assert_eq!(snapshot.outstanding_bytes, 0);
        assert!(!snapshot.writer_active);
        assert!(!path.join("manifest.json").exists());
    }

    #[test]
    fn writer_errors_release_current_and_queued_reservations() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        let outstanding = Arc::new(AtomicU64::new(0));
        let statistics = Statistics::default();
        let (sender, receiver) = mpsc::sync_channel(3);
        for offset_ns in [1, 0, 2] {
            sender
                .try_send(queued_with_statistics(
                    Batch {
                        offset_ns,
                        rows: vec![row(1)],
                    },
                    &outstanding,
                    4096,
                    statistics.clone(),
                ))
                .unwrap();
        }
        drop(sender);
        assert!(write_batches(
            receiver,
            bundle::RowWriter::with_statistics(&path, statistics.clone()).unwrap(),
            statistics.clone(),
        )
        .is_err());
        assert_eq!(outstanding.load(Ordering::Relaxed), 0);
        assert!(!path.join("manifest.json").exists());
        assert!(Bundle::read(&path).is_err());
        let snapshot = statistics.snapshot();
        assert_eq!(snapshot.accepted_batches, 3);
        assert_eq!(snapshot.processed_batches, 1);
        assert_eq!(snapshot.writer_failures, 1);
        assert_eq!(snapshot.publication_failures, 0);
        assert_eq!(snapshot.queued_batches, 0);
        assert_eq!(snapshot.outstanding_bytes, 0);
        assert!(!snapshot.writer_active);
        assert!(!snapshot.published);
    }

    #[test]
    fn empty_capture_counts_publication_failure() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        let recorder = Recorder::start(&path, profile(), BTreeMap::new(), limits()).unwrap();
        let statistics = recorder.statistics();
        assert!(recorder.finish(Duration::from_secs(60)).is_err());
        let snapshot = statistics.snapshot();
        assert_eq!(snapshot.writer_failures, 0);
        assert_eq!(snapshot.publication_failures, 1);
        assert_eq!(snapshot.outstanding_bytes, 0);
        assert!(!snapshot.writer_active);
        assert!(!snapshot.published);
    }

    #[test]
    fn writer_panics_release_gauges_and_count_one_failure() {
        struct PanickingPayload;

        impl AsRef<[u8]> for PanickingPayload {
            fn as_ref(&self) -> &[u8] {
                b"value"
            }
        }

        impl Drop for PanickingPayload {
            fn drop(&mut self) {
                panic!("injected payload teardown failure");
            }
        }

        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        let mut recorder = Recorder::start(&path, profile(), BTreeMap::new(), limits()).unwrap();
        let statistics = recorder.statistics();
        let outstanding = Arc::clone(&recorder.outstanding);
        let mut captured = row(1);
        captured.value = Bytes::from_owner(PanickingPayload);
        assert!(recorder.record(vec![captured]).unwrap());
        assert!(recorder.finish(Duration::from_secs(60)).is_err());
        let snapshot = statistics.snapshot();
        assert_eq!(snapshot.accepted_batches, 1);
        assert_eq!(snapshot.writer_failures, 1);
        assert_eq!(snapshot.publication_failures, 0);
        assert_eq!(snapshot.queued_batches, 0);
        assert_eq!(snapshot.outstanding_bytes, 0);
        assert_eq!(outstanding.load(Ordering::Relaxed), 0);
        assert!(!snapshot.writer_active);
        assert!(!snapshot.published);
    }

    #[test]
    fn statistics_survive_recorder_drop_and_receiver_cleanup() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        let mut recorder = Recorder::start(&path, profile(), BTreeMap::new(), limits()).unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        recorder.sender = sender;
        let statistics = recorder.statistics();
        assert!(recorder.record(vec![row(1)]).unwrap());
        drop(recorder);
        let snapshot = statistics.snapshot();
        assert_eq!(snapshot.accepted_batches, 1);
        assert_eq!(snapshot.queued_batches, 1);
        assert!(snapshot.outstanding_bytes > 0);
        assert!(!snapshot.published);
        drop(receiver);
        let snapshot = statistics.snapshot();
        assert_eq!(snapshot.accepted_batches, 1);
        assert_eq!(snapshot.queued_batches, 0);
        assert_eq!(snapshot.outstanding_bytes, 0);
        assert!(!snapshot.published);
    }

    #[test]
    fn closed_queue_drains_every_accepted_batch_before_publication() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        let outstanding = Arc::new(AtomicU64::new(0));
        let (sender, receiver) = mpsc::sync_channel(8);
        let batches: Vec<_> = (0..8)
            .map(|offset_ns| Batch {
                offset_ns,
                rows: vec![row(1), row(1), row(offset_ns as u8)],
            })
            .collect();
        for batch in &batches {
            sender
                .try_send(queued(batch.clone(), &outstanding, 4096))
                .unwrap();
        }
        assert!(outstanding.load(Ordering::Relaxed) > 0);
        drop(sender);
        let spool = write_batches(
            receiver,
            bundle::RowWriter::new(&path).unwrap(),
            Statistics::default(),
        )
        .unwrap();
        assert_eq!(outstanding.load(Ordering::Relaxed), 0);
        assert!(!path.join("manifest.json").exists());
        bundle::publish(&path, &profile(), BTreeMap::new(), 8, spool).unwrap();
        assert_eq!(Bundle::read(&path).unwrap().batches, batches);
    }

    #[test]
    fn queued_byte_exhaustion_invalidates_whole_sample() {
        for spare_capacity in [false, true] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("capture");
            let mut recorder =
                Recorder::start(&path, profile(), BTreeMap::new(), limits()).unwrap();
            let (sender, receiver) = mpsc::sync_channel(8);
            recorder.sender = sender;
            recorder.limits.max_queued_bytes = queued_size(&vec![row(1)]).unwrap();
            if spare_capacity {
                let mut rows = Vec::with_capacity(32);
                rows.push(row(1));
                assert!(recorder.record(rows).is_err());
                assert_eq!(recorder.outstanding.load(Ordering::Relaxed), 0);
            } else {
                assert!(recorder.record(vec![row(1)]).unwrap());
                let held = receiver.recv().unwrap();
                assert!(recorder.record(vec![row(2)]).is_err());
                drop(held);
                assert_eq!(recorder.outstanding.load(Ordering::Relaxed), 0);
            }
            assert!(recorder.record(vec![row(3)]).is_err());
            assert!(recorder.finish(Duration::from_secs(60)).is_err());
            assert!(!path.join("manifest.json").exists());
        }
    }

    #[test]
    fn start_validates_declarations_before_creating_output() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        let mut invalid = profile();
        invalid.version = 2;
        assert!(Recorder::start(&path, invalid, BTreeMap::new(), limits()).is_err());
        assert!(!path.exists());
        for field in 0..3 {
            let mut invalid = limits();
            match field {
                0 => invalid.max_bytes = 0,
                1 => invalid.max_queued_bytes = 0,
                2 => invalid.queue_batches = 0,
                _ => unreachable!(),
            }
            assert!(Recorder::start(&path, profile(), BTreeMap::new(), invalid).is_err());
            assert!(!path.exists());
        }

        let mut declared = profile();
        declared
            .domains
            .insert("unused".into(), Domain::Identity { width: 32 });
        let mut unused = declared.families[0].clone();
        unused.id = 8;
        unused.name = "unused".into();
        unused.key_prefix_hex = "bb".into();
        declared.families.push(unused);
        let mut recorder = Recorder::start(&path, declared, BTreeMap::new(), limits()).unwrap();
        assert!(recorder.record(vec![row(1)]).unwrap());
        recorder.finish(Duration::from_secs(60)).unwrap();
        assert!(Bundle::read(&path).is_ok());
    }

    #[test]
    fn finish_publishes_drained_batches_and_issue_offsets() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        let source = BTreeMap::from([("producer".into(), "test".into())]);
        let mut recorder = Recorder::start(&path, profile(), source.clone(), limits()).unwrap();
        let statistics = recorder.statistics();
        let processed_bytes = bundle::encoded_size(&[row(1), row(2)]).unwrap()
            + bundle::encoded_size(&[row(3)]).unwrap()
            - 2 * bundle::EVENT_HEADER_BYTES;
        assert!(recorder.record(vec![row(1), row(2)]).unwrap());
        assert!(recorder.record(vec![row(3)]).unwrap());
        assert!(!path.join("manifest.json").exists());
        recorder.finish(Duration::from_secs(60)).unwrap();
        let bundle = Bundle::read(&path).unwrap();
        assert_eq!(bundle.batches.len(), 2);
        assert_eq!(bundle.batches[0].rows, vec![row(1), row(2)]);
        assert_eq!(bundle.batches[1].rows, vec![row(3)]);
        assert!(bundle.batches[0].offset_ns <= bundle.batches[1].offset_ns);
        assert_eq!(bundle.source, source);
        let snapshot = statistics.snapshot();
        assert_eq!(snapshot.accepted_batches, 2);
        assert_eq!(snapshot.processed_batches, 2);
        assert_eq!(snapshot.processed_rows, 3);
        assert_eq!(snapshot.processed_bytes, processed_bytes);
        assert_eq!(snapshot.queued_batches, 0);
        assert_eq!(snapshot.outstanding_bytes, 0);
        assert!(!snapshot.writer_active);
        assert_eq!(snapshot.writer_failures, 0);
        assert_eq!(snapshot.publication_failures, 0);
        assert!(snapshot.published);
    }

    #[test]
    fn budget_stop_keeps_whole_prefix_and_is_permanent() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        let first = vec![row(1), row(2)];
        let max_bytes =
            bundle::encoded_size(&first).unwrap() + bundle::encoded_size(&[row(3)]).unwrap();
        let mut recorder = Recorder::start(
            &path,
            profile(),
            BTreeMap::new(),
            Limits {
                max_bytes,
                max_queued_bytes: 4096,
                queue_batches: 8,
            },
        )
        .unwrap();
        assert!(recorder.record(first.clone()).unwrap());
        assert!(!recorder.record(vec![row(3), row(4)]).unwrap());
        assert!(!recorder.record(vec![row(3)]).unwrap());
        recorder.finish(Duration::from_secs(60)).unwrap();
        let bundle = Bundle::read(&path).unwrap();
        assert_eq!(bundle.batches.len(), 1);
        assert_eq!(bundle.batches[0].rows, first);
    }

    #[test]
    fn oversized_or_invalid_batch_invalidates_finish() {
        for oversized in [true, false] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("capture");
            let mut recorder = Recorder::start(
                &path,
                profile(),
                BTreeMap::new(),
                Limits {
                    max_bytes: 64,
                    max_queued_bytes: 4096,
                    queue_batches: 8,
                },
            )
            .unwrap();
            assert!(recorder.record(vec![row(1)]).unwrap());
            let invalid = if oversized {
                vec![row(2), row(3)]
            } else {
                Vec::new()
            };
            assert!(recorder.record(invalid).is_err());
            assert!(recorder.record(vec![row(4)]).is_err());
            assert!(recorder.finish(Duration::from_secs(60)).is_err());
            assert!(!path.join("manifest.json").exists());
            assert!(Bundle::read(&path).is_err());
        }
    }

    #[test]
    fn drop_empty_finish_and_invalid_period_leave_incomplete_capture() {
        for action in 0..4 {
            let temp = tempdir().unwrap();
            let path = temp.path().join("capture");
            let mut recorder =
                Recorder::start(&path, profile(), BTreeMap::new(), limits()).unwrap();
            match action {
                0 => {
                    assert!(recorder.record(vec![row(1)]).unwrap());
                    drop(recorder);
                }
                1 => assert!(recorder.finish(Duration::from_secs(60)).is_err()),
                2 => {
                    assert!(recorder.record(vec![row(1)]).unwrap());
                    assert!(recorder.finish(Duration::ZERO).is_err());
                }
                3 => {
                    recorder.start = Instant::now() - Duration::from_secs(2);
                    assert!(recorder.record(vec![row(1)]).unwrap());
                    assert!(recorder.finish(Duration::from_secs(1)).is_err());
                }
                _ => unreachable!(),
            }
            assert!(!path.join("manifest.json").exists());
            assert!(Bundle::read(&path).is_err());
        }
    }

    #[test]
    fn full_or_disconnected_queue_invalidates_finish() {
        for disconnected in [false, true] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("capture");
            let mut recorder =
                Recorder::start(&path, profile(), BTreeMap::new(), limits()).unwrap();
            let (sender, receiver) = mpsc::sync_channel(1);
            recorder.sender = sender;
            let statistics = recorder.statistics();
            if disconnected {
                drop(receiver);
                assert!(recorder.record(vec![row(1)]).is_err());
                assert_eq!(recorder.outstanding.load(Ordering::Relaxed), 0);
                let snapshot = statistics.snapshot();
                assert_eq!(snapshot.accepted_batches, 0);
                assert_eq!(snapshot.peak_queued_batches, 0);
                assert_eq!(snapshot.peak_outstanding_bytes, 0);
                assert_eq!(snapshot.queue_overflows, 0);
            } else {
                assert!(recorder.record(vec![row(1)]).unwrap());
                let reserved = recorder.outstanding.load(Ordering::Relaxed);
                assert!(recorder.record(vec![row(2)]).is_err());
                assert_eq!(recorder.outstanding.load(Ordering::Relaxed), reserved);
                let snapshot = statistics.snapshot();
                assert_eq!(snapshot.accepted_batches, 1);
                assert_eq!(snapshot.queued_batches, 1);
                assert_eq!(snapshot.outstanding_bytes, reserved);
                assert_eq!(snapshot.peak_queued_batches, 1);
                assert_eq!(snapshot.peak_outstanding_bytes, reserved);
                assert_eq!(snapshot.queue_overflows, 1);
                drop(receiver);
                assert_eq!(recorder.outstanding.load(Ordering::Relaxed), 0);
            }
            assert_eq!(statistics.snapshot().queued_batches, 0);
            assert_eq!(statistics.snapshot().outstanding_bytes, 0);
            assert!(recorder.finish(Duration::from_secs(60)).is_err());
            assert!(!path.join("manifest.json").exists());
        }
    }

    #[test]
    fn publication_failure_does_not_create_manifest() {
        for occupied in ["profile.json", "manifest.json"] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("capture");
            let mut recorder =
                Recorder::start(&path, profile(), BTreeMap::new(), limits()).unwrap();
            let statistics = recorder.statistics();
            assert!(recorder.record(vec![row(1)]).unwrap());
            fs::write(path.join(occupied), b"occupied").unwrap();
            assert!(recorder.finish(Duration::from_secs(60)).is_err());
            assert_eq!(fs::read(path.join(occupied)).unwrap(), b"occupied");
            assert!(Bundle::read(&path).is_err());
            let snapshot = statistics.snapshot();
            assert_eq!(snapshot.publication_failures, 1);
            assert_eq!(snapshot.writer_failures, 0);
            assert!(!snapshot.published);
        }
    }
}
