//! Naive reference storage for local development: user keys and values are written as-is to
//! RocksDB. A `meta` column family stores the monotonically increasing sequence number for RPCs.
//! A separate `log` column family keeps per-sequence-number batch payloads so the stream service
//! can serve replay and point lookups. Batch-log pruning is driven exclusively by the compact
//! service's `Sequence` scope.
//!
//! Durability is anchored on the replay log: each commit group makes its log rows plus the
//! durable-sequence meta row durable first (one synced batch for small groups; an ingested SST
//! file followed by a synced meta write for large ones), then the current-state rows are applied
//! without a WAL and the visible sequence frontier advances. The state rows are recovered from
//! the log, so `open` replays retained log rows above the persisted state-flushed watermark, and
//! pruning flushes the default column family (advancing that watermark) before deleting log rows
//! it may otherwise still need for recovery.

use std::cmp::Ordering as CmpOrdering;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use buffa::MessageView;
use bytes::Bytes;
use exoware_sdk::keys::KeyCodec;
use exoware_sdk::log::stream::v1::GetResponseView as StreamGetResponseView;
use exoware_sdk::prune_policy::{
    KeysScope, OrderEncoding, PolicyScope, PrunePolicyDocument, RetainPolicy,
};
use exoware_sdk::selector::compile_payload_regex;
use exoware_server::{
    Ingest, Log, LogBatch, Prune, Query, QueryExtra, RangeScan, RangeScanBatch, Sequence,
};
use regex::bytes::Regex;
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DBCompressionType, DBIterator, Direction,
    IngestExternalFileOptions, IteratorMode, Options, SstFileWriter, WriteOptions, DB,
};
use tokio::sync::oneshot;
use tracing::debug;

const META_CF: &str = "meta";
const SEQ_META_KEY: &[u8] = b"sequence";
/// Highest sequence whose current-state rows are durable in the default column family (flushed to
/// SSTs). Recovery replays retained log rows above this watermark to rebuild the state rows that
/// were applied without a WAL.
const STATE_FLUSHED_META_KEY: &[u8] = b"state_flushed_sequence";
const LOG_CF: &str = "log";
const LOG_BATCH_KEY_LEN: usize = 8;
const PRUNE_SCAN_BATCH_SIZE: usize = 4096;
const DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;
/// Directory under the store path where log SST files are staged before ingestion.
const LOG_INGEST_DIR: &str = "ingest";
/// Minimum accumulated log payload before a commit group's log rows are written as an ingested
/// SST file instead of a WAL-backed batch. Ingested rows reach the disk once, while WAL-backed
/// rows are written twice (WAL now, SST on flush), so large groups ingest and small groups keep
/// the cheaper single-fsync WAL commit.
const LOG_INGEST_MIN_BYTES: usize = 4 * 1024 * 1024;
type RocksIterItem = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>;

/// Owns the DB handle for a RocksDB iterator that is moved through blocking tasks.
struct OwnedRocksIterator {
    iter: DBIterator<'static>,
    _db: Arc<DB>,
}

impl OwnedRocksIterator {
    /// Creates a RocksDB iterator whose borrowed DB handle is kept alive by the wrapper.
    fn new(db: Arc<DB>, mode: IteratorMode<'_>) -> Self {
        // SAFETY: `iter` is dropped before `db` because fields are dropped in
        // declaration order. The RocksDB iterator therefore cannot outlive the
        // Arc-owned DB it borrows.
        let db_ref: &'static DB = unsafe { &*Arc::as_ptr(&db) };
        let iter = db_ref.iterator(mode);
        Self { iter, _db: db }
    }

    /// Advances the wrapped RocksDB iterator without exposing its borrowed lifetime.
    fn next(&mut self) -> Option<RocksIterItem> {
        self.iter.next()
    }
}

struct RocksRangeScanState {
    iterator: OwnedRocksIterator,
    start: Bytes,
    end: Bytes,
    limit: usize,
    forward: bool,
    emitted: usize,
    done: bool,
}

impl RocksRangeScanState {
    /// Creates an iterator positioned at the first row that may belong to the requested range.
    fn new(db: Arc<DB>, start: Bytes, end: Bytes, limit: usize, forward: bool) -> Self {
        let mode = if forward {
            IteratorMode::From(start.as_ref(), Direction::Forward)
        } else if end.is_empty() {
            IteratorMode::End
        } else {
            IteratorMode::From(end.as_ref(), Direction::Reverse)
        };
        Self {
            iterator: OwnedRocksIterator::new(db, mode),
            start,
            end,
            limit,
            forward,
            emitted: 0,
            done: limit == 0,
        }
    }

    /// Reads one page from the existing RocksDB iterator and stops at the range or item limit.
    fn next_batch(&mut self, max_items: usize) -> Result<Vec<(Bytes, Bytes)>, String> {
        if max_items == 0 || self.done {
            return Ok(Vec::new());
        }

        let mut batch = Vec::new();
        while batch.len() < max_items && !self.done {
            let Some(item) = self.iterator.next() else {
                self.done = true;
                break;
            };
            let (key, value) = match item {
                Ok(row) => row,
                Err(e) => {
                    self.done = true;
                    return Err(e.to_string());
                }
            };
            let key_ref = key.as_ref();
            if self.forward {
                if !self.end.is_empty() && key_ref > self.end.as_ref() {
                    self.done = true;
                    break;
                }
            } else if key_ref < self.start.as_ref() {
                self.done = true;
                break;
            }

            self.emitted += 1;
            if self.emitted >= self.limit {
                self.done = true;
            }
            batch.push((
                Bytes::copy_from_slice(key_ref),
                Bytes::copy_from_slice(value.as_ref()),
            ));
        }
        Ok(batch)
    }
}

pub struct RocksRangeScanCursor {
    state: Option<RocksRangeScanState>,
}

impl RocksRangeScanCursor {
    /// Stores scan state in an `Option` so it can be moved into `spawn_blocking` per page.
    fn new(db: Arc<DB>, start: Bytes, end: Bytes, limit: usize, forward: bool) -> Self {
        Self {
            state: Some(RocksRangeScanState::new(db, start, end, limit, forward)),
        }
    }
}

impl RangeScan for RocksRangeScanCursor {
    async fn next_batch(&mut self, max_items: usize) -> Result<RangeScanBatch, String> {
        let Some(mut state) = self.state.take() else {
            return Ok(RangeScanBatch::default());
        };
        let (state, result) = tokio::task::spawn_blocking(move || {
            let result = state.next_batch(max_items);
            (state, result)
        })
        .await
        .map_err(|e| format!("range scan task failed: {e}"))?;
        self.state = Some(state);
        result.map(|rows| RangeScanBatch {
            rows,
            extra: QueryExtra::default(),
        })
    }
}

struct KeyEntry {
    key: Bytes,
    order_value: Vec<u8>,
}

/// Extracts the per-key ordering value used to decide which matching keys a prune policy retains.
fn extract_order_value(payload: &[u8], regex: &Regex, scope: &KeysScope) -> Option<Vec<u8>> {
    let order_by = scope.order_by.as_ref()?;
    let captures = regex.captures(payload)?;
    let matched = captures.name(&order_by.capture_group)?;
    let raw = matched.as_bytes();
    match order_by.encoding {
        OrderEncoding::BytesAsc => Some(raw.to_vec()),
        OrderEncoding::U64Be | OrderEncoding::I64Be => {
            if raw.len() == 8 {
                Some(raw.to_vec())
            } else {
                None
            }
        }
    }
}

/// Builds the grouping key that scopes retention independently within a key prune policy.
fn extract_group_key(payload: &[u8], regex: &Regex, scope: &KeysScope) -> Option<Vec<u8>> {
    if scope.group_by.capture_groups.is_empty() {
        return Some(Vec::new());
    }
    let captures = regex.captures(payload)?;
    let mut group_key = Vec::new();
    for group_name in &scope.group_by.capture_groups {
        let matched = captures.name(group_name)?;
        let bytes = matched.as_bytes();
        group_key.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        group_key.extend_from_slice(bytes);
    }
    Some(group_key)
}

/// Compares captured policy order values according to the encoding declared by the key scope.
fn compare_order_values(a: &[u8], b: &[u8], scope: &KeysScope) -> CmpOrdering {
    match scope.order_by.as_ref().map(|o| &o.encoding) {
        Some(OrderEncoding::U64Be) => {
            let a_val = a.try_into().map(u64::from_be_bytes).unwrap_or(0);
            let b_val = b.try_into().map(u64::from_be_bytes).unwrap_or(0);
            a_val.cmp(&b_val)
        }
        Some(OrderEncoding::I64Be) => {
            let a_val = a.try_into().map(i64::from_be_bytes).unwrap_or(0);
            let b_val = b.try_into().map(i64::from_be_bytes).unwrap_or(0);
            a_val.cmp(&b_val)
        }
        Some(OrderEncoding::BytesAsc) | None => a.cmp(b),
    }
}

/// Encodes a retention threshold into the same representation used by captured order values.
fn threshold_order_value(scope: &KeysScope, threshold: u64) -> Result<[u8; 8], String> {
    match scope.order_by.as_ref().map(|o| &o.encoding) {
        Some(OrderEncoding::U64Be) => Ok(threshold.to_be_bytes()),
        Some(OrderEncoding::I64Be | OrderEncoding::BytesAsc) => Err(
            "threshold retention requires order_by.encoding = u64_be for key scopes".to_string(),
        ),
        None => Err("threshold retention requires order_by for key scopes".to_string()),
    }
}

/// Selects the keys to delete from one already-partitioned retention group.
fn keys_to_delete(
    mut entries: Vec<KeyEntry>,
    scope: &KeysScope,
    retain: &RetainPolicy,
) -> Result<Vec<Bytes>, String> {
    entries.sort_by(|a, b| compare_order_values(&a.order_value, &b.order_value, scope));

    match retain {
        RetainPolicy::KeepLatest { count } => {
            if entries.len() <= *count {
                return Ok(Vec::new());
            }
            Ok(entries[..entries.len() - count]
                .iter()
                .map(|e| e.key.clone())
                .collect())
        }
        RetainPolicy::GreaterThan { threshold } => {
            let threshold = threshold_order_value(scope, *threshold)?;
            Ok(entries
                .iter()
                .filter(|e| {
                    compare_order_values(&e.order_value, &threshold, scope) != CmpOrdering::Greater
                })
                .map(|e| e.key.clone())
                .collect())
        }
        RetainPolicy::GreaterThanOrEqual { threshold } => {
            let threshold = threshold_order_value(scope, *threshold)?;
            Ok(entries
                .iter()
                .filter(|e| {
                    compare_order_values(&e.order_value, &threshold, scope) == CmpOrdering::Less
                })
                .map(|e| e.key.clone())
                .collect())
        }
        RetainPolicy::DropAll => Ok(entries.iter().map(|e| e.key.clone()).collect()),
    }
}

struct WriteRequest {
    kvs: Vec<(Bytes, Bytes)>,
    response: oneshot::Sender<Result<u64, String>>,
}

struct AssignedWrite {
    sequence: u64,
    request: WriteRequest,
}

/// How one commit group's replay-log rows (and the durable-sequence meta row) reach the disk.
/// Either way the log alone defines durability; the state rows are recoverable from it.
enum PreparedLog {
    /// Log rows plus the meta row in one WAL-backed batch, committed atomically by one synced
    /// write. Used for small groups, where a single fsync beats the ingestion overhead.
    Batch(rocksdb::WriteBatch),
    /// Encoded log rows (ascending sequence order) written as one SST file and ingested directly
    /// into the log column family, followed by a synced meta write. Large payloads reach the disk
    /// once instead of twice (WAL now, SST again on flush), and being ingested at the bottom
    /// level they are never rewritten by compaction.
    Ingest(Vec<(u64, Vec<u8>)>),
}

/// One commit group covering a contiguous run of assigned sequence numbers.
struct PreparedWrite {
    writes: Vec<AssignedWrite>,
    log: Result<PreparedLog, String>,
    /// Current-state rows for the same sequences, applied without a WAL once the log is durable.
    state_batch: rocksdb::WriteBatch,
    batch_bytes: usize,
    /// Assignment epoch; `commit` rejects a group whose epoch an earlier failure has superseded.
    epoch: u64,
}

/// A group whose log batch is durable and whose state rows still have to be applied.
struct CommittedWrite {
    writes: Vec<AssignedWrite>,
    state_batch: rocksdb::WriteBatch,
    last_sequence: u64,
}

struct Writer {
    sender: Mutex<Option<mpsc::Sender<WriteRequest>>>,
    handles: Mutex<Vec<thread::JoinHandle<()>>>,
}

impl Writer {
    /// Starts the three-stage write pipeline. `prepare` drains queued requests up to the
    /// configured byte cap, assigns a contiguous sequence number to each, and builds each wave's
    /// state batch and encoded log rows; `commit` makes each group's log rows durable (synced
    /// batch or ingested SST), publishing the durable frontier; `apply` inserts the state rows
    /// without a WAL, advances the visible frontier, and resolves the requests. The stages
    /// overlap, so while one group is being fsync'd the next is being built and the previous
    /// group's state rows are being applied.
    fn start(
        db: Arc<DB>,
        ingest_dir: PathBuf,
        sequence: Arc<AtomicU64>,
        durable: Arc<AtomicU64>,
        flushed: Arc<AtomicU64>,
        write_pipeline: RocksWritePipelineConfig,
    ) -> Self {
        let (request_sender, request_receiver) = mpsc::channel();
        // Rendezvous so `prepare` runs at most one wave ahead of `commit`: it hands off a built
        // group, then builds the next while `commit` syncs this one.
        let (group_sender, group_receiver) = mpsc::sync_channel(0);
        // Allow `commit` to fsync the next group while `apply` inserts this group's state rows.
        let (committed_sender, committed_receiver) = mpsc::sync_channel(1);
        let max_commit_batch_bytes = write_pipeline.max_commit_batch_bytes.get();

        // Bumped by `commit` whenever a group fails. That rejects the in-flight groups assigned
        // under the failed frontier and signals `prepare` to re-sync its counter to the durable
        // sequence, re-allocating the abandoned numbers.
        let epoch = Arc::new(AtomicU64::new(0));

        let apply_db = db.clone();
        let apply_sequence = sequence.clone();
        let apply = thread::Builder::new()
            .name("simulator-rocks-apply".to_string())
            .spawn(move || run_apply(apply_db, apply_sequence, flushed, committed_receiver))
            .expect("failed to spawn RocksDB apply worker");

        let commit_db = db.clone();
        let commit_durable = durable.clone();
        let commit_epoch = epoch.clone();
        let commit = thread::Builder::new()
            .name("simulator-rocks-commit".to_string())
            .spawn(move || {
                run_commit(
                    commit_db,
                    ingest_dir,
                    commit_durable,
                    commit_epoch,
                    group_receiver,
                    committed_sender,
                )
            })
            .expect("failed to spawn RocksDB commit worker");

        let prepare = thread::Builder::new()
            .name("simulator-rocks-prepare".to_string())
            .spawn(move || {
                run_prepare(
                    db,
                    durable,
                    epoch,
                    request_receiver,
                    group_sender,
                    max_commit_batch_bytes,
                )
            })
            .expect("failed to spawn RocksDB prepare worker");

        Self {
            sender: Mutex::new(Some(request_sender)),
            handles: Mutex::new(vec![prepare, commit, apply]),
        }
    }

    /// Enqueues one ingest request and resolves once `commit` has durably published it.
    async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, String> {
        let (response, result) = oneshot::channel();
        let sender = self
            .sender
            .lock()
            .map_err(|e| format!("rocks writer lock poisoned: {e}"))?
            .as_ref()
            .cloned()
            .ok_or_else(|| "rocks writer stopped".to_string())?;
        sender
            .send(WriteRequest { kvs, response })
            .map_err(|_| "rocks writer stopped".to_string())?;
        result
            .await
            .map_err(|_| "rocks writer stopped before completing write".to_string())?
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // Closing the request channel lets `prepare` drain and exit, which drops the group channel
        // and stops `commit`, which in turn stops `apply` after it drains the committed groups;
        // joining keeps background RocksDB writers from outliving the store.
        if let Ok(mut sender) = self.sender.lock() {
            sender.take();
        }
        if let Ok(mut handles) = self.handles.lock() {
            for handle in handles.drain(..) {
                let _ = handle.join();
            }
        }
    }
}

/// Drains each byte-bounded wave of queued requests, assigns contiguous sequence numbers, builds a
/// size-capped commit group, and hands it to `commit`. After a commit failure bumps the epoch, the
/// next wave re-syncs `next` to the durable frontier so the abandoned sequence numbers are
/// re-allocated.
fn run_prepare(
    db: Arc<DB>,
    durable: Arc<AtomicU64>,
    epoch: Arc<AtomicU64>,
    receiver: mpsc::Receiver<WriteRequest>,
    sender: mpsc::SyncSender<PreparedWrite>,
    max_commit_batch_bytes: usize,
) {
    let mut next = durable.load(Ordering::Acquire);
    let mut seen_epoch = epoch.load(Ordering::Acquire);

    while let Ok(first) = receiver.recv() {
        let current_epoch = epoch.load(Ordering::Acquire);
        if current_epoch != seen_epoch {
            // A commit failed: each log batch commits atomically so nothing past the durable
            // frontier persisted, and the failed numbers can be reclaimed.
            seen_epoch = current_epoch;
            next = durable.load(Ordering::Acquire);
        }

        let (group, disconnected) = match prepare_queued_write(
            &db,
            &receiver,
            first,
            next,
            max_commit_batch_bytes,
            seen_epoch,
        ) {
            Ok(prepared) => prepared,
            Err((requests, error)) => {
                fail_requests(requests, error);
                continue;
            }
        };
        if let Some(last) = group.writes.last() {
            next = last.sequence;
        }
        if !forward_group(&sender, group) {
            break;
        }

        if disconnected {
            break;
        }
    }
}

/// Estimated RocksDB `WriteBatch` size for one request's rows: payload plus per-record framing.
/// Presizing the batch avoids repeated grow-and-copy cycles while appending large requests.
fn write_batch_capacity(request: &WriteRequest) -> usize {
    let payload: usize = request.kvs.iter().map(|(k, v)| k.len() + v.len()).sum();
    payload + request.kvs.len() * 16 + 64
}

/// Builds one prepared write from requests already queued behind `first` without waiting for new
/// arrivals, stopping once the accumulated RocksDB batches reach the soft byte cap. The request
/// that crosses the cap stays in the wave so a single large request can still make progress.
fn prepare_queued_write(
    db: &DB,
    receiver: &mpsc::Receiver<WriteRequest>,
    first: WriteRequest,
    from: u64,
    max_batch_bytes: usize,
    epoch: u64,
) -> Result<(PreparedWrite, bool), (Vec<WriteRequest>, String)> {
    let mut writes = Vec::with_capacity(64);
    let mut state_batch = rocksdb::WriteBatch::with_capacity_bytes(write_batch_capacity(&first));
    let mut log_rows: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut log_bytes = 0usize;
    let mut next = from;
    let mut request = first;
    let mut disconnected = false;

    loop {
        next = match next.checked_add(1) {
            Some(next) => next,
            None => {
                return Err((
                    vec![request],
                    "rocks sequence number overflowed".to_string(),
                ));
            }
        };
        let write = AssignedWrite {
            sequence: next,
            request,
        };
        append_state_entries(&mut state_batch, std::slice::from_ref(&write.request));
        if let Some(value) = encode_log_value(next, std::slice::from_ref(&write.request)) {
            log_bytes += LOG_BATCH_KEY_LEN + value.len();
            log_rows.push((next, value));
        }
        writes.push(write);
        if state_batch.size_in_bytes() + log_bytes >= max_batch_bytes || next == u64::MAX {
            break;
        }

        match receiver.try_recv() {
            Ok(next_request) => request = next_request,
            Err(mpsc::TryRecvError::Empty) => break,
            Err(mpsc::TryRecvError::Disconnected) => {
                disconnected = true;
                break;
            }
        }
    }

    Ok((
        finalize_prepared_write(db, writes, state_batch, log_rows, log_bytes, epoch),
        disconnected,
    ))
}

/// Sends one group to `commit`, returning false if it has stopped.
fn forward_group(sender: &mpsc::SyncSender<PreparedWrite>, group: PreparedWrite) -> bool {
    if let Err(error) = sender.send(group) {
        fail_assigned_writes(error.0.writes, "rocks commit worker stopped".to_string());
        return false;
    }
    true
}

/// Commits prepared groups one at a time with a synced log write, publishing the durable frontier
/// after each success and handing the group to `apply`. A group whose epoch was superseded by an
/// earlier failure is rejected without being written; a failing group bumps the epoch so its
/// frontier (and every later group assigned under it) is abandoned and re-allocated by `prepare`.
fn run_commit(
    db: Arc<DB>,
    ingest_dir: PathBuf,
    durable: Arc<AtomicU64>,
    epoch: Arc<AtomicU64>,
    receiver: mpsc::Receiver<PreparedWrite>,
    committed_sender: mpsc::SyncSender<CommittedWrite>,
) {
    while let Ok(group) = receiver.recv() {
        let Some(committed) = commit_group(&db, &ingest_dir, &durable, &epoch, group) else {
            continue;
        };
        if let Err(error) = committed_sender.send(committed) {
            // The log batch is durable but the state rows can no longer be applied in this
            // process; recovery replays them on the next open, so the callers only lose the ack.
            fail_assigned_writes(error.0.writes, "rocks apply worker stopped".to_string());
            break;
        }
    }
}

/// Commits one group's log rows, returning the group for state application on success. Returns
/// `None` when the group is empty, rejected, or failed (with its requests already resolved).
fn commit_group(
    db: &DB,
    ingest_dir: &Path,
    durable: &AtomicU64,
    epoch: &AtomicU64,
    group: PreparedWrite,
) -> Option<CommittedWrite> {
    if group.writes.is_empty() {
        return None;
    }
    if group.epoch != epoch.load(Ordering::Acquire) {
        // This group was assigned under a frontier an earlier commit failure has since abandoned
        // (prepare can build one wave ahead before it observes the bump). Rejecting it keeps the
        // durable log gap-free; the requests never reached the disk, so the caller is told to
        // retry, which re-allocates them fresh sequence numbers under the current epoch.
        fail_assigned_writes(
            group.writes,
            "rocks write batch superseded by an earlier failure, retry".to_string(),
        );
        return None;
    }

    let requests = group.writes.len();
    let group_epoch = group.epoch;
    let PreparedWrite {
        writes,
        log,
        state_batch,
        batch_bytes,
        ..
    } = group;
    let last_sequence = writes
        .last()
        .expect("non-empty group has a last write")
        .sequence;
    let log = match log {
        Ok(log) => log,
        Err(error) => {
            epoch.fetch_add(1, Ordering::AcqRel);
            fail_assigned_writes(writes, error);
            return None;
        }
    };
    let committed = match log {
        PreparedLog::Batch(log_batch) => write_sequence_batch(db, log_batch),
        PreparedLog::Ingest(log_rows) => {
            ingest_log_rows(db, ingest_dir, log_rows, last_sequence, group_epoch)
        }
    };
    match committed {
        Ok(()) => {
            // Release so `prepare` re-syncs against a frontier whose log rows are already synced.
            durable.store(last_sequence, Ordering::Release);
            debug!(
                requests,
                batch_bytes,
                sequence = last_sequence,
                "committed write batch"
            );
            Some(CommittedWrite {
                writes,
                state_batch,
                last_sequence,
            })
        }
        Err(error) => {
            // Bump before failing: any in-flight group sharing the failed epoch is then rejected,
            // and `prepare` re-syncs to the durable frontier, leaving the abandoned numbers for
            // reuse.
            epoch.fetch_add(1, Ordering::AcqRel);
            fail_assigned_writes(writes, error);
            None
        }
    }
}

/// Applies committed state batches in commit order, advancing the visible frontier and resolving
/// requests after each group's rows are readable. On loop exit the applied rows are flushed so a
/// clean reopen can skip the recovery replay.
fn run_apply(
    db: Arc<DB>,
    sequence: Arc<AtomicU64>,
    flushed: Arc<AtomicU64>,
    receiver: mpsc::Receiver<CommittedWrite>,
) {
    let mut poisoned = None;
    while let Ok(committed) = receiver.recv() {
        apply_committed_write(&db, &sequence, &mut poisoned, committed);
    }
    if poisoned.is_none() {
        if let Err(error) = advance_state_flushed(&db, &flushed, sequence.load(Ordering::Acquire)) {
            debug!(error = %error, "failed to flush state rows on writer shutdown");
        }
    }
}

/// Applies one committed group's state rows and publishes its frontier. A failed state write
/// poisons the stage: the frontier freezes below the missing rows (later groups are only failed,
/// never published), so reads stay complete below the advertised sequence until a restart replays
/// the durable log.
fn apply_committed_write(
    db: &DB,
    sequence: &AtomicU64,
    poisoned: &mut Option<String>,
    committed: CommittedWrite,
) {
    if let Some(error) = poisoned.as_ref() {
        fail_assigned_writes(
            committed.writes,
            format!("rocks state apply previously failed: {error}"),
        );
        return;
    }
    match write_state_batch(db, committed.state_batch) {
        Ok(()) => {
            // Release so `current_sequence` readers only observe frontiers whose rows are already
            // readable (and, via the log commit, durable).
            sequence.store(committed.last_sequence, Ordering::Release);
            complete_assigned_writes(committed.writes);
        }
        Err(error) => {
            fail_assigned_writes(committed.writes, error.clone());
            *poisoned = Some(error);
        }
    }
}

fn finalize_prepared_write(
    db: &DB,
    writes: Vec<AssignedWrite>,
    state_batch: rocksdb::WriteBatch,
    log_rows: Vec<(u64, Vec<u8>)>,
    log_bytes: usize,
    epoch: u64,
) -> PreparedWrite {
    let batch_bytes = state_batch.size_in_bytes() + log_bytes;
    let log = if log_bytes >= LOG_INGEST_MIN_BYTES {
        PreparedLog::Ingest(log_rows)
    } else {
        let log_cf = db
            .cf_handle(LOG_CF)
            .expect("log CF must exist (created on open)");
        let mut log_batch = rocksdb::WriteBatch::with_capacity_bytes(log_bytes + 64);
        for (sequence, value) in log_rows {
            log_batch.put_cf(log_cf, sequence_log_key(sequence), value);
        }
        if let Some(write) = writes.last() {
            append_sequence_meta(db, &mut log_batch, write.sequence);
        }
        PreparedLog::Batch(log_batch)
    };
    PreparedWrite {
        writes,
        log: Ok(log),
        state_batch,
        batch_bytes,
        epoch,
    }
}

/// Appends the current-state rows for one sequence to the state batch.
fn append_state_entries(state_batch: &mut rocksdb::WriteBatch, requests: &[WriteRequest]) {
    for request in requests {
        for (k, v) in &request.kvs {
            state_batch.put(k.as_ref(), v.as_ref());
        }
    }
}

fn append_sequence_meta(db: &DB, batch: &mut rocksdb::WriteBatch, sequence: u64) {
    let meta_cf = db
        .cf_handle(META_CF)
        .expect("meta CF must exist (created on open)");
    batch.put_cf(meta_cf, SEQ_META_KEY, sequence.to_le_bytes());
}

/// Writes a log batch with sync enabled because it defines the durable high-water mark.
fn write_sequence_batch(db: &DB, batch: rocksdb::WriteBatch) -> Result<(), String> {
    let mut write_options = WriteOptions::default();
    write_options.set_sync(true);
    db.write_opt(batch, &write_options)
        .map_err(|e| e.to_string())
}

/// Commits one group's log rows by writing them as an SST file, ingesting it into the log column
/// family, and then durably advancing the sequence meta row. Ingestion syncs the file and the
/// manifest, so the rows are durable before the meta write publishes them; if the meta write is
/// lost, the orphaned rows sit above the durable frontier where `get_batch` cannot see them and
/// `open` deletes them.
fn ingest_log_rows(
    db: &DB,
    ingest_dir: &Path,
    log_rows: Vec<(u64, Vec<u8>)>,
    last_sequence: u64,
    epoch: u64,
) -> Result<(), String> {
    let first = log_rows
        .first()
        .expect("ingested log groups are never empty")
        .0;
    // Leftover files from failed ingestions are deleted when the store reopens, and epochs make
    // re-allocated sequence numbers unambiguous within one writer's lifetime.
    let path = ingest_dir.join(format!("log-{first:020}-{last_sequence:020}-e{epoch}.sst"));

    // Uncompressed for parity with the WAL-backed path (WAL payloads are not compressed either);
    // compressing on the commit path would trade ack latency for bytes.
    let mut options = Options::default();
    options.set_compression_type(DBCompressionType::None);
    let mut writer = SstFileWriter::create(&options);
    writer.open(&path).map_err(|e| e.to_string())?;
    for (sequence, value) in &log_rows {
        writer
            .put(sequence_log_key(*sequence), value)
            .map_err(|e| e.to_string())?;
    }
    // `finish` syncs the file before it is linked into the DB.
    writer.finish().map_err(|e| e.to_string())?;

    let log_cf = db
        .cf_handle(LOG_CF)
        .expect("log CF must exist (created on open)");
    let mut ingest_options = IngestExternalFileOptions::default();
    ingest_options.set_move_files(true);
    if let Err(error) = db.ingest_external_file_cf_opts(log_cf, &ingest_options, vec![&path]) {
        let _ = std::fs::remove_file(&path);
        return Err(error.to_string());
    }

    let mut meta_batch = rocksdb::WriteBatch::default();
    append_sequence_meta(db, &mut meta_batch, last_sequence);
    write_sequence_batch(db, meta_batch)
}

/// Writes current-state rows without a WAL: durability comes from the already-synced log batch,
/// which `open` replays above the state-flushed watermark after a crash.
fn write_state_batch(db: &DB, batch: rocksdb::WriteBatch) -> Result<(), String> {
    let mut write_options = WriteOptions::default();
    write_options.disable_wal(true);
    db.write_opt(batch, &write_options)
        .map_err(|e| e.to_string())
}

/// Makes every state row at or below `target` durable in the default column family, then persists
/// and mirrors the watermark. Recovery replays retained log rows above this watermark, so it must
/// only advance after the flush completes.
fn advance_state_flushed(db: &DB, flushed: &AtomicU64, target: u64) -> Result<(), String> {
    if flushed.load(Ordering::Acquire) >= target {
        return Ok(());
    }
    let default_cf = db
        .cf_handle(rocksdb::DEFAULT_COLUMN_FAMILY_NAME)
        .expect("default CF must exist (created on open)");
    db.flush_cf(default_cf).map_err(|e| e.to_string())?;

    let meta_cf = db
        .cf_handle(META_CF)
        .expect("meta CF must exist (created on open)");
    let mut batch = rocksdb::WriteBatch::default();
    batch.put_cf(meta_cf, STATE_FLUSHED_META_KEY, target.to_le_bytes());
    write_sequence_batch(db, batch)?;
    flushed.fetch_max(target, Ordering::AcqRel);
    Ok(())
}

/// Creates the SST staging directory and deletes files a crashed ingestion left behind. Staged
/// files are only ever moved into the DB by ingestion, so anything still here was never visible.
fn prepare_ingest_dir(store_path: &Path) -> Result<PathBuf, String> {
    let ingest_dir = store_path.join(LOG_INGEST_DIR);
    std::fs::create_dir_all(&ingest_dir)
        .map_err(|e| format!("failed to create log ingest directory: {e}"))?;
    for entry in std::fs::read_dir(&ingest_dir)
        .map_err(|e| format!("failed to read log ingest directory: {e}"))?
    {
        let entry = entry.map_err(|e| format!("failed to read log ingest directory: {e}"))?;
        std::fs::remove_file(entry.path())
            .map_err(|e| format!("failed to remove staged log file: {e}"))?;
    }
    Ok(ingest_dir)
}

/// Deletes log rows above the durable frontier. A crash between an SST ingestion and its meta
/// write can leave rows whose sequences were never published; those numbers will be re-allocated,
/// so the abandoned rows must not resurface.
fn remove_log_rows_above(db: &DB, durable: u64) -> Result<(), String> {
    let log_cf = db
        .cf_handle(LOG_CF)
        .expect("log CF must exist (created on open)");
    if durable == u64::MAX {
        return Ok(());
    }
    let start = sequence_log_key(durable + 1);
    let mut stale = db.iterator_cf(log_cf, IteratorMode::From(&start, Direction::Forward));
    if stale.next().is_none() {
        return Ok(());
    }
    db.delete_range_cf(log_cf, start, sequence_log_key(u64::MAX))
        .map_err(|e| e.to_string())?;
    db.delete_cf(log_cf, sequence_log_key(u64::MAX))
        .map_err(|e| e.to_string())
}

/// Reads a little-endian u64 sequence value from the meta column family, defaulting to zero.
fn read_meta_sequence(db: &DB, key: &[u8]) -> Result<u64, String> {
    let meta_cf = db
        .cf_handle(META_CF)
        .expect("meta CF must exist (created on open)");
    match db.get_cf(meta_cf, key).map_err(|e| e.to_string())? {
        Some(bytes) if bytes.len() == 8 => Ok(u64::from_le_bytes(bytes.try_into().unwrap())),
        _ => Ok(0),
    }
}

/// Re-applies the retained log rows in `(from_exclusive, to_inclusive]` to the default column
/// family. State rows are written without a WAL, so after a crash the rows above the flushed
/// watermark only exist in the log; replaying them in sequence order (last writer wins) rebuilds
/// the exact current state. Rows already covered by an earlier flush may have been pruned and are
/// simply absent from the iteration.
fn replay_state_from_log(db: &DB, from_exclusive: u64, to_inclusive: u64) -> Result<(), String> {
    let log_cf = db
        .cf_handle(LOG_CF)
        .expect("log CF must exist (created on open)");
    let start = sequence_log_key(from_exclusive.saturating_add(1));
    let mut batch = rocksdb::WriteBatch::default();
    for item in db.iterator_cf(log_cf, IteratorMode::From(&start, Direction::Forward)) {
        let (key, value) = item.map_err(|e| e.to_string())?;
        let sequence = sequence_from_log_key(key.as_ref())?;
        if sequence > to_inclusive {
            break;
        }
        let response = StreamGetResponseView::decode_view(value.as_ref())
            .map_err(|e| format!("corrupt log row for sequence {sequence}: {e}"))?;
        for entry in response.entries.iter() {
            batch.put(entry.key, entry.value);
        }
        if batch.size_in_bytes() >= DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES {
            write_state_batch(db, std::mem::take(&mut batch))?;
        }
    }
    if !batch.is_empty() {
        write_state_batch(db, batch)?;
    }
    Ok(())
}

/// Sends the same assignment failure to every request in a wave.
fn fail_requests(requests: Vec<WriteRequest>, error: String) {
    for request in requests {
        let _ = request.response.send(Err(error.clone()));
    }
}

/// Fails every assigned write with the same error.
fn fail_assigned_writes(writes: Vec<AssignedWrite>, error: String) {
    for write in writes {
        let _ = write.request.response.send(Err(error.clone()));
    }
}

/// Resolves every assigned write with its own committed sequence number.
fn complete_assigned_writes(writes: Vec<AssignedWrite>) {
    for write in writes {
        let _ = write.request.response.send(Ok(write.sequence));
    }
}

/// Application-level write pipeline options used by [`RocksStore::open`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RocksWritePipelineConfig {
    /// Soft maximum combined size (state rows plus encoded log rows) before cutting a prepared
    /// commit group.
    pub max_commit_batch_bytes: NonZeroUsize,
}

impl Default for RocksWritePipelineConfig {
    fn default() -> Self {
        Self {
            max_commit_batch_bytes: NonZeroUsize::new(DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES)
                .expect("default commit batch byte limit must be nonzero"),
        }
    }
}

/// RocksDB engine and application-level write pipeline options used by [`RocksStore::open`].
pub struct RocksConfig {
    /// Database-wide options.
    pub db_options: Options,
    /// Options for the default column family, which stores the current key-value state.
    pub default_cf_options: Options,
    /// Options for the metadata column family.
    pub meta_cf_options: Options,
    /// Options for the sequence log column family.
    pub log_cf_options: Options,
    /// Options for the application-level ingest write pipeline.
    pub write_pipeline: RocksWritePipelineConfig,
}

impl Default for RocksConfig {
    /// RocksDB options tuned for the simulator's ingest profile (hundreds of thousands of keys
    /// per batch) instead of stock RocksDB defaults.
    fn default() -> Self {
        let cores = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2) as i32;
        let mut db_options = Options::default();
        db_options.increase_parallelism(cores);

        // Smaller, more numerous state memtables keep skiplist inserts shallow and shift work to
        // background flushes.
        let mut default_cf_options = Options::default();
        default_cf_options.set_write_buffer_size(32 * 1024 * 1024);
        default_cf_options.set_max_write_buffer_number(4);

        // Replay-log values are large (one blob per ingest batch) and immutable until pruned.
        // Storing them in blob files keeps log-CF compactions rewriting only the 8-byte keys and
        // blob references instead of re-copying every batch payload.
        let mut log_cf_options = Options::default();
        log_cf_options.set_enable_blob_files(true);
        log_cf_options.set_min_blob_size(4096);
        log_cf_options.set_enable_blob_gc(true);

        Self {
            db_options,
            default_cf_options,
            meta_cf_options: Options::default(),
            log_cf_options,
            write_pipeline: RocksWritePipelineConfig::default(),
        }
    }
}

/// Minimal RocksDB-backed store for the simulator: batch writes plus a global sequence u64
/// plus a per-sequence log.
#[derive(Clone)]
pub struct RocksStore {
    db: Arc<DB>,
    sequence: Arc<AtomicU64>,
    flushed: Arc<AtomicU64>,
    writer: Arc<Writer>,
}

impl RocksStore {
    /// Open the store with stock RocksDB defaults, unless `config` overrides
    /// the database and column-family options. Replays retained log rows above the state-flushed
    /// watermark into the default column family so the current state is complete below the
    /// durable sequence even after a crash that lost un-flushed (WAL-less) state rows.
    pub fn open(path: &Path, config: Option<RocksConfig>) -> Result<Self, String> {
        let RocksConfig {
            mut db_options,
            default_cf_options,
            meta_cf_options,
            log_cf_options,
            write_pipeline,
        } = config.unwrap_or_default();

        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);

        let cf_default =
            ColumnFamilyDescriptor::new(rocksdb::DEFAULT_COLUMN_FAMILY_NAME, default_cf_options);
        let cf_meta = ColumnFamilyDescriptor::new(META_CF, meta_cf_options);
        let cf_log = ColumnFamilyDescriptor::new(LOG_CF, log_cf_options);
        let db = Arc::new(
            DB::open_cf_descriptors(&db_options, path, vec![cf_default, cf_meta, cf_log])
                .map_err(|e| e.to_string())?,
        );
        let seq = read_meta_sequence(&db, SEQ_META_KEY)?;
        let flushed_seq = read_meta_sequence(&db, STATE_FLUSHED_META_KEY)?;

        let ingest_dir = prepare_ingest_dir(path)?;
        remove_log_rows_above(&db, seq)?;

        let flushed = Arc::new(AtomicU64::new(flushed_seq));
        if flushed_seq < seq {
            replay_state_from_log(&db, flushed_seq, seq)?;
            advance_state_flushed(&db, &flushed, seq)?;
        }

        let sequence = Arc::new(AtomicU64::new(seq));
        let durable = Arc::new(AtomicU64::new(seq));
        let writer = Arc::new(Writer::start(
            db.clone(),
            ingest_dir,
            sequence.clone(),
            durable,
            flushed.clone(),
            write_pipeline,
        ));
        Ok(Self {
            db,
            sequence,
            flushed,
            writer,
        })
    }

    /// Returns the log column-family handle created during open.
    fn log_cf(&self) -> &ColumnFamily {
        self.db
            .cf_handle(LOG_CF)
            .expect("log CF must exist (created on open)")
    }

    /// Reads the current value for one default-column-family key.
    fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        self.db.get(key)
    }

    /// Deletes current rows without touching sequence metadata or the replay log.
    fn delete_keys(&self, keys: &[Bytes]) -> Result<(), rocksdb::Error> {
        if keys.is_empty() {
            return Ok(());
        }

        let mut batch = rocksdb::WriteBatch::default();
        for k in keys {
            batch.delete(k.as_ref());
        }
        self.db.write(batch)?;
        Ok(())
    }

    /// Deletes replay-log batches with sequence numbers below `cutoff_exclusive`.
    fn prune_log(&self, cutoff_exclusive: u64) -> Result<(), String> {
        if cutoff_exclusive == 0 {
            return Ok(());
        }
        let cf = self.log_cf();
        self.db
            .delete_range_cf(cf, sequence_log_key(0), sequence_log_key(cutoff_exclusive))
            .map_err(|e| e.to_string())
    }

    /// Applies each prune policy in document order to either current rows or replay-log rows.
    fn apply_prune_policies(&self, document: PrunePolicyDocument) -> Result<(), String> {
        for policy in &document.policies {
            match &policy.scope {
                PolicyScope::Keys(scope) => {
                    self.apply_key_prune_policy(scope, &policy.retain)?;
                }
                PolicyScope::Sequence => {
                    self.apply_sequence_prune_policy(&policy.retain)?;
                }
            }
        }
        Ok(())
    }

    /// Scans matching current keys in bounded chunks, groups them, and deletes non-retained rows.
    fn apply_key_prune_policy(
        &self,
        scope: &KeysScope,
        retain: &RetainPolicy,
    ) -> Result<(), String> {
        let codec = KeyCodec::new(scope.selector.reserved_bits, scope.selector.prefix);
        let regex = compile_payload_regex(&scope.selector.payload_regex)
            .map_err(|e| format!("policy: {e}"))?;

        let (start, end) = codec.prefix_bounds();
        let mut rows = RocksRangeScanState::new(self.db.clone(), start, end, usize::MAX, true);
        let mut groups: BTreeMap<Vec<u8>, Vec<KeyEntry>> = BTreeMap::new();

        loop {
            let batch = rows.next_batch(PRUNE_SCAN_BATCH_SIZE)?;
            if batch.is_empty() {
                break;
            }

            for (key, _value) in batch {
                if !codec.matches(&key) {
                    continue;
                }
                let payload_len = codec.payload_capacity_bytes_for_key_len(key.len());
                let payload = match codec.read_payload(&key, 0, payload_len) {
                    Ok(payload) => payload,
                    Err(_) => continue,
                };
                if !regex.is_match(&payload) {
                    continue;
                }

                let group_key = match extract_group_key(&payload, &regex, scope) {
                    Some(group_key) => group_key,
                    None => continue,
                };
                let order_value = extract_order_value(&payload, &regex, scope).unwrap_or_default();

                groups
                    .entry(group_key)
                    .or_default()
                    .push(KeyEntry { key, order_value });
            }
        }

        let mut all_deletes = Vec::new();
        for (_group_key, entries) in groups {
            all_deletes.extend(keys_to_delete(entries, scope, retain)?);
        }
        self.delete_keys(&all_deletes).map_err(|e| e.to_string())?;
        // Flush so a crash-recovery replay (which starts above the watermark) cannot re-apply the
        // puts of keys this policy just deleted.
        advance_state_flushed(
            &self.db,
            &self.flushed,
            self.sequence.load(Ordering::Acquire),
        )
    }

    /// Computes the replay-log cutoff for a sequence policy and prunes only log rows.
    fn apply_sequence_prune_policy(&self, retain: &RetainPolicy) -> Result<(), String> {
        let current = self.sequence.load(Ordering::Acquire);
        // Log rows below the cutoff may still be needed to rebuild WAL-less state rows after a
        // crash. Flushing first makes those state rows durable, so deleting their log rows is
        // safe; the watermark write precedes the range delete in the WAL, preserving that order
        // across a crash.
        advance_state_flushed(&self.db, &self.flushed, current)?;
        let cutoff_exclusive = match retain {
            RetainPolicy::KeepLatest { count } => {
                let count = *count as u64;
                current.saturating_add(1).saturating_sub(count)
            }
            RetainPolicy::GreaterThan { threshold } => threshold.saturating_add(1),
            RetainPolicy::GreaterThanOrEqual { threshold } => *threshold,
            RetainPolicy::DropAll => current.saturating_add(1),
        };
        // Never delete log rows above the flushed watermark: sequences committed but not yet
        // visible may still need them to rebuild their WAL-less state rows after a crash.
        let cutoff_exclusive =
            cutoff_exclusive.min(self.flushed.load(Ordering::Acquire).saturating_add(1));
        self.prune_log(cutoff_exclusive)
    }
}

impl Sequence for RocksStore {
    fn current_sequence(&self) -> u64 {
        self.sequence.load(Ordering::Acquire)
    }
}

// Ingest uses dedicated writer threads so blocking RocksDB writes do not occupy Tokio workers.
// The writer folds already-queued requests into one commit group while preserving a contiguous
// sequence number and replay-log row for each request.
impl Ingest for RocksStore {
    async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, String> {
        self.writer.put_batch(kvs).await
    }
}

impl Query for RocksStore {
    type RangeScan = RocksRangeScanCursor;

    async fn get(&self, key: Bytes) -> Result<(Option<Bytes>, QueryExtra), String> {
        let store = self.clone();
        store
            .get_raw(&key)
            .map(|value| (value.map(Bytes::from), QueryExtra::default()))
            .map_err(|e| e.to_string())
    }

    async fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Result<Self::RangeScan, String> {
        let db = self.db.clone();
        Ok(RocksRangeScanCursor::new(db, start, end, limit, forward))
    }

    async fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> Result<(Vec<(Bytes, Option<Bytes>)>, QueryExtra), String> {
        let store = self.clone();
        let results = store.db.multi_get(keys.iter().map(|key| key.as_ref()));
        let entries = keys
            .into_iter()
            .zip(results)
            .map(|(k, r)| {
                let value = r.map_err(|e| e.to_string())?;
                Ok((k, value.map(Bytes::from)))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok((entries, QueryExtra::default()))
    }
}

impl Prune for RocksStore {
    async fn apply_prune_policies(&self, document: PrunePolicyDocument) -> Result<(), String> {
        let store = self.clone();
        store.apply_prune_policies(document)
    }
}

impl Log for RocksStore {
    async fn get_batch(&self, sequence_number: u64) -> Result<Option<LogBatch>, String> {
        // Serve only published batches: rows above the visible frontier are still being
        // committed (or were abandoned by a crash) and must not be observable early.
        if sequence_number > self.sequence.load(Ordering::Acquire) {
            return Ok(None);
        }
        let store = self.clone();
        let cf = store.log_cf();
        let sequence_key = sequence_log_key(sequence_number);
        let value = match store
            .db
            .get_cf(cf, sequence_key)
            .map_err(|e| e.to_string())?
        {
            Some(value) => value,
            None => return Ok(None),
        };
        Ok(Some(LogBatch::from_response_bytes(sequence_number, value)))
    }

    async fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
        let store = self.clone();
        let cf = store.log_cf();
        let mut it = store.db.iterator_cf(cf, IteratorMode::Start);
        match it.next() {
            None => Ok(None),
            Some(item) => {
                let (key, _) = item.map_err(|e| e.to_string())?;
                Ok(Some(sequence_from_log_key(key.as_ref())?))
            }
        }
    }
}

/// Encodes a sequence number as a log-CF key that preserves numeric order in RocksDB.
fn sequence_log_key(sequence: u64) -> [u8; LOG_BATCH_KEY_LEN] {
    sequence.to_be_bytes()
}

/// Decodes a log-CF key back into the sequence number it indexes.
fn sequence_from_log_key(key: &[u8]) -> Result<u64, String> {
    if key.len() != LOG_BATCH_KEY_LEN {
        return Err(format!("log CF key has unexpected length {}", key.len()));
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&key[..8]);
    Ok(u64::from_be_bytes(raw))
}

/// `log.stream.v1.GetResponse.sequence_number` (varint).
const LOG_VALUE_SEQUENCE_TAG: u8 = 0x08;
/// `log.stream.v1.GetResponse.entries` (length-delimited).
const LOG_VALUE_ENTRY_TAG: u8 = 0x12;
/// `common.kv.v1.Entry.key` (length-delimited).
const LOG_ENTRY_KEY_TAG: u8 = 0x0a;
/// `common.kv.v1.Entry.value` (length-delimited).
const LOG_ENTRY_VALUE_TAG: u8 = 0x12;

/// Number of bytes a value occupies as a protobuf varint.
fn varint_len(value: u64) -> usize {
    (63 - (value | 1).leading_zeros() as usize) / 7 + 1
}

/// Appends a protobuf varint to `buf`.
fn put_varint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push(value as u8 | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

/// Encoded size of one `common.kv.v1.Entry` body. Empty fields are omitted,
/// matching the generated encoder.
fn encoded_entry_body_len(key: &[u8], value: &[u8]) -> usize {
    let mut len = 0;
    if !key.is_empty() {
        len += 1 + varint_len(key.len() as u64) + key.len();
    }
    if !value.is_empty() {
        len += 1 + varint_len(value.len() as u64) + value.len();
    }
    len
}

/// Encodes the replay payload for every key/value row folded into one sequence.
///
/// Writes the `log.stream.v1.GetResponse` wire format directly from the borrowed
/// key/value slices so a large batch is encoded with a single presized allocation
/// instead of one owned `Entry` per row. `log_value_matches_generated_encoder`
/// pins byte-for-byte equality with the generated encoder.
fn encode_log_value(sequence: u64, requests: &[WriteRequest]) -> Option<Vec<u8>> {
    let mut total = 0;
    let mut entries = 0usize;
    for request in requests {
        entries += request.kvs.len();
        for (key, value) in &request.kvs {
            let body_len = encoded_entry_body_len(key, value);
            total += 1 + varint_len(body_len as u64) + body_len;
        }
    }
    if entries == 0 {
        return None;
    }
    if sequence != 0 {
        total += 1 + varint_len(sequence);
    }

    let mut buf = Vec::with_capacity(total);
    if sequence != 0 {
        buf.push(LOG_VALUE_SEQUENCE_TAG);
        put_varint(&mut buf, sequence);
    }
    for request in requests {
        for (key, value) in &request.kvs {
            buf.push(LOG_VALUE_ENTRY_TAG);
            put_varint(&mut buf, encoded_entry_body_len(key, value) as u64);
            if !key.is_empty() {
                buf.push(LOG_ENTRY_KEY_TAG);
                put_varint(&mut buf, key.len() as u64);
                buf.extend_from_slice(key);
            }
            if !value.is_empty() {
                buf.push(LOG_ENTRY_VALUE_TAG);
                put_varint(&mut buf, value.len() as u64);
                buf.extend_from_slice(value);
            }
        }
    }
    debug_assert_eq!(buf.len(), total);
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use buffa::Message;
    use exoware_sdk::common::kv::v1::Entry;
    use exoware_sdk::log::stream::v1::GetResponse as StreamGetResponse;
    use exoware_server::{Ingest, Log, Sequence};
    use tempfile::tempdir;

    fn write_request(key: &'static [u8]) -> WriteRequest {
        let (response, _result) = oneshot::channel();
        WriteRequest {
            kvs: vec![(Bytes::from_static(key), Bytes::from_static(b"value"))],
            response,
        }
    }

    fn response_entries(response: StreamGetResponse) -> Vec<(Bytes, Bytes)> {
        response
            .entries
            .into_iter()
            .map(|entry| (Bytes::from(entry.key), entry.value))
            .collect()
    }

    fn decode_log_entries(value: &[u8]) -> Vec<(Bytes, Bytes)> {
        response_entries(StreamGetResponse::decode_from_slice(value).expect("decode log value"))
    }

    fn batch_entries(batch: LogBatch) -> Vec<(Bytes, Bytes)> {
        response_entries(batch.decode_response().expect("decode batch response"))
    }

    fn encoded_log_entry(sequence: u64, key: &'static [u8], value: &'static [u8]) -> Vec<u8> {
        StreamGetResponse {
            sequence_number: sequence,
            entries: vec![Entry {
                key: key.to_vec(),
                value: Bytes::from_static(value),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// Builds a group whose log batch is already an error, modeling a build/commit failure for a
    /// contiguous run of assigned sequence numbers tagged with `epoch`.
    fn failing_group(
        epoch: u64,
        entries: &[(u64, &'static [u8], &'static [u8])],
        error: &str,
    ) -> (PreparedWrite, Vec<oneshot::Receiver<Result<u64, String>>>) {
        let mut writes = Vec::new();
        let mut receivers = Vec::new();
        for (sequence, key, value) in entries {
            let (write, receiver) = assigned_write_with_response(*sequence, key, value);
            writes.push(write);
            receivers.push(receiver);
        }
        (
            PreparedWrite {
                writes,
                log: Err(error.to_string()),
                state_batch: rocksdb::WriteBatch::default(),
                batch_bytes: 0,
                epoch,
            },
            receivers,
        )
    }

    /// Commits one group and applies its state rows, mirroring the commit and apply stages.
    /// Returns the durable frontier afterwards.
    fn commit_and_apply(
        store: &RocksStore,
        durable: &AtomicU64,
        epoch: &AtomicU64,
        group: PreparedWrite,
    ) -> u64 {
        let ingest_dir = store.db.path().join(LOG_INGEST_DIR);
        if let Some(committed) = commit_group(&store.db, &ingest_dir, durable, epoch, group) {
            apply_committed_write(&store.db, &store.sequence, &mut None, committed);
        }
        durable.load(Ordering::Acquire)
    }

    fn commit_sequence_requests(
        db: &DB,
        sequence: &AtomicU64,
        requests: &[WriteRequest],
    ) -> Result<u64, String> {
        let next = sequence
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or_else(|| "rocks sequence number overflowed".to_string())?;
        let mut state_batch = rocksdb::WriteBatch::default();
        let mut log_batch = rocksdb::WriteBatch::default();
        append_state_entries(&mut state_batch, requests);
        if let Some(value) = encode_log_value(next, requests) {
            let log_cf = db
                .cf_handle(LOG_CF)
                .expect("log CF must exist (created on open)");
            log_batch.put_cf(log_cf, sequence_log_key(next), value);
        }
        append_sequence_meta(db, &mut log_batch, next);
        write_sequence_batch(db, log_batch)?;
        write_state_batch(db, state_batch)?;
        sequence.store(next, Ordering::Release);
        Ok(next)
    }

    fn assigned_write(sequence: u64, key: &'static [u8], value: &'static [u8]) -> AssignedWrite {
        assigned_write_with_response(sequence, key, value).0
    }

    fn assigned_write_with_response(
        sequence: u64,
        key: &'static [u8],
        value: &'static [u8],
    ) -> (AssignedWrite, oneshot::Receiver<Result<u64, String>>) {
        let (response, result) = oneshot::channel();
        (
            AssignedWrite {
                sequence,
                request: WriteRequest {
                    kvs: vec![(Bytes::from_static(key), Bytes::from_static(value))],
                    response,
                },
            },
            result,
        )
    }

    fn prepared_write(db: &DB, epoch: u64, writes: Vec<AssignedWrite>) -> PreparedWrite {
        let mut state_batch = rocksdb::WriteBatch::default();
        let mut log_rows = Vec::new();
        let mut log_bytes = 0;
        for write in &writes {
            let requests = std::slice::from_ref(&write.request);
            append_state_entries(&mut state_batch, requests);
            if let Some(value) = encode_log_value(write.sequence, requests) {
                log_bytes += LOG_BATCH_KEY_LEN + value.len();
                log_rows.push((write.sequence, value));
            }
        }
        finalize_prepared_write(db, writes, state_batch, log_rows, log_bytes, epoch)
    }

    #[test]
    fn log_value_matches_generated_encoder() {
        type RequestKvs = Vec<Vec<(Bytes, Bytes)>>;
        let cases: Vec<(u64, RequestKvs)> = vec![
            (
                1,
                vec![vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))]],
            ),
            // Coalesced requests, empty keys/values, and multi-byte varint lengths.
            (
                u64::MAX,
                vec![
                    vec![
                        (Bytes::new(), Bytes::from_static(b"value-for-empty-key")),
                        (Bytes::from_static(b"empty-value"), Bytes::new()),
                        (Bytes::new(), Bytes::new()),
                    ],
                    vec![(Bytes::from(vec![7u8; 200]), Bytes::from(vec![9u8; 20_000]))],
                ],
            ),
        ];

        for (sequence, kvs_per_request) in cases {
            let requests = kvs_per_request
                .into_iter()
                .map(|kvs| WriteRequest {
                    kvs,
                    response: oneshot::channel().0,
                })
                .collect::<Vec<_>>();
            let expected = StreamGetResponse {
                sequence_number: sequence,
                entries: requests
                    .iter()
                    .flat_map(|request| {
                        request.kvs.iter().map(|(key, value)| Entry {
                            key: key.to_vec(),
                            value: value.clone(),
                            ..Default::default()
                        })
                    })
                    .collect(),
                ..Default::default()
            }
            .encode_to_vec();
            let encoded = encode_log_value(sequence, &requests).expect("encode");
            assert_eq!(encoded, expected, "sequence {sequence}");
        }

        let empty = WriteRequest {
            kvs: Vec::new(),
            response: oneshot::channel().0,
        };
        assert!(encode_log_value(3, std::slice::from_ref(&empty)).is_none());
    }

    #[test]
    fn rocks_config_defaults_preserve_write_pipeline_profile() {
        assert_eq!(
            RocksWritePipelineConfig::default(),
            RocksWritePipelineConfig {
                max_commit_batch_bytes: NonZeroUsize::new(DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES,)
                    .expect("nonzero"),
            }
        );
        assert_eq!(
            RocksConfig::default().write_pipeline,
            RocksWritePipelineConfig::default()
        );
    }

    #[test]
    fn prepare_queued_write_collects_all_pending_below_byte_cap() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let (sender, receiver) = mpsc::channel();
        sender.send(write_request(b"a")).expect("send");
        sender.send(write_request(b"b")).expect("send");
        sender.send(write_request(b"c")).expect("send");
        drop(sender);

        let first = receiver.recv().expect("first request");
        let (group, disconnected) = match prepare_queued_write(
            &store.db,
            &receiver,
            first,
            0,
            DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES,
            7,
        ) {
            Ok(prepared) => prepared,
            Err((_, error)) => panic!("{error}"),
        };
        assert_eq!(group.writes.len(), 3);
        assert!(group.log.is_ok());
        assert!(group.batch_bytes > 0);
        assert_eq!(group.epoch, 7);
        assert!(disconnected);
    }

    #[test]
    fn prepare_queued_write_stops_after_soft_byte_cap() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let (sender, receiver) = mpsc::channel();
        sender.send(write_request(b"a")).expect("send");
        sender.send(write_request(b"b")).expect("send");
        sender.send(write_request(b"c")).expect("send");
        drop(sender);

        let first = receiver.recv().expect("first request");
        let (group, disconnected) = match prepare_queued_write(&store.db, &receiver, first, 0, 1, 7)
        {
            Ok(prepared) => prepared,
            Err((_, error)) => panic!("{error}"),
        };

        assert_eq!(group.writes.len(), 1);
        assert_eq!(group.writes[0].request.kvs[0].0.as_ref(), b"a");
        assert!(group.log.is_ok());
        assert!(group.batch_bytes >= 1);
        assert_eq!(group.epoch, 7);
        assert!(!disconnected);
        assert_eq!(
            receiver
                .try_recv()
                .expect("next wave should keep queued request")
                .kvs[0]
                .0
                .as_ref(),
            b"b"
        );
    }

    #[tokio::test]
    async fn forward_group_fails_request_when_commit_stopped() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let (group_sender, group_receiver) = mpsc::sync_channel(0);
        drop(group_receiver);

        let (write, result) = assigned_write_with_response(1, b"a", b"1");
        let group = prepared_write(&store.db, 0, vec![write]);
        let forwarded = forward_group(&group_sender, group);

        assert!(!forwarded);
        let error = result
            .await
            .expect("request should receive an explicit worker error")
            .expect_err("request should fail");
        assert_eq!(error, "rocks commit worker stopped");
    }

    #[tokio::test]
    async fn failed_group_supersedes_epoch_and_frees_sequence_numbers() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let durable = AtomicU64::new(0);
        let epoch = AtomicU64::new(0);

        // A group that cannot commit (modeled with an already-failed batch) at sequences 1 and 2.
        let (group, receivers) = failing_group(0, &[(1, b"a", b"1"), (2, b"b", b"2")], "disk full");
        let committed = commit_and_apply(&store, &durable, &epoch, group);

        // Nothing was published, and the epoch advanced so the abandoned numbers can be re-used.
        assert_eq!(committed, 0);
        assert_eq!(store.current_sequence(), 0);
        assert_eq!(epoch.load(Ordering::Acquire), 1);
        for receiver in receivers {
            assert_eq!(
                receiver.await.expect("response"),
                Err("disk full".to_string())
            );
        }

        // The next epoch re-allocates sequences 1 and 2 to fresh requests, which commit cleanly.
        let (write_x, result_x) = assigned_write_with_response(1, b"x", b"24");
        let (write_y, result_y) = assigned_write_with_response(2, b"y", b"25");
        let group = prepared_write(&store.db, 1, vec![write_x, write_y]);
        let committed = commit_and_apply(&store, &durable, &epoch, group);

        assert_eq!(committed, 2);
        assert_eq!(store.current_sequence(), 2);
        assert_eq!(result_x.await.expect("response"), Ok(1));
        assert_eq!(result_y.await.expect("response"), Ok(2));
        assert_eq!(
            batch_entries(store.get_batch(1).await.expect("get").expect("retained")),
            vec![(Bytes::from_static(b"x"), Bytes::from_static(b"24"))]
        );
        assert_eq!(
            batch_entries(store.get_batch(2).await.expect("get").expect("retained")),
            vec![(Bytes::from_static(b"y"), Bytes::from_static(b"25"))]
        );
    }

    #[tokio::test]
    async fn superseded_epoch_group_is_rejected_without_write() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let durable = AtomicU64::new(0);
        // The current epoch is 1: an earlier failure already superseded epoch 0.
        let epoch = AtomicU64::new(1);

        let (write, result) = assigned_write_with_response(1, b"a", b"1");
        let group = prepared_write(&store.db, 0, vec![write]);
        let committed = commit_and_apply(&store, &durable, &epoch, group);

        assert_eq!(committed, 0);
        assert_eq!(store.current_sequence(), 0);
        assert_eq!(epoch.load(Ordering::Acquire), 1);
        assert_eq!(
            result.await.expect("response"),
            Err("rocks write batch superseded by an earlier failure, retry".to_string())
        );
        assert!(store.get_batch(1).await.expect("get").is_none());
    }

    #[tokio::test]
    async fn writer_reallocates_sequence_numbers_after_failed_batch() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let durable = AtomicU64::new(0);
        let epoch = AtomicU64::new(5);

        // Two successive failures both abandon sequence 1 without ever consuming it.
        for attempt in [b"first" as &[u8], b"second"] {
            let current = epoch.load(Ordering::Acquire);
            let (group, receivers) = failing_group(current, &[(1, b"k", b"v")], "boom");
            let committed = commit_and_apply(&store, &durable, &epoch, group);
            assert_eq!(
                committed, 0,
                "attempt {attempt:?} must not advance the frontier"
            );
            assert_eq!(epoch.load(Ordering::Acquire), current + 1);
            for receiver in receivers {
                assert_eq!(receiver.await.expect("response"), Err("boom".to_string()));
            }
        }

        // The first durable write still takes sequence 1.
        let current = epoch.load(Ordering::Acquire);
        let (write, result) = assigned_write_with_response(1, b"k", b"v");
        let group = prepared_write(&store.db, current, vec![write]);
        let committed = commit_and_apply(&store, &durable, &epoch, group);
        assert_eq!(committed, 1);
        assert_eq!(result.await.expect("response"), Ok(1));
        assert_eq!(store.current_sequence(), 1);
    }

    #[tokio::test]
    async fn reused_sequence_overwrites_abandoned_log_row() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let durable = AtomicU64::new(0);
        let epoch = AtomicU64::new(0);

        // Model an abandoned sequence index: the durable frontier is still 0, but a row
        // already exists at the next log key and must be replaced by the successful retry.
        store
            .db
            .put_cf(
                store.log_cf(),
                sequence_log_key(1),
                encoded_log_entry(1, b"k", b"stale"),
            )
            .expect("seed abandoned log row");
        // Rows above the visible frontier are unreadable, so the abandoned row cannot leak.
        assert!(store.get_batch(1).await.expect("get").is_none());

        let (failed, receivers) = failing_group(0, &[(1, b"k", b"failed")], "boom");
        let committed = commit_and_apply(&store, &durable, &epoch, failed);
        assert_eq!(committed, 0);
        assert_eq!(store.current_sequence(), 0);
        assert_eq!(epoch.load(Ordering::Acquire), 1);
        for receiver in receivers {
            assert_eq!(receiver.await.expect("response"), Err("boom".to_string()));
        }

        let (write, result) = assigned_write_with_response(1, b"k", b"new");
        let group = prepared_write(&store.db, 1, vec![write]);
        let committed = commit_and_apply(&store, &durable, &epoch, group);

        assert_eq!(committed, 1);
        assert_eq!(result.await.expect("response"), Ok(1));
        assert_eq!(store.current_sequence(), 1);
        assert_eq!(
            batch_entries(store.get_batch(1).await.expect("get").expect("retained")),
            vec![(Bytes::from_static(b"k"), Bytes::from_static(b"new"))]
        );
    }

    /// One batch large enough to commit through the SST-ingestion path instead of a WAL batch.
    fn large_batch(tag: u8) -> Vec<(Bytes, Bytes)> {
        (0..(LOG_INGEST_MIN_BYTES / 4096 + 16))
            .map(|i| {
                let mut key = vec![tag];
                key.extend_from_slice(&(i as u64).to_be_bytes());
                (Bytes::from(key), Bytes::from(vec![tag; 4096]))
            })
            .collect()
    }

    #[tokio::test]
    async fn large_batches_commit_through_ingestion_and_survive_reopen() {
        let dir = tempdir().expect("tempdir");
        let (first, second) = {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            let first = store.put_batch(large_batch(1)).await.expect("put");
            let second = store.put_batch(large_batch(2)).await.expect("put");
            assert_eq!(store.current_sequence(), second);

            let batch = store
                .get_batch(first)
                .await
                .expect("get batch")
                .expect("batch retained");
            assert_eq!(batch_entries(batch), large_batch(1));
            (first, second)
        };

        let store = RocksStore::open(dir.path(), None).expect("reopen db");
        assert_eq!(store.current_sequence(), second);
        for (sequence, tag) in [(first, 1u8), (second, 2u8)] {
            let batch = store
                .get_batch(sequence)
                .await
                .expect("get batch")
                .expect("batch retained");
            assert_eq!(batch_entries(batch), large_batch(tag));
        }
        assert_eq!(
            store.get_raw(&[1u8, 0, 0, 0, 0, 0, 0, 0, 0]).expect("get"),
            Some(vec![1u8; 4096])
        );

        // Sequence pruning drops the ingested rows like any other log rows.
        store
            .apply_prune_policies(PrunePolicyDocument {
                version: exoware_sdk::prune_policy::PRUNE_POLICY_DOCUMENT_VERSION,
                policies: vec![exoware_sdk::prune_policy::PrunePolicy {
                    scope: PolicyScope::Sequence,
                    retain: RetainPolicy::KeepLatest { count: 1 },
                }],
            })
            .expect("prune");
        assert!(store.get_batch(first).await.expect("get").is_none());
        assert!(store.get_batch(second).await.expect("get").is_some());
        assert_eq!(
            store.oldest_retained_batch().await.expect("oldest"),
            Some(second)
        );
    }

    #[tokio::test]
    async fn reopen_replays_log_rows_missing_from_state() {
        let dir = tempdir().expect("tempdir");
        {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            store
                .put_batch(vec![(Bytes::from_static(b"k1"), Bytes::from_static(b"v1"))])
                .await
                .expect("put");

            // Simulate a crash that lost the WAL-less state rows for sequences 2 and 3 but kept
            // the synced log batches: append the log rows and durable-sequence meta directly,
            // bypassing the state apply stage.
            let mut log_batch = rocksdb::WriteBatch::default();
            log_batch.put_cf(
                store.log_cf(),
                sequence_log_key(2),
                encoded_log_entry(2, b"k2", b"v2-stale"),
            );
            log_batch.put_cf(
                store.log_cf(),
                sequence_log_key(3),
                StreamGetResponse {
                    sequence_number: 3,
                    entries: vec![
                        Entry {
                            key: b"k2".to_vec(),
                            value: Bytes::from_static(b"v2"),
                            ..Default::default()
                        },
                        Entry {
                            key: b"k3".to_vec(),
                            value: Bytes::from_static(b"v3"),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }
                .encode_to_vec(),
            );
            append_sequence_meta(&store.db, &mut log_batch, 3);
            write_sequence_batch(&store.db, log_batch).expect("write log rows");
        }

        let store = RocksStore::open(dir.path(), None).expect("reopen db");
        assert_eq!(store.current_sequence(), 3);
        // Replay applied the missing rows in sequence order: last writer wins for k2.
        for (key, value) in [
            (b"k1" as &[u8], b"v1" as &[u8]),
            (b"k2", b"v2"),
            (b"k3", b"v3"),
        ] {
            assert_eq!(
                store.get_raw(key).expect("get").as_deref(),
                Some(value),
                "key {key:?}"
            );
        }
        // A second reopen skips the replay because the watermark advanced with a flush.
        drop(store);
        let store = RocksStore::open(dir.path(), None).expect("reopen db again");
        assert_eq!(store.current_sequence(), 3);
        assert_eq!(
            store.get_raw(b"k2").expect("get").as_deref(),
            Some(b"v2" as &[u8])
        );
    }

    #[tokio::test]
    async fn rocks_store_accepts_configured_write_pipeline() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(
            dir.path(),
            Some(RocksConfig {
                write_pipeline: RocksWritePipelineConfig {
                    max_commit_batch_bytes: NonZeroUsize::new(1).expect("nonzero"),
                },
                ..Default::default()
            }),
        )
        .expect("open db");

        let sequence = store
            .put_batch(vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))])
            .await
            .expect("put");
        assert_eq!(sequence, 1);
        assert_eq!(store.current_sequence(), 1);
    }

    #[tokio::test]
    async fn single_sequence_write_logs_all_requests() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let (response_a, _rx_a) = oneshot::channel();
        let (response_b, _rx_b) = oneshot::channel();
        let requests = vec![
            WriteRequest {
                kvs: vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))],
                response: response_a,
            },
            WriteRequest {
                kvs: vec![
                    (Bytes::from_static(b"b"), Bytes::from_static(b"2")),
                    (Bytes::from_static(b"c"), Bytes::from_static(b"3")),
                ],
                response: response_b,
            },
        ];

        let sequence =
            commit_sequence_requests(&store.db, &store.sequence, &requests).expect("write");
        assert_eq!(sequence, 1);
        assert_eq!(store.current_sequence(), 1);
        let log_cf = store.log_cf();
        let log_rows = store
            .db
            .iterator_cf(log_cf, IteratorMode::Start)
            .collect::<Result<Vec<_>, _>>()
            .expect("read log rows");
        assert_eq!(log_rows.len(), 1);
        assert_eq!(log_rows[0].0.as_ref(), sequence_log_key(sequence));
        assert_eq!(
            decode_log_entries(log_rows[0].1.as_ref()),
            vec![
                (Bytes::from_static(b"a"), Bytes::from_static(b"1")),
                (Bytes::from_static(b"b"), Bytes::from_static(b"2")),
                (Bytes::from_static(b"c"), Bytes::from_static(b"3")),
            ]
        );
        let batch = store
            .get_batch(sequence)
            .await
            .expect("get batch")
            .expect("batch retained");
        assert_eq!(
            batch_entries(batch),
            vec![
                (Bytes::from_static(b"a"), Bytes::from_static(b"1")),
                (Bytes::from_static(b"b"), Bytes::from_static(b"2")),
                (Bytes::from_static(b"c"), Bytes::from_static(b"3")),
            ]
        );
    }

    #[tokio::test]
    async fn prepared_write_preserves_contiguous_sequence_logs() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let durable = AtomicU64::new(0);
        let epoch = AtomicU64::new(0);
        let prepared = prepared_write(
            &store.db,
            0,
            vec![
                assigned_write(1, b"a", b"1"),
                assigned_write(2, b"b", b"2"),
                assigned_write(3, b"c", b"3"),
            ],
        );

        assert_eq!(prepared.writes.len(), 3);
        assert!(prepared.batch_bytes > 0);
        let committed = commit_and_apply(&store, &durable, &epoch, prepared);
        assert_eq!(committed, 3);

        assert_eq!(store.current_sequence(), 3);
        for (sequence, key, value) in [
            (1, Bytes::from_static(b"a"), Bytes::from_static(b"1")),
            (2, Bytes::from_static(b"b"), Bytes::from_static(b"2")),
            (3, Bytes::from_static(b"c"), Bytes::from_static(b"3")),
        ] {
            let batch = store
                .get_batch(sequence)
                .await
                .expect("get batch")
                .expect("batch retained");
            assert_eq!(batch_entries(batch), vec![(key, value)]);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_puts_keep_all_rows_in_sequence_logs() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let mut puts = Vec::new();

        for i in 0u8..32 {
            let store = store.clone();
            puts.push(tokio::spawn(async move {
                store
                    .put_batch(vec![(Bytes::from(vec![i]), Bytes::from(vec![i + 1]))])
                    .await
                    .expect("put")
            }));
        }

        let mut sequences = Vec::new();
        for put in puts {
            sequences.push(put.await.expect("put task"));
        }
        let current = store.current_sequence();
        assert!((1..=32).contains(&current));
        assert!(sequences
            .iter()
            .all(|sequence| (1..=current).contains(sequence)));

        let mut logged_keys = BTreeSet::new();
        for sequence in 1..=current {
            let batch = store
                .get_batch(sequence)
                .await
                .expect("get batch")
                .expect("batch retained");
            let batch = batch_entries(batch);
            assert!(!batch.is_empty());
            for (key, value) in batch {
                assert_eq!(value.as_ref(), &[key[0] + 1]);
                logged_keys.insert(key[0]);
            }
        }
        assert_eq!(logged_keys, (0u8..32).collect::<BTreeSet<_>>());
    }

    #[tokio::test]
    async fn get_batch_reads_values_from_sequence_log() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let key = Bytes::from_static(b"key");
        let value = Bytes::from_static(b"value");
        let sequence = store
            .put_batch(vec![(key.clone(), value.clone())])
            .await
            .expect("put");

        store
            .delete_keys(std::slice::from_ref(&key))
            .expect("delete primary row");

        let batch = store
            .get_batch(sequence)
            .await
            .expect("get batch")
            .expect("batch retained");
        assert_eq!(batch_entries(batch), vec![(key, value)]);
    }

    #[tokio::test]
    async fn writer_accepts_concurrent_arrivals() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        let (seq_a, seq_b) = tokio::join!(
            store.put_batch(vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))]),
            store.put_batch(vec![(Bytes::from_static(b"b"), Bytes::from_static(b"2"))])
        );
        let seq_a = seq_a.expect("first write");
        let seq_b = seq_b.expect("second write");

        let current = store.current_sequence();
        assert!((1..=2).contains(&current));
        assert!((1..=current).contains(&seq_a));
        assert!((1..=current).contains(&seq_b));
        assert_eq!(
            store.db.get(b"a").expect("get a").as_deref(),
            Some(&b"1"[..])
        );
        assert_eq!(
            store.db.get(b"b").expect("get b").as_deref(),
            Some(&b"2"[..])
        );
    }
}
