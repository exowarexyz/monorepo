//! Naive reference storage for local development: user keys and values are written as-is to
//! RocksDB. A `meta` column family stores the monotonically increasing sequence number for RPCs.
//! A separate `log` column family keeps per-sequence-number batch payloads so the stream service
//! can serve replay and point lookups. Batch-log pruning is driven exclusively by the compact
//! service's `Sequence` scope.

use std::cmp::Ordering as CmpOrdering;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use buffa::Message;
use bytes::Bytes;
use exoware_sdk::common::kv::v1::Entry;
use exoware_sdk::keys::KeyCodec;
use exoware_sdk::log::stream::v1::GetResponse as StreamGetResponse;
use exoware_sdk::prune_policy::{
    KeysScope, OrderEncoding, PolicyScope, PrunePolicyDocument, RetainPolicy,
};
use exoware_sdk::selector::compile_payload_regex;
use exoware_server::{
    Ingest, Log, LogBatch, Prune, Query, QueryExtra, RangeScan, RangeScanBatch, Sequence,
};
use regex::bytes::Regex;
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DBIterator, Direction, IteratorMode, Options,
    WriteOptions, DB,
};
use tokio::sync::oneshot;
use tracing::debug;

const META_CF: &str = "meta";
const SEQ_META_KEY: &[u8] = b"sequence";
const LOG_CF: &str = "log";
const LOG_BATCH_KEY_LEN: usize = 8;
const PRUNE_SCAN_BATCH_SIZE: usize = 4096;
const DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;
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

/// One RocksDB `WriteBatch` covering a contiguous run of assigned sequence numbers, committed
/// atomically by a single synced write.
struct PreparedWrite {
    writes: Vec<AssignedWrite>,
    batch: Result<rocksdb::WriteBatch, String>,
    batch_bytes: usize,
    /// Assignment epoch; `commit` rejects a group whose epoch an earlier failure has superseded.
    epoch: u64,
}

struct Writer {
    sender: Mutex<Option<mpsc::Sender<WriteRequest>>>,
    handles: Mutex<Vec<thread::JoinHandle<()>>>,
}

impl Writer {
    /// Starts the two-stage write pipeline. `prepare` drains queued requests up to the configured
    /// byte cap, assigns a contiguous sequence number to each, and builds a size-capped
    /// `WriteBatch`; `commit` syncs each group and resolves its requests. Keeping `commit` on its
    /// own thread lets `prepare` build the next wave while the current one is being fsync'd.
    fn start(
        db: Arc<DB>,
        sequence: Arc<AtomicU64>,
        write_pipeline: RocksWritePipelineConfig,
    ) -> Self {
        let (request_sender, request_receiver) = mpsc::channel();
        // Rendezvous so `prepare` runs at most one wave ahead of `commit`: it hands off a built
        // group, then builds the next while `commit` syncs this one.
        let (group_sender, group_receiver) = mpsc::sync_channel(0);
        let max_commit_batch_bytes = write_pipeline.max_commit_batch_bytes.get();

        // Bumped by `commit` whenever a group fails. That rejects the in-flight groups assigned
        // under the failed frontier and signals `prepare` to re-sync its counter to the durable
        // sequence, re-allocating the abandoned numbers.
        let epoch = Arc::new(AtomicU64::new(0));

        let commit_db = db.clone();
        let commit_sequence = sequence.clone();
        let commit_epoch = epoch.clone();
        let commit = thread::Builder::new()
            .name("simulator-rocks-commit".to_string())
            .spawn(move || run_commit(commit_db, commit_sequence, commit_epoch, group_receiver))
            .expect("failed to spawn RocksDB commit worker");

        let prepare = thread::Builder::new()
            .name("simulator-rocks-prepare".to_string())
            .spawn(move || {
                run_prepare(
                    db,
                    sequence,
                    epoch,
                    request_receiver,
                    group_sender,
                    max_commit_batch_bytes,
                )
            })
            .expect("failed to spawn RocksDB prepare worker");

        Self {
            sender: Mutex::new(Some(request_sender)),
            handles: Mutex::new(vec![prepare, commit]),
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
        // and stops `commit`; joining keeps background RocksDB writers from outliving the store.
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
    sequence: Arc<AtomicU64>,
    epoch: Arc<AtomicU64>,
    receiver: mpsc::Receiver<WriteRequest>,
    sender: mpsc::SyncSender<PreparedWrite>,
    max_commit_batch_bytes: usize,
) {
    let mut next = sequence.load(Ordering::Acquire);
    let mut seen_epoch = epoch.load(Ordering::Acquire);

    while let Ok(first) = receiver.recv() {
        let current_epoch = epoch.load(Ordering::Acquire);
        if current_epoch != seen_epoch {
            // A commit failed: each group commits atomically so nothing past the durable frontier
            // persisted, and the failed numbers can be reclaimed.
            seen_epoch = current_epoch;
            next = sequence.load(Ordering::Acquire);
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

/// Builds one prepared write from requests already queued behind `first` without waiting for new
/// arrivals, stopping once the accumulated RocksDB batch reaches the soft byte cap. The request
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
    let mut batch = rocksdb::WriteBatch::default();
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
        if let Err(error) = append_assigned_write_batch(db, &mut batch, &write) {
            writes.push(write);
            let group = PreparedWrite {
                writes,
                batch: Err(error),
                batch_bytes: 0,
                epoch,
            };
            return Ok((group, disconnected));
        }
        writes.push(write);
        if batch.size_in_bytes() >= max_batch_bytes || next == u64::MAX {
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
        finalize_prepared_write(db, writes, batch, epoch),
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

/// Commits prepared groups one at a time with a synced write, publishing the durable frontier after
/// each success. A group whose epoch was superseded by an earlier failure is rejected without being
/// written; a failing group bumps the epoch so its frontier (and every later group assigned under
/// it) is abandoned and re-allocated by `prepare`.
fn run_commit(
    db: Arc<DB>,
    sequence: Arc<AtomicU64>,
    epoch: Arc<AtomicU64>,
    receiver: mpsc::Receiver<PreparedWrite>,
) {
    let mut committed = sequence.load(Ordering::Acquire);
    while let Ok(group) = receiver.recv() {
        committed = commit_group(&db, &sequence, &epoch, committed, group);
    }
}

/// Commits one group, returning the durable frontier afterwards (unchanged on rejection or failure).
fn commit_group(
    db: &DB,
    sequence: &AtomicU64,
    epoch: &AtomicU64,
    committed: u64,
    group: PreparedWrite,
) -> u64 {
    if group.writes.is_empty() {
        return committed;
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
        return committed;
    }

    let requests = group.writes.len();
    let batch_bytes = group.batch_bytes;
    match write_prepared_group(db, group) {
        Ok((writes, last_sequence)) => {
            // Release so `current_sequence` readers only observe rows that are already durable.
            sequence.store(last_sequence, Ordering::Release);
            debug!(
                requests,
                batch_bytes,
                sequence = last_sequence,
                "committed write batch"
            );
            complete_assigned_writes(writes);
            last_sequence
        }
        Err((writes, error)) => {
            // Bump before failing: any in-flight group sharing the failed epoch is then rejected,
            // and `prepare` re-syncs to `committed`, leaving the abandoned numbers for reuse.
            epoch.fetch_add(1, Ordering::AcqRel);
            fail_assigned_writes(writes, error);
            committed
        }
    }
}

/// Commits one prepared group with a single synced write. Returns the group's writes alongside its
/// last sequence number on success, or the writes and the error on failure.
fn write_prepared_group(
    db: &DB,
    group: PreparedWrite,
) -> Result<(Vec<AssignedWrite>, u64), (Vec<AssignedWrite>, String)> {
    let PreparedWrite { writes, batch, .. } = group;
    let last_sequence = match writes.last() {
        Some(write) => write.sequence,
        None => return Ok((writes, 0)),
    };
    let batch = match batch {
        Ok(batch) => batch,
        Err(error) => return Err((writes, error)),
    };
    match write_sequence_batch(db, batch) {
        Ok(()) => Ok((writes, last_sequence)),
        Err(error) => Err((writes, error)),
    }
}

fn finalize_prepared_write(
    db: &DB,
    writes: Vec<AssignedWrite>,
    mut batch: rocksdb::WriteBatch,
    epoch: u64,
) -> PreparedWrite {
    if let Some(write) = writes.last() {
        append_sequence_meta(db, &mut batch, write.sequence);
    }
    let batch_bytes = batch.size_in_bytes();
    PreparedWrite {
        writes,
        batch: Ok(batch),
        batch_bytes,
        epoch,
    }
}

fn append_assigned_write_batch(
    db: &DB,
    batch: &mut rocksdb::WriteBatch,
    write: &AssignedWrite,
) -> Result<(), String> {
    append_sequence_entries(
        db,
        batch,
        write.sequence,
        std::slice::from_ref(&write.request),
    )
}

/// Appends one sequence's current-state rows plus its replay-log row to `batch`.
fn append_sequence_entries(
    db: &DB,
    batch: &mut rocksdb::WriteBatch,
    sequence: u64,
    requests: &[WriteRequest],
) -> Result<(), String> {
    let log_cf = db
        .cf_handle(LOG_CF)
        .expect("log CF must exist (created on open)");

    for request in requests {
        for (k, v) in &request.kvs {
            batch.put(k.as_ref(), v.as_ref());
        }
    }
    if let Some(log_value) = encode_log_value(sequence, requests) {
        batch.put_cf(log_cf, sequence_log_key(sequence), log_value);
    }
    Ok(())
}

fn append_sequence_meta(db: &DB, batch: &mut rocksdb::WriteBatch, sequence: u64) {
    let meta_cf = db
        .cf_handle(META_CF)
        .expect("meta CF must exist (created on open)");
    batch.put_cf(meta_cf, SEQ_META_KEY, sequence.to_le_bytes());
}

/// Writes a sequence batch with sync enabled because it defines the stream log high-water mark.
fn write_sequence_batch(db: &DB, batch: rocksdb::WriteBatch) -> Result<(), String> {
    let mut write_options = WriteOptions::default();
    write_options.set_sync(true);
    db.write_opt(batch, &write_options)
        .map_err(|e| e.to_string())
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
    /// Soft maximum RocksDB `WriteBatch` size before cutting a prepared commit group.
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
#[derive(Default)]
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

/// Minimal RocksDB-backed store for the simulator: batch writes plus a global sequence u64
/// plus a per-sequence log.
#[derive(Clone)]
pub struct RocksStore {
    db: Arc<DB>,
    sequence: Arc<AtomicU64>,
    writer: Arc<Writer>,
}

impl RocksStore {
    /// Open the store with stock RocksDB defaults, unless `config` overrides
    /// the database and column-family options.
    pub fn open(path: &Path, config: Option<RocksConfig>) -> Result<Self, rocksdb::Error> {
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
        let db = Arc::new(DB::open_cf_descriptors(
            &db_options,
            path,
            vec![cf_default, cf_meta, cf_log],
        )?);
        let meta_cf = db
            .cf_handle(META_CF)
            .expect("meta CF must exist (created on open)");
        let seq = match db.get_cf(meta_cf, SEQ_META_KEY)? {
            Some(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes.try_into().unwrap()),
            _ => 0,
        };
        let sequence = Arc::new(AtomicU64::new(seq));
        let writer = Arc::new(Writer::start(db.clone(), sequence.clone(), write_pipeline));
        Ok(Self {
            db,
            sequence,
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
        self.delete_keys(&all_deletes).map_err(|e| e.to_string())
    }

    /// Computes the replay-log cutoff for a sequence policy and prunes only log rows.
    fn apply_sequence_prune_policy(&self, retain: &RetainPolicy) -> Result<(), String> {
        let current = self.sequence.load(Ordering::Acquire);
        let cutoff_exclusive = match retain {
            RetainPolicy::KeepLatest { count } => {
                let count = *count as u64;
                current.saturating_add(1).saturating_sub(count)
            }
            RetainPolicy::GreaterThan { threshold } => threshold.saturating_add(1),
            RetainPolicy::GreaterThanOrEqual { threshold } => *threshold,
            RetainPolicy::DropAll => current.saturating_add(1),
        };
        self.prune_log(cutoff_exclusive)
    }
}

impl Sequence for RocksStore {
    fn current_sequence(&self) -> u64 {
        self.sequence.load(Ordering::Acquire)
    }
}

// Ingest uses a dedicated writer thread so blocking RocksDB writes do not occupy Tokio workers.
// The writer folds already-queued requests into one RocksDB batch while preserving a contiguous
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

/// Encodes the replay payload for every key/value row folded into one sequence.
fn encode_log_value(sequence: u64, requests: &[WriteRequest]) -> Option<Vec<u8>> {
    let entries = requests
        .iter()
        .flat_map(|request| {
            request.kvs.iter().map(|(key, value)| Entry {
                key: key.to_vec(),
                value: value.clone(),
                ..Default::default()
            })
        })
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return None;
    }
    Some(
        StreamGetResponse {
            sequence_number: sequence,
            entries,
            ..Default::default()
        }
        .encode_to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

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

    /// Builds a group whose batch is already an error, modeling a build/commit failure for a
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
                batch: Err(error.to_string()),
                batch_bytes: 0,
                epoch,
            },
            receivers,
        )
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
        let mut batch = rocksdb::WriteBatch::default();
        append_sequence_entries(db, &mut batch, next, requests)?;
        append_sequence_meta(db, &mut batch, next);
        write_sequence_batch(db, batch)?;
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
        let mut prepared = Vec::with_capacity(writes.len());
        let mut batch = rocksdb::WriteBatch::default();
        for write in writes {
            if let Err(error) = append_assigned_write_batch(db, &mut batch, &write) {
                prepared.push(write);
                return PreparedWrite {
                    writes: prepared,
                    batch: Err(error),
                    batch_bytes: 0,
                    epoch,
                };
            }
            prepared.push(write);
        }
        finalize_prepared_write(db, prepared, batch, epoch)
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
        assert!(group.batch.is_ok());
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
        assert!(group.batch.is_ok());
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
        let epoch = AtomicU64::new(0);

        // A group that cannot commit (modeled with an already-failed batch) at sequences 1 and 2.
        let (group, receivers) = failing_group(0, &[(1, b"a", b"1"), (2, b"b", b"2")], "disk full");
        let committed = commit_group(&store.db, &store.sequence, &epoch, 0, group);

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
        let committed = commit_group(&store.db, &store.sequence, &epoch, committed, group);

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
        // The current epoch is 1: an earlier failure already superseded epoch 0.
        let epoch = AtomicU64::new(1);

        let (write, result) = assigned_write_with_response(1, b"a", b"1");
        let group = prepared_write(&store.db, 0, vec![write]);
        let committed = commit_group(&store.db, &store.sequence, &epoch, 0, group);

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
        let epoch = AtomicU64::new(5);

        // Two successive failures both abandon sequence 1 without ever consuming it.
        for attempt in [b"first" as &[u8], b"second"] {
            let current = epoch.load(Ordering::Acquire);
            let (group, receivers) = failing_group(current, &[(1, b"k", b"v")], "boom");
            let committed = commit_group(&store.db, &store.sequence, &epoch, 0, group);
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
        let committed = commit_group(&store.db, &store.sequence, &epoch, 0, group);
        assert_eq!(committed, 1);
        assert_eq!(result.await.expect("response"), Ok(1));
        assert_eq!(store.current_sequence(), 1);
    }

    #[tokio::test]
    async fn reused_sequence_overwrites_abandoned_log_row() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
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
        assert_eq!(
            batch_entries(store.get_batch(1).await.expect("get").expect("retained")),
            vec![(Bytes::from_static(b"k"), Bytes::from_static(b"stale"))]
        );

        let (failed, receivers) = failing_group(0, &[(1, b"k", b"failed")], "boom");
        let committed = commit_group(&store.db, &store.sequence, &epoch, 0, failed);
        assert_eq!(committed, 0);
        assert_eq!(store.current_sequence(), 0);
        assert_eq!(epoch.load(Ordering::Acquire), 1);
        for receiver in receivers {
            assert_eq!(receiver.await.expect("response"), Err("boom".to_string()));
        }

        let (write, result) = assigned_write_with_response(1, b"k", b"new");
        let group = prepared_write(&store.db, 1, vec![write]);
        let committed = commit_group(&store.db, &store.sequence, &epoch, committed, group);

        assert_eq!(committed, 1);
        assert_eq!(result.await.expect("response"), Ok(1));
        assert_eq!(store.current_sequence(), 1);
        assert_eq!(
            batch_entries(store.get_batch(1).await.expect("get").expect("retained")),
            vec![(Bytes::from_static(b"k"), Bytes::from_static(b"new"))]
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
        let committed = commit_group(&store.db, &store.sequence, &epoch, 0, prepared);
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
