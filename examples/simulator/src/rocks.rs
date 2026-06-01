//! Naive reference storage for local development: user keys and values are written as-is to
//! RocksDB. A `meta` column family stores the monotonically increasing sequence number for RPCs.
//! A separate `log` column family keeps per-sequence-number key lists so the stream service can
//! serve replay and point lookups. Batch-log pruning is driven exclusively by the compact service's
//! `Sequence` scope.

use std::cmp::Ordering as CmpOrdering;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use bytes::Bytes;
use exoware_sdk::keys::KeyCodec;
use exoware_sdk::match_key::compile_payload_regex;
use exoware_sdk::prune_policy::{
    KeysScope, OrderEncoding, PolicyScope, PrunePolicyDocument, RetainPolicy,
};
use exoware_server::{Ingest, Log, Prune, Query, QueryExtra, RangeScan, RangeScanBatch, Sequence};
use regex::bytes::Regex;
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DBIterator, Direction, IteratorMode, Options,
    WriteOptions, DB,
};
use tokio::sync::oneshot;

const META_CF: &str = "meta";
const SEQ_META_KEY: &[u8] = b"sequence";
const LOG_CF: &str = "log";
const LOG_BATCH_KEY_LEN: usize = 8;
const LOG_VALUE_COUNT_LEN: usize = 8;
const LOG_VALUE_KEY_LEN_LEN: usize = 4;
const PRUNE_SCAN_BATCH_SIZE: usize = 4096;
const WRITE_DRAIN_MAX_REQUESTS: usize = 256;
const WRITE_BUILDERS: usize = 4;
const ROCKS_BACKGROUND_JOBS: i32 = 16;
const ROCKS_MAX_SUBCOMPACTIONS: u32 = 8;
const ROCKS_WRITE_BUFFER_SIZE: usize = 256 * 1024 * 1024;
const ROCKS_DB_WRITE_BUFFER_SIZE: usize = 4 * 1024 * 1024 * 1024;
const ROCKS_MEMTABLE_MEMORY_BUDGET: usize = ROCKS_DB_WRITE_BUFFER_SIZE;
const ROCKS_TARGET_FILE_SIZE_BASE: u64 = 512 * 1024 * 1024;
const ROCKS_MAX_BYTES_FOR_LEVEL_BASE: u64 = 16 * 1024 * 1024 * 1024;
const ROCKS_LEVEL_ZERO_COMPACTION_TRIGGER: i32 = 16;
const ROCKS_LEVEL_ZERO_SLOWDOWN_WRITES_TRIGGER: i32 = 1024;
const ROCKS_LEVEL_ZERO_STOP_WRITES_TRIGGER: i32 = 2048;
const ROCKS_SOFT_PENDING_COMPACTION_BYTES_LIMIT: usize = 512 * 1024 * 1024 * 1024;
const ROCKS_HARD_PENDING_COMPACTION_BYTES_LIMIT: usize = 768 * 1024 * 1024 * 1024;
const ROCKS_SYNC_BYTES: u64 = 8 * 1024 * 1024;
const ROCKS_COMPACTION_READAHEAD_SIZE: usize = 8 * 1024 * 1024;
const ROCKS_MIN_BLOB_SIZE: u64 = 16 * 1024;
const ROCKS_BLOB_FILE_SIZE: u64 = 512 * 1024 * 1024;
type RocksIterItem = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>;

struct OwnedRocksIterator {
    iter: DBIterator<'static>,
    _db: Arc<DB>,
}

impl OwnedRocksIterator {
    fn new(db: Arc<DB>, mode: IteratorMode<'_>) -> Self {
        // SAFETY: `iter` is dropped before `db` because fields are dropped in
        // declaration order. The RocksDB iterator therefore cannot outlive the
        // Arc-owned DB it borrows.
        let db_ref: &'static DB = unsafe { &*Arc::as_ptr(&db) };
        let iter = db_ref.iterator(mode);
        Self { iter, _db: db }
    }

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

fn threshold_order_value(scope: &KeysScope, threshold: u64) -> Result<[u8; 8], String> {
    match scope.order_by.as_ref().map(|o| &o.encoding) {
        Some(OrderEncoding::U64Be) => Ok(threshold.to_be_bytes()),
        Some(OrderEncoding::I64Be | OrderEncoding::BytesAsc) => Err(
            "threshold retention requires order_by.encoding = u64_be for key scopes".to_string(),
        ),
        None => Err("threshold retention requires order_by for key scopes".to_string()),
    }
}

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

struct BuildJob {
    order: u64,
    sequence: u64,
    requests: Vec<WriteRequest>,
}

struct PreparedWrite {
    order: u64,
    sequence: u64,
    requests: Vec<WriteRequest>,
    batch: Result<rocksdb::WriteBatch, String>,
}

struct RocksWriter {
    sender: Mutex<Option<mpsc::Sender<WriteRequest>>>,
    handles: Mutex<Vec<thread::JoinHandle<()>>>,
}

impl RocksWriter {
    fn start(db: Arc<DB>, sequence: Arc<Mutex<u64>>) -> Self {
        let (sender, receiver) = mpsc::channel();
        let (prepared_sender, prepared_receiver) = mpsc::channel();
        let builders = WRITE_BUILDERS.max(1);
        let mut worker_senders = Vec::with_capacity(builders);
        let mut handles = Vec::with_capacity(builders + 2);

        for worker in 0..builders {
            let (job_sender, job_receiver) = mpsc::channel();
            worker_senders.push(job_sender);
            let db = db.clone();
            let prepared_sender = prepared_sender.clone();
            handles.push(
                thread::Builder::new()
                    .name(format!("simulator-rocks-build-{worker}"))
                    .spawn(move || run_rocks_build_worker(db, job_receiver, prepared_sender))
                    .expect("failed to spawn RocksDB build worker"),
            );
        }
        drop(prepared_sender);

        let dispatcher_sequence = sequence.clone();
        let dispatcher = thread::Builder::new()
            .name("simulator-rocks-dispatch".to_string())
            .spawn(move || {
                run_rocks_write_dispatcher(dispatcher_sequence, receiver, worker_senders)
            })
            .expect("failed to spawn RocksDB write dispatcher");
        handles.insert(0, dispatcher);
        handles.push(
            thread::Builder::new()
                .name("simulator-rocks-commit".to_string())
                .spawn(move || run_rocks_commit_worker(db, sequence, prepared_receiver))
                .expect("failed to spawn RocksDB commit worker"),
        );
        Self {
            sender: Mutex::new(Some(sender)),
            handles: Mutex::new(handles),
        }
    }

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

impl Drop for RocksWriter {
    fn drop(&mut self) {
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

fn run_rocks_write_dispatcher(
    sequence: Arc<Mutex<u64>>,
    receiver: mpsc::Receiver<WriteRequest>,
    worker_senders: Vec<mpsc::Sender<BuildJob>>,
) {
    let mut order = 0u64;
    let mut next_sequence = match sequence.lock() {
        Ok(sequence) => *sequence,
        Err(error) => {
            fail_pending_receiver(receiver, format!("rocks sequence lock poisoned: {error}"));
            return;
        }
    };
    let mut worker = 0usize;

    while let Ok(first) = receiver.recv() {
        let mut requests = vec![first];
        let mut disconnected = false;

        while requests.len() < WRITE_DRAIN_MAX_REQUESTS && !disconnected {
            match receiver.try_recv() {
                Ok(request) => requests.push(request),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    disconnected = true;
                }
            }
        }

        next_sequence = match next_sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => {
                fail_requests(requests, "rocks sequence number overflowed".to_string());
                fail_pending_receiver(receiver, "rocks sequence number overflowed".to_string());
                return;
            }
        };
        let Some(sender) = worker_senders.get(worker % worker_senders.len()) else {
            fail_requests(requests, "rocks write workers stopped".to_string());
            fail_pending_receiver(receiver, "rocks write workers stopped".to_string());
            return;
        };
        worker = worker.wrapping_add(1);

        if sender
            .send(BuildJob {
                order,
                sequence: next_sequence,
                requests,
            })
            .is_err()
        {
            fail_pending_receiver(receiver, "rocks write workers stopped".to_string());
            return;
        }
        order = match order.checked_add(1) {
            Some(order) => order,
            None => {
                fail_pending_receiver(receiver, "rocks write order overflowed".to_string());
                return;
            }
        };

        if disconnected {
            break;
        }
    }
}

fn run_rocks_build_worker(
    db: Arc<DB>,
    receiver: mpsc::Receiver<BuildJob>,
    sender: mpsc::Sender<PreparedWrite>,
) {
    while let Ok(job) = receiver.recv() {
        let batch = build_sequence_requests_rocksdb_batch(&db, job.sequence, &job.requests);
        if sender
            .send(PreparedWrite {
                order: job.order,
                sequence: job.sequence,
                requests: job.requests,
                batch,
            })
            .is_err()
        {
            break;
        }
    }
}

fn run_rocks_commit_worker(
    db: Arc<DB>,
    sequence: Arc<Mutex<u64>>,
    receiver: mpsc::Receiver<PreparedWrite>,
) {
    let mut next_order = 0u64;
    let mut pending = BTreeMap::new();

    while let Ok(prepared) = receiver.recv() {
        pending.insert(prepared.order, prepared);

        while let Some(prepared) = pending.remove(&next_order) {
            let result = match prepared.batch {
                Ok(batch) => {
                    commit_prepared_sequence_rocksdb(&db, &sequence, prepared.sequence, batch)
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(sequence) => fail_or_complete_requests(prepared.requests, Ok(sequence)),
                Err(error) => {
                    fail_or_complete_requests(prepared.requests, Err(error.clone()));
                    fail_pending_prepared(pending, error.clone());
                    fail_prepared_receiver(receiver, error);
                    return;
                }
            }
            next_order = match next_order.checked_add(1) {
                Some(order) => order,
                None => {
                    let error = "rocks write order overflowed".to_string();
                    fail_pending_prepared(pending, error.clone());
                    fail_prepared_receiver(receiver, error);
                    return;
                }
            };
        }
    }
}

#[cfg(test)]
fn commit_sequence_requests_rocksdb(
    db: &DB,
    sequence: &Mutex<u64>,
    requests: &[WriteRequest],
) -> Result<u64, String> {
    let mut sequence = sequence
        .lock()
        .map_err(|e| format!("rocks sequence lock poisoned: {e}"))?;
    let next = (*sequence)
        .checked_add(1)
        .ok_or_else(|| "rocks sequence number overflowed".to_string())?;
    let batch = build_sequence_requests_rocksdb_batch(db, next, requests)?;
    write_sequence_batch_rocksdb(db, next, batch)?;
    *sequence = next;
    Ok(next)
}

fn build_sequence_requests_rocksdb_batch(
    db: &DB,
    sequence: u64,
    requests: &[WriteRequest],
) -> Result<rocksdb::WriteBatch, String> {
    let meta_cf = db
        .cf_handle(META_CF)
        .expect("meta CF must exist (created on open)");
    let log_cf = db
        .cf_handle(LOG_CF)
        .expect("log CF must exist (created on open)");
    let mut batch = rocksdb::WriteBatch::default();
    let mut logged_keys = 0u64;
    let mut log_value = vec![0u8; LOG_VALUE_COUNT_LEN];

    for request in requests {
        for (k, v) in &request.kvs {
            batch.put(k.as_ref(), v.as_ref());
            append_sequence_log_key(&mut log_value, k.as_ref())?;
            logged_keys = logged_keys
                .checked_add(1)
                .ok_or_else(|| "sequence log index overflowed".to_string())?;
        }
    }
    if logged_keys > 0 {
        log_value[..LOG_VALUE_COUNT_LEN].copy_from_slice(&logged_keys.to_be_bytes());
        batch.put_cf(log_cf, sequence_log_key(sequence), log_value);
    }
    batch.put_cf(meta_cf, SEQ_META_KEY, sequence.to_le_bytes());
    Ok(batch)
}

fn commit_prepared_sequence_rocksdb(
    db: &DB,
    sequence: &Mutex<u64>,
    prepared_sequence: u64,
    batch: rocksdb::WriteBatch,
) -> Result<u64, String> {
    let mut sequence = sequence
        .lock()
        .map_err(|e| format!("rocks sequence lock poisoned: {e}"))?;
    let expected = (*sequence)
        .checked_add(1)
        .ok_or_else(|| "rocks sequence number overflowed".to_string())?;
    if prepared_sequence != expected {
        return Err(format!(
            "prepared rocks sequence {prepared_sequence} is not contiguous after {}",
            *sequence
        ));
    }
    write_sequence_batch_rocksdb(db, prepared_sequence, batch)?;
    *sequence = prepared_sequence;
    Ok(prepared_sequence)
}

fn write_sequence_batch_rocksdb(
    db: &DB,
    _sequence: u64,
    batch: rocksdb::WriteBatch,
) -> Result<(), String> {
    let mut write_options = WriteOptions::default();
    write_options.set_sync(true);
    db.write_opt(batch, &write_options)
        .map_err(|e| e.to_string())
}

fn fail_requests(requests: Vec<WriteRequest>, error: String) {
    fail_or_complete_requests(requests, Err(error));
}

fn fail_or_complete_requests(requests: Vec<WriteRequest>, result: Result<u64, String>) {
    for request in requests {
        let _ = request.response.send(result.clone());
    }
}

fn fail_pending_receiver(receiver: mpsc::Receiver<WriteRequest>, error: String) {
    for request in receiver {
        let _ = request.response.send(Err(error.clone()));
    }
}

fn fail_pending_prepared(pending: BTreeMap<u64, PreparedWrite>, error: String) {
    for (_, prepared) in pending {
        fail_requests(prepared.requests, error.clone());
    }
}

fn fail_prepared_receiver(receiver: mpsc::Receiver<PreparedWrite>, error: String) {
    for prepared in receiver {
        fail_requests(prepared.requests, error.clone());
    }
}

fn write_heavy_options() -> Options {
    let mut opts = Options::default();
    opts.increase_parallelism(ROCKS_BACKGROUND_JOBS);
    opts.set_max_background_jobs(ROCKS_BACKGROUND_JOBS);
    opts.set_max_subcompactions(ROCKS_MAX_SUBCOMPACTIONS);
    opts.optimize_universal_style_compaction(ROCKS_MEMTABLE_MEMORY_BUDGET);
    opts.set_write_buffer_size(ROCKS_WRITE_BUFFER_SIZE);
    opts.set_db_write_buffer_size(ROCKS_DB_WRITE_BUFFER_SIZE);
    opts.set_max_write_buffer_number(8);
    opts.set_target_file_size_base(ROCKS_TARGET_FILE_SIZE_BASE);
    opts.set_max_bytes_for_level_base(ROCKS_MAX_BYTES_FOR_LEVEL_BASE);
    opts.set_level_zero_file_num_compaction_trigger(ROCKS_LEVEL_ZERO_COMPACTION_TRIGGER);
    opts.set_level_zero_slowdown_writes_trigger(ROCKS_LEVEL_ZERO_SLOWDOWN_WRITES_TRIGGER);
    opts.set_level_zero_stop_writes_trigger(ROCKS_LEVEL_ZERO_STOP_WRITES_TRIGGER);
    opts.set_soft_pending_compaction_bytes_limit(ROCKS_SOFT_PENDING_COMPACTION_BYTES_LIMIT);
    opts.set_hard_pending_compaction_bytes_limit(ROCKS_HARD_PENDING_COMPACTION_BYTES_LIMIT);
    opts.set_bytes_per_sync(ROCKS_SYNC_BYTES);
    opts.set_wal_bytes_per_sync(ROCKS_SYNC_BYTES);
    opts.set_compaction_readahead_size(ROCKS_COMPACTION_READAHEAD_SIZE);
    opts.set_enable_blob_files(true);
    opts.set_min_blob_size(ROCKS_MIN_BLOB_SIZE);
    opts.set_blob_file_size(ROCKS_BLOB_FILE_SIZE);
    opts.set_blob_compaction_readahead_size(ROCKS_COMPACTION_READAHEAD_SIZE as u64);
    opts
}

/// Minimal RocksDB-backed store for the simulator: batch writes plus a global sequence u64
/// plus a per-sequence log.
#[derive(Clone)]
pub struct RocksStore {
    db: Arc<DB>,
    sequence: Arc<Mutex<u64>>,
    writer: Arc<RocksWriter>,
}

impl RocksStore {
    pub fn open(path: &Path) -> Result<Self, rocksdb::Error> {
        let mut opts = write_heavy_options();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_default =
            ColumnFamilyDescriptor::new(rocksdb::DEFAULT_COLUMN_FAMILY_NAME, write_heavy_options());
        let cf_meta = ColumnFamilyDescriptor::new(META_CF, Options::default());
        let cf_log = ColumnFamilyDescriptor::new(LOG_CF, write_heavy_options());
        let db = Arc::new(DB::open_cf_descriptors(
            &opts,
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
        let sequence = Arc::new(Mutex::new(seq));
        let writer = Arc::new(RocksWriter::start(db.clone(), sequence.clone()));
        Ok(Self {
            db,
            sequence,
            writer,
        })
    }

    fn log_cf(&self) -> &ColumnFamily {
        self.db
            .cf_handle(LOG_CF)
            .expect("log CF must exist (created on open)")
    }

    fn get_rocksdb(&self, key: &[u8]) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        self.db.get(key)
    }

    fn delete_keys_rocksdb(&self, keys: &[Bytes]) -> Result<(), rocksdb::Error> {
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

    fn prune_log_rocksdb(&self, cutoff_exclusive: u64) -> Result<u64, String> {
        // Count before deleting so callers know how much was pruned. For the
        // simulator a simple iterator scan is fine; a production engine would
        // expose delete_range_cf and return the logical count separately.
        let cf = self.log_cf();
        let mut deleted = 0u64;
        let mut batch = rocksdb::WriteBatch::default();
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        for item in iter {
            let (k, _) = item.map_err(|e| e.to_string())?;
            let sequence = sequence_from_log_key(k.as_ref())?;
            if sequence >= cutoff_exclusive {
                break;
            }
            batch.delete_cf(cf, k.as_ref());
            deleted += 1;
        }
        if deleted > 0 {
            self.db.write(batch).map_err(|e| e.to_string())?;
        }
        Ok(deleted)
    }

    fn apply_prune_policies_rocksdb(&self, document: PrunePolicyDocument) -> Result<(), String> {
        for policy in &document.policies {
            match &policy.scope {
                PolicyScope::Keys(scope) => {
                    self.apply_key_prune_policy_rocksdb(scope, &policy.retain)?;
                }
                PolicyScope::Sequence => {
                    self.apply_sequence_prune_policy_rocksdb(&policy.retain)?;
                }
            }
        }
        Ok(())
    }

    fn apply_key_prune_policy_rocksdb(
        &self,
        scope: &KeysScope,
        retain: &RetainPolicy,
    ) -> Result<(), String> {
        let codec = KeyCodec::new(scope.match_key.reserved_bits, scope.match_key.prefix);
        let regex = compile_payload_regex(&scope.match_key.payload_regex)
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
        self.delete_keys_rocksdb(&all_deletes)
            .map_err(|e| e.to_string())
    }

    fn apply_sequence_prune_policy_rocksdb(&self, retain: &RetainPolicy) -> Result<(), String> {
        let current = *self
            .sequence
            .lock()
            .map_err(|e| format!("rocks sequence lock poisoned: {e}"))?;
        let cutoff_exclusive = match retain {
            RetainPolicy::KeepLatest { count } => {
                let count = *count as u64;
                current.saturating_add(1).saturating_sub(count)
            }
            RetainPolicy::GreaterThan { threshold } => threshold.saturating_add(1),
            RetainPolicy::GreaterThanOrEqual { threshold } => *threshold,
            RetainPolicy::DropAll => current.saturating_add(1),
        };
        self.prune_log_rocksdb(cutoff_exclusive).map(|_| ())
    }
}

impl Sequence for RocksStore {
    fn current_sequence(&self) -> u64 {
        *self.sequence.lock().expect("rocks sequence lock poisoned")
    }
}

// Ingest uses a dedicated writer thread so blocking RocksDB writes do not occupy Tokio workers.
// The writer assigns one sequence to the first inbound request plus any request
// that arrives during a tiny bounded drain window, reducing synced commits and
// log-CF rows under concurrent upload load.
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
            .get_rocksdb(&key)
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
        store.apply_prune_policies_rocksdb(document)
    }
}

impl Log for RocksStore {
    async fn get_batch(&self, sequence_number: u64) -> Result<Option<Vec<(Bytes, Bytes)>>, String> {
        let store = self.clone();
        let cf = store.log_cf();
        let sequence_key = sequence_log_key(sequence_number);
        let keys = match store
            .db
            .get_cf(cf, sequence_key)
            .map_err(|e| e.to_string())?
        {
            Some(value) => decode_sequence_log_value(&value)?,
            None => return Ok(None),
        };
        if keys.is_empty() {
            return Ok(None);
        }

        let values = store.db.multi_get(keys.iter().map(|key| key.as_ref()));
        let mut entries = Vec::with_capacity(keys.len());
        for (key, value) in keys.into_iter().zip(values) {
            match value.map_err(|e| e.to_string())? {
                Some(value) => entries.push((key, Bytes::from(value))),
                None => return Ok(None),
            }
        }
        Ok(Some(entries))
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

fn sequence_log_key(sequence: u64) -> [u8; LOG_BATCH_KEY_LEN] {
    sequence.to_be_bytes()
}

fn sequence_from_log_key(key: &[u8]) -> Result<u64, String> {
    if key.len() != LOG_BATCH_KEY_LEN {
        return Err(format!("log CF key has unexpected length {}", key.len()));
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&key[..8]);
    Ok(u64::from_be_bytes(raw))
}

fn append_sequence_log_key(log_value: &mut Vec<u8>, key: &[u8]) -> Result<(), String> {
    let key_len = u32::try_from(key.len())
        .map_err(|_| format!("sequence log key length {} exceeds u32", key.len()))?;
    log_value.extend_from_slice(&key_len.to_be_bytes());
    log_value.extend_from_slice(key);
    Ok(())
}

fn decode_sequence_log_value(value: &[u8]) -> Result<Vec<Bytes>, String> {
    if value.len() < LOG_VALUE_COUNT_LEN {
        return Err(format!(
            "sequence log value too short: {} bytes",
            value.len()
        ));
    }
    let mut count_bytes = [0u8; LOG_VALUE_COUNT_LEN];
    count_bytes.copy_from_slice(&value[..LOG_VALUE_COUNT_LEN]);
    let count = u64::from_be_bytes(count_bytes);
    let mut offset = LOG_VALUE_COUNT_LEN;
    let mut keys = Vec::with_capacity(usize::try_from(count).unwrap_or(usize::MAX).min(4096));
    for _ in 0..count {
        let end_len = offset
            .checked_add(LOG_VALUE_KEY_LEN_LEN)
            .ok_or_else(|| "sequence log value offset overflowed".to_string())?;
        if end_len > value.len() {
            return Err("sequence log value ended before key length".to_string());
        }
        let mut key_len_bytes = [0u8; LOG_VALUE_KEY_LEN_LEN];
        key_len_bytes.copy_from_slice(&value[offset..end_len]);
        offset = end_len;
        let key_len = u32::from_be_bytes(key_len_bytes) as usize;
        let end_key = offset
            .checked_add(key_len)
            .ok_or_else(|| "sequence log key offset overflowed".to_string())?;
        if end_key > value.len() {
            return Err("sequence log value ended before key bytes".to_string());
        }
        keys.push(Bytes::copy_from_slice(&value[offset..end_key]));
        offset = end_key;
    }
    if offset != value.len() {
        return Err(format!(
            "sequence log value has {} trailing bytes",
            value.len() - offset
        ));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use exoware_server::{Ingest, Log, Sequence};
    use tempfile::tempdir;

    #[tokio::test]
    async fn coalesced_requests_share_sequence_and_log_batch() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path()).expect("open db");
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
            commit_sequence_requests_rocksdb(&store.db, &store.sequence, &requests).expect("write");
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
            decode_sequence_log_value(log_rows[0].1.as_ref()).expect("decode log value"),
            vec![
                Bytes::from_static(b"a"),
                Bytes::from_static(b"b"),
                Bytes::from_static(b"c"),
            ]
        );
        let batch = store
            .get_batch(sequence)
            .await
            .expect("get batch")
            .expect("batch retained");
        assert_eq!(
            batch,
            vec![
                (Bytes::from_static(b"a"), Bytes::from_static(b"1")),
                (Bytes::from_static(b"b"), Bytes::from_static(b"2")),
                (Bytes::from_static(b"c"), Bytes::from_static(b"3")),
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_puts_keep_all_rows_in_sequence_logs() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path()).expect("open db");
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
            assert!(!batch.is_empty());
            for (key, value) in batch {
                assert_eq!(value.as_ref(), &[key[0] + 1]);
                logged_keys.insert(key[0]);
            }
        }
        assert_eq!(logged_keys, (0u8..32).collect::<BTreeSet<_>>());
    }

    #[tokio::test]
    async fn writer_accepts_concurrent_arrivals_without_waiting() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path()).expect("open db");

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
