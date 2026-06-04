//! Naive reference storage for local development: user keys and values are written as-is to
//! RocksDB. A `meta` column family stores the monotonically increasing sequence number for RPCs.
//! A separate `log` column family keeps per-sequence-number batch payloads so the stream service
//! can serve replay and point lookups. Batch-log pruning is driven exclusively by the compact
//! service's `Sequence` scope.

use std::cmp::Ordering as CmpOrdering;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use buffa::Message;
use bytes::Bytes;
use exoware_sdk::keys::KeyCodec;
use exoware_sdk::match_key::compile_payload_regex;
use exoware_sdk::prune_policy::{
    KeysScope, OrderEncoding, PolicyScope, PrunePolicyDocument, RetainPolicy,
};
use exoware_sdk::store::{common::v1::KvEntry, stream::v1::GetResponse as StreamGetResponse};
use exoware_server::{
    Ingest, Log, LogBatch, Prune, Query, QueryExtra, RangeScan, RangeScanBatch, Sequence,
};
use regex::bytes::Regex;
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DBIterator, Direction, IteratorMode, Options,
    WriteOptions, DB,
};
use tokio::sync::oneshot;
use tracing::{debug, info};

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

struct BuildJob {
    writes: Vec<AssignedWrite>,
}

struct PreparedWrite {
    writes: Vec<AssignedWrite>,
    batch: Result<rocksdb::WriteBatch, String>,
    batch_bytes: usize,
}

struct Writer {
    sender: Mutex<Option<mpsc::Sender<WriteRequest>>>,
    handles: Mutex<Vec<thread::JoinHandle<()>>>,
}

impl Writer {
    /// Starts a three-stage write pipeline: dispatch assigns sequences, builders prepare
    /// side-effect-free `WriteBatch` values, and the commit worker publishes them in order.
    fn start(
        db: Arc<DB>,
        sequence: Arc<Mutex<u64>>,
        write_pipeline: RocksWritePipelineConfig,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        let (prepared_sender, prepared_receiver) = mpsc::sync_channel(0);
        let max_commit_batch_bytes = write_pipeline.max_commit_batch_bytes;
        let (job_sender, job_receiver) = mpsc::sync_channel(0);
        let mut handles = Vec::with_capacity(3);
        let build_db = db.clone();
        handles.push(
            thread::Builder::new()
                .name("simulator-rocks-build".to_string())
                .spawn(move || {
                    run_build_worker(
                        build_db,
                        job_receiver,
                        prepared_sender,
                        max_commit_batch_bytes,
                    )
                })
                .expect("failed to spawn RocksDB build worker"),
        );

        let dispatcher_sequence = sequence.clone();
        let dispatcher = thread::Builder::new()
            .name("simulator-rocks-dispatch".to_string())
            .spawn(move || run_write_dispatcher(dispatcher_sequence, receiver, job_sender))
            .expect("failed to spawn RocksDB write dispatcher");
        handles.insert(0, dispatcher);
        handles.push(
            thread::Builder::new()
                .name("simulator-rocks-commit".to_string())
                .spawn(move || run_commit_worker(db, sequence, prepared_receiver))
                .expect("failed to spawn RocksDB commit worker"),
        );
        Self {
            sender: Mutex::new(Some(sender)),
            handles: Mutex::new(handles),
        }
    }

    /// Enqueues one ingest request and resolves once the commit worker has durably published it.
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
        // Closing the request channel lets the dispatcher exit; joining keeps background RocksDB
        // users from outliving the store during tests and local shutdown.
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

/// Assigns contiguous sequence numbers and sends coalesced jobs to batch builders.
fn run_write_dispatcher(
    sequence: Arc<Mutex<u64>>,
    receiver: mpsc::Receiver<WriteRequest>,
    job_sender: mpsc::SyncSender<BuildJob>,
) {
    let mut next_sequence = match sequence.lock() {
        Ok(sequence) => *sequence,
        Err(error) => {
            fail_pending_receiver(receiver, format!("rocks sequence lock poisoned: {error}"));
            return;
        }
    };
    while let Ok(first) = receiver.recv() {
        // Drain requests that accumulated while downstream stages were backpressured.
        let (requests, disconnected) = collect_dispatch_requests(&receiver, first);

        debug!(requests = requests.len(), "dispatched write batch");

        let request_count = match u64::try_from(requests.len()) {
            Ok(count) => count,
            Err(_) => {
                fail_requests(requests, "rocks sequence number overflowed".to_string());
                fail_pending_receiver(receiver, "rocks sequence number overflowed".to_string());
                return;
            }
        };
        let last_sequence = match next_sequence.checked_add(request_count) {
            Some(sequence) => sequence,
            None => {
                fail_requests(requests, "rocks sequence number overflowed".to_string());
                fail_pending_receiver(receiver, "rocks sequence number overflowed".to_string());
                return;
            }
        };
        let mut assigned_sequence = next_sequence;
        let writes = requests
            .into_iter()
            .map(|request| {
                assigned_sequence += 1;
                AssignedWrite {
                    sequence: assigned_sequence,
                    request,
                }
            })
            .collect::<Vec<_>>();
        next_sequence = last_sequence;

        let job = BuildJob { writes };
        if let Err(error) = job_sender.send(job) {
            fail_assigned_writes(error.0.writes, "rocks build worker stopped".to_string());
            fail_pending_receiver(receiver, "rocks build worker stopped".to_string());
            return;
        }

        if disconnected {
            break;
        }
    }
}

fn collect_dispatch_requests(
    receiver: &mpsc::Receiver<WriteRequest>,
    first: WriteRequest,
) -> (Vec<WriteRequest>, bool) {
    let mut requests = Vec::with_capacity(64);
    requests.push(first);
    let mut disconnected = false;

    loop {
        match receiver.try_recv() {
            Ok(request) => requests.push(request),
            Err(mpsc::TryRecvError::Empty) => break,
            Err(mpsc::TryRecvError::Disconnected) => {
                disconnected = true;
                break;
            }
        }
    }

    (requests, disconnected)
}

/// Converts assigned write jobs into `WriteBatch` values without publishing them.
fn run_build_worker(
    db: Arc<DB>,
    receiver: mpsc::Receiver<BuildJob>,
    sender: mpsc::SyncSender<PreparedWrite>,
    max_commit_batch_bytes: NonZeroUsize,
) {
    while let Ok(job) = receiver.recv() {
        let mut prepared =
            build_prepared_writes(&db, job.writes, max_commit_batch_bytes.get()).into_iter();
        while let Some(write) = prepared.next() {
            if let Err(error) = sender.send(write) {
                fail_prepared_write(error.0, "rocks commit worker stopped".to_string());
                for remaining in prepared {
                    fail_prepared_write(remaining, "rocks commit worker stopped".to_string());
                }
                return;
            }
        }
    }
}

/// Publishes prepared batches in sequence order and resolves each request with the commit result.
fn run_commit_worker(
    db: Arc<DB>,
    sequence: Arc<Mutex<u64>>,
    receiver: mpsc::Receiver<PreparedWrite>,
) {
    while let Ok(prepared) = receiver.recv() {
        if prepared.writes.is_empty() {
            continue;
        };

        let stats = prepared_write_stats(&prepared);
        let (writes, result) = commit_prepared_write(&db, &sequence, prepared);
        match result {
            Ok(()) => {
                info!(
                    requests = stats.requests,
                    sequences = stats.sequences,
                    batch_bytes = stats.batch_bytes,
                    "committed write batch"
                );
                complete_assigned_writes(writes);
            }
            Err(error) => {
                fail_assigned_writes(writes, error.clone());
                fail_prepared_receiver(receiver, error);
                return;
            }
        };
    }
}

struct CommitGroupStats {
    sequences: usize,
    requests: usize,
    batch_bytes: usize,
}

fn prepared_write_stats(prepared: &PreparedWrite) -> CommitGroupStats {
    CommitGroupStats {
        sequences: prepared.writes.len(),
        requests: prepared.writes.len(),
        batch_bytes: prepared.batch_bytes,
    }
}

/// Builds RocksDB batches from contiguous sequence numbers, cutting after the soft size cap.
fn build_prepared_writes(
    db: &DB,
    writes: Vec<AssignedWrite>,
    max_batch_bytes: usize,
) -> Vec<PreparedWrite> {
    let mut prepared = Vec::new();
    let mut current_writes = Vec::new();
    let mut batch = rocksdb::WriteBatch::default();
    let mut writes = writes.into_iter();

    while let Some(write) = writes.next() {
        match append_assigned_write_batch(db, &mut batch, &write) {
            Ok(()) => {
                current_writes.push(write);
                let batch_bytes = batch.size_in_bytes();
                if batch_bytes >= max_batch_bytes {
                    prepared.push(finalize_prepared_write(
                        db,
                        std::mem::take(&mut current_writes),
                        std::mem::take(&mut batch),
                    ));
                }
            }
            Err(error) => {
                current_writes.push(write);
                current_writes.extend(writes);
                prepared.push(PreparedWrite {
                    writes: current_writes,
                    batch: Err(error),
                    batch_bytes: 0,
                });
                return prepared;
            }
        }
    }

    if !current_writes.is_empty() {
        prepared.push(finalize_prepared_write(db, current_writes, batch));
    }

    prepared
}

fn finalize_prepared_write(
    db: &DB,
    writes: Vec<AssignedWrite>,
    mut batch: rocksdb::WriteBatch,
) -> PreparedWrite {
    if let Some(write) = writes.last() {
        append_sequence_meta(db, &mut batch, write.sequence);
    }
    let batch_bytes = batch.size_in_bytes();
    PreparedWrite {
        writes,
        batch: Ok(batch),
        batch_bytes,
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

/// Commits a prepared write batch after rechecking contiguity under the sequence lock.
fn commit_prepared_write(
    db: &DB,
    sequence: &Mutex<u64>,
    prepared: PreparedWrite,
) -> (Vec<AssignedWrite>, Result<(), String>) {
    let PreparedWrite { writes, batch, .. } = prepared;
    let result = commit_batch_for_writes(db, sequence, &writes, batch);
    (writes, result)
}

fn commit_batch_for_writes(
    db: &DB,
    sequence: &Mutex<u64>,
    writes: &[AssignedWrite],
    batch: Result<rocksdb::WriteBatch, String>,
) -> Result<(), String> {
    if writes.is_empty() {
        return Ok(());
    }

    let mut sequence = sequence
        .lock()
        .map_err(|e| format!("rocks sequence lock poisoned: {e}"))?;
    let mut expected = *sequence;
    for write in writes {
        expected = expected
            .checked_add(1)
            .ok_or_else(|| "rocks sequence number overflowed".to_string())?;
        if write.sequence != expected {
            return Err(format!(
                "prepared rocks sequence {} is not contiguous after {}",
                write.sequence,
                expected - 1
            ));
        }
    }

    let batch = batch?;
    write_sequence_batch(db, batch)?;
    *sequence = expected;
    Ok(())
}

/// Writes a sequence batch with sync enabled because it defines the stream log high-water mark.
fn write_sequence_batch(db: &DB, batch: rocksdb::WriteBatch) -> Result<(), String> {
    let mut write_options = WriteOptions::default();
    write_options.set_sync(true);
    db.write_opt(batch, &write_options)
        .map_err(|e| e.to_string())
}

/// Sends the same failure to every request in a coalesced write job.
fn fail_requests(requests: Vec<WriteRequest>, error: String) {
    fail_or_complete_requests(requests, Err(error));
}

fn fail_assigned_writes(writes: Vec<AssignedWrite>, error: String) {
    for write in writes {
        fail_or_complete_request(write.request, Err(error.clone()));
    }
}

fn complete_assigned_writes(writes: Vec<AssignedWrite>) {
    for write in writes {
        fail_or_complete_request(write.request, Ok(write.sequence));
    }
}

fn fail_or_complete_request(request: WriteRequest, result: Result<u64, String>) {
    let _ = request.response.send(result);
}

/// Resolves every request folded into one assigned sequence with that sequence's commit result.
fn fail_or_complete_requests(requests: Vec<WriteRequest>, result: Result<u64, String>) {
    for request in requests {
        let _ = request.response.send(result.clone());
    }
}

/// Fails requests still waiting on the dispatcher input channel after a terminal worker error.
fn fail_pending_receiver(receiver: mpsc::Receiver<WriteRequest>, error: String) {
    for request in receiver {
        let _ = request.response.send(Err(error.clone()));
    }
}

fn fail_prepared_write(prepared: PreparedWrite, error: String) {
    fail_assigned_writes(prepared.writes, error);
}

/// Fails prepared batches produced after the commit worker has hit a terminal error.
fn fail_prepared_receiver(receiver: mpsc::Receiver<PreparedWrite>, error: String) {
    for prepared in receiver {
        fail_assigned_writes(prepared.writes, error.clone());
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
    sequence: Arc<Mutex<u64>>,
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
        let sequence = Arc::new(Mutex::new(seq));
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
        self.delete_keys(&all_deletes).map_err(|e| e.to_string())
    }

    /// Computes the replay-log cutoff for a sequence policy and prunes only log rows.
    fn apply_sequence_prune_policy(&self, retain: &RetainPolicy) -> Result<(), String> {
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
        self.prune_log(cutoff_exclusive)
    }
}

impl Sequence for RocksStore {
    fn current_sequence(&self) -> u64 {
        *self.sequence.lock().expect("rocks sequence lock poisoned")
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
            request.kvs.iter().map(|(key, value)| KvEntry {
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

    fn dispatch_write_jobs(requests: Vec<WriteRequest>) -> Vec<BuildJob> {
        let request_count = requests.len();
        let (request_sender, request_receiver) = mpsc::channel();
        for request in requests {
            request_sender.send(request).expect("send request");
        }
        drop(request_sender);

        let (worker_sender, worker_receiver) = mpsc::sync_channel(request_count);
        run_write_dispatcher(Arc::new(Mutex::new(0)), request_receiver, worker_sender);
        worker_receiver.try_iter().collect()
    }

    fn commit_sequence_requests(
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
        let mut batch = rocksdb::WriteBatch::default();
        append_sequence_entries(db, &mut batch, next, requests)?;
        append_sequence_meta(db, &mut batch, next);
        write_sequence_batch(db, batch)?;
        *sequence = next;
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

    fn prepared_write(db: &DB, writes: Vec<AssignedWrite>) -> PreparedWrite {
        build_prepared_writes(db, writes, DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES)
            .into_iter()
            .next()
            .expect("prepared write")
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
    fn dispatcher_drains_currently_queued_requests() {
        let jobs = dispatch_write_jobs(vec![
            write_request(b"a"),
            write_request(b"b"),
            write_request(b"c"),
        ]);

        assert_eq!(jobs.len(), 1);
        assert_eq!(
            jobs[0]
                .writes
                .iter()
                .map(|write| write.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(jobs[0]
            .writes
            .iter()
            .all(|write| write.request.kvs.len() == 1));
    }

    #[test]
    fn dispatcher_supports_single_request() {
        let jobs = dispatch_write_jobs(vec![write_request(b"a")]);

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].writes[0].sequence, 1);
        assert_eq!(jobs[0].writes[0].request.kvs.len(), 1);
    }

    #[test]
    fn builder_cuts_prepared_writes_after_soft_size_cap() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let prepared = build_prepared_writes(
            &store.db,
            vec![
                assigned_write(1, b"a", b"1"),
                assigned_write(2, b"b", b"2"),
                assigned_write(3, b"c", b"3"),
            ],
            1,
        );

        assert_eq!(prepared.len(), 3);
        assert_eq!(
            prepared
                .iter()
                .flat_map(|write| write.writes.iter().map(|write| write.sequence))
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(prepared
            .iter()
            .all(|write| write.writes.len() == 1 && write.batch_bytes > 0));
    }

    #[tokio::test]
    async fn dispatcher_fails_inflight_job_when_build_worker_stops() {
        let (request_sender, request_receiver) = mpsc::channel();
        let (worker_sender, worker_receiver) = mpsc::sync_channel(1);
        let (response, result) = oneshot::channel();

        drop(worker_receiver);
        request_sender
            .send(WriteRequest {
                kvs: vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))],
                response,
            })
            .expect("send request");
        drop(request_sender);

        run_write_dispatcher(Arc::new(Mutex::new(0)), request_receiver, worker_sender);

        let error = result
            .await
            .expect("request should receive an explicit worker error")
            .expect_err("request should fail");
        assert_eq!(error, "rocks build worker stopped");
    }

    #[tokio::test]
    async fn build_worker_fails_inflight_job_when_commit_worker_stops() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let (job_sender, job_receiver) = mpsc::channel();
        let (prepared_sender, prepared_receiver) = mpsc::sync_channel(1);
        let (response, result) = oneshot::channel();

        drop(prepared_receiver);
        job_sender
            .send(BuildJob {
                writes: vec![AssignedWrite {
                    sequence: 1,
                    request: WriteRequest {
                        kvs: vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))],
                        response,
                    },
                }],
            })
            .expect("send build job");
        drop(job_sender);

        run_build_worker(
            store.db.clone(),
            job_receiver,
            prepared_sender,
            NonZeroUsize::new(DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES).expect("nonzero"),
        );

        let error = result
            .await
            .expect("request should receive an explicit worker error")
            .expect_err("request should fail");
        assert_eq!(error, "rocks commit worker stopped");
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
        let prepared = prepared_write(
            &store.db,
            vec![
                assigned_write(1, b"a", b"1"),
                assigned_write(2, b"b", b"2"),
                assigned_write(3, b"c", b"3"),
            ],
        );

        let stats = prepared_write_stats(&prepared);
        assert_eq!(stats.sequences, 3);
        assert_eq!(stats.requests, 3);
        let (_writes, result) = commit_prepared_write(&store.db, &store.sequence, prepared);
        result.expect("commit batch");

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

    #[test]
    fn prepared_write_stats_count_assigned_sequences() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let prepared = prepared_write(
            &store.db,
            vec![assigned_write(1, b"a", b"1"), assigned_write(2, b"b", b"2")],
        );

        let stats = prepared_write_stats(&prepared);
        assert_eq!(stats.sequences, 2);
        assert_eq!(stats.requests, 2);
        assert!(stats.batch_bytes > 0);
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
