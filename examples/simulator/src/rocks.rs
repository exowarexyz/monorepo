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

const META_CF: &str = "meta";
const SEQ_META_KEY: &[u8] = b"sequence";
const LOG_CF: &str = "log";
const LOG_BATCH_KEY_LEN: usize = 8;
const PRUNE_SCAN_BATCH_SIZE: usize = 4096;
const DEFAULT_WRITE_MAX_COALESCED_REQUESTS: usize = 1;
const DEFAULT_WRITE_BUILDERS: usize = 1;
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
        let (prepared_sender, prepared_receiver) = mpsc::channel();
        let builders = write_pipeline.builder_threads.get();
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
                    .spawn(move || run_build_worker(db, job_receiver, prepared_sender))
                    .expect("failed to spawn RocksDB build worker"),
            );
        }
        drop(prepared_sender);

        let dispatcher_sequence = sequence.clone();
        let max_coalesced_requests = write_pipeline.max_coalesced_requests;
        let dispatcher = thread::Builder::new()
            .name("simulator-rocks-dispatch".to_string())
            .spawn(move || {
                run_write_dispatcher(
                    dispatcher_sequence,
                    receiver,
                    worker_senders,
                    max_coalesced_requests,
                )
            })
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
    worker_senders: Vec<mpsc::Sender<BuildJob>>,
    max_coalesced_requests: NonZeroUsize,
) {
    // `order` lets builders run in parallel while the commit worker preserves assignment order.
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
        // Drain only requests already queued so quiet writers do not wait for a wider batch.
        let mut requests = vec![first];
        let mut disconnected = false;

        while requests.len() < max_coalesced_requests.get() && !disconnected {
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

/// Converts assigned write jobs into `WriteBatch` values without publishing them.
fn run_build_worker(
    db: Arc<DB>,
    receiver: mpsc::Receiver<BuildJob>,
    sender: mpsc::Sender<PreparedWrite>,
) {
    while let Ok(job) = receiver.recv() {
        let batch = build_sequence_requests_batch(&db, job.sequence, &job.requests);
        let prepared = PreparedWrite {
            order: job.order,
            sequence: job.sequence,
            requests: job.requests,
            batch,
        };
        if let Err(error) = sender.send(prepared) {
            fail_requests(error.0.requests, "rocks commit worker stopped".to_string());
            break;
        }
    }
}

/// Publishes prepared batches in dispatcher order and resolves each request with the commit result.
fn run_commit_worker(
    db: Arc<DB>,
    sequence: Arc<Mutex<u64>>,
    receiver: mpsc::Receiver<PreparedWrite>,
) {
    let mut next_order = 0u64;
    // Buffer out-of-order builder results until every earlier batch has committed.
    let mut pending = BTreeMap::new();

    while let Ok(prepared) = receiver.recv() {
        pending.insert(prepared.order, prepared);

        while let Some(prepared) = pending.remove(&next_order) {
            let result = match prepared.batch {
                Ok(batch) => commit_prepared_sequence(&db, &sequence, prepared.sequence, batch),
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

/// Builds the atomic RocksDB batch for one assigned sequence number.
fn build_sequence_requests_batch(
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

    for request in requests {
        for (k, v) in &request.kvs {
            batch.put(k.as_ref(), v.as_ref());
        }
    }
    if let Some(log_value) = encode_log_value(sequence, requests) {
        batch.put_cf(log_cf, sequence_log_key(sequence), log_value);
    }
    batch.put_cf(meta_cf, SEQ_META_KEY, sequence.to_le_bytes());
    Ok(batch)
}

/// Commits one prepared sequence after rechecking contiguity under the sequence lock.
fn commit_prepared_sequence(
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
    write_sequence_batch(db, batch)?;
    *sequence = prepared_sequence;
    Ok(prepared_sequence)
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

/// Resolves every request folded into one sequence with that sequence's commit result.
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

/// Fails prepared batches buffered behind a commit error that cannot be published contiguously.
fn fail_pending_prepared(pending: BTreeMap<u64, PreparedWrite>, error: String) {
    for (_, prepared) in pending {
        fail_requests(prepared.requests, error.clone());
    }
}

/// Fails prepared batches produced after the commit worker has hit a terminal error.
fn fail_prepared_receiver(receiver: mpsc::Receiver<PreparedWrite>, error: String) {
    for prepared in receiver {
        fail_requests(prepared.requests, error.clone());
    }
}

/// Application-level write pipeline options used by [`RocksStore::open`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RocksWritePipelineConfig {
    /// Maximum number of already-queued ingest requests to fold into one RocksDB write.
    pub max_coalesced_requests: NonZeroUsize,
    /// Number of batch-building worker threads.
    pub builder_threads: NonZeroUsize,
}

impl Default for RocksWritePipelineConfig {
    fn default() -> Self {
        Self {
            max_coalesced_requests: NonZeroUsize::new(DEFAULT_WRITE_MAX_COALESCED_REQUESTS)
                .expect("default max coalesced requests must be nonzero"),
            builder_threads: NonZeroUsize::new(DEFAULT_WRITE_BUILDERS)
                .expect("default write builders must be nonzero"),
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
// The writer assigns one sequence to the first inbound request plus any already-queued requests,
// reducing synced commits and log-CF rows under concurrent upload load.
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

    fn dispatch_write_jobs(
        max_coalesced_requests: NonZeroUsize,
        requests: Vec<WriteRequest>,
    ) -> Vec<BuildJob> {
        let (request_sender, request_receiver) = mpsc::channel();
        for request in requests {
            request_sender.send(request).expect("send request");
        }
        drop(request_sender);

        let (worker_sender, worker_receiver) = mpsc::channel();
        run_write_dispatcher(
            Arc::new(Mutex::new(0)),
            request_receiver,
            vec![worker_sender],
            max_coalesced_requests,
        );
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
        let batch = build_sequence_requests_batch(db, next, requests)?;
        write_sequence_batch(db, batch)?;
        *sequence = next;
        Ok(next)
    }

    #[test]
    fn rocks_config_defaults_preserve_write_pipeline_profile() {
        assert_eq!(
            RocksWritePipelineConfig::default(),
            RocksWritePipelineConfig {
                max_coalesced_requests: NonZeroUsize::new(DEFAULT_WRITE_MAX_COALESCED_REQUESTS)
                    .expect("nonzero"),
                builder_threads: NonZeroUsize::new(DEFAULT_WRITE_BUILDERS).expect("nonzero"),
            }
        );
        assert_eq!(
            RocksConfig::default().write_pipeline,
            RocksWritePipelineConfig::default()
        );
    }

    #[test]
    fn dispatcher_uses_configured_coalescing_width() {
        let jobs = dispatch_write_jobs(
            NonZeroUsize::new(2).expect("nonzero"),
            vec![
                write_request(b"a"),
                write_request(b"b"),
                write_request(b"c"),
            ],
        );

        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].order, 0);
        assert_eq!(jobs[0].sequence, 1);
        assert_eq!(jobs[0].requests.len(), 2);
        assert_eq!(jobs[1].order, 1);
        assert_eq!(jobs[1].sequence, 2);
        assert_eq!(jobs[1].requests.len(), 1);
    }

    #[test]
    fn dispatcher_supports_single_request_coalescing_width() {
        let jobs = dispatch_write_jobs(
            NonZeroUsize::new(1).expect("nonzero"),
            vec![write_request(b"a"), write_request(b"b")],
        );

        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].sequence, 1);
        assert_eq!(jobs[0].requests.len(), 1);
        assert_eq!(jobs[1].sequence, 2);
        assert_eq!(jobs[1].requests.len(), 1);
    }

    #[tokio::test]
    async fn build_worker_fails_inflight_job_when_commit_worker_stops() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let (job_sender, job_receiver) = mpsc::channel();
        let (prepared_sender, prepared_receiver) = mpsc::channel();
        let (response, result) = oneshot::channel();

        drop(prepared_receiver);
        job_sender
            .send(BuildJob {
                order: 0,
                sequence: 1,
                requests: vec![WriteRequest {
                    kvs: vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))],
                    response,
                }],
            })
            .expect("send build job");
        drop(job_sender);

        run_build_worker(store.db.clone(), job_receiver, prepared_sender);

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
                    max_coalesced_requests: NonZeroUsize::new(1).expect("nonzero"),
                    builder_threads: NonZeroUsize::new(1).expect("nonzero"),
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
    async fn coalesced_requests_share_sequence_and_log_batch() {
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
    async fn writer_accepts_concurrent_arrivals_without_waiting() {
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
