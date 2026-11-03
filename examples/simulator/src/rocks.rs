//! RocksDB reference storage with atomic, durable writes.
//!
//! ```text
//!                parallel encoders       commit worker (sequence order)
//!                +-----------------+     +------------------------+
//! write groups ->| WriteBatch      |---->| lock publication       |
//!                | state values    |     | write batch + sync WAL |
//!                | stream response |     | publish sequence       |
//!                | sequence        |     | unlock                 |--> notify + reply
//!                +-----------------+     +------------------------+
//! ```
//!
//! Each batch spans the state, log, and metadata column families. The stream
//! preserves each group's rows in arrival order. Snapshot capture takes the
//! same lock so values and sequence describe the same committed prefix.
//!
//! Queued requests keep their admission leases and notifiers through commit,
//! even if their callers cancel. A write error stops the writer because the
//! batch may still appear after recovery.
//!
//! Reopening restores the sequence from metadata after WAL recovery. Pruning
//! keys or stream rows leaves that sequence intact.

#[cfg(test)]
use buffa::Message;
use buffa::ViewEncode;
use bytes::Bytes;
use commonware_codec::{Copying, DecodeExt, Encode};
#[cfg(test)]
use exoware_sdk::common::kv::v1::Entry;
#[cfg(test)]
use exoware_sdk::log::stream::v1::GetResponse as StreamGetResponse;
use exoware_sdk::{
    common::kv::v1::EntryView,
    keys::Prefix,
    limits::{put_encoded_len, PutTooLarge, MAX_PUT_ENTRIES, MAX_REQUEST_MESSAGE_BYTES},
    prune_policy::{KeysScope, OrderEncoding, PrunePolicyDocument, RetainPolicy},
    retention::{validate_retention_policy, RetentionPolicy},
    selector::compile_payload_regex,
};
use exoware_server::{
    ingest::{BudgetConfig, ByteLease, DecodeBuffers, IngestBudget, RequestLease},
    Ingest, IngestError, Log, LogBatch, Prune, PutError, PutInput, Query, QueryExtra, QueryResult,
    RangeScan, RangeScanBatch, RangeScanResult, Retention, Sequence, StreamNotifier,
};
use parking_lot::Mutex;
use regex::bytes::Regex;
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DBCompactionStyle, DBCompressionType, DBIterator,
    Direction, IteratorMode, Options, Snapshot, WriteOptions, DB,
};
use std::{
    cmp::Ordering as CmpOrdering,
    collections::BTreeMap,
    num::NonZeroUsize,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread,
};
use tokio::sync::oneshot;
use tracing::debug;

const STATE_CF: &str = rocksdb::DEFAULT_COLUMN_FAMILY_NAME;
const META_CF: &str = "meta";
const SEQ_META_KEY: &[u8] = b"sequence";
/// Meta row holding the active sequence-log retention rule (the codec-encoded
/// [`RetentionPolicy`]). Absence of the row means no rule is installed.
const RETENTION_META_KEY: &[u8] = b"retention";
const PRUNE_SCAN_BATCH_SIZE: usize = 4096;
const PRUNE_DELETE_CHUNK_KEYS: usize = 4096;
const DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;
const MAX_SEQUENCE_ENTRIES: usize = MAX_PUT_ENTRIES;
const LOG_CF: &str = "log";
const LOG_BATCH_KEY_LEN: usize = 8;
pub const WRITER_THREAD_PREFIX: &str = "simulator-rocks-";
const DEFAULT_STAGE_WORKERS: usize = 4;
const WRITER_OVERHEAD: usize = 16 * 1024;
type RocksIterItem = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>;

/// A resource dropped strictly after the database has closed (see [`Database`]).
type Closer = Box<dyn std::any::Any + Send + Sync>;

/// The open RocksDB handle plus everything that must outlive it.
///
/// Every holder of the database (store clones, the writer threads, open range-scan cursors,
/// in-flight blocking reads) shares one `Arc<Database>`, so the database closes exactly when
/// the last holder drops, wherever that happens. A closer attached at open drops strictly
/// after the database (fields drop in declaration order).
struct Database {
    db: DB,
    /// Dropped only after `db`. The database opens on a native copy of these options (see
    /// `RocksStore::open_database`), so this value is what keeps caller-supplied resources
    /// such as a custom environment or logger callback alive while the database is open.
    _options: Options,
    /// Dropped only after `db`: any resource that must outlive the open database. For a
    /// store opened with [`RocksStore::open_owned`], this is the owner whose drop deletes
    /// the data directory (for example a `tempfile::TempDir`).
    _closer: Option<Closer>,
}

impl std::ops::Deref for Database {
    type Target = DB;

    fn deref(&self) -> &DB {
        &self.db
    }
}

/// A snapshot and its published sequence, captured under the publication lock.
struct OwnedRocksSnapshot {
    snapshot: Snapshot<'static>,
    sequence_number: u64,
    _db: Arc<Database>,
}

impl OwnedRocksSnapshot {
    fn capture(db: Arc<Database>, frontiers: &Frontiers) -> Self {
        let _guard = frontiers.persist.lock();
        // SAFETY: `_db` keeps `db_ref` alive, and fields drop in declaration order,
        // so `snapshot` is released before its database.
        let db_ref: &'static DB = unsafe { &(*Arc::as_ptr(&db)).db };
        Self {
            snapshot: db_ref.snapshot(),
            sequence_number: frontiers.published.load(Ordering::Acquire),
            _db: db,
        }
    }
}

/// The iterator drops before its snapshot, which drops before the database.
struct OwnedRocksIterator {
    iter: DBIterator<'static>,
    _snapshot: OwnedRocksSnapshot,
}

impl OwnedRocksIterator {
    fn new(snapshot: OwnedRocksSnapshot, mode: IteratorMode<'_>) -> Self {
        let iter = snapshot.snapshot.iterator(mode);
        Self {
            iter,
            _snapshot: snapshot,
        }
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
    /// Creates an iterator positioned at the first row that may belong to the requested range.
    fn new(
        snapshot: OwnedRocksSnapshot,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Self {
        let mode = if forward {
            IteratorMode::From(start.as_ref(), Direction::Forward)
        } else if end.is_empty() {
            IteratorMode::End
        } else {
            IteratorMode::From(end.as_ref(), Direction::Reverse)
        };
        Self {
            iterator: OwnedRocksIterator::new(snapshot, mode),
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
    fn new(
        snapshot: OwnedRocksSnapshot,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Self {
        Self {
            state: Some(RocksRangeScanState::new(
                snapshot, start, end, limit, forward,
            )),
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

/// Sequence frontier shared by the store and its writer stages.
struct Frontiers {
    /// Highest sequence whose log and state rows are durably committed.
    published: AtomicU64,
    /// Serializes atomic commits, publication, snapshot capture, and log trimming.
    persist: Mutex<()>,
    /// Highest `cutoff_exclusive` already applied by `prune_log` in this process. Lets the
    /// per-append retention hook skip the write entirely when the floor has not advanced
    /// (static thresholds, coalesced ingest waves), so redundant range tombstones never pile
    /// up ahead of compaction. Starts at zero; open's one-shot enforcement re-seeds it
    /// when a rule is installed.
    trimmed: AtomicU64,
}

impl Frontiers {
    fn new(published: u64) -> Self {
        Self {
            published: AtomicU64::new(published),
            persist: Mutex::new(()),
            trimmed: AtomicU64::new(0),
        }
    }
}

// Cover owned row bytes, the encoded native batch, and the temporary stream payload.
// RocksDB memtables and its WAL buffer remain engine-owned allocations.
fn writer_growth(entries: usize, encoded_len: usize) -> usize {
    let row = std::mem::size_of::<(Bytes, Bytes)>();
    encoded_len
        .saturating_mul(3)
        .saturating_add(entries.saturating_mul(2 * row + 128))
}

fn writer_memory(entries: usize, encoded_len: usize, capacity: usize) -> usize {
    WRITER_OVERHEAD
        .saturating_add(writer_growth(entries, encoded_len))
        .saturating_add(capacity.saturating_mul(std::mem::size_of::<(Bytes, Bytes)>()))
}

#[derive(Default)]
struct WriterMemory {
    growth: Option<ByteLease>,
    rows: Option<ByteLease>,
}

impl WriterMemory {
    fn reserve(&mut self, request: &RequestLease, bytes: usize) -> Result<(), PutError> {
        if let Some(growth) = &mut self.growth {
            growth.try_extend(bytes)?;
        } else {
            self.growth = Some(request.reserve_bytes(bytes)?);
        }
        Ok(())
    }
}

struct WriteLease {
    _memory: WriterMemory,
    _request: Arc<RequestLease>,
}

struct WriteRequest {
    kvs: Vec<(Bytes, Bytes)>,
    encoded_len: usize,
    response: oneshot::Sender<Result<u64, IngestError>>,
    notifier: Option<Arc<dyn StreamNotifier>>,
    lease: Arc<WriteLease>,
}

/// One coalesced wave awaiting batch encoding: every request shares a single sequence number,
/// whose log row carries all their rows in arrival order.
struct QueuedWave {
    sequence: u64,
    rows: Vec<(Bytes, Bytes)>,
    requests: Vec<WriteRequest>,
    _leases: Vec<Arc<WriteLease>>,
}

/// One encoded atomic commit with all requests and admission leases still owned.
struct PreparedWrite {
    sequence: u64,
    batch: rocksdb::WriteBatch,
    encoded_bytes: usize,
    requests: Vec<WriteRequest>,
    _leases: Vec<Arc<WriteLease>>,
}

struct Writer {
    /// `None` only during `Drop`, which closes the channel before joining the workers.
    sender: Option<mpsc::Sender<WriteRequest>>,
    handles: Vec<thread::JoinHandle<()>>,
    local_budget: Arc<IngestBudget>,
}

impl Writer {
    /// Starts bounded parallel batch encoding and one ordered synchronous commit worker.
    fn start(
        db: Arc<Database>,
        frontiers: Arc<Frontiers>,
        write_pipeline: RocksWritePipelineConfig,
    ) -> Self {
        let next = frontiers.published.load(Ordering::Acquire);
        let (request_sender, request_receiver) = mpsc::channel();
        let max_commit_batch_bytes = write_pipeline.max_commit_batch_bytes.get();
        let stage_workers = write_pipeline.stage_workers.get();
        let max_queued_waves = write_pipeline.max_queued_waves.get();

        // Encoded groups queue toward the single ordered commit worker.
        let (staged_sender, staged_receiver) = mpsc::sync_channel(stage_workers);

        let commit = thread::Builder::new()
            .name(format!("{WRITER_THREAD_PREFIX}commit"))
            .spawn({
                let db = db.clone();
                move || run_commit(db, frontiers, staged_receiver, next)
            })
            .expect("failed to spawn RocksDB commit worker");

        // Queue capacity and retained admission leases bound preparation memory.
        let (wave_sender, wave_receiver) = mpsc::sync_channel::<QueuedWave>(max_queued_waves);
        let wave_receiver = Arc::new(Mutex::new(wave_receiver));
        let mut handles = Vec::with_capacity(stage_workers + 2);
        for worker in 0..stage_workers {
            let db = db.clone();
            let staged_sender = staged_sender.clone();
            let wave_receiver = wave_receiver.clone();
            handles.push(
                thread::Builder::new()
                    .name(format!("{WRITER_THREAD_PREFIX}stage-{worker}"))
                    .spawn(move || run_stage(db, wave_receiver, staged_sender))
                    .expect("failed to spawn RocksDB stage worker"),
            );
        }
        drop(staged_sender);
        drop(wave_receiver);

        let prepare = thread::Builder::new()
            .name(format!("{WRITER_THREAD_PREFIX}prepare"))
            .spawn(move || run_prepare(next, request_receiver, wave_sender, max_commit_batch_bytes))
            .expect("failed to spawn RocksDB prepare worker");

        handles.insert(0, prepare);
        handles.push(commit);
        Self {
            sender: Some(request_sender),
            handles,
            local_budget: IngestBudget::new(BudgetConfig::default()),
        }
    }

    /// Enqueues one ingest request and resolves once `commit` has durably published it.
    async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, IngestError> {
        // An empty batch would still cut a log row, but rejecting it keeps every sequence
        // backed by at least one entry. The RPC layer already requires at least one entry per
        // put.
        if kvs.is_empty() {
            return Err(IngestError::Internal {
                message: "cannot ingest an empty batch".to_string(),
            });
        }

        // Direct backend callers must also leave every committed sequence decodable.
        if kvs.len() > MAX_SEQUENCE_ENTRIES {
            return Err(PutTooLarge {
                entries: kvs.len(),
                max_entries: MAX_SEQUENCE_ENTRIES,
            }
            .into());
        }
        let encoded_len = put_encoded_len(
            kvs.iter()
                .map(|(key, value)| (key.as_ref(), value.as_ref())),
        );
        if encoded_len > MAX_REQUEST_MESSAGE_BYTES {
            return Err(IngestError::ResourceExhausted {
                message: "put exceeds the request message size limit".to_string(),
            });
        }

        let admission =
            self.local_budget
                .try_admit(0)
                .map_err(|error| IngestError::ResourceExhausted {
                    message: error.to_string(),
                })?;
        let request = admission.request_lease();
        let mut memory = WriterMemory::default();
        memory
            .reserve(&request, writer_memory(kvs.len(), encoded_len, kvs.len()))
            .map_err(|error| IngestError::ResourceExhausted {
                message: error.to_string(),
            })?;
        let mut admitted = Vec::with_capacity(kvs.len());
        for (key, value) in kvs {
            admitted.push((Bytes::copy_from_slice(&key), Bytes::copy_from_slice(&value)));
        }
        self.submit(admitted, encoded_len, None, memory, request)
            .await
    }

    async fn submit(
        &self,
        kvs: Vec<(Bytes, Bytes)>,
        encoded_len: usize,
        notifier: Option<Arc<dyn StreamNotifier>>,
        memory: WriterMemory,
        request: Arc<RequestLease>,
    ) -> Result<u64, IngestError> {
        let (response, result) = oneshot::channel();
        self.sender
            .as_ref()
            .expect("sender is None only during drop, which cannot overlap a call")
            .send(WriteRequest {
                kvs,
                encoded_len,
                response,
                notifier,
                lease: Arc::new(WriteLease {
                    _memory: memory,
                    _request: request,
                }),
            })
            .map_err(|_| IngestError::Internal {
                message: "rocks writer stopped".to_string(),
            })?;
        result.await.map_err(|_| IngestError::Internal {
            message: "rocks writer stopped before completing write".to_string(),
        })?
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // Closing the request channel lets the writer drain and exit; joining keeps the
        // background thread from outliving the store.
        self.sender.take();
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

/// Drains each byte-bounded wave of queued requests into a group with the next sequence number
/// and queues it for the stage workers. Exits when the request channel closes (store drop);
/// panics if every stage worker died, since that only happens on a fatal write error.
fn run_prepare(
    mut next: u64,
    receiver: mpsc::Receiver<WriteRequest>,
    waves: mpsc::SyncSender<QueuedWave>,
    max_commit_batch_bytes: usize,
) {
    let mut pending = None;
    while let Some(first) = pending.take().or_else(|| receiver.recv().ok()) {
        let (wave, carried) = coalesce_queued_write(&receiver, first, next, max_commit_batch_bytes);
        pending = carried;
        next = wave.sequence;
        if waves.send(wave).is_err() {
            panic!("rocks stage workers died");
        }
    }
}

/// Encodes groups from the shared queue without holding its lock during preparation.
fn run_stage(
    db: Arc<Database>,
    receiver: Arc<Mutex<mpsc::Receiver<QueuedWave>>>,
    sender: mpsc::SyncSender<PreparedWrite>,
) {
    loop {
        let Ok(wave) = receiver.lock().recv() else {
            break;
        };
        let group = prepare_wave(&db, wave);
        if sender.send(group).is_err() {
            panic!("rocks commit worker died");
        }
    }
}

/// Commits complete batches in sequence order, then publishes and acknowledges them.
fn run_commit(
    db: Arc<Database>,
    frontiers: Arc<Frontiers>,
    receiver: mpsc::Receiver<PreparedWrite>,
    mut committed: u64,
) {
    let mut pending: BTreeMap<u64, PreparedWrite> = BTreeMap::new();
    let commit_ready = |committed: &mut u64, pending: &mut BTreeMap<u64, PreparedWrite>| {
        while let Some(group) = pending.remove(&(*committed + 1)) {
            *committed = group.sequence;
            commit_group(&db, &frontiers, group);
        }
    };
    while let Ok(group) = receiver.recv() {
        pending.insert(group.sequence, group);
        commit_ready(&mut committed, &mut pending);
    }

    // Every preparation worker has handed over its groups before the channel closes.
    assert!(pending.is_empty(), "prepared groups lost at shutdown");
}

/// Coalesces one wave from requests already queued behind `first` without waiting for new
/// arrivals, stopping once the accumulated payload reaches the soft byte cap. The request that
/// crosses the cap stays in the wave so a single large request can still make progress.
/// Hard response limits carry an overflowing request intact into the next wave. Each wave
/// shares one sequence number and preserves arrival order.
fn coalesce_queued_write(
    receiver: &mpsc::Receiver<WriteRequest>,
    first: WriteRequest,
    from: u64,
    max_batch_bytes: usize,
) -> (QueuedWave, Option<WriteRequest>) {
    let sequence = from
        .checked_add(1)
        .expect("rocks sequence number overflowed");
    let mut leases = Vec::new();
    let mut requests = Vec::with_capacity(1);
    let mut rows: Vec<(Bytes, Bytes)> = Vec::with_capacity(first.kvs.len());
    let mut staged_bytes = 0usize;
    let mut encoded_bytes = 0;
    let mut request = first;
    let mut carried = None;

    loop {
        if !rows.is_empty()
            && (request.kvs.len() > MAX_SEQUENCE_ENTRIES.saturating_sub(rows.len())
                || request.encoded_len > MAX_REQUEST_MESSAGE_BYTES.saturating_sub(encoded_bytes))
        {
            carried = Some(request);
            break;
        }

        encoded_bytes += request.encoded_len;
        // Payload counted twice: once as state rows and once inside the encoded log batch.
        staged_bytes += 2 * request
            .kvs
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>();
        leases.push(request.lease.clone());
        rows.extend(request.kvs.iter().cloned());
        requests.push(request);
        if staged_bytes >= max_batch_bytes {
            break;
        }

        match receiver.try_recv() {
            Ok(next_request) => request = next_request,
            Err(_) => break,
        }
    }

    (
        QueuedWave {
            sequence,
            requests,
            rows,
            _leases: leases,
        },
        carried,
    )
}

/// Encodes the original stream rows and their current-state updates in one batch.
/// Ordered puts make the last duplicate win while the stream retains every entry.
fn prepare_wave(db: &DB, wave: QueuedWave) -> PreparedWrite {
    let log_cf = db.cf_handle(LOG_CF).expect("log CF exists");
    let meta_cf = db.cf_handle(META_CF).expect("meta CF exists");
    let mut batch = rocksdb::WriteBatch::default();
    batch.put_cf(
        log_cf,
        sequence_log_key(wave.sequence),
        encode_log_value(wave.sequence, &wave.rows),
    );
    for (key, value) in &wave.rows {
        batch.put(key, value);
    }
    batch.put_cf(meta_cf, SEQ_META_KEY, wave.sequence.to_le_bytes());
    let encoded_bytes = batch.size_in_bytes();
    PreparedWrite {
        sequence: wave.sequence,
        batch,
        encoded_bytes,
        requests: wave.requests,
        _leases: wave._leases,
    }
}

/// Makes the native batch durable before exposing its sequence to snapshots or streams.
/// A failed write can have an ambiguous durable outcome, so this worker stops on error.
fn commit_group(db: &DB, frontiers: &Frontiers, group: PreparedWrite) {
    assert!(!group.requests.is_empty(), "groups are never empty");
    let sequence = group.sequence;

    // Snapshot capture shares this lock to observe matching state and sequence.
    let publish_guard = frontiers.persist.lock();
    write_synced_batch(db, group.batch)
        .unwrap_or_else(|error| panic!("failed to commit synchronous WAL batch: {error}"));
    frontiers.published.store(sequence, Ordering::Release);
    drop(publish_guard);
    debug!(
        requests = group.requests.len(),
        encoded_bytes = group.encoded_bytes,
        sequence,
        "committed synchronous WAL batch"
    );
    for request in &group.requests {
        if let Some(notifier) = &request.notifier {
            notifier.advance(sequence);
        }
    }
    for request in group.requests {
        let _ = request.response.send(Ok(sequence));
    }
}

/// Syncs the WAL for the complete batch before returning success.
fn write_synced_batch(db: &DB, batch: rocksdb::WriteBatch) -> Result<(), String> {
    let mut write_options = WriteOptions::default();
    write_options.set_sync(true);
    write_options.disable_wal(false);
    db.write_opt(batch, &write_options)
        .map_err(|e| e.to_string())
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

/// Reads the durable frontier independently of the retained stream history.
fn read_committed_sequence(db: &DB) -> Result<u64, String> {
    let meta_cf = db
        .cf_handle(META_CF)
        .expect("meta CF must exist (created on open)");
    match db
        .get_cf(meta_cf, SEQ_META_KEY)
        .map_err(|e| e.to_string())?
    {
        Some(bytes) => {
            let bytes: [u8; 8] = bytes
                .try_into()
                .map_err(|_| "corrupt committed-sequence meta row".to_string())?;
            Ok(u64::from_le_bytes(bytes))
        }
        None => Ok(0),
    }
}

/// Reads the persisted retention rule. Absence of the row means no rule is installed (a cleared
/// rule deletes the row), so enforcement stops. A row that fails to decode or validate is
/// corruption and fails the open: a rule the RPC layer would reject (`keep_latest` count zero
/// enforces like `drop_all`) must not be enforced just because it round-trips the codec.
fn read_retention_policy(db: &DB) -> Result<Option<RetentionPolicy>, String> {
    let meta_cf = db
        .cf_handle(META_CF)
        .expect("meta CF must exist (created on open)");
    match db
        .get_cf(meta_cf, RETENTION_META_KEY)
        .map_err(|e| e.to_string())?
    {
        Some(bytes) => {
            let policy = RetentionPolicy::decode(Copying(bytes.as_slice()))
                .map_err(|e| format!("corrupt retention rule meta row: {e}"))?;
            validate_retention_policy(&policy)
                .map_err(|e| format!("corrupt retention rule meta row: {e}"))?;
            Ok(Some(policy))
        }
        None => Ok(None),
    }
}

/// Lowest sequence a retention rule keeps against `frontier`: the exclusive cutoff for log
/// trimming, so every row below it is evicted and the row at it (if any) is the oldest retained.
/// Mirrors the floor math the stream service owns end to end.
fn retention_floor(policy: &RetentionPolicy, frontier: u64) -> u64 {
    match policy {
        RetentionPolicy::KeepLatest { count } => frontier.saturating_sub(*count).saturating_add(1),
        RetentionPolicy::GreaterThan { threshold } => threshold.saturating_add(1),
        RetentionPolicy::GreaterThanOrEqual { threshold } => *threshold,
        RetentionPolicy::DropAll => frontier.saturating_add(1),
    }
}

/// Application-level write pipeline options used by [`RocksStore::open`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RocksWritePipelineConfig {
    /// Soft maximum combined size (state rows plus encoded log rows) before cutting a
    /// commit group.
    pub max_commit_batch_bytes: NonZeroUsize,
    /// Workers encoding atomic batches concurrently.
    pub stage_workers: NonZeroUsize,
    /// Coalesced waves that may queue ahead of the encoding workers. Admission leases
    /// remain held until commit; a single request may exceed the soft byte cap.
    pub max_queued_waves: NonZeroUsize,
}

impl Default for RocksWritePipelineConfig {
    fn default() -> Self {
        Self {
            max_commit_batch_bytes: NonZeroUsize::new(DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES)
                .expect("default commit batch byte limit must be nonzero"),
            stage_workers: NonZeroUsize::new(DEFAULT_STAGE_WORKERS)
                .expect("default stage worker count must be nonzero"),
            max_queued_waves: NonZeroUsize::new(DEFAULT_STAGE_WORKERS)
                .expect("default queued wave limit must be nonzero"),
        }
    }
}

/// RocksDB engine and application-level write pipeline options used by [`RocksStore::open`].
#[derive(Default)]
pub struct RocksConfig {
    /// Database-wide options. Ordered writes, WAL replay on open, and flushing during
    /// recovery are required for the snapshot and durable-commit contract and are pinned
    /// during open.
    pub db_options: Options,
    /// Options for the application-level ingest write pipeline.
    pub write_pipeline: RocksWritePipelineConfig,
}

/// Options for the state column family.
///
/// State keys can span overlapping ranges, so universal compaction merges whole sorted
/// runs. Raised level-zero slowdown and stop thresholds let compaction lag during ingest
/// bursts. Compression stays off to avoid its CPU cost during flushes and compaction.
fn state_cf_options() -> Options {
    let mut opts = Options::default();
    opts.set_compression_type(DBCompressionType::None);
    opts.set_bottommost_compression_type(DBCompressionType::None);
    opts.set_compaction_style(DBCompactionStyle::Universal);
    opts.set_level_zero_file_num_compaction_trigger(16);
    opts.set_level_zero_slowdown_writes_trigger(1024);
    opts.set_level_zero_stop_writes_trigger(2048);
    opts
}

/// Options for the log column family.
///
/// Log keys increase with the sequence, so successive batches occupy separate key ranges.
/// This family keeps the default compaction policy. Compression stays off to avoid its
/// CPU cost during flushes and compaction.
fn log_cf_options() -> Options {
    let mut opts = Options::default();
    opts.set_compression_type(DBCompressionType::None);
    opts.set_bottommost_compression_type(DBCompressionType::None);
    opts
}

/// Minimal RocksDB-backed store for the simulator: batch writes plus a global sequence u64
/// plus a per-sequence log.
#[derive(Clone)]
pub struct RocksStore {
    /// The last store drains its writer before releasing the database handle.
    writer: Arc<Writer>,
    db: Arc<Database>,
    frontiers: Arc<Frontiers>,
    /// In-memory mirror of the persisted retention rule (the meta row is the source of truth
    /// across reopens). The ingest path reads it on every commit to trim continuously, so a
    /// cheap cache keeps a rule-less store off the disk on that hot path.
    retention: Arc<Mutex<Option<RetentionPolicy>>>,
}

impl RocksStore {
    /// Open the store with default options, unless `config` overrides the database or
    /// write-pipeline options. Column families run options tuned to the store's write
    /// path (see `state_cf_options` and `log_cf_options`). Reads the durable sequence
    /// after RocksDB recovers its WAL.
    ///
    /// The caller keeps the directory at `path` alive until every handle to the store
    /// (clones, open cursors, in-flight operations) has dropped.
    /// [`RocksStore::open_owned`] hands that ordering to the store instead.
    pub fn open(path: &Path, config: Option<RocksConfig>) -> Result<Self, String> {
        Self::open_database(path, config, None)
    }

    /// Open a store that owns its data directory: `directory` is dropped strictly after the
    /// database has fully closed. Every store clone, open cursor, and in-flight operation
    /// keeps the database open, and the last of them releases the directory wherever it
    /// drops, so a directory whose drop has effects (for example `tempfile::TempDir`,
    /// which deletes it) can never be torn down under a live database.
    pub fn open_owned<D>(directory: D, config: Option<RocksConfig>) -> Result<Self, String>
    where
        D: AsRef<Path> + Send + Sync + 'static,
    {
        let path = directory.as_ref().to_path_buf();
        Self::open_database(&path, config, Some(Box::new(directory)))
    }

    /// Shared open path: see [`RocksStore::open`] for the recovery contract and
    /// [`RocksStore::open_owned`] for the directory-ownership contract.
    fn open_database(
        path: &Path,
        config: Option<RocksConfig>,
        closer: Option<Closer>,
    ) -> Result<Self, String> {
        let RocksConfig {
            mut db_options,
            write_pipeline,
        } = config.unwrap_or_default();

        // Create the database and its column families on first open. Ordered writes finish
        // each batch's memtable insert before the write returns, so a snapshot captured after
        // publication always includes the published batch.
        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);
        db_options.set_unordered_write(false);

        // Recovery must replay every WAL and flush what it recovers into synced SST files
        // before open returns. Best-efforts recovery ignores WAL files entirely, and RocksDB
        // never syncs a recovered WAL afterwards, so a sequence published from one could
        // vanish in a later crash. The crate has no typed setters for these options, and the
        // options-string parser yields a native copy of the caller's options that does not
        // keep their Rust-side resources alive, which is why the original options stay with
        // the database.
        let pinned = db_options
            .get_options_from_string(
                "best_efforts_recovery=false;avoid_flush_during_recovery=false",
            )
            .map_err(|e| e.to_string())?;

        // Open on the pinned copy. Each column family carries its own tuning, and the
        // caller's options stay with the database for as long as it is open.
        let cf_state = ColumnFamilyDescriptor::new(STATE_CF, state_cf_options());
        let cf_meta = ColumnFamilyDescriptor::new(META_CF, Options::default());
        let cf_log = ColumnFamilyDescriptor::new(LOG_CF, log_cf_options());
        let db = DB::open_cf_descriptors(&pinned, path, vec![cf_state, cf_meta, cf_log])
            .map_err(|e| e.to_string())?;
        let db = Arc::new(Database {
            db,
            _options: db_options,
            _closer: closer,
        });

        // WAL recovery restores the sequence committed atomically with state and log
        // rows. This metadata remains authoritative after the rows themselves are pruned.
        let seq = read_committed_sequence(&db)?;

        // Restore the retention rule so the ingest path keeps enforcing it after a reopen.
        let retention = Arc::new(Mutex::new(read_retention_policy(&db)?));

        // Publication and sequence allocation start at the same recovered sequence so
        // new batches continue after the durable prefix.
        let frontiers = Arc::new(Frontiers::new(seq));
        let writer = Arc::new(Writer::start(db.clone(), frontiers.clone(), write_pipeline));
        let store = Self {
            db,
            frontiers,
            writer,
            retention,
        };

        // Re-apply the rule against the reopened log before serving reads: a crash can
        // lose the last (unsynced) trim, and a batch observed as evicted must never
        // become readable again.
        if store.retention.lock().is_some() {
            store.enforce_retention()?;
        }
        Ok(store)
    }

    /// Returns the log column-family handle created during open.
    fn log_cf(&self) -> &ColumnFamily {
        self.db
            .cf_handle(LOG_CF)
            .expect("log CF must exist (created on open)")
    }

    /// Returns the meta column-family handle created during open.
    fn meta_cf(&self) -> &ColumnFamily {
        self.db
            .cf_handle(META_CF)
            .expect("meta CF must exist (created on open)")
    }

    /// Reads the current value for one default-column-family key.
    #[cfg(test)]
    fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        self.db.get(key)
    }

    /// Deletes keys in bounded chunks. The final synced write makes every deletion durable.
    fn delete_keys(&self, keys: &[Bytes]) -> Result<(), String> {
        let mut chunks = keys.chunks(PRUNE_DELETE_CHUNK_KEYS).peekable();
        while let Some(chunk) = chunks.next() {
            let mut batch = rocksdb::WriteBatch::default();
            for k in chunk {
                batch.delete(k.as_ref());
            }
            if chunks.peek().is_none() {
                write_synced_batch(&self.db, batch)?;
            } else {
                self.db.write(batch).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    /// Deletes stream-log rows with sequence numbers below `cutoff_exclusive`. A no-op when
    /// the cutoff does not advance past what this process already trimmed.
    fn prune_log(&self, cutoff_exclusive: u64) -> Result<(), String> {
        if cutoff_exclusive == 0
            || self.frontiers.trimmed.load(Ordering::Acquire) >= cutoff_exclusive
        {
            return Ok(());
        }

        // Recheck under the lock: a concurrent trim from the same ingest wave may have
        // covered this cutoff while we waited.
        let _guard = self.frontiers.persist.lock();
        if self.frontiers.trimmed.load(Ordering::Acquire) >= cutoff_exclusive {
            return Ok(());
        }

        // The committed sequence survives log collection independently of these rows.
        // A lost unsynced tombstone can only delay GC; open reapplies the durable rule.
        let mut batch = rocksdb::WriteBatch::default();
        batch.delete_range_cf(
            self.log_cf(),
            sequence_log_key(0),
            sequence_log_key(cutoff_exclusive),
        );
        self.db.write(batch).map_err(|e| e.to_string())?;
        self.frontiers
            .trimmed
            .store(cutoff_exclusive, Ordering::Release);
        Ok(())
    }

    /// Applies each prune policy in document order to current rows. A prune document is
    /// Keys-only; sequence-log retention is handled by `log.retention.v1.SetRetention`
    /// (see the [`Retention`] impl).
    fn apply_prune_policies(&self, document: PrunePolicyDocument) -> Result<(), String> {
        for policy in &document.policies {
            self.apply_key_prune_policy(&policy.scope, &policy.retain)?;
        }
        Ok(())
    }

    /// Scans matching current keys in bounded chunks, groups them, and deletes non-retained rows.
    fn apply_key_prune_policy(
        &self,
        scope: &KeysScope,
        retain: &RetainPolicy,
    ) -> Result<(), String> {
        let prefix =
            Prefix::new(scope.selector.prefix.clone()).map_err(|e| format!("policy: {e}"))?;
        let regex = compile_payload_regex(&scope.selector.payload_regex)
            .map_err(|e| format!("policy: {e}"))?;

        let (start, end) = prefix.bounds();
        let mut rows = RocksRangeScanState::new(
            OwnedRocksSnapshot::capture(self.db.clone(), &self.frontiers),
            start,
            end,
            usize::MAX,
            true,
        );
        let mut groups: BTreeMap<Vec<u8>, Vec<KeyEntry>> = BTreeMap::new();

        loop {
            let batch = rows.next_batch(PRUNE_SCAN_BATCH_SIZE)?;
            if batch.is_empty() {
                break;
            }

            for (key, _value) in batch {
                let payload = match prefix.strip(&key) {
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
        if all_deletes.is_empty() {
            return Ok(());
        }

        // The final delete chunk syncs all selected removals before this call returns.
        // Key pruning leaves the committed sequence and stream history intact.
        self.delete_keys(&all_deletes)
    }

    /// Lowest retained log sequence at or below the published frontier, or `None` when the log
    /// holds no such row. Shared by `oldest_retained_batch` and retention enforcement.
    fn oldest_retained_sequence(&self) -> Result<Option<u64>, String> {
        let mut it = self.db.iterator_cf(self.log_cf(), IteratorMode::Start);
        match it.next() {
            None => Ok(None),
            Some(item) => {
                let (key, _) = item.map_err(|e| e.to_string())?;
                let sequence = sequence_from_log_key(key.as_ref())?;

                // A native commit can finish before publication. Match `get_batch` so
                // this lookup never advertises a row readers cannot fetch.
                if sequence > self.frontiers.published.load(Ordering::Acquire) {
                    return Ok(None);
                }
                Ok(Some(sequence))
            }
        }
    }

    /// Persists the retention rule durably, or deletes the row when clearing. A single-admin
    /// control write, so it is synced and last-write-wins; enforcement reads go through the
    /// in-memory cache seeded from this row at open.
    fn store_retention_policy(&self, policy: Option<&RetentionPolicy>) -> Result<(), String> {
        let mut batch = rocksdb::WriteBatch::default();
        match policy {
            Some(policy) => batch.put_cf(self.meta_cf(), RETENTION_META_KEY, policy.encode()),
            None => batch.delete_cf(self.meta_cf(), RETENTION_META_KEY),
        }
        write_synced_batch(&self.db, batch)
    }

    /// Runs one round of retention enforcement against the current frontier and returns the
    /// resulting oldest retained sequence (`None` when the log is empty / no floor exists). With
    /// no rule installed this only reports the current oldest batch, leaving the log untouched.
    fn enforce_retention(&self) -> Result<Option<u64>, String> {
        // Clone the rule out in its own statement so the cache lock drops before trimming:
        // an `if let self.retention.lock().clone()` scrutinee would (edition 2021) hold the
        // guard for the whole block. `prune_log` takes the persist lock and issues a range
        // delete; holding the retention mutex across that disk write would block every
        // `put_batch` rule check on a Tokio worker.
        let policy = self.retention.lock().clone();
        if let Some(policy) = policy {
            let frontier = self.frontiers.published.load(Ordering::Acquire);

            // Collection is capped by the published prefix.
            let cutoff_exclusive =
                retention_floor(&policy, frontier).min(frontier.saturating_add(1));
            self.prune_log(cutoff_exclusive)?;
        }
        self.oldest_retained_sequence()
    }

    /// Installs (`Some`) or clears (`None`) the retention rule, then enforces it once. The rule
    /// is persisted durably and mirrored into the cache the ingest path reads, so it keeps
    /// tracking the frontier continuously; clearing stops enforcement but leaves already-evicted
    /// rows evicted. Returns the oldest retained sequence after this enforcement.
    fn set_retention(&self, policy: Option<RetentionPolicy>) -> Result<Option<u64>, String> {
        self.store_retention_policy(policy.as_ref())?;
        *self.retention.lock() = policy;
        self.enforce_retention()
    }
}

impl Sequence for RocksStore {
    fn current_sequence(&self) -> u64 {
        self.frontiers.published.load(Ordering::Acquire)
    }
}

struct AdmittedBatch {
    kvs: Vec<(Bytes, Bytes)>,
    memory: WriterMemory,
    request: Arc<RequestLease>,
}

impl AdmittedBatch {
    fn append(
        &mut self,
        chunk: &exoware_server::ingest::PutChunk,
        encoded_len: usize,
    ) -> Result<(), PutError> {
        let count = chunk.entries().len();
        let overhead = if self.memory.growth.is_none() {
            WRITER_OVERHEAD
        } else {
            0
        };
        self.memory
            .reserve(&self.request, writer_growth(count, encoded_len) + overhead)?;
        let required = self.kvs.len() + count;
        if required > self.kvs.capacity() {
            let capacity = required.max(self.kvs.capacity().saturating_mul(2));
            let rows = self
                .request
                .reserve_bytes(capacity * std::mem::size_of::<(Bytes, Bytes)>())?;
            let mut next = Vec::with_capacity(capacity);
            next.append(&mut self.kvs);

            // Keep the old backing charged until assignment destroys it.
            self.kvs = next;
            self.memory.rows = Some(rows);
        }
        self.kvs.extend(
            chunk
                .entries()
                .map(|(key, value)| (Bytes::copy_from_slice(key), Bytes::copy_from_slice(value))),
        );
        Ok(())
    }
}

impl Ingest for RocksStore {
    async fn put(&self, input: &mut PutInput) -> Result<u64, PutError> {
        let mut batch = Some(AdmittedBatch {
            kvs: Vec::new(),
            memory: WriterMemory::default(),
            request: input.request_lease(),
        });
        let mut encoded_len = 0usize;
        while let Some(chunk) = input.next_batch(DecodeBuffers::default()).await? {
            let Some(prepared) = batch.as_mut() else {
                continue;
            };
            let entries = chunk.entries();
            let count = entries.len();
            let chunk_len = put_encoded_len(entries);
            let rejection = if count > MAX_SEQUENCE_ENTRIES.saturating_sub(prepared.kvs.len()) {
                Some(IngestError::PutTooLarge(PutTooLarge {
                    entries: prepared.kvs.len() + count,
                    max_entries: MAX_SEQUENCE_ENTRIES,
                }))
            } else if chunk_len > MAX_REQUEST_MESSAGE_BYTES.saturating_sub(encoded_len) {
                Some(IngestError::ResourceExhausted {
                    message: "put exceeds the request message size limit".to_string(),
                })
            } else {
                None
            };
            if let Some(error) = rejection {
                input.reject(error.into());
                drop(batch.take());
                continue;
            }
            if let Err(error) = prepared.append(&chunk, chunk_len) {
                input.reject(error);
                drop(batch.take());
                continue;
            }
            encoded_len += chunk_len;
        }
        input.finish().await?;
        input.check_deadline()?;
        let batch = batch.expect("finalization rejects a failed writer reservation");
        let notifier = input.notifier();
        let sequence = self
            .writer
            .submit(
                batch.kvs,
                encoded_len,
                notifier,
                batch.memory,
                batch.request,
            )
            .await?;
        self.enforce_committed_retention(sequence).await;
        Ok(sequence)
    }
}

// Ingest uses dedicated writer threads so blocking storage writes do not occupy Tokio workers.
// The writer folds already-queued requests into one commit group that shares a single sequence
// number and stream-log batch.
impl RocksStore {
    /// Direct writes use a separate budget of 256 requests and 1 GiB.
    /// Mixed direct and HTTP traffic can consume this and the configured HTTP budget.
    pub async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, IngestError> {
        let sequence = self.writer.put_batch(kvs).await?;

        self.enforce_committed_retention(sequence).await;
        Ok(sequence)
    }

    async fn enforce_committed_retention(&self, sequence: u64) {
        // Best-effort: the batch is already durably committed and acked above, so a trim failure
        // must NOT fail the ingest. Failing here would make the caller re-ingest durable data
        // under a fresh sequence, duplicating the batch for subscribers. The trim is idempotent,
        // so the next append (or a `SetRetention`) reapplies it.
        if self.retention.lock().is_some() {
            let store = self.clone();
            match tokio::task::spawn_blocking(move || store.enforce_retention()).await {
                Ok(Ok(_)) => {}
                Ok(Err(message)) => tracing::warn!(
                    sequence,
                    error = %message,
                    "continuous retention trim failed after commit; batch is durable, retrying on the next append",
                ),
                Err(join_error) => tracing::warn!(
                    sequence,
                    error = %join_error,
                    "retention enforcement task failed after commit; batch is durable, retrying on the next append",
                ),
            }
        }
    }
}

impl Query for RocksStore {
    type RangeScan = RocksRangeScanCursor;

    async fn get(&self, key: Bytes) -> Result<QueryResult<Option<Bytes>>, String> {
        let snapshot = OwnedRocksSnapshot::capture(self.db.clone(), &self.frontiers);
        let value = snapshot
            .snapshot
            .get(key)
            .map_err(|e| e.to_string())?
            .map(Bytes::from);
        Ok(QueryResult {
            value,
            sequence_number: snapshot.sequence_number,
            extra: QueryExtra::default(),
        })
    }

    async fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Result<RangeScanResult<Self::RangeScan>, String> {
        let snapshot = OwnedRocksSnapshot::capture(self.db.clone(), &self.frontiers);
        let sequence_number = snapshot.sequence_number;
        Ok(RangeScanResult {
            scan: RocksRangeScanCursor::new(snapshot, start, end, limit, forward),
            sequence_number,
        })
    }

    async fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> Result<QueryResult<Vec<(Bytes, Option<Bytes>)>>, String> {
        let snapshot = OwnedRocksSnapshot::capture(self.db.clone(), &self.frontiers);
        let results = snapshot
            .snapshot
            .multi_get(keys.iter().map(|key| key.as_ref()));
        let entries = keys
            .into_iter()
            .zip(results)
            .map(|(k, r)| {
                let value = r.map_err(|e| e.to_string())?;
                Ok((k, value.map(Bytes::from)))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(QueryResult {
            value: entries,
            sequence_number: snapshot.sequence_number,
            extra: QueryExtra::default(),
        })
    }
}

// Pruning scans the full selector range and issues synced writes, so it runs on the blocking
// pool instead of occupying a Tokio worker.
impl Prune for RocksStore {
    async fn apply_prune_policies(&self, document: PrunePolicyDocument) -> Result<(), String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.apply_prune_policies(document))
            .await
            .map_err(|e| format!("prune task failed: {e}"))?
    }
}

// Log batches are loaded from the log column family on demand: no cache, one read per request.
impl Log for RocksStore {
    async fn get_batch(&self, sequence_number: u64) -> Result<Option<LogBatch>, String> {
        // Serve only published batches: rows above the visible frontier are still being
        // committed and must not be observable early.
        if sequence_number > self.frontiers.published.load(Ordering::Acquire) {
            return Ok(None);
        }

        // The read runs on the blocking pool so this future yields. An inline read
        // holds a Tokio worker for the whole RocksDB lookup, which serializes the
        // subscribe lookahead and stalls unrelated tasks on cold reads.
        let store = self.clone();
        let value = tokio::task::spawn_blocking(move || {
            store
                .db
                .get_cf(store.log_cf(), sequence_log_key(sequence_number))
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| format!("log read task failed: {e}"))??;

        let Some(value) = value else {
            return Ok(None);
        };
        Ok(Some(LogBatch::from_response_bytes(sequence_number, value)))
    }

    async fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
        self.oldest_retained_sequence()
    }
}

// Retention persists a rule (a synced write) and trims the sequence log, so it runs on the
// blocking pool instead of occupying a Tokio worker. The ingest path enforces the same rule
// continuously as the log grows (see `RocksStore::put_batch`).
impl Retention for RocksStore {
    async fn set_retention(&self, policy: Option<RetentionPolicy>) -> Result<Option<u64>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.set_retention(policy))
            .await
            .map_err(|e| format!("retention task failed: {e}"))?
    }
}

/// Encodes the batch payload served for one sequence's key/value rows.
fn encode_log_value(sequence: u64, kvs: &[(Bytes, Bytes)]) -> Vec<u8> {
    let sequence_len = if sequence == 0 {
        0
    } else {
        1 + buffa::encoding::varint_len(sequence)
    };
    let encoded_len = put_encoded_len(
        kvs.iter()
            .map(|(key, value)| (key.as_ref(), value.as_ref())),
    );
    let mut payload = Vec::with_capacity(sequence_len + encoded_len);
    if sequence != 0 {
        buffa::types::put_uint64_field(1, sequence, &mut payload);
    }
    let mut cache = buffa::SizeCache::new();
    for (key, value) in kvs {
        let entry = EntryView {
            key,
            value,
            ..Default::default()
        };
        let size = entry.compute_size(&mut cache);
        buffa::types::put_len_delimited_header(2, u64::from(size), &mut payload);
        entry.write_to(&mut cache, &mut payload);
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::encoding::varint_len;
    use exoware_sdk::{
        limits::{put_entry_encoded_len, MAX_RESPONSE_MESSAGE_BYTES, MAX_VALUE_LEN},
        log::ingest::v1::PutRequest,
    };
    use exoware_server::{Ingest, Log, Sequence};
    use std::{collections::BTreeSet, path::PathBuf};
    use tempfile::tempdir;

    fn wire_request(key: &[u8], value: &[u8]) -> Bytes {
        Bytes::from(
            PutRequest {
                kvs: vec![Entry {
                    key: key.to_vec(),
                    value: Bytes::copy_from_slice(value),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .encode_to_vec(),
        )
    }

    #[tokio::test]
    async fn fragmented_small_put_pays_writer_overhead_once() {
        let entry = wire_request(b"k", b"v");
        assert_eq!(entry.len(), 8);
        let wire = Bytes::from(entry.repeat(128));
        assert_eq!(wire.len(), 1024);
        for frames in [1, 128] {
            let dir = tempdir().unwrap();
            let store = RocksStore::open(dir.path(), None).unwrap();
            let budget = IngestBudget::new(BudgetConfig {
                max_requests: 1,
                max_bytes: 1024 * 1024,
            });
            let admission = budget.try_admit(wire.len()).unwrap();
            let fragments: Vec<_> = (0..frames)
                .map(|frame| {
                    let start = frame * wire.len() / frames;
                    let end = (frame + 1) * wire.len() / frames;
                    Ok::<_, std::io::Error>(wire.slice(start..end))
                })
                .collect();
            let mut input = PutInput::new(
                exoware_server::ingest::box_body(axum::body::Body::from_stream(
                    futures::stream::iter(fragments),
                )),
                exoware_server::ingest::PutMetadata::default(),
                exoware_server::ingest::PutLimits::default(),
                tokio::time::Instant::now() + std::time::Duration::from_secs(5),
                admission,
            );
            assert_eq!(store.put(&mut input).await.unwrap(), 1, "{frames} frames");
            assert_eq!(store.db.get(b"k").unwrap().unwrap(), b"v");
            let rows = store.get_batch(1).await.unwrap().unwrap();
            let response = rows.decode_response().unwrap();
            assert_eq!(response.entries.len(), 128);
            drop(input);

            // The receipt confirms publication before the writer drops its admission leases.
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while budget.usage() != (0, 0) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(budget.usage(), (0, 0));
        }
    }

    #[tokio::test]
    async fn published_receipt_can_precede_writer_admission_release() {
        struct PausedOwner {
            started: Option<oneshot::Sender<()>>,
            release: mpsc::Receiver<()>,
        }

        impl AsRef<[u8]> for PausedOwner {
            fn as_ref(&self) -> &[u8] {
                b"v"
            }
        }

        impl Drop for PausedOwner {
            fn drop(&mut self) {
                let _ = self.started.take().unwrap().send(());
                let _ = self.release.recv();
            }
        }

        let dir = tempdir().unwrap();
        let store = RocksStore::open(dir.path(), None).unwrap();
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 1024 * 1024,
        });
        let admission = budget.try_admit(0).unwrap();
        let request = admission.request_lease();
        let encoded_len = put_encoded_len((0..128).map(|_| (b"k".as_slice(), b"v".as_slice())));
        let reserved_bytes = writer_memory(128, encoded_len, 128);
        let mut memory = WriterMemory::default();
        memory.reserve(&request, reserved_bytes).unwrap();
        drop(admission);

        // Pausing the final payload drop makes the reply and cleanup ordering deterministic.
        let (started, dropping) = oneshot::channel();
        let (release, resume) = mpsc::channel();
        let value = Bytes::from_owner(PausedOwner {
            started: Some(started),
            release: resume,
        });
        let sequence = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            store.writer.submit(
                vec![(Bytes::from_static(b"k"), value); 128],
                encoded_len,
                None,
                memory,
                request,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), dropping)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sequence, 1);
        assert_eq!(store.current_sequence(), sequence);
        assert_eq!(store.db.get(b"k").unwrap().unwrap(), b"v");
        assert_eq!(budget.usage(), (1, reserved_bytes));
        assert!(budget.try_admit(0).is_err());

        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while budget.usage() != (0, 0) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(budget.try_admit(0).is_ok());
    }

    #[tokio::test]
    async fn row_growth_reserves_old_and_new_backing_before_allocation() {
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 1024 * 1024,
        });
        let wire = wire_request(b"k", b"v");
        let admission = budget.try_admit(2 * wire.len()).unwrap();
        let mut input = PutInput::new(
            exoware_server::ingest::box_body(axum::body::Body::from(wire.repeat(2))),
            exoware_server::ingest::PutMetadata::default(),
            exoware_server::ingest::PutLimits::default(),
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
            admission,
        );
        let mut batch = AdmittedBatch {
            kvs: Vec::new(),
            memory: WriterMemory::default(),
            request: input.request_lease(),
        };
        let chunk = input
            .next_batch(DecodeBuffers::new(1024, 1))
            .await
            .unwrap()
            .unwrap();
        batch.append(&chunk, wire.len()).unwrap();
        assert_eq!(batch.kvs.capacity(), 1);
        drop(chunk);
        let chunk = input
            .next_batch(DecodeBuffers::new(1024, 1))
            .await
            .unwrap()
            .unwrap();
        let old_allocation = batch.kvs.as_ptr();
        let row_bytes = std::mem::size_of::<(Bytes, Bytes)>();
        let available = writer_growth(1, wire.len()) + row_bytes;
        let pressure = batch
            .request
            .reserve_bytes(1024 * 1024 - budget.usage().1 - available)
            .unwrap();

        // A capacity delta would fit. The simultaneous replacement allocation does not.
        assert!(batch.append(&chunk, wire.len()).is_err());
        assert_eq!(batch.kvs.as_ptr(), old_allocation);
        assert_eq!(batch.kvs.len(), 1);
        assert_eq!(batch.kvs.capacity(), 1);
        drop(pressure);
        drop(chunk);
        drop(batch);
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[test]
    fn writer_reservation_growth_is_failure_atomic() {
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 32,
        });
        let admission = budget.try_admit(0).unwrap();
        let request = admission.request_lease();
        let mut memory = WriterMemory::default();
        memory.reserve(&request, 8).unwrap();
        memory.reserve(&request, 16).unwrap();
        assert_eq!(memory.growth.as_ref().unwrap().bytes(), 24);
        assert!(memory.reserve(&request, 9).is_err());
        assert_eq!(memory.growth.as_ref().unwrap().bytes(), 24);
        assert_eq!(budget.usage(), (1, 24));
        memory.reserve(&request, 8).unwrap();
        assert_eq!(budget.usage(), (1, 32));
        drop(memory);
        assert_eq!(budget.usage(), (1, 0));
        drop(request);
        drop(admission);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn cancelling_streamed_put_before_eof_never_enqueues() {
        struct SeenBatch(Arc<tokio::sync::Notify>);

        impl exoware_server::ingest::IngestObserver for SeenBatch {
            fn observe(&self, event: exoware_server::ingest::IngestEvent) {
                if matches!(event, exoware_server::ingest::IngestEvent::Batch { .. }) {
                    self.0.notify_one();
                }
            }
        }

        let dir = tempdir().unwrap();
        let store = RocksStore::open(dir.path(), None).unwrap();
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 1024 * 1024,
        });
        let admission = budget.try_admit(1024).unwrap();
        let (sender, receiver) = tokio::sync::mpsc::channel::<Bytes>(1);
        sender
            .send(wire_request(b"before-eof", b"value"))
            .await
            .unwrap();
        let stream = futures::stream::unfold(receiver, |mut receiver| async {
            receiver
                .recv()
                .await
                .map(|bytes| (Ok::<_, std::io::Error>(bytes), receiver))
        });
        let seen = Arc::new(tokio::sync::Notify::new());
        let mut input = PutInput::new(
            exoware_server::ingest::box_body(axum::body::Body::from_stream(stream)),
            exoware_server::ingest::PutMetadata::default(),
            exoware_server::ingest::PutLimits::default(),
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
            admission,
        )
        .with_observer(Arc::new(SeenBatch(seen.clone())));
        let put_store = store.clone();
        let task = tokio::spawn(async move { put_store.put(&mut input).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), seen.notified())
            .await
            .unwrap();
        assert_eq!(store.current_sequence(), 0);
        assert_eq!(budget.usage().0, 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while budget.usage() != (0, 0) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(store.current_sequence(), 0);
        assert!(store.db.get(b"before-eof").unwrap().is_none());
        drop(sender);
    }

    #[tokio::test]
    async fn malformed_suffix_releases_streamed_batch_without_publication() {
        let dir = tempdir().unwrap();
        let store = RocksStore::open(dir.path(), None).unwrap();
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 1024 * 1024,
        });
        let wire = wire_request(b"late-error", b"value");
        let admission = budget.try_admit(wire.len() + 1).unwrap();
        let stream = futures::stream::iter([
            Ok::<_, std::io::Error>(wire),
            Ok(Bytes::from_static(&[0x80])),
        ]);
        let mut input = PutInput::new(
            exoware_server::ingest::box_body(axum::body::Body::from_stream(stream)),
            exoware_server::ingest::PutMetadata::default(),
            exoware_server::ingest::PutLimits::default(),
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
            admission,
        );
        assert!(store.put(&mut input).await.is_err());
        assert_eq!(store.current_sequence(), 0);
        assert!(store.db.get(b"late-error").unwrap().is_none());
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn writer_reservation_failure_does_not_hide_malformed_tail() {
        struct ExhaustWriter {
            budget: Arc<IngestBudget>,
            request: Arc<RequestLease>,
            pressure: Mutex<Option<ByteLease>>,
            rejected: Arc<std::sync::atomic::AtomicBool>,
        }

        impl exoware_server::ingest::IngestObserver for ExhaustWriter {
            fn observe(&self, event: exoware_server::ingest::IngestEvent) {
                match event {
                    exoware_server::ingest::IngestEvent::Batch { .. } => {
                        let available = 1024 * 1024 - self.budget.usage().1;
                        *self.pressure.lock() =
                            Some(self.request.reserve_bytes(available - 1024).unwrap());
                    }
                    exoware_server::ingest::IngestEvent::Rejected => {
                        self.rejected.store(true, Ordering::Release);
                        self.pressure.lock().take();
                    }
                    _ => {}
                }
            }
        }

        let dir = tempdir().unwrap();
        let store = RocksStore::open(dir.path(), None).unwrap();
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 1024 * 1024,
        });
        let wire = wire_request(b"capacity", b"value");
        let admission = budget.try_admit(wire.len() + 1).unwrap();
        let rejected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observer = Arc::new(ExhaustWriter {
            budget: budget.clone(),
            request: admission.request_lease(),
            pressure: Mutex::new(None),
            rejected: rejected.clone(),
        });
        let stream = futures::stream::iter([
            Ok::<_, std::io::Error>(wire),
            Ok(Bytes::from_static(&[0x80])),
        ]);
        let mut input = PutInput::new(
            exoware_server::ingest::box_body(axum::body::Body::from_stream(stream)),
            exoware_server::ingest::PutMetadata::default(),
            exoware_server::ingest::PutLimits::default(),
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
            admission,
        )
        .with_observer(observer);
        let error = store.put(&mut input).await.unwrap_err().into_connect();
        assert!(rejected.load(Ordering::Acquire));
        assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
        assert!(error
            .message
            .as_deref()
            .unwrap()
            .contains("unexpected end of buffer"));
        assert_eq!(store.current_sequence(), 0);
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    // Keep publication blocked while cancelling an accepted request.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_streamed_put_after_enqueue_keeps_writer_and_notifier_alive() {
        struct Validated(tokio::sync::Notify);

        impl exoware_server::ingest::IngestObserver for Validated {
            fn observe(&self, event: exoware_server::ingest::IngestEvent) {
                if matches!(event, exoware_server::ingest::IngestEvent::Validated) {
                    self.0.notify_one();
                }
            }
        }

        let validated = Arc::new(Validated(tokio::sync::Notify::new()));
        let dir = tempdir().unwrap();
        let store = RocksStore::open(dir.path(), None).unwrap();
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 1024 * 1024,
        });
        let wire = wire_request(b"accepted", b"durable");
        let admission = budget.try_admit(wire.len()).unwrap();
        let hub = Arc::new(exoware_server::StreamHub::new(0));
        let notification = hub.subscribe();
        let notified = notification.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let mut input = PutInput::new(
            exoware_server::ingest::box_body(axum::body::Body::from(wire)),
            exoware_server::ingest::PutMetadata::default(),
            exoware_server::ingest::PutLimits::default(),
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
            admission,
        )
        .with_notifier(Some(hub.clone()))
        .with_observer(validated.clone());
        let publish_guard = store.frontiers.persist.lock();
        let put_store = store.clone();
        let task = tokio::spawn(async move { put_store.put(&mut input).await });

        // On this current-thread runtime, validation and enqueue finish in one poll.
        // The put task next yields while awaiting its writer response.
        tokio::time::timeout(std::time::Duration::from_secs(5), validated.0.notified())
            .await
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(store.current_sequence(), 0);
        assert_eq!(hub.current_sequence(), 0);
        assert_eq!(budget.usage().0, 1);
        assert!(budget.usage().1 > 0);
        assert!(budget.try_admit(0).is_err());

        // Cancellation leaves the accepted write with the writer. Once unblocked, it
        // must publish, notify subscribers, and release the admission budget.
        drop(publish_guard);
        tokio::time::timeout(std::time::Duration::from_secs(5), &mut notified)
            .await
            .unwrap();
        assert_eq!(store.current_sequence(), 1);
        assert_eq!(hub.current_sequence(), 1);
        assert_eq!(store.db.get(b"accepted").unwrap().unwrap(), b"durable");
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while budget.usage() != (0, 0) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    // Keep publication blocked while cancelling an accepted request.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn cancelled_writer_wait_keeps_admission_and_notifies_after_publication() {
        struct CheckedNotifier {
            hub: exoware_server::StreamHub,
            db: Arc<Database>,
            frontiers: Arc<Frontiers>,
        }

        impl StreamNotifier for CheckedNotifier {
            fn subscribe(&self) -> exoware_server::StreamNotification {
                self.hub.subscribe()
            }

            fn current_sequence(&self) -> u64 {
                self.hub.current_sequence()
            }

            fn advance(&self, sequence: u64) {
                assert_eq!(self.frontiers.published.load(Ordering::Acquire), sequence);
                assert_eq!(self.db.get(b"cancelled").unwrap().unwrap(), b"durable");
                self.hub.advance(sequence);
            }
        }

        struct CheckedOwner {
            budget: Arc<IngestBudget>,
            dropped: Arc<std::sync::atomic::AtomicBool>,
        }

        impl AsRef<[u8]> for CheckedOwner {
            fn as_ref(&self) -> &[u8] {
                b"durable"
            }
        }

        impl Drop for CheckedOwner {
            fn drop(&mut self) {
                let (requests, bytes) = self.budget.usage();
                assert_eq!(requests, 1);
                assert!(bytes > 0);
                self.dropped.store(true, Ordering::Release);
            }
        }

        let dir = tempdir().unwrap();
        let store = RocksStore::open(dir.path(), None).unwrap();
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 1024 * 1024,
        });
        let admission = budget.try_admit(0).unwrap();
        let request = admission.request_lease();
        let mut memory = WriterMemory::default();
        memory.reserve(&request, writer_memory(1, 32, 1)).unwrap();
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let value = Bytes::from_owner(CheckedOwner {
            budget: budget.clone(),
            dropped: dropped.clone(),
        });
        let notifier = Arc::new(CheckedNotifier {
            hub: exoware_server::StreamHub::new(0),
            db: store.db.clone(),
            frontiers: store.frontiers.clone(),
        });
        let notification = notifier.subscribe();
        let notified = notification.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let publish_guard = store.frontiers.persist.lock();
        let mut write = Box::pin(store.writer.submit(
            vec![(Bytes::from_static(b"cancelled"), value)],
            32,
            Some(notifier.clone()),
            memory,
            request,
        ));
        assert!(futures::poll!(&mut write).is_pending());
        drop(admission);
        drop(write);

        assert_eq!(budget.usage().0, 1);
        assert!(budget.try_admit(0).is_err());
        assert_eq!(notifier.current_sequence(), 0);
        assert!(!dropped.load(Ordering::Acquire));
        drop(publish_guard);
        tokio::time::timeout(std::time::Duration::from_secs(5), &mut notified)
            .await
            .unwrap();
        assert_eq!(notifier.current_sequence(), 1);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while budget.usage() != (0, 0) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(dropped.load(Ordering::Acquire));
    }

    fn write_request(key: &'static [u8]) -> WriteRequest {
        write_request_with_kvs(vec![(
            Bytes::from_static(key),
            Bytes::from_static(b"value"),
        )])
    }

    fn write_request_with_kvs(kvs: Vec<(Bytes, Bytes)>) -> WriteRequest {
        let (response, _result) = oneshot::channel();
        let encoded_len = put_encoded_len(
            kvs.iter()
                .map(|(key, value)| (key.as_ref(), value.as_ref())),
        );
        let bytes = writer_memory(kvs.len(), encoded_len, kvs.capacity());
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: bytes,
        });
        let admission = budget.try_admit(0).unwrap();
        let request = admission.request_lease();
        let mut memory = WriterMemory::default();
        memory.reserve(&request, bytes).unwrap();
        WriteRequest {
            kvs,
            encoded_len,
            response,
            notifier: None,
            lease: Arc::new(WriteLease {
                _memory: memory,
                _request: request,
            }),
        }
    }

    fn response_entries(response: StreamGetResponse) -> Vec<(Bytes, Bytes)> {
        response
            .entries
            .into_iter()
            .map(|entry| (Bytes::from(entry.key), entry.value))
            .collect()
    }

    fn batch_entries(batch: LogBatch) -> Vec<(Bytes, Bytes)> {
        response_entries(batch.decode_response().expect("decode batch response"))
    }

    /// Commits one group through the commit stage, returning the published frontier afterwards.
    fn commit_and_apply(store: &RocksStore, group: PreparedWrite) -> u64 {
        commit_group(&store.db, &store.frontiers, group);
        store.frontiers.published.load(Ordering::Acquire)
    }

    /// Encodes one commit group carrying `kvs` under the sequence after `from`.
    fn prepared_write(store: &RocksStore, from: u64, kvs: Vec<(Bytes, Bytes)>) -> PreparedWrite {
        let (_sender, receiver) = mpsc::channel::<WriteRequest>();
        let (wave, _) = coalesce_queued_write(
            &receiver,
            write_request_with_kvs(kvs),
            from,
            DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES,
        );
        prepare_wave(&store.db, wave)
    }

    #[test]
    fn snapshot_capture_waits_for_state_publication() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        // Keep the publication lock held after the write makes the new state durable.
        // Snapshot capture must wait until that state's sequence is published.
        let group = prepared_write(
            &store,
            0,
            vec![(Bytes::from_static(b"a"), Bytes::from_static(b"value"))],
        );
        let guard = store.frontiers.persist.lock();
        write_synced_batch(&store.db, group.batch).expect("native durable commit");
        assert_eq!(store.current_sequence(), 0);
        assert_eq!(
            store.db.get(b"a").expect("visible state"),
            Some(b"value".to_vec())
        );
        let reader = store.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let task = thread::spawn(move || {
            started_tx.send(()).expect("started");
            let snapshot = OwnedRocksSnapshot::capture(reader.db.clone(), &reader.frontiers);
            result_tx
                .send((
                    snapshot.sequence_number,
                    snapshot.snapshot.get(b"a").expect("snapshot get"),
                ))
                .expect("result");
        });
        started_rx.recv().expect("reader started");
        assert!(matches!(
            result_rx.recv_timeout(std::time::Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        store.frontiers.published.store(1, Ordering::Release);
        drop(guard);
        assert_eq!(
            result_rx.recv().expect("published snapshot"),
            (1, Some(b"value".to_vec()))
        );
        task.join().expect("reader");
    }

    #[test]
    fn snapshot_multi_get_survives_commit_and_prune() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let rows = vec![
            (Bytes::from_static(b"a"), Bytes::from_static(b"old")),
            (Bytes::from_static(b"b"), Bytes::from_static(b"old")),
        ];
        commit_and_apply(&store, prepared_write(&store, 0, rows));
        let snapshot = OwnedRocksSnapshot::capture(store.db.clone(), &store.frontiers);
        commit_and_apply(
            &store,
            prepared_write(
                &store,
                1,
                vec![
                    (Bytes::from_static(b"a"), Bytes::from_static(b"new")),
                    (Bytes::from_static(b"b"), Bytes::from_static(b"new")),
                ],
            ),
        );
        store
            .delete_keys(&[Bytes::from_static(b"b")])
            .expect("prune");
        let values = snapshot.snapshot.multi_get([b"a", b"b"]);
        assert_eq!(snapshot.sequence_number, 1);
        for value in values {
            assert_eq!(value.expect("snapshot value"), Some(b"old".to_vec()));
        }
        let latest = OwnedRocksSnapshot::capture(store.db.clone(), &store.frontiers);
        assert_eq!(latest.sequence_number, 2);
        assert_eq!(
            latest.snapshot.get(b"a").expect("new value"),
            Some(b"new".to_vec())
        );
        assert_eq!(latest.snapshot.get(b"b").expect("deleted"), None);
    }

    #[test]
    fn owned_directory_outlives_every_database_holder() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().to_path_buf();
        let store = RocksStore::open_owned(dir, None).expect("open owned store");

        // A cursor keeps the database, and therefore the owned directory, alive after every
        // store handle is gone.
        let cursor = RocksRangeScanCursor::new(
            OwnedRocksSnapshot::capture(store.db.clone(), &store.frontiers),
            Bytes::new(),
            Bytes::new(),
            usize::MAX,
            true,
        );
        drop(store);
        assert!(
            path.exists(),
            "directory must survive while a cursor still holds the database"
        );

        drop(cursor);
        assert!(
            !path.exists(),
            "directory must be deleted once the last database holder drops"
        );
    }

    /// A drop-order canary: reopening the path only succeeds once the previous database
    /// instance has released its `LOCK` file.
    struct ReopenOnDrop {
        path: PathBuf,
    }

    impl Drop for ReopenOnDrop {
        fn drop(&mut self) {
            DB::open(&Options::default(), &self.path)
                .expect("closer must drop only after the database has closed");
        }
    }

    #[test]
    fn closer_drops_only_after_database_closes() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("db");
        let mut options = Options::default();
        options.create_if_missing(true);
        let db = DB::open(&options, &path).expect("open db");

        // Struct fields drop in declaration order, so `db` drops (and releases its `LOCK`
        // file) before the canary closer runs. If the order ever flipped, the reopen inside
        // the closer would fail against the still-held lock.
        drop(Database {
            db,
            _options: options,
            _closer: Some(Box::new(ReopenOnDrop { path: path.clone() })),
        });
    }

    #[test]
    fn rocks_config_default_pins_commit_batch_cap() {
        assert_eq!(
            RocksConfig::default()
                .write_pipeline
                .max_commit_batch_bytes
                .get(),
            16 * 1024 * 1024
        );
    }

    #[test]
    fn coalesce_queued_write_collects_all_pending_below_byte_cap() {
        let dir = tempdir().expect("tempdir");
        let (sender, receiver) = mpsc::channel();
        sender.send(write_request(b"a")).expect("send");
        sender.send(write_request(b"b")).expect("send");
        sender.send(write_request(b"c")).expect("send");
        drop(sender);

        let first = receiver.recv().expect("first request");
        let (wave, carried) =
            coalesce_queued_write(&receiver, first, 0, DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES);
        assert_eq!(wave.sequence, 1);
        assert_eq!(wave.requests.len(), 3);
        assert!(carried.is_none());
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let group = prepare_wave(&store.db, wave);
        assert_eq!(group.sequence, 1);
        assert_eq!(group.requests.len(), 3);
        assert_eq!(group.batch.len(), 5);
        assert!(group.encoded_bytes > 0);
    }

    #[test]
    fn coalesce_queued_write_stops_after_soft_byte_cap() {
        let (sender, receiver) = mpsc::channel();
        sender.send(write_request(b"a")).expect("send");
        sender.send(write_request(b"b")).expect("send");
        sender.send(write_request(b"c")).expect("send");
        drop(sender);

        let first = receiver.recv().expect("first request");
        let (wave, carried) = coalesce_queued_write(&receiver, first, 0, 1);

        assert_eq!(wave.requests.len(), 1);
        assert_eq!(wave.requests[0].kvs[0].0.as_ref(), b"a");
        assert!(carried.is_none());
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

    #[test]
    fn coalescing_makes_progress_with_an_oversized_first_request() {
        for oversized_rows in [true, false] {
            let kvs = if oversized_rows {
                vec![(Bytes::from_static(b"a"), Bytes::new()); MAX_SEQUENCE_ENTRIES + 1]
            } else {
                vec![
                    (
                        Bytes::from_static(b"a"),
                        Bytes::from(vec![1; MAX_VALUE_LEN])
                    );
                    8
                ]
            };
            let first = write_request_with_kvs(kvs);
            let first_len = first.kvs.len();
            let (sender, receiver) = mpsc::channel();
            sender.send(write_request(b"next")).unwrap();
            drop(sender);

            let (wave, carried) = coalesce_queued_write(&receiver, first, 0, usize::MAX);
            assert_eq!(wave.sequence, 1);
            assert_eq!(wave.rows.len(), first_len);
            assert_eq!(wave.requests.len(), 1);
            let next = carried.unwrap();
            assert_eq!(next.kvs[0].0.as_ref(), b"next");

            let (wave, carried) = coalesce_queued_write(&receiver, next, wave.sequence, usize::MAX);
            assert_eq!(wave.sequence, 2);
            assert_eq!(wave.rows.len(), 1);
            assert_eq!(wave.requests.len(), 1);
            assert!(carried.is_none());
            assert!(matches!(
                receiver.try_recv(),
                Err(mpsc::TryRecvError::Disconnected)
            ));
        }
    }

    #[test]
    fn coalescing_preserves_whole_puts_at_and_across_entry_cap() {
        for second_len in [1, 2] {
            let (sender, receiver) = mpsc::channel();
            let first = write_request_with_kvs(vec![
                (Bytes::from_static(b"a"), Bytes::new());
                MAX_SEQUENCE_ENTRIES - 1
            ]);
            let second = write_request_with_kvs(vec![
                (
                    Bytes::from_static(b"b"),
                    Bytes::from_static(b"value")
                );
                second_len
            ]);
            sender.send(first).expect("send first");
            sender.send(second).expect("send second");
            sender.send(write_request(b"c")).expect("send third");
            drop(sender);

            let (waves, prepared) = mpsc::sync_channel(3);
            run_prepare(0, receiver, waves, DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES);
            let first = prepared.recv().expect("first wave");
            let second = prepared.recv().expect("second wave");
            assert_eq!((first.sequence, second.sequence), (1, 2));
            assert_eq!(
                first.rows.len(),
                MAX_SEQUENCE_ENTRIES - usize::from(second_len == 2)
            );
            assert_eq!(second.rows.len(), if second_len == 1 { 1 } else { 3 });
            assert_eq!(first.rows[0].0.as_ref(), b"a");
            assert_eq!(second.rows.last().expect("last row").0.as_ref(), b"c");
            let request_keys: Vec<_> = first
                .requests
                .iter()
                .chain(&second.requests)
                .map(|request| request.kvs[0].0.as_ref())
                .collect();
            assert_eq!(request_keys, [b"a", b"b", b"c"]);
            assert!(prepared.recv().is_err());
        }
    }

    #[test]
    fn coalescing_bounds_encoded_responses_above_soft_byte_cap() {
        let value = Bytes::from(vec![0; MAX_VALUE_LEN]);
        let (sender, receiver) = mpsc::channel();
        for key in [b"a", b"b", b"c"] {
            let request = write_request_with_kvs(vec![(Bytes::from_static(key), value.clone()); 3]);
            sender.send(request).expect("send request");
        }
        drop(sender);

        let (waves, prepared) = mpsc::sync_channel(3);
        run_prepare(0, receiver, waves, usize::MAX);
        let first = prepared.recv().expect("first wave");
        let second = prepared.recv().expect("second wave");
        assert_eq!((first.sequence, second.sequence), (1, 2));
        assert_eq!((first.requests.len(), second.requests.len()), (2, 1));
        assert!(
            put_encoded_len(
                first
                    .rows
                    .iter()
                    .map(|(key, value)| (key.as_ref(), value.as_ref()))
            ) <= MAX_REQUEST_MESSAGE_BYTES
        );
        assert_eq!(second.rows[0].0.as_ref(), b"c");
        assert!(prepared.recv().is_err());
    }

    #[test]
    fn coalescing_accepts_full_request_before_carrying_next() {
        let value = Bytes::from(vec![1; MAX_VALUE_LEN]);
        let overhead = 8 * put_entry_encoded_len(&[0], &value) - MAX_REQUEST_MESSAGE_BYTES;
        let kvs = (0..8)
            .map(|index| {
                let value = if index == 7 {
                    value.slice(..MAX_VALUE_LEN - overhead)
                } else {
                    value.clone()
                };
                (Bytes::from(vec![index]), value)
            })
            .collect();
        let first = write_request_with_kvs(kvs);
        assert_eq!(first.encoded_len, MAX_REQUEST_MESSAGE_BYTES);
        let (sender, receiver) = mpsc::channel();
        sender.send(first).unwrap();
        sender.send(write_request(b"next")).unwrap();
        drop(sender);
        let (waves, prepared) = mpsc::sync_channel(3);
        run_prepare(u64::MAX - 2, receiver, waves, usize::MAX);
        let first = prepared.recv().unwrap();
        let second = prepared.recv().unwrap();
        assert_eq!((first.sequence, second.sequence), (u64::MAX - 1, u64::MAX));
        assert_eq!((first.rows.len(), second.rows.len()), (8, 1));
        assert_eq!((first.requests.len(), second.requests.len()), (1, 1));
        assert!(
            put_encoded_len(
                first
                    .rows
                    .iter()
                    .map(|(key, value)| (key.as_ref(), value.as_ref()))
            ) + 1
                + varint_len(first.sequence)
                <= MAX_RESPONSE_MESSAGE_BYTES
        );
        assert_eq!(second.rows[0].0.as_ref(), b"next");
        assert!(prepared.recv().is_err());
    }

    #[test]
    fn put_size_matches_protobuf_framing() {
        assert_eq!(
            put_encoded_len(std::iter::empty()),
            PutRequest::default().encode_to_vec().len()
        );
        let mut kvs: Vec<_> = [0, 1, 127, 128, 16_383, 16_384]
            .into_iter()
            .map(|len| (Bytes::from(vec![1; len]), Bytes::from(vec![2; len])))
            .collect();
        kvs.extend([
            (Bytes::new(), Bytes::from_static(b"value")),
            (Bytes::from_static(b"key"), Bytes::new()),
        ]);
        let request = PutRequest {
            kvs: kvs
                .iter()
                .map(|(key, value)| Entry {
                    key: key.to_vec(),
                    value: value.clone(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let encoded_len = put_encoded_len(
            kvs.iter()
                .map(|(key, value)| (key.as_ref(), value.as_ref())),
        );
        assert_eq!(encoded_len, request.encode_to_vec().len());
        for sequence in [0, 1, 127, 128, u64::MAX] {
            let response = StreamGetResponse {
                sequence_number: sequence,
                entries: request.kvs.clone(),
                ..Default::default()
            };
            assert_eq!(encode_log_value(sequence, &kvs), response.encode_to_vec());
        }
    }

    #[tokio::test]
    async fn direct_oversized_puts_are_rejected_before_publication() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let entries = MAX_SEQUENCE_ENTRIES + 1;
        let error = store
            .put_batch(vec![(Bytes::new(), Bytes::new()); entries])
            .await
            .expect_err("reject oversized entry count");
        assert_eq!(
            error,
            IngestError::PutTooLarge(PutTooLarge {
                entries,
                max_entries: MAX_SEQUENCE_ENTRIES,
            })
        );

        let value = Bytes::from(vec![0; MAX_VALUE_LEN]);
        let kvs = vec![(Bytes::new(), value); 8];
        let error = store
            .put_batch(kvs)
            .await
            .expect_err("reject oversized encoded bytes");
        assert!(matches!(error, IngestError::ResourceExhausted { .. }));
        assert_eq!(store.current_sequence(), 0);
        assert_eq!(
            store
                .put_batch(vec![(Bytes::from_static(b"k"), Bytes::new())])
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn wal_commit_recovers_before_application_publication() {
        let dir = tempdir().expect("tempdir");
        let rows = vec![
            (Bytes::new(), Bytes::new()),
            (Bytes::from_static(b"k"), Bytes::from_static(b"old")),
            (Bytes::from_static(b"k"), Bytes::from_static(b"new")),
        ];

        // Close with a durable batch whose sequence was never published in memory.
        {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            let group = prepared_write(&store, 0, rows.clone());
            write_synced_batch(&store.db, group.batch).expect("native durable commit");
            assert_eq!(store.current_sequence(), 0);
            assert!(store.get_batch(1).await.expect("unpublished log").is_none());
        }
        let store = RocksStore::open(dir.path(), None).expect("reopen");
        assert_eq!(store.current_sequence(), 1);
        assert_eq!(store.get_raw(b"k").unwrap(), Some(b"new".to_vec()));
        assert_eq!(store.get_raw(b"").unwrap(), Some(Vec::new()));
        assert_eq!(
            batch_entries(store.get_batch(1).await.unwrap().unwrap()),
            rows
        );
        store.delete_keys(&[Bytes::from_static(b"k")]).unwrap();
        store.set_retention(Some(RetentionPolicy::DropAll)).unwrap();
        drop(store);
        let store = RocksStore::open(dir.path(), None).expect("reopen after GC");
        assert_eq!(store.current_sequence(), 1);
        assert_eq!(store.get_raw(b"k").unwrap(), None);
        assert!(store.get_batch(1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn wal_sequence_survives_gc_before_first_reopen() {
        let dir = tempdir().expect("tempdir");
        {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            let sequence = store
                .put_batch(vec![(Bytes::from_static(b"k"), Bytes::from_static(b"v"))])
                .await
                .expect("put");
            assert_eq!(sequence, 1);
            store.delete_keys(&[Bytes::from_static(b"k")]).unwrap();
            store.set_retention(Some(RetentionPolicy::DropAll)).unwrap();
        }
        let store = RocksStore::open(dir.path(), None).expect("reopen after GC");
        assert_eq!(store.current_sequence(), 1);
        assert_eq!(store.get_raw(b"k").unwrap(), None);
        assert!(store.get_batch(1).await.unwrap().is_none());
    }

    /// One multi-megabyte batch with a large stream record.
    fn large_batch(tag: u8) -> Vec<(Bytes, Bytes)> {
        (0..1040)
            .map(|i| {
                let mut key = vec![tag];
                key.extend_from_slice(&(i as u64).to_be_bytes());
                (Bytes::from(key), Bytes::from(vec![tag; 4096]))
            })
            .collect()
    }

    #[tokio::test]
    async fn batches_commit_through_wal_and_survive_reopen() {
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

        // Retention evicts log rows by key; space reclamation is compaction's job.
        store
            .set_retention(Some(RetentionPolicy::KeepLatest { count: 1 }))
            .expect("set retention");
        assert!(store.get_batch(first).await.expect("get").is_none());
        assert!(store.get_batch(second).await.expect("get").is_some());
        assert_eq!(
            store.oldest_retained_batch().await.expect("oldest"),
            Some(second)
        );
    }

    #[tokio::test]
    async fn reopen_enforces_restored_retention_rule() {
        let dir = tempdir().expect("tempdir");
        let (first, second, third) = {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            let first = store.put_batch(large_batch(1)).await.expect("put");
            let second = store.put_batch(large_batch(2)).await.expect("put");
            let third = store.put_batch(large_batch(3)).await.expect("put");
            // Persist the rule without running its enforcement, leaving rows below the
            // rule's floor in the log — the state a crash that lost the last (unsynced)
            // trim leaves behind.
            store
                .store_retention_policy(Some(&RetentionPolicy::KeepLatest { count: 1 }))
                .expect("store policy");
            (first, second, third)
        };

        let store = RocksStore::open(dir.path(), None).expect("reopen db");
        for evicted in [first, second] {
            assert!(store.get_batch(evicted).await.expect("get").is_none());
        }
        assert_eq!(
            store.oldest_retained_batch().await.expect("oldest"),
            Some(third)
        );
    }

    #[tokio::test]
    async fn reopen_rejects_invalid_persisted_retention_rule() {
        let dir = tempdir().expect("tempdir");
        {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            // Bypass `set_retention` (whose callers validate) to persist a rule the RPC
            // layer would reject: `keep_latest` count zero enforces like `drop_all`.
            store
                .store_retention_policy(Some(&RetentionPolicy::KeepLatest { count: 0 }))
                .expect("store policy");
        }

        let Err(error) = RocksStore::open(dir.path(), None) else {
            panic!("invalid rule must fail open");
        };
        assert!(error.contains("keep_latest count must be > 0"), "{error}");
    }

    /// Number of retained rows in the log column family.
    fn live_log_rows(store: &RocksStore) -> usize {
        store
            .db
            .iterator_cf(store.log_cf(), IteratorMode::Start)
            .count()
    }

    #[tokio::test]
    async fn empty_batches_are_rejected() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let error = store.put_batch(Vec::new()).await.expect_err("must reject");
        assert_eq!(
            error,
            IngestError::Internal {
                message: "cannot ingest an empty batch".to_string(),
            }
        );
        assert_eq!(store.current_sequence(), 0);
    }

    /// Concurrent puts prepared by parallel workers must still commit in
    /// contiguous sequence order and survive reopen.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_puts_commit_in_sequence_order() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        let puts: Vec<_> = (0..64u32)
            .map(|i| {
                let store = store.clone();
                tokio::spawn(async move {
                    let key = Bytes::from(format!("key-{i:03}"));
                    let value = Bytes::from(vec![i as u8; 4096]);
                    store.put_batch(vec![(key, value)]).await.expect("put")
                })
            })
            .collect();
        let mut sequences = Vec::with_capacity(puts.len());
        for put in puts {
            sequences.push(put.await.expect("put task"));
        }
        // Concurrent puts coalesce into shared-sequence waves; the waves must
        // still commit contiguously from 1 with none skipped or reordered.
        let top = store.current_sequence();
        sequences.sort_unstable();
        sequences.dedup();
        assert_eq!(sequences, (1..=top).collect::<Vec<u64>>());

        drop(store);
        let store = RocksStore::open(dir.path(), None).expect("reopen db");
        assert_eq!(store.current_sequence(), top);
    }

    /// A synced batch that still lives only in the WAL must survive a reopen, whatever
    /// recovery options the caller supplies.
    #[tokio::test]
    async fn reopen_replays_wal_under_best_efforts_recovery_request() {
        let dir = tempdir().expect("tempdir");

        // Request best-efforts recovery and skip the shutdown flush so the acknowledged
        // batch exists only in the WAL when the store reopens.
        let config = || RocksConfig {
            db_options: Options::default()
                .get_options_from_string(
                    "best_efforts_recovery=true;avoid_flush_during_shutdown=true",
                )
                .expect("database options"),
            ..Default::default()
        };

        // One acknowledged batch, then a clean close.
        {
            let store = RocksStore::open(dir.path(), Some(config())).expect("open db");
            let sequence = store
                .put_batch(vec![(Bytes::from_static(b"k"), Bytes::from_static(b"v"))])
                .await
                .expect("put");
            assert_eq!(sequence, 1);
        }

        // Nothing was flushed, so the batch can only come back through WAL replay.
        assert!(std::fs::read_dir(dir.path())
            .expect("read db dir")
            .filter_map(|entry| entry.ok())
            .all(|entry| entry.path().extension().is_none_or(|ext| ext != "sst")));

        // Reopening must replay the WAL despite the caller's recovery request.
        let store = RocksStore::open(dir.path(), Some(config())).expect("reopen db");
        assert_eq!(store.current_sequence(), 1);
        assert_eq!(store.get_raw(b"k").expect("get"), Some(b"v".to_vec()));
        assert!(store.get_batch(1).await.expect("get batch").is_some());
    }

    /// Required database settings and column-family tuning must reach RocksDB.
    /// Inspect the OPTIONS file the database persists on open.
    #[tokio::test]
    async fn database_and_column_family_options_apply() {
        let dir = tempdir().expect("tempdir");

        // Request the opposite of every pinned setting so the persisted options show the
        // pins winning.
        let db_options = Options::default()
            .get_options_from_string(
                "unordered_write=true;best_efforts_recovery=true;avoid_flush_during_recovery=true",
            )
            .expect("database options");
        let _store = RocksStore::open(
            dir.path(),
            Some(RocksConfig {
                db_options,
                ..Default::default()
            }),
        )
        .expect("open db");

        // RocksDB persists the effective options on every open, so the newest OPTIONS file
        // shows which values won.
        let options_file = std::fs::read_dir(dir.path())
            .expect("read db dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("OPTIONS-"))
            })
            .max()
            .expect("OPTIONS file exists");
        let options = std::fs::read_to_string(options_file).expect("read OPTIONS file");

        // Each pin overrides the caller's value.
        assert!(options.contains("unordered_write=false"));
        assert!(options.contains("best_efforts_recovery=false"));
        assert!(options.contains("avoid_flush_during_recovery=false"));

        // The state family runs universal compaction with raised level-zero thresholds and
        // no compression.
        let state = options
            .split("[CFOptions \"default\"]")
            .nth(1)
            .expect("state CF section")
            .split("[TableOptions")
            .next()
            .expect("state CF body");
        assert!(state.contains("compaction_style=kCompactionStyleUniversal"));
        assert!(state.contains("compression=kNoCompression"));
        assert!(state.contains("level0_slowdown_writes_trigger=1024"));

        // The log family keeps the default compaction policy and no compression.
        let log = options
            .split("[CFOptions \"log\"]")
            .nth(1)
            .expect("log CF section")
            .split("[TableOptions")
            .next()
            .expect("log CF body");
        assert!(log.contains("compression=kNoCompression"));
    }

    #[tokio::test]
    async fn rocks_store_accepts_custom_config() {
        let dir = tempdir().expect("tempdir");

        // A callback logger is a caller-supplied resource whose lifetime the database must
        // own. The lease inside the closure makes that lifetime observable.
        let logger_owner = Arc::new(());
        let logger_lease = logger_owner.clone();
        let mut db_options = Options::default();
        db_options.set_info_logger(rocksdb::InfoLogger::new_callback_logger(
            rocksdb::LogLevel::Info,
            move |_, _| {
                let _ = &logger_lease;
            },
        ));

        // Opening the store transfers the callback's lifetime to the database.
        let store = RocksStore::open(
            dir.path(),
            Some(RocksConfig {
                db_options,
                write_pipeline: RocksWritePipelineConfig {
                    max_commit_batch_bytes: NonZeroUsize::new(1).expect("nonzero"),
                    stage_workers: NonZeroUsize::new(2).expect("nonzero"),
                    max_queued_waves: NonZeroUsize::new(1).expect("nonzero"),
                },
            }),
        )
        .expect("open db");
        assert_eq!(Arc::strong_count(&logger_owner), 2);

        // Writes flow through the custom pipeline settings.
        let sequence = store
            .put_batch(vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))])
            .await
            .expect("put");
        assert_eq!(sequence, 1);
        assert_eq!(store.current_sequence(), 1);

        // The callback outlives every store handle and is released only when the database
        // closes.
        let db = store.db.clone();
        drop(store);
        assert_eq!(Arc::strong_count(&logger_owner), 2);
        drop(db);
        assert_eq!(Arc::strong_count(&logger_owner), 1);
    }

    #[tokio::test]
    async fn coalesced_group_shares_one_sequence() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let prepared = prepared_write(
            &store,
            0,
            vec![
                (Bytes::from_static(b"a"), Bytes::from_static(b"1")),
                (Bytes::from_static(b"b"), Bytes::from_static(b"2")),
            ],
        );
        assert_eq!(prepared.sequence, 1);
        assert_eq!(commit_and_apply(&store, prepared), 1);

        let second = prepared_write(
            &store,
            1,
            vec![(Bytes::from_static(b"c"), Bytes::from_static(b"3"))],
        );
        assert_eq!(second.sequence, 2);
        assert_eq!(commit_and_apply(&store, second), 2);

        // Each group serves one batch carrying all its rows.
        let batch = store
            .get_batch(1)
            .await
            .expect("get batch")
            .expect("batch retained");
        assert_eq!(
            batch_entries(batch),
            vec![
                (Bytes::from_static(b"a"), Bytes::from_static(b"1")),
                (Bytes::from_static(b"b"), Bytes::from_static(b"2")),
            ]
        );
        let batch = store
            .get_batch(2)
            .await
            .expect("get batch")
            .expect("batch retained");
        assert_eq!(
            batch_entries(batch),
            vec![(Bytes::from_static(b"c"), Bytes::from_static(b"3"))]
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
    async fn retention_spares_log_rows_above_published_frontier() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        // Make the batch durable without publishing its sequence. Retention must spare
        // its log row while it is above the published frontier.
        let group = prepared_write(
            &store,
            0,
            vec![(Bytes::from_static(b"k"), Bytes::from_static(b"v"))],
        );
        write_synced_batch(&store.db, group.batch).expect("native durable commit");

        store
            .set_retention(Some(RetentionPolicy::DropAll))
            .expect("set retention");

        assert_eq!(
            live_log_rows(&store),
            1,
            "unpublished log row must survive retention enforcement"
        );
    }

    #[tokio::test]
    async fn oldest_retained_batch_hides_rows_above_published_frontier() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        // Make the batch durable without publishing its sequence. Both the point read
        // and the oldest retained batch lookup must hide its log row.
        let group = prepared_write(
            &store,
            0,
            vec![(Bytes::from_static(b"k"), Bytes::from_static(b"v"))],
        );
        write_synced_batch(&store.db, group.batch).expect("native durable commit");

        assert!(store.get_batch(1).await.expect("get").is_none());
        assert_eq!(store.oldest_retained_batch().await.expect("oldest"), None);
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

    // The subscribe lookahead can only overlap log reads if `get_batch` yields.
    // An inline read completes within a single poll, so the in-flight gauge
    // would never exceed one and this test would fail.
    #[tokio::test]
    async fn get_batch_reads_overlap_under_buffered_lookahead() {
        use futures::StreamExt;

        let dir = tempdir().expect("tempdir");
        let store = Arc::new(RocksStore::open(dir.path(), None).expect("open db"));
        let batches = 8u64;
        for i in 0..batches {
            store
                .put_batch(vec![(
                    Bytes::from(format!("key-{i}")),
                    Bytes::from_static(b"value"),
                )])
                .await
                .expect("put");
        }

        let in_flight = Arc::new(AtomicU64::new(0));
        let max_in_flight = Arc::new(AtomicU64::new(0));
        let mut reads = futures::stream::iter(1..=batches)
            .map(|sequence| {
                let store = store.clone();
                let in_flight = in_flight.clone();
                let max_in_flight = max_in_flight.clone();
                async move {
                    let level = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    max_in_flight.fetch_max(level, Ordering::SeqCst);
                    let result = store.get_batch(sequence).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    result
                }
            })
            .buffered(batches as usize);
        while let Some(batch) = reads.next().await {
            batch.expect("get batch").expect("batch retained");
        }

        assert!(
            max_in_flight.load(Ordering::SeqCst) >= 2,
            "buffered get_batch reads never overlapped",
        );
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
