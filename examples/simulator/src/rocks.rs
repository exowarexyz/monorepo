//! Naive reference storage for local development: user keys and values are written as-is to
//! RocksDB. A `meta` column family holds the state-floor row (see below). A separate `log`
//! column family keeps per-sequence-number batch payloads so the stream service can serve
//! replay and point lookups. Batch-log pruning is driven exclusively by the compact service's
//! `Sequence` scope.
//!
//! Both structures are written as SST files and ingested, bypassing the WAL and the memtables
//! entirely: `prepare` stages one sorted state file and one log file per commit group, and
//! `commit` ingests the log file first (its rows alone define durability — `open` derives the
//! frontier from the highest retained row and the state-floor meta row), then the state file,
//! and only then publishes and acks. The two ingestions are not atomic, but the window is one
//! group wide: a crash between them leaves the log durable and the state missing for at most the
//! last group, which `open` repairs by replaying the retained log rows above the state floor
//! within the last retained log file, before the store serves reads. The floor meta row is
//! written only by pruning — atomically with the log range tombstone or the pruned state keys —
//! so a store recovers by reading one meta row, one file listing, and replaying at most one
//! group.
//!
//! Any write failure in the pipeline is fatal: once a group's log rows are durable it cannot be
//! rolled back (its sequence numbers must never be re-issued), so the writer panics and the next
//! open rolls the store forward instead of any in-process recovery.

use std::cmp::Ordering as CmpOrdering;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;

use buffa::{Message, MessageView};
use bytes::Bytes;
use exoware_sdk::common::kv::v1::Entry;
use exoware_sdk::keys::KeyCodec;
use exoware_sdk::log::stream::v1::{
    GetResponse as StreamGetResponse, GetResponseView as StreamGetResponseView,
};
use exoware_sdk::prune_policy::{
    KeysScope, OrderEncoding, PolicyScope, PrunePolicyDocument, RetainPolicy,
};
use exoware_sdk::selector::compile_payload_regex;
use exoware_server::{
    Ingest, Log, LogBatch, Prune, Query, QueryExtra, RangeScan, RangeScanBatch, Sequence,
};
use parking_lot::Mutex;
use regex::bytes::Regex;
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DBCompressionType, DBIterator, Direction,
    IngestExternalFileOptions, IteratorMode, Options, SstFileWriter, WriteOptions, DB,
};
use tokio::sync::oneshot;
use tracing::debug;

const STATE_CF: &str = rocksdb::DEFAULT_COLUMN_FAMILY_NAME;
const META_CF: &str = "meta";
/// State floor: the published frontier at the time of the last prune. The state below it is
/// authoritative — log rows at or below it are never replayed at open (replaying them could
/// resurrect key-pruned rows), and the frontier at open is the maximum of this row and the
/// highest retained log row (deleting log rows must not regress the derived frontier). Only
/// pruning writes it, atomically with its deletes — commits never do.
const SEQ_META_KEY: &[u8] = b"sequence";
const LOG_CF: &str = "log";
const LOG_BATCH_KEY_LEN: usize = 8;
const PRUNE_SCAN_BATCH_SIZE: usize = 4096;
const DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;
/// Directory under the store path where SST files are staged before ingestion.
const LOG_INGEST_DIR: &str = "ingest";
/// Name prefix for the store's writer threads, whose panics are fatal by design. The binary's
/// panic hook matches on it to turn a writer panic into a process exit.
pub const WRITER_THREAD_PREFIX: &str = "simulator-rocks-";
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

/// Sequence frontier shared by the store and its writer stages.
struct Frontiers {
    /// Highest sequence whose log rows and state rows are both ingested; gates every
    /// sequence-addressed read (`current_sequence`, `get_batch`, `oldest_retained_batch`).
    /// Point reads of current state are deliberately ungated: state may lead this frontier by
    /// the one group being published, but never lags it. The durable frontier (highest sequence
    /// whose log rows are durable) is not tracked in-process — it only runs ahead of `published`
    /// while a group's state ingestion is in flight, and is re-derived at open from the retained
    /// log rows and the state-floor meta row.
    published: AtomicU64,
    /// Serializes prunes (so the persisted state floor never moves backward) and orders state
    /// visibility against floor reads: `commit` ingests and publishes each group's state under
    /// this lock, so a prune that loads `published` under it sees a frontier covering every row
    /// its scan could have observed.
    persist: Mutex<()>,
}

impl Frontiers {
    fn new(published: u64) -> Self {
        Self {
            published: AtomicU64::new(published),
            persist: Mutex::new(()),
        }
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

/// SST files staged for one commit group, ready to be ingested.
struct StagedFiles {
    /// Replay-log rows (ascending sequence order), destined for the log column family.
    log: PathBuf,
    /// Current-state rows (sorted by key, last write per key), destined for the default column
    /// family.
    state: PathBuf,
    /// Combined payload bytes staged, for debug logging.
    staged_bytes: usize,
}

/// One commit group covering a contiguous run of assigned sequence numbers.
struct PreparedWrite {
    writes: Vec<AssignedWrite>,
    staged: StagedFiles,
}

struct Writer {
    /// `None` only during `Drop`, which closes the channel before joining the workers.
    sender: Option<mpsc::Sender<WriteRequest>>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl Writer {
    /// Starts the two-stage write pipeline. `prepare` drains queued requests up to the
    /// configured byte cap, assigns a contiguous sequence number to each (continuing from
    /// `next`, the frontier derived at open), and stages each wave's log and state SST files
    /// (including their data syncs); `commit` ingests the log file, then the state file,
    /// publishes the frontier, and resolves the requests. The stages overlap, so one group's
    /// files are being staged while the previous group's are being ingested. Any write failure
    /// in either stage is fatal (the worker panics): the log rows alone define durability, so
    /// the next open re-derives the frontier and repairs at most the last group — sequence
    /// numbers never need to be reclaimed in-process.
    fn start(
        db: Arc<DB>,
        ingest_dir: PathBuf,
        frontiers: Arc<Frontiers>,
        next: u64,
        write_pipeline: RocksWritePipelineConfig,
    ) -> Self {
        let (request_sender, request_receiver) = mpsc::channel();
        // Rendezvous so `prepare` runs at most one wave ahead of `commit`: it hands off a staged
        // group, then stages the next while `commit` ingests this one.
        let (group_sender, group_receiver) = mpsc::sync_channel(0);
        let max_commit_batch_bytes = write_pipeline.max_commit_batch_bytes.get();

        let commit = thread::Builder::new()
            .name(format!("{WRITER_THREAD_PREFIX}commit"))
            .spawn(move || run_commit(db, frontiers, group_receiver))
            .expect("failed to spawn RocksDB commit worker");

        let prepare = thread::Builder::new()
            .name(format!("{WRITER_THREAD_PREFIX}prepare"))
            .spawn(move || {
                run_prepare(
                    ingest_dir,
                    next,
                    request_receiver,
                    group_sender,
                    max_commit_batch_bytes,
                )
            })
            .expect("failed to spawn RocksDB prepare worker");

        Self {
            sender: Some(request_sender),
            handles: vec![prepare, commit],
        }
    }

    /// Enqueues one ingest request and resolves once `commit` has durably published it.
    async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, String> {
        // An empty batch has no log row, so its sequence number could not be re-derived from the
        // log after a crash; rejecting it keeps every acked sequence recoverable. The RPC layer
        // already requires at least one entry per put.
        if kvs.is_empty() {
            return Err("cannot ingest an empty batch".to_string());
        }
        let (response, result) = oneshot::channel();
        self.sender
            .as_ref()
            .expect("sender lives until drop")
            .send(WriteRequest { kvs, response })
            .map_err(|_| "rocks writer stopped".to_string())?;
        result
            .await
            .map_err(|_| "rocks writer stopped before completing write".to_string())?
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // Closing the request channel lets `prepare` drain and exit, which drops the group
        // channel and stops `commit`; joining keeps background RocksDB writers from outliving
        // the store.
        self.sender.take();
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

/// Drains each byte-bounded wave of queued requests, assigns contiguous sequence numbers, stages
/// the wave's SST files, and hands the group to `commit`. Exits when the request channel closes
/// (store drop); panics if `commit` died, since that only happens on a fatal write error.
fn run_prepare(
    ingest_dir: PathBuf,
    mut next: u64,
    receiver: mpsc::Receiver<WriteRequest>,
    sender: mpsc::SyncSender<PreparedWrite>,
    max_commit_batch_bytes: usize,
) {
    while let Ok(first) = receiver.recv() {
        let (group, disconnected) =
            prepare_queued_write(&ingest_dir, &receiver, first, next, max_commit_batch_bytes);
        next = group
            .writes
            .last()
            .expect("groups are never empty")
            .sequence;
        if sender.send(group).is_err() {
            panic!("rocks commit worker died");
        }

        if disconnected {
            break;
        }
    }
}

/// Builds one prepared write from requests already queued behind `first` without waiting for new
/// arrivals, stopping once the accumulated payload reaches the soft byte cap. The request that
/// crosses the cap stays in the wave so a single large request can still make progress.
fn prepare_queued_write(
    ingest_dir: &Path,
    receiver: &mpsc::Receiver<WriteRequest>,
    first: WriteRequest,
    from: u64,
    max_batch_bytes: usize,
) -> (PreparedWrite, bool) {
    let mut writes = Vec::with_capacity(64);
    let mut staged_bytes = 0usize;
    let mut next = from;
    let mut request = first;
    let mut disconnected = false;

    loop {
        next = next
            .checked_add(1)
            .expect("rocks sequence number overflowed");
        // Payload counted twice: once as state rows and once inside the encoded log row.
        staged_bytes += 2 * request
            .kvs
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>();
        writes.push(AssignedWrite {
            sequence: next,
            request,
        });
        if staged_bytes >= max_batch_bytes || next == u64::MAX {
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

    let staged = stage_group_files(ingest_dir, &writes);
    (PreparedWrite { writes, staged }, disconnected)
}

/// Writes and syncs one commit group's two SST files: the replay-log rows (already in ascending
/// sequence order) and the current-state rows (sorted by key, keeping the last write per key).
/// The two files are built concurrently — the state file on a scoped thread while this thread
/// writes the log file. Ingestion later links them into their column families, so each payload
/// byte reaches the disk exactly once, in its final resting place. A staging failure is fatal;
/// leftover files are removed by the next open.
fn stage_group_files(ingest_dir: &Path, writes: &[AssignedWrite]) -> StagedFiles {
    let first = writes.first().expect("groups are never empty").sequence;
    let last = writes.last().expect("groups are never empty").sequence;
    let log_path = ingest_dir.join(format!("log-{first:020}-{last:020}.sst"));
    let state_path = ingest_dir.join(format!("state-{first:020}-{last:020}.sst"));

    let (log_result, state_result) = thread::scope(|scope| {
        let state = thread::Builder::new()
            .name(format!("{WRITER_THREAD_PREFIX}stage"))
            .spawn_scoped(scope, || stage_state_file(&state_path, writes))
            .expect("failed to spawn SST staging thread");
        let log_result = stage_log_file(&log_path, writes);
        (
            log_result,
            state.join().expect("state staging thread panicked"),
        )
    });
    let log_bytes = log_result.unwrap_or_else(|error| panic!("failed to stage log SST: {error}"));
    let state_bytes =
        state_result.unwrap_or_else(|error| panic!("failed to stage state SST: {error}"));
    StagedFiles {
        log: log_path,
        state: state_path,
        staged_bytes: log_bytes + state_bytes,
    }
}

/// Options for staged SST files. Uncompressed: compressing on the ingest path would trade ack
/// latency for bytes, and lower levels re-compress state during compaction per the CF options.
fn staging_options() -> Options {
    let mut options = Options::default();
    options.set_compression_type(DBCompressionType::None);
    options
}

/// Stages the replay-log SST: one row per sequence, keyed in ascending sequence order.
fn stage_log_file(path: &Path, writes: &[AssignedWrite]) -> Result<usize, String> {
    let options = staging_options();
    let mut writer = SstFileWriter::create(&options);
    writer.open(path).map_err(|e| e.to_string())?;
    let mut bytes = 0;
    for write in writes {
        let value = encode_log_value(write.sequence, &write.request.kvs);
        bytes += LOG_BATCH_KEY_LEN + value.len();
        writer
            .put(sequence_log_key(write.sequence), &value)
            .map_err(|e| e.to_string())?;
    }
    // `finish` syncs the file before it is linked into the DB.
    writer.finish().map_err(|e| e.to_string())?;
    Ok(bytes)
}

/// Stages the current-state SST: the group's rows sorted by key, with the last write per key
/// winning (across coalesced requests, in sequence order).
fn stage_state_file(path: &Path, writes: &[AssignedWrite]) -> Result<usize, String> {
    let mut rows: Vec<(&Bytes, &Bytes)> =
        Vec::with_capacity(writes.iter().map(|write| write.request.kvs.len()).sum());
    for write in writes {
        for (key, value) in &write.request.kvs {
            rows.push((key, value));
        }
    }
    // Stable sort: equal keys keep arrival order, so the last occurrence is the newest.
    rows.sort_by(|a, b| a.0.cmp(b.0));

    let options = staging_options();
    let mut writer = SstFileWriter::create(&options);
    writer.open(path).map_err(|e| e.to_string())?;
    let mut bytes = 0;
    for (index, (key, value)) in rows.iter().enumerate() {
        if rows.get(index + 1).is_some_and(|next| next.0 == *key) {
            continue;
        }
        bytes += key.len() + value.len();
        writer
            .put(key.as_ref(), value.as_ref())
            .map_err(|e| e.to_string())?;
    }
    // `finish` syncs the file before it is linked into the DB.
    writer.finish().map_err(|e| e.to_string())?;
    Ok(bytes)
}

/// Commits prepared groups one at a time — log ingestion, state ingestion, publish, ack — until
/// the group channel closes (store drop). Any write failure panics inside `commit_group`.
fn run_commit(db: Arc<DB>, frontiers: Arc<Frontiers>, receiver: mpsc::Receiver<PreparedWrite>) {
    while let Ok(group) = receiver.recv() {
        commit_group(&db, &frontiers, group);
    }
}

/// Commits one group: ingests its log file (durability), then its state file (visibility), then
/// publishes the frontier and resolves the requests. Any write failure is fatal (panic): once
/// the log rows are durable the group cannot be rolled back (its sequences must not be
/// re-issued), and the next open rolls it forward by replaying the log file — so nothing is ever
/// reclaimed or retried in-process. The panic drops the group's response channels, so waiting
/// callers observe an error even though the group may resurface after the restart repair — an
/// accepted at-least-once ambiguity of this severe error path.
fn commit_group(db: &DB, frontiers: &Frontiers, group: PreparedWrite) {
    assert!(!group.writes.is_empty(), "groups are never empty");
    let PreparedWrite { writes, staged } = group;
    let requests = writes.len();
    let last_sequence = writes
        .last()
        .expect("non-empty group has a last write")
        .sequence;

    // Log first: its rows define durability, and an ingested state file without its log rows
    // could leave keys in the store that were never part of a sequenced batch. This runs outside
    // the floor lock, which is safe against a concurrent prune: every sequence in this file is
    // above the published frontier (publish happens below, only after the state ingestion),
    // while a prune's log deletes are capped at a published frontier it loaded earlier — so the
    // prune's tombstone and file unlink are always disjoint from the file being ingested, and
    // RocksDB serializes the metadata edits themselves.
    ingest_staged_file(db, LOG_CF, &staged.log);

    // Ingest and publish under the floor lock: a prune loads the published frontier as its
    // state floor under the same lock, so no scan-visible state row can outrun the frontier
    // covering it (a key prune must never delete a row the floor does not cover).
    let publish_guard = frontiers.persist.lock();
    ingest_staged_file(db, STATE_CF, &staged.state);

    // Release so `current_sequence` readers only observe frontiers whose rows are readable.
    frontiers.published.store(last_sequence, Ordering::Release);
    drop(publish_guard);
    debug!(
        requests,
        staged_bytes = staged.staged_bytes,
        sequence = last_sequence,
        "committed write batch"
    );
    complete_assigned_writes(writes);
}

/// Ingests one staged SST file into `cf`. Ingestion links the file into the column family and
/// syncs the manifest, so the rows are durable and readable once this returns. Failure is fatal:
/// see `commit_group`.
fn ingest_staged_file(db: &DB, cf: &str, path: &Path) {
    let handle = db.cf_handle(cf).expect("CFs exist (created on open)");
    let mut ingest_options = IngestExternalFileOptions::default();
    ingest_options.set_move_files(true);
    db.ingest_external_file_cf_opts(handle, &ingest_options, vec![path])
        .unwrap_or_else(|error| {
            panic!(
                "failed to ingest staged SST {} into {cf}: {error}",
                path.display()
            )
        });
}

/// Writes a batch with sync enabled, used for the meta row that defines the durable floor.
fn write_synced_batch(db: &DB, batch: rocksdb::WriteBatch) -> Result<(), String> {
    let mut write_options = WriteOptions::default();
    write_options.set_sync(true);
    db.write_opt(batch, &write_options)
        .map_err(|e| e.to_string())
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

/// Returns the sequence of the highest retained log row, or zero when the log is empty. Rows are
/// only ever ingested by sequential, atomic commits, so the highest retained row is a lower bound
/// on the durable frontier (pruning persists the state floor atomically with its deletes, so the
/// floor covers whatever was pruned).
fn highest_log_row(db: &DB) -> Result<u64, String> {
    let log_cf = db
        .cf_handle(LOG_CF)
        .expect("log CF must exist (created on open)");
    match db.iterator_cf(log_cf, IteratorMode::End).next() {
        None => Ok(0),
        Some(item) => {
            let (key, _) = item.map_err(|e| e.to_string())?;
            sequence_from_log_key(key.as_ref())
        }
    }
}

/// Reads the state-floor meta row, defaulting to zero when no prune has written it yet.
fn read_state_floor(db: &DB) -> Result<u64, String> {
    let meta_cf = db
        .cf_handle(META_CF)
        .expect("meta CF must exist (created on open)");
    match db
        .get_cf(meta_cf, SEQ_META_KEY)
        .map_err(|e| e.to_string())?
    {
        Some(bytes) if bytes.len() == 8 => Ok(u64::from_le_bytes(bytes.try_into().unwrap())),
        _ => Ok(0),
    }
}

/// Repairs the current state after a crash that hit between a group's two ingestions: the log
/// file is durable but the state file may be missing, and only for the last committed group
/// (commit ingests strictly in order and publishes before starting the next group). Re-applies
/// the rows of the last retained log file — the group whose state might be missing is always
/// the one that ends at the durable frontier — which is idempotent because those rows are the
/// newest writes for their keys. Rows at or below `floor` are skipped: their state is already
/// authoritative, and key pruning may have deleted rows a replay would resurrect.
fn replay_last_log_file(db: &DB, floor: u64) -> Result<(), String> {
    let last_file_start = db
        .live_files()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|file| file.column_family_name == LOG_CF)
        .filter_map(|file| file.start_key.zip(file.end_key))
        .max_by(|a, b| a.1.cmp(&b.1))
        .map(|(start, _)| sequence_from_log_key(&start))
        .transpose()?;
    let Some(start) = last_file_start else {
        return Ok(());
    };
    let Some(above_floor) = floor.checked_add(1) else {
        // The floor covers every representable sequence; nothing can need replay.
        return Ok(());
    };
    let start = start.max(above_floor);

    let log_cf = db
        .cf_handle(LOG_CF)
        .expect("log CF must exist (created on open)");
    let mut batch = rocksdb::WriteBatch::default();
    let from = sequence_log_key(start);
    for item in db.iterator_cf(log_cf, IteratorMode::From(&from, Direction::Forward)) {
        let (key, value) = item.map_err(|e| e.to_string())?;
        let sequence = sequence_from_log_key(key.as_ref())?;
        let response = StreamGetResponseView::decode_view(value.as_ref())
            .map_err(|e| format!("corrupt log row for sequence {sequence}: {e}"))?;
        for entry in response.entries.iter() {
            batch.put(entry.key, entry.value);
        }
    }
    if !batch.is_empty() {
        // Synced: once a later commit moves the last-file replay bound past this group, a
        // repair lost to power loss would never be re-run.
        write_synced_batch(db, batch)?;
    }
    Ok(())
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

/// The machine's available parallelism, defaulting to two when it cannot be queried.
fn available_parallelism() -> NonZeroUsize {
    thread::available_parallelism().unwrap_or_else(|_| NonZeroUsize::new(2).expect("nonzero"))
}

/// RocksDB engine and application-level write pipeline options used by [`RocksStore::open`].
///
/// Column-family options are deliberately not configurable — the store's correctness leans on
/// stock CF behavior: staged state SSTs and range-scan bounds assume bytewise key order, crash
/// repair depends on log-CF file boundaries staying aligned with commit groups (see
/// `replay_last_log_file`), and rows must never be dropped by a caller-supplied compaction
/// filter or TTL (acked writes must stay readable, the meta CF's state-floor row must persist,
/// and the repair replay would nondeterministically resurrect expired state rows).
pub struct RocksConfig {
    /// Database-wide options. The default raises RocksDB's background-job budget (flushes and
    /// the compactions that must keep merging the overlapping ingested state SSTs) from the
    /// stock 2 to the machine's available parallelism; a caller replacing `db_options`
    /// replaces that choice too — open applies these options as-is.
    pub db_options: Options,
    /// Options for the application-level ingest write pipeline.
    pub write_pipeline: RocksWritePipelineConfig,
}

impl Default for RocksConfig {
    /// Stock RocksDB options, with the background-job budget raised to the machine's available
    /// cores. Memtables are off the hot path (only the open-time replay and prune deletes write
    /// them), so they stay at stock defaults.
    fn default() -> Self {
        let mut db_options = Options::default();
        db_options.increase_parallelism(available_parallelism().get() as i32);
        Self {
            db_options,
            write_pipeline: RocksWritePipelineConfig::default(),
        }
    }
}

/// Minimal RocksDB-backed store for the simulator: batch writes plus a global sequence u64
/// plus a per-sequence log.
#[derive(Clone)]
pub struct RocksStore {
    db: Arc<DB>,
    frontiers: Arc<Frontiers>,
    writer: Arc<Writer>,
}

impl RocksStore {
    /// Open the store with default options, unless `config` overrides the database or
    /// write-pipeline options (column families always run stock options — see [`RocksConfig`]).
    /// Re-derives the durable frontier from the retained
    /// log rows and the state-floor meta row, then replays the last retained log file's rows
    /// above the floor into the default column family so the current state is complete below
    /// the durable sequence even after a crash between a group's log and state ingestions.
    pub fn open(path: &Path, config: Option<RocksConfig>) -> Result<Self, String> {
        let RocksConfig {
            mut db_options,
            write_pipeline,
        } = config.unwrap_or_default();

        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);

        let cf_state = ColumnFamilyDescriptor::new(STATE_CF, Options::default());
        let cf_meta = ColumnFamilyDescriptor::new(META_CF, Options::default());
        let cf_log = ColumnFamilyDescriptor::new(LOG_CF, Options::default());
        let db = Arc::new(
            DB::open_cf_descriptors(&db_options, path, vec![cf_state, cf_meta, cf_log])
                .map_err(|e| e.to_string())?,
        );
        // Commits do not write the state-floor meta row; the log rows are the durable record.
        let floor = read_state_floor(&db)?;
        let seq = floor.max(highest_log_row(&db)?);

        let ingest_dir = prepare_ingest_dir(path)?;
        replay_last_log_file(&db, floor)?;

        let frontiers = Arc::new(Frontiers::new(seq));
        let writer = Arc::new(Writer::start(
            db.clone(),
            ingest_dir,
            frontiers.clone(),
            seq,
            write_pipeline,
        ));
        Ok(Self {
            db,
            frontiers,
            writer,
        })
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
    fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        self.db.get(key)
    }

    /// Deletes key-pruned current rows, atomically raising the state floor to the published
    /// frontier in the same synced batch. Every deleted row's log entry sits at or below that
    /// floor, so the replay at the next open cannot resurrect it — and the sync makes an acked
    /// prune durable.
    fn delete_keys(&self, keys: &[Bytes]) -> Result<(), String> {
        if keys.is_empty() {
            return Ok(());
        }

        let _guard = self.frontiers.persist.lock();
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(
            self.meta_cf(),
            SEQ_META_KEY,
            self.frontiers
                .published
                .load(Ordering::Acquire)
                .to_le_bytes(),
        );
        for k in keys {
            batch.delete(k.as_ref());
        }
        write_synced_batch(&self.db, batch)
    }

    /// Deletes replay-log batches with sequence numbers below `cutoff_exclusive`.
    fn prune_log(&self, cutoff_exclusive: u64) -> Result<(), String> {
        if cutoff_exclusive == 0 {
            return Ok(());
        }
        let _guard = self.frontiers.persist.lock();
        let cf = self.log_cf();

        // One synced, atomic batch: the range tombstone that logically deletes the rows, and the
        // state floor that keeps `open` from re-deriving a regressed frontier once those rows
        // are gone. The published frontier covers every pruned row (the cutoff is capped at
        // published + 1), and everything at or below it is durable and applied to the state.
        // That cap is also what makes this safe against `commit`'s concurrent, lock-free log
        // ingestion: an in-flight group's rows all sit above every published frontier this
        // prune could have loaded, so neither the tombstone nor the file unlink below can touch
        // them (and `delete_file_in_range_cf` only drops files entirely inside its range).
        let published = self.frontiers.published.load(Ordering::Acquire);
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(self.meta_cf(), SEQ_META_KEY, published.to_le_bytes());
        batch.delete_range_cf(cf, sequence_log_key(0), sequence_log_key(cutoff_exclusive));
        write_synced_batch(&self.db, batch)?;

        // Unlink the ingested SST files that sit entirely below the cutoff (the common case,
        // since each file covers one commit group's contiguous sequence range). This reclaims
        // their space immediately, without compaction ever reading the massive log payloads;
        // rows in a file straddling the cutoff stay covered by the tombstone above.
        self.db
            .delete_file_in_range_cf(
                cf,
                sequence_log_key(0),
                sequence_log_key(cutoff_exclusive - 1),
            )
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
        self.delete_keys(&all_deletes)
    }

    /// Computes the replay-log cutoff for a sequence policy and prunes only log rows.
    fn apply_sequence_prune_policy(&self, retain: &RetainPolicy) -> Result<(), String> {
        let current = self.frontiers.published.load(Ordering::Acquire);
        let cutoff_exclusive = match retain {
            RetainPolicy::KeepLatest { count } => {
                let count = *count as u64;
                current.saturating_add(1).saturating_sub(count)
            }
            RetainPolicy::GreaterThan { threshold } => threshold.saturating_add(1),
            RetainPolicy::GreaterThanOrEqual { threshold } => *threshold,
            RetainPolicy::DropAll => current.saturating_add(1),
        };
        // Never delete log rows above the published frontier: a group whose log ingestion
        // committed but whose state ingestion did not still needs its rows for the repair replay
        // at the next open.
        let cutoff_exclusive = cutoff_exclusive.min(current.saturating_add(1));
        self.prune_log(cutoff_exclusive)
    }
}

impl Sequence for RocksStore {
    fn current_sequence(&self) -> u64 {
        self.frontiers.published.load(Ordering::Acquire)
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

impl Log for RocksStore {
    async fn get_batch(&self, sequence_number: u64) -> Result<Option<LogBatch>, String> {
        // Serve only published batches: rows above the visible frontier are still being
        // committed and must not be observable early.
        if sequence_number > self.frontiers.published.load(Ordering::Acquire) {
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
                let sequence = sequence_from_log_key(key.as_ref())?;
                // Gate on the published frontier like `get_batch`: never advertise an oldest
                // batch that `get_batch` would then hide (log rows can outrun the published
                // frontier while a group's state ingestion is in flight or has failed).
                if sequence > self.frontiers.published.load(Ordering::Acquire) {
                    return Ok(None);
                }
                Ok(Some(sequence))
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

/// Encodes the replay payload for one sequence's key/value rows.
fn encode_log_value(sequence: u64, kvs: &[(Bytes, Bytes)]) -> Vec<u8> {
    StreamGetResponse {
        sequence_number: sequence,
        entries: kvs
            .iter()
            .map(|(key, value)| Entry {
                key: key.to_vec(),
                value: value.clone(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
    .encode_to_vec()
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

    /// Commits one group through the commit stage, returning the published frontier afterwards.
    fn commit_and_apply(store: &RocksStore, group: PreparedWrite) -> u64 {
        commit_group(&store.db, &store.frontiers, group);
        store.frontiers.published.load(Ordering::Acquire)
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

    fn prepared_write(store: &RocksStore, writes: Vec<AssignedWrite>) -> PreparedWrite {
        let ingest_dir = store.db.path().join(LOG_INGEST_DIR);
        let staged = stage_group_files(&ingest_dir, &writes);
        PreparedWrite { writes, staged }
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
    fn prepare_queued_write_collects_all_pending_below_byte_cap() {
        let dir = tempdir().expect("tempdir");
        let (sender, receiver) = mpsc::channel();
        sender.send(write_request(b"a")).expect("send");
        sender.send(write_request(b"b")).expect("send");
        sender.send(write_request(b"c")).expect("send");
        drop(sender);

        let first = receiver.recv().expect("first request");
        let (group, disconnected) = prepare_queued_write(
            dir.path(),
            &receiver,
            first,
            0,
            DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES,
        );
        assert_eq!(group.writes.len(), 3);
        assert!(group.staged.log.exists());
        assert!(group.staged.state.exists());
        assert!(group.staged.staged_bytes > 0);
        assert!(disconnected);
    }

    #[test]
    fn prepare_queued_write_stops_after_soft_byte_cap() {
        let dir = tempdir().expect("tempdir");
        let (sender, receiver) = mpsc::channel();
        sender.send(write_request(b"a")).expect("send");
        sender.send(write_request(b"b")).expect("send");
        sender.send(write_request(b"c")).expect("send");
        drop(sender);

        let first = receiver.recv().expect("first request");
        let (group, disconnected) = prepare_queued_write(dir.path(), &receiver, first, 0, 1);

        assert_eq!(group.writes.len(), 1);
        assert_eq!(group.writes[0].request.kvs[0].0.as_ref(), b"a");
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

    /// A missing staged file makes ingestion fail, which is fatal: the group cannot be rolled
    /// back once any of it is durable, and the next open repairs whatever the dead writer left.
    #[test]
    #[should_panic(expected = "failed to ingest staged SST")]
    fn write_errors_are_fatal() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        let group = prepared_write(&store, vec![assigned_write(1, b"a", b"1")]);
        std::fs::remove_file(&group.staged.state).expect("sabotage staged state file");
        commit_and_apply(&store, group);
    }

    /// One multi-megabyte batch, sized to exercise multi-block ingested log SSTs.
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
    async fn batches_commit_through_ingestion_and_survive_reopen() {
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

        // Sequence pruning drops the ingested rows like any other log rows, and unlinks the
        // pruned batches' SST files outright instead of leaving them for compaction.
        let log_files_before = live_log_files(&store);
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
        let log_files_after = live_log_files(&store);
        assert_eq!(log_files_before, 2, "one ingested file per batch");
        assert_eq!(log_files_after, 1, "pruned batch's file is unlinked");
    }

    /// Number of live SST files backing the log column family.
    fn live_log_files(store: &RocksStore) -> usize {
        store
            .db
            .live_files()
            .expect("live files")
            .into_iter()
            .filter(|file| file.column_family_name == LOG_CF)
            .count()
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
            // the durable log rows: append them directly, bypassing the state apply stage. No
            // sequence meta row is written — the reopened store must re-derive the durable
            // frontier from the retained rows alone, exactly as after a real crash (commits
            // never write the meta row).
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
            write_synced_batch(&store.db, log_batch).expect("write log rows");
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
        // A second reopen replays again (the floor only advances on prune); idempotent.
        drop(store);
        let store = RocksStore::open(dir.path(), None).expect("reopen db again");
        assert_eq!(store.current_sequence(), 3);
        assert_eq!(
            store.get_raw(b"k2").expect("get").as_deref(),
            Some(b"v2" as &[u8])
        );
    }

    #[tokio::test]
    async fn empty_batches_are_rejected() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let error = store.put_batch(Vec::new()).await.expect_err("must reject");
        assert_eq!(error, "cannot ingest an empty batch");
        assert_eq!(store.current_sequence(), 0);
    }

    #[tokio::test]
    async fn rocks_store_accepts_custom_config() {
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
    async fn prepared_write_preserves_contiguous_sequence_logs() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let prepared = prepared_write(
            &store,
            vec![
                assigned_write(1, b"a", b"1"),
                assigned_write(2, b"b", b"2"),
                assigned_write(3, b"c", b"3"),
            ],
        );

        assert_eq!(prepared.writes.len(), 3);
        let committed = commit_and_apply(&store, prepared);
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
    async fn sequence_prune_spares_log_rows_above_published_frontier() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        // A durable log row whose group never published (its state ingestion was in flight at a
        // crash): pruning must spare it — it is the repair replay's input at the next open.
        store
            .db
            .put_cf(
                store.log_cf(),
                sequence_log_key(1),
                encoded_log_entry(1, b"k", b"v"),
            )
            .expect("seed log row");

        store
            .apply_prune_policies(PrunePolicyDocument {
                version: exoware_sdk::prune_policy::PRUNE_POLICY_DOCUMENT_VERSION,
                policies: vec![exoware_sdk::prune_policy::PrunePolicy {
                    scope: PolicyScope::Sequence,
                    retain: RetainPolicy::DropAll,
                }],
            })
            .expect("prune");

        let survivors = store
            .db
            .iterator_cf(store.log_cf(), IteratorMode::Start)
            .count();
        assert_eq!(survivors, 1, "unpublished log row must survive the prune");
    }

    #[tokio::test]
    async fn oldest_retained_batch_hides_rows_above_published_frontier() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        store
            .db
            .put_cf(
                store.log_cf(),
                sequence_log_key(1),
                encoded_log_entry(1, b"k", b"v"),
            )
            .expect("seed log row");

        // The row's group never published (e.g. its state ingestion is still in flight), so it
        // must stay invisible to both the point read and the oldest-retained probe.
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
