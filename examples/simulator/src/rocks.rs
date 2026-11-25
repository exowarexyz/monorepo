//! Naive reference storage for local development. User keys and values are written as-is to
//! RocksDB. A `log` column family keeps one row per commit group, the exact
//! `log.stream.v1.GetResponse` bytes the stream service serves for that sequence, loaded on
//! demand. A `meta` column family holds the state-floor row, the retention rule and the prune
//! policies.
//!
//! Everything is addressed by key. Recovery and pruning never assume which SST files rows live
//! in for their correctness, so RocksDB is free to place and compact them however it likes.
//!
//! # Write pipeline
//!
//! ```text
//!                                          stage workers
//!   put a --+                             +--> wave 6 --+
//!   put b --+   requests          waves   |             |   groups
//!   put c --+-----------> prepare --------+--> wave 7 --+-----------> commit --wake-up--> merge
//!   put d --+   unbounded    |   4 queued |             |   4 queued    |      1 queued
//!     ^                      |            +--> wave 8 --+               |
//!     |                   a b -> 6                                   6, 7, 8
//!     |                   c   -> 7                                   in order
//!     |                   d   -> 8                                      |
//!     +---------- each put gets its sequence, once published -----------+
//! ```
//!
//! Stage workers finish in any order, and `commit` holds a staged group until every earlier one
//! is applied. Both queues of four are defaults of [`RocksWritePipelineConfig`], and the wake-up
//! channel has room for one.
//!
//! # One commit
//!
//! ```text
//!                              ingest log file      apply state, publish         reply
//!                                     |                       |                    |
//!   time  ----------------------------+-----------------------+--------------------+------->
//!   log row 8                         [=====================================================
//!   state rows 8                                              [=============================
//!   published        <------------------ 7 ------------------>|<------------ 8 -------------
//!                                     |                       |
//!   a crash here     8 never existed  |  open replays row 8   |  8 is complete
//! ```
//!
//! A stage worker writes each group's log row and state rows as two SST files, and `commit`
//! ingests both (see `stage_wave`). Ingestion bypasses the WAL and the memtables.
//!
//! The durable log row alone defines a group. Each ingestion is atomic, and `commit` applies a
//! group's state before it ingests the next group's log row. A crash can therefore leave only
//! the newest group with a log row and no state, never a partial row or a partial state. `open`
//! re-applies the newest row above the state floor whether or not its state was complete (see
//! `replay_newest_log_row`).
//!
//! Any write failure in the pipeline is fatal. The writer panics and the next open rolls the
//! store forward (see `commit_group`).
//!
//! # Log files
//!
//! Each log row is ingested as its own file, bracketed by sentinel keys with empty values so that
//! ingestion and retention enforcement can skip its payload block (see `stage_log_file`). RocksDB
//! rebuilds a column family's file list on every ingestion into it, so commits slow down as the
//! families gain files.
//!
//! ```text
//!   log family, bottom level, without the merge
//!
//!   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ - - +-+
//!   |1|2|3|4|5|6|7|8| | | | | | | | | | | | | | | | | | | | | | | | |     |N|
//!   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ - - +-+
//!   |<------ N files after N commits, and every ingestion walks all N ----->|
//!
//!   with the merge
//!
//!   +-----------------+-----------------+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ - - +-+
//!   | 1 ..            |                 | | | | | | | | | | | | | | |     |N|
//!   +-----------------+-----------------+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ - - +-+
//!   |<--------- merged files ---------->|<-------- not merged yet --------->|
//! ```
//!
//! `commit` wakes the merge every `log_merge_files` groups, 1,024 by default (see
//! `plan_log_merge`). The merge copies each row with its sentinels and drops only what a
//! retention tombstone has already deleted.
//!
//! # Floor and retention
//!
//! `open` derives the frontier from the newest retained log row and the state floor, a meta row
//! that retention enforcement raises (see `RocksStore::prune_log`). A separate meta row persists
//! the active retention rule (see the [`Retention`] impl), and the ingest path re-enforces that
//! rule as the log grows.
//!
//! # Key pruning
//!
//! A Prune call replaces the installed policies with its own and replies. It writes the
//! request's document to a meta row and swaps the compiled policies that the state family's
//! compaction filter reads (see `RocksStore::install_prune_policies` and `PruneFilter`). The
//! rows a policy removes leave later, when RocksDB compacts the files that hold them, and the
//! store schedules no compaction for that.
//!
//! ```text
//!   Prune call   -----------[ write row ][ swap ]--> reply
//!                                       |       |
//!   meta row     .......................[############ stored document ########################
//!   policies     ...............................[####### compiled policies ###################
//!                                                            |                     |
//!                                                            v                     v
//!   compactions  -------------------------------------[ newer files ]-------[ every file ]--->
//!   a read finds k1 and k8 .........................................| k1 ................| none
//!
//!   # in force from here on      | the compaction above has finished
//! ```
//!
//! Both rows are ones a policy removes, k1 in the oldest file and k8 in a new one. A compaction
//! of the newer files removes k8, and k1 stays readable until a compaction takes the oldest
//! file.
//!
//! An installed policy also removes rows written after the call. It stays installed until the
//! store accepts another request, and that request's document replaces every installed policy.
//! A replaced policy stops deciding at the next key a compaction is shown, and the removals it
//! had already decided still land when their compaction finishes (see `PruneFilter`).
//!
//! Which rows `KeepLatest` removes depends on the other rows of their group, and a filter is shown
//! one row at a time. So the filter reads ahead in the live state to find the rows that follow
//! each one (see `ReadAhead::followed_by`). When a group's keys sort together, oldest first, a
//! compaction under an unchanged document removes every live row of the group it takes except the
//! latest `count` its read-ahead sees. Under any other layout it can keep more.
//!
//! `open` loads the document before the store serves. Re-applying the newest log row at open (see
//! `replay_newest_log_row`) can bring back rows of its commit group that a compaction had removed.
//! A policy that is still installed removes them again when a compaction takes them, and a row
//! that no installed policy removes stays.

#[cfg(test)]
use buffa::Message;
use buffa::{DecodeOptions, ViewEncode};
use bytes::Bytes;
use commonware_codec::{Copying, DecodeExt, Encode};
#[cfg(test)]
use exoware_sdk::common::kv::v1::Entry;
#[cfg(test)]
use exoware_sdk::log::stream::v1::GetResponse as StreamGetResponse;
use exoware_sdk::{
    common::kv::v1::EntryView,
    keys::Prefix,
    limits::{
        put_encoded_len, PutTooLarge, MAX_PUT_ENTRIES, MAX_REQUEST_MESSAGE_BYTES,
        MAX_RESPONSE_ELEMENT_MEMORY_BYTES, MAX_RESPONSE_MESSAGE_BYTES,
    },
    log::stream::v1::GetResponseView as StreamGetResponseView,
    prune_policy::{
        encode_policy_document, validate_policy_document, KeysScope, OrderEncoding, PrunePolicy,
        PrunePolicyDocument, RetainPolicy, PRUNE_POLICY_CONTROL_KEY,
    },
    retention::{validate_retention_policy, RetentionPolicy},
    selector::compile_payload_regex,
};
use exoware_server::{
    ingest::{BudgetConfig, ByteLease, DecodeBuffers, IngestBudget, RequestLease},
    Ingest, IngestError, Log, LogBatch, Prune, PutError, PutInput, Query, QueryExtra, QueryResult,
    RangeScan, RangeScanBatch, RangeScanResult, Retention, Sequence, StreamNotifier,
};
use parking_lot::Mutex;
use regex::bytes::{Captures, Regex};
use rocksdb::{
    compaction_filter::CompactionFilter,
    compaction_filter_factory::{CompactionFilterContext, CompactionFilterFactory},
    BlockBasedOptions, BottommostLevelCompaction, ColumnFamily, ColumnFamilyDescriptor,
    CompactOptions, CompactionDecision, DBCompactionStyle, DBCompressionType, DBIterator,
    DBRawIterator, Direction, IngestExternalFileOptions, IteratorMode, Options, ReadOptions,
    Snapshot, SstFileWriter, WriteOptions, DB,
};
use std::{
    cmp::Ordering as CmpOrdering,
    collections::{BTreeMap, VecDeque},
    ffi::CStr,
    marker::PhantomPinned,
    num::NonZeroUsize,
    ops::Range,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc, OnceLock, Weak,
    },
    thread,
};
use tokio::sync::oneshot;
use tracing::debug;

/// Column family of the state rows, RocksDB's default one.
const STATE_CF: &str = rocksdb::DEFAULT_COLUMN_FAMILY_NAME;

/// Column family of the store's own rows, the state floor, the retention rule and the prune
/// policies.
const META_CF: &str = "meta";

/// Meta row holding the state floor, a sequence number (see [`read_state_floor`]).
const SEQ_META_KEY: &[u8] = b"sequence";

/// Meta row holding the active sequence-log retention rule (the codec-encoded
/// [`RetentionPolicy`]). Absence of the row means no rule is installed.
const RETENTION_META_KEY: &[u8] = b"retention";

/// Meta row holding the installed prune policies as the SDK encodes a
/// [`PrunePolicyDocument`]. Absence of the row means no policy is installed.
const PRUNE_META_KEY: &[u8] = PRUNE_POLICY_CONTROL_KEY.as_bytes();

/// Fewest keys a read-ahead cursor is shown before the filter drops it for age (see
/// [`ReadAhead::aged`]). A cursor pins the files and memtables of the moment it was opened, so one
/// kept for a whole long compaction would keep alive files that other compactions have replaced.
/// The value is a round number.
const READ_AHEAD_REFRESH_KEYS: usize = 4096;

/// Default for [`RocksWritePipelineConfig::max_commit_batch_bytes`]. A larger wave commits
/// more requests at once and holds more memory while it is queued or staged. The value is a
/// round number.
const DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;

/// Most entries in one sequence, the protocol's limit for one put. A wave stops coalescing at
/// the limits of a single put, so every sequence fits in one response.
const MAX_SEQUENCE_ENTRIES: usize = MAX_PUT_ENTRIES;

/// Directory inside the store path where commit groups stage their SST files, so that ingestion
/// can hard-link them into the database. Where hard links are unsupported, as across
/// filesystems, RocksDB copies the file.
const LOG_INGEST_DIR: &str = "ingest";

/// Column family of the sequence log, one row per commit group.
const LOG_CF: &str = "log";

/// Length of a log row's key, the sequence number as a big-endian `u64`. Sentinel keys are
/// one byte longer, and readers tell them from rows by that length.
const LOG_BATCH_KEY_LEN: usize = 8;

/// Bottom level of the log column family, the last of RocksDB's default seven levels. Ingested
/// log files never overlap one another, so they normally land there, and the merge rewrites
/// them within it.
const LOG_BOTTOM_LEVEL: i32 = 6;

/// Default for [`RocksWritePipelineConfig::log_merge_files`]. The value is a round number.
const DEFAULT_LOG_MERGE_FILES: usize = 1024;

/// Size at which the merge cuts its output files. Larger files leave fewer for every commit
/// to pay for, and a retention cutoff that falls inside one costs a rewrite of the whole
/// file. The value is a round number.
const LOG_MERGE_TARGET_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Log files below this size are merged with their small neighbors. A merge's last output file can
/// fall below it and be merged again, so this also bounds what a merge rewrites of an earlier
/// one's output. The value equals RocksDB's default target file size.
const LOG_MERGE_SMALL_BYTES: u64 = 64 * 1024 * 1024;

/// Most bytes of bottom-level files one merge selects. This bounds a merge's temporary disk use
/// and the size of each merge a closing store waits for, unless a retention tombstone overlaps
/// the run and widens the compaction to every file it covers. The value is a round number.
const LOG_MERGE_PASS_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Most files one merge selects. RocksDB picks a manual compaction's files within one level in
/// time quadratic in their number, while it holds the database mutex that every commit and
/// snapshot needs. The value is four times the default merge trigger.
const LOG_MERGE_PASS_FILES: usize = 4096;

/// Size at which compaction cuts the state files it writes below level zero. Large files keep
/// down the file count that every state ingestion pays for. The value is four times RocksDB's
/// default target file size.
const STATE_TARGET_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Threads in the bottom-priority pool of RocksDB's default environment. A store on that
/// environment runs compactions into a family's last level there, apart from other compactions,
/// and the second thread lets a log merge start while a last-level state compaction holds the
/// first.
const BOTTOM_POOL_THREADS: i32 = 2;

/// Name prefix of every writer thread. A failed write is fatal to the store and panics its writer
/// thread, so a process can abort when a thread with this prefix panics.
pub const WRITER_THREAD_PREFIX: &str = "simulator-rocks-";

/// Default for [`RocksWritePipelineConfig::stage_workers`] and
/// [`RocksWritePipelineConfig::max_queued_waves`]. Each added worker or queue slot lets one more
/// wave stage or wait and holds that wave's payload in memory. The value is a round number.
const DEFAULT_STAGE_WORKERS: usize = 4;

/// Flat memory charge for one request, added to the charges that grow with its rows (see
/// [`writer_growth`]). The value is a round number.
const WRITER_OVERHEAD: usize = 16 * 1024;

type RocksIterItem = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>;

/// A resource dropped strictly after the database has closed (see [`Database`]).
type Closer = Box<dyn std::any::Any + Send + Sync>;

/// The open RocksDB handle plus everything that must outlive it.
///
/// Every holder of the store's database (store clones, the writer threads, open range-scan
/// cursors, in-flight blocking reads) shares one `Arc<Database>`, and the database closes when the
/// last of them drops, wherever that happens. A compaction filter holds only the inner handle, and
/// only while its compaction runs. A closer attached at open drops strictly after the database
/// (fields drop in declaration order).
struct Database {
    /// Shared only with the compaction filters while they read ahead (see [`ReadAhead`]).
    /// `Drop` ends every compaction first, so this is the last handle when the field drops.
    db: Arc<DB>,
    /// Dropped only after `db`: any resource that must outlive the open database. For a
    /// store opened with [`RocksStore::open_owned`], this is the owner whose drop deletes
    /// the data directory (for example a `tempfile::TempDir`).
    _closer: Option<Closer>,
}

impl Drop for Database {
    fn drop(&mut self) {
        // Stopping background work ends every compaction, and a compaction destroys its
        // filter as it ends. A filter left holding `db` would otherwise close the database
        // on a compaction thread, from inside the compaction the close then waits for.
        // Every store on one RocksDB environment shares its thread pools, and the stop also
        // waits for this database's queued jobs to leave them, so a close can wait for another
        // store's compaction.
        self.db.cancel_all_background_work(true);
    }
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

/// Extracts the per-key ordering value used to decide which matching keys a prune policy retains.
fn extract_order_value(captures: &Captures<'_>, scope: &KeysScope) -> Option<Vec<u8>> {
    let order_by = scope.order_by.as_ref()?;
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
fn extract_group_key(captures: &Captures<'_>, scope: &KeysScope) -> Option<Vec<u8>> {
    if scope.group_by.capture_groups.is_empty() {
        return Some(Vec::new());
    }
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

/// A policy's retain rule as the compaction filter evaluates it, with a threshold already in
/// the encoding of the order values it is compared with.
enum PruneRule {
    KeepLatest { count: usize },
    GreaterThan { threshold: [u8; 8] },
    GreaterThanOrEqual { threshold: [u8; 8] },
    DropAll,
}

/// One installed prune policy, compiled once when the store installs it or loads it at open.
struct CompiledPolicy {
    prefix: Prefix,
    regex: Regex,
    scope: KeysScope,
    rule: PruneRule,
}

impl CompiledPolicy {
    /// Compiles `policy`, or says why the store cannot apply it.
    fn compile(policy: &PrunePolicy) -> Result<Self, String> {
        let scope = policy.scope.clone();
        let prefix =
            Prefix::new(scope.selector.prefix.clone()).map_err(|e| format!("policy: {e}"))?;
        let regex = compile_payload_regex(&scope.selector.payload_regex)
            .map_err(|e| format!("policy: {e}"))?;
        let rule = match policy.retain {
            RetainPolicy::KeepLatest { count } => PruneRule::KeepLatest { count },
            RetainPolicy::GreaterThan { threshold } => PruneRule::GreaterThan {
                threshold: threshold_order_value(&scope, threshold)?,
            },
            RetainPolicy::GreaterThanOrEqual { threshold } => PruneRule::GreaterThanOrEqual {
                threshold: threshold_order_value(&scope, threshold)?,
            },
            RetainPolicy::DropAll => PruneRule::DropAll,
        };
        Ok(Self {
            prefix,
            regex,
            scope,
            rule,
        })
    }

    /// The group and the order value of `key`, or `None` when the policy does not select it.
    fn member(&self, key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let payload = self.prefix.strip_slice(key)?;
        let captures = self.regex.captures(payload)?;
        let group = extract_group_key(&captures, &self.scope)?;
        let order = extract_order_value(&captures, &self.scope).unwrap_or_default();
        Some((group, order))
    }
}

/// Compiles every policy of a document, in document order.
fn compile_policies(policies: &[PrunePolicy]) -> Result<Arc<[CompiledPolicy]>, String> {
    policies.iter().map(CompiledPolicy::compile).collect()
}

/// The installed prune policies, shared by the Prune call and the state family's filters.
//
// The two locks are separate so that a filter never waits for an install's write. An install
// holds `install` across a synced write, and that write can wait on a write stall that ends
// only when state compactions run. Every state compaction builds a filter first.
#[derive(Default)]
struct PrunePolicies {
    /// Held by an install from its write of the meta row to its swap, so the row and `compiled`
    /// change in the same order.
    install: Mutex<()>,
    /// The policies of the meta row, compiled. A new filter takes the list in force when it is
    /// built.
    compiled: Mutex<Arc<[CompiledPolicy]>>,
    /// Counts the changes of `compiled`. A running filter compares it at every key, so a
    /// replaced policy stops deciding at the next key.
    generation: AtomicU64,
    /// The open database, for the filters that read ahead. `open` sets it once the database
    /// exists, and until then a filter keeps every key of a `KeepLatest` policy. The handle is
    /// weak because the database owns the filter factory and the factory holds this cell.
    db: OnceLock<Weak<DB>>,
    /// Held by a test to stop every filter that has taken the database and is about to open
    /// its read-ahead cursor.
    #[cfg(test)]
    read_ahead_gate: Mutex<()>,
    /// Held by a test to stop a filter right after it has dropped its read-ahead cursor for
    /// age, with the keys before that one decided and its compaction not yet finished.
    #[cfg(test)]
    aged_gate: Mutex<()>,
    /// Held by a test to stop an install right before it writes the meta row. While its flag
    /// is set, that write fails without reaching RocksDB.
    #[cfg(test)]
    write_gate: Mutex<bool>,
}

impl PrunePolicies {
    /// The compiled policies and their generation.
    fn current(&self) -> (u64, Arc<[CompiledPolicy]>) {
        let compiled = self.compiled.lock();
        (self.generation.load(Ordering::Acquire), compiled.clone())
    }

    /// Puts `compiled` in force. A running filter takes it up at its next key.
    fn publish(&self, compiled: Arc<[CompiledPolicy]>) {
        let mut current = self.compiled.lock();
        *current = compiled;
        self.generation.fetch_add(1, Ordering::Release);
    }
}

/// Builds the state family's compaction filters.
//
// RocksDB can call `create` from several compaction threads at once, and the binding forms a
// `&mut` to this one object for each call. So the factory holds only a handle to shared
// state. The marker makes it `!Unpin`, and the compiler does not assume a `&mut` to such a
// type to be unique, since a pinned value can hold pointers into itself.
struct PruneFilterFactory(Arc<PrunePolicies>, PhantomPinned);

impl CompactionFilterFactory for PruneFilterFactory {
    type Filter = PruneFilter;

    fn create(&mut self, _context: CompactionFilterContext) -> PruneFilter {
        let (generation, policies) = self.0.current();
        PruneFilter {
            shared: self.0.clone(),
            generation,
            policies,
            ahead: None,
        }
    }

    fn name(&self) -> &CStr {
        c"exoware.prune"
    }
}

/// Applies the installed prune policies to the keys of one compaction. For each key, RocksDB
/// shows it the newest version among the files the compaction rewrites, when that version is a
/// value, and puts a tombstone in place of a version it removes. A compaction that takes the
/// oldest file can drop the tombstone, and it keeps the tombstone while an open snapshot still
/// shows an older version of the key.
//
// RocksDB does not run it on flushes or ingested files, so a row a policy removes leaves only
// when a compaction takes the file that holds it. It never writes to the database or takes the
// publication lock, and its only read is the read-ahead cursor.
//
// A removal does not advance the store's sequence, and a snapshot does not shield the version
// of a row that a compaction removes. What a query sees depends on when its read starts,
// because RocksDB fixes the files a read uses at that moment. A point read or a multi-key read
// sees all the removals of a finished compaction or none of them. A range cursor keeps the
// files it opened on for all its pages.
//
// A query that captured its snapshot before a compaction finished and starts its read afterward
// misses a row when the version that compaction removed is the one its snapshot showed. A query
// whose snapshot predates the removed version still sees the version that snapshot showed,
// until a compaction removes that one too. The `count` rows that let `KeepLatest` remove a
// version can be newer than that snapshot, so such a query can find fewer than `count` rows of
// a group.
//
// A request can replace a policy while compactions run. The replaced policy stops deciding at
// the next key, and the removals it has already decided still land when their compaction
// finishes. They take only rows written before the request is answered, so a group can hold
// fewer rows than a `KeepLatest` policy from the request would keep.
//
// Those rows stay live until the removals land. Another filter can decide meanwhile only with
// options above RocksDB's defaults, where `max_background_jobs` above two lets a second state
// compaction run and `max_subcompactions` above one splits a compaction among several
// filters. That filter counts those rows among the rows that follow a key under the new
// `KeepLatest` policy, so it can remove a row the new policy alone would keep. A second
// compaction can remove even one written after the request.
struct PruneFilter {
    /// The store's policy cell, checked at every key for a new generation.
    shared: Arc<PrunePolicies>,
    /// The generation at which `policies` was taken.
    generation: u64,
    /// The policies in force at `generation`.
    policies: Arc<[CompiledPolicy]>,
    /// The read-ahead cursor for `KeepLatest`, opened when a key needs one and none is open.
    ahead: Option<ReadAhead>,
}

impl CompactionFilter for PruneFilter {
    fn filter(&mut self, _level: u32, key: &[u8], _value: &[u8]) -> CompactionDecision {
        // The generation moves each time the store publishes a policy list, at open and at every
        // install. The filter then takes up the published list at this key and drops the cursor,
        // because its window was matched against the list it held.
        if self.shared.generation.load(Ordering::Acquire) != self.generation {
            (self.generation, self.policies) = self.shared.current();
            self.ahead = None;
        }

        // Every key the filter is shown ages the cursor, whether or not the key uses it. An
        // aged cursor is dropped here, and the next key that needs one opens a fresh one.
        if self.ahead.as_mut().is_some_and(ReadAhead::aged) {
            self.ahead = None;
            #[cfg(test)]
            drop(self.shared.aged_gate.lock());
        }

        // Policy prefixes never nest, so at most one policy selects a key.
        let Some(policy) = self
            .policies
            .iter()
            .find(|policy| policy.prefix.matches(key))
        else {
            return CompactionDecision::Keep;
        };
        let Some((group, order)) = policy.member(key) else {
            return CompactionDecision::Keep;
        };
        let removes = match &policy.rule {
            PruneRule::DropAll => true,
            PruneRule::GreaterThan { threshold } => {
                compare_order_values(&order, threshold, &policy.scope) != CmpOrdering::Greater
            }
            PruneRule::GreaterThanOrEqual { threshold } => {
                compare_order_values(&order, threshold, &policy.scope) == CmpOrdering::Less
            }
            PruneRule::KeepLatest { count } => {
                if self.ahead.is_none() {
                    self.ahead = ReadAhead::open(&self.shared);
                }

                // The cursor reads live rows, and a request may have replaced the policy while
                // it read. Rows written after that do not count against a row the old policy
                // would have kept, so the removal stands only under an unchanged generation.
                self.ahead
                    .as_mut()
                    .is_some_and(|ahead| ahead.followed_by(policy, key, &group, &order, *count))
                    && self.shared.generation.load(Ordering::Acquire) == self.generation
            }
        };
        if removes {
            CompactionDecision::Remove
        } else {
            CompactionDecision::Keep
        }
    }

    fn name(&self) -> &CStr {
        c"exoware.prune"
    }
}

/// A key the read-ahead cursor has read.
struct Ahead {
    /// The key, copied so it stays valid after the cursor moves on.
    key: Box<[u8]>,
    /// The key's group and order value, or `None` when the policy does not select the key.
    member: Option<(Vec<u8>, Vec<u8>)>,
}

/// A cursor over the state that runs ahead of one compaction, so that `KeepLatest` can ask
/// which keys follow the one the compaction is at. It reads the state as it was when the
/// cursor opened.
struct ReadAhead {
    /// Borrows `_db`, so it is declared first and drops first.
    cursor: DBRawIterator<'static>,
    /// Keeps the database open while the cursor reads it.
    _db: Arc<DB>,
    /// The keys the cursor has read after the key last asked about, in key order. The cursor
    /// is on the last of them unless it ran off the end. It holds at most as many keys as the
    /// `count` of the policy that reads ahead, and never more than a run of one group's keys
    /// in rising order and one key past it.
    window: VecDeque<Ahead>,
    /// How many keys at the front of `window` are linked into a chain. A chain is a run of one
    /// group's members whose order values never decrease from one key to the next. The keys
    /// after it are linked only when a key the compaction shows needs them.
    chain: usize,
    /// Whether the cursor ran off the end of the state. No key then follows a later key
    /// either, so the cursor stops reading.
    exhausted: bool,
    /// Keys the filter has been shown since the cursor opened.
    age: usize,
}

impl ReadAhead {
    /// Opens a cursor on the state as it is now, or returns `None` while `open` has not handed
    /// the database over.
    fn open(shared: &PrunePolicies) -> Option<Self> {
        let db = shared.db.get()?.upgrade()?;
        #[cfg(test)]
        drop(shared.read_ahead_gate.lock());

        // The cursor uses blocks that are already cached and adds none, so reading ahead does
        // not push out what queries use.
        let mut options = ReadOptions::default();
        options.fill_cache(false);

        // SAFETY: `_db` keeps `db_ref` alive, and fields drop in declaration order, so
        // `cursor` is released before its database.
        let db_ref: &'static DB = unsafe { &*Arc::as_ptr(&db) };
        Some(Self {
            cursor: db_ref.raw_iterator_opt(options),
            _db: db,
            window: VecDeque::new(),
            chain: 0,
            exhausted: false,
            age: 0,
        })
    }

    /// Counts one more key against the cursor and says whether it is due to be dropped.
    //
    // The limit is at least twice the window's length, so the reads a fresh cursor spends
    // rebuilding the window are at most half the keys this one was shown.
    fn aged(&mut self) -> bool {
        self.age += 1;
        self.age >= READ_AHEAD_REFRESH_KEYS.max(2 * self.window.len())
    }

    /// Whether the `count` keys after `key` are members of its group whose order values start
    /// at or above its own and never decrease. If so, `key` is not among the latest `count`
    /// of its group.
    ///
    /// ```text
    ///   keys in key order                     a|1    a|2    a|3    a|4    b|1
    ///
    ///   the compaction is at                  a|1
    ///   the next two live keys are                   a|2    a|3
    ///   both follow a|1 in group a, so a|1 is removed
    ///
    ///   the compaction is at                                a|3
    ///   the next two live keys are                                 a|4    b|1
    ///   b|1 is in another group, so a|3 is kept
    ///
    ///   a|1 is version 1 of group a, and the policy keeps the latest 2
    /// ```
    //
    // Each of those keys sorts after `key` by order value and then by key, so `count` members
    // of the group are newer than `key` whatever else the group holds. The latest `count`
    // members never have `count` newer members, so under an unchanged document no chain of
    // removals reaches them.
    //
    // The cursor's view can be stale. A row in it can have been removed by this same rule, and
    // then the group still holds `count` rows newer than that row, so newer than `key` too. A
    // row in it can also have been removed by a policy that this one replaced (see
    // `PruneFilter`).
    //
    // When a group's keys sort together, oldest first, this test removes a member a compaction
    // shows exactly when `count` members of its group follow it in the cursor's view, so of the
    // members in that view it keeps only the latest `count`. Under another layout the chain breaks
    // early, and the group can keep more than `count`.
    fn followed_by(
        &mut self,
        policy: &CompiledPolicy,
        key: &[u8],
        group: &[u8],
        order: &[u8],
        count: usize,
    ) -> bool {
        // The compaction has passed the window keys at or before `key`.
        while self.window.front().is_some_and(|ahead| &*ahead.key <= key) {
            self.window.pop_front();
            self.chain = self.chain.saturating_sub(1);
        }

        // With nothing read ahead of `key`, the cursor is still on `key` when the last read
        // ahead stopped there, and has to seek otherwise. The seek lands on the first key after
        // `key` when `key` is not live. An exhausted cursor does not seek again.
        if self.window.is_empty() && !self.exhausted && self.cursor.key() != Some(key) {
            self.cursor.seek(key);
            if self.cursor.key() != Some(key) {
                self.exhausted = !self.push(policy);
            }
        }

        // `key` can be removed only if the first key after it is a member of its group with an
        // order value at or above its own. When it is not, as after a group's newest key, `key`
        // is kept after this one read and the cursor reads no further into the next group.
        if self.window.is_empty() && !self.advance(policy) {
            return false;
        }
        let follows = self
            .window
            .front()
            .and_then(|first| first.member.as_ref())
            .is_some_and(|(its_group, its_order)| {
                its_group == group
                    && compare_order_values(its_order, order, &policy.scope) != CmpOrdering::Less
            });
        if !follows {
            return false;
        }

        // The chain grows until it holds `count` keys, breaks, or the keys run out. A cursor
        // reads and links each key once, however many keys before it ask. So the cursor's work
        // grows with the live keys it passes, not with the keys the compaction shows. A key
        // shown past the window empties it and pays a seek and up to `count` reads of its own.
        loop {
            while self.chain < self.window.len() && self.links(self.chain, &policy.scope) {
                self.chain += 1;
            }
            if self.chain >= count || self.chain < self.window.len() || !self.advance(policy) {
                break;
            }
        }
        self.chain >= count
    }

    /// Whether the window key at `index` continues the chain of the keys before it.
    fn links(&self, index: usize, scope: &KeysScope) -> bool {
        let Some((group, order)) = &self.window[index].member else {
            return false;
        };
        index == 0
            || self.window[index - 1]
                .member
                .as_ref()
                .is_some_and(|(before_group, before_order)| {
                    group == before_group
                        && compare_order_values(order, before_order, scope) != CmpOrdering::Less
                })
    }

    /// Appends the key under the cursor to the window. Returns `false` when the cursor is
    /// past the last key.
    fn push(&mut self, policy: &CompiledPolicy) -> bool {
        let Some(key) = self.cursor.key() else {
            return false;
        };
        self.window.push_back(Ahead {
            key: key.into(),
            member: policy.member(key),
        });
        true
    }

    /// Steps the cursor to the next key and appends it to the window. Returns `false` when
    /// there is none.
    fn advance(&mut self, policy: &CompiledPolicy) -> bool {
        if self.exhausted {
            return false;
        }
        self.cursor.next();
        self.exhausted = !self.push(policy);
        !self.exhausted
    }
}

/// Sequence frontier shared by the store and its writer stages.
struct Frontiers {
    /// Highest sequence whose log and state rows are durably committed.
    published: AtomicU64,
    /// Serializes state ingestion, publication, and snapshot capture.
    /// Also serializes floor persists so the durable floor cannot regress.
    persist: Mutex<()>,
    /// Highest `cutoff_exclusive` already applied by `prune_log` in this process. Lets the
    /// per-append retention hook skip the write entirely when the floor has not advanced
    /// (static thresholds, coalesced ingest waves), so redundant range tombstones never pile
    /// up ahead of compaction. Starts at zero; open's one-shot enforcement re-seeds it
    /// when a rule is installed.
    trimmed: AtomicU64,
}

impl Frontiers {
    const fn new(published: u64) -> Self {
        Self {
            published: AtomicU64::new(published),
            persist: Mutex::new(()),
            trimmed: AtomicU64::new(0),
        }
    }
}

// Row backing is charged separately. These charges cover later coalescing,
// indexed sorting, compact payload owners, and encoded log output.
const fn writer_growth(entries: usize, encoded_len: usize) -> usize {
    let row = std::mem::size_of::<(Bytes, Bytes)>();
    let sort_row = std::mem::size_of::<usize>();
    encoded_len
        .saturating_mul(2)
        .saturating_add(entries.saturating_mul(2 * row + sort_row + 128))
}

const fn writer_memory(entries: usize, encoded_len: usize, capacity: usize) -> usize {
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

/// One coalesced wave awaiting SST staging: every request shares a single sequence number,
/// whose log row carries all their rows in arrival order.
struct QueuedWave {
    sequence: u64,
    rows: Vec<(Bytes, Bytes)>,
    requests: Vec<WriteRequest>,
    _leases: Vec<Arc<WriteLease>>,
}

/// One staged commit group: every coalesced request shares a single sequence number, whose log
/// row carries all their rows in arrival order.
struct PreparedWrite {
    sequence: u64,
    /// Staged log SST (the group's encoded batch and its sentinel keys), ready for ingestion.
    log: PathBuf,
    /// Staged current-state SST (sorted by key, last write per key), ready for ingestion.
    state: PathBuf,
    /// Combined payload bytes staged, for debug logging.
    staged_bytes: usize,
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
    /// Starts the write pipeline the module docs describe: the `prepare` thread, the stage
    /// workers, the `commit` thread, and the log merge worker beside them.
    fn start(
        db: Arc<Database>,
        ingest_dir: PathBuf,
        frontiers: Arc<Frontiers>,
        write_pipeline: RocksWritePipelineConfig,
    ) -> Self {
        // Nothing has committed yet, so the published frontier is exactly the one `open`
        // derived, and sequence numbers continue from it.
        let next = frontiers.published.load(Ordering::Acquire);

        let (request_sender, request_receiver) = mpsc::channel();
        let max_commit_batch_bytes = write_pipeline.max_commit_batch_bytes.get();
        let stage_workers = write_pipeline.stage_workers.get();
        let max_queued_waves = write_pipeline.max_queued_waves.get();
        let log_merge_files = write_pipeline.log_merge_files.get();

        // Staged groups queue shallowly toward `commit`, which reorders them by sequence.
        let (staged_sender, staged_receiver) = mpsc::sync_channel(stage_workers);

        // The channel holds one wake-up, since an unread one covers every file ingested before
        // the merge worker reads it.
        let (merge_sender, merge_receiver) = mpsc::sync_channel(1);
        let merge = thread::Builder::new()
            .name(format!("{WRITER_THREAD_PREFIX}merge"))
            .spawn({
                let db = db.clone();
                move || run_log_merge(db, merge_receiver, log_merge_files)
            })
            .expect("RocksDB log merge worker must spawn");

        let commit = thread::Builder::new()
            .name(format!("{WRITER_THREAD_PREFIX}commit"))
            .spawn(move || {
                run_commit(
                    db,
                    frontiers,
                    staged_receiver,
                    next,
                    merge_sender,
                    log_merge_files,
                )
            })
            .expect("failed to spawn RocksDB commit worker");

        // One shared bounded queue, so `prepare` blocks once `max_queued_waves` waves wait for
        // staging, and any idle worker takes the next wave.
        let (wave_sender, wave_receiver) = mpsc::sync_channel::<QueuedWave>(max_queued_waves);
        let wave_receiver = Arc::new(Mutex::new(wave_receiver));
        let mut handles = Vec::with_capacity(stage_workers + 3);
        for worker in 0..stage_workers {
            let ingest_dir = ingest_dir.clone();
            let staged_sender = staged_sender.clone();
            let wave_receiver = wave_receiver.clone();
            handles.push(
                thread::Builder::new()
                    .name(format!("{WRITER_THREAD_PREFIX}stage-{worker}"))
                    .spawn(move || run_stage(ingest_dir, wave_receiver, staged_sender))
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
        handles.push(merge);
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

/// Stages waves pulled from the queue shared with the other workers and hands each group to
/// `commit`. The lock is held only while waiting on the channel, never while staging. Exits
/// when the wave channel closes (store drop); panics if `commit` died, since that only
/// happens on a fatal write error.
fn run_stage(
    ingest_dir: PathBuf,
    receiver: Arc<Mutex<mpsc::Receiver<QueuedWave>>>,
    sender: mpsc::SyncSender<PreparedWrite>,
) {
    loop {
        let Ok(wave) = receiver.lock().recv() else {
            break;
        };
        let group = stage_wave(&ingest_dir, wave);
        if sender.send(group).is_err() {
            panic!("rocks commit worker died");
        }
    }
}

/// Commits staged groups strictly in sequence order (log ingestion, state ingestion, publish,
/// ack), buffering groups whose predecessors are still staging, until the group channel closes
/// (store drop). Any write failure panics inside `commit_group`. Wakes the merge worker after
/// every `log_merge_files` groups, since each adds one log file.
fn run_commit(
    db: Arc<Database>,
    frontiers: Arc<Frontiers>,
    receiver: mpsc::Receiver<PreparedWrite>,
    mut committed: u64,
    merge: mpsc::SyncSender<()>,
    log_merge_files: usize,
) {
    let mut pending: BTreeMap<u64, PreparedWrite> = BTreeMap::new();
    let mut unmerged = 0;
    while let Ok(group) = receiver.recv() {
        pending.insert(group.sequence, group);
        while let Some(group) = pending.remove(&(committed + 1)) {
            committed = group.sequence;
            commit_group(&db, &frontiers, group);
            unmerged += 1;
            if unmerged >= log_merge_files {
                unmerged = 0;

                // A full channel means a wake-up is already waiting.
                let _ = merge.try_send(());
            }
        }
    }

    // The channel closes only once every stage worker has exited, after handing over every
    // staged group, so a clean shutdown leaves nothing buffered.
    assert!(pending.is_empty(), "staged groups lost at shutdown");
}

/// A bottom-level log file as the merge planner sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LogFile {
    /// Smallest key in the file.
    start: Vec<u8>,
    /// Largest key in the file.
    end: Vec<u8>,
    /// File size in bytes.
    size: u64,
}

/// Lists the log column family's bottom-level files in key order. Their key ranges are
/// disjoint, so the order is also sequence order.
fn bottom_log_files(db: &DB) -> Result<Vec<LogFile>, String> {
    let mut files: Vec<LogFile> = db
        .live_files()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|file| file.column_family_name == LOG_CF && file.level == LOG_BOTTOM_LEVEL)
        .filter_map(|file| {
            Some(LogFile {
                start: file.start_key?,
                end: file.end_key?,
                size: file.size as u64,
            })
        })
        .collect();
    files.sort_unstable_by(|a, b| a.start.cmp(&b.start));
    Ok(files)
}

/// Picks the oldest run of adjacent small log files worth merging, as an index range into
/// `files` (bottom-level log files in key order), or `None` when there is nothing to do.
///
/// ```text
///   oldest                                                       newest
///   +-----+-----+-+-+-+-----+-+-----+-+-+-+-+-+-+-+-+-+-+-+-+-+ - - +-+
///   |#####|#####| | | |#####| |#####| | | | | | | | | | | | | |     | |
///   +-----+-----+-+-+-+-----+-+-----+-+-+-+-+-+-+-+-+-+-+-+-+-+ - - +-+
///               |<--->|     |-|     |<--------- newest run ---------->|
///               merged      stays   waits for `trigger` files
///               first
///
///   ##### a file of `LOG_MERGE_SMALL_BYTES` or more     | | a smaller one
/// ```
///
/// A run needs two files. The newest run needs `trigger` of them when that is more, or
/// `LOG_MERGE_PASS_FILES` when `trigger` is above that. One pass selects at most
/// `LOG_MERGE_PASS_FILES` files holding at most `LOG_MERGE_PASS_BYTES`.
fn plan_log_merge(files: &[LogFile], trigger: usize) -> Option<Range<usize>> {
    let small = |file: &LogFile| file.size < LOG_MERGE_SMALL_BYTES;
    let mut start = 0;
    while start < files.len() {
        if !small(&files[start]) {
            start += 1;
            continue;
        }
        let run = files[start..].iter().take_while(|file| small(file)).count();

        // The newest run is still growing, so it waits for `trigger` files. Its first file is
        // usually the small last output of the previous merge, and waiting spreads the cost of
        // rewriting that file over many new ones. It waits for at most `LOG_MERGE_PASS_FILES`,
        // since a pass takes no more however long the run grows. A run with a large file after it
        // cannot grow, so waiting would gain nothing and two files are enough.
        let needed = if start + run == files.len() {
            trigger.clamp(2, LOG_MERGE_PASS_FILES)
        } else {
            2
        };
        if run >= needed {
            // One merge takes the first two files, then more until it holds
            // `LOG_MERGE_PASS_FILES` files or the next file would pass `LOG_MERGE_PASS_BYTES`.
            // A later call picks up the rest of the run.
            let mut bytes = 0;
            let taken = files[start..start + run]
                .iter()
                .enumerate()
                .take_while(|(index, file)| {
                    bytes += file.size;
                    *index < 2 || (*index < LOG_MERGE_PASS_FILES && bytes <= LOG_MERGE_PASS_BYTES)
                })
                .count();
            return Some(start..start + taken);
        }
        start += run;
    }
    None
}

/// Merges the oldest run [`plan_log_merge`] picks by compacting its key range within the bottom
/// level, and reports whether there was a run to merge.
//
// RocksDB swaps a compaction's output files for its inputs in one manifest edit, so a reader or
// a crash sees either the old files or the new ones, and every row stays readable by key. The
// compaction copies every row and sentinel except those under a retention tombstone. Files
// ingested meanwhile sort above the range, and the compaction takes one only when a retention
// tombstone written meanwhile covers it.
fn merge_log_run(db: &DB, trigger: usize) -> Result<bool, String> {
    let files = bottom_log_files(db)?;
    let Some(run) = plan_log_merge(&files, trigger) else {
        return Ok(false);
    };
    let log_cf = db
        .cf_handle(LOG_CF)
        .expect("log CF must exist (created on open)");
    let mut options = CompactOptions::default();

    // By default a manual compaction skips files that are already in the bottom level, and `Force`
    // makes it rewrite them. When a retention tombstone overlaps the run, RocksDB first rewrites
    // the bottom-level files under the tombstone without their deleted rows, and `Force` then
    // merges that output with the rest of the run. That copies the surviving rows of those files
    // twice and leaves the run merged after one call. `ForceOptimized` copies them once and leaves
    // that output apart from the rest of the run.
    options.set_bottommost_level_compaction(BottommostLevelCompaction::Force);

    // A non-exclusive manual compaction leaves automatic compactions running in every family.
    options.set_exclusive_manual_compaction(false);

    let start = &files[run.start].start;
    let end = &files[run.end - 1].end;
    db.compact_range_cf_opt(log_cf, Some(start), Some(end), &options);

    // The compaction reports no status, so its effect is read back from the file list. A range
    // that holds as many files as the run did was not merged.
    let left = bottom_log_files(db)?
        .iter()
        .filter(|file| file.start >= *start && file.end <= *end)
        .count();
    if left >= run.len() {
        return Err(format!(
            "compacting {} log files left {left} in their place",
            run.len()
        ));
    }
    Ok(true)
}

/// Merges runs until none is left or a merge fails, at start for files an earlier process left and
/// again on each wake-up from `commit`. Exits when the wake-up channel closes (store drop). A
/// merge in flight at that point finishes first, and a wake-up still queued can start one more.
///
/// ```text
///   groups            1,024           2,048           3,072
///   commit   -----------+---------------+---------------+-------------------------------------->
///                       | wake-up       | queued        x not sent, one is queued
///                       v               +----------------------+
///          at start                                            v
///   merge  [ plan ] . . [ plan ][========== compact ==========][ plan ][ compact ][ plan ] . . .
/// ```
///
/// The ticks are at the default `log_merge_files`. A wake-up that finds one already queued is
/// not sent. The queued one is taken before the next plan, and a plan lists the files as they
/// are when it runs, so it covers the groups behind both.
fn run_log_merge(db: Arc<Database>, wake: mpsc::Receiver<()>, trigger: usize) {
    loop {
        // Take a pending wake-up before reading the file list, so the worker never sleeps on a
        // list older than a wake-up it consumed.
        if matches!(wake.try_recv(), Err(mpsc::TryRecvError::Disconnected)) {
            break;
        }
        match merge_log_run(&db, trigger) {
            Ok(true) => continue,
            Ok(false) => {}

            // A failed merge loses no row, and the next wake-up retries it. RocksDB records some
            // compaction failures, a corrupt block among them, as a background error. It then
            // fails the next commit's ingestion, which is fatal to the store.
            Err(error) => {
                tracing::warn!(error = %error, "log file merge failed and will be retried after more commits");
            }
        }
        if wake.recv().is_err() {
            break;
        }
    }
}

/// Coalesces one wave from requests already queued behind `first` without waiting for new
/// arrivals. Each wave shares one sequence number and preserves arrival order.
///
/// ```text
///   wave 6   +---------+-------------------+
///            |    a    |         b         |
///            +---------+-------------------+
///                                   ^ soft cap        b crosses it and stays
///
///   wave 7   +---------------+ - - - - - - - - - +
///            |       c       |         d         :    c and d together pass the limits
///            +---------------+ - - - - - - - - - +    of one put, so d opens wave 8
/// ```
///
/// The soft cap compares `max_batch_bytes` with twice the wave's payload bytes, and it keeps
/// the crossing request so a single large request can still make progress. Before a request
/// joins a wave, the wave is checked against the entry count and encoded size of a single put,
/// so a sequence always fits one response.
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

/// Name of the staged file of `kind` (`log` or `state`) for `sequence`. The sequence is written
/// as 20 digits, the width of the largest `u64`.
fn staged_file_name(kind: &str, sequence: u64) -> String {
    format!("{kind}-{sequence:020}.sst")
}

/// Whether `name` is one that [`staged_file_name`] gives a file.
fn is_staged_file_name(name: &str) -> bool {
    ["log", "state"].into_iter().any(|kind| {
        name.strip_prefix(kind)
            .and_then(|rest| rest.strip_prefix('-'))
            .and_then(|rest| rest.strip_suffix(".sst"))
            .and_then(|digits| digits.parse().ok())
            .is_some_and(|sequence| name == staged_file_name(kind, sequence))
    })
}

/// Stages one wave's two SST files in parallel, the log SST on this thread and the sorted state
/// SST on a scoped thread. A staging failure is fatal, and the next open removes leftover files.
fn stage_wave(ingest_dir: &Path, wave: QueuedWave) -> PreparedWrite {
    let sequence = wave.sequence;
    let rows = &wave.rows;
    let log = ingest_dir.join(staged_file_name("log", sequence));
    let state = ingest_dir.join(staged_file_name("state", sequence));
    let (log_result, state_result) = thread::scope(|scope| {
        let state_task = thread::Builder::new()
            .name(format!("{WRITER_THREAD_PREFIX}stage"))
            .spawn_scoped(scope, || stage_state_file(&state, rows))
            .expect("failed to spawn SST staging thread");
        let log_result = stage_log_file(&log, sequence, rows);
        (
            log_result,
            state_task.join().expect("state staging thread panicked"),
        )
    });
    let log_bytes = log_result.unwrap_or_else(|error| panic!("failed to stage log SST: {error}"));
    let state_bytes =
        state_result.unwrap_or_else(|error| panic!("failed to stage state SST: {error}"));
    drop(wave.rows);
    PreparedWrite {
        sequence,
        requests: wave.requests,
        _leases: wave._leases,
        log,
        state,
        staged_bytes: log_bytes + state_bytes,
    }
}

/// Stages the log SST, one row mapping the group's sequence to the exact encoded batch the
/// stream service serves, bracketed by the sentinel keys. Built with [`log_cf_options`], like
/// the files the merge writes.
///
/// ```text
///   key order -->
///   +--------+---------+--------+--------+---------+--------+
///   |  head  |   row   |  tail  |  head  |   row   |  tail  |
///   |  6+01  |    7    |  7+00  |  7+01  |    8    |  8+00  |
///   +--------+---------+--------+--------+---------+--------+
///     empty    payload   empty    empty    payload   empty
///   |<------- file of 7 ------->|<------- file of 8 ------->|
///   |<---------------- or one merged file ----------------->|
///        ^                 ^
///        +-----------------+--- the blocks looked up for the first and last key of file 7
///
///   6+01 is the key of sequence 6 followed by the byte 01
/// ```
///
/// A sentinel has an empty value, and every key has its own block, so the lookups for a file's
/// first and last key land on blocks without a payload.
fn stage_log_file(path: &Path, sequence: u64, rows: &[(Bytes, Bytes)]) -> Result<usize, String> {
    let payload = encode_log_value(sequence, rows);
    let options = log_cf_options();
    let mut writer = SstFileWriter::create(&options);
    writer.open(path).map_err(|e| e.to_string())?;
    writer
        .put(log_head_sentinel(sequence), b"")
        .map_err(|e| e.to_string())?;
    writer
        .put(sequence_log_key(sequence), &payload)
        .map_err(|e| e.to_string())?;
    writer
        .put(log_tail_sentinel(sequence), b"")
        .map_err(|e| e.to_string())?;

    // `finish` syncs the file before it is linked into the DB.
    writer.finish().map_err(|e| e.to_string())?;
    Ok(LOG_BATCH_KEY_LEN + payload.len())
}

/// The head sentinel is the previous sequence's key with a trailing `1`, so the files of
/// consecutive sequences stay disjoint (see the figure on `stage_log_file`). `prune_log` ends the
/// tombstone for the sequences below at this key, so the tombstone stays clear of this file.
/// Readers that iterate rows skip keys of this length, and the oldest-retained lookup reads the
/// head sentinel in place of the row.
fn log_head_sentinel(sequence: u64) -> [u8; LOG_BATCH_KEY_LEN + 1] {
    // Sequences start at 1. A wrapped subtraction here would make the prune tombstone end
    // above every key and erase the whole log.
    assert!(sequence > 0, "log sequences must start at 1");
    let mut key = [0u8; LOG_BATCH_KEY_LEN + 1];
    key[..LOG_BATCH_KEY_LEN].copy_from_slice(&sequence_log_key(sequence - 1));
    key[LOG_BATCH_KEY_LEN] = 1;
    key
}

/// The tail sentinel is this sequence's key with a trailing `0`. It sorts after the row and
/// before the next sequence's head sentinel.
fn log_tail_sentinel(sequence: u64) -> [u8; LOG_BATCH_KEY_LEN + 1] {
    let mut key = [0u8; LOG_BATCH_KEY_LEN + 1];
    key[..LOG_BATCH_KEY_LEN].copy_from_slice(&sequence_log_key(sequence));
    key
}

/// Stages the current-state SST: the group's rows sorted by key, with the last write per key
/// winning (in arrival order across coalesced requests). Built with [`state_cf_options`], so
/// it is uncompressed and carries the key filter that compaction writes.
fn stage_state_file(path: &Path, rows: &[(Bytes, Bytes)]) -> Result<usize, String> {
    let mut order: Vec<usize> = (0..rows.len()).collect();

    // Arrival indices preserve the newest duplicate without a sorting workspace.
    order.sort_unstable_by(|a, b| rows[*a].0.cmp(&rows[*b].0).then_with(|| a.cmp(b)));

    // The writer requires strictly increasing keys. Sorting by key with arrival order as the
    // tiebreak places each key's newest write last in its run, so writing only the final row
    // of every run both collapses the duplicates and keeps the write that wins.
    let options = state_cf_options();
    let mut writer = SstFileWriter::create(&options);
    writer.open(path).map_err(|e| e.to_string())?;
    let mut bytes = 0;
    for (index, row) in order.iter().enumerate() {
        let (key, value) = &rows[*row];
        if order
            .get(index + 1)
            .is_some_and(|next| rows[*next].0 == *key)
        {
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

/// Commits one group: ingests its log row (durability), then its state file (visibility), then
/// publishes the frontier and resolves the requests. Any write failure panics. A durable log
/// row cannot be rolled back, because its sequence number must never be re-issued, so the next
/// open rolls the group forward from it.
///
/// ```text
///   commit    --[ ingest log 8 ]--[####### apply state 8, publish 8 #######]--[ reply ]-->
///   read A    ----[#]-------------------------------------------------------------------->
///                snapshot at 7
///   read B    ------------------------. . . . . . . waits . . . . . . . . .  [#]--------->
///                                                                       snapshot at 8
///   log trim  --------------[#]---------------------------------------------------------->
///                          floor = 7, tombstone excludes file 8
///
///   # holds the publication lock
/// ```
///
/// The lock is `Frontiers::persist`. A state read takes it in `OwnedRocksSnapshot::capture`, and a
/// log read does not. A log trim holds it for its tombstone and floor batch
/// (`RocksStore::prune_log`). Key pruning never takes it (see `PruneFilter`).
//
// The panic drops the group's response channels, so waiting callers observe an error even
// though the open-time repair may restore the group. This at-least-once ambiguity is accepted
// on a fatal error path.
fn commit_group(db: &DB, frontiers: &Frontiers, group: PreparedWrite) {
    assert!(!group.requests.is_empty(), "groups are never empty");
    let sequence = group.sequence;

    // The log goes first because the durable row alone defines the group (an ingested state
    // file without its log row could leave keys in the store that were never part of a
    // sequenced batch). It needs no lock against a concurrent log trim. A trim only deletes
    // rows at or below a published frontier it loaded earlier, and this sequence sits above
    // every published frontier until publish.
    ingest_staged_file(db, LOG_CF, &group.log);

    // Ingest and publish under the publication lock. A snapshot is captured under the same lock,
    // so it never holds a state row above the frontier it reports. A log trim records the
    // published frontier as the state floor under it too, so the floor covers only groups whose
    // state is applied.
    let publish_guard = frontiers.persist.lock();
    ingest_staged_file(db, STATE_CF, &group.state);

    // Release so `current_sequence` readers only observe frontiers whose rows are readable.
    frontiers.published.store(sequence, Ordering::Release);
    drop(publish_guard);
    debug!(
        requests = group.requests.len(),
        staged_bytes = group.staged_bytes,
        sequence,
        "committed write batch"
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

/// Ingests one staged SST file into `cf`. Ingestion links the file into the column family and
/// syncs the manifest, so the rows are durable and readable once this returns. Failure is fatal:
/// see `commit_group`.
fn ingest_staged_file(db: &DB, cf: &str, path: &Path) {
    let handle = db.cf_handle(cf).expect("CFs exist (created on open)");
    let mut ingest_options = IngestExternalFileOptions::default();
    ingest_options.set_move_files(true);
    ingest_options.set_snapshot_consistency(true);
    db.ingest_external_file_cf_opts(handle, &ingest_options, vec![path])
        .unwrap_or_else(|error| {
            panic!(
                "failed to ingest staged SST {} into {cf}: {error}",
                path.display()
            )
        });
}

/// Writes a batch with sync enabled, so it is durable once this returns.
fn write_synced_batch(db: &DB, batch: rocksdb::WriteBatch) -> Result<(), String> {
    let mut write_options = WriteOptions::default();
    write_options.set_sync(true);
    db.write_opt(batch, &write_options)
        .map_err(|e| e.to_string())
}

/// Creates the SST staging directory and deletes files a crashed writer left behind. A
/// leftover can exist even for an ingested group: move-ingestion hard-links the staged file
/// into the database and unlinks the original afterward, so a crash in between leaves the
/// original behind while its rows are already visible. Deleting leftovers is safe either way
/// because the database owns its own link to every ingested file. Nothing here decides
/// whether a group committed: the retained log rows alone do.
///
/// Only a file that carries a [`staged_file_name`] is deleted. [`RocksConfig::db_options`] can
/// place RocksDB's WAL, SST files and info log in this directory (`wal_dir`, `db_paths`,
/// `db_log_dir`). The open database is using those files, and RocksDB gives none of them such a
/// name.
fn prepare_ingest_dir(store_path: &Path) -> Result<PathBuf, String> {
    let ingest_dir = store_path.join(LOG_INGEST_DIR);
    std::fs::create_dir_all(&ingest_dir)
        .map_err(|e| format!("failed to create staging directory: {e}"))?;
    for entry in std::fs::read_dir(&ingest_dir)
        .map_err(|e| format!("failed to read staging directory: {e}"))?
    {
        let entry = entry.map_err(|e| format!("failed to read staging directory: {e}"))?;
        if entry.file_name().to_str().is_some_and(is_staged_file_name) {
            std::fs::remove_file(entry.path())
                .map_err(|e| format!("failed to remove staged file: {e}"))?;
        }
    }
    Ok(ingest_dir)
}

/// Encodes a sequence number as a log-CF key that preserves numeric order in RocksDB.
const fn sequence_log_key(sequence: u64) -> [u8; LOG_BATCH_KEY_LEN] {
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

/// Reads the state-floor meta row, defaulting to zero when no log trim has written it yet. A
/// malformed row is corruption and fails the open. Reading it as zero would let `open` derive a
/// frontier below sequences the store has already issued.
fn read_state_floor(db: &DB) -> Result<u64, String> {
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
                .map_err(|_| "corrupt state-floor meta row".to_string())?;
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

/// Reads the stored prune policies, or none when the row is absent. A row that fails to decode
/// or validate is corruption and fails the open.
fn read_prune_policies(db: &DB) -> Result<Vec<PrunePolicy>, String> {
    let meta_cf = db
        .cf_handle(META_CF)
        .expect("meta CF must exist (created on open)");
    match db
        .get_cf(meta_cf, PRUNE_META_KEY)
        .map_err(|e| e.to_string())?
    {
        Some(bytes) => {
            let document = PrunePolicyDocument::decode(Copying(bytes.as_slice()))
                .map_err(|e| format!("corrupt prune policy meta row: {e}"))?;
            validate_policy_document(&document)
                .map_err(|e| format!("corrupt prune policy meta row: {e}"))?;
            Ok(document.policies)
        }
        None => Ok(Vec::new()),
    }
}

/// Lowest sequence a retention rule keeps against `frontier`: the exclusive cutoff for log
/// trimming, so every row below it is evicted and the row at it (if any) is the oldest retained.
/// Mirrors the floor math the stream service owns end to end.
const fn retention_floor(policy: &RetentionPolicy, frontier: u64) -> u64 {
    match policy {
        RetentionPolicy::KeepLatest { count } => frontier.saturating_sub(*count).saturating_add(1),
        RetentionPolicy::GreaterThan { threshold } => threshold.saturating_add(1),
        RetentionPolicy::GreaterThanOrEqual { threshold } => *threshold,
        RetentionPolicy::DropAll => frontier.saturating_add(1),
    }
}

/// Re-applies the newest retained log row to the state column family and returns its sequence
/// (zero when the log is empty). `open` takes the larger of that and `floor` as the frontier.
///
/// ```text
///   sequence           5     6     7     8
///   log rows                [6]   [7]   [8]
///
///   floor 7      ####################]   ^ re-applied       frontier 8
///   floor 8      ##########################]   left alone   frontier 8
///
///   log rows                (none)
///   floor 8      ##########################]                frontier 8
///
///   # at or below the floor, never re-applied
/// ```
///
/// Rows are only ever ingested by sequential, atomic commits (a group's log row lands before
/// its state, and the next group's row only after that state). The returned sequence is
/// therefore a lower bound on the durable frontier, and at most the newest group can be missing
/// its state. Re-applying is idempotent because the row's entries are the newest writes for
/// their keys.
///
/// A row at or below `floor` is not replayed. A log trim takes the floor from the published
/// frontier, so the state of every group at or below it is already applied. Ingestion is atomic,
/// so no row is partial, and a re-applied row that fails to decode is corrupt and fails the open.
///
/// Re-applying can bring back rows of the group that a compaction had removed (see
/// `PruneFilter`). A policy that is still installed removes them again when a compaction takes
/// them, and a row that no installed policy removes stays.
fn replay_newest_log_row(db: &DB, floor: u64) -> Result<u64, String> {
    let log_cf = db
        .cf_handle(LOG_CF)
        .expect("log CF must exist (created on open)");

    // Skip the sentinel rows that bracket each log row.
    let mut newest = db.iterator_cf(log_cf, IteratorMode::End).filter(|item| {
        item.as_ref()
            .map_or(true, |(key, _)| key.len() == LOG_BATCH_KEY_LEN)
    });
    let Some(item) = newest.next() else {
        return Ok(0);
    };
    let (key, value) = item.map_err(|e| e.to_string())?;
    let sequence = sequence_from_log_key(key.as_ref())?;
    if sequence <= floor {
        return Ok(sequence);
    }
    let response: StreamGetResponseView<'_> = DecodeOptions::new()
        .with_max_message_size(MAX_RESPONSE_MESSAGE_BYTES)
        .with_element_memory_limit(MAX_RESPONSE_ELEMENT_MEMORY_BYTES)
        .decode_view(value.as_ref())
        .map_err(|e| format!("corrupt log row for sequence {sequence}: {e}"))?;
    let mut batch = rocksdb::WriteBatch::default();
    for entry in response.entries.iter() {
        batch.put(entry.key, entry.value);
    }

    // Synced: once a later commit moves the newest row past this group, a repair lost to power
    // loss would never be re-run.
    write_synced_batch(db, batch)?;
    Ok(sequence)
}

/// Application-level write pipeline options used by [`RocksStore::open`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RocksWritePipelineConfig {
    /// Soft maximum combined size (state rows plus encoded log rows) before cutting a prepared
    /// commit group.
    pub max_commit_batch_bytes: NonZeroUsize,
    /// Stage workers building wave SSTs concurrently. Each worker stages one wave at a time
    /// across two threads (log and state SSTs in parallel).
    pub stage_workers: NonZeroUsize,
    /// Coalesced waves that may queue ahead of the stage workers before `prepare` blocks. Each
    /// stage worker holds one more wave while it stages it. Groups already staged that wait in
    /// `commit` for an earlier sequence are not counted. Defaults to one queued wave per default
    /// worker.
    pub max_queued_waves: NonZeroUsize,
    /// Commit groups between wake-ups of the log merge, counted from `open`. At each wake-up, and
    /// once at `open`, the merge compacts the newest run of small log files if the run holds this
    /// many files, so a shorter run waits for a later wake-up. For that test a value of one counts
    /// as two and a value above `LOG_MERGE_PASS_FILES` as that bound, the fewest and the most
    /// files one merge takes. A smaller value leaves fewer files for every commit to pay for, and
    /// rewrites the previous merge's last, partly filled file more often. A value above the bound
    /// only leaves more files.
    pub log_merge_files: NonZeroUsize,
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
            log_merge_files: NonZeroUsize::new(DEFAULT_LOG_MERGE_FILES)
                .expect("default log merge file count must be nonzero"),
        }
    }
}

/// RocksDB engine and application-level write pipeline options used by [`RocksStore::open`].
#[derive(Default)]
pub struct RocksConfig {
    /// Database-wide options. `open` sets the bottom-priority thread pool of the process-wide
    /// default environment to `BOTTOM_POOL_THREADS` threads, whatever its size was. A store on
    /// that environment runs its log merges there.
    ///
    /// RocksDB derives from `max_background_jobs` how many flushes and automatic compactions run
    /// at once. A running log merge counts as one of those compactions but does not wait for a
    /// slot. With more than two jobs, or with `max_subcompactions` above one, several compaction
    /// filters can run at once, and a request that replaces a `KeepLatest` policy can then cost
    /// a group rows that the new policy keeps (see `PruneFilter`).
    ///
    /// `max_open_files` can be lower than the number of SST files. RocksDB closes the files read
    /// least recently, and the log files are rarely read back. Below the number of state files
    /// that reads probe, those reads reopen tables.
    ///
    /// A rate limiter throttles flushes and compactions, log merges included, but not the files a
    /// commit stages. It spreads a compaction over more time without reducing what it writes, so
    /// under a limit below the store's average compaction rate the backlog only grows.
    ///
    /// `open` relies on RocksDB replaying its WAL, where the store's meta rows stay until a
    /// flush. An option that skips the WAL at open (`best_efforts_recovery`) can bring the store
    /// up without the newest of them, even at a frontier below sequences it has issued.
    pub db_options: Options,
    /// Options for the application-level ingest write pipeline.
    pub write_pipeline: RocksWritePipelineConfig,
}

/// Options for the state column family. Ingested state SSTs can overlap one another, so compaction
/// has to merge them. Universal compaction merges whole sorted runs, and compression stays off to
/// match the staged files. The raised level-zero triggers let a larger compaction backlog build
/// before RocksDB slows or stops writes such as log trims. A ribbon filter lets a point read skip
/// the runs that lack its key in fewer bytes than a bloom filter.
fn state_cf_options() -> Options {
    let mut opts = Options::default();
    opts.set_compression_type(DBCompressionType::None);
    opts.set_bottommost_compression_type(DBCompressionType::None);
    opts.set_compaction_style(DBCompactionStyle::Universal);
    opts.set_level_zero_file_num_compaction_trigger(16);
    opts.set_level_zero_slowdown_writes_trigger(1024);
    opts.set_level_zero_stop_writes_trigger(2048);
    opts.set_target_file_size_base(STATE_TARGET_FILE_BYTES);
    let mut table = BlockBasedOptions::default();
    table.set_ribbon_filter(10.0);
    opts.set_block_based_table_factory(&table);
    opts
}

/// Options for the log column family and for the log files staged for ingestion into it. Log rows
/// are keyed by a monotonic sequence, so those files never overlap and settle in the bottom level,
/// where the merge compacts small ones into files it cuts at about `LOG_MERGE_TARGET_BYTES`.
fn log_cf_options() -> Options {
    let mut opts = Options::default();
    opts.set_compression_type(DBCompressionType::None);
    opts.set_bottommost_compression_type(DBCompressionType::None);
    opts.set_num_levels(LOG_BOTTOM_LEVEL + 1);
    opts.set_target_file_size_base(LOG_MERGE_TARGET_BYTES);

    // Every key gets its own block. Ingestion reads a staged file's first and last data blocks
    // to learn its key range, and the oldest-retained lookup reads the block of the first live
    // key, in a merged file as in a staged one. Those keys are sentinels with empty values, so
    // neither read loads a payload. In return the index holds an entry per key, and RocksDB
    // keeps a file's index in memory while the file is open.
    let mut table = BlockBasedOptions::default();
    table.set_block_size(1);
    opts.set_block_based_table_factory(&table);
    opts
}

/// Minimal RocksDB-backed store for the simulator: batch writes plus a global sequence u64
/// plus a per-sequence log.
#[derive(Clone)]
pub struct RocksStore {
    /// Declared before `db` so the last store drop joins the writer threads before releasing
    /// its database handle. The stage workers stage files inside the data directory without
    /// holding [`Database`], so they must never outlive the handles that keep the directory
    /// alive.
    writer: Arc<Writer>,
    db: Arc<Database>,
    frontiers: Arc<Frontiers>,
    /// In-memory mirror of the persisted retention rule (the meta row is the source of truth
    /// across reopens). The ingest path reads it on every commit to trim continuously, so a
    /// cheap cache keeps a rule-less store off the disk on that hot path.
    retention: Arc<Mutex<Option<RetentionPolicy>>>,
    /// The prune policies that the state family's compaction filters apply.
    prune: Arc<PrunePolicies>,
}

impl RocksStore {
    /// Open the store with default options, unless `config` overrides the database or
    /// write-pipeline options. Column families run options tuned to the store's write path
    /// (see `state_cf_options` and `log_cf_options`).
    /// Re-derives the durable frontier from the retained log rows and the state-floor meta row,
    /// then re-applies the newest log row to the state column family so the current state is
    /// complete below the durable sequence even after a crash mid-commit.
    ///
    /// The caller keeps the directory at `path` alive until every handle to the store (clones,
    /// open cursors, in-flight operations) has dropped. [`RocksStore::open_owned`] hands that
    /// ordering to the store instead.
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

        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);

        // The bottom-priority pool belongs to the process-wide default environment, so this
        // sizes it for every store that uses that environment.
        let mut env = rocksdb::Env::new().map_err(|e| e.to_string())?;
        env.set_bottom_priority_background_threads(BOTTOM_POOL_THREADS);

        // The filter factory has to be in the options before the database opens, but the
        // policies are stored inside the database. So the factory starts with an empty cell,
        // and the stored policies go into it once they are read below. Until then a filter has
        // no policy and keeps every key.
        let prune = Arc::new(PrunePolicies::default());
        let mut state_options = state_cf_options();
        state_options
            .set_compaction_filter_factory(PruneFilterFactory(prune.clone(), PhantomPinned));
        let cf_state = ColumnFamilyDescriptor::new(STATE_CF, state_options);
        let cf_meta = ColumnFamilyDescriptor::new(META_CF, Options::default());
        let cf_log = ColumnFamilyDescriptor::new(LOG_CF, log_cf_options());
        let db = DB::open_cf_descriptors(&db_options, path, vec![cf_state, cf_meta, cf_log])
            .map_err(|e| e.to_string())?;
        let db = Arc::new(Database {
            db: Arc::new(db),
            _closer: closer,
        });
        prune
            .db
            .set(Arc::downgrade(&db.db))
            .expect("a new policy cell must not hold a database yet");

        let ingest_dir = prepare_ingest_dir(path)?;

        // Commits do not write the state-floor meta row; the log rows are the durable record.
        let floor = read_state_floor(&db)?;
        let seq = floor.max(replay_newest_log_row(&db, floor)?);

        // Restore the retention rule so the ingest path keeps enforcing it after a reopen.
        let retention = Arc::new(Mutex::new(read_retention_policy(&db)?));

        // Restore the prune policies so compactions keep applying them after a reopen.
        prune.publish(compile_policies(&read_prune_policies(&db)?)?);

        let frontiers = Arc::new(Frontiers::new(seq));
        let writer = Arc::new(Writer::start(
            db.clone(),
            ingest_dir,
            frontiers.clone(),
            write_pipeline,
        ));
        let store = Self {
            db,
            frontiers,
            writer,
            retention,
            prune,
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

    /// Deletes replay-log rows with sequence numbers below `cutoff_exclusive`. A no-op when
    /// the cutoff does not advance past what this process already trimmed.
    ///
    /// ```text
    ///   sequence          1     2     3     4     5     6     7     8
    ///                                                   ^ cutoff    ^ published, the new floor
    ///   tombstone   [================================)
    ///
    ///   unmerged         [1]   [2]   [3]   [4]   [5]   [6]   [7]   [8]    file 6 untouched
    ///   merged           [1 ............... 4]   [5 ......... 7]   [8]    5 .. 7 rewritten later
    ///
    ///   keys at the cut  ..|  row 5  |  5+00  ||  5+01  |  row 6  |..
    ///   tombstone        =====================)^ its end, the first key of file 6
    /// ```
    ///
    /// The tombstone runs from key 0 to the head sentinel of the cutoff, and the same batch
    /// writes the floor. A later compaction drops the files under it, and the covered part of a
    /// merged file that the cutoff falls inside. Keys are drawn as on `stage_log_file`.
    fn prune_log(&self, cutoff_exclusive: u64) -> Result<(), String> {
        if cutoff_exclusive == 0
            || self.frontiers.trimmed.load(Ordering::Acquire) >= cutoff_exclusive
        {
            return Ok(());
        }
        let _guard = self.frontiers.persist.lock();
        // Recheck under the lock: a concurrent trim from the same ingest wave may have
        // covered this cutoff while we waited.
        if self.frontiers.trimmed.load(Ordering::Acquire) >= cutoff_exclusive {
            return Ok(());
        }

        // One atomic batch: the range tombstone that deletes the rows, and the state floor
        // that keeps `open` from re-deriving a regressed frontier once they are gone.
        // The published frontier covers every pruned row (the cutoff is capped at
        // published + 1), and everything at or below it is durable and applied to the state.
        // That also makes this safe against the writer's concurrent, lock-free log ingestion:
        // an in-flight group's row sits above every published frontier this prune could have
        // loaded. Space is reclaimed by ordinary compaction, and correctness never assumes
        // which SST files hold the rows.
        //
        // The tombstone ends at the first retained sequence's head sentinel, the smallest key of
        // a file that holds only that sequence, so it stays clear of every such file. Reaching
        // into one would pull its payload into the compaction that consumes the tombstone, and
        // reaching into the next group's file (at a cutoff of published + 1) would force a
        // memtable flush before that ingestion and place the file in L0. A merged file with
        // sequences on both sides of the cutoff does overlap, and that compaction rewrites it.
        //
        // Unsynced: batch atomicity means a crash loses the tombstone and the floor raise
        // together, leaving the rows intact and open's re-derivation consistent; the next
        // enforcement reapplies the trim. This keeps the per-append retention hook from
        // adding a second fsync to every ingest.
        let published = self.frontiers.published.load(Ordering::Acquire);
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(self.meta_cf(), SEQ_META_KEY, published.to_le_bytes());
        batch.delete_range_cf(
            self.log_cf(),
            &sequence_log_key(0)[..],
            &log_head_sentinel(cutoff_exclusive)[..],
        );
        self.db.write(batch).map_err(|e| e.to_string())?;
        self.frontiers
            .trimmed
            .store(cutoff_exclusive, Ordering::Release);
        Ok(())
    }

    /// Replaces the installed policies with those of `document`. Once this returns `Ok`, the
    /// document is durable and in force. The rows a policy removes leave when a compaction takes
    /// the files that hold them.
    //
    // A prune document covers keys only. Sequence-log retention is set through
    // `log.retention.v1.SetRetention` (see the `Retention` impl).
    fn install_prune_policies(&self, document: PrunePolicyDocument) -> Result<(), String> {
        let compiled = compile_policies(&document.policies)?;
        let row = encode_policy_document(&document).map_err(|e| e.to_string())?;

        // The row is durable before the swap, so no compaction applies a policy that a crash
        // could forget.
        let _install = self.prune.install.lock();
        self.write_prune_row(row)?;
        self.prune.publish(compiled);
        Ok(())
    }

    /// Writes the prune policy row with one synced put, so the row is durable once this returns
    /// `Ok`.
    //
    // A single put reports a value that RocksDB refuses to store. A put into a write batch
    // does not report that through the binding.
    fn write_prune_row(&self, row: Vec<u8>) -> Result<(), String> {
        #[cfg(test)]
        if *self.prune.write_gate.lock() {
            return Err("the write of the prune policy row failed".to_string());
        }
        let mut synced = WriteOptions::default();
        synced.set_sync(true);
        self.db
            .put_cf_opt(self.meta_cf(), PRUNE_META_KEY, row, &synced)
            .map_err(|e| e.to_string())
    }

    /// Lowest retained log sequence at or below the published frontier, or `None` when the log
    /// holds no such row. Shared by `oldest_retained_batch` and retention enforcement.
    fn oldest_retained_sequence(&self) -> Result<Option<u64>, String> {
        // The oldest file's head sentinel is the first live key and names the sequence by
        // itself, so the row's block stays unread. A raw iterator keeps it that way, since the
        // wrapping iterator steps onto the row when it yields the sentinel. A bare row key
        // belongs to a row written without sentinels.
        let mut it = self.db.raw_iterator_cf(self.log_cf());
        it.seek_to_first();
        let Some(key) = it.key() else {
            it.status().map_err(|e| e.to_string())?;
            return Ok(None);
        };
        let sequence = match key {
            [below @ .., 1] if below.len() == LOG_BATCH_KEY_LEN => {
                sequence_from_log_key(below)? + 1
            }
            key => sequence_from_log_key(key)?,
        };

        // Gate on the published frontier, so this never advertises an oldest batch that
        // `get_batch` would then hide. A log row can outrun the published frontier while its
        // group's state ingestion is in flight or has failed.
        if sequence > self.frontiers.published.load(Ordering::Acquire) {
            return Ok(None);
        }
        Ok(Some(sequence))
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

            // Never delete log rows above the published frontier: a group whose log ingestion
            // committed but whose state ingestion did not still needs its rows for the repair
            // replay at the next open.
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

    /// Compacts the whole state column family, memtable included, and returns when RocksDB is
    /// done. A compaction that succeeds applies the installed prune policies to every key that was
    /// live when this call began, and a failed one goes unreported. It lets a test prune at a
    /// known point.
    #[doc(hidden)]
    pub fn compact_state(&self) {
        self.db.compact_range(None::<&[u8]>, None::<&[u8]>);
    }

    /// Commits a batch and returns its sequence number. Queued batches may share a sequence.
    pub async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, IngestError> {
        // Dedicated writer threads keep blocking storage writes off Tokio workers.
        let sequence = self.writer.put_batch(kvs).await?;

        self.enforce_committed_retention(sequence).await;
        Ok(sequence)
    }

    /// Applies the active retention rule after a durable commit and logs any failures.
    async fn enforce_committed_retention(&self, sequence: u64) {
        // Reporting a trim failure as a write failure could cause the caller to retry the
        // durable batch under a new sequence number, duplicating it for subscribers. Trimming
        // is idempotent, so a later append or retention update can retry it.
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

// Installing policies issues a synced write, so it runs on the blocking pool instead of occupying
// a Tokio worker.
impl Prune for RocksStore {
    async fn apply_prune_policies(&self, document: PrunePolicyDocument) -> Result<(), String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.install_prune_policies(document))
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
        kv_codec::Utf8,
        limits::{put_entry_encoded_len, MAX_VALUE_LEN},
        log::ingest::v1::PutRequest,
        prune_policy::{GroupBy, OrderBy, PRUNE_POLICY_DOCUMENT_VERSION},
        selector::Selector,
    };
    use exoware_server::{Ingest, Log, Sequence};
    use std::collections::BTreeSet;
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
    #[tokio::test]
    async fn cancelled_streamed_put_after_enqueue_keeps_writer_and_notifier_alive() {
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
        .with_notifier(Some(hub.clone()));
        let publish_guard = store.frontiers.persist.lock();
        let put_store = store.clone();
        let task = tokio::spawn(async move { put_store.put(&mut input).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while store
                .db
                .get_cf(store.log_cf(), sequence_log_key(1))
                .unwrap()
                .is_none()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(store.current_sequence(), 0);
        assert_eq!(hub.current_sequence(), 0);
        assert_eq!(budget.usage().0, 1);
        assert!(budget.usage().1 > 0);
        assert!(budget.try_admit(0).is_err());
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

    /// Writes one log row directly, bypassing the write pipeline and the floor advance.
    fn seed_log_row(store: &RocksStore, sequence: u64, payload: &[u8]) {
        store
            .db
            .put_cf(store.log_cf(), sequence_log_key(sequence), payload)
            .expect("seed log row");
    }

    /// Stages one commit group carrying `kvs` under the sequence after `from`.
    fn prepared_write(store: &RocksStore, from: u64, kvs: Vec<(Bytes, Bytes)>) -> PreparedWrite {
        let (_sender, receiver) = mpsc::channel::<WriteRequest>();
        let ingest_dir = store.db.path().join(LOG_INGEST_DIR);
        let (wave, _) = coalesce_queued_write(
            &receiver,
            write_request_with_kvs(kvs),
            from,
            DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES,
        );
        stage_wave(&ingest_dir, wave)
    }

    #[test]
    fn snapshot_capture_waits_for_state_publication() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let group = prepared_write(
            &store,
            0,
            vec![(Bytes::from_static(b"a"), Bytes::from_static(b"value"))],
        );
        ingest_staged_file(&store.db, LOG_CF, &group.log);
        let guard = store.frontiers.persist.lock();
        ingest_staged_file(&store.db, STATE_CF, &group.state);
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
    fn snapshot_multi_get_survives_commit_and_misses_pruned_rows() {
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
                vec![(Bytes::from_static(b"a"), Bytes::from_static(b"new"))],
            ),
        );
        assert_eq!(snapshot.sequence_number, 1);
        let read = |snapshot: &OwnedRocksSnapshot| -> Vec<Option<Vec<u8>>> {
            snapshot
                .snapshot
                .multi_get([b"a", b"b"])
                .into_iter()
                .map(|value| value.expect("snapshot value"))
                .collect()
        };
        let old = Some(b"old".to_vec());
        assert_eq!(read(&snapshot), [old.clone(), old.clone()]);

        // A policy removes `b` and a compaction applies it. The snapshot keeps the value of
        // `a` that the commit replaced, and it does not shield `b` from the removal.
        install(&store, vec![drop_key(b"b")]);
        store.compact_state();
        assert_eq!(read(&snapshot), [old, None]);
        let latest = OwnedRocksSnapshot::capture(store.db.clone(), &store.frontiers);
        assert_eq!(latest.sequence_number, 2);
        assert_eq!(read(&latest), [Some(b"new".to_vec()), None]);
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
            db: Arc::new(db),
            _closer: Some(Box::new(ReopenOnDrop { path })),
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
        let group = stage_wave(dir.path(), wave);
        assert_eq!(group.sequence, 1);
        assert_eq!(group.requests.len(), 3);
        assert!(group.log.exists());
        assert!(group.state.exists());
        assert!(group.staged_bytes > 0);
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

    #[test]
    fn reopen_decodes_sequence_above_default_element_budget() {
        let dir = tempdir().expect("tempdir");
        let entries = 32 * 1024 * 1024 / std::mem::size_of::<EntryView<'_>>() + 1;
        let kvs = vec![(Bytes::from_static(b"a"), Bytes::from_static(b"value")); entries];
        let payload = encode_log_value(1, &kvs);
        drop(kvs);
        assert!(DecodeOptions::new()
            .decode_view::<StreamGetResponseView<'_>>(&payload)
            .is_err());
        {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            seed_log_row(&store, 1, &payload);
        }

        let store = RocksStore::open(dir.path(), None).expect("reopen large log row");
        assert_eq!(store.current_sequence(), 1);
        assert_eq!(
            store.get_raw(b"a").expect("get replayed value"),
            Some(b"value".to_vec())
        );
    }

    /// A missing staged file makes ingestion fail, which is fatal: the group cannot be rolled
    /// back once any of it is durable, and the next open repairs whatever the dead writer left.
    #[test]
    #[should_panic(expected = "failed to ingest staged SST")]
    fn write_errors_are_fatal() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        let group = prepared_write(
            &store,
            0,
            vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))],
        );
        std::fs::remove_file(&group.state).expect("sabotage staged state file");
        commit_and_apply(&store, group);
    }

    /// One multi-megabyte batch, sized to exercise multi-block ingested log rows.
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

            // Persist the rule without enforcing it to model a crash that lost the last
            // unsynced trim, leaving rows below the rule's floor in the log.
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

    #[tokio::test]
    async fn open_removes_only_staged_files_from_the_staging_directory() {
        // Each open places RocksDB's WAL in the staging directory.
        let dir = tempdir().expect("tempdir");
        let ingest_dir = dir.path().join(LOG_INGEST_DIR);
        let open = || {
            let mut config = RocksConfig::default();
            config.db_options.set_wal_dir(&ingest_dir);
            RocksStore::open(dir.path(), Some(config)).expect("open db")
        };

        // A retention rule evicts the first two of three groups, and only the WAL holds the rule
        // and the trim when the store closes. A fourth group is staged and never committed, as a
        // crash would leave it.
        let leftovers = {
            let store = open();
            for sequence in 1..=3 {
                store.put_batch(small_batch(sequence)).await.expect("put");
            }
            store
                .set_retention(Some(RetentionPolicy::KeepLatest { count: 1 }))
                .expect("set retention");
            assert_eq!(
                store.oldest_retained_batch().await.expect("oldest"),
                Some(3)
            );
            let group = prepared_write(&store, 3, small_batch(4));
            [group.log, group.state]
        };
        for path in &leftovers {
            assert!(path.exists(), "{} must be staged", path.display());
        }

        // Two more files have names that only resemble a staged one.
        let others = ["state-backup.sst", "log-4.sst"].map(|name| ingest_dir.join(name));
        for path in &others {
            std::fs::write(path, b"").expect("write file");
        }

        // The reopened store has the rule and the trim, so the evicted groups stay evicted. The
        // staged leftovers are gone, and the other files are not.
        let store = open();
        assert_eq!(
            store.oldest_retained_batch().await.expect("oldest"),
            Some(3)
        );
        assert!(store.get_batch(2).await.expect("get").is_none());
        for path in &leftovers {
            assert!(!path.exists(), "open must remove {}", path.display());
        }
        for path in &others {
            assert!(path.exists(), "open must keep {}", path.display());
        }

        // The rule is installed, so the next group moves the cutoff.
        store.put_batch(small_batch(4)).await.expect("put");
        assert_eq!(
            store.oldest_retained_batch().await.expect("oldest"),
            Some(4)
        );
    }

    /// A policy under `prefix` over keys laid out as a group, two zero bytes and a big-endian
    /// version. It groups keys by the group and orders them by the version.
    fn versioned_policy(prefix: &[u8], retain: RetainPolicy) -> PrunePolicy {
        PrunePolicy {
            scope: KeysScope {
                selector: Selector {
                    prefix: Bytes::copy_from_slice(prefix),
                    payload_regex: Utf8::from(
                        "(?s-u)^(?P<group>[^\\x00]*)\\x00\\x00(?P<version>.{8})$",
                    ),
                },
                group_by: GroupBy {
                    capture_groups: vec![Utf8::from("group")],
                },
                order_by: Some(OrderBy {
                    capture_group: Utf8::from("version"),
                    encoding: OrderEncoding::U64Be,
                }),
            },
            retain,
        }
    }

    /// The key of `version` of `group` for [`versioned_policy`].
    fn versioned_key(prefix: &[u8], group: &[u8], version: u64) -> Vec<u8> {
        [prefix, group, &[0, 0], &version.to_be_bytes()].concat()
    }

    /// Installs `policies` as a Prune request does.
    fn install(store: &RocksStore, policies: Vec<PrunePolicy>) {
        store
            .install_prune_policies(PrunePolicyDocument {
                version: PRUNE_POLICY_DOCUMENT_VERSION,
                policies,
            })
            .expect("install policies");
    }

    /// A policy that removes the one row keyed `key`.
    fn drop_key(key: &'static [u8]) -> PrunePolicy {
        PrunePolicy {
            scope: KeysScope {
                selector: Selector {
                    prefix: Bytes::from_static(key),
                    payload_regex: Utf8::from("(?s-u)^$"),
                },
                group_by: GroupBy::default(),
                order_by: None,
            },
            retain: RetainPolicy::DropAll,
        }
    }

    /// A filter over the policies in `shared`, built as RocksDB builds one for a compaction.
    fn filter_over(shared: &Arc<PrunePolicies>) -> PruneFilter {
        PruneFilterFactory(shared.clone(), PhantomPinned).create(CompactionFilterContext {
            is_full_compaction: false,
            is_manual_compaction: false,
        })
    }

    /// Whether `filter` removes `key`.
    fn removes(filter: &mut PruneFilter, key: &[u8]) -> bool {
        matches!(filter.filter(0, key, b""), CompactionDecision::Remove)
    }

    /// The keys that `filter` removes when it is shown `keys` in that order.
    fn removed(filter: &mut PruneFilter, keys: &[Vec<u8>]) -> Vec<Vec<u8>> {
        keys.iter()
            .filter(|key| removes(filter, key))
            .cloned()
            .collect()
    }

    /// The prefixes of the policies in the stored document, in document order.
    fn stored_prefixes(store: &RocksStore) -> Vec<Vec<u8>> {
        read_prune_policies(&store.db)
            .expect("read row")
            .iter()
            .map(|policy| policy.scope.selector.prefix.to_vec())
            .collect()
    }

    /// Waits until `ready` holds, and panics with `what` if thirty seconds pass first.
    fn wait_until(ready: impl Fn() -> bool, what: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !ready() {
            assert!(std::time::Instant::now() < deadline, "{what}");
            thread::yield_now();
        }
    }

    #[test]
    fn prune_request_replaces_every_installed_policy() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        install(
            &store,
            vec![
                versioned_policy(&[1], RetainPolicy::DropAll),
                versioned_policy(&[2], RetainPolicy::DropAll),
            ],
        );
        assert_eq!(stored_prefixes(&store), [[1], [2]]);

        // The second request names another prefix. Its document replaces the first request's in
        // the row, and a filter built afterward applies only its policy.
        install(&store, vec![versioned_policy(&[3], RetainPolicy::DropAll)]);
        assert_eq!(stored_prefixes(&store), [[3]]);
        let mut filter = filter_over(&store.prune);
        assert!(!removes(&mut filter, &versioned_key(&[1], b"row", 1)));
        assert!(!removes(&mut filter, &versioned_key(&[2], b"row", 1)));
        assert!(removes(&mut filter, &versioned_key(&[3], b"row", 1)));
    }

    #[test]
    fn only_the_last_prune_request_decides_after_reopen() {
        let dir = tempdir().expect("tempdir");
        {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            install(&store, vec![versioned_policy(&[1], RetainPolicy::DropAll)]);
            install(&store, vec![versioned_policy(&[2], RetainPolicy::DropAll)]);
        }

        // The stored document is the second request's, so only its policy decides after a
        // reopen.
        let store = RocksStore::open(dir.path(), None).expect("reopen db");
        assert_eq!(stored_prefixes(&store), [[2]]);
        let mut filter = filter_over(&store.prune);
        assert!(!removes(&mut filter, &versioned_key(&[1], b"row", 1)));
        assert!(removes(&mut filter, &versioned_key(&[2], b"row", 1)));
    }

    #[test]
    fn prune_install_syncs_the_wal() {
        let dir = tempdir().expect("tempdir");
        let mut config = RocksConfig::default();
        config.db_options.enable_statistics();

        // The clone shares the database's statistics.
        let statistics = config.db_options.clone();
        let store = RocksStore::open(dir.path(), Some(config)).expect("open db");
        let synced = || statistics.get_ticker_count(rocksdb::statistics::Ticker::WalFileSynced);

        // An install writes only the meta row, so a rise in the counter comes from that row.
        let before = synced();
        install(&store, vec![versioned_policy(&[1], RetainPolicy::DropAll)]);
        assert!(
            synced() > before,
            "the policy row must be synced before the request is answered"
        );
    }

    #[test]
    fn prune_install_holds_its_lock_until_the_swap() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        install(&store, vec![versioned_policy(&[1], RetainPolicy::DropAll)]);

        // The test holds the lock on the compiled list, so a second install writes its row and
        // then waits at the swap. It holds the install lock while it waits, so no third install
        // can write its row and swap ahead of it.
        let compiled = store.prune.compiled.lock();
        thread::scope(|scope| {
            let second = scope
                .spawn(|| install(&store, vec![versioned_policy(&[2], RetainPolicy::DropAll)]));
            wait_until(
                || stored_prefixes(&store) == [[2]],
                "the second install must write its row",
            );
            assert!(store.prune.install.is_locked());
            drop(compiled);
            second.join().expect("the second install must not panic");
        });
        assert_eq!(stored_prefixes(&store), [[2]]);
        let mut filter = filter_over(&store.prune);
        assert!(!removes(&mut filter, &versioned_key(&[1], b"row", 1)));
        assert!(removes(&mut filter, &versioned_key(&[2], b"row", 1)));
    }

    #[test]
    fn prune_install_that_fails_its_write_changes_nothing() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let document = |prefix: &[u8]| PrunePolicyDocument {
            version: PRUNE_POLICY_DOCUMENT_VERSION,
            policies: vec![versioned_policy(prefix, RetainPolicy::DropAll)],
        };
        store
            .install_prune_policies(document(&[1]))
            .expect("install policies");
        let (generation, compiled) = store.prune.current();

        // The write of the second request's row fails. The request gets the error, and the
        // row, the compiled list and the generation stay as the first request left them.
        *store.prune.write_gate.lock() = true;
        let error = store
            .install_prune_policies(document(&[2]))
            .expect_err("an install whose write fails must return an error");
        assert_eq!(error, "the write of the prune policy row failed");
        assert_eq!(stored_prefixes(&store), [[1]]);
        let (generation_after, compiled_after) = store.prune.current();
        assert_eq!(generation_after, generation);
        assert!(Arc::ptr_eq(&compiled_after, &compiled));

        // The failed install released its lock, and the request succeeds when it is sent again.
        *store.prune.write_gate.lock() = false;
        store
            .install_prune_policies(document(&[2]))
            .expect("install policies");
        assert_eq!(stored_prefixes(&store), [[2]]);
    }

    // A value this long needs a 64-bit address space.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn prune_row_write_reports_a_value_rocksdb_refuses() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        install(&store, vec![versioned_policy(&[1], RetainPolicy::DropAll)]);

        // The value is one byte longer than the longest that RocksDB stores. RocksDB refuses it
        // by its length, so its zeroed pages are never read or written.
        let refused = vec![0u8; u32::MAX as usize + 1];
        let error = store
            .write_prune_row(refused)
            .expect_err("RocksDB must refuse the value");
        assert!(error.contains("value is too large"), "{error}");
        assert_eq!(stored_prefixes(&store), [[1]]);
    }

    #[test]
    fn filter_does_not_wait_for_an_install_that_waits_on_its_write() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        install(&store, vec![versioned_policy(&[1], RetainPolicy::DropAll)]);
        let keys = [
            versioned_key(&[1], b"row", 1),
            versioned_key(&[2], b"row", 1),
        ];

        // The test holds the write gate, so a second install stops right before its write with
        // the install lock held, as it would while RocksDB stalls writes.
        let gate = store.prune.write_gate.lock();
        thread::scope(|scope| {
            let second = scope
                .spawn(|| install(&store, vec![versioned_policy(&[2], RetainPolicy::DropAll)]));
            wait_until(
                || store.prune.install.is_locked(),
                "the second install must reach its write",
            );

            // A filter is built meanwhile, as a compaction that could end the stall builds one.
            // It does not wait for the install, and it decides under the list still in force.
            let (sender, decided) = mpsc::channel();
            let (prune, keys) = (&store.prune, &keys);
            scope.spawn(move || {
                let mut filter = filter_over(prune);
                sender
                    .send(removed(&mut filter, keys))
                    .expect("the test must still wait for the decisions");
            });
            let gone = decided
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("a filter must not wait for an install");
            assert_eq!(gone, [keys[0].clone()]);
            assert_eq!(stored_prefixes(&store), [[1]]);
            drop(gate);
            second.join().expect("the second install must not panic");
        });

        // The install has finished, and a filter decides under its list.
        let mut filter = filter_over(&store.prune);
        assert_eq!(removed(&mut filter, &keys), [keys[1].clone()]);
    }

    #[test]
    fn prune_rules_decide_from_one_key() {
        let filter = |policy| {
            let shared = Arc::new(PrunePolicies::default());
            shared.publish(compile_policies(&[policy]).expect("compile"));
            filter_over(&shared)
        };
        let key = |version| versioned_key(&[1], b"row", version);

        let mut drop_all = filter(versioned_policy(&[1], RetainPolicy::DropAll));
        assert!(removes(&mut drop_all, &key(1)));

        // A key outside the prefix stays, and so does a key under it whose payload the regex
        // rejects.
        assert!(!removes(&mut drop_all, &versioned_key(&[2], b"row", 1)));
        assert!(!removes(&mut drop_all, &[1, b'r', 0, 0, 9]));

        let mut greater_than = filter(versioned_policy(
            &[1],
            RetainPolicy::GreaterThan { threshold: 4 },
        ));
        assert!(removes(&mut greater_than, &key(3)));
        assert!(removes(&mut greater_than, &key(4)));
        assert!(!removes(&mut greater_than, &key(5)));

        let mut at_least = filter(versioned_policy(
            &[1],
            RetainPolicy::GreaterThanOrEqual { threshold: 4 },
        ));
        assert!(removes(&mut at_least, &key(3)));
        assert!(!removes(&mut at_least, &key(4)));
        assert!(!removes(&mut at_least, &key(5)));

        // A group capture that did not take part in the match leaves the key alone, and an
        // order capture of the wrong length orders as zero.
        let mut loose = versioned_policy(&[1], RetainPolicy::GreaterThanOrEqual { threshold: 1 });
        loose.scope.selector.payload_regex =
            Utf8::from("(?s-u)^(?:(?P<group>a)|b)(?P<version>.*)$");
        let mut loose = filter(loose);
        assert!(!removes(&mut loose, &[1, b'b', 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(removes(&mut loose, &[1, b'a', 9, 9, 9]));
        assert!(!removes(&mut loose, &[1, b'a', 0, 0, 0, 0, 0, 0, 0, 1]));

        // With no database behind it, a filter keeps every key of a `KeepLatest` policy.
        let mut keep_latest = filter(versioned_policy(
            &[1],
            RetainPolicy::KeepLatest { count: 1 },
        ));
        assert!(!removes(&mut keep_latest, &key(1)));
    }

    #[test]
    fn reopen_rejects_corrupt_prune_policies() {
        // A row that does not decode.
        let dir = tempdir().expect("tempdir");
        {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            store
                .db
                .put_cf(store.meta_cf(), PRUNE_META_KEY, [0xFF; 3])
                .expect("write row");
        }
        let Err(error) = RocksStore::open(dir.path(), None) else {
            panic!("an undecodable document must fail open");
        };
        assert!(error.contains("corrupt prune policy meta row"), "{error}");

        // A valid document with a byte after it.
        let dir = tempdir().expect("tempdir");
        {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            let document = PrunePolicyDocument {
                version: PRUNE_POLICY_DOCUMENT_VERSION,
                policies: vec![versioned_policy(&[1], RetainPolicy::DropAll)],
            };
            let mut row = document.encode().to_vec();
            row.push(0);
            store
                .db
                .put_cf(store.meta_cf(), PRUNE_META_KEY, row)
                .expect("write row");
        }
        let Err(error) = RocksStore::open(dir.path(), None) else {
            panic!("a document with trailing bytes must fail open");
        };
        assert!(error.contains("corrupt prune policy meta row"), "{error}");

        // A row that decodes to a document the SDK rejects.
        let dir = tempdir().expect("tempdir");
        {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            let document = PrunePolicyDocument {
                version: PRUNE_POLICY_DOCUMENT_VERSION,
                policies: vec![versioned_policy(
                    &[1],
                    RetainPolicy::KeepLatest { count: 0 },
                )],
            };
            store
                .db
                .put_cf(store.meta_cf(), PRUNE_META_KEY, document.encode())
                .expect("write row");
        }
        let Err(error) = RocksStore::open(dir.path(), None) else {
            panic!("an invalid document must fail open");
        };
        assert!(error.contains("keep_latest count must be > 0"), "{error}");
    }

    #[test]
    fn keep_latest_accepts_a_count_above_any_group() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        // The store accepts a count of `usize::MAX` and stores it as sent.
        let policy = versioned_policy(&[1], RetainPolicy::KeepLatest { count: usize::MAX });
        install(&store, vec![policy.clone()]);
        assert_eq!(read_prune_policies(&store.db).expect("read row"), [policy]);

        // Group a has five versions and group b has three.
        let keys: Vec<Vec<u8>> = [(b"a", 1..=5), (b"b", 1..=3)]
            .into_iter()
            .flat_map(|(group, versions)| {
                versions.map(|version| versioned_key(&[1], group, version))
            })
            .collect();
        for key in &keys {
            store.db.put(key, b"row").expect("put");
        }

        // No group has that many rows, so nothing is removed. The window stops one key past the
        // end of a group. It is longest at the first key of group a, with the four versions
        // behind that key and the first key of group b.
        let mut filter = filter_over(&store.prune);
        let mut longest = 0;
        for key in &keys {
            assert!(!removes(&mut filter, key));
            longest = longest.max(filter.ahead.as_ref().map_or(0, |a| a.window.len()));
        }
        assert_eq!(longest, 5);
    }

    #[test]
    fn keep_latest_reads_ahead_in_the_live_state() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let key = |group: &[u8], version| versioned_key(&[1], group, version);

        // The one version of group b is higher than every version of group a before it.
        let keys: Vec<Vec<u8>> = [(b"a", 1..=4), (b"b", 9..=9), (b"c", 1..=2)]
            .into_iter()
            .flat_map(|(group, versions)| versions.map(move |version| key(group, version)))
            .collect();
        for key in &keys {
            store.db.put(key, b"row").expect("put");
        }

        // Shown every key in key order, the filter removes all but the latest `count` of each
        // group.
        for (count, expected) in [
            (
                1,
                vec![key(b"a", 1), key(b"a", 2), key(b"a", 3), key(b"c", 1)],
            ),
            (2, vec![key(b"a", 1), key(b"a", 2)]),
            (3, vec![key(b"a", 1)]),
            (4, vec![]),
        ] {
            install(
                &store,
                vec![versioned_policy(&[1], RetainPolicy::KeepLatest { count })],
            );
            let mut filter = filter_over(&store.prune);
            assert_eq!(removed(&mut filter, &keys), expected, "keep latest {count}");
        }

        // A compaction of some files shows the filter only the keys in them, and one of those
        // can be a version that is not live. The cursor reads the keys that follow from the
        // live state.
        install(
            &store,
            vec![versioned_policy(
                &[1],
                RetainPolicy::KeepLatest { count: 2 },
            )],
        );
        let mut filter = filter_over(&store.prune);
        let shown = [key(b"a", 0), key(b"a", 2), key(b"a", 3), key(b"c", 1)];
        assert_eq!(removed(&mut filter, &shown), [key(b"a", 0), key(b"a", 2)]);
    }

    #[test]
    fn keep_latest_breaks_ties_by_key_order() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        // Two rows of one group share an order value. The later key counts as the newer.
        let mut policy = versioned_policy(&[1], RetainPolicy::KeepLatest { count: 1 });
        policy.scope.selector.payload_regex =
            Utf8::from("(?s-u)^(?P<group>[a-z])(?P<version>.{8})[xyz]$");
        install(&store, vec![policy.clone()]);
        let key = |last: u8| [&[1, b'a'][..], &7u64.to_be_bytes(), &[last]].concat();
        let keys = [key(b'x'), key(b'y')];
        for key in &keys {
            store.db.put(key, b"row").expect("put");
        }
        let mut filter = filter_over(&store.prune);
        assert_eq!(removed(&mut filter, &keys), [key(b'x')]);

        // A third row with the same order value continues the chain behind the second. With a
        // count of two the first row has two newer rows behind it, and the second has one.
        policy.retain = RetainPolicy::KeepLatest { count: 2 };
        install(&store, vec![policy]);
        store.db.put(key(b'z'), b"row").expect("put");
        let keys = [key(b'x'), key(b'y'), key(b'z')];
        let mut filter = filter_over(&store.prune);
        assert_eq!(removed(&mut filter, &keys), [key(b'x')]);
    }

    #[test]
    fn keep_latest_reads_each_policy_under_its_own_rule() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        install(
            &store,
            vec![
                versioned_policy(&[1], RetainPolicy::KeepLatest { count: 2 }),
                versioned_policy(&[2], RetainPolicy::KeepLatest { count: 1 }),
            ],
        );

        // The last key of the first policy reads ahead into the keys of the second. The filter
        // still decides those keys under the second policy's own rule, which keeps one row
        // where the first policy's would keep two.
        let keys = [
            versioned_key(&[1], b"z", 1),
            versioned_key(&[2], b"a", 1),
            versioned_key(&[2], b"a", 2),
            versioned_key(&[2], b"a", 3),
        ];
        for key in &keys {
            store.db.put(key, b"row").expect("put");
        }
        let mut filter = filter_over(&store.prune);
        assert_eq!(removed(&mut filter, &keys), keys[1..3]);
    }

    #[test]
    fn keep_latest_keeps_extra_keys_when_a_group_does_not_sort_together() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        // The version comes first in the key, so the versions of one group are apart. Each key
        // is followed by a key of another group or by none, so nothing is removed.
        let mut policy = versioned_policy(&[1], RetainPolicy::KeepLatest { count: 1 });
        policy.scope.selector.payload_regex =
            Utf8::from("(?s-u)^(?P<version>.{8})(?P<group>[a-z])$");
        install(&store, vec![policy]);
        let key = |version: u64, group: u8| [&[1][..], &version.to_be_bytes(), &[group]].concat();
        let keys = [key(1, b'a'), key(1, b'b'), key(2, b'a'), key(2, b'b')];
        for key in &keys {
            store.db.put(key, b"row").expect("put");
        }
        let mut filter = filter_over(&store.prune);
        assert!(removed(&mut filter, &keys).is_empty());
    }

    #[test]
    fn keep_latest_keeps_the_newest_when_order_runs_against_key_order() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        // A tag sorts the keys of a group before their versions do. In key order the versions
        // run 5, 9, 1.
        let policy = |count| {
            let mut policy = versioned_policy(&[1], RetainPolicy::KeepLatest { count });
            policy.scope.selector.payload_regex =
                Utf8::from("(?s-u)^(?P<group>[a-z])[xyz](?P<version>.{8})$");
            policy
        };
        let key = |tag: u8, version: u64| [&[1, b'a', tag][..], &version.to_be_bytes()].concat();
        let keys = [key(b'x', 5), key(b'y', 9), key(b'z', 1)];
        for key in &keys {
            store.db.put(key, b"row").expect("put");
        }

        // Version 5 has the newer 9 behind it. Version 9 has only the older 1 behind it, and an
        // older version does not count against it.
        install(&store, vec![policy(1)]);
        let mut filter = filter_over(&store.prune);
        assert_eq!(removed(&mut filter, &keys), [key(b'x', 5)]);

        // Version 5 is one of the latest two. The 9 and the 1 behind it do not form a rising
        // chain, so they do not count against it together.
        install(&store, vec![policy(2)]);
        let mut filter = filter_over(&store.prune);
        assert!(removed(&mut filter, &keys).is_empty());
    }

    /// Runs `walk` and returns the cursor steps and seeks it made on this thread, from
    /// RocksDB's own counters. The rows of these tests sit in the memtable, where each cursor
    /// step is one memtable step.
    fn cursor_work(walk: impl FnOnce()) -> (u64, u64) {
        rocksdb::perf::set_perf_stats(rocksdb::perf::PerfStatsLevel::EnableCount);
        let mut perf = rocksdb::perf::PerfContext::default();
        perf.reset();
        walk();
        let work = (
            perf.metric(rocksdb::perf::PerfMetric::NextOnMemtableCount),
            perf.metric(rocksdb::perf::PerfMetric::SeekOnMemtableCount),
        );
        rocksdb::perf::set_perf_stats(rocksdb::perf::PerfStatsLevel::Disable);
        work
    }

    #[test]
    fn read_ahead_cursor_is_renewed_on_a_long_walk() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        install(
            &store,
            vec![versioned_policy(
                &[1],
                RetainPolicy::KeepLatest { count: 1 },
            )],
        );
        let versions = READ_AHEAD_REFRESH_KEYS as u64 + 16;
        let keys: Vec<Vec<u8>> = (1..=versions)
            .map(|version| versioned_key(&[1], b"row", version))
            .collect();
        let mut batch = rocksdb::WriteBatch::default();
        for key in &keys {
            batch.put(key, b"row");
        }
        store.db.write(batch).expect("write");

        // Every version but the last is removed, across the point where the filter drops its
        // cursor for a fresh one. The walk seeks once when it opens its first cursor and once
        // more when it opens the fresh one.
        let mut filter = filter_over(&store.prune);
        let mut gone = Vec::new();
        let (_, seeks) = cursor_work(|| gone = removed(&mut filter, &keys));
        assert_eq!(gone, keys[..keys.len() - 1]);
        assert_eq!(seeks, 2);
    }

    #[test]
    fn keep_latest_reads_a_long_window_about_once() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        // The window fills to `count`, twice the age at which the filter drops a cursor with a
        // short window. The group is longer still.
        let count = 2 * READ_AHEAD_REFRESH_KEYS;
        let versions = 5 * READ_AHEAD_REFRESH_KEYS;
        install(
            &store,
            vec![versioned_policy(&[1], RetainPolicy::KeepLatest { count })],
        );
        let keys: Vec<Vec<u8>> = (1..=versions as u64)
            .map(|version| versioned_key(&[1], b"row", version))
            .collect();
        let mut batch = rocksdb::WriteBatch::default();
        for key in &keys {
            batch.put(key, b"row");
        }
        store.db.write(batch).expect("write");

        // All but the latest `count` are removed. A dropped cursor costs its window again, and
        // the cursor is dropped rarely enough that the walk stays under two steps a key. The
        // window fills to `count` keys and never holds more.
        let mut filter = filter_over(&store.prune);
        let mut gone = Vec::new();
        let mut longest = 0;
        let (steps, _) = cursor_work(|| {
            for key in &keys {
                if removes(&mut filter, key) {
                    gone.push(key.clone());
                }
                longest = longest.max(filter.ahead.as_ref().map_or(0, |a| a.window.len()));
            }
        });
        assert_eq!(gone, keys[..versions - count]);
        assert!(steps < 2 * versions as u64, "{steps}");
        assert_eq!(longest, count);
    }

    #[test]
    fn keep_latest_reads_one_key_for_the_newest_of_a_group() {
        const GROUPS: u8 = 8;
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let count = 256;
        install(
            &store,
            vec![versioned_policy(&[1], RetainPolicy::KeepLatest { count })],
        );

        // Every group is twice as long as `count`.
        let versions = 2 * count as u64;
        let key = |group: u8, version| versioned_key(&[1], &[b'a' + group], version);
        let mut batch = rocksdb::WriteBatch::default();
        for group in 0..GROUPS {
            for version in 1..=versions {
                batch.put(key(group, version), b"row");
            }
        }
        store.db.write(batch).expect("write");

        // The compaction shows the newest key of each group and nothing else. The key after
        // it is the oldest of the next group, and after the last group the cursor steps off
        // the end. Either way the key is kept at the cost of one seek and one step.
        let newest: Vec<Vec<u8>> = (0..GROUPS).map(|group| key(group, versions)).collect();
        let mut filter = filter_over(&store.prune);
        let mut gone = Vec::new();
        let (steps, seeks) = cursor_work(|| gone = removed(&mut filter, &newest));
        assert!(gone.is_empty());
        assert_eq!((steps, seeks), (u64::from(GROUPS), u64::from(GROUPS)));
    }

    #[test]
    fn keep_latest_stops_reading_where_the_chain_breaks() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let count = 4;
        install(
            &store,
            vec![versioned_policy(&[1], RetainPolicy::KeepLatest { count })],
        );

        // Group a has three versions, and group b has a hundred behind them.
        let mut batch = rocksdb::WriteBatch::default();
        for version in 1..=3 {
            batch.put(versioned_key(&[1], b"a", version), b"row");
        }
        for version in 1..=100 {
            batch.put(versioned_key(&[1], b"b", version), b"row");
        }
        store.db.write(batch).expect("write");

        // The oldest key of group a has two followers in its group and then a key of group b.
        // The cursor reads those three and stops, whatever lies behind them.
        let mut filter = filter_over(&store.prune);
        let mut gone = false;
        let (steps, seeks) =
            cursor_work(|| gone = removes(&mut filter, &versioned_key(&[1], b"a", 1)));
        assert!(!gone);
        assert_eq!((steps, seeks), (3, 1));
        assert_eq!(
            filter
                .ahead
                .as_ref()
                .expect("cursor must be open")
                .window
                .len(),
            3
        );
    }

    #[test]
    fn keep_latest_seeks_once_past_the_last_live_key() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        install(
            &store,
            vec![versioned_policy(
                &[1],
                RetainPolicy::KeepLatest { count: 1 },
            )],
        );
        store.db.put([0], b"row").expect("put");

        // A compaction can show the filter versions that are not live. No live key follows the
        // first of these, so none follows the later ones either, and the cursor seeks once.
        let keys: Vec<Vec<u8>> = (1..=64)
            .map(|version| versioned_key(&[1], b"row", version))
            .collect();
        let mut filter = filter_over(&store.prune);
        let mut gone = Vec::new();
        let (_, seeks) = cursor_work(|| gone = removed(&mut filter, &keys));
        assert!(gone.is_empty());
        assert_eq!(seeks, 1);
    }

    #[test]
    fn read_ahead_cursor_is_dropped_when_it_goes_unused() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        install(
            &store,
            vec![versioned_policy(
                &[1],
                RetainPolicy::KeepLatest { count: 1 },
            )],
        );
        let inside = versioned_key(&[1], b"row", 1);
        store.db.put(&inside, b"row").expect("put");

        // Past the policy's prefix no key needs the cursor, and the filter drops it once it
        // has aged.
        let mut filter = filter_over(&store.prune);
        assert!(!removes(&mut filter, &inside));
        assert!(filter.ahead.is_some());
        for version in 0..READ_AHEAD_REFRESH_KEYS as u64 {
            assert!(!removes(&mut filter, &versioned_key(&[2], b"row", version)));
        }
        assert!(filter.ahead.is_none());
    }

    #[test]
    fn replaced_policy_stops_at_the_next_key() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        install(&store, vec![versioned_policy(&[1], RetainPolicy::DropAll)]);
        let keys: Vec<Vec<u8>> = (1..=2)
            .map(|version| versioned_key(&[1], b"row", version))
            .collect();

        // The filter is in the middle of a compaction when a request replaces its policy with
        // one that keeps every row. The new policy decides the next key.
        let mut filter = filter_over(&store.prune);
        assert!(removes(&mut filter, &keys[0]));
        install(
            &store,
            vec![versioned_policy(
                &[1],
                RetainPolicy::GreaterThanOrEqual { threshold: 0 },
            )],
        );
        assert!(!removes(&mut filter, &keys[1]));
    }

    #[test]
    fn replaced_policy_forgets_what_the_cursor_read() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        install(
            &store,
            vec![versioned_policy(
                &[1],
                RetainPolicy::KeepLatest { count: 2 },
            )],
        );
        let keys: Vec<Vec<u8>> = (1..=3)
            .map(|version| versioned_key(&[1], b"row", version))
            .collect();
        for key in &keys {
            store.db.put(key, b"row").expect("put");
        }

        // Version 1 has two versions behind it, and the cursor has read them.
        let mut filter = filter_over(&store.prune);
        assert!(removes(&mut filter, &keys[0]));

        // The new policy keeps one version and does not select version 3, so version 2 is the
        // newest row it selects. What the cursor read under the old policy does not count
        // against it.
        let mut policy = versioned_policy(&[1], RetainPolicy::KeepLatest { count: 1 });
        policy.scope.selector.payload_regex =
            Utf8::from("(?s-u)^(?P<group>[^\\x00]*)\\x00\\x00(?P<version>\\x00{7}[\\x01\\x02])$");
        install(&store, vec![policy]);
        assert!(!removes(&mut filter, &keys[1]));
    }

    #[test]
    fn keep_latest_does_not_count_rows_written_after_its_policy_was_replaced() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        install(
            &store,
            vec![versioned_policy(
                &[1],
                RetainPolicy::KeepLatest { count: 1 },
            )],
        );
        let only = versioned_key(&[1], b"row", 1);
        store.db.put(&only, b"row").expect("put");

        // The gate stops the filter after it has taken the database and before its cursor
        // opens. Meanwhile a request replaces the policy with one that keeps every row, and a
        // newer version is written. The cursor then sees that version, and the filter keeps
        // the key because its policy was replaced.
        let gate = store.prune.read_ahead_gate.lock();
        let mut filter = filter_over(&store.prune);
        let db = Arc::downgrade(&store.db.db);
        let removed = thread::scope(|scope| {
            let shown = scope.spawn(|| removes(&mut filter, &only));
            wait_until(|| db.strong_count() >= 2, "the filter must reach the gate");
            install(
                &store,
                vec![versioned_policy(
                    &[1],
                    RetainPolicy::GreaterThanOrEqual { threshold: 0 },
                )],
            );
            store
                .db
                .put(versioned_key(&[1], b"row", 2), b"row")
                .expect("put");
            drop(gate);
            shown.join().expect("the filter thread must not panic")
        });
        assert!(!removed);
    }

    /// Live SST files of the state column family as (name, level), sorted by name.
    fn state_file_names(store: &RocksStore) -> Vec<(String, i32)> {
        let mut files: Vec<_> = store
            .db
            .live_files()
            .expect("live files")
            .into_iter()
            .filter(|file| file.column_family_name == STATE_CF)
            .map(|file| (file.name, file.level))
            .collect();
        files.sort();
        files
    }

    /// Rows holding `version` of each group in `groups`, keyed for [`versioned_policy`] under
    /// the prefix `[1]`, with values of `value_len` bytes.
    fn version_rows(
        groups: std::ops::Range<u64>,
        version: u64,
        value_len: usize,
    ) -> Vec<(Bytes, Bytes)> {
        groups
            .map(|group| {
                (
                    Bytes::from(versioned_key(
                        &[1],
                        format!("g{group:03}").as_bytes(),
                        version,
                    )),
                    Bytes::from(vec![7; value_len]),
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn keep_latest_counts_newer_keys_in_a_file_the_compaction_skips() {
        // Fifteen files above the oldest one make sixteen sorted runs. At sixteen the state
        // family starts a compaction by itself.
        const OLD_VERSIONS: u64 = 15;
        const NEWEST: u64 = 100;
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        install(
            &store,
            vec![versioned_policy(
                &[1],
                RetainPolicy::KeepLatest { count: 1 },
            )],
        );

        // The newest version of every group is ingested first, as one large file.
        store
            .put_batch(version_rows(0..64, NEWEST, 4096))
            .await
            .expect("put");
        let oldest_file = state_file_names(&store);
        assert_eq!(oldest_file.len(), 1);

        // Older versions of a few groups follow as small files that overlap it. RocksDB
        // compacts the small files together and leaves the large one alone.
        for version in 1..=OLD_VERSIONS {
            store
                .put_batch(version_rows(1..6, version, 8))
                .await
                .expect("put");
        }
        store
            .db
            .wait_for_compact(&rocksdb::WaitForCompactOptions::default())
            .expect("wait for compaction");
        let files = state_file_names(&store);
        assert_eq!(files.len(), 2, "{files:?}");
        assert!(files.contains(&oldest_file[0]), "{files:?}");

        // The newest version of each group sorts after every older one and sits in the file
        // the compaction skipped. The cursor reads it from the live state, so the filter
        // removed every older version.
        for (key, _) in (1..=OLD_VERSIONS).flat_map(|version| version_rows(1..6, version, 8)) {
            assert_eq!(store.get_raw(&key).expect("get"), None);
        }
        for (key, value) in version_rows(0..64, NEWEST, 4096) {
            assert_eq!(
                store.get_raw(&key).expect("get").as_deref(),
                Some(&value[..])
            );
        }
    }

    #[test]
    fn keep_latest_keeps_count_rows_while_compactions_overlap() {
        const COUNT: usize = 3;
        const GROUPS: usize = 8;
        for seed in [1u64, 2, 3] {
            let dir = tempdir().expect("tempdir");

            // The default of two background jobs runs one compaction at a time. Four let RocksDB
            // run a second beside the first once thirty-two sorted runs wait.
            let mut config = RocksConfig::default();
            config.db_options.set_max_background_jobs(4);
            let store = RocksStore::open(dir.path(), Some(config)).expect("open db");
            install(
                &store,
                vec![versioned_policy(
                    &[1],
                    RetainPolicy::KeepLatest { count: COUNT },
                )],
            );
            let key = |group: usize, version: u64| {
                Bytes::from(versioned_key(&[1], &[b'a' + group as u8], version))
            };
            let row = Bytes::from_static(b"row");
            let mut state = seed;
            let mut random = |below: u64| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state % below
            };

            // The first commit's file spans every key, so each later file overlaps it.
            let mut sequence = 0;
            let mut commit = |rows: Vec<(Bytes, Bytes)>| {
                commit_and_apply(&store, prepared_write(&store, sequence, rows));
                sequence += 1;
            };
            commit(vec![
                (Bytes::from_static(&[0]), row.clone()),
                (Bytes::from_static(&[255]), row.clone()),
            ]);

            // Every version ever written, by group, and how many of them are gone.
            let mut written = vec![BTreeSet::new(); GROUPS];
            let mut pruned = 0;
            let anchor = Bytes::from_static(&[0, 1]);
            let db = Arc::downgrade(&store.db.db);
            for _ in 0..3 {
                // Sixteen files start a compaction, and the gate holds its filter before its
                // first read. Sixteen more start a second compaction beside it, held the same
                // way. Both are under way when the gate opens, so the rows one of them counts
                // can be rows the other removes.
                let gate = store.prune.read_ahead_gate.lock();
                for holders in [2, 3] {
                    for _ in 0..16 {
                        // Each file rewrites one key, so it overlaps every other file and
                        // makes a sorted run of its own. It adds up to three versions, most of
                        // them the newest of their group.
                        let mut rows = BTreeMap::from([(anchor.clone(), row.clone())]);
                        for _ in 0..3 {
                            let group = random(GROUPS as u64) as usize;
                            let newest = written[group].last().copied().unwrap_or(0);
                            let version = if random(4) == 0 {
                                1 + random(newest + 1)
                            } else {
                                newest + 1
                            };
                            written[group].insert(version);
                            rows.insert(key(group, version), row.clone());
                        }
                        commit(rows.into_iter().collect());
                    }
                    wait_until(
                        || db.strong_count() >= holders,
                        "a compaction must reach the gate",
                    );
                }
                drop(gate);
                store
                    .db
                    .wait_for_compact(&rocksdb::WaitForCompactOptions::default())
                    .expect("wait for compaction");

                // The compactions removed rows, and the latest `COUNT` versions of every group are
                // still there.
                let live = |group: usize, version: &u64| {
                    store.get_raw(&key(group, *version)).expect("get").is_some()
                };
                let mut gone = 0;
                for (group, versions) in written.iter().enumerate() {
                    gone += versions
                        .iter()
                        .filter(|version| !live(group, version))
                        .count();
                    for version in versions.iter().rev().take(COUNT) {
                        assert!(
                            live(group, version),
                            "seed {seed}: group {group} must keep {version} of {versions:?}"
                        );
                    }
                }
                assert!(gone > pruned, "seed {seed}: the compactions must prune");
                pruned = gone;
            }

            // A compaction of every file leaves exactly the latest `COUNT` versions of each
            // group.
            store.compact_state();
            for (group, versions) in written.iter().enumerate() {
                let live: Vec<u64> = versions
                    .iter()
                    .copied()
                    .filter(|version| store.get_raw(&key(group, *version)).expect("get").is_some())
                    .collect();
                let latest: Vec<u64> = versions.iter().rev().take(COUNT).rev().copied().collect();
                assert_eq!(live, latest, "seed {seed}: group {group}");
            }
        }
    }

    #[test]
    fn keep_latest_counts_rows_that_another_compaction_is_removing() {
        let dir = tempdir().expect("tempdir");

        // The default of two background jobs runs one compaction at a time. Four let RocksDB
        // run a second beside the first once thirty-two sorted runs wait.
        let mut config = RocksConfig::default();
        config.db_options.set_max_background_jobs(4);
        let store = RocksStore::open(dir.path(), Some(config)).expect("open db");
        install(
            &store,
            vec![versioned_policy(
                &[1],
                RetainPolicy::KeepLatest { count: 2 },
            )],
        );
        let key = |version: u64| Bytes::from(versioned_key(&[1], b"a", version));
        let live = || -> Vec<u64> {
            (1..=7)
                .filter(|version| store.get_raw(&key(*version)).expect("get").is_some())
                .collect()
        };
        let row = Bytes::from_static(b"row");
        let mut sequence = 0;
        let mut commit = |rows: Vec<(Bytes, Bytes)>| {
            commit_and_apply(&store, prepared_write(&store, sequence, rows));
            sequence += 1;
        };

        // The first file holds versions 3 to 7 of group a. Behind them it holds
        // `READ_AHEAD_REFRESH_KEYS` keys that the policy does not select, enough for a filter to
        // drop its cursor for age. The file spans every key, so each later file overlaps it.
        let mut rows = vec![
            (Bytes::from_static(&[0]), row.clone()),
            (Bytes::from_static(&[255]), row.clone()),
        ];
        rows.extend((3..=7).map(|version| (key(version), row.clone())));
        rows.extend((0..READ_AHEAD_REFRESH_KEYS as u32).map(|unselected| {
            let key = [&[1, b'b'][..], &unselected.to_be_bytes()].concat();
            (Bytes::from(key), Bytes::from(vec![0; 16]))
        }));
        let read_gate = store.prune.read_ahead_gate.lock();
        let aged_gate = store.prune.aged_gate.lock();
        commit(rows);

        // Fifteen files that rewrite one key make sixteen sorted runs with the first, large
        // enough together for RocksDB to compact them all. The gate holds that compaction's
        // filter at version 3, before its first read.
        let rewrite = (Bytes::from_static(&[0, 1]), Bytes::from(vec![0; 32 * 1024]));
        for _ in 0..15 {
            commit(vec![rewrite.clone()]);
        }
        let db = Arc::downgrade(&store.db.db);
        wait_until(
            || db.strong_count() == 2,
            "the first compaction must reach the read-ahead gate",
        );

        // Once the gate opens, the filter decides that versions 3, 4 and 5 go, each with two
        // newer versions behind it. It then drops its cursor for age and stops at the aged
        // gate, before its compaction finishes.
        drop(read_gate);
        wait_until(
            || db.strong_count() == 1,
            "the first compaction must drop its cursor",
        );
        assert_eq!(live(), [3, 4, 5, 6, 7]);

        // A request replaces the policy with one that keeps the latest five. The removals the
        // first compaction has decided still land when it finishes.
        install(
            &store,
            vec![versioned_policy(
                &[1],
                RetainPolicy::KeepLatest { count: 5 },
            )],
        );

        // Versions 1 and 2 arrive after the request, and sixteen more files start a second
        // compaction beside the first. Five rows follow version 1 and five follow version 2
        // only with versions 3, 4 and 5 among them, which the first compaction is removing.
        // The second counts them, removes versions 1 and 2 and finishes first.
        commit(vec![
            rewrite.clone(),
            (key(1), row.clone()),
            (key(2), row.clone()),
        ]);
        assert_eq!(live(), [1, 2, 3, 4, 5, 6, 7]);
        for _ in 0..15 {
            commit(vec![rewrite.clone()]);
        }
        wait_until(
            || live() == [3, 4, 5, 6, 7],
            "the second compaction must remove versions 1 and 2",
        );

        // The first compaction finishes, and the group holds two rows where the new policy
        // keeps five.
        drop(aged_gate);
        store
            .db
            .wait_for_compact(&rocksdb::WaitForCompactOptions::default())
            .expect("wait for compaction");
        assert_eq!(live(), [6, 7]);
    }

    #[test]
    fn store_closes_while_a_filter_reads_ahead() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        install(
            &store,
            vec![versioned_policy(
                &[1],
                RetainPolicy::KeepLatest { count: 1 },
            )],
        );

        // Sixteen overlapping files start a compaction, and the gate holds its filter at the
        // moment it has taken the database to read ahead.
        let prune = store.prune.clone();
        let gate = prune.read_ahead_gate.lock();
        for version in 1..=16 {
            let rows = version_rows(0..32, version, 4096);
            commit_and_apply(&store, prepared_write(&store, version - 1, rows));
        }
        let db = Arc::downgrade(&store.db.db);
        wait_until(|| db.strong_count() == 2, "a filter must open a cursor");

        // The last handle to the store drops while the filter still holds the database.
        let database = Arc::downgrade(&store.db);
        let (closed_sender, closed) = mpsc::channel();
        let closer = thread::spawn(move || {
            drop(store);
            closed_sender
                .send(())
                .expect("the test must still wait for the close");
        });
        wait_until(
            || database.strong_count() == 0,
            "the store must start to close",
        );
        drop(gate);
        closed
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the store must close while a filter reads ahead");
        closer.join().expect("the closing thread must not panic");
        assert_eq!(db.strong_count(), 0);

        // The close finished, so the store reopens, and the newest version of every group is
        // there.
        let store = RocksStore::open(dir.path(), None).expect("reopen db");
        for (key, value) in version_rows(0..32, 16, 4096) {
            assert_eq!(
                store.get_raw(&key).expect("get").as_deref(),
                Some(&value[..])
            );
        }
    }

    /// Number of retained rows in the log column family.
    fn live_log_rows(store: &RocksStore) -> usize {
        store
            .db
            .iterator_cf(store.log_cf(), IteratorMode::Start)
            .filter(|item| {
                item.as_ref()
                    .map_or(true, |(key, _)| key.len() == LOG_BATCH_KEY_LEN)
            })
            .count()
    }

    /// Readability of each key of `sequence`'s log file in file order (head sentinel, row,
    /// tail sentinel).
    fn log_file_keys_present(store: &RocksStore, sequence: u64) -> [bool; 3] {
        let present = |key: &[u8]| {
            store
                .db
                .get_cf(store.log_cf(), key)
                .expect("get log key")
                .is_some()
        };
        [
            present(&log_head_sentinel(sequence)),
            present(&sequence_log_key(sequence)),
            present(&log_tail_sentinel(sequence)),
        ]
    }

    /// Live SST files of the log column family as (name, level), sorted by name.
    fn log_files(store: &RocksStore) -> Vec<(String, i32)> {
        let mut files: Vec<_> = store
            .db
            .live_files()
            .expect("live files")
            .into_iter()
            .filter(|file| file.column_family_name == LOG_CF)
            .map(|file| (file.name, file.level))
            .collect();
        files.sort();
        files
    }

    #[tokio::test]
    async fn log_prune_keeps_the_oldest_retained_file_out_of_compaction() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        for tag in 1..=3u8 {
            store.put_batch(large_batch(tag)).await.expect("put");
        }

        // Cutoff 3 evicts sequence 2's whole file and must leave sequence 3's head sentinel in
        // place. That sentinel is the retained file's smallest key, so a tombstone reaching it
        // overlaps the file.
        store
            .set_retention(Some(RetentionPolicy::KeepLatest { count: 1 }))
            .expect("set retention");
        assert_eq!(log_file_keys_present(&store, 2), [false; 3]);
        assert_eq!(log_file_keys_present(&store, 3), [true; 3]);

        // The compaction that consumes the tombstone drops the evicted files. The retained file
        // must not be one of its inputs, since an input is read and rewritten in full.
        let before = log_files(&store);
        store.db.flush_cf(store.log_cf()).expect("flush log");
        store
            .db
            .compact_range_cf(store.log_cf(), None::<&[u8]>, None::<&[u8]>);
        let after = log_files(&store);
        assert_eq!(after.len(), 1, "only the retained file remains");
        assert!(
            before.contains(&after[0]),
            "the retained log file must survive compaction unchanged"
        );
    }

    #[tokio::test]
    async fn oldest_retained_lookup_reads_only_the_head_sentinel() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        for tag in 1..=2u8 {
            store.put_batch(large_batch(tag)).await.expect("put");
        }

        // Retention enforcement runs this lookup after every commit, so it must not load any
        // row's payload block. Ingestion leaves those blocks out of every cache, so loading one
        // would hit the disk on every commit.
        rocksdb::perf::set_perf_stats(rocksdb::perf::PerfStatsLevel::EnableCount);
        let mut perf = rocksdb::perf::PerfContext::default();
        let mut measured_lookup = || {
            perf.reset();
            let oldest = store.oldest_retained_sequence().expect("oldest");
            let read = perf.metric(rocksdb::perf::PerfMetric::BlockReadByte);
            assert!(
                read < 4096,
                "the oldest-retained lookup must read only sentinel blocks, read {read} bytes"
            );
            oldest
        };
        assert_eq!(measured_lookup(), Some(1));

        // With a rule installed, the evicted files below the cutoff sit under a tombstone. The
        // lookup must skip them by their sentinels as well, never through their rows.
        store
            .set_retention(Some(RetentionPolicy::KeepLatest { count: 1 }))
            .expect("set retention");
        assert_eq!(measured_lookup(), Some(2));
        rocksdb::perf::set_perf_stats(rocksdb::perf::PerfStatsLevel::Disable);
    }

    #[tokio::test]
    async fn drop_all_retention_ingests_log_files_straight_to_the_bottom_level() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        store
            .set_retention(Some(RetentionPolicy::DropAll))
            .expect("set retention");

        // Each trim ends at the head sentinel of the sequence that is not ingested yet, so the
        // next group's file never overlaps the memtable. An overlap would force a flush before
        // the ingestion, place the file in L0, and have compaction rewrite earlier files.
        let mut seen = Vec::new();
        for tag in 1..=4u8 {
            store.put_batch(large_batch(tag)).await.expect("put");
            let files = log_files(&store);
            assert_eq!(files.len(), seen.len() + 1, "each put adds one log file");
            assert!(
                files.iter().all(|(_, level)| *level == 6),
                "log files must land in the bottom level: {files:?}"
            );
            assert!(
                seen.iter().all(|file| files.contains(file)),
                "earlier log files must not be rewritten: {seen:?} vs {files:?}"
            );
            seen = files;
        }
    }

    /// Opens a store that merges its log files every `log_merge_files` commit groups.
    fn open_merging(path: &Path, log_merge_files: usize) -> RocksStore {
        RocksStore::open(
            path,
            Some(RocksConfig {
                write_pipeline: RocksWritePipelineConfig {
                    log_merge_files: NonZeroUsize::new(log_merge_files).expect("nonzero"),
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        .expect("open db")
    }

    /// Waits for the merge worker to leave at most `at_most` log files.
    async fn wait_for_log_files(store: &RocksStore, at_most: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while log_files(store).len() > at_most {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the merge worker must leave at most {at_most} log files: {:?}",
                log_files(store)
            )
        });
    }

    /// The rows of the small batch committed as `sequence`.
    fn small_batch(sequence: u64) -> Vec<(Bytes, Bytes)> {
        let mut key = b"merge-".to_vec();
        key.extend_from_slice(&sequence.to_be_bytes());
        vec![(
            Bytes::from(key),
            Bytes::from(sequence.to_le_bytes().to_vec()),
        )]
    }

    /// Asserts that sequences `1..=newest` are all in the log with their sentinels and in the
    /// state, exactly as [`small_batch`] wrote them.
    async fn assert_small_batches(store: &RocksStore, newest: u64) {
        assert_eq!(store.current_sequence(), newest);
        assert_eq!(
            store.oldest_retained_batch().await.expect("oldest"),
            Some(1)
        );
        for sequence in 1..=newest {
            let batch = store
                .get_batch(sequence)
                .await
                .expect("get batch")
                .unwrap_or_else(|| panic!("batch {sequence} must be retained"));
            assert_eq!(batch_entries(batch), small_batch(sequence));
            assert_eq!(log_file_keys_present(store, sequence), [true; 3]);
            let (key, value) = small_batch(sequence).remove(0);
            assert_eq!(
                store.get_raw(&key).expect("get").as_deref(),
                Some(&value[..])
            );
        }
    }

    /// A bottom-level log file holding sequences `first..=last`.
    fn log_file(first: u64, last: u64, size: u64) -> LogFile {
        LogFile {
            start: log_head_sentinel(first).to_vec(),
            end: log_tail_sentinel(last).to_vec(),
            size,
        }
    }

    #[test]
    fn log_merge_plan_waits_for_the_newest_run_and_closes_older_ones() {
        // A file of exactly the small-file limit is the smallest that counts as large.
        const LARGE: u64 = LOG_MERGE_SMALL_BYTES;
        let singles = |sequences: std::ops::RangeInclusive<u64>| {
            sequences.map(|sequence| log_file(sequence, sequence, 1024))
        };

        // The newest run merges only once it holds the trigger count.
        let mut files: Vec<LogFile> = singles(1..=7).collect();
        assert_eq!(plan_log_merge(&files, 8), None);
        files.push(log_file(8, 8, 1024));
        assert_eq!(plan_log_merge(&files, 8), Some(0..8));

        // A small file left by an earlier merge is part of the run, and large files are not.
        let mut files = vec![log_file(1, 100, LARGE), log_file(101, 150, LARGE - 1)];
        files.extend(singles(151..=157));
        assert_eq!(plan_log_merge(&files, 8), Some(1..9));
        assert_eq!(plan_log_merge(&files[..8], 8), None);

        // A run that a large file closes merges from two files up, oldest run first, and a
        // lone small file before a large one stays.
        let mut files = vec![log_file(1, 1, 1024), log_file(2, 2, LARGE)];
        files.extend(singles(3..=4));
        files.push(log_file(5, 5, LARGE));
        files.extend(singles(6..=9));
        assert_eq!(plan_log_merge(&files, 8), Some(2..4));
        assert_eq!(plan_log_merge(&files, 4), Some(2..4));
        assert_eq!(plan_log_merge(&files[4..], 4), Some(1..5));

        // One merge takes as many files as the byte budget of a pass holds, and a merge needs at
        // least two files.
        let files: Vec<LogFile> = (1..=200).map(|s| log_file(s, s, LARGE - 1)).collect();
        let run = plan_log_merge(&files, 8).expect("run");
        let bytes: u64 = files[run.clone()].iter().map(|file| file.size).sum();
        assert_eq!(run.start, 0);
        assert!(bytes <= LOG_MERGE_PASS_BYTES && bytes + LARGE > LOG_MERGE_PASS_BYTES);
        assert_eq!(plan_log_merge(&files[..2], 1), Some(0..2));
        assert_eq!(plan_log_merge(&files[..1], 1), None);
    }

    #[test]
    fn log_merge_plan_takes_a_backlog_in_bounded_passes() {
        // Four passes' worth of one-row files hold far less than the byte budget of one pass,
        // so the file limit alone ends the first pass.
        let mut files: Vec<LogFile> = (1..=4 * LOG_MERGE_PASS_FILES as u64)
            .map(|sequence| log_file(sequence, sequence, 1250))
            .collect();
        assert_eq!(
            plan_log_merge(&files, DEFAULT_LOG_MERGE_FILES),
            Some(0..LOG_MERGE_PASS_FILES)
        );

        // Drain the backlog the way the merge worker does. Each pass leaves one small output in
        // place of its inputs, and the next plan starts from that output.
        while let Some(run) = plan_log_merge(&files, DEFAULT_LOG_MERGE_FILES) {
            assert!(
                run.len() <= LOG_MERGE_PASS_FILES,
                "one pass must select at most {LOG_MERGE_PASS_FILES} files, selected {}",
                run.len()
            );
            let output = LogFile {
                start: files[run.start].start.clone(),
                end: files[run.end - 1].end.clone(),
                size: files[run.clone()].iter().map(|file| file.size).sum(),
            };
            files.splice(run, [output]);
        }
        assert!(
            files.len() < DEFAULT_LOG_MERGE_FILES,
            "the passes must drain the backlog below the trigger, left {} files",
            files.len()
        );

        // Under a trigger above the pass limit, the newest run merges once it holds
        // `LOG_MERGE_PASS_FILES` files.
        let files: Vec<LogFile> = (1..=LOG_MERGE_PASS_FILES as u64)
            .map(|sequence| log_file(sequence, sequence, 1250))
            .collect();
        assert_eq!(
            plan_log_merge(&files, 2 * LOG_MERGE_PASS_FILES),
            Some(0..LOG_MERGE_PASS_FILES)
        );
        assert_eq!(
            plan_log_merge(&files[..LOG_MERGE_PASS_FILES - 1], 2 * LOG_MERGE_PASS_FILES),
            None
        );
    }

    #[tokio::test]
    async fn log_merge_bounds_live_files_and_keeps_every_row() {
        // A hundred commits try twelve wake-ups at this trigger, with four commits after the last.
        const MERGE_FILES: usize = 8;
        const BATCHES: u64 = 100;
        let dir = tempdir().expect("tempdir");
        {
            let store = open_merging(dir.path(), MERGE_FILES);

            // Commit a hundred one-row groups while the merge worker runs.
            for sequence in 1..=BATCHES {
                assert_eq!(
                    store.put_batch(small_batch(sequence)).await.expect("put"),
                    sequence
                );
            }

            // Each commit group ingested one log file. The settled worker leaves fewer than
            // `MERGE_FILES` in the newest run, and fewer than that arrive after its last wake-up.
            wait_for_log_files(&store, 2 * MERGE_FILES).await;
            assert!(
                log_files(&store).iter().all(|(_, level)| *level == 6),
                "merged log files must stay in the bottom level"
            );
            assert_small_batches(&store, BATCHES).await;
        }

        // The reopened store reads every row, whether or not a merge rewrote its file.
        let store = open_merging(dir.path(), MERGE_FILES);
        assert_small_batches(&store, BATCHES).await;

        // Groups committed after the reopen ingest beside the merged files and merge in turn.
        for sequence in BATCHES + 1..=2 * BATCHES {
            store.put_batch(small_batch(sequence)).await.expect("put");
        }
        wait_for_log_files(&store, 2 * MERGE_FILES).await;
        assert_small_batches(&store, 2 * BATCHES).await;
    }

    #[tokio::test]
    async fn reopen_merges_log_files_left_by_an_earlier_process() {
        const BATCHES: u64 = 40;
        let dir = tempdir().expect("tempdir");
        {
            // The default trigger is far above forty files, so none of them is merged.
            let store = RocksStore::open(dir.path(), None).expect("open db");
            for sequence in 1..=BATCHES {
                store.put_batch(small_batch(sequence)).await.expect("put");
            }
            assert_eq!(log_files(&store).len(), BATCHES as usize);
        }

        // A store reopened with a low trigger merges the leftover files without a new commit.
        let store = open_merging(dir.path(), 8);
        wait_for_log_files(&store, 1).await;
        assert_small_batches(&store, BATCHES).await;
    }

    #[tokio::test]
    async fn reopen_replays_newest_log_row_above_merged_files() {
        const MERGE_FILES: usize = 4;
        const BATCHES: u64 = 16;
        let dir = tempdir().expect("tempdir");
        {
            let store = open_merging(dir.path(), MERGE_FILES);

            // The last of the sixteen commits wakes the worker, so it settles with fewer files
            // than the trigger, and at least one of them holds several sequences.
            for sequence in 1..=BATCHES {
                store.put_batch(small_batch(sequence)).await.expect("put");
            }
            wait_for_log_files(&store, MERGE_FILES - 1).await;

            // Ingest a group's log row without its state rows, as a crash between the two would
            // leave it.
            let group = prepared_write(&store, BATCHES, small_batch(BATCHES + 1));
            ingest_staged_file(&store.db, LOG_CF, &group.log);
            assert_eq!(store.current_sequence(), BATCHES);
        }

        // The reopen replays that group's log row above the merged files.
        let store = open_merging(dir.path(), MERGE_FILES);
        assert_small_batches(&store, BATCHES + 1).await;
    }

    #[tokio::test]
    async fn merged_log_files_keep_payloads_out_of_sentinel_reads() {
        let dir = tempdir().expect("tempdir");
        let store = open_merging(dir.path(), 4);

        // Four large groups merge into one file.
        for tag in 1..=4u8 {
            store.put_batch(large_batch(tag)).await.expect("put");
        }
        wait_for_log_files(&store, 1).await;

        // The merged file starts with sequence 1's head sentinel, directly followed by its
        // multi-megabyte row. If the two shared a block, the lookup would load the row.
        rocksdb::perf::set_perf_stats(rocksdb::perf::PerfStatsLevel::EnableCount);
        let mut perf = rocksdb::perf::PerfContext::default();
        perf.reset();
        assert_eq!(store.oldest_retained_sequence().expect("oldest"), Some(1));
        let read = perf.metric(rocksdb::perf::PerfMetric::BlockReadByte);
        rocksdb::perf::set_perf_stats(rocksdb::perf::PerfStatsLevel::Disable);
        assert!(
            read < 4096,
            "the oldest-retained lookup must not load a payload, but read {read} bytes"
        );

        // Every payload stays readable from the merged file.
        for tag in 1..=4u8 {
            let batch = store
                .get_batch(u64::from(tag))
                .await
                .expect("get batch")
                .expect("batch must be retained");
            assert_eq!(batch_entries(batch), large_batch(tag));
        }
    }

    #[tokio::test]
    async fn newest_write_wins_across_overlapping_state_files() {
        let dir = tempdir().expect("tempdir");
        let key = large_batch(7).remove(3).0;
        let small = |value: &'static [u8]| vec![(key.clone(), Bytes::from_static(value))];
        {
            let store = RocksStore::open(dir.path(), None).expect("open db");

            // The first group's state file holds only that key.
            store.put_batch(small(b"first")).await.expect("put");
            assert_eq!(
                store.get_raw(&key).expect("get").as_deref(),
                Some(&b"first"[..])
            );

            // A file that rewrites that key among many others must land above the first.
            store.put_batch(large_batch(7)).await.expect("put");
            assert_eq!(
                store.get_raw(&key).expect("get").as_deref(),
                Some(&[7u8; 4096][..])
            );

            // A file of that one key, inside the large file's key range, must land above it in
            // turn.
            store.put_batch(small(b"last")).await.expect("put");
            assert_eq!(
                store.get_raw(&key).expect("get").as_deref(),
                Some(&b"last"[..])
            );

            // A group with another key becomes the newest log row, so the reopen replays no
            // write of this key.
            store.put_batch(small_batch(4)).await.expect("put");
        }

        // The newest write survives a reopen.
        let store = RocksStore::open(dir.path(), None).expect("reopen db");
        assert_eq!(store.current_sequence(), 4);
        assert_eq!(
            store.get_raw(&key).expect("get").as_deref(),
            Some(&b"last"[..])
        );
    }

    #[test]
    fn overlapping_state_files_keep_the_newest_write_and_old_snapshots() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let key = large_batch(7).remove(3).0;
        let read = |snapshot: &OwnedRocksSnapshot| {
            snapshot
                .snapshot
                .get(&key)
                .expect("get")
                .map(|value| value[..5].to_vec())
        };

        // The stage workers can stage both groups before either commits. The overwrite commits
        // after the file that covers its key.
        let file = prepared_write(&store, 0, large_batch(7));
        let overwrite =
            prepared_write(&store, 1, vec![(key.clone(), Bytes::from_static(b"newer"))]);
        assert_eq!(commit_and_apply(&store, file), 1);
        let after_file = OwnedRocksSnapshot::capture(store.db.clone(), &store.frontiers);
        assert_eq!(commit_and_apply(&store, overwrite), 2);
        assert_eq!(
            store.get_raw(&key).expect("get").as_deref(),
            Some(&b"newer"[..])
        );

        // Another file that covers the key lands above the overwrite.
        let after_overwrite = OwnedRocksSnapshot::capture(store.db.clone(), &store.frontiers);
        let again = prepared_write(&store, 2, large_batch(7));
        assert_eq!(commit_and_apply(&store, again), 3);
        assert_eq!(
            store.get_raw(&key).expect("get").as_deref(),
            Some(&[7u8; 4096][..])
        );

        // Each snapshot reads the state of the sequence it was taken at, despite the later
        // writes.
        assert_eq!(after_file.sequence_number, 1);
        assert_eq!(read(&after_file), Some(vec![7u8; 5]));
        assert_eq!(after_overwrite.sequence_number, 2);
        assert_eq!(read(&after_overwrite), Some(b"newer".to_vec()));
    }

    #[tokio::test]
    async fn retention_cuts_through_a_merged_log_file() {
        const MERGE_FILES: usize = 4;
        let dir = tempdir().expect("tempdir");

        // Exactly `oldest..=newest` is retained, sentinels included, and nothing of the
        // sequence below it.
        let assert_window = |store: RocksStore, oldest: u64, newest: u64| async move {
            assert_eq!(store.current_sequence(), newest);
            assert_eq!(
                store.oldest_retained_batch().await.expect("oldest"),
                Some(oldest)
            );
            assert!(store.get_batch(oldest - 1).await.expect("get").is_none());
            assert_eq!(log_file_keys_present(&store, oldest - 1), [false; 3]);
            for sequence in oldest..=newest {
                let batch = store
                    .get_batch(sequence)
                    .await
                    .expect("get batch")
                    .unwrap_or_else(|| panic!("batch {sequence} must be retained"));
                assert_eq!(batch_entries(batch), small_batch(sequence));
                assert_eq!(log_file_keys_present(&store, sequence), [true; 3]);
            }
        };
        {
            let store = open_merging(dir.path(), MERGE_FILES);

            // The last of the twelve commits wakes the worker, so it settles with fewer files
            // than the trigger, and one merged file holds sequences 1 through at least 10.
            for sequence in 1..=12 {
                store.put_batch(small_batch(sequence)).await.expect("put");
            }
            wait_for_log_files(&store, MERGE_FILES - 1).await;

            // The cutoff, sequence 8, falls inside that merged file.
            store
                .set_retention(Some(RetentionPolicy::KeepLatest { count: 5 }))
                .expect("set retention");
            assert_window(store.clone(), 8, 12).await;

            // Ingestion, merging and trimming carry on together.
            for sequence in 13..=20 {
                store.put_batch(small_batch(sequence)).await.expect("put");
            }
            wait_for_log_files(&store, MERGE_FILES).await;
            assert_window(store.clone(), 16, 20).await;
        }

        // The window survives a reopen, and log retention leaves every state row in place.
        let store = open_merging(dir.path(), MERGE_FILES);
        assert_window(store.clone(), 16, 20).await;
        for sequence in 1..=20 {
            let (key, value) = small_batch(sequence).remove(0);
            assert_eq!(
                store.get_raw(&key).expect("get").as_deref(),
                Some(&value[..])
            );
        }
    }

    #[tokio::test]
    async fn log_merge_joins_a_file_that_retention_cut_with_its_neighbor() {
        let dir = tempdir().expect("tempdir");

        // The default trigger is far above nine files, so the merge worker stays idle and the
        // test runs each merge itself.
        let store = RocksStore::open(dir.path(), None).expect("open db");
        for sequence in 1..=8 {
            store.put_batch(small_batch(sequence)).await.expect("put");
        }
        assert_eq!(merge_log_run(&store.db, 8), Ok(true));
        store.put_batch(small_batch(9)).await.expect("put");
        assert_eq!(log_files(&store).len(), 2);

        // The cutoff, sequence 5, falls inside the merged file, and its tombstone is still in
        // the memtable when the next merge compacts the run of two.
        store
            .set_retention(Some(RetentionPolicy::KeepLatest { count: 5 }))
            .expect("set retention");

        // One call joins the two files. A run of two that stayed two files would be planned
        // again at every wake-up, ahead of every newer run.
        assert_eq!(merge_log_run(&store.db, 2), Ok(true));
        assert_eq!(log_files(&store).len(), 1);

        // The merged file holds exactly the retained window.
        assert_eq!(
            store.oldest_retained_batch().await.expect("oldest"),
            Some(5)
        );
        assert_eq!(log_file_keys_present(&store, 4), [false; 3]);
        for sequence in 5..=9 {
            let batch = store
                .get_batch(sequence)
                .await
                .expect("get batch")
                .unwrap_or_else(|| panic!("batch {sequence} must be retained"));
            assert_eq!(batch_entries(batch), small_batch(sequence));
            assert_eq!(log_file_keys_present(&store, sequence), [true; 3]);
        }
    }

    #[tokio::test]
    async fn reopen_replays_newest_log_batch_missing_from_state() {
        let dir = tempdir().expect("tempdir");
        {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            store
                .put_batch(vec![(Bytes::from_static(b"k1"), Bytes::from_static(b"v1"))])
                .await
                .expect("put");

            // Seed only sequence 2's durable log row, as a crash between its log ingestion and
            // its state ingestion would leave it. The reopened store must re-derive the frontier
            // from the retained rows alone and replay the row into the state.
            let payload = StreamGetResponse {
                sequence_number: 2,
                entries: vec![
                    Entry {
                        key: b"k2".to_vec(),
                        value: Bytes::from_static(b"v2-stale"),
                        ..Default::default()
                    },
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
            .encode_to_vec();
            seed_log_row(&store, 2, &payload);
        }

        let store = RocksStore::open(dir.path(), None).expect("reopen db");
        assert_eq!(store.current_sequence(), 2);

        // Replay applied the missing rows in arrival order: last writer wins for k2.
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

        // A second reopen replays again (only a log trim advances the floor); idempotent.
        drop(store);
        let store = RocksStore::open(dir.path(), None).expect("reopen db again");
        assert_eq!(store.current_sequence(), 2);
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
        assert_eq!(
            error,
            IngestError::Internal {
                message: "cannot ingest an empty batch".to_string(),
            }
        );
        assert_eq!(store.current_sequence(), 0);
    }

    /// Concurrent puts staged by parallel workers must still commit in
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

    /// The tuned column-family options must reach RocksDB: assert against the
    /// OPTIONS file the database persists on open.
    #[tokio::test]
    async fn column_family_options_apply() {
        let dir = tempdir().expect("tempdir");
        let _store = RocksStore::open(dir.path(), None).expect("open db");

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

        let log = options
            .split("[CFOptions \"log\"]")
            .nth(1)
            .expect("log CF section")
            .split("[TableOptions")
            .next()
            .expect("log CF body");
        assert!(log.contains("compression=kNoCompression"));
    }

    /// Ingested state SSTs serve reads before compaction rewrites them, so they must be
    /// staged with the key filter rather than gain one only once compacted.
    #[test]
    fn staged_state_file_carries_key_filter() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let group = prepared_write(
            &store,
            0,
            vec![(Bytes::from_static(b"a"), Bytes::from_static(b"value"))],
        );
        assert_eq!(commit_and_apply(&store, group), 1);

        // The state CF holds only the one ingested file, since nothing has flushed or compacted.
        let properties = store
            .db
            .property_value_cf(
                store.db.cf_handle(STATE_CF).expect("state CF"),
                "rocksdb.aggregated-table-properties",
            )
            .expect("read table properties")
            .expect("table properties exist");
        let filter_bytes: u64 = properties
            .split("; ")
            .find_map(|property| property.strip_prefix("filter block size="))
            .expect("filter block size property")
            .parse()
            .expect("filter block size is a number");
        assert!(filter_bytes > 0, "{properties}");
    }

    #[tokio::test]
    async fn rocks_store_accepts_custom_config() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(
            dir.path(),
            Some(RocksConfig {
                write_pipeline: RocksWritePipelineConfig {
                    max_commit_batch_bytes: NonZeroUsize::new(1).expect("nonzero"),
                    stage_workers: NonZeroUsize::new(2).expect("nonzero"),
                    max_queued_waves: NonZeroUsize::new(1).expect("nonzero"),
                    ..Default::default()
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

        // A durable log row whose group never published (its state ingestion was in flight at
        // a crash): retention must spare it. It is the repair replay's input at the next open.
        seed_log_row(&store, 1, &encoded_log_entry(1, b"k", b"v"));

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
        seed_log_row(&store, 1, &encoded_log_entry(1, b"k", b"v"));

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

        // A policy removes the state row, and the log row outlives it.
        install(&store, vec![drop_key(b"key")]);
        store.compact_state();
        assert_eq!(store.get_raw(&key).expect("get"), None);

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
