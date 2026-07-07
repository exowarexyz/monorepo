//! Flat-file staged ingest: durable uploads land as checksummed flat files, sequence numbers are
//! assigned by renaming those files, and a WAL-less RocksDB instance is populated asynchronously.
//!
//! Write path:
//! 1. Each `put_batch` call encodes its batch into one checksummed flat file under a temporary
//!    name in `staging/` and fsyncs it. Concurrent uploads write independent files, so the
//!    expensive part of durability runs fully in parallel instead of through a single shared WAL.
//! 2. A sequencer thread drains a wave of completed uploads, assigns each the next contiguous
//!    sequence number by renaming its file to `<seq>.seq` (same directory), makes the whole wave
//!    durable with one directory fsync, and acks every caller. The per-wave commit cost is one
//!    metadata fsync, independent of payload size.
//! 3. Applier threads populate RocksDB (WAL disabled on every write) from a bounded in-memory
//!    queue: the batch data is handed over in memory at sequencing time, so the flat files are
//!    never re-read except during crash recovery. Each apply writes the current-state rows plus
//!    the replay-log row (`log[seq] = GetResponse`); the contiguous applied frontier is recorded
//!    in the `meta` CF and published to readers.
//!
//! Durability and recovery: the flat files are the write-ahead log. RocksDB contents strictly
//! lag them and are made durable by an atomic multi-CF memtable flush every
//! [`FlatFileConfig::flush_gc_bytes`] applied bytes (plus a best-effort flush on clean shutdown);
//! only files at or beneath the flushed applied frontier are deleted. On open, `.tmp` files
//! (never sequenced, never acked) are deleted, `.seq` files beneath the recovered frontier are
//! garbage-collected, and the contiguous run of `.seq` files above it is checksum-verified and
//! reapplied - reapplying is idempotent because batches are applied in sequence order. Sequenced
//! files past a gap were never acked (a wave's renames are fsynced before any of its acks) and
//! are deleted so their numbers can be reassigned.
//!
//! Read visibility: acks happen at sequencing time, before the batch reaches RocksDB. To keep
//! "everything at or beneath a published sequence number is complete and queryable" true, every
//! read gates on the applied frontier: it waits until the frontier reaches the durable (acked)
//! sequence observed at call entry, then serves from RocksDB. `current_sequence` reports the
//! applied frontier. The wait is bounded by the in-memory apply queue
//! ([`FlatFileConfig::max_queued_apply_bytes`]), which backpressures ingest when appliers lag.
//!
//! Semantics vs. the ordered [`crate::RocksStore`]:
//! - No unsequenced junk can appear in query results: data enters RocksDB only after its
//!   sequence number is assigned. A crashed upload leaves at most a dead `.tmp` file, deleted on
//!   the next open. (The unordered store's "keys that are never part of a sequence" caveat does
//!   not exist here.)
//! - With `appliers = 1` batches are applied in exact sequence order, so replaying the log
//!   always reproduces the materialized state. With the default parallel appliers, two racing
//!   `put_batch` calls that write the *same key* may be applied out of order relative to their
//!   sequence numbers (the same caveat as [`crate::UnorderedRocksStore`]).
//! - Prune mutations are ordinary (WAL-backed, unsynced) RocksDB writes; a crash can undo a
//!   recent prune, which a subsequent policy run re-applies.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;

use buffa::Message;
use bytes::Bytes;
use exoware_sdk::log::stream::v1::GetResponse as StreamGetResponse;
use exoware_sdk::prune_policy::{PolicyScope, PrunePolicyDocument, RetainPolicy};
use exoware_server::{Ingest, Log, LogBatch, Prune, Query, QueryExtra, Sequence};
use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, IteratorMode, Options, WriteOptions, DB};
use tokio::sync::{oneshot, watch};
use tracing::{debug, error};

use crate::rocks::{
    collect_key_prune_deletes, flush_all_cfs, sequence_from_log_key, sequence_log_key,
    RocksRangeScanCursor, LOG_CF, META_CF, SEQ_META_KEY,
};
use crate::unordered::{encode_staged_value, staged_value_with_sequence};

const STAGING_DIR: &str = "staging";
const DB_DIR: &str = "db";
const TMP_SUFFIX: &str = ".tmp";
const SEQ_SUFFIX: &str = ".seq";
const DEFAULT_MAX_TICKETS_PER_WAVE: usize = 4096;
const DEFAULT_MAX_QUEUED_APPLY_BYTES: usize = 512 * 1024 * 1024;
const DEFAULT_FLUSH_GC_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_APPLIERS: usize = 4;

/// Options for [`FlatFileRocksStore::open`].
pub struct FlatFileConfig {
    /// Database-wide options for the serving RocksDB instance.
    pub db_options: Options,
    /// Options for the default column family, which stores the current key-value state.
    pub default_cf_options: Options,
    /// Options for the metadata column family.
    pub meta_cf_options: Options,
    /// Options for the replay-log column family.
    pub log_cf_options: Options,
    /// Maximum uploads sequenced (renamed and acked) per directory fsync.
    pub max_tickets_per_wave: NonZeroUsize,
    /// Bound on batch bytes buffered in memory between the sequencer and the appliers. When the
    /// appliers fall behind, the sequencer blocks on handoff, which stalls subsequent waves and
    /// backpressures ingest.
    pub max_queued_apply_bytes: NonZeroUsize,
    /// Applied bytes between explicit atomic flushes. Each flush makes the applied frontier
    /// durable in RocksDB and lets the flat files beneath it be deleted, so this bounds both
    /// recovery replay work and staging-directory disk usage.
    pub flush_gc_bytes: NonZeroUsize,
    /// RocksDB applier threads. With more than one, racing same-key writers may be applied out
    /// of sequence order (see module docs); with exactly one, apply order is strict.
    pub appliers: NonZeroUsize,
}

impl Default for FlatFileConfig {
    fn default() -> Self {
        Self {
            db_options: Options::default(),
            default_cf_options: Options::default(),
            meta_cf_options: Options::default(),
            log_cf_options: Options::default(),
            max_tickets_per_wave: NonZeroUsize::new(DEFAULT_MAX_TICKETS_PER_WAVE)
                .expect("default wave limit must be nonzero"),
            max_queued_apply_bytes: NonZeroUsize::new(DEFAULT_MAX_QUEUED_APPLY_BYTES)
                .expect("default apply queue bound must be nonzero"),
            flush_gc_bytes: NonZeroUsize::new(DEFAULT_FLUSH_GC_BYTES)
                .expect("default flush threshold must be nonzero"),
            appliers: NonZeroUsize::new(DEFAULT_APPLIERS)
                .expect("default applier count must be nonzero"),
        }
    }
}

/// A durable (written and fsynced) flat file waiting for its sequence number.
struct Ticket {
    tmp_path: PathBuf,
    /// Decoded rows, kept so the applier never re-reads the flat file.
    kvs: Vec<(Bytes, Bytes)>,
    /// Staged (sequence-less) replay payload; `None` when the batch logs nothing.
    payload: Option<Arc<Vec<u8>>>,
    /// Approximate in-memory size, charged against the apply queue bound.
    bytes: usize,
    response: oneshot::Sender<Result<u64, String>>,
}

/// A sequenced batch queued for the RocksDB appliers.
struct ApplyTask {
    sequence: u64,
    kvs: Vec<(Bytes, Bytes)>,
    payload: Option<Arc<Vec<u8>>>,
    bytes: usize,
}

/// Apply-side bookkeeping guarded by one mutex; the applied-frontier watch value is only
/// mutated while this lock is held, which keeps frontier advances and marker writes monotone.
struct ApplyProgress {
    /// Completed sequence numbers above the contiguous frontier (out-of-order applier finishes).
    completed: BTreeSet<u64>,
    /// Applied bytes since the last explicit flush; drives flush + file GC.
    bytes_since_flush: u64,
    /// True while some applier thread is running the (slow) flush + GC pass.
    flush_running: bool,
}

struct Shared {
    db: Arc<DB>,
    staging: PathBuf,
    /// Highest acked sequence number (its flat file rename has been fsynced).
    durable: AtomicU64,
    /// Publishes the contiguous applied frontier to gated readers.
    applied_tx: watch::Sender<u64>,
    progress: Mutex<ApplyProgress>,
    /// Bytes handed to appliers but not yet applied, bounded by `max_queued_apply_bytes`.
    queued_bytes: Mutex<usize>,
    queued_bytes_drained: Condvar,
    max_queued_apply_bytes: usize,
    flush_gc_bytes: u64,
    /// Set when an applier hits an unrecoverable error; gated reads fail instead of hanging.
    apply_failed: AtomicBool,
}

/// Owns the ingest threads; dropped once, when the last store clone goes away.
struct Pipeline {
    sender: Mutex<Option<mpsc::Sender<Ticket>>>,
    sequencer: Mutex<Option<thread::JoinHandle<()>>>,
    appliers: Mutex<Vec<thread::JoinHandle<()>>>,
    /// Kept to run a best-effort final flush after the threads drain.
    db: Arc<DB>,
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        if let Ok(mut sender) = self.sender.lock() {
            sender.take();
        }
        if let Ok(mut handle) = self.sequencer.lock() {
            if let Some(handle) = handle.take() {
                let _ = handle.join();
            }
        }
        if let Ok(mut handles) = self.appliers.lock() {
            for handle in handles.drain(..) {
                let _ = handle.join();
            }
        }
        // Make the applied frontier durable so the next open can skip file replay. Failure is
        // fine: un-flushed applies are replayed from their (still present) flat files.
        let _ = flush_all_cfs(&self.db);
    }
}

/// Store that stages uploads in flat files, sequences them by rename, and serves reads from an
/// asynchronously populated, WAL-less RocksDB instance.
///
/// Not wire-compatible with [`crate::RocksStore`] or [`crate::UnorderedRocksStore`] databases:
/// the DB lives under a `db/` subdirectory next to the `staging/` file area.
#[derive(Clone)]
pub struct FlatFileRocksStore {
    db: Arc<DB>,
    shared: Arc<Shared>,
    applied_rx: watch::Receiver<u64>,
    pipeline: Arc<Pipeline>,
    file_counter: Arc<AtomicU64>,
}

impl FlatFileRocksStore {
    /// Open the store, recovering any sequenced-but-unapplied flat files left by a crash.
    pub fn open(path: &Path, config: Option<FlatFileConfig>) -> Result<Self, String> {
        let FlatFileConfig {
            mut db_options,
            default_cf_options,
            meta_cf_options,
            log_cf_options,
            max_tickets_per_wave,
            max_queued_apply_bytes,
            flush_gc_bytes,
            appliers,
        } = config.unwrap_or_default();

        let staging = path.join(STAGING_DIR);
        fs::create_dir_all(&staging).map_err(|e| format!("create staging dir: {e}"))?;

        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);
        // Every write is WAL-less; durability comes from the flat files plus periodic flushes.
        // Flushes must be atomic across CFs or a crash could persist the applied-frontier marker
        // without the data and log rows beneath it.
        db_options.set_atomic_flush(true);

        let db = Arc::new(
            DB::open_cf_descriptors(
                &db_options,
                path.join(DB_DIR),
                vec![
                    ColumnFamilyDescriptor::new(
                        rocksdb::DEFAULT_COLUMN_FAMILY_NAME,
                        default_cf_options,
                    ),
                    ColumnFamilyDescriptor::new(META_CF, meta_cf_options),
                    ColumnFamilyDescriptor::new(LOG_CF, log_cf_options),
                ],
            )
            .map_err(|e| format!("open rocksdb: {e}"))?,
        );

        let meta_cf = db
            .cf_handle(META_CF)
            .expect("meta CF must exist (created on open)");
        let flushed_frontier = match db
            .get_cf(meta_cf, SEQ_META_KEY)
            .map_err(|e| e.to_string())?
        {
            Some(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes.try_into().unwrap()),
            _ => 0,
        };
        let frontier = recover_staging(&db, &staging, flushed_frontier)?;

        let (applied_tx, applied_rx) = watch::channel(frontier);
        let shared = Arc::new(Shared {
            db: db.clone(),
            staging: staging.clone(),
            durable: AtomicU64::new(frontier),
            applied_tx,
            progress: Mutex::new(ApplyProgress {
                completed: BTreeSet::new(),
                bytes_since_flush: 0,
                flush_running: false,
            }),
            queued_bytes: Mutex::new(0),
            queued_bytes_drained: Condvar::new(),
            max_queued_apply_bytes: max_queued_apply_bytes.get(),
            flush_gc_bytes: flush_gc_bytes.get() as u64,
            apply_failed: AtomicBool::new(false),
        });

        let (apply_tx, apply_rx) = mpsc::channel::<ApplyTask>();
        let apply_rx = Arc::new(Mutex::new(apply_rx));
        let applier_handles = (0..appliers.get())
            .map(|i| {
                let shared = shared.clone();
                let apply_rx = apply_rx.clone();
                thread::Builder::new()
                    .name(format!("simulator-flat-applier-{i}"))
                    .spawn(move || run_applier(shared, apply_rx))
                    .map_err(|e| format!("spawn applier: {e}"))
            })
            .collect::<Result<Vec<_>, String>>()?;

        let (ticket_tx, ticket_rx) = mpsc::channel::<Ticket>();
        let sequencer_shared = shared.clone();
        let staging_dir_handle =
            File::open(&staging).map_err(|e| format!("open staging dir: {e}"))?;
        let sequencer_handle = thread::Builder::new()
            .name("simulator-flat-sequencer".to_string())
            .spawn(move || {
                run_sequencer(
                    sequencer_shared,
                    staging_dir_handle,
                    ticket_rx,
                    apply_tx,
                    max_tickets_per_wave.get(),
                )
            })
            .map_err(|e| format!("spawn sequencer: {e}"))?;

        Ok(Self {
            db: db.clone(),
            shared,
            applied_rx,
            pipeline: Arc::new(Pipeline {
                sender: Mutex::new(Some(ticket_tx)),
                sequencer: Mutex::new(Some(sequencer_handle)),
                appliers: Mutex::new(applier_handles),
                db,
            }),
            file_counter: Arc::new(AtomicU64::new(0)),
        })
    }

    fn log_cf(&self) -> &ColumnFamily {
        self.db
            .cf_handle(LOG_CF)
            .expect("log CF must exist (created on open)")
    }

    /// Waits until the applied frontier reaches `target`, so RocksDB can serve everything at or
    /// beneath it. Fails (instead of hanging) if an applier died.
    async fn wait_applied(&self, target: u64) -> Result<(), String> {
        if *self.applied_rx.borrow() >= target {
            return Ok(());
        }
        let mut rx = self.applied_rx.clone();
        let shared = self.shared.clone();
        let applied = rx
            .wait_for(move |applied| {
                *applied >= target || shared.apply_failed.load(Ordering::Relaxed)
            })
            .await
            .map_err(|_| "flatfile applier stopped".to_string())?;
        if *applied >= target {
            Ok(())
        } else {
            Err(
                "flatfile applier failed; reads beyond the applied frontier are unavailable"
                    .to_string(),
            )
        }
    }

    /// Gates a read on everything acked before the call started.
    async fn wait_read_visible(&self) -> Result<(), String> {
        let durable = self.shared.durable.load(Ordering::Acquire);
        self.wait_applied(durable).await
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
        self.db.write(batch)
    }

    /// Deletes replay-log rows below `cutoff_exclusive`.
    fn prune_log(&self, cutoff_exclusive: u64) -> Result<(), String> {
        if cutoff_exclusive == 0 {
            return Ok(());
        }
        let log_cf = self.log_cf();
        let mut batch = rocksdb::WriteBatch::default();
        for item in self.db.iterator_cf(log_cf, IteratorMode::Start) {
            let (key, _) = item.map_err(|e| e.to_string())?;
            if key.as_ref() >= sequence_log_key(cutoff_exclusive).as_slice() {
                break;
            }
            batch.delete_cf(log_cf, key.as_ref());
        }
        self.db.write(batch).map_err(|e| e.to_string())
    }

    fn apply_prune_policies_inner(&self, document: PrunePolicyDocument) -> Result<(), String> {
        for policy in &document.policies {
            match &policy.scope {
                PolicyScope::Keys(scope) => {
                    let deletes =
                        collect_key_prune_deletes(self.db.clone(), scope, &policy.retain)?;
                    self.delete_keys(&deletes).map_err(|e| e.to_string())?;
                }
                PolicyScope::Sequence => {
                    self.apply_sequence_prune_policy(&policy.retain)?;
                }
            }
        }
        Ok(())
    }

    /// Computes the replay-log cutoff for a sequence policy and prunes only log rows.
    fn apply_sequence_prune_policy(&self, retain: &RetainPolicy) -> Result<(), String> {
        let current = *self.applied_rx.borrow();
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

/// Boot-time staging recovery. Deletes `.tmp` files and already-applied `.seq` files, reapplies
/// the contiguous run of `.seq` files above the flushed frontier (checksum-verified, in order),
/// and deletes sequenced files past a gap (never acked, so their numbers will be reassigned).
/// Returns the recovered applied frontier.
fn recover_staging(db: &DB, staging: &Path, flushed_frontier: u64) -> Result<u64, String> {
    let mut sequenced = BTreeMap::new();
    let entries = fs::read_dir(staging).map_err(|e| format!("read staging dir: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read staging dir: {e}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.ends_with(TMP_SUFFIX) {
            fs::remove_file(entry.path()).map_err(|e| format!("delete tmp file: {e}"))?;
        } else if let Some(stem) = name.strip_suffix(SEQ_SUFFIX) {
            let seq = stem
                .parse::<u64>()
                .map_err(|_| format!("unparseable sequenced file name: {name}"))?;
            if seq <= flushed_frontier {
                fs::remove_file(entry.path()).map_err(|e| format!("delete applied file: {e}"))?;
            } else {
                sequenced.insert(seq, entry.path());
            }
        }
    }

    let mut frontier = flushed_frontier;
    while let Some(path) = sequenced.remove(&(frontier + 1)) {
        frontier += 1;
        replay_file(db, frontier, &path)?;
    }
    write_applied_marker(db, frontier)?;
    // Anything left is past a gap: its wave's directory fsync never completed, so no caller was
    // acked at or beyond it. Delete so the numbers can be reassigned.
    for (_, path) in sequenced {
        fs::remove_file(&path).map_err(|e| format!("delete unacked sequenced file: {e}"))?;
    }
    Ok(frontier)
}

/// Reapplies one sequenced flat file: verifies its checksum, decodes the staged payload, and
/// applies it exactly as the in-memory path would have.
fn replay_file(db: &DB, sequence: u64, path: &Path) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|e| format!("read sequenced file {path:?}: {e}"))?;
    if bytes.len() < 4 {
        return Err(format!("sequenced file {path:?} is truncated"));
    }
    let (payload, crc_bytes) = bytes.split_at(bytes.len() - 4);
    let expected = u32::from_le_bytes(crc_bytes.try_into().unwrap());
    if crc32fast::hash(payload) != expected {
        return Err(format!(
            "sequenced file {path:?} failed checksum verification"
        ));
    }
    let kvs = if payload.is_empty() {
        Vec::new()
    } else {
        StreamGetResponse::decode_from_slice(payload)
            .map_err(|e| format!("decode sequenced file {path:?}: {e}"))?
            .entries
            .into_iter()
            .map(|entry| (Bytes::from(entry.key), entry.value))
            .collect()
    };
    let payload = (!payload.is_empty()).then(|| Arc::new(payload.to_vec()));
    write_apply_batch(db, sequence, &kvs, payload.as_deref())
}

/// Writes one batch's current-state rows and replay-log row, WAL-less.
fn write_apply_batch(
    db: &DB,
    sequence: u64,
    kvs: &[(Bytes, Bytes)],
    payload: Option<&Vec<u8>>,
) -> Result<(), String> {
    let mut batch = rocksdb::WriteBatch::default();
    for (k, v) in kvs {
        batch.put(k.as_ref(), v.as_ref());
    }
    if let Some(payload) = payload {
        let log_cf = db
            .cf_handle(LOG_CF)
            .expect("log CF must exist (created on open)");
        batch.put_cf(
            log_cf,
            sequence_log_key(sequence),
            staged_value_with_sequence(sequence, payload),
        );
    }
    let mut options = WriteOptions::default();
    options.disable_wal(true);
    db.write_opt(batch, &options).map_err(|e| e.to_string())
}

/// Records the contiguous applied frontier in the meta CF (WAL-less). Callers must keep marker
/// writes monotone; with atomic flushes this guarantees a recovered marker never exceeds the
/// recovered data.
fn write_applied_marker(db: &DB, frontier: u64) -> Result<(), String> {
    let meta_cf = db
        .cf_handle(META_CF)
        .expect("meta CF must exist (created on open)");
    let mut batch = rocksdb::WriteBatch::default();
    batch.put_cf(meta_cf, SEQ_META_KEY, frontier.to_le_bytes());
    let mut options = WriteOptions::default();
    options.disable_wal(true);
    db.write_opt(batch, &options).map_err(|e| e.to_string())
}

/// Drains waves of durable uploads, assigns contiguous sequence numbers by rename, commits each
/// wave with one directory fsync, acks the callers, and hands the batches to the appliers.
fn run_sequencer(
    shared: Arc<Shared>,
    staging_dir: File,
    receiver: mpsc::Receiver<Ticket>,
    applier: mpsc::Sender<ApplyTask>,
    max_tickets_per_wave: usize,
) {
    let mut next = shared.durable.load(Ordering::Acquire);
    while let Ok(first) = receiver.recv() {
        let mut wave = vec![first];
        while wave.len() < max_tickets_per_wave {
            match receiver.try_recv() {
                Ok(ticket) => wave.push(ticket),
                Err(_) => break,
            }
        }

        // Rename every file in the wave, then make all the renames durable with one directory
        // fsync before acking anyone. On failure the whole wave is failed and `next` is left
        // unchanged: leftover renamed files are either overwritten when their numbers are
        // reassigned or discarded as past-a-gap during recovery (no caller was acked).
        let mut renamed = Vec::with_capacity(wave.len());
        let mut failure: Option<String> = None;
        let mut failed = Vec::new();
        for ticket in wave {
            if failure.is_some() {
                failed.push(ticket);
                continue;
            }
            let seq = next + renamed.len() as u64 + 1;
            let seq_path = shared.staging.join(format!("{seq:020}{SEQ_SUFFIX}"));
            match fs::rename(&ticket.tmp_path, &seq_path) {
                Ok(()) => renamed.push((seq, ticket)),
                Err(e) => {
                    failure = Some(format!("rename staged file: {e}"));
                    failed.push(ticket);
                }
            }
        }
        if failure.is_none() {
            if let Err(e) = staging_dir.sync_all() {
                failure = Some(format!("fsync staging dir: {e}"));
            }
        }
        if let Some(failure) = failure {
            for (_, ticket) in renamed {
                let _ = ticket.response.send(Err(failure.clone()));
            }
            for ticket in failed {
                let _ = ticket.response.send(Err(failure.clone()));
            }
            continue;
        }

        next += renamed.len() as u64;
        // Publish durability before the acks so a reader racing an acked caller always gates on
        // a frontier at least as high as that caller's sequence.
        shared.durable.store(next, Ordering::Release);
        debug!(requests = renamed.len(), sequence = next, "sequenced wave");
        for (sequence, ticket) in renamed {
            let Ticket {
                kvs,
                payload,
                bytes,
                response,
                ..
            } = ticket;
            let _ = response.send(Ok(sequence));
            // Bounded in-memory handoff: block (stalling subsequent waves, i.e. backpressuring
            // ingest) while the appliers have too many bytes outstanding.
            {
                let mut queued = shared
                    .queued_bytes
                    .lock()
                    .expect("apply queue lock poisoned");
                while *queued > shared.max_queued_apply_bytes {
                    queued = shared
                        .queued_bytes_drained
                        .wait(queued)
                        .expect("apply queue lock poisoned");
                }
                *queued += bytes;
            }
            // If the appliers are gone the batch is still acked and durable in its flat file;
            // the next open replays it.
            if applier
                .send(ApplyTask {
                    sequence,
                    kvs,
                    payload,
                    bytes,
                })
                .is_err()
            {
                return;
            }
        }
    }
}

/// Applies sequenced batches to RocksDB and advances the contiguous applied frontier. On an
/// unrecoverable error the thread marks the store failed and exits; acked data stays safe in the
/// flat files and is replayed on the next open.
fn run_applier(shared: Arc<Shared>, receiver: Arc<Mutex<mpsc::Receiver<ApplyTask>>>) {
    loop {
        let received = receiver
            .lock()
            .expect("apply receiver lock poisoned")
            .recv();
        let Ok(task) = received else {
            return;
        };
        let result = write_apply_batch(
            &shared.db,
            task.sequence,
            &task.kvs,
            task.payload.as_deref(),
        )
        .and_then(|()| {
            release_queued_bytes(&shared, task.bytes);
            complete_apply(&shared, task.sequence, task.bytes as u64)
        });
        if let Err(e) = result {
            error!(sequence = task.sequence, error = %e, "flatfile apply failed");
            shared.apply_failed.store(true, Ordering::Relaxed);
            // Wake gated readers so they observe the failure instead of waiting forever.
            let current = *shared.applied_tx.borrow();
            shared.applied_tx.send_replace(current);
            return;
        }
    }
}

fn release_queued_bytes(shared: &Shared, bytes: usize) {
    let mut queued = shared
        .queued_bytes
        .lock()
        .expect("apply queue lock poisoned");
    *queued = queued.saturating_sub(bytes);
    shared.queued_bytes_drained.notify_all();
}

/// Marks one sequence applied, advances the contiguous frontier (persisting the marker and
/// waking gated readers), and periodically runs the flush + file GC pass.
fn complete_apply(shared: &Shared, sequence: u64, bytes: u64) -> Result<(), String> {
    let mut gc_cutoff = None;
    {
        let mut progress = shared
            .progress
            .lock()
            .expect("apply progress lock poisoned");
        progress.completed.insert(sequence);
        let mut frontier = *shared.applied_tx.borrow();
        let mut advanced = false;
        while progress.completed.remove(&(frontier + 1)) {
            frontier += 1;
            advanced = true;
        }
        progress.bytes_since_flush += bytes;
        if advanced {
            // Persist and publish under the lock so marker writes stay monotone.
            write_applied_marker(&shared.db, frontier)?;
            shared.applied_tx.send_replace(frontier);
        }
        if progress.bytes_since_flush >= shared.flush_gc_bytes && !progress.flush_running {
            progress.flush_running = true;
            progress.bytes_since_flush = 0;
            gc_cutoff = Some(*shared.applied_tx.borrow());
        }
    }
    if let Some(cutoff) = gc_cutoff {
        // The atomic flush persists a marker >= cutoff, so files at or beneath it are no longer
        // needed for recovery. Other appliers keep applying while this runs.
        let result = flush_all_cfs(&shared.db);
        if result.is_ok() {
            gc_staging(&shared.staging, cutoff);
        }
        shared
            .progress
            .lock()
            .expect("apply progress lock poisoned")
            .flush_running = false;
        result?;
    }
    Ok(())
}

/// Deletes sequenced flat files at or beneath the flushed frontier. Best-effort: anything left
/// behind is cleaned up by the next open.
fn gc_staging(staging: &Path, cutoff: u64) {
    let Ok(entries) = fs::read_dir(staging) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(stem) = name.strip_suffix(SEQ_SUFFIX) {
            if let Ok(seq) = stem.parse::<u64>() {
                if seq <= cutoff {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}

impl Sequence for FlatFileRocksStore {
    fn current_sequence(&self) -> u64 {
        *self.applied_rx.borrow()
    }
}

impl Ingest for FlatFileRocksStore {
    async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, String> {
        // Phase 1 (parallel across callers): encode the batch into one checksummed flat file
        // under a temporary name and fsync it. This is the only payload-sized durability cost.
        let id = self.file_counter.fetch_add(1, Ordering::Relaxed);
        let tmp_path = self.shared.staging.join(format!("{id:020}{TMP_SUFFIX}"));
        let write_path = tmp_path.clone();
        let (kvs, payload, bytes) = tokio::task::spawn_blocking(move || {
            let payload = encode_staged_value(&kvs);
            let payload_bytes = payload.as_deref().unwrap_or(&[]);
            let crc = crc32fast::hash(payload_bytes);
            let mut file = File::create(&write_path).map_err(|e| e.to_string())?;
            file.write_all(payload_bytes).map_err(|e| e.to_string())?;
            file.write_all(&crc.to_le_bytes())
                .map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            let bytes = payload_bytes.len() + 64;
            Ok::<_, String>((kvs, payload.map(Arc::new), bytes))
        })
        .await
        .map_err(|e| format!("flatfile write task failed: {e}"))??;

        // Phase 2: wait for the sequencer to rename the file to its sequence number and fsync
        // the directory. The RocksDB apply happens after the ack, off the latency path.
        let (response, result) = oneshot::channel();
        self.pipeline
            .sender
            .lock()
            .map_err(|e| format!("flatfile sequencer lock poisoned: {e}"))?
            .as_ref()
            .ok_or_else(|| "flatfile sequencer stopped".to_string())?
            .send(Ticket {
                tmp_path,
                kvs,
                payload,
                bytes,
                response,
            })
            .map_err(|_| "flatfile sequencer stopped".to_string())?;
        result
            .await
            .map_err(|_| "flatfile sequencer stopped before sequencing write".to_string())?
    }
}

impl Query for FlatFileRocksStore {
    type RangeScan = RocksRangeScanCursor;

    async fn get(&self, key: Bytes) -> Result<(Option<Bytes>, QueryExtra), String> {
        self.wait_read_visible().await?;
        self.db
            .get(&key)
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
        self.wait_read_visible().await?;
        Ok(RocksRangeScanCursor::new(
            self.db.clone(),
            start,
            end,
            limit,
            forward,
        ))
    }

    async fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> Result<(Vec<(Bytes, Option<Bytes>)>, QueryExtra), String> {
        self.wait_read_visible().await?;
        let results = self.db.multi_get(keys.iter().map(|key| key.as_ref()));
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

impl Prune for FlatFileRocksStore {
    async fn apply_prune_policies(&self, document: PrunePolicyDocument) -> Result<(), String> {
        self.wait_read_visible().await?;
        self.apply_prune_policies_inner(document)
    }
}

impl Log for FlatFileRocksStore {
    async fn get_batch(&self, sequence_number: u64) -> Result<Option<LogBatch>, String> {
        // Only wait for batches that are known durable; anything beyond the acked frontier is
        // legitimately not-found.
        let durable = self.shared.durable.load(Ordering::Acquire);
        self.wait_applied(sequence_number.min(durable)).await?;
        let value = match self
            .db
            .get_cf(self.log_cf(), sequence_log_key(sequence_number))
            .map_err(|e| e.to_string())?
        {
            Some(value) => value,
            None => return Ok(None),
        };
        Ok(Some(LogBatch::from_response_bytes(sequence_number, value)))
    }

    async fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
        self.wait_read_visible().await?;
        let mut it = self.db.iterator_cf(self.log_cf(), IteratorMode::Start);
        match it.next() {
            None => Ok(None),
            Some(item) => {
                let (key, _) = item.map_err(|e| e.to_string())?;
                sequence_from_log_key(key.as_ref()).map(Some)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use tempfile::tempdir;

    fn batch_entries(batch: LogBatch) -> Vec<(Bytes, Bytes)> {
        batch
            .decode_response()
            .expect("decode batch response")
            .entries
            .into_iter()
            .map(|entry| (Bytes::from(entry.key), entry.value))
            .collect()
    }

    /// Writes a sequenced flat file the way a crashed process would have left it.
    fn write_sequenced_file(staging: &Path, sequence: u64, kvs: &[(Bytes, Bytes)]) {
        let payload = encode_staged_value(kvs).unwrap_or_default();
        let crc = crc32fast::hash(&payload);
        let mut bytes = payload;
        bytes.extend_from_slice(&crc.to_le_bytes());
        fs::write(staging.join(format!("{sequence:020}{SEQ_SUFFIX}")), bytes)
            .expect("write sequenced file");
    }

    #[tokio::test]
    async fn put_batch_assigns_monotonic_sequences_and_logs_batches() {
        let dir = tempdir().expect("tempdir");
        let store = FlatFileRocksStore::open(dir.path(), None).expect("open store");

        let s1 = store
            .put_batch(vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))])
            .await
            .expect("put");
        let s2 = store
            .put_batch(vec![(Bytes::from_static(b"b"), Bytes::from_static(b"2"))])
            .await
            .expect("put");
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(
            store.get(Bytes::from_static(b"a")).await.expect("get").0,
            Some(Bytes::from_static(b"1"))
        );
        assert_eq!(
            batch_entries(store.get_batch(1).await.expect("get").expect("retained")),
            vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))]
        );
        assert_eq!(
            batch_entries(store.get_batch(2).await.expect("get").expect("retained")),
            vec![(Bytes::from_static(b"b"), Bytes::from_static(b"2"))]
        );
        assert_eq!(
            store.oldest_retained_batch().await.expect("oldest"),
            Some(1)
        );
        // Reads gated on the acked frontier, so by now it must be applied and published.
        assert_eq!(store.current_sequence(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_puts_keep_all_rows_in_sequence_logs() {
        let dir = tempdir().expect("tempdir");
        let store = FlatFileRocksStore::open(dir.path(), None).expect("open store");
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

        let mut sequences = BTreeSet::new();
        for put in puts {
            sequences.insert(put.await.expect("put task"));
        }
        assert_eq!(sequences, (1..=32).collect::<BTreeSet<_>>());

        let mut logged_keys = BTreeSet::new();
        for sequence in 1..=32 {
            let batch = store
                .get_batch(sequence)
                .await
                .expect("get batch")
                .expect("batch retained");
            for (key, value) in batch_entries(batch) {
                assert_eq!(value.as_ref(), &[key[0] + 1]);
                assert_eq!(
                    store.get(key.clone()).await.expect("get").0,
                    Some(value.clone())
                );
                logged_keys.insert(key[0]);
            }
        }
        assert_eq!(logged_keys, (0u8..32).collect::<BTreeSet<_>>());
        assert_eq!(store.current_sequence(), 32);
    }

    #[tokio::test]
    async fn empty_batches_take_a_sequence_number_without_a_log_row() {
        let dir = tempdir().expect("tempdir");
        let store = FlatFileRocksStore::open(dir.path(), None).expect("open store");
        let s1 = store.put_batch(Vec::new()).await.expect("put");
        assert_eq!(s1, 1);
        assert!(store.get_batch(1).await.expect("get").is_none());
        let s2 = store
            .put_batch(vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))])
            .await
            .expect("put");
        assert_eq!(s2, 2);
        assert!(store.get_batch(2).await.expect("get").is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn state_persists_across_reopen() {
        let dir = tempdir().expect("tempdir");
        {
            let store = FlatFileRocksStore::open(dir.path(), None).expect("open store");
            let mut puts = Vec::new();
            for i in 0u8..16 {
                let store = store.clone();
                puts.push(tokio::spawn(async move {
                    store
                        .put_batch(vec![(Bytes::from(vec![i]), Bytes::from(vec![i + 1]))])
                        .await
                        .expect("put")
                }));
            }
            let mut sequences = BTreeSet::new();
            for put in puts {
                sequences.insert(put.await.expect("put task"));
            }
            assert_eq!(sequences, (1..=16).collect::<BTreeSet<_>>());
        }

        let reopened = FlatFileRocksStore::open(dir.path(), None).expect("reopen store");
        assert_eq!(reopened.current_sequence(), 16);
        let mut logged_keys = BTreeSet::new();
        for sequence in 1..=16 {
            let batch = reopened
                .get_batch(sequence)
                .await
                .expect("get batch")
                .expect("batch retained");
            for (key, value) in batch_entries(batch) {
                assert_eq!(value.as_ref(), &[key[0] + 1]);
                assert_eq!(
                    reopened.get(key.clone()).await.expect("get").0,
                    Some(value.clone())
                );
                logged_keys.insert(key[0]);
            }
        }
        assert_eq!(logged_keys, (0u8..16).collect::<BTreeSet<_>>());
        let s17 = reopened
            .put_batch(vec![(Bytes::from_static(b"z"), Bytes::from_static(b"9"))])
            .await
            .expect("put");
        assert_eq!(s17, 17);
    }

    #[tokio::test]
    async fn open_replays_staged_files_and_discards_junk() {
        let dir = tempdir().expect("tempdir");
        {
            let store = FlatFileRocksStore::open(dir.path(), None).expect("open store");
            store
                .put_batch(vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))])
                .await
                .expect("put");
            store
                .put_batch(vec![(Bytes::from_static(b"b"), Bytes::from_static(b"2"))])
                .await
                .expect("put");
        }
        let staging = dir.path().join(STAGING_DIR);
        // Model a crash: sequence 3 was renamed + fsynced (acked) but never applied; sequence 5
        // is past a gap (its wave's dir fsync never completed, nobody was acked); one upload
        // never got sequenced at all.
        write_sequenced_file(
            &staging,
            3,
            &[(Bytes::from_static(b"c"), Bytes::from_static(b"3"))],
        );
        write_sequenced_file(
            &staging,
            5,
            &[(Bytes::from_static(b"x"), Bytes::from_static(b"x"))],
        );
        fs::write(staging.join(format!("{:020}{TMP_SUFFIX}", 99)), b"junk").expect("write tmp");

        let reopened = FlatFileRocksStore::open(dir.path(), None).expect("reopen store");
        assert_eq!(reopened.current_sequence(), 3);
        assert_eq!(
            reopened.get(Bytes::from_static(b"c")).await.expect("get").0,
            Some(Bytes::from_static(b"3"))
        );
        assert_eq!(
            batch_entries(reopened.get_batch(3).await.expect("get").expect("retained")),
            vec![(Bytes::from_static(b"c"), Bytes::from_static(b"3"))]
        );
        // The gap file and the unsequenced upload are gone; their data never becomes visible.
        assert_eq!(
            reopened.get(Bytes::from_static(b"x")).await.expect("get").0,
            None
        );
        assert!(!staging.join(format!("{:020}{SEQ_SUFFIX}", 5)).exists());
        assert!(!staging.join(format!("{:020}{TMP_SUFFIX}", 99)).exists());
        // Sequence 4 (the gap) and 5 are reassigned to new writes.
        let s4 = reopened
            .put_batch(vec![(Bytes::from_static(b"d"), Bytes::from_static(b"4"))])
            .await
            .expect("put");
        assert_eq!(s4, 4);
    }

    #[tokio::test]
    async fn open_rejects_corrupt_sequenced_files() {
        let dir = tempdir().expect("tempdir");
        {
            let store = FlatFileRocksStore::open(dir.path(), None).expect("open store");
            store
                .put_batch(vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))])
                .await
                .expect("put");
        }
        let staging = dir.path().join(STAGING_DIR);
        let payload = encode_staged_value(&[(Bytes::from_static(b"c"), Bytes::from_static(b"3"))])
            .expect("payload");
        let mut bytes = payload;
        bytes.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());
        fs::write(staging.join(format!("{:020}{SEQ_SUFFIX}", 2)), bytes).expect("write corrupt");

        let error = match FlatFileRocksStore::open(dir.path(), None) {
            Ok(_) => panic!("open must fail on a corrupt sequenced file"),
            Err(error) => error,
        };
        assert!(error.contains("checksum"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn sequence_prune_removes_log_rows_but_not_state() {
        let dir = tempdir().expect("tempdir");
        let store = FlatFileRocksStore::open(dir.path(), None).expect("open store");
        for i in 0u8..3 {
            store
                .put_batch(vec![(Bytes::from(vec![i]), Bytes::from(vec![i]))])
                .await
                .expect("put");
        }

        store.prune_log(3).expect("prune");

        assert!(store.get_batch(1).await.expect("get").is_none());
        assert!(store.get_batch(2).await.expect("get").is_none());
        assert!(store.get_batch(3).await.expect("get").is_some());
        assert_eq!(
            store.oldest_retained_batch().await.expect("oldest"),
            Some(3)
        );
        assert_eq!(
            store.get(Bytes::from(vec![0u8])).await.expect("get").0,
            Some(Bytes::from(vec![0u8]))
        );
    }
}
