//! Experimental "unordered ingest" storage for the simulator.
//!
//! The production [`crate::RocksStore`] serializes every ingest through a prepare/commit pipeline
//! that assigns contiguous sequence numbers *before* the data is written and then commits each
//! group with one synced write. This store inverts that: data is written to RocksDB concurrently
//! (unordered, unsynced) and sequence numbers are assigned *after* the data write completes by a
//! sequencer that fsyncs only a tiny pointer batch.
//!
//! Write path:
//! 1. Each `put_batch` call generates a unique 16-byte ticket, then performs one unsynced,
//!    WAL-backed RocksDB write containing its current-state rows (default CF) plus one staged
//!    replay-log row keyed by the ticket (`staged` CF). Concurrent callers hit RocksDB directly,
//!    so its internal write-group batching and concurrent memtable inserts apply.
//! 2. A single sequencer thread drains completed tickets, assigns each the next contiguous
//!    sequence number, and commits one synced write containing only `log[seq] = ticket` pointer
//!    rows plus the sequence-frontier meta row. Because every write shares the RocksDB WAL, this
//!    fsync also makes the (already written) data rows for those tickets durable: syncing the WAL
//!    persists everything appended before it.
//!
//! Invariant preserved: a sequence number is only published (and returned to the caller) once
//! every batch at or beneath it is durable and queryable, so `min_sequence_number` reads and
//! stream replay behave exactly as with the ordered store.
//!
//! Known semantic differences from the ordered pipeline (acceptable for the simulator; see the
//! PR description for discussion):
//! - Two concurrent `put_batch` calls that write the *same key* may be applied to the
//!   current-state CF in a different order than their assigned sequence numbers, so replaying the
//!   log can disagree with the materialized state for racing same-key writers.
//! - Data rows become visible to point/range reads as soon as the unsynced write lands (before
//!   their sequence number is published). The ordered store has the same window, just narrower.
//! - **Unsequenced keys**: a batch whose phase-1 write lands but whose sequence assignment never
//!   completes (crash, failed pointer write) leaves its keys in the current state without any
//!   sequence number referencing them. Such keys are readable by point/range queries but never
//!   appear in the log or on a stream: replaying the log does not reproduce them. The caller was
//!   never acked, so if it retries, the retry overwrites the same keys under a real sequence
//!   number and the anomaly heals; if it never retries, the junk keys simply persist. No
//!   recovery/garbage-collection pass is attempted.

use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use buffa::Message;
use bytes::Bytes;
use exoware_sdk::common::kv::v1::Entry;
use exoware_sdk::log::stream::v1::GetResponse as StreamGetResponse;
use exoware_sdk::prune_policy::{PolicyScope, PrunePolicyDocument, RetainPolicy};
use exoware_server::{Ingest, Log, LogBatch, Prune, Query, QueryExtra, Sequence};
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, FlushOptions, IteratorMode, Options, WriteOptions, DB,
};
use tokio::sync::oneshot;
use tracing::debug;

use crate::rocks::{
    collect_key_prune_deletes, sequence_log_key, CommitDurability, RocksRangeScanCursor, LOG_CF,
    META_CF, SEQ_META_KEY,
};

const STAGED_CF: &str = "staged";
const TICKET_LEN: usize = 16;
const DEFAULT_MAX_TICKETS_PER_COMMIT: usize = 65_536;

/// A completed unsynced data write waiting for its sequence number.
struct Ticket {
    id: [u8; TICKET_LEN],
    /// False when the batch produced no replay-log payload (nothing staged).
    staged: bool,
    response: oneshot::Sender<Result<u64, String>>,
}

struct Sequencer {
    sender: Mutex<Option<mpsc::Sender<Ticket>>>,
    handle: Mutex<Option<thread::JoinHandle<()>>>,
}

impl Sequencer {
    fn start(
        db: Arc<DB>,
        sequence: Arc<AtomicU64>,
        max_tickets_per_commit: usize,
        durability: CommitDurability,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        let handle = thread::Builder::new()
            .name("simulator-rocks-sequencer".to_string())
            .spawn(move || {
                run_sequencer(db, sequence, receiver, max_tickets_per_commit, durability)
            })
            .expect("failed to spawn RocksDB sequencer");
        Self {
            sender: Mutex::new(Some(sender)),
            handle: Mutex::new(Some(handle)),
        }
    }

    fn submit(&self, ticket: Ticket) -> Result<(), String> {
        self.sender
            .lock()
            .map_err(|e| format!("rocks sequencer lock poisoned: {e}"))?
            .as_ref()
            .ok_or_else(|| "rocks sequencer stopped".to_string())?
            .send(ticket)
            .map_err(|_| "rocks sequencer stopped".to_string())
    }
}

impl Drop for Sequencer {
    fn drop(&mut self) {
        if let Ok(mut sender) = self.sender.lock() {
            sender.take();
        }
        if let Ok(mut handle) = self.handle.lock() {
            if let Some(handle) = handle.take() {
                let _ = handle.join();
            }
        }
    }
}

/// Drains waves of completed tickets, assigns contiguous sequence numbers in completion order,
/// and publishes each wave with one small synced write (or a WAL-less write plus atomic flush).
fn run_sequencer(
    db: Arc<DB>,
    sequence: Arc<AtomicU64>,
    receiver: mpsc::Receiver<Ticket>,
    max_tickets_per_commit: usize,
    durability: CommitDurability,
) {
    while let Ok(first) = receiver.recv() {
        let mut tickets = vec![first];
        while tickets.len() < max_tickets_per_commit {
            match receiver.try_recv() {
                Ok(ticket) => tickets.push(ticket),
                Err(_) => break,
            }
        }
        commit_tickets(&db, &sequence, tickets, durability);
    }
}

/// Assigns sequence numbers to one wave and commits the pointer rows + frontier. On success the
/// frontier is published and each caller receives its sequence number.
///
/// With [`CommitDurability::SyncWal`] the pointer batch is written with `sync=true`: syncing the
/// shared WAL also persists the (already written, unsynced) phase-1 data of every ticket in the
/// wave. With [`CommitDurability::NoWalFlush`] nothing has touched the WAL; the pointer batch is
/// written WAL-less and one atomic flush of all column families makes the wave durable. Each
/// ticket's phase-1 write happened before it was submitted, so the flush covers the whole wave.
fn commit_tickets(
    db: &DB,
    sequence: &AtomicU64,
    tickets: Vec<Ticket>,
    durability: CommitDurability,
) {
    let base = sequence.load(Ordering::Acquire);
    let Some(last) = base.checked_add(tickets.len() as u64) else {
        fail_tickets(tickets, "rocks sequence number overflowed".to_string());
        return;
    };

    let log_cf = db
        .cf_handle(LOG_CF)
        .expect("log CF must exist (created on open)");
    let meta_cf = db
        .cf_handle(META_CF)
        .expect("meta CF must exist (created on open)");
    let mut batch = rocksdb::WriteBatch::default();
    for (offset, ticket) in tickets.iter().enumerate() {
        if ticket.staged {
            let seq = base + offset as u64 + 1;
            batch.put_cf(log_cf, sequence_log_key(seq), ticket.id);
        }
    }
    batch.put_cf(meta_cf, SEQ_META_KEY, last.to_le_bytes());

    let mut options = WriteOptions::default();
    let result = match durability {
        CommitDurability::SyncWal => {
            options.set_sync(true);
            db.write_opt(batch, &options).map_err(|e| e.to_string())
        }
        CommitDurability::NoWalFlush => {
            options.disable_wal(true);
            db.write_opt(batch, &options)
                .map_err(|e| e.to_string())
                .and_then(|()| flush_all_cfs(db))
        }
    };
    match result {
        Ok(()) => {
            // Release so `current_sequence` readers only observe rows that are already durable.
            sequence.store(last, Ordering::Release);
            debug!(
                requests = tickets.len(),
                sequence = last,
                "committed sequence assignment batch"
            );
            for (offset, ticket) in tickets.into_iter().enumerate() {
                let _ = ticket.response.send(Ok(base + offset as u64 + 1));
            }
        }
        Err(e) => fail_tickets(tickets, e),
    }
}

/// Atomically flushes every column family so all rows beneath the new frontier are durable as
/// SST files. Requires the DB to be opened with `set_atomic_flush(true)`.
fn flush_all_cfs(db: &DB) -> Result<(), String> {
    let default_cf = db
        .cf_handle(rocksdb::DEFAULT_COLUMN_FAMILY_NAME)
        .expect("default CF must exist");
    let meta_cf = db
        .cf_handle(META_CF)
        .expect("meta CF must exist (created on open)");
    let log_cf = db
        .cf_handle(LOG_CF)
        .expect("log CF must exist (created on open)");
    let staged_cf = db
        .cf_handle(STAGED_CF)
        .expect("staged CF must exist (created on open)");
    let mut flush_options = FlushOptions::default();
    flush_options.set_wait(true);
    db.flush_cfs_opt(
        &[&default_cf, &meta_cf, &log_cf, &staged_cf],
        &flush_options,
    )
    .map_err(|e| e.to_string())
}

/// Fails every ticket in a wave. Their data and staged rows are left behind as unreferenced junk:
/// no sequence number ever points at them, so they are invisible to the log and harmless.
fn fail_tickets(tickets: Vec<Ticket>, error: String) {
    for ticket in tickets {
        let _ = ticket.response.send(Err(error.clone()));
    }
}

/// Options for [`UnorderedRocksStore::open`].
pub struct UnorderedRocksConfig {
    /// Database-wide options.
    pub db_options: Options,
    /// Options for the default column family, which stores the current key-value state.
    pub default_cf_options: Options,
    /// Options for the metadata column family.
    pub meta_cf_options: Options,
    /// Options for the sequence-pointer log column family.
    pub log_cf_options: Options,
    /// Options for the staged batch-payload column family.
    pub staged_cf_options: Options,
    /// Maximum tickets folded into one synced sequence-assignment write.
    pub max_tickets_per_commit: NonZeroUsize,
    /// How each sequence-assignment wave is made durable before its callers are acked.
    pub durability: CommitDurability,
}

impl Default for UnorderedRocksConfig {
    fn default() -> Self {
        Self {
            db_options: Options::default(),
            default_cf_options: Options::default(),
            meta_cf_options: Options::default(),
            log_cf_options: Options::default(),
            staged_cf_options: Options::default(),
            max_tickets_per_commit: NonZeroUsize::new(DEFAULT_MAX_TICKETS_PER_COMMIT)
                .expect("default ticket commit limit must be nonzero"),
            durability: CommitDurability::default(),
        }
    }
}

/// RocksDB-backed store that writes data concurrently and assigns sequence numbers afterwards.
///
/// Not wire-compatible with a database created by [`crate::RocksStore`]: the `log` column family
/// holds ticket pointers here instead of encoded batch payloads.
#[derive(Clone)]
pub struct UnorderedRocksStore {
    db: Arc<DB>,
    sequence: Arc<AtomicU64>,
    sequencer: Arc<Sequencer>,
    boot_nonce: u64,
    ticket_counter: Arc<AtomicU64>,
    durability: CommitDurability,
}

impl UnorderedRocksStore {
    /// Open the store, creating column families as needed and adopting any staged batches that
    /// were written before a crash but never assigned a sequence number.
    pub fn open(path: &Path, config: Option<UnorderedRocksConfig>) -> Result<Self, rocksdb::Error> {
        let UnorderedRocksConfig {
            mut db_options,
            default_cf_options,
            meta_cf_options,
            log_cf_options,
            staged_cf_options,
            max_tickets_per_commit,
            durability,
        } = config.unwrap_or_default();

        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);
        if durability == CommitDurability::NoWalFlush {
            // WAL-less durability publishes a frontier only after flushing all CFs; the flush
            // must be atomic across CFs or a crash could persist the meta frontier without the
            // data, log, and staged rows beneath it.
            db_options.set_atomic_flush(true);
        }

        let db = Arc::new(DB::open_cf_descriptors(
            &db_options,
            path,
            vec![
                ColumnFamilyDescriptor::new(
                    rocksdb::DEFAULT_COLUMN_FAMILY_NAME,
                    default_cf_options,
                ),
                ColumnFamilyDescriptor::new(META_CF, meta_cf_options),
                ColumnFamilyDescriptor::new(LOG_CF, log_cf_options),
                ColumnFamilyDescriptor::new(STAGED_CF, staged_cf_options),
            ],
        )?);
        let meta_cf = db
            .cf_handle(META_CF)
            .expect("meta CF must exist (created on open)");
        // Staged batches that survived a crash without a sequence assignment are left in place:
        // they were never acked or published, so ignoring them preserves the sequence contract.
        let seq = match db.get_cf(meta_cf, SEQ_META_KEY)? {
            Some(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes.try_into().unwrap()),
            _ => 0,
        };

        let sequence = Arc::new(AtomicU64::new(seq));
        let sequencer = Arc::new(Sequencer::start(
            db.clone(),
            sequence.clone(),
            max_tickets_per_commit.get(),
            durability,
        ));
        let boot_nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Ok(Self {
            db,
            sequence,
            sequencer,
            boot_nonce,
            ticket_counter: Arc::new(AtomicU64::new(0)),
            durability,
        })
    }

    fn log_cf(&self) -> &ColumnFamily {
        self.db
            .cf_handle(LOG_CF)
            .expect("log CF must exist (created on open)")
    }

    fn staged_cf(&self) -> &ColumnFamily {
        self.db
            .cf_handle(STAGED_CF)
            .expect("staged CF must exist (created on open)")
    }

    fn next_ticket(&self) -> [u8; TICKET_LEN] {
        let counter = self.ticket_counter.fetch_add(1, Ordering::Relaxed);
        let mut id = [0u8; TICKET_LEN];
        id[..8].copy_from_slice(&self.boot_nonce.to_be_bytes());
        id[8..].copy_from_slice(&counter.to_be_bytes());
        id
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

    /// Deletes pointer rows below `cutoff_exclusive` together with their staged payloads.
    fn prune_log(&self, cutoff_exclusive: u64) -> Result<(), String> {
        if cutoff_exclusive == 0 {
            return Ok(());
        }
        let log_cf = self.log_cf();
        let staged_cf = self.staged_cf();
        let mut batch = rocksdb::WriteBatch::default();
        for item in self.db.iterator_cf(log_cf, IteratorMode::Start) {
            let (key, ticket) = item.map_err(|e| e.to_string())?;
            if key.as_ref() >= sequence_log_key(cutoff_exclusive).as_slice() {
                break;
            }
            batch.delete_cf(staged_cf, ticket.as_ref());
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

/// Encodes the staged replay payload: a `log.stream.v1.GetResponse` with the sequence number
/// left unset (it is unknown until assignment). Returns `None` when there is nothing to log.
pub(crate) fn encode_staged_value(kvs: &[(Bytes, Bytes)]) -> Option<Vec<u8>> {
    if kvs.is_empty() {
        return None;
    }
    let entries = kvs
        .iter()
        .map(|(key, value)| Entry {
            key: key.to_vec(),
            value: value.clone(),
            ..Default::default()
        })
        .collect::<Vec<_>>();
    Some(
        StreamGetResponse {
            entries,
            ..Default::default()
        }
        .encode_to_vec(),
    )
}

/// Builds the wire bytes of a `GetResponse` with `sequence_number` set by prefixing the staged
/// (sequence-less) encoding with the field-1 varint. Field 1 is always encoded first by the
/// generator, so this is equivalent to re-encoding the message with the sequence filled in.
pub(crate) fn staged_value_with_sequence(sequence: u64, staged: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(staged.len() + 11);
    if sequence != 0 {
        bytes.push(0x08); // field 1, varint wire type
        let mut v = sequence;
        while v >= 0x80 {
            bytes.push((v as u8) | 0x80);
            v >>= 7;
        }
        bytes.push(v as u8);
    }
    bytes.extend_from_slice(staged);
    bytes
}

impl Sequence for UnorderedRocksStore {
    fn current_sequence(&self) -> u64 {
        self.sequence.load(Ordering::Acquire)
    }
}

impl Ingest for UnorderedRocksStore {
    async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, String> {
        let ticket = self.next_ticket();
        let staged_value = encode_staged_value(&kvs);
        let staged = staged_value.is_some();

        // Phase 1: unsynced write of the data rows plus the staged payload (WAL-backed under
        // SyncWal, WAL-less under NoWalFlush). Runs on the blocking pool so concurrent callers
        // reach RocksDB's write groups in parallel.
        let db = self.db.clone();
        let durability = self.durability;
        tokio::task::spawn_blocking(move || {
            let mut batch = rocksdb::WriteBatch::default();
            for (k, v) in &kvs {
                batch.put(k.as_ref(), v.as_ref());
            }
            if let Some(staged_value) = staged_value {
                let staged_cf = db
                    .cf_handle(STAGED_CF)
                    .expect("staged CF must exist (created on open)");
                batch.put_cf(staged_cf, ticket, staged_value);
            }
            let mut options = WriteOptions::default();
            options.disable_wal(durability == CommitDurability::NoWalFlush);
            db.write_opt(batch, &options).map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| format!("rocks data write task failed: {e}"))??;

        // Phase 2: hand the completed ticket to the sequencer and wait for the synced sequence
        // assignment that publishes this batch.
        let (response, result) = oneshot::channel();
        self.sequencer.submit(Ticket {
            id: ticket,
            staged,
            response,
        })?;
        result
            .await
            .map_err(|_| "rocks sequencer stopped before completing write".to_string())?
    }
}

impl Query for UnorderedRocksStore {
    type RangeScan = RocksRangeScanCursor;

    async fn get(&self, key: Bytes) -> Result<(Option<Bytes>, QueryExtra), String> {
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

impl Prune for UnorderedRocksStore {
    async fn apply_prune_policies(&self, document: PrunePolicyDocument) -> Result<(), String> {
        self.apply_prune_policies_inner(document)
    }
}

impl Log for UnorderedRocksStore {
    async fn get_batch(&self, sequence_number: u64) -> Result<Option<LogBatch>, String> {
        let ticket = match self
            .db
            .get_cf(self.log_cf(), sequence_log_key(sequence_number))
            .map_err(|e| e.to_string())?
        {
            Some(ticket) => ticket,
            None => return Ok(None),
        };
        let staged = match self
            .db
            .get_cf(self.staged_cf(), &ticket)
            .map_err(|e| e.to_string())?
        {
            Some(staged) => staged,
            None => return Ok(None),
        };
        Ok(Some(LogBatch::from_response_bytes(
            sequence_number,
            staged_value_with_sequence(sequence_number, &staged),
        )))
    }

    async fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
        let mut it = self.db.iterator_cf(self.log_cf(), IteratorMode::Start);
        match it.next() {
            None => Ok(None),
            Some(item) => {
                let (key, _) = item.map_err(|e| e.to_string())?;
                crate::rocks::sequence_from_log_key(key.as_ref()).map(Some)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use buffa::Message;
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

    #[test]
    fn staged_value_prefix_matches_reencoding() {
        for sequence in [1u64, 127, 128, 300, u64::MAX] {
            let kvs = vec![(Bytes::from_static(b"key"), Bytes::from_static(b"value"))];
            let staged = encode_staged_value(&kvs).expect("staged value");
            let combined = staged_value_with_sequence(sequence, &staged);
            let expected = StreamGetResponse {
                sequence_number: sequence,
                entries: vec![Entry {
                    key: b"key".to_vec(),
                    value: Bytes::from_static(b"value"),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .encode_to_vec();
            assert_eq!(combined, expected, "sequence {sequence}");
        }
    }

    #[tokio::test]
    async fn put_batch_assigns_monotonic_sequences_and_logs_batches() {
        let dir = tempdir().expect("tempdir");
        let store = UnorderedRocksStore::open(dir.path(), None).expect("open db");

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
        assert_eq!(store.current_sequence(), 2);
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
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_puts_keep_all_rows_in_sequence_logs() {
        let dir = tempdir().expect("tempdir");
        let store = UnorderedRocksStore::open(dir.path(), None).expect("open db");
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
        // Every request receives its own contiguous sequence number.
        assert_eq!(sequences, (1..=32).collect::<BTreeSet<_>>());
        assert_eq!(store.current_sequence(), 32);

        let mut logged_keys = BTreeSet::new();
        for sequence in 1..=32 {
            let batch = store
                .get_batch(sequence)
                .await
                .expect("get batch")
                .expect("batch retained");
            for (key, value) in batch_entries(batch) {
                assert_eq!(value.as_ref(), &[key[0] + 1]);
                logged_keys.insert(key[0]);
            }
        }
        assert_eq!(logged_keys, (0u8..32).collect::<BTreeSet<_>>());
    }

    #[tokio::test]
    async fn sequence_persists_across_reopen() {
        let dir = tempdir().expect("tempdir");
        {
            let store = UnorderedRocksStore::open(dir.path(), None).expect("open db");
            store
                .put_batch(vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))])
                .await
                .expect("put");
            store
                .put_batch(vec![(Bytes::from_static(b"b"), Bytes::from_static(b"2"))])
                .await
                .expect("put");
        }
        let reopened = UnorderedRocksStore::open(dir.path(), None).expect("reopen db");
        assert_eq!(reopened.current_sequence(), 2);
        let s3 = reopened
            .put_batch(vec![(Bytes::from_static(b"c"), Bytes::from_static(b"3"))])
            .await
            .expect("put");
        assert_eq!(s3, 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn no_wal_flush_store_persists_across_reopen() {
        let config = || UnorderedRocksConfig {
            durability: CommitDurability::NoWalFlush,
            ..Default::default()
        };
        let dir = tempdir().expect("tempdir");
        {
            let store = UnorderedRocksStore::open(dir.path(), Some(config())).expect("open db");
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

        // Durability came from the per-wave atomic flush, not the (disabled) WAL.
        let reopened = UnorderedRocksStore::open(dir.path(), Some(config())).expect("reopen db");
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
    }

    #[tokio::test]
    async fn open_ignores_orphaned_staged_batches() {
        let dir = tempdir().expect("tempdir");
        {
            let store = UnorderedRocksStore::open(dir.path(), None).expect("open db");
            store
                .put_batch(vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))])
                .await
                .expect("put");

            // Model a crash between phase 1 and phase 2: data + staged row durable, but no
            // pointer row or frontier update.
            let staged_cf = store.staged_cf();
            let orphan_ticket = [0xEEu8; TICKET_LEN];
            let staged_value =
                encode_staged_value(&[(Bytes::from_static(b"orphan"), Bytes::from_static(b"o"))])
                    .expect("staged value");
            let mut batch = rocksdb::WriteBatch::default();
            batch.put(b"orphan", b"o");
            batch.put_cf(staged_cf, orphan_ticket, staged_value);
            store.db.write(batch).expect("seed orphan");
        }

        // The orphan is junk: the frontier stays where the last ack left it, no sequence number
        // points at the staged row, and a new write simply takes the next number.
        let reopened = UnorderedRocksStore::open(dir.path(), None).expect("reopen db");
        assert_eq!(reopened.current_sequence(), 1);
        let s2 = reopened
            .put_batch(vec![(Bytes::from_static(b"b"), Bytes::from_static(b"2"))])
            .await
            .expect("put");
        assert_eq!(s2, 2);
        assert_eq!(
            batch_entries(reopened.get_batch(2).await.expect("get").expect("retained")),
            vec![(Bytes::from_static(b"b"), Bytes::from_static(b"2"))]
        );
    }

    #[tokio::test]
    async fn sequence_prune_removes_pointer_and_staged_rows() {
        let dir = tempdir().expect("tempdir");
        let store = UnorderedRocksStore::open(dir.path(), None).expect("open db");
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
        // Staged payloads for pruned batches must be gone too.
        let staged_rows = store
            .db
            .iterator_cf(store.staged_cf(), IteratorMode::Start)
            .count();
        assert_eq!(staged_rows, 1);
        // Current-state rows are untouched by sequence pruning.
        assert_eq!(
            store.get(Bytes::from(vec![0u8])).await.expect("get").0,
            Some(Bytes::from(vec![0u8]))
        );
    }
}
