//! Naive reference storage for local development: user keys and values are written as-is to
//! RocksDB. A `meta` column family stores the monotonically increasing sequence number for RPCs.
//! A separate `log` column family keeps per-sequence-number batches so the stream service
//! can serve replay and point lookups. Batch-log pruning is driven exclusively by the compact
//! service's `Sequence` scope.

use std::cmp::Ordering as CmpOrdering;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use exoware_sdk::keys::KeyCodec;
use exoware_sdk::match_key::compile_payload_regex;
use exoware_sdk::prune_policy::{
    KeysScope, OrderEncoding, PolicyScope, PrunePolicyDocument, RetainPolicy,
};
use exoware_server::{Ingest, Log, Prune, Query, QueryExtra, RangeScan, RangeScanBatch, Sequence};
use regex::bytes::Regex;
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DBIterator, Direction, IteratorMode, Options, DB,
};

const META_CF: &str = "meta";
const SEQ_META_KEY: &[u8] = b"sequence";
const LOG_CF: &str = "log";
const PRUNE_SCAN_BATCH_SIZE: usize = 4096;
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

/// Minimal RocksDB-backed store for the simulator: batch writes plus a global sequence u64
/// plus a per-sequence log.
#[derive(Clone)]
pub struct RocksStore {
    db: Arc<DB>,
    sequence: Arc<Mutex<u64>>,
}

impl RocksStore {
    pub fn open(path: &Path) -> Result<Self, rocksdb::Error> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_default =
            ColumnFamilyDescriptor::new(rocksdb::DEFAULT_COLUMN_FAMILY_NAME, Options::default());
        let cf_meta = ColumnFamilyDescriptor::new(META_CF, Options::default());
        let cf_log = ColumnFamilyDescriptor::new(LOG_CF, Options::default());
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
        Ok(Self {
            db,
            sequence: Arc::new(Mutex::new(seq)),
        })
    }

    fn log_cf(&self) -> &ColumnFamily {
        self.db
            .cf_handle(LOG_CF)
            .expect("log CF must exist (created on open)")
    }

    fn meta_cf(&self) -> &ColumnFamily {
        self.db
            .cf_handle(META_CF)
            .expect("meta CF must exist (created on open)")
    }

    fn commit_sequence_batch_rocksdb(
        &self,
        mut batch: rocksdb::WriteBatch,
        encoded_log: Vec<u8>,
    ) -> Result<u64, rocksdb::Error> {
        let mut sequence = self.sequence.lock().expect("rocks sequence lock poisoned");
        let next = *sequence + 1;
        batch.put_cf(self.meta_cf(), SEQ_META_KEY, next.to_le_bytes());
        batch.put_cf(self.log_cf(), next.to_be_bytes(), &encoded_log);
        self.db.write(batch)?;
        *sequence = next;
        Ok(next)
    }

    fn batch_put_rocksdb(&self, kvs: &[(Bytes, Bytes)]) -> Result<u64, rocksdb::Error> {
        let encoded = encode_batch_entries(kvs);
        let mut batch = rocksdb::WriteBatch::default();
        for (k, v) in kvs {
            batch.put(k.as_ref(), v.as_ref());
        }
        self.commit_sequence_batch_rocksdb(batch, encoded)
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
        // Record an empty batch so sequence numbers stay contiguous for stream replay.
        self.commit_sequence_batch_rocksdb(batch, encode_batch_entries(&[]))?;
        Ok(())
    }

    fn prune_log_rocksdb(&self, cutoff_exclusive: u64) -> Result<u64, rocksdb::Error> {
        // Count before deleting so callers know how much was pruned. For the
        // simulator a simple iterator scan is fine; a production engine would
        // expose delete_range_cf and return the logical count separately.
        let cf = self.log_cf();
        let end_key = cutoff_exclusive.to_be_bytes();
        let mut deleted = 0u64;
        let mut batch = rocksdb::WriteBatch::default();
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        for item in iter {
            let (k, _) = item?;
            if k.as_ref() >= &end_key[..] {
                break;
            }
            batch.delete_cf(cf, k.as_ref());
            deleted += 1;
        }
        if deleted > 0 {
            self.db.write(batch)?;
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
        self.prune_log_rocksdb(cutoff_exclusive)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

impl Sequence for RocksStore {
    fn current_sequence(&self) -> u64 {
        *self.sequence.lock().expect("rocks sequence lock poisoned")
    }
}

// The simulator keeps short point RocksDB operations as direct calls inside async futures to keep
// this local reference backend simple. Long-running range cursor pulls already use
// `spawn_blocking`; production engines should avoid blocking Tokio workers for disk I/O.
impl Ingest for RocksStore {
    async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, String> {
        let store = self.clone();
        store.batch_put_rocksdb(&kvs).map_err(|e| e.to_string())
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
        match store
            .db
            .get_cf(cf, sequence_number.to_be_bytes())
            .map_err(|e| e.to_string())?
        {
            Some(raw) => Ok(Some(decode_batch_entries(&raw).map_err(|e| e.to_string())?)),
            None => Ok(None),
        }
    }

    async fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
        let store = self.clone();
        let cf = store.log_cf();
        let mut it = store.db.iterator_cf(cf, IteratorMode::Start);
        match it.next() {
            None => Ok(None),
            Some(item) => {
                let (key, _) = item.map_err(|e| e.to_string())?;
                if key.len() != 8 {
                    return Err(format!("log CF key has unexpected length {}", key.len()));
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(key.as_ref());
                Ok(Some(u64::from_be_bytes(buf)))
            }
        }
    }
}

// --- log codec: `count: u32_be | for each (k,v): klen: u32_be | k | vlen: u32_be | v` ---

fn encode_batch_entries(kvs: &[(Bytes, Bytes)]) -> Vec<u8> {
    let mut size = 4;
    for (k, v) in kvs {
        size += 4 + k.len() + 4 + v.len();
    }
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&(kvs.len() as u32).to_be_bytes());
    for (k, v) in kvs {
        out.extend_from_slice(&(k.len() as u32).to_be_bytes());
        out.extend_from_slice(k.as_ref());
        out.extend_from_slice(&(v.len() as u32).to_be_bytes());
        out.extend_from_slice(v.as_ref());
    }
    out
}

fn decode_batch_entries(mut raw: &[u8]) -> Result<Vec<(Bytes, Bytes)>, String> {
    fn take_u32(buf: &mut &[u8]) -> Result<u32, String> {
        if buf.len() < 4 {
            return Err("log truncated at u32 header".to_string());
        }
        let (head, rest) = buf.split_at(4);
        *buf = rest;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(head);
        Ok(u32::from_be_bytes(raw))
    }
    fn take_n<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], String> {
        if buf.len() < n {
            return Err("log truncated at payload".to_string());
        }
        let (head, rest) = buf.split_at(n);
        *buf = rest;
        Ok(head)
    }
    let n = take_u32(&mut raw)? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let klen = take_u32(&mut raw)? as usize;
        let k = Bytes::copy_from_slice(take_n(&mut raw, klen)?);
        let vlen = take_u32(&mut raw)? as usize;
        let v = Bytes::copy_from_slice(take_n(&mut raw, vlen)?);
        out.push((k, v));
    }
    if !raw.is_empty() {
        return Err(format!("log had {} trailing bytes after decode", raw.len()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use tempfile::tempdir;

    #[test]
    fn batch_entries_codec_round_trip() {
        let kvs = vec![
            (Bytes::from_static(b"a"), Bytes::from_static(b"1")),
            (Bytes::from_static(b""), Bytes::from_static(b"empty key ok")),
            (
                Bytes::from_static(b"binary\x00\xff"),
                Bytes::from_static(&[0u8, 1, 2, 3]),
            ),
        ];
        let encoded = encode_batch_entries(&kvs);
        let decoded = decode_batch_entries(&encoded).unwrap();
        assert_eq!(decoded, kvs);
    }

    #[test]
    fn empty_batch_round_trips() {
        let encoded = encode_batch_entries(&[]);
        let decoded = decode_batch_entries(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn concurrent_writes_keep_sequence_log_contiguous() {
        const WRITERS: usize = 16;

        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path()).expect("open db");
        let start = Arc::new(Barrier::new(WRITERS));
        let mut handles = Vec::new();

        for i in 0..WRITERS {
            let store = store.clone();
            let start = start.clone();
            handles.push(thread::spawn(move || {
                start.wait();
                store
                    .batch_put_rocksdb(&[(
                        Bytes::from(format!("k{i}")),
                        Bytes::from(format!("v{i}")),
                    )])
                    .expect("put")
            }));
        }

        let mut sequences = handles
            .into_iter()
            .map(|handle| handle.join().expect("writer thread"))
            .collect::<Vec<_>>();
        sequences.sort_unstable();

        assert_eq!(sequences, (1..=WRITERS as u64).collect::<Vec<_>>());
        assert_eq!(store.current_sequence(), WRITERS as u64);
        for seq in 1..=WRITERS as u64 {
            assert!(
                store
                    .db
                    .get_cf(store.log_cf(), seq.to_be_bytes())
                    .expect("get log batch")
                    .is_some(),
                "missing log batch {seq}"
            );
        }

        drop(store);
        let reopened = RocksStore::open(dir.path()).expect("reopen db");
        assert_eq!(reopened.current_sequence(), WRITERS as u64);
    }
}
