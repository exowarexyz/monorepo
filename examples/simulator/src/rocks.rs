//! Naive reference storage for local development: user keys and values are written as-is to
//! RocksDB. A single reserved key holds the monotonically increasing sequence number for RPCs.
//! A separate `batch_log` column family keeps per-sequence-number batches so the stream service
//! can serve replay and point lookups. Batch-log pruning is driven exclusively by the compact
//! service's `Sequence` scope (see `server::prune::execute_prune`).

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use exoware_server::{QueryExtra, RangeScan, RangeScanCursor, StoreEngine};
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DBIterator, Direction, IteratorMode, Options, DB,
};

/// One reserved key for the sequence counter (not visible to normal range scans that skip it).
const SEQ_META_KEY: &[u8] = b"__simulator_seq__";
const BATCH_LOG_CF: &str = "batch_log";
type RocksIterItem = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>;
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

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
            if key_ref == SEQ_META_KEY {
                continue;
            }
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

struct RocksRangeScanCursor {
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
    fn next_batch<'a>(
        &'a mut self,
        max_items: usize,
    ) -> BoxFuture<'a, Result<Vec<(Bytes, Bytes)>, String>> {
        Box::pin(async move {
            let Some(mut state) = self.state.take() else {
                return Ok(Vec::new());
            };
            let (state, result) = tokio::task::spawn_blocking(move || {
                let result = state.next_batch(max_items);
                (state, result)
            })
            .await
            .map_err(|e| format!("range scan task failed: {e}"))?;
            self.state = Some(state);
            result
        })
    }

    fn extra(&self) -> QueryExtra {
        QueryExtra::default()
    }
}

/// Minimal RocksDB-backed store for the simulator: batch writes plus a global sequence u64
/// plus a per-sequence batch log.
#[derive(Clone)]
pub struct RocksStore {
    db: Arc<DB>,
    sequence: Arc<AtomicU64>,
    /// Optional handle updated whenever the sequence advances (for tests).
    observer: Option<Arc<AtomicU64>>,
}

impl RocksStore {
    pub fn open(path: &Path) -> Result<Self, rocksdb::Error> {
        Self::open_with_observer(path, None)
    }

    pub fn open_with_observer(
        path: &Path,
        observer: Option<Arc<AtomicU64>>,
    ) -> Result<Self, rocksdb::Error> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_default =
            ColumnFamilyDescriptor::new(rocksdb::DEFAULT_COLUMN_FAMILY_NAME, Options::default());
        let cf_batch_log = ColumnFamilyDescriptor::new(BATCH_LOG_CF, Options::default());
        let db = Arc::new(DB::open_cf_descriptors(
            &opts,
            path,
            vec![cf_default, cf_batch_log],
        )?);
        let seq = match db.get(SEQ_META_KEY)? {
            Some(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes.try_into().unwrap()),
            _ => 0,
        };
        Ok(Self {
            db,
            sequence: Arc::new(AtomicU64::new(seq)),
            observer,
        })
    }

    fn batch_log_cf(&self) -> &ColumnFamily {
        self.db
            .cf_handle(BATCH_LOG_CF)
            .expect("batch_log CF must exist (created on open)")
    }

    fn batch_put_rocksdb(&self, kvs: &[(Bytes, Bytes)]) -> Result<u64, rocksdb::Error> {
        let next = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let encoded = encode_batch_entries(kvs);
        let mut batch = rocksdb::WriteBatch::default();
        for (k, v) in kvs {
            batch.put(k.as_ref(), v.as_ref());
        }
        batch.put(SEQ_META_KEY, next.to_le_bytes());
        batch.put_cf(self.batch_log_cf(), next.to_be_bytes(), &encoded);
        self.db.write(batch)?;
        if let Some(obs) = &self.observer {
            obs.store(next, Ordering::SeqCst);
        }
        Ok(next)
    }

    fn get_rocksdb(&self, key: &[u8]) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        if key == SEQ_META_KEY {
            return Ok(None);
        }
        self.db.get(key)
    }
}

impl StoreEngine for RocksStore {
    fn put_batch(&self, kvs: &[(Bytes, Bytes)]) -> Result<u64, String> {
        self.batch_put_rocksdb(kvs).map_err(|e| e.to_string())
    }

    fn get(&self, key: &[u8]) -> Result<(Option<Vec<u8>>, QueryExtra), String> {
        self.get_rocksdb(key)
            .map(|value| (value, QueryExtra::default()))
            .map_err(|e| e.to_string())
    }

    fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Result<RangeScanCursor, String> {
        Ok(Box::new(RocksRangeScanCursor::new(
            self.db.clone(),
            start,
            end,
            limit,
            forward,
        )))
    }

    fn get_many(
        &self,
        keys: &[&[u8]],
    ) -> Result<(Vec<(Vec<u8>, Option<Vec<u8>>)>, QueryExtra), String> {
        let results = self.db.multi_get(keys);
        let entries = keys
            .iter()
            .zip(results)
            .map(|(k, r)| {
                if *k == SEQ_META_KEY {
                    return Ok((k.to_vec(), None));
                }
                let value = r.map_err(|e| e.to_string())?;
                Ok((k.to_vec(), value))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok((entries, QueryExtra::default()))
    }

    fn delete_batch(&self, keys: &[&[u8]]) -> Result<u64, String> {
        let next = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let mut batch = rocksdb::WriteBatch::default();
        for k in keys {
            batch.delete(k);
        }
        batch.put(SEQ_META_KEY, next.to_le_bytes());
        // delete_batch is a second-class writer with no payload to log; record
        // an empty batch so sequence numbers remain contiguous and GetBatch
        // can distinguish "this sequence happened but contained no tracked
        // entries" from "evicted / never existed".
        batch.put_cf(
            self.batch_log_cf(),
            next.to_be_bytes(),
            encode_batch_entries(&[]),
        );
        self.db.write(batch).map_err(|e| e.to_string())?;
        if let Some(obs) = &self.observer {
            obs.store(next, Ordering::SeqCst);
        }
        Ok(next)
    }

    fn current_sequence(&self) -> u64 {
        self.sequence.load(Ordering::SeqCst)
    }

    fn get_batch(&self, sequence_number: u64) -> Result<Option<Vec<(Bytes, Bytes)>>, String> {
        let cf = self.batch_log_cf();
        match self
            .db
            .get_cf(cf, sequence_number.to_be_bytes())
            .map_err(|e| e.to_string())?
        {
            Some(raw) => Ok(Some(decode_batch_entries(&raw).map_err(|e| e.to_string())?)),
            None => Ok(None),
        }
    }

    fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
        let cf = self.batch_log_cf();
        let mut it = self.db.iterator_cf(cf, IteratorMode::Start);
        match it.next() {
            None => Ok(None),
            Some(item) => {
                let (key, _) = item.map_err(|e| e.to_string())?;
                if key.len() != 8 {
                    return Err(format!(
                        "batch_log CF key has unexpected length {}",
                        key.len()
                    ));
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(key.as_ref());
                Ok(Some(u64::from_be_bytes(buf)))
            }
        }
    }

    fn prune_batch_log(&self, cutoff_exclusive: u64) -> Result<u64, String> {
        // Count before deleting so callers know how much was pruned. For the
        // simulator a simple iterator scan is fine; a production engine would
        // expose delete_range_cf and return the logical count separately.
        let cf = self.batch_log_cf();
        let end_key = cutoff_exclusive.to_be_bytes();
        let mut deleted = 0u64;
        let mut batch = rocksdb::WriteBatch::default();
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        for item in iter {
            let (k, _) = item.map_err(|e| e.to_string())?;
            if k.as_ref() >= &end_key[..] {
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
}

// --- batch log codec: `count: u32_be | for each (k,v): klen: u32_be | k | vlen: u32_be | v` ---

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
            return Err("batch log truncated at u32 header".to_string());
        }
        let (head, rest) = buf.split_at(4);
        *buf = rest;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(head);
        Ok(u32::from_be_bytes(raw))
    }
    fn take_n<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], String> {
        if buf.len() < n {
            return Err("batch log truncated at payload".to_string());
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
        return Err(format!(
            "batch log had {} trailing bytes after decode",
            raw.len()
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
