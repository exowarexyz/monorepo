//! Naive reference storage for local development: user keys and values are written as-is to
//! RocksDB. A single reserved key holds the monotonically increasing sequence number for RPCs.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use exoware_server::StoreEngine;
use rocksdb::{Direction, IteratorMode, Options, DB};

/// One reserved key for the sequence counter (not visible to normal range scans that skip it).
const SEQ_META_KEY: &[u8] = b"__simulator_seq__";

/// Minimal RocksDB-backed store for the simulator: batch writes plus a global sequence u64.
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
        let db = Arc::new(DB::open(&opts, path)?);
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

    fn batch_put_rocksdb(&self, kvs: &[(Bytes, Bytes)]) -> Result<u64, rocksdb::Error> {
        let mut batch = rocksdb::WriteBatch::default();
        for (k, v) in kvs {
            batch.put(k.as_ref(), v.as_ref());
        }
        let next = self.sequence.load(Ordering::SeqCst).saturating_add(1);
        batch.put(SEQ_META_KEY, next.to_le_bytes());
        self.db.write(batch)?;
        self.sequence.store(next, Ordering::SeqCst);
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

    /// Inclusive `end` when non-empty: include keys `k` with `start <= k <= end`.
    fn range_scan_rocksdb(
        &self,
        start: &[u8],
        end: &[u8],
        limit: usize,
        forward: bool,
    ) -> Result<Vec<(Bytes, Bytes)>, rocksdb::Error> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mode = IteratorMode::From(start, Direction::Forward);
        let mut tmp = Vec::new();
        for item in self.db.iterator(mode) {
            let (k, v) = item?;
            if k.as_ref() == SEQ_META_KEY {
                continue;
            }
            if k.as_ref() < start {
                continue;
            }
            if !end.is_empty() && k.as_ref() > end {
                break;
            }
            tmp.push((
                Bytes::copy_from_slice(k.as_ref()),
                Bytes::copy_from_slice(&v),
            ));
        }
        if tmp.is_empty() {
            return Ok(tmp);
        }
        if forward {
            tmp.truncate(limit);
            return Ok(tmp);
        }
        if tmp.len() > limit {
            tmp = tmp.split_off(tmp.len() - limit);
        }
        tmp.reverse();
        Ok(tmp)
    }
}

impl StoreEngine for RocksStore {
    fn put_batch(&self, kvs: &[(Bytes, Bytes)]) -> Result<u64, String> {
        self.batch_put_rocksdb(kvs).map_err(|e| e.to_string())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.get_rocksdb(key).map_err(|e| e.to_string())
    }

    fn range_scan(
        &self,
        start: &[u8],
        end: &[u8],
        limit: usize,
        forward: bool,
    ) -> Result<Vec<(Bytes, Bytes)>, String> {
        self.range_scan_rocksdb(start, end, limit, forward)
            .map_err(|e| e.to_string())
    }

    fn current_sequence(&self) -> u64 {
        self.sequence.load(Ordering::SeqCst)
    }
}

/// Backwards-compatible name for tooling and tests.
pub type DbState = RocksStore;
