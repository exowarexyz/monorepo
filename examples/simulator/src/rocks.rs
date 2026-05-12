use std::{
    path::Path,
    sync::{atomic::AtomicU64, Arc},
};

use bytes::Bytes;
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DBIterator, Direction, IteratorMode, Options, DB,
};

use crate::{
    kv_backend::beyond_upper_bound, store::SEQ_META_KEY, Column, KvBackend, KvWrite, RowScan,
    ScanBounds, Store,
};

const META_CF: &str = "meta";
const LOG_CF: &str = "log";

type RocksIterItem = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>;

pub type RocksStore = Store<RocksBackend>;

#[derive(Clone)]
pub struct RocksBackend {
    db: Arc<DB>,
    initial_sequence: u64,
}

impl Store<RocksBackend> {
    pub fn open(path: &Path) -> Result<Self, rocksdb::Error> {
        Self::open_with_observer(path, None)
    }

    pub fn open_with_observer(
        path: &Path,
        observer: Option<Arc<AtomicU64>>,
    ) -> Result<Self, rocksdb::Error> {
        Ok(Self::with_observer(RocksBackend::open(path)?, observer))
    }
}

impl RocksBackend {
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
        let initial_sequence = match db.get_cf(meta_cf, SEQ_META_KEY)? {
            Some(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes.try_into().unwrap()),
            _ => 0,
        };
        Ok(Self {
            db,
            initial_sequence,
        })
    }

    fn cf(&self, column: Column) -> Option<&ColumnFamily> {
        match column {
            Column::Default => None,
            Column::Meta => Some(
                self.db
                    .cf_handle(META_CF)
                    .expect("meta CF must exist (created on open)"),
            ),
            Column::Log => Some(
                self.db
                    .cf_handle(LOG_CF)
                    .expect("log CF must exist (created on open)"),
            ),
        }
    }
}

impl KvBackend for RocksBackend {
    type Scan = RocksScan;

    fn initial_sequence(&self) -> u64 {
        self.initial_sequence
    }

    async fn get(&self, column: Column, key: Bytes) -> Result<Option<Vec<u8>>, String> {
        match self.cf(column) {
            Some(cf) => self.db.get_cf(cf, key).map_err(|e| e.to_string()),
            None => self.db.get(key).map_err(|e| e.to_string()),
        }
    }

    async fn get_many(
        &self,
        column: Column,
        keys: Vec<Bytes>,
    ) -> Result<Vec<Option<Vec<u8>>>, String> {
        match column {
            Column::Default => self
                .db
                .multi_get(keys.iter().map(|key| key.as_ref()))
                .into_iter()
                .map(|result| result.map_err(|e| e.to_string()))
                .collect(),
            _ => {
                let mut values = Vec::with_capacity(keys.len());
                for key in keys {
                    values.push(self.get(column, key).await?);
                }
                Ok(values)
            }
        }
    }

    async fn write_batch(&self, writes: Vec<KvWrite>) -> Result<(), String> {
        if writes.is_empty() {
            return Ok(());
        }

        let mut batch = rocksdb::WriteBatch::default();
        for write in writes {
            match write {
                KvWrite::Put { column, key, value } => match self.cf(column) {
                    Some(cf) => batch.put_cf(cf, key.as_ref(), value.as_ref()),
                    None => batch.put(key.as_ref(), value.as_ref()),
                },
                KvWrite::Delete { column, key } => match self.cf(column) {
                    Some(cf) => batch.delete_cf(cf, key.as_ref()),
                    None => batch.delete(key.as_ref()),
                },
            }
        }
        self.db.write(batch).map_err(|e| e.to_string())
    }

    async fn scan(&self, column: Column, bounds: ScanBounds) -> Result<Self::Scan, String> {
        Ok(RocksScan {
            state: Some(RocksScanState::new(self.db.clone(), column, bounds)),
        })
    }
}

struct OwnedRocksIterator {
    iter: DBIterator<'static>,
    _db: Arc<DB>,
}

impl OwnedRocksIterator {
    fn new(db: Arc<DB>, column: Column, mode: IteratorMode<'_>) -> Self {
        // The iterator is dropped before `_db`, so the Arc-owned DB outlives the borrowed handle.
        let db_ref: &'static DB = unsafe { &*Arc::as_ptr(&db) };
        let iter = match column {
            Column::Default => db_ref.iterator(mode),
            Column::Meta => db_ref.iterator_cf(
                db_ref
                    .cf_handle(META_CF)
                    .expect("meta CF must exist (created on open)"),
                mode,
            ),
            Column::Log => db_ref.iterator_cf(
                db_ref
                    .cf_handle(LOG_CF)
                    .expect("log CF must exist (created on open)"),
                mode,
            ),
        };
        Self { iter, _db: db }
    }

    fn next(&mut self) -> Option<RocksIterItem> {
        self.iter.next()
    }
}

struct RocksScanState {
    iterator: OwnedRocksIterator,
    bounds: ScanBounds,
    emitted: usize,
    done: bool,
}

impl RocksScanState {
    fn new(db: Arc<DB>, column: Column, bounds: ScanBounds) -> Self {
        let mode = if bounds.forward {
            IteratorMode::From(bounds.start.as_ref(), Direction::Forward)
        } else {
            match &bounds.end {
                Some(end) => IteratorMode::From(end.as_ref(), Direction::Reverse),
                None => IteratorMode::End,
            }
        };
        let done = bounds.limit == 0;
        Self {
            iterator: OwnedRocksIterator::new(db, column, mode),
            bounds,
            emitted: 0,
            done,
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
            if self.bounds.forward {
                if beyond_upper_bound(
                    key_ref,
                    self.bounds.end.as_deref(),
                    self.bounds.end_inclusive,
                ) {
                    self.done = true;
                    break;
                }
            } else if key_ref < self.bounds.start.as_ref() {
                self.done = true;
                break;
            }

            self.emitted += 1;
            if self.emitted >= self.bounds.limit {
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

pub struct RocksScan {
    state: Option<RocksScanState>,
}

impl RowScan for RocksScan {
    async fn next_batch(&mut self, max_items: usize) -> Result<Vec<(Bytes, Bytes)>, String> {
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
    }
}
