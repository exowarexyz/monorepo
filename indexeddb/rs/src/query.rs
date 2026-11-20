//! Point reads and range scans.

use crate::{
    idb::{self, Budget, Read, Stored, KV, META, SEQUENCE},
    store::{run, IndexedDbStore},
};
use bytes::Bytes;
use exoware_server::{Query, QueryExtra, QueryResult, RangeScan, RangeScanBatch, RangeScanResult};
use std::{collections::VecDeque, future::Future};
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{IdbCursorDirection, IdbCursorWithValue};

/// Point reads of one multi-key read that may be outstanding at once.
///
/// The browser loads the value of every read that was placed, whether or not the budget still
/// has room for it. A read that goes over the budget therefore leaves at most this many values
/// for the browser to load.
const GET_MANY_WINDOW: usize = 16;

/// The rows of one range scan, read at one sequence number.
///
/// IndexedDB keeps a consistent view only while a transaction is live, and a transaction
/// cannot wait for a consumer. The scan therefore reads its rows when it is opened and this
/// cursor hands them out from memory.
pub struct IndexedDbRangeScan {
    rows: VecDeque<(Bytes, Bytes)>,
}

impl RangeScan for IndexedDbRangeScan {
    async fn next_batch(&mut self, max_items: usize) -> Result<RangeScanBatch, String> {
        let take = max_items.min(self.rows.len());
        Ok(RangeScanBatch {
            rows: self.rows.drain(..take).collect(),
            extra: QueryExtra::default(),
        })
    }
}

/// Copies a value out of JS once the budget has room for it, or returns `None` for an absent
/// row. The caller has already counted the row's key.
fn value(stored: &JsValue, budget: &mut Budget) -> Result<Option<Bytes>, String> {
    if stored.is_undefined() {
        return Ok(None);
    }
    let stored = Stored::new(stored)?;
    budget.admit(stored.len())?;
    Ok(Some(stored.copy()))
}

impl Query for IndexedDbStore {
    type RangeScan = IndexedDbRangeScan;

    fn get(
        &self,
        key: Bytes,
    ) -> impl Future<Output = Result<QueryResult<Option<Bytes>>, String>> + Send {
        let inner = self.inner.clone();
        run(move || async move {
            let mut budget = Budget::new(inner.config.max_query_bytes);
            budget.row(key.len())?;
            let read = Read::begin(&inner.db, &[KV, META])?;
            let sequence = idb::request(read.store(META)?.get(&idb::key(SEQUENCE)));
            let stored = idb::request(read.store(KV)?.get(&idb::key(&key)));
            let sequence = idb::frontier(&sequence.await?)?;
            let value = value(&stored.await?, &mut budget)?;
            inner.observe(sequence);
            Ok(QueryResult {
                value,
                sequence_number: sequence,
                extra: QueryExtra::default(),
            })
        })
    }

    fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> impl Future<Output = Result<RangeScanResult<Self::RangeScan>, String>> + Send {
        let inner = self.inner.clone();
        run(move || async move {
            let read = Read::begin(&inner.db, &[KV, META])?;
            let sequence = idb::request(read.store(META)?.get(&idb::key(SEQUENCE)));
            let mut rows = VecDeque::new();
            if let Some(range) = idb::key_range(&start, &end)?.filter(|_| limit > 0) {
                let direction = if forward {
                    IdbCursorDirection::Next
                } else {
                    IdbCursorDirection::Prev
                };
                let cursor = read
                    .store(KV)?
                    .open_cursor_with_range_and_direction(&range, direction);
                let mut budget = Budget::new(inner.config.max_query_bytes);
                idb::walk(cursor, |cursor| {
                    let cursor: &IdbCursorWithValue = cursor.unchecked_ref();
                    let key = idb::stored_key(cursor)?;
                    let value = Stored::new(&cursor.value().map_err(idb::describe)?)?;
                    budget.row(key.len().saturating_add(value.len()))?;
                    rows.push_back((key.copy(), value.copy()));
                    Ok(rows.len() < limit)
                })
                .await?;
            }
            let sequence = idb::frontier(&sequence.await?)?;
            inner.observe(sequence);
            Ok(RangeScanResult {
                scan: IndexedDbRangeScan { rows },
                sequence_number: sequence,
            })
        })
    }

    fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> impl Future<Output = Result<QueryResult<Vec<(Bytes, Option<Bytes>)>>, String>> + Send {
        let inner = self.inner.clone();
        run(move || async move {
            // The answer holds a row per key whatever the database holds, so the keys are
            // counted before anything is read.
            let mut budget = Budget::new(inner.config.max_query_bytes);
            for key in &keys {
                budget.row(key.len())?;
            }
            let read = Read::begin(&inner.db, &[KV, META])?;
            let sequence = idb::request(read.store(META)?.get(&idb::key(SEQUENCE)));
            let kv = read.store(KV)?;
            let mut values = Vec::with_capacity(keys.len());
            let mut unread = keys.iter();
            let mut placed = VecDeque::with_capacity(GET_MANY_WINDOW);
            loop {
                while placed.len() < GET_MANY_WINDOW {
                    let Some(key) = unread.next() else {
                        break;
                    };
                    placed.push_back((key, idb::request(kv.get(&idb::key(key)))));
                }
                let Some((key, stored)) = placed.pop_front() else {
                    break;
                };
                values.push((key.clone(), value(&stored.await?, &mut budget)?));
            }
            let sequence = idb::frontier(&sequence.await?)?;
            inner.observe(sequence);
            Ok(QueryResult {
                value: values,
                sequence_number: sequence,
                extra: QueryExtra::default(),
            })
        })
    }
}
