use std::{
    cmp::Ordering as CmpOrdering,
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use bytes::Bytes;
use exoware_sdk::{
    keys::KeyCodec,
    match_key::compile_payload_regex,
    prune_policy::{KeysScope, OrderEncoding, PolicyScope, PrunePolicyDocument, RetainPolicy},
};
use exoware_server::{Ingest, Log, Prune, Query, QueryExtra, RangeScan, RangeScanBatch, Sequence};
use regex::bytes::Regex;

use crate::{Column, KvBackend, KvWrite, RowScan, ScanBounds};

pub(crate) const SEQ_META_KEY: &[u8] = b"sequence";
const PRUNE_SCAN_BATCH_SIZE: usize = 4096;

#[derive(Clone)]
pub struct Store<B: KvBackend> {
    backend: B,
    sequence: Arc<AtomicU64>,
    observer: Option<Arc<AtomicU64>>,
}

impl<B: KvBackend> Store<B> {
    pub fn new(backend: B) -> Self {
        Self::with_observer(backend, None)
    }

    pub fn with_observer(backend: B, observer: Option<Arc<AtomicU64>>) -> Self {
        let initial_sequence = backend.initial_sequence();
        Self {
            backend,
            sequence: Arc::new(AtomicU64::new(initial_sequence)),
            observer,
        }
    }

    fn record_observer(&self, sequence: u64) {
        if let Some(observer) = &self.observer {
            observer.store(sequence, Ordering::SeqCst);
        }
    }

    async fn delete_keys(&self, keys: Vec<Bytes>) -> Result<(), String> {
        if keys.is_empty() {
            return Ok(());
        }

        let next = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let mut writes = Vec::with_capacity(keys.len() + 2);
        for key in keys {
            writes.push(KvWrite::Delete {
                column: Column::Default,
                key,
            });
        }
        writes.push(sequence_meta_write(next));
        writes.push(KvWrite::Put {
            column: Column::Log,
            key: Bytes::copy_from_slice(&next.to_be_bytes()),
            value: Bytes::from(encode_batch_entries(&[])),
        });
        self.backend.write_batch(writes).await?;
        self.record_observer(next);
        Ok(())
    }

    async fn apply_prune_policies_inner(
        &self,
        document: PrunePolicyDocument,
    ) -> Result<(), String> {
        for policy in &document.policies {
            match &policy.scope {
                PolicyScope::Keys(scope) => {
                    self.apply_key_prune_policy(scope, &policy.retain).await?;
                }
                PolicyScope::Sequence => {
                    self.apply_sequence_prune_policy(&policy.retain).await?;
                }
            }
        }
        Ok(())
    }

    async fn apply_key_prune_policy(
        &self,
        scope: &KeysScope,
        retain: &RetainPolicy,
    ) -> Result<(), String> {
        let codec = KeyCodec::new(scope.match_key.reserved_bits, scope.match_key.prefix);
        let regex = compile_payload_regex(&scope.match_key.payload_regex)
            .map_err(|e| format!("policy: {e}"))?;

        let (start, end) = codec.prefix_bounds();
        let mut rows = self
            .backend
            .scan(
                Column::Default,
                ScanBounds {
                    start,
                    end: Some(end),
                    end_inclusive: true,
                    forward: true,
                    limit: usize::MAX,
                },
            )
            .await?;
        let mut groups: BTreeMap<Vec<u8>, Vec<KeyEntry>> = BTreeMap::new();

        loop {
            let batch = rows.next_batch(PRUNE_SCAN_BATCH_SIZE).await?;
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

        let mut deletes = Vec::new();
        for (_group_key, entries) in groups {
            deletes.extend(keys_to_delete(entries, scope, retain)?);
        }
        self.delete_keys(deletes).await
    }

    async fn apply_sequence_prune_policy(&self, retain: &RetainPolicy) -> Result<(), String> {
        let current = self.sequence.load(Ordering::SeqCst);
        let cutoff_exclusive = match retain {
            RetainPolicy::KeepLatest { count } => {
                let count = *count as u64;
                current.saturating_add(1).saturating_sub(count)
            }
            RetainPolicy::GreaterThan { threshold } => threshold.saturating_add(1),
            RetainPolicy::GreaterThanOrEqual { threshold } => *threshold,
            RetainPolicy::DropAll => current.saturating_add(1),
        };
        self.prune_batch_log(cutoff_exclusive).await.map(|_| ())
    }

    async fn prune_batch_log(&self, cutoff_exclusive: u64) -> Result<u64, String> {
        let mut scan = self
            .backend
            .scan(
                Column::Log,
                ScanBounds {
                    start: Bytes::new(),
                    end: Some(Bytes::copy_from_slice(&cutoff_exclusive.to_be_bytes())),
                    end_inclusive: false,
                    forward: true,
                    limit: usize::MAX,
                },
            )
            .await?;
        let mut deleted = 0u64;
        let mut writes = Vec::new();
        loop {
            let batch = scan.next_batch(PRUNE_SCAN_BATCH_SIZE).await?;
            if batch.is_empty() {
                break;
            }
            deleted += batch.len() as u64;
            writes.extend(batch.into_iter().map(|(key, _)| KvWrite::Delete {
                column: Column::Log,
                key,
            }));
        }
        if !writes.is_empty() {
            self.backend.write_batch(writes).await?;
        }
        Ok(deleted)
    }
}

impl<B: KvBackend> Sequence for Store<B> {
    fn current_sequence(&self) -> u64 {
        self.sequence.load(Ordering::SeqCst)
    }
}

impl<B: KvBackend> Ingest for Store<B> {
    async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, String> {
        let next = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let mut writes = Vec::with_capacity(kvs.len() + 2);
        for (key, value) in &kvs {
            writes.push(KvWrite::Put {
                column: Column::Default,
                key: key.clone(),
                value: value.clone(),
            });
        }
        writes.push(sequence_meta_write(next));
        writes.push(KvWrite::Put {
            column: Column::Log,
            key: Bytes::copy_from_slice(&next.to_be_bytes()),
            value: Bytes::from(encode_batch_entries(&kvs)),
        });
        self.backend.write_batch(writes).await?;
        self.record_observer(next);
        Ok(next)
    }
}

impl<B: KvBackend> Query for Store<B> {
    type RangeScan = RangeScanAdapter<B::Scan>;

    async fn get(&self, key: Bytes) -> Result<(Option<Vec<u8>>, QueryExtra), String> {
        self.backend
            .get(Column::Default, key)
            .await
            .map(|value| (value, QueryExtra::default()))
    }

    async fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Result<Self::RangeScan, String> {
        let scan = self
            .backend
            .scan(
                Column::Default,
                ScanBounds {
                    start,
                    end: (!end.is_empty()).then_some(end),
                    end_inclusive: true,
                    forward,
                    limit,
                },
            )
            .await?;
        Ok(RangeScanAdapter { scan })
    }

    async fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> Result<(Vec<(Vec<u8>, Option<Vec<u8>>)>, QueryExtra), String> {
        let values = self.backend.get_many(Column::Default, keys.clone()).await?;
        let entries = keys
            .into_iter()
            .zip(values)
            .map(|(key, value)| (key.to_vec(), value))
            .collect();
        Ok((entries, QueryExtra::default()))
    }
}

impl<B: KvBackend> Prune for Store<B> {
    async fn apply_prune_policies(&self, document: PrunePolicyDocument) -> Result<(), String> {
        self.apply_prune_policies_inner(document).await
    }
}

impl<B: KvBackend> Log for Store<B> {
    async fn get_batch(&self, sequence_number: u64) -> Result<Option<Vec<(Bytes, Bytes)>>, String> {
        match self
            .backend
            .get(
                Column::Log,
                Bytes::copy_from_slice(&sequence_number.to_be_bytes()),
            )
            .await?
        {
            Some(raw) => Ok(Some(decode_batch_entries(&raw)?)),
            None => Ok(None),
        }
    }

    async fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
        let mut scan = self
            .backend
            .scan(
                Column::Log,
                ScanBounds {
                    start: Bytes::new(),
                    end: None,
                    end_inclusive: true,
                    forward: true,
                    limit: 1,
                },
            )
            .await?;
        let rows = scan.next_batch(1).await?;
        let Some((key, _)) = rows.into_iter().next() else {
            return Ok(None);
        };
        if key.len() != 8 {
            return Err(format!(
                "log column key has unexpected length {}",
                key.len()
            ));
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(key.as_ref());
        Ok(Some(u64::from_be_bytes(buf)))
    }
}

pub struct RangeScanAdapter<S> {
    scan: S,
}

impl<S: RowScan> RangeScan for RangeScanAdapter<S> {
    async fn next_batch(&mut self, max_items: usize) -> Result<RangeScanBatch, String> {
        self.scan
            .next_batch(max_items)
            .await
            .map(|rows| RangeScanBatch {
                rows,
                extra: QueryExtra::default(),
            })
    }
}

fn sequence_meta_write(sequence: u64) -> KvWrite {
    KvWrite::Put {
        column: Column::Meta,
        key: Bytes::copy_from_slice(SEQ_META_KEY),
        value: Bytes::copy_from_slice(&sequence.to_le_bytes()),
    }
}

struct KeyEntry {
    key: Bytes,
    order_value: Vec<u8>,
}

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

fn encode_batch_entries(kvs: &[(Bytes, Bytes)]) -> Vec<u8> {
    let mut size = 4;
    for (key, value) in kvs {
        size += 4 + key.len() + 4 + value.len();
    }
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&(kvs.len() as u32).to_be_bytes());
    for (key, value) in kvs {
        out.extend_from_slice(&(key.len() as u32).to_be_bytes());
        out.extend_from_slice(key.as_ref());
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value.as_ref());
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
        let key_len = take_u32(&mut raw)? as usize;
        let key = Bytes::copy_from_slice(take_n(&mut raw, key_len)?);
        let value_len = take_u32(&mut raw)? as usize;
        let value = Bytes::copy_from_slice(take_n(&mut raw, value_len)?);
        out.push((key, value));
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
    fn batch_entries_round_trip() {
        let kvs = vec![
            (Bytes::from_static(b"a"), Bytes::from_static(b"1")),
            (Bytes::from_static(b"bb"), Bytes::from_static(b"22")),
        ];
        assert_eq!(decode_batch_entries(&encode_batch_entries(&kvs)), Ok(kvs));
    }
}
