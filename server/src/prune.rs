//! Prune execution: apply prune policies against the store.
//!
//! Each policy's `scope` discriminates the keyspace:
//! - `UserKeys` — scan key family keys matching `match_key`, partition by
//!   `group_by` capture groups, order within each group, and delete entries
//!   that don't survive `retain`.
//! - `BatchLog` — translate `retain` into a cutoff sequence number and call
//!   `StoreEngine::prune_batch_log`. No key scan; no grouping.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use exoware_sdk::keys::KeyCodec;
use exoware_sdk::match_key::compile_payload_regex;
use exoware_sdk::prune_policy::{
    KeysScope, OrderEncoding, PolicyScope, PrunePolicyDocument, RetainPolicy,
};
use regex::bytes::Regex;

use crate::StoreEngine;

#[derive(Debug)]
pub enum PruneError {
    Engine(String),
    Policy(String),
}

impl std::fmt::Display for PruneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PruneError::Engine(s) => write!(f, "engine: {s}"),
            PruneError::Policy(s) => write!(f, "policy: {s}"),
        }
    }
}

impl std::error::Error for PruneError {}

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

struct KeyEntry {
    key: Bytes,
    order_value: Vec<u8>,
}

fn compare_order_values(a: &[u8], b: &[u8], scope: &KeysScope) -> Ordering {
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

fn keys_to_delete(
    mut entries: Vec<KeyEntry>,
    scope: &KeysScope,
    retain: &RetainPolicy,
) -> Vec<Bytes> {
    entries.sort_by(|a, b| compare_order_values(&a.order_value, &b.order_value, scope));

    match retain {
        RetainPolicy::KeepLatest { count } => {
            if entries.len() <= *count {
                return Vec::new();
            }
            entries[..entries.len() - count]
                .iter()
                .map(|e| e.key.clone())
                .collect()
        }
        RetainPolicy::GreaterThan { threshold } => {
            let threshold = threshold.to_be_bytes();
            entries
                .iter()
                .filter(|e| {
                    compare_order_values(&e.order_value, &threshold, scope) != Ordering::Greater
                })
                .map(|e| e.key.clone())
                .collect()
        }
        RetainPolicy::GreaterThanOrEqual { threshold } => {
            let threshold = threshold.to_be_bytes();
            entries
                .iter()
                .filter(|e| {
                    compare_order_values(&e.order_value, &threshold, scope) == Ordering::Less
                })
                .map(|e| e.key.clone())
                .collect()
        }
        RetainPolicy::DropAll => entries.iter().map(|e| e.key.clone()).collect(),
    }
}

pub fn execute_prune(
    engine: &Arc<dyn StoreEngine>,
    document: &PrunePolicyDocument,
) -> Result<(), PruneError> {
    for policy in &document.policies {
        match &policy.scope {
            PolicyScope::Keys(scope) => {
                execute_user_keys_policy(engine, scope, &policy.retain)?;
            }
            PolicyScope::Sequence => {
                execute_batch_log_policy(engine, &policy.retain)?;
            }
        }
    }
    Ok(())
}

fn execute_user_keys_policy(
    engine: &Arc<dyn StoreEngine>,
    scope: &KeysScope,
    retain: &RetainPolicy,
) -> Result<(), PruneError> {
    let codec = KeyCodec::new(scope.match_key.reserved_bits, scope.match_key.prefix);
    let regex: Regex = compile_payload_regex(&scope.match_key.payload_regex)
        .map_err(|e| PruneError::Policy(e.to_string()))?;

    let (start, end) = codec.prefix_bounds();
    let rows = engine
        .range_scan(start.as_ref(), end.as_ref(), usize::MAX, true)
        .map_err(PruneError::Engine)?;

    let mut groups: BTreeMap<Vec<u8>, Vec<KeyEntry>> = BTreeMap::new();

    for row in rows {
        let (key, _value) = row.map_err(PruneError::Engine)?;
        if !codec.matches(&key) {
            continue;
        }
        let payload_len = codec.payload_capacity_bytes_for_key_len(key.len());
        let payload = match codec.read_payload(&key, 0, payload_len) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if !regex.is_match(&payload) {
            continue;
        }

        let group_key = match extract_group_key(&payload, &regex, scope) {
            Some(gk) => gk,
            None => continue,
        };

        let order_value = extract_order_value(&payload, &regex, scope).unwrap_or_default();

        groups
            .entry(group_key)
            .or_default()
            .push(KeyEntry { key, order_value });
    }

    let mut all_deletes = Vec::new();
    for (_group_key, entries) in groups {
        all_deletes.extend(keys_to_delete(entries, scope, retain));
    }

    if !all_deletes.is_empty() {
        let refs: Vec<&[u8]> = all_deletes.iter().map(|k| k.as_ref()).collect();
        engine.delete_batch(&refs).map_err(PruneError::Engine)?;
    }

    Ok(())
}

fn execute_batch_log_policy(
    engine: &Arc<dyn StoreEngine>,
    retain: &RetainPolicy,
) -> Result<(), PruneError> {
    let current = engine.current_sequence();
    let cutoff_exclusive = match retain {
        RetainPolicy::KeepLatest { count } => {
            // Keep the last N batches: cutoff = current + 1 - N (saturating).
            let count = *count as u64;
            current.saturating_add(1).saturating_sub(count)
        }
        RetainPolicy::GreaterThan { threshold } => threshold.saturating_add(1),
        RetainPolicy::GreaterThanOrEqual { threshold } => *threshold,
        RetainPolicy::DropAll => current.saturating_add(1),
    };

    engine
        .prune_batch_log(cutoff_exclusive)
        .map_err(PruneError::Engine)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::RangeScanIter;
    use exoware_sdk::keys::KeyCodec;
    use exoware_sdk::kv_codec::Utf8;
    use exoware_sdk::match_key::MatchKey;
    use exoware_sdk::prune_policy::{GroupBy, OrderBy, PrunePolicy, PRUNE_POLICY_DOCUMENT_VERSION};

    struct FakePruneEngine {
        rows: Vec<(Bytes, Bytes)>,
        deleted: Mutex<Vec<Bytes>>,
    }

    impl FakePruneEngine {
        fn new(rows: Vec<(Bytes, Bytes)>) -> Self {
            Self {
                rows,
                deleted: Mutex::new(Vec::new()),
            }
        }

        fn deleted(&self) -> Vec<Bytes> {
            self.deleted.lock().expect("lock").clone()
        }
    }

    impl StoreEngine for FakePruneEngine {
        fn put_batch(&self, _kvs: &[(Bytes, Bytes)]) -> Result<u64, String> {
            Ok(0)
        }

        fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }

        fn range_scan(
            &self,
            _start: &[u8],
            _end: &[u8],
            _limit: usize,
            _forward: bool,
        ) -> Result<RangeScanIter<'_>, String> {
            Ok(Box::new(self.rows.clone().into_iter().map(Ok)))
        }

        fn delete_batch(&self, keys: &[&[u8]]) -> Result<u64, String> {
            self.deleted
                .lock()
                .expect("lock")
                .extend(keys.iter().map(|key| Bytes::copy_from_slice(key)));
            Ok(1)
        }

        fn current_sequence(&self) -> u64 {
            0
        }

        fn get_batch(&self, _sequence_number: u64) -> Result<Option<Vec<(Bytes, Bytes)>>, String> {
            Ok(None)
        }

        fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
            Ok(None)
        }

        fn prune_batch_log(&self, _cutoff_exclusive: u64) -> Result<u64, String> {
            Ok(0)
        }
    }

    fn make_scope() -> KeysScope {
        KeysScope {
            match_key: MatchKey {
                reserved_bits: 4,
                prefix: 1,
                payload_regex: Utf8::from(
                    "(?s-u)^(?P<logical>(?:\\x00\\xFF|[^\\x00])*)\\x00\\x00(?P<version>.{8})$",
                ),
            },
            group_by: GroupBy {
                capture_groups: vec![Utf8::from("logical")],
            },
            order_by: Some(OrderBy {
                capture_group: Utf8::from("version"),
                encoding: OrderEncoding::U64Be,
            }),
        }
    }

    fn make_entry(order: u64) -> KeyEntry {
        KeyEntry {
            key: Bytes::from(vec![order as u8]),
            order_value: order.to_be_bytes().to_vec(),
        }
    }

    fn encoded_policy_key(logical: &[u8], version: u64) -> Bytes {
        let codec = KeyCodec::new(4, 1);
        let mut payload = Vec::new();
        payload.extend_from_slice(logical);
        payload.extend_from_slice(b"\0\0");
        payload.extend_from_slice(&version.to_be_bytes());
        codec.encode(&payload).expect("encode key")
    }

    #[test]
    fn keep_latest_retains_newest() {
        let scope = make_scope();
        let retain = RetainPolicy::KeepLatest { count: 2 };
        let entries = vec![make_entry(1), make_entry(2), make_entry(3)];
        let deletes = keys_to_delete(entries, &scope, &retain);
        assert_eq!(deletes.len(), 1);
        assert_eq!(deletes[0].as_ref(), &[1u8]);
    }

    #[test]
    fn keep_latest_no_delete_when_under_count() {
        let scope = make_scope();
        let retain = RetainPolicy::KeepLatest { count: 5 };
        let entries = vec![make_entry(1), make_entry(2)];
        let deletes = keys_to_delete(entries, &scope, &retain);
        assert!(deletes.is_empty());
    }

    #[test]
    fn drop_all_deletes_everything() {
        let scope = make_scope();
        let retain = RetainPolicy::DropAll;
        let entries = vec![make_entry(1), make_entry(2)];
        let deletes = keys_to_delete(entries, &scope, &retain);
        assert_eq!(deletes.len(), 2);
    }

    #[test]
    fn greater_than_threshold() {
        let scope = make_scope();
        let retain = RetainPolicy::GreaterThan { threshold: 5 };
        let entries = vec![make_entry(3), make_entry(5), make_entry(7)];
        let deletes = keys_to_delete(entries, &scope, &retain);
        assert_eq!(deletes.len(), 2);
    }

    #[test]
    fn greater_than_or_equal_threshold() {
        let scope = make_scope();
        let retain = RetainPolicy::GreaterThanOrEqual { threshold: 5 };
        let entries = vec![make_entry(3), make_entry(5), make_entry(7)];
        let deletes = keys_to_delete(entries, &scope, &retain);
        assert_eq!(deletes.len(), 1);
    }

    #[test]
    fn execute_prune_deletes_keys_from_range_iterator() {
        let old = encoded_policy_key(b"acct", 1);
        let new = encoded_policy_key(b"acct", 2);
        let engine = Arc::new(FakePruneEngine::new(vec![
            (old.clone(), Bytes::from_static(b"old")),
            (new.clone(), Bytes::from_static(b"new")),
        ]));
        let store: Arc<dyn StoreEngine> = engine.clone();
        let document = PrunePolicyDocument {
            version: PRUNE_POLICY_DOCUMENT_VERSION,
            policies: vec![PrunePolicy {
                scope: PolicyScope::Keys(make_scope()),
                retain: RetainPolicy::KeepLatest { count: 1 },
            }],
        };

        execute_prune(&store, &document).expect("prune");

        assert_eq!(engine.deleted(), vec![old]);
    }
}
