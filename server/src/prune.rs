//! Prune execution: apply prune policies against the store.
//!
//! For each policy, scan keys matching the policy's prefix family, filter by payload regex,
//! group by capture groups, order within groups, and delete keys that do not survive the
//! retain policy.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use exoware_sdk_rs::keys::KeyCodec;
use exoware_sdk_rs::prune_policy::{
    compile_payload_regex, OrderEncoding, PrunePolicy, PrunePolicyDocument, RetainPolicy,
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

fn extract_order_value(
    payload: &[u8],
    regex: &Regex,
    policy: &PrunePolicy,
) -> Option<Vec<u8>> {
    let order_by = policy.order_by.as_ref()?;
    let captures = regex.captures(payload)?;
    let matched = captures.name(&order_by.capture_group)?;
    let raw = matched.as_bytes();
    match order_by.encoding {
        OrderEncoding::BytesAsc => Some(raw.to_vec()),
        OrderEncoding::U64Be => {
            if raw.len() == 8 {
                Some(raw.to_vec())
            } else {
                None
            }
        }
        OrderEncoding::I64Be => {
            if raw.len() == 8 {
                Some(raw.to_vec())
            } else {
                None
            }
        }
    }
}

fn extract_group_key(
    payload: &[u8],
    regex: &Regex,
    policy: &PrunePolicy,
) -> Option<Vec<u8>> {
    if policy.group_by.capture_groups.is_empty() {
        return Some(Vec::new());
    }
    let captures = regex.captures(payload)?;
    let mut group_key = Vec::new();
    for group_name in &policy.group_by.capture_groups {
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

fn compare_order_values(a: &[u8], b: &[u8], policy: &PrunePolicy) -> Ordering {
    match policy.order_by.as_ref().map(|o| &o.encoding) {
        Some(OrderEncoding::U64Be) => {
            let a_val = a
                .try_into()
                .map(u64::from_be_bytes)
                .unwrap_or(0);
            let b_val = b
                .try_into()
                .map(u64::from_be_bytes)
                .unwrap_or(0);
            a_val.cmp(&b_val)
        }
        Some(OrderEncoding::I64Be) => {
            let a_val = a
                .try_into()
                .map(i64::from_be_bytes)
                .unwrap_or(0);
            let b_val = b
                .try_into()
                .map(i64::from_be_bytes)
                .unwrap_or(0);
            a_val.cmp(&b_val)
        }
        Some(OrderEncoding::BytesAsc) | None => a.cmp(b),
    }
}

fn keys_to_delete(
    mut entries: Vec<KeyEntry>,
    policy: &PrunePolicy,
) -> Vec<Bytes> {
    entries.sort_by(|a, b| compare_order_values(&a.order_value, &b.order_value, policy));

    match &policy.retain {
        RetainPolicy::KeepLatest { count } => {
            if entries.len() <= *count {
                return Vec::new();
            }
            entries[..entries.len() - count]
                .iter()
                .map(|e| e.key.clone())
                .collect()
        }
        RetainPolicy::GreaterThan { threshold_u64 } => {
            let threshold = threshold_u64.to_be_bytes();
            entries
                .iter()
                .filter(|e| compare_order_values(&e.order_value, &threshold, policy) != Ordering::Greater)
                .map(|e| e.key.clone())
                .collect()
        }
        RetainPolicy::GreaterThanOrEqual { threshold_u64 } => {
            let threshold = threshold_u64.to_be_bytes();
            entries
                .iter()
                .filter(|e| compare_order_values(&e.order_value, &threshold, policy) == Ordering::Less)
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
        execute_single_policy(engine, policy)?;
    }
    Ok(())
}

fn execute_single_policy(
    engine: &Arc<dyn StoreEngine>,
    policy: &PrunePolicy,
) -> Result<(), PruneError> {
    let codec = KeyCodec::new(policy.match_key.reserved_bits, policy.match_key.prefix);
    let regex = compile_payload_regex(&policy.match_key.payload_regex)
        .map_err(|e| PruneError::Policy(e.to_string()))?;

    let (start, end) = codec.prefix_bounds();
    let rows = engine
        .range_scan(start.as_ref(), end.as_ref(), usize::MAX, true)
        .map_err(PruneError::Engine)?;

    let mut groups: BTreeMap<Vec<u8>, Vec<KeyEntry>> = BTreeMap::new();

    for (key, _value) in &rows {
        if !codec.matches(key) {
            continue;
        }
        let payload_len = codec.payload_capacity_bytes_for_key_len(key.len());
        let payload = match codec.read_payload(key, 0, payload_len) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if !regex.is_match(&payload) {
            continue;
        }

        let group_key = match extract_group_key(&payload, &regex, policy) {
            Some(gk) => gk,
            None => continue,
        };

        let order_value = extract_order_value(&payload, &regex, policy).unwrap_or_default();

        groups.entry(group_key).or_default().push(KeyEntry {
            key: key.clone(),
            order_value,
        });
    }

    let mut all_deletes = Vec::new();
    for (_group_key, entries) in groups {
        all_deletes.extend(keys_to_delete(entries, policy));
    }

    if !all_deletes.is_empty() {
        let refs: Vec<&[u8]> = all_deletes.iter().map(|k| k.as_ref()).collect();
        engine.delete_batch(&refs).map_err(PruneError::Engine)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use exoware_sdk_rs::kv_codec::Utf8;
    use exoware_sdk_rs::prune_policy::{GroupBy, MatchKey, OrderBy};

    fn make_policy(retain: RetainPolicy) -> PrunePolicy {
        PrunePolicy {
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
            retain,
        }
    }

    fn make_entry(order: u64) -> KeyEntry {
        KeyEntry {
            key: Bytes::from(vec![order as u8]),
            order_value: order.to_be_bytes().to_vec(),
        }
    }

    #[test]
    fn keep_latest_retains_newest() {
        let policy = make_policy(RetainPolicy::KeepLatest { count: 2 });
        let entries = vec![make_entry(1), make_entry(2), make_entry(3)];
        let deletes = keys_to_delete(entries, &policy);
        assert_eq!(deletes.len(), 1);
        assert_eq!(deletes[0].as_ref(), &[1u8]);
    }

    #[test]
    fn keep_latest_no_delete_when_under_count() {
        let policy = make_policy(RetainPolicy::KeepLatest { count: 5 });
        let entries = vec![make_entry(1), make_entry(2)];
        let deletes = keys_to_delete(entries, &policy);
        assert!(deletes.is_empty());
    }

    #[test]
    fn drop_all_deletes_everything() {
        let policy = make_policy(RetainPolicy::DropAll);
        let entries = vec![make_entry(1), make_entry(2)];
        let deletes = keys_to_delete(entries, &policy);
        assert_eq!(deletes.len(), 2);
    }

    #[test]
    fn greater_than_threshold() {
        let policy = make_policy(RetainPolicy::GreaterThan { threshold_u64: 5 });
        let entries = vec![make_entry(3), make_entry(5), make_entry(7)];
        let deletes = keys_to_delete(entries, &policy);
        assert_eq!(deletes.len(), 2);
    }

    #[test]
    fn greater_than_or_equal_threshold() {
        let policy = make_policy(RetainPolicy::GreaterThanOrEqual { threshold_u64: 5 });
        let entries = vec![make_entry(3), make_entry(5), make_entry(7)];
        let deletes = keys_to_delete(entries, &policy);
        assert_eq!(deletes.len(), 1);
    }
}
