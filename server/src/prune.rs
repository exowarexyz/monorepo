//! Key selection for prune policies.
//!
//! A prune policy names a family of keys by prefix and payload regex, partitions the matching
//! keys into groups, orders each group, and keeps part of it. [`PruneSelection`] holds that
//! logic so every backend deletes the same keys for the same policy.

use bytes::Bytes;
use exoware_sdk::{
    keys::{Key, Prefix},
    prune_policy::{KeysScope, OrderEncoding, PrunePolicy, RetainPolicy},
    selector::compile_payload_regex,
};
use regex::bytes::Regex;
use std::{
    cmp::Ordering,
    collections::{btree_map::Entry, BTreeMap},
};

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

/// Builds the key of the group a matching key belongs to. A policy retains keys within each
/// group on its own.
///
/// For every capture group the policy groups by, the key holds a 4-byte big-endian length and
/// the captured bytes. Its buffer is allocated once at that total size.
fn extract_group_key(payload: &[u8], regex: &Regex, scope: &KeysScope) -> Option<Vec<u8>> {
    let groups = &scope.group_by.capture_groups;
    if groups.is_empty() {
        return Some(Vec::new());
    }
    let captures = regex.captures(payload)?;
    let mut size = 0;
    for group_name in groups {
        size += size_of::<u32>() + captures.name(group_name)?.len();
    }
    let mut group_key = Vec::with_capacity(size);
    for group_name in groups {
        let bytes = captures.name(group_name)?.as_bytes();
        group_key.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        group_key.extend_from_slice(bytes);
    }
    Some(group_key)
}

/// Compares captured policy order values according to the encoding declared by the key scope.
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

/// Encodes a retention threshold into the same representation used by captured order values.
fn threshold_order_value(scope: &KeysScope, threshold: u64) -> Result<[u8; 8], String> {
    match scope.order_by.as_ref().map(|o| &o.encoding) {
        Some(OrderEncoding::U64Be) => Ok(threshold.to_be_bytes()),
        Some(OrderEncoding::I64Be | OrderEncoding::BytesAsc) => Err(
            "threshold retention requires order_by.encoding = u64_be for key scopes".to_string(),
        ),
        None => Err("threshold retention requires order_by for key scopes".to_string()),
    }
}

/// Selects the keys to delete from one already-partitioned retention group.
fn keys_to_delete(
    mut entries: Vec<KeyEntry>,
    scope: &KeysScope,
    retain: &RetainPolicy,
) -> Result<Vec<Bytes>, String> {
    // Keys with equal order values are ordered by key, so the selection does not depend on
    // the order in which the keys were offered.
    entries.sort_by(|a, b| {
        compare_order_values(&a.order_value, &b.order_value, scope).then_with(|| a.key.cmp(&b.key))
    });

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
                    compare_order_values(&e.order_value, &threshold, scope) != Ordering::Greater
                })
                .map(|e| e.key.clone())
                .collect())
        }
        RetainPolicy::GreaterThanOrEqual { threshold } => {
            let threshold = threshold_order_value(scope, *threshold)?;
            Ok(entries
                .iter()
                .filter(|e| {
                    compare_order_values(&e.order_value, &threshold, scope) == Ordering::Less
                })
                .map(|e| e.key.clone())
                .collect())
        }
        RetainPolicy::DropAll => Ok(entries.iter().map(|e| e.key.clone()).collect()),
    }
}

/// Selects the keys that one prune policy deletes.
///
/// A backend offers every current key inside [`Self::bounds`] through [`Self::push`], in any
/// order, and then deletes what [`Self::finish`] returns. The selection ignores keys the
/// policy's selector does not match, so a backend may offer more keys than the selector covers.
/// Among keys of one group with equal order values, the greater key counts as the later one.
///
/// The selection holds every key the selector matched until [`Self::finish`], together with the
/// data it groups and orders the key by. That data can be many times larger than the key,
/// because every capture group a policy groups by repeats the bytes it captured. A backend that
/// bounds its memory can read [`Self::retained_bytes`] as it offers keys.
pub struct PruneSelection {
    prefix: Prefix,
    regex: Regex,
    policy: PrunePolicy,
    groups: BTreeMap<Vec<u8>, Vec<KeyEntry>>,
    retained: usize,
}

impl PruneSelection {
    /// Compiles the selector of `policy`.
    pub fn new(policy: &PrunePolicy) -> Result<Self, String> {
        let selector = &policy.scope.selector;
        let prefix = Prefix::new(selector.prefix.clone()).map_err(|e| format!("policy: {e}"))?;
        let regex =
            compile_payload_regex(&selector.payload_regex).map_err(|e| format!("policy: {e}"))?;
        Ok(Self {
            prefix,
            regex,
            policy: policy.clone(),
            groups: BTreeMap::new(),
            retained: 0,
        })
    }

    /// The inclusive key range that contains every key the selector can match.
    pub fn bounds(&self) -> (Key, Key) {
        self.prefix.bounds()
    }

    /// Offers one current key.
    pub fn push(&mut self, key: Bytes) {
        let scope = &self.policy.scope;
        let Some(payload) = self.prefix.strip_slice(&key) else {
            return;
        };
        if !self.regex.is_match(payload) {
            return;
        }
        let Some(group_key) = extract_group_key(payload, &self.regex, scope) else {
            return;
        };
        let order_value = extract_order_value(payload, &self.regex, scope).unwrap_or_default();

        let mut retained = key.len() + order_value.capacity();
        let entries = match self.groups.entry(group_key) {
            Entry::Vacant(group) => {
                retained += group.key().capacity() + size_of::<(Vec<u8>, Vec<KeyEntry>)>();
                group.insert(Vec::new())
            }
            Entry::Occupied(group) => group.into_mut(),
        };
        let capacity = entries.capacity();
        entries.push(KeyEntry { key, order_value });
        retained += (entries.capacity() - capacity) * size_of::<KeyEntry>();
        self.retained += retained;
    }

    /// Bytes the selection holds for the keys the selector matched. The count covers the keys,
    /// their order values, the grouping data of every group, and the list slots and map entries
    /// that hold them.
    pub const fn retained_bytes(&self) -> usize {
        self.retained
    }

    /// Returns the keys to delete.
    ///
    /// Fails when the policy retains by threshold but does not order by `u64_be`, and only if
    /// at least one offered key matched.
    pub fn finish(self) -> Result<Vec<Bytes>, String> {
        let mut deletes = Vec::new();
        for entries in self.groups.into_values() {
            deletes.extend(keys_to_delete(
                entries,
                &self.policy.scope,
                &self.policy.retain,
            )?);
        }
        Ok(deletes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exoware_sdk::{
        kv_codec::Utf8,
        prune_policy::{GroupBy, OrderBy},
        selector::Selector,
    };

    const FAMILY: u8 = 7;

    /// A key of the family, one group byte followed by an eight byte version.
    fn key(group: u8, version: u64) -> Bytes {
        let mut key = vec![FAMILY, group];
        key.extend_from_slice(&version.to_be_bytes());
        Bytes::from(key)
    }

    fn policy(retain: RetainPolicy, encoding: OrderEncoding) -> PrunePolicy {
        PrunePolicy {
            scope: KeysScope {
                selector: Selector {
                    prefix: Bytes::from_static(&[FAMILY]),
                    payload_regex: Utf8::from("(?s-u)^(?P<group>.)(?P<version>.{8})$"),
                },
                group_by: GroupBy {
                    capture_groups: vec![Utf8::from("group")],
                },
                order_by: Some(OrderBy {
                    capture_group: Utf8::from("version"),
                    encoding,
                }),
            },
            retain,
        }
    }

    fn select(policy: &PrunePolicy, keys: &[Bytes]) -> Result<Vec<Bytes>, String> {
        let mut selection = PruneSelection::new(policy)?;
        for key in keys {
            selection.push(key.clone());
        }
        selection.finish()
    }

    #[test]
    fn keep_latest_keeps_the_newest_of_each_group() {
        let keys = [key(1, 3), key(2, 9), key(1, 1), key(1, 2), key(2, 8)];
        let deleted = select(
            &policy(RetainPolicy::KeepLatest { count: 1 }, OrderEncoding::U64Be),
            &keys,
        )
        .unwrap();
        assert_eq!(deleted, vec![key(1, 1), key(1, 2), key(2, 8)]);
    }

    #[test]
    fn thresholds_compare_versions_as_numbers() {
        let keys = [key(1, 255), key(1, 256), key(1, 257)];
        let greater = policy(
            RetainPolicy::GreaterThan { threshold: 256 },
            OrderEncoding::U64Be,
        );
        assert_eq!(
            select(&greater, &keys).unwrap(),
            vec![key(1, 255), key(1, 256)]
        );
        let at_least = policy(
            RetainPolicy::GreaterThanOrEqual { threshold: 256 },
            OrderEncoding::U64Be,
        );
        assert_eq!(select(&at_least, &keys).unwrap(), vec![key(1, 255)]);
    }

    #[test]
    fn drop_all_deletes_every_matching_key() {
        let keys = [key(1, 1), key(2, 1)];
        let deleted = select(&policy(RetainPolicy::DropAll, OrderEncoding::U64Be), &keys).unwrap();
        assert_eq!(deleted, keys.to_vec());
    }

    #[test]
    fn keys_outside_the_selector_are_ignored() {
        let mut other_family = key(1, 1).to_vec();
        other_family[0] = FAMILY + 1;
        let mut wrong_shape = key(1, 1).to_vec();
        wrong_shape.push(0);
        let keys = [
            Bytes::from(other_family),
            Bytes::from(wrong_shape),
            Bytes::from_static(&[FAMILY]),
            key(1, 1),
        ];
        let deleted = select(&policy(RetainPolicy::DropAll, OrderEncoding::U64Be), &keys).unwrap();
        assert_eq!(deleted, vec![key(1, 1)]);
    }

    /// A policy that deletes every key of the family, grouped by `captures` nested capture
    /// groups that each capture the whole payload after the family byte.
    fn repeating(captures: usize) -> PrunePolicy {
        let names: Vec<_> = (0..captures).map(|group| format!("g{group}")).collect();
        let opened: String = names.iter().map(|name| format!("(?P<{name}>")).collect();
        let regex = format!("(?s-u)^{opened}.*{}$", ")".repeat(captures));
        let mut policy = policy(RetainPolicy::DropAll, OrderEncoding::U64Be);
        policy.scope.selector.payload_regex = Utf8::from(regex.as_str());
        policy.scope.group_by.capture_groups =
            names.iter().map(|name| Utf8::from(name.as_str())).collect();
        policy.scope.order_by = None;
        policy
    }

    /// The bytes a selection holds after it is offered `keys`.
    fn retained(policy: &PrunePolicy, keys: &[Bytes]) -> usize {
        let mut selection = PruneSelection::new(policy).unwrap();
        for key in keys {
            selection.push(key.clone());
        }
        selection.retained_bytes()
    }

    #[test]
    fn retained_bytes_count_keys_order_values_and_grouping_data() {
        let ordered = policy(RetainPolicy::DropAll, OrderEncoding::U64Be);
        let keys = [key(1, 1), key(1, 2), key(2, 1)];

        // Nothing is held for a key the selector does not match.
        assert_eq!(retained(&ordered, &[Bytes::from_static(&[FAMILY])]), 0);

        // A key that starts a group also adds the group's grouping data and list, so it costs
        // more than a key that joins an existing group.
        let one = retained(&ordered, &keys[..1]);
        let joined = retained(&ordered, &keys[..2]) - one;
        let started = retained(&ordered, &[keys[0].clone(), keys[2].clone()]) - one;
        assert!(one > 0 && joined > 0 && started > joined);

        // Every key is held with its order value, the eight bytes of its version.
        let mut unordered = ordered.clone();
        unordered.scope.order_by = None;
        assert_eq!(
            retained(&ordered, &keys) - retained(&unordered, &keys),
            keys.len() * 8
        );

        // Every capture group a policy groups by holds a 4-byte length and the bytes it
        // captured. Seven more captures of the 9-byte payload add 7 * (4 + 9) bytes per key.
        assert_eq!(
            retained(&repeating(8), &keys) - retained(&repeating(1), &keys),
            keys.len() * 7 * (4 + 9)
        );

        // A longer key is held with its additional bytes, once as the key and once more for
        // every capture that repeats them.
        let (short, long) = (
            Bytes::from(vec![FAMILY; 10]),
            Bytes::from(vec![FAMILY; 110]),
        );
        assert_eq!(
            retained(&repeating(1), &[long]) - retained(&repeating(1), &[short]),
            2 * 100
        );
    }

    #[test]
    fn equal_order_values_are_ordered_by_key_whatever_the_offer_order() {
        let mut ungrouped = policy(RetainPolicy::KeepLatest { count: 1 }, OrderEncoding::U64Be);
        ungrouped.scope.group_by = GroupBy::default();
        let ascending = [key(1, 5), key(2, 5)];
        let descending = [ascending[1].clone(), ascending[0].clone()];
        for offered in [&ascending, &descending] {
            assert_eq!(select(&ungrouped, offered).unwrap(), ascending[..1]);
        }
    }

    #[test]
    fn threshold_needs_a_numeric_ordering_once_a_key_matches() {
        for encoding in [OrderEncoding::BytesAsc, OrderEncoding::I64Be] {
            for retain in [
                RetainPolicy::GreaterThan { threshold: 1 },
                RetainPolicy::GreaterThanOrEqual { threshold: 2 },
                RetainPolicy::GreaterThanOrEqual { threshold: 1 << 63 },
            ] {
                let policy = policy(retain, encoding.clone());
                assert_eq!(select(&policy, &[]).unwrap(), Vec::<Bytes>::new());
                assert!(select(&policy, &[key(1, 1)]).is_err());
            }
        }
    }

    #[test]
    fn signed_ordering_puts_negative_versions_first() {
        let negative = key(1, (-1i64) as u64);
        let keys = [key(1, 1), negative.clone()];
        let deleted = select(
            &policy(RetainPolicy::KeepLatest { count: 1 }, OrderEncoding::I64Be),
            &keys,
        )
        .unwrap();
        assert_eq!(deleted, vec![negative]);
    }

    #[test]
    fn bounds_cover_the_selector_prefix() {
        let selection =
            PruneSelection::new(&policy(RetainPolicy::DropAll, OrderEncoding::U64Be)).unwrap();
        let (start, end) = selection.bounds();
        assert!(start.as_ref() <= key(0, 0).as_ref());
        assert!(key(255, u64::MAX).as_ref() <= end.as_ref());
    }

    #[test]
    fn invalid_selector_is_rejected() {
        let mut invalid = policy(RetainPolicy::DropAll, OrderEncoding::U64Be);
        invalid.scope.selector.payload_regex = Utf8::from("(");
        assert!(PruneSelection::new(&invalid).is_err());
    }
}
