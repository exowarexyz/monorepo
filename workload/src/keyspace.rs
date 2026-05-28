use anyhow::ensure;
use exoware_sdk::keys::{validate_key_size, Key};

use crate::deterministic::{mix64, GOLDEN_RATIO_64};

/// Default physical key length used by the workload commands.
pub const DEFAULT_KEY_LEN: usize = 48;

/// Version of the deterministic key layout used by workload reports.
pub const KEYSPACE_LAYOUT_VERSION: u16 = 1;

// Keep inserted and intentionally-missing keys in disjoint key domains.
const INSERTED_KEY_DOMAIN: u8 = 0x10;
const MISSING_KEY_DOMAIN: u8 = 0xF0;
const NAMESPACE_LEN_BYTES: usize = 1;
const DOMAIN_BYTES: usize = 1;
const INDEX_BYTES: usize = 8;

/// Deterministic workload key generator.
///
/// The workload schema uses namespaces to isolate runs and domains to keep
/// inserted keys disjoint from keys that should be missing.
///
/// Keys sort by namespace, domain, then numeric index. The suffix is filled with
/// deterministic mixed bytes so configurable key lengths do not leave an all-zero tail.
#[derive(Clone, Debug)]
pub struct Keyspace {
    pub namespace: Vec<u8>,
    pub key_len: usize,
}

impl Keyspace {
    /// Creates a keyspace with explicit namespace bytes and physical key length.
    pub fn new(namespace: Vec<u8>, key_len: usize) -> anyhow::Result<Self> {
        validate_key_size(key_len)?;
        ensure!(
            namespace.len() <= u8::MAX as usize,
            "keyspace namespace length must fit in one byte"
        );
        ensure!(
            key_len >= min_key_len(namespace.len()),
            "--key-len must be >= {} for this namespace",
            min_key_len(namespace.len())
        );
        Ok(Self { namespace, key_len })
    }

    pub fn unnamespaced(key_len: usize) -> anyhow::Result<Self> {
        Self::new(Vec::new(), key_len)
    }

    pub fn from_u64_namespace(namespace: u64, key_len: usize) -> anyhow::Result<Self> {
        Self::new(namespace.to_be_bytes().to_vec(), key_len)
    }

    /// Returns the deterministic key for an inserted logical index.
    pub fn inserted_key(&self, index: u64) -> anyhow::Result<Key> {
        self.key(index, INSERTED_KEY_DOMAIN)
    }

    /// Returns a deterministic key from a disjoint domain for negative lookups.
    pub fn missing_key(&self, index: u64) -> anyhow::Result<Key> {
        self.key(index, MISSING_KEY_DOMAIN)
    }

    /// Returns the next lexicographic key after the provided raw key bytes.
    pub fn next_lex_key(key: &Key) -> Option<Key> {
        let mut next = key.as_ref().to_vec();
        for idx in (0..next.len()).rev() {
            if next[idx] != u8::MAX {
                next[idx] += 1;
                for byte in next.iter_mut().skip(idx + 1) {
                    *byte = 0;
                }
                return Some(Key::from(next));
            }
        }
        None
    }

    fn key(&self, index: u64, domain: u8) -> anyhow::Result<Key> {
        ensure!(
            self.key_len >= min_key_len(self.namespace.len()),
            "keyspace key_len is too small for namespace"
        );

        // Layout: namespace length, namespace bytes, domain byte, big-endian index, suffix.
        let mut key = vec![0u8; self.key_len];
        key[0] = self.namespace.len() as u8;
        let namespace_start = NAMESPACE_LEN_BYTES;
        let namespace_end = namespace_start + self.namespace.len();
        key[namespace_start..namespace_end].copy_from_slice(&self.namespace);

        let domain_offset = namespace_end;
        key[domain_offset] = domain;

        let index_start = domain_offset + DOMAIN_BYTES;
        let index_end = index_start + INDEX_BYTES;
        key[index_start..index_end].copy_from_slice(&index.to_be_bytes());

        fill_suffix(
            &mut key[index_end..],
            mix64(namespace_hash(&self.namespace) ^ index ^ u64::from(domain)),
        );
        Ok(Key::from(key))
    }
}

fn min_key_len(namespace_len: usize) -> usize {
    NAMESPACE_LEN_BYTES + namespace_len + DOMAIN_BYTES + INDEX_BYTES
}

fn fill_suffix(out: &mut [u8], mut seed: u64) {
    let mut offset = 0usize;
    while offset < out.len() {
        seed = mix64(seed.wrapping_add(offset as u64));
        let bytes = seed.to_be_bytes();
        let len = (out.len() - offset).min(bytes.len());
        out[offset..offset + len].copy_from_slice(&bytes[..len]);
        offset += len;
    }
}

fn namespace_hash(namespace: &[u8]) -> u64 {
    let mut hash = GOLDEN_RATIO_64 ^ namespace.len() as u64;
    for chunk in namespace.chunks(8) {
        let mut bytes = [0u8; 8];
        bytes[..chunk.len()].copy_from_slice(chunk);
        hash = mix64(hash ^ u64::from_be_bytes(bytes));
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_key_len_too_small_for_namespace() {
        assert!(Keyspace::new(b"namespace".to_vec(), 12).is_err());
    }

    #[test]
    fn inserted_and_missing_keys_do_not_overlap() {
        let keyspace = Keyspace::new(b"test".to_vec(), DEFAULT_KEY_LEN).unwrap();
        let inserted = keyspace.inserted_key(7).unwrap();
        let missing = keyspace.missing_key(7).unwrap();
        assert_ne!(inserted, missing);
    }

    #[test]
    fn inserted_keys_are_sorted_by_index() {
        let keyspace = Keyspace::new(b"test".to_vec(), DEFAULT_KEY_LEN).unwrap();
        let first = keyspace.inserted_key(1).unwrap();
        let second = keyspace.inserted_key(2).unwrap();
        assert!(first < second);
    }

    #[test]
    fn keys_use_configured_length() {
        let keyspace = Keyspace::unnamespaced(24).unwrap();
        assert_eq!(keyspace.inserted_key(0).unwrap().len(), 24);
    }

    #[test]
    fn next_lex_key_advances_last_byte() {
        let key = Key::from(vec![0x00, 0x10]);
        let next = Keyspace::next_lex_key(&key).expect("next key should exist");
        assert_eq!(next.as_ref(), &[0x00, 0x11]);
    }

    #[test]
    fn next_lex_key_carries_and_resets_suffix() {
        let key = Key::from(vec![0x01, 0xFF]);
        let next = Keyspace::next_lex_key(&key).expect("next key should exist");
        assert_eq!(next.as_ref(), &[0x02, 0x00]);
    }

    #[test]
    fn next_lex_key_none_when_actual_key_bytes_are_max() {
        let key = Key::from(vec![u8::MAX; 3]);
        assert!(Keyspace::next_lex_key(&key).is_none());
    }

    #[test]
    fn u64_namespace_keys_are_sorted_by_index() {
        let keyspace = Keyspace::from_u64_namespace(42, DEFAULT_KEY_LEN).unwrap();
        assert!(keyspace.inserted_key(1).unwrap() < keyspace.inserted_key(2).unwrap());
    }

    #[test]
    fn u64_namespaces_form_isolated_ranges() {
        let keyspace_a = Keyspace::from_u64_namespace(100, DEFAULT_KEY_LEN).unwrap();
        let keyspace_b = Keyspace::from_u64_namespace(101, DEFAULT_KEY_LEN).unwrap();
        let mut a = (0..8u64)
            .map(|i| keyspace_a.inserted_key(i).unwrap())
            .collect::<Vec<_>>();
        let b = (0..8u64)
            .map(|i| keyspace_b.inserted_key(i).unwrap())
            .collect::<Vec<_>>();
        a.sort_unstable();
        let min_a = a.first().cloned().expect("min key for namespace A");
        let max_a = a.last().cloned().expect("max key for namespace A");

        assert!(b.iter().all(|key| *key < min_a || *key > max_a));
    }
}
