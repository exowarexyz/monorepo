use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::ensure;
use exoware_sdk::keys::{validate_key_size, Key};

use crate::deterministic::{mix64, GOLDEN_RATIO_64};

/// Default physical key length used by the workload commands.
pub const DEFAULT_KEY_LEN: usize = 48;

/// Version of the deterministic key layout used by workload reports.
pub const KEYSPACE_LAYOUT_VERSION: u16 = 2;

// Keep inserted and intentionally-missing keys in disjoint key domains.
const INSERTED_KEY_DOMAIN: u8 = 0x10;
const MISSING_KEY_DOMAIN: u8 = 0xF0;
const ENTROPY_BYTES: usize = 1;
const NAMESPACE_LEN_BYTES: usize = 1;
const DOMAIN_BYTES: usize = 1;
const INDEX_BYTES: usize = 8;

/// Defaults are run-specific so independent runs against persistent stores do
/// not reuse the same physical keys unless the caller opts into a namespace.
pub fn default_run_namespace() -> u64 {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    now_nanos ^ u64::from(std::process::id()).rotate_left(17)
}

/// Deterministic workload key generator.
///
/// Every key opens with an entropy byte derived from the logical index, so a
/// run's keys spread across the entire physical key range instead of sharing a
/// fixed prefix and stores that shard on leading key bits see load on every
/// shard. The rest of the key carries the run's identity: namespaces isolate
/// runs, domains keep inserted keys disjoint from intentionally-missing ones,
/// and the big-endian index makes every key reproducible from
/// (namespace, index).
///
/// The spread means a run's keys do not form a contiguous lexicographic block:
/// key order does not follow index order, and any key range bounded by a run's
/// keys interleaves whatever else the store holds.
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

    /// Returns the logical index that produced `key`, or `None` when `key` is
    /// not exactly one of this keyspace's inserted keys.
    ///
    /// Spread keys share the physical key range with other namespaces and runs,
    /// so range validation uses this to recognize its own rows and skip the rest.
    pub fn inserted_index_of(&self, key: &Key) -> Option<u64> {
        if key.len() != self.key_len {
            return None;
        }
        let index_start = ENTROPY_BYTES + NAMESPACE_LEN_BYTES + self.namespace.len() + DOMAIN_BYTES;
        let index_bytes = key.as_ref().get(index_start..index_start + INDEX_BYTES)?;
        let index = u64::from_be_bytes(index_bytes.try_into().expect("slice is INDEX_BYTES long"));

        // Regenerating and comparing rejects everything that merely resembles an
        // inserted key: other namespaces, the missing-key domain, or stale layouts.
        let expected = self.inserted_key(index).ok()?;
        (expected == *key).then_some(index)
    }

    /// Yields `0..total` reordered to match the lexicographic order of the keys
    /// those indices produce.
    ///
    /// One keyspace's inserted keys differ only in the entropy byte and the
    /// big-endian index, so key order is (entropy byte, index): walk the 256
    /// entropy values in byte order and indices in numeric order within each.
    /// The O(256 * total) rescan keeps memory flat so full-range validation can
    /// stream expected keys at any key count.
    pub fn inserted_indices_in_key_order(total: u64) -> impl Iterator<Item = u64> {
        (0..=u8::MAX).flat_map(move |entropy| {
            (0..total).filter(move |index| entropy_byte(*index) == entropy)
        })
    }

    fn key(&self, index: u64, domain: u8) -> anyhow::Result<Key> {
        ensure!(
            self.key_len >= min_key_len(self.namespace.len()),
            "keyspace key_len is too small for namespace"
        );

        // Layout: entropy byte, namespace length, namespace bytes, domain byte,
        // big-endian index, mixed suffix.
        let mut key = vec![0u8; self.key_len];
        key[0] = entropy_byte(index);

        let namespace_start = ENTROPY_BYTES + NAMESPACE_LEN_BYTES;
        let namespace_end = namespace_start + self.namespace.len();
        key[ENTROPY_BYTES] = self.namespace.len() as u8;
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

/// First physical byte of every generated key.
///
/// Deriving it from the logical index alone spreads keys uniformly across all
/// leading-bit shards while keeping inserted and missing keys for the same
/// index aligned and reproducible.
fn entropy_byte(index: u64) -> u8 {
    mix64(index) as u8
}

fn min_key_len(namespace_len: usize) -> usize {
    ENTROPY_BYTES + NAMESPACE_LEN_BYTES + namespace_len + DOMAIN_BYTES + INDEX_BYTES
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
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn rejects_key_len_too_small_for_namespace() {
        assert!(Keyspace::new(b"namespace".to_vec(), 12).is_err());
    }

    #[test]
    fn inserted_and_missing_domains_stay_disjoint() {
        let keyspace = Keyspace::new(b"test".to_vec(), DEFAULT_KEY_LEN).unwrap();
        let mut seen = HashSet::new();
        for index in 0..64u64 {
            let inserted = keyspace.inserted_key(index).unwrap();
            let missing = keyspace.missing_key(index).unwrap();
            assert_eq!(inserted[0], missing[0]);
            assert!(seen.insert(inserted));
            assert!(seen.insert(missing));
        }
    }

    #[test]
    fn keys_are_reproducible_across_instances() {
        let a = Keyspace::from_u64_namespace(42, DEFAULT_KEY_LEN).unwrap();
        let b = Keyspace::from_u64_namespace(42, DEFAULT_KEY_LEN).unwrap();
        for index in 0..16u64 {
            assert_eq!(
                a.inserted_key(index).unwrap(),
                b.inserted_key(index).unwrap()
            );
            assert_eq!(a.missing_key(index).unwrap(), b.missing_key(index).unwrap());
        }
    }

    #[test]
    fn entropy_byte_spreads_keys_across_all_leading_buckets() {
        let keyspace = Keyspace::unnamespaced(DEFAULT_KEY_LEN).unwrap();
        let buckets: HashSet<u8> = (0..128u64)
            .map(|index| keyspace.inserted_key(index).unwrap()[0] >> 5)
            .collect();
        assert_eq!(buckets.len(), 8);
    }

    #[test]
    fn keys_use_configured_length() {
        let keyspace = Keyspace::unnamespaced(24).unwrap();
        assert_eq!(keyspace.inserted_key(0).unwrap().len(), 24);
    }

    #[test]
    fn u64_namespaces_generate_disjoint_keys() {
        let keyspace_a = Keyspace::from_u64_namespace(100, DEFAULT_KEY_LEN).unwrap();
        let keyspace_b = Keyspace::from_u64_namespace(101, DEFAULT_KEY_LEN).unwrap();
        let a: HashSet<Key> = (0..64u64)
            .map(|index| keyspace_a.inserted_key(index).unwrap())
            .collect();

        assert!((0..64u64).all(|index| !a.contains(&keyspace_b.inserted_key(index).unwrap())));
    }

    #[test]
    fn inserted_indices_in_key_order_matches_key_sort() {
        let keyspace = Keyspace::from_u64_namespace(42, DEFAULT_KEY_LEN).unwrap();
        let total = 300u64;
        let ordered: Vec<Key> = Keyspace::inserted_indices_in_key_order(total)
            .map(|index| keyspace.inserted_key(index).unwrap())
            .collect();

        let mut sorted: Vec<Key> = (0..total)
            .map(|index| keyspace.inserted_key(index).unwrap())
            .collect();
        sorted.sort_unstable();

        assert_eq!(ordered, sorted);
    }

    #[test]
    fn inserted_index_of_round_trips_and_rejects_foreign_keys() {
        let keyspace = Keyspace::from_u64_namespace(7, DEFAULT_KEY_LEN).unwrap();
        for index in [0u64, 1, 255, 1 << 40] {
            let key = keyspace.inserted_key(index).unwrap();
            assert_eq!(keyspace.inserted_index_of(&key), Some(index));
        }

        let missing = keyspace.missing_key(3).unwrap();
        assert_eq!(keyspace.inserted_index_of(&missing), None);

        let other_namespace = Keyspace::from_u64_namespace(8, DEFAULT_KEY_LEN)
            .unwrap()
            .inserted_key(3)
            .unwrap();
        assert_eq!(keyspace.inserted_index_of(&other_namespace), None);

        let other_len = Keyspace::from_u64_namespace(7, 32)
            .unwrap()
            .inserted_key(3)
            .unwrap();
        assert_eq!(keyspace.inserted_index_of(&other_len), None);

        let zeroes = Key::from(vec![0u8; DEFAULT_KEY_LEN]);
        assert_eq!(keyspace.inserted_index_of(&zeroes), None);
    }
}
