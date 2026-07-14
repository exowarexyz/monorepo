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

// This prefix cannot be emitted by the spread layout: a spread key with a zero
// namespace length has an inserted or missing domain byte in this position.
const VALIDATION_PREFIX: [u8; 3] = [0xFE, 0x00, 0xFF];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyLayout {
    Spread,
    Validation,
}

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
/// Load and benchmark keys open with entropy derived from the logical index, so
/// stores that shard on leading bits see load on every shard. Validator keys
/// reserve a contiguous region so sampled range checks remain bounded.
///
/// Namespaces isolate runs, domains keep inserted keys disjoint from
/// intentionally-missing ones, and the big-endian index makes every key
/// reproducible from `(namespace, index)`.
#[derive(Clone, Debug)]
pub struct Keyspace {
    namespace: Vec<u8>,
    key_len: usize,
    layout: KeyLayout,
}

impl Keyspace {
    /// Creates a keyspace with explicit namespace bytes and physical key length.
    pub fn new(namespace: Vec<u8>, key_len: usize) -> anyhow::Result<Self> {
        Self::new_with_layout(namespace, key_len, KeyLayout::Spread)
    }

    fn new_with_layout(
        namespace: Vec<u8>,
        key_len: usize,
        layout: KeyLayout,
    ) -> anyhow::Result<Self> {
        validate_key_size(key_len)?;
        ensure!(
            namespace.len() <= u8::MAX as usize,
            "keyspace namespace length must fit in one byte"
        );
        ensure!(
            key_len >= min_key_len(layout, namespace.len()),
            "--key-len must be >= {} for this namespace",
            min_key_len(layout, namespace.len())
        );
        Ok(Self {
            namespace,
            key_len,
            layout,
        })
    }

    pub fn unnamespaced(key_len: usize) -> anyhow::Result<Self> {
        Self::new(Vec::new(), key_len)
    }

    pub fn from_u64_namespace(namespace: u64, key_len: usize) -> anyhow::Result<Self> {
        Self::new(namespace.to_be_bytes().to_vec(), key_len)
    }

    /// Creates a contiguous keyspace reserved for validator-owned records.
    pub fn validation_from_u64_namespace(namespace: u64, key_len: usize) -> anyhow::Result<Self> {
        Self::new_with_layout(
            namespace.to_be_bytes().to_vec(),
            key_len,
            KeyLayout::Validation,
        )
    }

    /// Returns the namespace bytes embedded in every generated key.
    pub fn namespace(&self) -> &[u8] {
        &self.namespace
    }

    /// Returns the configured physical key length.
    pub fn key_len(&self) -> usize {
        self.key_len
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
    /// Regenerating the key rejects other namespaces, domains, and layouts.
    pub fn inserted_index_of(&self, key: &Key) -> Option<u64> {
        if key.len() != self.key_len {
            return None;
        }
        let index_start = self.namespace_start() + self.namespace.len() + DOMAIN_BYTES;
        let index_bytes = key.as_ref().get(index_start..index_start + INDEX_BYTES)?;
        let index = u64::from_be_bytes(index_bytes.try_into().expect("slice is INDEX_BYTES long"));

        let expected = self.inserted_key(index).ok()?;
        (expected == *key).then_some(index)
    }

    /// Yields `0..total` reordered to match spread-key lexicographic order.
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
            self.key_len >= min_key_len(self.layout, self.namespace.len()),
            "keyspace key_len is too small for namespace"
        );

        let mut key = vec![0u8; self.key_len];
        let namespace_start = self.namespace_start();
        match self.layout {
            KeyLayout::Spread => {
                // Leading entropy keeps the benchmark and load phases balanced across shards.
                key[0] = entropy_byte(index);
                key[ENTROPY_BYTES] = self.namespace.len() as u8;
            }
            KeyLayout::Validation => {
                // A fixed prefix keeps validator range samples bounded to their own run.
                key[..VALIDATION_PREFIX.len()].copy_from_slice(&VALIDATION_PREFIX);
                key[VALIDATION_PREFIX.len()] = self.namespace.len() as u8;
            }
        }
        let namespace_end = namespace_start + self.namespace.len();
        key[namespace_start..namespace_end].copy_from_slice(&self.namespace);

        let domain_offset = namespace_end;
        key[domain_offset] = domain;

        let index_start = domain_offset + DOMAIN_BYTES;
        let index_end = index_start + INDEX_BYTES;
        key[index_start..index_end].copy_from_slice(&index.to_be_bytes());

        fill_suffix(
            &mut key[index_end..],
            mix64(
                namespace_hash(&self.namespace)
                    ^ index
                    ^ u64::from(domain)
                    ^ match self.layout {
                        KeyLayout::Spread => 0,
                        KeyLayout::Validation => GOLDEN_RATIO_64,
                    },
            ),
        );
        Ok(Key::from(key))
    }

    fn namespace_start(&self) -> usize {
        match self.layout {
            KeyLayout::Spread => ENTROPY_BYTES + NAMESPACE_LEN_BYTES,
            KeyLayout::Validation => VALIDATION_PREFIX.len() + NAMESPACE_LEN_BYTES,
        }
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

fn min_key_len(layout: KeyLayout, namespace_len: usize) -> usize {
    let prefix_len = match layout {
        KeyLayout::Spread => ENTROPY_BYTES,
        KeyLayout::Validation => VALIDATION_PREFIX.len(),
    };
    prefix_len + NAMESPACE_LEN_BYTES + namespace_len + DOMAIN_BYTES + INDEX_BYTES
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

    #[test]
    fn validation_keys_are_contiguous_and_disjoint_from_spread_keys() {
        let validation = Keyspace::validation_from_u64_namespace(7, DEFAULT_KEY_LEN).unwrap();
        let spread = Keyspace::from_u64_namespace(7, DEFAULT_KEY_LEN).unwrap();
        let unnamespaced_spread = Keyspace::unnamespaced(DEFAULT_KEY_LEN).unwrap();

        let ordered: Vec<Key> = (0..64u64)
            .map(|index| validation.inserted_key(index).unwrap())
            .collect();
        let mut sorted = ordered.clone();
        sorted.sort_unstable();
        assert_eq!(ordered, sorted);

        for index in 0..64u64 {
            let validation_key = validation.inserted_key(index).unwrap();
            assert_eq!(
                &validation_key[..VALIDATION_PREFIX.len()],
                VALIDATION_PREFIX
            );
            assert_ne!(
                &spread.inserted_key(index).unwrap()[..VALIDATION_PREFIX.len()],
                VALIDATION_PREFIX
            );
            assert_ne!(
                &unnamespaced_spread.inserted_key(index).unwrap()[..VALIDATION_PREFIX.len()],
                VALIDATION_PREFIX
            );
        }
    }
}
