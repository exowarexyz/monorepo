use anyhow::ensure;

use crate::deterministic::{mix64, FXHASH_MULTIPLIER_64};

/// Default generated value size used by load and benchmark writes.
pub const DEFAULT_VALUE_SIZE: usize = 160;

/// Default guardrail for generated values in validation runs.
pub const DEFAULT_MAX_VALUE_SIZE: usize = 10 * 1024 * 1024;

/// Compatibility limit for deployments that still cap encoded values at u16::MAX.
pub const KV_MK1_COMPAT_MAX_VALUE_SIZE: usize = u16::MAX as usize;

/// Version of the deterministic value generator used by workload reports.
pub const VALUE_GENERATOR_VERSION: u16 = 1;

/// Validates a generated value size against an explicit run-level limit.
pub fn validate_value_size(value_size: usize, max_value_size: usize) -> anyhow::Result<()> {
    ensure!(
        value_size <= max_value_size,
        "value_size must be <= max_value_size ({} > {})",
        value_size,
        max_value_size
    );
    Ok(())
}

/// Returns a deterministic value for a namespace/index pair.
///
/// The bytes are stable for reproducibility, but are not intended to be random
/// or cryptographic.
pub fn value_for_index(namespace: u64, index: u64, value_size: usize) -> Vec<u8> {
    let h1 = mix64(namespace ^ index);
    let h2 = mix64(namespace.rotate_left(13) ^ index.rotate_left(27));
    let seeds = [namespace, index, h1, h2];
    let mut value = vec![0u8; value_size];
    for (chunk_idx, chunk) in value.chunks_mut(8).enumerate() {
        let seed = seeds[chunk_idx % seeds.len()]
            .wrapping_add((chunk_idx as u64).wrapping_mul(FXHASH_MULTIPLIER_64));
        let bytes = seed.to_be_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    value
}

/// Returns a human-inspectable deterministic value for overlap-ledger records.
pub fn overlap_value_for_index(namespace: u64, index: u64) -> Vec<u8> {
    format!("overlap-ledger:{namespace:016x}:{index:016x}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_generation_is_deterministic_and_sized() {
        let value_a = value_for_index(7, 42, 160);
        let value_b = value_for_index(7, 42, 160);
        assert_eq!(value_a, value_b);
        assert_eq!(value_a.len(), 160);
    }

    #[test]
    fn overlap_value_generation_is_deterministic() {
        let value_a = overlap_value_for_index(7, 42);
        let value_b = overlap_value_for_index(7, 42);
        assert_eq!(value_a, value_b);
        assert!(value_a.starts_with(b"overlap-ledger:"));
    }

    #[test]
    fn value_size_limit_is_explicit() {
        assert!(validate_value_size(10, 10).is_ok());
        assert!(validate_value_size(11, 10).is_err());
    }
}
