// Constants used to derive reproducible pseudo-random-looking bytes. They are
// intentionally fixed because changing them changes benchmark key/value data.
pub(crate) const GOLDEN_RATIO_64: u64 = 0x9E37_79B9_7F4A_7C15;
pub(crate) const FXHASH_MULTIPLIER_64: u64 = 0x517C_C1B7_2722_0A95;

// MurmurHash3 fmix64 avalanche multipliers.
const MURMUR3_FMIX64_MULTIPLIER_1: u64 = 0xFF51_AFD7_ED55_8CCD;
const MURMUR3_FMIX64_MULTIPLIER_2: u64 = 0xC4CE_B9FE_1A85_EC53;

/// Deterministic 64-bit avalanche used for workload data generation.
pub(crate) fn mix64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(MURMUR3_FMIX64_MULTIPLIER_1);
    x ^= x >> 33;
    x = x.wrapping_mul(MURMUR3_FMIX64_MULTIPLIER_2);
    x ^= x >> 33;
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mix64_is_deterministic() {
        assert_eq!(mix64(42), mix64(42));
        assert_ne!(mix64(42), mix64(43));
    }
}
