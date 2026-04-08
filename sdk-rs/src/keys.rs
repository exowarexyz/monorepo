use bytes::{Bytes, BytesMut};

/// Maximum physical key length in bytes.
///
/// The storage stack is intentionally non-backwards-compatible with prior
/// fixed-width key formats. All keys must now fit in a single `u8` length
/// field, so the largest valid key is 254 bytes.
pub const MAX_KEY_LEN: usize = 254;

/// Maximum key scratch width retained for stack buffers and legacy callers.
///
/// This is no longer a fixed physical key width. It is simply the largest
/// valid key length in bytes.
pub const KEY_SIZE: usize = MAX_KEY_LEN;

/// Minimum physical key length in bytes.
pub const MIN_KEY_LEN: usize = 0;

/// A store key. Variable-length, lexicographically ordered raw bytes.
///
/// Stored as [`Bytes`] so keys can share backing storage (e.g. RPC wire buffers via
/// [`bytes::Bytes::slice_ref`]) without copying.
pub type Key = Bytes;

/// Mutable buffer used while constructing a key with [`KeyCodec`]. Freeze to [`Key`] with
/// [`Bytes::from`] / [`BytesMut::freeze`] when done mutating.
pub type KeyMut = BytesMut;

/// A store value. Variable length.
pub type Value = Bytes;

/// Errors returned by key-length validation helpers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyValidationError {
    #[error("key length {len} exceeds max {max}")]
    TooLong { len: usize, max: usize },
}

/// Errors returned by [`KeyCodec`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyCodecError {
    #[error("key length {len} is outside valid range [{min}, {max}]")]
    InvalidKeyLength { len: usize, min: usize, max: usize },
    #[error("payload length {payload_len} exceeds codec capacity {max_payload_len}")]
    PayloadTooLarge {
        payload_len: usize,
        max_payload_len: usize,
    },
    #[error("payload range offset={offset} len={len} exceeds codec capacity {max_payload_len}")]
    PayloadRangeOutOfBounds {
        offset: usize,
        len: usize,
        max_payload_len: usize,
    },
    #[error("key does not match this codec prefix")]
    PrefixMismatch,
}

/// Bit-packed key layout: a small prefix id in the leading reserved bits, payload in the remainder.
///
/// For example, with 4 reserved bits the first nibble selects the prefix and the rest of the key
/// carries the encoded logical payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyCodec {
    reserved_bits: u8,
    prefix: u16,
}

impl KeyCodec {
    /// Build a codec with `reserved_bits` high bits reserved for `prefix`.
    pub const fn new(reserved_bits: u8, prefix: u16) -> Self {
        assert!(reserved_bits <= 16, "reserved bits must be <= 16");
        let max_prefix = prefix_bit_mask(reserved_bits);
        assert!(prefix <= max_prefix, "prefix does not fit in reserved bits");
        Self {
            reserved_bits,
            prefix,
        }
    }

    /// The number of reserved high bits at the start of the key.
    #[inline]
    pub const fn reserved_bits(self) -> u8 {
        self.reserved_bits
    }

    /// Family id stored in the reserved high bits.
    #[inline]
    pub const fn prefix(self) -> u16 {
        self.prefix
    }

    /// Minimum key length in bytes needed to store this codec's reserved bits.
    #[inline]
    pub const fn min_key_len(self) -> usize {
        (self.reserved_bits as usize).div_ceil(8)
    }

    /// Maximum logical payload bytes that can ever fit under this codec.
    #[inline]
    pub const fn max_payload_capacity_bytes(self) -> usize {
        ((MAX_KEY_LEN * 8) - self.reserved_bits as usize) / 8
    }

    /// Maximum logical payload bytes that fit under this codec.
    ///
    /// This reflects the global physical key cap rather than a per-key fixed
    /// width. Families that need an exact key length should use
    /// [`Self::payload_capacity_bytes_for_key_len`].
    #[inline]
    pub const fn payload_capacity_bytes(self) -> usize {
        self.max_payload_capacity_bytes()
    }

    /// Maximum logical payload bytes that fit in a key of `key_len` bytes.
    #[inline]
    pub const fn payload_capacity_bytes_for_key_len(self, key_len: usize) -> usize {
        ((key_len * 8).saturating_sub(self.reserved_bits as usize)) / 8
    }

    /// Smallest physical key length that can store `payload_len` bytes.
    #[inline]
    pub const fn min_key_len_for_payload(self, payload_len: usize) -> usize {
        (self.reserved_bits as usize + payload_len * 8).div_ceil(8)
    }

    /// Absolute bit offset for a payload byte offset within the physical key.
    #[inline]
    pub const fn payload_bit_offset(self, payload_byte_offset: usize) -> usize {
        self.reserved_bits as usize + (payload_byte_offset * 8)
    }

    /// Create a zero-filled key buffer with the prefix id written in the reserved bits.
    pub fn new_key_with_len(self, total_bytes: usize) -> Result<KeyMut, KeyCodecError> {
        self.validate_key_len(total_bytes)?;
        let mut key = BytesMut::with_capacity(total_bytes);
        key.resize(total_bytes, 0);
        write_prefix_bits(&mut key, self.reserved_bits, self.prefix);
        Ok(key)
    }

    /// Create the shortest zero-filled key for this prefix.
    pub fn new_key(self) -> Key {
        Bytes::from(
            self.new_key_with_len(self.min_key_len())
                .expect("minimum codec key length must always be valid"),
        )
    }

    /// Encode an entire logical payload into a physical key.
    pub fn encode(self, payload: &[u8]) -> Result<Key, KeyCodecError> {
        let max_payload_len = self.max_payload_capacity_bytes();
        if payload.len() > max_payload_len {
            return Err(KeyCodecError::PayloadTooLarge {
                payload_len: payload.len(),
                max_payload_len,
            });
        }
        let mut key = self.new_key_with_len(self.min_key_len_for_payload(payload.len()))?;
        self.write_payload(&mut key, 0, payload)?;
        Ok(key.freeze())
    }

    /// Decode `payload_len` bytes from a key that belongs to this codec.
    pub fn decode(self, key: &Key, payload_len: usize) -> Result<Vec<u8>, KeyCodecError> {
        if !self.matches(key) {
            return Err(KeyCodecError::PrefixMismatch);
        }
        self.read_payload(key, 0, payload_len)
    }

    /// Write logical payload bytes at a byte offset within the shifted payload.
    pub fn write_payload(
        self,
        key: &mut KeyMut,
        payload_byte_offset: usize,
        bytes: &[u8],
    ) -> Result<(), KeyCodecError> {
        self.ensure_payload_range(key.len(), payload_byte_offset, bytes.len())?;
        let start_bit = self.payload_bit_offset(payload_byte_offset);
        write_bits_from_bytes(key, start_bit, bytes, bytes.len() * 8);
        Ok(())
    }

    /// Fill a payload byte range with a repeated byte value.
    pub fn fill_payload(
        self,
        key: &mut KeyMut,
        payload_byte_offset: usize,
        len: usize,
        value: u8,
    ) -> Result<(), KeyCodecError> {
        self.ensure_payload_range(key.len(), payload_byte_offset, len)?;
        if len == 0 {
            return Ok(());
        }
        self.write_payload(key, payload_byte_offset, &vec![value; len])
    }

    /// Read logical payload bytes at a byte offset within the shifted payload.
    pub fn read_payload(
        self,
        key: &Key,
        payload_byte_offset: usize,
        len: usize,
    ) -> Result<Vec<u8>, KeyCodecError> {
        self.ensure_payload_range(key.len(), payload_byte_offset, len)?;
        let start_bit = self.payload_bit_offset(payload_byte_offset);
        let mut out = vec![0u8; len];
        read_bits_to_bytes(key, start_bit, &mut out, len * 8);
        Ok(out)
    }

    /// Read an exact-size payload slice into an array.
    pub fn read_payload_exact<const N: usize>(
        self,
        key: &Key,
        payload_byte_offset: usize,
    ) -> Result<[u8; N], KeyCodecError> {
        let bytes = self.read_payload(key, payload_byte_offset, N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    /// Copy payload bytes from one codec-managed key into another.
    pub fn copy_payload(
        self,
        src: &Key,
        src_payload_byte_offset: usize,
        dst: &mut KeyMut,
        dst_payload_byte_offset: usize,
        len: usize,
    ) -> Result<(), KeyCodecError> {
        let bytes = self.read_payload(src, src_payload_byte_offset, len)?;
        self.write_payload(dst, dst_payload_byte_offset, &bytes)
    }

    /// True when the key belongs to this codec prefix.
    #[inline]
    pub fn matches(self, key: &Key) -> bool {
        key.len() >= self.min_key_len() && read_prefix_bits(key, self.reserved_bits) == self.prefix
    }

    /// Inclusive lower and upper bounds for keys in this prefix with a fixed byte length.
    pub fn prefix_bounds_for_len(self, total_bytes: usize) -> Result<(Key, Key), KeyCodecError> {
        self.validate_key_len(total_bytes)?;
        let mut start = vec![0u8; total_bytes];
        let mut end = vec![0xFFu8; total_bytes];
        write_prefix_bits(&mut start, self.reserved_bits, self.prefix);
        write_prefix_bits(&mut end, self.reserved_bits, self.prefix);
        Ok((Bytes::from(start), Bytes::from(end)))
    }

    /// Inclusive lower and upper bounds for this prefix across the full supported key-length domain.
    pub fn prefix_bounds(self) -> (Key, Key) {
        let start = Bytes::from(
            self.new_key_with_len(self.min_key_len())
                .expect("minimum codec key length must always be valid"),
        );
        let mut end = vec![0xFFu8; MAX_KEY_LEN];
        write_prefix_bits(&mut end, self.reserved_bits, self.prefix);
        (start, Bytes::from(end))
    }

    fn validate_key_len(self, len: usize) -> Result<(), KeyCodecError> {
        if !(MIN_KEY_LEN..=MAX_KEY_LEN).contains(&len) || len < self.min_key_len() {
            return Err(KeyCodecError::InvalidKeyLength {
                len,
                min: self.min_key_len(),
                max: MAX_KEY_LEN,
            });
        }
        Ok(())
    }

    fn ensure_payload_range(
        self,
        key_len: usize,
        offset: usize,
        len: usize,
    ) -> Result<(), KeyCodecError> {
        self.validate_key_len(key_len)?;
        let max_payload_len = self.payload_capacity_bytes_for_key_len(key_len);
        if offset.saturating_add(len) > max_payload_len {
            return Err(KeyCodecError::PayloadRangeOutOfBounds {
                offset,
                len,
                max_payload_len,
            });
        }
        Ok(())
    }
}

/// True when a key size is valid for ingest/storage.
#[inline]
pub fn is_valid_key_size(size: usize) -> bool {
    (MIN_KEY_LEN..=MAX_KEY_LEN).contains(&size)
}

/// Validate a key length against the store's physical key limits.
#[inline]
pub fn validate_key_size(size: usize) -> Result<(), KeyValidationError> {
    if is_valid_key_size(size) {
        Ok(())
    } else {
        Err(KeyValidationError::TooLong {
            len: size,
            max: MAX_KEY_LEN,
        })
    }
}

/// Return the smallest valid key strictly greater than `key`.
///
/// Lexicographic ordering on variable-length byte strings means appending a
/// trailing `0x00` is the immediate successor whenever the key is shorter than
/// `MAX_KEY_LEN`.
pub fn next_key(key: &Key) -> Option<Key> {
    if key.len() < MAX_KEY_LEN {
        let mut out = key.to_vec();
        out.push(0);
        return Some(Bytes::from(out));
    }

    let mut out = key.to_vec();
    for idx in (0..out.len()).rev() {
        if out[idx] != u8::MAX {
            out[idx] += 1;
            out.truncate(idx + 1);
            return Some(Bytes::from(out));
        }
    }
    None
}

#[inline]
const fn prefix_bit_mask(bits: u8) -> u16 {
    if bits == 0 {
        0
    } else if bits >= 16 {
        u16::MAX
    } else {
        (1u16 << bits) - 1
    }
}

fn write_prefix_bits(key: &mut [u8], reserved_bits: u8, prefix: u16) {
    for bit_idx in 0..reserved_bits as usize {
        let shift = reserved_bits as usize - 1 - bit_idx;
        let value = ((prefix >> shift) & 1) != 0;
        write_bit_be(key, bit_idx, value);
    }
}

fn read_prefix_bits(key: &Key, reserved_bits: u8) -> u16 {
    let mut prefix = 0u16;
    for bit_idx in 0..reserved_bits as usize {
        prefix <<= 1;
        if read_bit_be(key, bit_idx) {
            prefix |= 1;
        }
    }
    prefix
}

pub(crate) fn write_bits_from_bytes(
    dst: &mut [u8],
    dst_bit_offset: usize,
    src: &[u8],
    bit_len: usize,
) {
    for bit_idx in 0..bit_len {
        let value = read_bit_be(src, bit_idx);
        write_bit_be(dst, dst_bit_offset + bit_idx, value);
    }
}

pub(crate) fn read_bits_to_bytes(
    src: &[u8],
    src_bit_offset: usize,
    dst: &mut [u8],
    bit_len: usize,
) {
    dst.fill(0);
    for bit_idx in 0..bit_len {
        let value = read_bit_be(src, src_bit_offset + bit_idx);
        write_bit_be(dst, bit_idx, value);
    }
}

pub(crate) fn read_bit_be(bytes: &[u8], bit_idx: usize) -> bool {
    let byte_idx = bit_idx / 8;
    let bit_in_byte = 7 - (bit_idx % 8);
    bytes
        .get(byte_idx)
        .is_some_and(|byte| ((byte >> bit_in_byte) & 1) != 0)
}

pub(crate) fn write_bit_be(bytes: &mut [u8], bit_idx: usize, value: bool) {
    let byte_idx = bit_idx / 8;
    let bit_in_byte = 7 - (bit_idx % 8);
    let mask = 1 << bit_in_byte;
    if let Some(byte) = bytes.get_mut(byte_idx) {
        if value {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }
}

/// Target block size for each tier.
pub fn target_block_size(tier: u8) -> usize {
    const KB: usize = 1024;
    const MB: usize = 1024 * KB;
    const GB: usize = 1024 * MB;
    match tier {
        0 => 64 * MB,
        1 => 128 * MB,
        2 => 256 * MB,
        3 => 512 * MB,
        4 => GB,
        5 => 2 * GB,
        _ => 2 * GB,
    }
}

/// Sub-block size: fixed at 64KB uncompressed across all tiers.
///
/// We compress sub-blocks from this fixed logical size so every decoded chunk
/// has a small, known upper bound. That keeps compaction and other merge/decode
/// paths incremental instead of materializing huge blocks in memory, which
/// avoids OOM risk. It also limits waste on point lookups: a cache miss fetches
/// and decompresses only one small slice instead of an entire large block,
/// improving cache granularity. Range scans still coalesce adjacent sub-blocks
/// into larger range GETs, so we keep fine-grained point reads without forcing
/// one network request per sub-block on sequential reads.
pub const SUB_BLOCK_SIZE: usize = 64 * 1024;

/// Bloom filter bits per key by tier.
pub fn bloom_bits_per_key(tier: u8) -> Option<u32> {
    match tier {
        0 => Some(14),
        1..=3 => Some(10),
        _ => None, // T4-T5: no bloom
    }
}

/// Compute tier from block age.
pub fn compute_tier(age: chrono::Duration) -> u8 {
    if age < chrono::Duration::hours(4) {
        0
    } else if age < chrono::Duration::hours(12) {
        1
    } else if age < chrono::Duration::hours(36) {
        2
    } else if age < chrono::Duration::days(4) {
        3
    } else if age < chrono::Duration::days(30) {
        4
    } else {
        5
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_codec_uses_4_reserved_bits_plus_payload() {
        let codec = KeyCodec::new(4, 0x5);
        let key = codec.encode(&[0xAB, 0xCD]).expect("encoded key");
        assert_eq!(key[0], 0x5A);
        assert_eq!(key[1], 0xBC);
        assert_eq!(
            codec.decode(&key, 2).expect("decoded payload"),
            vec![0xAB, 0xCD]
        );
    }

    #[test]
    fn key_codec_preserves_payload_order_within_prefix() {
        let codec = KeyCodec::new(4, 0x3);
        let lower = codec.encode(&[0x10, 0x00]).expect("lower key");
        let mid = codec.encode(&[0x10, 0x01]).expect("mid key");
        let upper = codec.encode(&[0x20, 0x00]).expect("upper key");
        assert!(lower < mid);
        assert!(mid < upper);
    }

    #[test]
    fn key_codec_prefix_bounds_cover_only_one_prefix() {
        let codec = KeyCodec::new(4, 0xA);
        let (start, end) = codec.prefix_bounds();
        let key = codec.encode(&[0x11, 0x22]).expect("prefix key");
        assert!(codec.matches(&start));
        assert!(codec.matches(&end));
        assert!(codec.matches(&key));
        assert!(start <= key && key <= end);

        let other = KeyCodec::new(4, 0xB)
            .encode(&[0x11, 0x22])
            .expect("other key");
        assert!(!codec.matches(&other));
        assert!(other > end || other < start);
        assert!(start <= end);
    }

    #[test]
    fn key_codec_reads_and_writes_payload_at_byte_offsets() {
        let codec = KeyCodec::new(3, 0b101);
        let mut key = codec.new_key_with_len(4).expect("new key");
        codec
            .write_payload(&mut key, 0, &[0xDE, 0xAD])
            .expect("write head");
        codec
            .write_payload(&mut key, 2, &[0xBE])
            .expect("write tail");
        assert_eq!(
            codec
                .read_payload(&key.freeze(), 0, 3)
                .expect("read payload"),
            vec![0xDE, 0xAD, 0xBE]
        );
    }

    #[test]
    #[should_panic(expected = "prefix does not fit in reserved bits")]
    fn key_codec_rejects_out_of_range_prefix() {
        KeyCodec::new(3, 0b1000);
    }

    #[test]
    fn key_codec_rejects_oversized_payload() {
        let codec = KeyCodec::new(4, 0);
        let payload = vec![0u8; codec.max_payload_capacity_bytes() + 1];
        let err = codec.encode(&payload).expect_err("payload should not fit");
        assert!(matches!(err, KeyCodecError::PayloadTooLarge { .. }));
    }

    #[test]
    fn next_key_prefers_append_zero_for_short_keys() {
        assert_eq!(
            next_key(&Bytes::from(vec![0x12, 0x34])),
            Some(Bytes::from(vec![0x12, 0x34, 0x00]))
        );
    }

    #[test]
    fn next_key_carries_when_at_max_length() {
        let mut key = vec![0u8; MAX_KEY_LEN];
        key[MAX_KEY_LEN - 2] = 0x12;
        key[MAX_KEY_LEN - 1] = 0xFF;
        let key = Bytes::from(key);
        let next = next_key(&key).expect("next");
        assert_eq!(next.len(), MAX_KEY_LEN - 1);
        assert_eq!(next[MAX_KEY_LEN - 2], 0x13);
    }

    #[test]
    fn key_size_validation_bounds() {
        assert!(validate_key_size(0).is_ok());
        assert!(validate_key_size(MAX_KEY_LEN).is_ok());
        assert!(validate_key_size(MAX_KEY_LEN + 1).is_err());
    }

    #[test]
    fn tier_assignment() {
        assert_eq!(compute_tier(chrono::Duration::minutes(30)), 0);
        assert_eq!(compute_tier(chrono::Duration::hours(6)), 1);
        assert_eq!(compute_tier(chrono::Duration::hours(24)), 2);
        assert_eq!(compute_tier(chrono::Duration::days(3)), 3);
        assert_eq!(compute_tier(chrono::Duration::days(15)), 4);
        assert_eq!(compute_tier(chrono::Duration::days(60)), 5);
    }

}
