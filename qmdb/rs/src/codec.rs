use commonware_codec::DecodeExt;
use commonware_cryptography::Digest;
use commonware_storage::merkle::{Family, Location, Position};
use exoware_sdk::keys::{Key, KeyCodec};

use crate::error::QmdbError;
use crate::MAX_OPERATION_SIZE;

pub(crate) const RESERVED_BITS: u8 = 4;
pub(crate) const UPDATE_FAMILY: u16 = 0x1;
pub(crate) const PRESENCE_FAMILY: u16 = 0x2;
pub(crate) const WATERMARK_FAMILY: u16 = 0x3;
pub(crate) const OP_FAMILY: u16 = 0x4;
pub(crate) const NODE_FAMILY: u16 = 0x5;
pub(crate) const GRAFTED_NODE_FAMILY: u16 = 0x6;
pub(crate) const CHUNK_FAMILY: u16 = 0x7;
pub(crate) const CURRENT_META_FAMILY: u16 = 0x8;
pub(crate) const OPS_ROOT_WITNESS_FAMILY: u16 = 0x9;

pub(crate) const UPDATE_VERSION_LEN: usize = 8;
const UPDATE_INDEX_INACTIVE: u8 = 0;
const UPDATE_INDEX_ACTIVE: u8 = 1;
pub(crate) const ORDERED_KEY_ESCAPE_BYTE: u8 = 0x00;
pub(crate) const ORDERED_KEY_ZERO_ESCAPE: u8 = 0xFF;
pub(crate) const ORDERED_KEY_TERMINATOR_LEN: usize = 2;

pub(crate) const UPDATE_CODEC: KeyCodec = KeyCodec::new(RESERVED_BITS, UPDATE_FAMILY);
pub(crate) const PRESENCE_CODEC: KeyCodec = KeyCodec::new(RESERVED_BITS, PRESENCE_FAMILY);
pub(crate) const WATERMARK_CODEC: KeyCodec = KeyCodec::new(RESERVED_BITS, WATERMARK_FAMILY);
pub(crate) const OPERATION_CODEC: KeyCodec = KeyCodec::new(RESERVED_BITS, OP_FAMILY);
pub(crate) const NODE_CODEC: KeyCodec = KeyCodec::new(RESERVED_BITS, NODE_FAMILY);
pub(crate) const CURRENT_META_CODEC: KeyCodec = KeyCodec::new(RESERVED_BITS, CURRENT_META_FAMILY);
pub(crate) const GRAFTED_NODE_CODEC: KeyCodec = KeyCodec::new(RESERVED_BITS, GRAFTED_NODE_FAMILY);
pub(crate) const CHUNK_CODEC: KeyCodec = KeyCodec::new(RESERVED_BITS, CHUNK_FAMILY);
pub(crate) const OPS_ROOT_WITNESS_CODEC: KeyCodec =
    KeyCodec::new(RESERVED_BITS, OPS_ROOT_WITNESS_FAMILY);

pub(crate) const fn bitmap_chunk_bits<const N: usize>() -> u64 {
    (N as u64) * 8
}

pub(crate) fn chunk_index_for_location<F: Family, const N: usize>(location: Location<F>) -> u64 {
    *location / bitmap_chunk_bits::<N>()
}

pub(crate) fn decode_digest<D: Digest>(
    bytes: &[u8],
    label: impl std::fmt::Display,
) -> Result<D, QmdbError> {
    D::decode(bytes).map_err(|e| QmdbError::CorruptData(format!("{label} decode error: {e}")))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CurrentBoundaryMetadata<D: Digest> {
    pub(crate) root: D,
    pub(crate) pruned_chunks: u64,
}

impl<D: Digest> commonware_codec::Write for CurrentBoundaryMetadata<D> {
    fn write(&self, buf: &mut impl ::bytes::BufMut) {
        <(D, u64) as commonware_codec::Write>::write(&(self.root, self.pruned_chunks), buf);
    }
}

impl<D: Digest> commonware_codec::FixedSize for CurrentBoundaryMetadata<D> {
    const SIZE: usize =
        <D as commonware_codec::FixedSize>::SIZE + <u64 as commonware_codec::FixedSize>::SIZE;
}

impl<D: Digest> commonware_codec::Read for CurrentBoundaryMetadata<D> {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl ::bytes::Buf,
        _: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let (root, pruned_chunks) = <(D, u64) as commonware_codec::Read>::read_cfg(buf, &((), ()))?;
        Ok(CurrentBoundaryMetadata {
            root,
            pruned_chunks,
        })
    }
}

pub(crate) fn decode_current_boundary_metadata<D: Digest>(
    bytes: &[u8],
    label: impl std::fmt::Display,
) -> Result<CurrentBoundaryMetadata<D>, QmdbError> {
    CurrentBoundaryMetadata::<D>::decode(bytes)
        .map_err(|e| QmdbError::CorruptData(format!("{label} decode error: {e}")))
}

pub(crate) fn merkle_size_for_watermark<F: Family>(
    watermark: Location<F>,
) -> Result<Position<F>, QmdbError> {
    let leaves = watermark
        .checked_add(1)
        .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
    Position::try_from(leaves)
        .map_err(|e| QmdbError::CorruptData(format!("invalid merkle size for watermark: {e}")))
}

pub(crate) fn ensure_encoded_value_size(len: usize) -> Result<(), QmdbError> {
    if len <= MAX_OPERATION_SIZE {
        Ok(())
    } else {
        Err(QmdbError::EncodedValueTooLarge {
            len,
            max: MAX_OPERATION_SIZE,
        })
    }
}

pub(crate) fn ordered_key_encoded_len(raw_key: &[u8]) -> usize {
    raw_key.len()
        + raw_key
            .iter()
            .filter(|&&byte| byte == ORDERED_KEY_ESCAPE_BYTE)
            .count()
        + ORDERED_KEY_TERMINATOR_LEN
}

pub(crate) fn encode_ordered_key_bytes(raw_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ordered_key_encoded_len(raw_key));
    for &byte in raw_key {
        if byte == ORDERED_KEY_ESCAPE_BYTE {
            out.push(ORDERED_KEY_ESCAPE_BYTE);
            out.push(ORDERED_KEY_ZERO_ESCAPE);
        } else {
            out.push(byte);
        }
    }
    out.push(ORDERED_KEY_ESCAPE_BYTE);
    out.push(ORDERED_KEY_ESCAPE_BYTE);
    out
}

pub(crate) fn validate_ordered_key_bytes(bytes: &[u8], label: &str) -> Result<(), QmdbError> {
    if bytes.len() < ORDERED_KEY_TERMINATOR_LEN {
        return Err(QmdbError::CorruptData(format!(
            "{label} shorter than ordered-key terminator"
        )));
    }
    let mut idx = 0usize;
    let end = bytes.len() - ORDERED_KEY_TERMINATOR_LEN;
    while idx < end {
        if bytes[idx] == ORDERED_KEY_ESCAPE_BYTE {
            match bytes.get(idx + 1) {
                Some(&ORDERED_KEY_ZERO_ESCAPE) => idx += 2,
                Some(_) => {
                    return Err(QmdbError::CorruptData(format!(
                        "{label} contains invalid ordered-key escape"
                    )))
                }
                None => {
                    return Err(QmdbError::CorruptData(format!(
                        "{label} truncated in ordered-key escape"
                    )))
                }
            }
        } else {
            idx += 1;
        }
    }
    if bytes[end] != ORDERED_KEY_ESCAPE_BYTE || bytes[end + 1] != ORDERED_KEY_ESCAPE_BYTE {
        return Err(QmdbError::CorruptData(format!(
            "{label} missing ordered-key terminator"
        )));
    }
    Ok(())
}

pub(crate) fn decode_ordered_key_bytes(bytes: &[u8]) -> Result<Vec<u8>, QmdbError> {
    validate_ordered_key_bytes(bytes, "update key")?;
    let mut out = Vec::with_capacity(bytes.len().saturating_sub(ORDERED_KEY_TERMINATOR_LEN));
    let end = bytes.len() - ORDERED_KEY_TERMINATOR_LEN;
    let mut idx = 0usize;
    while idx < end {
        if bytes[idx] == ORDERED_KEY_ESCAPE_BYTE {
            out.push(ORDERED_KEY_ESCAPE_BYTE);
            idx += 2;
        } else {
            out.push(bytes[idx]);
            idx += 1;
        }
    }
    Ok(out)
}

pub(crate) fn encode_ordered_update_payload(
    codec: KeyCodec,
    raw_key: &[u8],
    fixed_suffix_len: usize,
) -> Result<Vec<u8>, QmdbError> {
    let encoded = encode_ordered_key_bytes(raw_key);
    let payload_len = encoded.len() + fixed_suffix_len;
    let max = codec.max_payload_capacity_bytes();
    if payload_len > max {
        return Err(QmdbError::SortableKeyTooLarge {
            raw_len: raw_key.len(),
            encoded_len: payload_len,
            max,
        });
    }
    Ok(encoded)
}

pub(crate) fn encode_update_key<F: Family>(
    raw_key: &[u8],
    location: Location<F>,
) -> Result<Key, QmdbError> {
    let codec = UPDATE_CODEC;
    let ordered_key = encode_ordered_update_payload(codec, raw_key, UPDATE_VERSION_LEN)?;
    let total_len = codec.min_key_len_for_payload(ordered_key.len() + UPDATE_VERSION_LEN);
    let mut key = codec
        .new_key_with_len(total_len)
        .expect("update key length should fit");
    codec
        .write_payload(&mut key, 0, &ordered_key)
        .expect("update key bytes fit");
    codec
        .write_payload(
            &mut key,
            ordered_key.len(),
            &location.as_u64().to_be_bytes(),
        )
        .expect("update location fits");
    Ok(key.freeze())
}

pub(crate) fn decode_update_location<F: Family>(key: &Key) -> Result<Location<F>, QmdbError> {
    let codec = UPDATE_CODEC;
    if !codec.matches(key) {
        return Err(QmdbError::CorruptData(
            "update key prefix mismatch".to_string(),
        ));
    }
    let payload_capacity = codec.payload_capacity_bytes_for_key_len(key.len());
    if payload_capacity < ORDERED_KEY_TERMINATOR_LEN + UPDATE_VERSION_LEN {
        return Err(QmdbError::CorruptData(
            "update key payload shorter than minimum layout".to_string(),
        ));
    }
    let ordered_len = payload_capacity - UPDATE_VERSION_LEN;
    let ordered_key = codec
        .read_payload(key, 0, ordered_len)
        .map_err(|e| QmdbError::CorruptData(format!("cannot decode update key bytes: {e}")))?;
    validate_ordered_key_bytes(&ordered_key, "update key")?;
    let bytes = codec
        .read_payload_exact::<8>(key, ordered_len)
        .map_err(|e| QmdbError::CorruptData(format!("cannot decode update location: {e}")))?;
    Ok(Location::new(u64::from_be_bytes(bytes)))
}

pub(crate) fn decode_update_raw_key(key: &Key) -> Result<Vec<u8>, QmdbError> {
    let codec = UPDATE_CODEC;
    if !codec.matches(key) {
        return Err(QmdbError::CorruptData(
            "update key prefix mismatch".to_string(),
        ));
    }
    let payload_capacity = codec.payload_capacity_bytes_for_key_len(key.len());
    if payload_capacity < ORDERED_KEY_TERMINATOR_LEN + UPDATE_VERSION_LEN {
        return Err(QmdbError::CorruptData(
            "update key payload shorter than minimum layout".to_string(),
        ));
    }
    let ordered_len = payload_capacity - UPDATE_VERSION_LEN;
    let ordered_key = codec
        .read_payload(key, 0, ordered_len)
        .map_err(|e| QmdbError::CorruptData(format!("cannot decode update key bytes: {e}")))?;
    decode_ordered_key_bytes(&ordered_key)
}

pub(crate) fn encode_update_index_value(value_present: bool) -> Vec<u8> {
    vec![if value_present {
        UPDATE_INDEX_ACTIVE
    } else {
        UPDATE_INDEX_INACTIVE
    }]
}

pub(crate) fn decode_update_index_value_present(bytes: &[u8]) -> Result<bool, QmdbError> {
    match bytes {
        [UPDATE_INDEX_INACTIVE] => Ok(false),
        [UPDATE_INDEX_ACTIVE] => Ok(true),
        _ => Err(QmdbError::CorruptData(format!(
            "update index value has unexpected length {}",
            bytes.len()
        ))),
    }
}

pub(crate) fn encode_presence_key<F: Family>(latest_location: Location<F>) -> Key {
    let codec = PRESENCE_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("presence key length should fit");
    codec
        .write_payload(&mut key, 0, &latest_location.as_u64().to_be_bytes())
        .expect("presence latest location fits");
    key.freeze()
}

pub(crate) fn encode_watermark_key<F: Family>(location: Location<F>) -> Key {
    let codec = WATERMARK_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("watermark key length should fit");
    codec
        .write_payload(&mut key, 0, &location.as_u64().to_be_bytes())
        .expect("watermark location fits");
    key.freeze()
}

pub(crate) fn decode_watermark_location<F: Family>(key: &Key) -> Result<Location<F>, QmdbError> {
    let codec = WATERMARK_CODEC;
    if !codec.matches(key) {
        return Err(QmdbError::CorruptData(
            "watermark key prefix mismatch".to_string(),
        ));
    }
    let bytes = codec
        .read_payload_exact::<8>(key, 0)
        .map_err(|e| QmdbError::CorruptData(format!("cannot decode watermark location: {e}")))?;
    Ok(Location::new(u64::from_be_bytes(bytes)))
}

pub(crate) fn encode_operation_key<F: Family>(location: Location<F>) -> Key {
    let codec = OPERATION_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("operation key length should fit");
    codec
        .write_payload(&mut key, 0, &location.as_u64().to_be_bytes())
        .expect("operation location fits");
    key.freeze()
}

pub(crate) fn encode_node_key<F: Family>(position: Position<F>) -> Key {
    let codec = NODE_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("node key length should fit");
    codec
        .write_payload(&mut key, 0, &position.as_u64().to_be_bytes())
        .expect("node position fits");
    key.freeze()
}

pub(crate) fn encode_current_meta_key<F: Family>(location: Location<F>) -> Key {
    let codec = CURRENT_META_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("current meta key length should fit");
    codec
        .write_payload(&mut key, 0, &location.as_u64().to_be_bytes())
        .expect("current meta location fits");
    key.freeze()
}

pub(crate) fn encode_ops_root_witness_key<F: Family>(location: Location<F>) -> Key {
    let codec = OPS_ROOT_WITNESS_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("ops root witness key length should fit");
    codec
        .write_payload(&mut key, 0, &location.as_u64().to_be_bytes())
        .expect("ops root witness location fits");
    key.freeze()
}

pub(crate) fn encode_grafted_node_key<F: Family>(
    position: Position<F>,
    watermark: Location<F>,
) -> Key {
    let codec = GRAFTED_NODE_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(16))
        .expect("grafted node key length should fit");
    codec
        .write_payload(&mut key, 0, &position.as_u64().to_be_bytes())
        .expect("grafted node position fits");
    codec
        .write_payload(&mut key, 8, &watermark.as_u64().to_be_bytes())
        .expect("grafted node watermark fits");
    key.freeze()
}

pub(crate) fn encode_chunk_key<F: Family>(chunk_index: u64, watermark: Location<F>) -> Key {
    let codec = CHUNK_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(16))
        .expect("chunk key length should fit");
    codec
        .write_payload(&mut key, 0, &chunk_index.to_be_bytes())
        .expect("chunk index fits");
    codec
        .write_payload(&mut key, 8, &watermark.as_u64().to_be_bytes())
        .expect("chunk watermark fits");
    key.freeze()
}

/// Clear every bitmap bit below `floor` within the chunk at `chunk_index`.
///
/// Bits below the inactivity floor are definitionally 0 at any watermark; the
/// writer does not republish a chunk every time floor advancement flips one
/// of its bits, so the stored payload may carry stale 1s. Fold those clears
/// in deterministically at read time. Mirrors the bit layout used by
/// `commonware_utils::bitmap::BitMap`: byte offset within the chunk is
/// `(L / 8) % N`, bit mask is `1 << (L % 8)`.
pub(crate) fn clear_below_floor<F: Family, const N: usize>(
    chunk: &mut [u8; N],
    chunk_index: u64,
    floor: Location<F>,
) {
    let chunk_bits = bitmap_chunk_bits::<N>();
    let chunk_start = chunk_index.saturating_mul(chunk_bits);
    let chunk_end_exclusive = chunk_start.saturating_add(chunk_bits);
    if *floor <= chunk_start {
        return;
    }
    if *floor >= chunk_end_exclusive {
        *chunk = [0u8; N];
        return;
    }
    let bits_to_clear = (*floor - chunk_start) as usize;
    let whole_bytes = bits_to_clear / 8;
    let remainder = bits_to_clear % 8;
    for byte in &mut chunk[..whole_bytes] {
        *byte = 0;
    }
    if remainder != 0 {
        chunk[whole_bytes] &= !((1u8 << remainder) - 1);
    }
}

pub(crate) fn decode_operation_location_key<F: Family>(
    key: &Key,
) -> Result<Location<F>, QmdbError> {
    let codec = OPERATION_CODEC;
    if !codec.matches(key) {
        return Err(QmdbError::CorruptData(
            "operation key prefix mismatch".to_string(),
        ));
    }
    let bytes = codec
        .read_payload_exact::<8>(key, 0)
        .map_err(|e| QmdbError::CorruptData(format!("cannot decode operation location: {e}")))?;
    Ok(Location::new(u64::from_be_bytes(bytes)))
}

pub(crate) fn decode_presence_location<F: Family>(key: &Key) -> Result<Location<F>, QmdbError> {
    let codec = PRESENCE_CODEC;
    if !codec.matches(key) {
        return Err(QmdbError::CorruptData(
            "presence key prefix mismatch".to_string(),
        ));
    }
    let bytes = codec
        .read_payload_exact::<8>(key, 0)
        .map_err(|e| QmdbError::CorruptData(format!("cannot decode presence location: {e}")))?;
    Ok(Location::new(u64::from_be_bytes(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;
    use commonware_cryptography::Sha256;
    use commonware_storage::merkle::mmr;

    #[test]
    fn current_boundary_metadata_uses_commonware_codec_layout() {
        let root = Sha256::fill(0xA5);
        let metadata = CurrentBoundaryMetadata {
            root,
            pruned_chunks: 0x0102_0304_0506_0708,
        };
        let encoded = metadata.encode().to_vec();

        assert_eq!(encoded.len(), root.as_ref().len() + 8);
        assert_eq!(&encoded[..root.as_ref().len()], root.as_ref());
        assert_eq!(
            &encoded[root.as_ref().len()..],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );

        let decoded = decode_current_boundary_metadata::<commonware_cryptography::sha256::Digest>(
            &encoded,
            "test current boundary metadata".to_string(),
        )
        .unwrap();
        assert_eq!(decoded, metadata);
    }

    fn clear_below_floor_bitwise<F: Family, const N: usize>(
        chunk: &mut [u8; N],
        chunk_index: u64,
        floor: Location<F>,
    ) {
        let chunk_bits = bitmap_chunk_bits::<N>();
        let chunk_start = chunk_index.saturating_mul(chunk_bits);
        let chunk_end_exclusive = chunk_start.saturating_add(chunk_bits);
        if *floor <= chunk_start {
            return;
        }
        if *floor >= chunk_end_exclusive {
            *chunk = [0u8; N];
            return;
        }
        for bit in chunk_start..*floor {
            let byte_offset = ((bit / 8) % N as u64) as usize;
            let mask: u8 = 1u8 << (bit % 8);
            chunk[byte_offset] &= !mask;
        }
    }

    #[test]
    fn clear_below_floor_matches_bitwise_reference() {
        const N: usize = 4;
        let chunk_bits = bitmap_chunk_bits::<N>();
        for chunk_index in 0..3u64 {
            let chunk_start = chunk_index * chunk_bits;
            for floor_bit in 0..=(chunk_start + chunk_bits + 4) {
                let original = [0xAB_u8; N];
                let mut optimized = original;
                let mut reference = original;
                clear_below_floor::<mmr::Family, N>(
                    &mut optimized,
                    chunk_index,
                    Location::new(floor_bit),
                );
                clear_below_floor_bitwise::<mmr::Family, N>(
                    &mut reference,
                    chunk_index,
                    Location::new(floor_bit),
                );
                assert_eq!(
                    optimized, reference,
                    "mismatch at chunk_index={chunk_index} floor={floor_bit}"
                );
            }
        }
    }
}
