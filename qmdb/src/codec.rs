use commonware_codec::DecodeExt;
use commonware_cryptography::Digest;
use commonware_storage::mmr::{Location, Position};
use exoware_sdk_rs::keys::{Key, KeyCodec};

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

pub(crate) const UPDATE_VERSION_LEN: usize = 8;
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

pub(crate) const NO_PARTIAL_CHUNK: u64 = 0;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UpdateRow<K, V> {
    pub(crate) key: K,
    pub(crate) value: Option<V>,
}

impl<K: commonware_codec::Encode, V: commonware_codec::Encode> commonware_codec::Write
    for UpdateRow<K, V>
{
    fn write(&self, buf: &mut impl ::bytes::BufMut) {
        self.key.write(buf);
        self.value.write(buf);
    }
}

impl<K: commonware_codec::Encode, V: commonware_codec::Encode> commonware_codec::EncodeSize
    for UpdateRow<K, V>
{
    fn encode_size(&self) -> usize {
        self.key.encode_size() + self.value.encode_size()
    }
}

impl<K: commonware_codec::Read, V: commonware_codec::Read> commonware_codec::Read
    for UpdateRow<K, V>
{
    type Cfg = (K::Cfg, V::Cfg);
    fn read_cfg(
        buf: &mut impl ::bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let key = K::read_cfg(buf, &cfg.0)?;
        let value = Option::<V>::read_cfg(buf, &cfg.1)?;
        Ok(UpdateRow { key, value })
    }
}

pub(crate) const fn bitmap_chunk_bits<const N: usize>() -> u64 {
    (N as u64) * 8
}

pub(crate) const fn grafting_height_for<const N: usize>() -> u32 {
    bitmap_chunk_bits::<N>().trailing_zeros()
}

pub(crate) fn chunk_index_for_location<const N: usize>(location: Location) -> u64 {
    *location / bitmap_chunk_bits::<N>()
}

pub(crate) fn ops_to_grafted_pos(ops_pos: Position, grafting_height: u32) -> Position {
    let ops_height = position_height(ops_pos);
    assert!(
        ops_height >= grafting_height,
        "position height {ops_height} < grafting height {grafting_height}"
    );
    let grafted_height = ops_height - grafting_height;
    let leftmost_ops_leaf_pos = *ops_pos + 2 - (1u64 << (ops_height + 1));
    let ops_leaf_loc = Location::try_from(Position::new(leftmost_ops_leaf_pos))
        .expect("leftmost ops leaf is not a valid leaf");
    let chunk_idx = *ops_leaf_loc >> grafting_height;
    let grafted_leaf_pos =
        Position::try_from(Location::new(chunk_idx)).expect("chunk index overflow");
    Position::new(*grafted_leaf_pos + (1u64 << (grafted_height + 1)) - 2)
}

pub(crate) fn position_height(pos: Position) -> u32 {
    let mut pos = pos.as_u64();
    if pos == 0 {
        return 0;
    }

    let mut size = u64::MAX >> pos.leading_zeros();
    while size != 0 {
        if pos >= size {
            pos -= size;
        }
        size >>= 1;
    }
    pos as u32
}

pub(crate) fn decode_digest<D: Digest>(bytes: &[u8], label: String) -> Result<D, QmdbError> {
    if bytes.len() != D::SIZE {
        return Err(QmdbError::CorruptData(format!(
            "{label} has invalid length {}",
            bytes.len()
        )));
    }
    D::decode(bytes).map_err(|e| QmdbError::CorruptData(format!("{label} decode error: {e}")))
}

pub(crate) fn mmr_size_for_watermark(watermark: Location) -> Result<Position, QmdbError> {
    let leaves = watermark
        .checked_add(1)
        .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
    Position::try_from(leaves)
        .map_err(|e| QmdbError::CorruptData(format!("invalid MMR size for watermark: {e}")))
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

pub(crate) fn encode_update_key(raw_key: &[u8], location: Location) -> Result<Key, QmdbError> {
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

pub(crate) fn decode_update_location(key: &Key) -> Result<Location, QmdbError> {
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

pub(crate) fn encode_presence_key(latest_location: Location) -> Key {
    let codec = PRESENCE_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("presence key length should fit");
    codec
        .write_payload(&mut key, 0, &latest_location.as_u64().to_be_bytes())
        .expect("presence latest location fits");
    key.freeze()
}

pub(crate) fn encode_watermark_key(location: Location) -> Key {
    let codec = WATERMARK_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("watermark key length should fit");
    codec
        .write_payload(&mut key, 0, &location.as_u64().to_be_bytes())
        .expect("watermark location fits");
    key.freeze()
}

pub(crate) fn decode_watermark_location(key: &Key) -> Result<Location, QmdbError> {
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

pub(crate) fn encode_operation_key(location: Location) -> Key {
    let codec = OPERATION_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("operation key length should fit");
    codec
        .write_payload(&mut key, 0, &location.as_u64().to_be_bytes())
        .expect("operation location fits");
    key.freeze()
}

pub(crate) fn encode_node_key(position: Position) -> Key {
    let codec = NODE_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("node key length should fit");
    codec
        .write_payload(&mut key, 0, &position.as_u64().to_be_bytes())
        .expect("node position fits");
    key.freeze()
}

pub(crate) fn encode_current_meta_key(location: Location) -> Key {
    let codec = CURRENT_META_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("current meta key length should fit");
    codec
        .write_payload(&mut key, 0, &location.as_u64().to_be_bytes())
        .expect("current meta location fits");
    key.freeze()
}

pub(crate) fn encode_grafted_node_key(position: Position, watermark: Location) -> Key {
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

pub(crate) fn encode_chunk_key(chunk_index: u64, watermark: Location) -> Key {
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
pub(crate) fn clear_below_floor<const N: usize>(
    chunk: &mut [u8; N],
    chunk_index: u64,
    floor: Location,
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

pub(crate) fn decode_operation_location_key(key: &Key) -> Result<Location, QmdbError> {
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

pub(crate) fn decode_presence_location(key: &Key) -> Result<Location, QmdbError> {
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
