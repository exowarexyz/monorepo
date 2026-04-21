use commonware_codec::{Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::mmr::{self, iterator::PeakIterator, Location, Position, StandardHasher};
use commonware_utils::Array;
use exoware_sdk_rs::keys::{Key, KeyCodec};
use exoware_sdk_rs::{RangeMode, SerializableReadSession};

use crate::codec::{
    decode_digest, encode_ordered_update_payload, ensure_encoded_value_size,
    mmr_size_for_watermark, validate_ordered_key_bytes, UpdateRow, ORDERED_KEY_TERMINATOR_LEN,
    RESERVED_BITS, UPDATE_VERSION_LEN,
};
use crate::error::QmdbError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthenticatedBackendNamespace {
    Immutable = 1,
    Keyless = 2,
}

impl AuthenticatedBackendNamespace {
    pub(crate) const fn tag(self) -> u8 {
        self as u8
    }
}

const AUTH_OP_FAMILY: u16 = 0x9;
const AUTH_NODE_FAMILY: u16 = 0xA;
const AUTH_WATERMARK_FAMILY: u16 = 0xB;
const AUTH_INDEX_FAMILY: u16 = 0xC;
const AUTH_IMMUTABLE_UPDATE_FAMILY: u16 = 0xD;
const AUTH_NAMESPACE_LEN: usize = 1;

pub(crate) const AUTH_OPERATION_CODEC: KeyCodec = KeyCodec::new(RESERVED_BITS, AUTH_OP_FAMILY);
pub(crate) const AUTH_NODE_CODEC: KeyCodec = KeyCodec::new(RESERVED_BITS, AUTH_NODE_FAMILY);
pub(crate) const AUTH_WATERMARK_CODEC: KeyCodec =
    KeyCodec::new(RESERVED_BITS, AUTH_WATERMARK_FAMILY);
pub(crate) const AUTH_PRESENCE_CODEC: KeyCodec = KeyCodec::new(RESERVED_BITS, AUTH_INDEX_FAMILY);
pub(crate) const AUTH_IMMUTABLE_UPDATE_CODEC: KeyCodec =
    KeyCodec::new(RESERVED_BITS, AUTH_IMMUTABLE_UPDATE_FAMILY);

pub(crate) fn auth_namespace_bounds(
    codec: KeyCodec,
    namespace: AuthenticatedBackendNamespace,
) -> (Key, Key) {
    let tail_len = 8usize;
    let total_len = codec.min_key_len_for_payload(AUTH_NAMESPACE_LEN + tail_len);
    let mut start = codec
        .new_key_with_len(total_len)
        .expect("authenticated namespace start key length should fit");
    let mut end = codec
        .new_key_with_len(total_len)
        .expect("authenticated namespace end key length should fit");
    codec
        .write_payload(&mut start, 0, &[namespace.tag()])
        .expect("authenticated namespace tag fits");
    codec
        .write_payload(&mut end, 0, &[namespace.tag()])
        .expect("authenticated namespace tag fits");
    codec
        .fill_payload(&mut start, AUTH_NAMESPACE_LEN, tail_len, 0)
        .expect("authenticated start tail fits");
    codec
        .fill_payload(&mut end, AUTH_NAMESPACE_LEN, tail_len, 0xFF)
        .expect("authenticated end tail fits");
    (start.freeze(), end.freeze())
}

pub(crate) fn ensure_auth_namespace(
    codec: KeyCodec,
    namespace: AuthenticatedBackendNamespace,
    key: &Key,
    label: &str,
) -> Result<(), QmdbError> {
    if !codec.matches(key) {
        return Err(QmdbError::CorruptData(format!(
            "{label} key prefix mismatch"
        )));
    }
    let actual = codec
        .read_payload_exact::<1>(key, 0)
        .map_err(|e| QmdbError::CorruptData(format!("cannot decode {label} namespace: {e}")))?[0];
    if actual != namespace.tag() {
        return Err(QmdbError::CorruptData(format!(
            "{label} namespace mismatch: expected {}, got {actual}",
            namespace.tag()
        )));
    }
    Ok(())
}

pub(crate) fn encode_auth_operation_key(
    namespace: AuthenticatedBackendNamespace,
    location: Location,
) -> Key {
    let codec = AUTH_OPERATION_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(AUTH_NAMESPACE_LEN + 8))
        .expect("authenticated operation key length should fit");
    codec
        .write_payload(&mut key, 0, &[namespace.tag()])
        .expect("authenticated operation namespace fits");
    codec
        .write_payload(
            &mut key,
            AUTH_NAMESPACE_LEN,
            &location.as_u64().to_be_bytes(),
        )
        .expect("authenticated operation location fits");
    key.freeze()
}

pub(crate) fn encode_auth_node_key(
    namespace: AuthenticatedBackendNamespace,
    position: Position,
) -> Key {
    let codec = AUTH_NODE_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(AUTH_NAMESPACE_LEN + 8))
        .expect("authenticated node key length should fit");
    codec
        .write_payload(&mut key, 0, &[namespace.tag()])
        .expect("authenticated node namespace fits");
    codec
        .write_payload(
            &mut key,
            AUTH_NAMESPACE_LEN,
            &position.as_u64().to_be_bytes(),
        )
        .expect("authenticated node position fits");
    key.freeze()
}

pub(crate) fn encode_auth_watermark_key(
    namespace: AuthenticatedBackendNamespace,
    location: Location,
) -> Key {
    let codec = AUTH_WATERMARK_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(AUTH_NAMESPACE_LEN + 8))
        .expect("authenticated watermark key length should fit");
    codec
        .write_payload(&mut key, 0, &[namespace.tag()])
        .expect("authenticated watermark namespace fits");
    codec
        .write_payload(
            &mut key,
            AUTH_NAMESPACE_LEN,
            &location.as_u64().to_be_bytes(),
        )
        .expect("authenticated watermark fits");
    key.freeze()
}

pub(crate) fn encode_auth_presence_key(
    namespace: AuthenticatedBackendNamespace,
    location: Location,
) -> Key {
    let codec = AUTH_PRESENCE_CODEC;
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(AUTH_NAMESPACE_LEN + 8))
        .expect("authenticated presence key length should fit");
    codec
        .write_payload(&mut key, 0, &[namespace.tag()])
        .expect("authenticated presence namespace fits");
    codec
        .write_payload(
            &mut key,
            AUTH_NAMESPACE_LEN,
            &location.as_u64().to_be_bytes(),
        )
        .expect("authenticated presence location fits");
    key.freeze()
}

pub(crate) fn encode_auth_immutable_update_key(
    raw_key: &[u8],
    location: Location,
) -> Result<Key, QmdbError> {
    let codec = AUTH_IMMUTABLE_UPDATE_CODEC;
    let ordered_key = encode_ordered_update_payload(codec, raw_key, UPDATE_VERSION_LEN)?;
    let total_len = codec.min_key_len_for_payload(ordered_key.len() + UPDATE_VERSION_LEN);
    let mut key = codec
        .new_key_with_len(total_len)
        .expect("authenticated immutable update key length should fit");
    codec
        .write_payload(&mut key, 0, &ordered_key)
        .expect("authenticated immutable update key bytes fit");
    codec
        .write_payload(
            &mut key,
            ordered_key.len(),
            &location.as_u64().to_be_bytes(),
        )
        .expect("authenticated immutable update location fits");
    Ok(key.freeze())
}

pub(crate) fn decode_auth_immutable_update_location(key: &Key) -> Result<Location, QmdbError> {
    let codec = AUTH_IMMUTABLE_UPDATE_CODEC;
    if !codec.matches(key) {
        return Err(QmdbError::CorruptData(
            "authenticated immutable update key prefix mismatch".to_string(),
        ));
    }
    let payload_capacity = codec.payload_capacity_bytes_for_key_len(key.len());
    if payload_capacity < ORDERED_KEY_TERMINATOR_LEN + UPDATE_VERSION_LEN {
        return Err(QmdbError::CorruptData(
            "authenticated immutable update payload shorter than minimum layout".to_string(),
        ));
    }
    let ordered_len = payload_capacity - UPDATE_VERSION_LEN;
    let ordered_key = codec.read_payload(key, 0, ordered_len).map_err(|e| {
        QmdbError::CorruptData(format!(
            "cannot decode authenticated immutable update key bytes: {e}"
        ))
    })?;
    validate_ordered_key_bytes(&ordered_key, "authenticated immutable update key")?;
    let bytes = codec
        .read_payload_exact::<8>(key, ordered_len)
        .map_err(|e| {
            QmdbError::CorruptData(format!(
                "cannot decode authenticated immutable update location: {e}"
            ))
        })?;
    Ok(Location::new(u64::from_be_bytes(bytes)))
}

pub(crate) async fn load_latest_auth_immutable_update_row(
    session: &SerializableReadSession,
    watermark: Location,
    key: &[u8],
) -> Result<Option<(Key, Vec<u8>)>, QmdbError> {
    let start = encode_auth_immutable_update_key(key, Location::new(0))?;
    let end = encode_auth_immutable_update_key(key, watermark)?;
    let rows = session
        .range_with_mode(&start, &end, 1, RangeMode::Reverse)
        .await?;
    Ok(rows
        .into_iter()
        .next()
        .map(|(key, value)| (key, value.to_vec())))
}

pub(crate) async fn read_latest_auth_watermark(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
) -> Result<Option<Location>, QmdbError> {
    let (start, end) = auth_namespace_bounds(AUTH_WATERMARK_CODEC, namespace);
    let rows = session
        .range_with_mode(&start, &end, 1, RangeMode::Reverse)
        .await?;
    match rows.into_iter().next() {
        Some((key, _)) => Ok(Some(decode_auth_watermark_location(namespace, &key)?)),
        None => Ok(None),
    }
}

pub(crate) async fn require_published_auth_watermark(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    watermark: Location,
) -> Result<(), QmdbError> {
    let available = read_latest_auth_watermark(session, namespace)
        .await?
        .unwrap_or(Location::new(0));
    let watermark_exists = session
        .get(&encode_auth_watermark_key(namespace, watermark))
        .await?
        .is_some();
    if available < watermark
        || (!watermark_exists && available == Location::new(0) && watermark == Location::new(0))
    {
        return Err(QmdbError::WatermarkTooLow {
            requested: watermark,
            available,
        });
    }
    Ok(())
}

/// Consumes `encoded_operations` into the returned `PreparedUpload`'s
/// `op_rows` — no clones.
pub(crate) fn build_auth_upload_rows(
    namespace: AuthenticatedBackendNamespace,
    latest_location: Location,
    encoded_operations: Vec<Vec<u8>>,
) -> Result<crate::core::PreparedUpload, QmdbError> {
    let count = encoded_operations.len();
    let count_u64 = count as u64;
    let Some(start_location) = latest_location
        .checked_add(1)
        .and_then(|next| next.checked_sub(count_u64))
    else {
        return Err(QmdbError::InvalidLocationRange {
            start_location: Location::new(0),
            latest_location,
            count,
        });
    };
    let mut op_rows = Vec::<(Key, Vec<u8>)>::with_capacity(count);
    for (index, encoded) in encoded_operations.into_iter().enumerate() {
        ensure_encoded_value_size(encoded.len())?;
        op_rows.push((
            encode_auth_operation_key(namespace, start_location + index as u64),
            encoded,
        ));
    }
    let operation_count = u32::try_from(count).map_err(|_| {
        QmdbError::CorruptData("authenticated operation count overflow".to_string())
    })?;
    Ok(crate::core::PreparedUpload {
        operation_count,
        keyed_operation_count: 0,
        op_rows,
        aux_rows: vec![(
            encode_auth_presence_key(namespace, latest_location),
            Vec::new(),
        )],
    })
}

/// Encodes `operations` exactly once — the encoded bytes move into the
/// returned `PreparedUpload`'s `op_rows`.
pub(crate) fn build_auth_immutable_upload_rows<K, V>(
    latest_location: Location,
    operations: &[commonware_storage::qmdb::immutable::Operation<K, V>],
) -> Result<crate::core::PreparedUpload, QmdbError>
where
    K: Array + AsRef<[u8]>,
    V: commonware_codec::Codec + Clone + Send + Sync,
{
    use commonware_storage::qmdb::immutable::Operation as ImmutableOperation;

    let count = operations.len();
    let count_u64 = count as u64;
    let Some(start_location) = latest_location
        .checked_add(1)
        .and_then(|next| next.checked_sub(count_u64))
    else {
        return Err(QmdbError::InvalidLocationRange {
            start_location: Location::new(0),
            latest_location,
            count,
        });
    };
    let mut op_rows = Vec::<(Key, Vec<u8>)>::with_capacity(count);
    let mut aux_rows = Vec::<(Key, Vec<u8>)>::with_capacity(count + 1);
    let mut keyed_operation_count = 0u32;
    for (index, operation) in operations.iter().enumerate() {
        let location = start_location + index as u64;
        let encoded = operation.encode().to_vec();
        ensure_encoded_value_size(encoded.len())?;
        op_rows.push((
            encode_auth_operation_key(AuthenticatedBackendNamespace::Immutable, location),
            encoded,
        ));
        if let ImmutableOperation::Set(key, value) = operation {
            keyed_operation_count += 1;
            let update_row = UpdateRow {
                key: key.clone(),
                value: Some(value.clone()),
            };
            aux_rows.push((
                encode_auth_immutable_update_key(key.as_ref(), location)?,
                update_row.encode().to_vec(),
            ));
        }
    }
    aux_rows.push((
        encode_auth_presence_key(AuthenticatedBackendNamespace::Immutable, latest_location),
        Vec::new(),
    ));
    let operation_count = u32::try_from(count).map_err(|_| {
        QmdbError::CorruptData("authenticated operation count overflow".to_string())
    })?;
    Ok(crate::core::PreparedUpload {
        operation_count,
        keyed_operation_count,
        op_rows,
        aux_rows,
    })
}

pub(crate) async fn compute_auth_root<H: Hasher>(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    watermark: Location,
) -> Result<H::Digest, QmdbError> {
    let size = mmr_size_for_watermark(watermark)?;
    let leaves = watermark
        .checked_add(1)
        .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
    let peak_positions: Vec<(Position, u32)> = PeakIterator::new(size).collect();
    let fetched = if peak_positions.is_empty() {
        std::collections::HashMap::new()
    } else {
        let peak_keys: Vec<Key> = peak_positions
            .iter()
            .map(|(pos, _)| encode_auth_node_key(namespace, *pos))
            .collect();
        let peak_key_refs: Vec<&Key> = peak_keys.iter().collect();
        session
            .get_many(&peak_key_refs, peak_key_refs.len() as u32)
            .await?
            .collect()
            .await?
    };
    let mut peaks = Vec::with_capacity(peak_positions.len());
    for (peak_pos, _) in &peak_positions {
        let key = encode_auth_node_key(namespace, *peak_pos);
        let Some(bytes) = fetched.get(&key) else {
            return Err(QmdbError::CorruptData(format!(
                "missing authenticated MMR peak node at position {peak_pos}"
            )));
        };
        peaks.push(decode_digest(
            bytes.as_ref(),
            format!("authenticated peak node at position {peak_pos}"),
        )?);
    }
    let mut hasher = StandardHasher::<H>::new();
    Ok(mmr::hasher::Hasher::root(&mut hasher, leaves, peaks.iter()))
}

pub(crate) async fn load_auth_operation_at<Op>(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    location: Location,
    cfg: &Op::Cfg,
) -> Result<Op, QmdbError>
where
    Op: Decode,
{
    let Some(bytes) = session
        .get(&encode_auth_operation_key(namespace, location))
        .await?
    else {
        return Err(QmdbError::CorruptData(format!(
            "missing authenticated operation row at location {location}"
        )));
    };
    Op::decode_cfg(bytes.as_ref(), cfg).map_err(|e| {
        QmdbError::CorruptData(format!(
            "failed to decode authenticated operation at location {location}: {e}"
        ))
    })
}

pub(crate) async fn load_auth_operation_bytes_range(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    start_location: Location,
    end_location_exclusive: Location,
) -> Result<Vec<Vec<u8>>, QmdbError> {
    if start_location >= end_location_exclusive {
        return Ok(Vec::new());
    }
    let start = encode_auth_operation_key(namespace, start_location);
    let end = encode_auth_operation_key(namespace, end_location_exclusive - 1);
    let rows = session
        .range(
            &start,
            &end,
            (*end_location_exclusive - *start_location) as usize,
        )
        .await?;
    if rows.len() != (*end_location_exclusive - *start_location) as usize {
        return Err(QmdbError::CorruptData(format!(
            "expected {} authenticated operation rows in range [{start_location}, {end_location_exclusive}), found {}",
            *end_location_exclusive - *start_location,
            rows.len()
        )));
    }
    let mut operations = Vec::with_capacity(rows.len());
    for (offset, (key, value)) in rows.into_iter().enumerate() {
        let expected_location = start_location + offset as u64;
        let location = decode_auth_operation_location(namespace, &key)?;
        if location != expected_location {
            return Err(QmdbError::CorruptData(format!(
                "authenticated operation row order mismatch: expected {expected_location}, got {location}"
            )));
        }
        operations.push(value.to_vec());
    }
    Ok(operations)
}

fn decode_auth_location_field(
    codec: KeyCodec,
    namespace: AuthenticatedBackendNamespace,
    key: &Key,
    label: &str,
) -> Result<Location, QmdbError> {
    ensure_auth_namespace(codec, namespace, key, label)?;
    let bytes = codec
        .read_payload_exact::<8>(key, AUTH_NAMESPACE_LEN)
        .map_err(|e| QmdbError::CorruptData(format!("cannot decode {label} location: {e}")))?;
    Ok(Location::new(u64::from_be_bytes(bytes)))
}

pub(crate) fn decode_auth_operation_location(
    namespace: AuthenticatedBackendNamespace,
    key: &Key,
) -> Result<Location, QmdbError> {
    decode_auth_location_field(
        AUTH_OPERATION_CODEC,
        namespace,
        key,
        "authenticated operation",
    )
}

pub(crate) fn decode_auth_watermark_location(
    namespace: AuthenticatedBackendNamespace,
    key: &Key,
) -> Result<Location, QmdbError> {
    decode_auth_location_field(
        AUTH_WATERMARK_CODEC,
        namespace,
        key,
        "authenticated watermark",
    )
}

pub(crate) fn decode_auth_presence_location(
    namespace: AuthenticatedBackendNamespace,
    key: &Key,
) -> Result<Location, QmdbError> {
    decode_auth_location_field(
        AUTH_PRESENCE_CODEC,
        namespace,
        key,
        "authenticated presence",
    )
}

/// Family constants exposed to the stream driver.
pub(crate) const AUTH_OP_FAMILY_PREFIX: u16 = AUTH_OP_FAMILY;
pub(crate) const AUTH_PRESENCE_FAMILY_PREFIX: u16 = AUTH_INDEX_FAMILY;
pub(crate) const AUTH_WATERMARK_FAMILY_PREFIX: u16 = AUTH_WATERMARK_FAMILY;
pub(crate) const AUTH_FAMILY_RESERVED_BITS: u8 = RESERVED_BITS;

/// Byte regex matching a 1-byte namespace tag + 8-byte location payload.
/// Used by the stream filter to restrict fan-out to one authenticated namespace
/// (Immutable vs Keyless) even though both share the same reserved family prefix.
pub(crate) fn auth_payload_regex_for_namespace(namespace: AuthenticatedBackendNamespace) -> String {
    format!("(?s-u)^\\x{:02x}.{{8}}$", namespace.tag())
}
