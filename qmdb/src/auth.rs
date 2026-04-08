use commonware_codec::{Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::mmr::{
    self, iterator::PeakIterator, Location, Position, StandardHasher,
};
use commonware_utils::Array;
use exoware_sdk_rs::keys::{Key, KeyCodec};
use exoware_sdk_rs::{RangeMode, SerializableReadSession};

use crate::codec::{
    decode_digest, encode_ordered_update_payload, ensure_encoded_value_size, mmr_size_for_watermark,
    validate_ordered_key_bytes, UpdateRow, ORDERED_KEY_TERMINATOR_LEN, RESERVED_BITS,
    UPDATE_VERSION_LEN,
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

pub(crate) type AuthRows = Vec<(Key, Vec<u8>)>;

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

pub(crate) async fn require_auth_uploaded_boundary(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    location: Location,
) -> Result<(), QmdbError> {
    if session
        .get(&encode_auth_presence_key(namespace, location))
        .await?
        .is_some()
    {
        Ok(())
    } else {
        Err(QmdbError::CorruptData(format!(
            "authenticated backend upload boundary missing at {location}"
        )))
    }
}

pub(crate) fn build_auth_upload_rows(
    namespace: AuthenticatedBackendNamespace,
    latest_location: Location,
    encoded_operations: &[Vec<u8>],
) -> Result<(u32, AuthRows), QmdbError> {
    let mut rows = Vec::<(Key, Vec<u8>)>::with_capacity(encoded_operations.len() + 1);
    let count_u64 = encoded_operations.len() as u64;
    let Some(start_location) = latest_location
        .checked_add(1)
        .and_then(|next| next.checked_sub(count_u64))
    else {
        return Err(QmdbError::InvalidLocationRange {
            start_location: Location::new(0),
            latest_location,
            count: encoded_operations.len(),
        });
    };
    for (index, encoded) in encoded_operations.iter().enumerate() {
        ensure_encoded_value_size(encoded.len())?;
        rows.push((
            encode_auth_operation_key(namespace, start_location + index as u64),
            encoded.clone(),
        ));
    }
    rows.push((
        encode_auth_presence_key(namespace, latest_location),
        Vec::new(),
    ));
    let operation_count = u32::try_from(encoded_operations.len()).map_err(|_| {
        QmdbError::CorruptData("authenticated operation count overflow".to_string())
    })?;
    Ok((operation_count, rows))
}

pub(crate) fn build_auth_immutable_upload_rows<K, V>(
    latest_location: Location,
    operations: &[commonware_storage::qmdb::immutable::Operation<K, V>],
) -> Result<(u32, AuthRows), QmdbError>
where
    K: Array + AsRef<[u8]>,
    V: commonware_codec::Codec + Clone + Send + Sync,
{
    use commonware_storage::qmdb::immutable::Operation as ImmutableOperation;

    let count_u64 = operations.len() as u64;
    let Some(start_location) = latest_location
        .checked_add(1)
        .and_then(|next| next.checked_sub(count_u64))
    else {
        return Err(QmdbError::InvalidLocationRange {
            start_location: Location::new(0),
            latest_location,
            count: operations.len(),
        });
    };
    let mut rows = Vec::<(Key, Vec<u8>)>::with_capacity(operations.len() * 2 + 1);
    let mut keyed_operation_count = 0u32;
    for (index, operation) in operations.iter().enumerate() {
        let location = start_location + index as u64;
        let encoded = operation.encode().to_vec();
        ensure_encoded_value_size(encoded.len())?;
        rows.push((
            encode_auth_operation_key(AuthenticatedBackendNamespace::Immutable, location),
            encoded,
        ));
        if let ImmutableOperation::Set(key, value) = operation {
            keyed_operation_count += 1;
            let update_row = UpdateRow {
                key: key.clone(),
                value: Some(value.clone()),
            };
            rows.push((
                encode_auth_immutable_update_key(key.as_ref(), location)?,
                update_row.encode().to_vec(),
            ));
        }
    }
    rows.push((
        encode_auth_presence_key(AuthenticatedBackendNamespace::Immutable, latest_location),
        Vec::new(),
    ));
    Ok((keyed_operation_count, rows))
}

pub(crate) async fn append_auth_nodes_incrementally<H: Hasher>(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    previous_ops_size: Position,
    delta_operations: &[Vec<u8>],
    rows: &mut Vec<(Key, Vec<u8>)>,
) -> Result<(Position, H::Digest), QmdbError> {
    let peak_entries: Vec<(Position, u32)> = PeakIterator::new(previous_ops_size).collect();
    let fetched = if peak_entries.is_empty() {
        std::collections::HashMap::new()
    } else {
        let peak_keys: Vec<Key> = peak_entries.iter().map(|(pos, _)| encode_auth_node_key(namespace, *pos)).collect();
        let peak_key_refs: Vec<&Key> = peak_keys.iter().collect();
        session
            .get_many(&peak_key_refs, peak_key_refs.len() as u32)
            .await?
            .collect()
            .await?
    };
    let mut peaks = Vec::<(Position, u32, H::Digest)>::with_capacity(peak_entries.len());
    for (peak_pos, height) in &peak_entries {
        let key = encode_auth_node_key(namespace, *peak_pos);
        let Some(bytes) = fetched.get(&key) else {
            return Err(QmdbError::CorruptData(format!(
                "missing authenticated peak node at position {peak_pos}"
            )));
        };
        peaks.push((
            *peak_pos,
            *height,
            decode_digest(
                bytes.as_ref(),
                format!("authenticated peak node at position {peak_pos}"),
            )?,
        ));
    }

    let mut current_size = previous_ops_size;
    let mut hasher = StandardHasher::<H>::new();
    for encoded in delta_operations {
        let leaf_pos = current_size;
        let leaf_digest = mmr::hasher::Hasher::leaf_digest(&mut hasher, leaf_pos, encoded);
        rows.push((
            encode_auth_node_key(namespace, leaf_pos),
            leaf_digest.as_ref().to_vec(),
        ));
        current_size = Position::new(*current_size + 1);

        let mut carry_pos = leaf_pos;
        let mut carry_digest = leaf_digest;
        let mut carry_height = 0u32;
        while peaks
            .last()
            .is_some_and(|(_, height, _)| *height == carry_height)
        {
            let (_, _, left_digest) = peaks.pop().expect("peak exists");
            let parent_pos = current_size;
            let parent_digest = mmr::hasher::Hasher::node_digest(
                &mut hasher,
                parent_pos,
                &left_digest,
                &carry_digest,
            );
            rows.push((
                encode_auth_node_key(namespace, parent_pos),
                parent_digest.as_ref().to_vec(),
            ));
            current_size = Position::new(*current_size + 1);
            carry_pos = parent_pos;
            carry_digest = parent_digest;
            carry_height += 1;
        }
        peaks.push((carry_pos, carry_height, carry_digest));
    }

    let leaves = Location::try_from(current_size)
        .map_err(|e| QmdbError::CorruptData(format!("invalid authenticated ops size: {e}")))?;
    let root = mmr::hasher::Hasher::root(
        &mut hasher,
        leaves,
        peaks.iter().map(|(_, _, digest)| digest),
    );
    Ok((current_size, root))
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
        let peak_keys: Vec<Key> = peak_positions.iter().map(|(pos, _)| encode_auth_node_key(namespace, *pos)).collect();
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

pub(crate) async fn load_auth_operation_range<Op>(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    start_location: Location,
    end_location_exclusive: Location,
    cfg: &Op::Cfg,
) -> Result<Vec<Op>, QmdbError>
where
    Op: Decode,
{
    load_auth_operation_bytes_range(session, namespace, start_location, end_location_exclusive)
        .await?
        .into_iter()
        .enumerate()
        .map(|(offset, bytes)| {
            let location = start_location + offset as u64;
            Op::decode_cfg(bytes.as_slice(), cfg).map_err(|e| {
                QmdbError::CorruptData(format!(
                    "failed to decode authenticated operation at location {location}: {e}"
                ))
            })
        })
        .collect()
}

pub(crate) fn decode_auth_operation_location(
    namespace: AuthenticatedBackendNamespace,
    key: &Key,
) -> Result<Location, QmdbError> {
    let codec = AUTH_OPERATION_CODEC;
    ensure_auth_namespace(codec, namespace, key, "authenticated operation")?;
    let bytes = codec
        .read_payload_exact::<8>(key, AUTH_NAMESPACE_LEN)
        .map_err(|e| {
            QmdbError::CorruptData(format!(
                "cannot decode authenticated operation location: {e}"
            ))
        })?;
    Ok(Location::new(u64::from_be_bytes(bytes)))
}

pub(crate) fn decode_auth_watermark_location(
    namespace: AuthenticatedBackendNamespace,
    key: &Key,
) -> Result<Location, QmdbError> {
    let codec = AUTH_WATERMARK_CODEC;
    ensure_auth_namespace(codec, namespace, key, "authenticated watermark")?;
    let bytes = codec
        .read_payload_exact::<8>(key, AUTH_NAMESPACE_LEN)
        .map_err(|e| {
            QmdbError::CorruptData(format!(
                "cannot decode authenticated watermark location: {e}"
            ))
        })?;
    Ok(Location::new(u64::from_be_bytes(bytes)))
}
