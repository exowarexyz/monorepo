use commonware_codec::{Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::merkle::{hasher::Hasher as MerkleHasher, Family, Location, Position};
use commonware_utils::Array;
use exoware_sdk::keys::{Key, Prefix};
use exoware_sdk::{RangeMode, SerializableReadSession};

use crate::codec::{
    decode_digest, decode_location_bytes, encode_update_index_value, encode_update_key,
    ensure_encoded_value_size, merkle_size_for_watermark, NODE_PREFIX, OPERATION_PREFIX,
    PRESENCE_PREFIX, WATERMARK_PREFIX,
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

const AUTH_NAMESPACE_LEN: usize = 1;

pub(crate) fn auth_namespace_bounds(
    prefix: &Prefix,
    namespace: AuthenticatedBackendNamespace,
) -> (Key, Key) {
    let tail_len = 8usize;
    let mut start_payload = vec![0u8; AUTH_NAMESPACE_LEN + tail_len];
    start_payload[0] = namespace.tag();
    let mut end_payload = vec![0xFFu8; AUTH_NAMESPACE_LEN + tail_len];
    end_payload[0] = namespace.tag();
    let start = prefix
        .encode(&start_payload)
        .expect("authenticated namespace start key length should fit");
    let end = prefix
        .encode(&end_payload)
        .expect("authenticated namespace end key length should fit");
    (start, end)
}

/// Strip `prefix` from `key`, verify the namespace tag, and return the
/// stripped payload (tag byte included).
pub(crate) fn ensure_auth_namespace(
    prefix: &Prefix,
    namespace: AuthenticatedBackendNamespace,
    key: &Key,
    label: &str,
) -> Result<Key, QmdbError> {
    let payload = prefix
        .strip(key)
        .map_err(|_| QmdbError::CorruptData(format!("{label} key prefix mismatch")))?;
    let actual = *payload.first().ok_or_else(|| {
        QmdbError::CorruptData(format!("cannot decode {label} namespace: short key"))
    })?;
    if actual != namespace.tag() {
        return Err(QmdbError::CorruptData(format!(
            "{label} namespace mismatch: expected {}, got {actual}",
            namespace.tag()
        )));
    }
    Ok(payload)
}

/// Build a `[namespace tag] ++ 8-byte big-endian value` auth-family key.
fn encode_auth_namespaced_key(prefix: &Prefix, tag: u8, value: u64) -> Key {
    let mut payload = [0u8; AUTH_NAMESPACE_LEN + 8];
    payload[0] = tag;
    payload[AUTH_NAMESPACE_LEN..].copy_from_slice(&value.to_be_bytes());
    prefix
        .encode(&payload)
        .expect("authenticated namespaced key length should fit")
}

pub(crate) fn encode_auth_operation_key<F: Family>(
    namespace: AuthenticatedBackendNamespace,
    location: Location<F>,
) -> Key {
    encode_auth_namespaced_key(&OPERATION_PREFIX, namespace.tag(), location.as_u64())
}

pub(crate) fn encode_auth_node_key<F: Family>(
    namespace: AuthenticatedBackendNamespace,
    position: Position<F>,
) -> Key {
    encode_auth_namespaced_key(&NODE_PREFIX, namespace.tag(), position.as_u64())
}

pub(crate) fn encode_auth_watermark_key<F: Family>(
    namespace: AuthenticatedBackendNamespace,
    location: Location<F>,
) -> Key {
    encode_auth_namespaced_key(&WATERMARK_PREFIX, namespace.tag(), location.as_u64())
}

pub(crate) fn encode_auth_presence_key<F: Family>(
    namespace: AuthenticatedBackendNamespace,
    location: Location<F>,
) -> Key {
    encode_auth_namespaced_key(&PRESENCE_PREFIX, namespace.tag(), location.as_u64())
}

pub(crate) async fn load_latest_auth_immutable_update_row<F: Family>(
    session: &SerializableReadSession,
    watermark: Location<F>,
    key: &[u8],
) -> Result<Option<(Key, Vec<u8>)>, QmdbError> {
    let start = encode_update_key(key, Location::<F>::new(0))?;
    let end = encode_update_key(key, watermark)?;
    let rows = session
        .range_with_mode(&start, &end, 1, RangeMode::Reverse)
        .await?;
    Ok(rows
        .into_iter()
        .next()
        .map(|(key, value)| (key, value.to_vec())))
}

pub(crate) async fn read_latest_auth_watermark<F: Family>(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
) -> Result<Option<Location<F>>, QmdbError> {
    let (start, end) = auth_namespace_bounds(&WATERMARK_PREFIX, namespace);
    let rows = session
        .range_with_mode(&start, &end, 1, RangeMode::Reverse)
        .await?;
    match rows.into_iter().next() {
        Some((key, _)) => Ok(Some(decode_auth_watermark_location(namespace, &key)?)),
        None => Ok(None),
    }
}

pub(crate) async fn require_published_auth_watermark<F: Family>(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    watermark: Location<F>,
) -> Result<(), QmdbError> {
    let available = read_latest_auth_watermark::<F>(session, namespace)
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
            requested: watermark.as_u64(),
            available: available.as_u64(),
        });
    }
    Ok(())
}

/// Consumes `encoded_operations` into the returned `PreparedUpload`'s
/// `op_rows` — no clones.
pub(crate) fn build_auth_upload_rows<F: Family>(
    namespace: AuthenticatedBackendNamespace,
    latest_location: Location<F>,
    encoded_operations: Vec<Vec<u8>>,
) -> Result<crate::core::PreparedUpload, QmdbError> {
    let count = encoded_operations.len();
    let count_u64 = count as u64;
    let Some(start_location) = latest_location
        .checked_add(1)
        .and_then(|next| next.checked_sub(count_u64))
    else {
        return Err(QmdbError::InvalidLocationRange {
            start_location: 0,
            latest_location: latest_location.as_u64(),
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
pub(crate) fn build_auth_immutable_upload_rows<F: Family, K, E>(
    latest_location: Location<F>,
    operations: &[commonware_storage::qmdb::immutable::Operation<F, K, E>],
) -> Result<crate::core::PreparedUpload, QmdbError>
where
    K: Array + commonware_codec::Codec + Clone + AsRef<[u8]>,
    E: commonware_storage::qmdb::any::value::ValueEncoding,
    E::Value: commonware_codec::Codec + Clone + Send + Sync,
    commonware_storage::qmdb::immutable::Operation<F, K, E>: Encode,
{
    use commonware_storage::qmdb::immutable::Operation as ImmutableOperation;

    let count = operations.len();
    let count_u64 = count as u64;
    let Some(start_location) = latest_location
        .checked_add(1)
        .and_then(|next| next.checked_sub(count_u64))
    else {
        return Err(QmdbError::InvalidLocationRange {
            start_location: 0,
            latest_location: latest_location.as_u64(),
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
        if let ImmutableOperation::Set(key, _) = operation {
            keyed_operation_count += 1;
            aux_rows.push((
                encode_update_key(key.as_ref(), location)?,
                encode_update_index_value(true),
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

pub(crate) fn auth_inactive_peaks<F: Family>(
    watermark: Location<F>,
    inactivity_floor: Location<F>,
) -> Result<usize, QmdbError> {
    Ok(F::inactive_peaks(
        merkle_size_for_watermark(watermark)?,
        inactivity_floor,
    ))
}

pub(crate) async fn compute_auth_root<F: Family, H: Hasher>(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    watermark: Location<F>,
    inactive_peaks: usize,
) -> Result<H::Digest, QmdbError> {
    let size = merkle_size_for_watermark(watermark)?;
    let leaves = watermark
        .checked_add(1)
        .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
    let peak_positions: Vec<(Position<F>, u32)> = F::peaks(size).collect();
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
                "missing authenticated Merkle peak node at position {peak_pos}"
            )));
        };
        peaks.push(decode_digest(
            bytes.as_ref(),
            format!("authenticated peak node at position {peak_pos}"),
        )?);
    }
    let hasher = commonware_storage::qmdb::hasher::<H>();
    hasher
        .root(leaves, inactive_peaks, peaks.iter())
        .map_err(|e| QmdbError::CommonwareMerkle(e.to_string()))
}

pub(crate) async fn load_auth_operation_at<F: Family, Op>(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    location: Location<F>,
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

pub(crate) async fn load_auth_operation_bytes_range<F: Family>(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    start_location: Location<F>,
    end_location_exclusive: Location<F>,
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

fn decode_auth_location_field<F: Family>(
    prefix: &Prefix,
    namespace: AuthenticatedBackendNamespace,
    key: &Key,
    label: &str,
) -> Result<Location<F>, QmdbError> {
    let payload = ensure_auth_namespace(prefix, namespace, key, label)?;
    Ok(Location::new(decode_location_bytes(
        &payload[AUTH_NAMESPACE_LEN..],
        format_args!("{label} location"),
    )?))
}

pub(crate) fn decode_auth_operation_location<F: Family>(
    namespace: AuthenticatedBackendNamespace,
    key: &Key,
) -> Result<Location<F>, QmdbError> {
    decode_auth_location_field(&OPERATION_PREFIX, namespace, key, "authenticated operation")
}

pub(crate) fn decode_auth_watermark_location<F: Family>(
    namespace: AuthenticatedBackendNamespace,
    key: &Key,
) -> Result<Location<F>, QmdbError> {
    decode_auth_location_field(&WATERMARK_PREFIX, namespace, key, "authenticated watermark")
}

pub(crate) fn decode_auth_presence_location<F: Family>(
    namespace: AuthenticatedBackendNamespace,
    key: &Key,
) -> Result<Location<F>, QmdbError> {
    decode_auth_location_field(&PRESENCE_PREFIX, namespace, key, "authenticated presence")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode_update_index_value_present, encode_update_index_value};
    use commonware_storage::merkle::mmr;
    use commonware_storage::qmdb::any::value::VariableEncoding;
    use commonware_storage::qmdb::immutable::Operation as ImmutableOperation;
    use commonware_utils::sequence::FixedBytes;

    type TestOp = ImmutableOperation<mmr::Family, FixedBytes<32>, VariableEncoding<Vec<u8>>>;

    #[test]
    fn immutable_update_rows_store_only_a_presence_flag() {
        let key = FixedBytes::<32>::new([0x11; 32]);
        let value = b"a value long enough to dwarf a one byte presence flag".to_vec();
        let ops = vec![
            TestOp::Set(key.clone(), value),
            TestOp::Commit(None, Location::new(0)),
        ];

        let prepared = build_auth_immutable_upload_rows::<
            mmr::Family,
            FixedBytes<32>,
            VariableEncoding<Vec<u8>>,
        >(Location::new(1), &ops)
        .expect("build immutable upload rows");

        assert_eq!(prepared.keyed_operation_count, 1);

        let update_key = encode_update_key(key.as_ref(), Location::<mmr::Family>::new(0))
            .expect("encode update key");
        let (_, row_value) = prepared
            .aux_rows
            .iter()
            .find(|(row_key, _)| *row_key == update_key)
            .expect("immutable update row present");

        assert_eq!(row_value, &encode_update_index_value(true));
        assert_eq!(row_value.len(), 1, "update index row must be a single byte");
        assert!(decode_update_index_value_present(row_value).expect("decode presence"));
    }
}
