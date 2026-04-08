use exoware_sdk_rs::keys::{Key, KeyCodec, KeyMut};
use exoware_sdk_rs::kv_codec::{
    interleave_ordered_key_fields, StoredRow, StoredValue,
};
use datafusion::arrow::datatypes::i256;
use datafusion::common::{DataFusionError, Result as DataFusionResult};

use crate::types::*;
use crate::builder::archived_non_pk_value_is_valid;
use crate::writer::decode_list_element_archived;

pub(crate) fn primary_key_codec(table_prefix: u8) -> Result<KeyCodec, String> {
    if usize::from(table_prefix) >= MAX_TABLES {
        return Err(format!(
            "table prefix {table_prefix} exceeds max {} for codec layout",
            MAX_TABLES - 1
        ));
    }
    Ok(KeyCodec::new(
        PRIMARY_RESERVED_BITS,
        u16::from(table_prefix) << KEY_KIND_BITS,
    ))
}

pub(crate) fn secondary_index_codec(table_prefix: u8, index_id: u8) -> Result<KeyCodec, String> {
    if usize::from(table_prefix) >= MAX_TABLES {
        return Err(format!(
            "table prefix {table_prefix} exceeds max {} for codec layout",
            MAX_TABLES - 1
        ));
    }
    if index_id == 0 || usize::from(index_id) > MAX_INDEX_SPECS {
        return Err(format!(
            "index id {index_id} exceeds max {} for codec layout",
            MAX_INDEX_SPECS
        ));
    }
    let family = (u16::from(table_prefix) << (KEY_KIND_BITS + INDEX_SLOT_BITS))
        | (1u16 << INDEX_SLOT_BITS)
        | u16::from(index_id);
    Ok(KeyCodec::new(INDEX_FAMILY_BITS, family))
}

pub(crate) fn allocate_codec_key(codec: KeyCodec, payload_len: usize) -> Result<KeyMut, String> {
    let total_len = codec.min_key_len_for_payload(payload_len);
    codec
        .new_key_with_len(total_len)
        .map_err(|e| format!("failed to allocate codec key: {e}"))
}

pub(crate) fn ensure_codec_payload_fits(
    codec: KeyCodec,
    payload_len: usize,
    context: &str,
) -> Result<(), String> {
    let max_payload_len = codec.payload_capacity_bytes();
    if payload_len > max_payload_len {
        return Err(format!(
            "{context} exceeds codec payload capacity {max_payload_len} bytes"
        ));
    }
    Ok(())
}


pub(crate) fn primary_key_prefix_range(table_prefix: u8) -> KeyRange {
    let codec = primary_key_codec(table_prefix).expect("table prefix should fit primary key codec");
    let (start, end) = codec.prefix_bounds();
    KeyRange { start, end }
}

pub(crate) fn encode_i64_ordered(value: i64) -> [u8; 8] {
    ((value as u64) ^ 0x8000_0000_0000_0000).to_be_bytes()
}

pub(crate) fn decode_i64_ordered(bytes: [u8; 8]) -> i64 {
    (u64::from_be_bytes(bytes) ^ 0x8000_0000_0000_0000) as i64
}

pub(crate) fn encode_f64_ordered(value: f64) -> [u8; 8] {
    let bits = value.to_bits();
    let encoded = if bits & 0x8000_0000_0000_0000 != 0 {
        !bits
    } else {
        bits ^ 0x8000_0000_0000_0000
    };
    encoded.to_be_bytes()
}

pub(crate) fn decode_f64_ordered(bytes: [u8; 8]) -> f64 {
    let bits = u64::from_be_bytes(bytes);
    let decoded = if bits & 0x8000_0000_0000_0000 != 0 {
        bits ^ 0x8000_0000_0000_0000
    } else {
        !bits
    };
    f64::from_bits(decoded)
}

pub(crate) fn encode_i32_ordered(value: i32) -> [u8; 4] {
    ((value as u32) ^ 0x8000_0000).to_be_bytes()
}

pub(crate) fn decode_i32_ordered(bytes: [u8; 4]) -> i32 {
    (u32::from_be_bytes(bytes) ^ 0x8000_0000) as i32
}

pub(crate) fn encode_i128_ordered(value: i128) -> [u8; 16] {
    ((value as u128) ^ (1u128 << 127)).to_be_bytes()
}

pub(crate) fn decode_i128_ordered(bytes: [u8; 16]) -> i128 {
    (u128::from_be_bytes(bytes) ^ (1u128 << 127)) as i128
}

pub(crate) fn encode_i256_ordered(value: i256) -> [u8; 32] {
    let mut bytes = value.to_be_bytes();
    bytes[0] ^= 0x80;
    bytes
}

pub(crate) fn decode_i256_ordered(mut bytes: [u8; 32]) -> i256 {
    bytes[0] ^= 0x80;
    i256::from_be_bytes(bytes)
}

pub(crate) fn decode_fixed_text(bytes: &[u8]) -> Option<String> {
    decode_variable_text(bytes)
}

pub(crate) fn encode_string_variable(value: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(value.len() + 1);
    for byte in value.as_bytes() {
        match *byte {
            STRING_KEY_TERMINATOR => {
                out.push(STRING_KEY_ESCAPE_PREFIX);
                out.push(STRING_KEY_TERMINATOR);
            }
            STRING_KEY_ESCAPE_PREFIX => {
                out.push(STRING_KEY_ESCAPE_PREFIX);
                out.push(STRING_KEY_ESCAPE_PREFIX);
            }
            0xFF => {
                out.push(STRING_KEY_ESCAPE_PREFIX);
                out.push(STRING_KEY_ESCAPE_FF);
            }
            other => out.push(other),
        }
    }
    out.push(STRING_KEY_TERMINATOR);
    if out.len() > exoware_sdk_rs::keys::MAX_KEY_LEN {
        return Err(format!(
            "indexed string value '{}' exceeds max encoded key length {}",
            value,
            exoware_sdk_rs::keys::MAX_KEY_LEN
        ));
    }
    Ok(out)
}

pub(crate) fn decode_variable_text(bytes: &[u8]) -> Option<String> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0usize;
    while idx < bytes.len() {
        match bytes[idx] {
            STRING_KEY_TERMINATOR => return String::from_utf8(out).ok(),
            STRING_KEY_ESCAPE_PREFIX => {
                let escaped = *bytes.get(idx + 1)?;
                match escaped {
                    STRING_KEY_TERMINATOR => out.push(STRING_KEY_TERMINATOR),
                    STRING_KEY_ESCAPE_PREFIX => out.push(STRING_KEY_ESCAPE_PREFIX),
                    STRING_KEY_ESCAPE_FF => out.push(0xFF),
                    _ => return None,
                }
                idx += 2;
            }
            byte => {
                out.push(byte);
                idx += 1;
            }
        }
    }
    None
}

pub(crate) fn encode_cell_into_ordered_key_bytes(
    cell: &CellValue,
    kind: ColumnKind,
) -> Result<Vec<u8>, String> {
    if let (ColumnKind::Utf8, CellValue::Utf8(v)) = (kind, cell) {
        return encode_string_variable(v);
    }
    let mut out = vec![0u8; kind.key_width()];
    match (kind, cell) {
        (ColumnKind::Int64, CellValue::Int64(v)) => {
            out.copy_from_slice(&encode_i64_ordered(*v));
            Ok(out)
        }
        (ColumnKind::UInt64, CellValue::UInt64(v)) => {
            out.copy_from_slice(&v.to_be_bytes());
            Ok(out)
        }
        (ColumnKind::Float64, CellValue::Float64(v)) => {
            out.copy_from_slice(&encode_f64_ordered(*v));
            Ok(out)
        }
        (ColumnKind::Boolean, CellValue::Boolean(v)) => {
            out[0] = u8::from(*v);
            Ok(out)
        }
        (ColumnKind::Date32, CellValue::Date32(v)) => {
            out.copy_from_slice(&encode_i32_ordered(*v));
            Ok(out)
        }
        (ColumnKind::Date64, CellValue::Date64(v)) => {
            out.copy_from_slice(&encode_i64_ordered(*v));
            Ok(out)
        }
        (ColumnKind::Timestamp, CellValue::Timestamp(v)) => {
            out.copy_from_slice(&encode_i64_ordered(*v));
            Ok(out)
        }
        (ColumnKind::Decimal128, CellValue::Decimal128(v)) => {
            out.copy_from_slice(&encode_i128_ordered(*v));
            Ok(out)
        }
        (ColumnKind::Decimal256, CellValue::Decimal256(v)) => {
            out.copy_from_slice(&encode_i256_ordered(*v));
            Ok(out)
        }
        (ColumnKind::FixedSizeBinary(n), CellValue::FixedBinary(v)) => {
            if v.len() != n {
                return Err(format!(
                    "FixedSizeBinary({n}) key column requires exactly {n} bytes, got {}",
                    v.len()
                ));
            }
            out.copy_from_slice(v);
            Ok(out)
        }
        _ => Err(format!(
            "type mismatch while encoding key value (expected {kind:?}, got {cell:?})"
        )),
    }
}

pub(crate) fn decode_cell_from_ordered_key_bytes(bytes: &[u8], kind: ColumnKind) -> Option<CellValue> {
    Some(match kind {
        ColumnKind::Int64 => {
            let raw = bytes.try_into().ok()?;
            CellValue::Int64(decode_i64_ordered(raw))
        }
        ColumnKind::UInt64 => {
            let raw = bytes.try_into().ok()?;
            CellValue::UInt64(u64::from_be_bytes(raw))
        }
        ColumnKind::Float64 => {
            let raw = bytes.try_into().ok()?;
            CellValue::Float64(decode_f64_ordered(raw))
        }
        ColumnKind::Boolean => CellValue::Boolean(*bytes.first()? != 0),
        ColumnKind::Utf8 => CellValue::Utf8(decode_fixed_text(bytes)?),
        ColumnKind::Date32 => {
            let raw = bytes.try_into().ok()?;
            CellValue::Date32(decode_i32_ordered(raw))
        }
        ColumnKind::Date64 => {
            let raw = bytes.try_into().ok()?;
            CellValue::Date64(decode_i64_ordered(raw))
        }
        ColumnKind::Timestamp => {
            let raw = bytes.try_into().ok()?;
            CellValue::Timestamp(decode_i64_ordered(raw))
        }
        ColumnKind::Decimal128 => {
            let raw = bytes.try_into().ok()?;
            CellValue::Decimal128(decode_i128_ordered(raw))
        }
        ColumnKind::Decimal256 => {
            let raw = bytes.try_into().ok()?;
            CellValue::Decimal256(decode_i256_ordered(raw))
        }
        ColumnKind::FixedSizeBinary(n) => {
            if bytes.len() != n {
                return None;
            }
            CellValue::FixedBinary(bytes.to_vec())
        }
        ColumnKind::List(_) => return None,
    })
}

pub(crate) fn decode_cell_from_codec_payload_with_len(
    codec: KeyCodec,
    key: &Key,
    payload_offset: usize,
    kind: ColumnKind,
) -> Option<(CellValue, usize)> {
    match kind {
        ColumnKind::Utf8 => {
            let mut bytes = Vec::new();
            let mut idx = 0usize;
            let mut escaped = false;
            loop {
                let byte = codec
                    .read_payload(key, payload_offset + idx, 1)
                    .ok()?
                    .into_iter()
                    .next()?;
                bytes.push(byte);
                idx += 1;
                if escaped {
                    escaped = false;
                    continue;
                }
                if byte == STRING_KEY_ESCAPE_PREFIX {
                    escaped = true;
                    continue;
                }
                if byte == STRING_KEY_TERMINATOR {
                    break;
                }
            }
            decode_cell_from_ordered_key_bytes(&bytes, kind).map(|cell| (cell, bytes.len()))
        }
        _ => {
            let bytes = codec
                .read_payload(key, payload_offset, kind.key_width())
                .ok()?;
            decode_cell_from_ordered_key_bytes(&bytes, kind).map(|cell| (cell, kind.key_width()))
        }
    }
}

pub(crate) fn encode_primary_key(
    table_prefix: u8,
    pk_values: &[&CellValue],
    model: &TableModel,
) -> Result<Key, String> {
    if table_prefix != model.table_prefix {
        return Err("table prefix does not match model".to_string());
    }
    let codec = model.primary_key_codec;
    let payload_len = pk_values
        .iter()
        .zip(model.primary_key_kinds.iter())
        .try_fold(0usize, |acc, (val, kind)| {
            encode_cell_into_ordered_key_bytes(val, *kind).map(|encoded| acc + encoded.len())
        })?;
    ensure_codec_payload_fits(codec, payload_len, "primary key payload")?;
    let mut key = allocate_codec_key(codec, payload_len)?;
    let mut payload_offset = 0usize;
    for (val, kind) in pk_values.iter().zip(model.primary_key_kinds.iter()) {
        let encoded = encode_cell_into_ordered_key_bytes(val, *kind)?;
        codec
            .write_payload(&mut key, payload_offset, &encoded)
            .map_err(|e| format!("failed to write codec payload: {e}"))?;
        payload_offset += encoded.len();
    }
    Ok(key.freeze())
}

pub(crate) fn encode_primary_key_from_row(
    table_prefix: u8,
    row: &KvRow,
    model: &TableModel,
) -> Result<Key, String> {
    let vals: Vec<&CellValue> = row.primary_key_values(model);
    encode_primary_key(table_prefix, &vals, model)
}

pub(crate) fn encode_primary_key_bound(
    table_prefix: u8,
    pk_values: &[&CellValue],
    model: &TableModel,
    upper_tail: bool,
) -> Result<Key, String> {
    if table_prefix != model.table_prefix {
        return Err("table prefix does not match model".to_string());
    }
    let codec = model.primary_key_codec;
    let encoded_parts = pk_values
        .iter()
        .zip(model.primary_key_kinds.iter())
        .map(|(val, kind)| encode_cell_into_ordered_key_bytes(val, *kind))
        .collect::<Result<Vec<_>, _>>()?;
    let encoded_width = encoded_parts.iter().map(|part| part.len()).sum::<usize>();
    let payload_len = if upper_tail {
        codec.payload_capacity_bytes()
    } else {
        model.primary_key_width.max(encoded_width)
    };
    let mut key = allocate_codec_key(codec, payload_len)?;
    let mut payload_offset = 0usize;
    for encoded in &encoded_parts {
        codec
            .write_payload(&mut key, payload_offset, encoded)
            .map_err(|e| format!("failed to write codec payload: {e}"))?;
        payload_offset += encoded.len();
    }
    if upper_tail {
        let remaining = codec.payload_capacity_bytes().saturating_sub(encoded_width);
        codec
            .fill_payload(&mut key, encoded_width, remaining, 0xFF)
            .map_err(|e| format!("failed to fill codec payload: {e}"))?;
    }
    Ok(key.freeze())
}

#[cfg(test)]
pub(crate) fn decode_primary_key(table_prefix: u8, key: &Key, model: &TableModel) -> Option<Vec<CellValue>> {
    if table_prefix != model.table_prefix || !model.primary_key_codec.matches(key) {
        return None;
    }
    let mut values = Vec::with_capacity(model.primary_key_kinds.len());
    let mut payload_offset = 0usize;
    for kind in &model.primary_key_kinds {
        let (val, consumed) = decode_cell_from_codec_payload_with_len(
            model.primary_key_codec,
            key,
            payload_offset,
            *kind,
        )?;
        payload_offset += consumed;
        values.push(val);
    }
    Some(values)
}

pub(crate) fn decode_primary_key_selected(
    table_prefix: u8,
    key: &Key,
    model: &TableModel,
    required_pk_mask: &[bool],
) -> Option<Vec<CellValue>> {
    if table_prefix != model.table_prefix || !model.primary_key_codec.matches(key) {
        return None;
    }
    if !required_pk_mask.iter().any(|required| *required) {
        return Some(Vec::new());
    }
    if required_pk_mask.len() != model.primary_key_kinds.len() {
        return None;
    }
    let mut values = vec![CellValue::Null; model.primary_key_kinds.len()];
    let mut payload_offset = 0usize;
    for (pk_pos, kind) in model.primary_key_kinds.iter().enumerate() {
        let (cell, consumed) = decode_cell_from_codec_payload_with_len(
            model.primary_key_codec,
            key,
            payload_offset,
            *kind,
        )?;
        if required_pk_mask[pk_pos] {
            values[pk_pos] = cell;
        }
        payload_offset += consumed;
    }
    Some(values)
}

pub(crate) fn encode_secondary_index_key(
    table_prefix: u8,
    spec: &ResolvedIndexSpec,
    model: &TableModel,
    row: &KvRow,
) -> Result<Key, String> {
    if table_prefix != model.table_prefix {
        return Err("table prefix does not match model".to_string());
    }
    let codec = spec.codec;
    let mut payload_offset = 0usize;
    let encoded_index_fields = spec
        .key_columns
        .iter()
        .map(|col_idx| {
            let col = model.column(*col_idx);
            encode_cell_into_ordered_key_bytes(row.value_at(*col_idx), col.kind)
                .map_err(|e| format!("index '{}' column '{}': {e}", spec.name, col.name))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let encoded_index_key = match spec.layout {
        IndexLayout::Lexicographic => encoded_index_fields.concat(),
        IndexLayout::ZOrder => interleave_ordered_key_fields(&encoded_index_fields),
    };
    let pk_payload_len = model
        .primary_key_indices
        .iter()
        .zip(model.primary_key_kinds.iter())
        .try_fold(0usize, |acc, (&pk_idx, &pk_kind)| {
            encode_cell_into_ordered_key_bytes(row.value_at(pk_idx), pk_kind)
                .map(|encoded| acc + encoded.len())
        })?;
    let total_payload_len = encoded_index_key.len() + pk_payload_len;
    ensure_codec_payload_fits(
        codec,
        total_payload_len,
        &format!("index '{}' payload", spec.name),
    )?;
    let mut key = allocate_codec_key(codec, total_payload_len)?;
    codec
        .write_payload(&mut key, payload_offset, &encoded_index_key)
        .map_err(|e| format!("failed to write codec payload: {e}"))?;
    payload_offset += encoded_index_key.len();
    debug_assert!(payload_offset <= codec.payload_capacity_bytes());

    for (&pk_idx, &pk_kind) in model
        .primary_key_indices
        .iter()
        .zip(model.primary_key_kinds.iter())
    {
        let encoded = encode_cell_into_ordered_key_bytes(row.value_at(pk_idx), pk_kind)?;
        codec
            .write_payload(&mut key, payload_offset, &encoded)
            .map_err(|e| format!("failed to write codec payload: {e}"))?;
        payload_offset += encoded.len();
    }
    Ok(key.freeze())
}

pub(crate) fn encode_secondary_index_key_from_parts(
    table_prefix: u8,
    spec: &ResolvedIndexSpec,
    model: &TableModel,
    pk_values: &[CellValue],
    archived: &StoredRow,
) -> DataFusionResult<Key> {
    if table_prefix != model.table_prefix {
        return Err(DataFusionError::Execution(
            "table prefix does not match model".to_string(),
        ));
    }
    if pk_values.len() != model.primary_key_indices.len() {
        return Err(DataFusionError::Execution(
            "primary key value count does not match model".to_string(),
        ));
    }
    if archived.values.len() != model.columns.len() {
        return Err(DataFusionError::Execution(
            "archived row column count mismatch".to_string(),
        ));
    }

    let codec = spec.codec;
    let mut payload_offset = 0usize;

    let encoded_index_fields = spec
        .key_columns
        .iter()
        .map(|&col_idx| encode_index_column_from_parts(spec, model, col_idx, pk_values, archived))
        .collect::<DataFusionResult<Vec<_>>>()?;
    let encoded_index_key = match spec.layout {
        IndexLayout::Lexicographic => encoded_index_fields.concat(),
        IndexLayout::ZOrder => interleave_ordered_key_fields(&encoded_index_fields),
    };
    let pk_payload_len = model.primary_key_kinds.iter().enumerate().try_fold(
        0usize,
        |acc, (pk_pos, &pk_kind)| {
            let value = pk_values.get(pk_pos).ok_or_else(|| {
                DataFusionError::Execution(
                    "missing primary key value while sizing index key".to_string(),
                )
            })?;
            encode_cell_into_ordered_key_bytes(value, pk_kind)
                .map(|encoded| acc + encoded.len())
                .map_err(DataFusionError::Execution)
        },
    )?;
    let total_payload_len = encoded_index_key.len() + pk_payload_len;
    ensure_codec_payload_fits(
        codec,
        total_payload_len,
        &format!("index '{}' payload", spec.name),
    )
    .map_err(DataFusionError::Execution)?;
    let mut key =
        allocate_codec_key(codec, total_payload_len).map_err(DataFusionError::Execution)?;
    codec
        .write_payload(&mut key, payload_offset, &encoded_index_key)
        .map_err(|e| DataFusionError::Execution(format!("failed to write codec payload: {e}")))?;
    payload_offset += encoded_index_key.len();
    debug_assert!(payload_offset <= codec.payload_capacity_bytes());

    for (pk_pos, &pk_kind) in model.primary_key_kinds.iter().enumerate() {
        let value = pk_values.get(pk_pos).ok_or_else(|| {
            DataFusionError::Execution("missing primary key value while encoding index".to_string())
        })?;
        let encoded = encode_cell_into_ordered_key_bytes(value, pk_kind)
            .map_err(DataFusionError::Execution)?;
        codec
            .write_payload(&mut key, payload_offset, &encoded)
            .map_err(|e| {
                DataFusionError::Execution(format!("failed to write codec payload: {e}"))
            })?;
        payload_offset += encoded.len();
    }
    Ok(key.freeze())
}

pub(crate) fn encode_index_column_from_parts(
    spec: &ResolvedIndexSpec,
    model: &TableModel,
    col_idx: usize,
    pk_values: &[CellValue],
    archived: &StoredRow,
) -> DataFusionResult<Vec<u8>> {
    let col = model.column(col_idx);
    if let Some(pk_pos) = model.pk_position(col_idx) {
        let value = pk_values.get(pk_pos).ok_or_else(|| {
            DataFusionError::Execution(format!(
                "missing primary key value for index '{}' column '{}'",
                spec.name, col.name
            ))
        })?;
        return encode_cell_into_ordered_key_bytes(value, col.kind)
            .map_err(DataFusionError::Execution);
    }

    let stored_opt = archived
        .values
        .get(col_idx)
        .and_then(|value| value.as_ref());
    if !archived_non_pk_value_is_valid(col, stored_opt) {
        return Err(DataFusionError::Execution(format!(
            "invalid archived value for index '{}' column '{}'",
            spec.name, col.name
        )));
    }
    let value = cell_value_from_archived_non_pk(col, stored_opt)?.ok_or_else(|| {
        DataFusionError::Execution(format!(
            "index '{}' column '{}' is NULL but key columns must be non-null",
            spec.name, col.name
        ))
    })?;
    encode_cell_into_ordered_key_bytes(&value, col.kind).map_err(DataFusionError::Execution)
}

pub(crate) fn cell_value_from_archived_non_pk(
    col: &ResolvedColumn,
    stored_opt: Option<&StoredValue>,
) -> DataFusionResult<Option<CellValue>> {
    let Some(stored) = stored_opt else {
        if col.nullable {
            return Ok(None);
        }
        return Err(DataFusionError::Execution(format!(
            "column '{}' is not nullable but archived value is NULL",
            col.name
        )));
    };
    let value = match (col.kind, stored) {
        (ColumnKind::Int64, StoredValue::Int64(v)) => CellValue::Int64(*v),
        (ColumnKind::UInt64, StoredValue::UInt64(v)) => CellValue::UInt64(*v),
        (ColumnKind::Float64, StoredValue::Float64(v)) => CellValue::Float64(*v),
        (ColumnKind::Float64, StoredValue::Int64(v)) => {
            CellValue::Float64(*v as f64)
        }
        (ColumnKind::Boolean, StoredValue::Boolean(v)) => CellValue::Boolean(*v),
        (ColumnKind::Date32, StoredValue::Int64(v)) => {
            CellValue::Date32(*v as i32)
        }
        (ColumnKind::Date64, StoredValue::Int64(v)) => CellValue::Date64(*v),
        (ColumnKind::Timestamp, StoredValue::Int64(v)) => CellValue::Timestamp(*v),
        (ColumnKind::Decimal128, StoredValue::Bytes(bytes)) => {
            let arr: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
                DataFusionError::Execution(format!(
                    "column '{}' expected Decimal128 archived payload width 16",
                    col.name
                ))
            })?;
            CellValue::Decimal128(i128::from_le_bytes(arr))
        }
        (ColumnKind::Decimal256, StoredValue::Bytes(bytes)) => {
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                DataFusionError::Execution(format!(
                    "column '{}' expected Decimal256 archived payload width 32",
                    col.name
                ))
            })?;
            CellValue::Decimal256(i256::from_le_bytes(arr))
        }
        (ColumnKind::Utf8, StoredValue::Utf8(v)) => CellValue::Utf8(v.as_str().to_string()),
        (ColumnKind::FixedSizeBinary(expected), StoredValue::Bytes(v)) => {
            if v.as_slice().len() != expected {
                return Err(DataFusionError::Execution(format!(
                    "column '{}' expects FixedSizeBinary({expected}) archived payload width {}, got {}",
                    col.name,
                    expected,
                    v.as_slice().len()
                )));
            }
            CellValue::FixedBinary(v.as_slice().to_vec())
        }
        (ColumnKind::List(elem), StoredValue::List(items)) => {
            let mut cells = Vec::with_capacity(items.len());
            for item in items.iter() {
                cells.push(decode_list_element_archived(elem, item).ok_or_else(|| {
                    DataFusionError::Execution(format!(
                        "column '{}' list element type mismatch in archived payload",
                        col.name
                    ))
                })?);
            }
            CellValue::List(cells)
        }
        _ => {
            return Err(DataFusionError::Execution(format!(
                "column '{}' archived type mismatch (expected {:?})",
                col.name, col.kind
            )))
        }
    };
    Ok(Some(value))
}

#[cfg(test)]
pub(crate) fn decode_secondary_index_key(
    table_prefix: u8,
    spec: &ResolvedIndexSpec,
    model: &TableModel,
    key: &Key,
) -> Option<DecodedIndexEntry> {
    decode_secondary_index_key_with_masks(table_prefix, spec, model, key, None, None)
}

pub(crate) fn decode_secondary_index_key_with_masks(
    table_prefix: u8,
    spec: &ResolvedIndexSpec,
    model: &TableModel,
    key: &Key,
    required_index_columns: Option<&[bool]>,
    required_pk_mask: Option<&[bool]>,
) -> Option<DecodedIndexEntry> {
    if table_prefix != model.table_prefix || !spec.codec.matches(key) {
        return None;
    }
    let mut decoded = DecodedIndexEntry::default();
    let zorder_fields = if spec.layout == IndexLayout::ZOrder {
        let index_key_bytes = spec
            .codec
            .read_payload(key, 0, spec.key_columns_width)
            .ok()?;
        Some(exoware_sdk_rs::kv_codec::deinterleave_ordered_key_fields(
            &index_key_bytes,
            &spec
                .key_columns
                .iter()
                .map(|col_idx| u8::try_from(model.column(*col_idx).kind.key_width()).ok())
                .collect::<Option<Vec<_>>>()?,
        )?)
    } else {
        None
    };
    let mut payload_offset = 0usize;
    for (key_pos, col_idx) in spec.key_columns.iter().enumerate() {
        let col = model.column(*col_idx);
        let should_decode = required_index_columns
            .and_then(|cols| cols.get(*col_idx))
            .copied()
            .unwrap_or(true);
        if should_decode {
            let cell = if let Some(fields) = &zorder_fields {
                decode_cell_from_ordered_key_bytes(fields.get(key_pos)?, col.kind)?
            } else {
                decode_cell_from_codec_payload_with_len(spec.codec, key, payload_offset, col.kind)?
                    .0
            };
            decoded.values.insert(*col_idx, cell);
        }
        if spec.layout == IndexLayout::Lexicographic {
            let consumed =
                decode_cell_from_codec_payload_with_len(spec.codec, key, payload_offset, col.kind)?
                    .1;
            payload_offset += consumed;
        }
    }
    if let Some(fields) = &zorder_fields {
        payload_offset = fields.iter().map(Vec::len).sum();
    }
    debug_assert!(payload_offset <= spec.codec.payload_capacity_bytes());
    let decode_all_pk = required_pk_mask.is_none();
    let decode_some_pk = required_pk_mask
        .map(|mask: &[bool]| mask.iter().any(|required| *required))
        .unwrap_or(true);
    if decode_all_pk || decode_some_pk {
        decoded.primary_key_values = vec![CellValue::Null; model.primary_key_kinds.len()];
    }
    let mut all_pk_values = Vec::with_capacity(model.primary_key_kinds.len());
    for (pk_pos, kind) in model.primary_key_kinds.iter().enumerate() {
        let should_decode = if decode_all_pk {
            true
        } else {
            required_pk_mask
                .and_then(|mask| mask.get(pk_pos))
                .copied()
                .unwrap_or(false)
        };
        let (val, consumed) =
            decode_cell_from_codec_payload_with_len(spec.codec, key, payload_offset, *kind)?;
        if should_decode {
            decoded.primary_key_values[pk_pos] = val.clone();
        }
        all_pk_values.push(
            decoded
                .primary_key_values
                .get(pk_pos)
                .cloned()
                .unwrap_or(val),
        );
        payload_offset += consumed;
    }
    let pk_refs = all_pk_values.iter().collect::<Vec<_>>();
    decoded.primary_key = match encode_primary_key(table_prefix, &pk_refs, model) {
        Ok(key) => key,
        Err(_) => {
            return None;
        }
    };
    Some(decoded)
}

pub(crate) fn decode_secondary_index_primary_key(
    table_prefix: u8,
    spec: &ResolvedIndexSpec,
    model: &TableModel,
    key: &Key,
) -> Option<Key> {
    if table_prefix != model.table_prefix || !spec.codec.matches(key) {
        return None;
    }
    decode_secondary_index_key_with_masks(table_prefix, spec, model, key, Some(&[]), None)
        .map(|decoded| decoded.primary_key)
}

pub(crate) fn next_key(key: &Key) -> Option<Key> {
    exoware_sdk_rs::keys::next_key(key)
}
