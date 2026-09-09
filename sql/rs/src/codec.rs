use datafusion::arrow::datatypes::i256;
use datafusion::common::{DataFusionError, Result as DataFusionResult};
use exoware_sdk::keys::{Key, Prefix};
use exoware_sdk::kv_codec::{interleave_ordered_key_fields, StoredRow, StoredValue};

use crate::builder::archived_non_pk_value_is_valid;
use crate::types::*;
use crate::writer::decode_list_element_archived;

/// Pack table prefix (high nibble) and family discriminator (low nibble)
/// into the one-byte family prefix. Callers validate both fit in 4 bits.
pub(crate) fn family_byte(table_prefix: u8, discriminator: u8) -> u8 {
    debug_assert!(table_prefix < 0x10 && discriminator < 0x10);
    (table_prefix << 4) | discriminator
}

pub(crate) fn primary_key_prefix(table_prefix: u8) -> Result<Prefix, String> {
    if usize::from(table_prefix) >= MAX_TABLES {
        return Err(format!(
            "table prefix {table_prefix} exceeds max {} for key layout",
            MAX_TABLES - 1
        ));
    }
    Ok(Prefix::from_byte(family_byte(
        table_prefix,
        PRIMARY_FAMILY_DISCRIMINATOR,
    )))
}

pub(crate) fn secondary_index_prefix(table_prefix: u8, index_id: u8) -> Result<Prefix, String> {
    if usize::from(table_prefix) >= MAX_TABLES {
        return Err(format!(
            "table prefix {table_prefix} exceeds max {} for key layout",
            MAX_TABLES - 1
        ));
    }
    if index_id == 0 {
        return Err("index id 0 collides with the primary key family discriminator".to_string());
    }
    if usize::from(index_id) > MAX_INDEX_SPECS {
        return Err(format!(
            "index id {index_id} exceeds max {} for key layout",
            MAX_INDEX_SPECS
        ));
    }
    Ok(Prefix::from_byte(family_byte(table_prefix, index_id)))
}

pub(crate) fn primary_key_prefix_range(table_prefix: u8) -> KeyRange {
    let prefix =
        primary_key_prefix(table_prefix).expect("table prefix should fit primary key prefix");
    let (start, end) = prefix.bounds();
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
    if out.len() > exoware_sdk::keys::MAX_KEY_LEN {
        return Err(format!(
            "indexed string value '{}' exceeds max encoded key length {}",
            value,
            exoware_sdk::keys::MAX_KEY_LEN
        ));
    }
    Ok(out)
}

pub(crate) fn decode_variable_text(bytes: &[u8]) -> Option<String> {
    decode_key_text(bytes, true)?.0
}

fn decode_key_text(bytes: &[u8], selected: bool) -> Option<(Option<String>, usize)> {
    let mut text = selected.then(|| String::with_capacity(bytes.len()));
    let mut segment = 0;
    let mut offset = 0;
    loop {
        let byte = *bytes.get(offset)?;
        if byte != STRING_KEY_TERMINATOR && byte != STRING_KEY_ESCAPE_PREFIX {
            offset += 1;
            continue;
        }
        let plain = std::str::from_utf8(&bytes[segment..offset]).ok()?;
        if let Some(text) = &mut text {
            text.push_str(plain);
        }
        offset += 1;
        if byte == STRING_KEY_TERMINATOR {
            return Some((text, offset));
        }
        let escaped = *bytes.get(offset)?;
        // Escaped 0xFF cannot occur in a UTF-8 string
        if !matches!(escaped, STRING_KEY_TERMINATOR | STRING_KEY_ESCAPE_PREFIX) {
            return None;
        }
        if let Some(text) = &mut text {
            text.push(char::from(escaped));
        }
        offset += 1;
        segment = offset;
    }
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

pub(crate) fn decode_cell_from_ordered_key_bytes(
    bytes: &[u8],
    kind: ColumnKind,
) -> Option<CellValue> {
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
        ColumnKind::Utf8 => CellValue::Utf8(decode_variable_text(bytes)?),
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
        ColumnKind::Binary | ColumnKind::List(_) => return None,
    })
}

/// Validate one ordered-key cell, optionally decode its value, and return the consumed byte count.
fn decode_key_cell(
    bytes: &[u8],
    kind: ColumnKind,
    selected: bool,
) -> Option<(Option<CellValue>, usize)> {
    if kind == ColumnKind::Utf8 {
        let (text, len) = decode_key_text(bytes, selected)?;
        return Some((text.map(CellValue::Utf8), len));
    }
    let width = kind.fixed_key_width()?;
    let field = bytes.get(..width)?;
    if kind == ColumnKind::Boolean && !matches!(field.first(), Some(0 | 1)) {
        return None;
    }
    let value = if selected {
        Some(decode_cell_from_ordered_key_bytes(field, kind)?)
    } else {
        None
    };
    Some((value, width))
}

pub(crate) fn encode_primary_key(
    table_prefix: u8,
    pk_values: &[&CellValue],
    model: &TableModel,
) -> Result<Key, String> {
    if table_prefix != model.table_prefix {
        return Err("table prefix does not match model".to_string());
    }
    let prefix = &model.primary_key_prefix;
    let mut payload = Vec::with_capacity(model.primary_key_width);
    for (val, kind) in pk_values.iter().zip(model.primary_key_kinds.iter()) {
        let encoded = encode_cell_into_ordered_key_bytes(val, *kind)?;
        payload.extend_from_slice(&encoded);
    }
    prefix
        .encode(&payload)
        .map_err(|e| format!("failed to encode primary key: {e}"))
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
    let prefix = &model.primary_key_prefix;
    let mut payload = Vec::new();
    for (val, kind) in pk_values.iter().zip(model.primary_key_kinds.iter()) {
        payload.extend_from_slice(&encode_cell_into_ordered_key_bytes(val, *kind)?);
    }
    if upper_tail {
        // Upper bound: pad the encoded fields with 0xFF out to the family's
        // payload capacity so the bound is `prefix ++ fields ++ 0xFF-to-MAX`.
        payload.resize(prefix.max_payload_len().max(payload.len()), 0xFF);
    }
    // Lower bound: exactly the encoded prefix. Padding to the fixed
    // primary-key width would sort the bound above variable-width stored keys
    // that encode shorter (e.g. a Utf8 pk below the reserved slot width).
    prefix
        .encode(&payload)
        .map_err(|e| format!("failed to encode primary key bound: {e}"))
}

#[cfg(test)]
pub(crate) fn decode_primary_key(
    table_prefix: u8,
    key: &Key,
    model: &TableModel,
) -> Option<Vec<CellValue>> {
    if table_prefix != model.table_prefix {
        return None;
    }
    decode_primary_key_payload(model.primary_key_prefix.strip_slice(key)?, model, None)
}

/// Validate a complete canonical key and decode only the selected primary-key fields.
/// An empty mask validates the key without materializing any values.
pub(crate) fn decode_primary_key_selected(
    table_prefix: u8,
    key: &Key,
    model: &TableModel,
    required_pk_mask: &[bool],
) -> Option<Vec<CellValue>> {
    if table_prefix != model.table_prefix {
        return None;
    }
    decode_primary_key_payload(
        model.primary_key_prefix.strip_slice(key)?,
        model,
        Some(required_pk_mask),
    )
}

fn decode_primary_key_payload(
    payload: &[u8],
    model: &TableModel,
    mask: Option<&[bool]>,
) -> Option<Vec<CellValue>> {
    if payload.len() > model.primary_key_prefix.max_payload_len() {
        return None;
    }
    if mask.is_some_and(|mask| !mask.is_empty() && mask.len() != model.primary_key_kinds.len()) {
        return None;
    }
    let mut values = if mask.is_none_or(|mask| mask.iter().any(|selected| *selected)) {
        vec![CellValue::Null; model.primary_key_kinds.len()]
    } else {
        Vec::new()
    };
    let mut offset = 0;
    for (idx, kind) in model.primary_key_kinds.iter().enumerate() {
        let selected = mask.is_none_or(|mask| mask.get(idx).copied().unwrap_or(false));
        let (value, len) = decode_key_cell(payload.get(offset..)?, *kind, selected)?;
        if let Some(value) = value {
            values[idx] = value;
        }
        offset += len;
    }
    (offset == payload.len()).then_some(values)
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
    let prefix = &spec.prefix;
    let encoded_index_fields = spec
        .key_columns
        .iter()
        .map(|col_idx| {
            let col = model.column(*col_idx);
            encode_cell_into_ordered_key_bytes(row.value_at(*col_idx), col.kind)
                .map_err(|e| format!("index '{}' column '{}': {e}", spec.name, col.name))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut payload = match spec.layout {
        IndexLayout::Lexicographic => encoded_index_fields.concat(),
        IndexLayout::ZOrder => interleave_ordered_key_fields(&encoded_index_fields),
    };
    payload.reserve(model.primary_key_width);
    for (&pk_idx, &pk_kind) in model
        .primary_key_indices
        .iter()
        .zip(model.primary_key_kinds.iter())
    {
        let encoded = encode_cell_into_ordered_key_bytes(row.value_at(pk_idx), pk_kind)?;
        payload.extend_from_slice(&encoded);
    }
    prefix
        .encode(&payload)
        .map_err(|e| format!("failed to encode index '{}' key: {e}", spec.name))
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

    let prefix = &spec.prefix;

    let encoded_index_fields = spec
        .key_columns
        .iter()
        .map(|&col_idx| encode_index_column_from_parts(spec, model, col_idx, pk_values, archived))
        .collect::<DataFusionResult<Vec<_>>>()?;
    let mut payload = match spec.layout {
        IndexLayout::Lexicographic => encoded_index_fields.concat(),
        IndexLayout::ZOrder => interleave_ordered_key_fields(&encoded_index_fields),
    };
    payload.reserve(model.primary_key_width);
    for (pk_pos, &pk_kind) in model.primary_key_kinds.iter().enumerate() {
        let value = pk_values.get(pk_pos).ok_or_else(|| {
            DataFusionError::Execution("missing primary key value while encoding index".to_string())
        })?;
        let encoded = encode_cell_into_ordered_key_bytes(value, pk_kind)
            .map_err(DataFusionError::Execution)?;
        payload.extend_from_slice(&encoded);
    }
    prefix.encode(&payload).map_err(|e| {
        DataFusionError::Execution(format!("failed to encode index '{}' key: {e}", spec.name))
    })
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
        (ColumnKind::Float64, StoredValue::Int64(v)) => CellValue::Float64(*v as f64),
        (ColumnKind::Boolean, StoredValue::Boolean(v)) => CellValue::Boolean(*v),
        (ColumnKind::Date32, StoredValue::Int64(v)) => CellValue::Date32(*v as i32),
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
        (ColumnKind::Binary, StoredValue::Bytes(v)) => CellValue::Binary(v.as_slice().to_vec()),
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
    if table_prefix != model.table_prefix {
        return None;
    }
    let payload = spec.prefix.strip_slice(key)?;
    if payload.len() > spec.prefix.max_payload_len() {
        return None;
    }
    let mut decoded = DecodedIndexEntry::default();
    let selected = |idx: usize| {
        required_index_columns.is_none_or(|mask| mask.get(idx).copied().unwrap_or(false))
    };
    let mut offset = 0;
    if spec.layout == IndexLayout::ZOrder {
        let key_fields = payload.get(..spec.key_columns_width)?;
        if spec
            .key_columns
            .iter()
            .any(|&idx| selected(idx) || model.column(idx).kind == ColumnKind::Boolean)
        {
            let fields = exoware_sdk::kv_codec::deinterleave_ordered_key_fields(
                key_fields,
                &spec
                    .key_columns
                    .iter()
                    .map(|&idx| u8::try_from(model.column(idx).kind.key_width()).ok())
                    .collect::<Option<Vec<_>>>()?,
            )?;
            for (&idx, field) in spec.key_columns.iter().zip(&fields) {
                if let (Some(value), _) =
                    decode_key_cell(field, model.column(idx).kind, selected(idx))?
                {
                    decoded.values.insert(idx, value);
                }
            }
        }
        offset = spec.key_columns_width;
    } else {
        for &idx in &spec.key_columns {
            let (value, len) = decode_key_cell(
                payload.get(offset..)?,
                model.column(idx).kind,
                selected(idx),
            )?;
            if let Some(value) = value {
                decoded.values.insert(idx, value);
            }
            offset += len;
        }
    }
    let suffix = payload.get(offset..)?;
    decoded.primary_key_values = decode_primary_key_payload(suffix, model, required_pk_mask)?;
    decoded.primary_key = model.primary_key_prefix.encode(suffix).ok()?;
    Some(decoded)
}

#[cfg(test)]
pub(crate) fn decode_secondary_index_primary_key(
    table_prefix: u8,
    spec: &ResolvedIndexSpec,
    model: &TableModel,
    key: &Key,
) -> Option<Key> {
    decode_secondary_index_key_with_masks(table_prefix, spec, model, key, Some(&[]), Some(&[]))
        .map(|decoded| decoded.primary_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::datatypes::DataType;

    fn model() -> TableModel {
        TableModel::from_config(
            &KvTableConfig::new(
                0,
                vec![
                    TableColumnConfig::new("entity", DataType::Utf8, false),
                    TableColumnConfig::new("version", DataType::UInt64, false),
                    TableColumnConfig::new("active", DataType::Boolean, false),
                ],
                vec!["entity".into(), "version".into()],
                vec![],
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn selected_primary_key_decoder_validates_unselected_fields_and_exact_length() {
        let model = model();
        let entity = CellValue::Utf8("a\0é\u{1}z".into());
        let version = CellValue::UInt64(9);
        let key = encode_primary_key(0, &[&entity, &version], &model).unwrap();
        let selected = decode_primary_key_selected(0, &key, &model, &[false, true]).unwrap();
        assert!(matches!(
            selected.as_slice(),
            [CellValue::Null, CellValue::UInt64(9)]
        ));
        assert!(decode_primary_key_selected(0, &key, &model, &[])
            .unwrap()
            .is_empty());
        let payload = model.primary_key_prefix.strip(&key).unwrap();
        let malformed = [
            payload[..payload.len() - 1].to_vec(),
            [payload.as_ref(), &[0]].concat(),
            [b"no terminator".as_slice(), &[0xff; 8]].concat(),
            [&[0xff, 0], &9u64.to_be_bytes()[..]].concat(),
            [&[1, 2, 0], &9u64.to_be_bytes()[..]].concat(),
            [&[1, 3, 0], &9u64.to_be_bytes()[..]].concat(),
        ];
        for payload in malformed {
            let key = model.primary_key_prefix.encode(&payload).unwrap();
            for mask in [&[][..], &[false, false], &[false, true], &[true, true]] {
                assert!(
                    decode_primary_key_selected(0, &key, &model, mask).is_none(),
                    "accepted malformed key {key:?} with mask {mask:?}"
                );
            }
        }
        let oversized = bytes::Bytes::from(
            [
                model.primary_key_prefix.as_bytes().as_ref(),
                &vec![b'a'; exoware_sdk::keys::MAX_KEY_LEN],
                &[0],
                &9u64.to_be_bytes(),
            ]
            .concat(),
        );
        assert!(decode_primary_key_selected(0, &oversized, &model, &[]).is_none());
    }

    #[test]
    fn index_decoder_preserves_canonical_suffix_without_materializing_it() {
        let model = model();
        let row = KvRow {
            values: vec![
                CellValue::Utf8("é\0\u{1}".into()),
                CellValue::UInt64(u64::MAX),
                CellValue::Boolean(true),
            ],
        };
        let expected = encode_primary_key_from_row(0, &row, &model).unwrap();
        for layout in [IndexLayout::Lexicographic, IndexLayout::ZOrder] {
            let specs = model
                .resolve_index_specs(&[IndexSpec::lexicographic("active", vec!["active".into()])
                    .unwrap()
                    .with_layout(layout)])
                .unwrap();
            let spec = &specs[0];
            let key = encode_secondary_index_key(0, spec, &model, &row).unwrap();
            let decoded =
                decode_secondary_index_key_with_masks(0, spec, &model, &key, Some(&[]), Some(&[]))
                    .unwrap();
            assert_eq!(decoded.primary_key, expected);
            assert!(decoded.values.is_empty());
            assert!(decoded.primary_key_values.is_empty());

            let payload = spec.prefix.strip(&key).unwrap();
            let mut malformed_bool = payload.to_vec();
            malformed_bool[0] = 2;
            for payload in [
                malformed_bool,
                [payload.as_ref(), &[0]].concat(),
                payload[..payload.len() - 1].to_vec(),
            ] {
                let key = spec.prefix.encode(&payload).unwrap();
                assert!(decode_secondary_index_primary_key(0, spec, &model, &key).is_none());
            }
        }
    }
}
