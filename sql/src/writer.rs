use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use datafusion::arrow::array::{
    ArrayRef, BooleanArray, Date32Array, Date64Array, Decimal128Array, Decimal256Array,
    FixedSizeBinaryArray, Float64Array, Int64Array, LargeStringArray, ListArray,
    StringArray, StringViewArray, TimestampMicrosecondArray, UInt64Array,
};
use datafusion::arrow::datatypes::{i256, SchemaRef};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::common::{DataFusionError, Result as DataFusionResult};
use datafusion::datasource::sink::DataSink;
use datafusion::execution::context::TaskContext;
use datafusion::physical_plan::{DisplayAs, DisplayFormatType, SendableRecordBatchStream};
use commonware_codec::Encode;
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::kv_codec::{StoredRow, StoredValue};
#[cfg(test)]
use exoware_sdk_rs::kv_codec::decode_stored_row;
use exoware_sdk_rs::StoreClient;
use futures::TryStreamExt;

use crate::types::*;
use crate::codec::*;
use crate::builder::archived_non_pk_value_is_valid;

#[derive(Debug)]
pub struct TableWriter {
    model: Arc<TableModel>,
    index_specs: Arc<Vec<ResolvedIndexSpec>>,
}

impl TableWriter {
    pub fn encode_row(&self, values: Vec<CellValue>) -> Result<Vec<(Key, Vec<u8>)>, String> {
        let row = KvRow { values };
        if row.values.len() != self.model.columns.len() {
            return Err(format!(
                "expected {} values, got {}",
                self.model.columns.len(),
                row.values.len()
            ));
        }
        let base_key = encode_primary_key_from_row(self.model.table_prefix, &row, &self.model)?;
        let base_value = encode_base_row_value(&row, &self.model).map_err(|e| format!("{e}"))?;
        let mut out = vec![(base_key, base_value)];
        for spec in self.index_specs.iter() {
            let idx_key =
                encode_secondary_index_key(self.model.table_prefix, spec, &self.model, &row)?;
            let idx_value = encode_secondary_index_value(&row, &self.model, spec)
                .map_err(|e| format!("{e}"))?;
            out.push((idx_key, idx_value));
        }
        Ok(out)
    }
}

#[derive(Debug)]
pub struct BatchWriter {
    client: StoreClient,
    tables: HashMap<String, TableWriter>,
    pub(crate) pending_keys: Vec<Key>,
    pub(crate) pending_values: Vec<Vec<u8>>,
}

impl BatchWriter {
    pub(crate) fn new(client: StoreClient, table_configs: &[(String, KvTableConfig)]) -> Self {
        let mut tables = HashMap::new();
        for (name, config) in table_configs {
            let model = Arc::new(
                TableModel::from_config(config).expect("config already validated by KvSchema"),
            );
            let index_specs = Arc::new(
                model
                    .resolve_index_specs(&config.index_specs)
                    .expect("specs already validated by KvSchema"),
            );
            tables.insert(name.clone(), TableWriter { model, index_specs });
        }
        Self {
            client,
            tables,
            pending_keys: Vec::new(),
            pending_values: Vec::new(),
        }
    }

    pub fn insert(
        &mut self,
        table_name: &str,
        values: Vec<CellValue>,
    ) -> Result<&mut Self, String> {
        let writer = self
            .tables
            .get(table_name)
            .ok_or_else(|| format!("unknown table '{table_name}'"))?;
        let entries = writer.encode_row(values)?;
        for (key, value) in entries {
            self.pending_keys.push(key);
            self.pending_values.push(value);
        }
        Ok(self)
    }

    pub fn pending_count(&self) -> usize {
        self.pending_keys.len()
    }

    /// Flush pending rows to ingest and return the post-ingest consistency token.
    pub async fn flush(&mut self) -> DataFusionResult<u64> {
        if self.pending_keys.is_empty() {
            return Ok(0);
        }
        flush_ingest_batch(
            &self.client,
            &mut self.pending_keys,
            &mut self.pending_values,
        )
        .await
    }
}

#[derive(Debug)]
pub(crate) struct KvIngestSink {
    pub(crate) client: StoreClient,
    pub(crate) schema: SchemaRef,
    pub(crate) model: Arc<TableModel>,
    pub(crate) index_specs: Arc<Vec<ResolvedIndexSpec>>,
}

impl KvIngestSink {
    pub(crate) fn new(
        client: StoreClient,
        schema: SchemaRef,
        model: Arc<TableModel>,
        index_specs: Arc<Vec<ResolvedIndexSpec>>,
    ) -> Self {
        Self {
            client,
            schema,
            model,
            index_specs,
        }
    }
}

impl DisplayAs for KvIngestSink {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KvIngestSink")
    }
}

#[async_trait]
impl DataSink for KvIngestSink {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> &SchemaRef {
        &self.schema
    }

    async fn write_all(
        &self,
        data: SendableRecordBatchStream,
        _context: &Arc<TaskContext>,
    ) -> DataFusionResult<u64> {
        let mut data = data;
        let mut pending_keys: Vec<Key> = Vec::new();
        let mut pending_values: Vec<Vec<u8>> = Vec::new();
        let mut logical_rows_written = 0u64;

        while let Some(batch) = data.try_next().await? {
            let encoded_entries = encode_insert_entries(&batch, &self.model, &self.index_specs)?;
            logical_rows_written += batch.num_rows() as u64;
            for (key, value) in encoded_entries {
                pending_keys.push(key);
                pending_values.push(value);
            }
        }

        if !pending_keys.is_empty() {
            flush_ingest_batch(&self.client, &mut pending_keys, &mut pending_values).await?;
        }
        Ok(logical_rows_written)
    }
}

pub(crate) fn encode_insert_entries(
    batch: &RecordBatch,
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
) -> DataFusionResult<Vec<(Key, Vec<u8>)>> {
    let mut out = Vec::with_capacity(batch.num_rows() * (1 + index_specs.len()));
    for row_idx in 0..batch.num_rows() {
        let row = extract_row_from_batch(batch, row_idx, model)?;
        let base_key = encode_primary_key_from_row(model.table_prefix, &row, model)
            .map_err(DataFusionError::Execution)?;
        let base_value = encode_base_row_value(&row, model)?;
        out.push((base_key, base_value));

        for spec in index_specs {
            let secondary_key = encode_secondary_index_key(model.table_prefix, spec, model, &row)
                .map_err(DataFusionError::Execution)?;
            let secondary_value = encode_secondary_index_value(&row, model, spec)?;
            out.push((secondary_key, secondary_value));
        }
    }
    Ok(out)
}

pub(crate) fn extract_row_from_batch(
    batch: &RecordBatch,
    row_idx: usize,
    model: &TableModel,
) -> DataFusionResult<KvRow> {
    let mut values = Vec::with_capacity(model.columns.len());
    for col in &model.columns {
        let array = required_column(batch, &col.name)?;
        if col.nullable && array.is_null(row_idx) {
            values.push(CellValue::Null);
            continue;
        }
        let value = match col.kind {
            ColumnKind::Int64 => CellValue::Int64(i64_value_at(array, row_idx, &col.name)?),
            ColumnKind::UInt64 => CellValue::UInt64(uint64_value_at(array, row_idx, &col.name)?),
            ColumnKind::Float64 => CellValue::Float64(f64_value_at(array, row_idx, &col.name)?),
            ColumnKind::Boolean => CellValue::Boolean(bool_value_at(array, row_idx, &col.name)?),
            ColumnKind::Date32 => CellValue::Date32(date32_value_at(array, row_idx, &col.name)?),
            ColumnKind::Date64 => CellValue::Date64(date64_value_at(array, row_idx, &col.name)?),
            ColumnKind::Timestamp => {
                CellValue::Timestamp(timestamp_micros_value_at(array, row_idx, &col.name)?)
            }
            ColumnKind::Decimal128 => {
                CellValue::Decimal128(decimal128_value_at(array, row_idx, &col.name)?)
            }
            ColumnKind::Decimal256 => {
                CellValue::Decimal256(decimal256_value_at(array, row_idx, &col.name)?)
            }
            ColumnKind::Utf8 => CellValue::Utf8(string_value_at(array, row_idx, &col.name)?),
            ColumnKind::FixedSizeBinary(_) => {
                CellValue::FixedBinary(fixed_binary_value_at(array, row_idx, &col.name)?)
            }
            ColumnKind::List(elem) => list_value_at(array, row_idx, &col.name, elem)?,
        };
        values.push(value);
    }
    Ok(KvRow { values })
}

pub(crate) fn encode_base_row_value(row: &KvRow, model: &TableModel) -> DataFusionResult<Vec<u8>> {
    let mut values = Vec::with_capacity(model.columns.len());
    for (idx, col) in model.columns.iter().enumerate() {
        if model.is_pk_column(idx) {
            values.push(None);
            continue;
        }
        values.push(encode_non_pk_cell_value(row.value_at(idx), col)?);
    }
    let stored_row = StoredRow { values };
    Ok(stored_row.encode().to_vec())
}

pub(crate) fn encode_secondary_index_value(
    row: &KvRow,
    model: &TableModel,
    spec: &ResolvedIndexSpec,
) -> DataFusionResult<Vec<u8>> {
    let mut values = Vec::with_capacity(model.columns.len());
    for (idx, col) in model.columns.iter().enumerate() {
        if model.is_pk_column(idx) || !spec.value_column_mask[idx] {
            values.push(None);
            continue;
        }
        values.push(encode_non_pk_cell_value(row.value_at(idx), col)?);
    }
    let stored_row = StoredRow { values };
    Ok(stored_row.encode().to_vec())
}

pub(crate) fn encode_secondary_index_value_from_archived(
    archived: &StoredRow,
    model: &TableModel,
    spec: &ResolvedIndexSpec,
) -> DataFusionResult<Vec<u8>> {
    if archived.values.len() != model.columns.len() {
        return Err(DataFusionError::Execution(
            "archived row column count mismatch".to_string(),
        ));
    }
    let mut values = Vec::with_capacity(model.columns.len());
    for (idx, col) in model.columns.iter().enumerate() {
        if model.is_pk_column(idx) || !spec.value_column_mask[idx] {
            values.push(None);
            continue;
        }
        let stored_opt = archived.values.get(idx).and_then(|value| value.as_ref());
        if !archived_non_pk_value_is_valid(col, stored_opt) {
            return Err(DataFusionError::Execution(format!(
                "invalid archived value for secondary index column '{}'",
                col.name
            )));
        }
        values.push(owned_stored_value_from_archived(stored_opt)?);
    }
    let stored_row = StoredRow { values };
    Ok(stored_row.encode().to_vec())
}

pub(crate) fn encode_non_pk_cell_value(
    value: &CellValue,
    col: &ResolvedColumn,
) -> DataFusionResult<Option<StoredValue>> {
    match (col.kind, value) {
        (_, CellValue::Null) => {
            if !col.nullable {
                return Err(DataFusionError::Execution(format!(
                    "column '{}' is not nullable but received NULL",
                    col.name
                )));
            }
            Ok(None)
        }
        (ColumnKind::Int64, CellValue::Int64(v)) => Ok(Some(StoredValue::Int64(*v))),
        (ColumnKind::UInt64, CellValue::UInt64(v)) => Ok(Some(StoredValue::UInt64(*v))),
        (ColumnKind::Float64, CellValue::Float64(v)) => Ok(Some(StoredValue::Float64(*v))),
        (ColumnKind::Boolean, CellValue::Boolean(v)) => Ok(Some(StoredValue::Boolean(*v))),
        (ColumnKind::Date32, CellValue::Date32(v)) => Ok(Some(StoredValue::Int64(*v as i64))),
        (ColumnKind::Date64, CellValue::Date64(v)) => Ok(Some(StoredValue::Int64(*v))),
        (ColumnKind::Timestamp, CellValue::Timestamp(v)) => Ok(Some(StoredValue::Int64(*v))),
        (ColumnKind::Decimal128, CellValue::Decimal128(v)) => {
            Ok(Some(StoredValue::Bytes(v.to_le_bytes().to_vec())))
        }
        (ColumnKind::Decimal256, CellValue::Decimal256(v)) => {
            Ok(Some(StoredValue::Bytes(v.to_le_bytes().to_vec())))
        }
        (ColumnKind::Utf8, CellValue::Utf8(v)) => Ok(Some(StoredValue::Utf8(v.clone()))),
        (ColumnKind::FixedSizeBinary(n), CellValue::FixedBinary(v)) => {
            if v.len() != n {
                return Err(DataFusionError::Execution(format!(
                    "column '{}' expects FixedSizeBinary({n}) value with exactly {n} bytes, got {}",
                    col.name,
                    v.len()
                )));
            }
            Ok(Some(StoredValue::Bytes(v.clone())))
        }
        (ColumnKind::List(elem), CellValue::List(items)) => {
            let mut stored_items = Vec::with_capacity(items.len());
            for item in items {
                let stored_item = match (elem, item) {
                    (ListElementKind::Int64, CellValue::Int64(v)) => StoredValue::Int64(*v),
                    (ListElementKind::Float64, CellValue::Float64(v)) => StoredValue::Float64(*v),
                    (ListElementKind::Boolean, CellValue::Boolean(v)) => StoredValue::Boolean(*v),
                    (ListElementKind::Utf8, CellValue::Utf8(v)) => StoredValue::Utf8(v.clone()),
                    _ => {
                        return Err(DataFusionError::Execution(format!(
                            "column '{}' list element type mismatch (expected {:?}, got {:?})",
                            col.name, elem, item
                        )))
                    }
                };
                stored_items.push(stored_item);
            }
            Ok(Some(StoredValue::List(stored_items)))
        }
        _ => Err(DataFusionError::Execution(format!(
            "column '{}' type mismatch (expected {:?}, got {:?})",
            col.name, col.kind, value
        ))),
    }
}

pub(crate) fn owned_stored_value_from_archived(
    stored_opt: Option<&StoredValue>,
) -> DataFusionResult<Option<StoredValue>> {
    let Some(stored) = stored_opt else {
        return Ok(None);
    };
    Ok(Some(match stored {
        StoredValue::Int64(v) => StoredValue::Int64(*v),
        StoredValue::UInt64(v) => StoredValue::UInt64(*v),
        StoredValue::Float64(v) => StoredValue::Float64(*v),
        StoredValue::Boolean(v) => StoredValue::Boolean(*v),
        StoredValue::Utf8(v) => StoredValue::Utf8(v.as_str().to_string()),
        StoredValue::Bytes(v) => StoredValue::Bytes(v.as_slice().to_vec()),
        StoredValue::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items.iter() {
                let owned = owned_stored_value_from_archived(Some(item))?.ok_or_else(|| {
                    DataFusionError::Execution(
                        "archived list item unexpectedly decoded as NULL".to_string(),
                    )
                })?;
                out.push(owned);
            }
            StoredValue::List(out)
        }
    }))
}

#[cfg(test)]
pub(crate) fn decode_base_row(pk_values: Vec<CellValue>, value: &[u8], model: &TableModel) -> Option<KvRow> {
    if pk_values.len() != model.primary_key_indices.len() {
        return None;
    }
    let archived = decode_stored_row(value).ok()?;
    if archived.values.len() != model.columns.len() {
        return None;
    }
    let mut values = vec![CellValue::Null; model.columns.len()];
    for (pk_pos, pk_value) in pk_values.into_iter().enumerate() {
        let col_idx = *model.primary_key_indices.get(pk_pos)?;
        values[col_idx] = pk_value;
    }

    for (idx, col) in model.columns.iter().enumerate() {
        if model.is_pk_column(idx) {
            continue;
        }
        let Some(stored) = archived.values[idx].as_ref() else {
            if col.nullable {
                continue;
            }
            return None;
        };
        values[idx] = match (col.kind, stored) {
            (ColumnKind::Int64, StoredValue::Int64(v)) => CellValue::Int64(*v),
            (ColumnKind::UInt64, StoredValue::UInt64(v)) => CellValue::UInt64(*v),
            (ColumnKind::Float64, StoredValue::Float64(v)) => {
                CellValue::Float64(*v)
            }
            (ColumnKind::Float64, StoredValue::Int64(v)) => {
                CellValue::Float64(*v as f64)
            }
            (ColumnKind::Boolean, StoredValue::Boolean(v)) => CellValue::Boolean(*v),
            (ColumnKind::Date32, StoredValue::Int64(v)) => {
                CellValue::Date32(*v as i32)
            }
            (ColumnKind::Date64, StoredValue::Int64(v)) => CellValue::Date64(*v),
            (ColumnKind::Timestamp, StoredValue::Int64(v)) => {
                CellValue::Timestamp(*v)
            }
            (ColumnKind::Decimal128, StoredValue::Bytes(bytes)) => {
                let arr: [u8; 16] = bytes.as_slice().try_into().ok()?;
                CellValue::Decimal128(i128::from_le_bytes(arr))
            }
            (ColumnKind::Decimal256, StoredValue::Bytes(bytes)) => {
                let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
                CellValue::Decimal256(i256::from_le_bytes(arr))
            }
            (ColumnKind::Utf8, StoredValue::Utf8(v)) => {
                CellValue::Utf8(v.as_str().to_string())
            }
            (ColumnKind::FixedSizeBinary(_), StoredValue::Bytes(v)) => {
                CellValue::FixedBinary(v.as_slice().to_vec())
            }
            (ColumnKind::List(elem), StoredValue::List(items)) => {
                let mut cells = Vec::with_capacity(items.len());
                for item in items.iter() {
                    cells.push(decode_list_element_archived(elem, item)?);
                }
                CellValue::List(cells)
            }
            _ => return None,
        };
    }
    Some(KvRow { values })
}

pub(crate) fn decode_list_element_archived(
    elem: ListElementKind,
    stored: &StoredValue,
) -> Option<CellValue> {
    Some(match (elem, stored) {
        (ListElementKind::Int64, StoredValue::Int64(v)) => CellValue::Int64(*v),
        (ListElementKind::Float64, StoredValue::Float64(v)) => {
            CellValue::Float64(*v)
        }
        (ListElementKind::Float64, StoredValue::Int64(v)) => {
            CellValue::Float64(*v as f64)
        }
        (ListElementKind::Boolean, StoredValue::Boolean(v)) => CellValue::Boolean(*v),
        (ListElementKind::Utf8, StoredValue::Utf8(v)) => {
            CellValue::Utf8(v.as_str().to_string())
        }
        _ => return None,
    })
}

pub(crate) fn required_column<'a>(batch: &'a RecordBatch, name: &str) -> DataFusionResult<&'a ArrayRef> {
    batch.column_by_name(name).ok_or_else(|| {
        DataFusionError::Execution(format!("insert batch is missing required column '{name}'"))
    })
}

pub(crate) fn i64_value_at(array: &ArrayRef, row_idx: usize, column_name: &str) -> DataFusionResult<i64> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array.as_any().downcast_ref::<Int64Array>().ok_or_else(|| {
        DataFusionError::Execution(format!(
            "column '{column_name}' expected Int64, got {:?}",
            array.data_type()
        ))
    })?;
    Ok(values.value(row_idx))
}

pub(crate) fn string_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
) -> DataFusionResult<String> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    if let Some(values) = array.as_any().downcast_ref::<StringArray>() {
        return Ok(values.value(row_idx).to_string());
    }
    if let Some(values) = array.as_any().downcast_ref::<LargeStringArray>() {
        return Ok(values.value(row_idx).to_string());
    }
    if let Some(values) = array.as_any().downcast_ref::<StringViewArray>() {
        return Ok(values.value(row_idx).to_string());
    }
    Err(DataFusionError::Execution(format!(
        "column '{column_name}' expected string, got {:?}",
        array.data_type()
    )))
}

pub(crate) fn f64_value_at(array: &ArrayRef, row_idx: usize, column_name: &str) -> DataFusionResult<f64> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<Float64Array>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected Float64, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

pub(crate) fn bool_value_at(array: &ArrayRef, row_idx: usize, column_name: &str) -> DataFusionResult<bool> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<BooleanArray>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected Boolean, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

pub(crate) fn date32_value_at(array: &ArrayRef, row_idx: usize, column_name: &str) -> DataFusionResult<i32> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<Date32Array>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected Date32, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

pub(crate) fn date64_value_at(array: &ArrayRef, row_idx: usize, column_name: &str) -> DataFusionResult<i64> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<Date64Array>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected Date64, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

pub(crate) fn timestamp_micros_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
) -> DataFusionResult<i64> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected TimestampMicrosecond, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

pub(crate) fn decimal128_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
) -> DataFusionResult<i128> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<Decimal128Array>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected Decimal128, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

pub(crate) fn uint64_value_at(array: &ArrayRef, row_idx: usize, column_name: &str) -> DataFusionResult<u64> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected UInt64, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

pub(crate) fn decimal256_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
) -> DataFusionResult<i256> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<Decimal256Array>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected Decimal256, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

pub(crate) fn fixed_binary_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
) -> DataFusionResult<Vec<u8>> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<FixedSizeBinaryArray>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected FixedSizeBinary, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx).to_vec())
}

pub(crate) fn list_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
    elem: ListElementKind,
) -> DataFusionResult<CellValue> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let list_array = array.as_any().downcast_ref::<ListArray>().ok_or_else(|| {
        DataFusionError::Execution(format!(
            "column '{column_name}' expected List, got {:?}",
            array.data_type()
        ))
    })?;
    let child = list_array.value(row_idx);
    let mut items = Vec::with_capacity(child.len());
    for i in 0..child.len() {
        let item = match elem {
            ListElementKind::Int64 => {
                let arr = child.as_any().downcast_ref::<Int64Array>().ok_or_else(|| {
                    DataFusionError::Execution(format!(
                        "column '{column_name}' list element expected Int64"
                    ))
                })?;
                CellValue::Int64(arr.value(i))
            }
            ListElementKind::Float64 => {
                let arr = child
                    .as_any()
                    .downcast_ref::<Float64Array>()
                    .ok_or_else(|| {
                        DataFusionError::Execution(format!(
                            "column '{column_name}' list element expected Float64"
                        ))
                    })?;
                CellValue::Float64(arr.value(i))
            }
            ListElementKind::Boolean => {
                let arr = child
                    .as_any()
                    .downcast_ref::<BooleanArray>()
                    .ok_or_else(|| {
                        DataFusionError::Execution(format!(
                            "column '{column_name}' list element expected Boolean"
                        ))
                    })?;
                CellValue::Boolean(arr.value(i))
            }
            ListElementKind::Utf8 => {
                let arr = child
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .ok_or_else(|| {
                        DataFusionError::Execution(format!(
                            "column '{column_name}' list element expected Utf8"
                        ))
                    })?;
                CellValue::Utf8(arr.value(i).to_string())
            }
        };
        items.push(item);
    }
    Ok(CellValue::List(items))
}

pub(crate) async fn flush_ingest_batch(
    client: &StoreClient,
    keys: &mut Vec<Key>,
    values: &mut Vec<Vec<u8>>,
) -> DataFusionResult<u64> {
    if keys.is_empty() {
        return Ok(0);
    }
    let refs: Vec<(&Key, &[u8])> = keys
        .iter()
        .zip(values.iter())
        .map(|(key, value)| (key, value.as_slice()))
        .collect();
    let token = client
        .put(&refs)
        .await
        .map_err(|e| DataFusionError::External(Box::new(e)))?;
    keys.clear();
    values.clear();
    Ok(token)
}
