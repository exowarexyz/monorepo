use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use commonware_codec::Encode;
use datafusion::arrow::array::{ArrayAccessor, ArrayRef, AsArray};
#[cfg(test)]
use datafusion::arrow::datatypes::i256;
use datafusion::arrow::datatypes::{
    ArrowPrimitiveType, Date32Type, Date64Type, Decimal128Type, Decimal256Type, Float64Type,
    Int64Type, SchemaRef, TimestampMicrosecondType, UInt64Type,
};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::common::{DataFusionError, Result as DataFusionResult};
use datafusion::datasource::sink::DataSink;
use datafusion::execution::context::TaskContext;
use datafusion::physical_plan::{DisplayAs, DisplayFormatType, SendableRecordBatchStream};
use exoware_sdk::keys::Key;
#[cfg(test)]
use exoware_sdk::kv_codec::decode_stored_row;
use exoware_sdk::kv_codec::{StoredRow, StoredValue};
use exoware_sdk::{PrefixedStoreClient, StoreBatchUpload, StoreWriteBatch};
use futures::{future::BoxFuture, TryStreamExt};

use crate::builder::archived_non_pk_value_is_valid;
use crate::codec::*;
use crate::types::*;

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
    client: PrefixedStoreClient,
    tables: HashMap<String, TableWriter>,
    next_request_id: u64,
    failed_prepared: Mutex<Vec<PreparedBatch>>,
    pub(crate) pending_keys: Vec<Key>,
    pub(crate) pending_values: Vec<Bytes>,
}

#[derive(Debug)]
#[must_use]
pub struct PreparedBatch {
    request_id: u64,
    entry_count: usize,
    keys: Vec<Key>,
    values: Vec<Bytes>,
}

impl PreparedBatch {
    pub fn request_id(&self) -> u64 {
        self.request_id
    }

    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchReceipt {
    pub writer_request_id: u64,
    pub entry_count: usize,
    pub store_sequence_number: u64,
}

impl BatchWriter {
    pub(crate) fn new(client: PrefixedStoreClient, tables: &[(String, Arc<KvTable>)]) -> Self {
        let tables = tables
            .iter()
            .map(|(name, table)| {
                (
                    name.clone(),
                    TableWriter {
                        model: table.model.clone(),
                        index_specs: table.index_specs.clone(),
                    },
                )
            })
            .collect();
        Self {
            client,
            tables,
            next_request_id: 0,
            failed_prepared: Mutex::new(Vec::new()),
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
            self.pending_values.push(value.into());
        }
        Ok(self)
    }

    pub fn pending_count(&self) -> usize {
        self.pending_keys.len()
            + self
                .failed_prepared
                .lock()
                .expect("failed prepared mutex poisoned")
                .iter()
                .map(PreparedBatch::entry_count)
                .sum::<usize>()
    }

    /// Flush pending rows to ingest and return the post-ingest consistency token.
    pub async fn flush(&mut self) -> DataFusionResult<u64> {
        Ok(self
            .flush_with_receipt()
            .await?
            .map(|receipt| receipt.store_sequence_number)
            .unwrap_or(0))
    }

    /// Flush pending rows to ingest and return metadata for the persisted batch.
    pub async fn flush_with_receipt(&mut self) -> DataFusionResult<Option<BatchReceipt>> {
        let Some(prepared) = self.prepare_flush()? else {
            return Ok(None);
        };
        Ok(Some(self.commit_upload(prepared).await?))
    }

    pub fn prepare_flush(&mut self) -> DataFusionResult<Option<PreparedBatch>> {
        if let Some(prepared) = self.take_failed_prepared() {
            return Ok(Some(prepared));
        }
        if self.pending_keys.is_empty() {
            return Ok(None);
        }
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        Ok(Some(PreparedBatch {
            request_id,
            entry_count: self.pending_keys.len(),
            keys: std::mem::take(&mut self.pending_keys),
            values: std::mem::take(&mut self.pending_values),
        }))
    }

    pub fn stage_flush(
        &self,
        prepared: &PreparedBatch,
        batch: &mut StoreWriteBatch,
    ) -> DataFusionResult<()> {
        for (key, value) in prepared.keys.iter().zip(prepared.values.iter()) {
            batch
                .push(&self.client, key, value)
                .map_err(|e| DataFusionError::External(Box::new(e)))?;
        }
        Ok(())
    }

    pub fn mark_flush_persisted(
        &self,
        prepared: PreparedBatch,
        sequence_number: u64,
    ) -> BatchReceipt {
        BatchReceipt {
            writer_request_id: prepared.request_id,
            entry_count: prepared.entry_count(),
            store_sequence_number: sequence_number,
        }
    }

    pub fn mark_flush_failed(&self, prepared: PreparedBatch) {
        self.failed_prepared
            .lock()
            .expect("failed prepared mutex poisoned")
            .push(prepared);
    }

    fn take_failed_prepared(&self) -> Option<PreparedBatch> {
        let mut failed = self
            .failed_prepared
            .lock()
            .expect("failed prepared mutex poisoned");
        let (idx, _) = failed
            .iter()
            .enumerate()
            .min_by_key(|(_, prepared)| prepared.request_id)?;
        Some(failed.remove(idx))
    }
}

impl StoreBatchUpload for BatchWriter {
    type Prepared = PreparedBatch;
    type Receipt = BatchReceipt;
    type Error = DataFusionError;

    fn store_client(&self) -> &PrefixedStoreClient {
        &self.client
    }

    fn stage_upload(
        &self,
        prepared: &mut Self::Prepared,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error> {
        self.stage_flush(prepared, batch)
    }

    fn commit_error(&self, error: exoware_sdk::ClientError) -> Self::Error {
        DataFusionError::External(Box::new(error))
    }

    fn mark_upload_persisted<'a>(
        &'a self,
        prepared: Self::Prepared,
        sequence_number: u64,
    ) -> BoxFuture<'a, Self::Receipt>
    where
        Self: Sync + 'a,
        Self::Prepared: 'a,
    {
        Box::pin(async move { self.mark_flush_persisted(prepared, sequence_number) })
    }

    fn mark_upload_failed<'a>(
        &'a self,
        prepared: Self::Prepared,
        _error: String,
    ) -> BoxFuture<'a, ()>
    where
        Self: Sync + 'a,
        Self::Prepared: 'a,
    {
        Box::pin(async move {
            self.mark_flush_failed(prepared);
        })
    }
}

#[derive(Debug)]
pub(crate) struct KvIngestSink {
    pub(crate) client: PrefixedStoreClient,
    pub(crate) schema: SchemaRef,
    pub(crate) model: Arc<TableModel>,
    pub(crate) index_specs: Arc<Vec<ResolvedIndexSpec>>,
}

impl KvIngestSink {
    pub(crate) fn new(
        client: PrefixedStoreClient,
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
        let mut pending_values: Vec<Bytes> = Vec::new();
        let mut logical_rows_written = 0u64;

        while let Some(batch) = data.try_next().await? {
            let encoded_entries = encode_insert_entries(&batch, &self.model, &self.index_specs)?;
            logical_rows_written += batch.num_rows() as u64;
            for (key, value) in encoded_entries {
                pending_keys.push(key);
                pending_values.push(value.into());
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
        if array.is_null(row_idx) {
            if !col.nullable {
                return Err(DataFusionError::Execution(format!(
                    "column '{}' cannot be NULL for kv table insert",
                    col.name
                )));
            }
            values.push(CellValue::Null);
            continue;
        }
        let value = match col.kind {
            ColumnKind::Int64 => {
                CellValue::Int64(primitive_value_at::<Int64Type>(array, row_idx, &col.name)?)
            }
            ColumnKind::UInt64 => {
                CellValue::UInt64(primitive_value_at::<UInt64Type>(array, row_idx, &col.name)?)
            }
            ColumnKind::Float64 => CellValue::Float64(primitive_value_at::<Float64Type>(
                array, row_idx, &col.name,
            )?),
            ColumnKind::Boolean => CellValue::Boolean(bool_value_at(array, row_idx, &col.name)?),
            ColumnKind::Date32 => {
                CellValue::Date32(primitive_value_at::<Date32Type>(array, row_idx, &col.name)?)
            }
            ColumnKind::Date64 => {
                CellValue::Date64(primitive_value_at::<Date64Type>(array, row_idx, &col.name)?)
            }
            ColumnKind::Timestamp => CellValue::Timestamp(primitive_value_at::<
                TimestampMicrosecondType,
            >(array, row_idx, &col.name)?),
            ColumnKind::Decimal128 => CellValue::Decimal128(primitive_value_at::<Decimal128Type>(
                array, row_idx, &col.name,
            )?),
            ColumnKind::Decimal256 => CellValue::Decimal256(primitive_value_at::<Decimal256Type>(
                array, row_idx, &col.name,
            )?),
            ColumnKind::Utf8 => CellValue::Utf8(string_value_at(array, row_idx, &col.name)?),
            ColumnKind::FixedSizeBinary(_) => {
                CellValue::FixedBinary(fixed_binary_value_at(array, row_idx, &col.name)?)
            }
            ColumnKind::Binary => CellValue::Binary(binary_value_at(array, row_idx, &col.name)?),
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
        values.push(stored_opt.cloned());
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
        (ColumnKind::Binary, CellValue::Binary(v)) => Ok(Some(StoredValue::Bytes(v.clone()))),
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

#[cfg(test)]
pub(crate) fn decode_base_row(
    pk_values: Vec<CellValue>,
    value: &[u8],
    model: &TableModel,
) -> Option<KvRow> {
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
            (ColumnKind::Float64, StoredValue::Float64(v)) => CellValue::Float64(*v),
            (ColumnKind::Float64, StoredValue::Int64(v)) => CellValue::Float64(*v as f64),
            (ColumnKind::Boolean, StoredValue::Boolean(v)) => CellValue::Boolean(*v),
            (ColumnKind::Date32, StoredValue::Int64(v)) => CellValue::Date32(*v as i32),
            (ColumnKind::Date64, StoredValue::Int64(v)) => CellValue::Date64(*v),
            (ColumnKind::Timestamp, StoredValue::Int64(v)) => CellValue::Timestamp(*v),
            (ColumnKind::Decimal128, StoredValue::Bytes(bytes)) => {
                let arr: [u8; 16] = bytes.as_slice().try_into().ok()?;
                CellValue::Decimal128(i128::from_le_bytes(arr))
            }
            (ColumnKind::Decimal256, StoredValue::Bytes(bytes)) => {
                let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
                CellValue::Decimal256(i256::from_le_bytes(arr))
            }
            (ColumnKind::Utf8, StoredValue::Utf8(v)) => CellValue::Utf8(v.as_str().to_string()),
            (ColumnKind::Binary, StoredValue::Bytes(v)) => CellValue::Binary(v.as_slice().to_vec()),
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
        (ListElementKind::Float64, StoredValue::Float64(v)) => CellValue::Float64(*v),
        (ListElementKind::Float64, StoredValue::Int64(v)) => CellValue::Float64(*v as f64),
        (ListElementKind::Boolean, StoredValue::Boolean(v)) => CellValue::Boolean(*v),
        (ListElementKind::Utf8, StoredValue::Utf8(v)) => CellValue::Utf8(v.as_str().to_string()),
        _ => return None,
    })
}

fn required_column<'a>(batch: &'a RecordBatch, name: &str) -> DataFusionResult<&'a ArrayRef> {
    batch.column_by_name(name).ok_or_else(|| {
        DataFusionError::Execution(format!("insert batch is missing required column '{name}'"))
    })
}

fn primitive_value_at<T: ArrowPrimitiveType>(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
) -> DataFusionResult<T::Native> {
    let values = array.as_primitive_opt::<T>().ok_or_else(|| {
        DataFusionError::Execution(format!(
            "column '{column_name}' expected {:?}, got {:?}",
            T::DATA_TYPE,
            array.data_type()
        ))
    })?;
    Ok(values.value(row_idx))
}

fn string_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
) -> DataFusionResult<String> {
    if let Some(values) = array.as_string_opt::<i32>() {
        return Ok(values.value(row_idx).to_string());
    }
    if let Some(values) = array.as_string_opt::<i64>() {
        return Ok(values.value(row_idx).to_string());
    }
    if let Some(values) = array.as_string_view_opt() {
        return Ok(values.value(row_idx).to_string());
    }
    Err(DataFusionError::Execution(format!(
        "column '{column_name}' expected string, got {:?}",
        array.data_type()
    )))
}

fn bool_value_at(array: &ArrayRef, row_idx: usize, column_name: &str) -> DataFusionResult<bool> {
    let values = array.as_boolean_opt().ok_or_else(|| {
        DataFusionError::Execution(format!(
            "column '{column_name}' expected Boolean, got {:?}",
            array.data_type()
        ))
    })?;
    Ok(values.value(row_idx))
}

fn binary_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
) -> DataFusionResult<Vec<u8>> {
    if let Some(values) = array.as_binary_opt::<i32>() {
        return Ok(values.value(row_idx).to_vec());
    }
    if let Some(values) = array.as_binary_opt::<i64>() {
        return Ok(values.value(row_idx).to_vec());
    }
    if let Some(values) = array.as_binary_view_opt() {
        return Ok(values.value(row_idx).to_vec());
    }
    Err(DataFusionError::Execution(format!(
        "column '{column_name}' expected Binary, got {:?}",
        array.data_type()
    )))
}

fn fixed_binary_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
) -> DataFusionResult<Vec<u8>> {
    let values = array.as_fixed_size_binary_opt().ok_or_else(|| {
        DataFusionError::Execution(format!(
            "column '{column_name}' expected FixedSizeBinary, got {:?}",
            array.data_type()
        ))
    })?;
    Ok(values.value(row_idx).to_vec())
}

fn list_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
    elem: ListElementKind,
) -> DataFusionResult<CellValue> {
    let list_array = array.as_list_opt::<i32>().ok_or_else(|| {
        DataFusionError::Execution(format!(
            "column '{column_name}' expected List, got {:?}",
            array.data_type()
        ))
    })?;
    let offsets = list_array.value_offsets();
    let range = offsets[row_idx] as usize..offsets[row_idx + 1] as usize;
    let child = list_array.values();
    if child
        .nulls()
        .is_some_and(|nulls| range.clone().any(|idx| nulls.is_null(idx)))
    {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' list elements cannot be NULL"
        )));
    }
    let type_error = || {
        DataFusionError::Execution(format!(
            "column '{column_name}' list element expected {elem:?}"
        ))
    };
    let items = match elem {
        ListElementKind::Int64 => collect_list(
            child
                .as_primitive_opt::<Int64Type>()
                .ok_or_else(type_error)?,
            range,
            CellValue::Int64,
        ),
        ListElementKind::Float64 => collect_list(
            child
                .as_primitive_opt::<Float64Type>()
                .ok_or_else(type_error)?,
            range,
            CellValue::Float64,
        ),
        ListElementKind::Boolean => collect_list(
            child.as_boolean_opt().ok_or_else(type_error)?,
            range,
            CellValue::Boolean,
        ),
        ListElementKind::Utf8 => {
            let cell = |value: &str| CellValue::Utf8(value.to_owned());
            if let Some(values) = child.as_string_opt::<i32>() {
                collect_list(values, range, cell)
            } else if let Some(values) = child.as_string_opt::<i64>() {
                collect_list(values, range, cell)
            } else {
                collect_list(
                    child.as_string_view_opt().ok_or_else(type_error)?,
                    range,
                    cell,
                )
            }
        }
    };
    Ok(CellValue::List(items))
}

fn collect_list<A: ArrayAccessor>(
    values: A,
    range: std::ops::Range<usize>,
    cell: impl Fn(A::Item) -> CellValue,
) -> Vec<CellValue> {
    range.map(|idx| cell(values.value(idx))).collect()
}

pub(crate) async fn flush_ingest_batch(
    client: &PrefixedStoreClient,
    keys: &mut Vec<Key>,
    values: &mut Vec<Bytes>,
) -> DataFusionResult<u64> {
    if keys.is_empty() {
        return Ok(0);
    }
    let mut batch = StoreWriteBatch::new();
    for (key, value) in keys.iter().zip(values.iter()) {
        batch
            .push(client, key, value)
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
    }
    let token = batch
        .commit(client.client())
        .await
        .map_err(|e| DataFusionError::External(Box::new(e)))?;
    keys.clear();
    values.clear();
    Ok(token)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use exoware_sdk::StoreClient;

    use super::*;
    use crate::builder::{append_archived_non_pk_value, make_column_builder};
    use datafusion::arrow::array::builder::Int64Builder;
    use datafusion::arrow::array::{
        BinaryArray, BinaryViewArray, Int64Array, LargeBinaryArray, ListBuilder, StringArray,
        UInt64Array,
    };
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use exoware_sdk::kv_codec::decode_stored_row;

    /// Variable-length Binary values survive the encode -> store -> arrow
    /// round trip with their exact lengths.
    #[test]
    fn binary_cells_round_trip_through_stored_rows() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::UInt64, false),
                TableColumnConfig::new("body", DataType::Binary, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("binary column config");
        let model = TableModel::from_config(&config).expect("binary column model");

        let bodies: Vec<Vec<u8>> = vec![vec![], vec![0xAB], vec![0xCD; 300]];
        let body_idx = *model.columns_by_name.get("body").expect("body column");
        let mut builder = make_column_builder(&model, body_idx);
        for (id, body) in bodies.iter().enumerate() {
            let row = KvRow {
                values: vec![
                    CellValue::UInt64(id as u64),
                    CellValue::Binary(body.clone()),
                ],
            };
            let encoded = encode_base_row_value(&row, &model).expect("encode row");
            let stored = decode_stored_row(&encoded).expect("decode stored row");
            append_archived_non_pk_value(
                &mut builder,
                &model.columns[body_idx],
                stored.values[body_idx].as_ref(),
            )
            .expect("append archived binary");
        }
        let array = builder
            .finish(&DataType::Binary)
            .expect("finish binary array");
        let array = array
            .as_any()
            .downcast_ref::<BinaryArray>()
            .expect("binary array");
        for (id, body) in bodies.iter().enumerate() {
            assert_eq!(array.value(id), body.as_slice());
        }
    }

    fn binary_body_model() -> TableModel {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::UInt64, false),
                TableColumnConfig::new("body", DataType::Binary, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("binary column config");
        TableModel::from_config(&config).expect("binary column model")
    }

    fn binary_body_batch(body_type: DataType, body_array: ArrayRef) -> RecordBatch {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::UInt64, false),
            Field::new("body", body_type, false),
        ]));
        RecordBatch::try_new(
            schema,
            vec![Arc::new(UInt64Array::from(vec![7u64])), body_array],
        )
        .expect("insert batch")
    }

    /// The insert path accepts all three arrow encodings for a Binary column:
    /// plain `Binary`, `LargeBinary`, and `BinaryView` (tables may declare the
    /// wide or view types, and DataFusion may coerce batches to view arrays).
    #[test]
    fn extract_row_reads_all_binary_encodings() {
        let model = binary_body_model();
        let body: &[u8] = &[0xAB, 0xCD, 0xEF];
        let arrays: Vec<(DataType, ArrayRef)> = vec![
            (
                DataType::Binary,
                Arc::new(BinaryArray::from_iter_values([body])),
            ),
            (
                DataType::LargeBinary,
                Arc::new(LargeBinaryArray::from_iter_values([body])),
            ),
            (
                DataType::BinaryView,
                Arc::new(BinaryViewArray::from_iter_values([body])),
            ),
        ];
        for (body_type, array) in arrays {
            let batch = binary_body_batch(body_type.clone(), array);
            let row = extract_row_from_batch(&batch, 0, &model).expect("extract row");
            assert!(
                matches!(&row.values[1], CellValue::Binary(v) if v.as_slice() == body),
                "wrong cell for {body_type:?}: {:?}",
                row.values[1]
            );
        }
    }

    /// A non-binary array for a Binary column is rejected with the column name
    /// and the offending arrow type.
    #[test]
    fn extract_row_rejects_non_binary_array_for_binary_column() {
        let model = binary_body_model();
        let batch = binary_body_batch(
            DataType::Utf8,
            Arc::new(StringArray::from(vec!["not bytes"])),
        );
        let error = extract_row_from_batch(&batch, 0, &model).expect_err("utf8 body must fail");
        let message = error.to_string();
        assert!(
            message.contains("'body'") && message.contains("expected Binary"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn list_extraction_uses_sliced_offsets_and_rejects_only_selected_null_elements() {
        let mut builder = ListBuilder::new(Int64Builder::new());
        builder.values().append_null();
        builder.append(true);
        builder.values().append_value(7);
        builder.values().append_value(-3);
        builder.append(true);
        builder.append(true);
        let array: ArrayRef = Arc::new(builder.finish());
        let error = list_value_at(&array, 0, "items", ListElementKind::Int64).unwrap_err();
        assert!(error.to_string().contains("list elements cannot be NULL"));

        let sliced = array.slice(1, 2);
        let CellValue::List(items) =
            list_value_at(&sliced, 0, "items", ListElementKind::Int64).unwrap()
        else {
            panic!("expected list");
        };
        assert!(matches!(
            items.as_slice(),
            [CellValue::Int64(7), CellValue::Int64(-3)]
        ));
        let CellValue::List(items) =
            list_value_at(&sliced, 1, "items", ListElementKind::Int64).unwrap()
        else {
            panic!("expected empty list");
        };
        assert!(items.is_empty());
    }

    #[test]
    fn row_extraction_checks_column_nullability_before_primitive_access() {
        for nullable in [false, true] {
            let config = KvTableConfig::new(
                0,
                vec![
                    TableColumnConfig::new("id", DataType::UInt64, false),
                    TableColumnConfig::new("value", DataType::Int64, nullable),
                ],
                vec!["id".into()],
                vec![],
            )
            .unwrap();
            let model = TableModel::from_config(&config).unwrap();
            let batch = RecordBatch::try_from_iter(vec![
                ("id", Arc::new(UInt64Array::from(vec![1])) as ArrayRef),
                ("value", Arc::new(Int64Array::from(vec![None])) as ArrayRef),
            ])
            .unwrap();
            let result = extract_row_from_batch(&batch, 0, &model);
            if nullable {
                assert!(matches!(result.unwrap().values[1], CellValue::Null));
            } else {
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("'value' cannot be NULL"));
            }
        }
    }

    #[test]
    fn string_list_aliases_preserve_declared_fields_and_round_trip_through_arrow() {
        for child_type in [DataType::Utf8, DataType::LargeUtf8, DataType::Utf8View] {
            for large_list in [false, true] {
                let child = Arc::new(Field::new("element", child_type.clone(), false));
                let list_type = if large_list {
                    DataType::LargeList(child)
                } else {
                    DataType::List(child)
                };
                let config = KvTableConfig::new(
                    0,
                    vec![
                        TableColumnConfig::new("id", DataType::UInt64, false),
                        TableColumnConfig::new("items", list_type, false),
                    ],
                    vec!["id".into()],
                    vec![],
                )
                .unwrap();
                let model = TableModel::from_config(&config).unwrap();
                let row = KvRow {
                    values: vec![
                        CellValue::UInt64(4),
                        CellValue::List(vec![
                            CellValue::Utf8("é".into()),
                            CellValue::Utf8(String::new()),
                        ]),
                    ],
                };
                let encoded = encode_base_row_value(&row, &model).unwrap();
                let stored = decode_stored_row(&encoded).unwrap();
                let mut builder = make_column_builder(&model, 1);
                append_archived_non_pk_value(
                    &mut builder,
                    &model.columns[1],
                    stored.values[1].as_ref(),
                )
                .unwrap();
                let array = builder.finish(model.schema.field(1).data_type()).unwrap();
                let batch = RecordBatch::try_new(
                    model.schema.clone(),
                    vec![Arc::new(UInt64Array::from(vec![4])), array],
                )
                .unwrap();
                let recovered = extract_row_from_batch(&batch, 0, &model).unwrap();
                assert_eq!(encode_base_row_value(&recovered, &model).unwrap(), encoded);
            }
        }
    }

    #[test]
    fn store_batch_upload_stage_preserves_rows_for_failed_retry() {
        let writer = BatchWriter::new(
            PrefixedStoreClient::empty(StoreClient::new("http://127.0.0.1:1")),
            &[],
        );
        let mut prepared = PreparedBatch {
            request_id: 7,
            entry_count: 2,
            keys: vec![Bytes::from_static(b"a"), Bytes::from_static(b"b")],
            values: vec![Bytes::from_static(&[1]), Bytes::from_static(&[2, 3])],
        };
        let mut batch = StoreWriteBatch::new();

        StoreBatchUpload::stage_upload(&writer, &mut prepared, &mut batch).expect("stage flush");

        assert_eq!(batch.len(), 2);
        assert_eq!(prepared.entry_count(), 2);
        assert_eq!(prepared.keys.len(), 2);
        assert_eq!(prepared.values.len(), 2);

        writer.mark_flush_failed(prepared);
        let mut retry = writer.take_failed_prepared().expect("failed batch queued");
        assert_eq!(retry.entry_count(), 2);

        let mut retry_batch = StoreWriteBatch::new();
        StoreBatchUpload::stage_upload(&writer, &mut retry, &mut retry_batch).expect("stage retry");
        assert_eq!(retry_batch.len(), 2);
    }
}
