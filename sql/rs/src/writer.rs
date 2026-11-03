use crate::{builder::archived_non_pk_value_is_valid, codec::*, types::*};
use async_trait::async_trait;
use bytes::Bytes;
use commonware_codec::Encode;
#[cfg(test)]
use datafusion::arrow::datatypes::i256;
use datafusion::{
    arrow::{
        array::{ArrayAccessor, ArrayRef, AsArray},
        datatypes::{
            ArrowPrimitiveType, Date32Type, Date64Type, Decimal128Type, Decimal256Type,
            Float64Type, Int64Type, SchemaRef, TimestampMicrosecondType, UInt64Type,
        },
        record_batch::RecordBatch,
    },
    common::{DataFusionError, Result as DataFusionResult},
    datasource::sink::DataSink,
    execution::context::TaskContext,
    physical_plan::{DisplayAs, DisplayFormatType, SendableRecordBatchStream},
};
#[cfg(test)]
use exoware_sdk::kv_codec::decode_stored_row;
use exoware_sdk::{
    keys::Key,
    kv_codec::{StoredRow, StoredValue},
    PrefixedStoreClient, StoreBatchUpload, StoreWriteBatch,
};
use futures::{future::BoxFuture, TryStreamExt};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
};

/// Encodes rows of one table into Store entries.
#[derive(Debug)]
pub struct TableWriter {
    /// Table layout that determines the primary-key and row-value encodings.
    model: Arc<TableModel>,
    /// Secondary indexes. Each row produces one index entry per spec, in this order.
    index_specs: Arc<Vec<ResolvedIndexSpec>>,
}

impl TableWriter {
    /// Encodes `values`, given in table column order, as the base-row entry followed by one
    /// entry per secondary index.
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

/// Buffers rows across a schema's tables for upload in atomic Store batches.
#[derive(Debug)]
pub struct BatchWriter {
    /// Store client whose namespace prefixes staged keys and that commits each batch.
    client: PrefixedStoreClient,
    /// Row encoders keyed by registered table name.
    tables: HashMap<String, TableWriter>,
    /// Next ID assigned when pending entries are taken into a new batch. Retries reuse
    /// their original ID.
    next_request_id: u64,
    /// Batches whose upload failed, awaiting retry by `prepare_flush` in request ID order.
    /// The mutex lets upload outcomes be reported through a shared reference.
    failed_prepared: Mutex<Vec<PreparedBatch>>,
    /// Encoded entries not yet taken into a batch, in insert order. Each row adds its
    /// base entry and then its index entries.
    pub(crate) pending_entries: Vec<(Key, Bytes)>,
}

/// Entries taken from a `BatchWriter` for one upload attempt.
///
/// Report the outcome with `mark_flush_persisted` or `mark_flush_failed`. The writer retains
/// no copy until `mark_flush_failed` queues the batch for retry.
#[derive(Debug)]
#[must_use]
pub struct PreparedBatch {
    /// Writer-assigned ID retained across retries.
    request_id: u64,
    /// Encoded entries in insert order, retained until the upload outcome is reported.
    entries: Vec<(Key, Bytes)>,
}

impl PreparedBatch {
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Outcome of a persisted `PreparedBatch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchReceipt {
    /// Request ID of the persisted batch.
    pub writer_request_id: u64,
    /// Number of key-value entries written, counting index entries separately from base rows.
    pub entry_count: usize,
    /// Store sequence number returned by the commit.
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
            pending_entries: Vec::new(),
        }
    }

    /// Buffers one row's base and index entries. A row whose keys would exceed the Store
    /// key limit under the client's namespace is rejected before anything is buffered, so
    /// every prepared batch can be staged.
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
        for (key, _) in &entries {
            self.client
                .encode_store_key(key)
                .map_err(|e| e.to_string())?;
        }
        self.pending_entries
            .extend(entries.into_iter().map(|(key, value)| (key, value.into())));
        Ok(self)
    }

    pub fn pending_count(&self) -> usize {
        self.pending_entries.len()
            + self
                .failed_prepared
                .lock()
                .expect("failed prepared mutex poisoned")
                .iter()
                .map(PreparedBatch::entry_count)
                .sum::<usize>()
    }

    /// Flushes the next prepared batch and returns its Store sequence number, or zero when
    /// nothing is pending.
    pub async fn flush(&mut self) -> DataFusionResult<u64> {
        Ok(self
            .flush_with_receipt()
            .await?
            .map(|receipt| receipt.store_sequence_number)
            .unwrap_or(0))
    }

    /// Flushes the next prepared batch and returns its receipt, or `None` when nothing is
    /// pending.
    pub async fn flush_with_receipt(&mut self) -> DataFusionResult<Option<BatchReceipt>> {
        let Some(prepared) = self.prepare_flush()? else {
            return Ok(None);
        };
        Ok(Some(self.commit_upload(prepared).await?))
    }

    /// Takes the failed batch with the lowest request ID, or else every pending entry as a new
    /// batch. Returns `None` when neither exists.
    pub fn prepare_flush(&mut self) -> DataFusionResult<Option<PreparedBatch>> {
        if let Some(prepared) = self.take_failed_prepared() {
            return Ok(Some(prepared));
        }
        if self.pending_entries.is_empty() {
            return Ok(None);
        }
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        Ok(Some(PreparedBatch {
            request_id,
            entries: std::mem::take(&mut self.pending_entries),
        }))
    }

    pub fn stage_flush(
        &self,
        prepared: &PreparedBatch,
        batch: &mut StoreWriteBatch,
    ) -> DataFusionResult<()> {
        for (key, value) in &prepared.entries {
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

/// DataFusion sink for `INSERT` into one table.
///
/// Encodes every input row with its index entries and commits them in one atomic Store write
/// after the input ends. Reports the number of input rows written.
#[derive(Debug)]
pub(crate) struct KvIngestSink {
    /// Table provider supplying the sink's schema, row encodings, and Store namespace.
    pub(crate) table: KvTable,
}

impl DisplayAs for KvIngestSink {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KvIngestSink")
    }
}

#[async_trait]
impl DataSink for KvIngestSink {
    fn schema(&self) -> &SchemaRef {
        &self.table.model.schema
    }

    async fn write_all(
        &self,
        data: SendableRecordBatchStream,
        _context: &Arc<TaskContext>,
    ) -> DataFusionResult<u64> {
        let mut data = data;
        let mut pending_entries = Vec::new();
        let mut logical_rows_written = 0u64;

        while let Some(batch) = data.try_next().await? {
            let encoded_entries =
                encode_insert_entries(&batch, &self.table.model, &self.table.index_specs)?;
            logical_rows_written += batch.num_rows() as u64;
            pending_entries.extend(
                encoded_entries
                    .into_iter()
                    .map(|(key, value)| (key, value.into())),
            );
        }

        flush_ingest_batch(&self.table.client, &mut pending_entries).await?;
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
    encode_selected_values(model, |idx, col| {
        if model.is_pk_column(idx) {
            Ok(None)
        } else {
            encode_non_pk_cell_value(row.value_at(idx), col)
        }
    })
}

pub(crate) fn encode_secondary_index_value(
    row: &KvRow,
    model: &TableModel,
    spec: &ResolvedIndexSpec,
) -> DataFusionResult<Vec<u8>> {
    encode_selected_values(model, |idx, col| {
        if spec.value_column_mask[idx] {
            encode_non_pk_cell_value(row.value_at(idx), col)
        } else {
            Ok(None)
        }
    })
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
    encode_selected_values(model, |idx, col| {
        if !spec.value_column_mask[idx] {
            return Ok(None);
        }
        let stored_opt = archived.values.get(idx).and_then(|value| value.as_ref());
        if !archived_non_pk_value_is_valid(col, stored_opt) {
            return Err(DataFusionError::Execution(format!(
                "invalid archived value for secondary index column '{}'",
                col.name
            )));
        }
        Ok(stored_opt.cloned())
    })
}

/// Encodes a stored row with one slot per table column. Columns for which `value_at` returns
/// `None` occupy null slots.
fn encode_selected_values(
    model: &TableModel,
    mut value_at: impl FnMut(usize, &ResolvedColumn) -> DataFusionResult<Option<StoredValue>>,
) -> DataFusionResult<Vec<u8>> {
    let mut values = Vec::with_capacity(model.columns.len());
    for (idx, col) in model.columns.iter().enumerate() {
        values.push(value_at(idx, col)?);
    }
    Ok(StoredRow { values }.encode().to_vec())
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
    entries: &mut Vec<(Key, Bytes)>,
) -> DataFusionResult<u64> {
    if entries.is_empty() {
        return Ok(0);
    }
    let mut batch = StoreWriteBatch::new();
    for (key, value) in entries.iter() {
        batch
            .push(client, key, value)
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
    }
    let token = batch
        .commit(client.client())
        .await
        .map_err(|e| DataFusionError::External(Box::new(e)))?;
    entries.clear();
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{append_archived_non_pk_value, make_column_builder};
    use bytes::Bytes;
    use datafusion::arrow::{
        array::{
            builder::Int64Builder, BinaryArray, BinaryViewArray, Int64Array, LargeBinaryArray,
            ListBuilder, StringArray, UInt64Array,
        },
        datatypes::{DataType, Field, Schema},
    };
    use exoware_sdk::{kv_codec::decode_stored_row, StoreClient, StoreKeyPrefix};

    #[test]
    fn secondary_index_storage_encoding_is_stable() {
        for (layout, expected_key) in [
            (
                IndexLayout::Lexicographic,
                "217ffffffe12fe000000000000000912fe",
            ),
            (IndexLayout::ZOrder, "212baefffefffe000000000000000912fe"),
        ] {
            // Mixed-width index fields precede a composite primary key. Stored
            // values retain table-column positions, including unselected slots.
            let config = KvTableConfig::new(
                2,
                vec![
                    TableColumnConfig::new("day", DataType::Date32, false),
                    TableColumnConfig::new("id", DataType::UInt64, false),
                    TableColumnConfig::new("note", DataType::Utf8, true),
                    TableColumnConfig::new("tag", DataType::FixedSizeBinary(2), false),
                    TableColumnConfig::new("unused", DataType::Int64, false),
                ],
                vec!["id".into(), "tag".into()],
                vec![IndexSpec::new("by_stamp", vec!["day".into(), "tag".into()])
                    .unwrap()
                    .with_layout(layout)
                    .with_cover_columns(vec!["note".into()])],
            )
            .unwrap();
            let model = TableModel::from_config(&config).unwrap();
            let specs = model.resolve_index_specs(&config.index_specs).unwrap();
            let spec = &specs[0];
            for (note, expected_base, expected_index) in [
                (
                    CellValue::Null,
                    "050100fffffffffffffffe0000000100fffffffffffffff9",
                    "050100fffffffffffffffe00000000",
                ),
                (
                    CellValue::Utf8("é\0x".into()),
                    "050100fffffffffffffffe00010404c3a90078000100fffffffffffffff9",
                    "050100fffffffffffffffe00010404c3a900780000",
                ),
            ] {
                // The write path must produce the pinned base value, index key, and index value.
                let row = KvRow {
                    values: vec![
                        CellValue::Date32(-2),
                        CellValue::UInt64(9),
                        note,
                        CellValue::FixedBinary(vec![0x12, 0xfe]),
                        CellValue::Int64(-7),
                    ],
                };
                let base = encode_base_row_value(&row, &model).unwrap();
                assert_eq!(hex::encode(&base), expected_base);
                assert_eq!(
                    hex::encode(encode_secondary_index_key(2, spec, &model, &row).unwrap()),
                    expected_key
                );
                assert_eq!(
                    hex::encode(encode_secondary_index_value(&row, &model, spec).unwrap()),
                    expected_index
                );

                // Backfill reconstructs the same entry from the stored base value
                // and primary key, without access to the original row.
                let stored = decode_stored_row(&base).unwrap();
                let pk = [
                    CellValue::UInt64(9),
                    CellValue::FixedBinary(vec![0x12, 0xfe]),
                ];
                assert_eq!(
                    hex::encode(
                        encode_secondary_index_key_from_parts(2, spec, &model, &pk, &stored)
                            .unwrap()
                    ),
                    expected_key
                );
                assert_eq!(
                    hex::encode(
                        encode_secondary_index_value_from_archived(&stored, &model, spec).unwrap()
                    ),
                    expected_index
                );
            }
        }
    }

    #[test]
    fn oversized_index_keys_preserve_writer_and_backfill_errors() {
        // The 251-byte primary key fits in the base key, but the index key that appends it to
        // the tag exceeds the Store key limit.
        let schema = crate::KvSchema::new(PrefixedStoreClient::empty(StoreClient::new(
            "http://127.0.0.1:1",
        )))
        .table(
            "orders",
            vec![
                TableColumnConfig::new("id", DataType::Utf8, false),
                TableColumnConfig::new("tag", DataType::Utf8, false),
            ],
            vec!["id".into()],
            vec![IndexSpec::new("tag_idx", vec!["tag".into()]).unwrap()],
        )
        .unwrap();
        let row = KvRow {
            values: vec![
                CellValue::Utf8("i".repeat(251)),
                CellValue::Utf8("t".into()),
            ],
        };
        let expected = "failed to encode index 'tag_idx' key: key length 255 exceeds max 254";

        // A failed insert must not leave the base entry pending on its own.
        let mut writer = schema.batch_writer();
        assert_eq!(
            writer.insert("orders", row.values.clone()).unwrap_err(),
            expected
        );
        assert_eq!(writer.pending_count(), 0);

        // Backfill rebuilds the index key from the stored base row and must fail with the
        // writer's error.
        let table = &schema.tables()[0].1;
        let base = encode_base_row_value(&row, &table.model).unwrap();
        let stored = decode_stored_row(&base).unwrap();
        let error = encode_secondary_index_key_from_parts(
            table.model.table_prefix,
            &table.index_specs[0],
            &table.model,
            &row.values[..1],
            &stored,
        )
        .unwrap_err();
        assert!(matches!(error, DataFusionError::Execution(message) if message == expected));
    }

    #[test]
    fn insert_rejects_keys_that_exceed_the_namespace_limit() {
        // The namespace leaves 251 bytes for logical keys, so this row's 253-byte base key
        // fits the Store limit on its own but not inside the namespace.
        let prefix = StoreKeyPrefix::new(Bytes::from_static(b"ns/")).unwrap();
        let schema = crate::KvSchema::new(StoreClient::new("http://127.0.0.1:1").prefixed(prefix))
            .table(
                "orders",
                vec![TableColumnConfig::new("id", DataType::Utf8, false)],
                vec!["id".into()],
                vec![],
            )
            .unwrap();
        let mut writer = schema.batch_writer();

        // The row must be rejected before it is buffered, so no later flush can fail
        // while staging it.
        let err = writer
            .insert("orders", vec![CellValue::Utf8("i".repeat(251))])
            .unwrap_err();
        assert!(err.contains("exceeds max"), "{err}");
        assert_eq!(writer.pending_count(), 0);
    }

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
            append_archived_non_pk_value(&mut builder, stored.values[body_idx].as_ref())
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
                append_archived_non_pk_value(&mut builder, stored.values[1].as_ref()).unwrap();
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
            entries: vec![
                (Bytes::from_static(b"a"), Bytes::from_static(&[1])),
                (Bytes::from_static(b"b"), Bytes::from_static(&[2, 3])),
            ],
        };
        let entries = prepared.entries.clone();
        let mut batch = StoreWriteBatch::new();

        StoreBatchUpload::stage_upload(&writer, &mut prepared, &mut batch).expect("stage flush");

        assert_eq!(batch.len(), 2);
        assert_eq!(prepared.entry_count(), 2);
        assert_eq!(prepared.entries, entries);

        writer.mark_flush_failed(prepared);
        let mut retry = writer.take_failed_prepared().expect("failed batch queued");
        assert_eq!(retry.entry_count(), 2);

        let mut retry_batch = StoreWriteBatch::new();
        StoreBatchUpload::stage_upload(&writer, &mut retry, &mut retry_batch).expect("stage retry");
        assert_eq!(retry_batch.len(), 2);
        assert_eq!(retry.entries, entries);
    }
}
