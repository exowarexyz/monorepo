use std::sync::Arc;

use datafusion::arrow::array::{
    ArrayRef, BooleanBuilder, Date32Builder, Date64Builder, Decimal128Builder, Decimal256Builder,
    FixedSizeBinaryBuilder, Float64Builder, Int64Builder, ListBuilder, StringBuilder,
    TimestampMicrosecondBuilder, UInt64Builder,
};
use datafusion::arrow::compute::cast;
use datafusion::arrow::datatypes::{i256, DataType, SchemaRef};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::common::{DataFusionError, Result as DataFusionResult};
use exoware_sdk_rs::kv_codec::{StoredRow, StoredValue};

use crate::filter::*;
use crate::types::*;

pub(crate) enum ColumnBuilder {
    Int64(Int64Builder),
    UInt64(UInt64Builder),
    Float64(Float64Builder),
    Boolean(BooleanBuilder),
    Date32(Date32Builder),
    Date64(Date64Builder),
    Timestamp(TimestampMicrosecondBuilder),
    Decimal128(Decimal128Builder),
    Decimal256(Decimal256Builder),
    Utf8 {
        builder: StringBuilder,
        target_type: DataType,
    },
    FixedBinary(FixedSizeBinaryBuilder),
    ListInt64(ListBuilder<Int64Builder>),
    ListFloat64(ListBuilder<Float64Builder>),
    ListBoolean(ListBuilder<BooleanBuilder>),
    ListUtf8(ListBuilder<StringBuilder>),
}

impl ColumnBuilder {
    pub(crate) fn append(&mut self, value: &CellValue) -> DataFusionResult<()> {
        match (self, value) {
            (Self::Int64(b), CellValue::Null) => b.append_null(),
            (Self::UInt64(b), CellValue::Null) => b.append_null(),
            (Self::Float64(b), CellValue::Null) => b.append_null(),
            (Self::Boolean(b), CellValue::Null) => b.append_null(),
            (Self::Date32(b), CellValue::Null) => b.append_null(),
            (Self::Date64(b), CellValue::Null) => b.append_null(),
            (Self::Timestamp(b), CellValue::Null) => b.append_null(),
            (Self::Decimal128(b), CellValue::Null) => b.append_null(),
            (Self::Decimal256(b), CellValue::Null) => b.append_null(),
            (Self::Utf8 { builder, .. }, CellValue::Null) => builder.append_null(),
            (Self::FixedBinary(b), CellValue::Null) => b.append_null(),
            (Self::ListInt64(b), CellValue::Null) => b.append_null(),
            (Self::ListFloat64(b), CellValue::Null) => b.append_null(),
            (Self::ListBoolean(b), CellValue::Null) => b.append_null(),
            (Self::ListUtf8(b), CellValue::Null) => b.append_null(),
            (Self::Int64(b), CellValue::Int64(v)) => b.append_value(*v),
            (Self::UInt64(b), CellValue::UInt64(v)) => b.append_value(*v),
            (Self::Float64(b), CellValue::Float64(v)) => b.append_value(*v),
            (Self::Boolean(b), CellValue::Boolean(v)) => b.append_value(*v),
            (Self::Date32(b), CellValue::Date32(v)) => b.append_value(*v),
            (Self::Date64(b), CellValue::Date64(v)) => b.append_value(*v),
            (Self::Timestamp(b), CellValue::Timestamp(v)) => b.append_value(*v),
            (Self::Decimal128(b), CellValue::Decimal128(v)) => b.append_value(*v),
            (Self::Decimal256(b), CellValue::Decimal256(v)) => b.append_value(*v),
            (Self::Utf8 { builder, .. }, CellValue::Utf8(v)) => builder.append_value(v),
            (Self::FixedBinary(b), CellValue::FixedBinary(v)) => {
                b.append_value(v).map_err(|e| {
                    DataFusionError::Execution(format!("FixedBinary append error: {e}"))
                })?
            }
            (Self::ListInt64(b), CellValue::List(items)) => {
                for item in items {
                    match item {
                        CellValue::Int64(v) => b.values().append_value(*v),
                        _ => {
                            return Err(DataFusionError::Execution(
                                "list element type mismatch".into(),
                            ))
                        }
                    }
                }
                b.append(true);
            }
            (Self::ListFloat64(b), CellValue::List(items)) => {
                for item in items {
                    match item {
                        CellValue::Float64(v) => b.values().append_value(*v),
                        _ => {
                            return Err(DataFusionError::Execution(
                                "list element type mismatch".into(),
                            ))
                        }
                    }
                }
                b.append(true);
            }
            (Self::ListBoolean(b), CellValue::List(items)) => {
                for item in items {
                    match item {
                        CellValue::Boolean(v) => b.values().append_value(*v),
                        _ => {
                            return Err(DataFusionError::Execution(
                                "list element type mismatch".into(),
                            ))
                        }
                    }
                }
                b.append(true);
            }
            (Self::ListUtf8(b), CellValue::List(items)) => {
                for item in items {
                    match item {
                        CellValue::Utf8(v) => b.values().append_value(v),
                        _ => {
                            return Err(DataFusionError::Execution(
                                "list element type mismatch".into(),
                            ))
                        }
                    }
                }
                b.append(true);
            }
            _ => {
                return Err(DataFusionError::Execution(
                    "column type mismatch".to_string(),
                ))
            }
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> DataFusionResult<ArrayRef> {
        match self {
            Self::Int64(mut b) => Ok(Arc::new(b.finish())),
            Self::UInt64(mut b) => Ok(Arc::new(b.finish())),
            Self::Float64(mut b) => Ok(Arc::new(b.finish())),
            Self::Boolean(mut b) => Ok(Arc::new(b.finish())),
            Self::Date32(mut b) => Ok(Arc::new(b.finish())),
            Self::Date64(mut b) => Ok(Arc::new(b.finish())),
            Self::Timestamp(mut b) => Ok(Arc::new(b.finish())),
            Self::Decimal128(mut b) => Ok(Arc::new(b.finish())),
            Self::Decimal256(mut b) => Ok(Arc::new(b.finish())),
            Self::Utf8 {
                mut builder,
                target_type,
            } => {
                let array: ArrayRef = Arc::new(builder.finish());
                if target_type == DataType::Utf8 {
                    Ok(array)
                } else {
                    Ok(cast(&array, &target_type)?)
                }
            }
            Self::FixedBinary(mut b) => Ok(Arc::new(b.finish())),
            Self::ListInt64(mut b) => Ok(Arc::new(b.finish())),
            Self::ListFloat64(mut b) => Ok(Arc::new(b.finish())),
            Self::ListBoolean(mut b) => Ok(Arc::new(b.finish())),
            Self::ListUtf8(mut b) => Ok(Arc::new(b.finish())),
        }
    }
}

#[cfg(test)]
pub(crate) fn build_projected_batch(
    rows: &[KvRow],
    model: &TableModel,
    projected_schema: &SchemaRef,
    projection: &Option<Vec<usize>>,
) -> DataFusionResult<RecordBatch> {
    let col_indices = projected_column_indices(model, projection);
    let mut builders: Vec<ColumnBuilder> = col_indices
        .iter()
        .map(|&idx| make_column_builder(model, idx))
        .collect();
    for row in rows {
        for (builder, &col_idx) in builders.iter_mut().zip(col_indices.iter()) {
            builder.append(&row.values[col_idx])?;
        }
    }
    let columns: Vec<ArrayRef> = builders
        .into_iter()
        .map(ColumnBuilder::finish)
        .collect::<DataFusionResult<Vec<_>>>()?;
    Ok(RecordBatch::try_new(projected_schema.clone(), columns)?)
}

pub(crate) fn projected_column_indices(
    model: &TableModel,
    projection: &Option<Vec<usize>>,
) -> Vec<usize> {
    match projection {
        Some(proj) => proj.clone(),
        None => (0..model.columns.len()).collect(),
    }
}

pub(crate) fn make_column_builder(model: &TableModel, idx: usize) -> ColumnBuilder {
    let col = &model.columns[idx];
    match col.kind {
        ColumnKind::Int64 => ColumnBuilder::Int64(Int64Builder::new()),
        ColumnKind::UInt64 => ColumnBuilder::UInt64(UInt64Builder::new()),
        ColumnKind::Float64 => ColumnBuilder::Float64(Float64Builder::new()),
        ColumnKind::Boolean => ColumnBuilder::Boolean(BooleanBuilder::new()),
        ColumnKind::Date32 => ColumnBuilder::Date32(Date32Builder::new()),
        ColumnKind::Date64 => ColumnBuilder::Date64(Date64Builder::new()),
        ColumnKind::Timestamp => {
            let dt = model.schema.field(idx).data_type().clone();
            ColumnBuilder::Timestamp(TimestampMicrosecondBuilder::new().with_data_type(dt))
        }
        ColumnKind::Decimal128 => {
            let dt = model.schema.field(idx).data_type().clone();
            ColumnBuilder::Decimal128(Decimal128Builder::new().with_data_type(dt))
        }
        ColumnKind::Decimal256 => {
            let dt = model.schema.field(idx).data_type().clone();
            ColumnBuilder::Decimal256(Decimal256Builder::new().with_data_type(dt))
        }
        ColumnKind::Utf8 => ColumnBuilder::Utf8 {
            builder: StringBuilder::new(),
            target_type: model.schema.field(idx).data_type().clone(),
        },
        ColumnKind::FixedSizeBinary(n) => {
            ColumnBuilder::FixedBinary(FixedSizeBinaryBuilder::new(n as i32))
        }
        ColumnKind::List(elem) => match elem {
            ListElementKind::Int64 => {
                ColumnBuilder::ListInt64(ListBuilder::new(Int64Builder::new()))
            }
            ListElementKind::Float64 => {
                ColumnBuilder::ListFloat64(ListBuilder::new(Float64Builder::new()))
            }
            ListElementKind::Boolean => {
                ColumnBuilder::ListBoolean(ListBuilder::new(BooleanBuilder::new()))
            }
            ListElementKind::Utf8 => {
                ColumnBuilder::ListUtf8(ListBuilder::new(StringBuilder::new()))
            }
        },
    }
}

pub(crate) fn archived_non_pk_value_is_valid(
    col: &ResolvedColumn,
    stored_opt: Option<&StoredValue>,
) -> bool {
    let Some(stored) = stored_opt else {
        return col.nullable;
    };
    match (col.kind, stored) {
        (ColumnKind::Int64, StoredValue::Int64(_)) => true,
        (ColumnKind::UInt64, StoredValue::UInt64(_)) => true,
        (ColumnKind::Float64, StoredValue::Float64(_)) => true,
        (ColumnKind::Float64, StoredValue::Int64(_)) => true,
        (ColumnKind::Boolean, StoredValue::Boolean(_)) => true,
        (ColumnKind::Date32, StoredValue::Int64(_)) => true,
        (ColumnKind::Date64, StoredValue::Int64(_)) => true,
        (ColumnKind::Timestamp, StoredValue::Int64(_)) => true,
        (ColumnKind::Decimal128, StoredValue::Bytes(bytes)) => bytes.as_slice().len() == 16,
        (ColumnKind::Decimal256, StoredValue::Bytes(bytes)) => bytes.as_slice().len() == 32,
        (ColumnKind::Utf8, StoredValue::Utf8(_)) => true,
        (ColumnKind::FixedSizeBinary(expected), StoredValue::Bytes(bytes)) => {
            bytes.as_slice().len() == expected
        }
        (ColumnKind::List(ListElementKind::Int64), StoredValue::List(items)) => items
            .iter()
            .all(|item| matches!(item, StoredValue::Int64(_))),
        (ColumnKind::List(ListElementKind::Float64), StoredValue::List(items)) => items
            .iter()
            .all(|item| matches!(item, StoredValue::Float64(_) | StoredValue::Int64(_))),
        (ColumnKind::List(ListElementKind::Boolean), StoredValue::List(items)) => items
            .iter()
            .all(|item| matches!(item, StoredValue::Boolean(_))),
        (ColumnKind::List(ListElementKind::Utf8), StoredValue::List(items)) => items
            .iter()
            .all(|item| matches!(item, StoredValue::Utf8(_))),
        _ => false,
    }
}

pub(crate) fn append_archived_non_pk_value(
    builder: &mut ColumnBuilder,
    col: &ResolvedColumn,
    stored_opt: Option<&StoredValue>,
) -> DataFusionResult<()> {
    let Some(stored) = stored_opt else {
        return builder.append(&CellValue::Null);
    };
    match (builder, col.kind, stored) {
        (ColumnBuilder::Int64(b), ColumnKind::Int64, StoredValue::Int64(v)) => b.append_value(*v),
        (ColumnBuilder::UInt64(b), ColumnKind::UInt64, StoredValue::UInt64(v)) => {
            b.append_value(*v)
        }
        (ColumnBuilder::Float64(b), ColumnKind::Float64, StoredValue::Float64(v)) => {
            b.append_value(*v)
        }
        (ColumnBuilder::Float64(b), ColumnKind::Float64, StoredValue::Int64(v)) => {
            b.append_value(*v as f64)
        }
        (ColumnBuilder::Boolean(b), ColumnKind::Boolean, StoredValue::Boolean(v)) => {
            b.append_value(*v)
        }
        (ColumnBuilder::Date32(b), ColumnKind::Date32, StoredValue::Int64(v)) => {
            b.append_value(*v as i32)
        }
        (ColumnBuilder::Date64(b), ColumnKind::Date64, StoredValue::Int64(v)) => b.append_value(*v),
        (ColumnBuilder::Timestamp(b), ColumnKind::Timestamp, StoredValue::Int64(v)) => {
            b.append_value(*v)
        }
        (ColumnBuilder::Decimal128(b), ColumnKind::Decimal128, StoredValue::Bytes(bytes)) => {
            let arr: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
                DataFusionError::Execution("invalid Decimal128 byte width".to_string())
            })?;
            b.append_value(i128::from_le_bytes(arr))
        }
        (ColumnBuilder::Decimal256(b), ColumnKind::Decimal256, StoredValue::Bytes(bytes)) => {
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                DataFusionError::Execution("invalid Decimal256 byte width".to_string())
            })?;
            b.append_value(i256::from_le_bytes(arr))
        }
        (ColumnBuilder::Utf8 { builder, .. }, ColumnKind::Utf8, StoredValue::Utf8(v)) => {
            builder.append_value(v.as_str())
        }
        (ColumnBuilder::FixedBinary(b), ColumnKind::FixedSizeBinary(_), StoredValue::Bytes(v)) => b
            .append_value(v.as_slice())
            .map_err(|e| DataFusionError::Execution(format!("FixedBinary append error: {e}")))?,
        (
            ColumnBuilder::ListInt64(b),
            ColumnKind::List(ListElementKind::Int64),
            StoredValue::List(items),
        ) => {
            for item in items.iter() {
                let StoredValue::Int64(v) = item else {
                    return Err(DataFusionError::Execution(
                        "list element type mismatch".to_string(),
                    ));
                };
                b.values().append_value(*v);
            }
            b.append(true);
        }
        (
            ColumnBuilder::ListFloat64(b),
            ColumnKind::List(ListElementKind::Float64),
            StoredValue::List(items),
        ) => {
            for item in items.iter() {
                match item {
                    StoredValue::Float64(v) => b.values().append_value(*v),
                    StoredValue::Int64(v) => b.values().append_value(*v as f64),
                    _ => {
                        return Err(DataFusionError::Execution(
                            "list element type mismatch".to_string(),
                        ))
                    }
                }
            }
            b.append(true);
        }
        (
            ColumnBuilder::ListBoolean(b),
            ColumnKind::List(ListElementKind::Boolean),
            StoredValue::List(items),
        ) => {
            for item in items.iter() {
                let StoredValue::Boolean(v) = item else {
                    return Err(DataFusionError::Execution(
                        "list element type mismatch".to_string(),
                    ));
                };
                b.values().append_value(*v);
            }
            b.append(true);
        }
        (
            ColumnBuilder::ListUtf8(b),
            ColumnKind::List(ListElementKind::Utf8),
            StoredValue::List(items),
        ) => {
            for item in items.iter() {
                let StoredValue::Utf8(v) = item else {
                    return Err(DataFusionError::Execution(
                        "list element type mismatch".to_string(),
                    ));
                };
                b.values().append_value(v.as_str());
            }
            b.append(true);
        }
        _ => {
            return Err(DataFusionError::Execution(
                "column type mismatch".to_string(),
            ))
        }
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) enum ProjectionSource {
    Pk { col_idx: usize, pk_pos: usize },
    NonPk { col_idx: usize, col: ResolvedColumn },
}

pub(crate) struct ProjectedBatchBuilder {
    pub(crate) sources: Vec<ProjectionSource>,
    pub(crate) builders: Vec<ColumnBuilder>,
    pub(crate) row_count: usize,
}

impl ProjectedBatchBuilder {
    pub(crate) fn from_access_plan(model: &TableModel, access_plan: &ScanAccessPlan) -> Self {
        let col_indices: Vec<usize> = access_plan
            .projection_sources
            .iter()
            .map(|source| match source {
                ProjectionSource::Pk { col_idx, .. } => *col_idx,
                ProjectionSource::NonPk { col_idx, .. } => *col_idx,
            })
            .collect();
        let builders = col_indices
            .iter()
            .map(|&idx| make_column_builder(model, idx))
            .collect();
        Self {
            sources: access_plan.projection_sources.clone(),
            builders,
            row_count: 0,
        }
    }

    pub(crate) fn append_archived_row(
        &mut self,
        pk_values: &[CellValue],
        archived: &StoredRow,
    ) -> DataFusionResult<bool> {
        for source in &self.sources {
            match source {
                ProjectionSource::Pk { pk_pos, .. } => {
                    if pk_values.get(*pk_pos).is_none() {
                        return Ok(false);
                    }
                }
                ProjectionSource::NonPk { col_idx, col } => {
                    let stored_opt = archived.values.get(*col_idx).and_then(|v| v.as_ref());
                    if !archived_non_pk_value_is_valid(col, stored_opt) {
                        return Ok(false);
                    }
                }
            }
        }
        for (builder, source) in self.builders.iter_mut().zip(self.sources.iter()) {
            match source {
                ProjectionSource::Pk { pk_pos, .. } => {
                    let value = pk_values.get(*pk_pos).ok_or_else(|| {
                        DataFusionError::Execution("missing primary key value".to_string())
                    })?;
                    builder.append(value)?;
                }
                ProjectionSource::NonPk { col_idx, col } => {
                    let stored_opt = archived.values.get(*col_idx).and_then(|v| v.as_ref());
                    append_archived_non_pk_value(builder, col, stored_opt)?;
                }
            }
        }
        self.row_count += 1;
        Ok(true)
    }

    pub(crate) fn row_count(&self) -> usize {
        self.row_count
    }

    pub(crate) fn finish(self, projected_schema: &SchemaRef) -> DataFusionResult<RecordBatch> {
        let columns: Vec<ArrayRef> = self
            .builders
            .into_iter()
            .map(ColumnBuilder::finish)
            .collect::<DataFusionResult<Vec<_>>>()?;
        Ok(RecordBatch::try_new(projected_schema.clone(), columns)?)
    }
}
