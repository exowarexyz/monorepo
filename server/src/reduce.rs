//! Native worker aggregation over evaluated Store expressions.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use datafusion::arrow::array::{
    ArrayRef, BinaryArray, BooleanArray, Date32Array, Date64Array, Decimal128Array,
    Decimal256Array, Float64Array, Int64Array, StringArray, TimestampMicrosecondArray, UInt64Array,
};
use datafusion::arrow::datatypes::{i256, DataType, Field, Schema, SchemaRef, TimeUnit};
use datafusion::arrow::record_batch::{RecordBatch, RecordBatchOptions};
use datafusion::common::{DataFusionError, Result as DfResult, ScalarValue};
use datafusion::execution::context::TaskContext;
use datafusion::execution::memory_pool::MemoryLimit;
use datafusion::functions_aggregate::{
    count::count_udaf,
    min_max::{max_udaf, min_udaf},
    sum::sum_udaf,
};
use datafusion::logical_expr::AggregateUDF;
use datafusion::physical_expr::aggregate::{AggregateExprBuilder, AggregateFunctionExpr};
use datafusion::physical_expr::expressions::{Column, Literal};
use datafusion::physical_expr::PhysicalExpr;
use datafusion::physical_plan::aggregates::{AggregateExec, AggregateMode, PhysicalGroupBy};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::streaming::{PartitionStream, StreamingTableExec};
use datafusion::physical_plan::{ExecutionPlan, SendableRecordBatchStream};
use exoware_sdk::keys::Key;
use exoware_sdk::kv_codec::{
    canonicalize_reduced_group_values, decode_stored_row, eval_expr, eval_predicate,
    expr_needs_value, predicate_needs_value, KvExpr, KvFieldKind, KvFieldRef, KvReducedValue,
};
use exoware_sdk::{RangeReduceGroup, RangeReduceOp, RangeReduceRequest, RangeReduceResult};

use crate::{Query, QueryExtra, RangeScan};

pub(crate) const REDUCE_BATCH_ROWS: usize = 4096;
const REDUCE_BATCH_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum RangeError {
    Reduce(String),
    Backend(String),
    Resources(String),
}

impl fmt::Display for RangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reduce(s) | Self::Backend(s) | Self::Resources(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for RangeError {}

impl From<DataFusionError> for RangeError {
    fn from(error: DataFusionError) -> Self {
        match error.find_root() {
            DataFusionError::ResourcesExhausted(_) => Self::Resources(error.to_string()),
            DataFusionError::External(source) if source.downcast_ref::<RangeError>().is_some() => {
                match source.downcast_ref::<RangeError>().unwrap() {
                    Self::Backend(s) => Self::Backend(s.clone()),
                    Self::Resources(s) => Self::Resources(s.clone()),
                    Self::Reduce(s) => Self::Reduce(s.clone()),
                }
            }
            DataFusionError::IoError(_) | DataFusionError::Internal(_) => {
                Self::Backend(error.to_string())
            }
            _ => Self::Reduce(error.to_string()),
        }
    }
}

fn execution_error(error: impl ToString) -> DataFusionError {
    DataFusionError::Execution(error.to_string())
}

#[derive(Debug)]
struct ExtractedReductionRow {
    group_values: Vec<Option<KvReducedValue>>,
    reducer_values: Vec<Option<KvReducedValue>>,
}

#[derive(Debug)]
struct ReducePlan {
    request: Arc<RangeReduceRequest>,
    needs_value: bool,
    reducer_columns: Vec<ReduceColumn>,
    schema: SchemaRef,
    aggregates: Vec<Arc<AggregateFunctionExpr>>,
    result_kinds: Vec<ResultKind>,
}

#[derive(Debug)]
struct ReduceColumn {
    expr: KvExpr,
    ordered_float: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ResultKind {
    Value,
    Count,
    OrderedFloat,
}

impl ReducePlan {
    fn new(request: Arc<RangeReduceRequest>) -> Result<Self, RangeError> {
        validate_reduce_request(&request)?;
        let needs_value = request
            .group_by
            .iter()
            .chain(
                request
                    .reducers
                    .iter()
                    .filter_map(|reducer| reducer.expr.as_ref()),
            )
            .any(expr_needs_value)
            || request.filter.as_ref().is_some_and(predicate_needs_value);
        let mut fields = Vec::with_capacity(request.group_by.len() + request.reducers.len());
        for (i, expr) in request.group_by.iter().enumerate() {
            fields.push(Field::new(
                format!("group_{i}"),
                expression_type(expr)?,
                true,
            ));
        }
        let mut result_kinds = Vec::with_capacity(request.reducers.len());
        let mut reducer_columns: Vec<ReduceColumn> = Vec::new();
        let mut field_columns = HashMap::new();
        let mut arguments: Vec<Arc<dyn PhysicalExpr>> = Vec::with_capacity(request.reducers.len());
        for reducer in &request.reducers {
            let Some(expr) = &reducer.expr else {
                result_kinds.push(ResultKind::Count);
                arguments.push(Arc::new(Literal::new(ScalarValue::Boolean(Some(true)))));
                continue;
            };
            let mut data_type = expression_type(expr)?;
            let result_kind = match reducer.op {
                RangeReduceOp::CountAll | RangeReduceOp::CountField => ResultKind::Count,
                RangeReduceOp::MinField | RangeReduceOp::MaxField
                    if data_type == DataType::Float64 && !request.group_by.is_empty() =>
                {
                    // Native grouped float extrema do not implement total ordering
                    data_type = DataType::Int64;
                    ResultKind::OrderedFloat
                }
                _ => ResultKind::Value,
            };
            result_kinds.push(result_kind);
            let ordered_float = matches!(result_kind, ResultKind::OrderedFloat);
            let insert_column = || {
                let index = reducer_columns.len();
                fields.push(Field::new(format!("value_{index}"), data_type, true));
                reducer_columns.push(ReduceColumn {
                    expr: expr.clone(),
                    ordered_float,
                });
                index
            };
            let index = match expr {
                KvExpr::Field(field) => *field_columns
                    .entry((field, ordered_float))
                    .or_insert_with(insert_column),
                _ => insert_column(),
            };
            arguments.push(Arc::new(Column::new(
                &format!("value_{index}"),
                request.group_by.len() + index,
            )));
        }
        let schema = Arc::new(Schema::new(fields));
        let mut aggregates = Vec::with_capacity(request.reducers.len());
        for (i, (reducer, expr)) in request.reducers.iter().zip(arguments).enumerate() {
            aggregates.push(Arc::new(
                AggregateExprBuilder::new(match_function(reducer.op), vec![expr])
                    .schema(schema.clone())
                    .alias(format!("result_{i}"))
                    .build()?,
            ));
        }
        Ok(Self {
            request,
            needs_value,
            reducer_columns,
            schema,
            aggregates,
            result_kinds,
        })
    }

    fn physical_plan(&self, source: Arc<dyn ExecutionPlan>) -> DfResult<AggregateExec> {
        let groups = PhysicalGroupBy::new_single(
            (0..self.request.group_by.len())
                .map(|i| {
                    (
                        Arc::new(Column::new(&format!("group_{i}"), i)) as Arc<dyn PhysicalExpr>,
                        format!("group_{i}"),
                    )
                })
                .collect(),
        );
        AggregateExec::try_new(
            AggregateMode::Single,
            groups,
            self.aggregates.clone(),
            vec![None; self.aggregates.len()],
            source,
            self.schema.clone(),
        )
    }

    fn execute(
        &self,
        source: Arc<dyn ExecutionPlan>,
        context: Arc<TaskContext>,
    ) -> DfResult<SendableRecordBatchStream> {
        self.physical_plan(source)?.execute(0, context)
    }

    fn extracted_batch(&self, rows: Vec<ExtractedReductionRow>) -> DfResult<RecordBatch> {
        let row_count = rows.len();
        let mut columns = (0..self.schema.fields().len())
            .map(|_| Vec::with_capacity(rows.len()))
            .collect::<Vec<_>>();
        for row in rows {
            for (column, value) in columns
                .iter_mut()
                .zip(row.group_values.into_iter().chain(row.reducer_values))
            {
                column.push(value);
            }
        }
        let arrays = columns
            .into_iter()
            .zip(self.schema.fields())
            .map(|(values, field)| values_to_array(values, field.data_type()))
            .collect::<DfResult<Vec<_>>>()?;
        RecordBatch::try_new_with_options(
            self.schema.clone(),
            arrays,
            &RecordBatchOptions::new().with_row_count(Some(row_count)),
        )
        .map_err(Into::into)
    }

    #[cfg(test)]
    fn batch(&self, rows: &[(Key, Bytes)]) -> DfResult<RecordBatch> {
        let rows = rows
            .iter()
            .map(|(key, value)| {
                extract_reduce_row(key, value, self)
                    .map_err(|error| DataFusionError::External(Box::new(error)))
            })
            .collect::<DfResult<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        self.extracted_batch(rows)
    }
}

fn match_function(op: RangeReduceOp) -> Arc<AggregateUDF> {
    match op {
        RangeReduceOp::CountAll | RangeReduceOp::CountField => count_udaf(),
        RangeReduceOp::SumField => sum_udaf(),
        RangeReduceOp::MinField => min_udaf(),
        RangeReduceOp::MaxField => max_udaf(),
    }
}

pub(crate) struct ReduceExecution {
    pub(crate) batches: SendableRecordBatchStream,
    pub(crate) extra: Arc<Mutex<QueryExtra>>,
    pub(crate) group_count: usize,
    pub(crate) result_kinds: Vec<ResultKind>,
}

pub(crate) fn execute_reduce<Q: Query>(
    query: Arc<Q>,
    start: Key,
    end: Key,
    request: RangeReduceRequest,
    context: Arc<TaskContext>,
) -> Result<ReduceExecution, RangeError> {
    let plan = Arc::new(ReducePlan::new(Arc::new(request))?);
    let extra = Arc::new(Mutex::new(QueryExtra::new()));
    let partition = ReducePartition {
        query,
        start,
        end,
        plan: plan.clone(),
        extra: extra.clone(),
    };
    let source = StreamingTableExec::try_new(
        plan.schema.clone(),
        vec![Arc::new(partition)],
        None,
        [],
        false,
        None,
    )?;
    let batches = plan.execute(Arc::new(source), context)?;
    Ok(ReduceExecution {
        batches,
        extra,
        group_count: plan.request.group_by.len(),
        result_kinds: plan.result_kinds.clone(),
    })
}

struct ReducePartition<Q: Query> {
    query: Arc<Q>,
    start: Key,
    end: Key,
    plan: Arc<ReducePlan>,
    extra: Arc<Mutex<QueryExtra>>,
}

impl<Q: Query> fmt::Debug for ReducePartition<Q> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReducePartition").finish_non_exhaustive()
    }
}

struct InputState<Q: Query> {
    query: Arc<Q>,
    start: Key,
    end: Key,
    plan: Arc<ReducePlan>,
    extra: Arc<Mutex<QueryExtra>>,
    scan: Option<Q::RangeScan>,
    pending: VecDeque<(Key, Bytes)>,
    extracted: Option<ExtractedReductionRow>,
    batch_bytes: usize,
}

impl<Q: Query> PartitionStream for ReducePartition<Q> {
    fn schema(&self) -> &SchemaRef {
        &self.plan.schema
    }

    fn execute(&self, context: Arc<TaskContext>) -> SendableRecordBatchStream {
        let state = InputState {
            query: self.query.clone(),
            start: self.start.clone(),
            end: self.end.clone(),
            plan: self.plan.clone(),
            extra: self.extra.clone(),
            scan: None,
            pending: VecDeque::new(),
            extracted: None,
            batch_bytes: match context.memory_pool().memory_limit() {
                MemoryLimit::Finite(limit) => (limit / 8).clamp(1, REDUCE_BATCH_BYTES),
                MemoryLimit::Infinite => REDUCE_BATCH_BYTES,
                _ => REDUCE_BATCH_BYTES,
            },
        };
        let stream = futures::stream::try_unfold(state, |mut state| async move {
            if state.scan.is_none() {
                state.scan = Some(
                    state
                        .query
                        .range_scan(state.start.clone(), state.end.clone(), usize::MAX, true)
                        .await
                        .map_err(|e| DataFusionError::External(Box::new(RangeError::Backend(e))))?,
                );
            }
            if state.pending.is_empty() && state.extracted.is_none() {
                let batch = state
                    .scan
                    .as_mut()
                    .unwrap()
                    .next_batch(REDUCE_BATCH_ROWS)
                    .await
                    .map_err(|e| DataFusionError::External(Box::new(RangeError::Backend(e))))?;
                if !batch.extra.is_empty() || !batch.rows.is_empty() {
                    *state.extra.lock().unwrap() = batch.extra;
                }
                if batch.rows.is_empty() {
                    return Ok(None);
                }
                state.pending.extend(batch.rows);
            }
            // Input batches remain transient so their reservation cannot prevent the aggregate from spilling
            let mut rows = Vec::new();
            let mut bytes = 0usize;
            loop {
                let row = if let Some(row) = state.extracted.take() {
                    row
                } else {
                    let Some((key, value)) = state.pending.pop_front() else {
                        break;
                    };
                    let Some(row) = extract_reduce_row(&key, &value, &state.plan)
                        .map_err(|error| DataFusionError::External(Box::new(error)))?
                    else {
                        continue;
                    };
                    row
                };
                let row_bytes = row
                    .group_values
                    .iter()
                    .chain(&row.reducer_values)
                    .map(|value| reduced_size(value.as_ref()))
                    .sum::<usize>();
                if !rows.is_empty() && bytes.saturating_add(row_bytes) > state.batch_bytes {
                    state.extracted = Some(row);
                    break;
                }
                bytes = bytes.saturating_add(row_bytes);
                rows.push(row);
                if rows.len() == REDUCE_BATCH_ROWS {
                    break;
                }
            }
            let batch = state.plan.extracted_batch(rows)?;
            Ok(Some((batch, state)))
        });
        Box::pin(RecordBatchStreamAdapter::new(
            self.plan.schema.clone(),
            stream,
        ))
    }
}

pub(crate) fn decode_group(
    batch: &RecordBatch,
    row: usize,
    group_count: usize,
    result_kinds: &[ResultKind],
) -> DfResult<RangeReduceGroup> {
    let mut values = batch
        .columns()
        .iter()
        .map(|array| ScalarValue::try_from_array(array, row).and_then(scalar_to_reduced));
    let group_values = values
        .by_ref()
        .take(group_count)
        .collect::<DfResult<Vec<_>>>()?;
    let results = values
        .zip(result_kinds)
        .map(|(value, kind)| {
            let value = match (value?, kind) {
                (Some(KvReducedValue::Int64(count)), ResultKind::Count) => {
                    Some(KvReducedValue::UInt64(u64::try_from(count).map_err(
                        |_| DataFusionError::Internal("native Reduce count is negative".into()),
                    )?))
                }
                (Some(KvReducedValue::Int64(bits)), ResultKind::OrderedFloat) => Some(
                    KvReducedValue::Float64(f64::from_bits(float_order_bits(bits) as u64)),
                ),
                (value, _) => value,
            };
            Ok(RangeReduceResult { value })
        })
        .collect::<DfResult<Vec<_>>>()?;
    Ok(RangeReduceGroup {
        group_values,
        results,
    })
}

// This involution maps float bits to signed integers ordered by f64::total_cmp
fn float_order_bits(bits: i64) -> i64 {
    bits ^ ((bits >> 63) & i64::MAX)
}

fn expression_type(expr: &KvExpr) -> Result<DataType, RangeError> {
    let invalid = || RangeError::Reduce("unsupported Reduce expression types".into());
    match expr {
        KvExpr::Field(field) => Ok(match field {
            KvFieldRef::Key { kind, .. }
            | KvFieldRef::ZOrderKey { kind, .. }
            | KvFieldRef::Value { kind, .. } => field_type(*kind),
        }),
        KvExpr::Literal(value) => Ok(match value {
            KvReducedValue::Int64(_) => DataType::Int64,
            KvReducedValue::UInt64(_) => DataType::UInt64,
            KvReducedValue::Float64(_) => DataType::Float64,
            KvReducedValue::Boolean(_) => DataType::Boolean,
            KvReducedValue::Utf8(_) => DataType::Utf8,
            KvReducedValue::Date32(_) => DataType::Date32,
            KvReducedValue::Date64(_) => DataType::Date64,
            KvReducedValue::Timestamp(_) => DataType::Timestamp(TimeUnit::Microsecond, None),
            KvReducedValue::Decimal128(_) => DataType::Decimal128(38, 0),
            KvReducedValue::Decimal256(_) => DataType::Decimal256(76, 0),
            KvReducedValue::FixedSizeBinary(_) => DataType::Binary,
        }),
        KvExpr::Add(a, b) | KvExpr::Sub(a, b) | KvExpr::Mul(a, b) | KvExpr::Div(a, b) => {
            let a = expression_type(a)?;
            let b = expression_type(b)?;
            let numeric = matches!(
                (&a, &b),
                (DataType::Int64, DataType::Int64)
                    | (DataType::UInt64, DataType::UInt64)
                    | (
                        DataType::Float64,
                        DataType::Int64 | DataType::UInt64 | DataType::Float64
                    )
                    | (DataType::Int64 | DataType::UInt64, DataType::Float64)
            );
            if !numeric {
                return Err(invalid());
            }
            Ok(
                if matches!(expr, KvExpr::Div(..))
                    || a == DataType::Float64
                    || b == DataType::Float64
                {
                    DataType::Float64
                } else {
                    a
                },
            )
        }
        KvExpr::Lower(expr) => {
            if expression_type(expr)? == DataType::Utf8 {
                Ok(DataType::Utf8)
            } else {
                Err(invalid())
            }
        }
        KvExpr::DateTruncDay(expr) => match expression_type(expr)? {
            t @ (DataType::Date32
            | DataType::Date64
            | DataType::Timestamp(TimeUnit::Microsecond, _)) => Ok(t),
            _ => Err(invalid()),
        },
    }
}

fn field_type(kind: KvFieldKind) -> DataType {
    match kind {
        KvFieldKind::Int64 => DataType::Int64,
        KvFieldKind::UInt64 => DataType::UInt64,
        KvFieldKind::Float64 => DataType::Float64,
        KvFieldKind::Boolean => DataType::Boolean,
        KvFieldKind::Utf8 => DataType::Utf8,
        KvFieldKind::Date32 => DataType::Date32,
        KvFieldKind::Date64 => DataType::Date64,
        KvFieldKind::Timestamp => DataType::Timestamp(TimeUnit::Microsecond, None),
        // Store decimals carry raw words, so internal aggregation keeps an unscaled representation
        KvFieldKind::Decimal128 => DataType::Decimal128(38, 0),
        KvFieldKind::Decimal256 => DataType::Decimal256(76, 0),
        KvFieldKind::FixedSizeBinary(_) => DataType::Binary,
    }
}

fn reduced_size(value: Option<&KvReducedValue>) -> usize {
    std::mem::size_of::<Option<KvReducedValue>>()
        + match value {
            Some(KvReducedValue::Utf8(s)) => s.len(),
            Some(KvReducedValue::FixedSizeBinary(b)) => b.len(),
            _ => 0,
        }
}

fn values_to_array(
    values: Vec<Option<KvReducedValue>>,
    data_type: &DataType,
) -> DfResult<ArrayRef> {
    macro_rules! primitive {
        ($variant:ident, $array:ty) => {{
            let values = values
                .into_iter()
                .map(|v| match v {
                    Some(KvReducedValue::$variant(v)) => Ok(Some(v)),
                    None => Ok(None),
                    _ => Err(execution_error("Reduce expression type mismatch")),
                })
                .collect::<DfResult<Vec<_>>>()?;
            Arc::new(<$array>::from(values)) as ArrayRef
        }};
    }
    Ok(match data_type {
        DataType::Int64 => primitive!(Int64, Int64Array),
        DataType::UInt64 => primitive!(UInt64, UInt64Array),
        DataType::Float64 => primitive!(Float64, Float64Array),
        DataType::Boolean => primitive!(Boolean, BooleanArray),
        DataType::Date32 => primitive!(Date32, Date32Array),
        DataType::Date64 => primitive!(Date64, Date64Array),
        DataType::Timestamp(TimeUnit::Microsecond, _) => {
            primitive!(Timestamp, TimestampMicrosecondArray)
        }
        DataType::Utf8 => {
            let strings = values
                .into_iter()
                .map(|v| match v {
                    Some(KvReducedValue::Utf8(v)) => Ok(Some(v)),
                    None => Ok(None),
                    _ => Err(execution_error("Reduce expression type mismatch")),
                })
                .collect::<DfResult<Vec<_>>>()?;
            Arc::new(StringArray::from_iter(strings.iter().map(|v| v.as_deref())))
        }
        DataType::Binary => {
            let bytes = values
                .into_iter()
                .map(|v| match v {
                    Some(KvReducedValue::FixedSizeBinary(v)) => Ok(Some(v)),
                    None => Ok(None),
                    _ => Err(execution_error("Reduce expression type mismatch")),
                })
                .collect::<DfResult<Vec<_>>>()?;
            Arc::new(BinaryArray::from_iter(bytes.iter().map(|v| v.as_deref())))
        }
        DataType::Decimal128(..) => {
            let values = values
                .into_iter()
                .map(|v| match v {
                    Some(KvReducedValue::Decimal128(v)) => Ok(Some(v)),
                    None => Ok(None),
                    _ => Err(execution_error("Reduce expression type mismatch")),
                })
                .collect::<DfResult<Vec<_>>>()?;
            Arc::new(Decimal128Array::from(values).with_data_type(data_type.clone()))
        }
        DataType::Decimal256(..) => {
            let values = values
                .into_iter()
                .map(|v| match v {
                    Some(KvReducedValue::Decimal256(v)) => Ok(Some(i256::from_le_bytes(v))),
                    None => Ok(None),
                    _ => Err(execution_error("Reduce expression type mismatch")),
                })
                .collect::<DfResult<Vec<_>>>()?;
            Arc::new(Decimal256Array::from(values).with_data_type(data_type.clone()))
        }
        _ => return Err(execution_error("unsupported Reduce array type")),
    })
}

fn scalar_to_reduced(value: ScalarValue) -> DfResult<Option<KvReducedValue>> {
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(match value {
        ScalarValue::Int64(Some(v)) => KvReducedValue::Int64(v),
        ScalarValue::UInt64(Some(v)) => KvReducedValue::UInt64(v),
        ScalarValue::Float64(Some(v)) => KvReducedValue::Float64(v),
        ScalarValue::Boolean(Some(v)) => KvReducedValue::Boolean(v),
        ScalarValue::Utf8(Some(v))
        | ScalarValue::LargeUtf8(Some(v))
        | ScalarValue::Utf8View(Some(v)) => KvReducedValue::Utf8(v),
        ScalarValue::Date32(Some(v)) => KvReducedValue::Date32(v),
        ScalarValue::Date64(Some(v)) => KvReducedValue::Date64(v),
        ScalarValue::TimestampMicrosecond(Some(v), _) => KvReducedValue::Timestamp(v),
        ScalarValue::Decimal128(Some(v), _, _) => KvReducedValue::Decimal128(v),
        ScalarValue::Decimal256(Some(v), _, _) => KvReducedValue::Decimal256(v.to_le_bytes()),
        ScalarValue::Binary(Some(v))
        | ScalarValue::BinaryView(Some(v))
        | ScalarValue::LargeBinary(Some(v))
        | ScalarValue::FixedSizeBinary(_, Some(v)) => KvReducedValue::FixedSizeBinary(v.into()),
        _ => return Err(execution_error("unsupported native Reduce result type")),
    }))
}

fn validate_reduce_request(request: &RangeReduceRequest) -> Result<(), RangeError> {
    if request.reducers.is_empty() && request.group_by.is_empty() {
        return Err(RangeError::Reduce(
            "range reduction request requires at least one reducer or group-by field".to_string(),
        ));
    }
    for reducer in &request.reducers {
        match reducer.op {
            RangeReduceOp::CountAll => {
                if reducer.expr.is_some() {
                    return Err(RangeError::Reduce(
                        "count_all reducer must not specify an expression".to_string(),
                    ));
                }
            }
            RangeReduceOp::CountField
            | RangeReduceOp::SumField
            | RangeReduceOp::MinField
            | RangeReduceOp::MaxField => {
                if reducer.expr.is_none() {
                    return Err(RangeError::Reduce(
                        "expression reducer requires an expression".to_string(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn extract_reduce_row(
    key: &Key,
    value: &Bytes,
    plan: &ReducePlan,
) -> Result<Option<ExtractedReductionRow>, RangeError> {
    let request = &plan.request;
    let decoded = if plan.needs_value {
        Some(
            decode_stored_row(value.as_ref())
                .map_err(|error| RangeError::Reduce(error.to_string()))?,
        )
    } else {
        None
    };
    let archived = decoded.as_ref();

    if let Some(filter) = &request.filter {
        if !eval_predicate(key, archived, filter).map_err(RangeError::Reduce)? {
            return Ok(None);
        }
    }

    let mut group_values = Vec::with_capacity(request.group_by.len());
    for expr in &request.group_by {
        let extracted_value = eval_expr(key, archived, expr).map_err(RangeError::Reduce)?;
        group_values.push(extracted_value);
    }
    canonicalize_reduced_group_values(&mut group_values);

    let mut reducer_values = Vec::with_capacity(plan.reducer_columns.len());
    for column in &plan.reducer_columns {
        let extracted_value = eval_expr(key, archived, &column.expr).map_err(RangeError::Reduce)?;
        let extracted_value = match (extracted_value, column.ordered_float) {
            (Some(KvReducedValue::Float64(number)), true) => Some(KvReducedValue::Int64(
                float_order_bits(number.to_bits() as i64),
            )),
            (value, _) => value,
        };
        reducer_values.push(extracted_value);
    }

    Ok(Some(ExtractedReductionRow {
        group_values,
        reducer_values,
    }))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use commonware_codec::Encode as _;
    use exoware_sdk::keys::Key;
    use exoware_sdk::kv_codec::{
        KvExpr, KvFieldKind, KvFieldRef, KvPredicate, KvPredicateCheck, KvPredicateConstraint,
        KvReducedValue, StoredRow, StoredValue,
    };
    use exoware_sdk::{RangeReduceOp, RangeReduceRequest, RangeReducerSpec};

    use super::*;
    use exoware_sdk::RangeReduceResponse;
    use futures::StreamExt;

    #[derive(Debug)]
    struct FixturePartition {
        schema: SchemaRef,
        batches: Vec<RecordBatch>,
    }

    impl PartitionStream for FixturePartition {
        fn schema(&self) -> &SchemaRef {
            &self.schema
        }
        fn execute(&self, _: Arc<TaskContext>) -> SendableRecordBatchStream {
            Box::pin(RecordBatchStreamAdapter::new(
                self.schema.clone(),
                futures::stream::iter(self.batches.clone().into_iter().map(Ok)),
            ))
        }
    }

    fn make_row(key: &[u8], values: Vec<Option<StoredValue>>) -> (Key, Bytes) {
        let encoded = StoredRow { values }.encode();
        (Key::from(key.to_vec()), encoded)
    }

    fn reducer(op: RangeReduceOp, expr: Option<KvExpr>) -> RangeReducerSpec {
        RangeReducerSpec { op, expr }
    }

    fn int64_value_field(index: u16) -> KvExpr {
        KvExpr::Field(KvFieldRef::Value {
            index,
            kind: KvFieldKind::Int64,
            nullable: true,
        })
    }

    fn float64_value_field(index: u16) -> KvExpr {
        KvExpr::Field(KvFieldRef::Value {
            index,
            kind: KvFieldKind::Float64,
            nullable: true,
        })
    }

    fn utf8_value_field(index: u16) -> KvExpr {
        KvExpr::Field(KvFieldRef::Value {
            index,
            kind: KvFieldKind::Utf8,
            nullable: true,
        })
    }

    fn scalar_request(reducers: Vec<RangeReducerSpec>) -> RangeReduceRequest {
        RangeReduceRequest {
            reducers,
            group_by: Vec::new(),
            filter: None,
        }
    }

    fn result_u64(v: u64) -> Option<KvReducedValue> {
        Some(KvReducedValue::UInt64(v))
    }

    fn result_i64(v: i64) -> Option<KvReducedValue> {
        Some(KvReducedValue::Int64(v))
    }

    fn result_f64(v: f64) -> Option<KvReducedValue> {
        Some(KvReducedValue::Float64(v))
    }

    fn reduce(
        rows: &[(Key, Bytes)],
        request: &RangeReduceRequest,
    ) -> Result<RangeReduceResponse, RangeError> {
        futures::executor::block_on(async {
            let plan = ReducePlan::new(Arc::new(request.clone()))?;
            let batches = rows
                .chunks(REDUCE_BATCH_ROWS)
                .map(|rows| plan.batch(rows))
                .collect::<DfResult<Vec<_>>>()?;
            let partition = FixturePartition {
                schema: plan.schema.clone(),
                batches,
            };
            let source = StreamingTableExec::try_new(
                plan.schema.clone(),
                vec![Arc::new(partition)],
                None,
                [],
                false,
                None,
            )?;
            let mut stream = plan.execute(Arc::new(source), Arc::new(TaskContext::default()))?;
            let mut response = RangeReduceResponse {
                results: Vec::new(),
                groups: Vec::new(),
            };
            while let Some(batch) = stream.next().await {
                let batch = batch?;
                for row in 0..batch.num_rows() {
                    let group =
                        decode_group(&batch, row, request.group_by.len(), &plan.result_kinds)?;
                    if request.group_by.is_empty() {
                        response.results = group.results;
                    } else {
                        response.groups.push(group);
                    }
                }
            }
            response.groups.sort_by_key(|group| {
                exoware_sdk::kv_codec::encode_reduced_group_key(&group.group_values)
            });
            Ok(response)
        })
    }

    #[test]
    fn malformed_rows_and_expression_errors_fail_instead_of_skipping_rows() {
        let sum = reducer(RangeReduceOp::SumField, Some(int64_value_field(0)));
        let request = scalar_request(vec![reducer(RangeReduceOp::CountAll, None), sum]);
        let malformed = [(Key::from(b"a".to_vec()), Bytes::from_static(b"invalid row"))];
        assert!(reduce(&malformed, &request).is_err());
        let rows = [make_row(b"a", vec![Some(StoredValue::Int64(7))])];
        let divide_zero = KvExpr::Div(
            Box::new(int64_value_field(0)),
            Box::new(KvExpr::Literal(KvReducedValue::Int64(0))),
        );
        let mut request = scalar_request(vec![
            reducer(RangeReduceOp::CountAll, None),
            reducer(RangeReduceOp::SumField, Some(divide_zero.clone())),
        ]);
        assert!(reduce(&rows, &request).is_err());
        request.reducers.truncate(1);
        request.group_by = vec![divide_zero];
        assert!(reduce(&rows, &request).is_err());
        request.group_by.clear();
        request.filter = Some(KvPredicate {
            checks: vec![KvPredicateCheck {
                field: KvFieldRef::Value {
                    index: 2,
                    kind: KvFieldKind::Int64,
                    nullable: true,
                },
                constraint: KvPredicateConstraint::IsNotNull,
            }],
            contradiction: false,
        });
        assert!(reduce(&rows, &request).is_err());
    }

    #[test]
    fn fused_reducers_retain_rows_when_integer_arithmetic_wraps() {
        let rows = [
            make_row(b"a", vec![Some(StoredValue::Int64(i64::MAX))]),
            make_row(b"b", vec![Some(StoredValue::Int64(2))]),
        ];
        let request = scalar_request(vec![
            reducer(RangeReduceOp::CountAll, None),
            reducer(RangeReduceOp::SumField, Some(int64_value_field(0))),
            reducer(
                RangeReduceOp::SumField,
                Some(KvExpr::Add(
                    Box::new(int64_value_field(0)),
                    Box::new(KvExpr::Literal(KvReducedValue::Int64(1))),
                )),
            ),
        ]);
        let response = reduce(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_u64(2));
        assert_eq!(response.results[1].value, result_i64(i64::MIN + 1));
        assert_eq!(response.results[2].value, result_i64(i64::MIN + 3));
    }

    #[test]
    fn count_all_over_empty_rows() {
        let request = scalar_request(vec![reducer(RangeReduceOp::CountAll, None)]);
        let response = reduce(&[], &request).unwrap();
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].value, result_u64(0));
    }

    #[test]
    fn count_all_over_multiple_rows() {
        let rows = vec![
            make_row(b"a", vec![]),
            make_row(b"b", vec![]),
            make_row(b"c", vec![]),
        ];
        let request = scalar_request(vec![reducer(RangeReduceOp::CountAll, None)]);
        let response = reduce(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_u64(3));
    }

    #[test]
    fn count_field_skips_nulls() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Int64(1))]),
            make_row(b"b", vec![None]),
            make_row(b"c", vec![Some(StoredValue::Int64(3))]),
        ];
        let request = scalar_request(vec![reducer(
            RangeReduceOp::CountField,
            Some(int64_value_field(0)),
        )]);
        let response = reduce(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_u64(2));
    }

    #[test]
    fn sum_int64_values() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Int64(10))]),
            make_row(b"b", vec![Some(StoredValue::Int64(20))]),
            make_row(b"c", vec![Some(StoredValue::Int64(-5))]),
        ];
        let request = scalar_request(vec![reducer(
            RangeReduceOp::SumField,
            Some(int64_value_field(0)),
        )]);
        let response = reduce(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_i64(25));
    }

    #[test]
    fn sum_float64_values() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Float64(1.5))]),
            make_row(b"b", vec![Some(StoredValue::Float64(2.5))]),
        ];
        let request = scalar_request(vec![reducer(
            RangeReduceOp::SumField,
            Some(float64_value_field(0)),
        )]);
        let response = reduce(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_f64(4.0));
    }

    #[test]
    fn min_selects_smallest() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Int64(30))]),
            make_row(b"b", vec![Some(StoredValue::Int64(10))]),
            make_row(b"c", vec![Some(StoredValue::Int64(20))]),
        ];
        let request = scalar_request(vec![reducer(
            RangeReduceOp::MinField,
            Some(int64_value_field(0)),
        )]);
        let response = reduce(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_i64(10));
    }

    #[test]
    fn max_selects_largest() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Int64(30))]),
            make_row(b"b", vec![Some(StoredValue::Int64(10))]),
            make_row(b"c", vec![Some(StoredValue::Int64(50))]),
        ];
        let request = scalar_request(vec![reducer(
            RangeReduceOp::MaxField,
            Some(int64_value_field(0)),
        )]);
        let response = reduce(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_i64(50));
    }

    #[test]
    fn grouped_count() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Utf8("x".into()))]),
            make_row(b"b", vec![Some(StoredValue::Utf8("y".into()))]),
            make_row(b"c", vec![Some(StoredValue::Utf8("x".into()))]),
            make_row(b"d", vec![Some(StoredValue::Utf8("y".into()))]),
            make_row(b"e", vec![Some(StoredValue::Utf8("x".into()))]),
        ];
        let request = RangeReduceRequest {
            reducers: vec![reducer(RangeReduceOp::CountAll, None)],
            group_by: vec![utf8_value_field(0)],
            filter: None,
        };
        let response = reduce(&rows, &request).unwrap();
        assert!(response.results.is_empty());
        assert_eq!(response.groups.len(), 2);

        let mut counts: Vec<(Option<KvReducedValue>, Option<KvReducedValue>)> = response
            .groups
            .iter()
            .map(|g| (g.group_values[0].clone(), g.results[0].value.clone()))
            .collect();
        counts.sort_by(|a, b| {
            let a_str = match &a.0 {
                Some(KvReducedValue::Utf8(s)) => s.clone(),
                _ => String::new(),
            };
            let b_str = match &b.0 {
                Some(KvReducedValue::Utf8(s)) => s.clone(),
                _ => String::new(),
            };
            a_str.cmp(&b_str)
        });
        assert_eq!(
            counts,
            vec![
                (Some(KvReducedValue::Utf8("x".into())), result_u64(3),),
                (Some(KvReducedValue::Utf8("y".into())), result_u64(2),),
            ]
        );
    }

    #[test]
    fn validates_empty_request() {
        let request = RangeReduceRequest {
            reducers: Vec::new(),
            group_by: Vec::new(),
            filter: None,
        };
        let err = reduce(&[], &request).unwrap_err();
        assert!(
            err.to_string().contains("at least one reducer"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn count_all_rejects_expression() {
        let request = scalar_request(vec![reducer(
            RangeReduceOp::CountAll,
            Some(int64_value_field(0)),
        )]);
        let err = reduce(&[], &request).unwrap_err();
        assert!(
            err.to_string()
                .contains("count_all reducer must not specify an expression"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn expression_reducer_requires_expression() {
        for op in [
            RangeReduceOp::SumField,
            RangeReduceOp::MinField,
            RangeReduceOp::MaxField,
            RangeReduceOp::CountField,
        ] {
            let request = scalar_request(vec![reducer(op, None)]);
            let err = reduce(&[], &request).unwrap_err();
            assert!(
                err.to_string()
                    .contains("expression reducer requires an expression"),
                "op {op:?} should require an expression, got: {err}"
            );
        }
    }

    #[test]
    fn filter_excludes_rows() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Int64(10))]),
            make_row(b"b", vec![Some(StoredValue::Int64(20))]),
            make_row(b"c", vec![Some(StoredValue::Int64(30))]),
        ];
        let request = RangeReduceRequest {
            reducers: vec![reducer(RangeReduceOp::SumField, Some(int64_value_field(0)))],
            group_by: Vec::new(),
            filter: Some(KvPredicate {
                checks: vec![KvPredicateCheck {
                    field: KvFieldRef::Value {
                        index: 0,
                        kind: KvFieldKind::Int64,
                        nullable: false,
                    },
                    constraint: KvPredicateConstraint::IntRange {
                        min: Some(15),
                        max: None,
                    },
                }],
                contradiction: false,
            }),
        };
        let response = reduce(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_i64(50));
    }

    #[test]
    fn scalar_reducer_handles_multiple_specs() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Int64(10))]),
            make_row(b"b", vec![None]),
            make_row(b"c", vec![Some(StoredValue::Int64(30))]),
        ];
        let request = scalar_request(vec![
            reducer(RangeReduceOp::CountAll, None),
            reducer(RangeReduceOp::SumField, Some(int64_value_field(0))),
        ]);
        let response = reduce(&rows, &request).unwrap();
        assert_eq!(response.results.len(), 2);
        assert_eq!(response.results[0].value, result_u64(3));
        assert_eq!(response.results[1].value, result_i64(40));
    }

    #[test]
    fn scalar_reducer_handles_all_field_indexes() {
        let request = scalar_request(
            (0..=u16::MAX)
                .map(|index| reducer(RangeReduceOp::CountField, Some(int64_value_field(index))))
                .collect(),
        );
        let response = reduce(&[], &request).unwrap();
        assert_eq!(response.results.len(), usize::from(u16::MAX) + 1);
        assert!(response
            .results
            .iter()
            .all(|result| result.value == result_u64(0)));
        assert!(response.groups.is_empty());
    }

    #[test]
    fn grouped_reducer_sums_per_group() {
        let rows = vec![
            make_row(
                b"a",
                vec![
                    Some(StoredValue::Utf8("west".into())),
                    Some(StoredValue::Int64(10)),
                ],
            ),
            make_row(
                b"b",
                vec![
                    Some(StoredValue::Utf8("east".into())),
                    Some(StoredValue::Int64(20)),
                ],
            ),
            make_row(
                b"c",
                vec![
                    Some(StoredValue::Utf8("west".into())),
                    Some(StoredValue::Int64(30)),
                ],
            ),
        ];
        let request = RangeReduceRequest {
            reducers: vec![reducer(RangeReduceOp::SumField, Some(int64_value_field(1)))],
            group_by: vec![utf8_value_field(0)],
            filter: None,
        };
        let response = reduce(&rows, &request).unwrap();
        assert!(response.results.is_empty());
        assert_eq!(response.groups.len(), 2);

        let mut sums: Vec<(Option<KvReducedValue>, Option<KvReducedValue>)> = response
            .groups
            .iter()
            .map(|g| (g.group_values[0].clone(), g.results[0].value.clone()))
            .collect();
        sums.sort_by(|a, b| {
            let a_str = match &a.0 {
                Some(KvReducedValue::Utf8(s)) => s.clone(),
                _ => String::new(),
            };
            let b_str = match &b.0 {
                Some(KvReducedValue::Utf8(s)) => s.clone(),
                _ => String::new(),
            };
            a_str.cmp(&b_str)
        });
        assert_eq!(
            sums,
            vec![
                (Some(KvReducedValue::Utf8("east".into())), result_i64(20),),
                (Some(KvReducedValue::Utf8("west".into())), result_i64(40),),
            ]
        );
    }

    #[test]
    fn filtered_reducer_counts_matching_rows() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Int64(10))]),
            make_row(b"b", vec![Some(StoredValue::Int64(20))]),
            make_row(b"c", vec![Some(StoredValue::Int64(30))]),
        ];
        let request = RangeReduceRequest {
            reducers: vec![reducer(RangeReduceOp::CountAll, None)],
            group_by: Vec::new(),
            filter: Some(KvPredicate {
                checks: vec![KvPredicateCheck {
                    field: KvFieldRef::Value {
                        index: 0,
                        kind: KvFieldKind::Int64,
                        nullable: false,
                    },
                    constraint: KvPredicateConstraint::IntRange {
                        min: Some(20),
                        max: None,
                    },
                }],
                contradiction: false,
            }),
        };
        let response = reduce(&rows, &request).unwrap();
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].value, result_u64(2));
    }

    #[test]
    fn mixed_type_min_max_returns_error() {
        let request = scalar_request(vec![reducer(
            RangeReduceOp::MinField,
            Some(int64_value_field(0)),
        )]);
        let rows = [make_row(
            b"a",
            vec![Some(StoredValue::Utf8("hello".into()))],
        )];
        assert!(reduce(&rows, &request).is_err());
    }
    #[test]
    fn native_grouping_preserves_null_nan_payloads_and_signed_zero() {
        let nan_a = f64::from_bits(0x7ff8_0000_0000_0001);
        let nan_b = f64::from_bits(0x7ff8_0000_0000_0002);
        let values = [
            None,
            Some(-0.0),
            Some(0.0),
            Some(nan_a),
            Some(nan_a),
            Some(nan_b),
        ];
        let rows = values
            .into_iter()
            .enumerate()
            .map(|(i, value)| make_row(&i.to_be_bytes(), vec![value.map(StoredValue::Float64)]))
            .collect::<Vec<_>>();
        let request = RangeReduceRequest {
            reducers: vec![reducer(RangeReduceOp::CountAll, None)],
            group_by: vec![float64_value_field(0)],
            filter: None,
        };
        let response = reduce(&rows, &request).unwrap();
        assert_eq!(response.groups.len(), 4);
        let groups = response
            .groups
            .iter()
            .map(|group| {
                (
                    exoware_sdk::kv_codec::encode_reduced_group_key(&group.group_values),
                    group.results[0].value.clone(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        for (value, count) in [
            (None, 1),
            (Some(0.0), 2),
            (Some(nan_a), 2),
            (Some(nan_b), 1),
        ] {
            assert_eq!(
                groups[&exoware_sdk::kv_codec::encode_reduced_group_key(&[
                    value.map(KvReducedValue::Float64)
                ])],
                result_u64(count)
            );
        }
    }

    #[test]
    fn native_float_extrema_preserve_total_order() {
        let positive_nan = f64::from_bits(0x7ff8_0000_0000_0001);
        let negative_nan = f64::from_bits(0xfff8_0000_0000_0001);
        for values in [
            vec![f64::INFINITY],
            vec![f64::NEG_INFINITY],
            vec![positive_nan, 0.0],
            vec![negative_nan, f64::NEG_INFINITY],
            vec![0.0, -0.0],
            vec![-0.0, 0.0],
        ] {
            let rows = values
                .iter()
                .enumerate()
                .map(|(i, value)| {
                    make_row(&i.to_be_bytes(), vec![Some(StoredValue::Float64(*value))])
                })
                .collect::<Vec<_>>();
            let expected = [
                *values
                    .iter()
                    .min_by(|left, right| left.total_cmp(right))
                    .unwrap(),
                *values
                    .iter()
                    .max_by(|left, right| left.total_cmp(right))
                    .unwrap(),
            ];
            for grouped in [false, true] {
                let request = RangeReduceRequest {
                    reducers: vec![
                        reducer(RangeReduceOp::MinField, Some(float64_value_field(0))),
                        reducer(RangeReduceOp::MaxField, Some(float64_value_field(0))),
                        reducer(RangeReduceOp::CountField, Some(float64_value_field(0))),
                    ],
                    group_by: if grouped {
                        vec![KvExpr::Literal(KvReducedValue::Int64(0))]
                    } else {
                        Vec::new()
                    },
                    filter: None,
                };
                let response = reduce(&rows, &request).unwrap();
                let results = if grouped {
                    &response.groups[0].results
                } else {
                    &response.results
                };
                assert_eq!(results[2].value, result_u64(values.len() as u64));
                for (result, expected) in results.iter().zip(expected) {
                    let Some(KvReducedValue::Float64(actual)) = result.value else {
                        panic!("float result");
                    };
                    assert_eq!(
                        actual.to_bits(),
                        expected.to_bits(),
                        "grouped={grouped}, inputs={values:?}",
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn native_spill_preserves_full_width_decimal_states_and_repeated_groups() {
        use datafusion::execution::context::SessionConfig;
        use datafusion::execution::memory_pool::FairSpillPool;
        use datafusion::execution::runtime_env::RuntimeEnvBuilder;
        let groups = 4096usize;
        let field = |index, kind| {
            KvExpr::Field(KvFieldRef::Value {
                index,
                kind,
                nullable: true,
            })
        };
        let decimal128 = field(1, KvFieldKind::Decimal128);
        let decimal256 = field(2, KvFieldKind::Decimal256);
        let float = float64_value_field(3);
        let request = RangeReduceRequest {
            reducers: vec![
                reducer(RangeReduceOp::CountAll, None),
                reducer(RangeReduceOp::SumField, Some(decimal128.clone())),
                reducer(RangeReduceOp::SumField, Some(decimal256.clone())),
                reducer(RangeReduceOp::MinField, Some(decimal128)),
                reducer(RangeReduceOp::MaxField, Some(decimal256)),
                reducer(RangeReduceOp::MinField, Some(float.clone())),
                reducer(RangeReduceOp::MaxField, Some(float)),
            ],
            group_by: vec![utf8_value_field(0)],
            filter: None,
        };
        let mut maximum256 = [255; 32];
        maximum256[31] = 127;
        let mut one256 = [0; 32];
        one256[0] = 1;
        let mut minimum256 = [0; 32];
        minimum256[31] = 128;
        let rows = (0..2)
            .flat_map(|pass| {
                (0..groups).map(move |group| {
                    make_row(
                        &(pass * groups + group).to_be_bytes(),
                        vec![
                            Some(StoredValue::Utf8(format!("{group:08}-{}", "x".repeat(512)))),
                            (group != 0).then(|| {
                                StoredValue::Bytes(
                                    if pass == 0 { i128::MAX } else { 1 }.to_le_bytes().to_vec(),
                                )
                            }),
                            (group != 0).then(|| {
                                StoredValue::Bytes(
                                    if pass == 0 { maximum256 } else { one256 }.to_vec(),
                                )
                            }),
                            (group != 0).then(|| {
                                StoredValue::Float64(if pass == 0 {
                                    f64::from_bits(0x7ff8_0000_0000_0001)
                                } else {
                                    0.0
                                })
                            }),
                        ],
                    )
                })
            })
            .collect::<Vec<_>>();
        let plan = ReducePlan::new(Arc::new(request)).unwrap();
        let batches = rows
            .chunks(128)
            .map(|rows| plan.batch(rows).unwrap())
            .collect();
        let source = StreamingTableExec::try_new(
            plan.schema.clone(),
            vec![Arc::new(FixturePartition {
                schema: plan.schema.clone(),
                batches,
            })],
            None,
            [],
            false,
            None,
        )
        .unwrap();
        let runtime = RuntimeEnvBuilder::new()
            .with_memory_pool(Arc::new(FairSpillPool::new(512 * 1024)))
            .build_arc()
            .unwrap();
        let context = Arc::new(
            TaskContext::default()
                .with_runtime(runtime.clone())
                .with_session_config(SessionConfig::new().with_batch_size(128)),
        );
        let aggregate = plan.physical_plan(Arc::new(source)).unwrap();
        let mut output = aggregate.execute(0, context).unwrap();
        let mut seen = std::collections::BTreeSet::new();
        while let Some(batch) = output.next().await {
            let batch = batch.unwrap();
            assert!(batch.num_rows() <= 128);
            for row in 0..batch.num_rows() {
                let group = decode_group(&batch, row, 1, &plan.result_kinds).unwrap();
                let Some(KvReducedValue::Utf8(key)) = &group.group_values[0] else {
                    panic!("missing group key");
                };
                assert!(seen.insert(key.clone()), "each group must be emitted once");
                assert_eq!(group.results[0].value, result_u64(2));
                if key.starts_with("00000000-") {
                    assert!(group.results[1..].iter().all(|value| value.value.is_none()));
                } else {
                    assert_eq!(
                        group.results[1].value,
                        Some(KvReducedValue::Decimal128(i128::MIN))
                    );
                    assert_eq!(
                        group.results[2].value,
                        Some(KvReducedValue::Decimal256(minimum256))
                    );
                    assert_eq!(group.results[3].value, Some(KvReducedValue::Decimal128(1)));
                    assert_eq!(
                        group.results[4].value,
                        Some(KvReducedValue::Decimal256(maximum256))
                    );
                    for (result, expected) in group.results[5..]
                        .iter()
                        .zip([0.0_f64.to_bits(), 0x7ff8_0000_0000_0001])
                    {
                        let Some(KvReducedValue::Float64(value)) = result.value else {
                            panic!("float result");
                        };
                        assert_eq!(value.to_bits(), expected);
                    }
                }
            }
        }
        assert_eq!(seen.len(), groups);
        assert!(aggregate.metrics().unwrap().spill_count().unwrap_or(0) > 0);
        drop(output);
        assert_eq!(runtime.memory_pool.reserved(), 0);
    }
}
