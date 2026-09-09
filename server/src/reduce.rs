//! Native worker aggregation over evaluated Store expressions.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use datafusion::arrow::array::{
    ArrayRef, BinaryArray, BooleanArray, BooleanBuilder, Date32Array, Date64Array, Decimal128Array,
    Decimal256Array, Float64Array, Int64Array, StringArray, TimestampMicrosecondArray, UInt64Array,
};
use datafusion::arrow::datatypes::{i256, DataType, Field, Schema, SchemaRef, TimeUnit};
use datafusion::arrow::record_batch::{RecordBatch, RecordBatchOptions};
use datafusion::common::{DFSchema, DataFusionError, Result as DfResult, ScalarValue};
use datafusion::execution::context::TaskContext;
use datafusion::execution::memory_pool::MemoryLimit;
use datafusion::functions_aggregate::{
    count::count_udaf,
    min_max::{max_udaf, min_udaf},
    sum::sum_udaf,
};
use datafusion::logical_expr::binary::binary_numeric_coercion;
use datafusion::logical_expr::execution_props::ExecutionProps;
use datafusion::logical_expr::expr::Cast;
use datafusion::logical_expr::physical_planning_context::PhysicalPlanningContext;
use datafusion::logical_expr::{col, lit, AggregateUDF, Expr};
use datafusion::optimizer::simplify_expressions::{ExprSimplifier, SimplifyContext};
use datafusion::physical_expr::aggregate::{AggregateExprBuilder, AggregateFunctionExpr};
use datafusion::physical_expr::expressions::{BinaryExpr, CastExpr, Column, Literal};
use datafusion::physical_expr::{create_physical_expr, PhysicalExpr};
use datafusion::physical_plan::aggregates::{AggregateExec, AggregateMode, PhysicalGroupBy};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::streaming::{PartitionStream, StreamingTableExec};
use datafusion::physical_plan::{ExecutionPlan, SendableRecordBatchStream};
use exoware_sdk::keys::Key;
use exoware_sdk::kv_codec::{
    decode_stored_row, eval_predicate, extract_field, predicate_needs_value, KvExpr, KvFieldKind,
    KvFieldRef, KvPredicate, KvReducedValue,
};
use exoware_sdk::proto::to_proto_reduced_value;
use exoware_sdk::{RangeReduceOp, RangeReduceRequest};
use futures::StreamExt;

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

struct ExtractedReductionRow {
    values: Vec<Option<KvReducedValue>>,
    masks: Vec<bool>,
}

#[derive(Debug)]
struct ReducePlan {
    request: Arc<RangeReduceRequest>,
    needs_value: bool,
    fields: Vec<KvFieldRef>,
    field_copies: Vec<usize>,
    literal_bytes: usize,
    groups: PhysicalGroupBy,
    filter_predicates: Vec<KvPredicate>,
    filters: Vec<Option<Arc<dyn PhysicalExpr>>>,
    schema: SchemaRef,
    aggregates: Vec<Arc<AggregateFunctionExpr>>,
    result_kinds: Vec<ResultKind>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ResultKind {
    Value,
    Count,
}

impl ReducePlan {
    fn new(request: Arc<RangeReduceRequest>, context: &TaskContext) -> Result<Self, RangeError> {
        validate_reduce_request(&request)?;
        let mut fields = Vec::new();
        let mut columns = HashMap::new();
        let group_exprs = request
            .group_by
            .iter()
            .map(|expr| lower_expr(expr, &mut fields, &mut columns))
            .collect::<Vec<_>>();
        let count_all_expr = KvExpr::Literal(KvReducedValue::Boolean(true));
        let arguments = request
            .reducers
            .iter()
            .map(|reducer| {
                lower_expr(
                    reducer.expr.as_ref().unwrap_or(&count_all_expr),
                    &mut fields,
                    &mut columns,
                )
            })
            .collect::<Vec<_>>();
        // Native columns share the input array; only computed expressions
        // need an additional materialization allowance.
        let mut field_copies = vec![0; fields.len()];
        let literal_bytes = request
            .group_by
            .iter()
            .chain(
                request
                    .reducers
                    .iter()
                    .map(|reducer| reducer.expr.as_ref().unwrap_or(&count_all_expr)),
            )
            .filter(|expr| !matches!(expr, KvExpr::Field(_)))
            .map(|expr| materialization_bytes(expr, &columns, &mut field_copies, 1))
            .fold(0usize, usize::saturating_add);
        let needs_value = fields
            .iter()
            .any(|field| matches!(field, KvFieldRef::Value { .. }))
            || request.filter.as_ref().is_some_and(predicate_needs_value)
            || request
                .reducers
                .iter()
                .any(|reducer| reducer.filter.as_ref().is_some_and(predicate_needs_value));
        let mut input_fields = fields
            .iter()
            .enumerate()
            .map(|(index, field)| {
                let (kind, nullable) = match field {
                    KvFieldRef::Key { kind, .. } | KvFieldRef::ZOrderKey { kind, .. } => {
                        (*kind, false)
                    }
                    KvFieldRef::Value { kind, nullable, .. } => (*kind, *nullable),
                };
                Field::new(format!("field_{index}"), field_type(kind), nullable)
            })
            .collect::<Vec<_>>();
        let mut filter_predicates = Vec::new();
        let filters = request
            .reducers
            .iter()
            .map(|reducer| {
                reducer.filter.as_ref().map(|predicate| {
                    let index = input_fields.len();
                    let name = format!("filter_{index}");
                    input_fields.push(Field::new(&name, DataType::Boolean, false));
                    filter_predicates.push(predicate.clone());
                    Arc::new(Column::new(&name, index)) as Arc<dyn PhysicalExpr>
                })
            })
            .collect();
        let schema = Arc::new(Schema::new(input_fields));
        let mut native_context = None;
        let mut compiled = HashMap::<Expr, Arc<dyn PhysicalExpr>>::new();
        let mut compile =
            |expr: Expr, original: Option<&KvExpr>| -> DfResult<Arc<dyn PhysicalExpr>> {
                // Requests can name all 65,536 stored fields. Use their assigned indexes
                // because native logical name lookup scans the schema.
                if let Some(KvExpr::Field(field)) = original {
                    let index = columns[field];
                    return Ok(Arc::new(Column::new(schema.field(index).name(), index)));
                }
                if let Some(physical) = compiled.get(&expr) {
                    return Ok(physical.clone());
                }
                let physical = match compile_numeric_expr(&expr, &schema)? {
                    Some((physical, data_type)) if matches!(&expr, Expr::BinaryExpr(_)) => {
                        // The native numeric type is fixed for this input schema.
                        // Retain its field for aggregate schema queries; native casts
                        // share arrays whose type already matches the target field.
                        let field =
                            Arc::new(Field::new("value", data_type, physical.nullable(&schema)?));
                        Arc::new(CastExpr::new_with_target_field(physical, field, None))
                            as Arc<dyn PhysicalExpr>
                    }
                    Some((physical, _)) => physical,
                    None => {
                        if native_context.is_none() {
                            let df_schema = Arc::new(DFSchema::try_from(schema.as_ref().clone())?);
                            let options = context.session_config().options().clone();
                            let simplifier = ExprSimplifier::new(
                                SimplifyContext::builder()
                                    .with_schema(df_schema.clone())
                                    .with_config_options(options.clone())
                                    .build(),
                            );
                            let mut props = ExecutionProps::new();
                            props.mark_start_execution(options);
                            native_context = Some((df_schema, simplifier, props));
                        }
                        let (df_schema, simplifier, props) = native_context.as_ref().unwrap();
                        let coerced = simplifier.coerce(expr.clone(), df_schema)?;
                        create_physical_expr(
                            &coerced,
                            df_schema,
                            props,
                            &PhysicalPlanningContext::default(),
                        )?
                    }
                };
                compiled.insert(expr, physical.clone());
                Ok(physical)
            };
        let groups = PhysicalGroupBy::new_single(
            group_exprs
                .into_iter()
                .zip(&request.group_by)
                .enumerate()
                .map(|(index, (expr, original))| {
                    Ok((compile(expr, Some(original))?, format!("group_{index}")))
                })
                .collect::<DfResult<Vec<_>>>()?,
        );
        let mut result_kinds = Vec::with_capacity(request.reducers.len());
        let mut aggregates = Vec::with_capacity(request.reducers.len());
        for (index, (reducer, expr)) in request.reducers.iter().zip(arguments).enumerate() {
            result_kinds.push(match reducer.op {
                RangeReduceOp::CountAll | RangeReduceOp::CountField => ResultKind::Count,
                _ => ResultKind::Value,
            });
            aggregates.push(Arc::new(
                AggregateExprBuilder::new(
                    match_function(reducer.op),
                    vec![compile(expr, reducer.expr.as_ref())?],
                )
                .schema(schema.clone())
                .alias(format!("result_{index}"))
                .build()?,
            ));
        }
        Ok(Self {
            request,
            needs_value,
            fields,
            field_copies,
            literal_bytes,
            groups,
            filter_predicates,
            filters,
            schema,
            aggregates,
            result_kinds,
        })
    }

    fn physical_plan(&self, source: Arc<dyn ExecutionPlan>) -> DfResult<AggregateExec> {
        AggregateExec::try_new(
            AggregateMode::Single,
            self.groups.clone(),
            self.aggregates.clone(),
            self.filters.clone(),
            source,
            self.schema.clone(),
        )
    }

    fn execute(
        &self,
        source: Arc<dyn ExecutionPlan>,
        context: Arc<TaskContext>,
    ) -> DfResult<SendableRecordBatchStream> {
        let stream = self.physical_plan(source)?.execute(0, context)?;
        let schema = stream.schema();

        // Native temporal kernels can panic on extreme timestamps. Terminate the
        // request after a panic so operator state is never polled again.
        let stream = AssertUnwindSafe(stream).catch_unwind().map(|result| {
            result.unwrap_or_else(|_| {
                Err(DataFusionError::Internal(
                    "native Reduce execution panicked".into(),
                ))
            })
        });
        Ok(Box::pin(RecordBatchStreamAdapter::new(schema, stream)))
    }

    fn extracted_batch(&self, rows: Vec<ExtractedReductionRow>) -> DfResult<RecordBatch> {
        let row_count = rows.len();
        let mut columns = (0..self.fields.len())
            .map(|_| Vec::with_capacity(row_count))
            .collect::<Vec<_>>();
        let mut masks = self
            .filter_predicates
            .iter()
            .map(|_| BooleanBuilder::with_capacity(row_count))
            .collect::<Vec<_>>();
        for row in rows {
            for (column, value) in columns.iter_mut().zip(row.values) {
                column.push(value);
            }
            for (mask, value) in masks.iter_mut().zip(row.masks) {
                mask.append_value(value);
            }
        }
        let mut arrays = columns
            .into_iter()
            .zip(self.schema.fields())
            .map(|(values, field)| values_to_array(values, field.data_type()))
            .collect::<DfResult<Vec<_>>>()?;
        arrays.extend(
            masks
                .into_iter()
                .map(|mut mask| Arc::new(mask.finish()) as ArrayRef),
        );
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
    let plan = Arc::new(ReducePlan::new(Arc::new(request), &context)?);
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
                    .values
                    .iter()
                    .zip(&state.plan.field_copies)
                    .map(|(value, copies)| {
                        reduced_size(value.as_ref()).saturating_mul(copies.saturating_add(1))
                    })
                    .fold(state.plan.literal_bytes, usize::saturating_add)
                    .saturating_add(row.masks.len());
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
) -> DfResult<exoware_sdk::query::RangeReduceGroup> {
    let mut values = batch
        .columns()
        .iter()
        .map(|array| ScalarValue::try_from_array(array, row).and_then(scalar_to_reduced));
    let mut group_values = Vec::with_capacity(group_count);
    let mut group_values_present = Vec::with_capacity(group_count);
    for value in values.by_ref().take(group_count) {
        let value = value?;
        group_values_present.push(value.is_some());
        if let Some(value) = value {
            group_values.push(to_proto_reduced_value(value));
        }
    }
    let results = values
        .zip(result_kinds)
        .map(|(value, kind)| {
            let value = match (value?, kind) {
                (Some(KvReducedValue::Int64(count)), ResultKind::Count) => {
                    Some(KvReducedValue::UInt64(u64::try_from(count).map_err(
                        |_| DataFusionError::Internal("native Reduce count is negative".into()),
                    )?))
                }
                (value, _) => value,
            };
            Ok(exoware_sdk::query::RangeReduceResult {
                value: value.map(to_proto_reduced_value).into(),
                ..Default::default()
            })
        })
        .collect::<DfResult<Vec<_>>>()?;
    Ok(exoware_sdk::query::RangeReduceGroup {
        group_values,
        group_values_present,
        results,
        ..Default::default()
    })
}

// Primitive arithmetic has a uniform native numeric type. Carry it through the
// compilation traversal because BinaryExpr::data_type probes Arrow kernels with
// allocated empty arrays. Decimal and temporal rewrites use the full analyzer.
fn compile_numeric_expr(
    expr: &Expr,
    schema: &Schema,
) -> DfResult<Option<(Arc<dyn PhysicalExpr>, DataType)>> {
    let (physical, data_type): (Arc<dyn PhysicalExpr>, DataType) = match expr {
        Expr::Column(column) => {
            // Store lowering generates unique, unqualified field names.
            let index = schema.index_of(&column.name)?;
            (
                Arc::new(Column::new(&column.name, index)),
                schema.field(index).data_type().clone(),
            )
        }
        Expr::Literal(value, metadata) => (
            Arc::new(Literal::new_with_metadata(value.clone(), metadata.clone())),
            value.data_type(),
        ),
        Expr::Cast(cast) if cast.field.data_type() == &DataType::Float64 => {
            let Some((child, data_type)) = compile_numeric_expr(&cast.expr, schema)? else {
                return Ok(None);
            };
            if !matches!(
                data_type,
                DataType::Int64 | DataType::UInt64 | DataType::Float64
            ) {
                return Ok(None);
            }
            (
                Arc::new(CastExpr::new_with_target_field(
                    child,
                    cast.field.clone(),
                    None,
                )),
                DataType::Float64,
            )
        }
        Expr::BinaryExpr(binary) => {
            let Some((mut left, left_type)) = compile_numeric_expr(&binary.left, schema)? else {
                return Ok(None);
            };
            let Some((mut right, right_type)) = compile_numeric_expr(&binary.right, schema)? else {
                return Ok(None);
            };
            if !matches!(
                left_type,
                DataType::Int64 | DataType::UInt64 | DataType::Float64
            ) || !matches!(
                right_type,
                DataType::Int64 | DataType::UInt64 | DataType::Float64
            ) {
                return Ok(None);
            }
            let Some(data_type) = binary_numeric_coercion(&left_type, &right_type) else {
                return Ok(None);
            };
            if !matches!(
                data_type,
                DataType::Int64 | DataType::UInt64 | DataType::Float64
            ) {
                return Ok(None);
            }
            if left_type != data_type {
                left = Arc::new(CastExpr::new(left, data_type.clone(), None));
            }
            if right_type != data_type {
                right = Arc::new(CastExpr::new(right, data_type.clone(), None));
            }
            (Arc::new(BinaryExpr::new(left, binary.op, right)), data_type)
        }
        _ => return Ok(None),
    };
    Ok(Some((physical, data_type)))
}

// Aggregate arguments may broadcast literals or allocate one output per expression.
// Charge each occurrence even when its compiled physical expression is shared.
fn materialization_bytes(
    expr: &KvExpr,
    columns: &HashMap<KvFieldRef, usize>,
    field_copies: &mut [usize],
    copies: usize,
) -> usize {
    match expr {
        KvExpr::Field(field) => {
            let count = &mut field_copies[columns[field]];
            *count = count.saturating_add(copies);
            0
        }
        KvExpr::Literal(value) => reduced_size(Some(value)).saturating_mul(copies),
        KvExpr::Add(left, right)
        | KvExpr::Sub(left, right)
        | KvExpr::Mul(left, right)
        | KvExpr::Div(left, right) => materialization_bytes(left, columns, field_copies, copies)
            .saturating_add(materialization_bytes(right, columns, field_copies, copies)),
        // A lowercase mapping contains at most three Unicode scalars, each at most
        // four UTF-8 bytes. This bounds expansion without evaluating guarded inputs.
        KvExpr::Lower(inner) => {
            materialization_bytes(inner, columns, field_copies, copies.saturating_mul(12))
        }
        KvExpr::DateTruncDay(inner) | KvExpr::CastFloat64(inner) => {
            materialization_bytes(inner, columns, field_copies, copies)
        }
    }
}

fn lower_expr(
    expr: &KvExpr,
    fields: &mut Vec<KvFieldRef>,
    columns: &mut HashMap<KvFieldRef, usize>,
) -> Expr {
    match expr {
        KvExpr::Field(field) => {
            let index = *columns.entry(field.clone()).or_insert_with(|| {
                let index = fields.len();
                fields.push(field.clone());
                index
            });
            col(format!("field_{index}"))
        }
        KvExpr::Literal(value) => lit(match value {
            KvReducedValue::Int64(v) => ScalarValue::Int64(Some(*v)),
            KvReducedValue::UInt64(v) => ScalarValue::UInt64(Some(*v)),
            KvReducedValue::Float64(v) => ScalarValue::Float64(Some(*v)),
            KvReducedValue::Boolean(v) => ScalarValue::Boolean(Some(*v)),
            KvReducedValue::Utf8(v) => ScalarValue::Utf8(Some(v.clone())),
            KvReducedValue::Date32(v) => ScalarValue::Date32(Some(*v)),
            KvReducedValue::Date64(v) => ScalarValue::Date64(Some(*v)),
            KvReducedValue::Timestamp(v) => ScalarValue::TimestampMicrosecond(Some(*v), None),
            KvReducedValue::Decimal128(v) => ScalarValue::Decimal128(Some(*v), 38, 0),
            KvReducedValue::Decimal256(v) => {
                ScalarValue::Decimal256(Some(i256::from_le_bytes(*v)), 76, 0)
            }
            KvReducedValue::FixedSizeBinary(v) => ScalarValue::Binary(Some(v.to_vec())),
        }),
        KvExpr::Add(a, b) => lower_expr(a, fields, columns) + lower_expr(b, fields, columns),
        KvExpr::Sub(a, b) => lower_expr(a, fields, columns) - lower_expr(b, fields, columns),
        KvExpr::Mul(a, b) => lower_expr(a, fields, columns) * lower_expr(b, fields, columns),
        KvExpr::Div(a, b) => lower_expr(a, fields, columns) / lower_expr(b, fields, columns),
        KvExpr::CastFloat64(expr) => Expr::Cast(Cast::new(
            Box::new(lower_expr(expr, fields, columns)),
            DataType::Float64,
        )),
        KvExpr::Lower(expr) => {
            datafusion::functions::string::lower().call(vec![lower_expr(expr, fields, columns)])
        }
        KvExpr::DateTruncDay(expr) => datafusion::functions::datetime::date_trunc()
            .call(vec![lit("day"), lower_expr(expr, fields, columns)]),
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
        value @ (ScalarValue::TimestampSecond(..)
        | ScalarValue::TimestampMillisecond(..)
        | ScalarValue::TimestampNanosecond(..)) => {
            return scalar_to_reduced(
                value.cast_to(&DataType::Timestamp(TimeUnit::Microsecond, None))?,
            );
        }
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

    let values = plan
        .fields
        .iter()
        .map(|field| extract_field(key, archived, field).map_err(RangeError::Reduce))
        .collect::<Result<Vec<_>, _>>()?;
    let masks = plan
        .filter_predicates
        .iter()
        .map(|predicate| eval_predicate(key, archived, predicate).map_err(RangeError::Reduce))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(ExtractedReductionRow { values, masks }))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use commonware_codec::Encode as _;
    use datafusion::arrow::compute::{
        concat_batches, lexsort_to_indices, take_record_batch, SortColumn,
    };
    use exoware_sdk::keys::Key;
    use exoware_sdk::kv_codec::{
        KvExpr, KvFieldKind, KvFieldRef, KvPredicate, KvPredicateCheck, KvPredicateConstraint,
        KvReducedValue, StoredRow, StoredValue,
    };
    use exoware_sdk::{RangeReduceGroup, RangeReduceOp, RangeReduceRequest, RangeReducerSpec};

    use super::*;
    use exoware_sdk::RangeReduceResponse;
    use futures::{StreamExt, TryStreamExt};

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
        RangeReducerSpec {
            op,
            expr,
            filter: None,
        }
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

    fn decode_group(
        batch: &RecordBatch,
        row: usize,
        group_count: usize,
        result_kinds: &[ResultKind],
    ) -> DfResult<RangeReduceGroup> {
        let response = exoware_sdk::query::ReduceResponse {
            groups: vec![super::decode_group(batch, row, group_count, result_kinds)?],
            ..Default::default()
        };
        let message = connectrpc::StreamMessage::from_message(&response);
        let mut response =
            exoware_sdk::to_domain_reduce_response(message.view()).map_err(execution_error)?;
        Ok(response.groups.remove(0))
    }

    fn reduce(
        rows: &[(Key, Bytes)],
        request: &RangeReduceRequest,
    ) -> Result<RangeReduceResponse, RangeError> {
        futures::executor::block_on(async {
            let plan = ReducePlan::new(Arc::new(request.clone()), &TaskContext::default())?;
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
            let stream = plan.execute(Arc::new(source), Arc::new(TaskContext::default()))?;
            let schema = stream.schema();
            let batches = stream.try_collect::<Vec<_>>().await?;
            let mut batch = concat_batches(&schema, &batches).map_err(DataFusionError::from)?;
            if !request.group_by.is_empty() {
                let columns = batch.columns()[..request.group_by.len()]
                    .iter()
                    .map(|values| SortColumn {
                        values: values.clone(),
                        options: None,
                    })
                    .collect::<Vec<_>>();
                let indices = lexsort_to_indices(&columns, None).map_err(DataFusionError::from)?;
                batch = take_record_batch(&batch, &indices).map_err(DataFusionError::from)?;
            }
            let mut response = RangeReduceResponse {
                results: Vec::new(),
                groups: Vec::new(),
            };
            for row in 0..batch.num_rows() {
                let group = decode_group(&batch, row, request.group_by.len(), &plan.result_kinds)?;
                if request.group_by.is_empty() {
                    response.results = group.results;
                } else {
                    response.groups.push(group);
                }
            }
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
    fn expressions_preserve_types_and_values() {
        use datafusion::prelude::SessionContext;

        let field = |index, kind| {
            KvExpr::Field(KvFieldRef::Value {
                index,
                kind,
                nullable: true,
            })
        };
        let i = field(0, KvFieldKind::Int64);
        let u = field(1, KvFieldKind::UInt64);
        let f = field(2, KvFieldKind::Float64);
        let text = field(3, KvFieldKind::Utf8);
        let timestamp = field(4, KvFieldKind::Timestamp);
        let date32 = field(5, KvFieldKind::Date32);
        let date64 = field(6, KvFieldKind::Date64);
        let cases = [
            (
                KvExpr::Add(
                    Box::new(i.clone()),
                    Box::new(KvExpr::Literal(KvReducedValue::Int64(2))),
                ),
                col("i") + lit(2_i64),
            ),
            (
                KvExpr::Sub(
                    Box::new(u.clone()),
                    Box::new(KvExpr::Literal(KvReducedValue::UInt64(9))),
                ),
                col("u") - lit(9_u64),
            ),
            (
                KvExpr::Mul(Box::new(i.clone()), Box::new(i.clone())),
                col("i") * col("i"),
            ),
            (
                KvExpr::Div(
                    Box::new(i.clone()),
                    Box::new(KvExpr::Literal(KvReducedValue::Int64(2))),
                ),
                col("i") / lit(2_i64),
            ),
            (
                KvExpr::Div(
                    Box::new(u.clone()),
                    Box::new(KvExpr::Literal(KvReducedValue::UInt64(2))),
                ),
                col("u") / lit(2_u64),
            ),
            (
                KvExpr::Div(Box::new(i.clone()), Box::new(f.clone())),
                col("i") / col("f"),
            ),
            (
                KvExpr::Lower(Box::new(text)),
                datafusion::functions::string::lower().call(vec![col("text")]),
            ),
            (
                KvExpr::DateTruncDay(Box::new(timestamp)),
                datafusion::functions::datetime::date_trunc()
                    .call(vec![lit("day"), col("timestamp")]),
            ),
            (
                KvExpr::DateTruncDay(Box::new(date32)),
                datafusion::functions::datetime::date_trunc().call(vec![lit("day"), col("date32")]),
            ),
            (
                KvExpr::DateTruncDay(Box::new(date64)),
                datafusion::functions::datetime::date_trunc().call(vec![lit("day"), col("date64")]),
            ),
            (
                KvExpr::Add(Box::new(i.clone()), Box::new(u.clone())),
                col("i") + col("u"),
            ),
            (
                KvExpr::Div(Box::new(u.clone()), Box::new(i.clone())),
                col("u") / col("i"),
            ),
            (
                KvExpr::Mul(Box::new(u.clone()), Box::new(f.clone())),
                col("u") * col("f"),
            ),
            (
                KvExpr::CastFloat64(Box::new(i.clone())),
                Expr::Cast(Cast::new(Box::new(col("i")), DataType::Float64)),
            ),
            (
                KvExpr::CastFloat64(Box::new(u.clone())),
                Expr::Cast(Cast::new(Box::new(col("u")), DataType::Float64)),
            ),
            (
                KvExpr::CastFloat64(Box::new(f.clone())),
                Expr::Cast(Cast::new(Box::new(col("f")), DataType::Float64)),
            ),
            (
                KvExpr::Sub(
                    Box::new(KvExpr::Mul(
                        Box::new(KvExpr::Add(
                            Box::new(i),
                            Box::new(KvExpr::Literal(KvReducedValue::Int64(10))),
                        )),
                        Box::new(KvExpr::Literal(KvReducedValue::Int64(2))),
                    )),
                    Box::new(KvExpr::Literal(KvReducedValue::Int64(5))),
                ),
                (col("i") + lit(10_i64)) * lit(2_i64) - lit(5_i64),
            ),
        ];
        let rows = [
            make_row(
                b"a",
                vec![
                    Some(StoredValue::Int64(7)),
                    Some(StoredValue::UInt64(7)),
                    Some(StoredValue::Float64(2.0)),
                    Some(StoredValue::Utf8("ΟΣ İ MIXED".into())),
                    Some(StoredValue::Int64(-1)),
                    Some(StoredValue::Int64(-1)),
                    Some(StoredValue::Int64(-1)),
                ],
            ),
            make_row(b"b", vec![None; 7]),
        ];
        let input = RecordBatch::try_from_iter([
            (
                "i",
                Arc::new(Int64Array::from(vec![Some(7), None])) as ArrayRef,
            ),
            (
                "u",
                Arc::new(UInt64Array::from(vec![Some(7), None])) as ArrayRef,
            ),
            (
                "f",
                Arc::new(Float64Array::from(vec![Some(2.0), None])) as ArrayRef,
            ),
            (
                "text",
                Arc::new(StringArray::from(vec![Some("ΟΣ İ MIXED"), None])) as ArrayRef,
            ),
            (
                "timestamp",
                Arc::new(TimestampMicrosecondArray::from(vec![Some(-1), None])) as ArrayRef,
            ),
            (
                "date32",
                Arc::new(Date32Array::from(vec![Some(-1), None])) as ArrayRef,
            ),
            (
                "date64",
                Arc::new(Date64Array::from(vec![Some(-1), None])) as ArrayRef,
            ),
        ])
        .unwrap();
        let request = scalar_request(
            cases
                .iter()
                .map(|(expr, _)| reducer(RangeReduceOp::MinField, Some(expr.clone())))
                .collect(),
        );
        let plan = ReducePlan::new(Arc::new(request.clone()), &TaskContext::default()).unwrap();
        assert_eq!(plan.fields.len(), 7);
        let response = reduce(&rows, &request).unwrap();
        let context = SessionContext::new();
        let schema = DFSchema::try_from(input.schema().as_ref().clone()).unwrap();
        for (index, (_, expr)) in cases.into_iter().enumerate() {
            let native = context.create_physical_expr(expr, &schema).unwrap();
            let actual_field = plan.aggregates[index].expressions()[0]
                .return_field(&plan.schema)
                .unwrap();
            let native_field = native.return_field(input.schema().as_ref()).unwrap();
            assert_eq!(actual_field.data_type(), native_field.data_type());
            assert_eq!(actual_field.is_nullable(), native_field.is_nullable());
            let values = native
                .evaluate(&input)
                .unwrap()
                .into_array(input.num_rows())
                .unwrap();
            assert_eq!(
                plan.aggregates[index].field().data_type(),
                &native.data_type(input.schema().as_ref()).unwrap()
            );
            let expected =
                scalar_to_reduced(ScalarValue::try_from_array(&values, 0).unwrap()).unwrap();
            assert_eq!(response.results[index].value, expected);
            assert!(values.is_null(1));
        }
        for result in &response.results[7..10] {
            assert_eq!(
                result.value,
                Some(KvReducedValue::Timestamp(-86_400_000_000))
            );
        }
        assert_eq!(response.results[3].value, result_i64(3));
        assert_eq!(response.results[4].value, result_u64(3));
    }

    #[test]
    fn literal_integer_arithmetic_wraps_on_overflow() {
        let cases = [
            (
                KvExpr::Add(
                    Box::new(KvExpr::Literal(KvReducedValue::Int64(i64::MAX))),
                    Box::new(KvExpr::Literal(KvReducedValue::Int64(1))),
                ),
                result_i64(i64::MIN),
            ),
            (
                KvExpr::Sub(
                    Box::new(KvExpr::Literal(KvReducedValue::UInt64(0))),
                    Box::new(KvExpr::Literal(KvReducedValue::UInt64(1))),
                ),
                result_u64(u64::MAX),
            ),
            (
                KvExpr::Mul(
                    Box::new(KvExpr::Literal(KvReducedValue::Int64(i64::MAX))),
                    Box::new(KvExpr::Literal(KvReducedValue::Int64(2))),
                ),
                result_i64(-2),
            ),
        ];
        for (expr, expected) in cases {
            let response = reduce(
                &[(Key::default(), Bytes::from_static(b"invalid row"))],
                &scalar_request(vec![reducer(RangeReduceOp::MinField, Some(expr))]),
            )
            .unwrap();
            assert_eq!(response.results[0].value, expected);
        }
    }

    #[test]
    fn float_division_accepts_signed_zero_and_nan() {
        for denominator in [-0.0_f64, 0.0] {
            for numerator in [0.0, 1.0] {
                let rows = [make_row(
                    b"a",
                    vec![
                        Some(StoredValue::Float64(numerator)),
                        Some(StoredValue::Float64(denominator)),
                    ],
                )];
                let expr = KvExpr::Div(
                    Box::new(float64_value_field(0)),
                    Box::new(float64_value_field(1)),
                );
                let response = reduce(
                    &rows,
                    &scalar_request(vec![reducer(RangeReduceOp::SumField, Some(expr))]),
                )
                .unwrap();
                let Some(KvReducedValue::Float64(actual)) = response.results[0].value else {
                    panic!("float result")
                };
                let expected = numerator / denominator;
                if expected.is_nan() {
                    assert!(actual.is_nan());
                } else {
                    assert_eq!(actual.to_bits(), expected.to_bits());
                }
            }
        }
    }

    #[test]
    fn arithmetic_evaluates_required_fields_and_nested_operands() {
        let expr = KvExpr::Add(
            Box::new(int64_value_field(0)),
            Box::new(KvExpr::Div(
                Box::new(int64_value_field(1)),
                Box::new(int64_value_field(2)),
            )),
        );
        let request = scalar_request(vec![reducer(RangeReduceOp::SumField, Some(expr))]);
        for values in [
            vec![None],
            vec![
                None,
                Some(StoredValue::Int64(1)),
                Some(StoredValue::Int64(0)),
            ],
        ] {
            assert!(reduce(&[make_row(b"a", values)], &request).is_err());
        }
    }

    #[test]
    fn key_only_expressions_share_fields_and_skip_payload_decoding() {
        let field = KvExpr::Field(KvFieldRef::Key {
            byte_offset: 0,
            kind: KvFieldKind::Int64,
        });
        let expr = KvExpr::Add(Box::new(field.clone()), Box::new(field));
        let request = RangeReduceRequest {
            group_by: vec![expr.clone()],
            reducers: vec![
                reducer(RangeReduceOp::SumField, Some(expr.clone())),
                reducer(RangeReduceOp::CountAll, None),
                reducer(
                    RangeReduceOp::SumField,
                    Some(KvExpr::CastFloat64(Box::new(expr))),
                ),
            ],
            filter: None,
        };
        let plan = ReducePlan::new(Arc::new(request.clone()), &TaskContext::default()).unwrap();
        assert_eq!(plan.fields.len(), 1);
        assert!(!plan.needs_value);
        let key = ((3_i64 as u64) ^ (1 << 63)).to_be_bytes().to_vec();
        let response = reduce(
            &[(Key::from(key), Bytes::from_static(b"not a stored row"))],
            &request,
        )
        .unwrap();
        assert_eq!(response.groups[0].group_values, vec![result_i64(6)]);
        assert_eq!(response.groups[0].results[0].value, result_i64(6));
        assert_eq!(response.groups[0].results[1].value, result_u64(1));
        assert_eq!(response.groups[0].results[2].value, result_f64(6.0));
    }

    #[tokio::test]
    async fn extreme_date_failure_terminates_only_its_stream() {
        use datafusion::prelude::SessionContext;

        let input = RecordBatch::try_from_iter([(
            "timestamp",
            Arc::new(TimestampMicrosecondArray::from(vec![i64::MIN])) as ArrayRef,
        )])
        .unwrap();
        let schema = DFSchema::try_from(input.schema().as_ref().clone()).unwrap();
        let native = SessionContext::new()
            .create_physical_expr(
                datafusion::functions::datetime::date_trunc()
                    .call(vec![lit("day"), col("timestamp")]),
                &schema,
            )
            .unwrap();
        let expected = std::panic::catch_unwind(AssertUnwindSafe(|| native.evaluate(&input)));
        let request = scalar_request(vec![reducer(
            RangeReduceOp::MinField,
            Some(KvExpr::DateTruncDay(Box::new(KvExpr::Field(
                KvFieldRef::Value {
                    index: 0,
                    kind: KvFieldKind::Timestamp,
                    nullable: true,
                },
            )))),
        )]);
        let context = Arc::new(TaskContext::default());
        let plan = ReducePlan::new(Arc::new(request), &context).unwrap();
        let batch = plan
            .batch(&[make_row(b"a", vec![Some(StoredValue::Int64(i64::MIN))])])
            .unwrap();
        let source = StreamingTableExec::try_new(
            plan.schema.clone(),
            vec![Arc::new(FixturePartition {
                schema: plan.schema.clone(),
                batches: vec![batch],
            })],
            None,
            [],
            false,
            None,
        )
        .unwrap();
        let mut stream = plan.execute(Arc::new(source), context).unwrap();
        let actual = stream.next().await.unwrap();
        match expected {
            Err(_) => assert!(
                matches!(actual, Err(DataFusionError::Internal(message)) if message == "native Reduce execution panicked")
            ),
            Ok(Err(_)) => assert!(actual.is_err()),
            Ok(Ok(value)) => {
                let values = value.into_array(1).unwrap();
                let expected =
                    scalar_to_reduced(ScalarValue::try_from_array(&values, 0).unwrap()).unwrap();
                assert_eq!(
                    decode_group(&actual.unwrap(), 0, 0, &plan.result_kinds)
                        .unwrap()
                        .results[0]
                        .value,
                    expected
                );
            }
        }
        assert!(stream.next().await.is_none());
        let good = scalar_request(vec![reducer(RangeReduceOp::CountAll, None)]);
        assert_eq!(
            reduce(&[make_row(b"b", vec![])], &good).unwrap().results[0].value,
            result_u64(1)
        );
    }

    #[test]
    fn float64_cast_rounds_integers_and_preserves_nulls() {
        use datafusion::prelude::SessionContext;

        let signed = [
            None,
            Some(i64::MIN),
            Some(-(1_i64 << 53) - 1),
            Some(0),
            Some((1_i64 << 53) + 1),
            Some(i64::MAX),
        ];
        let unsigned = [
            None,
            Some(0),
            Some((1_u64 << 53) - 1),
            Some(1_u64 << 53),
            Some((1_u64 << 53) + 1),
            Some(u64::MAX),
        ];
        let cases = [
            (
                KvFieldKind::Int64,
                signed.map(|value| value.map(StoredValue::Int64)).to_vec(),
                Arc::new(Int64Array::from(signed.to_vec())) as ArrayRef,
            ),
            (
                KvFieldKind::UInt64,
                unsigned
                    .map(|value| value.map(StoredValue::UInt64))
                    .to_vec(),
                Arc::new(UInt64Array::from(unsigned.to_vec())) as ArrayRef,
            ),
            (
                KvFieldKind::Boolean,
                vec![
                    None,
                    Some(StoredValue::Boolean(false)),
                    Some(StoredValue::Boolean(true)),
                ],
                Arc::new(BooleanArray::from(vec![None, Some(false), Some(true)])) as ArrayRef,
            ),
            (
                KvFieldKind::Utf8,
                vec![
                    None,
                    Some(StoredValue::Utf8("3.25".into())),
                    Some(StoredValue::Utf8("-0.5".into())),
                ],
                Arc::new(StringArray::from(vec![None, Some("3.25"), Some("-0.5")])) as ArrayRef,
            ),
        ];
        let context = SessionContext::new();
        for (kind, values, array) in cases {
            let input = RecordBatch::try_from_iter([("value", array)]).unwrap();
            let schema = DFSchema::try_from(input.schema().as_ref().clone()).unwrap();
            let native = context
                .create_physical_expr(
                    Expr::Cast(Cast::new(Box::new(col("value")), DataType::Float64)),
                    &schema,
                )
                .unwrap()
                .evaluate(&input)
                .unwrap()
                .into_array(input.num_rows())
                .unwrap();
            let request = scalar_request(vec![reducer(
                RangeReduceOp::MinField,
                Some(KvExpr::CastFloat64(Box::new(KvExpr::Field(
                    KvFieldRef::Value {
                        index: 0,
                        kind,
                        nullable: true,
                    },
                )))),
            )]);
            for (index, value) in values.into_iter().enumerate() {
                let expected =
                    scalar_to_reduced(ScalarValue::try_from_array(&native, index).unwrap())
                        .unwrap();
                let response = reduce(&[make_row(b"a", vec![value])], &request).unwrap();
                assert_eq!(response.results[0].value, expected, "{kind:?} row {index}");
            }
        }
    }

    #[test]
    fn reducer_filters_preserve_scalar_and_grouped_evaluation_order() {
        let filter = KvPredicate {
            checks: vec![KvPredicateCheck {
                field: KvFieldRef::Value {
                    index: 0,
                    kind: KvFieldKind::Int64,
                    nullable: true,
                },
                constraint: KvPredicateConstraint::IntRange {
                    min: Some(2),
                    max: None,
                },
            }],
            contradiction: false,
        };
        let rows = (1..=4)
            .map(|id| make_row(&[id], vec![Some(StoredValue::Int64(i64::from(id)))]))
            .collect::<Vec<_>>();
        let division = KvExpr::Div(
            Box::new(int64_value_field(0)),
            Box::new(KvExpr::Sub(
                Box::new(int64_value_field(0)),
                Box::new(KvExpr::Literal(KvReducedValue::Int64(1))),
            )),
        );
        for (expr, expected) in [
            (division.clone(), result_i64(4)),
            (KvExpr::CastFloat64(Box::new(division)), result_f64(4.0)),
        ] {
            let mut sum = reducer(RangeReduceOp::SumField, Some(expr));
            sum.filter = Some(filter.clone());
            let mut request = scalar_request(vec![reducer(RangeReduceOp::CountAll, None), sum]);
            let response = reduce(&rows, &request).unwrap();
            assert_eq!(response.results[0].value, result_u64(4));
            assert_eq!(response.results[1].value, expected);

            request.group_by = vec![KvExpr::Literal(KvReducedValue::Int64(0))];
            let error = reduce(&rows, &request).unwrap_err();
            assert!(error.to_string().contains("Divide by zero"), "{error}");

            request.filter = Some(filter.clone());
            let response = reduce(&rows, &request).unwrap();
            assert_eq!(response.groups[0].results[0].value, result_u64(3));
            assert_eq!(response.groups[0].results[1].value, expected);
        }
    }

    #[test]
    fn reducer_masks_retain_groups_and_decode_filter_only_values() {
        let mut filtered_count = reducer(RangeReduceOp::CountAll, None);
        filtered_count.filter = Some(KvPredicate {
            checks: vec![KvPredicateCheck {
                field: KvFieldRef::Value {
                    index: 0,
                    kind: KvFieldKind::Int64,
                    nullable: true,
                },
                constraint: KvPredicateConstraint::IntRange {
                    min: Some(2),
                    max: None,
                },
            }],
            contradiction: false,
        });
        let mut request =
            scalar_request(vec![filtered_count, reducer(RangeReduceOp::CountAll, None)]);
        let rows = [
            make_row(b"a", vec![Some(StoredValue::Int64(1))]),
            make_row(b"b", vec![None]),
            make_row(b"c", vec![Some(StoredValue::Int64(3))]),
        ];
        let plan = ReducePlan::new(Arc::new(request.clone()), &TaskContext::default()).unwrap();
        assert!(plan.needs_value);
        assert!(plan.fields.is_empty());
        let batch = plan.batch(&rows).unwrap();
        assert_eq!(batch.num_rows(), 3);
        assert_eq!(batch.num_columns(), 1);
        assert_eq!(
            batch
                .column(0)
                .as_any()
                .downcast_ref::<BooleanArray>()
                .unwrap(),
            &BooleanArray::from(vec![false, false, true])
        );
        let response = reduce(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_u64(1));
        assert_eq!(response.results[1].value, result_u64(3));
        assert!(reduce(
            &[(Key::default(), Bytes::from_static(b"bad row"))],
            &request
        )
        .is_err());

        request.group_by = vec![int64_value_field(0)];
        let response = reduce(&rows, &request).unwrap();
        assert_eq!(response.groups.len(), 3);
        for group in response.groups {
            let accepted = group.group_values[0] == result_i64(3);
            assert_eq!(group.results[0].value, result_u64(u64::from(accepted)));
            assert_eq!(group.results[1].value, result_u64(1));
        }
    }

    #[test]
    fn reducer_key_masks_do_not_require_payloads() {
        let key_field = KvFieldRef::Key {
            byte_offset: 0,
            kind: KvFieldKind::Int64,
        };
        let mut filtered = reducer(RangeReduceOp::CountAll, None);
        filtered.filter = Some(KvPredicate {
            checks: vec![KvPredicateCheck {
                field: key_field,
                constraint: KvPredicateConstraint::IntRange {
                    min: Some(2),
                    max: None,
                },
            }],
            contradiction: false,
        });
        let request = scalar_request(vec![filtered, reducer(RangeReduceOp::CountAll, None)]);
        let plan = ReducePlan::new(Arc::new(request.clone()), &TaskContext::default()).unwrap();
        assert!(!plan.needs_value);
        let rows = [1_i64, 2]
            .into_iter()
            .map(|value| {
                (
                    Key::from(((value as u64) ^ (1 << 63)).to_be_bytes().to_vec()),
                    Bytes::from_static(b"bad row"),
                )
            })
            .collect::<Vec<_>>();
        let response = reduce(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_u64(1));
        assert_eq!(response.results[1].value, result_u64(2));
    }

    #[tokio::test]
    async fn expression_materialization_respects_input_byte_budget() {
        use datafusion::execution::memory_pool::FairSpillPool;
        use datafusion::execution::runtime_env::RuntimeEnvBuilder;

        #[derive(Clone)]
        struct Rows(Vec<(Bytes, Bytes)>);
        impl crate::Sequence for Rows {
            fn current_sequence(&self) -> u64 {
                1
            }
        }
        impl RangeScan for Rows {
            async fn next_batch(
                &mut self,
                max_items: usize,
            ) -> Result<crate::RangeScanBatch, String> {
                Ok(crate::RangeScanBatch {
                    rows: self.0.drain(..max_items.min(self.0.len())).collect(),
                    extra: QueryExtra::new(),
                })
            }
        }
        impl Query for Rows {
            type RangeScan = Rows;
            async fn range_scan(&self, _: Key, _: Key, _: usize, _: bool) -> Result<Rows, String> {
                Ok(self.clone())
            }
            async fn get(&self, _: Bytes) -> Result<(Option<Bytes>, QueryExtra), String> {
                unreachable!()
            }
            async fn get_many(
                &self,
                _: Vec<Bytes>,
            ) -> Result<(Vec<(Bytes, Option<Bytes>)>, QueryExtra), String> {
                unreachable!()
            }
        }
        let literal_bytes = 256 * 1024;
        let literal = KvExpr::Literal(KvReducedValue::Utf8("X".repeat(literal_bytes)));
        let context = Arc::new(TaskContext::default());
        let mut cases = Vec::new();
        for expressions in [
            vec![literal.clone()],
            vec![KvExpr::Lower(Box::new(literal.clone())); 4],
            vec![
                KvExpr::CastFloat64(Box::new(KvExpr::Literal(KvReducedValue::Utf8(
                    "0".repeat(literal_bytes),
                ))));
                4
            ],
        ] {
            let outputs = expressions.len();
            let request = scalar_request(
                expressions
                    .into_iter()
                    .map(|expr| reducer(RangeReduceOp::MinField, Some(expr)))
                    .collect(),
            );
            cases.push((
                request,
                literal_bytes * outputs,
                REDUCE_BATCH_BYTES,
                context.clone(),
            ));
        }
        let budget = 8 * 1024;
        let context = Arc::new(
            TaskContext::default().with_runtime(
                RuntimeEnvBuilder::new()
                    .with_memory_pool(Arc::new(FairSpillPool::new(budget * 8)))
                    .build_arc()
                    .unwrap(),
            ),
        );
        for (group_by, count) in [
            (vec![KvExpr::Literal(KvReducedValue::Int64(0))], 1024),
            (Vec::new(), 32),
        ] {
            let request = RangeReduceRequest {
                reducers: vec![reducer(RangeReduceOp::CountAll, None); count],
                group_by,
                filter: None,
            };
            cases.push((request, count / 8, budget, context.clone()));
        }
        for (request, bytes_per_row, budget, context) in cases {
            let plan = Arc::new(ReducePlan::new(Arc::new(request), &context).unwrap());
            let partition = ReducePartition {
                query: Arc::new(Rows(vec![(Bytes::new(), Bytes::new()); REDUCE_BATCH_ROWS])),
                start: Bytes::new(),
                end: Bytes::new(),
                plan,
                extra: Arc::new(Mutex::new(QueryExtra::new())),
            };
            let mut stream = partition.execute(context.clone());
            let mut total_rows = 0;
            while let Some(batch) = stream.next().await {
                let batch = batch.unwrap();
                assert!(
                    batch.num_rows() * bytes_per_row <= budget,
                    "{} rows broadcast {} bytes per row",
                    batch.num_rows(),
                    bytes_per_row
                );
                total_rows += batch.num_rows();
            }
            assert_eq!(total_rows, REDUCE_BATCH_ROWS);
        }
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
    fn grouping_preserves_null_nan_payloads_and_signed_zero() {
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
                let key = match group.group_values.as_slice() {
                    [None] => None,
                    [Some(KvReducedValue::Float64(value))] => Some(value.to_bits()),
                    other => panic!("unexpected float group key {other:?}"),
                };
                (key, group.results[0].value.clone())
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        for (value, count) in [
            (None, 1),
            (Some(0.0), 2),
            (Some(nan_a), 2),
            (Some(nan_b), 1),
        ] {
            assert_eq!(groups[&value.map(f64::to_bits)], result_u64(count));
        }
    }

    #[tokio::test]
    async fn float_extrema_preserve_nan_and_signed_zero_results() {
        let positive_nan = f64::from_bits(0x7ff8_0000_0000_0001);
        let negative_nan = f64::from_bits(0xfff8_0000_0000_0001);
        for values in [
            vec![],
            vec![None],
            vec![Some(f64::INFINITY)],
            vec![Some(f64::NEG_INFINITY)],
            vec![Some(positive_nan), Some(0.0)],
            vec![Some(0.0), Some(positive_nan)],
            vec![Some(negative_nan), Some(f64::NEG_INFINITY)],
            vec![Some(f64::NEG_INFINITY), Some(negative_nan)],
            vec![Some(positive_nan), Some(negative_nan)],
            vec![Some(negative_nan), Some(positive_nan)],
            vec![Some(0.0), Some(-0.0)],
            vec![Some(-0.0), Some(0.0)],
            vec![None, Some(1.0), Some(positive_nan), Some(2.0), None],
        ] {
            let rows = values
                .iter()
                .enumerate()
                .map(|(i, value)| make_row(&i.to_be_bytes(), vec![value.map(StoredValue::Float64)]))
                .collect::<Vec<_>>();
            let batch = RecordBatch::try_from_iter([
                (
                    "category",
                    Arc::new(Int64Array::from(vec![0; values.len()])) as ArrayRef,
                ),
                (
                    "value",
                    Arc::new(Float64Array::from(values.clone())) as ArrayRef,
                ),
            ])
            .unwrap();
            let schema = batch.schema();
            let source = Arc::new(
                StreamingTableExec::try_new(
                    schema.clone(),
                    vec![Arc::new(FixturePartition {
                        schema: schema.clone(),
                        batches: vec![batch],
                    })],
                    None,
                    [],
                    false,
                    None,
                )
                .unwrap(),
            );
            let aggregates = [min_udaf(), max_udaf(), count_udaf()]
                .into_iter()
                .enumerate()
                .map(|(index, function)| {
                    Arc::new(
                        AggregateExprBuilder::new(
                            function,
                            vec![Arc::new(Column::new("value", 1))],
                        )
                        .schema(schema.clone())
                        .alias(format!("result_{index}"))
                        .build()
                        .unwrap(),
                    )
                })
                .collect::<Vec<_>>();

            // Each Store range uses Single aggregation; NaN results depend on this phase.
            for grouped in [false, true] {
                let native = AggregateExec::try_new(
                    AggregateMode::Single,
                    PhysicalGroupBy::new_single(if grouped {
                        vec![(Arc::new(Column::new("category", 0)), "category".into())]
                    } else {
                        Vec::new()
                    }),
                    aggregates.clone(),
                    vec![None; aggregates.len()],
                    source.clone(),
                    schema.clone(),
                )
                .unwrap();
                let expected = datafusion::physical_plan::collect(
                    Arc::new(native),
                    Arc::new(TaskContext::default()),
                )
                .await
                .unwrap();
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
                let Some(expected) = expected.iter().find(|batch| batch.num_rows() != 0) else {
                    assert!(response.groups.is_empty());
                    continue;
                };
                let results = if grouped {
                    assert_eq!(response.groups.len(), 1);
                    &response.groups[0].results
                } else {
                    &response.results
                };
                assert_eq!(
                    results[2].value,
                    result_u64(values.iter().flatten().count() as u64)
                );
                for (index, result) in results.iter().take(2).enumerate() {
                    let actual = match result.value {
                        Some(KvReducedValue::Float64(value)) => Some(value.to_bits()),
                        None => None,
                        _ => panic!("float result"),
                    };
                    let ScalarValue::Float64(expected) = ScalarValue::try_from_array(
                        expected.column(usize::from(grouped) + index),
                        0,
                    )
                    .unwrap() else {
                        panic!("expected Float64 result");
                    };
                    assert_eq!(
                        actual,
                        expected.map(f64::to_bits),
                        "grouped={grouped}, inputs={values:?}",
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn spill_preserves_full_width_decimal_states_and_repeated_groups() {
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
                                StoredValue::Float64(if pass == 0 { -100.0 } else { 100.0 })
                            }),
                        ],
                    )
                })
            })
            .collect::<Vec<_>>();
        let plan = ReducePlan::new(Arc::new(request), &TaskContext::default()).unwrap();
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
                        .zip([(-100.0_f64).to_bits(), 100.0_f64.to_bits()])
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
