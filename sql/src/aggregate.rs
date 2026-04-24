use std::any::Any;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use datafusion::arrow::array::new_empty_array;
use datafusion::arrow::compute::cast;
use datafusion::arrow::datatypes::{i256, DataType, SchemaRef, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::catalog::Session;
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::{DataFusionError, Result as DataFusionResult, ScalarValue};
use datafusion::datasource::{provider_as_source, source_as_provider, TableProvider};
use datafusion::execution::context::TaskContext;
use datafusion::logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder, Operator, TableType};
use datafusion::optimizer::optimizer::OptimizerRule;
use datafusion::physical_expr::{EquivalenceProperties, Partitioning};
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::{
    stream::RecordBatchStreamAdapter, DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties,
    SendableRecordBatchStream,
};
use exoware_proto::to_domain_reduce_response;
use exoware_proto::{
    RangeReduceGroup, RangeReduceOp, RangeReduceRequest, RangeReduceResponse, RangeReduceResult,
    RangeReducerSpec,
};
use exoware_sdk as exoware_proto;
use exoware_sdk::kv_codec::{
    canonicalize_reduced_group_values, encode_reduced_group_key, KvExpr, KvFieldKind, KvFieldRef,
    KvPredicate, KvPredicateCheck, KvPredicateConstraint, KvReducedValue,
};
use exoware_sdk::{SerializableReadSession, StoreClient};
use futures::SinkExt;

use crate::diagnostics::*;
use crate::filter::*;
use crate::predicate::*;
use crate::types::*;

#[derive(Debug)]
pub(crate) struct KvAggregatePushdownRule;

#[derive(Debug, Clone)]
pub(crate) enum AggregateAccessPath {
    PrimaryKey,
    SecondaryIndex { spec_idx: usize },
}

#[derive(Debug, Clone)]
pub(crate) enum AggregateOutputPlan {
    Direct {
        reducer_idx: usize,
        data_type: DataType,
    },
    Avg {
        sum_idx: usize,
        count_idx: usize,
        data_type: DataType,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AggregatePushdownFunction {
    Count,
    Sum,
    Min,
    Max,
    Avg,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PushdownValueExpr {
    Column(usize),
    Literal(KvReducedValue),
    Add(Box<PushdownValueExpr>, Box<PushdownValueExpr>),
    Sub(Box<PushdownValueExpr>, Box<PushdownValueExpr>),
    Mul(Box<PushdownValueExpr>, Box<PushdownValueExpr>),
    Div(Box<PushdownValueExpr>, Box<PushdownValueExpr>),
    Lower(Box<PushdownValueExpr>),
    DateTruncDay(Box<PushdownValueExpr>),
}

impl PushdownValueExpr {
    pub(crate) fn collect_columns(&self, out: &mut Vec<usize>) {
        match self {
            Self::Column(col_idx) => out.push(*col_idx),
            Self::Literal(_) => {}
            Self::Add(left, right)
            | Self::Sub(left, right)
            | Self::Mul(left, right)
            | Self::Div(left, right) => {
                left.collect_columns(out);
                right.collect_columns(out);
            }
            Self::Lower(inner) | Self::DateTruncDay(inner) => inner.collect_columns(out),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum AggregatePushdownArgument {
    CountAll,
    Expr(PushdownValueExpr),
}

#[derive(Debug, Clone)]
pub(crate) struct NormalizedAggregateExpr {
    pub(crate) func: AggregatePushdownFunction,
    pub(crate) argument: AggregatePushdownArgument,
    pub(crate) filter: Option<Expr>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AggregateReduceJob {
    pub(crate) request: RangeReduceRequest,
    pub(crate) ranges: Vec<KeyRange>,
}

#[derive(Debug, Clone)]
pub(crate) struct AggregateExprPlan {
    pub(crate) job: AggregateReduceJob,
    pub(crate) output: AggregateOutputPlan,
}

#[derive(Debug, Clone)]
pub(crate) struct CombinedAggregateJob {
    pub(crate) job: AggregateReduceJob,
    pub(crate) expr_plans: Vec<AggregateOutputPlan>,
}

#[derive(Debug, Clone)]
pub(crate) struct AggregateGroupPlan {
    pub(crate) data_type: DataType,
}

#[derive(Debug, Clone)]
pub(crate) struct AggregatePushdownSpec {
    pub(crate) client: StoreClient,
    pub(crate) group_plans: Vec<AggregateGroupPlan>,
    pub(crate) seed_job: Option<AggregateReduceJob>,
    pub(crate) aggregate_jobs: Vec<CombinedAggregateJob>,
    pub(crate) diagnostics: AggregatePushdownDiagnostics,
    pub(crate) schema: SchemaRef,
}

#[derive(Debug)]
pub(crate) struct KvAggregateExec {
    pub(crate) spec: AggregatePushdownSpec,
    pub(crate) projection: Option<Vec<usize>>,
    pub(crate) projected_schema: SchemaRef,
    pub(crate) properties: PlanProperties,
}

impl KvAggregatePushdownRule {
    pub(crate) fn new() -> Self {
        Self
    }

    pub(crate) fn try_rewrite_plan(
        &self,
        plan: LogicalPlan,
    ) -> DataFusionResult<Transformed<LogicalPlan>> {
        let LogicalPlan::Aggregate(aggregate) = plan else {
            return Ok(Transformed::no(plan));
        };

        let (scan, group_exprs, aggr_exprs) = match aggregate.input.as_ref() {
            LogicalPlan::TableScan(scan) => (
                scan,
                aggregate.group_expr.clone(),
                aggregate.aggr_expr.clone(),
            ),
            LogicalPlan::Projection(projection) => {
                let LogicalPlan::TableScan(scan) = projection.input.as_ref() else {
                    return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate)));
                };
                let group_exprs = match aggregate
                    .group_expr
                    .iter()
                    .map(|expr| inline_projection_aliases(expr, projection))
                    .collect::<DataFusionResult<Vec<_>>>()
                {
                    Ok(exprs) => exprs,
                    Err(_) => return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate))),
                };
                let aggr_exprs = match aggregate
                    .aggr_expr
                    .iter()
                    .map(|expr| inline_projection_aliases(expr, projection))
                    .collect::<DataFusionResult<Vec<_>>>()
                {
                    Ok(exprs) => exprs,
                    Err(_) => return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate))),
                };
                (scan, group_exprs, aggr_exprs)
            }
            _ => return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate))),
        };
        let Ok(provider) = source_as_provider(&scan.source) else {
            return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate)));
        };
        let Some(kv_table) = provider.as_any().downcast_ref::<KvTable>() else {
            return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate)));
        };
        let Some(spec) = try_build_aggregate_pushdown_spec(
            kv_table,
            scan,
            &group_exprs,
            &aggr_exprs,
            &aggregate.schema,
        )?
        else {
            return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate)));
        };

        let table = Arc::new(KvAggregateTable { spec });
        let plan =
            LogicalPlanBuilder::scan(scan.table_name.clone(), provider_as_source(table), None)?
                .build()?;
        Ok(Transformed::yes(plan))
    }
}

fn inline_projection_aliases(
    expr: &Expr,
    projection: &datafusion::logical_expr::logical_plan::Projection,
) -> DataFusionResult<Expr> {
    let alias_map = projection
        .expr
        .iter()
        .zip(projection.schema.fields().iter())
        .map(|(projection_expr, field)| {
            (
                field.name().to_string(),
                strip_alias_expr(projection_expr).clone(),
            )
        })
        .collect::<HashMap<_, _>>();
    Ok(expr
        .clone()
        .transform(|node| {
            if let Expr::Column(column) = &node {
                if column.relation.is_none() {
                    if let Some(replacement) = alias_map.get(&column.name) {
                        return Ok(Transformed::yes(replacement.clone()));
                    }
                }
            }
            Ok(Transformed::no(node))
        })?
        .data)
}

impl OptimizerRule for KvAggregatePushdownRule {
    fn name(&self) -> &str {
        "kv_aggregate_pushdown"
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn datafusion::optimizer::optimizer::OptimizerConfig,
    ) -> DataFusionResult<Transformed<LogicalPlan>> {
        plan.transform_up(|node| self.try_rewrite_plan(node))
    }
}

#[async_trait]
impl TableProvider for KvAggregateTable {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.spec.schema.clone()
    }

    fn table_type(&self) -> TableType {
        TableType::Temporary
    }

    async fn scan(
        &self,
        _state: &dyn Session,
        projection: Option<&Vec<usize>>,
        _filters: &[Expr],
        _limit: Option<usize>,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        let projected_schema = match projection {
            Some(proj) => Arc::new(self.spec.schema.project(proj)?),
            None => self.spec.schema.clone(),
        };
        Ok(Arc::new(KvAggregateExec::new(
            self.spec.clone(),
            projection.cloned(),
            projected_schema,
        )))
    }
}

impl KvAggregateExec {
    pub(crate) fn new(
        spec: AggregatePushdownSpec,
        projection: Option<Vec<usize>>,
        projected_schema: SchemaRef,
    ) -> Self {
        let properties = PlanProperties::new(
            EquivalenceProperties::new(projected_schema.clone()),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Bounded,
        );
        Self {
            spec,
            projection,
            projected_schema,
            properties,
        }
    }
}

impl DisplayAs for KvAggregateExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KvAggregateExec: grouped={}, seed_job={}, aggregate_jobs=[{}], query_stats={}",
            self.spec.diagnostics.grouped,
            self.spec
                .diagnostics
                .seed_job
                .as_ref()
                .map(format_access_path_diagnostics)
                .unwrap_or_else(|| "none".to_string()),
            self.spec
                .diagnostics
                .aggregate_jobs
                .iter()
                .enumerate()
                .map(|(idx, diag)| format!("job{idx}{{{}}}", format_access_path_diagnostics(diag)))
                .collect::<Vec<_>>()
                .join("; "),
            format_query_stats_explain(QueryStatsExplainSurface::RangeReduceHeader)
        )
    }
}

impl ExecutionPlan for KvAggregateExec {
    fn name(&self) -> &str {
        "KvAggregateExec"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.projected_schema.clone()
    }

    fn properties(&self) -> &PlanProperties {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![]
    }

    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        if !children.is_empty() {
            return Err(DataFusionError::Internal(
                "KvAggregateExec has no children".to_string(),
            ));
        }
        Ok(self)
    }

    fn execute(
        &self,
        partition: usize,
        _context: Arc<TaskContext>,
    ) -> DataFusionResult<SendableRecordBatchStream> {
        if partition != 0 {
            return Err(DataFusionError::Internal(format!(
                "KvAggregateExec only supports 1 partition, got {partition}"
            )));
        }

        let (mut tx, rx) = futures::channel::mpsc::channel::<DataFusionResult<RecordBatch>>(1);
        let spec = self.spec.clone();
        let projection = self.projection.clone();
        let projected_schema = self.projected_schema.clone();

        tokio::spawn(async move {
            let batch =
                execute_aggregate_pushdown(spec, projection, projected_schema.clone()).await;
            let _ = tx.send(batch).await;
        });

        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.projected_schema.clone(),
            rx,
        )))
    }
}

#[derive(Debug, Clone)]
pub(crate) enum PartialAggregateState {
    Count(u64),
    Sum(Option<KvReducedValue>),
    Min(Option<KvReducedValue>),
    Max(Option<KvReducedValue>),
}

impl PartialAggregateState {
    pub(crate) fn from_op(op: RangeReduceOp) -> Self {
        match op {
            RangeReduceOp::CountAll | RangeReduceOp::CountField => Self::Count(0),
            RangeReduceOp::SumField => Self::Sum(None),
            RangeReduceOp::MinField => Self::Min(None),
            RangeReduceOp::MaxField => Self::Max(None),
        }
    }

    pub(crate) fn merge_partial(
        &mut self,
        op: RangeReduceOp,
        value: Option<&KvReducedValue>,
    ) -> DataFusionResult<()> {
        match (self, op) {
            (Self::Count(total), RangeReduceOp::CountAll | RangeReduceOp::CountField) => {
                let Some(v) = value else {
                    return Err(DataFusionError::Execution(
                        "count reducer returned non-UInt64 partial".to_string(),
                    ));
                };
                let KvReducedValue::UInt64(partial) = v else {
                    return Err(DataFusionError::Execution(
                        "count reducer returned non-UInt64 partial".to_string(),
                    ));
                };
                *total = total.saturating_add(*partial);
                Ok(())
            }
            (Self::Sum(total), RangeReduceOp::SumField) => {
                let Some(value) = value else {
                    return Ok(());
                };
                match total {
                    Some(existing) => existing
                        .checked_add_assign(value)
                        .map_err(DataFusionError::Execution),
                    None => {
                        *total = Some(value.clone());
                        Ok(())
                    }
                }
            }
            (Self::Min(current), RangeReduceOp::MinField) => merge_extreme(current, value, true),
            (Self::Max(current), RangeReduceOp::MaxField) => merge_extreme(current, value, false),
            _ => Err(DataFusionError::Execution(
                "aggregate reducer state/op mismatch".to_string(),
            )),
        }
    }

    pub(crate) fn as_scalar_value(&self, data_type: &DataType) -> DataFusionResult<ScalarValue> {
        match self {
            Self::Count(count) => match data_type {
                DataType::UInt64 => Ok(ScalarValue::UInt64(Some(*count))),
                DataType::Int64 => Ok(ScalarValue::Int64(Some(i64::try_from(*count).map_err(
                    |_| DataFusionError::Execution("count exceeds Int64 range".to_string()),
                )?))),
                _ => Err(DataFusionError::Execution(format!(
                    "unsupported count return type {:?}",
                    data_type
                ))),
            },
            Self::Sum(value) | Self::Min(value) | Self::Max(value) => {
                reduced_value_to_scalar(value.clone(), data_type)
            }
        }
    }
}

pub(crate) fn merge_extreme(
    current: &mut Option<KvReducedValue>,
    value: Option<&KvReducedValue>,
    is_min: bool,
) -> DataFusionResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    match current {
        Some(existing) => {
            let ordering = value.partial_cmp_same_kind(existing).ok_or_else(|| {
                DataFusionError::Execution("aggregate extreme type mismatch".to_string())
            })?;
            if (is_min && ordering == Ordering::Less) || (!is_min && ordering == Ordering::Greater)
            {
                *current = Some(value.clone());
            }
        }
        None => {
            *current = Some(value.clone());
        }
    }
    Ok(())
}

pub(crate) fn reduced_value_to_scalar(
    value: Option<KvReducedValue>,
    data_type: &DataType,
) -> DataFusionResult<ScalarValue> {
    Ok(match (data_type, value) {
        (_, Some(KvReducedValue::Int64(v))) => {
            cast_scalar_value(ScalarValue::Int64(Some(v)), data_type)?
        }
        (_, Some(KvReducedValue::UInt64(v))) => {
            cast_scalar_value(ScalarValue::UInt64(Some(v)), data_type)?
        }
        (_, Some(KvReducedValue::Float64(v))) => {
            cast_scalar_value(ScalarValue::Float64(Some(v)), data_type)?
        }
        (_, Some(KvReducedValue::Boolean(v))) => {
            cast_scalar_value(ScalarValue::Boolean(Some(v)), data_type)?
        }
        (_, Some(KvReducedValue::Utf8(v))) => {
            cast_scalar_value(ScalarValue::Utf8(Some(v)), data_type)?
        }
        (_, Some(KvReducedValue::Date32(v))) => {
            cast_scalar_value(ScalarValue::Date32(Some(v)), data_type)?
        }
        (_, Some(KvReducedValue::Date64(v))) => {
            cast_scalar_value(ScalarValue::Date64(Some(v)), data_type)?
        }
        (DataType::Timestamp(TimeUnit::Microsecond, tz), Some(KvReducedValue::Timestamp(v))) => {
            ScalarValue::TimestampMicrosecond(Some(v), tz.clone())
        }
        (_, Some(KvReducedValue::Timestamp(v))) => {
            cast_scalar_value(ScalarValue::TimestampMicrosecond(Some(v), None), data_type)?
        }
        (_, Some(KvReducedValue::Decimal128(v))) => match data_type {
            DataType::Decimal128(precision, scale) => {
                ScalarValue::Decimal128(Some(v), *precision, *scale)
            }
            _ => {
                return Err(DataFusionError::Execution(format!(
                    "unsupported reduced scalar conversion to {:?}",
                    data_type
                )))
            }
        },
        (_, Some(KvReducedValue::Decimal256(v))) => match data_type {
            DataType::Decimal256(precision, scale) => {
                ScalarValue::Decimal256(Some(i256::from_le_bytes(v)), *precision, *scale)
            }
            _ => {
                return Err(DataFusionError::Execution(format!(
                    "unsupported reduced scalar conversion to {:?}",
                    data_type
                )))
            }
        },
        (_, Some(KvReducedValue::FixedSizeBinary(v))) => cast_scalar_value(
            ScalarValue::FixedSizeBinary(v.len() as i32, Some(v)),
            data_type,
        )?,
        (DataType::Null, None) => ScalarValue::Null,
        (DataType::Int64, None) => ScalarValue::Int64(None),
        (DataType::UInt64, None) => ScalarValue::UInt64(None),
        (DataType::Float64, None) => ScalarValue::Float64(None),
        (DataType::Boolean, None) => ScalarValue::Boolean(None),
        (DataType::Utf8, None) => ScalarValue::Utf8(None),
        (DataType::LargeUtf8, None) => ScalarValue::LargeUtf8(None),
        (DataType::Utf8View, None) => ScalarValue::Utf8View(None),
        (DataType::Date32, None) => ScalarValue::Date32(None),
        (DataType::Date64, None) => ScalarValue::Date64(None),
        (DataType::Timestamp(TimeUnit::Microsecond, tz), None) => {
            ScalarValue::TimestampMicrosecond(None, tz.clone())
        }
        _ => {
            return Err(DataFusionError::Execution(format!(
                "unsupported reduced scalar conversion to {:?}",
                data_type
            )))
        }
    })
}

pub(crate) fn cast_scalar_value(
    value: ScalarValue,
    data_type: &DataType,
) -> DataFusionResult<ScalarValue> {
    if value.data_type() == *data_type {
        return Ok(value);
    }
    let array = value.to_array_of_size(1)?;
    let casted = cast(&array, data_type)?;
    ScalarValue::try_from_array(&casted, 0)
}

#[derive(Debug, Clone)]
pub(crate) struct MergedGroupResponseState {
    pub(crate) group_values: Vec<Option<KvReducedValue>>,
    pub(crate) states: Vec<PartialAggregateState>,
}

#[derive(Debug, Clone)]
pub(crate) struct GroupAccumulatorState {
    pub(crate) group_values: Vec<Option<KvReducedValue>>,
    pub(crate) aggregate_states: Vec<Option<Vec<PartialAggregateState>>>,
}

impl GroupAccumulatorState {
    pub(crate) fn new(group_values: Vec<Option<KvReducedValue>>, aggregate_count: usize) -> Self {
        Self {
            group_values,
            aggregate_states: vec![None; aggregate_count],
        }
    }

    pub(crate) fn merge_expr_results(
        &mut self,
        expr_idx: usize,
        reducers: &[RangeReducerSpec],
        partials: &[RangeReduceResult],
    ) -> DataFusionResult<()> {
        if partials.len() != reducers.len() {
            return Err(DataFusionError::Execution(
                "range reduction response length mismatch".to_string(),
            ));
        }
        let states = self.aggregate_states[expr_idx].get_or_insert_with(|| {
            reducers
                .iter()
                .map(|reducer| PartialAggregateState::from_op(reducer.op))
                .collect::<Vec<_>>()
        });
        for ((state, reducer), partial) in
            states.iter_mut().zip(reducers.iter()).zip(partials.iter())
        {
            state.merge_partial(reducer.op, partial.value.as_ref())?;
        }
        Ok(())
    }
}

pub(crate) async fn execute_aggregate_pushdown(
    spec: AggregatePushdownSpec,
    projection: Option<Vec<usize>>,
    projected_schema: SchemaRef,
) -> DataFusionResult<RecordBatch> {
    let session = spec.client.create_session();
    let mut groups = BTreeMap::<Vec<u8>, GroupAccumulatorState>::new();
    if spec.group_plans.is_empty() {
        groups.insert(
            Vec::new(),
            GroupAccumulatorState::new(Vec::new(), total_aggregate_outputs(&spec.aggregate_jobs)),
        );
    }

    if let Some(seed_job) = &spec.seed_job {
        let response = execute_reduce_job(&session, seed_job).await?;
        if !response.results.is_empty() {
            return Err(DataFusionError::Execution(
                "group seed job returned scalar reductions".to_string(),
            ));
        }
        for group in response.groups {
            let key = encode_reduced_group_key(&group.group_values);
            groups.entry(key).or_insert_with(|| {
                GroupAccumulatorState::new(
                    group.group_values,
                    total_aggregate_outputs(&spec.aggregate_jobs),
                )
            });
        }
    }

    let mut output_base_idx = 0usize;
    for combined_job in &spec.aggregate_jobs {
        let response = execute_reduce_job(&session, &combined_job.job).await?;
        if spec.group_plans.is_empty() {
            if !response.groups.is_empty() {
                return Err(DataFusionError::Execution(
                    "scalar aggregate job returned grouped reductions".to_string(),
                ));
            }
            let group = groups.get_mut(&Vec::new()).ok_or_else(|| {
                DataFusionError::Execution("missing scalar aggregate accumulator".to_string())
            })?;
            for (expr_offset, expr_plan) in combined_job.expr_plans.iter().enumerate() {
                group.merge_expr_results(
                    output_base_idx + expr_offset,
                    reducers_for_output(&combined_job.job.request.reducers, expr_plan),
                    results_for_output(&response.results, expr_plan),
                )?;
            }
        } else {
            if !response.results.is_empty() {
                return Err(DataFusionError::Execution(
                    "grouped aggregate job returned scalar reductions".to_string(),
                ));
            }
            for group_response in &response.groups {
                let key = encode_reduced_group_key(&group_response.group_values);
                let group = groups.entry(key).or_insert_with(|| {
                    GroupAccumulatorState::new(
                        group_response.group_values.clone(),
                        total_aggregate_outputs(&spec.aggregate_jobs),
                    )
                });
                for (expr_offset, expr_plan) in combined_job.expr_plans.iter().enumerate() {
                    group.merge_expr_results(
                        output_base_idx + expr_offset,
                        reducers_for_output(&combined_job.job.request.reducers, expr_plan),
                        results_for_output(&group_response.results, expr_plan),
                    )?;
                }
            }
        }
        output_base_idx += combined_job.expr_plans.len();
    }

    let mut rows = Vec::new();
    for group in groups.into_values() {
        let mut row = Vec::with_capacity(
            spec.group_plans.len() + total_aggregate_outputs(&spec.aggregate_jobs),
        );
        for (idx, group_plan) in spec.group_plans.iter().enumerate() {
            let value = group.group_values.get(idx).cloned().unwrap_or(None);
            row.push(reduced_value_to_scalar(value, &group_plan.data_type)?);
        }
        let mut output_idx = 0usize;
        for combined_job in &spec.aggregate_jobs {
            for expr_plan in &combined_job.expr_plans {
                row.push(finalize_aggregate_output(
                    expr_plan,
                    group.aggregate_states[output_idx].as_deref(),
                    reducers_for_output(&combined_job.job.request.reducers, expr_plan),
                )?);
                output_idx += 1;
            }
        }
        rows.push(row);
    }

    build_projected_record_batch(rows, spec.schema, projection, projected_schema)
}

pub(crate) fn finalize_avg(
    sum_state: &PartialAggregateState,
    count_state: &PartialAggregateState,
    data_type: &DataType,
) -> DataFusionResult<ScalarValue> {
    let PartialAggregateState::Count(count) = count_state else {
        return Err(DataFusionError::Execution(
            "avg count state must be Count".to_string(),
        ));
    };
    if *count == 0 {
        return reduced_value_to_scalar(None, data_type);
    }
    let avg = match sum_state {
        PartialAggregateState::Sum(Some(KvReducedValue::Int64(v))) => *v as f64 / *count as f64,
        PartialAggregateState::Sum(Some(KvReducedValue::UInt64(v))) => *v as f64 / *count as f64,
        PartialAggregateState::Sum(Some(KvReducedValue::Float64(v))) => *v / *count as f64,
        _ => {
            return Err(DataFusionError::Execution(
                "unsupported avg input type for pushdown".to_string(),
            ))
        }
    };
    match data_type {
        DataType::Float64 => Ok(ScalarValue::Float64(Some(avg))),
        _ => Err(DataFusionError::Execution(format!(
            "unsupported avg return type {:?}",
            data_type
        ))),
    }
}

pub(crate) async fn execute_reduce_job(
    session: &SerializableReadSession,
    job: &AggregateReduceJob,
) -> DataFusionResult<RangeReduceResponse> {
    if job.request.group_by.is_empty() {
        let mut states = job
            .request
            .reducers
            .iter()
            .map(|reducer| PartialAggregateState::from_op(reducer.op))
            .collect::<Vec<_>>();
        for range in &job.ranges {
            let response = session
                .range_reduce_response(&range.start, &range.end, &job.request)
                .await
                .map_err(|e| DataFusionError::External(Box::new(e)))?;
            let archived = to_domain_reduce_response(response).map_err(|e| {
                DataFusionError::Execution(format!("range reduction response decode: {e}"))
            })?;
            if !archived.groups.is_empty() {
                return Err(DataFusionError::Execution(
                    "scalar reduction job returned grouped results".to_string(),
                ));
            }
            if archived.results.len() != states.len() {
                return Err(DataFusionError::Execution(
                    "range reduction response length mismatch".to_string(),
                ));
            }
            for ((state, reducer), partial) in states
                .iter_mut()
                .zip(job.request.reducers.iter())
                .zip(archived.results.iter())
            {
                state.merge_partial(reducer.op, partial.value.as_ref())?;
            }
        }
        return Ok(RangeReduceResponse {
            results: states
                .into_iter()
                .map(|state| RangeReduceResult {
                    value: match state {
                        PartialAggregateState::Count(count) => Some(KvReducedValue::UInt64(count)),
                        PartialAggregateState::Sum(value)
                        | PartialAggregateState::Min(value)
                        | PartialAggregateState::Max(value) => value,
                    },
                })
                .collect(),
            groups: Vec::new(),
        });
    }

    let mut groups = BTreeMap::<Vec<u8>, MergedGroupResponseState>::new();
    for range in &job.ranges {
        let response = session
            .range_reduce_response(&range.start, &range.end, &job.request)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
        let archived = to_domain_reduce_response(response).map_err(|e| {
            DataFusionError::Execution(format!("range reduction response decode: {e}"))
        })?;
        if !archived.results.is_empty() {
            return Err(DataFusionError::Execution(
                "grouped reduction job returned scalar results".to_string(),
            ));
        }
        for group in archived.groups {
            merge_domain_group_reduce_response(&mut groups, &job.request.reducers, group)?;
        }
    }
    Ok(RangeReduceResponse {
        results: Vec::new(),
        groups: groups
            .into_values()
            .map(|group| RangeReduceGroup {
                group_values: group.group_values,
                results: group
                    .states
                    .into_iter()
                    .map(|state| RangeReduceResult {
                        value: match state {
                            PartialAggregateState::Count(count) => {
                                Some(KvReducedValue::UInt64(count))
                            }
                            PartialAggregateState::Sum(value)
                            | PartialAggregateState::Min(value)
                            | PartialAggregateState::Max(value) => value,
                        },
                    })
                    .collect(),
            })
            .collect(),
    })
}

pub(crate) fn merge_domain_group_reduce_response(
    groups: &mut BTreeMap<Vec<u8>, MergedGroupResponseState>,
    reducers: &[RangeReducerSpec],
    mut group: RangeReduceGroup,
) -> DataFusionResult<()> {
    if group.results.len() != reducers.len() {
        return Err(DataFusionError::Execution(
            "grouped range reduction response length mismatch".to_string(),
        ));
    }
    canonicalize_reduced_group_values(&mut group.group_values);
    let key = encode_reduced_group_key(&group.group_values);
    let entry = groups
        .entry(key)
        .or_insert_with(|| MergedGroupResponseState {
            group_values: group.group_values.clone(),
            states: reducers
                .iter()
                .map(|reducer| PartialAggregateState::from_op(reducer.op))
                .collect(),
        });
    for ((state, reducer), partial) in entry
        .states
        .iter_mut()
        .zip(reducers.iter())
        .zip(group.results.iter())
    {
        state.merge_partial(reducer.op, partial.value.as_ref())?;
    }
    Ok(())
}

pub(crate) fn finalize_aggregate_output(
    output: &AggregateOutputPlan,
    states: Option<&[PartialAggregateState]>,
    reducers: &[RangeReducerSpec],
) -> DataFusionResult<ScalarValue> {
    let default_states;
    let states = match states {
        Some(states) => states,
        None => {
            default_states = reducers
                .iter()
                .map(|reducer| PartialAggregateState::from_op(reducer.op))
                .collect::<Vec<_>>();
            &default_states
        }
    };
    match output {
        AggregateOutputPlan::Direct {
            reducer_idx,
            data_type,
        } => states[*reducer_idx].as_scalar_value(data_type),
        AggregateOutputPlan::Avg {
            sum_idx,
            count_idx,
            data_type,
        } => finalize_avg(&states[*sum_idx], &states[*count_idx], data_type),
    }
}

pub(crate) fn build_projected_record_batch(
    rows: Vec<Vec<ScalarValue>>,
    full_schema: SchemaRef,
    projection: Option<Vec<usize>>,
    projected_schema: SchemaRef,
) -> DataFusionResult<RecordBatch> {
    let projected_indices = projection.unwrap_or_else(|| (0..full_schema.fields().len()).collect());
    let mut arrays = Vec::with_capacity(projected_indices.len());
    for (projected_pos, idx) in projected_indices.into_iter().enumerate() {
        if rows.is_empty() {
            arrays.push(new_empty_array(
                projected_schema.field(projected_pos).data_type(),
            ));
        } else {
            let values = rows.iter().map(|row| row[idx].clone());
            arrays.push(ScalarValue::iter_to_array(values)?);
        }
    }
    RecordBatch::try_new(projected_schema, arrays).map_err(Into::into)
}

pub(crate) fn total_aggregate_outputs(jobs: &[CombinedAggregateJob]) -> usize {
    jobs.iter().map(|job| job.expr_plans.len()).sum()
}

pub(crate) fn reducers_for_output<'a>(
    reducers: &'a [RangeReducerSpec],
    output: &AggregateOutputPlan,
) -> &'a [RangeReducerSpec] {
    match output {
        AggregateOutputPlan::Direct { reducer_idx, .. } => {
            &reducers[*reducer_idx..*reducer_idx + 1]
        }
        AggregateOutputPlan::Avg {
            sum_idx, count_idx, ..
        } => &reducers[*sum_idx..*count_idx + 1],
    }
}

pub(crate) fn results_for_output<'a>(
    results: &'a [RangeReduceResult],
    output: &AggregateOutputPlan,
) -> &'a [RangeReduceResult] {
    match output {
        AggregateOutputPlan::Direct { reducer_idx, .. } => &results[*reducer_idx..*reducer_idx + 1],
        AggregateOutputPlan::Avg {
            sum_idx, count_idx, ..
        } => &results[*sum_idx..*count_idx + 1],
    }
}

pub(crate) fn rebase_output_plan(
    output: AggregateOutputPlan,
    offset: usize,
) -> AggregateOutputPlan {
    match output {
        AggregateOutputPlan::Direct {
            reducer_idx,
            data_type,
        } => AggregateOutputPlan::Direct {
            reducer_idx: reducer_idx + offset,
            data_type,
        },
        AggregateOutputPlan::Avg {
            sum_idx,
            count_idx,
            data_type,
        } => AggregateOutputPlan::Avg {
            sum_idx: sum_idx + offset,
            count_idx: count_idx + offset,
            data_type,
        },
    }
}

pub(crate) fn combine_aggregate_jobs(exprs: Vec<AggregateExprPlan>) -> Vec<CombinedAggregateJob> {
    let mut combined: Vec<CombinedAggregateJob> = Vec::new();
    for expr in exprs {
        if let Some(existing) = combined
            .iter_mut()
            .find(|candidate| candidate.job == expr.job)
        {
            let offset = existing.job.request.reducers.len();
            let rebased_output = rebase_output_plan(expr.output, offset);
            existing
                .job
                .request
                .reducers
                .extend(expr.job.request.reducers);
            existing.expr_plans.push(rebased_output);
        } else {
            combined.push(CombinedAggregateJob {
                job: expr.job,
                expr_plans: vec![expr.output],
            });
        }
    }
    combined
}

#[derive(Debug, Clone)]
pub(crate) struct CompiledGroupExpr {
    pub(crate) expr: PushdownValueExpr,
    pub(crate) data_type: DataType,
}

pub(crate) fn try_build_aggregate_pushdown_spec(
    table: &KvTable,
    scan: &datafusion::logical_expr::logical_plan::TableScan,
    group_exprs: &[Expr],
    aggr_exprs: &[Expr],
    schema: &datafusion::common::DFSchemaRef,
) -> DataFusionResult<Option<AggregatePushdownSpec>> {
    let mut compiled_group_exprs = Vec::with_capacity(group_exprs.len());
    for (idx, expr) in group_exprs.iter().enumerate() {
        let data_type = schema.field(idx).data_type().clone();
        let compiled_expr = match compile_pushdown_value_expr(expr, &table.model) {
            Ok((compiled_expr, _)) => compiled_expr,
            Err(_) => return Ok(None),
        };
        compiled_group_exprs.push(CompiledGroupExpr {
            expr: compiled_expr,
            data_type,
        });
    }

    let mut aggregate_exprs = Vec::new();
    let mut aggregate_diagnostics = Vec::new();
    let mut has_filtered_aggregate = false;
    for (expr_idx, expr) in aggr_exprs.iter().enumerate() {
        let data_type = schema
            .field(group_exprs.len() + expr_idx)
            .data_type()
            .clone();
        let local_filter = match aggregate_expr_filter(expr, &table.model) {
            Ok(filter) => filter,
            Err(_) => return Ok(None),
        };
        has_filtered_aggregate |= local_filter.is_some();
        let mut filters = scan.filters.clone();
        if let Some(filter) = local_filter {
            if !QueryPredicate::supports_filter(&filter, &table.model) {
                return Ok(None);
            }
            filters.push(filter);
        }
        let Some((job, diagnostics, output)) = build_aggregate_reduce_job(
            table,
            &filters,
            &compiled_group_exprs,
            Some(expr),
            Some(data_type),
        )?
        else {
            return Ok(None);
        };
        let Some(output) = output else {
            return Ok(None);
        };
        aggregate_exprs.push(AggregateExprPlan { job, output });
        aggregate_diagnostics.push(diagnostics);
    }

    if aggregate_exprs.is_empty() {
        return Ok(None);
    }

    let seed_job = if !compiled_group_exprs.is_empty() && has_filtered_aggregate {
        let Some((job, diagnostics, _)) =
            build_aggregate_reduce_job(table, &scan.filters, &compiled_group_exprs, None, None)?
        else {
            return Ok(None);
        };
        Some((job, diagnostics))
    } else {
        None
    };

    Ok(Some(AggregatePushdownSpec {
        client: table.client.clone(),
        group_plans: compiled_group_exprs
            .iter()
            .map(|group| AggregateGroupPlan {
                data_type: group.data_type.clone(),
            })
            .collect(),
        seed_job: seed_job.as_ref().map(|(job, _)| job.clone()),
        aggregate_jobs: combine_aggregate_jobs(aggregate_exprs),
        diagnostics: AggregatePushdownDiagnostics {
            grouped: !compiled_group_exprs.is_empty(),
            seed_job: seed_job.map(|(_, diagnostics)| diagnostics),
            aggregate_jobs: aggregate_diagnostics,
        },
        schema: Arc::new(schema.as_arrow().clone()),
    }))
}

pub(crate) fn build_aggregate_reduce_job(
    table: &KvTable,
    filters: &[Expr],
    group_exprs: &[CompiledGroupExpr],
    aggr_expr: Option<&Expr>,
    data_type: Option<DataType>,
) -> DataFusionResult<
    Option<(
        AggregateReduceJob,
        AccessPathDiagnostics,
        Option<AggregateOutputPlan>,
    )>,
> {
    let predicate = QueryPredicate::from_filters(filters, &table.model);
    let required_projection =
        match reduce_job_required_projection(group_exprs, aggr_expr, &table.model) {
            Ok(required_projection) => required_projection,
            Err(_) => return Ok(None),
        };
    let projection = Some(required_projection);
    let access_plan = ScanAccessPlan::new(&table.model, &projection, &predicate);
    let Some((ranges, access_path, constrained_prefix_len, exact)) =
        choose_aggregate_access_path(table, &predicate, &access_plan)?
    else {
        return Ok(None);
    };
    let Some(group_by) =
        compile_group_exprs(group_exprs, &table.model, &table.index_specs, &access_path)
    else {
        return Ok(None);
    };
    let (reducers, output) = match (aggr_expr, data_type) {
        (Some(expr), Some(data_type)) => match compile_aggregate_expr(
            expr,
            &table.model,
            &table.index_specs,
            &access_path,
            0,
            data_type,
        ) {
            Ok((reducers, output)) => (reducers, Some(output)),
            Err(_) => return Ok(None),
        },
        (None, None) => (Vec::new(), None),
        _ => {
            return Err(DataFusionError::Execution(
                "aggregate reduction job configuration mismatch".to_string(),
            ))
        }
    };
    let diagnostics = build_aggregate_access_path_diagnostics(
        &table.model,
        &table.index_specs,
        &predicate,
        &access_path,
        &ranges,
        constrained_prefix_len,
        exact,
    );
    let filter = if exact {
        None
    } else {
        compile_reduce_filter(&predicate, &table.model, &table.index_specs, &access_path)
    };
    if !exact && filter.is_none() {
        return Ok(None);
    }
    Ok(Some((
        AggregateReduceJob {
            request: RangeReduceRequest {
                reducers,
                group_by,
                filter,
            },
            ranges,
        },
        diagnostics,
        output,
    )))
}

pub(crate) fn choose_aggregate_access_path(
    table: &KvTable,
    predicate: &QueryPredicate,
    access_plan: &ScanAccessPlan,
) -> DataFusionResult<Option<ChosenAggregateAccessPath>> {
    Ok(Some(
        if let Some(index_plan) = predicate.choose_index_plan(&table.model, &table.index_specs)? {
            if !index_plan.ranges.is_empty()
                && access_plan.index_covers_required_non_pk(&table.index_specs[index_plan.spec_idx])
            {
                let exact = access_plan.predicate_fully_enforced_by_index_key(
                    &table.model,
                    &table.index_specs[index_plan.spec_idx],
                );
                (
                    index_plan.ranges,
                    AggregateAccessPath::SecondaryIndex {
                        spec_idx: index_plan.spec_idx,
                    },
                    Some(index_plan.constrained_prefix_len),
                    exact,
                )
            } else if access_plan.predicate_fully_enforced_by_primary_key(&table.model) {
                (
                    predicate.primary_key_ranges(&table.model)?,
                    AggregateAccessPath::PrimaryKey,
                    None,
                    true,
                )
            } else {
                return Ok(None);
            }
        } else if access_plan.predicate_fully_enforced_by_primary_key(&table.model) {
            (
                predicate.primary_key_ranges(&table.model)?,
                AggregateAccessPath::PrimaryKey,
                None,
                true,
            )
        } else {
            return Ok(None);
        },
    ))
}

pub(crate) fn reduce_job_required_projection(
    group_exprs: &[CompiledGroupExpr],
    aggr_expr: Option<&Expr>,
    model: &TableModel,
) -> DataFusionResult<Vec<usize>> {
    let mut cols = group_exprs
        .iter()
        .flat_map(|group| {
            let mut cols = Vec::new();
            group.expr.collect_columns(&mut cols);
            cols
        })
        .collect::<Vec<_>>();
    if let Some(expr) = aggr_expr {
        aggregate_argument_columns(expr, model, &mut cols)?;
    }
    cols.sort_unstable();
    cols.dedup();
    Ok(cols)
}

pub(crate) fn compile_group_exprs(
    group_exprs: &[CompiledGroupExpr],
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
    access_path: &AggregateAccessPath,
) -> Option<Vec<KvExpr>> {
    group_exprs
        .iter()
        .map(|group| compile_reduce_expr(&group.expr, model, index_specs, access_path))
        .collect()
}

pub(crate) fn compile_aggregate_expr(
    expr: &Expr,
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
    access_path: &AggregateAccessPath,
    next_reducer_idx: usize,
    data_type: DataType,
) -> DataFusionResult<(Vec<RangeReducerSpec>, AggregateOutputPlan)> {
    let normalized = normalize_aggregate_expr(expr, model)?;
    match (normalized.func, normalized.argument) {
        (AggregatePushdownFunction::Count, AggregatePushdownArgument::CountAll) => Ok((
            vec![RangeReducerSpec {
                op: RangeReduceOp::CountAll,
                expr: None,
            }],
            AggregateOutputPlan::Direct {
                reducer_idx: next_reducer_idx,
                data_type,
            },
        )),
        (func, AggregatePushdownArgument::Expr(value_expr)) => {
            let compiled_expr = compile_reduce_expr(&value_expr, model, index_specs, access_path)
                .ok_or_else(|| {
                DataFusionError::Execution(
                    "aggregate argument is not available from pushdown access path".to_string(),
                )
            })?;
            match func {
                AggregatePushdownFunction::Count => Ok((
                    vec![RangeReducerSpec {
                        op: RangeReduceOp::CountField,
                        expr: Some(compiled_expr),
                    }],
                    AggregateOutputPlan::Direct {
                        reducer_idx: next_reducer_idx,
                        data_type,
                    },
                )),
                AggregatePushdownFunction::Sum => Ok((
                    vec![RangeReducerSpec {
                        op: RangeReduceOp::SumField,
                        expr: Some(compiled_expr),
                    }],
                    AggregateOutputPlan::Direct {
                        reducer_idx: next_reducer_idx,
                        data_type,
                    },
                )),
                AggregatePushdownFunction::Min => Ok((
                    vec![RangeReducerSpec {
                        op: RangeReduceOp::MinField,
                        expr: Some(compiled_expr),
                    }],
                    AggregateOutputPlan::Direct {
                        reducer_idx: next_reducer_idx,
                        data_type,
                    },
                )),
                AggregatePushdownFunction::Max => Ok((
                    vec![RangeReducerSpec {
                        op: RangeReduceOp::MaxField,
                        expr: Some(compiled_expr),
                    }],
                    AggregateOutputPlan::Direct {
                        reducer_idx: next_reducer_idx,
                        data_type,
                    },
                )),
                AggregatePushdownFunction::Avg => Ok((
                    vec![
                        RangeReducerSpec {
                            op: RangeReduceOp::SumField,
                            expr: Some(compiled_expr.clone()),
                        },
                        RangeReducerSpec {
                            op: RangeReduceOp::CountField,
                            expr: Some(compiled_expr),
                        },
                    ],
                    AggregateOutputPlan::Avg {
                        sum_idx: next_reducer_idx,
                        count_idx: next_reducer_idx + 1,
                        data_type,
                    },
                )),
            }
        }
        (_, AggregatePushdownArgument::CountAll) => Err(DataFusionError::Execution(
            "aggregate pushdown normalized unsupported count-all aggregate".to_string(),
        )),
    }
}

pub(crate) fn strip_alias_expr(expr: &Expr) -> &Expr {
    if let Expr::Alias(alias) = expr {
        return strip_alias_expr(&alias.expr);
    }
    expr
}

pub(crate) fn aggregate_expr_filter(
    expr: &Expr,
    model: &TableModel,
) -> DataFusionResult<Option<Expr>> {
    Ok(normalize_aggregate_expr(expr, model)?.filter)
}

pub(crate) fn aggregate_argument_columns(
    expr: &Expr,
    model: &TableModel,
    out: &mut Vec<usize>,
) -> DataFusionResult<()> {
    match normalize_aggregate_expr(expr, model)?.argument {
        AggregatePushdownArgument::CountAll => {}
        AggregatePushdownArgument::Expr(expr) => expr.collect_columns(out),
    }
    Ok(())
}

pub(crate) fn compile_reduce_filter(
    predicate: &QueryPredicate,
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
    access_path: &AggregateAccessPath,
) -> Option<KvPredicate> {
    if predicate.contradiction {
        return Some(KvPredicate {
            checks: Vec::new(),
            contradiction: true,
        });
    }
    let mut cols = predicate.constraints.keys().copied().collect::<Vec<_>>();
    cols.sort_unstable();
    let mut checks = Vec::with_capacity(cols.len());
    for col_idx in cols {
        checks.push(KvPredicateCheck {
            field: aggregate_field_ref(col_idx, model, index_specs, access_path)?,
            constraint: compile_kv_predicate_constraint(predicate.constraints.get(&col_idx)?)?,
        });
    }
    Some(KvPredicate {
        checks,
        contradiction: false,
    })
}

pub(crate) fn compile_kv_predicate_constraint(
    constraint: &PredicateConstraint,
) -> Option<KvPredicateConstraint> {
    Some(match constraint {
        PredicateConstraint::StringEq(value) => KvPredicateConstraint::StringEq(value.clone()),
        PredicateConstraint::BoolEq(value) => KvPredicateConstraint::BoolEq(*value),
        PredicateConstraint::FixedBinaryEq(value) => {
            KvPredicateConstraint::FixedSizeBinaryEq(value.clone())
        }
        PredicateConstraint::IntRange { min, max } => KvPredicateConstraint::IntRange {
            min: *min,
            max: *max,
        },
        PredicateConstraint::UInt64Range { min, max } => KvPredicateConstraint::UInt64Range {
            min: *min,
            max: *max,
        },
        PredicateConstraint::FloatRange { min, max } => KvPredicateConstraint::FloatRange {
            min: *min,
            max: *max,
        },
        PredicateConstraint::Decimal128Range { min, max } => {
            KvPredicateConstraint::Decimal128Range {
                min: *min,
                max: *max,
            }
        }
        PredicateConstraint::IsNull => KvPredicateConstraint::IsNull,
        PredicateConstraint::IsNotNull => KvPredicateConstraint::IsNotNull,
        PredicateConstraint::StringIn(values) => KvPredicateConstraint::StringIn(values.clone()),
        PredicateConstraint::IntIn(values) => KvPredicateConstraint::IntIn(values.clone()),
        PredicateConstraint::UInt64In(values) => KvPredicateConstraint::UInt64In(values.clone()),
        PredicateConstraint::FixedBinaryIn(values) => {
            KvPredicateConstraint::FixedSizeBinaryIn(values.clone())
        }
        PredicateConstraint::Decimal256Range { min, max } => {
            KvPredicateConstraint::Decimal256Range {
                min: min.map(|v| v.to_le_bytes()),
                max: max.map(|v| v.to_le_bytes()),
            }
        }
    })
}

#[allow(deprecated)]
pub(crate) fn is_count_rows_arg(expr: &Expr) -> bool {
    matches!(expr, Expr::Wildcard { .. })
        || matches!(
            strip_aggregate_argument_expr(expr),
            Expr::Literal(value, _) if !value.is_null()
        )
}

pub(crate) fn strip_aggregate_argument_expr(expr: &Expr) -> &Expr {
    match expr {
        Expr::Alias(alias) => strip_aggregate_argument_expr(&alias.expr),
        Expr::Cast(cast) => strip_aggregate_argument_expr(&cast.expr),
        Expr::TryCast(cast) => strip_aggregate_argument_expr(&cast.expr),
        other => other,
    }
}

pub(crate) fn compile_pushdown_value_expr(
    expr: &Expr,
    model: &TableModel,
) -> DataFusionResult<(PushdownValueExpr, KvFieldKind)> {
    match strip_aggregate_argument_expr(expr) {
        Expr::Column(column) => {
            let Some(&col_idx) = model.columns_by_name.get(&column.name) else {
                return Err(DataFusionError::Execution(format!(
                    "unknown pushdown expression column '{}'",
                    column.name
                )));
            };
            let kind = kv_field_kind(model.column(col_idx).kind).ok_or_else(|| {
                DataFusionError::Execution(format!(
                    "pushdown expression does not support column '{}'",
                    column.name
                ))
            })?;
            Ok((PushdownValueExpr::Column(col_idx), kind))
        }
        Expr::Literal(value, _) => scalar_to_reduced_literal(value)
            .ok_or_else(|| {
                DataFusionError::Execution("unsupported pushdown expression literal".to_string())
            })
            .map(|(value, kind)| (PushdownValueExpr::Literal(value), kind)),
        Expr::BinaryExpr(binary) if binary.op == Operator::Plus => {
            let (left, left_kind) = compile_pushdown_value_expr(binary.left.as_ref(), model)?;
            let (right, right_kind) = compile_pushdown_value_expr(binary.right.as_ref(), model)?;
            let kind = infer_pushdown_add_sub_kind(left_kind, right_kind, "addition")?;
            Ok((
                PushdownValueExpr::Add(Box::new(left), Box::new(right)),
                kind,
            ))
        }
        Expr::BinaryExpr(binary) if binary.op == Operator::Minus => {
            let (left, left_kind) = compile_pushdown_value_expr(binary.left.as_ref(), model)?;
            let (right, right_kind) = compile_pushdown_value_expr(binary.right.as_ref(), model)?;
            let kind = infer_pushdown_add_sub_kind(left_kind, right_kind, "subtraction")?;
            Ok((
                PushdownValueExpr::Sub(Box::new(left), Box::new(right)),
                kind,
            ))
        }
        Expr::BinaryExpr(binary) if binary.op == Operator::Multiply => {
            let (left, left_kind) = compile_pushdown_value_expr(binary.left.as_ref(), model)?;
            let (right, right_kind) = compile_pushdown_value_expr(binary.right.as_ref(), model)?;
            let kind = infer_pushdown_mul_kind(left_kind, right_kind)?;
            Ok((
                PushdownValueExpr::Mul(Box::new(left), Box::new(right)),
                kind,
            ))
        }
        Expr::BinaryExpr(binary) if binary.op == Operator::Divide => {
            let (left, left_kind) = compile_pushdown_value_expr(binary.left.as_ref(), model)?;
            let (right, right_kind) = compile_pushdown_value_expr(binary.right.as_ref(), model)?;
            ensure_pushdown_divisor_supported(&right)?;
            let kind = infer_pushdown_div_kind(left_kind, right_kind)?;
            Ok((
                PushdownValueExpr::Div(Box::new(left), Box::new(right)),
                kind,
            ))
        }
        Expr::ScalarFunction(func) => compile_pushdown_scalar_function(func, model),
        _ => Err(DataFusionError::Execution(
            "pushdown expression shape is unsupported".to_string(),
        )),
    }
}

pub(crate) fn compile_pushdown_scalar_function(
    func: &datafusion::logical_expr::expr::ScalarFunction,
    model: &TableModel,
) -> DataFusionResult<(PushdownValueExpr, KvFieldKind)> {
    let func_name = func.name().to_ascii_lowercase();
    match func_name.as_str() {
        "lower" => {
            if func.args.len() != 1 {
                return Err(DataFusionError::Execution(
                    "lower() pushdown requires exactly one argument".to_string(),
                ));
            }
            let (inner, kind) = compile_pushdown_value_expr(&func.args[0], model)?;
            if kind != KvFieldKind::Utf8 {
                return Err(DataFusionError::Execution(
                    "lower() pushdown requires Utf8 input".to_string(),
                ));
            }
            Ok((PushdownValueExpr::Lower(Box::new(inner)), KvFieldKind::Utf8))
        }
        "date_trunc" => {
            if func.args.len() != 2 {
                return Err(DataFusionError::Execution(
                    "date_trunc() pushdown requires exactly two arguments".to_string(),
                ));
            }
            let unit = extract_pushdown_string_literal(&func.args[0]).ok_or_else(|| {
                DataFusionError::Execution(
                    "date_trunc() pushdown requires a string literal unit".to_string(),
                )
            })?;
            if !unit.eq_ignore_ascii_case("day") {
                return Err(DataFusionError::Execution(
                    "date_trunc() pushdown only supports 'day'".to_string(),
                ));
            }
            let (inner, kind) = compile_pushdown_value_expr(&func.args[1], model)?;
            if !matches!(
                kind,
                KvFieldKind::Date32 | KvFieldKind::Date64 | KvFieldKind::Timestamp
            ) {
                return Err(DataFusionError::Execution(
                    "date_trunc('day', ...) pushdown requires Date32/Date64/Timestamp input"
                        .to_string(),
                ));
            }
            Ok((PushdownValueExpr::DateTruncDay(Box::new(inner)), kind))
        }
        _ => Err(DataFusionError::Execution(format!(
            "pushdown expression does not support function '{func_name}'"
        ))),
    }
}

pub(crate) fn infer_pushdown_mul_kind(
    left: KvFieldKind,
    right: KvFieldKind,
) -> DataFusionResult<KvFieldKind> {
    match (left, right) {
        (KvFieldKind::Int64, KvFieldKind::Int64) => Ok(KvFieldKind::Int64),
        (KvFieldKind::UInt64, KvFieldKind::UInt64) => Ok(KvFieldKind::UInt64),
        (KvFieldKind::Float64, KvFieldKind::Float64)
        | (KvFieldKind::Float64, KvFieldKind::Int64)
        | (KvFieldKind::Int64, KvFieldKind::Float64)
        | (KvFieldKind::Float64, KvFieldKind::UInt64)
        | (KvFieldKind::UInt64, KvFieldKind::Float64) => Ok(KvFieldKind::Float64),
        _ => Err(DataFusionError::Execution(
            "pushdown multiplication only supports Int64, UInt64, and Float64".to_string(),
        )),
    }
}

pub(crate) fn infer_pushdown_add_sub_kind(
    left: KvFieldKind,
    right: KvFieldKind,
    op_name: &str,
) -> DataFusionResult<KvFieldKind> {
    match (left, right) {
        (KvFieldKind::Int64, KvFieldKind::Int64) => Ok(KvFieldKind::Int64),
        (KvFieldKind::UInt64, KvFieldKind::UInt64) => Ok(KvFieldKind::UInt64),
        (KvFieldKind::Float64, KvFieldKind::Float64)
        | (KvFieldKind::Float64, KvFieldKind::Int64)
        | (KvFieldKind::Int64, KvFieldKind::Float64)
        | (KvFieldKind::Float64, KvFieldKind::UInt64)
        | (KvFieldKind::UInt64, KvFieldKind::Float64) => Ok(KvFieldKind::Float64),
        _ => Err(DataFusionError::Execution(format!(
            "pushdown {op_name} only supports Int64, UInt64, and Float64"
        ))),
    }
}

pub(crate) fn infer_pushdown_div_kind(
    left: KvFieldKind,
    right: KvFieldKind,
) -> DataFusionResult<KvFieldKind> {
    match (left, right) {
        (KvFieldKind::Int64, KvFieldKind::Int64)
        | (KvFieldKind::UInt64, KvFieldKind::UInt64)
        | (KvFieldKind::Float64, KvFieldKind::Float64)
        | (KvFieldKind::Float64, KvFieldKind::Int64)
        | (KvFieldKind::Int64, KvFieldKind::Float64)
        | (KvFieldKind::Float64, KvFieldKind::UInt64)
        | (KvFieldKind::UInt64, KvFieldKind::Float64) => Ok(KvFieldKind::Float64),
        _ => Err(DataFusionError::Execution(
            "pushdown division only supports Int64, UInt64, and Float64".to_string(),
        )),
    }
}

pub(crate) fn ensure_pushdown_divisor_supported(expr: &PushdownValueExpr) -> DataFusionResult<()> {
    match expr {
        PushdownValueExpr::Literal(KvReducedValue::Int64(v)) if *v != 0 => Ok(()),
        PushdownValueExpr::Literal(KvReducedValue::UInt64(v)) if *v != 0 => Ok(()),
        PushdownValueExpr::Literal(KvReducedValue::Float64(v)) if *v != 0.0 => Ok(()),
        PushdownValueExpr::Literal(_) => Err(DataFusionError::Execution(
            "pushdown division does not support a zero literal divisor".to_string(),
        )),
        _ => Err(DataFusionError::Execution(
            "pushdown division requires a non-zero literal divisor".to_string(),
        )),
    }
}

pub(crate) fn scalar_to_reduced_literal(
    value: &ScalarValue,
) -> Option<(KvReducedValue, KvFieldKind)> {
    scalar_to_i64(value)
        .map(|v| (KvReducedValue::Int64(v), KvFieldKind::Int64))
        .or_else(|| scalar_to_u64(value).map(|v| (KvReducedValue::UInt64(v), KvFieldKind::UInt64)))
        .or_else(|| {
            scalar_to_f64(value).map(|v| (KvReducedValue::Float64(v), KvFieldKind::Float64))
        })
        .or_else(|| scalar_to_string(value).map(|v| (KvReducedValue::Utf8(v), KvFieldKind::Utf8)))
        .or_else(|| {
            scalar_to_date32_i64(value)
                .and_then(|v| i32::try_from(v).ok())
                .map(|v| (KvReducedValue::Date32(v), KvFieldKind::Date32))
        })
        .or_else(|| {
            scalar_to_date64(value).map(|v| (KvReducedValue::Date64(v), KvFieldKind::Date64))
        })
        .or_else(|| {
            scalar_to_timestamp_micros(value)
                .map(|v| (KvReducedValue::Timestamp(v), KvFieldKind::Timestamp))
        })
}

pub(crate) fn extract_pushdown_string_literal(expr: &Expr) -> Option<String> {
    match strip_aggregate_argument_expr(expr) {
        Expr::Literal(value, _) => scalar_to_string(value),
        _ => None,
    }
}

pub(crate) fn normalize_aggregate_expr(
    expr: &Expr,
    model: &TableModel,
) -> DataFusionResult<NormalizedAggregateExpr> {
    let expr = strip_alias_expr(expr);
    let Expr::AggregateFunction(agg) = expr else {
        return Err(DataFusionError::Execution(
            "aggregate pushdown only supports aggregate-function expressions".to_string(),
        ));
    };
    if agg.params.distinct || !agg.params.order_by.is_empty() {
        return Err(DataFusionError::Execution(
            "aggregate pushdown does not support DISTINCT/ORDER BY".to_string(),
        ));
    }
    if agg.params.args.len() != 1 {
        return Err(DataFusionError::Execution(
            "aggregate pushdown requires exactly one aggregate argument".to_string(),
        ));
    }

    let explicit_filter = agg
        .params
        .filter
        .as_ref()
        .map(|filter| strip_alias_expr(filter.as_ref()).clone());
    let (func, argument, case_filter) = match agg.func.name().to_ascii_lowercase().as_str() {
        "count" => normalize_count_aggregate_argument(&agg.params.args[0], model)?,
        "sum" => normalize_sum_aggregate_argument(&agg.params.args[0], model)?,
        "min" => normalize_column_or_case_aggregate(
            AggregatePushdownFunction::Min,
            &agg.params.args[0],
            model,
        )?,
        "max" => normalize_column_or_case_aggregate(
            AggregatePushdownFunction::Max,
            &agg.params.args[0],
            model,
        )?,
        "avg" => normalize_column_or_case_aggregate(
            AggregatePushdownFunction::Avg,
            &agg.params.args[0],
            model,
        )?,
        func_name => {
            return Err(DataFusionError::Execution(format!(
                "aggregate pushdown does not support function '{func_name}'"
            )))
        }
    };

    Ok(NormalizedAggregateExpr {
        func,
        argument,
        filter: combine_optional_filters(explicit_filter, case_filter, Operator::And),
    })
}

pub(crate) fn normalize_count_aggregate_argument(
    arg: &Expr,
    model: &TableModel,
) -> DataFusionResult<(
    AggregatePushdownFunction,
    AggregatePushdownArgument,
    Option<Expr>,
)> {
    if is_count_rows_arg(arg) {
        return Ok((
            AggregatePushdownFunction::Count,
            AggregatePushdownArgument::CountAll,
            None,
        ));
    }
    if let Some((argument, filter)) =
        normalize_case_aggregate_argument(AggregatePushdownFunction::Count, arg, model)?
    {
        return Ok((AggregatePushdownFunction::Count, argument, Some(filter)));
    }
    Ok((
        AggregatePushdownFunction::Count,
        AggregatePushdownArgument::Expr(compile_pushdown_value_expr(arg, model)?.0),
        None,
    ))
}

pub(crate) fn normalize_sum_aggregate_argument(
    arg: &Expr,
    model: &TableModel,
) -> DataFusionResult<(
    AggregatePushdownFunction,
    AggregatePushdownArgument,
    Option<Expr>,
)> {
    if let Some((argument, filter)) =
        normalize_case_aggregate_argument(AggregatePushdownFunction::Sum, arg, model)?
    {
        let func = if argument == AggregatePushdownArgument::CountAll {
            AggregatePushdownFunction::Count
        } else {
            AggregatePushdownFunction::Sum
        };
        return Ok((func, argument, Some(filter)));
    }
    Ok((
        AggregatePushdownFunction::Sum,
        AggregatePushdownArgument::Expr(compile_pushdown_value_expr(arg, model)?.0),
        None,
    ))
}

pub(crate) fn normalize_column_or_case_aggregate(
    func: AggregatePushdownFunction,
    arg: &Expr,
    model: &TableModel,
) -> DataFusionResult<(
    AggregatePushdownFunction,
    AggregatePushdownArgument,
    Option<Expr>,
)> {
    if let Some((argument, filter)) = normalize_case_aggregate_argument(func, arg, model)? {
        return Ok((func, argument, Some(filter)));
    }
    Ok((
        func,
        AggregatePushdownArgument::Expr(compile_pushdown_value_expr(arg, model)?.0),
        None,
    ))
}

pub(crate) fn normalize_case_aggregate_argument(
    func: AggregatePushdownFunction,
    arg: &Expr,
    model: &TableModel,
) -> DataFusionResult<Option<(AggregatePushdownArgument, Expr)>> {
    let Expr::Case(case) = strip_aggregate_argument_expr(arg) else {
        return Ok(None);
    };
    if case.when_then_expr.is_empty() {
        return Ok(None);
    }

    let mut argument = None;
    let mut filter = None;
    for (when_expr, then_expr) in &case.when_then_expr {
        let branch_argument = match normalize_case_then_expr(func, then_expr.as_ref(), model) {
            Ok(argument) => argument,
            Err(_) => return Ok(None),
        };
        if let Some(ref current) = argument {
            if current != &branch_argument {
                return Ok(None);
            }
        } else {
            argument = Some(branch_argument);
        }
        let branch_filter = build_case_branch_filter(case.expr.as_deref(), when_expr.as_ref());
        filter = combine_optional_filters(filter, Some(branch_filter), Operator::Or);
    }

    if !case_else_matches_case_aggregate(argument.as_ref(), case.else_expr.as_deref())? {
        return Ok(None);
    }

    match (argument, filter) {
        (Some(argument), Some(filter)) => Ok(Some((argument, filter))),
        _ => Ok(None),
    }
}

pub(crate) fn normalize_case_then_expr(
    func: AggregatePushdownFunction,
    expr: &Expr,
    model: &TableModel,
) -> DataFusionResult<AggregatePushdownArgument> {
    match func {
        AggregatePushdownFunction::Count => {
            if aggregate_non_null_literal(expr).is_some() {
                Ok(AggregatePushdownArgument::CountAll)
            } else if let Ok((compiled_expr, _)) = compile_pushdown_value_expr(expr, model) {
                Ok(AggregatePushdownArgument::Expr(compiled_expr))
            } else {
                Err(DataFusionError::Execution(
                    "count pushdown case branch must yield a supported expression or non-null literal"
                        .to_string(),
                ))
            }
        }
        AggregatePushdownFunction::Sum => {
            if is_integer_one_literal(expr) {
                Ok(AggregatePushdownArgument::CountAll)
            } else if let Ok((compiled_expr, _)) = compile_pushdown_value_expr(expr, model) {
                Ok(AggregatePushdownArgument::Expr(compiled_expr))
            } else {
                Err(DataFusionError::Execution(
                    "sum pushdown case branch must yield a supported expression or literal 1"
                        .to_string(),
                ))
            }
        }
        AggregatePushdownFunction::Min
        | AggregatePushdownFunction::Max
        | AggregatePushdownFunction::Avg => Ok(AggregatePushdownArgument::Expr(
            compile_pushdown_value_expr(expr, model)?.0,
        )),
    }
}

pub(crate) fn case_else_matches_case_aggregate(
    argument: Option<&AggregatePushdownArgument>,
    else_expr: Option<&Expr>,
) -> DataFusionResult<bool> {
    let Some(_argument) = argument else {
        return Ok(false);
    };
    let Some(else_expr) = else_expr else {
        return Ok(true);
    };
    if aggregate_literal(else_expr).is_some_and(ScalarValue::is_null) {
        return Ok(true);
    }
    Ok(false)
}

pub(crate) fn build_case_branch_filter(case_expr: Option<&Expr>, when_expr: &Expr) -> Expr {
    match case_expr {
        Some(base_expr) => Expr::BinaryExpr(datafusion::logical_expr::BinaryExpr {
            left: Box::new(strip_alias_expr(base_expr).clone()),
            op: Operator::Eq,
            right: Box::new(strip_alias_expr(when_expr).clone()),
        }),
        None => strip_alias_expr(when_expr).clone(),
    }
}

pub(crate) fn combine_optional_filters(
    left: Option<Expr>,
    right: Option<Expr>,
    op: Operator,
) -> Option<Expr> {
    match (left, right) {
        (Some(left), Some(right)) => Some(Expr::BinaryExpr(datafusion::logical_expr::BinaryExpr {
            left: Box::new(left),
            op,
            right: Box::new(right),
        })),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

pub(crate) fn aggregate_non_null_literal(expr: &Expr) -> Option<&ScalarValue> {
    aggregate_literal(expr).filter(|value| !value.is_null())
}

pub(crate) fn aggregate_literal(expr: &Expr) -> Option<&ScalarValue> {
    match strip_aggregate_argument_expr(expr) {
        Expr::Literal(value, _) => Some(value),
        _ => None,
    }
}

pub(crate) fn is_integer_one_literal(expr: &Expr) -> bool {
    aggregate_literal(expr).is_some_and(|value| {
        matches!(
            value,
            ScalarValue::Int8(Some(1))
                | ScalarValue::Int16(Some(1))
                | ScalarValue::Int32(Some(1))
                | ScalarValue::Int64(Some(1))
                | ScalarValue::UInt8(Some(1))
                | ScalarValue::UInt16(Some(1))
                | ScalarValue::UInt32(Some(1))
                | ScalarValue::UInt64(Some(1))
        )
    })
}

pub(crate) fn aggregate_field_ref(
    col_idx: usize,
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
    access_path: &AggregateAccessPath,
) -> Option<KvFieldRef> {
    match access_path {
        AggregateAccessPath::PrimaryKey => base_row_field_ref(col_idx, model),
        AggregateAccessPath::SecondaryIndex { spec_idx } => {
            index_row_field_ref(col_idx, model, &index_specs[*spec_idx])
        }
    }
}

pub(crate) fn compile_reduce_expr(
    expr: &PushdownValueExpr,
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
    access_path: &AggregateAccessPath,
) -> Option<KvExpr> {
    match expr {
        PushdownValueExpr::Column(col_idx) => {
            aggregate_field_ref(*col_idx, model, index_specs, access_path).map(KvExpr::Field)
        }
        PushdownValueExpr::Literal(value) => Some(KvExpr::Literal(value.clone())),
        PushdownValueExpr::Add(left, right) => Some(KvExpr::Add(
            Box::new(compile_reduce_expr(left, model, index_specs, access_path)?),
            Box::new(compile_reduce_expr(right, model, index_specs, access_path)?),
        )),
        PushdownValueExpr::Sub(left, right) => Some(KvExpr::Sub(
            Box::new(compile_reduce_expr(left, model, index_specs, access_path)?),
            Box::new(compile_reduce_expr(right, model, index_specs, access_path)?),
        )),
        PushdownValueExpr::Mul(left, right) => Some(KvExpr::Mul(
            Box::new(compile_reduce_expr(left, model, index_specs, access_path)?),
            Box::new(compile_reduce_expr(right, model, index_specs, access_path)?),
        )),
        PushdownValueExpr::Div(left, right) => Some(KvExpr::Div(
            Box::new(compile_reduce_expr(left, model, index_specs, access_path)?),
            Box::new(compile_reduce_expr(right, model, index_specs, access_path)?),
        )),
        PushdownValueExpr::Lower(inner) => Some(KvExpr::Lower(Box::new(compile_reduce_expr(
            inner,
            model,
            index_specs,
            access_path,
        )?))),
        PushdownValueExpr::DateTruncDay(inner) => Some(KvExpr::DateTruncDay(Box::new(
            compile_reduce_expr(inner, model, index_specs, access_path)?,
        ))),
    }
}

pub(crate) fn base_row_field_ref(col_idx: usize, model: &TableModel) -> Option<KvFieldRef> {
    if let Some(pk_pos) = model.pk_position(col_idx) {
        let bit_offset = PRIMARY_KEY_BIT_OFFSET
            + model.primary_key_kinds[..pk_pos]
                .iter()
                .map(|kind| kind.key_width() * 8)
                .sum::<usize>();
        Some(KvFieldRef::Key {
            bit_offset: u16::try_from(bit_offset).ok()?,
            kind: kv_field_kind(model.column(col_idx).kind)?,
        })
    } else {
        Some(KvFieldRef::Value {
            index: u16::try_from(col_idx).ok()?,
            kind: kv_field_kind(model.column(col_idx).kind)?,
            nullable: model.column(col_idx).nullable,
        })
    }
}

pub(crate) fn pk_field_ref_for_secondary_index(
    pk_pos: usize,
    model: &TableModel,
    spec: &ResolvedIndexSpec,
) -> Option<KvFieldRef> {
    let bit_offset = INDEX_KEY_BIT_OFFSET
        + spec.key_columns_width * 8
        + model.primary_key_kinds[..pk_pos]
            .iter()
            .map(|kind| kind.key_width() * 8)
            .sum::<usize>();
    Some(KvFieldRef::Key {
        bit_offset: u16::try_from(bit_offset).ok()?,
        kind: kv_field_kind(*model.primary_key_kinds.get(pk_pos)?)?,
    })
}

pub(crate) fn index_row_field_ref(
    col_idx: usize,
    model: &TableModel,
    spec: &ResolvedIndexSpec,
) -> Option<KvFieldRef> {
    if let Some(pos) = spec
        .key_columns
        .iter()
        .position(|candidate| *candidate == col_idx)
    {
        return match spec.layout {
            IndexLayout::Lexicographic => {
                let bit_offset = INDEX_KEY_BIT_OFFSET
                    + spec.key_columns[..pos]
                        .iter()
                        .map(|idx| model.column(*idx).kind.key_width() * 8)
                        .sum::<usize>();
                Some(KvFieldRef::Key {
                    bit_offset: u16::try_from(bit_offset).ok()?,
                    kind: kv_field_kind(model.column(col_idx).kind)?,
                })
            }
            IndexLayout::ZOrder => Some(KvFieldRef::ZOrderKey {
                bit_offset: u16::try_from(INDEX_KEY_BIT_OFFSET).ok()?,
                field_position: u8::try_from(pos).ok()?,
                field_widths: spec
                    .key_columns
                    .iter()
                    .map(|idx| u8::try_from(model.column(*idx).kind.key_width()).ok())
                    .collect::<Option<Vec<_>>>()?,
                kind: kv_field_kind(model.column(col_idx).kind)?,
            }),
        };
    }
    if let Some(pk_pos) = model.pk_position(col_idx) {
        return pk_field_ref_for_secondary_index(pk_pos, model, spec);
    }
    if spec.value_column_mask[col_idx] {
        return Some(KvFieldRef::Value {
            index: u16::try_from(col_idx).ok()?,
            kind: kv_field_kind(model.column(col_idx).kind)?,
            nullable: model.column(col_idx).nullable,
        });
    }
    None
}

pub(crate) fn kv_field_kind(kind: ColumnKind) -> Option<KvFieldKind> {
    match kind {
        ColumnKind::Int64 => Some(KvFieldKind::Int64),
        ColumnKind::UInt64 => Some(KvFieldKind::UInt64),
        ColumnKind::Float64 => Some(KvFieldKind::Float64),
        ColumnKind::Boolean => Some(KvFieldKind::Boolean),
        ColumnKind::Utf8 => Some(KvFieldKind::Utf8),
        ColumnKind::Date32 => Some(KvFieldKind::Date32),
        ColumnKind::Date64 => Some(KvFieldKind::Date64),
        ColumnKind::Timestamp => Some(KvFieldKind::Timestamp),
        ColumnKind::FixedSizeBinary(width) => Some(KvFieldKind::FixedSizeBinary(width as u8)),
        ColumnKind::Decimal128 => Some(KvFieldKind::Decimal128),
        ColumnKind::Decimal256 => Some(KvFieldKind::Decimal256),
        ColumnKind::List(_) => None,
    }
}
