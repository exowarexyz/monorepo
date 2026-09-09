use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use async_trait::async_trait;
use datafusion::arrow::array::new_empty_array;
use datafusion::arrow::datatypes::{i256, DataType, SchemaRef, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::catalog::Session;
use datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use datafusion::common::{DFSchemaRef, DataFusionError, Result as DataFusionResult, ScalarValue};
use datafusion::datasource::source_as_provider;
use datafusion::execution::context::{QueryPlanner, TaskContext};
use datafusion::functions_aggregate::{
    average::Avg,
    count::Count,
    min_max::{Max, Min},
    sum::Sum,
};
use datafusion::logical_expr::physical_planning_context::PhysicalPlanningContext;
use datafusion::logical_expr::utils::{conjunction, disjunction};
use datafusion::logical_expr::{
    Aggregate, Expr, ExprSchemable, Extension, LogicalPlan, Operator, UserDefinedLogicalNode,
    UserDefinedLogicalNodeCore,
};
use datafusion::optimizer::optimizer::OptimizerRule;
use datafusion::physical_expr::{EquivalenceProperties, Partitioning, PhysicalExpr};
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::{
    stream::RecordBatchStreamAdapter, DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties,
    SendableRecordBatchStream,
};
use datafusion::physical_planner::{DefaultPhysicalPlanner, ExtensionPlanner, PhysicalPlanner};
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
use exoware_sdk::{PrefixedStoreClient, SerializableReadSession};
use futures::TryStreamExt;

use crate::diagnostics::*;
use crate::filter::*;
use crate::predicate::*;
use crate::types::*;

#[cfg(test)]
#[path = "aggregate_tests.rs"]
mod tests;

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
    pub(crate) expr_plans: Vec<(usize, AggregateOutputPlan)>,
}

#[derive(Debug, Clone)]
pub(crate) struct AggregateGroupPlan {
    pub(crate) data_type: DataType,
}

#[derive(Debug, Clone)]
pub(crate) struct AggregatePushdownSpec {
    pub(crate) client: PrefixedStoreClient,
    pub(crate) group_plans: Vec<AggregateGroupPlan>,
    pub(crate) seed_job: Option<AggregateReduceJob>,
    pub(crate) aggregate_jobs: Vec<CombinedAggregateJob>,
    pub(crate) diagnostics: AggregatePushdownDiagnostics,
    pub(crate) schema: SchemaRef,
}

#[derive(Debug)]
pub(crate) struct KvAggregateExec {
    pub(crate) spec: AggregatePushdownSpec,
    pub(crate) properties: Arc<PlanProperties>,
}

impl KvAggregatePushdownRule {
    pub(crate) fn new() -> Self {
        Self
    }

    fn rewrite_with_limit(
        &self,
        plan: LogicalPlan,
        limited: bool,
    ) -> DataFusionResult<Transformed<LogicalPlan>> {
        // DataFusion only stops distinct aggregation early when the limit sits directly above it.
        let input_limited = matches!(plan, LogicalPlan::Limit(_)) && plan.fetch()?.is_some();
        plan.map_children(|input| self.rewrite_with_limit(input, input_limited))?
            .transform_data(|node| {
                if limited
                    && matches!(&node, LogicalPlan::Aggregate(aggregate) if aggregate.aggr_expr.is_empty())
                {
                    return Ok(Transformed::no(node));
                }
                self.try_rewrite_plan(node)
            })
    }

    pub(crate) fn try_rewrite_plan(
        &self,
        plan: LogicalPlan,
    ) -> DataFusionResult<Transformed<LogicalPlan>> {
        let LogicalPlan::Aggregate(aggregate) = plan else {
            return Ok(Transformed::no(plan));
        };

        let expressions = aggregate
            .group_expr
            .iter()
            .chain(&aggregate.aggr_expr)
            .cloned()
            .collect();
        let Ok(Some((scan, expressions))) = aggregate_scan_input(&aggregate.input, expressions)
        else {
            return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate)));
        };
        let (group_exprs, aggr_exprs) = expressions.split_at(aggregate.group_expr.len());
        let Ok(provider) = source_as_provider(&scan.source) else {
            return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate)));
        };
        let Some(kv_table) = provider.downcast_ref::<KvTable>() else {
            return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate)));
        };
        let Some(spec) = try_build_aggregate_pushdown_spec(
            kv_table,
            scan,
            group_exprs,
            aggr_exprs,
            &aggregate.schema,
        )?
        else {
            return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate)));
        };

        let plan = LogicalPlan::Extension(Extension {
            node: Arc::new(KvAggregateNode { aggregate, spec }),
        });
        Ok(Transformed::yes(plan))
    }
}

fn aggregate_scan_input(
    mut input: &LogicalPlan,
    mut expressions: Vec<Expr>,
) -> DataFusionResult<Option<(&datafusion::logical_expr::TableScan, Vec<Expr>)>> {
    loop {
        let (schema, replacements, next) = match input {
            LogicalPlan::TableScan(scan) if scan.fetch.is_none() => {
                return Ok(Some((scan, expressions)))
            }
            LogicalPlan::Projection(projection) => (
                &projection.schema,
                projection
                    .expr
                    .iter()
                    .map(|expr| strip_alias_expr(expr).clone())
                    .collect::<Vec<_>>(),
                projection.input.as_ref(),
            ),
            LogicalPlan::SubqueryAlias(alias) => (
                &alias.schema,
                alias
                    .input
                    .schema()
                    .columns()
                    .into_iter()
                    .map(Expr::Column)
                    .collect(),
                alias.input.as_ref(),
            ),
            _ => return Ok(None),
        };
        expressions = expressions
            .into_iter()
            .map(|expr| {
                Ok(expr
                    .transform_up(|expr| match expr {
                        Expr::Column(column) => Ok(Transformed::yes(
                            replacements[schema.index_of_column(&column)?].clone(),
                        )),
                        expr => Ok(Transformed::no(expr)),
                    })?
                    .data)
            })
            .collect::<DataFusionResult<_>>()?;
        input = next;
    }
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
        self.rewrite_with_limit(plan, false)
    }
}

#[derive(Debug, Clone)]
struct KvAggregateNode {
    // The original aggregate owns the output schema and logical identity of the compiled Store job
    aggregate: Aggregate,
    spec: AggregatePushdownSpec,
}

impl PartialEq for KvAggregateNode {
    fn eq(&self, other: &Self) -> bool {
        self.aggregate == other.aggregate
    }
}

impl Eq for KvAggregateNode {}

impl PartialOrd for KvAggregateNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.aggregate.partial_cmp(&other.aggregate)
    }
}

impl Hash for KvAggregateNode {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.aggregate.hash(state);
    }
}

impl UserDefinedLogicalNodeCore for KvAggregateNode {
    fn name(&self) -> &str {
        "KvAggregate"
    }

    fn inputs(&self) -> Vec<&LogicalPlan> {
        vec![]
    }

    fn schema(&self) -> &DFSchemaRef {
        &self.aggregate.schema
    }

    fn expressions(&self) -> Vec<Expr> {
        vec![]
    }

    fn fmt_for_explain(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KvAggregate: grouped={}", self.spec.diagnostics.grouped)
    }

    fn with_exprs_and_inputs(
        &self,
        exprs: Vec<Expr>,
        inputs: Vec<LogicalPlan>,
    ) -> DataFusionResult<Self> {
        if !exprs.is_empty() || !inputs.is_empty() {
            return Err(DataFusionError::Internal(
                "KvAggregate has no expressions or inputs".to_string(),
            ));
        }
        Ok(self.clone())
    }
}

/// Plans Store aggregates when composing a custom DataFusion physical planner.
#[derive(Debug, Default)]
pub struct KvAggregateExtensionPlanner;

#[async_trait]
impl ExtensionPlanner for KvAggregateExtensionPlanner {
    async fn plan_extension(
        &self,
        _planner: &dyn PhysicalPlanner,
        node: &dyn UserDefinedLogicalNode,
        _logical_inputs: &[&LogicalPlan],
        _physical_inputs: &[Arc<dyn ExecutionPlan>],
        _session: &dyn Session,
        _planning_ctx: &PhysicalPlanningContext,
    ) -> DataFusionResult<Option<Arc<dyn ExecutionPlan>>> {
        let Some(node) = node.as_any().downcast_ref::<KvAggregateNode>() else {
            return Ok(None);
        };
        Ok(Some(Arc::new(KvAggregateExec::new(node.spec.clone()))))
    }
}

#[derive(Debug)]
pub(crate) struct KvQueryPlanner;

#[async_trait]
impl QueryPlanner for KvQueryPlanner {
    async fn create_physical_plan(
        &self,
        plan: &LogicalPlan,
        session: &dyn Session,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        DefaultPhysicalPlanner::with_extension_planners(vec![Arc::new(KvAggregateExtensionPlanner)])
            .create_physical_plan(plan, session)
            .await
    }
}

impl KvAggregateExec {
    pub(crate) fn new(spec: AggregatePushdownSpec) -> Self {
        let properties = Arc::new(PlanProperties::new(
            EquivalenceProperties::new(spec.schema.clone()),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Bounded,
        ));
        Self { spec, properties }
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
            format_query_stats_explain(QueryStatsExplainSurface::RangeReduceDetail)
        )
    }
}

impl ExecutionPlan for KvAggregateExec {
    fn name(&self) -> &str {
        "KvAggregateExec"
    }

    fn properties(&self) -> &Arc<PlanProperties> {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![]
    }

    fn apply_expressions(
        &self,
        _f: &mut dyn FnMut(&Arc<dyn PhysicalExpr>) -> DataFusionResult<TreeNodeRecursion>,
    ) -> DataFusionResult<TreeNodeRecursion> {
        Ok(TreeNodeRecursion::Continue)
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

        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.schema(),
            futures::stream::once(execute_aggregate_pushdown(self.spec.clone())),
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
                        .wrapping_add_assign(value)
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
            ScalarValue::FixedSizeBinary(v.len() as i32, Some(v.to_vec())),
            data_type,
        )?,
        (_, None) => ScalarValue::try_new_null(data_type)?,
    })
}

pub(crate) fn cast_scalar_value(
    value: ScalarValue,
    data_type: &DataType,
) -> DataFusionResult<ScalarValue> {
    if value.data_type() == *data_type {
        return Ok(value);
    }
    value.cast_to(data_type)
}

#[derive(Debug, Clone)]
pub(crate) struct MergedGroupResponseState {
    pub(crate) group_values: Vec<Option<KvReducedValue>>,
    pub(crate) states: Vec<PartialAggregateState>,
}

#[derive(Debug, Clone)]
pub(crate) struct AggregateGroupOutput {
    pub(crate) group_values: Vec<Option<KvReducedValue>>,
    pub(crate) outputs: Vec<ScalarValue>,
}

impl AggregateGroupOutput {
    pub(crate) fn new(group_values: Vec<Option<KvReducedValue>>, defaults: &[ScalarValue]) -> Self {
        Self {
            group_values,
            outputs: defaults.to_vec(),
        }
    }
}

pub(crate) async fn execute_aggregate_pushdown(
    spec: AggregatePushdownSpec,
) -> DataFusionResult<RecordBatch> {
    let session = spec.client.create_session();
    let mut defaults = vec![
        ScalarValue::Null;
        spec.aggregate_jobs
            .iter()
            .map(|job| job.expr_plans.len())
            .sum()
    ];
    for combined_job in &spec.aggregate_jobs {
        for (output_idx, expr_plan) in &combined_job.expr_plans {
            defaults[*output_idx] =
                finalize_aggregate_output(expr_plan, None, &combined_job.job.request.reducers)?;
        }
    }
    let mut groups = BTreeMap::<Vec<u8>, AggregateGroupOutput>::new();
    if spec.group_plans.is_empty() {
        groups.insert(Vec::new(), AggregateGroupOutput::new(Vec::new(), &defaults));
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
            groups
                .entry(key)
                .or_insert_with(|| AggregateGroupOutput::new(group.group_values, &defaults));
        }
    }

    for combined_job in &spec.aggregate_jobs {
        let response = execute_reduce_job(&session, &combined_job.job).await?;
        if spec.group_plans.is_empty() {
            if !response.groups.is_empty() {
                return Err(DataFusionError::Execution(
                    "scalar aggregate job returned grouped reductions".to_string(),
                ));
            }
            let group = groups.get_mut(&Vec::new()).ok_or_else(|| {
                DataFusionError::Execution("missing scalar aggregate output".to_string())
            })?;
            for (output_idx, expr_plan) in &combined_job.expr_plans {
                group.outputs[*output_idx] = finalize_aggregate_output(
                    expr_plan,
                    Some(&response.results),
                    &combined_job.job.request.reducers,
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
                    AggregateGroupOutput::new(group_response.group_values.clone(), &defaults)
                });
                for (output_idx, expr_plan) in &combined_job.expr_plans {
                    group.outputs[*output_idx] = finalize_aggregate_output(
                        expr_plan,
                        Some(&group_response.results),
                        &combined_job.job.request.reducers,
                    )?;
                }
            }
        }
    }

    let mut rows = Vec::new();
    for group in groups.into_values() {
        let mut row = Vec::with_capacity(spec.group_plans.len() + defaults.len());
        for (idx, group_plan) in spec.group_plans.iter().enumerate() {
            let value = group.group_values.get(idx).cloned().unwrap_or(None);
            row.push(reduced_value_to_scalar(value, &group_plan.data_type)?);
        }
        row.extend(group.outputs);
        rows.push(row);
    }

    build_aggregate_record_batch(rows, spec.schema)
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
            let values = session
                .range_reduce(&range.start, &range.end, &job.request)
                .await
                .map_err(|e| DataFusionError::External(Box::new(e)))?;
            if values.len() != states.len() {
                return Err(DataFusionError::Execution(
                    "range reduction response length mismatch".to_string(),
                ));
            }
            for ((state, reducer), partial) in states
                .iter_mut()
                .zip(job.request.reducers.iter())
                .zip(values.iter())
            {
                state.merge_partial(reducer.op, partial.as_ref())?;
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
        let mut responses = session
            .range_reduce_stream(&range.start, &range.end, &job.request)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
        while let Some(response) = responses
            .try_next()
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?
        {
            let archived = to_domain_reduce_response(response.view()).map_err(|e| {
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
    results: Option<&[RangeReduceResult]>,
    reducers: &[RangeReducerSpec],
) -> DataFusionResult<ScalarValue> {
    match output {
        AggregateOutputPlan::Direct {
            reducer_idx,
            data_type,
        } => match results {
            Some(results) => {
                reduced_value_to_scalar(results[*reducer_idx].value.clone(), data_type)
            }
            None if matches!(
                reducers[*reducer_idx].op,
                RangeReduceOp::CountAll | RangeReduceOp::CountField
            ) =>
            {
                ScalarValue::new_zero(data_type)
            }
            None => ScalarValue::try_new_null(data_type),
        },
        AggregateOutputPlan::Avg {
            sum_idx,
            count_idx,
            data_type,
        } => {
            let Some(results) = results else {
                return ScalarValue::try_new_null(data_type);
            };
            let Some(KvReducedValue::UInt64(count)) = &results[*count_idx].value else {
                return Err(DataFusionError::Execution(
                    "avg count reducer returned non-UInt64 value".to_string(),
                ));
            };
            if *count == 0 {
                return ScalarValue::try_new_null(data_type);
            }
            let sum = match &results[*sum_idx].value {
                Some(KvReducedValue::Int64(value)) => *value as f64,
                Some(KvReducedValue::UInt64(value)) => *value as f64,
                Some(KvReducedValue::Float64(value)) => *value,
                _ => {
                    return Err(DataFusionError::Execution(
                        "unsupported avg input type for pushdown".to_string(),
                    ))
                }
            };
            cast_scalar_value(ScalarValue::Float64(Some(sum / *count as f64)), data_type)
        }
    }
}

pub(crate) fn build_aggregate_record_batch(
    rows: Vec<Vec<ScalarValue>>,
    schema: SchemaRef,
) -> DataFusionResult<RecordBatch> {
    let mut arrays = Vec::with_capacity(schema.fields().len());
    for (idx, field) in schema.fields().iter().enumerate() {
        if rows.is_empty() {
            arrays.push(new_empty_array(field.data_type()));
        } else {
            let values = rows.iter().map(|row| row[idx].clone());
            arrays.push(ScalarValue::iter_to_array(values)?);
        }
    }
    RecordBatch::try_new(schema, arrays).map_err(Into::into)
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
    for (output_idx, expr) in exprs.into_iter().enumerate() {
        if let Some(existing) = combined.iter_mut().find(|candidate| {
            candidate.job.ranges == expr.job.ranges
                && candidate.job.request.group_by == expr.job.request.group_by
                && candidate.job.request.filter == expr.job.request.filter
        }) {
            let offset = existing.job.request.reducers.len();
            let rebased_output = rebase_output_plan(expr.output, offset);
            existing
                .job
                .request
                .reducers
                .extend(expr.job.request.reducers);
            existing.expr_plans.push((output_idx, rebased_output));
        } else {
            combined.push(CombinedAggregateJob {
                job: expr.job,
                expr_plans: vec![(output_idx, expr.output)],
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
    let mut has_unfiltered_aggregate = false;
    for (expr_idx, expr) in aggr_exprs.iter().enumerate() {
        let data_type = schema
            .field(group_exprs.len() + expr_idx)
            .data_type()
            .clone();
        let normalized = match normalize_aggregate_expr(expr, &table.model) {
            Ok(normalized) => normalized,
            Err(_) => return Ok(None),
        };
        has_unfiltered_aggregate |= normalized.filter.is_none();
        let mut filters = scan.filters.clone();
        if let Some(filter) = &normalized.filter {
            if !QueryPredicate::supports_filter(filter, &table.model) {
                return Ok(None);
            }
            filters.push(filter.clone());
        }
        let Some((job, diagnostics, output)) = build_aggregate_reduce_job(
            table,
            &filters,
            &compiled_group_exprs,
            Some(&normalized),
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

    if aggregate_exprs.is_empty() && compiled_group_exprs.is_empty() {
        return Ok(None);
    }

    let seed_job = if !compiled_group_exprs.is_empty() && !has_unfiltered_aggregate {
        let Some((job, diagnostics, _)) =
            build_aggregate_reduce_job(table, &scan.filters, &compiled_group_exprs, None, None)?
        else {
            return Ok(None);
        };
        Some((job, diagnostics))
    } else {
        None
    };

    let aggregate_jobs = combine_aggregate_jobs(aggregate_exprs);
    let aggregate_diagnostics = aggregate_jobs
        .iter()
        .map(|job| aggregate_diagnostics[job.expr_plans[0].0].clone())
        .collect();
    Ok(Some(AggregatePushdownSpec {
        client: table.client.clone(),
        group_plans: compiled_group_exprs
            .iter()
            .map(|group| AggregateGroupPlan {
                data_type: group.data_type.clone(),
            })
            .collect(),
        seed_job: seed_job.as_ref().map(|(job, _)| job.clone()),
        aggregate_jobs,
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
    aggr_expr: Option<&NormalizedAggregateExpr>,
    data_type: Option<DataType>,
) -> DataFusionResult<
    Option<(
        AggregateReduceJob,
        AccessPathDiagnostics,
        Option<AggregateOutputPlan>,
    )>,
> {
    if !filters
        .iter()
        .all(|filter| QueryPredicate::supports_filter(filter, &table.model))
    {
        return Ok(None);
    }
    let predicate = QueryPredicate::from_filters(filters, &table.model);
    let required_projection = reduce_job_required_projection(group_exprs, aggr_expr);
    let projection = Some(required_projection);
    let access_plan = ScanAccessPlan::new(&table.model, &projection, &predicate);
    let Some((ranges, access_path, constrained_prefix_len)) =
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
    let filter = if filters.is_empty() {
        None
    } else {
        let Some(filter) =
            compile_reduce_filter(&predicate, &table.model, &table.index_specs, &access_path)
        else {
            return Ok(None);
        };
        Some(filter)
    };
    let diagnostics = build_aggregate_access_path_diagnostics(
        &table.model,
        &table.index_specs,
        &predicate,
        &access_path,
        &ranges,
        constrained_prefix_len,
        filter.is_none(),
    );
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
    if let Some(index_plan) =
        predicate.choose_index_plan(&table.model, &table.index_specs, access_plan)?
    {
        if !index_plan.ranges.is_empty()
            && access_plan.index_covers_required_non_pk(&table.index_specs[index_plan.spec_idx])
        {
            return Ok(Some((
                index_plan.ranges,
                AggregateAccessPath::SecondaryIndex {
                    spec_idx: index_plan.spec_idx,
                },
                Some(index_plan.constrained_prefix_len),
            )));
        }
    }
    Ok(Some((
        predicate.primary_key_ranges(
            &table.model,
            table.client.key_prefix().max_logical_key_len(),
        )?,
        AggregateAccessPath::PrimaryKey,
        None,
    )))
}

pub(crate) fn reduce_job_required_projection(
    group_exprs: &[CompiledGroupExpr],
    aggr_expr: Option<&NormalizedAggregateExpr>,
) -> Vec<usize> {
    let mut cols = group_exprs
        .iter()
        .flat_map(|group| {
            let mut cols = Vec::new();
            group.expr.collect_columns(&mut cols);
            cols
        })
        .collect::<Vec<_>>();
    if let Some(expr) = aggr_expr {
        if let AggregatePushdownArgument::Expr(argument) = &expr.argument {
            argument.collect_columns(&mut cols);
        }
    }
    cols.sort_unstable();
    cols.dedup();
    cols
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
    normalized: &NormalizedAggregateExpr,
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
    access_path: &AggregateAccessPath,
    next_reducer_idx: usize,
    data_type: DataType,
) -> DataFusionResult<(Vec<RangeReducerSpec>, AggregateOutputPlan)> {
    let expr = match &normalized.argument {
        AggregatePushdownArgument::CountAll => None,
        AggregatePushdownArgument::Expr(expr) => Some(
            compile_reduce_expr(expr, model, index_specs, access_path).ok_or_else(|| {
                DataFusionError::Execution(
                    "aggregate argument is unavailable from its access path".to_string(),
                )
            })?,
        ),
    };
    if normalized.func == AggregatePushdownFunction::Avg {
        if data_type != DataType::Float64 {
            return Err(DataFusionError::Execution(
                "Store AVG requires a Float64 result".to_string(),
            ));
        }
        return Ok((
            vec![
                RangeReducerSpec {
                    op: RangeReduceOp::SumField,
                    expr: expr.clone(),
                },
                RangeReducerSpec {
                    op: RangeReduceOp::CountField,
                    expr,
                },
            ],
            AggregateOutputPlan::Avg {
                sum_idx: next_reducer_idx,
                count_idx: next_reducer_idx + 1,
                data_type,
            },
        ));
    }
    let op = match normalized.func {
        AggregatePushdownFunction::Count if expr.is_none() => RangeReduceOp::CountAll,
        AggregatePushdownFunction::Count => RangeReduceOp::CountField,
        AggregatePushdownFunction::Sum => RangeReduceOp::SumField,
        AggregatePushdownFunction::Min => RangeReduceOp::MinField,
        AggregatePushdownFunction::Max => RangeReduceOp::MaxField,
        AggregatePushdownFunction::Avg => unreachable!(),
    };
    Ok((
        vec![RangeReducerSpec { op, expr }],
        AggregateOutputPlan::Direct {
            reducer_idx: next_reducer_idx,
            data_type,
        },
    ))
}

pub(crate) fn strip_alias_expr(expr: &Expr) -> &Expr {
    if let Expr::Alias(alias) = expr {
        return strip_alias_expr(&alias.expr);
    }
    expr
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
            KvPredicateConstraint::FixedSizeBinaryEq(value.clone().into())
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
        PredicateConstraint::FixedBinaryIn(values) => KvPredicateConstraint::FixedSizeBinaryIn(
            values.iter().cloned().map(Into::into).collect(),
        ),
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
            strip_alias_expr(expr),
            Expr::Literal(value, _) if !value.is_null()
        )
}

pub(crate) fn compile_pushdown_value_expr(
    expr: &Expr,
    model: &TableModel,
) -> DataFusionResult<(PushdownValueExpr, KvFieldKind)> {
    match strip_alias_expr(expr) {
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
        Expr::Cast(cast) => compile_pushdown_cast(&cast.expr, cast.field.data_type(), model),
        Expr::TryCast(cast) => compile_pushdown_cast(&cast.expr, cast.field.data_type(), model),
        Expr::ScalarFunction(func) => compile_pushdown_scalar_function(func, model),
        _ => Err(DataFusionError::Execution(
            "pushdown expression shape is unsupported".to_string(),
        )),
    }
}

#[derive(Debug)]
struct AggregateExprSchema<'a>(&'a TableModel);

impl datafusion::common::ExprSchema for AggregateExprSchema<'_> {
    fn field_from_column(
        &self,
        column: &datafusion::common::Column,
    ) -> DataFusionResult<&datafusion::arrow::datatypes::FieldRef> {
        let index = self.0.columns_by_name.get(&column.name).ok_or_else(|| {
            DataFusionError::Execution(format!("unknown aggregate column '{}'", column.name))
        })?;
        Ok(&self.0.schema.fields()[*index])
    }
}

fn compile_pushdown_cast(
    expr: &Expr,
    data_type: &DataType,
    model: &TableModel,
) -> DataFusionResult<(PushdownValueExpr, KvFieldKind)> {
    let (inner, kind) = compile_pushdown_value_expr(expr, model)?;
    let input_type = expr.get_type(&AggregateExprSchema(model))?;
    let identity = input_type == *data_type
        || match (&input_type, data_type) {
            (
                DataType::Decimal128(source_precision, source_scale),
                DataType::Decimal128(precision, scale),
            )
            | (
                DataType::Decimal256(source_precision, source_scale),
                DataType::Decimal256(precision, scale),
            ) => source_scale == scale && source_precision <= precision,
            // Arrow preserves raw values when the source already has a timezone
            (
                DataType::Timestamp(TimeUnit::Microsecond, Some(_)),
                DataType::Timestamp(TimeUnit::Microsecond, _),
            ) => true,
            _ => false,
        }
        || matches!(
            (kind, data_type),
            (
                KvFieldKind::Utf8,
                DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View
            )
        );
    if identity {
        return Ok((inner, kind));
    }
    if *data_type == DataType::Float64 && matches!(kind, KvFieldKind::Int64 | KvFieldKind::UInt64) {
        return Ok((
            PushdownValueExpr::Mul(
                Box::new(inner),
                Box::new(PushdownValueExpr::Literal(KvReducedValue::Float64(1.0))),
            ),
            KvFieldKind::Float64,
        ));
    }
    Err(DataFusionError::Execution(
        "pushdown cast changes an unsupported type or value".to_string(),
    ))
}

pub(crate) fn compile_pushdown_scalar_function(
    func: &datafusion::logical_expr::expr::ScalarFunction,
    model: &TableModel,
) -> DataFusionResult<(PushdownValueExpr, KvFieldKind)> {
    let func_name = func.name().to_ascii_lowercase();
    match func_name.as_str() {
        "lower"
            if func
                .func
                .inner()
                .downcast_ref::<datafusion::functions::string::lower::LowerFunc>()
                .is_some() =>
        {
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
        "date_trunc"
            if func
                .func
                .inner()
                .downcast_ref::<datafusion::functions::datetime::date_trunc::DateTruncFunc>()
                .is_some() =>
        {
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
            if matches!(
                func.args[1].get_type(&AggregateExprSchema(model))?,
                DataType::Timestamp(_, Some(_))
            ) {
                return Err(DataFusionError::Execution(
                    "date_trunc pushdown requires timestamps without timezone metadata".to_string(),
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
        (KvFieldKind::Float64, KvFieldKind::Float64)
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
    Some(match value {
        ScalarValue::Int64(Some(v)) => (KvReducedValue::Int64(*v), KvFieldKind::Int64),
        ScalarValue::UInt64(Some(v)) => (KvReducedValue::UInt64(*v), KvFieldKind::UInt64),
        ScalarValue::Float64(Some(v)) => (KvReducedValue::Float64(*v), KvFieldKind::Float64),
        ScalarValue::Boolean(Some(v)) => (KvReducedValue::Boolean(*v), KvFieldKind::Boolean),
        ScalarValue::Utf8(Some(v))
        | ScalarValue::LargeUtf8(Some(v))
        | ScalarValue::Utf8View(Some(v)) => (KvReducedValue::Utf8(v.clone()), KvFieldKind::Utf8),
        ScalarValue::Date32(Some(v)) => (KvReducedValue::Date32(*v), KvFieldKind::Date32),
        ScalarValue::Date64(Some(v)) => (KvReducedValue::Date64(*v), KvFieldKind::Date64),
        ScalarValue::TimestampMicrosecond(Some(v), _) => {
            (KvReducedValue::Timestamp(*v), KvFieldKind::Timestamp)
        }
        _ => return None,
    })
}

pub(crate) fn extract_pushdown_string_literal(expr: &Expr) -> Option<String> {
    match strip_alias_expr(expr) {
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
    let function = agg.func.inner();
    let func = if function.downcast_ref::<Count>().is_some() {
        AggregatePushdownFunction::Count
    } else if function.downcast_ref::<Sum>().is_some() {
        AggregatePushdownFunction::Sum
    } else if function.downcast_ref::<Min>().is_some() {
        AggregatePushdownFunction::Min
    } else if function.downcast_ref::<Max>().is_some() {
        AggregatePushdownFunction::Max
    } else if function.downcast_ref::<Avg>().is_some() {
        AggregatePushdownFunction::Avg
    } else {
        return Err(DataFusionError::Execution(format!(
            "aggregate pushdown does not support function '{}'",
            agg.func.name()
        )));
    };
    let (func, argument, case_filter) = if func == AggregatePushdownFunction::Count {
        normalize_count_aggregate_argument(&agg.params.args[0], model)?
    } else {
        normalize_column_or_case_aggregate(func, &agg.params.args[0], model)?
    };

    Ok(NormalizedAggregateExpr {
        func,
        argument,
        filter: conjunction(explicit_filter.into_iter().chain(case_filter)),
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
    let cast_inner = match strip_alias_expr(arg) {
        Expr::Cast(cast) => Some((&cast.expr, cast.field.data_type(), false)),
        Expr::TryCast(cast) => Some((&cast.expr, cast.field.data_type(), true)),
        _ => None,
    };
    if let Some((inner, data_type, try_cast)) = cast_inner {
        if let Expr::Case(case) = strip_alias_expr(inner) {
            let mut case = case.clone();
            let cast_branch = |expr: Expr| {
                if try_cast {
                    Expr::TryCast(datafusion::logical_expr::TryCast::new(
                        Box::new(expr),
                        data_type.clone(),
                    ))
                } else {
                    Expr::Cast(datafusion::logical_expr::Cast::new(
                        Box::new(expr),
                        data_type.clone(),
                    ))
                }
            };
            case.when_then_expr = case
                .when_then_expr
                .into_iter()
                .map(|(when, then)| (when, Box::new(cast_branch(*then))))
                .collect();
            // Null ELSE branches are unchanged by either cast
            if case
                .else_expr
                .as_deref()
                .is_some_and(|expr| aggregate_literal(expr).is_some_and(ScalarValue::is_null))
            {
                case.else_expr = None;
            } else {
                case.else_expr = case.else_expr.map(|expr| Box::new(cast_branch(*expr)));
            }
            return normalize_case_aggregate_argument(func, &Expr::Case(case), model);
        }
    }
    let Expr::Case(case) = strip_alias_expr(arg) else {
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
        filter = disjunction(filter.into_iter().chain(Some(branch_filter)));
    }

    if case
        .else_expr
        .as_deref()
        .is_some_and(|expr| !aggregate_literal(expr).is_some_and(ScalarValue::is_null))
    {
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
        AggregatePushdownFunction::Sum
        | AggregatePushdownFunction::Min
        | AggregatePushdownFunction::Max
        | AggregatePushdownFunction::Avg => Ok(AggregatePushdownArgument::Expr(
            compile_pushdown_value_expr(expr, model)?.0,
        )),
    }
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

pub(crate) fn aggregate_non_null_literal(expr: &Expr) -> Option<&ScalarValue> {
    aggregate_literal(expr).filter(|value| !value.is_null())
}

pub(crate) fn aggregate_literal(expr: &Expr) -> Option<&ScalarValue> {
    match strip_alias_expr(expr) {
        Expr::Literal(value, _) => Some(value),
        _ => None,
    }
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
        if model.primary_key_kinds[..=pk_pos]
            .iter()
            .any(|kind| kind.fixed_key_width().is_none())
        {
            return None;
        }
        let byte_offset = PRIMARY_KEY_BYTE_OFFSET
            + model.primary_key_kinds[..pk_pos]
                .iter()
                .map(|kind| kind.key_width())
                .sum::<usize>();
        Some(KvFieldRef::Key {
            byte_offset: u16::try_from(byte_offset).ok()?,
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
    if spec
        .key_columns
        .iter()
        .any(|idx| model.column(*idx).kind.fixed_key_width().is_none())
        || model.primary_key_kinds[..=pk_pos]
            .iter()
            .any(|kind| kind.fixed_key_width().is_none())
    {
        return None;
    }
    let byte_offset = INDEX_KEY_BYTE_OFFSET
        + spec.key_columns_width
        + model.primary_key_kinds[..pk_pos]
            .iter()
            .map(|kind| kind.key_width())
            .sum::<usize>();
    Some(KvFieldRef::Key {
        byte_offset: u16::try_from(byte_offset).ok()?,
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
                if spec.key_columns[..=pos]
                    .iter()
                    .any(|idx| model.column(*idx).kind.fixed_key_width().is_none())
                {
                    if !spec.value_column_mask[col_idx] {
                        return None;
                    }
                    return Some(KvFieldRef::Value {
                        index: u16::try_from(col_idx).ok()?,
                        kind: kv_field_kind(model.column(col_idx).kind)?,
                        nullable: model.column(col_idx).nullable,
                    });
                }
                let byte_offset = INDEX_KEY_BYTE_OFFSET
                    + spec.key_columns[..pos]
                        .iter()
                        .map(|idx| model.column(*idx).kind.key_width())
                        .sum::<usize>();
                Some(KvFieldRef::Key {
                    byte_offset: u16::try_from(byte_offset).ok()?,
                    kind: kv_field_kind(model.column(col_idx).kind)?,
                })
            }
            IndexLayout::ZOrder => Some(KvFieldRef::ZOrderKey {
                bit_offset: u16::try_from(INDEX_KEY_BYTE_OFFSET * 8).ok()?,
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
        ColumnKind::FixedSizeBinary(width) => {
            Some(KvFieldKind::FixedSizeBinary(u8::try_from(width).ok()?))
        }
        ColumnKind::Decimal128 => Some(KvFieldKind::Decimal128),
        ColumnKind::Decimal256 => Some(KvFieldKind::Decimal256),
        ColumnKind::Binary => None,
        ColumnKind::List(_) => None,
    }
}
