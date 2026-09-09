use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use async_trait::async_trait;
use datafusion::arrow::array::{ArrayRef, UInt64Array};
use datafusion::arrow::compute::cast_with_options;
use datafusion::arrow::datatypes::{i256, DataType, Schema, SchemaRef, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::catalog::Session;
use datafusion::common::format::DEFAULT_CAST_OPTIONS;
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
use datafusion::physical_expr::aggregate::LoweredAggregateBuilder;
use datafusion::physical_expr::expressions::Column;
use datafusion::physical_expr::{EquivalenceProperties, Partitioning, PhysicalExpr};
use datafusion::physical_plan::aggregates::{AggregateExec, AggregateMode, PhysicalGroupBy};
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::{
    stream::RecordBatchStreamAdapter, DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties,
    SendableRecordBatchStream,
};
use datafusion::physical_planner::{DefaultPhysicalPlanner, ExtensionPlanner, PhysicalPlanner};
use exoware_proto::{
    query, to_domain_reduced_value_from_view, RangeReduceOp, RangeReduceRequest, RangeReducerSpec,
};
use exoware_sdk as exoware_proto;
use exoware_sdk::kv_codec::{
    KvExpr, KvFieldKind, KvFieldRef, KvPredicate, KvPredicateCheck, KvPredicateConstraint,
    KvReducedValue,
};
use exoware_sdk::{PrefixedStoreClient, SerializableReadSession};
use futures::{stream::BoxStream, StreamExt, TryStreamExt};

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
    Direct { reducer_idx: usize },
    Avg { sum_idx: usize, count_idx: usize },
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
    CastFloat64(Box<PushdownValueExpr>),
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
            Self::CastFloat64(inner) | Self::Lower(inner) | Self::DateTruncDay(inner) => {
                inner.collect_columns(out)
            }
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
    pub(crate) guard: Option<Expr>,
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
pub(crate) struct AggregatePushdownSpec {
    pub(crate) client: PrefixedStoreClient,
    pub(crate) group_count: usize,
    pub(crate) seed_job: Option<AggregateReduceJob>,
    pub(crate) aggregate_jobs: Vec<CombinedAggregateJob>,
    pub(crate) diagnostics: AggregatePushdownDiagnostics,
    pub(crate) schema: SchemaRef,
}

#[derive(Debug, Clone)]
pub(crate) struct KvAggregateExec {
    pub(crate) spec: Arc<AggregatePushdownSpec>,
    pub(crate) properties: Arc<PlanProperties>,
    state_offsets: Vec<usize>,
    empty_states: Vec<ScalarValue>,
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
        let Ok(Some((scan, expressions))) = aggregate_scan_input(
            &aggregate.input,
            expressions,
            !aggregate.group_expr.is_empty(),
        ) else {
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
            node: Arc::new(KvAggregateNode {
                aggregate,
                spec: Arc::new(spec),
            }),
        });
        Ok(Transformed::yes(plan))
    }
}

fn aggregate_scan_input(
    mut input: &LogicalPlan,
    mut expressions: Vec<Expr>,
    grouped: bool,
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

        // Input projections execute before scalar FILTER and CASE. Inlining their
        // arguments behind those guards would suppress prior evaluation.
        for expr in &expressions {
            let Expr::AggregateFunction(aggregate) = strip_alias_expr(expr) else {
                continue;
            };
            for argument in &aggregate.params.args {
                let guarded = (!grouped && aggregate.params.filter.is_some())
                    || argument.exists(|expr| Ok(matches!(expr, Expr::Case(_))))?;
                if guarded
                    && argument.exists(|expr| {
                        let Expr::Column(column) = expr else {
                            return Ok(false);
                        };
                        Ok(!matches!(
                            strip_alias_expr(&replacements[schema.index_of_column(column)?]),
                            Expr::Column(_) | Expr::Literal(..)
                        ))
                    })?
                {
                    return Ok(None);
                }
            }
        }
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
    spec: Arc<AggregatePushdownSpec>,
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
        session: &dyn Session,
        planning_ctx: &PhysicalPlanningContext,
    ) -> DataFusionResult<Option<Arc<dyn ExecutionPlan>>> {
        let Some(node) = node.as_any().downcast_ref::<KvAggregateNode>() else {
            return Ok(None);
        };
        let input_schema = node.aggregate.input.schema();
        let group_count = node.spec.group_count;
        let aggregates = node
            .aggregate
            .aggr_expr
            .iter()
            .enumerate()
            .map(|(idx, expr)| {
                Ok(LoweredAggregateBuilder::new(
                    expr,
                    input_schema,
                    input_schema.as_arrow(),
                    session.execution_props(),
                    planning_ctx,
                )
                .with_name(node.spec.schema.field(group_count + idx).name())
                .build()?
                .aggregate)
            })
            .collect::<DataFusionResult<Vec<_>>>()?;
        let mut fields = node.spec.schema.fields()[..group_count].to_vec();
        let mut state_offsets = Vec::with_capacity(aggregates.len());
        let mut empty_states = Vec::new();
        for aggregate in &aggregates {
            state_offsets.push(fields.len());
            for field in aggregate.state_fields()? {
                empty_states.push(if field.is_nullable() {
                    ScalarValue::try_new_null(field.data_type())?
                } else {
                    ScalarValue::new_zero(field.data_type())?
                });
                fields.push(field);
            }
        }
        let state_schema = Arc::new(Schema::new(fields));
        let group_by = PhysicalGroupBy::new_single(
            node.spec.schema.fields()[..group_count]
                .iter()
                .enumerate()
                .map(|(idx, field)| {
                    (
                        Arc::new(Column::new(field.name(), idx)) as Arc<dyn PhysicalExpr>,
                        field.name().clone(),
                    )
                })
                .collect(),
        );
        let source = Arc::new(KvAggregateExec {
            spec: node.spec.clone(),
            properties: Arc::new(PlanProperties::new(
                EquivalenceProperties::new(state_schema),
                Partitioning::UnknownPartitioning(1),
                EmissionType::Incremental,
                Boundedness::Bounded,
            )),
            state_offsets,
            empty_states,
        });
        Ok(Some(Arc::new(AggregateExec::try_new(
            AggregateMode::Final,
            group_by,
            aggregates,
            vec![None; node.aggregate.aggr_expr.len()],
            source,
            Arc::new(input_schema.as_arrow().clone()),
        )?)))
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
        context: Arc<TaskContext>,
    ) -> DataFusionResult<SendableRecordBatchStream> {
        if partition != 0 {
            return Err(DataFusionError::Internal(format!(
                "KvAggregateExec only supports 1 partition, got {partition}"
            )));
        }

        let session = self.spec.client.create_session();
        let source = Arc::new(self.clone());
        let concurrency = context.session_config().target_partitions().max(1);
        let jobs = self
            .spec
            .seed_job
            .clone()
            .into_iter()
            .map(|job| CombinedAggregateJob {
                job,
                expr_plans: Vec::new(),
            })
            .chain(self.spec.aggregate_jobs.clone());
        let batches = futures::stream::iter(jobs)
            .map(move |job| {
                execute_reduce_job(session.clone(), Arc::new(job), source.clone(), concurrency)
            })
            .flatten();
        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.schema(),
            batches,
        )))
    }
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

fn execute_reduce_job(
    session: SerializableReadSession,
    job: Arc<CombinedAggregateJob>,
    source: Arc<KvAggregateExec>,
    concurrency: usize,
) -> impl futures::Stream<Item = DataFusionResult<RecordBatch>> {
    let mut ranges = job.job.ranges.clone().into_iter();
    let first_range = if session.fixed_sequence().is_none() {
        ranges.next()
    } else {
        None
    };
    let first_session = session.clone();
    let first_job = job.clone();
    let first_source = source.clone();
    let first = futures::stream::iter(first_range)
        .then(move |range| {
            execute_reduce_range(
                first_session.clone(),
                first_job.clone(),
                first_source.clone(),
                range,
            )
        })
        .try_flatten();

    // Every frame of an unseeded read can advance its floor. Drain that range
    // before opening concurrent reads, and keep a zero-floor session sequential.
    let remaining_count = ranges.len();
    let remaining = futures::stream::once(async move {
        let concurrency = if session.fixed_sequence().is_some() {
            concurrency
        } else {
            1
        };
        Ok::<_, DataFusionError>(
            futures::stream::iter(ranges)
                .map(move |range| {
                    execute_reduce_range(session.clone(), job.clone(), source.clone(), range)
                })
                .buffered(concurrency)
                .try_flatten(),
        )
    })
    .take(remaining_count)
    .try_flatten();
    first.chain(remaining)
}

async fn execute_reduce_range(
    session: SerializableReadSession,
    job: Arc<CombinedAggregateJob>,
    source: Arc<KvAggregateExec>,
    range: KeyRange,
) -> DataFusionResult<BoxStream<'static, DataFusionResult<RecordBatch>>> {
    let responses = session
        .range_reduce_stream(&range.start, &range.end, &job.job.request)
        .await
        .map_err(|error| DataFusionError::External(Box::new(error)))?;
    if job.job.request.group_by.is_empty() {
        let response = exoware_sdk::scalar_reduce_response(responses, &job.job.request)
            .await
            .map_err(|error| DataFusionError::External(Box::new(error)))?;
        let batch = source.decode_reduce_batch(&job, response.view())?;
        return Ok(futures::stream::once(futures::future::ready(Ok(batch))).boxed());
    }
    Ok(responses
        .map(move |response| {
            let response = response.map_err(|error| DataFusionError::External(Box::new(error)))?;
            source.decode_reduce_batch(&job, response.view())
        })
        .boxed())
}

fn decode_reduced_value(
    value: Option<&query::KvReducedValueView<'_>>,
) -> DataFusionResult<Option<KvReducedValue>> {
    value
        .map(to_domain_reduced_value_from_view)
        .transpose()
        .map_err(|error| {
            DataFusionError::Execution(format!("range reduction response decode: {error}"))
        })
}

fn reduced_count(value: Option<&query::KvReducedValueView<'_>>) -> DataFusionResult<u64> {
    match decode_reduced_value(value)? {
        Some(KvReducedValue::UInt64(count)) => Ok(count),
        _ => Err(DataFusionError::Execution(
            "count reducer returned non-UInt64 partial".to_string(),
        )),
    }
}

impl KvAggregateExec {
    fn decode_reduce_batch(
        &self,
        job: &CombinedAggregateJob,
        response: &query::ReduceResponseView<'_>,
    ) -> DataFusionResult<RecordBatch> {
        let row_count = if self.spec.group_count == 0 {
            if !response.groups.is_empty()
                || response.results.len() != job.job.request.reducers.len()
            {
                return Err(DataFusionError::Execution(
                    "scalar aggregate response shape mismatch".to_string(),
                ));
            }
            1
        } else {
            if !response.results.is_empty() {
                return Err(DataFusionError::Execution(
                    "grouped aggregate job returned scalar reductions".to_string(),
                ));
            }
            response.groups.len()
        };
        let schema = self.schema();
        if row_count == 0 {
            return Ok(RecordBatch::new_empty(schema));
        }
        for group in &response.groups {
            if group.group_values_present.len() != self.spec.group_count
                || group.results.len() != job.job.request.reducers.len()
                || group.group_values.len()
                    != group
                        .group_values_present
                        .iter()
                        .filter(|present| **present)
                        .count()
            {
                return Err(DataFusionError::Execution(
                    "range reduction response length mismatch".to_string(),
                ));
            }
        }
        let mut columns = Vec::with_capacity(schema.fields().len());

        // Dense key iterators advance with each group's validity flags as columns
        // are built directly from the borrowed response.
        let mut group_values = response
            .groups
            .iter()
            .map(|group| group.group_values.iter())
            .collect::<Vec<_>>();
        for (idx, field) in schema.fields()[..self.spec.group_count].iter().enumerate() {
            let values = response
                .groups
                .iter()
                .zip(&mut group_values)
                .map(|(group, values)| {
                    let value = if group.group_values_present[idx] {
                        values.next()
                    } else {
                        None
                    };
                    reduced_value_to_scalar(decode_reduced_value(value)?, field.data_type())
                })
                .collect::<DataFusionResult<Vec<_>>>()?;
            columns.push(ScalarValue::iter_to_array(values)?);
        }
        let result_value = |row: usize, reducer: usize| {
            let results = if self.spec.group_count == 0 {
                &response.results
            } else {
                &response.groups[row].results
            };
            results[reducer].value.as_option()
        };
        let mut state_columns: Vec<Option<ArrayRef>> = vec![None; self.empty_states.len()];
        for (output_idx, output) in &job.expr_plans {
            let offset = self.state_offsets[*output_idx];
            let state_idx = offset - self.spec.group_count;
            match output {
                AggregateOutputPlan::Direct { reducer_idx } => {
                    let reducer = &job.job.request.reducers[*reducer_idx];
                    let data_type = schema.field(offset).data_type();
                    let values = if matches!(
                        reducer.op,
                        RangeReduceOp::CountAll | RangeReduceOp::CountField
                    ) {
                        let counts = (0..row_count)
                            .map(|row| reduced_count(result_value(row, *reducer_idx)))
                            .collect::<DataFusionResult<Vec<_>>>()?;
                        cast_with_options(
                            &UInt64Array::from(counts),
                            data_type,
                            &DEFAULT_CAST_OPTIONS,
                        )?
                    } else {
                        let values = (0..row_count)
                            .map(|row| {
                                reduced_value_to_scalar(
                                    decode_reduced_value(result_value(row, *reducer_idx))?,
                                    data_type,
                                )
                            })
                            .collect::<DataFusionResult<Vec<_>>>()?;
                        ScalarValue::iter_to_array(values)?
                    };
                    state_columns[state_idx] = Some(values);
                }
                AggregateOutputPlan::Avg { sum_idx, count_idx } => {
                    let mut counts = Vec::with_capacity(row_count);
                    let mut sums = Vec::with_capacity(row_count);
                    for row in 0..row_count {
                        let count = reduced_count(result_value(row, *count_idx))?;
                        let sum = reduced_value_to_scalar(
                            decode_reduced_value(result_value(row, *sum_idx))?,
                            schema.field(offset + 1).data_type(),
                        )?;

                        // Native grouped AVG shares count/sum validity; a valid zero count
                        // would turn an empty group's null result into division by zero.
                        counts.push((!sum.is_null()).then_some(count));
                        sums.push(sum);
                    }
                    state_columns[state_idx] = Some(Arc::new(UInt64Array::from(counts)));
                    state_columns[state_idx + 1] = Some(ScalarValue::iter_to_array(sums)?);
                }
            }
        }

        // Jobs contribute to separate state slots; neutral states preserve seed-only groups.
        for (state, empty) in state_columns.into_iter().zip(&self.empty_states) {
            columns.push(match state {
                Some(state) => state,
                None => empty.to_array_of_size(row_count)?,
            });
        }
        RecordBatch::try_new(schema, columns).map_err(Into::into)
    }
}

pub(crate) fn rebase_output_plan(
    output: AggregateOutputPlan,
    offset: usize,
) -> AggregateOutputPlan {
    match output {
        AggregateOutputPlan::Direct { reducer_idx } => AggregateOutputPlan::Direct {
            reducer_idx: reducer_idx + offset,
        },
        AggregateOutputPlan::Avg { sum_idx, count_idx } => AggregateOutputPlan::Avg {
            sum_idx: sum_idx + offset,
            count_idx: count_idx + offset,
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

pub(crate) fn try_build_aggregate_pushdown_spec(
    table: &KvTable,
    scan: &datafusion::logical_expr::logical_plan::TableScan,
    group_exprs: &[Expr],
    aggr_exprs: &[Expr],
    schema: &datafusion::common::DFSchemaRef,
) -> DataFusionResult<Option<AggregatePushdownSpec>> {
    let mut compiled_group_exprs = Vec::with_capacity(group_exprs.len());
    for expr in group_exprs {
        let compiled_expr = match compile_pushdown_value_expr(expr, &table.model) {
            Ok((compiled_expr, _)) => compiled_expr,
            Err(_) => return Ok(None),
        };
        compiled_group_exprs.push(compiled_expr);
    }

    let mut aggregate_exprs = Vec::new();
    let mut aggregate_diagnostics = Vec::new();
    let mut has_unguarded_aggregate = false;
    for (expr_idx, expr) in aggr_exprs.iter().enumerate() {
        let data_type = schema
            .field(group_exprs.len() + expr_idx)
            .data_type()
            .clone();
        let mut normalized = match normalize_aggregate_expr(expr, &table.model) {
            Ok(normalized) => normalized,
            Err(_) => return Ok(None),
        };

        // Native scalar aggregates filter rows before evaluating arguments, allowing
        // the same predicate to narrow the Store access path.
        if compiled_group_exprs.is_empty() {
            normalized.guard =
                conjunction(normalized.guard.into_iter().chain(normalized.filter.take()));
        }

        has_unguarded_aggregate |= normalized.guard.is_none();
        let mut filters = scan.filters.clone();
        if let Some(filter) = &normalized.guard {
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

    let seed_job = if !compiled_group_exprs.is_empty() && !has_unguarded_aggregate {
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
        group_count: compiled_group_exprs.len(),
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
    group_exprs: &[PushdownValueExpr],
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
    let reducer_predicate = if let Some(filter) = aggr_expr.and_then(|expr| expr.filter.as_ref()) {
        if !QueryPredicate::supports_filter(filter, &table.model) {
            return Ok(None);
        }
        Some(QueryPredicate::from_filters(
            std::slice::from_ref(filter),
            &table.model,
        ))
    } else {
        None
    };
    let required_projection =
        reduce_job_required_projection(group_exprs, aggr_expr, reducer_predicate.as_ref());
    let projection = Some(required_projection);
    let access_plan = ScanAccessPlan::new(&table.model, &projection, &predicate);
    let (ranges, access_path, constrained_prefix_len) =
        choose_aggregate_access_path(table, &predicate, &access_plan)?;
    let Some(group_by) =
        compile_group_exprs(group_exprs, &table.model, &table.index_specs, &access_path)
    else {
        return Ok(None);
    };
    let reducer_filter = if let Some(predicate) = &reducer_predicate {
        let Some(filter) =
            compile_reduce_filter(predicate, &table.model, &table.index_specs, &access_path)
        else {
            return Ok(None);
        };
        Some(filter)
    } else {
        None
    };
    let (reducers, output) = match (aggr_expr, data_type) {
        (Some(expr), Some(data_type)) => match compile_aggregate_expr(
            expr,
            &table.model,
            &table.index_specs,
            &access_path,
            0,
            data_type,
            reducer_filter,
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
) -> DataFusionResult<ChosenAggregateAccessPath> {
    if let Some(index_plan) =
        predicate.choose_index_plan(&table.model, &table.index_specs, access_plan)?
    {
        if !index_plan.ranges.is_empty()
            && access_plan.index_covers_required_non_pk(&table.index_specs[index_plan.spec_idx])
        {
            return Ok((
                index_plan.ranges,
                AggregateAccessPath::SecondaryIndex {
                    spec_idx: index_plan.spec_idx,
                },
                Some(index_plan.constrained_prefix_len),
            ));
        }
    }
    Ok((
        predicate.primary_key_ranges(
            &table.model,
            table.client.key_prefix().max_logical_key_len(),
        )?,
        AggregateAccessPath::PrimaryKey,
        None,
    ))
}

pub(crate) fn reduce_job_required_projection(
    group_exprs: &[PushdownValueExpr],
    aggr_expr: Option<&NormalizedAggregateExpr>,
    filter: Option<&QueryPredicate>,
) -> Vec<usize> {
    let mut cols = group_exprs
        .iter()
        .flat_map(|group| {
            let mut cols = Vec::new();
            group.collect_columns(&mut cols);
            cols
        })
        .collect::<Vec<_>>();
    if let Some(expr) = aggr_expr {
        if let AggregatePushdownArgument::Expr(argument) = &expr.argument {
            argument.collect_columns(&mut cols);
        }
    }
    if let Some(filter) = filter {
        cols.extend(filter.constraints.keys().copied());
    }
    cols.sort_unstable();
    cols.dedup();
    cols
}

pub(crate) fn compile_group_exprs(
    group_exprs: &[PushdownValueExpr],
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
    access_path: &AggregateAccessPath,
) -> Option<Vec<KvExpr>> {
    group_exprs
        .iter()
        .map(|group| compile_reduce_expr(group, model, index_specs, access_path))
        .collect()
}

pub(crate) fn compile_aggregate_expr(
    normalized: &NormalizedAggregateExpr,
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
    access_path: &AggregateAccessPath,
    next_reducer_idx: usize,
    data_type: DataType,
    filter: Option<KvPredicate>,
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
                    filter: filter.clone(),
                },
                RangeReducerSpec {
                    op: RangeReduceOp::CountField,
                    expr,
                    filter,
                },
            ],
            AggregateOutputPlan::Avg {
                sum_idx: next_reducer_idx,
                count_idx: next_reducer_idx + 1,
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
        vec![RangeReducerSpec { op, expr, filter }],
        AggregateOutputPlan::Direct {
            reducer_idx: next_reducer_idx,
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
        Expr::BinaryExpr(binary)
            if matches!(
                binary.op,
                Operator::Plus | Operator::Minus | Operator::Multiply | Operator::Divide
            ) =>
        {
            let (left, left_kind) = compile_pushdown_value_expr(binary.left.as_ref(), model)?;
            let (right, right_kind) = compile_pushdown_value_expr(binary.right.as_ref(), model)?;
            let kind = match (left_kind, right_kind) {
                (KvFieldKind::Int64, KvFieldKind::Int64) => KvFieldKind::Int64,
                (KvFieldKind::UInt64, KvFieldKind::UInt64) => KvFieldKind::UInt64,
                (KvFieldKind::Float64, KvFieldKind::Float64)
                | (KvFieldKind::Float64, KvFieldKind::Int64)
                | (KvFieldKind::Int64, KvFieldKind::Float64)
                | (KvFieldKind::Float64, KvFieldKind::UInt64)
                | (KvFieldKind::UInt64, KvFieldKind::Float64) => KvFieldKind::Float64,
                _ => {
                    return Err(DataFusionError::Execution(format!(
                        "unsupported pushdown operand types for {}",
                        binary.op
                    )))
                }
            };
            let (left, right) = (Box::new(left), Box::new(right));
            let expr = match binary.op {
                Operator::Plus => PushdownValueExpr::Add(left, right),
                Operator::Minus => PushdownValueExpr::Sub(left, right),
                Operator::Multiply => PushdownValueExpr::Mul(left, right),
                Operator::Divide => PushdownValueExpr::Div(left, right),
                _ => unreachable!(),
            };
            Ok((expr, kind))
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
            PushdownValueExpr::CastFloat64(Box::new(inner)),
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
        filter: explicit_filter,
        guard: case_filter,
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
        PushdownValueExpr::CastFloat64(inner) => Some(KvExpr::CastFloat64(Box::new(
            compile_reduce_expr(inner, model, index_specs, access_path)?,
        ))),
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

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Message;
    use std::collections::BTreeMap;
    use std::sync::{
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
        Mutex,
    };

    use axum::{extract::Request, middleware::Next, response::Response, Router};
    use bytes::Bytes;
    use datafusion::arrow::array::{
        ArrayRef, Decimal128Array, FixedSizeBinaryBuilder, Float64Array, Int64Array, StringArray,
        UInt64Array,
    };
    use datafusion::datasource::MemTable;
    use datafusion::prelude::SessionContext;
    use exoware_sdk::{RangeReduceGroup, RangeReduceResponse, RangeReduceResult, StoreClient};
    use exoware_server::{Query, QueryExtra, QueryState, RangeScan, RangeScanBatch, Sequence};

    #[derive(Default)]
    struct Rows {
        values: Mutex<BTreeMap<Bytes, Bytes>>,
        paths: Mutex<Vec<String>>,
        reductions: Mutex<Vec<exoware_sdk::query::ReduceRequest>>,
        scanned_rows: AtomicUsize,
    }

    impl Sequence for Rows {
        fn current_sequence(&self) -> u64 {
            7
        }
    }

    struct Cursor(std::vec::IntoIter<(Bytes, Bytes)>);

    impl RangeScan for Cursor {
        async fn next_batch(&mut self, max_items: usize) -> Result<RangeScanBatch, String> {
            Ok(RangeScanBatch {
                rows: self.0.by_ref().take(max_items).collect(),
                extra: QueryExtra::new(),
            })
        }
    }

    impl Query for Rows {
        type RangeScan = Cursor;

        async fn get(&self, key: Bytes) -> Result<(Option<Bytes>, QueryExtra), String> {
            Ok((
                self.values.lock().unwrap().get(&key).cloned(),
                QueryExtra::new(),
            ))
        }

        async fn get_many(
            &self,
            keys: Vec<Bytes>,
        ) -> Result<(Vec<(Bytes, Option<Bytes>)>, QueryExtra), String> {
            let values = self.values.lock().unwrap();
            Ok((
                keys.into_iter()
                    .map(|key| {
                        let value = values.get(&key).cloned();
                        (key, value)
                    })
                    .collect(),
                QueryExtra::new(),
            ))
        }

        async fn range_scan(
            &self,
            start: Bytes,
            end: Bytes,
            limit: usize,
            forward: bool,
        ) -> Result<Cursor, String> {
            let mut rows = self
                .values
                .lock()
                .unwrap()
                .iter()
                .filter(|(key, _)| **key >= start && (end.is_empty() || **key <= end))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>();
            if !forward {
                rows.reverse();
            }
            rows.truncate(limit);
            self.scanned_rows
                .fetch_add(rows.len(), AtomicOrdering::Relaxed);
            Ok(Cursor(rows.into_iter()))
        }
    }

    type FloatRangeRow = (i64, i64, Option<i64>, i64, Option<f64>);

    struct Fixture {
        store: SessionContext,
        native: SessionContext,
        rows: Arc<Rows>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    impl Fixture {
        async fn new() -> Self {
            Self::with_amounts([Some(10), Some(30), None, Some(20)]).await
        }

        async fn with_amounts(amounts: [Option<i64>; 4]) -> Self {
            let rows = Arc::new(Rows::default());
            let observed = rows.clone();
            let app = Router::new()
                .fallback_service(exoware_server::query_service(QueryState::new(rows.clone())))
                .layer(axum::middleware::from_fn(
                    move |request: Request, next: Next| {
                        let observed = observed.clone();
                        async move {
                            observed
                                .paths
                                .lock()
                                .unwrap()
                                .push(request.uri().path().to_string());
                            let request = if request.uri().path().ends_with("/Reduce") {
                                let (parts, body) = request.into_parts();
                                let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                                observed
                                    .reductions
                                    .lock()
                                    .unwrap()
                                    .push(crate::tests::decode_reduce_request(&body));
                                Request::from_parts(parts, axum::body::Body::from(body))
                            } else {
                                request
                            };
                            let response: Response = next.run(request).await;
                            response
                        }
                    },
                ));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let store = crate::session_context();
            let schema = crate::KvSchema::new(PrefixedStoreClient::empty(StoreClient::new(&url)))
                .table(
                    "orders",
                    vec![
                        TableColumnConfig::new("id", DataType::Int64, false),
                        TableColumnConfig::new("region", DataType::Utf8, true),
                        TableColumnConfig::new("status", DataType::Utf8, false),
                        TableColumnConfig::new("amount", DataType::Int64, true),
                    ],
                    vec!["id".to_string()],
                    vec![],
                )
                .unwrap();
            schema.register_all(&store).unwrap();
            let provider = store.table_provider("orders").await.unwrap();
            let model = &provider.downcast_ref::<KvTable>().unwrap().model;
            let regions = [Some("east"), Some("east"), Some("west"), None];
            let statuses = ["open", "closed", "closed", "open"];
            for idx in 0..4 {
                let row = KvRow {
                    values: vec![
                        CellValue::Int64(idx as i64 + 1),
                        regions[idx]
                            .map(|s| CellValue::Utf8(s.to_string()))
                            .unwrap_or(CellValue::Null),
                        CellValue::Utf8(statuses[idx].to_string()),
                        amounts[idx]
                            .map(CellValue::Int64)
                            .unwrap_or(CellValue::Null),
                    ],
                };
                let key = crate::codec::encode_primary_key_from_row(0, &row, model).unwrap();
                let value = crate::writer::encode_base_row_value(&row, model).unwrap();
                rows.values.lock().unwrap().insert(key, value.into());
            }
            let batch = RecordBatch::try_new(
                model.schema.clone(),
                vec![
                    Arc::new(Int64Array::from(vec![1, 2, 3, 4])),
                    Arc::new(StringArray::from(regions.to_vec())),
                    Arc::new(StringArray::from(statuses.to_vec())),
                    Arc::new(Int64Array::from(amounts.to_vec())),
                ],
            )
            .unwrap();
            let native = SessionContext::new();
            native
                .register_table(
                    "orders",
                    Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]]).unwrap()),
                )
                .unwrap();
            Self {
                store,
                native,
                rows,
                server,
            }
        }

        async fn install_indexed_table(
            &self,
            name: &str,
            columns: Vec<TableColumnConfig>,
            primary_key: &[&str],
            indexes: Vec<IndexSpec>,
            rows: Vec<KvRow>,
            arrays: Vec<ArrayRef>,
        ) {
            let provider = self.store.table_provider("orders").await.unwrap();
            let client = provider.downcast_ref::<KvTable>().unwrap().client.clone();
            let schema = crate::KvSchema::new(client)
                .table(
                    name,
                    columns,
                    primary_key.iter().map(|name| name.to_string()).collect(),
                    indexes,
                )
                .unwrap();
            schema.register_all(&self.store).unwrap();
            let provider = self.store.table_provider(name).await.unwrap();
            let table = provider.downcast_ref::<KvTable>().unwrap();
            let mut stored = self.rows.values.lock().unwrap();
            stored.clear();
            for row in rows {
                stored.insert(
                    crate::codec::encode_primary_key_from_row(0, &row, &table.model).unwrap(),
                    crate::writer::encode_base_row_value(&row, &table.model)
                        .unwrap()
                        .into(),
                );
                for spec in table.index_specs.iter() {
                    stored.insert(
                        crate::codec::encode_secondary_index_key(0, spec, &table.model, &row)
                            .unwrap(),
                        crate::writer::encode_secondary_index_value(&row, &table.model, spec)
                            .unwrap()
                            .into(),
                    );
                }
            }
            drop(stored);
            let batch = RecordBatch::try_new(table.model.schema.clone(), arrays).unwrap();
            self.native
                .register_table(
                    name,
                    Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]]).unwrap()),
                )
                .unwrap();
        }

        async fn replace_value_column(
            &self,
            data_type: DataType,
            values: Vec<CellValue>,
            array: ArrayRef,
        ) {
            let provider = self.store.table_provider("orders").await.unwrap();
            let client = provider.downcast_ref::<KvTable>().unwrap().client.clone();
            let schema = crate::KvSchema::new(client)
                .table(
                    "numbers",
                    vec![
                        TableColumnConfig::new("id", DataType::Int64, false),
                        TableColumnConfig::new("value", data_type, true),
                    ],
                    vec!["id".to_string()],
                    vec![],
                )
                .unwrap();
            schema.register_all(&self.store).unwrap();
            let provider = self.store.table_provider("numbers").await.unwrap();
            let model = &provider.downcast_ref::<KvTable>().unwrap().model;
            let mut stored = self.rows.values.lock().unwrap();
            stored.clear();
            for (idx, value) in values.into_iter().enumerate() {
                let row = KvRow {
                    values: vec![CellValue::Int64(idx as i64), value],
                };
                stored.insert(
                    crate::codec::encode_primary_key_from_row(0, &row, model).unwrap(),
                    crate::writer::encode_base_row_value(&row, model)
                        .unwrap()
                        .into(),
                );
            }
            let batch = RecordBatch::try_new(
                model.schema.clone(),
                vec![
                    Arc::new(Int64Array::from_iter_values(0..array.len() as i64)),
                    array,
                ],
            )
            .unwrap();
            self.native
                .register_table(
                    "numbers",
                    Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]]).unwrap()),
                )
                .unwrap();
        }

        async fn install_float_ranges(&self, rows: &[FloatRangeRow]) -> RecordBatch {
            let arrays: Vec<ArrayRef> = vec![
                Arc::new(Int64Array::from_iter_values(rows.iter().map(|row| row.0))),
                Arc::new(Int64Array::from_iter_values(rows.iter().map(|row| row.1))),
                Arc::new(Int64Array::from_iter(rows.iter().map(|row| row.2))),
                Arc::new(Int64Array::from_iter_values(rows.iter().map(|row| row.3))),
                Arc::new(Float64Array::from_iter(rows.iter().map(|row| row.4))),
            ];
            self.install_indexed_table(
                "float_ranges",
                vec![
                    TableColumnConfig::new("bucket", DataType::Int64, false),
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("category", DataType::Int64, true),
                    TableColumnConfig::new("flag", DataType::Int64, false),
                    TableColumnConfig::new("value", DataType::Float64, true),
                ],
                &["bucket", "id"],
                vec![],
                rows.iter()
                    .map(|&(bucket, id, category, flag, value)| KvRow {
                        values: vec![
                            CellValue::Int64(bucket),
                            CellValue::Int64(id),
                            category.map(CellValue::Int64).unwrap_or(CellValue::Null),
                            CellValue::Int64(flag),
                            value.map(CellValue::Float64).unwrap_or(CellValue::Null),
                        ],
                    })
                    .collect(),
                arrays.clone(),
            )
            .await;
            let schema = self
                .native
                .table_provider("float_ranges")
                .await
                .unwrap()
                .schema();
            RecordBatch::try_new(schema, arrays).unwrap()
        }

        fn assert_range_jobs(&self, range_count: usize, jobs: usize, scanned_rows: usize) {
            let requests = self.rows.reductions.lock().unwrap();
            let mut ranges = BTreeMap::new();
            for request in requests.iter() {
                *ranges
                    .entry((request.start.clone(), request.end.clone()))
                    .or_insert(0) += 1;
            }
            assert_eq!(ranges.len(), range_count, "{requests:?}");
            assert!(ranges.values().all(|count| *count == jobs), "{requests:?}");
            let bounds = ranges.keys().collect::<Vec<_>>();
            assert!(
                bounds.windows(2).all(|pair| pair[0].1 < pair[1].0),
                "{requests:?}"
            );
            assert_eq!(
                self.rows.scanned_rows.load(AtomicOrdering::Relaxed),
                scanned_rows
            );
        }

        async fn check(&self, sql: &str, reductions: usize) {
            let expected = values(&self.native, sql).await.unwrap();
            self.check_expected(sql, reductions, &expected).await;
        }

        async fn check_expected(
            &self,
            sql: &str,
            reductions: usize,
            expected: &[Vec<ScalarValue>],
        ) {
            self.rows.paths.lock().unwrap().clear();
            self.rows.reductions.lock().unwrap().clear();
            self.rows.scanned_rows.store(0, AtomicOrdering::Relaxed);
            let actual = values(&self.store, sql).await.unwrap();
            assert_eq!(actual.as_slice(), expected, "{sql}");
            let requests = self.rows.reductions.lock().unwrap();
            for (idx, request) in requests.iter().enumerate() {
                assert_eq!(
                    request.min_sequence_number,
                    (idx > 0).then_some(7),
                    "shared read floor: {sql}"
                );
            }
            let paths = self.rows.paths.lock().unwrap();
            assert_eq!(
                paths.iter().filter(|p| p.ends_with("/Reduce")).count(),
                reductions,
                "{sql}: {paths:?}"
            );
            assert!(
                !paths.iter().any(|p| p.ends_with("/Range")
                    || p.ends_with("/GetMany")
                    || p.ends_with("/Get")),
                "{sql}: {paths:?}"
            );
        }
    }

    async fn values(ctx: &SessionContext, sql: &str) -> DataFusionResult<Vec<Vec<ScalarValue>>> {
        let batches = ctx.sql(sql).await?.collect().await?;
        batch_values(&batches)
    }

    fn batch_values(batches: &[RecordBatch]) -> DataFusionResult<Vec<Vec<ScalarValue>>> {
        batches
            .iter()
            .flat_map(|batch| {
                (0..batch.num_rows()).map(|row| {
                    (0..batch.num_columns())
                        .map(|col| ScalarValue::try_from_array(batch.column(col), row))
                        .collect()
                })
            })
            .collect()
    }

    #[tokio::test]
    async fn existing_reduce_capabilities_use_one_request() {
        let fixture = Fixture::new().await;
        for sql in [
            "SELECT SUM(amount), MIN(amount), MAX(amount), AVG(amount) FROM orders",
            "SELECT SUM(amount) FROM orders WHERE status = 'open'",
            "SELECT DISTINCT region FROM orders ORDER BY region",
            "SELECT region FROM orders GROUP BY region ORDER BY region",
            "SELECT SUM(q.v), AVG(q.v) FROM (SELECT amount AS v FROM orders) q",
        ] {
            fixture.check(sql, 1).await;
        }
    }

    #[tokio::test]
    async fn limited_distinct_preserves_aggregation_limits() {
        use datafusion::physical_plan::aggregates::AggregateExec;

        let fixture = Fixture::new().await;
        for ctx in [&fixture.native, &fixture.store] {
            values(ctx, "SET datafusion.execution.target_partitions = 1")
                .await
                .unwrap();
        }
        for (sql, unordered_input) in [
            ("SELECT DISTINCT id FROM orders LIMIT 1", false),
            ("SELECT DISTINCT status FROM orders LIMIT 1", true),
        ] {
            let native_plan = fixture
                .native
                .sql(sql)
                .await
                .unwrap()
                .create_physical_plan()
                .await
                .unwrap();
            assert!(native_plan
                .exists(|node| Ok(node
                    .downcast_ref::<AggregateExec>()
                    .and_then(AggregateExec::limit_options)
                    .is_some_and(|options| options.limit() == 1)))
                .unwrap());
            let frame = fixture.store.sql(sql).await.unwrap();
            let logical = frame.clone().into_optimized_plan().unwrap();
            let physical = frame.create_physical_plan().await.unwrap();
            let expected = values(&fixture.native, sql).await.unwrap();
            fixture.rows.paths.lock().unwrap().clear();
            fixture.rows.reductions.lock().unwrap().clear();
            let actual = values(&fixture.store, sql).await.unwrap();
            let paths = fixture.rows.paths.lock().unwrap().clone();
            assert_eq!(
                paths
                    .iter()
                    .filter(|path| path.ends_with("/Reduce"))
                    .count(),
                0,
                "{sql}: {paths:?}\n{}",
                datafusion::physical_plan::displayable(physical.as_ref()).indent(true),
            );
            assert_eq!(
                paths.iter().filter(|path| path.ends_with("/Range")).count(),
                1,
                "{sql}: {paths:?}",
            );
            assert_eq!(actual, expected, "{sql}");
            assert!(logical
            .exists(|node| Ok(
                matches!(node, LogicalPlan::Aggregate(aggregate) if aggregate.aggr_expr.is_empty())
            ))
            .unwrap());
            assert!(physical
                .exists(|node| Ok(node.downcast_ref::<AggregateExec>().is_some()))
                .unwrap());
            if unordered_input {
                assert!(physical
                    .exists(|node| Ok(node
                        .downcast_ref::<AggregateExec>()
                        .and_then(AggregateExec::limit_options)
                        .is_some_and(|options| options.limit() == 1)))
                    .unwrap());
            }
        }
        fixture
            .check("SELECT DISTINCT id FROM orders ORDER BY id", 1)
            .await;
        fixture
            .check("SELECT COUNT(*) FROM orders LIMIT 1", 1)
            .await;
    }

    #[tokio::test]
    async fn limit_outside_the_aggregate_keeps_group_only_pushdown() {
        let fixture = Fixture::new().await;

        // Sorting requires all groups before the limit can select its result.
        for sql in [
            "SELECT region FROM orders GROUP BY region ORDER BY region LIMIT 10",
            "SELECT region FROM orders GROUP BY region ORDER BY region DESC LIMIT 1",
        ] {
            fixture.check(sql, 1).await;
        }
    }

    #[tokio::test]
    async fn limit_on_an_unrelated_branch_keeps_group_only_pushdown() {
        let fixture = Fixture::new().await;
        let sql = "SELECT r.region FROM (SELECT DISTINCT region FROM orders) r \
               CROSS JOIN (SELECT id FROM orders LIMIT 1) l ORDER BY r.region";
        let expected = values(&fixture.native, sql).await.unwrap();
        fixture.rows.paths.lock().unwrap().clear();
        let actual = values(&fixture.store, sql).await.unwrap();
        assert_eq!(actual, expected, "{sql}");
        let paths = fixture.rows.paths.lock().unwrap().clone();
        assert_eq!(
            paths.iter().filter(|p| p.ends_with("/Reduce")).count(),
            1,
            "{sql}: {paths:?}"
        );
        assert_eq!(
            paths.iter().filter(|p| p.ends_with("/Range")).count(),
            1,
            "{sql}: {paths:?}"
        );
    }

    #[tokio::test]
    async fn interleaved_jobs_preserve_output_positions() {
        let fixture = Fixture::new().await;
        fixture.check("SELECT SUM(amount), COUNT(*) FILTER (WHERE status = 'open'), AVG(amount), MIN(amount), MAX(amount) FROM orders", 2).await;
        fixture.check("SELECT region, SUM(amount), COUNT(*) FILTER (WHERE status = 'open'), AVG(amount), MIN(amount), MAX(amount) FROM orders GROUP BY region ORDER BY region", 1).await;
    }

    #[tokio::test]
    async fn filters_keep_empty_groups_and_share_one_request() {
        let fixture = Fixture::new().await;
        fixture.check("SELECT region, COUNT(*), COUNT(*) FILTER (WHERE status = 'open') FROM orders GROUP BY region ORDER BY region", 1).await;
        fixture.check("SELECT region, SUM(amount) FILTER (WHERE status = 'open'), COUNT(*) FILTER (WHERE status = 'open') FROM orders GROUP BY region ORDER BY region", 1).await;
        fixture.check("SELECT region, SUM(amount) FILTER (WHERE status = 'open'), COUNT(*) FILTER (WHERE status = 'closed'), AVG(amount) FILTER (WHERE id > 99) FROM orders GROUP BY region ORDER BY region", 1).await;
        {
            let requests = fixture.rows.reductions.lock().unwrap();
            assert!(requests[0].params.filter.as_option().is_none());
            assert!(requests[0]
                .params
                .reducers
                .iter()
                .all(|reducer| reducer.filter.as_option().is_some()));
        }
        assert_eq!(fixture.rows.scanned_rows.load(AtomicOrdering::Relaxed), 4);
        fixture.check("SELECT region, SUM(CASE WHEN id > 1 THEN amount END) FILTER (WHERE status = 'open'), COUNT(*) FILTER (WHERE status = 'closed') FROM orders GROUP BY region ORDER BY region", 2).await;
    }

    #[tokio::test]
    async fn grouped_filter_keeps_computed_projections_in_reduce() {
        let fixture = Fixture::new().await;
        for sql in [
            "SELECT region, SUM(amount + 1) FILTER (WHERE status = 'open'), \
             MIN(amount + 1) FILTER (WHERE status = 'open') \
             FROM orders GROUP BY region ORDER BY region",
            "SELECT region, SUM(value) FILTER (WHERE status = 'open') FROM \
             (SELECT region, status, amount + 1 AS value FROM orders) q \
             GROUP BY region ORDER BY region",
        ] {
            fixture.check(sql, 1).await;
        }
    }

    #[tokio::test]
    async fn filter_columns_participate_in_covering_access_selection() {
        for cover_filter in [false, true] {
            let fixture = Fixture::new().await;
            let mut cover = vec!["amount".to_string()];
            if cover_filter {
                cover.push("flag".to_string());
            }
            fixture
                .install_indexed_table(
                    "filtered_index",
                    vec![
                        TableColumnConfig::new("id", DataType::Int64, false),
                        TableColumnConfig::new("category", DataType::Int64, false),
                        TableColumnConfig::new("amount", DataType::Int64, false),
                        TableColumnConfig::new("flag", DataType::Int64, false),
                    ],
                    &["id"],
                    vec![IndexSpec::new("category_idx", vec!["category".to_string()])
                        .unwrap()
                        .with_cover_columns(cover)],
                    (0..4)
                        .map(|id| KvRow {
                            values: vec![
                                CellValue::Int64(id),
                                CellValue::Int64(id / 2),
                                CellValue::Int64(id * 10),
                                CellValue::Int64(id % 2),
                            ],
                        })
                        .collect(),
                    vec![
                        Arc::new(Int64Array::from(vec![0, 1, 2, 3])),
                        Arc::new(Int64Array::from(vec![0, 0, 1, 1])),
                        Arc::new(Int64Array::from(vec![0, 10, 20, 30])),
                        Arc::new(Int64Array::from(vec![0, 1, 0, 1])),
                    ],
                )
                .await;
            fixture.check("SELECT category, SUM(amount) FILTER (WHERE flag = 1) FROM filtered_index WHERE category = 1 GROUP BY category", 1).await;
            assert_eq!(
                fixture.rows.scanned_rows.load(AtomicOrdering::Relaxed),
                if cover_filter { 2 } else { 4 }
            );
            fixture
                .check(
                    "SELECT SUM(amount) FILTER (WHERE category = 1) FROM filtered_index",
                    1,
                )
                .await;
            assert_eq!(fixture.rows.scanned_rows.load(AtomicOrdering::Relaxed), 2);
        }
    }

    #[tokio::test]
    async fn integer_arithmetic_wraps_in_both_ansi_modes() {
        let fixture = Fixture::new().await;
        let sql = "SELECT COUNT(*), SUM(amount + 9223372036854775807) FROM orders";
        fixture.check(sql, 1).await;
        for ctx in [&fixture.native, &fixture.store] {
            values(ctx, "SET datafusion.execution.enable_ansi_mode = true")
                .await
                .unwrap();
        }
        fixture.check(sql, 1).await;
    }

    #[tokio::test]
    async fn avg_converts_each_integer_before_accumulation() {
        let fixture = Fixture::with_amounts([Some(i64::MAX), Some(i64::MAX), None, Some(3)]).await;
        fixture
            .check(
                "SELECT SUM(amount), AVG(amount), MIN(amount), MAX(amount) FROM orders",
                1,
            )
            .await;
    }

    #[tokio::test]
    async fn integer_division_preserves_quotients_and_nulls_in_reduce() {
        let fixture = Fixture::with_amounts([Some(257), Some(-30), None, Some(20)]).await;
        fixture
            .check("SELECT SUM(amount / 2), COUNT(*) FROM orders", 1)
            .await;
        fixture
            .check(
                "SELECT region, SUM(amount / id), AVG(amount / id), COUNT(*), \
                 SUM(amount / 2) FILTER (WHERE status = 'open') \
                 FROM orders GROUP BY region ORDER BY region",
                1,
            )
            .await;

        fixture
            .replace_value_column(
                DataType::UInt64,
                vec![
                    CellValue::UInt64(u64::MAX),
                    CellValue::UInt64(31),
                    CellValue::Null,
                    CellValue::UInt64(1),
                ],
                Arc::new(UInt64Array::from(vec![
                    Some(u64::MAX),
                    Some(31),
                    None,
                    Some(1),
                ])),
            )
            .await;
        fixture
            .check(
                "SELECT SUM(value / arrow_cast(2, 'UInt64')), SUM(value / value), \
                 AVG(value / arrow_cast(2, 'UInt64')) FROM numbers",
                1,
            )
            .await;
    }

    #[tokio::test]
    async fn integer_float_casts_use_explicit_wire_casts() {
        let signed = vec![
            Some(i64::MIN),
            Some((1_i64 << 53) - 1),
            Some((1_i64 << 53) + 1),
            Some(i64::MAX),
            None,
        ];
        let unsigned = vec![
            Some(0),
            Some((1_u64 << 53) - 1),
            Some((1_u64 << 53) + 1),
            Some(u64::MAX),
            None,
        ];
        for (data_type, cells, array) in [
            (
                DataType::Int64,
                signed
                    .iter()
                    .map(|v| v.map(CellValue::Int64).unwrap_or(CellValue::Null))
                    .collect(),
                Arc::new(Int64Array::from(signed)) as ArrayRef,
            ),
            (
                DataType::UInt64,
                unsigned
                    .iter()
                    .map(|v| v.map(CellValue::UInt64).unwrap_or(CellValue::Null))
                    .collect(),
                Arc::new(UInt64Array::from(unsigned)) as ArrayRef,
            ),
        ] {
            let fixture = Fixture::new().await;
            fixture.replace_value_column(data_type, cells, array).await;
            for cast in ["CAST", "TRY_CAST"] {
                let expr = format!("{cast}(value AS DOUBLE)");
                for (sql, requests, grouped) in [
                    (format!("SELECT SUM({expr}) FROM numbers"), 1, false),
                    (format!("SELECT {expr}, SUM({expr}), COUNT(*) FROM numbers GROUP BY {expr} ORDER BY 1"), 1, true),
                    (format!("SELECT MIN({expr}), MAX({expr}) FROM numbers WHERE id IN (0, 2, 4)"), 3, false),
                ] {
                    fixture.check(&sql, requests).await;
                    for request in fixture.rows.reductions.lock().unwrap().iter() {
                        let request = exoware_sdk::to_domain_reduce_request(&request.params).unwrap();
                        if grouped {
                            assert!(matches!(request.group_by[0], KvExpr::CastFloat64(_)), "{sql}: {request:?}");
                        }
                        assert!(matches!(request.reducers[0].expr, Some(KvExpr::CastFloat64(_))), "{sql}: {request:?}");
                    }
                }
            }
            fixture
                .check("SELECT SUM(value * 2.0) FROM numbers", 1)
                .await;
            let requests = fixture.rows.reductions.lock().unwrap();
            let request = exoware_sdk::to_domain_reduce_request(&requests[0].params).unwrap();
            assert!(
                matches!(request.reducers[0].expr, Some(KvExpr::Mul(_, _))),
                "{request:?}"
            );
        }
    }

    #[tokio::test]
    async fn floating_division_preserves_zero_divisors_and_nulls_in_reduce() {
        let fixture = Fixture::new().await;
        fixture
            .replace_value_column(
                DataType::Float64,
                vec![
                    CellValue::Float64(1.0),
                    CellValue::Float64(2.0),
                    CellValue::Null,
                    CellValue::Float64(4.0),
                ],
                Arc::new(Float64Array::from(vec![
                    Some(1.0),
                    Some(2.0),
                    None,
                    Some(4.0),
                ])),
            )
            .await;
        for sql in [
            "SELECT SUM(value / 0.0), AVG(value / 0.0), COUNT(value / 0.0) FROM numbers",
            "SELECT SUM(value / -0.0), AVG(value / -0.0) FROM numbers",
            "SELECT SUM(value / (value - 1.0)), AVG(value / value), COUNT(*) FROM numbers",
            "SELECT SUM(value / (value - 1.0)) FROM numbers WHERE id > 0",
            "SELECT COUNT((value - value) / (value - value)) FROM numbers",
        ] {
            fixture.check(sql, 1).await;
        }
    }

    #[tokio::test]
    async fn integer_division_errors_come_from_reduce() {
        let fixture = Fixture::with_amounts([None, Some(i64::MIN), Some(0), Some(20)]).await;
        for (sql, error_fragment) in [
            ("SELECT SUM(amount / 0) FROM orders", "Divide by zero"),
            (
                "SELECT SUM(CAST(amount / 0 AS DOUBLE)) FROM orders",
                "Divide by zero",
            ),
            (
                "SELECT SUM(TRY_CAST(amount / 0 AS DOUBLE)) FROM orders",
                "Divide by zero",
            ),
            ("SELECT SUM(id / amount) FROM orders", "Divide by zero"),
            ("SELECT SUM(amount / -1) FROM orders", "overflow"),
            (
                "SELECT region, COUNT(*), SUM(id / (id - 1)) FILTER (WHERE id > 1) \
                 FROM orders GROUP BY region",
                "Divide by zero",
            ),
            (
                "SELECT SUM(amount + id / (id - 1)) FROM orders",
                "Divide by zero",
            ),
        ] {
            let native_error = values(&fixture.native, sql).await.unwrap_err();
            assert!(
                native_error
                    .to_string()
                    .to_lowercase()
                    .contains(&error_fragment.to_lowercase()),
                "{sql}: {native_error}"
            );
            fixture.rows.paths.lock().unwrap().clear();
            fixture.rows.reductions.lock().unwrap().clear();
            let store_error = values(&fixture.store, sql).await.unwrap_err();
            assert!(
                store_error
                    .to_string()
                    .to_lowercase()
                    .contains(&error_fragment.to_lowercase()),
                "{sql}: {store_error}"
            );
            let paths = fixture.rows.paths.lock().unwrap();
            assert_eq!(paths.len(), 1, "{sql}: {paths:?}");
            assert!(paths[0].ends_with("/Reduce"), "{sql}: {paths:?}");
        }
    }

    #[tokio::test]
    async fn integer_division_preserves_filter_and_case_evaluation_order() {
        let fixture = Fixture::new().await;
        for sql in [
            "SELECT COUNT(*), SUM(id / (id - 1)) FILTER (WHERE id > 1) FROM orders",
            "SELECT COUNT(*), SUM(v / (v - 1)) FILTER (WHERE v > 1) FROM (SELECT id AS v FROM orders) q",
        ] {
            fixture.check(sql, 2).await;
        }
        fixture.rows.reductions.lock().unwrap().clear();
        for sql in [
            "SELECT SUM(id / (id - 1)) FILTER (WHERE id > 1), MIN(id / (id - 1)) FILTER (WHERE id > 1) FROM orders",
            "SELECT SUM(v) FILTER (WHERE id > 1) FROM (SELECT id, id / (id - 1) AS v FROM orders) q",
            "SELECT SUM(CASE WHEN id > 1 THEN v END) FROM (SELECT id, id / (id - 1) AS v FROM orders) q",
        ] {
            for context in [&fixture.native, &fixture.store] {
                let error = values(context, sql).await.unwrap_err();
                assert!(
                    error.to_string().contains("Divide by zero"),
                    "{sql}: {error}"
                );
            }
            assert!(fixture.rows.reductions.lock().unwrap().is_empty(), "{sql}");
        }
        fixture
            .check(
                "SELECT COUNT(*), SUM(CASE WHEN id > 1 THEN id / (id - 1) END) FROM orders",
                2,
            )
            .await;
        fixture
            .check(
                "SELECT region, COUNT(*), SUM(CASE WHEN id > 1 THEN id / (id - 1) END) \
                 FROM orders GROUP BY region ORDER BY region",
                2,
            )
            .await;

        let fixture = Fixture::with_amounts([None; 4]).await;
        fixture
            .check("SELECT SUM(amount / 0), COUNT(amount / 0) FROM orders", 1)
            .await;
    }

    #[tokio::test]
    async fn lower_preserves_unicode_and_nulls_in_reduce() {
        let fixture = Fixture::new().await;
        let strings = vec![Some("İΣ"), Some("ΟΣ"), Some("Straße"), Some(""), None];
        fixture
            .replace_value_column(
                DataType::Utf8,
                strings
                    .iter()
                    .map(|value| {
                        value
                            .map(|value| CellValue::Utf8(value.to_owned()))
                            .unwrap_or(CellValue::Null)
                    })
                    .collect(),
                Arc::new(StringArray::from(strings)),
            )
            .await;
        fixture
            .check(
                "SELECT lower(value), COUNT(*), MIN(lower(value)), MAX(lower(value)) \
                 FROM numbers GROUP BY lower(value) ORDER BY lower(value)",
                1,
            )
            .await;
    }

    #[tokio::test]
    async fn date_trunc_preserves_day_boundaries_in_reduce() {
        use datafusion::arrow::array::TimestampMicrosecondArray;

        let fixture = Fixture::new().await;
        let day = 86_400_000_000;
        let timestamps = vec![
            Some(-day - 1),
            Some(-1),
            Some(0),
            Some(day - 1),
            Some(day),
            None,
        ];
        fixture
            .replace_value_column(
                DataType::Timestamp(TimeUnit::Microsecond, None),
                timestamps
                    .iter()
                    .map(|value| value.map(CellValue::Timestamp).unwrap_or(CellValue::Null))
                    .collect(),
                Arc::new(TimestampMicrosecondArray::from(timestamps)),
            )
            .await;
        fixture
            .check(
                "SELECT date_trunc('day', value), COUNT(*), MIN(date_trunc('day', value)), \
                 MAX(date_trunc('day', value)) FROM numbers \
                 GROUP BY date_trunc('day', value) ORDER BY date_trunc('day', value)",
                1,
            )
            .await;
    }

    #[tokio::test]
    async fn date_trunc_date_casts_preserve_units_and_fallback() {
        use datafusion::arrow::array::{Date32Array, Date64Array};

        for (data_type, rows, array) in [
            (
                DataType::Date32,
                vec![
                    CellValue::Date32(-1),
                    CellValue::Date32(0),
                    CellValue::Date32(1),
                    CellValue::Null,
                ],
                Arc::new(Date32Array::from(vec![Some(-1), Some(0), Some(1), None])) as ArrayRef,
            ),
            (
                DataType::Date64,
                vec![
                    CellValue::Date64(-86_400_000),
                    CellValue::Date64(0),
                    CellValue::Date64(86_400_000),
                    CellValue::Null,
                ],
                Arc::new(Date64Array::from(vec![
                    Some(-86_400_000),
                    Some(0),
                    Some(86_400_000),
                    None,
                ])) as ArrayRef,
            ),
        ] {
            let fixture = Fixture::new().await;
            fixture.replace_value_column(data_type, rows, array).await;
            for expr in [
                "date_trunc('day', value)",
                "date_trunc('day', arrow_cast(value, 'Timestamp(Microsecond, None)'))",
            ] {
                let sql =
                    format!("SELECT {expr}, COUNT(*) FROM numbers GROUP BY {expr} ORDER BY 1");
                let expected = values(&fixture.native, &sql).await.unwrap();
                let actual = values(&fixture.store, &sql).await.unwrap();
                assert_eq!(actual, expected, "{sql}");
                assert!(fixture.rows.reductions.lock().unwrap().is_empty(), "{sql}");
            }
        }
    }

    #[tokio::test]
    async fn unsupported_casts_and_filters_preserve_results_and_errors() {
        let fixture = Fixture::with_amounts([Some(257), Some(30), None, Some(20)]).await;
        for sql in [
            "SELECT SUM(TRY_CAST(amount AS TINYINT)) FROM orders",
            "SELECT COUNT(*) FROM orders WHERE TRY_CAST(status AS BIGINT) IS NULL",
            "SELECT SUM(amount) FROM orders WHERE status = 'open' AND amount % 3 = 1",
            "SELECT COUNT(*) FILTER (WHERE amount / 2 > 10) FROM orders",
            "SELECT SUM(amount) FROM (SELECT amount FROM orders LIMIT 2) q",
        ] {
            let expected = values(&fixture.native, sql).await.unwrap();
            let actual = values(&fixture.store, sql).await.unwrap();
            assert_eq!(actual, expected, "{sql}");
        }
        let sql = "SELECT SUM(CAST(amount AS TINYINT)) FROM orders";
        assert!(values(&fixture.native, sql).await.is_err());
        assert!(values(&fixture.store, sql).await.is_err());
    }

    #[tokio::test]
    async fn empty_inputs_and_null_groups_preserve_aggregate_shapes() {
        let fixture = Fixture::with_amounts([None; 4]).await;
        fixture
        .check(
            "SELECT SUM(amount), AVG(amount), MIN(amount), MAX(amount), COUNT(amount) FROM orders",
            1,
        )
        .await;
        fixture
            .check(
                "SELECT SUM(amount), AVG(amount), COUNT(*) FROM orders WHERE status = 'missing'",
                1,
            )
            .await;
        fixture
            .check(
                "SELECT DISTINCT region FROM orders WHERE status = 'missing'",
                1,
            )
            .await;
    }

    #[tokio::test]
    async fn float_groups_and_worker_filters_preserve_total_ordering() {
        let fixture = Fixture::new().await;
        let values = vec![
            Some(-0.0),
            Some(0.0),
            Some(f64::NEG_INFINITY),
            Some(f64::INFINITY),
            Some(f64::NAN),
            Some(-f64::NAN),
            None,
        ];
        fixture
            .replace_value_column(
                DataType::Float64,
                values
                    .iter()
                    .map(|value| value.map(CellValue::Float64).unwrap_or(CellValue::Null))
                    .collect(),
                Arc::new(Float64Array::from(values)),
            )
            .await;
        for sql in [
            "SELECT value, COUNT(*) FROM numbers GROUP BY value ORDER BY value",
            "SELECT MIN(value), MAX(value) FROM numbers",
            "SELECT COUNT(*) FROM numbers WHERE value = 0.0",
            "SELECT COUNT(*) FROM numbers WHERE value > 0.0",
            "SELECT COUNT(*) FROM numbers WHERE value < 0.0",
            "SELECT COUNT(*) FROM numbers WHERE value >= 'NaN'::DOUBLE",
        ] {
            fixture.check(sql, 1).await;
        }
    }

    // Every input batch is one Store range, in request order. Partial states
    // come from raw Arrow rows so the oracle is independent of the Store wire decoder.
    async fn reference_extrema_ranges(
        batches: Vec<RecordBatch>,
        partial_final: bool,
    ) -> Vec<Vec<ScalarValue>> {
        use datafusion::datasource::memory::MemorySourceConfig;
        use datafusion::execution::context::SessionConfig;
        use datafusion::functions_aggregate::{
            count::count_udaf,
            min_max::{max_udaf, min_udaf},
        };
        use datafusion::physical_expr::aggregate::AggregateExprBuilder;
        use datafusion::physical_expr::expressions::Column;
        use datafusion::physical_expr::PhysicalExpr;
        use datafusion::physical_plan::aggregates::{
            AggregateExec, AggregateMode, PhysicalGroupBy,
        };
        use datafusion::physical_plan::{collect, ExecutionPlan};

        let schema = batches[0].schema();
        let groups = PhysicalGroupBy::new_single(vec![(
            Arc::new(Column::new("category", 2)) as Arc<dyn PhysicalExpr>,
            "category".to_string(),
        )]);
        let aggregates = [min_udaf(), max_udaf(), count_udaf()]
            .into_iter()
            .enumerate()
            .map(|(index, function)| {
                Arc::new(
                    AggregateExprBuilder::new(function, vec![Arc::new(Column::new("value", 4))])
                        .schema(schema.clone())
                        .alias(format!("result_{index}"))
                        .build()
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let mut config = SessionConfig::new();
        config
            .options_mut()
            .execution
            .skip_partial_aggregation_probe_rows_threshold = usize::MAX;
        let context = SessionContext::new_with_config(config).task_ctx();
        let (mode, source, groups) = if partial_final {
            let mut states = Vec::new();
            let mut state_schema = None;
            for batch in batches {
                let source =
                    MemorySourceConfig::try_new_exec(&[vec![batch]], schema.clone(), None).unwrap();
                let partial = AggregateExec::try_new(
                    AggregateMode::Partial,
                    groups.clone(),
                    aggregates.clone(),
                    vec![None; aggregates.len()],
                    source,
                    schema.clone(),
                )
                .unwrap();
                state_schema.get_or_insert_with(|| partial.schema());
                states.extend(collect(Arc::new(partial), context.clone()).await.unwrap());
            }
            (
                AggregateMode::Final,
                MemorySourceConfig::try_new_exec(&[states], state_schema.unwrap(), None).unwrap(),
                groups.as_final(),
            )
        } else {
            (
                AggregateMode::Single,
                MemorySourceConfig::try_new_exec(&[batches], schema.clone(), None).unwrap(),
                groups,
            )
        };
        let aggregate =
            AggregateExec::try_new(mode, groups, aggregates, vec![None; 3], source, schema)
                .unwrap();
        let batches = collect(Arc::new(aggregate), context).await.unwrap();
        let mut rows = batch_values(&batches).unwrap();
        rows.sort_by_key(|row| match &row[0] {
            ScalarValue::Int64(value) => *value,
            other => panic!("unexpected group key {other:?}"),
        });
        rows
    }

    #[tokio::test]
    async fn grouped_float_aggregates_use_reduce_across_ranges() {
        let fixture = Fixture::new().await;
        fixture
            .install_float_ranges(&[
                (1, 1, Some(1), 1, Some(2.0)),
                (1, 2, Some(1), 1, Some(4.0)),
                (1, 3, Some(2), 0, Some(50.0)),
                (1, 4, Some(3), 1, None),
                (1, 5, None, 1, Some(8.0)),
                (3, 1, Some(1), 1, Some(12.0)),
                (3, 2, Some(2), 0, Some(70.0)),
                (3, 3, Some(3), 1, None),
                (3, 4, None, 0, Some(16.0)),
                (5, 1, Some(1), 0, None),
                (5, 2, Some(4), 1, Some(24.0)),
                (9, 1, Some(99), 1, Some(999.0)),
            ])
            .await;

        let aggregates = [
            "COUNT(*)",
            "MIN(value)",
            "AVG(value)",
            "COUNT(value)",
            "MAX(value)",
            "SUM(value)",
        ];
        let filtered = |flag| {
            aggregates
                .iter()
                .map(|aggregate| format!("{aggregate} FILTER (WHERE flag = {flag})"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        for (name, select) in [
            ("fused", aggregates.join(", ")),
            ("filtered", filtered(1)),
            ("empty_filter", filtered(99)),
            ("interleaved", "MIN(value) FILTER (WHERE flag = 1), COUNT(*), AVG(value) FILTER (WHERE flag = 1), SUM(value), COUNT(value) FILTER (WHERE flag = 1), MAX(value)".to_string()),
        ] {
            let sql = format!("SELECT category, {select} FROM float_ranges WHERE bucket IN (1, 3, 5, 7) GROUP BY category ORDER BY category NULLS FIRST");
            let expected = values(&fixture.native, &sql).await.unwrap();
            assert_eq!(expected.len(), 5, "{name}");
            assert!(expected.iter().all(|row| row.len() == 7), "{name}");
            assert_eq!(expected[0][0], ScalarValue::Int64(None), "{name}");
            assert_eq!(expected[3][0], ScalarValue::Int64(Some(3)), "{name}");
            assert_eq!(expected[3][3], ScalarValue::Float64(None), "null-only AVG: {name}");
            if name == "empty_filter" {
                for row in &expected {
                    assert_eq!(row[1], ScalarValue::Int64(Some(0)));
                    assert_eq!(row[4], ScalarValue::Int64(Some(0)));
                    for index in [2, 3, 5, 6] {
                        assert_eq!(row[index], ScalarValue::Float64(None), "{name}");
                    }
                }
            } else {
                assert_eq!(expected[1][0], ScalarValue::Int64(Some(1)), "{name}");
                assert_eq!(expected[1][3], ScalarValue::Float64(Some(6.0)), "weighted AVG: {name}");
            }
            if name == "filtered" {
                assert_eq!(expected[2][0], ScalarValue::Int64(Some(2)));
                assert_eq!(expected[2][1], ScalarValue::Int64(Some(0)));
                assert_eq!(expected[2][3], ScalarValue::Float64(None), "filtered empty AVG");
            }
            fixture.check_expected(&sql, 4, &expected).await;
            fixture.assert_range_jobs(4, 1, 11);
            if name == "fused" {
                assert!(fixture.rows.reductions.lock().unwrap().iter()
                    .all(|request| request.params.reducers.len() == 7));
            }
        }

        for grouped in [false, true] {
            let (key, group_by) = if grouped {
                (
                    "category, ",
                    " GROUP BY category ORDER BY category NULLS FIRST",
                )
            } else {
                ("", "")
            };
            let sql = format!("SELECT {key}COUNT(*), COUNT(value), SUM(value), AVG(value), MIN(value), MAX(value) FROM float_ranges WHERE bucket IN (11, 13){group_by}");
            let expected = values(&fixture.native, &sql).await.unwrap();
            if grouped {
                assert!(expected.is_empty());
            } else {
                assert_eq!(
                    expected,
                    vec![vec![
                        ScalarValue::Int64(Some(0)),
                        ScalarValue::Int64(Some(0)),
                        ScalarValue::Float64(None),
                        ScalarValue::Float64(None),
                        ScalarValue::Float64(None),
                        ScalarValue::Float64(None),
                    ]]
                );
            }
            fixture.check_expected(&sql, 2, &expected).await;
            fixture.assert_range_jobs(2, 1, 0);
        }
    }

    #[tokio::test]
    async fn grouped_float_extrema_preserve_partial_final_range_order() {
        let nan_a = f64::from_bits(0x7ff8_0000_0000_0001);
        let nan_b = f64::from_bits(0x7ff8_0000_0000_0002);
        let negative_nan = f64::from_bits(0xfff8_0000_0000_0001);
        let cases = [
            ("positive_infinity", vec![Some(f64::INFINITY)], 1),
            ("negative_infinity", vec![Some(f64::NEG_INFINITY)], 1),
            ("negative_zero_first", vec![Some(-0.0), Some(0.0)], 1),
            ("positive_zero_first", vec![Some(0.0), Some(-0.0)], 1),
            ("positive_nan_first", vec![Some(nan_a), Some(1.0)], 1),
            ("positive_nan_last", vec![Some(1.0), Some(nan_a)], 1),
            ("negative_nan_first", vec![Some(negative_nan), Some(1.0)], 1),
            ("negative_nan_last", vec![Some(1.0), Some(negative_nan)], 1),
            ("payloads_forward", vec![Some(nan_a), Some(nan_b)], 1),
            ("payloads_reverse", vec![Some(nan_b), Some(nan_a)], 1),
            ("signs_forward", vec![Some(negative_nan), Some(nan_a)], 1),
            ("signs_reverse", vec![Some(nan_a), Some(negative_nan)], 1),
            (
                "non_associative_min",
                vec![Some(1.0), Some(nan_a), Some(2.0)],
                1,
            ),
            (
                "non_associative_max",
                vec![Some(2.0), Some(nan_b), Some(1.0)],
                1,
            ),
            ("null_only", vec![None, None], 1),
            ("late_group", vec![Some(3.0)], 0),
            ("null_then_finite", vec![None, Some(4.0)], 1),
            ("finite_then_null", vec![Some(4.0), None], 1),
        ];
        let mut rows = Vec::new();
        for (category, (_, values, split)) in cases.iter().enumerate() {
            for (index, value) in values.iter().enumerate() {
                rows.push((
                    if index < *split { 1 } else { 3 },
                    (category * 10 + index) as i64,
                    Some(category as i64),
                    1,
                    *value,
                ));
            }
        }
        rows.sort_by_key(|row| (row.0, row.1));
        let first_range_len = rows.iter().take_while(|row| row.0 == 1).count();
        let fixture = Fixture::new().await;
        let raw = fixture.install_float_ranges(&rows).await;
        let ranges = vec![
            raw.slice(0, 0),
            raw.slice(0, first_range_len),
            raw.slice(first_range_len, raw.num_rows() - first_range_len),
            raw.slice(0, 0),
        ];
        let single = reference_extrema_ranges(ranges.clone(), false).await;
        let partial_final = reference_extrema_ranges(ranges, true).await;
        assert_eq!(partial_final.len(), cases.len());
        for (case, column, single_value, final_value) in [
            ("non_associative_min", 1, 2.0, 1.0),
            ("non_associative_max", 2, 1.0, 2.0),
        ] {
            let index = cases.iter().position(|(name, _, _)| *name == case).unwrap();
            assert_eq!(
                single[index][column],
                ScalarValue::Float64(Some(single_value)),
                "{case}"
            );
            assert_eq!(
                partial_final[index][column],
                ScalarValue::Float64(Some(final_value)),
                "{case}"
            );
        }

        // Partial/Final defines the result for this range order. ScalarValue
        // equality checks NaN payload/sign bits and signed-zero representatives.
        fixture.check_expected(
            "SELECT category, MIN(value), MAX(value), COUNT(value) FROM float_ranges WHERE bucket IN (0, 1, 3, 7) GROUP BY category ORDER BY category NULLS FIRST",
            4,
            &partial_final,
        ).await;
        fixture.assert_range_jobs(4, 1, rows.len());

        for (index, (name, inputs, _)) in cases.iter().enumerate() {
            assert_eq!(
                partial_final[index][0],
                ScalarValue::Int64(Some(index as i64)),
                "{name}"
            );
            assert_eq!(
                partial_final[index][3],
                ScalarValue::Int64(Some(inputs.iter().flatten().count() as i64)),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn grouped_float_extrema_preserve_nan_and_signed_zero_results() {
        for inputs in [
            vec![f64::INFINITY],
            vec![f64::NEG_INFINITY],
            vec![1.0, f64::NAN],
            vec![f64::NAN, 1.0],
            vec![-0.0, 0.0],
        ] {
            let fixture = Fixture::new().await;
            let len = inputs.len();
            fixture
                .install_indexed_table(
                    "extrema",
                    vec![
                        TableColumnConfig::new("id", DataType::Int64, false),
                        TableColumnConfig::new("category", DataType::Int64, false),
                        TableColumnConfig::new("flag", DataType::Int64, false),
                        TableColumnConfig::new("value", DataType::Float64, false),
                    ],
                    &["id"],
                    vec![],
                    inputs
                        .iter()
                        .enumerate()
                        .map(|(id, value)| KvRow {
                            values: vec![
                                CellValue::Int64(id as i64),
                                CellValue::Int64(7),
                                CellValue::Int64(1),
                                CellValue::Float64(*value),
                            ],
                        })
                        .collect(),
                    vec![
                        Arc::new(Int64Array::from_iter_values(0..len as i64)),
                        Arc::new(Int64Array::from(vec![7; len])),
                        Arc::new(Int64Array::from(vec![1; len])),
                        Arc::new(Float64Array::from(inputs)),
                    ],
                )
                .await;
            for function in ["MIN", "MAX"] {
                let sql = format!(
                "SELECT category, {function}(value) FROM extrema WHERE flag = 1 GROUP BY category"
            );
                fixture.check(&sql, 1).await;
            }
            fixture
                .check(
                    "SELECT MIN(value), MAX(value) FROM extrema WHERE flag = 1",
                    1,
                )
                .await;
        }
    }

    #[tokio::test]
    async fn fixed_binary_value_widths_preserve_aggregate_results() {
        let mut failures = Vec::new();
        for width in [0, 255, 256, 300] {
            let fixture = Fixture::new().await;
            let mut array = FixedSizeBinaryBuilder::new(width);
            let mut cells = Vec::new();
            for byte in [Some(1), Some(1), Some(2), None] {
                if let Some(byte) = byte {
                    let value = vec![byte; width as usize];
                    array.append_value(&value).unwrap();
                    cells.push(CellValue::FixedBinary(value));
                } else {
                    array.append_null();
                    cells.push(CellValue::Null);
                }
            }
            fixture
                .replace_value_column(
                    DataType::FixedSizeBinary(width),
                    cells,
                    Arc::new(array.finish()),
                )
                .await;
            for sql in [
                "SELECT COUNT(value) FROM numbers",
                "SELECT value, COUNT(*) FROM numbers GROUP BY value ORDER BY value",
                "SELECT COUNT(*) FROM numbers WHERE value IS NOT NULL",
            ] {
                // DataFusion grouping cannot materialize zero-width binary output arrays
                if width == 0 && sql.contains("GROUP BY") {
                    continue;
                }
                let expected = values(&fixture.native, sql).await.unwrap();
                fixture.rows.paths.lock().unwrap().clear();
                match values(&fixture.store, sql).await {
                    Ok(actual) => {
                        assert_eq!(actual, expected, "width {width}: {sql}");
                        let paths = fixture.rows.paths.lock().unwrap();
                        assert_eq!(
                            paths
                                .iter()
                                .filter(|path| path.ends_with("/Reduce"))
                                .count(),
                            usize::from(width <= 255),
                            "width {width}: {sql}: {paths:?}"
                        );
                        assert_eq!(
                            paths.iter().filter(|path| path.ends_with("/Range")).count(),
                            usize::from(width > 255),
                            "width {width}: {sql}: {paths:?}"
                        );
                    }
                    Err(error) => failures.push(format!("width {width}: {sql}: {error}")),
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[tokio::test]
    async fn count_output_rejects_out_of_range_values() {
        let fixture = Fixture::new().await;
        let plan = fixture
            .store
            .sql("SELECT region, COUNT(*) FROM orders GROUP BY region")
            .await
            .unwrap()
            .create_physical_plan()
            .await
            .unwrap();
        let mut source = None;
        plan.apply(|node| {
            if let Some(exec) = node.downcast_ref::<KvAggregateExec>() {
                source = Some(exec.clone());
            }
            Ok(TreeNodeRecursion::Continue)
        })
        .unwrap();
        let source = source.unwrap();
        let job = &source.spec.aggregate_jobs[0];
        for value in [
            Some(KvReducedValue::UInt64(0)),
            Some(KvReducedValue::UInt64(i64::MAX as u64)),
            Some(KvReducedValue::UInt64(i64::MAX as u64 + 1)),
            Some(KvReducedValue::UInt64(u64::MAX)),
            None,
            Some(KvReducedValue::Int64(1)),
            Some(KvReducedValue::Float64(1.0)),
        ] {
            let response = RangeReduceResponse {
                results: Vec::new(),
                groups: [Some(KvReducedValue::UInt64(0)), value.clone()]
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| RangeReduceGroup {
                        group_values: vec![Some(KvReducedValue::Utf8(index.to_string()))],
                        results: vec![RangeReduceResult { value }],
                    })
                    .collect(),
            };
            let (results, groups) = exoware_sdk::to_proto_reduce_response(response);
            let frame = connectrpc::StreamMessage::from_message(&query::ReduceResponse {
                results,
                groups,
                ..Default::default()
            });
            let actual = source.decode_reduce_batch(job, frame.view());
            match value {
                Some(KvReducedValue::UInt64(count)) => {
                    let native = ScalarValue::UInt64(Some(count)).cast_to(&DataType::Int64);
                    if let Ok(expected) = native {
                        let batch = actual.unwrap();
                        assert_eq!(batch.num_rows(), 2);
                        assert_eq!(batch.column(1).null_count(), 0);
                        assert_eq!(
                            ScalarValue::try_from_array(batch.column(1), 1).unwrap(),
                            expected
                        );
                    } else {
                        assert!(
                            actual.is_err(),
                            "overflowing second count must fail the batch"
                        );
                    }
                }
                _ => assert!(actual.is_err(), "count must be a present UInt64"),
            }
        }
        for malformed in ["flags", "missing_key", "extra_key", "results", "value"] {
            let mut group: query::RangeReduceGroup = RangeReduceGroup {
                group_values: vec![Some(KvReducedValue::Utf8("east".to_string()))],
                results: vec![RangeReduceResult {
                    value: Some(KvReducedValue::UInt64(1)),
                }],
            }
            .into();
            match malformed {
                "flags" => group.group_values_present.clear(),
                "missing_key" => group.group_values.clear(),
                "extra_key" => group.group_values_present[0] = false,
                "results" => group.results.clear(),
                "value" => group.group_values[0] = Default::default(),
                _ => unreachable!(),
            }
            let frame = connectrpc::StreamMessage::from_message(&query::ReduceResponse {
                groups: vec![group],
                ..Default::default()
            });
            assert!(
                source.decode_reduce_batch(job, frame.view()).is_err(),
                "{malformed}"
            );
        }
        fixture.check("SELECT region, amount, status, COUNT(*) FROM orders GROUP BY region, amount, status ORDER BY region, amount, status", 1).await;
    }

    #[tokio::test]
    async fn unsigned_and_decimal_accumulation_preserves_overflow_and_empty_results() {
        let fixture = Fixture::new().await;
        fixture
            .replace_value_column(
                DataType::UInt64,
                vec![
                    CellValue::UInt64(u64::MAX),
                    CellValue::UInt64(2),
                    CellValue::Null,
                ],
                Arc::new(UInt64Array::from(vec![Some(u64::MAX), Some(2), None])),
            )
            .await;
        fixture
            .check(
                "SELECT SUM(value), MIN(value), MAX(value), AVG(value) FROM numbers",
                1,
            )
            .await;
        fixture
            .check(
                "SELECT SUM(value + CAST(1 AS BIGINT UNSIGNED)) FROM numbers",
                1,
            )
            .await;
        let fixture = Fixture::new().await;
        fixture
            .replace_value_column(
                DataType::Decimal128(10, 2),
                vec![
                    CellValue::Decimal128(1234),
                    CellValue::Decimal128(-501),
                    CellValue::Null,
                ],
                Arc::new(
                    Decimal128Array::from(vec![Some(1234), Some(-501), None])
                        .with_precision_and_scale(10, 2)
                        .unwrap(),
                ),
            )
            .await;
        fixture
            .check(
                "SELECT SUM(value), MIN(value), MAX(value), COUNT(value) FROM numbers",
                1,
            )
            .await;
        fixture
            .check(
                "SELECT SUM(value), MIN(value), MAX(value) FROM numbers WHERE id > 5",
                1,
            )
            .await;
        for sql in [
            "SELECT AVG(value) FROM numbers",
            "SELECT SUM(CAST(value AS DECIMAL(10, 1))) FROM numbers",
        ] {
            assert_eq!(
                values(&fixture.store, sql).await.unwrap(),
                values(&fixture.native, sql).await.unwrap(),
                "{sql}"
            );
        }
    }

    #[tokio::test]
    async fn sum_case_one_preserves_null_when_no_rows_contribute() {
        let fixture = Fixture::new().await;
        fixture.check("SELECT SUM(CASE WHEN status = 'missing' THEN 1 END), COUNT(CASE WHEN status = 'missing' THEN 1 END) FROM orders", 1).await;
        fixture.check("SELECT region, SUM(CASE WHEN status = 'open' THEN 1 END), COUNT(*) FROM orders GROUP BY region ORDER BY region", 2).await;
    }

    #[tokio::test]
    async fn variable_text_keys_support_stored_fields_and_row_decoding() {
        let fixture = Fixture::new().await;
        let provider = fixture.store.table_provider("orders").await.unwrap();
        let client = provider.downcast_ref::<KvTable>().unwrap().client.clone();
        let schema = crate::KvSchema::new(client)
            .table(
                "texts",
                vec![
                    TableColumnConfig::new("id", DataType::Utf8, false),
                    TableColumnConfig::new("suffix", DataType::Int64, false),
                    TableColumnConfig::new("label", DataType::Utf8, false),
                    TableColumnConfig::new("measure", DataType::Int64, false),
                ],
                vec!["id".to_string(), "suffix".to_string()],
                vec![IndexSpec::new("label_idx", vec!["label".to_string()])
                    .unwrap()
                    .with_cover_columns(vec!["measure".to_string()])],
            )
            .unwrap();
        schema.register_all(&fixture.store).unwrap();
        let provider = fixture.store.table_provider("texts").await.unwrap();
        let table = provider.downcast_ref::<KvTable>().unwrap();
        let ids = [
            "short",
            "very-long-primary-key-over-sixteen-bytes",
            "a\0b",
            "a\u{1}b",
        ];
        let labels = [
            "x",
            "label-longer-than-sixteen-bytes",
            "label\0zero",
            "label\u{1}escape",
        ];
        {
            let mut stored = fixture.rows.values.lock().unwrap();
            stored.clear();
            for idx in 0..4 {
                let row = KvRow {
                    values: vec![
                        CellValue::Utf8(ids[idx].to_string()),
                        CellValue::Int64(idx as i64),
                        CellValue::Utf8(labels[idx].to_string()),
                        CellValue::Int64(10),
                    ],
                };
                stored.insert(
                    crate::codec::encode_primary_key_from_row(0, &row, &table.model).unwrap(),
                    crate::writer::encode_base_row_value(&row, &table.model)
                        .unwrap()
                        .into(),
                );
                let spec = &table.index_specs[0];
                stored.insert(
                    crate::codec::encode_secondary_index_key(0, spec, &table.model, &row).unwrap(),
                    crate::writer::encode_secondary_index_value(&row, &table.model, spec)
                        .unwrap()
                        .into(),
                );
            }
        }
        let batch = RecordBatch::try_new(
            table.model.schema.clone(),
            vec![
                Arc::new(StringArray::from(ids.to_vec())),
                Arc::new(Int64Array::from(vec![0, 1, 2, 3])),
                Arc::new(StringArray::from(labels.to_vec())),
                Arc::new(Int64Array::from(vec![10; 4])),
            ],
        )
        .unwrap();
        fixture
            .native
            .register_table(
                "texts",
                Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]]).unwrap()),
            )
            .unwrap();
        fixture.check("SELECT label, SUM(measure), COUNT(*) FROM texts WHERE label = 'label-longer-than-sixteen-bytes' GROUP BY label ORDER BY label", 1).await;
        for sql in [
            "SELECT id, SUM(suffix) FROM texts GROUP BY id ORDER BY id",
            "SELECT SUM(suffix) FROM texts",
        ] {
            assert_eq!(
                values(&fixture.store, sql).await.unwrap(),
                values(&fixture.native, sql).await.unwrap(),
                "{sql}"
            );
        }
    }

    #[tokio::test]
    async fn fusion_and_seed_elimination_reduce_store_rows_with_one_session() {
        let fixture = Fixture::new().await;
        fixture
            .check(
                "SELECT SUM(amount), MIN(amount), MAX(amount), AVG(amount) FROM orders",
                1,
            )
            .await;
        assert_eq!(fixture.rows.scanned_rows.load(AtomicOrdering::Relaxed), 4);
        fixture.check("SELECT region, COUNT(*), COUNT(*) FILTER (WHERE status = 'open') FROM orders GROUP BY region ORDER BY region", 1).await;
        assert_eq!(fixture.rows.scanned_rows.load(AtomicOrdering::Relaxed), 4);
        fixture
            .check(
                "SELECT SUM(amount), MIN(amount), MAX(amount) FROM orders WHERE id IN (1, 4)",
                2,
            )
            .await;
        assert_eq!(fixture.rows.scanned_rows.load(AtomicOrdering::Relaxed), 2);
    }

    fn final_reduce_plan(plan: Arc<dyn ExecutionPlan>) -> Arc<dyn ExecutionPlan> {
        let mut found = None;
        plan.apply(|node| {
            if let Some(aggregate) = node.downcast_ref::<AggregateExec>() {
                if matches!(
                    aggregate.mode(),
                    AggregateMode::Final | AggregateMode::FinalPartitioned
                ) && aggregate
                    .input()
                    .exists(|input| Ok(input.downcast_ref::<KvAggregateExec>().is_some()))?
                {
                    assert!(
                        found.is_none(),
                        "expected one Final aggregation over REDUCE"
                    );
                    found = Some(node.clone());
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })
        .unwrap();
        found.expect("Final aggregation must consume the Store REDUCE source")
    }

    fn aggregate_session_with_pool(
        fixture: &Fixture,
        limit: usize,
        target_partitions: usize,
    ) -> (
        SessionContext,
        Arc<datafusion::execution::memory_pool::PeakRecordingPool>,
    ) {
        use datafusion::execution::memory_pool::{FairSpillPool, PeakRecordingPool};
        use datafusion::execution::runtime_env::RuntimeEnvBuilder;
        use datafusion::execution::session_state::SessionStateBuilder;

        let pool = Arc::new(PeakRecordingPool::new(Arc::new(FairSpillPool::new(limit))));
        let runtime = RuntimeEnvBuilder::new()
            .with_memory_pool(pool.clone())
            .build_arc()
            .unwrap();
        let mut state = fixture.store.state();
        *state.config_mut() = state
            .config()
            .clone()
            .with_batch_size(128)
            .with_target_partitions(target_partitions);
        let state = SessionStateBuilder::new_from_existing(state)
            .with_runtime_env(runtime)
            .build();
        (SessionContext::new_with_state(state), pool)
    }

    #[tokio::test]
    async fn sql_final_spills_repeated_reduce_groups_in_query_pool() {
        use datafusion::execution::memory_pool::MemoryPool;

        let fixture = Fixture::new().await;
        let group_count = 8192usize;
        let rows = (0..2)
            .flat_map(|pass| {
                (0..group_count).map(move |group| {
                    (
                        (pass * 32 + (group / 512) * 2 + 1) as i64,
                        group as i64,
                        (group != 0).then(|| format!("{group:05}-{}", "x".repeat(512))),
                        (group != 0).then_some(if pass == 0 { 2.0 } else { 4.0 }),
                    )
                })
            })
            .collect::<Vec<_>>();
        fixture
            .install_indexed_table(
                "spill_ranges",
                vec![
                    TableColumnConfig::new("bucket", DataType::Int64, false),
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("category", DataType::Utf8, true),
                    TableColumnConfig::new("value", DataType::Float64, true),
                ],
                &["bucket", "id"],
                vec![],
                rows.iter()
                    .map(|(bucket, id, category, value)| KvRow {
                        values: vec![
                            CellValue::Int64(*bucket),
                            CellValue::Int64(*id),
                            category
                                .clone()
                                .map(CellValue::Utf8)
                                .unwrap_or(CellValue::Null),
                            value.map(CellValue::Float64).unwrap_or(CellValue::Null),
                        ],
                    })
                    .collect(),
                vec![
                    Arc::new(Int64Array::from_iter_values(rows.iter().map(|row| row.0))),
                    Arc::new(Int64Array::from_iter_values(rows.iter().map(|row| row.1))),
                    Arc::new(StringArray::from_iter(
                        rows.iter().map(|row| row.2.as_deref()),
                    )),
                    Arc::new(Float64Array::from_iter(rows.iter().map(|row| row.3))),
                ],
            )
            .await;
        let buckets = (1..64)
            .step_by(2)
            .map(|bucket| bucket.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("SELECT category, COUNT(*), SUM(value), AVG(value), MIN(value), MAX(value) FROM spill_ranges WHERE bucket IN ({buckets}) GROUP BY category");
        let expected = values(
            &fixture.native,
            &format!("{sql} ORDER BY category NULLS FIRST"),
        )
        .await
        .unwrap();
        let (context, pool) = aggregate_session_with_pool(&fixture, 2 * 1024 * 1024, 2);
        let plan = context
            .sql(&sql)
            .await
            .unwrap()
            .create_physical_plan()
            .await
            .unwrap();
        let final_plan = final_reduce_plan(plan.clone());
        let mut output = plan.execute(0, context.task_ctx()).unwrap();
        let mut actual = Vec::new();
        while let Some(batch) = output.next().await {
            let batch = batch.unwrap();
            assert!(batch.num_rows() <= 128);
            actual.extend(batch_values(&[batch]).unwrap());
        }
        drop(output);
        assert!(final_plan.metrics().unwrap().spill_count().unwrap_or(0) > 0);
        assert!(
            pool.peak_reserved() > 0,
            "the SQL query pool must own Final state"
        );
        assert_eq!(pool.reserved(), 0);
        actual.sort_by(|left, right| left[0].partial_cmp(&right[0]).unwrap());
        assert_eq!(actual.len(), group_count);
        assert_eq!(expected.len(), group_count);
        for (actual, expected) in actual.iter().zip(&expected) {
            assert_eq!(actual, expected);
        }
        fixture.assert_range_jobs(32, 1, rows.len());
        let paths = fixture.rows.paths.lock().unwrap();
        assert_eq!(paths.len(), 32, "{paths:?}");
        assert!(
            paths.iter().all(|path| path.ends_with("/Reduce")),
            "{paths:?}"
        );
    }

    #[tokio::test]
    async fn sql_final_cancellation_drops_current_and_prefetched_reduce_bodies() {
        use datafusion::execution::memory_pool::MemoryPool;

        type BodyReceiver =
            futures::channel::mpsc::UnboundedReceiver<Result<Bytes, std::convert::Infallible>>;

        #[derive(Clone)]
        struct ControlledReduceTransport {
            bodies: Arc<Mutex<BTreeMap<Vec<u8>, BodyReceiver>>>,
            requests: Arc<Mutex<Vec<exoware_sdk::query::ReduceRequest>>>,
        }

        impl connectrpc::client::ClientTransport for ControlledReduceTransport {
            type ResponseBody = axum::body::Body;
            type Error = connectrpc::ConnectError;

            fn send(
                &self,
                request: axum::http::Request<connectrpc::client::ClientBody>,
            ) -> connectrpc::client::BoxFuture<
                'static,
                Result<axum::http::Response<Self::ResponseBody>, Self::Error>,
            > {
                let transport = self.clone();
                Box::pin(async move {
                    assert_eq!(request.uri().path(), "/store.query.v1.Service/Reduce");
                    let bytes = axum::body::to_bytes(
                        axum::body::Body::new(request.into_body()),
                        usize::MAX,
                    )
                    .await
                    .unwrap();
                    let request = crate::tests::decode_reduce_request(&bytes);
                    let receiver = transport
                        .bodies
                        .lock()
                        .unwrap()
                        .remove(&request.start)
                        .expect("unexpected range or retry");
                    transport.requests.lock().unwrap().push(request);
                    Ok(axum::http::Response::builder()
                        .header("content-type", "application/connect+proto")
                        .body(axum::body::Body::from_stream(receiver))
                        .unwrap())
                })
            }
        }

        let transport = ControlledReduceTransport {
            bodies: Arc::new(Mutex::new(BTreeMap::new())),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let client = StoreClient::builder()
            .url("http://query.test")
            .retry_config(exoware_sdk::RetryConfig::disabled())
            .client_transport(transport.clone())
            .build()
            .unwrap();
        let fixture = Fixture::new().await;
        crate::KvSchema::new(PrefixedStoreClient::empty(client))
            .table(
                "pending_ranges",
                vec![
                    TableColumnConfig::new("bucket", DataType::Int64, false),
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("category", DataType::Int64, false),
                ],
                vec!["bucket".to_string(), "id".to_string()],
                vec![],
            )
            .unwrap()
            .register_all(&fixture.store)
            .unwrap();
        let provider = fixture
            .store
            .table_provider("pending_ranges")
            .await
            .unwrap();
        let model = &provider.downcast_ref::<KvTable>().unwrap().model;
        let mut senders = Vec::new();
        for bucket in [1, 3, 5] {
            let start = crate::codec::encode_primary_key_bound(
                model.table_prefix,
                &[&CellValue::Int64(bucket)],
                model,
                false,
            )
            .unwrap();
            let (sender, receiver) = futures::channel::mpsc::unbounded();
            transport
                .bodies
                .lock()
                .unwrap()
                .insert(start.to_vec(), receiver);
            senders.push(sender);
        }
        let frame = |keys: std::ops::Range<i64>| {
            let (results, groups) = exoware_sdk::to_proto_reduce_response(RangeReduceResponse {
                results: vec![],
                groups: keys
                    .map(|key| RangeReduceGroup {
                        group_values: vec![Some(KvReducedValue::Int64(key))],
                        results: vec![RangeReduceResult {
                            value: Some(KvReducedValue::UInt64(1)),
                        }],
                    })
                    .collect(),
            });
            let response = exoware_sdk::query::ReduceResponse {
                results,
                groups,
                detail: Some(exoware_sdk::query::Detail {
                    sequence_number: 7,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            };
            connectrpc::envelope::Envelope::data(response.encode_to_bytes()).encode()
        };
        senders[0].unbounded_send(Ok(frame(0..1))).unwrap();
        senders[0]
            .unbounded_send(Ok(connectrpc::envelope::Envelope::end_stream(
                Bytes::from_static(b"{}"),
            )
            .encode()))
            .unwrap();
        let sql = "SELECT category, COUNT(*) FROM pending_ranges WHERE bucket IN (1, 3, 5, 7) GROUP BY category";
        let (context, pool) = aggregate_session_with_pool(&fixture, 4 * 1024 * 1024, 2);
        let plan = context
            .sql(sql)
            .await
            .unwrap()
            .create_physical_plan()
            .await
            .unwrap();
        final_reduce_plan(plan.clone());
        let mut output = plan.execute(0, context.task_ctx()).unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                assert!(futures::poll!(output.next()).is_pending());
                if transport.requests.lock().unwrap().len() == 3 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let first_peak = pool.peak_reserved();
        assert!(
            first_peak > 0,
            "the seed range must reach Final aggregation before prefetch"
        );
        senders[1].unbounded_send(Ok(frame(1..1025))).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                assert!(futures::poll!(output.next()).is_pending());
                if pool.peak_reserved() > first_peak {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!senders[1].is_closed());
        assert!(!senders[2].is_closed());
        drop(output);
        assert!(senders[1].is_closed(), "current range body must be dropped");
        assert!(
            senders[2].is_closed(),
            "prefetched range body must be dropped"
        );
        assert_eq!(pool.reserved(), 0);
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 3, "the fourth range must not open");
        assert_eq!(requests[0].min_sequence_number, None);
        assert!(requests[1..]
            .iter()
            .all(|request| request.min_sequence_number == Some(7)));
    }

    #[tokio::test]
    async fn sql_final_discards_state_after_a_later_reduce_range_fails() {
        use datafusion::execution::memory_pool::MemoryPool;

        let fixture = Fixture::new().await;
        fixture
            .install_float_ranges(&[
                (1, 1, Some(7), 1, Some(2.0)),
                (3, 1, Some(7), 1, Some(4.0)),
                (5, 1, Some(7), 1, Some(8.0)),
            ])
            .await;
        *fixture
            .rows
            .values
            .lock()
            .unwrap()
            .values_mut()
            .nth(1)
            .unwrap() = Bytes::from_static(b"invalid row");
        let sql = "SELECT category, COUNT(*), SUM(value), AVG(value) FROM float_ranges WHERE bucket IN (1, 3, 5) GROUP BY category";
        let (context, pool) = aggregate_session_with_pool(&fixture, 1024 * 1024, 1);
        let plan = context
            .sql(sql)
            .await
            .unwrap()
            .create_physical_plan()
            .await
            .unwrap();
        final_reduce_plan(plan.clone());
        let mut output = plan.execute(0, context.task_ctx()).unwrap();
        let error = output
            .next()
            .await
            .expect("query must report the later range failure")
            .expect_err("partial range state must not become a successful SQL result");
        let DataFusionError::External(error) = error.find_root() else {
            panic!("expected Store transport error, got {error}");
        };
        let error = error.downcast_ref::<exoware_sdk::ClientError>().unwrap();
        assert_eq!(
            error.rpc_code(),
            Some(connectrpc::ErrorCode::FailedPrecondition)
        );
        assert!(
            pool.peak_reserved() > 0,
            "the first range must have reached Final aggregation"
        );
        assert_eq!(pool.reserved(), 0, "query state must be released on error");
        assert!(output.next().await.is_none());
        drop(output);
        fixture.assert_range_jobs(2, 1, 2);
        let paths = fixture.rows.paths.lock().unwrap();
        assert_eq!(paths.len(), 2, "the third range must not open: {paths:?}");
        assert!(
            paths.iter().all(|path| path.ends_with("/Reduce")),
            "{paths:?}"
        );
    }

    #[tokio::test]
    async fn deterministic_reduce_errors_are_not_retried_by_the_sdk() {
        let fixture = Fixture::new().await;
        let provider = fixture.store.table_provider("orders").await.unwrap();
        let session = provider
            .downcast_ref::<KvTable>()
            .unwrap()
            .client
            .create_session();
        let start = Bytes::from_static(&[0]);
        let end = Bytes::from_static(&[1]);
        let invalid = RangeReduceRequest {
            reducers: vec![RangeReducerSpec {
                op: RangeReduceOp::CountAll,
                expr: Some(KvExpr::Literal(KvReducedValue::Int64(1))),
                filter: None,
            }],
            group_by: vec![],
            filter: None,
        };
        let error = session
            .range_reduce(&start, &end, &invalid)
            .await
            .unwrap_err();
        assert_eq!(
            error.rpc_code(),
            Some(connectrpc::ErrorCode::InvalidArgument)
        );
        assert_eq!(fixture.rows.reductions.lock().unwrap().len(), 1);
        assert_eq!(fixture.rows.scanned_rows.load(AtomicOrdering::Relaxed), 0);
        fixture.rows.reductions.lock().unwrap().clear();
        *fixture
            .rows
            .values
            .lock()
            .unwrap()
            .first_entry()
            .unwrap()
            .get_mut() = Bytes::from_static(b"invalid row");
        let request = RangeReduceRequest {
            reducers: vec![RangeReducerSpec {
                op: RangeReduceOp::SumField,
                expr: Some(KvExpr::Field(KvFieldRef::Value {
                    index: 3,
                    kind: KvFieldKind::Int64,
                    nullable: true,
                })),
                filter: None,
            }],
            group_by: vec![],
            filter: None,
        };
        let error = session
            .range_reduce(&start, &end, &request)
            .await
            .unwrap_err();
        assert_eq!(
            error.rpc_code(),
            Some(connectrpc::ErrorCode::FailedPrecondition)
        );
        assert_eq!(fixture.rows.reductions.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn overlapping_secondary_ranges_do_not_double_count_rows() {
        let fixture = Fixture::new().await;
        let provider = fixture.store.table_provider("orders").await.unwrap();
        let client = provider.downcast_ref::<KvTable>().unwrap().client.clone();
        let schema = crate::KvSchema::new(client)
            .table(
                "points",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("x", DataType::Int64, false),
                    TableColumnConfig::new("y", DataType::Int64, false),
                    TableColumnConfig::new("measure", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("xy", vec!["x".to_string(), "y".to_string()])
                    .unwrap()
                    .with_cover_columns(vec!["measure".to_string()])],
            )
            .unwrap();
        schema.register_all(&fixture.store).unwrap();
        let provider = fixture.store.table_provider("points").await.unwrap();
        let table = provider.downcast_ref::<KvTable>().unwrap();
        {
            let mut stored = fixture.rows.values.lock().unwrap();
            stored.clear();
            for id in [1, 2] {
                let row = KvRow {
                    values: vec![
                        CellValue::Int64(id),
                        CellValue::Int64(2),
                        CellValue::Int64(id),
                        CellValue::Int64(id * 10),
                    ],
                };
                stored.insert(
                    crate::codec::encode_primary_key_from_row(0, &row, &table.model).unwrap(),
                    crate::writer::encode_base_row_value(&row, &table.model)
                        .unwrap()
                        .into(),
                );
                let spec = &table.index_specs[0];
                stored.insert(
                    crate::codec::encode_secondary_index_key(0, spec, &table.model, &row).unwrap(),
                    crate::writer::encode_secondary_index_value(&row, &table.model, spec)
                        .unwrap()
                        .into(),
                );
            }
        }
        let batch = RecordBatch::try_new(
            table.model.schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1, 2])),
                Arc::new(Int64Array::from(vec![2, 2])),
                Arc::new(Int64Array::from(vec![1, 2])),
                Arc::new(Int64Array::from(vec![10, 20])),
            ],
        )
        .unwrap();
        fixture
            .native
            .register_table(
                "points",
                Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]]).unwrap()),
            )
            .unwrap();
        fixture
            .check(
                "SELECT COUNT(*), SUM(measure) FROM points WHERE x BETWEEN 1 AND 3 AND y IN (1, 2)",
                1,
            )
            .await;
        assert_eq!(fixture.rows.scanned_rows.load(AtomicOrdering::Relaxed), 2);
    }

    #[tokio::test]
    async fn timestamp_casts_preserve_values_and_reduce_identity_casts() {
        use datafusion::arrow::array::TimestampMicrosecondArray;

        for source_timezone in [None, Some(Arc::<str>::from("+02:00"))] {
            let fixture = Fixture::new().await;
            fixture
                .replace_value_column(
                    DataType::Timestamp(TimeUnit::Microsecond, source_timezone.clone()),
                    vec![CellValue::Timestamp(0), CellValue::Null],
                    Arc::new(
                        TimestampMicrosecondArray::from(vec![Some(0), None])
                            .with_timezone_opt(source_timezone.clone()),
                    ),
                )
                .await;
            for target_timezone in [None, Some("-05:00"), Some("UTC")] {
                let expr =
                    format!("arrow_cast(value, 'Timestamp(Microsecond, {target_timezone:?})')");
                let identity = source_timezone.is_some() || target_timezone.is_none();
                for sql in [
                    format!("SELECT MIN({expr}), MAX({expr}) FROM numbers"),
                    format!("SELECT {expr}, COUNT(*) FROM numbers GROUP BY {expr} ORDER BY 1"),
                ] {
                    if identity {
                        fixture.check(&sql, 1).await;
                    } else {
                        let expected = values(&fixture.native, &sql).await.unwrap();
                        fixture.rows.reductions.lock().unwrap().clear();
                        let actual = values(&fixture.store, &sql).await.unwrap();
                        assert_eq!(actual, expected, "{sql}");
                        assert!(fixture.rows.reductions.lock().unwrap().is_empty(), "{sql}");
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn naive_timestamp_casts_preserve_errors_and_nulls() {
        use datafusion::arrow::array::TimestampMicrosecondArray;
        use datafusion::functions_aggregate::expr_fn::min;
        use datafusion::logical_expr::{Cast, TryCast};
        use datafusion::prelude::col;

        let fixture = Fixture::new().await;
        fixture
            .replace_value_column(
                DataType::Timestamp(TimeUnit::Microsecond, None),
                vec![CellValue::Timestamp(i64::MAX)],
                Arc::new(TimestampMicrosecondArray::from(vec![i64::MAX])),
            )
            .await;
        for try_cast in [true, false] {
            let target = DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()));
            let expr = if try_cast {
                Expr::TryCast(TryCast::new(Box::new(col("value")), target.clone()))
            } else {
                Expr::Cast(Cast::new(Box::new(col("value")), target.clone()))
            };
            let mut results = Vec::new();
            fixture.rows.reductions.lock().unwrap().clear();
            for ctx in [&fixture.native, &fixture.store] {
                results.push(
                    ctx.table("numbers")
                        .await
                        .unwrap()
                        .aggregate(vec![], vec![min(expr.clone())])
                        .unwrap()
                        .collect()
                        .await,
                );
            }
            for result in results {
                if try_cast {
                    let batches = result.unwrap();
                    assert_eq!(
                        ScalarValue::try_from_array(batches[0].column(0), 0).unwrap(),
                        ScalarValue::try_new_null(&target).unwrap()
                    );
                } else {
                    assert!(result.is_err());
                }
            }
            assert!(fixture.rows.reductions.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn tagged_date_trunc_preserves_timestamp_overflow_errors() {
        use datafusion::arrow::array::TimestampMicrosecondArray;
        for timezone in [
            Some(Arc::<str>::from("UTC")),
            Some(Arc::<str>::from("+00:00")),
            None,
        ] {
            let fixture = Fixture::new().await;
            let timestamp = 10_000_000_000_000_000;
            fixture
                .replace_value_column(
                    DataType::Timestamp(TimeUnit::Microsecond, timezone.clone()),
                    vec![CellValue::Timestamp(timestamp)],
                    Arc::new(
                        TimestampMicrosecondArray::from(vec![timestamp])
                            .with_timezone_opt(timezone.clone()),
                    ),
                )
                .await;
            let sql = "SELECT date_trunc('day', value), COUNT(*) FROM numbers GROUP BY date_trunc('day', value)";
            if timezone.is_some() {
                let native_error = values(&fixture.native, sql).await.unwrap_err();
                assert!(
                    native_error.to_string().contains("out of range"),
                    "{native_error}"
                );
                let store_error = values(&fixture.store, sql).await.unwrap_err();
                assert!(
                    store_error.to_string().contains("out of range"),
                    "{store_error}"
                );
                assert!(fixture.rows.reductions.lock().unwrap().is_empty());
            } else {
                fixture.check(sql, 1).await;
            }
        }
    }

    #[tokio::test]
    async fn secondary_float_boundaries_are_rechecked_before_reduction() {
        let fixture = Fixture::new().await;
        fixture
            .install_indexed_table(
                "scores",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("score", DataType::Float64, false),
                ],
                &["id"],
                vec![IndexSpec::new("score_idx", vec!["score".to_string()]).unwrap()],
                (0..4)
                    .map(|id| KvRow {
                        values: vec![CellValue::Int64(id), CellValue::Float64(id as f64)],
                    })
                    .collect(),
                vec![
                    Arc::new(Int64Array::from(vec![0, 1, 2, 3])),
                    Arc::new(Float64Array::from(vec![0.0, 1.0, 2.0, 3.0])),
                ],
            )
            .await;
        for sql in [
            "SELECT COUNT(*), SUM(id) FROM scores WHERE score > 1.0",
            "SELECT COUNT(*), SUM(id) FROM scores WHERE score < 2.0",
        ] {
            fixture.check(sql, 1).await;
            assert!(fixture.rows.reductions.lock().unwrap()[0]
                .params
                .filter
                .as_option()
                .is_some());
        }
    }

    #[tokio::test]
    async fn secondary_variable_key_prefix_does_not_skip_primary_suffix_filter() {
        let fixture = Fixture::new().await;
        let entries = [(0, 2), (1, 1), (1, 2), (2, 3)];
        fixture
            .install_indexed_table(
                "tenants",
                vec![
                    TableColumnConfig::new("tenant", DataType::Int64, false),
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                ],
                &["tenant", "id"],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()]).unwrap()],
                entries
                    .iter()
                    .map(|(tenant, id)| KvRow {
                        values: vec![
                            CellValue::Int64(*tenant),
                            CellValue::Int64(*id),
                            CellValue::Utf8("open".to_string()),
                        ],
                    })
                    .collect(),
                vec![
                    Arc::new(Int64Array::from(vec![0, 1, 1, 2])),
                    Arc::new(Int64Array::from(vec![2, 1, 2, 3])),
                    Arc::new(StringArray::from(vec!["open"; 4])),
                ],
            )
            .await;
        let sql = "SELECT COUNT(*) FROM tenants WHERE status = 'open' AND id = 2";
        assert_eq!(
            values(&fixture.store, sql).await.unwrap(),
            values(&fixture.native, sql).await.unwrap()
        );
        assert!(fixture.rows.reductions.lock().unwrap().is_empty());
    }
}
