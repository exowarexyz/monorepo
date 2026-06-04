use std::any::Any;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::common::config::ConfigOptions;
use datafusion::common::tree_node::{Transformed, TransformedResult, TreeNode};
use datafusion::common::{DataFusionError, Result as DataFusionResult};
use datafusion::execution::context::TaskContext;
use datafusion::physical_expr::expressions::Column;
use datafusion::physical_expr::{EquivalenceProperties, Partitioning, PhysicalSortExpr};
use datafusion::physical_optimizer::PhysicalOptimizerRule;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::sorts::sort::SortExec;
use datafusion::physical_plan::{
    coop::CooperativeExec, stream::RecordBatchStreamAdapter, DisplayAs, DisplayFormatType,
    ExecutionPlan, PlanProperties, SendableRecordBatchStream, SortOrderPushdownResult,
};
use exoware_sdk::keys::Key;
use exoware_sdk::kv_codec::decode_stored_row;
use exoware_sdk::StoreClient;
use exoware_sdk::{RangeMode, RangeStream, SerializableReadSession};
use futures::SinkExt;

use crate::builder::*;
use crate::codec::*;
use crate::diagnostics::*;
use crate::filter::*;
use crate::predicate::*;
use crate::types::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanDirection {
    Forward,
    Reverse,
}

impl ScanDirection {
    fn range_mode(self) -> RangeMode {
        match self {
            Self::Forward => RangeMode::Forward,
            Self::Reverse => RangeMode::Reverse,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct KvScanExec {
    pub(crate) client: StoreClient,
    pub(crate) model: Arc<TableModel>,
    pub(crate) index_specs: Arc<Vec<ResolvedIndexSpec>>,
    pub(crate) predicate: QueryPredicate,
    pub(crate) limit: Option<usize>,
    pub(crate) direction: ScanDirection,
    pub(crate) projected_schema: SchemaRef,
    pub(crate) projection: Option<Vec<usize>>,
    pub(crate) properties: PlanProperties,
}

impl KvScanExec {
    fn make_properties(
        projected_schema: SchemaRef,
        output_ordering: Option<Vec<PhysicalSortExpr>>,
    ) -> PlanProperties {
        let equivalence_properties = match output_ordering {
            Some(ordering) if !ordering.is_empty() => {
                EquivalenceProperties::new_with_orderings(projected_schema.clone(), [ordering])
            }
            _ => EquivalenceProperties::new(projected_schema.clone()),
        };
        PlanProperties::new(
            equivalence_properties,
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Bounded,
        )
    }

    pub(crate) fn new(
        client: StoreClient,
        model: Arc<TableModel>,
        index_specs: Arc<Vec<ResolvedIndexSpec>>,
        predicate: QueryPredicate,
        limit: Option<usize>,
        projected_schema: SchemaRef,
        projection: Option<Vec<usize>>,
    ) -> Self {
        let properties = Self::make_properties(projected_schema.clone(), None);
        Self {
            client,
            model,
            index_specs,
            predicate,
            limit,
            direction: ScanDirection::Forward,
            projected_schema,
            projection,
            properties,
        }
    }

    fn with_scan_options(
        &self,
        limit: Option<usize>,
        direction: ScanDirection,
        output_ordering: Option<Vec<PhysicalSortExpr>>,
    ) -> Self {
        let properties = Self::make_properties(self.projected_schema.clone(), output_ordering);
        Self {
            client: self.client.clone(),
            model: self.model.clone(),
            index_specs: self.index_specs.clone(),
            predicate: self.predicate.clone(),
            limit,
            direction,
            projected_schema: self.projected_schema.clone(),
            projection: self.projection.clone(),
            properties,
        }
    }

    fn with_ordering(
        &self,
        direction: ScanDirection,
        output_ordering: Vec<PhysicalSortExpr>,
    ) -> Self {
        self.with_scan_options(self.limit, direction, Some(output_ordering))
    }

    fn order_direction_for_primary_key(
        &self,
        order: &[PhysicalSortExpr],
    ) -> DataFusionResult<Option<ScanDirection>> {
        if order.is_empty() || self.predicate.contradiction {
            return Ok(None);
        }
        if self
            .predicate
            .choose_index_plan(&self.model, &self.index_specs)?
            .is_some()
        {
            return Ok(None);
        }

        let key_columns = self.primary_key_order_columns_after_eq_prefix();
        if order.len() > key_columns.len() {
            return Ok(None);
        }

        let first_desc = order[0].options.descending;
        let direction = if first_desc {
            ScanDirection::Reverse
        } else {
            ScanDirection::Forward
        };

        for (sort_expr, &expected_col_idx) in order.iter().zip(key_columns.iter()) {
            if sort_expr.options.descending != first_desc {
                return Ok(None);
            }
            let Some(column) = sort_expr.expr.as_any().downcast_ref::<Column>() else {
                return Ok(None);
            };
            let Some(&actual_col_idx) = self.model.columns_by_name.get(column.name()) else {
                return Ok(None);
            };
            if actual_col_idx != expected_col_idx {
                return Ok(None);
            }
        }

        Ok(Some(direction))
    }

    fn primary_key_order_columns_after_eq_prefix(&self) -> Vec<usize> {
        self.model
            .primary_key_indices
            .iter()
            .copied()
            .skip_while(|col_idx| {
                self.predicate
                    .constraints
                    .get(col_idx)
                    .is_some_and(single_value_constraint)
            })
            .collect()
    }

    pub(crate) fn plan_diagnostics(&self) -> DataFusionResult<AccessPathDiagnostics> {
        build_scan_access_path_diagnostics(
            &self.model,
            &self.index_specs,
            &self.predicate,
            &self.projection,
        )
    }
}

impl DisplayAs for KvScanExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.plan_diagnostics() {
            Ok(diag) => write!(
                f,
                "KvScanExec: limit={:?}, direction={:?}, {}, query_stats={}",
                self.limit,
                self.direction,
                format_access_path_diagnostics(&diag),
                format_query_stats_explain(QueryStatsExplainSurface::StreamedRangeDetail)
            ),
            Err(err) => write!(
                f,
                "KvScanExec: limit={:?}, direction={:?}, diagnostics_error={err}",
                self.limit, self.direction
            ),
        }
    }
}

impl ExecutionPlan for KvScanExec {
    fn name(&self) -> &str {
        "KvScanExec"
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
                "KvScanExec has no children".to_string(),
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
                "KvScanExec only supports 1 partition, got {partition}"
            )));
        }

        let (mut tx, rx) = futures::channel::mpsc::channel::<DataFusionResult<RecordBatch>>(2);
        let session = self.client.create_session();
        let model = self.model.clone();
        let index_specs = self.index_specs.clone();
        let predicate = self.predicate.clone();
        let limit = self.limit;
        let direction = self.direction;
        let projection = self.projection.clone();
        let projected_schema = self.projected_schema.clone();
        let access_plan = Arc::new(ScanAccessPlan::new(&model, &projection, &predicate));

        tokio::spawn(async move {
            let ctx = ScanCtx {
                session: &session,
                model: &model,
                predicate: &predicate,
                projected_schema: &projected_schema,
                access_plan: &access_plan,
            };
            if let Err(e) = stream_kv_scan(&mut tx, &ctx, &index_specs, limit, direction).await {
                let _ = tx.send(Err(e)).await;
            }
        });

        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.projected_schema.clone(),
            rx,
        )))
    }

    fn with_fetch(&self, limit: Option<usize>) -> Option<Arc<dyn ExecutionPlan>> {
        let limit = match (self.limit, limit) {
            (Some(existing), Some(limit)) => Some(existing.min(limit)),
            (None, Some(limit)) => Some(limit),
            (_, None) => None,
        };
        Some(Arc::new(
            self.with_scan_options(
                limit,
                self.direction,
                self.properties
                    .output_ordering()
                    .map(|ordering| ordering.iter().cloned().collect::<Vec<PhysicalSortExpr>>()),
            ),
        ))
    }

    fn fetch(&self) -> Option<usize> {
        self.limit
    }

    fn try_pushdown_sort(
        &self,
        order: &[PhysicalSortExpr],
    ) -> DataFusionResult<SortOrderPushdownResult<Arc<dyn ExecutionPlan>>> {
        let Some(direction) = self.order_direction_for_primary_key(order)? else {
            return Ok(SortOrderPushdownResult::Unsupported);
        };
        Ok(SortOrderPushdownResult::Inexact {
            inner: Arc::new(self.with_ordering(direction, order.to_vec())),
        })
    }
}

pub(crate) struct ScanCtx<'a> {
    pub(crate) session: &'a SerializableReadSession,
    pub(crate) model: &'a TableModel,
    pub(crate) predicate: &'a QueryPredicate,
    pub(crate) projected_schema: &'a SchemaRef,
    pub(crate) access_plan: &'a ScanAccessPlan,
}

pub(crate) async fn flush_projected_batch(
    tx: &mut futures::channel::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'_>,
    batch_builder: &mut ProjectedBatchBuilder,
    emitted: &mut usize,
) -> DataFusionResult<bool> {
    let batch_size = batch_builder.row_count();
    if batch_size == 0 {
        return Ok(true);
    }
    let ready = std::mem::replace(
        batch_builder,
        ProjectedBatchBuilder::from_access_plan(ctx.model, ctx.access_plan),
    );
    *emitted += batch_size;
    let batch = ready.finish(ctx.projected_schema)?;
    if tx.send(Ok(batch)).await.is_err() {
        return Ok(false);
    }
    Ok(true)
}

pub(crate) async fn stream_kv_scan(
    tx: &mut futures::channel::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'_>,
    index_specs: &[ResolvedIndexSpec],
    limit: Option<usize>,
    direction: ScanDirection,
) -> DataFusionResult<()> {
    if ctx.predicate.contradiction {
        return Ok(());
    }
    if limit == Some(0) {
        return Ok(());
    }
    let target_rows = limit.unwrap_or(usize::MAX);
    let flush_threshold = limit.unwrap_or(BATCH_FLUSH_ROWS).min(BATCH_FLUSH_ROWS);

    if let Some(plan) = ctx.predicate.choose_index_plan(ctx.model, index_specs)? {
        if plan.ranges.is_empty() {
            return Ok(());
        }
        if ctx
            .access_plan
            .index_covers_required_non_pk(&index_specs[plan.spec_idx])
        {
            return stream_index_scan(
                tx,
                ctx,
                index_specs,
                &plan,
                flush_threshold,
                target_rows,
                direction,
            )
            .await;
        }
        return stream_index_lookup_scan(
            tx,
            ctx,
            index_specs,
            &plan,
            flush_threshold,
            target_rows,
            direction,
        )
        .await;
    }

    let exact = ctx
        .access_plan
        .predicate_fully_enforced_by_primary_key(ctx.model);
    stream_pk_scan(tx, ctx, flush_threshold, target_rows, exact, direction).await
}

pub(crate) async fn stream_pk_scan(
    tx: &mut futures::channel::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'_>,
    flush_threshold: usize,
    target_rows: usize,
    exact: bool,
    direction: ScanDirection,
) -> DataFusionResult<()> {
    let ranges = ctx.predicate.primary_key_ranges(ctx.model)?;
    let mut emitted = 0usize;
    let mut batch_builder = ProjectedBatchBuilder::from_access_plan(ctx.model, ctx.access_plan);

    for range in ordered_ranges(&ranges, direction) {
        if range.start > range.end {
            continue;
        }
        if emitted + batch_builder.row_count() >= target_rows {
            break;
        }
        let remaining = target_rows.saturating_sub(emitted + batch_builder.row_count());
        if remaining == 0 {
            break;
        }
        let raw_limit = if exact { remaining } else { usize::MAX };

        let mut stream =
            range_stream_with_direction(ctx.session, range, raw_limit, flush_threshold, direction)
                .await?;
        while let Some(chunk) = stream
            .next_chunk()
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?
        {
            for (key, value) in &chunk.rows {
                if emitted + batch_builder.row_count() >= target_rows {
                    break;
                }
                let Some(pk) = decode_primary_key_selected(
                    ctx.model.table_prefix,
                    key,
                    ctx.model,
                    &ctx.access_plan.required_pk_mask,
                ) else {
                    continue;
                };
                let Ok(archived) = decode_stored_row(value) else {
                    continue;
                };
                if archived.values.len() != ctx.model.columns.len() {
                    continue;
                }
                if !ctx.access_plan.matches_archived_row(&pk, &archived) {
                    continue;
                }
                if !batch_builder.append_archived_row(&pk, &archived)? {
                    continue;
                }
                if batch_builder.row_count() >= flush_threshold
                    && !flush_projected_batch(tx, ctx, &mut batch_builder, &mut emitted).await?
                {
                    return Ok(());
                }
            }
            if emitted + batch_builder.row_count() >= target_rows {
                break;
            }
        }
    }

    let _ = flush_projected_batch(tx, ctx, &mut batch_builder, &mut emitted).await?;
    Ok(())
}

pub(crate) async fn stream_index_lookup_scan(
    tx: &mut futures::channel::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'_>,
    index_specs: &[ResolvedIndexSpec],
    plan: &IndexPlan,
    flush_threshold: usize,
    target_rows: usize,
    direction: ScanDirection,
) -> DataFusionResult<()> {
    let spec = &index_specs[plan.spec_idx];
    let key_predicate_plan = ctx
        .access_plan
        .compile_index_predicate_plan(ctx.model, spec);
    if key_predicate_plan.is_impossible() {
        return Ok(());
    }
    let mut seen: HashSet<Key> = HashSet::new();
    let mut emitted = 0usize;
    let mut batch_builder = ProjectedBatchBuilder::from_access_plan(ctx.model, ctx.access_plan);

    for range in ordered_ranges(&plan.ranges, direction) {
        if emitted + batch_builder.row_count() >= target_rows {
            break;
        }
        let mut stream =
            range_stream_with_direction(ctx.session, range, usize::MAX, flush_threshold, direction)
                .await?;
        while let Some(chunk) = stream
            .next_chunk()
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?
        {
            let mut pk_batch: Vec<Key> = Vec::new();
            for (key, _index_value) in &chunk.rows {
                if emitted + batch_builder.row_count() + pk_batch.len() >= target_rows {
                    break;
                }
                if !key_predicate_plan.matches_key(key) {
                    continue;
                }
                let Some(primary_key) = decode_secondary_index_primary_key(
                    ctx.model.table_prefix,
                    spec,
                    ctx.model,
                    key,
                ) else {
                    continue;
                };
                if !seen.insert(primary_key.clone()) {
                    continue;
                }
                pk_batch.push(primary_key);
            }

            if !pk_batch.is_empty() {
                let pk_refs: Vec<&Key> = pk_batch.iter().collect();
                let mut get_stream = ctx
                    .session
                    .get_many(&pk_refs, flush_threshold as u32)
                    .await
                    .map_err(|e| DataFusionError::External(Box::new(e)))?;
                while let Some(chunk) = get_stream
                    .next_chunk()
                    .await
                    .map_err(|e| DataFusionError::External(Box::new(e)))?
                {
                    for (pk_key, base_value) in chunk.entries {
                        let Some(base_value) = base_value else {
                            continue;
                        };
                        let Some(pk_values) = decode_primary_key_selected(
                            ctx.model.table_prefix,
                            &pk_key,
                            ctx.model,
                            &ctx.access_plan.required_pk_mask,
                        ) else {
                            continue;
                        };
                        let Ok(archived) = decode_stored_row(&base_value) else {
                            continue;
                        };
                        if archived.values.len() != ctx.model.columns.len() {
                            continue;
                        }
                        if !ctx.access_plan.matches_archived_row(&pk_values, &archived) {
                            continue;
                        }
                        if !batch_builder.append_archived_row(&pk_values, &archived)? {
                            continue;
                        }
                        if batch_builder.row_count() >= flush_threshold
                            && !flush_projected_batch(tx, ctx, &mut batch_builder, &mut emitted)
                                .await?
                        {
                            return Ok(());
                        }
                    }
                }
            }

            if emitted + batch_builder.row_count() >= target_rows {
                break;
            }
        }
    }
    let _ = flush_projected_batch(tx, ctx, &mut batch_builder, &mut emitted).await?;
    Ok(())
}

pub(crate) async fn stream_index_scan(
    tx: &mut futures::channel::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'_>,
    index_specs: &[ResolvedIndexSpec],
    plan: &IndexPlan,
    flush_threshold: usize,
    target_rows: usize,
    direction: ScanDirection,
) -> DataFusionResult<()> {
    let spec = &index_specs[plan.spec_idx];
    let key_predicate_plan = ctx
        .access_plan
        .compile_index_predicate_plan(ctx.model, spec);
    if key_predicate_plan.is_impossible() {
        return Ok(());
    }
    let mut seen: HashSet<Key> = HashSet::new();
    let mut emitted = 0usize;
    let mut batch_builder = ProjectedBatchBuilder::from_access_plan(ctx.model, ctx.access_plan);

    for range in ordered_ranges(&plan.ranges, direction) {
        if emitted + batch_builder.row_count() >= target_rows {
            break;
        }
        let remaining = target_rows.saturating_sub(emitted + batch_builder.row_count());
        if remaining == 0 {
            break;
        }
        let mut stream =
            range_stream_with_direction(ctx.session, range, usize::MAX, flush_threshold, direction)
                .await?;
        while let Some(chunk) = stream
            .next_chunk()
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?
        {
            for (key, index_value) in &chunk.rows {
                if emitted + batch_builder.row_count() >= target_rows {
                    break;
                }
                if !key_predicate_plan.matches_key(key) {
                    continue;
                }
                let Some(primary_key) = decode_secondary_index_primary_key(
                    ctx.model.table_prefix,
                    spec,
                    ctx.model,
                    key,
                ) else {
                    continue;
                };
                if !seen.insert(primary_key.clone()) {
                    continue;
                }
                if index_value.is_empty() {
                    return Err(DataFusionError::Execution(
                        "secondary index entry missing covering payload".to_string(),
                    ));
                }

                let Some(pk_values) = decode_primary_key_selected(
                    ctx.model.table_prefix,
                    &primary_key,
                    ctx.model,
                    &ctx.access_plan.required_pk_mask,
                ) else {
                    continue;
                };
                let archived = decode_stored_row(index_value).map_err(|e| {
                    DataFusionError::Execution(format!(
                        "invalid covering index payload for key {}: {e}",
                        hex::encode(key)
                    ))
                })?;
                if archived.values.len() != ctx.model.columns.len() {
                    continue;
                }
                if !ctx.access_plan.matches_archived_row(&pk_values, &archived) {
                    continue;
                }
                if !batch_builder.append_archived_row(&pk_values, &archived)? {
                    continue;
                }
                if batch_builder.row_count() >= flush_threshold
                    && !flush_projected_batch(tx, ctx, &mut batch_builder, &mut emitted).await?
                {
                    return Ok(());
                }
            }
            if emitted + batch_builder.row_count() >= target_rows {
                break;
            }
        }
    }

    let _ = flush_projected_batch(tx, ctx, &mut batch_builder, &mut emitted).await?;
    Ok(())
}

fn ordered_ranges<'a>(
    ranges: &'a [KeyRange],
    direction: ScanDirection,
) -> Box<dyn Iterator<Item = &'a KeyRange> + Send + 'a> {
    match direction {
        ScanDirection::Forward => Box::new(ranges.iter()),
        ScanDirection::Reverse => Box::new(ranges.iter().rev()),
    }
}

async fn range_stream_with_direction(
    session: &SerializableReadSession,
    range: &KeyRange,
    limit: usize,
    batch_size: usize,
    direction: ScanDirection,
) -> DataFusionResult<RangeStream> {
    session
        .range_stream_with_mode(
            &range.start,
            &range.end,
            limit,
            batch_size,
            direction.range_mode(),
        )
        .await
        .map_err(|e| DataFusionError::External(Box::new(e)))
}

fn single_value_constraint(constraint: &PredicateConstraint) -> bool {
    match constraint {
        PredicateConstraint::StringEq(_)
        | PredicateConstraint::BoolEq(_)
        | PredicateConstraint::FixedBinaryEq(_) => true,
        PredicateConstraint::IntRange {
            min: Some(min),
            max: Some(max),
        } => min == max,
        PredicateConstraint::UInt64Range {
            min: Some(min),
            max: Some(max),
        } => min == max,
        PredicateConstraint::FloatRange {
            min: Some((min, min_inclusive)),
            max: Some((max, max_inclusive)),
        } => *min_inclusive && *max_inclusive && min == max,
        PredicateConstraint::Decimal128Range {
            min: Some(min),
            max: Some(max),
        } => min == max,
        PredicateConstraint::Decimal256Range {
            min: Some(min),
            max: Some(max),
        } => min == max,
        _ => false,
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct KvTopKSortPushdownRule;

impl KvTopKSortPushdownRule {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl PhysicalOptimizerRule for KvTopKSortPushdownRule {
    fn optimize(
        &self,
        plan: Arc<dyn ExecutionPlan>,
        config: &ConfigOptions,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        if !config.optimizer.enable_sort_pushdown {
            return Ok(plan);
        }

        plan.transform_down(|plan: Arc<dyn ExecutionPlan>| {
            let Some(sort_exec) = plan.as_any().downcast_ref::<SortExec>() else {
                return Ok(Transformed::no(plan));
            };
            let Some(fetch) = sort_exec.fetch() else {
                return Ok(Transformed::no(plan));
            };
            let Some(ordered_scan) = push_topk_fetch_to_ordered_scan(
                sort_exec.input().clone(),
                sort_exec.expr(),
                fetch,
            )?
            else {
                return Ok(Transformed::no(plan));
            };
            let sort = SortExec::new(sort_exec.expr().clone(), ordered_scan)
                .with_fetch(Some(fetch))
                .with_preserve_partitioning(sort_exec.preserve_partitioning());
            Ok(Transformed::yes(Arc::new(sort) as Arc<dyn ExecutionPlan>))
        })
        .data()
    }

    fn name(&self) -> &str {
        "kv_topk_sort_pushdown"
    }

    fn schema_check(&self) -> bool {
        true
    }
}

fn push_topk_fetch_to_ordered_scan(
    plan: Arc<dyn ExecutionPlan>,
    order: &[PhysicalSortExpr],
    fetch: usize,
) -> DataFusionResult<Option<Arc<dyn ExecutionPlan>>> {
    if let Some(scan_exec) = plan.as_any().downcast_ref::<KvScanExec>() {
        let Some(direction) = scan_exec.order_direction_for_primary_key(order)? else {
            return Ok(None);
        };
        let limit = Some(
            scan_exec
                .limit
                .map_or(fetch, |existing| existing.min(fetch)),
        );
        return Ok(Some(Arc::new(scan_exec.with_scan_options(
            limit,
            direction,
            Some(order.to_vec()),
        ))));
    }

    if plan.as_any().downcast_ref::<CooperativeExec>().is_none() {
        return Ok(None);
    }
    let children = plan.children();
    if children.len() != 1 {
        return Ok(None);
    }
    let Some(new_child) = push_topk_fetch_to_ordered_scan(Arc::clone(children[0]), order, fetch)?
    else {
        return Ok(None);
    };
    plan.with_new_children(vec![new_child]).map(Some)
}
