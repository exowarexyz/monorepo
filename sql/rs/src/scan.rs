use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::common::{DataFusionError, Result as DataFusionResult};
use datafusion::execution::context::TaskContext;
use datafusion::physical_expr::expressions::Column;
use datafusion::physical_expr::{
    EquivalenceProperties, LexOrdering, Partitioning, PhysicalExpr, PhysicalSortExpr,
};
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::{
    stream::RecordBatchStreamAdapter, DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties,
    SendableRecordBatchStream, SortOrderPushdownResult,
};
use exoware_sdk::keys::Key;
use exoware_sdk::kv_codec::decode_stored_row;
use exoware_sdk::PrefixedStoreClient;
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

/// An output ordering proven to match primary-key traversal.
#[derive(Debug, Clone)]
struct ScanOrdering {
    expressions: LexOrdering,
    direction: ScanDirection,
}

#[derive(Debug, Clone)]
pub(crate) struct KvScanExec {
    pub(crate) client: PrefixedStoreClient,
    pub(crate) model: Arc<TableModel>,
    pub(crate) index_specs: Arc<Vec<ResolvedIndexSpec>>,
    pub(crate) predicate: QueryPredicate,
    pub(crate) fetch: Option<usize>,
    /// Without a required ordering, traversal is unconstrained and defaults to forward.
    ordering: Option<ScanOrdering>,
    pub(crate) projected_schema: SchemaRef,
    pub(crate) projection: Option<Vec<usize>>,
    pub(crate) properties: Arc<PlanProperties>,
}

impl KvScanExec {
    fn make_properties(
        projected_schema: SchemaRef,
        ordering: Option<&ScanOrdering>,
    ) -> Arc<PlanProperties> {
        let equivalence_properties = match ordering {
            Some(ordering) => EquivalenceProperties::new_with_orderings(
                projected_schema.clone(),
                [ordering.expressions.clone()],
            ),
            None => EquivalenceProperties::new(projected_schema.clone()),
        };
        Arc::new(PlanProperties::new(
            equivalence_properties,
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Bounded,
        ))
    }

    pub(crate) fn new(
        client: PrefixedStoreClient,
        model: Arc<TableModel>,
        index_specs: Arc<Vec<ResolvedIndexSpec>>,
        predicate: QueryPredicate,
        fetch: Option<usize>,
        projected_schema: SchemaRef,
        projection: Option<Vec<usize>>,
    ) -> Self {
        let properties = Self::make_properties(projected_schema.clone(), None);
        Self {
            client,
            model,
            index_specs,
            predicate,
            fetch,
            ordering: None,
            projected_schema,
            projection,
            properties,
        }
    }

    fn with_scan_options(&self, fetch: Option<usize>, ordering: Option<ScanOrdering>) -> Self {
        let properties = Self::make_properties(self.projected_schema.clone(), ordering.as_ref());
        Self {
            client: self.client.clone(),
            model: self.model.clone(),
            index_specs: self.index_specs.clone(),
            predicate: self.predicate.clone(),
            fetch,
            ordering,
            projected_schema: self.projected_schema.clone(),
            projection: self.projection.clone(),
            properties,
        }
    }

    pub(crate) fn scan_direction(&self) -> ScanDirection {
        self.ordering
            .as_ref()
            .map_or(ScanDirection::Forward, |ordering| ordering.direction)
    }

    fn order_direction_for_primary_key(
        &self,
        order: &LexOrdering,
    ) -> DataFusionResult<Option<ScanDirection>> {
        if self.predicate.contradiction {
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
            let Some(column) = sort_expr.expr.downcast_ref::<Column>() else {
                return Ok(None);
            };
            let actual_col_idx = self
                .projection
                .as_ref()
                .map_or(Some(column.index()), |proj| {
                    proj.get(column.index()).copied()
                });
            if actual_col_idx != Some(expected_col_idx) {
                return Ok(None);
            }
        }

        Ok(Some(direction))
    }

    fn primary_key_order_columns_after_eq_prefix(&self) -> Vec<usize> {
        let mut prefix_encoded_width = 0usize;
        let mut key_columns = Vec::new();
        let mut in_order_tail = false;

        for (&col_idx, &kind) in self
            .model
            .primary_key_indices
            .iter()
            .zip(self.model.primary_key_kinds.iter())
        {
            if in_order_tail {
                key_columns.push(col_idx);
                continue;
            }

            let Some(constraint) = self.predicate.constraints.get(&col_idx) else {
                in_order_tail = true;
                key_columns.push(col_idx);
                continue;
            };
            match primary_key_range_constraint_for_prefix(
                &self.model,
                prefix_encoded_width,
                kind,
                constraint,
            ) {
                PrimaryKeyRangeConstraint::Point(point) => {
                    prefix_encoded_width += point.encoded_width;
                }
                PrimaryKeyRangeConstraint::Terminal(_) | PrimaryKeyRangeConstraint::NotEnforced => {
                    in_order_tail = true;
                    key_columns.push(col_idx);
                }
            }
        }

        key_columns
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
        let direction = self.ordering.as_ref().map(|ordering| ordering.direction);
        match self.plan_diagnostics() {
            Ok(diag) => write!(
                f,
                "KvScanExec: fetch={:?}, direction={:?}, {}, query_stats={}",
                self.fetch,
                direction,
                format_access_path_diagnostics(&diag),
                format_query_stats_explain(QueryStatsExplainSurface::StreamedRangeDetail)
            ),
            Err(err) => write!(
                f,
                "KvScanExec: fetch={:?}, direction={:?}, diagnostics_error={err}",
                self.fetch, direction
            ),
        }
    }
}

impl ExecutionPlan for KvScanExec {
    fn name(&self) -> &str {
        "KvScanExec"
    }

    fn schema(&self) -> SchemaRef {
        self.projected_schema.clone()
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
        let fetch = self.fetch;
        let direction = self.scan_direction();
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
            if let Err(e) = stream_kv_scan(&mut tx, &ctx, &index_specs, fetch, direction).await {
                let _ = tx.send(Err(e)).await;
            }
        });

        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.projected_schema.clone(),
            rx,
        )))
    }

    fn with_fetch(&self, limit: Option<usize>) -> Option<Arc<dyn ExecutionPlan>> {
        let fetch = match (self.fetch, limit) {
            (Some(existing), Some(limit)) => Some(existing.min(limit)),
            (None, Some(limit)) => Some(limit),
            (_, None) => None,
        };
        Some(Arc::new(
            self.with_scan_options(fetch, self.ordering.clone()),
        ))
    }

    fn fetch(&self) -> Option<usize> {
        self.fetch
    }

    fn try_pushdown_sort(
        &self,
        order: &[PhysicalSortExpr],
    ) -> DataFusionResult<SortOrderPushdownResult<Arc<dyn ExecutionPlan>>> {
        let Some(expressions) = LexOrdering::new(order.iter().cloned()) else {
            return Ok(SortOrderPushdownResult::Unsupported);
        };
        if self
            .properties
            .equivalence_properties()
            .ordering_satisfy(expressions.clone())?
        {
            return Ok(SortOrderPushdownResult::Exact {
                inner: Arc::new(self.clone()),
            });
        }
        let Some(direction) = self.order_direction_for_primary_key(&expressions)? else {
            return Ok(SortOrderPushdownResult::Unsupported);
        };
        // Reversing under a fetch would change which rows the limit selects.
        if self.fetch.is_some()
            && self
                .ordering
                .as_ref()
                .is_some_and(|current| direction != current.direction)
        {
            return Ok(SortOrderPushdownResult::Unsupported);
        }
        Ok(SortOrderPushdownResult::Exact {
            inner: Arc::new(self.with_scan_options(
                self.fetch,
                Some(ScanOrdering {
                    expressions,
                    direction,
                }),
            )),
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
            return stream_index_scan(tx, ctx, index_specs, &plan, flush_threshold, target_rows)
                .await;
        }
        return stream_index_lookup_scan(tx, ctx, index_specs, &plan, flush_threshold, target_rows)
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

    for range in &plan.ranges {
        if emitted + batch_builder.row_count() >= target_rows {
            break;
        }
        let mut stream = range_stream_with_direction(
            ctx.session,
            range,
            usize::MAX,
            flush_threshold,
            ScanDirection::Forward,
        )
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

    for range in &plan.ranges {
        if emitted + batch_builder.row_count() >= target_rows {
            break;
        }
        let remaining = target_rows.saturating_sub(emitted + batch_builder.row_count());
        if remaining == 0 {
            break;
        }
        let mut stream = range_stream_with_direction(
            ctx.session,
            range,
            usize::MAX,
            flush_threshold,
            ScanDirection::Forward,
        )
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
