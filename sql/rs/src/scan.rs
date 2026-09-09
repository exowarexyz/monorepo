use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use datafusion::arrow::array::{as_boolean_array, Array};
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::catalog::Session;
use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::common::DFSchema;
use datafusion::common::{DataFusionError, Result as DataFusionResult};
use datafusion::execution::context::TaskContext;
use datafusion::logical_expr::{
    utils::{conjunction, iter_conjunction},
    Expr,
};
use datafusion::physical_expr::expressions::Column;
use datafusion::physical_expr::{
    EquivalenceProperties, LexOrdering, Partitioning, PhysicalExpr, PhysicalSortExpr,
};
use datafusion::physical_plan::execution_plan::{
    apply_expression_roots, Boundedness, EmissionType,
};
use datafusion::physical_plan::{
    stream::RecordBatchReceiverStreamBuilder, DisplayAs, DisplayFormatType, ExecutionPlan,
    PlanProperties, SendableRecordBatchStream, SortOrderPushdownResult,
};
use exoware_sdk::keys::Key;
use exoware_sdk::kv_codec::{decode_stored_row, StoredRow};
use exoware_sdk::PrefixedStoreClient;
use exoware_sdk::{RangeMode, RangeStream, SerializableReadSession, StoreKeyPrefix};

use crate::builder::*;
use crate::codec::*;
use crate::diagnostics::*;
use crate::filter::*;
use crate::predicate::*;
use crate::types::*;

// Amortize RPC framing and native predicate evaluation even with a small output limit
const MIN_FETCH_BATCH_ROWS: usize = 64;

#[derive(Clone)]
pub(crate) struct ScanFilter {
    expression: Arc<dyn PhysicalExpr>,
    schema: SchemaRef,
    access: ScanAccessPlan,
    complete_ranges: bool,
}

impl fmt::Debug for ScanFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.expression.fmt(f)
    }
}

impl ScanFilter {
    fn access_plan(model: &TableModel, filters: &[Expr]) -> (Vec<usize>, ScanAccessPlan) {
        let mut refs = HashSet::new();
        for expr in filters {
            expr.add_column_refs(&mut refs);
        }
        let columns = model
            .columns
            .iter()
            .enumerate()
            .filter_map(|(i, c)| refs.iter().any(|r| r.name == c.name).then_some(i))
            .collect::<Vec<_>>();
        let access = ScanAccessPlan::new(model, &Some(columns.clone()), &QueryPredicate::default());
        (columns, access)
    }

    fn compile(
        state: &dyn Session,
        model: &TableModel,
        filters: &[Expr],
        (columns, access): (Vec<usize>, ScanAccessPlan),
    ) -> DataFusionResult<Option<Self>> {
        let Some(expr) = conjunction(filters.iter().cloned()) else {
            return Ok(None);
        };
        let schema = Arc::new(model.schema.project(&columns)?);
        let expression = state.create_physical_expr(expr, &DFSchema::try_from(schema.clone())?)?;
        Ok(Some(Self {
            expression,
            schema,
            access,
            complete_ranges: filters
                .iter()
                .all(|f| QueryPredicate::supports_filter(f, model)),
        }))
    }

    fn select(
        &self,
        model: &TableModel,
        rows: &[(Vec<CellValue>, StoredRow)],
    ) -> DataFusionResult<Vec<usize>> {
        let mut builder = ProjectedBatchBuilder::from_access_plan(model, &self.access);
        let mut valid = Vec::with_capacity(rows.len());
        for (i, (pk, row)) in rows.iter().enumerate() {
            if builder.append_archived_row(pk, row)? {
                valid.push(i);
            }
        }
        if valid.is_empty() {
            return Ok(valid);
        }
        let batch = builder.finish(&self.schema)?;
        let mask = self
            .expression
            .evaluate(&batch)?
            .into_array(batch.num_rows())?;
        let mask = as_boolean_array(&mask);
        if mask.null_count() == mask.len() {
            return Ok(Vec::new());
        }
        Ok(mask
            .values()
            .set_indices()
            .filter(|&i| mask.is_valid(i))
            .map(|i| valid[i])
            .collect())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct KvScanExec {
    pub(crate) client: PrefixedStoreClient,
    pub(crate) model: Arc<TableModel>,
    pub(crate) index_specs: Arc<Vec<ResolvedIndexSpec>>,
    pub(crate) predicate: QueryPredicate,
    pub(crate) fetch: Option<usize>,
    pub(crate) filter: Option<ScanFilter>,
    cover_filter: Option<ScanFilter>,
    /// Without a required ordering, traversal is unconstrained and defaults to forward.
    direction: Option<RangeMode>,
    pub(crate) projection: Option<Vec<usize>>,
    pub(crate) properties: Arc<PlanProperties>,
}

impl KvScanExec {
    fn make_properties(
        projected_schema: SchemaRef,
        ordering: Option<LexOrdering>,
    ) -> Arc<PlanProperties> {
        let equivalence_properties = match ordering {
            Some(ordering) => {
                EquivalenceProperties::new_with_orderings(projected_schema, [ordering])
            }
            None => EquivalenceProperties::new(projected_schema),
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
        let properties = Self::make_properties(projected_schema, None);
        Self {
            client,
            model,
            index_specs,
            predicate,
            fetch,
            filter: None,
            cover_filter: None,
            direction: None,
            projection,
            properties,
        }
    }

    pub(crate) fn set_filters(
        &mut self,
        state: &dyn Session,
        filters: &[Expr],
    ) -> DataFusionResult<()> {
        if filters.is_empty() {
            self.filter = None;
            self.cover_filter = None;
            return Ok(());
        }
        let filter_access = ScanFilter::access_plan(&self.model, filters);
        let access = self.access_plan_with_filter(Some(&filter_access.1));
        let mut cover_filter = None;
        if let Some(plan) =
            self.predicate
                .choose_index_plan(&self.model, &self.index_specs, &access)?
        {
            let spec = &self.index_specs[plan.spec_idx];
            if !access.index_covers_required_non_pk(spec) {
                let available = filters
                    .iter()
                    .flat_map(iter_conjunction)
                    .filter(|expr| {
                        expr.column_refs().iter().all(|col| {
                            self.model.columns_by_name.get(&col.name).is_some_and(|&i| {
                                self.model.pk_position(i).is_some() || spec.value_column_mask[i]
                            })
                        })
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                cover_filter = ScanFilter::compile(
                    state,
                    &self.model,
                    &available,
                    ScanFilter::access_plan(&self.model, &available),
                )?;
            }
        } else if filters
            .iter()
            .all(|filter| QueryPredicate::supports_filter(filter, &self.model))
            && access.predicate_fully_enforced_by_primary_key(&self.model)
        {
            self.filter = None;
            self.cover_filter = None;
            return Ok(());
        }
        self.filter = ScanFilter::compile(state, &self.model, filters, filter_access)?;
        self.cover_filter = cover_filter;
        Ok(())
    }

    fn access_plan(&self) -> ScanAccessPlan {
        self.access_plan_with_filter(self.filter.as_ref().map(|filter| &filter.access))
    }

    fn access_plan_with_filter(&self, filter_access: Option<&ScanAccessPlan>) -> ScanAccessPlan {
        let mut access = ScanAccessPlan::new(&self.model, &self.projection, &self.predicate);
        if let Some(filter_access) = filter_access {
            for (required, filter_required) in access
                .required_pk_mask
                .iter_mut()
                .zip(&filter_access.required_pk_mask)
            {
                *required |= filter_required;
            }
            for (required, filter_required) in access
                .required_non_pk_columns
                .iter_mut()
                .zip(&filter_access.required_non_pk_columns)
            {
                *required |= filter_required;
            }
        }
        access
    }

    pub(crate) fn scan_direction(&self) -> RangeMode {
        self.direction.unwrap_or(RangeMode::Forward)
    }

    fn order_direction_for_primary_key(
        &self,
        order: &LexOrdering,
    ) -> DataFusionResult<Option<RangeMode>> {
        if self.predicate.contradiction {
            return Ok(None);
        }
        let access_plan = self.access_plan();
        let index_plan =
            self.predicate
                .choose_index_plan(&self.model, &self.index_specs, &access_plan)?;
        let (key_columns, constant_prefix_len) = if let Some(plan) = index_plan {
            let spec = &self.index_specs[plan.spec_idx];
            if spec.layout != IndexLayout::Lexicographic
                || !access_plan.index_covers_required_non_pk(spec)
            {
                return Ok(None);
            }
            let columns = spec
                .key_columns
                .iter()
                .chain(&self.model.primary_key_indices)
                .copied()
                .collect::<Vec<_>>();
            if columns.iter().any(|&i| {
                let c = self.model.column(i);
                c.nullable
                    || !matches!(
                        c.kind,
                        ColumnKind::Int64
                            | ColumnKind::UInt64
                            | ColumnKind::Utf8
                            | ColumnKind::FixedSizeBinary(_)
                            | ColumnKind::Boolean
                            | ColumnKind::Date32
                            | ColumnKind::Date64
                            | ColumnKind::Timestamp
                            | ColumnKind::Decimal128
                            | ColumnKind::Decimal256
                    )
            }) {
                return Ok(None);
            }
            let constant_prefix_len = columns
                .iter()
                .take_while(|&&i| {
                    self.predicate.constraints.get(&i).is_some_and(|c| {
                        !matches!(
                            c,
                            PredicateConstraint::StringIn(_)
                                | PredicateConstraint::IntIn(_)
                                | PredicateConstraint::UInt64In(_)
                                | PredicateConstraint::FixedBinaryIn(_)
                        ) && QueryPredicate::constraint_is_point(self.model.column(i).kind, c)
                    })
                })
                .count();
            (columns, constant_prefix_len)
        } else {
            (
                self.model.primary_key_indices.clone(),
                self.primary_key_point_prefix_len(),
            )
        };
        let (constant_columns, ordered_columns) = key_columns.split_at(constant_prefix_len);
        let mut ordered_columns = ordered_columns.iter();
        let mut direction = None;

        for sort_expr in order {
            let Some(column) = sort_expr.expr.downcast_ref::<Column>() else {
                return Ok(None);
            };
            let Some(actual_col_idx) = self
                .projection
                .as_ref()
                .map_or(Some(column.index()), |proj| {
                    proj.get(column.index()).copied()
                })
            else {
                return Ok(None);
            };
            if constant_columns.contains(&actual_col_idx) {
                continue;
            }
            let requested_direction = if sort_expr.options.descending {
                RangeMode::Reverse
            } else {
                RangeMode::Forward
            };
            if ordered_columns.next() != Some(&actual_col_idx)
                || direction.is_some_and(|current| current != requested_direction)
            {
                return Ok(None);
            }
            direction = Some(requested_direction);
        }

        Ok(Some(direction.unwrap_or(self.scan_direction())))
    }

    // Leading point-constrained key columns are fixed by the scanned range, so any
    // requested ordering over them is trivially satisfied.
    fn primary_key_point_prefix_len(&self) -> usize {
        let mut prefix_encoded_width = 0usize;

        for (position, (&col_idx, &kind)) in self
            .model
            .primary_key_indices
            .iter()
            .zip(self.model.primary_key_kinds.iter())
            .enumerate()
        {
            let Some(constraint) = self.predicate.constraints.get(&col_idx) else {
                return position;
            };
            match primary_key_range_constraint_for_prefix(
                self.model.primary_key_prefix.max_payload_len(),
                prefix_encoded_width,
                kind,
                constraint,
            ) {
                PrimaryKeyRangeConstraint::Point(point) => {
                    prefix_encoded_width += point.encoded_width;
                }
                PrimaryKeyRangeConstraint::Terminal(_) | PrimaryKeyRangeConstraint::NotEnforced => {
                    return position;
                }
            }
        }

        self.model.primary_key_indices.len()
    }

    pub(crate) fn plan_diagnostics(&self) -> DataFusionResult<AccessPathDiagnostics> {
        build_scan_access_path_diagnostics(
            &self.model,
            self.client.key_prefix().max_logical_key_len(),
            &self.index_specs,
            &self.predicate,
            &self.access_plan(),
            self.filter
                .as_ref()
                .is_none_or(|filter| filter.complete_ranges),
        )
    }
}

impl DisplayAs for KvScanExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.plan_diagnostics() {
            Ok(diag) => write!(
                f,
                "KvScanExec: fetch={:?}, direction={:?}, {}, query_stats={}",
                self.fetch,
                self.direction,
                format_access_path_diagnostics(&diag),
                format_query_stats_explain(QueryStatsExplainSurface::StreamedRangeDetail)
            ),
            Err(err) => write!(
                f,
                "KvScanExec: fetch={:?}, direction={:?}, diagnostics_error={err}",
                self.fetch, self.direction
            ),
        }
    }
}

impl ExecutionPlan for KvScanExec {
    fn name(&self) -> &str {
        "KvScanExec"
    }

    fn properties(&self) -> &Arc<PlanProperties> {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![]
    }

    fn apply_expressions(
        &self,
        f: &mut dyn FnMut(&Arc<dyn PhysicalExpr>) -> DataFusionResult<TreeNodeRecursion>,
    ) -> DataFusionResult<TreeNodeRecursion> {
        apply_expression_roots(
            self.filter
                .iter()
                .chain(self.cover_filter.iter())
                .map(|filter| &filter.expression),
            f,
        )
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
        context: Arc<TaskContext>,
    ) -> DataFusionResult<SendableRecordBatchStream> {
        if partition != 0 {
            return Err(DataFusionError::Internal(format!(
                "KvScanExec only supports 1 partition, got {partition}"
            )));
        }

        let mut builder = RecordBatchReceiverStreamBuilder::new(self.schema(), 2);
        let tx = builder.tx();
        let session = request_read_session(context.session_config(), &self.client)
            .unwrap_or_else(|| self.client.create_session());
        let key_prefix = self.client.key_prefix().clone();
        let model = self.model.clone();
        let index_specs = self.index_specs.clone();
        let predicate = self.predicate.clone();
        let fetch = self.fetch;
        let direction = self.scan_direction();
        let projected_schema = self.schema();
        let access_plan = self.access_plan();
        let filter = self.filter.clone();
        let cover_filter = self.cover_filter.clone();

        builder.spawn(async move {
            let ctx = ScanCtx {
                session: &session,
                key_prefix: &key_prefix,
                model: &model,
                predicate: &predicate,
                projected_schema: &projected_schema,
                access_plan: &access_plan,
                filter: filter.as_ref(),
                cover_filter: cover_filter.as_ref(),
            };
            if let Err(e) = stream_kv_scan(&tx, &ctx, &index_specs, fetch, direction).await {
                let _ = tx.send(Err(e)).await;
            }
            Ok(())
        });

        Ok(builder.build())
    }

    fn with_fetch(&self, limit: Option<usize>) -> Option<Arc<dyn ExecutionPlan>> {
        let fetch = match (self.fetch, limit) {
            (Some(existing), Some(limit)) => Some(existing.min(limit)),
            (None, Some(limit)) => Some(limit),
            (_, None) => None,
        };
        Some(Arc::new(Self {
            fetch,
            ..self.clone()
        }))
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
        if self.fetch.is_some() && self.direction.is_some_and(|current| direction != current) {
            return Ok(SortOrderPushdownResult::Unsupported);
        }
        Ok(SortOrderPushdownResult::Exact {
            inner: Arc::new(Self {
                direction: Some(direction),
                properties: Self::make_properties(self.schema(), Some(expressions)),
                ..self.clone()
            }),
        })
    }
}

pub(crate) struct ScanCtx<'a> {
    pub(crate) session: &'a SerializableReadSession,
    key_prefix: &'a StoreKeyPrefix,
    pub(crate) model: &'a TableModel,
    pub(crate) predicate: &'a QueryPredicate,
    pub(crate) projected_schema: &'a SchemaRef,
    pub(crate) access_plan: &'a ScanAccessPlan,
    filter: Option<&'a ScanFilter>,
    cover_filter: Option<&'a ScanFilter>,
}

impl ScanCtx<'_> {
    fn decode_row(
        &self,
        key: &Key,
        value: &[u8],
        covering: bool,
    ) -> DataFusionResult<Option<(Vec<CellValue>, StoredRow)>> {
        let Some(pk) = decode_primary_key_selected(
            self.model.table_prefix,
            key,
            self.model,
            &self.access_plan.required_pk_mask,
        ) else {
            return Ok(None);
        };
        self.decode_value(pk, value, covering)
    }

    fn decode_value(
        &self,
        pk: Vec<CellValue>,
        value: &[u8],
        covering: bool,
    ) -> DataFusionResult<Option<(Vec<CellValue>, StoredRow)>> {
        let row = match decode_stored_row(value) {
            Ok(row) => row,
            Err(error) if covering => {
                return Err(DataFusionError::Execution(format!(
                    "invalid covering index payload: {error}"
                )))
            }
            Err(_) => return Ok(None),
        };
        Ok((row.values.len() == self.model.columns.len()).then_some((pk, row)))
    }

    fn append_rows(
        &self,
        rows: &[(Vec<CellValue>, StoredRow)],
        output: &mut ProjectedBatchBuilder,
        remaining: usize,
    ) -> DataFusionResult<()> {
        let mut accepted = 0;
        if let Some(filter) = self.filter {
            for i in filter.select(self.model, rows)? {
                if accepted == remaining {
                    break;
                }
                if output.append_archived_row(&rows[i].0, &rows[i].1)? {
                    accepted += 1;
                }
            }
        } else {
            for (pk, row) in rows {
                if accepted == remaining {
                    break;
                }
                if output.append_archived_row(pk, row)? {
                    accepted += 1;
                }
            }
        }
        Ok(())
    }
}

pub(crate) async fn flush_projected_batch(
    tx: &tokio::sync::mpsc::Sender<DataFusionResult<RecordBatch>>,
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
    tx: &tokio::sync::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'_>,
    index_specs: &[ResolvedIndexSpec],
    limit: Option<usize>,
    direction: RangeMode,
) -> DataFusionResult<()> {
    if ctx.predicate.contradiction {
        return Ok(());
    }
    if limit == Some(0) {
        return Ok(());
    }
    let target_rows = limit.unwrap_or(usize::MAX);
    let flush_threshold = limit.unwrap_or(BATCH_FLUSH_ROWS).min(BATCH_FLUSH_ROWS);

    if let Some(mut keys) = ctx.predicate.primary_key_points(ctx.model)? {
        keys.retain(|key| key.len() <= ctx.key_prefix.max_logical_key_len());
        if direction == RangeMode::Reverse {
            keys.reverse();
        }
        return stream_point_scan(tx, ctx, &keys, flush_threshold, target_rows).await;
    }

    if let Some(plan) = ctx
        .predicate
        .choose_index_plan(ctx.model, index_specs, ctx.access_plan)?
    {
        if plan.ranges.is_empty() {
            return Ok(());
        }
        if ctx
            .access_plan
            .index_covers_required_non_pk(&index_specs[plan.spec_idx])
        {
            return stream_range_scan(
                tx,
                ctx,
                &plan.ranges,
                Some(&index_specs[plan.spec_idx]),
                flush_threshold,
                target_rows,
                direction,
            )
            .await;
        }
        return stream_index_lookup_scan(tx, ctx, index_specs, &plan, flush_threshold, target_rows)
            .await;
    }

    let ranges = ctx
        .predicate
        .primary_key_ranges(ctx.model, ctx.key_prefix.max_logical_key_len())?;
    stream_range_scan(
        tx,
        ctx,
        &ranges,
        None,
        flush_threshold,
        target_rows,
        direction,
    )
    .await
}

async fn get_rows(
    ctx: &ScanCtx<'_>,
    keys: &[Key],
) -> DataFusionResult<Vec<(Vec<CellValue>, StoredRow)>> {
    let refs = keys.iter().collect::<Vec<_>>();
    let mut stream = ctx
        .session
        .get_many(&refs, keys.len() as u32)
        .await
        .map_err(|e| DataFusionError::External(Box::new(e)))?;
    let mut values = HashMap::with_capacity(keys.len());
    while let Some(chunk) = stream
        .next_chunk()
        .await
        .map_err(|e| DataFusionError::External(Box::new(e)))?
    {
        values.extend(chunk.entries);
    }
    let mut rows = Vec::with_capacity(keys.len());
    for key in keys {
        if let Some(value) = values.remove(key).flatten() {
            if let Some(row) = ctx.decode_row(key, &value, false)? {
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

async fn stream_point_scan(
    tx: &tokio::sync::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'_>,
    keys: &[Key],
    flush_threshold: usize,
    target_rows: usize,
) -> DataFusionResult<()> {
    let mut emitted = 0;
    let mut output = ProjectedBatchBuilder::from_access_plan(ctx.model, ctx.access_plan);
    let exact = ctx.filter.is_none_or(|filter| filter.complete_ranges)
        && ctx
            .access_plan
            .predicate_fully_enforced_by_primary_key(ctx.model);
    let lookup_batch = if exact {
        flush_threshold
    } else {
        flush_threshold.max(MIN_FETCH_BATCH_ROWS)
    };
    for keys in keys.chunks(lookup_batch) {
        let rows = get_rows(ctx, keys).await?;
        let remaining = target_rows.saturating_sub(emitted + output.row_count());
        ctx.append_rows(&rows, &mut output, remaining)?;
        if output.row_count() >= flush_threshold
            && !flush_projected_batch(tx, ctx, &mut output, &mut emitted).await?
        {
            return Ok(());
        }
        if emitted + output.row_count() >= target_rows {
            break;
        }
    }
    let _ = flush_projected_batch(tx, ctx, &mut output, &mut emitted).await?;
    Ok(())
}

pub(crate) async fn stream_index_lookup_scan(
    tx: &tokio::sync::mpsc::Sender<DataFusionResult<RecordBatch>>,
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
    let mut emitted = 0usize;
    let mut batch_builder = ProjectedBatchBuilder::from_access_plan(ctx.model, ctx.access_plan);

    'ranges: for range in &plan.ranges {
        let mut stream = range_stream_with_direction(
            ctx.session,
            range,
            usize::MAX,
            flush_threshold.max(MIN_FETCH_BATCH_ROWS),
            RangeMode::Forward,
        )
        .await?;
        while let Some(chunk) = stream
            .next_chunk()
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?
        {
            let mut pk_batch: Vec<Key> = Vec::new();
            let mut cover_rows = Vec::new();
            let cover_filter = ctx.cover_filter;
            for (key, index_value) in &chunk.rows {
                if !key_predicate_plan.matches_key(key) {
                    continue;
                }
                let required_pk =
                    cover_filter.map_or(&[][..], |filter| &filter.access.required_pk_mask);
                let Some(decoded) = decode_secondary_index_key_with_masks(
                    ctx.model.table_prefix,
                    spec,
                    ctx.model,
                    key,
                    Some(&[]),
                    Some(required_pk),
                ) else {
                    continue;
                };
                if cover_filter.is_some() {
                    let Some(row) =
                        ctx.decode_value(decoded.primary_key_values, index_value, true)?
                    else {
                        continue;
                    };
                    cover_rows.push(row);
                }
                pk_batch.push(decoded.primary_key);
            }

            if let Some(filter) = cover_filter {
                pk_batch = filter
                    .select(ctx.model, &cover_rows)?
                    .into_iter()
                    .map(|i| pk_batch[i].clone())
                    .collect();
            }
            if !pk_batch.is_empty() {
                let rows = get_rows(ctx, &pk_batch).await?;
                let remaining = target_rows.saturating_sub(emitted + batch_builder.row_count());
                ctx.append_rows(&rows, &mut batch_builder, remaining)?;
                if emitted + batch_builder.row_count() >= target_rows {
                    break 'ranges;
                }
                if batch_builder.row_count() >= flush_threshold
                    && !flush_projected_batch(tx, ctx, &mut batch_builder, &mut emitted).await?
                {
                    return Ok(());
                }
            }
        }
    }
    let _ = flush_projected_batch(tx, ctx, &mut batch_builder, &mut emitted).await?;
    Ok(())
}

async fn stream_range_scan(
    tx: &tokio::sync::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'_>,
    ranges: &[KeyRange],
    index: Option<&ResolvedIndexSpec>,
    flush_threshold: usize,
    target_rows: usize,
    direction: RangeMode,
) -> DataFusionResult<()> {
    let key_predicate = index.map(|spec| {
        ctx.access_plan
            .compile_index_predicate_plan(ctx.model, spec)
    });
    if key_predicate
        .as_ref()
        .is_some_and(IndexPredicatePlan::is_impossible)
    {
        return Ok(());
    }
    let exact = ctx.filter.is_none_or(|filter| filter.complete_ranges)
        && index.map_or_else(
            || {
                ctx.access_plan
                    .predicate_fully_enforced_by_primary_key(ctx.model)
            },
            |spec| {
                ctx.access_plan
                    .predicate_fully_enforced_by_index_key(ctx.model, spec)
            },
        );
    let mut emitted = 0;
    let mut output = ProjectedBatchBuilder::from_access_plan(ctx.model, ctx.access_plan);
    for range in ordered_ranges(ranges, direction) {
        let mut range = range.clone();
        loop {
            let remaining = target_rows.saturating_sub(emitted + output.row_count());
            if remaining == 0 || range.start > range.end {
                break;
            }
            let raw_limit = if exact {
                remaining.min(u32::MAX as usize)
            } else {
                usize::MAX
            };
            let mut stream = range_stream_with_direction(
                ctx.session,
                &range,
                raw_limit,
                flush_threshold.max(MIN_FETCH_BATCH_ROWS),
                direction,
            )
            .await?;
            let mut scanned = 0;
            let mut last_key = None;
            while let Some(chunk) = stream
                .next_chunk()
                .await
                .map_err(|e| DataFusionError::External(Box::new(e)))?
            {
                scanned += chunk.rows.len();
                if let Some((key, _)) = chunk.rows.last() {
                    last_key = Some(key.clone());
                }
                let mut rows = Vec::new();
                for (key, value) in &chunk.rows {
                    let row = if let (Some(spec), Some(key_predicate)) = (index, &key_predicate) {
                        if !key_predicate.matches_key(key) {
                            continue;
                        }
                        let Some(decoded) = decode_secondary_index_key_with_masks(
                            ctx.model.table_prefix,
                            spec,
                            ctx.model,
                            key,
                            Some(&[]),
                            Some(&ctx.access_plan.required_pk_mask),
                        ) else {
                            continue;
                        };
                        if value.is_empty() {
                            return Err(DataFusionError::Execution(
                                "secondary index entry missing covering payload".into(),
                            ));
                        }
                        ctx.decode_value(decoded.primary_key_values, value, true)?
                    } else {
                        ctx.decode_row(key, value, false)?
                    };
                    let Some(row) = row else { continue };
                    if ctx.filter.is_some() {
                        rows.push(row);
                    } else if emitted + output.row_count() < target_rows {
                        output.append_archived_row(&row.0, &row.1)?;
                    }
                }
                if ctx.filter.is_some() {
                    let remaining = target_rows.saturating_sub(emitted + output.row_count());
                    ctx.append_rows(&rows, &mut output, remaining)?;
                }
                if output.row_count() >= flush_threshold
                    && !flush_projected_batch(tx, ctx, &mut output, &mut emitted).await?
                {
                    return Ok(());
                }
                if emitted + output.row_count() >= target_rows {
                    break;
                }
            }
            if emitted + output.row_count() >= target_rows || scanned < raw_limit {
                break;
            }
            // Raw limits count entries rejected by decoding or residual validation too
            let Some(last_key) = last_key else { break };
            match direction {
                RangeMode::Forward => {
                    let Some(next) = ctx
                        .key_prefix
                        .next_key(&last_key)
                        .map_err(|e| DataFusionError::External(Box::new(e)))?
                    else {
                        break;
                    };
                    range.start = next;
                }
                RangeMode::Reverse => {
                    let Some(previous) = exoware_sdk::keys::previous_key(&last_key) else {
                        break;
                    };
                    range.end = previous;
                }
            }
        }
        if emitted + output.row_count() >= target_rows {
            break;
        }
    }
    let _ = flush_projected_batch(tx, ctx, &mut output, &mut emitted).await?;
    Ok(())
}

fn ordered_ranges<'a>(
    ranges: &'a [KeyRange],
    direction: RangeMode,
) -> Box<dyn Iterator<Item = &'a KeyRange> + Send + 'a> {
    match direction {
        RangeMode::Forward => Box::new(ranges.iter()),
        RangeMode::Reverse => Box::new(ranges.iter().rev()),
    }
}

async fn range_stream_with_direction(
    session: &SerializableReadSession,
    range: &KeyRange,
    limit: usize,
    batch_size: usize,
    direction: RangeMode,
) -> DataFusionResult<RangeStream> {
    session
        .range_stream_with_mode(&range.start, &range.end, limit, batch_size, direction)
        .await
        .map_err(|e| DataFusionError::External(Box::new(e)))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use bytes::Bytes;
    use datafusion::arrow::array::{
        ArrayRef, Decimal128Array, FixedSizeBinaryArray, Float64Array, Int64Array, StringArray,
        TimestampMicrosecondArray, UInt64Array,
    };
    use datafusion::arrow::datatypes::{DataType, TimeUnit};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::common::{Result as DataFusionResult, ScalarValue};
    use datafusion::datasource::MemTable;
    use datafusion::prelude::SessionContext;
    use exoware_sdk::{StoreClient, StoreKeyPrefix};
    use exoware_server::{Query, QueryExtra, QueryState, RangeScan, RangeScanBatch, Sequence};

    use crate::types::KvTable;
    use crate::{IndexSpec, KvSchema, TableColumnConfig};

    #[derive(Clone, Debug)]
    enum Request {
        Get(Bytes),
        GetMany(Vec<Bytes>),
        Range {
            start: Bytes,
            end: Bytes,
            limit: usize,
            forward: bool,
        },
    }

    #[derive(Default)]
    struct Rows {
        values: Mutex<BTreeMap<Bytes, Bytes>>,
        requests: Mutex<Vec<Request>>,
        returned_rows: Arc<AtomicUsize>,
        returned_bytes: Arc<AtomicUsize>,
    }

    impl Sequence for Rows {
        fn current_sequence(&self) -> u64 {
            7
        }
    }

    struct Cursor {
        rows: std::vec::IntoIter<(Bytes, Bytes)>,
        returned_rows: Arc<AtomicUsize>,
        returned_bytes: Arc<AtomicUsize>,
    }

    impl RangeScan for Cursor {
        async fn next_batch(&mut self, max_items: usize) -> Result<RangeScanBatch, String> {
            let rows: Vec<_> = self.rows.by_ref().take(max_items).collect();
            self.returned_rows.fetch_add(rows.len(), Ordering::SeqCst);
            self.returned_bytes.fetch_add(
                rows.iter()
                    .map(|(key, value)| key.len() + value.len())
                    .sum(),
                Ordering::SeqCst,
            );
            Ok(RangeScanBatch {
                rows,
                extra: QueryExtra::new(),
            })
        }
    }

    impl Query for Rows {
        type RangeScan = Cursor;

        async fn get(&self, key: Bytes) -> Result<(Option<Bytes>, QueryExtra), String> {
            self.requests
                .lock()
                .unwrap()
                .push(Request::Get(key.clone()));
            Ok((
                self.values.lock().unwrap().get(&key).cloned(),
                QueryExtra::new(),
            ))
        }

        async fn get_many(
            &self,
            keys: Vec<Bytes>,
        ) -> Result<(Vec<(Bytes, Option<Bytes>)>, QueryExtra), String> {
            self.requests
                .lock()
                .unwrap()
                .push(Request::GetMany(keys.clone()));
            let values = self.values.lock().unwrap();
            let rows: Vec<_> = keys
                .into_iter()
                .rev()
                .map(|key| {
                    let value = values.get(&key).cloned();
                    (key, value)
                })
                .collect();
            self.returned_rows.fetch_add(rows.len(), Ordering::SeqCst);
            self.returned_bytes.fetch_add(
                rows.iter()
                    .map(|(key, value)| key.len() + value.as_ref().map_or(0, Bytes::len))
                    .sum(),
                Ordering::SeqCst,
            );
            Ok((rows, QueryExtra::new()))
        }

        async fn range_scan(
            &self,
            start: Bytes,
            end: Bytes,
            limit: usize,
            forward: bool,
        ) -> Result<Cursor, String> {
            self.requests.lock().unwrap().push(Request::Range {
                start: start.clone(),
                end: end.clone(),
                limit,
                forward,
            });
            let mut rows: Vec<_> = self
                .values
                .lock()
                .unwrap()
                .iter()
                .filter(|(key, _)| **key >= start && (end.is_empty() || **key <= end))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            if !forward {
                rows.reverse();
            }
            rows.truncate(limit);
            Ok(Cursor {
                rows: rows.into_iter(),
                returned_rows: self.returned_rows.clone(),
                returned_bytes: self.returned_bytes.clone(),
            })
        }
    }

    struct Fixture {
        store: SessionContext,
        native: SessionContext,
        rows: Arc<Rows>,
        table: Arc<KvTable>,
        prefix: StoreKeyPrefix,
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    impl Fixture {
        async fn new(
            columns: Vec<TableColumnConfig>,
            primary_key: &[&str],
            indexes: Vec<IndexSpec>,
            arrays: Vec<ArrayRef>,
        ) -> Self {
            let rows = Arc::new(Rows::default());
            let app = Router::new()
                .fallback_service(exoware_server::query_service(QueryState::new(rows.clone())));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let prefix = StoreKeyPrefix::new(Bytes::from_static(b"scan-tests/")).unwrap();
            let schema = KvSchema::new(StoreClient::new(&url).prefixed(prefix.clone()))
                .table(
                    "orders",
                    columns,
                    primary_key.iter().map(|name| name.to_string()).collect(),
                    indexes,
                )
                .unwrap();
            let table = schema.tables()[0].1.clone();
            let batch = RecordBatch::try_new(table.model.schema.clone(), arrays).unwrap();
            let entries =
                crate::writer::encode_insert_entries(&batch, &table.model, &table.index_specs)
                    .unwrap();
            rows.values.lock().unwrap().extend(
                entries
                    .into_iter()
                    .map(|(key, value)| (prefix.encode_key(&key).unwrap(), Bytes::from(value))),
            );
            let store = crate::session_context();
            schema.register_all(&store).unwrap();
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
                table,
                prefix,
                server,
            }
        }

        async fn check(&self, sql: &str) -> Vec<Request> {
            let expected = values(&self.native, sql).await.unwrap();
            self.rows.requests.lock().unwrap().clear();
            self.rows.returned_rows.store(0, Ordering::SeqCst);
            self.rows.returned_bytes.store(0, Ordering::SeqCst);
            let actual = values(&self.store, sql).await.unwrap();
            assert_eq!(actual, expected, "{sql}");
            let requests = self.rows.requests.lock().unwrap().clone();
            for request in &requests {
                match request {
                    Request::Get(key) => assert!(self.prefix.matches(key)),
                    Request::GetMany(keys) => {
                        assert!(keys.iter().all(|key| self.prefix.matches(key)))
                    }
                    Request::Range { start, end, .. } => {
                        assert!(self.prefix.matches(start));
                        assert!(self.prefix.matches(end));
                    }
                }
            }
            requests
        }

        fn index_matches(&self, index: usize, key: &Bytes) -> bool {
            let key = self.prefix.decode_key(key).unwrap();
            self.table.index_specs[index].prefix.matches(&key)
        }
    }

    async fn values(ctx: &SessionContext, sql: &str) -> DataFusionResult<Vec<Vec<ScalarValue>>> {
        let batches = ctx.sql(sql).await?.collect().await?;
        batches
            .iter()
            .flat_map(|batch| {
                (0..batch.num_rows()).map(|row| {
                    (0..batch.num_columns())
                        .map(|column| ScalarValue::try_from_array(batch.column(column), row))
                        .collect()
                })
            })
            .collect()
    }

    fn column(name: &str, data_type: DataType, nullable: bool) -> TableColumnConfig {
        TableColumnConfig::new(name, data_type, nullable)
    }

    fn index(name: &str, keys: &[&str], cover: &[&str]) -> IndexSpec {
        IndexSpec::lexicographic(name, keys.iter().map(|name| name.to_string()).collect())
            .unwrap()
            .with_cover_columns(cover.iter().map(|name| name.to_string()).collect())
    }

    #[tokio::test]
    async fn limit_continues_after_invalid_value_at_namespace_key_capacity() {
        let width = exoware_sdk::keys::MAX_KEY_LEN - b"scan-tests/".len() - 1;
        let invalid_pk = vec![0; width];
        let mut valid_pk = invalid_pk.clone();
        valid_pk[width - 1] = 1;
        let fixture = Fixture::new(
            vec![
                column("id", DataType::FixedSizeBinary(width as i32), false),
                column("amount", DataType::Int64, false),
            ],
            &["id"],
            vec![],
            vec![
                Arc::new(FixedSizeBinaryArray::try_from_iter([valid_pk].into_iter()).unwrap()),
                Arc::new(Int64Array::from(vec![42])),
            ],
        )
        .await;
        let logical_key = crate::codec::encode_primary_key(
            fixture.table.model.table_prefix,
            &[&crate::types::CellValue::FixedBinary(invalid_pk)],
            &fixture.table.model,
        )
        .unwrap();
        let invalid_key = fixture.prefix.encode_key(&logical_key).unwrap();
        assert_eq!(invalid_key.len(), exoware_sdk::keys::MAX_KEY_LEN);
        let next_key = exoware_sdk::keys::next_key(&invalid_key).unwrap();
        fixture
            .rows
            .values
            .lock()
            .unwrap()
            .insert(invalid_key, Bytes::from_static(b"invalid row"));

        let requests = fixture.check("SELECT amount FROM orders LIMIT 1").await;
        assert_eq!(requests.len(), 2);
        assert_eq!(fixture.rows.returned_rows.load(Ordering::SeqCst), 2);
        for (i, request) in requests.iter().enumerate() {
            let Request::Range {
                start,
                end,
                limit,
                forward,
            } = request
            else {
                panic!("expected Range, got {request:?}");
            };
            assert_eq!(*limit, 1);
            assert!(*forward);
            assert!(start.len() <= exoware_sdk::keys::MAX_KEY_LEN);
            assert!(end.len() <= exoware_sdk::keys::MAX_KEY_LEN);
            if i == 1 {
                assert_eq!(start, &next_key);
            }
        }
    }

    #[tokio::test]
    async fn reverse_limit_stops_at_empty_predecessor() {
        let fixture = Fixture::new(
            vec![column("id", DataType::Int64, false)],
            &["id"],
            vec![],
            vec![Arc::new(Int64Array::from(vec![1]))],
        )
        .await;
        let key = fixture
            .prefix
            .encode_key(&Bytes::from_static(&[0]))
            .unwrap();
        fixture
            .rows
            .values
            .lock()
            .unwrap()
            .insert(key, Bytes::new());

        let requests = fixture
            .check("SELECT id FROM orders ORDER BY id DESC LIMIT 2")
            .await;
        assert!(
            matches!(
                requests.as_slice(),
                [Request::Range {
                    forward: false,
                    limit: 2,
                    ..
                }]
            ),
            "{requests:?}"
        );
        assert_eq!(fixture.rows.returned_rows.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn residuals_preserve_casts_nulls_functions_and_limits() {
        let fixture = Fixture::new(
            vec![
                column("id", DataType::Int64, false),
                column("status", DataType::Utf8, true),
                column("amount", DataType::Int64, false),
            ],
            &["id"],
            vec![],
            vec![
                Arc::new(Int64Array::from(vec![1, 2, 3, 4])),
                Arc::new(StringArray::from(vec![
                    Some("open"),
                    Some("12"),
                    None,
                    Some("closed"),
                ])),
                Arc::new(Int64Array::from(vec![10, 20, 30, 40])),
            ],
        )
        .await;
        for sql in [
        "SELECT id FROM orders WHERE TRY_CAST(status AS BIGINT) IS NULL ORDER BY id",
        "SELECT id FROM orders WHERE TRY_CAST(status AS BIGINT) IS NOT NULL ORDER BY id",
        "SELECT id FROM orders WHERE CAST(id AS VARCHAR) = '2' ORDER BY id",
        "SELECT id FROM orders WHERE upper(status) = 'OPEN' ORDER BY id",
        "SELECT id FROM orders WHERE coalesce(status, 'missing') = 'missing' ORDER BY id",
        "SELECT id FROM orders WHERE id > 0 AND CAST(amount AS DOUBLE) / 3 > 8.5 ORDER BY id DESC LIMIT 1",
        "SELECT id FROM orders WHERE id > 0 AND (status LIKE 'op%' OR amount % 3 = 0) ORDER BY id DESC LIMIT 1",
        "SELECT id FROM orders WHERE CASE WHEN status IS NULL THEN TRUE ELSE amount > 30 END ORDER BY id",
        "SELECT 1 FROM orders WHERE upper(status) = 'OPEN'",
        "SELECT 1 FROM orders WHERE TRY_CAST(status AS BIGINT) IS NULL LIMIT 1",
        "SELECT id FROM orders WHERE id > 0 AND random() >= 0 ORDER BY id DESC LIMIT 2",
        "SELECT id FROM orders WHERE NULL",
    ] { fixture.check(sql).await; }
    }

    #[tokio::test]
    async fn numeric_points_batch_missing_keys_and_restore_wire_order() {
        let fixture = Fixture::new(
            vec![
                column("id", DataType::UInt64, false),
                column("amount", DataType::Int64, false),
            ],
            &["id"],
            vec![],
            vec![
                Arc::new(UInt64Array::from(vec![1, 3, 7, u64::MAX])),
                Arc::new(Int64Array::from(vec![10, 30, 70, 90])),
            ],
        )
        .await;
        let requests = fixture.check("SELECT id, amount FROM orders WHERE id IN (1, 2, 7, 18446744073709551615) ORDER BY id DESC").await;
        assert!(
            matches!(requests.as_slice(), [Request::GetMany(keys)] if keys.len() == 4),
            "{requests:?}"
        );
        let requests = fixture.check("SELECT id, amount FROM orders WHERE id IN (1, 2, 3, 7) AND abs(amount - 70) < 1 ORDER BY id LIMIT 1").await;
        assert!(
            matches!(requests.as_slice(), [Request::GetMany(keys)] if keys.len() == 4),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn string_points_batch_missing_keys_and_residual_limit() {
        let fixture = Fixture::new(
            vec![
                column("id", DataType::Utf8, false),
                column("amount", DataType::Int64, false),
            ],
            &["id"],
            vec![],
            vec![
                Arc::new(StringArray::from(vec!["a", "b", "c", "d"])),
                Arc::new(Int64Array::from(vec![10, 20, 30, 40])),
            ],
        )
        .await;
        let requests = fixture
            .check("SELECT id FROM orders WHERE id IN ('missing', 'a', 'd', 'b') ORDER BY id DESC")
            .await;
        assert!(
            matches!(requests.as_slice(), [Request::GetMany(keys)] if keys.len() == 4),
            "{requests:?}"
        );
        let overlong = "x".repeat(exoware_sdk::keys::MAX_KEY_LEN + 1);
        fixture
            .check(&format!(
                "SELECT id FROM orders WHERE id IN ('a', '{overlong}') ORDER BY id"
            ))
            .await;
        fixture
            .check(&format!(
                "SELECT id FROM orders WHERE id IN ('{overlong}', '{overlong}y') ORDER BY id"
            ))
            .await;
        let requests = fixture.check("SELECT id FROM orders WHERE id IN ('a', 'b', 'c', 'd') AND amount > 25 ORDER BY id LIMIT 1").await;
        assert!(
            matches!(requests.as_slice(), [Request::GetMany(keys)] if keys.len() == 4),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn composite_point_products_restore_descending_order() {
        let fixture = Fixture::new(
            vec![
                column("tenant", DataType::Utf8, false),
                column("version", DataType::Int64, false),
                column("amount", DataType::Int64, false),
            ],
            &["tenant", "version"],
            vec![],
            vec![
                Arc::new(StringArray::from(vec!["a", "a", "a", "b", "b", "b"])),
                Arc::new(Int64Array::from(vec![1, 2, 3, 1, 2, 3])),
                Arc::new(Int64Array::from(vec![10, 20, 30, 40, 50, 60])),
            ],
        )
        .await;
        let requests = fixture.check("SELECT tenant, version, amount FROM orders WHERE tenant IN ('a', 'b') AND version IN (1, 3, 99) ORDER BY tenant DESC, version DESC").await;
        assert!(
            matches!(requests.as_slice(), [Request::GetMany(keys)] if keys.len() == 6),
            "{requests:?}"
        );
        fixture.check("SELECT tenant, version FROM orders WHERE tenant IN ('a', 'b') AND version IN (1, 3, 99) AND amount > 20 ORDER BY tenant DESC, version DESC LIMIT 2").await;
    }

    #[tokio::test]
    async fn covering_selection_includes_projected_and_residual_columns() {
        let fixture = Fixture::new(
            vec![
                column("id", DataType::Int64, false),
                column("status", DataType::Utf8, false),
                column("amount", DataType::Int64, false),
            ],
            &["id"],
            vec![
                index("plain", &["status"], &[]),
                index("cover", &["status"], &["amount"]),
            ],
            vec![
                Arc::new(Int64Array::from(vec![1, 2, 3])),
                Arc::new(StringArray::from(vec!["open", "closed", "open"])),
                Arc::new(Int64Array::from(vec![10, 20, 30])),
            ],
        )
        .await;
        let requests = fixture
            .check("SELECT amount FROM orders WHERE status = 'open' ORDER BY amount")
            .await;
        assert!(
            matches!(requests.as_slice(), [Request::Range { start, .. }] if fixture.index_matches(1, start)),
            "{requests:?}"
        );
        let requests = fixture
            .check(
                "SELECT id FROM orders WHERE status = 'open' AND abs(amount - 30) < 1 ORDER BY id",
            )
            .await;
        assert!(
            matches!(requests.as_slice(), [Request::Range { start, .. }] if fixture.index_matches(1, start)),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn covering_index_supplies_reverse_suffix_order_and_limit() {
        let fixture = Fixture::new(
            vec![
                column("id", DataType::Int64, false),
                column("account", DataType::Int64, false),
                column("height", DataType::Int64, false),
                column("payload", DataType::Utf8, false),
            ],
            &["id"],
            vec![index(
                "account_height",
                &["account", "height"],
                &["payload"],
            )],
            vec![
                Arc::new(Int64Array::from(vec![1, 2, 3, 4, 5])),
                Arc::new(Int64Array::from(vec![7, 7, 7, 7, 8])),
                Arc::new(Int64Array::from(vec![10, 20, 30, 40, 99])),
                Arc::new(StringArray::from(vec!["a", "b", "c", "d", "other"])),
            ],
        )
        .await;
        let requests = fixture
            .check(
                "SELECT height, payload FROM orders WHERE account = 7 ORDER BY height DESC LIMIT 2",
            )
            .await;
        assert!(
            matches!(requests.as_slice(), [Request::Range { start, forward: false, limit: 2, .. }] if fixture.index_matches(0, start)),
            "{requests:?}"
        );
        let requests = fixture.check("SELECT height, payload FROM orders WHERE account = 7 AND upper(payload) <> 'D' ORDER BY height DESC LIMIT 2").await;
        assert!(
            matches!(
                requests.as_slice(),
                [Request::Range {
                    forward: false,
                    limit: usize::MAX,
                    ..
                }]
            ),
            "{requests:?}"
        );
        fixture
            .check(
                "SELECT height FROM orders WHERE account = 7 ORDER BY height DESC LIMIT 1 OFFSET 2",
            )
            .await;
    }

    #[tokio::test]
    async fn sort_pushdown_ignores_constant_key_prefix_columns() {
        for indexed in [false, true] {
            let fixture = Fixture::new(
                vec![
                    column("a", DataType::Int64, false),
                    column("b", DataType::Int64, false),
                ],
                if indexed { &["b"] } else { &["a", "b"] },
                if indexed {
                    vec![index("a", &["a"], &[])]
                } else {
                    vec![]
                },
                vec![
                    Arc::new(Int64Array::from(vec![1, 1, 1, 1, 2])),
                    Arc::new(Int64Array::from(vec![1, 2, 3, 4, 5])),
                ],
            )
            .await;
            for (columns, ordering, forward) in [
                ("a, b", "b", true),
                ("a, b", "a, b", true),
                ("a, b", "a DESC, b DESC", false),
                ("a, b", "a ASC, b DESC", false),
                ("a, b", "b ASC, a DESC", true),
                ("b, a", "a, b DESC", false),
                ("a", "a DESC", true),
            ] {
                let sql =
                    format!("SELECT {columns} FROM orders WHERE a = 1 ORDER BY {ordering} LIMIT 2");
                let plan = fixture
                    .store
                    .sql(&sql)
                    .await
                    .unwrap()
                    .create_physical_plan()
                    .await
                    .unwrap();
                let rendered = datafusion::physical_plan::displayable(plan.as_ref())
                    .indent(true)
                    .to_string();
                assert!(
                    !rendered.contains("SortExec"),
                    "{sql} (indexed={indexed})\n{rendered}"
                );
                let requests = fixture.check(&sql).await;
                assert!(
                    matches!(requests.as_slice(), [Request::Range { start, limit: 2, forward: actual, .. }]
                    if *actual == forward && (!indexed || fixture.index_matches(0, start))),
                    "{sql} (indexed={indexed}): {requests:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn covering_index_with_multiple_prefix_values_retains_global_sort() {
        let fixture = Fixture::new(
            vec![
                column("id", DataType::Int64, false),
                column("status", DataType::Utf8, false),
                column("amount", DataType::Int64, false),
            ],
            &["id"],
            vec![index("status_amount", &["status", "amount"], &[])],
            vec![
                Arc::new(Int64Array::from(vec![1, 2, 3, 4])),
                Arc::new(StringArray::from(vec!["a", "a", "z", "z"])),
                Arc::new(Int64Array::from(vec![30, 10, 40, 20])),
            ],
        )
        .await;
        for sql in [
            "SELECT amount FROM orders WHERE status IN ('a', 'z') ORDER BY amount LIMIT 3",
            "SELECT amount FROM orders WHERE status IN ('a', 'z') ORDER BY amount DESC LIMIT 3",
        ] {
            let requests = fixture.check(sql).await;
            assert!(
                requests.iter().all(|request| matches!(request,
                    Request::Range { start, .. } if fixture.index_matches(0, start)
                )),
                "{requests:?}"
            );
        }
    }

    #[tokio::test]
    async fn bounded_point_expansion_handles_large_lists_and_products() {
        let fixture = Fixture::new(
            vec![column("id", DataType::Int64, false)],
            &["id"],
            vec![],
            vec![Arc::new(Int64Array::from(vec![1, 257, 513]))],
        )
        .await;
        let list = (0..257)
            .map(|i| (2 * i + 1).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let requests = fixture
            .check(&format!(
                "SELECT id FROM orders WHERE id IN ({list}) ORDER BY id DESC"
            ))
            .await;
        assert!(
            matches!(requests.as_slice(), [Request::GetMany(keys)] if keys.len() == 257),
            "{requests:?}"
        );

        let fixture = Fixture::new(
            vec![
                column("tenant", DataType::Utf8, false),
                column("version", DataType::Int64, false),
            ],
            &["tenant", "version"],
            vec![],
            vec![
                Arc::new(StringArray::from(vec![
                    "tenant00", "tenant00", "tenant64", "other",
                ])),
                Arc::new(Int64Array::from(vec![0, 64, 64, 0])),
            ],
        )
        .await;
        let tenants = (0..65)
            .map(|i| format!("'tenant{i:02}'"))
            .collect::<Vec<_>>()
            .join(",");
        let versions = (0..65).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        let requests = fixture.check(&format!("SELECT tenant, version FROM orders WHERE tenant IN ({tenants}) AND version IN ({versions}) ORDER BY tenant, version")).await;
        assert!(
            requests
                .iter()
                .any(|request| matches!(request, Request::Range { .. })),
            "{requests:?}"
        );
        assert!(
            requests
                .iter()
                .all(|request| !matches!(request, Request::GetMany(keys) if keys.len() > 4096)),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn decimal_scale_and_timestamp_casts_preserve_predicate_results() {
        for indexed in [false, true] {
            let fixture = Fixture::new(
                vec![
                    column("id", DataType::Int64, false),
                    column("amount", DataType::Decimal128(12, 2), !indexed),
                    column(
                        "happened_at",
                        DataType::Timestamp(TimeUnit::Microsecond, None),
                        !indexed,
                    ),
                ],
                &["id"],
                if indexed {
                    vec![
                        index("amount", &["amount"], &[]),
                        index("happened_at", &["happened_at"], &[]),
                    ]
                } else {
                    vec![]
                },
                vec![
                    Arc::new(Int64Array::from(if indexed {
                        vec![1, 2, 3, 4]
                    } else {
                        vec![1, 2, 3, 4, 5]
                    })),
                    Arc::new(
                        Decimal128Array::from(if indexed {
                            vec![Some(100), Some(199), Some(200), Some(201)]
                        } else {
                            vec![Some(100), Some(199), Some(200), Some(201), None]
                        })
                        .with_precision_and_scale(12, 2)
                        .unwrap(),
                    ),
                    Arc::new(TimestampMicrosecondArray::from(if indexed {
                        vec![Some(0), Some(1), Some(1_000_000), Some(1_000_001)]
                    } else {
                        vec![Some(0), Some(1), Some(1_000_000), Some(1_000_001), None]
                    })),
                ],
            )
            .await;
            for sql in [
            "SELECT id FROM orders WHERE amount > 1.995 ORDER BY id",
            "SELECT id FROM orders WHERE amount = CAST(2 AS DECIMAL(12, 2)) ORDER BY id",
            "SELECT id FROM orders WHERE CAST(amount AS DECIMAL(12, 1)) = 2.0 ORDER BY id",
            "SELECT id FROM orders WHERE CAST(amount AS DOUBLE) < 2.001 ORDER BY id",
            "SELECT id FROM orders WHERE amount IS NULL ORDER BY id",
            "SELECT id FROM orders WHERE happened_at > TIMESTAMP '1970-01-01 00:00:01' ORDER BY id",
            "SELECT id FROM orders WHERE happened_at = TIMESTAMP '1970-01-01 00:00:00.000001' ORDER BY id",
            "SELECT id FROM orders WHERE CAST(happened_at AS BIGINT) > 1000000 ORDER BY id",
            "SELECT id FROM orders WHERE CAST(happened_at AS DATE) = DATE '1970-01-01' ORDER BY id",
            "SELECT id FROM orders WHERE happened_at IS NULL ORDER BY id",
        ] {
            fixture.check(&format!("{sql} /* indexed={indexed} */")).await;
        }
        }
    }

    #[tokio::test]
    async fn timestamp_units_coerce_comparisons() {
        for indexed in [false, true] {
            let fixture = Fixture::new(
                vec![
                    column("id", DataType::Int64, false),
                    column(
                        "happened_at",
                        DataType::Timestamp(TimeUnit::Microsecond, None),
                        false,
                    ),
                ],
                &["id"],
                if indexed {
                    vec![index("happened_at", &["happened_at"], &[])]
                } else {
                    vec![]
                },
                vec![
                    Arc::new(Int64Array::from_iter_values(0..7)),
                    Arc::new(TimestampMicrosecondArray::from_iter_values(-3..4)),
                ],
            )
            .await;
            for (unit, value) in [
                ("Microsecond", -2),
                ("Microsecond", 2),
                ("Nanosecond", -2000),
                ("Nanosecond", -1500),
                ("Nanosecond", 1500),
                ("Nanosecond", 2000),
            ] {
                let literal = format!("arrow_cast({value}, 'Timestamp({unit}, None)')");
                for op in ["=", "<", "<=", ">", ">="] {
                    for predicate in [
                        format!("happened_at {op} {literal}"),
                        format!("{literal} {op} happened_at"),
                    ] {
                        let requests = fixture
                            .check(&format!(
                                "SELECT id FROM orders WHERE {predicate} ORDER BY id"
                            ))
                            .await;
                        if indexed && unit == "Microsecond" {
                            assert!(
                                requests.iter().any(|request| matches!(request,
                                    Request::Range { start, .. } if fixture.index_matches(0, start)
                                )),
                                "{predicate}: {requests:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn covering_predicates_reject_rows_before_base_lookups() {
        let fixture = Fixture::new(
            vec![
                column("id", DataType::Int64, false),
                column("status", DataType::Utf8, false),
                column("amount", DataType::Int64, false),
                column("payload", DataType::Utf8, false),
            ],
            &["id"],
            vec![index("status_amount", &["status"], &["amount"])],
            vec![
                Arc::new(Int64Array::from(vec![1, 2, 3, 4])),
                Arc::new(StringArray::from(vec!["open", "open", "closed", "open"])),
                Arc::new(Int64Array::from(vec![10, 20, 30, 40])),
                Arc::new(StringArray::from(vec!["a", "b", "c", "d"])),
            ],
        )
        .await;
        let requests = fixture.check("SELECT payload FROM orders WHERE status = 'open' AND abs(amount - 40) < 1 ORDER BY payload").await;
        let lookup_keys: Vec<_> = requests
            .iter()
            .filter_map(|request| match request {
                Request::GetMany(keys) => Some(keys),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(lookup_keys.len(), 1, "{requests:?}");
        assert!(
            matches!(requests.first(), Some(Request::Range { start, .. }) if fixture.index_matches(0, start)),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn full_primary_points_win_over_secondary_filters() {
        let fixture = Fixture::new(
            vec![
                column("id", DataType::Utf8, false),
                column("status", DataType::Utf8, false),
            ],
            &["id"],
            vec![index("status", &["status"], &[])],
            vec![
                Arc::new(StringArray::from(vec!["a", "b", "c"])),
                Arc::new(StringArray::from(vec!["open", "open", "closed"])),
            ],
        )
        .await;
        let requests = fixture
            .check("SELECT id FROM orders WHERE id = 'b' AND status = 'open'")
            .await;
        assert!(
            matches!(requests.as_slice(), [Request::GetMany(keys)] if keys.len() == 1),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn float_predicates_preserve_total_order_with_and_without_indexes() {
        for indexed in [false, true] {
            let fixture = Fixture::new(
                vec![
                    column("id", DataType::Int64, false),
                    column("score", DataType::Float64, false),
                ],
                &["id"],
                if indexed {
                    vec![index("score", &["score"], &[])]
                } else {
                    vec![]
                },
                vec![
                    Arc::new(Int64Array::from(vec![1, 2, 3, 4, 5, 6, 7, 8])),
                    Arc::new(Float64Array::from(vec![
                        -f64::NAN,
                        f64::NEG_INFINITY,
                        -0.0,
                        0.0,
                        1.0,
                        f64::INFINITY,
                        f64::NAN,
                        f64::from_bits(f64::NAN.to_bits() + 1),
                    ])),
                ],
            )
            .await;
            for sql in [
                "SELECT id FROM orders WHERE score = 0.0 ORDER BY id",
                "SELECT id FROM orders WHERE score = CAST('-0' AS DOUBLE) ORDER BY id",
                "SELECT id FROM orders WHERE score >= 0.0 ORDER BY id",
                "SELECT id FROM orders WHERE score < 0.0 ORDER BY id",
                "SELECT id FROM orders WHERE score > CAST('Infinity' AS DOUBLE) ORDER BY id",
                "SELECT id FROM orders WHERE score <= CAST('-Infinity' AS DOUBLE) ORDER BY id",
                "SELECT id FROM orders WHERE score = CAST('NaN' AS DOUBLE) ORDER BY id",
                "SELECT id FROM orders WHERE score >= CAST('NaN' AS DOUBLE) ORDER BY id",
                "SELECT id FROM orders WHERE score <= CAST('-NaN' AS DOUBLE) ORDER BY id",
                "SELECT id FROM orders WHERE score <> 0.0 ORDER BY id",
            ] {
                fixture
                    .check(&format!("{sql} /* indexed={indexed} */"))
                    .await;
            }
        }
    }

    #[tokio::test]
    async fn partial_primary_key_ranges_respect_namespace_capacity() {
        let near_limit = "n".repeat(233);
        let fixture = Fixture::new(
            vec![
                column("tenant", DataType::Utf8, false),
                column("version", DataType::Int64, false),
            ],
            &["tenant", "version"],
            vec![],
            vec![
                Arc::new(StringArray::from(vec!["a", "b", near_limit.as_str()])),
                Arc::new(Int64Array::from(vec![1, 1, 1])),
            ],
        )
        .await;
        let too_long = "x".repeat(fixture.prefix.max_logical_key_len());
        let escaped_too_long = "\u{1}".repeat(122);
        for predicate in [
            format!("tenant IN ('a', '{too_long}')"),
            format!("tenant IN ('a', '{escaped_too_long}')"),
            format!("tenant IN ('{too_long}', '{too_long}y')"),
            format!("tenant = '{too_long}'"),
            format!("tenant IN ('a', '{near_limit}', '{too_long}')"),
            format!("tenant = '{near_limit}'"),
        ] {
            for projection in ["tenant, version", "COUNT(*)"] {
                fixture
                    .check(&format!(
                        "SELECT {projection} FROM orders WHERE {predicate} ORDER BY 1"
                    ))
                    .await;
            }
            fixture
            .check(&format!(
                "SELECT tenant, COUNT(*) FROM orders WHERE {predicate} GROUP BY tenant ORDER BY tenant"
            ))
            .await;
        }
    }
}
