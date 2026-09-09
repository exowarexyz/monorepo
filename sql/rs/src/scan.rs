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
        _context: Arc<TaskContext>,
    ) -> DataFusionResult<SendableRecordBatchStream> {
        if partition != 0 {
            return Err(DataFusionError::Internal(format!(
                "KvScanExec only supports 1 partition, got {partition}"
            )));
        }

        let mut builder = RecordBatchReceiverStreamBuilder::new(self.schema(), 2);
        let tx = builder.tx();
        let session = self.client.create_session();
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
