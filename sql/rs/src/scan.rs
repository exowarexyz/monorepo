use crate::{
    builder::*, codec::*, diagnostics::*, filter::*, predicate::*, session::read_session, types::*,
};
use datafusion::{
    arrow::{
        array::{as_boolean_array, Array},
        datatypes::SchemaRef,
        record_batch::RecordBatch,
    },
    catalog::Session,
    common::{tree_node::TreeNodeRecursion, DFSchema, DataFusionError, Result as DataFusionResult},
    execution::context::TaskContext,
    logical_expr::{
        utils::{conjunction, iter_conjunction},
        Expr,
    },
    physical_expr::{
        expressions::Column, EquivalenceProperties, LexOrdering, Partitioning, PhysicalExpr,
        PhysicalSortExpr,
    },
    physical_plan::{
        execution_plan::{apply_expression_roots, Boundedness, EmissionType},
        stream::RecordBatchReceiverStreamBuilder,
        DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties, SendableRecordBatchStream,
        SortOrderPushdownResult,
    },
};
use exoware_sdk::{
    keys::Key,
    kv_codec::{decode_stored_row, StoredRow},
    PrefixedStoreClient, RangeMode, RangeStream, ReadSession, StoreKeyPrefix,
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
};

/// Minimum fetch batch size, in rows, to amortize RPC framing and filter evaluation.
const MIN_FETCH_BATCH_ROWS: usize = 64;

/// A physical predicate evaluated over the table columns it references.
#[derive(Clone)]
pub(crate) struct ScanFilter {
    /// Predicate bound to column positions in `schema`.
    expression: Arc<dyn PhysicalExpr>,
    /// Referenced columns in table order.
    schema: SchemaRef,
    /// Decoding and projection needed to build the predicate's input batch.
    access: ScanAccessPlan,
    /// Whether constraint extraction supports every source filter. Raw scan limits
    /// also require the chosen key to enforce those constraints.
    complete_ranges: bool,
}

impl fmt::Debug for ScanFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.expression.fmt(f)
    }
}

impl ScanFilter {
    /// Selects the columns needed to evaluate the filters as physical expressions.
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

    /// Compiles nonempty filters against their selected input columns.
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

    /// Returns positions of decodable rows whose predicate evaluates to true.
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

/// A DataFusion leaf that reads a table through its primary key or a secondary index.
///
/// Construction fixes column access and index selection. Limit and sort pushdown
/// clone the scan and share its cached plan.
#[derive(Debug, Clone)]
pub(crate) struct KvScanExec {
    /// Client for the Store namespace containing the table.
    pub(crate) store: PrefixedStoreClient,
    /// Column types, primary-key layout, and row schema for the table.
    model: Arc<TableModel>,
    /// Resolved secondary indexes available to the scan.
    index_specs: Arc<Vec<ResolvedIndexSpec>>,
    /// Extracted filter constraints used to bound reads and check index keys.
    predicate: QueryPredicate,
    /// Maximum matching rows to emit, or `None` for no limit.
    pub(crate) fetch: Option<usize>,
    /// Predicate evaluated on decoded rows, including conditions key ranges cannot enforce.
    filter: Option<ScanFilter>,
    /// Filter conjuncts evaluated from index entries before base-row lookups.
    cover_filter: Option<ScanFilter>,
    /// Column access and index selection, shared by every clone of the scan.
    plan: Arc<ScanPlan>,
    /// Direction required by sort pushdown. `None` defaults to forward traversal
    /// without promising an output ordering.
    direction: Option<RangeMode>,
    /// Output schema, ordering guarantees, and single-partition execution metadata.
    pub(crate) properties: Arc<PlanProperties>,
}

/// Column access and index selection fixed when a scan is built.
#[derive(Debug)]
struct ScanPlan {
    /// Output projection and the columns required for decoding and filtering.
    access: ScanAccessPlan,
    /// Selected secondary index and its key ranges, or `None` for primary-key access.
    index: Option<IndexPlan>,
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

    /// Plans a scan for a projection, pushed-down filters, and an optional output limit.
    pub(crate) fn try_new(
        table: &KvTable,
        state: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        fetch: Option<usize>,
    ) -> DataFusionResult<Self> {
        // Keep the output schema limited to projected columns. The access plan also
        // includes columns needed to check the extracted constraints.
        let model = table.model.clone();
        let predicate = QueryPredicate::from_filters(filters, &model);
        let projected_schema = match projection {
            Some(proj) => Arc::new(model.schema.project(proj)?),
            None => model.schema.clone(),
        };
        let projection = projection.cloned();
        let plan = Arc::new(ScanPlan {
            access: ScanAccessPlan::new(&model, &projection, &predicate),
            index: None,
        });
        let mut scan = Self {
            store: table.store.clone(),
            model,
            index_specs: table.index_specs.clone(),
            predicate,
            fetch,
            filter: None,
            cover_filter: None,
            plan,
            direction: None,
            properties: Self::make_properties(projected_schema, None),
        };

        // Finalize the plan with any columns needed only by row filters.
        scan.set_filters(state, filters)?;
        Ok(scan)
    }

    /// Compiles filters and caches the column access and index choice they require.
    fn set_filters(&mut self, state: &dyn Session, filters: &[Expr]) -> DataFusionResult<()> {
        // Without filters, the constructor's plan already describes a primary-key scan of
        // the projected columns.
        if filters.is_empty() {
            return Ok(());
        }

        // Residual-filter columns determine whether an index covers the scan.
        let filter_access = ScanFilter::access_plan(&self.model, filters);
        let access = self.access_with_filter(&filter_access.1);
        let index_plan = self
            .predicate
            .choose_index_plan(&self.model, &self.index_specs, &access);
        let mut cover_filter = None;
        if let Some(plan) = &index_plan {
            let spec = &self.index_specs[plan.spec_idx];
            if !access.index_covers_required_non_pk(spec) {
                // Evaluate available conjuncts before fetching missing base-table values.
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
            // Primary-key ranges enforce every filter, so the scan needs no row filter and
            // only the projected and constrained columns. Column requirements only rank
            // candidate indexes, so the narrower column set cannot make one eligible.
            return Ok(());
        }

        // Keep the complete row filter even when some conjuncts can run on the index.
        // Cache the plan with all columns that filter requires.
        self.filter = ScanFilter::compile(state, &self.model, filters, filter_access)?;
        self.cover_filter = cover_filter;
        self.plan = Arc::new(ScanPlan {
            access,
            index: index_plan,
        });
        Ok(())
    }

    /// Extends required-column masks with the physical filter's input columns.
    fn access_with_filter(&self, filter_access: &ScanAccessPlan) -> ScanAccessPlan {
        let mut access = self.plan.access.clone();
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
        access
    }

    pub(crate) fn scan_direction(&self) -> RangeMode {
        self.direction.unwrap_or(RangeMode::Forward)
    }

    /// Finds a scan direction that satisfies the requested ordering on the selected key.
    fn order_direction_for_primary_key(&self, order: &LexOrdering) -> Option<RangeMode> {
        if self.predicate.contradiction {
            return None;
        }
        let (key_columns, constant_prefix_len) = if let Some(plan) = &self.plan.index {
            // Index ordering requires a covering lexicographic scan.
            let spec = &self.index_specs[plan.spec_idx];
            if spec.layout != IndexLayout::Lexicographic
                || !self.plan.access.index_covers_required_non_pk(spec)
            {
                return None;
            }

            // Require non-null columns with encodings that preserve SQL value order.
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
                return None;
            }

            // Skip leading columns fixed to one value. An IN constraint can span
            // several values, so it does not establish a constant prefix.
            let constant_prefix_len = columns
                .iter()
                .take_while(|&&i| {
                    self.predicate.constraints.get(&i).is_some_and(|c| {
                        !matches!(
                            c,
                            PredicateConstraint::StringIn(_)
                                | PredicateConstraint::IntIn(_)
                                | PredicateConstraint::UInt64In(_)
                                | PredicateConstraint::FixedSizeBinaryIn(_)
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

        // Skip fixed columns and require the remaining requested sort keys to
        // follow the stored key order in one consistent direction.
        let (constant_columns, ordered_columns) = key_columns.split_at(constant_prefix_len);
        let mut ordered_columns = ordered_columns.iter();
        let mut direction = None;

        for sort_expr in order {
            let column = sort_expr.expr.downcast_ref::<Column>()?;
            let actual_col_idx = match self.plan.access.projection_sources.get(column.index())? {
                ProjectionSource::Pk { col_idx, .. } | ProjectionSource::NonPk { col_idx, .. } => {
                    *col_idx
                }
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
                return None;
            }
            direction = Some(requested_direction);
        }

        Some(direction.unwrap_or(self.scan_direction()))
    }

    /// Counts leading primary-key columns fixed to one value by the scanned ranges.
    /// These columns place no restriction on the scan direction needed for ordering.
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
            self.store.key_prefix().max_logical_key_len(),
            &self.index_specs,
            &self.predicate,
            &self.plan.access,
            self.plan.index.as_ref(),
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

        // The stream task owns its read session and cloned plan so it can keep
        // reading after this method returns.
        let mut builder = RecordBatchReceiverStreamBuilder::new(self.schema(), 2);
        let tx = builder.tx();
        let session = read_session(context.session_config(), &self.store)?;
        let key_prefix = self.store.key_prefix().clone();
        let model = self.model.clone();
        let index_specs = self.index_specs.clone();
        let predicate = self.predicate.clone();
        let fetch = self.fetch;
        let direction = self.scan_direction();
        let projected_schema = self.schema();
        let plan = self.plan.clone();
        let filter = self.filter.clone();
        let cover_filter = self.cover_filter.clone();

        builder.spawn(async move {
            let ctx = ScanCtx {
                session: &session,
                key_prefix: &key_prefix,
                model: &model,
                predicate: &predicate,
                projected_schema: &projected_schema,
                access_plan: &plan.access,
                filter: filter.as_ref(),
                cover_filter: cover_filter.as_ref(),
            };
            if let Err(e) = stream_kv_scan(
                &tx,
                &ctx,
                &index_specs,
                plan.index.as_ref(),
                fetch,
                direction,
            )
            .await
            {
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
        let Some(direction) = self.order_direction_for_primary_key(&expressions) else {
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

/// Borrowed inputs shared by the streaming paths for one scan execution.
pub(crate) struct ScanCtx<'a> {
    /// Read session used by every Store request in the execution.
    pub(crate) session: &'a ReadSession,
    /// Store namespace used to bound and advance logical scan keys.
    key_prefix: &'a StoreKeyPrefix,
    /// Column types and key layout used to decode stored rows.
    pub(crate) model: &'a TableModel,
    /// Extracted constraints for primary-key points and ranges.
    pub(crate) predicate: &'a QueryPredicate,
    /// Arrow schema of each emitted record batch.
    pub(crate) projected_schema: &'a SchemaRef,
    /// Required key and value columns, and their positions in the output.
    pub(crate) access_plan: &'a ScanAccessPlan,
    /// Predicate applied to decoded rows before they enter output batches.
    filter: Option<&'a ScanFilter>,
    /// Predicate applied to index entries before base-row lookups.
    cover_filter: Option<&'a ScanFilter>,
}

impl ScanCtx<'_> {
    fn decode_row(
        &self,
        key: &Key,
        value: &[u8],
    ) -> DataFusionResult<Option<(Vec<CellValue>, StoredRow)>> {
        let Some(pk) = decode_primary_key_selected(
            self.model.table_prefix,
            key,
            self.model,
            &self.access_plan.required_pk_mask,
        ) else {
            return Ok(None);
        };
        self.decode_value(pk, value, false)
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
        output: &mut ProjectedBatchBuilder<'_>,
        remaining: &mut usize,
    ) -> DataFusionResult<()> {
        if let Some(filter) = self.filter {
            for i in filter.select(self.model, rows)? {
                if *remaining == 0 {
                    break;
                }
                if output.append_archived_row(&rows[i].0, &rows[i].1)? {
                    *remaining -= 1;
                }
            }
        } else {
            for (pk, row) in rows {
                if *remaining == 0 {
                    break;
                }
                if output.append_archived_row(pk, row)? {
                    *remaining -= 1;
                }
            }
        }
        Ok(())
    }
}

/// Sends a nonempty batch and resets its builder. Returns false if the receiver closed.
pub(crate) async fn flush_projected_batch<'a>(
    tx: &tokio::sync::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'a>,
    batch_builder: &mut ProjectedBatchBuilder<'a>,
) -> DataFusionResult<bool> {
    let batch_size = batch_builder.row_count();
    if batch_size == 0 {
        return Ok(true);
    }
    let ready = std::mem::replace(
        batch_builder,
        ProjectedBatchBuilder::from_access_plan(ctx.model, ctx.access_plan),
    );
    let batch = ready.finish(ctx.projected_schema)?;
    if tx.send(Ok(batch)).await.is_err() {
        return Ok(false);
    }
    Ok(true)
}

/// Streams matching rows through point reads, a secondary index, or primary-key ranges.
pub(crate) async fn stream_kv_scan(
    tx: &tokio::sync::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'_>,
    index_specs: &[ResolvedIndexSpec],
    index_plan: Option<&IndexPlan>,
    limit: Option<usize>,
    direction: RangeMode,
) -> DataFusionResult<()> {
    // A contradiction or a zero limit yields no rows. Otherwise output batches flush at
    // the smaller of the limit and `BATCH_FLUSH_ROWS`.
    if ctx.predicate.contradiction {
        return Ok(());
    }
    if limit == Some(0) {
        return Ok(());
    }
    let target_rows = limit.unwrap_or(usize::MAX);
    let flush_threshold = limit.unwrap_or(BATCH_FLUSH_ROWS).min(BATCH_FLUSH_ROWS);

    // Complete primary-key constraints permit direct reads. Keep their sorted
    // order aligned with the requested traversal direction.
    if let Some(mut keys) = ctx.predicate.primary_key_points(ctx.model)? {
        keys.retain(|key| key.len() <= ctx.key_prefix.max_logical_key_len());
        if direction == RangeMode::Reverse {
            keys.reverse();
        }
        return stream_point_scan(tx, ctx, &keys, flush_threshold, target_rows).await;
    }

    // A covering index supplies the required values directly. Other index
    // scans use its entries to fetch base rows.
    if let Some(plan) = index_plan {
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
        return stream_index_lookup_scan(tx, ctx, index_specs, plan, flush_threshold, target_rows)
            .await;
    }

    // Primary-key ranges handle scans without point keys or a selected secondary index.
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

/// Fetches decodable base rows in request order, regardless of response order.
async fn get_rows(
    ctx: &ScanCtx<'_>,
    keys: &[Key],
) -> DataFusionResult<Vec<(Vec<CellValue>, StoredRow)>> {
    let refs = keys.iter().collect::<Vec<_>>();
    let mut stream = ctx
        .session
        .get_many(&refs, keys.len())
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
            if let Some(row) = ctx.decode_row(key, &value)? {
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

/// Streams primary-key points in batches sized to the output flush threshold. Filters that
/// the keys cannot enforce raise the batch to at least `MIN_FETCH_BATCH_ROWS`.
async fn stream_point_scan(
    tx: &tokio::sync::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'_>,
    keys: &[Key],
    flush_threshold: usize,
    target_rows: usize,
) -> DataFusionResult<()> {
    let mut remaining = target_rows;
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

        ctx.append_rows(&rows, &mut output, &mut remaining)?;
        if output.row_count() >= flush_threshold
            && !flush_projected_batch(tx, ctx, &mut output).await?
        {
            return Ok(());
        }
        if remaining == 0 {
            break;
        }
    }
    let _ = flush_projected_batch(tx, ctx, &mut output).await?;
    Ok(())
}

/// Filters secondary-index entries before fetching and filtering their base rows.
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
    let mut remaining = target_rows;
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

                ctx.append_rows(&rows, &mut batch_builder, &mut remaining)?;
                if remaining == 0 {
                    break 'ranges;
                }
                if batch_builder.row_count() >= flush_threshold
                    && !flush_projected_batch(tx, ctx, &mut batch_builder).await?
                {
                    return Ok(());
                }
            }
        }
    }
    let _ = flush_projected_batch(tx, ctx, &mut batch_builder).await?;
    Ok(())
}

/// Streams primary-key or covering-index ranges up to the matching-row limit.
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
    let mut remaining = target_rows;
    let mut output = ProjectedBatchBuilder::from_access_plan(ctx.model, ctx.access_plan);
    for range in ordered_ranges(ranges, direction) {
        let mut range = range.clone();
        loop {
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
                        ctx.decode_row(key, value)?
                    };
                    let Some(row) = row else { continue };
                    if ctx.filter.is_some() {
                        rows.push(row);
                    } else if remaining > 0 && output.append_archived_row(&row.0, &row.1)? {
                        remaining -= 1;
                    }
                }
                if ctx.filter.is_some() {
                    ctx.append_rows(&rows, &mut output, &mut remaining)?;
                }
                if output.row_count() >= flush_threshold
                    && !flush_projected_batch(tx, ctx, &mut output).await?
                {
                    return Ok(());
                }
                if remaining == 0 {
                    break;
                }
            }
            if remaining == 0 || scanned < raw_limit {
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
        if remaining == 0 {
            break;
        }
    }
    let _ = flush_projected_batch(tx, ctx, &mut output).await?;
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
    session: &ReadSession,
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
    use super::KvScanExec;
    use crate::{filter::ScanAccessPlan, types::KvTable, IndexSpec, KvSchema, TableColumnConfig};
    use axum::{
        serve::{Listener, ListenerExt},
        Router,
    };
    use bytes::Bytes;
    use commonware_codec::Encode;
    use datafusion::{
        arrow::{
            array::{
                ArrayRef, Decimal128Array, FixedSizeBinaryArray, Float64Array, Int64Array,
                StringArray, TimestampMicrosecondArray, UInt64Array,
            },
            compute::SortOptions,
            datatypes::{DataType, TimeUnit},
            record_batch::RecordBatch,
        },
        common::{Result as DataFusionResult, ScalarValue},
        datasource::MemTable,
        logical_expr::{col, in_list, lit},
        physical_expr::{expressions::Column, PhysicalSortExpr},
        physical_plan::{ExecutionPlan, SortOrderPushdownResult},
        prelude::SessionContext as DataFusionSessionContext,
    };
    use exoware_sdk::{
        kv_codec::{StoredRow, StoredValue},
        transport::set_tcp_nodelay,
        RangeMode, StoreClient, StoreKeyPrefix,
    };
    use exoware_server::{
        Query, QueryExtra, QueryResult, QueryState, RangeScan, RangeScanBatch, RangeScanResult,
        Sequence,
    };
    use futures::TryStreamExt;
    use std::{
        collections::BTreeMap,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    /// Store reads observed while executing a query.
    #[derive(Clone, Debug)]
    enum Request {
        /// A point lookup by its physical Store key.
        Get(Bytes),
        /// A batch of point lookups in request order.
        GetMany(Vec<Bytes>),
        /// An inclusive range read over physical Store keys.
        Range {
            /// Inclusive lower key bound.
            start: Bytes,
            /// Inclusive upper key bound, or empty for no upper bound.
            end: Bytes,
            /// Maximum stored entries the request may return.
            limit: usize,
            /// Whether entries are returned in ascending key order.
            forward: bool,
        },
    }

    /// Stored test data and observations shared with the query service.
    #[derive(Default)]
    struct Rows {
        /// Encoded primary and secondary entries, indexed by physical Store key.
        values: Mutex<BTreeMap<Bytes, Bytes>>,
        /// Reads recorded in arrival order.
        requests: Mutex<Vec<Request>>,
        /// Entries returned by batch lookups and range cursors, including missing lookups.
        returned_rows: Arc<AtomicUsize>,
        /// Key and value bytes returned by batch lookups and range cursors.
        returned_bytes: Arc<AtomicUsize>,
    }

    impl Sequence for Rows {
        fn current_sequence(&self) -> u64 {
            7
        }
    }

    /// A range snapshot that records data returned to the test's query client.
    struct Cursor {
        /// Remaining entries in the requested traversal order.
        rows: std::vec::IntoIter<(Bytes, Bytes)>,
        /// Shared count of entries returned by batch lookups and range cursors.
        returned_rows: Arc<AtomicUsize>,
        /// Shared count of returned key and value bytes.
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

        async fn get(&self, key: Bytes) -> Result<QueryResult<Option<Bytes>>, String> {
            let sequence_number = self.current_sequence();
            self.requests
                .lock()
                .unwrap()
                .push(Request::Get(key.clone()));
            Ok(QueryResult {
                value: self.values.lock().unwrap().get(&key).cloned(),
                sequence_number,
                extra: QueryExtra::new(),
            })
        }

        async fn get_many(
            &self,
            keys: Vec<Bytes>,
        ) -> Result<QueryResult<Vec<(Bytes, Option<Bytes>)>>, String> {
            let sequence_number = self.current_sequence();
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
            Ok(QueryResult {
                value: rows,
                sequence_number,
                extra: QueryExtra::new(),
            })
        }

        async fn range_scan(
            &self,
            start: Bytes,
            end: Bytes,
            limit: usize,
            forward: bool,
        ) -> Result<RangeScanResult<Cursor>, String> {
            let sequence_number = self.current_sequence();
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
            Ok(RangeScanResult {
                scan: Cursor {
                    rows: rows.into_iter(),
                    returned_rows: self.returned_rows.clone(),
                    returned_bytes: self.returned_bytes.clone(),
                },
                sequence_number,
            })
        }
    }

    /// Identical Store and in-memory tables for checking query results and Store reads.
    struct Fixture {
        /// SQL context backed by the test's Store query service.
        context: crate::SqlContext,
        /// DataFusion context backed by an in-memory reference table.
        native: DataFusionSessionContext,
        /// Stored entries and observations for the current query.
        rows: Arc<Rows>,
        /// Table model and indexes used to encode the test data.
        table: Arc<KvTable>,
        /// Namespace prepended to each table and index key in the Store.
        prefix: StoreKeyPrefix,
        /// Query-service task aborted when the fixture is dropped.
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
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap()
                .tap_io(set_tcp_nodelay);
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
                    .map(|(key, value)| (prefix.encode_key(&key).unwrap(), value)),
            );
            let context = crate::SqlContext::new(schema.store().clone());
            context.register_schema(schema).unwrap();
            let native = DataFusionSessionContext::new();
            native
                .register_table(
                    "orders",
                    Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]]).unwrap()),
                )
                .unwrap();
            Self {
                context,
                native,
                rows,
                table,
                prefix,
                server,
            }
        }

        /// Checks result parity and namespace isolation, then returns the observed reads.
        async fn check(&self, sql: &str) -> Vec<Request> {
            let expected = values(&self.native, sql).await.unwrap();
            self.rows.requests.lock().unwrap().clear();
            self.rows.returned_rows.store(0, Ordering::SeqCst);
            self.rows.returned_bytes.store(0, Ordering::SeqCst);
            let actual = values(self.context.datafusion(), sql).await.unwrap();
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

    async fn values(
        ctx: &DataFusionSessionContext,
        sql: &str,
    ) -> DataFusionResult<Vec<Vec<ScalarValue>>> {
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
    async fn limit_counts_only_rows_with_valid_projected_values() {
        // Both tables start with one valid row, and each limited query must return it.
        let fixture = Fixture::new(
            vec![
                column("id", DataType::Int64, false),
                column("tag", DataType::Int64, false),
                column("amount", DataType::Int64, false),
            ],
            &["id"],
            vec![index("tag", &["tag"], &[])],
            vec![
                Arc::new(Int64Array::from(vec![2])),
                Arc::new(Int64Array::from(vec![7])),
                Arc::new(Int64Array::from(vec![42])),
            ],
        )
        .await;

        // This row decodes successfully, but its nonnullable projection is invalid.
        // It precedes the valid row in both the primary and secondary key order.
        let invalid = RecordBatch::try_new(
            fixture.table.model.schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![0])),
                Arc::new(Int64Array::from(vec![7])),
                Arc::new(Int64Array::from(vec![999])),
            ],
        )
        .unwrap();
        let entries = crate::writer::encode_insert_entries(
            &invalid,
            &fixture.table.model,
            &fixture.table.index_specs,
        )
        .unwrap();
        fixture
            .rows
            .values
            .lock()
            .unwrap()
            .extend(entries.into_iter().map(|(key, value)| {
                let value = if fixture.table.model.primary_key_prefix.matches(&key) {
                    StoredRow {
                        values: vec![None, Some(StoredValue::Int64(7)), None],
                    }
                    .encode()
                } else {
                    value
                };
                (fixture.prefix.encode_key(&key).unwrap(), value)
            }));

        // Range retries, residual filtering, point reads, and index lookups all
        // count accepted output rows rather than decoded or fetched entries.
        for sql in [
            "SELECT amount FROM orders LIMIT 1",
            "SELECT amount FROM orders WHERE id % 2 = 0 LIMIT 1",
            "SELECT amount FROM orders WHERE id IN (0, 2) LIMIT 1",
            "SELECT amount FROM orders WHERE tag = 7 LIMIT 1",
        ] {
            let requests = fixture.check(sql).await;
            assert!(
                fixture.rows.returned_rows.load(Ordering::SeqCst) >= 2,
                "{sql}"
            );
            if sql.contains("IN") {
                assert!(requests.iter().all(|r| matches!(r, Request::GetMany(_))));
            } else if sql.contains("tag") {
                assert!(requests.iter().any(|r| matches!(r, Request::GetMany(_))));
                assert!(requests.iter().any(|r| matches!(
                    r, Request::Range { start, .. } if fixture.index_matches(0, start)
                )));
            } else {
                assert!(requests.iter().all(|r| matches!(r, Request::Range { .. })));
            }
        }
    }

    #[tokio::test]
    async fn limit_spans_output_batches_without_resetting_the_budget() {
        // One row past a full flush makes the limit span two output batches. Rows beyond
        // the limit would surface a budget that resets after the first flush.
        let limit = super::BATCH_FLUSH_ROWS + 1;
        let count = limit + 5;
        let fixture = Fixture::new(
            vec![
                column("id", DataType::Int64, false),
                column("tag", DataType::Int64, false),
                column("amount", DataType::Int64, false),
            ],
            &["id"],
            vec![index("tag", &["tag"], &[])],
            vec![
                Arc::new(Int64Array::from_iter_values(0..count as i64)),
                Arc::new(Int64Array::from(vec![7; count])),
                Arc::new(Int64Array::from_iter_values(0..count as i64)),
            ],
        )
        .await;

        // Range scans, point reads, and index lookups must each stop at the limit.
        let points = (0..count as i64).map(lit).collect();
        for filters in [
            vec![],
            vec![in_list(col("id"), points, false)],
            vec![col("tag").eq(lit(7i64))],
        ] {
            // Execute the scan node itself so the test sees the batches it emits.
            let scan = KvScanExec::try_new(
                &fixture.table,
                &fixture.context.datafusion().state(),
                Some(&vec![2]),
                &filters,
                Some(limit),
            )
            .unwrap();
            let batches = scan
                .execute(0, fixture.context.datafusion().task_ctx())
                .unwrap()
                .try_collect::<Vec<_>>()
                .await
                .unwrap();

            // The first batch must be full and the second must hold only the last row
            // the limit allows, with the first `limit` amounts in key order.
            assert_eq!(
                batches
                    .iter()
                    .map(RecordBatch::num_rows)
                    .collect::<Vec<_>>(),
                [super::BATCH_FLUSH_ROWS, 1]
            );
            let amounts = batches.iter().flat_map(|batch| {
                batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .unwrap()
                    .values()
                    .iter()
                    .copied()
            });
            assert!(amounts.eq(0..limit as i64));
        }
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
            &[&crate::types::CellValue::FixedSizeBinary(invalid_pk)],
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
                    .context
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

    /// Cached column requirements and index ranges agree with the optimized scan inputs.
    #[tokio::test]
    async fn optimized_scan_keeps_the_plan_its_inputs_give() {
        // Both indexes cover amount, while payload requires a base-row lookup.
        let fixture = Fixture::new(
            vec![
                column("id", DataType::Int64, false),
                column("status", DataType::Utf8, false),
                column("amount", DataType::Int64, false),
                column("payload", DataType::Utf8, false),
            ],
            &["id"],
            vec![
                index("status_idx", &["status"], &["amount"]),
                index("status_amount_idx", &["status", "amount"], &[]),
            ],
            vec![
                Arc::new(Int64Array::from((0..8).collect::<Vec<i64>>())),
                Arc::new(StringArray::from(vec![
                    "a", "b", "c", "a", "b", "c", "a", "b",
                ])),
                Arc::new(Int64Array::from(vec![5, 3, 8, 1, 9, 2, 7, 4])),
                Arc::new(StringArray::from(
                    (0..8).map(|i| format!("p{i}")).collect::<Vec<_>>(),
                )),
            ],
        )
        .await;

        // Exercise both key paths with residual filters, ordering, and limits.
        for (sql, uses_index, filtered) in [
            ("SELECT * FROM orders", false, false),
            (
                "SELECT id, amount FROM orders WHERE status IN ('a', 'b') AND amount > 2 ORDER BY id",
                true,
                true,
            ),
            (
                "SELECT payload FROM orders WHERE status IN ('a', 'c') AND amount % 2 = 1 ORDER BY id",
                true,
                true,
            ),
            (
                "SELECT id, amount FROM orders WHERE status = 'a' AND payload <> 'p0' ORDER BY id",
                true,
                true,
            ),
            (
                "SELECT id, amount FROM orders WHERE status = 'a' ORDER BY amount DESC LIMIT 2",
                true,
                true,
            ),
            ("SELECT payload FROM orders WHERE id >= 2 AND id < 6", false, false),
            (
                "SELECT payload FROM orders WHERE id >= 2 AND payload <> 'p3' ORDER BY id LIMIT 3",
                false,
                true,
            ),
        ] {
            // Each query must match the reference results and plan the expected key path
            // and row filter.
            fixture.check(sql).await;
            let mut plan = fixture
                .context
                .datafusion()
                .sql(sql)
                .await
                .unwrap()
                .create_physical_plan()
                .await
                .unwrap();
            while let Some(child) = plan.children().first() {
                plan = (*child).clone();
            }
            let scan = plan
                .downcast_ref::<KvScanExec>()
                .expect("optimized plan must end in a KV scan");
            assert_eq!(scan.plan.index.is_some(), uses_index, "{sql}");
            assert_eq!(scan.filter.is_some(), filtered, "{sql}");

            // Required columns and index ranges must agree with the optimized scan
            // schema and residual filter.
            let projection = plan
                .schema()
                .fields()
                .iter()
                .map(|field| scan.model.columns_by_name[field.name()])
                .collect();
            let mut access = ScanAccessPlan::new(&scan.model, &Some(projection), &scan.predicate);
            if let Some(filter) = &scan.filter {
                for (required, filter_required) in access
                    .required_pk_mask
                    .iter_mut()
                    .zip(&filter.access.required_pk_mask)
                {
                    *required |= filter_required;
                }
                for (required, filter_required) in access
                    .required_non_pk_columns
                    .iter_mut()
                    .zip(&filter.access.required_non_pk_columns)
                {
                    *required |= filter_required;
                }
            }
            assert_eq!(
                access.required_pk_mask, scan.plan.access.required_pk_mask,
                "{sql}"
            );
            assert_eq!(
                access.required_non_pk_columns, scan.plan.access.required_non_pk_columns,
                "{sql}"
            );
            let fresh = scan
                .predicate
                .choose_index_plan(&scan.model, &scan.index_specs, &access);
            assert_eq!(
                scan.plan
                    .index
                    .as_ref()
                    .map(|plan| (plan.spec_idx, plan.ranges.clone())),
                fresh.map(|plan| (plan.spec_idx, plan.ranges)),
                "{sql}"
            );
        }
    }

    /// A primary-key prefix constraint keeps the qualifying index plan and is enforced by its key.
    #[tokio::test]
    async fn primary_key_prefix_keeps_qualifying_index_plan() {
        // Fixing tenant leaves order_id unconstrained, so the index remains eligible. Within
        // each tenant, the index orders by created and the primary key orders by order_id.
        let fixture = Fixture::new(
            vec![
                column("tenant", DataType::Int64, false),
                column("order_id", DataType::Int64, false),
                column("created", DataType::Int64, false),
                column("payload", DataType::Int64, false),
            ],
            &["tenant", "order_id"],
            vec![index("tenant_created", &["tenant", "created"], &[])],
            vec![
                Arc::new(Int64Array::from(vec![5, 5, 5, 5, 6, 6])),
                Arc::new(Int64Array::from(vec![1, 2, 3, 4, 1, 2])),
                Arc::new(Int64Array::from(vec![40, 10, 30, 20, 50, 60])),
                Arc::new(Int64Array::from(vec![100, 200, 300, 400, 500, 600])),
            ],
        )
        .await;

        // The covering index supplies both projected columns in the requested order, and
        // its leading key column enforces the tenant constraint. Results must match
        // DataFusion with exactly one reverse index range read limited to the two rows.
        let sql =
            "SELECT order_id, created FROM orders WHERE tenant = 5 ORDER BY created DESC LIMIT 2";
        let requests = fixture.check(sql).await;
        assert!(
            matches!(requests.as_slice(), [Request::Range { start, forward: false, limit: 2, .. }] if fixture.index_matches(0, start)),
            "the query must use exactly one reverse index range read of two rows, got {requests:?}"
        );
        assert_eq!(fixture.rows.returned_rows.load(Ordering::SeqCst), 2);

        // The leaf scan must keep the index plan with the reversed direction and the limit.
        let mut plan = fixture
            .context
            .datafusion()
            .sql(sql)
            .await
            .unwrap()
            .create_physical_plan()
            .await
            .unwrap();
        while let Some(child) = plan.children().first() {
            plan = (*child).clone();
        }
        let scan = plan.downcast_ref::<KvScanExec>().unwrap();
        assert_eq!(scan.plan.index.as_ref().map(|plan| plan.spec_idx), Some(0));
        assert_eq!(scan.direction, Some(RangeMode::Reverse));
        assert_eq!(scan.fetch, Some(2));
    }

    /// Index ranges share one budget for accepted rows.
    #[tokio::test]
    async fn limit_spans_distinct_index_ranges() {
        // Varying the cover columns exercises both covering scans and base row lookups.
        for covering in [false, true] {
            // Two rows per tag let the query cross a range boundary before reaching the limit.
            let cover: &[&str] = if covering { &["amount"] } else { &[] };
            let fixture = Fixture::new(
                vec![
                    column("id", DataType::Int64, false),
                    column("tag", DataType::Int64, false),
                    column("amount", DataType::Int64, false),
                ],
                &["id"],
                vec![index("tag", &["tag"], cover)],
                vec![
                    Arc::new(Int64Array::from(vec![0, 1, 2, 3])),
                    Arc::new(Int64Array::from(vec![7, 7, 9, 9])),
                    Arc::new(Int64Array::from(vec![10, 20, 30, 40])),
                ],
            )
            .await;

            // The IN list must yield two index ranges with the configured coverage.
            let scan = KvScanExec::try_new(
                &fixture.table,
                &fixture.context.datafusion().state(),
                Some(&vec![2]),
                &[in_list(col("tag"), vec![lit(7i64), lit(9i64)], false)],
                Some(3),
            )
            .unwrap();
            let plan = scan.plan.index.as_ref().unwrap();
            assert_eq!(plan.ranges.len(), 2);
            assert_eq!(
                scan.plan
                    .access
                    .index_covers_required_non_pk(&scan.index_specs[plan.spec_idx]),
                covering,
            );

            // The scan itself must emit exactly three amounts. The second range must contribute
            // only its first row.
            let batches = scan
                .execute(0, fixture.context.datafusion().task_ctx())
                .unwrap()
                .try_collect::<Vec<_>>()
                .await
                .unwrap();
            let amounts = batches.iter().flat_map(|batch| {
                batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .unwrap()
                    .values()
                    .iter()
                    .copied()
            });
            assert!(amounts.eq([10, 20, 30]));
        }
    }

    /// Sort and limit pushdown share the cached plan.
    #[test]
    fn sort_and_fetch_clones_share_cached_plan() {
        // The tag index covers amount so the scan can use its key order.
        let schema = KvSchema::new(StoreClient::new("http://127.0.0.1:1").unprefixed())
            .table(
                "orders",
                vec![
                    column("id", DataType::Int64, false),
                    column("tag", DataType::Int64, false),
                    column("amount", DataType::Int64, false),
                ],
                vec!["id".into()],
                vec![index("tag", &["tag"], &["amount"])],
            )
            .unwrap();

        // Fixing tag leaves the id suffix ordered. The projection puts id at output position 2.
        let state = DataFusionSessionContext::new().state();
        let scan = KvScanExec::try_new(
            &schema.tables()[0].1,
            &state,
            Some(&vec![2, 1, 0]),
            &[col("tag").eq(lit(7i64))],
            None,
        )
        .unwrap();

        // A descending id sort must push down exactly and clone the scan. Applying a limit
        // creates another clone.
        let SortOrderPushdownResult::Exact { inner: sorted } = scan
            .try_pushdown_sort(&[PhysicalSortExpr {
                expr: Arc::new(Column::new("id", 2)),
                options: SortOptions {
                    descending: true,
                    ..Default::default()
                },
            }])
            .unwrap()
        else {
            panic!("a fixed tag must leave the primary-key suffix ordered");
        };
        let limited = sorted.with_fetch(Some(2)).unwrap();

        // Both clones must share the original plan.
        for clone in [sorted, limited] {
            let clone = clone.downcast_ref::<KvScanExec>().unwrap();
            assert!(Arc::ptr_eq(&scan.plan, &clone.plan));
        }
    }
}
