use std::any::Any;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::common::{DataFusionError, Result as DataFusionResult};
use datafusion::execution::context::TaskContext;
use datafusion::physical_expr::{EquivalenceProperties, Partitioning};
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::{
    stream::RecordBatchStreamAdapter, DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties,
    SendableRecordBatchStream,
};
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::kv_codec::decode_stored_row;
use exoware_sdk_rs::SerializableReadSession;
use exoware_sdk_rs::StoreClient;
use futures::SinkExt;

use crate::builder::*;
use crate::codec::*;
use crate::diagnostics::*;
use crate::filter::*;
use crate::predicate::*;
use crate::types::*;

#[derive(Debug)]
pub(crate) struct KvScanExec {
    pub(crate) client: StoreClient,
    pub(crate) model: Arc<TableModel>,
    pub(crate) index_specs: Arc<Vec<ResolvedIndexSpec>>,
    pub(crate) predicate: QueryPredicate,
    pub(crate) limit: Option<usize>,
    pub(crate) projected_schema: SchemaRef,
    pub(crate) projection: Option<Vec<usize>>,
    pub(crate) properties: PlanProperties,
}

impl KvScanExec {
    pub(crate) fn new(
        client: StoreClient,
        model: Arc<TableModel>,
        index_specs: Arc<Vec<ResolvedIndexSpec>>,
        predicate: QueryPredicate,
        limit: Option<usize>,
        projected_schema: SchemaRef,
        projection: Option<Vec<usize>>,
    ) -> Self {
        let properties = PlanProperties::new(
            EquivalenceProperties::new(projected_schema.clone()),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Bounded,
        );
        Self {
            client,
            model,
            index_specs,
            predicate,
            limit,
            projected_schema,
            projection,
            properties,
        }
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
                "KvScanExec: limit={:?}, {}, query_stats={}",
                self.limit,
                format_access_path_diagnostics(&diag),
                format_query_stats_explain(QueryStatsExplainSurface::StreamedRangeTrailer)
            ),
            Err(err) => write!(
                f,
                "KvScanExec: limit={:?}, diagnostics_error={err}",
                self.limit
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
            if let Err(e) = stream_kv_scan(&mut tx, &ctx, &index_specs, limit).await {
                let _ = tx.send(Err(e)).await;
            }
        });

        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.projected_schema.clone(),
            rx,
        )))
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
    stream_pk_scan(tx, ctx, flush_threshold, target_rows, exact).await
}

pub(crate) async fn stream_pk_scan(
    tx: &mut futures::channel::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'_>,
    flush_threshold: usize,
    target_rows: usize,
    exact: bool,
) -> DataFusionResult<()> {
    let ranges = ctx.predicate.primary_key_ranges(ctx.model)?;
    let mut emitted = 0usize;
    let mut batch_builder = ProjectedBatchBuilder::from_access_plan(ctx.model, ctx.access_plan);

    for range in &ranges {
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

        let mut stream = ctx
            .session
            .range_stream(&range.start, &range.end, raw_limit, flush_threshold)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
        while let Some(chunk) = stream
            .next_chunk()
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?
        {
            for (key, value) in &chunk {
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
        let mut stream = ctx
            .session
            .range_stream(&range.start, &range.end, usize::MAX, flush_threshold)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
        while let Some(chunk) = stream
            .next_chunk()
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?
        {
            let mut pk_batch: Vec<Key> = Vec::new();
            for (key, _index_value) in &chunk {
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
                while let Some(entries) = get_stream
                    .next_chunk()
                    .await
                    .map_err(|e| DataFusionError::External(Box::new(e)))?
                {
                    for (pk_key, base_value) in entries {
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
        let mut stream = ctx
            .session
            .range_stream(&range.start, &range.end, usize::MAX, flush_threshold)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
        while let Some(chunk) = stream
            .next_chunk()
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?
        {
            for (key, index_value) in &chunk {
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
