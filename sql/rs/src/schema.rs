use crate::{codec::*, scan::*, types::*, writer::*, SqlContext};
use async_trait::async_trait;
use datafusion::{
    arrow::datatypes::SchemaRef,
    catalog::Session,
    common::{tree_node::TreeNode, DataFusionError, Result as DataFusionResult, SchemaExt},
    datasource::{sink::DataSinkExec, TableProvider},
    logical_expr::{dml::InsertOp, Expr, TableProviderFilterPushDown, TableType},
    physical_plan::ExecutionPlan,
};
use exoware_sdk::{kv_codec::decode_stored_row, PrefixedStoreClient};
use std::sync::Arc;

/// Named tables sharing one storage namespace. Table insertion order assigns family
/// identifiers in persisted keys and must remain stable when reopening data.
pub struct KvSchema {
    /// Namespace-scoped Store client shared by every table built through this schema.
    store: PrefixedStoreClient,
    /// Unique table names and shared providers in table-prefix order, with at most
    /// `MAX_TABLES` entries.
    tables: Vec<(String, Arc<KvTable>)>,
}

impl KvSchema {
    /// Build a schema over `store`'s namespace prefix. When the Store is
    /// co-tenanted, the caller must pick a prefix disjoint from every co-tenant
    /// so SQL's prefix-bounded scans can't observe another's keys.
    pub const fn new(store: PrefixedStoreClient) -> Self {
        Self {
            store,
            tables: Vec::new(),
        }
    }

    pub fn table(
        mut self,
        name: impl Into<String>,
        columns: Vec<TableColumnConfig>,
        primary_key_columns: Vec<String>,
        index_specs: Vec<IndexSpec>,
    ) -> DataFusionResult<Self> {
        let name = name.into();
        if self.tables.iter().any(|(existing, _)| existing == &name) {
            return Err(DataFusionError::Plan(format!(
                "duplicate table name '{name}'"
            )));
        }
        if self.tables.len() >= MAX_TABLES {
            return Err(DataFusionError::Plan(format!(
                "too many tables for key layout (max {MAX_TABLES})"
            )));
        }
        // Tables are only ever appended, so the next free prefix is the count.
        let prefix = self.tables.len() as u8;
        let config = KvTableConfig::new(prefix, columns, primary_key_columns, index_specs)
            .map_err(DataFusionError::Plan)?;
        let table =
            Arc::new(KvTable::new(self.store.clone(), config).map_err(DataFusionError::Plan)?);
        self.tables.push((name, table));
        Ok(self)
    }

    /// Create a table with a versioned composite primary key.
    ///
    /// The entity column and version column together form the composite
    /// primary key. The version column must be `UInt64` and distinct from the
    /// entity column. The entity can be any supported primary-key type,
    /// including variable-length logical keys encoded through the crate's
    /// ordered variable-length `Utf8` mapping.
    ///
    /// Versions sort numerically via big-endian encoding, so a reverse range
    /// scan from `(entity, V)` downward with LIMIT 1 yields the latest version
    /// <= V. See `examples/versioned_kv.rs` for the query pattern.
    pub fn versioned_table(
        self,
        name: impl Into<String>,
        columns: Vec<TableColumnConfig>,
        entity_column: impl Into<String>,
        version_column: impl Into<String>,
        index_specs: Vec<IndexSpec>,
    ) -> DataFusionResult<Self> {
        let name = name.into();
        let schema = self.table(
            name.clone(),
            columns,
            vec![entity_column.into(), version_column.into()],
            index_specs,
        )?;
        let (_, table) = schema.tables.last().expect("table was just added");
        table.model.versioned_entity_kind(&name)?;
        Ok(schema)
    }

    pub const fn table_count(&self) -> usize {
        self.tables.len()
    }

    pub(crate) const fn store(&self) -> &PrefixedStoreClient {
        &self.store
    }

    pub(crate) fn tables(&self) -> &[(String, Arc<KvTable>)] {
        &self.tables
    }

    /// Registers the tables in a SQL context.
    pub(crate) fn register_all(self, ctx: &SqlContext) -> DataFusionResult<()> {
        for (name, table) in self.tables {
            ctx.register_table(name, table)?;
        }
        Ok(())
    }

    pub fn batch_writer(&self) -> BatchWriter {
        BatchWriter::new(self.store.clone(), &self.tables)
    }

    /// Backfill secondary index entries after adding new index specs.
    ///
    /// `previous_index_specs` must represent the index list used when existing
    /// rows were written. The current schema's index list must be an append-only
    /// extension of that list (same order/layout for existing indexes, with new
    /// indexes only added at the tail).
    ///
    /// Disable base-row retention policies before adding indexes. Store
    /// pruning does not remove the corresponding secondary index entries.
    ///
    /// Operational ordering requirement: start writing new rows with the new
    /// index specs before backfilling historical rows, or rows written during
    /// the backfill window may be missing from the new index.
    ///
    /// Invalid arguments fail with `DataFusionError::Plan`, and Store and scan
    /// failures with `External` or `Execution`.
    pub async fn backfill_added_indexes(
        &self,
        table_name: &str,
        previous_index_specs: &[IndexSpec],
    ) -> DataFusionResult<IndexBackfillReport> {
        self.backfill_added_indexes_with_options(
            table_name,
            previous_index_specs,
            IndexBackfillOptions::default(),
        )
        .await
    }

    /// Backfill secondary index entries after adding new index specs, with
    /// configurable response batch size for the streaming scan.
    pub async fn backfill_added_indexes_with_options(
        &self,
        table_name: &str,
        previous_index_specs: &[IndexSpec],
        options: IndexBackfillOptions,
    ) -> DataFusionResult<IndexBackfillReport> {
        self.backfill_added_indexes_inner(table_name, previous_index_specs, options, None)
            .await
    }

    /// Backfill secondary index entries after adding new index specs, with
    /// configurable response batch size for the streaming scan, reporting
    /// progress events on `progress_tx`.
    ///
    /// Progress events are emitted only after buffered ingest writes for the
    /// reported cursor are flushed, so `Progress.next_cursor` can be persisted
    /// and used to resume later.
    pub async fn backfill_added_indexes_with_options_and_progress(
        &self,
        table_name: &str,
        previous_index_specs: &[IndexSpec],
        options: IndexBackfillOptions,
        progress_tx: &tokio::sync::mpsc::UnboundedSender<IndexBackfillEvent>,
    ) -> DataFusionResult<IndexBackfillReport> {
        self.backfill_added_indexes_inner(
            table_name,
            previous_index_specs,
            options,
            Some(progress_tx),
        )
        .await
    }

    async fn backfill_added_indexes_inner(
        &self,
        table_name: &str,
        previous_index_specs: &[IndexSpec],
        options: IndexBackfillOptions,
        progress_tx: Option<&tokio::sync::mpsc::UnboundedSender<IndexBackfillEvent>>,
    ) -> DataFusionResult<IndexBackfillReport> {
        if options.row_batch_size == 0 {
            return Err(DataFusionError::Plan(
                "index backfill row_batch_size must be > 0".to_string(),
            ));
        }

        let table = self
            .tables
            .iter()
            .find(|(name, _)| name == table_name)
            .map(|(_, table)| table)
            .ok_or_else(|| {
                DataFusionError::Plan(format!("unknown table '{table_name}' for index backfill"))
            })?;

        let model = &table.model;
        let current_specs = &table.index_specs;
        let previous_specs = model
            .resolve_index_specs(previous_index_specs)
            .map_err(|e| DataFusionError::Plan(format!("invalid previous index specs: {e}")))?;

        if previous_specs.len() > current_specs.len() {
            return Err(DataFusionError::Plan(format!(
                "table '{table_name}' previous index count ({}) exceeds current index count ({})",
                previous_specs.len(),
                current_specs.len()
            )));
        }
        for (idx, previous) in previous_specs.iter().enumerate() {
            let current = &current_specs[idx];
            if previous != current {
                return Err(DataFusionError::Plan(format!(
                    "table '{table_name}' index evolution must be append-only; index at position {} changed",
                    idx + 1
                )));
            }
        }

        let full_range = primary_key_prefix_range(model.table_prefix);
        let cursor = options
            .start_cursor
            .unwrap_or_else(|| full_range.start.clone());
        if !model.primary_key_prefix.matches(&cursor) {
            return Err(DataFusionError::Plan(
                "index backfill start_cursor must use this table's primary-key prefix".to_string(),
            ));
        }
        if cursor < full_range.start || cursor > full_range.end {
            return Err(DataFusionError::Plan(
                "index backfill start_cursor is outside table key range".to_string(),
            ));
        }

        let new_specs = &current_specs[previous_specs.len()..];
        send_backfill_event(
            progress_tx,
            IndexBackfillEvent::Started {
                table_name: table_name.to_string(),
                indexes_backfilled: new_specs.len(),
                row_batch_size: options.row_batch_size,
                start_cursor: cursor.clone(),
            },
        );
        if new_specs.is_empty() {
            let report = IndexBackfillReport::default();
            send_backfill_event(progress_tx, IndexBackfillEvent::Completed { report });
            return Ok(report);
        }

        let mut report = IndexBackfillReport {
            scanned_rows: 0,
            indexes_backfilled: new_specs.len(),
            index_entries_written: 0,
        };
        let mut pending_entries = Vec::new();
        let session = self.store.create_session();
        let decode_pk_mask = vec![true; model.primary_key_kinds.len()];

        let mut stream = session
            .range_stream(&cursor, &full_range.end, usize::MAX, options.row_batch_size)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
        while let Some(chunk) = stream
            .next_chunk()
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?
        {
            let Some((last_key, _)) = chunk.rows.last() else {
                continue;
            };
            for (base_key, base_value) in &chunk.rows {
                let Some(pk_values) = decode_primary_key_selected(
                    model.table_prefix,
                    base_key,
                    model,
                    &decode_pk_mask,
                ) else {
                    return Err(DataFusionError::Execution(format!(
                        "invalid primary key while backfilling index (key={})",
                        hex::encode(base_key)
                    )));
                };
                let archived = decode_stored_row(base_value).map_err(|e| {
                    DataFusionError::Execution(format!(
                        "invalid base row payload while backfilling index (key={}): {e}",
                        hex::encode(base_key)
                    ))
                })?;
                if archived.values.len() != model.columns.len() {
                    return Err(DataFusionError::Execution(format!(
                        "invalid base row payload while backfilling index (key={})",
                        hex::encode(base_key)
                    )));
                }
                report.scanned_rows += 1;

                for spec in new_specs {
                    let index_key = encode_secondary_index_key_from_parts(
                        model.table_prefix,
                        spec,
                        model,
                        &pk_values,
                        &archived,
                    )?;
                    let index_value =
                        encode_secondary_index_value_from_archived(&archived, model, spec)?;
                    pending_entries.push((index_key, index_value));
                    report.index_entries_written += 1;
                }

                if pending_entries.len() >= INDEX_BACKFILL_FLUSH_ENTRIES {
                    flush_ingest_batch(&self.store, &mut pending_entries).await?;
                }
            }
            let next_cursor = self
                .store
                .key_prefix()
                .next_key(last_key)
                .map_err(|e| DataFusionError::External(Box::new(e)))?
                .filter(|key| key <= &full_range.end);
            flush_ingest_batch(&self.store, &mut pending_entries).await?;
            send_backfill_event(
                progress_tx,
                IndexBackfillEvent::Progress {
                    scanned_rows: report.scanned_rows,
                    index_entries_written: report.index_entries_written,
                    last_scanned_primary_key: last_key.clone(),
                    next_cursor: next_cursor.clone(),
                },
            );

            if next_cursor.is_none() {
                break;
            }
        }

        send_backfill_event(progress_tx, IndexBackfillEvent::Completed { report });
        Ok(report)
    }
}

pub(crate) fn send_backfill_event(
    progress_tx: Option<&tokio::sync::mpsc::UnboundedSender<IndexBackfillEvent>>,
    event: IndexBackfillEvent,
) {
    if let Some(tx) = progress_tx {
        let _ = tx.send(event);
    }
}

#[async_trait]
impl TableProvider for KvTable {
    fn schema(&self) -> SchemaRef {
        self.model.schema.clone()
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> DataFusionResult<Vec<TableProviderFilterPushDown>> {
        filters
            .iter()
            .map(|expr| {
                let relational = expr.exists(|node| {
                    Ok(matches!(
                        node,
                        Expr::ScalarSubquery(_)
                            | Expr::InSubquery(_)
                            | Expr::Exists(_)
                            | Expr::SetComparison(_)
                            | Expr::OuterReferenceColumn(..)
                            | Expr::Unnest(_)
                    ))
                })?;
                Ok(if relational || expr.is_volatile() {
                    TableProviderFilterPushDown::Unsupported
                } else {
                    TableProviderFilterPushDown::Exact
                })
            })
            .collect()
    }

    async fn scan(
        &self,
        state: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        Ok(Arc::new(KvScanExec::try_new(
            self, state, projection, filters, limit,
        )?))
    }

    async fn insert_into(
        &self,
        _state: &dyn Session,
        input: Arc<dyn ExecutionPlan>,
        insert_op: InsertOp,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        self.schema()
            .logically_equivalent_names_and_types(&input.schema())?;
        if insert_op != InsertOp::Append {
            return Err(DataFusionError::NotImplemented(format!(
                "{insert_op} not implemented for kv table"
            )));
        }

        let sink = KvIngestSink {
            table: self.clone(),
        };
        Ok(Arc::new(DataSinkExec::new(input, Arc::new(sink), None)))
    }
}
