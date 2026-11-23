use crate::{codec::*, scan::*, types::*, writer::*, SqlContext};
use async_trait::async_trait;
use datafusion::{
    arrow::datatypes::SchemaRef,
    catalog::Session,
    common::{
        tree_node::TreeNode, DataFusionError, Result as DataFusionResult, SchemaExt, TableReference,
    },
    datasource::{sink::DataSinkExec, TableProvider},
    logical_expr::{dml::InsertOp, Expr, TableProviderFilterPushDown, TableType},
    physical_expr::{
        expressions::{cast, Column},
        PhysicalExpr,
    },
    physical_plan::{projection::ProjectionExec, ExecutionPlan},
};
use exoware_sdk::{kv_codec::decode_stored_row, PrefixedStoreClient, StoreWriteBatch};
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

    /// Adds a table. `name` is the table's exact, case-sensitive name in SQL, in the `Tables`
    /// and `Subscribe` RPCs, and in this crate's APIs. It has 1 to 255 characters, the range a
    /// `Subscribe` request carries.
    ///
    /// In SQL, a double-quoted identifier always names the table. The quotes are optional for
    /// a lower-case identifier, because SQL folds unquoted identifiers to lower case.
    ///
    /// DataFusion parses a table name passed as a string the same way, for example in
    /// [`SqlContext::table`] and `DataFrame::write_table`. Double-quote the name there too, or
    /// pass `TableReference::bare(name)` where a reference is accepted.
    pub fn table(
        mut self,
        name: impl Into<String>,
        columns: Vec<TableColumnConfig>,
        primary_key_columns: Vec<String>,
        index_specs: Vec<IndexSpec>,
    ) -> DataFusionResult<Self> {
        let name = name.into();
        if !(1..=MAX_TABLE_NAME_LEN).contains(&name.chars().count()) {
            return Err(DataFusionError::Plan(format!(
                "table name must have 1 to {MAX_TABLE_NAME_LEN} characters"
            )));
        }
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
        // A declared name is the table's exact name, so each table is registered under a bare
        // reference. DataFusion parses a plain string as SQL, folding its case and splitting it on
        // dots.
        for (name, table) in self.tables {
            ctx.register_table(TableReference::bare(name), table)?;
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
    /// and used to resume later. The entries of one response batch are sent in
    /// as many Store writes as the limits of one write require, and its event
    /// follows the last of them. A backfill that stops between two of those
    /// writes resumes from the cursor before that batch and writes its entries
    /// again, which leaves the same index entries.
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
        let mut staged = StoreWriteBatch::new();
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
                    stage_ingest_entry(&self.store, &mut staged, &index_key, index_value).await?;
                    report.index_entries_written += 1;
                }

                if staged.len() >= INDEX_BACKFILL_FLUSH_ENTRIES {
                    flush_ingest_batch(&self.store, &mut staged).await?;
                }
            }
            let next_cursor = self
                .store
                .key_prefix()
                .next_key(last_key)
                .map_err(|e| DataFusionError::External(Box::new(e)))?
                .filter(|key| key <= &full_range.end);
            flush_ingest_batch(&self.store, &mut staged).await?;
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
                // The scan evaluates filters synchronously on its own batches. Subqueries, outer
                // references, unnest, and async functions need DataFusion operators, so filters
                // using them stay above the scan.
                let unsupported = expr.exists(|node| {
                    Ok(match node {
                        Expr::ScalarSubquery(_)
                        | Expr::InSubquery(_)
                        | Expr::Exists(_)
                        | Expr::SetComparison(_)
                        | Expr::OuterReferenceColumn(..)
                        | Expr::Unnest(_) => true,
                        Expr::ScalarFunction(function) => function.func.as_async().is_some(),
                        _ => false,
                    })
                })?;
                Ok(if unsupported || expr.is_volatile() {
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
        let schema = self.schema();
        let input_schema = input.schema();
        schema.logically_equivalent_names_and_types(&input_schema)?;
        if insert_op != InsertOp::Append {
            return Err(DataFusionError::NotImplemented(format!(
                "{insert_op} not implemented for kv table"
            )));
        }

        // DataFusion accepts any input column castable to the table type, but only SQL
        // INSERT plans the cast. Cast here with the same semantics so the sink always
        // receives the table's types.
        let input = if schema
            .fields()
            .iter()
            .zip(input_schema.fields())
            .all(|(table, input)| table.data_type() == input.data_type())
        {
            input
        } else {
            let exprs = schema
                .fields()
                .iter()
                .enumerate()
                .map(|(idx, field)| {
                    let column: Arc<dyn PhysicalExpr> = Arc::new(Column::new(field.name(), idx));
                    let expr = cast(column, &input_schema, field.data_type().clone())?;
                    Ok((expr, field.name().clone()))
                })
                .collect::<DataFusionResult<Vec<_>>>()?;
            Arc::new(ProjectionExec::try_new(exprs, input)?)
        };

        let sink = KvIngestSink {
            table: self.clone(),
        };
        Ok(Arc::new(DataSinkExec::new(input, Arc::new(sink), None)))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        CellValue, IndexBackfillEvent, IndexBackfillOptions, IndexSpec, KvSchema, SqlContext,
        TableColumnConfig,
    };
    use async_trait::async_trait;
    use datafusion::{
        arrow::{
            array::{
                ArrayRef, Decimal128Array, DictionaryArray, Int32Array, Int64Array, NullArray,
                TimestampMicrosecondArray,
            },
            datatypes::{DataType, Field, Int32Type, Schema, TimeUnit},
            record_batch::RecordBatch,
            util::pretty::pretty_format_batches,
        },
        common::{internal_err, DataFusionError, Result as DataFusionResult},
        dataframe::DataFrameWriteOptions,
        logical_expr::{
            async_udf::{AsyncScalarUDF, AsyncScalarUDFImpl},
            ColumnarValue, ScalarFunctionArgs, ScalarUDFImpl, Signature, Volatility,
        },
    };
    use exoware_sdk::PrefixedStoreClient;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    async fn write_batch(
        ctx: &SqlContext,
        table: &str,
        batch: RecordBatch,
    ) -> DataFusionResult<()> {
        ctx.datafusion()
            .read_batch(batch)?
            .write_table(table, DataFrameWriteOptions::new())
            .await
            .map(|_| ())
    }

    async fn query(ctx: &SqlContext, sql: &str) -> Vec<String> {
        let batches = ctx.sql(sql).await.unwrap().collect().await.unwrap();
        pretty_format_batches(&batches)
            .unwrap()
            .to_string()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn batch(columns: Vec<(&str, ArrayRef)>) -> RecordBatch {
        let fields = columns
            .iter()
            .map(|(name, array)| Field::new(*name, array.data_type().clone(), true))
            .collect::<Vec<_>>();
        RecordBatch::try_new(
            Arc::new(Schema::new(fields)),
            columns.into_iter().map(|(_, array)| array).collect(),
        )
        .unwrap()
    }

    /// Forwards every request to the Store except one Put, counted from zero among the Puts it
    /// is given, which fails before the Store receives it.
    #[derive(Clone)]
    struct InterruptedStore {
        store: exoware_sdk::proto::PreferZstdHttpClient,
        puts: Arc<AtomicUsize>,
        failed_put: usize,
    }

    impl connectrpc::client::ClientTransport for InterruptedStore {
        type ResponseBody =
            <exoware_sdk::proto::PreferZstdHttpClient as connectrpc::client::ClientTransport>::ResponseBody;
        type Error = connectrpc::ConnectError;

        fn send(
            &self,
            request: axum::http::Request<connectrpc::client::ClientBody>,
        ) -> connectrpc::client::BoxFuture<
            'static,
            Result<axum::http::Response<Self::ResponseBody>, Self::Error>,
        > {
            if request.uri().path() == "/log.ingest.v1.Service/Put"
                && self.puts.fetch_add(1, Ordering::SeqCst) == self.failed_put
            {
                return Box::pin(async {
                    Err(connectrpc::ConnectError::unavailable(
                        "the backfill is interrupted",
                    ))
                });
            }
            self.store.send(request)
        }
    }

    /// The entries a backfill builds from one page of rows can pass the byte limit of one Store
    /// write. The backfill then sends them in several writes and reports progress for the page
    /// only after the last of them. A backfill that stops between two of those writes has
    /// published no cursor past an entry it did not write, and a run from the last cursor it
    /// did publish completes both indexes.
    #[tokio::test]
    async fn backfill_reports_a_page_only_after_the_last_of_its_writes() {
        let (_task, url) = exoware_simulator::open_temp()
            .await
            .expect("the simulator must start");
        let builder = || {
            exoware_sdk::StoreClient::builder()
                .url(&url)
                .retry_config(exoware_sdk::RetryConfig::disabled())
        };
        let store = builder().build().unwrap().unprefixed();
        let schema = |store: &PrefixedStoreClient, indexes: &[&str]| {
            KvSchema::new(store.clone())
                .table(
                    "items",
                    vec![
                        TableColumnConfig::new("id", DataType::Int64, false),
                        TableColumnConfig::new("body", DataType::Utf8, false),
                    ],
                    vec!["id".to_string()],
                    indexes
                        .iter()
                        .map(|name| {
                            IndexSpec::new(*name, vec!["id".to_string()])
                                .unwrap()
                                .with_cover_columns(vec!["body".to_string()])
                        })
                        .collect(),
                )
                .unwrap()
        };

        // The first page holds five small rows and the second five rows of 27 MiB. Each of the
        // two added indexes covers the body, so the ten entries of the second page need 270 MiB,
        // more than the 256 MiB of one write. Nine of them fill its first write, which leaves
        // the last row's entry in the second index to another.
        let page = 5;
        let body = "x".repeat(27 * 1024 * 1024);
        let mut writer = schema(&store, &[]).batch_writer();
        for id in 0..2 * page {
            let body = if id < page { "x" } else { body.as_str() };
            writer
                .insert(
                    "items",
                    vec![CellValue::Int64(id), CellValue::Utf8(body.to_string())],
                )
                .unwrap();
        }
        writer.flush().await.expect("the rows must be written");

        // Runs a backfill of both indexes and returns its result with the rows, entries, and
        // cursor of each Progress event it published.
        let backfill = |store: &PrefixedStoreClient, start_cursor| {
            let indexed = schema(store, &["first", "second"]);
            async move {
                let (events, mut received) = tokio::sync::mpsc::unbounded_channel();
                let options = IndexBackfillOptions {
                    row_batch_size: page as usize,
                    start_cursor,
                };
                let result = indexed
                    .backfill_added_indexes_with_options_and_progress(
                        "items",
                        &[],
                        options,
                        &events,
                    )
                    .await;
                let mut progress = Vec::new();
                while let Ok(event) = received.try_recv() {
                    if let IndexBackfillEvent::Progress {
                        scanned_rows,
                        index_entries_written,
                        next_cursor,
                        ..
                    } = event
                    {
                        progress.push((scanned_rows, index_entries_written, next_cursor));
                    }
                }
                (result, progress)
            }
        };

        // Returns the length of every value each index holds.
        let index_values = || async {
            let session = store.create_session();
            let mut indexes = Vec::new();
            for spec in schema(&store, &["first", "second"]).tables()[0]
                .1
                .index_specs
                .iter()
            {
                let (start, end) = spec.prefix.bounds();
                let mut stream = session
                    .range_stream(&start, &end, usize::MAX, 1)
                    .await
                    .unwrap();
                let mut values = Vec::new();
                while let Some(chunk) = stream.next_chunk().await.unwrap() {
                    values.extend(chunk.rows.iter().map(|(_, value)| value.len()));
                }
                indexes.push(values);
            }
            indexes
        };

        // The first page takes one write and the second takes two. The last of the three fails.
        let interrupted = builder()
            .client_transport(InterruptedStore {
                store: exoware_sdk::proto::PreferZstdHttpClient::plaintext(),
                puts: Arc::new(AtomicUsize::new(0)),
                failed_put: 2,
            })
            .build()
            .unwrap()
            .unprefixed();
        let (result, progress) = backfill(&interrupted, None).await;
        let error = result.expect_err("the backfill must stop at the failed write");
        assert!(
            error.to_string().contains("the backfill is interrupted"),
            "{error}"
        );

        // The second page stopped with the last row in one index only, and only the first page
        // was reported.
        let entries = |indexes: Vec<Vec<usize>>| indexes.iter().map(Vec::len).collect::<Vec<_>>();
        assert_eq!(entries(index_values().await), [10, 9]);
        assert_eq!(progress.len(), 1, "{progress:?}");
        let (scanned_rows, index_entries_written, cursor) = progress[0].clone();
        assert_eq!((scanned_rows, index_entries_written), (5, 10));
        assert!(cursor.is_some());

        // A run from the reported cursor reads the second page again and reports it once, after
        // both of its writes.
        let (result, progress) = backfill(&store, cursor).await;
        let report = result.expect("the backfill must split the entries over several writes");
        assert_eq!((report.scanned_rows, report.index_entries_written), (5, 10));
        assert_eq!(progress.len(), 1, "{progress:?}");
        assert_eq!((progress[0].0, progress[0].1), (5, 10));

        // Both indexes hold one entry for every row, five of them with a covered 27 MiB body.
        for values in index_values().await {
            assert_eq!(values.len(), 10);
            assert_eq!(values.iter().filter(|len| **len > body.len()).count(), 5);
        }
    }

    /// DataFrame inserts cast each column to the table type the way SQL INSERT does.
    #[tokio::test]
    async fn dataframe_insert_casts_input_to_table_types() {
        let (_task, url) = exoware_simulator::open_temp()
            .await
            .expect("the simulator must start");
        let store = exoware_sdk::StoreClient::new(&url).unprefixed();
        let schema = KvSchema::new(store.clone())
            .table(
                "prices",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("amount", DataType::Decimal128(10, 2), true),
                    TableColumnConfig::new(
                        "at",
                        DataType::Timestamp(TimeUnit::Microsecond, Some("+07:00".into())),
                        true,
                    ),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap()
            .table(
                "items",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("qty", DataType::Int64, true),
                    TableColumnConfig::new("name", DataType::Utf8, true),
                    TableColumnConfig::new("stock", DataType::UInt64, true),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();
        let ctx = SqlContext::new(store);
        ctx.register_schema(schema).unwrap();

        // A DataFrame and a SQL INSERT rescale the decimal and reinterpret the timestamp alike.
        write_batch(
            &ctx,
            "prices",
            batch(vec![
                ("id", Arc::new(Int64Array::from(vec![1]))),
                (
                    "amount",
                    Arc::new(
                        Decimal128Array::from(vec![12345])
                            .with_precision_and_scale(10, 4)
                            .unwrap(),
                    ),
                ),
                ("at", Arc::new(TimestampMicrosecondArray::from(vec![0]))),
            ]),
        )
        .await
        .unwrap();
        ctx.sql(
            "INSERT INTO prices VALUES (2, arrow_cast(1.2345, 'Decimal128(10, 4)'), \
             arrow_cast(0, 'Timestamp(Microsecond, None)'))",
        )
        .await
        .unwrap()
        .collect()
        .await
        .unwrap();
        assert_eq!(
            query(
                &ctx,
                "SELECT id, CAST(amount AS VARCHAR) AS amount, CAST(at AS BIGINT) AS at \
                 FROM prices ORDER BY id"
            )
            .await,
            vec![
                "+----+--------+--------------+",
                "| id | amount | at           |",
                "+----+--------+--------------+",
                "| 1  | 1.23   | -25200000000 |",
                "| 2  | 1.23   | -25200000000 |",
                "+----+--------+--------------+",
            ]
        );

        // Narrower integers, dictionary strings, and an all-null column cast to the table types.
        write_batch(
            &ctx,
            "items",
            batch(vec![
                ("id", Arc::new(Int64Array::from(vec![1]))),
                ("qty", Arc::new(Int32Array::from(vec![5]))),
                (
                    "name",
                    Arc::new(DictionaryArray::<Int32Type>::from_iter(["bolt"])),
                ),
                ("stock", Arc::new(NullArray::new(1))),
            ]),
        )
        .await
        .unwrap();
        assert_eq!(
            query(&ctx, "SELECT * FROM items").await,
            vec![
                "+----+-----+------+-------+",
                "| id | qty | name | stock |",
                "+----+-----+------+-------+",
                "| 1  | 5   | bolt |       |",
                "+----+-----+------+-------+",
            ]
        );

        // A value that does not fit its table type fails the write and stores nothing.
        let err = write_batch(
            &ctx,
            "items",
            batch(vec![
                ("id", Arc::new(Int64Array::from(vec![2]))),
                ("qty", Arc::new(Int64Array::from(vec![5]))),
                (
                    "name",
                    Arc::new(DictionaryArray::<Int32Type>::from_iter(["nut"])),
                ),
                ("stock", Arc::new(Int64Array::from(vec![-1]))),
            ]),
        )
        .await
        .expect_err("a negative stock does not fit UInt64");
        assert!(
            err.to_string()
                .contains("Can't cast value -1 to type UInt64"),
            "{err}"
        );
        assert_eq!(query(&ctx, "SELECT id FROM items").await.len(), 5);
    }

    /// Async identity function over Int64 that has no synchronous implementation.
    #[derive(Debug, PartialEq, Eq, Hash)]
    struct AsyncIdentity {
        signature: Signature,
    }

    impl ScalarUDFImpl for AsyncIdentity {
        fn name(&self) -> &str {
            "async_identity"
        }

        fn signature(&self) -> &Signature {
            &self.signature
        }

        fn return_type(&self, _arg_types: &[DataType]) -> DataFusionResult<DataType> {
            Ok(DataType::Int64)
        }

        fn invoke_with_args(&self, _args: ScalarFunctionArgs) -> DataFusionResult<ColumnarValue> {
            internal_err!("async_identity only runs asynchronously")
        }
    }

    #[async_trait]
    impl AsyncScalarUDFImpl for AsyncIdentity {
        async fn invoke_async_with_args(
            &self,
            args: ScalarFunctionArgs,
        ) -> DataFusionResult<ColumnarValue> {
            Ok(args.args[0].clone())
        }
    }

    /// A filter that calls an async function stays above the scan, where DataFusion
    /// evaluates it asynchronously.
    #[tokio::test]
    async fn filters_calling_async_functions_run_in_datafusion() {
        let (_task, url) = exoware_simulator::open_temp()
            .await
            .expect("the simulator must start");
        let store = exoware_sdk::StoreClient::new(&url).unprefixed();
        let schema = KvSchema::new(store.clone())
            .table(
                "items",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("qty", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();
        let ctx = SqlContext::new(store);
        ctx.register_schema(schema).unwrap();
        ctx.register_udf(
            AsyncScalarUDF::new(Arc::new(AsyncIdentity {
                signature: Signature::exact(vec![DataType::Int64], Volatility::Immutable),
            }))
            .into_scalar_udf(),
        );
        ctx.sql("INSERT INTO items VALUES (1, 2), (2, 5), (3, 4), (4, 1)")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        // The async filter runs above the scan and keeps only rows whose qty exceeds 3.
        assert_eq!(
            query(
                &ctx,
                "SELECT id, qty FROM items WHERE async_identity(qty) > 3 ORDER BY id"
            )
            .await,
            vec![
                "+----+-----+",
                "| id | qty |",
                "+----+-----+",
                "| 2  | 5   |",
                "| 3  | 4   |",
                "+----+-----+",
            ]
        );
    }

    #[test]
    fn table_names_fit_the_subscribe_request() {
        let declare = |name: String| {
            KvSchema::new(exoware_sdk::StoreClient::new("http://127.0.0.1:1").unprefixed()).table(
                name,
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
        };

        // Each "é" is one character in two bytes, so the limit counts characters.
        assert!(declare("é".repeat(255)).is_ok());
        for name in [String::new(), "é".repeat(256)] {
            assert!(matches!(declare(name), Err(DataFusionError::Plan(_))));
        }
    }
}
