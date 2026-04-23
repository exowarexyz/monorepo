//! Connect-backed server for `store.sql.v1`.
//!
//! [`SqlServer`] builds a DataFusion session over a [`KvSchema`] and exposes:
//! - [`Service::query`] unary SQL against that session.
//! - [`Service::subscribe`] streaming: for every atomic ingest batch that
//!   touches a registered table's primary-key codec family, decode its rows
//!   and re-run the subscriber's SQL `WHERE` predicate against just those
//!   rows. Each matching batch produces one [`SubscribeResponse`] carrying
//!   only the rows that satisfied the predicate.
//!
//! The streaming path builds a small transient [`MemTable`] per batch and
//! runs `SELECT * FROM <table> WHERE <where_sql>` against it, so any SQL
//! expression DataFusion accepts (referring to the table's columns) works
//! as the predicate.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use connectrpc::{ConnectError, ConnectRpcService, Context};
use datafusion::arrow::array::{
    Array, ArrayRef, BooleanArray, Date32Array, Date64Array, Decimal128Array, Decimal256Array,
    FixedSizeBinaryArray, Float32Array, Float64Array, Int32Array, Int64Array, LargeListArray,
    LargeStringArray, ListArray, StringArray, StringViewArray, TimestampMicrosecondArray,
    TimestampMillisecondArray, TimestampNanosecondArray, TimestampSecondArray, UInt32Array,
    UInt64Array,
};
use datafusion::arrow::datatypes::{DataType, SchemaRef, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::common::{DataFusionError, Result as DataFusionResult};
use datafusion::datasource::MemTable;
use datafusion::prelude::SessionContext;
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::kv_codec::{decode_stored_row, Utf8};
use exoware_sdk_rs::match_key::MatchKey;
use exoware_sdk_rs::store::sql::v1::{
    cell::Kind as ProtoCellKind, Cell as ProtoCell, Column as ProtoColumn, Index as ProtoIndex,
    IndexLayout as ProtoIndexLayout, ListValue as ProtoListValue, Null as ProtoNull,
    QueryRequestView, QueryResponse, Row as ProtoRow, Service, ServiceServer,
    SubscribeRequestView, SubscribeResponse, Table as ProtoTable, TablesRequestView,
    TablesResponse,
};
use exoware_sdk_rs::stream_filter::StreamFilter;
use exoware_sdk_rs::{StoreClient, StreamSubscription};
use futures::stream::Stream;

use crate::builder::{projected_column_indices, ProjectedBatchBuilder};
use crate::codec::decode_primary_key_selected;
use crate::filter::ScanAccessPlan;
use crate::predicate::QueryPredicate;
use crate::schema::KvSchema;
use crate::types::{
    IndexLayout, ResolvedIndexSpec, TableModel, KEY_KIND_BITS, PRIMARY_RESERVED_BITS,
};

const MAX_CONNECTRPC_BODY_BYTES: usize = 256 * 1024 * 1024;

type SubscribeStream =
    Pin<Box<dyn Stream<Item = Result<SubscribeResponse, ConnectError>> + Send>>;

/// One registered table's streaming-decode state.
#[derive(Clone)]
struct TableStream {
    model: Arc<TableModel>,
    schema: SchemaRef,
    access_plan: Arc<ScanAccessPlan>,
    match_key: MatchKey,
    indexes: Arc<Vec<ResolvedIndexSpec>>,
}

impl TableStream {
    fn new(model: Arc<TableModel>, indexes: Vec<ResolvedIndexSpec>) -> Self {
        let projection: Option<Vec<usize>> = Some((0..model.columns.len()).collect());
        let access_plan = Arc::new(ScanAccessPlan::new(
            &model,
            &projection,
            &QueryPredicate::default(),
        ));
        let prefix = u16::from(model.table_prefix) << KEY_KIND_BITS;
        let match_key = MatchKey {
            reserved_bits: PRIMARY_RESERVED_BITS,
            prefix,
            payload_regex: Utf8::from("(?s-u).*"),
        };
        Self {
            schema: model.schema.clone(),
            access_plan,
            model,
            match_key,
            indexes: Arc::new(indexes),
        }
    }

    fn decode_batch(&self, entries: &[(Key, Bytes)]) -> DataFusionResult<RecordBatch> {
        let mut builder = ProjectedBatchBuilder::from_access_plan(&self.model, &self.access_plan);
        for (key, value) in entries {
            if !self.model.primary_key_codec.matches(key) {
                continue;
            }
            let Some(pk_values) = decode_primary_key_selected(
                self.model.table_prefix,
                key,
                &self.model,
                &self.access_plan.required_pk_mask,
            ) else {
                continue;
            };
            let Ok(archived) = decode_stored_row(value) else {
                continue;
            };
            if archived.values.len() != self.model.columns.len() {
                continue;
            }
            let _ = builder.append_archived_row(&pk_values, &archived)?;
        }
        builder.finish(&self.schema)
    }
}

/// SQL server bound to a single [`KvSchema`].
///
/// Construct with [`SqlServer::new`], pass to [`sql_connect_stack`] to mount
/// on an axum router.
pub struct SqlServer {
    ctx: Arc<SessionContext>,
    streams: HashMap<String, TableStream>,
    // Registration order, preserved for the `Tables` RPC so clients see
    // tables in the same order the operator declared them.
    table_names: Vec<String>,
    store: StoreClient,
}

impl SqlServer {
    /// Build a server from a [`KvSchema`]. The schema's tables are registered
    /// in a new [`SessionContext`] that drives both unary `Query` and the
    /// per-batch predicate evaluation on `Subscribe`.
    pub fn new(schema: KvSchema) -> DataFusionResult<Self> {
        let store = schema.client().clone();
        let mut streams = HashMap::with_capacity(schema.tables().len());
        let mut table_names = Vec::with_capacity(schema.tables().len());
        for (name, config) in schema.tables() {
            let model = Arc::new(
                TableModel::from_config(config)
                    .map_err(|e| DataFusionError::Execution(format!("invalid table config: {e}")))?,
            );
            let indexes = model
                .resolve_index_specs(&config.index_specs)
                .map_err(|e| DataFusionError::Execution(format!("invalid index specs: {e}")))?;
            streams.insert(name.clone(), TableStream::new(model, indexes));
            table_names.push(name.clone());
        }
        let ctx = SessionContext::new();
        schema.register_all(&ctx)?;
        Ok(Self {
            ctx: Arc::new(ctx),
            streams,
            table_names,
            store,
        })
    }

    /// Borrow the underlying DataFusion session, e.g. to `INSERT` seed rows
    /// without going through the connect API.
    pub fn session(&self) -> &SessionContext {
        &self.ctx
    }

    fn stream(&self, table: &str) -> Result<&TableStream, ConnectError> {
        self.streams.get(table).ok_or_else(|| {
            ConnectError::not_found(format!("unknown table '{table}'"))
        })
    }

    fn describe_tables(&self) -> Vec<ProtoTable> {
        self.table_names
            .iter()
            .filter_map(|name| {
                let stream = self.streams.get(name)?;
                let columns = stream
                    .schema
                    .fields()
                    .iter()
                    .map(|field| ProtoColumn {
                        name: field.name().clone(),
                        data_type: format!("{}", field.data_type()),
                        nullable: field.is_nullable(),
                        ..Default::default()
                    })
                    .collect();
                let primary_key_columns = stream
                    .model
                    .primary_key_indices
                    .iter()
                    .map(|&idx| idx as u32)
                    .collect();
                let indexes = stream
                    .indexes
                    .iter()
                    .map(|spec| {
                        let key_set: std::collections::HashSet<usize> =
                            spec.key_columns.iter().copied().collect();
                        ProtoIndex {
                            name: spec.name.clone(),
                            layout: proto_index_layout(spec.layout).into(),
                            key_columns: spec.key_columns.iter().map(|&idx| idx as u32).collect(),
                            // Columns stored in the index payload beyond the
                            // key itself ("covered" columns that let point
                            // lookups skip the base-row fetch).
                            cover_columns: spec
                                .value_column_mask
                                .iter()
                                .enumerate()
                                .filter_map(|(idx, covered)| {
                                    (*covered && !key_set.contains(&idx)).then_some(idx as u32)
                                })
                                .collect(),
                            ..Default::default()
                        }
                    })
                    .collect();
                Some(ProtoTable {
                    name: name.clone(),
                    columns,
                    primary_key_columns,
                    indexes,
                    ..Default::default()
                })
            })
            .collect()
    }
}

fn proto_index_layout(layout: IndexLayout) -> ProtoIndexLayout {
    match layout {
        IndexLayout::Lexicographic => ProtoIndexLayout::INDEX_LAYOUT_LEXICOGRAPHIC,
        IndexLayout::ZOrder => ProtoIndexLayout::INDEX_LAYOUT_Z_ORDER,
    }
}

/// Turn a [`SqlServer`] into a mounted Connect service stack ready to hand to
/// axum's `fallback_service`.
pub fn sql_connect_stack(server: Arc<SqlServer>) -> ConnectRpcService<ServiceServer<SqlConnect>> {
    ConnectRpcService::new(ServiceServer::new(SqlConnect::new(server)))
        .with_limits(
            connectrpc::Limits::default()
                .max_request_body_size(MAX_CONNECTRPC_BODY_BYTES)
                .max_message_size(MAX_CONNECTRPC_BODY_BYTES),
        )
        .with_compression(exoware_sdk_rs::connect_compression_registry())
}

/// Connect handler implementing `store.sql.v1.Service`.
#[derive(Clone)]
pub struct SqlConnect {
    server: Arc<SqlServer>,
}

impl SqlConnect {
    pub fn new(server: Arc<SqlServer>) -> Self {
        Self { server }
    }
}

impl Service for SqlConnect {
    fn subscribe(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<SubscribeRequestView<'static>>,
    ) -> impl Future<Output = Result<(SubscribeStream, Context), ConnectError>> + Send {
        let server = self.server.clone();
        async move {
            let table_name = request.table.to_string();
            let where_sql = request.where_sql.trim().to_string();
            let since = request.since_sequence_number.filter(|seq| *seq != 0);
            let stream = server.stream(&table_name)?.clone();

            let filter = StreamFilter {
                match_keys: vec![stream.match_key.clone()],
                value_filters: vec![],
            };
            let sub = server
                .store
                .stream()
                .subscribe(filter, since)
                .await
                .map_err(client_error_to_connect)?;

            let output = Box::pin(BatchPredicateStream::new(sub, stream, table_name, where_sql));
            Ok((output as SubscribeStream, ctx))
        }
    }

    fn tables(
        &self,
        ctx: Context,
        _request: buffa::view::OwnedView<TablesRequestView<'static>>,
    ) -> impl Future<Output = Result<(TablesResponse, Context), ConnectError>> + Send {
        let server = self.server.clone();
        async move {
            Ok((
                TablesResponse {
                    tables: server.describe_tables(),
                    ..Default::default()
                },
                ctx,
            ))
        }
    }

    fn query(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<QueryRequestView<'static>>,
    ) -> impl Future<Output = Result<(QueryResponse, Context), ConnectError>> + Send {
        let server = self.server.clone();
        async move {
            let sql = request.sql.to_string();
            let df = server
                .ctx
                .sql(&sql)
                .await
                .map_err(datafusion_error_to_connect)?;
            let schema = df.schema().clone();
            let batches = df.collect().await.map_err(datafusion_error_to_connect)?;
            let columns: Vec<String> = schema
                .fields()
                .iter()
                .map(|f| f.name().clone())
                .collect();
            let rows = record_batches_to_proto_rows(&batches).map_err(datafusion_error_to_connect)?;
            Ok((
                QueryResponse {
                    column: columns,
                    rows,
                    ..Default::default()
                },
                ctx,
            ))
        }
    }
}

struct BatchPredicateStream {
    sub: StreamSubscription,
    state: TableStream,
    table_name: String,
    where_sql: String,
    building: Option<
        Pin<Box<dyn Future<Output = Result<Option<SubscribeResponse>, ConnectError>> + Send>>,
    >,
}

impl BatchPredicateStream {
    fn new(
        sub: StreamSubscription,
        state: TableStream,
        table_name: String,
        where_sql: String,
    ) -> Self {
        Self {
            sub,
            state,
            table_name,
            where_sql,
            building: None,
        }
    }
}

impl Stream for BatchPredicateStream {
    type Item = Result<SubscribeResponse, ConnectError>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(fut) = this.building.as_mut() {
                match fut.as_mut().poll(cx) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Ok(Some(resp))) => {
                        this.building = None;
                        return std::task::Poll::Ready(Some(Ok(resp)));
                    }
                    std::task::Poll::Ready(Ok(None)) => {
                        this.building = None;
                    }
                    std::task::Poll::Ready(Err(err)) => {
                        this.building = None;
                        return std::task::Poll::Ready(Some(Err(err)));
                    }
                }
            }

            let frame = {
                let next_fut = this.sub.next();
                tokio::pin!(next_fut);
                match next_fut.as_mut().poll(cx) {
                    std::task::Poll::Ready(Ok(Some(frame))) => frame,
                    std::task::Poll::Ready(Ok(None)) => {
                        return std::task::Poll::Ready(None)
                    }
                    std::task::Poll::Ready(Err(err)) => {
                        return std::task::Poll::Ready(Some(Err(client_error_to_connect(err))));
                    }
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            };

            let sequence_number = frame.sequence_number;
            let entries: Vec<(Key, Bytes)> = frame
                .entries
                .into_iter()
                .map(|entry| (entry.key, entry.value))
                .collect();
            let state = this.state.clone();
            let table_name = this.table_name.clone();
            let where_sql = this.where_sql.clone();
            this.building = Some(Box::pin(async move {
                evaluate_batch(state, table_name, where_sql, sequence_number, entries).await
            }));
        }
    }
}

async fn evaluate_batch(
    state: TableStream,
    table_name: String,
    where_sql: String,
    sequence_number: u64,
    entries: Vec<(Key, Bytes)>,
) -> Result<Option<SubscribeResponse>, ConnectError> {
    let batch = state
        .decode_batch(&entries)
        .map_err(datafusion_error_to_connect)?;
    if batch.num_rows() == 0 {
        return Ok(None);
    }

    let filtered = if where_sql.is_empty() {
        batch
    } else {
        apply_where(state.schema.clone(), batch, &table_name, &where_sql)
            .await
            .map_err(datafusion_error_to_connect)?
    };
    if filtered.num_rows() == 0 {
        return Ok(None);
    }

    let columns: Vec<String> = filtered
        .schema()
        .fields()
        .iter()
        .map(|f| f.name().clone())
        .collect();
    let rows = record_batches_to_proto_rows(std::slice::from_ref(&filtered))
        .map_err(datafusion_error_to_connect)?;
    Ok(Some(SubscribeResponse {
        sequence_number,
        column: columns,
        rows,
        ..Default::default()
    }))
}

async fn apply_where(
    schema: SchemaRef,
    batch: RecordBatch,
    table_name: &str,
    where_sql: &str,
) -> DataFusionResult<RecordBatch> {
    let ctx = SessionContext::new();
    let mem = MemTable::try_new(schema.clone(), vec![vec![batch]])?;
    ctx.register_table(table_name, Arc::new(mem))?;
    let sql = format!("SELECT * FROM {table_name} WHERE {where_sql}");
    let df = ctx.sql(&sql).await?;
    let batches = df.collect().await?;
    if batches.is_empty() {
        return Ok(RecordBatch::new_empty(schema));
    }
    datafusion::arrow::compute::concat_batches(&schema, batches.iter())
        .map_err(|e| DataFusionError::ArrowError(Box::new(e), None))
}

fn record_batches_to_proto_rows(batches: &[RecordBatch]) -> DataFusionResult<Vec<ProtoRow>> {
    let mut out = Vec::with_capacity(batches.iter().map(|b| b.num_rows()).sum());
    for batch in batches {
        for row_idx in 0..batch.num_rows() {
            let mut cells = Vec::with_capacity(batch.num_columns());
            for col_idx in 0..batch.num_columns() {
                cells.push(arrow_value_to_cell(batch.column(col_idx), row_idx)?);
            }
            out.push(ProtoRow {
                cells,
                ..Default::default()
            });
        }
    }
    Ok(out)
}

fn arrow_value_to_cell(array: &ArrayRef, row: usize) -> DataFusionResult<ProtoCell> {
    let kind = if array.is_null(row) {
        ProtoCellKind::NullValue(Box::new(ProtoNull::default()))
    } else {
        arrow_value_to_kind(array, row)?
    };
    Ok(ProtoCell {
        kind: Some(kind),
        ..Default::default()
    })
}

fn arrow_value_to_kind(array: &ArrayRef, row: usize) -> DataFusionResult<ProtoCellKind> {
    match array.data_type() {
        DataType::Int64 => Ok(ProtoCellKind::Int64Value(
            array.as_any().downcast_ref::<Int64Array>().unwrap().value(row),
        )),
        DataType::Int32 => Ok(ProtoCellKind::Int64Value(
            array.as_any().downcast_ref::<Int32Array>().unwrap().value(row) as i64,
        )),
        DataType::UInt64 => Ok(ProtoCellKind::Uint64Value(
            array.as_any().downcast_ref::<UInt64Array>().unwrap().value(row),
        )),
        DataType::UInt32 => Ok(ProtoCellKind::Uint64Value(
            array.as_any().downcast_ref::<UInt32Array>().unwrap().value(row) as u64,
        )),
        DataType::Float64 => Ok(ProtoCellKind::Float64Value(
            array.as_any().downcast_ref::<Float64Array>().unwrap().value(row),
        )),
        DataType::Float32 => Ok(ProtoCellKind::Float64Value(
            array.as_any().downcast_ref::<Float32Array>().unwrap().value(row) as f64,
        )),
        DataType::Boolean => Ok(ProtoCellKind::BooleanValue(
            array.as_any().downcast_ref::<BooleanArray>().unwrap().value(row),
        )),
        DataType::Utf8 => Ok(ProtoCellKind::Utf8Value(
            array.as_any().downcast_ref::<StringArray>().unwrap().value(row).to_string(),
        )),
        DataType::LargeUtf8 => Ok(ProtoCellKind::Utf8Value(
            array.as_any().downcast_ref::<LargeStringArray>().unwrap().value(row).to_string(),
        )),
        DataType::Utf8View => Ok(ProtoCellKind::Utf8Value(
            array.as_any().downcast_ref::<StringViewArray>().unwrap().value(row).to_string(),
        )),
        DataType::FixedSizeBinary(_) => Ok(ProtoCellKind::FixedSizeBinaryValue(
            array
                .as_any()
                .downcast_ref::<FixedSizeBinaryArray>()
                .unwrap()
                .value(row)
                .to_vec(),
        )),
        DataType::Date32 => Ok(ProtoCellKind::Date32Value(
            array.as_any().downcast_ref::<Date32Array>().unwrap().value(row),
        )),
        DataType::Date64 => Ok(ProtoCellKind::Date64Value(
            array.as_any().downcast_ref::<Date64Array>().unwrap().value(row),
        )),
        DataType::Timestamp(unit, _) => {
            let v = match unit {
                TimeUnit::Second => array
                    .as_any()
                    .downcast_ref::<TimestampSecondArray>()
                    .unwrap()
                    .value(row),
                TimeUnit::Millisecond => array
                    .as_any()
                    .downcast_ref::<TimestampMillisecondArray>()
                    .unwrap()
                    .value(row),
                TimeUnit::Microsecond => array
                    .as_any()
                    .downcast_ref::<TimestampMicrosecondArray>()
                    .unwrap()
                    .value(row),
                TimeUnit::Nanosecond => array
                    .as_any()
                    .downcast_ref::<TimestampNanosecondArray>()
                    .unwrap()
                    .value(row),
            };
            Ok(ProtoCellKind::TimestampValue(v))
        }
        DataType::Decimal128(_, _) => {
            let v = array
                .as_any()
                .downcast_ref::<Decimal128Array>()
                .unwrap()
                .value(row);
            Ok(ProtoCellKind::Decimal128Value(v.to_be_bytes().to_vec()))
        }
        DataType::Decimal256(_, _) => {
            let v = array
                .as_any()
                .downcast_ref::<Decimal256Array>()
                .unwrap()
                .value(row);
            Ok(ProtoCellKind::Decimal256Value(v.to_be_bytes().to_vec()))
        }
        DataType::List(_) => {
            let list = array.as_any().downcast_ref::<ListArray>().unwrap();
            Ok(ProtoCellKind::ListValue(Box::new(list_array_to_proto(
                &list.value(row),
            )?)))
        }
        DataType::LargeList(_) => {
            let list = array.as_any().downcast_ref::<LargeListArray>().unwrap();
            Ok(ProtoCellKind::ListValue(Box::new(list_array_to_proto(
                &list.value(row),
            )?)))
        }
        other => Err(DataFusionError::NotImplemented(format!(
            "cell conversion for arrow type {other:?}"
        ))),
    }
}

fn list_array_to_proto(elements: &ArrayRef) -> DataFusionResult<ProtoListValue> {
    let mut cells = Vec::with_capacity(elements.len());
    for idx in 0..elements.len() {
        cells.push(arrow_value_to_cell(elements, idx)?);
    }
    Ok(ProtoListValue {
        elements: cells,
        ..Default::default()
    })
}

fn datafusion_error_to_connect(err: DataFusionError) -> ConnectError {
    match err {
        DataFusionError::Plan(msg)
        | DataFusionError::SQL(_, Some(msg))
        | DataFusionError::Configuration(msg)
        | DataFusionError::NotImplemented(msg) => ConnectError::invalid_argument(msg),
        DataFusionError::SchemaError(err, _) => ConnectError::invalid_argument(err.to_string()),
        other => ConnectError::internal(other.to_string()),
    }
}

fn client_error_to_connect(err: exoware_sdk_rs::ClientError) -> ConnectError {
    if let Some(rpc) = err.rpc_error() {
        ConnectError::new(rpc.code, rpc.message.clone().unwrap_or_default())
    } else {
        ConnectError::internal(err.to_string())
    }
}

// Silence unused import when no tests reference them.
#[allow(dead_code)]
fn _assert_projected_column_indices_visible() {
    let _ = projected_column_indices;
}
