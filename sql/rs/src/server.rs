//! Connect-backed server for `sql.v1`.
//!
//! [`SqlServer`] builds a DataFusion session over a [`KvSchema`] and exposes:
//! - [`Service::query`] unary SQL against that session.
//! - [`Service::subscribe`] streaming: for every atomic ingest batch that
//!   touches a registered table's primary-key family, decode its rows
//!   and re-run the subscriber's SQL `WHERE` predicate against just those
//!   rows. Each matching batch produces one [`SubscribeResponse`] carrying
//!   only the rows that satisfied the predicate.
//!
//! The streaming path builds a small transient [`MemTable`] per batch and
//! runs `SELECT * FROM <table> WHERE <where_sql>` against it, so any SQL
//! expression DataFusion accepts (referring to the table's columns) works
//! as the predicate.

#![allow(refining_impl_trait)]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::proto::sql::v1::{
    cell::Kind as ProtoCellKind, Cell as ProtoCell, Column as ProtoColumn, Index as ProtoIndex,
    IndexLayout as ProtoIndexLayout, ListValue as ProtoListValue, Null as ProtoNull,
    QueryRequestView, QueryResponse, Row as ProtoRow, Service, ServiceServer, SubscribeRequestView,
    SubscribeResponse, Table as ProtoTable, TablesRequestView, TablesResponse,
};
use bytes::Bytes;
use connectrpc::{ConnectError, ConnectRpcService, RequestContext as Context};
use datafusion::arrow::array::{
    Array, ArrayRef, BinaryArray, BinaryViewArray, BooleanArray, Date32Array, Date64Array,
    Decimal128Array, Decimal256Array, FixedSizeBinaryArray, Float32Array, Float64Array, Int32Array,
    Int64Array, LargeBinaryArray, LargeListArray, LargeStringArray, ListArray, StringArray,
    StringViewArray, TimestampMicrosecondArray, TimestampMillisecondArray,
    TimestampNanosecondArray, TimestampSecondArray, UInt32Array, UInt64Array,
};
use datafusion::arrow::datatypes::{DataType, SchemaRef, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::common::{DataFusionError, Result as DataFusionResult};
use datafusion::datasource::MemTable;
use datafusion::prelude::SessionContext;
use exoware_sdk::keys::Key;
use exoware_sdk::kv_codec::{decode_stored_row, Utf8};
use exoware_sdk::selector::Selector;
use exoware_sdk::stream_filter::StreamFilter;
use exoware_sdk::{PrefixedStoreClient, StreamSubscription, StreamSubscriptionFrame};
use futures::future::BoxFuture;
use futures::stream::{self, Stream};
use futures::FutureExt;

use crate::builder::{projected_column_indices, ProjectedBatchBuilder};
use crate::codec::decode_primary_key_selected;
use crate::filter::ScanAccessPlan;
use crate::predicate::QueryPredicate;
use crate::schema::KvSchema;
use crate::types::{IndexLayout, ResolvedIndexSpec, TableModel};

const MAX_CONNECTRPC_BODY_BYTES: usize = 256 * 1024 * 1024;

type SubscribeStream = Pin<Box<dyn Stream<Item = Result<SubscribeResponse, ConnectError>> + Send>>;

/// One registered table's streaming-decode state.
#[derive(Clone)]
struct TableStream {
    model: Arc<TableModel>,
    schema: SchemaRef,
    access_plan: Arc<ScanAccessPlan>,
    selector: Selector,
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
        let selector = Selector {
            prefix: model.primary_key_prefix.as_bytes().clone(),
            payload_regex: Utf8::from("(?s-u).*"),
        };
        Self {
            schema: model.schema.clone(),
            access_plan,
            model,
            selector,
            indexes: Arc::new(indexes),
        }
    }

    fn decode_batch(&self, entries: &[(Key, Bytes)]) -> DataFusionResult<RecordBatch> {
        let mut builder = ProjectedBatchBuilder::from_access_plan(&self.model, &self.access_plan);
        for (key, value) in entries {
            if !self.model.primary_key_prefix.matches(key) {
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
    store: PrefixedStoreClient,
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
            let model =
                Arc::new(TableModel::from_config(config).map_err(|e| {
                    DataFusionError::Execution(format!("invalid table config: {e}"))
                })?);
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

    #[allow(clippy::result_large_err)]
    fn stream(&self, table: &str) -> Result<&TableStream, ConnectError> {
        self.streams
            .get(table)
            .ok_or_else(|| ConnectError::not_found(format!("unknown table '{table}'")))
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
        .with_compression(exoware_sdk::connect_compression_registry())
}

/// Connect handler implementing `sql.v1.Service`.
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
        _ctx: Context,
        request: buffa::view::OwnedView<SubscribeRequestView<'static>>,
    ) -> impl Future<Output = connectrpc::ServiceResult<SubscribeStream>> + Send {
        let server = self.server.clone();
        async move {
            let table_name = request.table.to_string();
            let where_sql = request.where_sql.trim().to_string();
            let since = request.since_sequence_number.filter(|seq| *seq != 0);
            let stream = server.stream(&table_name)?.clone();

            let filter = StreamFilter {
                selectors: vec![stream.selector.clone()],
                value_filters: vec![],
            };
            let sub = server
                .store
                .stream()
                .subscribe(filter, since)
                .await
                .map_err(client_error_to_connect)?;

            let output = Box::pin(BatchPredicateStream::new(
                sub, stream, table_name, where_sql,
            ));
            Ok(connectrpc::Response::stream(output as SubscribeStream))
        }
    }

    fn tables(
        &self,
        _ctx: Context,
        _request: buffa::view::OwnedView<TablesRequestView<'static>>,
    ) -> impl Future<Output = connectrpc::ServiceResult<TablesResponse>> + Send {
        let server = self.server.clone();
        async move {
            connectrpc::Response::ok(TablesResponse {
                tables: server.describe_tables(),
                ..Default::default()
            })
        }
    }

    fn query(
        &self,
        _ctx: Context,
        request: buffa::view::OwnedView<QueryRequestView<'static>>,
    ) -> impl Future<Output = connectrpc::ServiceResult<QueryResponse>> + Send {
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
            let columns: Vec<String> = schema.fields().iter().map(|f| f.name().clone()).collect();
            let rows =
                record_batches_to_proto_rows(&batches).map_err(datafusion_error_to_connect)?;
            connectrpc::Response::ok(QueryResponse {
                column: columns,
                rows,
                ..Default::default()
            })
        }
    }
}

type BatchEvaluation = BoxFuture<'static, Result<Option<SubscribeResponse>, ConnectError>>;
type BatchEvaluator = Box<dyn FnMut(StreamSubscriptionFrame) -> BatchEvaluation + Send>;
type SubscriptionStream =
    Pin<Box<dyn Stream<Item = Result<StreamSubscriptionFrame, ConnectError>> + Send>>;

enum StagedSubscriptionEvent {
    Frame(StreamSubscriptionFrame),
    End,
    Error(ConnectError),
}

struct BatchPredicateStream {
    upstream: SubscriptionStream,
    evaluator: BatchEvaluator,
    building: Option<BatchEvaluation>,
    staged: Option<StagedSubscriptionEvent>,
    done: bool,
}

impl BatchPredicateStream {
    fn new(
        sub: StreamSubscription,
        state: TableStream,
        table_name: String,
        where_sql: String,
    ) -> Self {
        let upstream = subscription_stream(sub);
        let evaluator = move |frame: StreamSubscriptionFrame| {
            let sequence_number = frame.sequence_number;
            let entries = frame
                .entries
                .into_iter()
                .map(|entry| (entry.key, entry.value))
                .collect();
            let state = state.clone();
            let table_name = table_name.clone();
            let where_sql = where_sql.clone();
            async move { evaluate_batch(state, table_name, where_sql, sequence_number, entries).await }
        };
        Self::with_evaluator(upstream, evaluator)
    }

    fn with_evaluator<S, E, F>(upstream: S, mut evaluator: E) -> Self
    where
        S: Stream<Item = Result<StreamSubscriptionFrame, ConnectError>> + Send + 'static,
        E: FnMut(StreamSubscriptionFrame) -> F + Send + 'static,
        F: Future<Output = Result<Option<SubscribeResponse>, ConnectError>> + Send + 'static,
    {
        Self {
            upstream: Box::pin(upstream),
            evaluator: Box::new(move |frame| evaluator(frame).boxed()),
            building: None,
            staged: None,
            done: false,
        }
    }

    fn poll_upstream(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<StagedSubscriptionEvent> {
        match self.upstream.as_mut().poll_next(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Some(Ok(frame))) => {
                std::task::Poll::Ready(StagedSubscriptionEvent::Frame(frame))
            }
            std::task::Poll::Ready(Some(Err(err))) => {
                std::task::Poll::Ready(StagedSubscriptionEvent::Error(err))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(StagedSubscriptionEvent::End),
        }
    }

    fn finish_event(
        &mut self,
        event: StagedSubscriptionEvent,
    ) -> Option<Result<SubscribeResponse, ConnectError>> {
        self.done = true;
        match event {
            StagedSubscriptionEvent::End => None,
            StagedSubscriptionEvent::Error(err) => Some(Err(err)),
            StagedSubscriptionEvent::Frame(_) => unreachable!(),
        }
    }
}

fn subscription_stream(sub: StreamSubscription) -> SubscriptionStream {
    Box::pin(stream::unfold(Some(sub), |sub| async move {
        let mut sub = sub?;
        match sub.next().await {
            Ok(Some(frame)) => Some((Ok(frame), Some(sub))),
            Ok(None) => None,
            Err(err) => Some((Err(client_error_to_connect(err)), None)),
        }
    }))
}

impl Stream for BatchPredicateStream {
    type Item = Result<SubscribeResponse, ConnectError>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return std::task::Poll::Ready(None);
        }

        loop {
            if let Some(fut) = this.building.as_mut() {
                match fut.as_mut().poll(cx) {
                    std::task::Poll::Pending => {
                        if this.staged.is_none() {
                            if let std::task::Poll::Ready(event) = this.poll_upstream(cx) {
                                this.staged = Some(event);
                            }
                        }
                        return std::task::Poll::Pending;
                    }
                    std::task::Poll::Ready(Ok(Some(resp))) => {
                        this.building = None;
                        return std::task::Poll::Ready(Some(Ok(resp)));
                    }
                    std::task::Poll::Ready(Ok(None)) => {
                        this.building = None;
                    }
                    std::task::Poll::Ready(Err(err)) => {
                        this.building = None;
                        this.staged = None;
                        this.done = true;
                        return std::task::Poll::Ready(Some(Err(err)));
                    }
                }
            }

            let event = match this.staged.take() {
                Some(event) => event,
                None => match this.poll_upstream(cx) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(event) => event,
                },
            };

            match event {
                StagedSubscriptionEvent::Frame(frame) => {
                    this.building = Some((this.evaluator)(frame));
                }
                terminal => return std::task::Poll::Ready(this.finish_event(terminal)),
            }
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
        ProtoCellKind::NullValue(Box::<ProtoNull>::default())
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
            array
                .as_any()
                .downcast_ref::<Int64Array>()
                .unwrap()
                .value(row),
        )),
        DataType::Int32 => Ok(ProtoCellKind::Int64Value(
            array
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap()
                .value(row) as i64,
        )),
        DataType::UInt64 => Ok(ProtoCellKind::Uint64Value(
            array
                .as_any()
                .downcast_ref::<UInt64Array>()
                .unwrap()
                .value(row),
        )),
        DataType::UInt32 => Ok(ProtoCellKind::Uint64Value(
            array
                .as_any()
                .downcast_ref::<UInt32Array>()
                .unwrap()
                .value(row) as u64,
        )),
        DataType::Float64 => Ok(ProtoCellKind::Float64Value(
            array
                .as_any()
                .downcast_ref::<Float64Array>()
                .unwrap()
                .value(row),
        )),
        DataType::Float32 => Ok(ProtoCellKind::Float64Value(
            array
                .as_any()
                .downcast_ref::<Float32Array>()
                .unwrap()
                .value(row) as f64,
        )),
        DataType::Boolean => Ok(ProtoCellKind::BooleanValue(
            array
                .as_any()
                .downcast_ref::<BooleanArray>()
                .unwrap()
                .value(row),
        )),
        DataType::Utf8 => Ok(ProtoCellKind::Utf8Value(
            array
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap()
                .value(row)
                .to_string(),
        )),
        DataType::LargeUtf8 => Ok(ProtoCellKind::Utf8Value(
            array
                .as_any()
                .downcast_ref::<LargeStringArray>()
                .unwrap()
                .value(row)
                .to_string(),
        )),
        DataType::Utf8View => Ok(ProtoCellKind::Utf8Value(
            array
                .as_any()
                .downcast_ref::<StringViewArray>()
                .unwrap()
                .value(row)
                .to_string(),
        )),
        DataType::FixedSizeBinary(_) => {
            Ok(ProtoCellKind::FixedSizeBinaryValue(Bytes::copy_from_slice(
                array
                    .as_any()
                    .downcast_ref::<FixedSizeBinaryArray>()
                    .unwrap()
                    .value(row),
            )))
        }
        DataType::Binary => Ok(ProtoCellKind::BinaryValue(Bytes::copy_from_slice(
            array
                .as_any()
                .downcast_ref::<BinaryArray>()
                .unwrap()
                .value(row),
        ))),
        DataType::LargeBinary => Ok(ProtoCellKind::BinaryValue(Bytes::copy_from_slice(
            array
                .as_any()
                .downcast_ref::<LargeBinaryArray>()
                .unwrap()
                .value(row),
        ))),
        DataType::BinaryView => Ok(ProtoCellKind::BinaryValue(Bytes::copy_from_slice(
            array
                .as_any()
                .downcast_ref::<BinaryViewArray>()
                .unwrap()
                .value(row),
        ))),
        DataType::Date32 => Ok(ProtoCellKind::Date32Value(
            array
                .as_any()
                .downcast_ref::<Date32Array>()
                .unwrap()
                .value(row),
        )),
        DataType::Date64 => Ok(ProtoCellKind::Date64Value(
            array
                .as_any()
                .downcast_ref::<Date64Array>()
                .unwrap()
                .value(row),
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
            Ok(ProtoCellKind::Decimal128Value(Bytes::copy_from_slice(
                &v.to_be_bytes(),
            )))
        }
        DataType::Decimal256(_, _) => {
            let v = array
                .as_any()
                .downcast_ref::<Decimal256Array>()
                .unwrap()
                .value(row);
            Ok(ProtoCellKind::Decimal256Value(Bytes::copy_from_slice(
                &v.to_be_bytes(),
            )))
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

fn client_error_to_connect(err: exoware_sdk::ClientError) -> ConnectError {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use futures::channel::oneshot;
    use futures::StreamExt;

    enum ControlledEvent {
        Frame(u64),
        End,
        Error,
    }

    struct ControlledInput {
        events: VecDeque<ControlledEvent>,
        polls: Arc<AtomicUsize>,
    }

    impl Stream for ControlledInput {
        type Item = Result<StreamSubscriptionFrame, ConnectError>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            match self.events.pop_front() {
                Some(ControlledEvent::Frame(sequence_number)) => {
                    std::task::Poll::Ready(Some(Ok(StreamSubscriptionFrame {
                        sequence_number,
                        entries: Vec::new(),
                    })))
                }
                Some(ControlledEvent::End) => std::task::Poll::Ready(None),
                Some(ControlledEvent::Error) => {
                    std::task::Poll::Ready(Some(Err(ConnectError::internal("upstream failed"))))
                }
                None => std::task::Poll::Pending,
            }
        }
    }

    struct ActiveEvaluation(Arc<AtomicUsize>);

    impl Drop for ActiveEvaluation {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    type EvaluationResult = Result<Option<SubscribeResponse>, ConnectError>;

    struct ControlledEvaluator {
        evaluator: BatchEvaluator,
        senders: HashMap<u64, oneshot::Sender<EvaluationResult>>,
        started: Arc<Mutex<Vec<u64>>>,
        max_active: Arc<AtomicUsize>,
    }

    fn controlled_input(
        events: impl IntoIterator<Item = ControlledEvent>,
    ) -> (ControlledInput, Arc<AtomicUsize>) {
        let polls = Arc::new(AtomicUsize::new(0));
        (
            ControlledInput {
                events: events.into_iter().collect(),
                polls: polls.clone(),
            },
            polls,
        )
    }

    fn controlled_evaluator(sequence_numbers: &[u64]) -> ControlledEvaluator {
        let mut senders = HashMap::new();
        let mut receivers = HashMap::new();
        for &sequence_number in sequence_numbers {
            let (sender, receiver) = oneshot::channel();
            senders.insert(sequence_number, sender);
            receivers.insert(sequence_number, receiver);
        }

        let started = Arc::new(Mutex::new(Vec::new()));
        let evaluator_started = started.clone();
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let evaluator_active = active.clone();
        let evaluator_max_active = max_active.clone();
        let evaluator: BatchEvaluator = Box::new(move |frame| {
            let sequence_number = frame.sequence_number;
            evaluator_started.lock().unwrap().push(sequence_number);
            let receiver = receivers
                .remove(&sequence_number)
                .expect("evaluation receiver");
            let active = evaluator_active.clone();
            let max_active = evaluator_max_active.clone();
            async move {
                let active_count = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_active.fetch_max(active_count, Ordering::SeqCst);
                let _active = ActiveEvaluation(active);
                receiver.await.expect("evaluation result")
            }
            .boxed()
        });
        ControlledEvaluator {
            evaluator,
            senders,
            started,
            max_active,
        }
    }

    fn response(sequence_number: u64) -> SubscribeResponse {
        SubscribeResponse {
            sequence_number,
            ..Default::default()
        }
    }

    fn next_ready(
        stream: &mut BatchPredicateStream,
    ) -> Option<Result<SubscribeResponse, ConnectError>> {
        stream
            .next()
            .now_or_never()
            .expect("stream should be ready")
    }

    #[test]
    fn prefetches_one_frame_and_keeps_evaluation_ordered() {
        let (input, polls) = controlled_input([
            ControlledEvent::Frame(1),
            ControlledEvent::Frame(2),
            ControlledEvent::Frame(3),
        ]);
        let mut evaluator = controlled_evaluator(&[1, 2]);
        let mut stream = BatchPredicateStream::with_evaluator(input, evaluator.evaluator);

        assert!(stream.next().now_or_never().is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(*evaluator.started.lock().unwrap(), vec![1]);

        assert!(stream.next().now_or_never().is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(*evaluator.started.lock().unwrap(), vec![1]);

        evaluator
            .senders
            .remove(&1)
            .unwrap()
            .send(Ok(Some(response(1))))
            .unwrap();
        assert_eq!(next_ready(&mut stream).unwrap().unwrap().sequence_number, 1);
        assert_eq!(polls.load(Ordering::SeqCst), 2);

        assert!(stream.next().now_or_never().is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 3);
        assert_eq!(*evaluator.started.lock().unwrap(), vec![1, 2]);

        evaluator
            .senders
            .remove(&2)
            .unwrap()
            .send(Ok(Some(response(2))))
            .unwrap();
        assert_eq!(next_ready(&mut stream).unwrap().unwrap().sequence_number, 2);
        assert_eq!(evaluator.max_active.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn filtered_frame_advances_to_staged_frame() {
        let (input, polls) = controlled_input([
            ControlledEvent::Frame(1),
            ControlledEvent::Frame(2),
            ControlledEvent::End,
        ]);
        let mut evaluator = controlled_evaluator(&[1, 2]);
        let mut stream = BatchPredicateStream::with_evaluator(input, evaluator.evaluator);

        assert!(stream.next().now_or_never().is_none());
        evaluator
            .senders
            .remove(&1)
            .unwrap()
            .send(Ok(None))
            .unwrap();
        assert!(stream.next().now_or_never().is_none());
        assert_eq!(*evaluator.started.lock().unwrap(), vec![1, 2]);
        assert_eq!(polls.load(Ordering::SeqCst), 3);

        evaluator
            .senders
            .remove(&2)
            .unwrap()
            .send(Ok(Some(response(2))))
            .unwrap();
        assert_eq!(next_ready(&mut stream).unwrap().unwrap().sequence_number, 2);
        assert!(next_ready(&mut stream).is_none());
        assert!(next_ready(&mut stream).is_none());
        assert_eq!(evaluator.max_active.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn defers_upstream_end_until_pending_evaluation_finishes() {
        let (input, polls) = controlled_input([ControlledEvent::Frame(1), ControlledEvent::End]);
        let mut evaluator = controlled_evaluator(&[1]);
        let mut stream = BatchPredicateStream::with_evaluator(input, evaluator.evaluator);

        assert!(stream.next().now_or_never().is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 2);

        evaluator
            .senders
            .remove(&1)
            .unwrap()
            .send(Ok(Some(response(1))))
            .unwrap();
        assert_eq!(next_ready(&mut stream).unwrap().unwrap().sequence_number, 1);
        assert!(next_ready(&mut stream).is_none());
        assert!(next_ready(&mut stream).is_none());
    }

    #[test]
    fn defers_upstream_error_until_pending_evaluation_finishes() {
        let (input, polls) = controlled_input([
            ControlledEvent::Frame(1),
            ControlledEvent::Error,
            ControlledEvent::Frame(2),
        ]);
        let mut evaluator = controlled_evaluator(&[1]);
        let mut stream = BatchPredicateStream::with_evaluator(input, evaluator.evaluator);

        assert!(stream.next().now_or_never().is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 2);

        evaluator
            .senders
            .remove(&1)
            .unwrap()
            .send(Ok(Some(response(1))))
            .unwrap();
        assert_eq!(next_ready(&mut stream).unwrap().unwrap().sequence_number, 1);
        assert!(next_ready(&mut stream).unwrap().is_err());
        assert!(next_ready(&mut stream).is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(*evaluator.started.lock().unwrap(), vec![1]);
    }

    #[test]
    fn predicate_error_fuses_and_discards_staged_frame() {
        let (input, polls) = controlled_input([
            ControlledEvent::Frame(1),
            ControlledEvent::Frame(2),
            ControlledEvent::Frame(3),
        ]);
        let mut evaluator = controlled_evaluator(&[1]);
        let mut stream = BatchPredicateStream::with_evaluator(input, evaluator.evaluator);

        assert!(stream.next().now_or_never().is_none());
        evaluator
            .senders
            .remove(&1)
            .unwrap()
            .send(Err(ConnectError::internal("predicate failed")))
            .unwrap();

        assert!(next_ready(&mut stream).unwrap().is_err());
        assert!(next_ready(&mut stream).is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(*evaluator.started.lock().unwrap(), vec![1]);
    }

    /// Result cells for Binary columns can arrive as any of the three arrow
    /// binary encodings; every one becomes a `binary_value` cell.
    #[test]
    fn binary_arrays_convert_to_binary_cells() {
        let body: &[u8] = &[0x00, 0xFF, 0x42];
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(BinaryArray::from_iter_values([body])),
            Arc::new(LargeBinaryArray::from_iter_values([body])),
            Arc::new(BinaryViewArray::from_iter_values([body])),
        ];
        for array in arrays {
            let body_type = array.data_type().clone();
            let cell = arrow_value_to_cell(&array, 0).expect("cell conversion");
            match cell.kind {
                Some(ProtoCellKind::BinaryValue(bytes)) => {
                    assert_eq!(bytes.as_ref(), body, "wrong bytes for {body_type:?}")
                }
                other => panic!("expected binary_value for {body_type:?}, got {other:?}"),
            }
        }
    }
}
