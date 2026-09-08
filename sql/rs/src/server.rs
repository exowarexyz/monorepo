//! Connect-backed server for `sql.v1`.
//!
//! [`SqlServer`] builds a DataFusion session over a [`KvSchema`] and exposes:
//! - [`Service::query`] unary SQL against that session.
//! - [`Service::subscribe`] streaming: for every atomic ingest batch that
//!   touches a registered table's primary-key family, decode its rows
//!   and evaluate the subscriber's SQL `WHERE` predicate against just those
//!   rows. Each matching batch produces one [`SubscribeResponse`] carrying
//!   only the rows that satisfied the predicate.
//!
//! Query results and subscription frames preserve their Arrow schema in IPC streams.
//!
//! Subscription predicates are scalar boolean expressions over the named table.
//! DataFusion compiles each predicate once and filters incoming Arrow batches.
//! Stable functions such as `now()` use the subscription start time. Volatile
//! functions are evaluated for each batch. Subqueries, aggregates, window
//! functions, and row-expanding expressions are not subscription predicates.

#![allow(refining_impl_trait)]

use std::collections::HashMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;

use crate::proto::sql::v1::{
    Column as ProtoColumn, Index as ProtoIndex, IndexLayout as ProtoIndexLayout, QueryRequest,
    QueryResponse, Service, ServiceServer, SubscribeRequest, SubscribeResponse,
    Table as ProtoTable, TablesRequest, TablesResponse,
};
use bytes::Bytes;
use connectrpc::{ConnectError, ConnectRpcService, RequestContext as Context, ServiceRequest};
use datafusion::arrow::datatypes::{DataType, SchemaRef};
use datafusion::arrow::ipc::writer::StreamWriter;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::{DFSchema, DataFusionError, Result as DataFusionResult, TableReference};
use datafusion::execution::SessionStateBuilder;
use datafusion::logical_expr::{simplify::SimplifyContext, Expr, ExprSchemable};
use datafusion::optimizer::simplify_expressions::ExprSimplifier;
use datafusion::physical_expr::PhysicalExpr;
use datafusion::physical_plan::filter::batch_filter;
use datafusion::prelude::SessionContext;
use exoware_sdk::keys::Key;
use exoware_sdk::kv_codec::{decode_stored_row, Utf8};
use exoware_sdk::selector::Selector;
use exoware_sdk::stream_filter::StreamFilter;
use exoware_sdk::{PrefixedStoreClient, StreamSubscription, StreamSubscriptionFrame};
use futures::stream::{self, Stream};
use futures::{FutureExt, TryStreamExt};

use crate::builder::ProjectedBatchBuilder;
use crate::codec::decode_primary_key_selected;
use crate::filter::ScanAccessPlan;
use crate::predicate::QueryPredicate;
use crate::schema::KvSchema;
use crate::types::{IndexLayout, RequestReadSession, ResolvedIndexSpec, TableModel};

const MAX_CONNECTRPC_BODY_BYTES: usize = 256 * 1024 * 1024;

type SubscribeStream = Pin<Box<dyn Stream<Item = Result<SubscribeResponse, ConnectError>> + Send>>;

/// Build a query context whose Store scans share the supplied minimum sequence.
pub fn query_context_with_min_sequence(
    ctx: &SessionContext,
    store: &PrefixedStoreClient,
    min_sequence_number: u64,
) -> SessionContext {
    let read_session = store.create_session_with_sequence(min_sequence_number);

    // Extend the cloned state before rebuilding so DataFusion preserves its catalog.
    let mut state = ctx.state();
    state
        .config_mut()
        .set_extension(Arc::new(RequestReadSession(read_session)));
    let state = SessionStateBuilder::new_from_existing(state).build();
    SessionContext::new_with_state(state)
}

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
    fn new(model: Arc<TableModel>, indexes: Arc<Vec<ResolvedIndexSpec>>) -> Self {
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
            indexes,
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
    /// scalar predicate compilation on `Subscribe`.
    pub fn new(schema: KvSchema) -> DataFusionResult<Self> {
        let store = schema.client().clone();
        let mut streams = HashMap::with_capacity(schema.tables().len());
        let mut table_names = Vec::with_capacity(schema.tables().len());
        for (name, table) in schema.tables() {
            streams.insert(
                name.clone(),
                TableStream::new(table.model.clone(), table.index_specs.clone()),
            );
            table_names.push(name.clone());
        }
        let ctx = crate::session_context();
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

    fn query_session(
        &self,
        min_sequence_number: u64,
    ) -> (SessionContext, exoware_sdk::SerializableReadSession) {
        let ctx = query_context_with_min_sequence(&self.ctx, &self.store, min_sequence_number);
        let read_session = crate::types::request_read_session(&ctx.state())
            .expect("query context must retain its Store read session");
        (ctx, read_session)
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
                .with_max_request_body_size(MAX_CONNECTRPC_BODY_BYTES)
                .with_max_message_size(MAX_CONNECTRPC_BODY_BYTES),
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
        request: ServiceRequest<'_, SubscribeRequest>,
    ) -> impl Future<Output = connectrpc::ServiceResult<SubscribeStream>> + Send {
        let server = self.server.clone();
        async move {
            let table_name = request.table.to_string();
            let where_sql = request.where_sql.trim().to_string();
            let since = request.since_sequence_number.filter(|seq| *seq != 0);
            let stream = server.stream(&table_name)?.clone();
            let predicate = compile_subscription_predicate(
                &server.ctx,
                &stream.schema,
                &table_name,
                &where_sql,
            )
            .map_err(datafusion_error_to_connect)?;

            let filter = StreamFilter {
                selectors: vec![stream.selector.clone()],
                value_filters: vec![],
            };
            let sub = server
                .store
                .stream()
                .subscribe(filter, since)
                .await
                .map_err(|err| client_error_to_connect(&err))?;

            let output = Box::pin(BatchPredicateStream::new(sub, stream, predicate));
            Ok(connectrpc::Response::stream(output as SubscribeStream))
        }
    }

    fn tables(
        &self,
        _ctx: Context,
        _request: ServiceRequest<'_, TablesRequest>,
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
        request: ServiceRequest<'_, QueryRequest>,
    ) -> impl Future<Output = connectrpc::ServiceResult<QueryResponse>> + Send {
        let server = self.server.clone();
        AssertUnwindSafe(async move {
            let sql = request.sql.to_string();
            let min_sequence_number = request.min_sequence_number.unwrap_or_default();
            let (ctx, read_session) = server.query_session(min_sequence_number);
            let df = ctx.sql(&sql).await.map_err(datafusion_error_to_connect)?;
            let mut batches = df
                .execute_stream()
                .await
                .map_err(datafusion_error_to_connect)?;
            let mut writer = StreamWriter::try_new(Vec::new(), &batches.schema())
                .map_err(|error| datafusion_error_to_connect(error.into()))?;
            while let Some(batch) = batches
                .try_next()
                .await
                .map_err(datafusion_error_to_connect)?
            {
                writer
                    .write(&batch)
                    .map_err(|error| datafusion_error_to_connect(error.into()))?;
            }
            let results = writer
                .into_inner()
                .map_err(|error| datafusion_error_to_connect(error.into()))?
                .into();
            // Queries that skip Store reads preserve the requested floor.
            let sequence_number = read_session
                .evaluated_sequence()
                .unwrap_or(min_sequence_number);
            connectrpc::Response::ok(QueryResponse {
                results,
                sequence_number,
                ..Default::default()
            })
        })
        .catch_unwind()
        .map(|result| {
            result.unwrap_or_else(|_| Err(ConnectError::internal("SQL query execution panicked")))
        })
    }
}

type BatchEvaluator = Box<
    dyn FnMut(StreamSubscriptionFrame) -> Result<Option<SubscribeResponse>, ConnectError> + Send,
>;
type SubscriptionStream =
    Pin<Box<dyn Stream<Item = Result<StreamSubscriptionFrame, ConnectError>> + Send>>;
type SubscriptionEvent = Option<Result<StreamSubscriptionFrame, ConnectError>>;

const MAX_FILTERED_FRAMES_PER_POLL: usize = 16;

struct BatchPredicateStream {
    upstream: SubscriptionStream,
    evaluator: BatchEvaluator,
    staged: Option<SubscriptionEvent>,
    done: bool,
}

impl BatchPredicateStream {
    fn new(
        sub: StreamSubscription,
        state: TableStream,
        predicate: Option<Arc<dyn PhysicalExpr>>,
    ) -> Self {
        let upstream = subscription_stream(sub);
        let evaluator = move |frame: StreamSubscriptionFrame| {
            let sequence_number = frame.sequence_number;
            let entries = frame
                .entries
                .into_iter()
                .map(|entry| (entry.key, entry.value))
                .collect();
            evaluate_batch(&state, predicate.as_ref(), sequence_number, entries)
        };
        Self::with_evaluator(upstream, evaluator)
    }

    fn with_evaluator<S, E>(upstream: S, evaluator: E) -> Self
    where
        S: Stream<Item = Result<StreamSubscriptionFrame, ConnectError>> + Send + 'static,
        E: FnMut(StreamSubscriptionFrame) -> Result<Option<SubscribeResponse>, ConnectError>
            + Send
            + 'static,
    {
        Self {
            upstream: Box::pin(upstream),
            evaluator: Box::new(evaluator),
            staged: None,
            done: false,
        }
    }
}

fn subscription_stream(sub: StreamSubscription) -> SubscriptionStream {
    Box::pin(stream::unfold(Some(sub), |sub| async move {
        let mut sub = sub?;
        match sub.next().await {
            Ok(Some(frame)) => Some((Ok(frame), Some(sub))),
            Ok(None) => None,
            Err(err) => Some((Err(client_error_to_connect(&err)), None)),
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

        for _ in 0..MAX_FILTERED_FRAMES_PER_POLL {
            let event = match this.staged.take() {
                Some(event) => event,
                None => match this.upstream.as_mut().poll_next(cx) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(event) => event,
                },
            };

            let frame = match event {
                Some(Ok(frame)) => frame,
                Some(Err(err)) => {
                    this.done = true;
                    return std::task::Poll::Ready(Some(Err(err)));
                }
                None => {
                    this.done = true;
                    return std::task::Poll::Ready(None);
                }
            };
            // Register demand for one later frame before evaluating this batch
            if let std::task::Poll::Ready(event) = this.upstream.as_mut().poll_next(cx) {
                this.staged = Some(event);
            }
            match (this.evaluator)(frame) {
                Ok(Some(response)) => return std::task::Poll::Ready(Some(Ok(response))),
                Ok(None) => {}
                Err(err) => {
                    this.staged = None;
                    this.done = true;
                    return std::task::Poll::Ready(Some(Err(err)));
                }
            }
        }
        // Yield after a run of rejected frames so cancellation and other tasks can progress
        cx.waker().wake_by_ref();
        std::task::Poll::Pending
    }
}

fn evaluate_batch(
    state: &TableStream,
    predicate: Option<&Arc<dyn PhysicalExpr>>,
    sequence_number: u64,
    entries: Vec<(Key, Bytes)>,
) -> Result<Option<SubscribeResponse>, ConnectError> {
    let batch = state
        .decode_batch(&entries)
        .map_err(datafusion_error_to_connect)?;
    if batch.num_rows() == 0 {
        return Ok(None);
    }

    let filtered = match predicate {
        Some(predicate) => batch_filter(&batch, predicate).map_err(datafusion_error_to_connect)?,
        None => batch,
    };
    if filtered.num_rows() == 0 {
        return Ok(None);
    }

    let mut writer = StreamWriter::try_new(Vec::new(), &filtered.schema())
        .map_err(|error| datafusion_error_to_connect(error.into()))?;
    writer
        .write(&filtered)
        .map_err(|error| datafusion_error_to_connect(error.into()))?;
    let results = writer
        .into_inner()
        .map_err(|error| datafusion_error_to_connect(error.into()))?
        .into();
    Ok(Some(SubscribeResponse {
        sequence_number,
        results,
        ..Default::default()
    }))
}

fn compile_subscription_predicate(
    ctx: &SessionContext,
    schema: &SchemaRef,
    table_name: &str,
    where_sql: &str,
) -> DataFusionResult<Option<Arc<dyn PhysicalExpr>>> {
    if where_sql.trim().is_empty() {
        return Ok(None);
    }
    let df_schema = DFSchema::try_from_qualified_schema(TableReference::bare(table_name), schema)?;
    let expression = ctx.parse_sql_expr(where_sql, &df_schema)?;
    expression.apply(|expr| {
        if matches!(
            expr,
            Expr::AggregateFunction(_)
                | Expr::WindowFunction(_)
                | Expr::Exists(_)
                | Expr::InSubquery(_)
                | Expr::SetComparison(_)
                | Expr::ScalarSubquery(_)
                | Expr::GroupingSet(_)
                | Expr::Placeholder(_)
                | Expr::OuterReferenceColumn(_, _)
                | Expr::Unnest(_)
        ) {
            return Err(DataFusionError::Plan(
                "subscription predicate must be a scalar boolean expression over the named table"
                    .to_string(),
            ));
        }
        Ok(TreeNodeRecursion::Continue)
    })?;
    let state = ctx.state();
    let context = SimplifyContext::builder()
        .with_schema(Arc::new(df_schema.clone()))
        .with_config_options(state.config_options().clone())
        .with_query_execution_start_time(state.execution_props().query_execution_start_time)
        .build();
    let simplifier = ExprSimplifier::new(context);
    let expression = simplifier.coerce(expression, &df_schema)?;
    let expression = match expression.get_type(&df_schema)? {
        DataType::Boolean => expression,
        DataType::Null => expression.cast_to(&DataType::Boolean, &df_schema)?,
        data_type => {
            return Err(DataFusionError::Plan(format!(
                "subscription predicate must return Boolean, got {data_type}"
            )))
        }
    };
    state
        .create_physical_expr(simplifier.simplify(expression)?, &df_schema)
        .map(Some)
}

fn datafusion_error_to_connect(err: DataFusionError) -> ConnectError {
    // DataFusion wraps planner errors in Diagnostic and Context layers, so classify the root cause.
    match err.find_root() {
        DataFusionError::Plan(msg)
        | DataFusionError::Configuration(msg)
        | DataFusionError::NotImplemented(msg) => ConnectError::invalid_argument(msg.clone()),
        DataFusionError::SQL(parser_error, _) => {
            ConnectError::invalid_argument(parser_error.to_string())
        }
        DataFusionError::SchemaError(schema_error, _) => {
            ConnectError::invalid_argument(schema_error.to_string())
        }
        DataFusionError::External(external) => {
            match external.downcast_ref::<exoware_sdk::ClientError>() {
                Some(client_error) => client_error_to_connect(client_error),
                None => ConnectError::internal(err.to_string()),
            }
        }
        _ => ConnectError::internal(err.to_string()),
    }
}

fn client_error_to_connect(err: &exoware_sdk::ClientError) -> ConnectError {
    if let Some(rpc) = err.rpc_error() {
        ConnectError::new(rpc.code, rpc.message.clone().unwrap_or_default())
    } else {
        ConnectError::internal(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::array::{
        Array, ArrayRef, BinaryViewArray, Date32Array, Date64Array, Decimal256Array,
        FixedSizeBinaryBuilder, Int64Array, LargeListArray, StringArray, StringViewArray,
    };
    use datafusion::arrow::compute::concat_batches;
    use datafusion::arrow::datatypes::{i256, Int64Type, Schema};
    use datafusion::arrow::ipc::reader::StreamReader;
    use datafusion::arrow::record_batch::RecordBatchOptions;
    use datafusion::datasource::MemTable;
    use datafusion::logical_expr::{create_udf, ColumnarValue, Volatility};
    use exoware_sdk::StoreClient;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use futures::{FutureExt, StreamExt};

    fn check_ipc_fixture(name: &str, ipc: &[u8]) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ts/tests/fixtures")
            .join(name);
        if std::env::var_os("UPDATE_SQL_IPC_FIXTURES").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, ipc).unwrap();
        }
        assert_eq!(std::fs::read(&path).unwrap(), ipc, "{}", path.display());
    }

    fn ipc_layout_batch() -> RecordBatch {
        let mut zero = FixedSizeBinaryBuilder::new(0);
        zero.append_value([]).unwrap();
        zero.append_null();
        zero.append_value([]).unwrap();
        let mut wide = FixedSizeBinaryBuilder::new(300);
        wide.append_value([7; 300]).unwrap();
        wide.append_null();
        wide.append_value([9; 300]).unwrap();
        let arrays: Vec<(&str, ArrayRef)> = vec![
            (
                "dates",
                Arc::new(Date64Array::from(vec![
                    Some(9_223_372_036_828_800_000),
                    None,
                    Some(-9_223_372_036_828_800_000),
                ])),
            ),
            ("binary0", Arc::new(zero.finish())),
            ("binary300", Arc::new(wide.finish())),
            (
                "text_view",
                Arc::new(StringViewArray::from(vec![
                    Some("short"),
                    Some("this value lives outside the inline view"),
                    None,
                ])),
            ),
            (
                "binary_view",
                Arc::new(BinaryViewArray::from_iter([
                    Some(b"abc".as_slice()),
                    Some(b"this binary value also exceeds twelve bytes".as_slice()),
                    None,
                ])),
            ),
            (
                "large_list",
                Arc::new(LargeListArray::from_iter_primitive::<Int64Type, _, _>([
                    Some(vec![Some(1), None]),
                    None,
                    Some(vec![]),
                ])),
            ),
            (
                "decimal256",
                Arc::new(
                    Decimal256Array::from(vec![
                        Some(i256::from_i128(-12345)),
                        None,
                        Some(i256::from_i128(9007199254740993)),
                    ])
                    .with_precision_and_scale(50, 2)
                    .unwrap(),
                ),
            ),
            ("all_null", Arc::new(Date32Array::from(vec![None; 3]))),
        ];
        let batch = RecordBatch::try_from_iter(arrays).unwrap();
        let schema = Schema::new_with_metadata(
            batch.schema().fields().clone(),
            HashMap::from([("source".to_string(), "native IPC fixture".to_string())]),
        );
        batch.with_schema(Arc::new(schema)).unwrap()
    }

    #[tokio::test]
    async fn query_encoding_preserves_computed_result_types() {
        use crate::proto::sql::v1::ServiceClient;
        use connectrpc::client::{ClientConfig, HttpClient};

        let schema = KvSchema::new(PrefixedStoreClient::empty(exoware_sdk::StoreClient::new(
            "http://127.0.0.1:1",
        )));
        let server = Arc::new(SqlServer::new(schema).unwrap());
        let layouts = ipc_layout_batch();
        server
            .session()
            .register_table(
                "layouts",
                Arc::new(
                    MemTable::try_new(
                        layouts.schema(),
                        vec![vec![layouts.slice(0, 1), layouts.slice(1, 2)]],
                    )
                    .unwrap(),
                ),
            )
            .unwrap();
        let zero_columns = RecordBatch::try_new_with_options(
            Arc::new(Schema::empty()),
            vec![],
            &RecordBatchOptions::new().with_row_count(Some(3)),
        )
        .unwrap();
        server
            .session()
            .register_table(
                "zero_columns",
                Arc::new(
                    MemTable::try_new(zero_columns.schema(), vec![vec![zero_columns]]).unwrap(),
                ),
            )
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new().fallback_service(sql_connect_stack(server.clone()));
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = ServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(format!("http://{address}").parse().unwrap()),
        );
        let computed = r#"SELECT
            to_timestamp_seconds(1) AS seconds,
            to_timestamp_millis(1) AS milliseconds,
            to_timestamp_micros(1) AS microseconds,
            to_timestamp_nanos(1735689600123456789) AS nanoseconds,
            arrow_cast(to_timestamp_nanos(1735689600123456789), 'Timestamp(Nanosecond, Some("UTC"))') AS zoned,
            CAST(1 AS DECIMAL(10, 0)) AS decimal_integer,
            CAST(0.01 AS DECIMAL(10, 2)) AS decimal_fraction,
            arrow_cast(-12345, 'Decimal64(12, 2)') AS decimal64_negative,
            CAST(-7 AS TINYINT) AS tiny,
            CAST(-300 AS SMALLINT) AS small,
            named_struct('value', 42, 'missing', CAST(NULL AS TEXT)) AS nested,
            map(['a', 'b'], [1, NULL]) AS mapping,
            INTERVAL '1 month 2 days 3 seconds' AS duration,
            arrow_cast(100000001, 'Date32') AS date32_far,
            arrow_cast(-100000001, 'Date32') AS date32_negative,
            arrow_cast(8640000086400000, 'Date64') AS date64_far,
            arrow_cast(9223372036854775807, 'Timestamp(Second, None)') AS seconds_extreme"#;
        for (name, sql) in [
            ("computed.arrow", computed.to_string()),
            ("layouts.arrow", "SELECT * FROM layouts".to_string()),
            ("empty.arrow", format!("{computed} WHERE FALSE")),
            (
                "zero_columns.arrow",
                "SELECT * FROM zero_columns".to_string(),
            ),
            (
                "duplicates.arrow",
                "SELECT a.id, b.id FROM (VALUES (1)) a(id) CROSS JOIN (VALUES ('two')) b(id)"
                    .to_string(),
            ),
        ] {
            let frame = server.session().sql(&sql).await.unwrap();
            let stream = frame.execute_stream().await.unwrap();
            let schema = stream.schema();
            let expected: Vec<_> = stream.try_collect().await.unwrap();
            let response = client
                .query(QueryRequest {
                    sql,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_owned();
            let reader = StreamReader::try_new(response.results.as_ref(), None).unwrap();
            assert_eq!(reader.schema(), schema, "{name}");
            let actual = reader.collect::<Result<Vec<_>, _>>().unwrap();
            assert_eq!(
                concat_batches(&schema, &actual).unwrap(),
                concat_batches(&schema, &expected).unwrap(),
                "{name}"
            );
            check_ipc_fixture(name, &response.results);
        }
        task.abort();
    }

    #[tokio::test]
    async fn query_rpc_returns_internal_on_count_overflow_and_remains_usable() {
        use crate::proto::sql::v1::ServiceClient;
        use crate::TableColumnConfig;
        use buffa::Message;
        use connectrpc::client::{ClientConfig, HttpClient};
        use datafusion::execution::memory_pool::{FairSpillPool, MemoryPool, PeakRecordingPool};
        use datafusion::execution::runtime_env::RuntimeEnvBuilder;
        use datafusion::prelude::SessionConfig;
        use exoware_sdk::kv_codec::KvReducedValue;
        use exoware_sdk::{RangeReduceGroup, RangeReduceResponse, RangeReduceResult, StoreClient};

        #[derive(Clone, Default)]
        struct OverflowReduceTransport {
            requests: Arc<Mutex<Vec<exoware_sdk::query::ReduceRequest>>>,
        }

        impl connectrpc::client::ClientTransport for OverflowReduceTransport {
            type ResponseBody = axum::body::Body;
            type Error = ConnectError;

            fn send(
                &self,
                request: axum::http::Request<connectrpc::client::ClientBody>,
            ) -> connectrpc::client::BoxFuture<
                'static,
                Result<axum::http::Response<Self::ResponseBody>, Self::Error>,
            > {
                let transport = self.clone();
                Box::pin(async move {
                    assert_eq!(request.uri().path(), "/store.query.v1.Service/Reduce");
                    let body = axum::body::to_bytes(
                        axum::body::Body::new(request.into_body()),
                        usize::MAX,
                    )
                    .await
                    .unwrap();
                    let request = crate::tests::decode_reduce_request(&body);
                    let first = {
                        let mut requests = transport.requests.lock().unwrap();
                        let first = requests.is_empty();
                        requests.push(request.clone());
                        first
                    };
                    let average = request.params.reducers.iter().any(|reducer| {
                        reducer.op.as_known() == Some(exoware_sdk::query::RangeReduceOp::SumField)
                    });
                    let count = if first {
                        if average {
                            u64::MAX
                        } else {
                            i64::MAX as u64
                        }
                    } else {
                        1
                    };
                    let results = request
                        .params
                        .reducers
                        .iter()
                        .map(|reducer| {
                            let value = match reducer.op.as_known().unwrap() {
                                exoware_sdk::query::RangeReduceOp::CountAll
                                | exoware_sdk::query::RangeReduceOp::CountField => {
                                    KvReducedValue::UInt64(count)
                                }
                                exoware_sdk::query::RangeReduceOp::SumField => {
                                    KvReducedValue::Float64(1.0)
                                }
                                other => panic!("unexpected reducer {other:?}"),
                            };
                            RangeReduceResult { value: Some(value) }
                        })
                        .collect();
                    let response = if request.params.group_by.is_empty() {
                        RangeReduceResponse {
                            results,
                            groups: vec![],
                        }
                    } else {
                        RangeReduceResponse {
                            results: vec![],
                            groups: vec![RangeReduceGroup {
                                group_values: vec![Some(KvReducedValue::Int64(7))],
                                results,
                            }],
                        }
                    };
                    let (results, groups) = exoware_sdk::to_proto_reduce_response(response);
                    let response = exoware_sdk::query::ReduceResponse {
                        results,
                        groups,
                        detail: Some(exoware_sdk::query::Detail {
                            sequence_number: 7,
                            ..Default::default()
                        })
                        .into(),
                        ..Default::default()
                    };
                    let mut body = connectrpc::envelope::Envelope::data(response.encode_to_bytes())
                        .encode()
                        .to_vec();
                    body.extend_from_slice(
                        &connectrpc::envelope::Envelope::end_stream(Bytes::from_static(b"{}"))
                            .encode(),
                    );
                    Ok(axum::http::Response::builder()
                        .header("content-type", "application/connect+proto")
                        .body(axum::body::Body::from(body))
                        .unwrap())
                })
            }
        }

        let transport = OverflowReduceTransport::default();
        let client = StoreClient::builder()
            .url("http://faulty-store.test")
            .client_transport(transport.clone())
            .retry_config(exoware_sdk::RetryConfig::disabled())
            .build()
            .unwrap();
        let schema = KvSchema::new(PrefixedStoreClient::empty(client))
            .table(
                "counts",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("category", DataType::Int64, false),
                    TableColumnConfig::new("value", DataType::Float64, true),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();
        let mut server = SqlServer::new(schema).unwrap();
        let pool = Arc::new(PeakRecordingPool::new(Arc::new(FairSpillPool::new(
            8 * 1024 * 1024,
        ))));
        let runtime = RuntimeEnvBuilder::new()
            .with_memory_pool(pool.clone())
            .build_arc()
            .unwrap();
        let ctx = SessionContext::new_with_state(
            crate::session_state_builder()
                .with_runtime_env(runtime)
                .with_config(SessionConfig::new().with_target_partitions(1))
                .build(),
        );
        ctx.register_table(
            "counts",
            server.session().table_provider("counts").await.unwrap(),
        )
        .unwrap();
        server.ctx = Arc::new(ctx);
        let server = Arc::new(server);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new().fallback_service(sql_connect_stack(server));
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = ServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(format!("http://{address}").parse().unwrap())
                .with_default_timeout(std::time::Duration::from_secs(5)),
        );
        for aggregate in ["COUNT(*)", "AVG(value)"] {
            for grouped in [true, false] {
                transport.requests.lock().unwrap().clear();
                pool.reset_peak();
                let (key, group_by) = if grouped {
                    ("category, ", " GROUP BY category")
                } else {
                    ("", "")
                };
                let sql =
                    format!("SELECT {key}{aggregate} FROM counts WHERE id IN (1, 3){group_by}");
                let error = client
                    .query(QueryRequest {
                        sql: sql.clone(),
                        ..Default::default()
                    })
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.code,
                    connectrpc::ErrorCode::Internal,
                    "{sql}: {error}"
                );
                assert_eq!(
                    error.message.as_deref(),
                    Some("SQL query execution panicked"),
                    "{sql}"
                );
                assert_eq!(pool.reserved(), 0, "query reservation after panic: {sql}");
                if grouped {
                    assert!(
                        pool.peak_reserved() > 0,
                        "first partial must reach Final aggregation: {sql}"
                    );
                }
                {
                    let requests = transport.requests.lock().unwrap();
                    assert_eq!(requests.len(), 2, "{sql}: {requests:?}");
                    assert!(
                        requests[0].end < requests[1].start,
                        "disjoint ranges: {sql}"
                    );
                    assert_eq!(requests[0].params, requests[1].params, "{sql}");
                    assert_eq!(requests[0].min_sequence_number, None);
                    assert_eq!(requests[1].min_sequence_number, Some(7));
                    assert_eq!(requests[0].params.group_by.len(), usize::from(grouped));
                }
                let response = client
                    .query(QueryRequest {
                        sql: "SELECT 1".into(),
                        ..Default::default()
                    })
                    .await
                    .unwrap()
                    .into_owned();
                let batch = StreamReader::try_new(response.results.as_ref(), None)
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap();
                assert_eq!(batch.num_rows(), 1);
                assert_eq!(
                    batch
                        .column(0)
                        .as_any()
                        .downcast_ref::<Int64Array>()
                        .unwrap()
                        .value(0),
                    1
                );
                assert_eq!(transport.requests.lock().unwrap().len(), 2);
            }
        }
        let error = client
            .query(QueryRequest {
                sql: "SELECT FROM".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
        task.abort();
    }

    #[tokio::test]
    async fn query_parse_errors_map_to_invalid_argument() {
        let ctx = SessionContext::new();
        let DataFusionError::SQL(parser_error, _) = ctx.sql("SELECT FROM").await.unwrap_err()
        else {
            panic!("malformed SQL did not return a parser error");
        };
        let expected_message = parser_error.to_string();
        for backtrace in [None, Some("backtrace ...".to_string())] {
            let connect_error =
                datafusion_error_to_connect(DataFusionError::SQL(parser_error.clone(), backtrace));
            assert_eq!(connect_error.code, connectrpc::ErrorCode::InvalidArgument);
            assert_eq!(
                connect_error.message.as_deref(),
                Some(expected_message.as_str()),
            );
        }
    }

    #[tokio::test]
    async fn wrapped_planning_errors_map_to_invalid_argument() {
        let ctx = SessionContext::new();
        for sql in ["SELECT * FROM nope", "SELECT 1 + 'a'", "SELECT 1 LIMIT 'x'"] {
            let query_error = match ctx.sql(sql).await {
                Ok(frame) => frame.create_physical_plan().await.unwrap_err(),
                Err(err) => err,
            };
            assert!(
                matches!(
                    query_error,
                    DataFusionError::Diagnostic(..) | DataFusionError::Context(..)
                ),
                "{sql}: {query_error:?}"
            );
            let DataFusionError::Plan(expected_message) = query_error.find_root() else {
                panic!("{sql}: {query_error:?}");
            };
            let expected_message = expected_message.clone();
            let connect_error = datafusion_error_to_connect(query_error);
            assert_eq!(
                connect_error.code,
                connectrpc::ErrorCode::InvalidArgument,
                "{sql}"
            );
            assert_eq!(
                connect_error.message.as_deref(),
                Some(expected_message.as_str()),
                "{sql}"
            );
        }
    }

    #[test]
    fn query_context_installs_the_supplied_store_sequence_floor() {
        let ctx = SessionContext::new();
        let store = PrefixedStoreClient::empty(StoreClient::new("http://localhost:10000"));
        let query_ctx = query_context_with_min_sequence(&ctx, &store, 41);
        let first = crate::types::request_read_session(&query_ctx.state()).unwrap();
        let second = crate::types::request_read_session(&query_ctx.state()).unwrap();

        assert_eq!(first.fixed_sequence(), Some(41));
        assert_eq!(second.fixed_sequence(), Some(41));
        assert!(crate::types::request_read_session(&ctx.state()).is_none());
    }

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
    fn prefetches_one_frame_before_evaluation_and_preserves_order() {
        let (input, polls) = controlled_input([
            ControlledEvent::Frame(1),
            ControlledEvent::Frame(2),
            ControlledEvent::Frame(3),
            ControlledEvent::End,
        ]);
        let evaluation_polls = polls.clone();
        let started = Arc::new(Mutex::new(Vec::new()));
        let evaluations = started.clone();
        let mut output = BatchPredicateStream::with_evaluator(input, move |frame| {
            assert_eq!(
                evaluation_polls.load(Ordering::SeqCst),
                frame.sequence_number as usize + 1,
                "one later frame must be polled before evaluation",
            );
            evaluations.lock().unwrap().push(frame.sequence_number);
            Ok(Some(response(frame.sequence_number)))
        });
        for sequence in 1..=3 {
            assert_eq!(
                next_ready(&mut output).unwrap().unwrap().sequence_number,
                sequence
            );
            assert_eq!(started.lock().unwrap().len(), sequence as usize);
        }
        assert!(next_ready(&mut output).is_none());
        assert!(next_ready(&mut output).is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn filtered_frame_advances_to_staged_frame() {
        let (input, polls) = controlled_input([
            ControlledEvent::Frame(1),
            ControlledEvent::Frame(2),
            ControlledEvent::End,
        ]);
        let mut output = BatchPredicateStream::with_evaluator(input, |frame| {
            Ok((frame.sequence_number == 2).then(|| response(frame.sequence_number)))
        });
        assert_eq!(next_ready(&mut output).unwrap().unwrap().sequence_number, 2);
        assert!(next_ready(&mut output).is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn upstream_error_follows_the_preceding_frame_and_fuses() {
        let (input, polls) = controlled_input([
            ControlledEvent::Frame(1),
            ControlledEvent::Error,
            ControlledEvent::Frame(2),
        ]);
        let mut output = BatchPredicateStream::with_evaluator(input, |frame| {
            Ok(Some(response(frame.sequence_number)))
        });
        assert_eq!(next_ready(&mut output).unwrap().unwrap().sequence_number, 1);
        assert!(next_ready(&mut output).unwrap().is_err());
        assert!(next_ready(&mut output).is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn predicate_error_discards_the_staged_frame_and_fuses() {
        let (input, polls) = controlled_input([
            ControlledEvent::Frame(1),
            ControlledEvent::Frame(2),
            ControlledEvent::Frame(3),
        ]);
        let mut output = BatchPredicateStream::with_evaluator(input, |frame| {
            assert_eq!(frame.sequence_number, 1);
            Err(ConnectError::internal("predicate failed"))
        });
        assert!(next_ready(&mut output).unwrap().is_err());
        assert!(next_ready(&mut output).is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn rejected_frames_yield_and_cancellation_drops_upstream() {
        let (input, polls) = controlled_input(
            (0..MAX_FILTERED_FRAMES_PER_POLL + 2).map(|seq| ControlledEvent::Frame(seq as u64)),
        );
        let mut output = BatchPredicateStream::with_evaluator(input, |_| Ok(None));
        assert!(output.next().now_or_never().is_none());
        assert_eq!(
            polls.load(Ordering::SeqCst),
            MAX_FILTERED_FRAMES_PER_POLL + 1
        );
        assert_eq!(Arc::strong_count(&polls), 2);
        drop(output);
        assert_eq!(Arc::strong_count(&polls), 1);
    }

    fn predicate_batch() -> RecordBatch {
        RecordBatch::try_from_iter(vec![
            (
                "id",
                Arc::new(Int64Array::from(vec![1, 2, 3, 4])) as ArrayRef,
            ),
            (
                "status",
                Arc::new(StringArray::from(vec![
                    Some("12"),
                    Some("bad"),
                    None,
                    Some("30"),
                ])) as ArrayRef,
            ),
        ])
        .unwrap()
    }

    fn matching_ids(predicate: &Arc<dyn PhysicalExpr>, batch: &RecordBatch) -> Vec<i64> {
        let filtered = batch_filter(batch, predicate).unwrap();
        filtered
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap()
            .values()
            .to_vec()
    }

    #[tokio::test]
    async fn subscription_scalar_predicates_match_sql_results() {
        use datafusion::datasource::MemTable;

        let batch = predicate_batch();
        let ctx = SessionContext::new();
        ctx.register_table(
            "orders",
            Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch.clone()]]).unwrap()),
        )
        .unwrap();
        for sql in [
            "orders.id >= 2 AND orders.status IS NOT NULL",
            "TRY_CAST(status AS BIGINT) IS NULL",
            "CAST(id AS DOUBLE) / 2 > 1",
            "id IN (1, NULL, 4)",
            "status = '12' OR status IS NULL",
            "NULL",
            "CASE WHEN status IS NULL THEN true ELSE id > 3 END",
        ] {
            let predicate = compile_subscription_predicate(&ctx, &batch.schema(), "orders", sql)
                .unwrap()
                .unwrap();
            let native = ctx
                .sql(&format!("SELECT * FROM orders WHERE {sql}"))
                .await
                .unwrap()
                .collect()
                .await
                .unwrap();
            let expected: Vec<i64> = native
                .iter()
                .flat_map(|batch| {
                    batch
                        .column(0)
                        .as_any()
                        .downcast_ref::<Int64Array>()
                        .unwrap()
                        .values()
                        .to_vec()
                })
                .collect();
            assert_eq!(matching_ids(&predicate, &batch), expected, "{sql}");
            assert_eq!(matching_ids(&predicate, &batch), expected, "reused {sql}");
        }
    }

    #[test]
    fn subscription_rejects_non_scalar_and_non_boolean_predicates() {
        let ctx = SessionContext::new();
        let batch = predicate_batch();
        for sql in [
            "id + 1",
            "SUM(id) > 0",
            "row_number() OVER () > 0",
            "id = (SELECT 1)",
            "id IN (SELECT 1)",
            "EXISTS (SELECT 1)",
            "TRUE OR id = (SELECT 1)",
            "unnest([1, 2]) > 0",
            "id = $1",
            "missing.id = 1",
            "id >",
        ] {
            assert!(
                compile_subscription_predicate(&ctx, &batch.schema(), "orders", sql).is_err(),
                "accepted {sql}"
            );
        }
        assert!(
            compile_subscription_predicate(&ctx, &batch.schema(), "orders", "  ")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn subscription_quoted_table_names_are_resolved_without_sql_interpolation() {
        let ctx = SessionContext::new();
        let batch = predicate_batch();
        let predicate = compile_subscription_predicate(
            &ctx,
            &batch.schema(),
            "Order Events",
            "\"Order Events\".id = 2",
        )
        .unwrap()
        .unwrap();
        assert_eq!(matching_ids(&predicate, &batch), vec![2]);
    }

    #[test]
    fn subscription_evaluates_decoded_frames_and_preserves_their_sequence() {
        let ctx = SessionContext::new();
        let batch = predicate_batch();
        let schema = KvSchema::new(exoware_sdk::PrefixedStoreClient::empty(
            exoware_sdk::StoreClient::new("http://127.0.0.1:1"),
        ))
        .table(
            "orders",
            vec![
                crate::TableColumnConfig::new("id", DataType::Int64, false),
                crate::TableColumnConfig::new("status", DataType::Utf8, true),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let table = &schema.tables()[0].1;
        let state = TableStream::new(table.model.clone(), table.index_specs.clone());
        let entries =
            crate::writer::encode_insert_entries(&batch, &table.model, &table.index_specs)
                .unwrap()
                .into_iter()
                .map(|(key, value)| (key, Bytes::from(value)))
                .collect();
        let predicate = compile_subscription_predicate(
            &ctx,
            &batch.schema(),
            "orders",
            "TRY_CAST(status AS BIGINT) IS NULL",
        )
        .unwrap();
        let response = evaluate_batch(&state, predicate.as_ref(), 42, entries)
            .unwrap()
            .unwrap();
        assert_eq!(response.sequence_number, 42);
        let reader = StreamReader::try_new(response.results.as_ref(), None).unwrap();
        assert_eq!(reader.schema(), state.schema);
        let batches = reader.collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(batches.len(), 1);
        let ids = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap();
        assert_eq!(ids.values().as_ref(), &[2, 3]);
        check_ipc_fixture("subscription.arrow", &response.results);

        let predicate = compile_subscription_predicate(
            &ctx,
            &batch.schema(),
            "orders",
            "CAST(status AS BIGINT) > 0",
        )
        .unwrap()
        .unwrap();
        assert!(batch_filter(&batch, &predicate).is_err());
    }

    #[test]
    fn subscription_time_is_bound_once_and_random_remains_volatile() {
        let ctx = SessionContext::new();
        let batch = predicate_batch();
        let predicate = compile_subscription_predicate(
            &ctx,
            &batch.schema(),
            "orders",
            "id > 0 AND now() = current_timestamp()",
        )
        .unwrap()
        .unwrap();
        assert_eq!(matching_ids(&predicate, &batch), vec![1, 2, 3, 4]);
        assert_eq!(matching_ids(&predicate, &batch), vec![1, 2, 3, 4]);
        assert!(!predicate.to_string().contains("now()"));
        assert!(!predicate.to_string().contains("current_timestamp()"));

        let random = compile_subscription_predicate(
            &ctx,
            &batch.schema(),
            "orders",
            "random() >= 0 AND random() < 1",
        )
        .unwrap()
        .unwrap();
        assert!(random.to_string().contains("random()"));
        assert_eq!(matching_ids(&random, &batch), vec![1, 2, 3, 4]);
        assert_eq!(matching_ids(&random, &batch), vec![1, 2, 3, 4]);
    }

    #[test]
    fn subscription_compiles_stable_functions_once_and_evaluates_volatile_functions_per_batch() {
        let batch = predicate_batch();
        for volatility in [Volatility::Stable, Volatility::Volatile] {
            let ctx = SessionContext::new();
            let calls = Arc::new(AtomicUsize::new(0));
            let evaluations = calls.clone();
            ctx.register_udf(create_udf(
                "count_evaluations",
                vec![],
                DataType::Boolean,
                volatility,
                Arc::new(move |_| {
                    evaluations.fetch_add(1, Ordering::SeqCst);
                    Ok(ColumnarValue::Scalar(
                        datafusion::common::ScalarValue::Boolean(Some(true)),
                    ))
                }),
            ));
            let predicate = compile_subscription_predicate(
                &ctx,
                &batch.schema(),
                "orders",
                "count_evaluations() AND id > 0",
            )
            .unwrap()
            .unwrap();
            let stable = volatility == Volatility::Stable;
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(stable));
            for frame in 1..=2 {
                assert_eq!(matching_ids(&predicate, &batch), vec![1, 2, 3, 4]);
                assert_eq!(calls.load(Ordering::SeqCst), if stable { 1 } else { frame });
            }
        }
    }
}
