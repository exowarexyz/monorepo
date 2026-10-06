#![allow(refining_impl_trait)]

use std::sync::{Arc, Mutex};

use axum::Router;
use bytes::Bytes;
use commonware_codec::Encode;
use connectrpc::{ConnectError, ConnectRpcService, RequestContext, ServiceRequest};
use datafusion::arrow::array::Int64Array;
use datafusion::arrow::datatypes::DataType;
use datafusion::prelude::SessionConfig;
use exoware_sdk::common::kv::v1::Entry;
use exoware_sdk::kv_codec::StoredRow;
use exoware_sdk::store::query::v1::{
    Detail, GetManyFrame, GetManyRequest, GetRequest, GetResponse, RangeFrame, RangeRequest,
    ReduceRequest, ReduceResponse, Service, ServiceServer,
};
use exoware_sdk::{PrefixedStoreClient, ReadSession, StoreClient};
use exoware_sql::{KvSchema, SqlContext, TableColumnConfig};
use futures::stream;

#[derive(Clone)]
struct RangeHarness {
    requested_floors: Arc<Mutex<Vec<Option<u64>>>>,
    response_sequence: u64,
}

impl Service for RangeHarness {
    async fn get(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetRequest>,
    ) -> connectrpc::ServiceResult<GetResponse> {
        Err(ConnectError::unimplemented("test harness"))
    }

    async fn get_many(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetManyRequest>,
    ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<GetManyFrame>> {
        Err(ConnectError::unimplemented("test harness"))
    }

    async fn range(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, RangeRequest>,
    ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<RangeFrame>> {
        self.requested_floors
            .lock()
            .expect("floor mutex")
            .push(request.min_sequence_number);

        let frame = RangeFrame {
            results: vec![Entry {
                key: row_key().to_vec(),
                value: row_value(),
                ..Default::default()
            }],
            detail: Some(Detail {
                sequence_number: self.response_sequence,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        Ok(connectrpc::Response::stream(stream::iter([Ok(frame)])))
    }

    async fn reduce(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, ReduceRequest>,
    ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<ReduceResponse>> {
        Err(ConnectError::unimplemented("test harness"))
    }
}

struct MockStore {
    client: PrefixedStoreClient,
    requested_floors: Arc<Mutex<Vec<Option<u64>>>>,
    server: tokio::task::JoinHandle<()>,
}

impl MockStore {
    async fn start(response_sequence: u64) -> Self {
        let requested_floors = Arc::new(Mutex::new(Vec::new()));
        let service = ConnectRpcService::new(ServiceServer::new(RangeHarness {
            requested_floors: requested_floors.clone(),
            response_sequence,
        }))
        .with_compression(exoware_sdk::connect_compression_registry());
        let app = Router::new().fallback_service(service);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock Store");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("mock Store address")
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock Store");
        });
        Self {
            client: PrefixedStoreClient::empty(StoreClient::new(&url)),
            requested_floors,
            server,
        }
    }

    fn requested_floors(&self) -> Vec<Option<u64>> {
        self.requested_floors.lock().expect("floor mutex").clone()
    }
}

impl Drop for MockStore {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn row_key() -> Bytes {
    let mut key = vec![0];
    key.extend_from_slice(&(1u64 ^ (1u64 << 63)).to_be_bytes());
    key.into()
}

fn row_value() -> Bytes {
    StoredRow { values: vec![None] }.encode()
}

fn context_with_table(client: PrefixedStoreClient) -> SqlContext {
    let ctx = SqlContext::new(client.clone());
    let schema = KvSchema::new(client)
        .table(
            "items",
            vec![TableColumnConfig::new("id", DataType::Int64, false)],
            vec!["id".to_string()],
            vec![],
        )
        .expect("table schema");
    ctx.register_schema(schema).expect("register table");
    ctx
}

async fn execute_table_scan(ctx: &SqlContext) {
    let batches = ctx
        .sql("SELECT id FROM items")
        .await
        .expect("plan table scan")
        .collect()
        .await
        .expect("execute table scan");
    let ids = batches
        .iter()
        .flat_map(|batch| {
            batch
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("Int64 id")
                .values()
                .iter()
                .copied()
        })
        .collect::<Vec<_>>();
    assert_eq!(ids, [1]);
}

async fn run_two_scans(monotonic: bool, floor: Option<u64>) -> (Vec<Option<u64>>, Option<u64>) {
    let store = MockStore::start(11).await;
    let session = if monotonic {
        ReadSession::monotonic(store.client.clone(), floor)
    } else {
        ReadSession::fixed(store.client.clone(), floor)
    };
    let retained = session.clone();
    let base = context_with_table(store.client.clone());
    let ctx = base.with_read_session(session);

    execute_table_scan(&ctx).await;
    execute_table_scan(&ctx).await;

    (store.requested_floors(), retained.min_sequence_number())
}

#[tokio::test]
async fn default_context_retains_observations_and_independent_contexts_start_fresh() {
    let store = MockStore::start(11).await;
    let ctx = context_with_table(store.client.clone());

    execute_table_scan(&ctx).await;
    execute_table_scan(&ctx.clone()).await;
    execute_table_scan(&context_with_table(store.client.clone())).await;

    assert_eq!(store.requested_floors(), [None, Some(11), None]);
}

#[tokio::test]
async fn builder_config_replacement_preserves_supplied_read_session() {
    for (monotonic, floor) in [(true, None), (true, Some(0)), (false, Some(0))] {
        let store = MockStore::start(11).await;
        let base = context_with_table(store.client.clone());
        let session = if monotonic {
            ReadSession::monotonic(store.client.clone(), floor)
        } else {
            ReadSession::fixed(store.client.clone(), floor)
        };
        let ctx = SqlContext::builder(store.client.clone())
            .with_read_session(session.clone())
            .with_config(SessionConfig::new().with_batch_size(3))
            .with_config(SessionConfig::new().with_batch_size(5))
            .configure_datafusion(|builder| {
                builder.with_config(SessionConfig::new().with_batch_size(7))
            })
            .build();
        ctx.register_table("items", base.table_provider("items").await.unwrap())
            .unwrap();

        assert_eq!(ctx.datafusion().copied_config().batch_size(), 7);

        execute_table_scan(&ctx).await;
        execute_table_scan(&ctx).await;

        assert_eq!(
            store.requested_floors(),
            [floor, if monotonic { Some(11) } else { floor }]
        );
        assert_eq!(session.evaluated_sequence(), Some(11));
        assert_eq!(ctx.read_session().evaluated_sequence(), Some(11));
        assert_eq!(ctx.datafusion().copied_config().batch_size(), 7);
    }
}

#[tokio::test]
async fn request_contexts_replace_the_base_session() {
    let store = MockStore::start(11).await;
    let base = context_with_table(store.client.clone());
    execute_table_scan(&base).await;

    for _ in 0..2 {
        let ctx = base.with_read_session(ReadSession::monotonic(store.client.clone(), None));
        execute_table_scan(&ctx).await;
    }

    assert_eq!(store.requested_floors(), [None, None, None]);
}

#[tokio::test]
async fn monotonic_session_shares_observations_across_sql_statements() {
    let store = MockStore::start(11).await;
    let session = ReadSession::monotonic(store.client.clone(), None);
    let retained = session.clone();
    let base = context_with_table(store.client.clone());
    let ctx = base.with_read_session(session);

    execute_table_scan(&ctx).await;
    assert_eq!(retained.evaluated_sequence(), Some(11));
    execute_table_scan(&ctx).await;

    assert_eq!(store.requested_floors(), [None, Some(11)]);
}

#[tokio::test]
async fn fixed_and_monotonic_policies_preserve_absent_and_zero_floors() {
    let (fixed_absent, fixed_absent_min) = run_two_scans(false, None).await;
    assert_eq!(fixed_absent, [None, None]);
    assert_eq!(fixed_absent_min, None);

    let (fixed_zero, fixed_zero_min) = run_two_scans(false, Some(0)).await;
    assert_eq!(fixed_zero, [Some(0), Some(0)]);
    assert_eq!(fixed_zero_min, Some(0));

    let (monotonic_zero, monotonic_zero_min) = run_two_scans(true, Some(0)).await;
    assert_eq!(monotonic_zero, [Some(0), Some(11)]);
    assert_eq!(monotonic_zero_min, Some(11));
}

#[tokio::test]
async fn store_free_sql_does_not_create_an_observation() {
    let store = MockStore::start(11).await;
    let ctx = SqlContext::new(store.client.clone());
    let retained = ctx.read_session();

    let batches = ctx
        .sql("SELECT 1")
        .await
        .expect("plan literal query")
        .collect()
        .await
        .expect("execute literal query");

    assert_eq!(
        batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
        1
    );
    assert!(store.requested_floors().is_empty());
    assert_eq!(retained.evaluated_sequence(), None);
}

#[test]
fn context_override_preserves_optional_store_sequence_floor() {
    let store = PrefixedStoreClient::empty(StoreClient::new("http://localhost:10000"));
    let ctx = SqlContext::new(store.clone());
    for floor in [None, Some(0), Some(41)] {
        let query_ctx = ctx.with_read_session(ReadSession::monotonic(store.clone(), floor));
        let first = query_ctx.read_session();
        let second = query_ctx.read_session();

        assert_eq!(first.min_sequence_number(), floor);
        assert_eq!(second.min_sequence_number(), floor);
    }
    assert_eq!(ctx.read_session().min_sequence_number(), None);
}
