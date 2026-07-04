//! Local E2E: ephemeral RocksDB dir + simulator on an ephemeral port (no env vars).

#![allow(refining_impl_trait)]

use std::num::NonZeroU64;
use std::time::Duration;

use axum::{routing::get, Router};
use commonware_codec::{Codec, Decode, Encode};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Sequential;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_storage::qmdb::{
    any::{ordered, unordered, value::ValueEncoding},
    operation::Key as QmdbKey,
};
use commonware_storage::{
    journal::contiguous::variable::Config as VariableJournalConfig,
    merkle::{Family, Graftable},
    mmr::full::Config as MerkleConfig,
    qmdb::{any, current, immutable, keyless},
    translator::TwoCap,
};
use commonware_utils::Array;
use commonware_utils::{NZUsize, NZU64};
use connectrpc::client::ClientConfig;
use connectrpc::{ConnectError, ConnectRpcService, ErrorCode, RequestContext as Context};
use exoware_qmdb::proto::qmdb::v1::{
    GetOperationRangeRequestView, GetOperationRangeResponse, OperationLogService,
    OperationLogServiceClient, OperationLogServiceServer, SubscribeRequestView, SubscribeResponse,
};
use exoware_qmdb::{
    CurrentBoundaryState, ImmutableWriter, KeylessWriter, OrderedWriter, QmdbError,
    UnorderedWriter, UploadReceipt,
};
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::{StoreBatchUpload, StoreClient};

#[allow(dead_code)]
pub fn merkle_config(prefix: &str, page_cache: CacheRef) -> MerkleConfig<Sequential> {
    MerkleConfig {
        journal_partition: format!("{prefix}-mmr-journal"),
        metadata_partition: format!("{prefix}-mmr-metadata"),
        items_per_blob: NZU64!(8),
        write_buffer: NZUsize!(1024),
        strategy: Sequential,
        page_cache,
    }
}

#[allow(dead_code)]
pub fn variable_journal_config<C>(
    prefix: &str,
    page_cache: CacheRef,
    codec_config: C,
    items_per_section: NonZeroU64,
) -> VariableJournalConfig<C> {
    VariableJournalConfig {
        partition: format!("{prefix}-log"),
        items_per_section,
        compression: None,
        codec_config,
        page_cache,
        write_buffer: NZUsize!(1024),
    }
}

#[allow(dead_code)]
pub fn keyless_config<C>(
    prefix: &str,
    page_cache: CacheRef,
    codec_config: C,
    items_per_section: NonZeroU64,
) -> keyless::variable::Config<C, Sequential> {
    keyless::Config {
        merkle: merkle_config(prefix, page_cache.clone()),
        log: variable_journal_config(prefix, page_cache, codec_config, items_per_section),
    }
}

#[allow(dead_code)]
pub fn any_variable_config<C>(
    prefix: &str,
    page_cache: CacheRef,
    codec_config: C,
    items_per_section: NonZeroU64,
) -> any::VariableConfig<TwoCap, C, Sequential> {
    any::Config {
        merkle_config: merkle_config(prefix, page_cache.clone()),
        journal_config: variable_journal_config(
            prefix,
            page_cache,
            codec_config,
            items_per_section,
        ),
        translator: TwoCap,
        init_cache_size: None,
    }
}

#[allow(dead_code)]
pub fn unordered_variable_config<C>(
    prefix: &str,
    page_cache: CacheRef,
    codec_config: C,
    items_per_section: NonZeroU64,
) -> any::VariableConfig<TwoCap, C, Sequential> {
    any_variable_config(prefix, page_cache, codec_config, items_per_section)
}

#[allow(dead_code)]
pub fn ordered_variable_config<C>(
    prefix: &str,
    page_cache: CacheRef,
    codec_config: C,
    items_per_section: NonZeroU64,
) -> current::VariableConfig<TwoCap, C, Sequential> {
    current::Config {
        merkle_config: merkle_config(prefix, page_cache.clone()),
        journal_config: variable_journal_config(
            prefix,
            page_cache,
            codec_config,
            items_per_section,
        ),
        grafted_metadata_partition: format!("{prefix}-grafted-metadata"),
        translator: TwoCap,
        init_cache_size: None,
    }
}

#[allow(dead_code)]
pub fn immutable_variable_config<C>(
    prefix: &str,
    page_cache: CacheRef,
    codec_config: C,
    items_per_section: NonZeroU64,
) -> immutable::variable::Config<TwoCap, C, Sequential> {
    immutable::Config {
        merkle_config: merkle_config(prefix, page_cache.clone()),
        log: variable_journal_config(prefix, page_cache, codec_config, items_per_section),
        translator: TwoCap,
        init_cache_size: None,
    }
}

/// Keep `_dir` and `_server` alive for the whole test.
pub async fn local_store_client() -> (tempfile::TempDir, tokio::task::JoinHandle<()>, StoreClient) {
    let dir = tempfile::tempdir().expect("tempdir");
    let (jh, url) = exoware_simulator::spawn_for_test(dir.path())
        .await
        .expect("spawn simulator");
    let client = StoreClient::new(&url);
    (dir, jh, client)
}

#[allow(dead_code)]
pub async fn retry<F, Fut, T>(f: F, label: &str) -> T
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, QmdbError>>,
{
    for attempt in 1..=15 {
        match f().await {
            Ok(v) => return v,
            Err(e) if attempt < 15 => {
                eprintln!("{label}: attempt {attempt}/{e}, retrying...");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => panic!("{label}: failed after 15 attempts: {e}"),
        }
    }
    panic!("{label}: exhausted retries");
}

#[allow(dead_code)]
pub async fn commit_keyless_upload<F, H, V, E>(
    writer: &KeylessWriter<F, H, V, E>,
    ops: &[keyless::Operation<F, E>],
) -> Result<UploadReceipt<F>, QmdbError>
where
    F: Family,
    H: Hasher + Sync,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V> + Sync,
    keyless::Operation<F, E>: Encode,
{
    let prepared = writer.prepare_upload(ops).await?;
    writer.commit_upload(prepared).await
}

#[allow(dead_code)]
pub async fn commit_unordered_upload<F, H, K, V, E>(
    writer: &UnorderedWriter<F, H, K, V, E>,
    ops: &[unordered::Operation<F, K, E>],
) -> Result<UploadReceipt<F>, QmdbError>
where
    F: Graftable,
    H: Hasher + Sync,
    K: QmdbKey + Codec + Sync,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    E: ValueEncoding<Value = V> + Sync,
    unordered::Operation<F, K, E>: Encode,
{
    let prepared = writer.prepare_upload(ops).await?;
    writer.commit_upload(prepared).await
}

#[allow(dead_code)]
pub async fn commit_unordered_current_upload<F, H, K, V, const N: usize, E>(
    writer: &UnorderedWriter<F, H, K, V, E>,
    ops: &[unordered::Operation<F, K, E>],
    current_boundary: &CurrentBoundaryState<H::Digest, N, F>,
) -> Result<UploadReceipt<F>, QmdbError>
where
    F: Graftable,
    H: Hasher + Sync,
    K: QmdbKey + Codec + Sync,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    E: ValueEncoding<Value = V> + Sync,
    unordered::Operation<F, K, E>: Encode,
{
    let prepared = writer.prepare_current_upload(ops, current_boundary).await?;
    writer.commit_upload(prepared).await
}

#[allow(dead_code)]
pub async fn commit_ordered_upload<F, H, K, V, const N: usize, E>(
    writer: &OrderedWriter<F, H, K, V, N, E>,
    ops: &[ordered::Operation<F, K, E>],
    current_boundary: &CurrentBoundaryState<H::Digest, N, F>,
) -> Result<UploadReceipt<F>, QmdbError>
where
    F: Graftable,
    H: Hasher + Sync,
    K: QmdbKey + Codec + Sync,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    E: ValueEncoding<Value = V> + Sync,
    ordered::Operation<F, K, E>: Encode + Decode,
{
    let prepared = writer.prepare_upload(ops, current_boundary).await?;
    writer.commit_upload(prepared).await
}

#[allow(dead_code)]
pub async fn commit_immutable_upload<F, H, K, V, E>(
    writer: &ImmutableWriter<F, H, K, V, E>,
    ops: &[immutable::Operation<F, K, E>],
) -> Result<UploadReceipt<F>, QmdbError>
where
    F: Family,
    H: Hasher + Sync,
    K: Array + Codec + Clone + AsRef<[u8]> + Sync,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    K::Cfg: Clone,
    E: ValueEncoding<Value = V> + Sync,
    immutable::Operation<F, K, E>: Encode + Decode + Clone,
{
    let prepared = writer.prepare_upload(ops).await?;
    writer.commit_upload(prepared).await
}

#[allow(dead_code)]
async fn health_handler() -> &'static str {
    "ok"
}

#[allow(dead_code)]
pub async fn wait_for_health(base: &str) {
    let url = format!("{base}/health");
    let client = reqwest::Client::new();
    for _ in 0..200 {
        if client
            .get(&url)
            .send()
            .await
            .ok()
            .is_some_and(|res| res.status().is_success())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("qmdb server did not become ready at {url}");
}

/// Bind a QMDB operation-log `ConnectRpcService` stack to a random local port
/// alongside `/health`, and block until it responds.
#[allow(dead_code)]
pub async fn spawn_operation_log_service<D>(
    dispatcher: ConnectRpcService<D>,
) -> (tokio::task::JoinHandle<()>, String)
where
    D: ::connectrpc::Dispatcher + Send + Sync + 'static,
{
    let app = Router::new()
        .route("/health", get(health_handler))
        .fallback_service(dispatcher);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind qmdb server");
    let port = listener.local_addr().expect("local addr").port();
    let url = format!("http://127.0.0.1:{port}");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    wait_for_health(&url).await;
    (handle, url)
}

#[allow(dead_code)]
pub fn operation_log_rpc_client(base: &str) -> OperationLogServiceClient<PreferZstdHttpClient> {
    OperationLogServiceClient::new(
        PreferZstdHttpClient::plaintext(),
        ClientConfig::new(base.parse().expect("qmdb uri")),
    )
}

#[allow(dead_code)]
pub fn trusted_root<D: Digest, F: commonware_storage::merkle::Family>(
    root: D,
) -> impl FnOnce(commonware_storage::merkle::Location<F>) -> Result<D, QmdbError> {
    move |_| Ok(root)
}

/// An `OperationLogService` impl that yields one caller-supplied
/// `SubscribeResponse`
/// and then closes. Used to feed tampered proofs into the validated client.
#[derive(Clone)]
pub struct StaticOperationLogService {
    pub subscribe_response: SubscribeResponse,
}

impl OperationLogService for StaticOperationLogService {
    async fn get_operation_range(
        &self,
        _ctx: Context,
        _request: buffa::view::OwnedView<GetOperationRangeRequestView<'static>>,
    ) -> connectrpc::ServiceResult<GetOperationRangeResponse> {
        Err(ConnectError::new(
            ErrorCode::Unimplemented,
            "not implemented",
        ))
    }

    fn subscribe(
        &self,
        _ctx: Context,
        _request: buffa::view::OwnedView<SubscribeRequestView<'static>>,
    ) -> impl std::future::Future<
        Output = connectrpc::ServiceResult<connectrpc::ServiceStream<SubscribeResponse>>,
    > + Send {
        let response = self.subscribe_response.clone();
        async move {
            Ok(connectrpc::Response::stream(futures::stream::iter([Ok(
                response,
            )])))
        }
    }
}

/// An `OperationLogService` impl that returns one caller-supplied
/// `GetOperationRangeResponse`. Used to feed tampered range proofs into the
/// validated client.
#[derive(Clone)]
pub struct StaticOperationRangeService {
    pub operation_range_response: GetOperationRangeResponse,
}

impl OperationLogService for StaticOperationRangeService {
    async fn get_operation_range(
        &self,
        _ctx: Context,
        _request: buffa::view::OwnedView<GetOperationRangeRequestView<'static>>,
    ) -> connectrpc::ServiceResult<GetOperationRangeResponse> {
        connectrpc::Response::ok(self.operation_range_response.clone())
    }

    async fn subscribe(
        &self,
        _ctx: Context,
        _request: buffa::view::OwnedView<SubscribeRequestView<'static>>,
    ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<SubscribeResponse>> {
        Err(ConnectError::new(
            ErrorCode::Unimplemented,
            "not implemented",
        ))
    }
}

#[allow(dead_code)]
pub async fn spawn_static_operation_log_service(
    service: StaticOperationLogService,
) -> (tokio::task::JoinHandle<()>, String) {
    spawn_operation_log_service(
        ConnectRpcService::new(OperationLogServiceServer::new(service))
            .with_compression(exoware_sdk::connect_compression_registry()),
    )
    .await
}

#[allow(dead_code)]
pub async fn spawn_static_operation_range_service(
    service: StaticOperationRangeService,
) -> (tokio::task::JoinHandle<()>, String) {
    spawn_operation_log_service(
        ConnectRpcService::new(OperationLogServiceServer::new(service))
            .with_compression(exoware_sdk::connect_compression_registry()),
    )
    .await
}

#[allow(dead_code)]
pub fn tamper_subscribe_response(mut response: SubscribeResponse) -> SubscribeResponse {
    if let Some(proof) = response.proof.as_option_mut() {
        let mut bytes = proof.proof.to_vec();
        bytes[0] ^= 0x01;
        proof.proof = bytes.into();
    }
    response
}
