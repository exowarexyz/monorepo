//! In-process ConnectRPC helpers for tests and simulators.

use connectrpc::client::{ClientConfig, ClientTransport, ServiceTransport};
use exoware_sdk::{
    compact::ServiceClient as CompactServiceClient, ingest::ServiceClient as IngestServiceClient,
    query::ServiceClient as QueryServiceClient, stream::ServiceClient as StreamServiceClient,
    RetryConfig, StoreClient,
};

use crate::{connect_stack, AppState, StoreEngine};

const MAX_CONNECTRPC_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Synthetic base URI used only to build ConnectRPC request paths.
pub const BASE_URI: &str = "http://exoware.in-process";

/// Build the same client-side ConnectRPC envelope the HTTP SDK uses, without an HTTP transport.
pub fn client_config() -> ClientConfig {
    ClientConfig::new(BASE_URI.parse().expect("in-process base URI is valid"))
        .compression(exoware_sdk::connect_compression_registry())
        .compress_requests("zstd")
        .default_max_message_size(MAX_CONNECTRPC_BODY_BYTES)
}

/// Wrap a Tower service so ConnectRPC clients can call it in process.
pub fn service_transport<S>(service: S) -> ServiceTransport<S> {
    ServiceTransport::new(service)
}

/// Build a high-level Store SDK client over an in-process Store service stack.
pub fn store_client<E>(
    state: AppState<E>,
) -> StoreClient<ServiceTransport<crate::connect::ConnectStack<E, E, E, E>>>
where
    E: StoreEngine,
{
    let service = connect_stack(state);
    let transport = service_transport(service);
    StoreClient::with_transport(
        transport,
        BASE_URI.parse().expect("in-process base URI is valid"),
        RetryConfig::disabled(),
    )
}

/// Generated Store clients sharing one in-process transport.
#[derive(Clone)]
pub struct StoreClients<T> {
    pub ingest: IngestServiceClient<T>,
    pub query: QueryServiceClient<T>,
    pub compact: CompactServiceClient<T>,
    pub stream: StreamServiceClient<T>,
}

impl<T> StoreClients<T>
where
    T: ClientTransport,
    <T::ResponseBody as http_body::Body>::Error: std::fmt::Display,
{
    pub fn new(transport: T) -> Self {
        Self {
            ingest: IngestServiceClient::new(transport.clone(), client_config()),
            query: QueryServiceClient::new(transport.clone(), client_config()),
            compact: CompactServiceClient::new(transport.clone(), client_config()),
            stream: StreamServiceClient::new(transport, client_config()),
        }
    }
}
