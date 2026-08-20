use std::num::NonZeroUsize;
use std::time::Duration;

use exoware_sdk::{BalancedHttp2Config, Key, RetryConfig, StoreClient, StoreKeyPrefix};

#[tokio::test]
async fn balanced_transport_bounds_response_header_wait() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let mut sockets = Vec::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            sockets.push(socket);
        }
    });

    let client = StoreClient::builder()
        .url(&url)
        .retry_config(RetryConfig::disabled())
        .balanced_http2_transport(
            BalancedHttp2Config::default()
                .with_connections_per_origin(NonZeroUsize::new(2).unwrap())
                .with_request_timeout(Duration::from_millis(100)),
        )
        .build()
        .unwrap()
        .prefixed(StoreKeyPrefix::new("timeout/").unwrap());
    let result = tokio::time::timeout(
        Duration::from_millis(400),
        client.query().get(&Key::from(b"key".to_vec())),
    )
    .await;
    server.abort();

    assert!(
        result.is_ok(),
        "the transport must bound response header waits"
    );
}
