use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use connectrpc::rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use connectrpc::rustls::server::WebPkiClientVerifier;
use connectrpc::rustls::{ClientConfig, RootCertStore, ServerConfig};
use exoware_sdk::kv_codec::Utf8;
use exoware_sdk::selector::Selector;
use exoware_sdk::stream_filter::StreamFilter;
use exoware_sdk::transport::HttpClient;
use exoware_sdk::{BalancedHttp2Config, Key, RetryConfig, StoreClient, StoreKeyPrefix};
use exoware_simulator::{connect_stack, AppState, RocksStore};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use tokio_rustls::TlsAcceptor;

const LOCALHOST_CERT: &str = include_str!("data/localhost-cert.pem");
const LOCALHOST_KEY: &str = include_str!("data/localhost-key.pem");

fn prefixed(client: StoreClient) -> exoware_sdk::PrefixedStoreClient {
    client.prefixed(StoreKeyPrefix::new("transport/").unwrap())
}

fn all_keys_filter() -> StreamFilter {
    StreamFilter {
        selectors: vec![Selector {
            prefix: bytes::Bytes::new(),
            payload_regex: Utf8::from("(?s-u).*"),
        }],
        value_filters: vec![],
    }
}

fn store_app() -> Router {
    let data_dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(RocksStore::open_owned(data_dir, None).unwrap());
    Router::new().fallback_service(connect_stack(AppState::new(engine)))
}

async fn tls_store_with_protocol(
    server_alpn: Option<&'static [u8]>,
    require_client_auth: bool,
) -> (
    tokio::task::JoinHandle<()>,
    String,
    Arc<ClientConfig>,
    Arc<AtomicBool>,
) {
    let cert = CertificateDer::from_pem_slice(LOCALHOST_CERT.as_bytes()).unwrap();
    let key = PrivateKeyDer::from_pem_slice(LOCALHOST_KEY.as_bytes()).unwrap();
    let server_config = ServerConfig::builder();
    let server_config = if require_client_auth {
        let mut roots = RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let verifier = WebPkiClientVerifier::builder(roots.into()).build().unwrap();
        server_config.with_client_cert_verifier(verifier)
    } else {
        server_config.with_no_client_auth()
    };
    let mut server_config = server_config
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    server_config.alpn_protocols = server_alpn.into_iter().map(<[u8]>::to_vec).collect();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let app = store_app();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let negotiated_h2 = Arc::new(AtomicBool::new(false));
    let observed_h2 = negotiated_h2.clone();
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let app = app.clone();
            let observed_h2 = observed_h2.clone();
            tokio::spawn(async move {
                let stream = acceptor.accept(socket).await.unwrap();
                observed_h2.store(
                    stream.get_ref().1.alpn_protocol() == server_alpn,
                    Ordering::Relaxed,
                );
                let service = TowerToHyperService::new(app);
                if server_alpn != Some(b"http/1.1") {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                }
            });
        }
    });

    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (server, url, Arc::new(client_config), negotiated_h2)
}

fn balanced_client_with_config(url: &str, config: BalancedHttp2Config) -> StoreClient {
    StoreClient::builder()
        .url(url)
        .retry_config(RetryConfig::disabled())
        .balanced_http2_transport(config)
        .build()
        .unwrap()
}

fn tls_client(url: &str, tls_config: Arc<ClientConfig>) -> StoreClient {
    balanced_client_with_config(
        url,
        BalancedHttp2Config::default()
            .with_tls_config(tls_config)
            .with_request_timeout(Duration::from_secs(2)),
    )
}

fn balanced_client(url: &str, request_timeout: Duration) -> StoreClient {
    balanced_client_with_config(
        url,
        BalancedHttp2Config::default().with_request_timeout(request_timeout),
    )
}

#[tokio::test]
async fn balanced_h2c_supports_unary_and_long_lived_streaming_calls() {
    let (_server, url) = exoware_simulator::open_temp().await.unwrap();
    let store = prefixed(balanced_client(&url, Duration::from_millis(250)));
    let key = Key::from(b"middle".to_vec());

    store.ingest().put(&[(&key, b"value")]).await.unwrap();
    assert_eq!(
        store.query().get(&key).await.unwrap().as_deref(),
        Some(&b"value"[..])
    );

    let mut stream = store
        .query()
        .range_stream(&Key::from(b"a".to_vec()), &Key::from(b"z".to_vec()), 10, 1)
        .await
        .unwrap();
    let chunk = stream.next_chunk().await.unwrap().unwrap();
    assert_eq!(chunk.rows, [(key, b"value".as_slice().into())]);
    let mut subscription = store
        .stream()
        .subscribe(all_keys_filter(), None)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;
    let key = Key::from(b"late".to_vec());
    store.ingest().put(&[(&key, b"value")]).await.unwrap();

    let frame = tokio::time::timeout(Duration::from_secs(2), subscription.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(frame.entries[0].key, key);
}

#[test]
fn balanced_client_survives_runtime_shutdown() {
    let server_runtime = tokio::runtime::Runtime::new().unwrap();
    let (_server, url) = server_runtime
        .block_on(exoware_simulator::open_temp())
        .unwrap();
    let client = balanced_client(&url, Duration::from_secs(2));
    let key = Key::from(b"runtime".to_vec());

    let first_runtime = tokio::runtime::Runtime::new().unwrap();
    first_runtime
        .block_on(prefixed(client.clone()).query().get(&key))
        .unwrap();
    drop(first_runtime);

    let second_runtime = tokio::runtime::Runtime::new().unwrap();
    second_runtime
        .block_on(prefixed(client).query().get(&key))
        .unwrap();
}

#[tokio::test]
async fn custom_transport_routes_real_requests_across_origins() {
    let (_ingest_server, ingest_url) = exoware_simulator::open_temp().await.unwrap();
    let (_query_server, query_url) = exoware_simulator::open_temp().await.unwrap();
    let client = StoreClient::builder()
        .health_url(&query_url)
        .ingest_url(&ingest_url)
        .query_url(&query_url)
        .prune_url(&query_url)
        .retention_url(&query_url)
        .stream_url(&query_url)
        .retry_config(RetryConfig::disabled())
        .client_transport(HttpClient::plaintext())
        .build()
        .unwrap();
    let store = prefixed(client);
    let key = Key::from(b"split".to_vec());

    store.ingest().put(&[(&key, b"ingest")]).await.unwrap();
    assert_eq!(store.query().get(&key).await.unwrap(), None);

    let mut stream = store
        .query()
        .range_stream(&Key::from(b"a".to_vec()), &Key::from(b"z".to_vec()), 10, 1)
        .await
        .unwrap();
    let _ = stream.next_chunk().await.unwrap();
}

#[tokio::test]
async fn balanced_https_uses_custom_roots_client_identity_and_h2_alpn() {
    let (_server, url, _, negotiated_h2) = tls_store_with_protocol(Some(b"h2"), true).await;
    let cert = CertificateDer::from_pem_slice(LOCALHOST_CERT.as_bytes()).unwrap();
    let key = PrivateKeyDer::from_pem_slice(LOCALHOST_KEY.as_bytes()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![cert], key)
        .unwrap();
    let store = prefixed(tls_client(&url, Arc::new(client_config)));
    let key = Key::from(b"tls".to_vec());

    store.ingest().put(&[(&key, b"h2")]).await.unwrap();
    assert_eq!(
        store.query().get(&key).await.unwrap().as_deref(),
        Some(&b"h2"[..])
    );
    assert!(negotiated_h2.load(Ordering::Relaxed));
}

#[tokio::test]
async fn balanced_https_rejects_http1_alpn_fallback() {
    let (_server, url, tls_config, _) = tls_store_with_protocol(Some(b"http/1.1"), false).await;
    let client = tls_client(&url, tls_config);
    let key = Key::from(b"tls-http1".to_vec());

    assert!(prefixed(client).query().get(&key).await.is_err());
}

#[tokio::test]
async fn balanced_https_rejects_missing_alpn() {
    let (_server, url, tls_config, _) = tls_store_with_protocol(None, false).await;
    let client = tls_client(&url, tls_config);
    let key = Key::from(b"tls-no-alpn".to_vec());

    let message = prefixed(client)
        .query()
        .get(&key)
        .await
        .unwrap_err()
        .to_string();
    assert!(message.contains("did not negotiate h2"), "{message}");
}

#[tokio::test]
async fn balanced_transport_recovers_after_an_origin_restart() {
    let app = store_app();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let url = format!("http://{address}");
    let store = prefixed(balanced_client(&url, Duration::from_millis(200)));
    let key = Key::from(b"restart".to_vec());
    for _ in 0..4 {
        assert!(store.query().get(&key).await.is_err());
    }

    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    let _server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    assert_eq!(store.query().get(&key).await.unwrap(), None);
}
