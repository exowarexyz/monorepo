use exoware_sdk::{error::Error, testing::with_server, Client};
use futures_util::StreamExt;
use std::time::Duration;

#[tokio::test]
async fn test_store_set_get() {
    with_server(true, 0, 0, |client| async move {
        let store = client.store();
        store.set("key1", b"value1".to_vec()).await.unwrap();
        let res = store.get("key1").await.unwrap().unwrap();
        assert_eq!(res.value, b"value1");
    })
    .await;
}

#[tokio::test]
async fn test_store_query() {
    with_server(true, 0, 0, |client| async move {
        let store = client.store();
        store.set("a", b"1".to_vec()).await.unwrap();
        store.set("b", b"2".to_vec()).await.unwrap();
        store.set("c", b"3".to_vec()).await.unwrap();

        let res = store.query(Some("a"), Some("c"), None).await.unwrap();
        assert_eq!(res.results.len(), 2);
        assert_eq!(res.results[0].key, "a");
        assert_eq!(res.results[1].key, "b");
    })
    .await;
}

#[tokio::test]
async fn test_get_not_found() {
    with_server(true, 0, 0, |client| async move {
        let store = client.store();
        let res = store.get("nonexistent").await.unwrap();
        assert!(res.is_none());
    })
    .await;
}

#[tokio::test]
async fn test_stream() {
    with_server(true, 0, 0, |client| async move {
        let stream = client.stream();
        let mut sub = stream.subscribe("test-stream").await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        stream
            .publish("test-stream", b"hello".to_vec())
            .await
            .unwrap();

        let msg = sub.read.next().await.unwrap().unwrap();
        assert_eq!(msg.into_data(), b"hello".to_vec());

        sub.close().await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_auth() {
    with_server(false, 0, 0, |client| async move {
        let unauth_client = Client::new(client.base_url().to_string(), "".to_string());
        let store = unauth_client.store();
        let err = store.get("key").await.unwrap_err();
        match err {
            Error::Http(status) => assert_eq!(status, 401),
            _ => panic!("unexpected error type"),
        }

        let bad_client = Client::new(client.base_url().to_string(), "bad_token".to_string());
        let store = bad_client.store();
        let err = store.set("key", b"value".to_vec()).await.unwrap_err();
        match err {
            Error::Http(status) => assert_eq!(status, 401),
            _ => panic!("unexpected error type"),
        }

        let stream = bad_client.stream();
        let err = stream.subscribe("test-stream").await.unwrap_err();
        match err {
            Error::WebSocket(_) => {}
            _ => panic!("unexpected error type"),
        }
    })
    .await;
}

#[tokio::test]
async fn test_limits() {
    with_server(true, 0, 0, |client| async move {
        let store = client.store();
        let large_key = "a".repeat(1024);
        let err = store.set(&large_key, b"value".to_vec()).await.unwrap_err();
        match err {
            Error::Http(status) => assert_eq!(status, 413),
            _ => panic!("unexpected error type"),
        }

        store.set("key", b"value".to_vec()).await.unwrap();
        let err = store.set("key", b"value2".to_vec()).await.unwrap_err();
        match err {
            Error::Http(status) => assert_eq!(status, 429),
            _ => panic!("unexpected error type"),
        }
    })
    .await;
}

#[tokio::test]
async fn test_eventual_consistency() {
    with_server(true, 200, 300, |client| async move {
        let store = client.store();
        store.set("key", b"value".to_vec()).await.unwrap();

        // Check that the value is not visible before the minimum consistency bound.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let res = store.get("key").await.unwrap();
        assert!(res.is_none());

        // Check that the value is visible after the maximum consistency bound.
        tokio::time::sleep(Duration::from_millis(300)).await;

        let res = store.get("key").await.unwrap().unwrap();
        assert_eq!(res.value, b"value");
    })
    .await;
}
