use exoware_sdk_rs::{Client, Error};
use exoware_simulator::testing::with_server;
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

        let err = stream
            .publish("test-stream", b"hello".to_vec())
            .await
            .unwrap_err();
        match err {
            Error::Http(status) => assert_eq!(status, 401),
            _ => panic!("unexpected error type"),
        }
    })
    .await;
}

#[tokio::test]
async fn test_limits_fail() {
    with_server(true, 0, 0, |client| async move {
        // Key exceeds limit
        let store = client.store();
        let large_key = "a".repeat(513);
        let err = store.set(&large_key, b"value".to_vec()).await.unwrap_err();
        match err {
            Error::Http(status) => assert_eq!(status, 413),
            _ => panic!("unexpected error type: {:?}", err),
        }

        // Update rate exceeds limit
        store.set("key", b"value".to_vec()).await.unwrap();
        let err = store.set("key", b"value2".to_vec()).await.unwrap_err();
        match err {
            Error::Http(status) => assert_eq!(status, 429),
            _ => panic!("unexpected error type: {:?}", err),
        }

        // Value exceeds limit
        let large_value = vec![0; 20 * 1024 * 1024 + 1];
        let err = store
            .set("large_value_key", large_value.clone())
            .await
            .unwrap_err();
        match err {
            Error::Http(status) => assert_eq!(status, 413),
            _ => panic!("unexpected error type: {:?}", err),
        }

        // Stream name exceeds limit
        let stream = client.stream();
        let large_stream_name = "a".repeat(513);
        let err = stream
            .publish(&large_stream_name, b"hello".to_vec())
            .await
            .unwrap_err();
        match err {
            Error::Http(status) => assert_eq!(status, 413),
            _ => panic!("unexpected error type: {:?}", err),
        }
        let err = stream.subscribe(&large_stream_name).await.unwrap_err();
        match err {
            Error::WebSocket(_) => {}
            _ => panic!("unexpected error type: {:?}", err),
        }

        // Message exceeds limit
        let err = stream
            .publish("test-stream", large_value)
            .await
            .unwrap_err();
        match err {
            Error::Http(status) => assert_eq!(status, 413),
            _ => panic!("unexpected error type: {:?}", err),
        }
    })
    .await;
}

#[tokio::test]
async fn test_limits_ok() {
    with_server(true, 0, 0, |client| async move {
        // Key exactly at limit
        let store = client.store();
        let key_at_limit = "a".repeat(512);
        store.set(&key_at_limit, b"value".to_vec()).await.unwrap();
        let res = store.get(&key_at_limit).await.unwrap().unwrap();
        assert_eq!(res.value, b"value");

        // Value exactly at limit
        let value_at_limit = vec![0; 20 * 1024 * 1024];
        store
            .set("value_at_limit", value_at_limit.clone())
            .await
            .unwrap();
        let res = store.get("value_at_limit").await.unwrap().unwrap();
        assert_eq!(res.value, value_at_limit);

        // Stream name exactly at limit
        let stream = client.stream();
        let stream_name_at_limit = "s".repeat(512);
        let mut sub = stream.subscribe(&stream_name_at_limit).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        stream
            .publish(&stream_name_at_limit, b"hello".to_vec())
            .await
            .unwrap();
        let msg = sub.read.next().await.unwrap().unwrap();
        assert_eq!(msg.into_data(), b"hello".to_vec());
        sub.close().await.unwrap();

        // Value exactly at limit
        let mut sub = stream.subscribe("stream_value_at_limit").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        stream
            .publish("stream_value_at_limit", value_at_limit.clone())
            .await
            .unwrap();
        let msg = sub.read.next().await.unwrap().unwrap();
        assert_eq!(msg.into_data(), value_at_limit);
        sub.close().await.unwrap();
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

#[tokio::test]
async fn test_eventual_consistency_query() {
    with_server(true, 200, 300, |client| async move {
        let store = client.store();

        // Set the first key and wait for it to become consistent.
        store.set("a", b"1".to_vec()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;

        // Set the second key, which will not be immediately visible.
        store.set("c", b"3".to_vec()).await.unwrap();

        // Query for a range of keys. Only "a" should be visible.
        let res = store.query(Some("a"), Some("d"), None).await.unwrap();
        assert_eq!(res.results.len(), 1);
        assert_eq!(res.results[0].key, "a");

        // Wait for the second key to become consistent.
        tokio::time::sleep(Duration::from_millis(400)).await;

        // Query again. Both "a" and "c" should now be visible.
        let res = store.query(Some("a"), Some("d"), None).await.unwrap();
        assert_eq!(res.results.len(), 2);
        assert_eq!(res.results[0].key, "a");
        assert_eq!(res.results[1].key, "c");
    })
    .await;
}
