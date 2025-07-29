use exoware_simulator::testing::with_server;
use futures_util::StreamExt;
use std::time::Duration;

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
