//! Local E2E: ephemeral RocksDB dir + simulator on an ephemeral port (no env vars).

use exoware_sdk::StoreClient;

pub async fn local_store_client() -> (tempfile::TempDir, tokio::task::JoinHandle<()>, StoreClient) {
    let dir = tempfile::tempdir().expect("tempdir");
    let (jh, url) = exoware_simulator::spawn_for_test(dir.path())
        .await
        .expect("spawn simulator");
    let client = StoreClient::with_split_urls(&url, &url, &url, &url);
    (dir, jh, client)
}
