//! Local E2E: ephemeral RocksDB dir + simulator on an ephemeral port (no env vars).

use exoware_sdk::StoreClient;

/// Keep `_server` alive for the whole test; the store's tempdir lives inside the store engine
/// so it cannot be deleted while the store is still running.
pub async fn local_store_client() -> (tokio::task::JoinHandle<()>, StoreClient) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();
    let (jh, url) = exoware_simulator::spawn_for_test(&path, dir)
        .await
        .expect("spawn simulator");
    let client = StoreClient::new(&url);
    (jh, client)
}
