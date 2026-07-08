//! Local E2E: simulator on an ephemeral port (no env vars).

use exoware_sdk::StoreClient;

/// Spawns a local simulator and returns a client for it.
pub async fn local_store_client() -> StoreClient {
    let (_task, url) = exoware_simulator::open_temp()
        .await
        .expect("spawn simulator");
    StoreClient::new(&url)
}
