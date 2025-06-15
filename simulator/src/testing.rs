use exoware_sdk_rs::Client;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::future::Future;
use std::time::Duration;
use tempfile::tempdir;
use tokio::task::JoinHandle;

/// A test helper to run a server and a test function against it.
///
/// It sets up a temporary directory for storage, picks an unused port,
/// generates a random auth token, and starts the server in the background.
/// It then runs the provided test function with a configured `Client`.
/// When the test function completes, the server is aborted.
///
/// # Panics
///
/// This function will panic if it fails to find an unused port or create a temporary directory.
pub async fn with_server<F, Fut>(
    allow_public_access: bool,
    consistency_bound_min: u64,
    consistency_bound_max: u64,
    test_fn: F,
) where
    F: FnOnce(Client) -> Fut,
    Fut: Future<Output = ()>,
{
    let port = portpicker::pick_unused_port().expect("failed to find unused port");
    let addr = format!("http://127.0.0.1:{}", port);
    let dir = tempdir().unwrap();
    let token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let server_task: JoinHandle<Result<(), crate::server::Error>> = tokio::spawn({
        let token = token.clone();
        async move {
            crate::server::run(
                dir.path(),
                &port,
                consistency_bound_min,
                consistency_bound_max,
                token,
                allow_public_access,
            )
            .await
        }
    });

    // Give the server a moment to start up
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = Client::new(addr, token.clone());
    test_fn(client).await;

    server_task.abort();
}
