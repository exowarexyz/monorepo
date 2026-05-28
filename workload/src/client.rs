use std::time::Duration;

use anyhow::ensure;
use exoware_sdk::{RetryConfig, StoreClient};

const DEFAULT_INITIAL_BACKOFF_MS: u64 = 50;
const DEFAULT_MAX_BACKOFF_MS: u64 = 1_000;

/// Normalized SDK client settings shared by workload commands.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub endpoint: String,
    pub read_retry_attempts: usize,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

impl ClientConfig {
    /// Builds a client config from CLI-style endpoint and retry inputs.
    pub fn new(endpoint: impl Into<String>, read_retry_attempts: usize) -> anyhow::Result<Self> {
        let config = Self {
            endpoint: normalize_endpoint(&endpoint.into()),
            read_retry_attempts,
            initial_backoff_ms: DEFAULT_INITIAL_BACKOFF_MS,
            max_backoff_ms: DEFAULT_MAX_BACKOFF_MS,
        };
        validate_config(&config)?;
        Ok(config)
    }
}

/// Constructs the SDK client used by load, bench, and validate commands.
pub fn build_client(config: &ClientConfig) -> anyhow::Result<StoreClient> {
    validate_config(config)?;
    let endpoint = normalize_endpoint(&config.endpoint);
    Ok(StoreClient::with_retry_config(
        &endpoint,
        RetryConfig::standard()
            .with_max_attempts(config.read_retry_attempts)
            .with_initial_backoff(Duration::from_millis(config.initial_backoff_ms))
            .with_max_backoff(Duration::from_millis(config.max_backoff_ms)),
    ))
}

fn validate_config(config: &ClientConfig) -> anyhow::Result<()> {
    ensure!(
        config.read_retry_attempts > 0,
        "--read-retry-attempts must be > 0"
    );
    Ok(())
}

fn normalize_endpoint(endpoint: &str) -> String {
    endpoint.trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_normalizes_endpoint() {
        let config =
            ClientConfig::new("http://localhost:10000/", 3).expect("client config should parse");
        assert_eq!(config.endpoint, "http://localhost:10000");
    }

    #[test]
    fn config_preserves_endpoint_without_trailing_slash() {
        let config =
            ClientConfig::new("http://localhost:10000", 3).expect("client config should parse");
        assert_eq!(config.endpoint, "http://localhost:10000");
    }

    #[test]
    fn config_rejects_zero_read_retry_attempts() {
        assert!(ClientConfig::new("http://localhost:10000", 0).is_err());
    }
}
