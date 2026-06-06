use std::time::Duration;

use anyhow::{ensure, Context};
use exoware_sdk::{RetryConfig, StoreClient};

const DEFAULT_INITIAL_BACKOFF_MS: u64 = 50;
const DEFAULT_MAX_BACKOFF_MS: u64 = 1_000;

/// Normalized SDK client settings shared by workload commands.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub endpoint: String,
    pub read_retry_attempts: usize,
}

impl ClientConfig {
    /// Builds a client config from CLI-style endpoint and retry inputs.
    pub fn new(endpoint: impl Into<String>, read_retry_attempts: usize) -> anyhow::Result<Self> {
        let config = Self {
            endpoint: normalize_endpoint(&endpoint.into()),
            read_retry_attempts,
        };
        validate_config(&config)?;
        Ok(config)
    }
}

/// Constructs the SDK client used by load, bench, and validate commands.
pub fn build_client(config: &ClientConfig) -> anyhow::Result<StoreClient> {
    // `ClientConfig` exposes public fields, so re-validate here to catch a config built without
    // `new`. The endpoint is already normalized by `new`, so it is passed through unchanged.
    validate_config(config)?;
    Ok(StoreClient::builder()
        .url(&config.endpoint)
        .retry_config(
            RetryConfig::standard()
                .with_max_attempts(config.read_retry_attempts)
                .with_initial_backoff(Duration::from_millis(DEFAULT_INITIAL_BACKOFF_MS))
                .with_max_backoff(Duration::from_millis(DEFAULT_MAX_BACKOFF_MS)),
        )
        .build()?)
}

fn validate_config(config: &ClientConfig) -> anyhow::Result<()> {
    ensure!(
        config.read_retry_attempts > 0,
        "--read-retry-attempts must be > 0"
    );
    validate_endpoint(&config.endpoint)?;
    Ok(())
}

fn validate_endpoint(endpoint: &str) -> anyhow::Result<()> {
    let uri = endpoint
        .parse::<http::Uri>()
        .with_context(|| format!("invalid endpoint URL `{endpoint}`"))?;
    ensure!(
        matches!(uri.scheme_str(), Some("http" | "https")),
        "--url must use http:// or https://"
    );
    ensure!(uri.authority().is_some(), "--url must include a host");
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

    #[test]
    fn config_rejects_relative_endpoint() {
        let err = ClientConfig::new("not-a-url", 3).expect_err("relative URL should be rejected");
        assert!(err.to_string().contains("http:// or https://"));
    }

    #[test]
    fn build_client_rejects_malformed_endpoint_without_panicking() {
        let config = ClientConfig {
            endpoint: "http://[::1".to_string(),
            read_retry_attempts: 3,
        };
        let err = build_client(&config).expect_err("malformed endpoint should be rejected");
        assert!(err.to_string().contains("invalid endpoint URL"));
    }
}
