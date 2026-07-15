use std::time::Duration;

use anyhow::{ensure, Context};
use connectrpc::ErrorCode;
use exoware_sdk::{ClientError, PrefixedStoreClient, RetryConfig, StoreClient};

const DEFAULT_INITIAL_BACKOFF_MS: u64 = 50;
const DEFAULT_MAX_BACKOFF_MS: u64 = 1_000;

/// Shared SDK client CLI flags for validation commands.
#[derive(clap::Args, Clone, Debug)]
pub struct ClientArgs {
    #[arg(long, default_value = "http://localhost:10000")]
    pub url: String,
    /// Max client read retry attempts for lookup/range calls.
    #[arg(long, default_value_t = 3)]
    pub read_retry_attempts: usize,
}

impl ClientArgs {
    pub fn into_config(self) -> anyhow::Result<ClientConfig> {
        ClientConfig::new(self.url, self.read_retry_attempts)
    }
}

/// Normalized SDK client settings shared by validation commands.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    endpoint: String,
    read_retry_attempts: usize,
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

    /// Returns the normalized endpoint passed to the SDK client.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Returns the maximum number of attempts for SDK reads.
    pub fn read_retry_attempts(&self) -> usize {
        self.read_retry_attempts
    }
}

/// Constructs the SDK client used by load, bench, and validate commands.
pub fn build_client(config: &ClientConfig) -> anyhow::Result<PrefixedStoreClient> {
    let client = StoreClient::builder()
        .url(config.endpoint())
        .retry_config(
            RetryConfig::standard()
                .with_max_attempts(config.read_retry_attempts())
                .with_initial_backoff(Duration::from_millis(DEFAULT_INITIAL_BACKOFF_MS))
                .with_max_backoff(Duration::from_millis(DEFAULT_MAX_BACKOFF_MS)),
        )
        .build()?;

    // Workload keys already embed a run namespace after a leading entropy byte so they remain
    // spread across physical shards. The identity prefix exposes the public logical API without
    // adding a fixed prefix that would defeat that distribution.
    Ok(PrefixedStoreClient::empty(client))
}

/// Ingest error codes that can self-resolve, so retrying the same batch is worthwhile.
///
/// Deliberately broader than the query list below: validation writes are
/// deterministic and idempotent, so replaying a batch whose first attempt may
/// have landed is safe.
pub(crate) fn is_transient_ingest_code(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::ResourceExhausted
            | ErrorCode::Unavailable
            | ErrorCode::DeadlineExceeded
            | ErrorCode::Unknown
            | ErrorCode::Aborted
            | ErrorCode::Internal
    )
}

pub(crate) fn is_transient_ingest_error(err: &ClientError) -> bool {
    err.rpc_code().is_some_and(is_transient_ingest_code)
}

/// Query error codes worth re-polling; anything else fails validation fast so
/// store bugs are not retried into a timeout.
pub(crate) fn is_transient_query_code(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::Aborted | ErrorCode::ResourceExhausted | ErrorCode::Unavailable
    )
}

pub(crate) fn is_transient_query_error(err: &ClientError) -> bool {
    match err {
        ClientError::Http(_) => true,
        _ => err.rpc_code().is_some_and(is_transient_query_code),
    }
}

fn validate_config(config: &ClientConfig) -> anyhow::Result<()> {
    ensure!(
        config.read_retry_attempts > 0,
        "read_retry_attempts must be > 0"
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
        "endpoint must use http:// or https://"
    );
    ensure!(uri.authority().is_some(), "endpoint must include a host");
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
        assert_eq!(config.endpoint(), "http://localhost:10000");
    }

    #[test]
    fn config_preserves_endpoint_without_trailing_slash() {
        let config =
            ClientConfig::new("http://localhost:10000", 3).expect("client config should parse");
        assert_eq!(config.endpoint(), "http://localhost:10000");
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
        build_client(&config).expect_err("malformed endpoint should be rejected");
    }

    #[test]
    fn transient_ingest_codes_cover_connect_transients() {
        assert!(is_transient_ingest_code(ErrorCode::ResourceExhausted));
        assert!(is_transient_ingest_code(ErrorCode::Unavailable));
        assert!(is_transient_ingest_code(ErrorCode::DeadlineExceeded));
        assert!(is_transient_ingest_code(ErrorCode::Unknown));
        assert!(is_transient_ingest_code(ErrorCode::Aborted));
        assert!(is_transient_ingest_code(ErrorCode::Internal));
        assert!(!is_transient_ingest_code(ErrorCode::InvalidArgument));
    }

    #[test]
    fn transient_query_codes_cover_consistency_and_gateway_transients() {
        assert!(is_transient_query_code(ErrorCode::Aborted));
        assert!(is_transient_query_code(ErrorCode::ResourceExhausted));
        assert!(is_transient_query_code(ErrorCode::Unavailable));
        assert!(!is_transient_query_code(ErrorCode::InvalidArgument));
        assert!(!is_transient_query_code(ErrorCode::Internal));
    }

    #[test]
    fn transient_query_error_classifies_api_statuses() {
        assert!(is_transient_query_error(&ClientError::Rpc(Box::new(
            connectrpc::ConnectError::aborted("consistency not ready"),
        ))));
        assert!(is_transient_query_error(&ClientError::Rpc(Box::new(
            connectrpc::ConnectError::unavailable("load shed"),
        ))));
        assert!(!is_transient_query_error(&ClientError::Rpc(Box::new(
            connectrpc::ConnectError::invalid_argument("bad request"),
        ))));
    }
}
