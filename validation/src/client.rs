use anyhow::{ensure, Context};
use connectrpc::ErrorCode;
use exoware_sdk::{
    ClientError, ConnectRequestCompression, PrefixedStoreClient, RetryConfig, StoreClient,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_INITIAL_BACKOFF_MS: u64 = 50;
const DEFAULT_MAX_BACKOFF_MS: u64 = 1_000;

// Deterministic validation values contain long zero-filled regions. Zstd keeps
// generated write batches small without changing the SDK default for callers
// with less compressible payloads.
/// Request-body compression for outgoing RPCs.
#[derive(Copy, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum RequestCompression {
    #[default]
    Zstd,
    None,
}

impl From<RequestCompression> for ConnectRequestCompression {
    fn from(value: RequestCompression) -> Self {
        match value {
            RequestCompression::Zstd => Self::Zstd { level: 0 },
            RequestCompression::None => Self::None,
        }
    }
}

/// Shared SDK client CLI flags for validation commands.
#[derive(clap::Args, Clone, Debug)]
pub struct ClientArgs {
    /// Store base URL.
    #[arg(long, default_value = "http://localhost:8080")]
    pub store_url: String,
    /// Max client read retry attempts for lookup/range calls.
    #[arg(long, default_value_t = 3)]
    pub read_retry_attempts: usize,
    /// Request-body compression for outgoing RPCs.
    #[arg(long, value_enum, default_value_t = RequestCompression::Zstd)]
    pub request_compression: RequestCompression,
}

impl ClientArgs {
    pub fn into_config(self) -> anyhow::Result<ClientConfig> {
        Ok(ClientConfig::new(self.store_url, self.read_retry_attempts)?
            .with_request_compression(self.request_compression))
    }
}

/// Normalized SDK client settings shared by validation commands.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    store_url: String,
    read_retry_attempts: usize,
    request_compression: RequestCompression,
}

impl ClientConfig {
    /// Builds a client config from CLI-style Store URL and retry inputs.
    pub fn new(store_url: impl Into<String>, read_retry_attempts: usize) -> anyhow::Result<Self> {
        let config = Self {
            store_url: normalize_store_url(&store_url.into()),
            read_retry_attempts,
            request_compression: RequestCompression::default(),
        };
        validate_config(&config)?;
        Ok(config)
    }

    /// Overrides the request-body compression (see [`RequestCompression`]).
    pub const fn with_request_compression(mut self, compression: RequestCompression) -> Self {
        self.request_compression = compression;
        self
    }

    /// Returns the normalized Store URL passed to the SDK client.
    pub fn store_url(&self) -> &str {
        &self.store_url
    }

    /// Returns the maximum number of attempts for SDK reads.
    pub const fn read_retry_attempts(&self) -> usize {
        self.read_retry_attempts
    }

    /// Returns the request-body compression used by the SDK client.
    pub const fn request_compression(&self) -> RequestCompression {
        self.request_compression
    }
}

/// Constructs the SDK client used by load, bench, and validate commands.
pub fn build_client(config: &ClientConfig) -> anyhow::Result<PrefixedStoreClient> {
    let client = StoreClient::builder()
        .url(config.store_url())
        .connect_request_compression(config.request_compression.into())
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
    Ok(client.unprefixed())
}

/// Ingest error codes that can self-resolve, so retrying the same batch is worthwhile.
///
/// Deliberately broader than the query list below: validation writes are
/// deterministic and idempotent, so replaying a batch whose first attempt may
/// have landed is safe.
pub(crate) const fn is_transient_ingest_code(code: ErrorCode) -> bool {
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
pub(crate) const fn is_transient_query_code(code: ErrorCode) -> bool {
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
    validate_store_url(&config.store_url)?;
    Ok(())
}

fn validate_store_url(store_url: &str) -> anyhow::Result<()> {
    let uri = store_url
        .parse::<http::Uri>()
        .with_context(|| format!("invalid Store URL `{store_url}`"))?;
    ensure!(
        matches!(uri.scheme_str(), Some("http" | "https")),
        "Store URL must use http:// or https://"
    );
    ensure!(uri.authority().is_some(), "Store URL must include a host");
    Ok(())
}

fn normalize_store_url(store_url: &str) -> String {
    store_url.trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct ClientCli {
        #[command(flatten)]
        client: ClientArgs,
    }

    #[test]
    fn request_compression_cli_accepts_zstd_and_none_without_gzip() {
        for (arg, expected) in [
            ("zstd", RequestCompression::Zstd),
            ("none", RequestCompression::None),
        ] {
            let parsed =
                ClientCli::try_parse_from(["validation", "--request-compression", arg]).unwrap();
            assert_eq!(parsed.client.request_compression, expected);
        }
        assert!(
            ClientCli::try_parse_from(["validation", "--request-compression", "gzip"]).is_err()
        );
    }

    #[test]
    fn config_normalizes_store_url() {
        let config =
            ClientConfig::new("http://localhost:8080/", 3).expect("client config should parse");
        assert_eq!(config.store_url(), "http://localhost:8080");
    }

    #[test]
    fn config_preserves_store_url_without_trailing_slash() {
        let config =
            ClientConfig::new("http://localhost:8080", 3).expect("client config should parse");
        assert_eq!(config.store_url(), "http://localhost:8080");
    }

    #[test]
    fn config_rejects_zero_read_retry_attempts() {
        assert!(ClientConfig::new("http://localhost:8080", 0).is_err());
    }

    #[test]
    fn config_rejects_relative_store_url() {
        let err = ClientConfig::new("not-a-url", 3).expect_err("relative URL should be rejected");
        assert!(err.to_string().contains("http:// or https://"));
    }

    #[test]
    fn build_client_rejects_malformed_store_url_without_panicking() {
        let config = ClientConfig {
            store_url: "http://[::1".to_string(),
            read_retry_attempts: 3,
            request_compression: RequestCompression::default(),
        };
        build_client(&config).expect_err("malformed Store URL should be rejected");
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
