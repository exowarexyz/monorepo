use std::time::Duration;

use anyhow::anyhow;
use connectrpc::ErrorCode;
use exoware_sdk::keys::Key;
use exoware_sdk::{ClientError, PrefixedStoreClient};

/// Ingest error codes that can self-resolve, so retrying the same batch is worthwhile.
pub(crate) fn is_transient_ingest_code(code: ErrorCode) -> bool {
    matches!(code, ErrorCode::ResourceExhausted | ErrorCode::Unavailable)
}

pub(crate) fn is_transient_ingest_error(err: &ClientError) -> bool {
    err.rpc_code().is_some_and(is_transient_ingest_code)
}

/// Result of a batch that ingested successfully.
pub(crate) struct IngestOutcome {
    /// Store sequence number returned by the successful put.
    pub sequence_number: u64,
    /// Transient failures retried before the batch succeeded (0 on first-attempt success).
    pub transient_retries: u64,
}

/// Ingests `refs`, retrying transient failures up to `attempts` times with a fixed `backoff`.
///
/// Each retry is logged so write-path backpressure stays visible rather than hidden, and the
/// surviving transient-retry count is returned so callers can report it. Permanent errors and
/// exhausted retries return an error tagged with `label`.
pub(crate) async fn ingest_with_retry(
    client: &PrefixedStoreClient,
    refs: &[(&Key, &[u8])],
    attempts: usize,
    backoff: Duration,
    label: &str,
) -> anyhow::Result<IngestOutcome> {
    let mut transient_retries = 0u64;
    let mut last_err: Option<ClientError> = None;
    for attempt in 1..=attempts {
        match client.ingest().put(refs).await {
            Ok(sequence_number) => {
                return Ok(IngestOutcome {
                    sequence_number,
                    transient_retries,
                });
            }
            Err(err) if is_transient_ingest_error(&err) && attempt < attempts => {
                transient_retries += 1;
                tracing::warn!(
                    label,
                    attempt,
                    code = ?err.rpc_code(),
                    error = %err,
                    "transient ingest failure; retrying"
                );
                tokio::time::sleep(backoff).await;
            }
            Err(err) => {
                last_err = Some(err);
                break;
            }
        }
    }

    let err_text = last_err
        .map(|e| e.to_string())
        .unwrap_or_else(|| "ingest exhausted retries without success".to_string());
    Err(anyhow!(
        "ingest failed for {label} after {attempts} attempts: {err_text}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_ingest_codes_cover_connect_transients() {
        assert!(is_transient_ingest_code(ErrorCode::ResourceExhausted));
        assert!(is_transient_ingest_code(ErrorCode::Unavailable));
        assert!(!is_transient_ingest_code(ErrorCode::InvalidArgument));
    }
}
