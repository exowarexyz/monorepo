use std::time::Duration;

use anyhow::anyhow;
use connectrpc::ErrorCode;
use exoware_sdk::keys::Key;
use exoware_sdk::{ClientError, PrefixedStoreClient};
use rand::RngExt;

const MAX_INGEST_RETRY_BACKOFF: Duration = Duration::from_secs(5);

/// Default number of key/value pairs in one ingest request for workload commands.
pub(crate) const DEFAULT_INGEST_BATCH_SIZE: usize = 100;

/// Ingest error codes that can self-resolve, so retrying the same batch is worthwhile.
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

/// Result of a batch that ingested successfully.
pub(crate) struct IngestOutcome {
    /// Store sequence number returned by the successful put.
    pub sequence_number: u64,
    /// Transient failures retried before the batch succeeded (0 on first-attempt success).
    pub transient_retries: u64,
}

/// Calculates a capped exponential retry delay with full jitter.
pub(crate) fn retry_delay(backoff: Duration, retry_number: u64) -> Duration {
    let exponent = retry_number.saturating_sub(1).min(5) as u32;
    let cap = backoff
        .saturating_mul(1_u32 << exponent)
        .min(MAX_INGEST_RETRY_BACKOFF);
    Duration::from_millis(rand::rng().random_range(0..=cap.as_millis() as u64))
}

/// Keeps server retry hints as a minimum delay and adds local jitter to avoid synchronized retries.
pub(crate) fn retry_delay_for_error(
    err: &ClientError,
    backoff: Duration,
    retry_number: u64,
) -> Duration {
    let hinted = err
        .decoded_rpc_error()
        .ok()
        .flatten()
        .and_then(|decoded| decoded.retry_info)
        .and_then(|retry_info| {
            let delay = retry_info.retry_delay.as_option()?;
            let seconds = u64::try_from(delay.seconds).ok()?;
            let nanos = u32::try_from(delay.nanos.max(0)).ok()?;
            let delay = Duration::new(seconds, nanos);
            (!delay.is_zero()).then_some(delay)
        });
    hinted
        .map(|delay| retry_delay_after_hint(delay, backoff, retry_number))
        .unwrap_or_else(|| retry_delay(backoff, retry_number))
}

fn retry_delay_after_hint(hint: Duration, backoff: Duration, retry_number: u64) -> Duration {
    hint.saturating_add(retry_delay(backoff, retry_number))
}

/// Ingests `refs`, retrying transient failures up to `attempts` times with capped exponential
/// backoff and full jitter.
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
    let mut attempts_made = 0usize;
    for attempt in 1..=attempts {
        attempts_made = attempt;
        match client.ingest().put(refs).await {
            Ok(sequence_number) => {
                return Ok(IngestOutcome {
                    sequence_number,
                    transient_retries,
                });
            }
            Err(err) if is_transient_ingest_error(&err) && attempt < attempts => {
                transient_retries += 1;
                let delay = retry_delay_for_error(&err, backoff, transient_retries);
                tracing::warn!(
                    label,
                    attempt,
                    code = ?err.rpc_code(),
                    error = %err,
                    backoff_ms = delay.as_millis(),
                    "transient ingest failure; retrying"
                );
                tokio::time::sleep(delay).await;
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
        "ingest failed for {label} after {attempts_made} attempt(s) (configured maximum: {attempts}): {err_text}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn retry_delay_stays_within_the_capped_backoff_window() {
        let delay = retry_delay(Duration::from_secs(1), 6);
        assert!(delay <= MAX_INGEST_RETRY_BACKOFF);
    }

    #[test]
    fn server_retry_hints_are_never_shortened() {
        let hint = Duration::from_secs(10);
        let delay = retry_delay_after_hint(hint, Duration::from_secs(1), 1);
        assert!(delay >= hint);
        assert!(delay <= hint + Duration::from_secs(1));
    }
}
