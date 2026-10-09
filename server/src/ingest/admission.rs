use std::sync::{Arc, Mutex};
use std::time::Duration;

use buffa::MessageName;
use connectrpc::{error::ErrorDetail, ConnectError};
use exoware_sdk::{
    google::rpc::{ErrorInfo, RetryInfo},
    limits::{INGEST_ADMISSION_EXHAUSTED_REASON, INGEST_ERROR_DOMAIN},
};

const ADMISSION_RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug)]
pub struct BudgetConfig {
    pub max_requests: usize,
    pub max_bytes: usize,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            max_requests: 256,
            max_bytes: 1024 * 1024 * 1024,
        }
    }
}

#[derive(Default)]
struct Used {
    requests: usize,
    bytes: usize,
}

pub struct IngestBudget {
    config: BudgetConfig,
    used: Mutex<Used>,
}

impl IngestBudget {
    pub fn new(config: BudgetConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            used: Mutex::new(Used::default()),
        })
    }

    pub fn try_admit(self: &Arc<Self>, wire_bound: usize) -> Result<Admission, ConnectError> {
        self.admit(wire_bound, wire_bound, true)
    }

    pub(super) fn try_admit_cleanup(
        self: &Arc<Self>,
        wire_bound: usize,
    ) -> Result<Admission, ConnectError> {
        self.admit(wire_bound, 0, false)
    }

    fn admit(
        self: &Arc<Self>,
        wire_bound: usize,
        reserved_bytes: usize,
        retryable: bool,
    ) -> Result<Admission, ConnectError> {
        let mut used = self
            .used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if used.requests >= self.config.max_requests
            || reserved_bytes > self.config.max_bytes.saturating_sub(used.bytes)
        {
            return Err(admission_exhausted(
                retryable
                    && self.config.max_requests > 0
                    && reserved_bytes <= self.config.max_bytes,
            ));
        }
        used.requests += 1;
        used.bytes += reserved_bytes;
        Ok(Admission {
            wire_bound,
            transport: Arc::new(ByteLease {
                budget: self.clone(),
                bytes: reserved_bytes,
            }),
            request: Arc::new(RequestLease {
                budget: self.clone(),
            }),
        })
    }

    pub fn usage(&self) -> (usize, usize) {
        let used = self
            .used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (used.requests, used.bytes)
    }

    fn reserve(self: &Arc<Self>, bytes: usize) -> Result<ByteLease, ConnectError> {
        self.charge(bytes)?;
        Ok(ByteLease {
            budget: self.clone(),
            bytes,
        })
    }

    fn charge(&self, bytes: usize) -> Result<(), ConnectError> {
        let mut used = self
            .used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if bytes > self.config.max_bytes.saturating_sub(used.bytes) {
            return Err(ConnectError::resource_exhausted(
                "ingest memory budget exhausted",
            ));
        }
        used.bytes += bytes;
        Ok(())
    }
}

fn admission_exhausted(retryable: bool) -> ConnectError {
    let error = ConnectError::resource_exhausted("ingest admission exhausted");
    if !retryable {
        return error;
    }

    error
        .with_detail(ErrorDetail::from_message(
            ErrorInfo::FULL_NAME,
            &ErrorInfo {
                domain: INGEST_ERROR_DOMAIN.to_owned(),
                reason: INGEST_ADMISSION_EXHAUSTED_REASON.to_owned(),
                ..Default::default()
            },
        ))
        .with_detail(ErrorDetail::from_message(
            RetryInfo::FULL_NAME,
            &RetryInfo {
                retry_delay: Some(ADMISSION_RETRY_DELAY.into()).into(),
                ..Default::default()
            },
        ))
}

// Independent leases let cleanup retain bytes without occupying another request slot.
pub struct ByteLease {
    budget: Arc<IngestBudget>,
    bytes: usize,
}

impl ByteLease {
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn try_extend(&mut self, bytes: usize) -> Result<(), ConnectError> {
        self.budget.charge(bytes)?;
        self.bytes += bytes;
        Ok(())
    }
}

impl Drop for ByteLease {
    fn drop(&mut self) {
        self.budget
            .used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .bytes -= self.bytes;
    }
}

pub struct RequestLease {
    budget: Arc<IngestBudget>,
}

impl RequestLease {
    pub fn reserve_bytes(&self, bytes: usize) -> Result<ByteLease, ConnectError> {
        self.budget.reserve(bytes)
    }
}

impl Drop for RequestLease {
    fn drop(&mut self) {
        self.budget
            .used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .requests -= 1;
    }
}

pub struct Admission {
    wire_bound: usize,
    pub(super) transport: Arc<ByteLease>,
    pub(super) request: Arc<RequestLease>,
}

impl Admission {
    pub fn request_lease(&self) -> Arc<RequestLease> {
        self.request.clone()
    }
    pub fn reserve_bytes(&self, bytes: usize) -> Result<ByteLease, ConnectError> {
        self.request.reserve_bytes(bytes)
    }
    pub fn wire_bound(&self) -> usize {
        self.wire_bound
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exoware_sdk::proto::decode_connect_error;

    #[test]
    fn only_transient_initial_admission_has_retry_details() {
        for requests_full in [false, true] {
            let budget = IngestBudget::new(BudgetConfig {
                max_requests: if requests_full { 1 } else { 2 },
                max_bytes: 8,
            });
            let held = budget.try_admit(8).unwrap();
            let error = budget.try_admit(1).err().unwrap();
            let decoded = decode_connect_error(&error).unwrap();
            assert_eq!(decoded.code, connectrpc::ErrorCode::ResourceExhausted);
            let info = decoded.error_info.unwrap();
            assert_eq!(info.domain, INGEST_ERROR_DOMAIN);
            assert_eq!(info.reason, INGEST_ADMISSION_EXHAUSTED_REASON);
            let delay = decoded.retry_info.unwrap().retry_delay.unwrap();
            assert_eq!((delay.seconds, delay.nanos), (0, 100_000_000));
            assert!(held.reserve_bytes(1).err().unwrap().details.is_empty());
            let mut lease = held.reserve_bytes(0).unwrap();
            assert!(lease.try_extend(1).unwrap_err().details.is_empty());
            assert!(budget.try_admit(9).err().unwrap().details.is_empty());
            if requests_full {
                assert!(budget
                    .try_admit_cleanup(1)
                    .err()
                    .unwrap()
                    .details
                    .is_empty());
            }
        }
        let disabled = IngestBudget::new(BudgetConfig {
            max_requests: 0,
            max_bytes: 8,
        });
        assert!(disabled.try_admit(1).err().unwrap().details.is_empty());
    }
}
