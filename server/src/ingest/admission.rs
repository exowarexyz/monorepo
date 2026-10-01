use std::sync::{Arc, Mutex};

use connectrpc::ConnectError;

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
        self.admit(wire_bound, wire_bound)
    }

    pub(super) fn try_admit_cleanup(
        self: &Arc<Self>,
        wire_bound: usize,
    ) -> Result<Admission, ConnectError> {
        self.admit(wire_bound, 0)
    }

    fn admit(
        self: &Arc<Self>,
        wire_bound: usize,
        reserved_bytes: usize,
    ) -> Result<Admission, ConnectError> {
        let mut used = self
            .used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if used.requests >= self.config.max_requests
            || reserved_bytes > self.config.max_bytes.saturating_sub(used.bytes)
        {
            return Err(ConnectError::resource_exhausted(
                "ingest admission exhausted",
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
