//! The `qmdb.v1` ConnectRPC services.
//!
//! [`server`] and [`client`] each have one module per proto service, plus one
//! module per QMDB kind that bundles the services that kind supports.

pub mod client;
pub mod proto;
pub mod server;

use crate::{request::OperationLocations, QmdbError};

/// Maximum number of locations in a `GetOperations` RPC.
pub(crate) const MAX_REQUESTED_LOCATIONS: usize = 1024;

pub(crate) fn validate_operations_request(
    tip: u64,
    locations: &[u64],
) -> Result<OperationLocations<'_>, QmdbError> {
    if locations.len() > MAX_REQUESTED_LOCATIONS {
        return Err(QmdbError::InvalidRequestedLocations(format!(
            "operations request has {} locations, maximum is {MAX_REQUESTED_LOCATIONS}",
            locations.len()
        )));
    }
    Ok(OperationLocations::new(tip, locations)?)
}
