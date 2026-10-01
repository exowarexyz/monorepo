//! The `qmdb.v1` ConnectRPC services.
//!
//! [`server`] and [`client`] each have one module per proto service, plus one
//! module per QMDB kind that bundles the services that kind supports.

pub mod client;
pub mod proto;
pub mod server;
