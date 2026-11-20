//! The helpers the cases use, exported for a backend's own tests.
//!
//! They build rows, Put requests and admitted Put inputs, send Connect requests held in memory
//! to [`exoware_server::connect_stack`] as a tower service and decode the answers, read ranges
//! through cursors, and wait for background work through [`crate::Backend::pause`].

pub use crate::{
    rpc::{
        call, error_info, open_stream, request, streaming, unary, unary_call, Envelope, Envelopes,
        LOG_GET, PUT, RANGE, REDUCE, SUBSCRIBE, UNARY_PROTO,
    },
    support::{admitted_put, drain, put_request, row, scan, settle, stored_row},
};
