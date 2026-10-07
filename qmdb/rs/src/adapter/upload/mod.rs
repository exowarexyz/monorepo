//! Stage authenticated Commonware operation ranges and watermarks as Store rows.

mod authenticated_range;
mod boundary;

pub use authenticated_range::{
    prepare_authenticated_range, stage_authenticated_range, stage_watermark,
    AuthenticatedOperationRange, PreparedAuthenticatedRange, UploadOperation,
};
pub use boundary::recover_boundary_state;
