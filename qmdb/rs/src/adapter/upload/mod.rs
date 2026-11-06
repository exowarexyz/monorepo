//! Stage authenticated Commonware operation ranges and watermarks as Store rows.

mod authenticated_range;

pub use authenticated_range::{
    prepare_authenticated_range, prepare_publication, stage_authenticated_range, stage_watermark,
    AuthenticatedOperationRange, PreparedAuthenticatedRange, Publication, PublicationCfg,
    UploadOperation,
};
