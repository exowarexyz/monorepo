use exoware_sdk::ClientError;

#[derive(Debug, thiserror::Error)]
pub enum SimplexError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("codec error: {0}")]
    Codec(#[from] commonware_codec::Error),
    #[error("simplex certificate payload does not match header digest")]
    CertificateHeaderMismatch,
    #[error("simplex artifact does not match requested index")]
    RecordKeyMismatch,
    #[error("simplex upload contains no rows")]
    EmptyUpload,
}
