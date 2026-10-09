#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestEvent {
    WireBytes(usize),
    ReceiveElapsed(std::time::Duration),
    DecodedBytes(usize),
    DecodeElapsed(std::time::Duration),
    HttpEof,
    ValidationElapsed(std::time::Duration),
    CleanupElapsed(std::time::Duration),
    ResponseElapsed(std::time::Duration),
    Batch { entries: usize, bytes: usize },
    Validated,
    Drained { bytes: usize },
    Rejected,
}

pub trait IngestObserver: Send + Sync + 'static {
    fn observe(&self, event: IngestEvent);
}

impl IngestObserver for () {
    fn observe(&self, _: IngestEvent) {}
}
