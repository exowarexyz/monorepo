#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PutEvent {
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

pub trait PutObserver: Send + Sync + 'static {
    fn observe(&self, event: PutEvent);
}

impl PutObserver for () {
    fn observe(&self, _: PutEvent) {}
}
