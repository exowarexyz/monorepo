use std::{ops::Range, sync::Arc};

use bytes::Bytes;

use super::{ByteLease, RequestLease};

#[derive(Clone, Copy)]
pub struct DecodeBuffers {
    pub byte_capacity: usize,
    pub entry_capacity: usize,
    pub(super) inspect_header: bool,
}

impl DecodeBuffers {
    pub fn new(byte_capacity: usize, entry_capacity: usize) -> Self {
        Self {
            byte_capacity,
            entry_capacity,
            inspect_header: false,
        }
    }

    pub(super) fn header() -> Self {
        Self {
            inspect_header: true,
            ..Self::new(0, 0)
        }
    }
}

impl Default for DecodeBuffers {
    fn default() -> Self {
        Self::new(64 * 1024, 4096)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryRanges {
    pub key: Range<usize>,
    pub value: Range<usize>,
}

// Data must be destroyed before reservations are released, including abandoned CPU output.
pub struct PutChunk {
    pub data: Bytes,
    pub(super) ranges: Vec<EntryRanges>,
    pub(super) _range_bytes: Option<ByteLease>,
    pub(super) request: Arc<RequestLease>,
    pub(super) backing_capacity: usize,
}

pub(super) struct ChunkBacking {
    pub(super) data: Vec<u8>,
    pub(super) _bytes: Option<ByteLease>,
    pub(super) _request: Arc<RequestLease>,
}

impl AsRef<[u8]> for ChunkBacking {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl PutChunk {
    /// Full byte allocation retained by any clone or slice of this chunk.
    pub fn backing_capacity(&self) -> usize {
        self.backing_capacity
    }

    pub fn ranges(&self) -> &[EntryRanges] {
        &self.ranges
    }
    pub fn entries(&self) -> impl ExactSizeIterator<Item = (&[u8], &[u8])> {
        self.ranges.iter().map(|entry| {
            (
                &self.data[entry.key.clone()],
                &self.data[entry.value.clone()],
            )
        })
    }

    pub fn request_lease(&self) -> Arc<RequestLease> {
        self.request.clone()
    }
}
