use bytes::{BufMut, Bytes, BytesMut};
use commonware_consensus::types::{Height, View};
use commonware_cryptography::Digest;
use exoware_sdk::keys::Key;

pub const FORMAT_VERSION: u8 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    BlockByDigest = 0x10,
    NotarizationByView = 0x20,
    FinalizationByView = 0x30,
    FinalizedByHeight = 0x31,
}

impl RecordKind {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn prefix(self) -> [u8; 2] {
        [FORMAT_VERSION, self.as_u8()]
    }
}

fn key_from_parts(kind: RecordKind, suffix: &[u8]) -> Key {
    let mut key = BytesMut::with_capacity(2 + suffix.len());
    key.put_u8(FORMAT_VERSION);
    key.put_u8(kind.as_u8());
    key.put_slice(suffix);
    key.freeze()
}

fn u64_suffix(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn block_by_digest<D: Digest>(digest: &D) -> Key {
    key_from_parts(RecordKind::BlockByDigest, digest.as_ref())
}

pub fn notarization_by_view(view: View) -> Key {
    key_from_parts(RecordKind::NotarizationByView, &u64_suffix(view.get()))
}

pub fn finalization_by_view(view: View) -> Key {
    key_from_parts(RecordKind::FinalizationByView, &u64_suffix(view.get()))
}

pub fn finalized_by_height(height: Height) -> Key {
    key_from_parts(RecordKind::FinalizedByHeight, &u64_suffix(height.get()))
}

pub fn range_for_kind(kind: RecordKind) -> (Key, Key) {
    let start = Bytes::copy_from_slice(&kind.prefix());
    let end = Bytes::copy_from_slice(&[FORMAT_VERSION, kind.as_u8() + 1]);
    (start, end)
}
