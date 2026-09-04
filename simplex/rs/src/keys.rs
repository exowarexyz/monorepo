use bytes::{BufMut, Bytes, BytesMut};
use commonware_consensus::types::{Height, Round};
use commonware_cryptography::Digest;
use exoware_sdk::keys::Key;

pub const FORMAT_VERSION: u8 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    HeaderByDigest = 0x10,
    BlockByDigest = 0x11,
    NotarizationByRound = 0x21,
    FinalizedByHeight = 0x31,
    FinalizationByRound = 0x32,
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

pub fn header_by_digest<D: Digest>(digest: &D) -> Key {
    key_from_parts(RecordKind::HeaderByDigest, digest.as_ref())
}

pub fn block_by_digest<D: Digest>(digest: &D) -> Key {
    key_from_parts(RecordKind::BlockByDigest, digest.as_ref())
}

fn round_key(kind: RecordKind, round: Round) -> Key {
    let mut suffix = [0; 16];
    suffix[..8].copy_from_slice(&round.epoch().get().to_be_bytes());
    suffix[8..].copy_from_slice(&round.view().get().to_be_bytes());
    key_from_parts(kind, &suffix)
}

pub fn notarization_by_round(round: Round) -> Key {
    round_key(RecordKind::NotarizationByRound, round)
}

pub fn finalization_by_round(round: Round) -> Key {
    round_key(RecordKind::FinalizationByRound, round)
}

pub fn finalized_by_height(height: Height) -> Key {
    key_from_parts(RecordKind::FinalizedByHeight, &u64_suffix(height.get()))
}

pub fn range_for_kind(kind: RecordKind) -> (Key, Key) {
    let start = Bytes::copy_from_slice(&kind.prefix());
    let end = Bytes::copy_from_slice(&[FORMAT_VERSION, kind.as_u8() + 1]);
    (start, end)
}
