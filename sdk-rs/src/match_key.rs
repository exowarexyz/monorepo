//! Shared key-filter shape: `(reserved_bits, prefix, payload_regex)`.
//!
//! Used by both `prune_policy` (compact service) and `stream_filter` (stream
//! service) so one domain type round-trips through the `store.common.v1.MatchKey`
//! proto message and one regex compiler handles validation everywhere.

use anyhow::{ensure, Context};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use regex::bytes::Regex;

use crate::kv_codec::Utf8;

/// Identifies a subset of keys by `KeyCodec` family + payload regex. Matches
/// the `store.common.v1.MatchKey` wire shape (see `proto/store/v1/common.proto`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MatchKey {
    pub reserved_bits: u8,
    pub prefix: u16,
    pub payload_regex: Utf8,
}

impl Write for MatchKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.reserved_bits.write(buf);
        self.prefix.write(buf);
        self.payload_regex.write(buf);
    }
}

impl EncodeSize for MatchKey {
    fn encode_size(&self) -> usize {
        u8::SIZE + u16::SIZE + self.payload_regex.encode_size()
    }
}

impl Read for MatchKey {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(MatchKey {
            reserved_bits: u8::read(buf)?,
            prefix: u16::read(buf)?,
            payload_regex: Utf8::read(buf)?,
        })
    }
}

/// Compile the payload regex, rejecting empty / blank strings. Bytes-regex
/// because keys carry arbitrary non-UTF8 payloads.
pub fn compile_payload_regex(raw: &str) -> anyhow::Result<Regex> {
    ensure!(
        !raw.trim().is_empty(),
        "match_key payload_regex must not be empty"
    );
    Regex::new(raw).with_context(|| format!("invalid match_key payload_regex {raw:?}"))
}
