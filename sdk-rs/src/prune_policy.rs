use anyhow::{ensure, Context};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use regex::bytes::Regex;
use std::collections::HashSet;

use crate::keys::KeyCodec;
use crate::kv_codec::Utf8;

pub const PRUNE_POLICY_CONTROL_KEY: &str = "manifest/control/compaction-prune-policies";
pub const PRUNE_POLICY_DOCUMENT_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrunePolicy {
    pub match_key: MatchKey,
    pub group_by: GroupBy,
    pub order_by: Option<OrderBy>,
    pub retain: RetainPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MatchKey {
    pub reserved_bits: u8,
    pub prefix: u16,
    pub payload_regex: Utf8,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct GroupBy {
    pub capture_groups: Vec<Utf8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderBy {
    pub capture_group: Utf8,
    pub encoding: OrderEncoding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderEncoding {
    BytesAsc,
    U64Be,
    I64Be,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetainPolicy {
    KeepLatest { count: usize },
    GreaterThan { threshold: u64 },
    GreaterThanOrEqual { threshold: u64 },
    DropAll,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrunePolicyDocument {
    pub version: u32,
    pub policies: Vec<PrunePolicy>,
}

impl Write for OrderEncoding {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            OrderEncoding::BytesAsc => 0u8.write(buf),
            OrderEncoding::U64Be => 1u8.write(buf),
            OrderEncoding::I64Be => 2u8.write(buf),
        }
    }
}

impl FixedSize for OrderEncoding {
    const SIZE: usize = 1;
}

impl Read for OrderEncoding {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(OrderEncoding::BytesAsc),
            1 => Ok(OrderEncoding::U64Be),
            2 => Ok(OrderEncoding::I64Be),
            v => Err(CodecError::InvalidEnum(v)),
        }
    }
}

impl Write for RetainPolicy {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            RetainPolicy::KeepLatest { count } => {
                0u8.write(buf);
                (*count as u64).write(buf);
            }
            RetainPolicy::GreaterThan { threshold } => {
                1u8.write(buf);
                threshold.write(buf);
            }
            RetainPolicy::GreaterThanOrEqual { threshold } => {
                2u8.write(buf);
                threshold.write(buf);
            }
            RetainPolicy::DropAll => {
                3u8.write(buf);
            }
        }
    }
}

impl EncodeSize for RetainPolicy {
    fn encode_size(&self) -> usize {
        1 + match self {
            RetainPolicy::KeepLatest { .. }
            | RetainPolicy::GreaterThan { .. }
            | RetainPolicy::GreaterThanOrEqual { .. } => u64::SIZE,
            RetainPolicy::DropAll => 0,
        }
    }
}

impl Read for RetainPolicy {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(RetainPolicy::KeepLatest {
                count: u64::read(buf)? as usize,
            }),
            1 => Ok(RetainPolicy::GreaterThan {
                threshold: u64::read(buf)?,
            }),
            2 => Ok(RetainPolicy::GreaterThanOrEqual {
                threshold: u64::read(buf)?,
            }),
            3 => Ok(RetainPolicy::DropAll),
            v => Err(CodecError::InvalidEnum(v)),
        }
    }
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

impl Write for GroupBy {
    fn write(&self, buf: &mut impl BufMut) {
        self.capture_groups.as_slice().write(buf);
    }
}

impl EncodeSize for GroupBy {
    fn encode_size(&self) -> usize {
        self.capture_groups.as_slice().encode_size()
    }
}

impl Read for GroupBy {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let range: RangeCfg<usize> = (..).into();
        let capture_groups = Vec::<Utf8>::read_cfg(buf, &(range, ()))?;
        Ok(GroupBy { capture_groups })
    }
}

impl Write for OrderBy {
    fn write(&self, buf: &mut impl BufMut) {
        self.capture_group.write(buf);
        self.encoding.write(buf);
    }
}

impl EncodeSize for OrderBy {
    fn encode_size(&self) -> usize {
        self.capture_group.encode_size() + OrderEncoding::SIZE
    }
}

impl Read for OrderBy {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(OrderBy {
            capture_group: Utf8::read(buf)?,
            encoding: OrderEncoding::read(buf)?,
        })
    }
}

impl Write for PrunePolicy {
    fn write(&self, buf: &mut impl BufMut) {
        self.match_key.write(buf);
        self.group_by.write(buf);
        self.order_by.write(buf);
        self.retain.write(buf);
    }
}

impl EncodeSize for PrunePolicy {
    fn encode_size(&self) -> usize {
        self.match_key.encode_size()
            + self.group_by.encode_size()
            + self.order_by.encode_size()
            + self.retain.encode_size()
    }
}

impl Read for PrunePolicy {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(PrunePolicy {
            match_key: MatchKey::read(buf)?,
            group_by: GroupBy::read(buf)?,
            order_by: Option::<OrderBy>::read(buf)?,
            retain: RetainPolicy::read(buf)?,
        })
    }
}

impl Write for PrunePolicyDocument {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.policies.as_slice().write(buf);
    }
}

impl EncodeSize for PrunePolicyDocument {
    fn encode_size(&self) -> usize {
        u32::SIZE + self.policies.as_slice().encode_size()
    }
}

impl Read for PrunePolicyDocument {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let version = u32::read(buf)?;
        let range: RangeCfg<usize> = (..).into();
        let policies = Vec::<PrunePolicy>::read_cfg(buf, &(range, ()))?;
        Ok(PrunePolicyDocument { version, policies })
    }
}

pub fn validate_policy(policy: &PrunePolicy) -> anyhow::Result<()> {
    KeyCodec::new(policy.match_key.reserved_bits, policy.match_key.prefix);
    let regex = compile_payload_regex(&policy.match_key.payload_regex)?;
    validate_capture_groups(
        &regex,
        &policy.group_by.capture_groups,
        "group_by capture_groups",
    )?;
    ensure!(
        capture_groups_are_unique(&policy.group_by.capture_groups),
        "group_by capture_groups must not contain duplicates"
    );

    if let Some(order_by) = &policy.order_by {
        validate_capture_groups(
            &regex,
            std::slice::from_ref(&order_by.capture_group),
            "order_by capture_group",
        )?;
    }

    match policy.retain {
        RetainPolicy::KeepLatest { count } => {
            ensure!(count > 0, "keep_latest count must be > 0");
            ensure!(
                policy.order_by.is_some(),
                "keep_latest requires order_by to be configured"
            );
        }
        RetainPolicy::GreaterThan { .. } | RetainPolicy::GreaterThanOrEqual { .. } => {
            let order_by = policy
                .order_by
                .as_ref()
                .context("threshold retention requires order_by to be configured")?;
            ensure!(
                matches!(order_by.encoding, OrderEncoding::U64Be),
                "threshold retention currently requires order_by.encoding = u64_be"
            );
        }
        RetainPolicy::DropAll => {}
    }

    Ok(())
}

pub fn ensure_unique_policy_families(policies: &[PrunePolicy]) -> anyhow::Result<()> {
    let mut families = HashSet::new();
    for policy in policies {
        ensure!(
            families.insert((policy.match_key.reserved_bits, policy.match_key.prefix)),
            "duplicate compaction prune policy for reserved_bits={} family={}",
            policy.match_key.reserved_bits,
            policy.match_key.prefix
        );
    }
    Ok(())
}

pub fn validate_policy_document(document: &PrunePolicyDocument) -> anyhow::Result<()> {
    ensure!(
        document.version == PRUNE_POLICY_DOCUMENT_VERSION,
        "unsupported prune policy document version {} (expected {})",
        document.version,
        PRUNE_POLICY_DOCUMENT_VERSION
    );
    for policy in &document.policies {
        validate_policy(policy)?;
    }
    ensure_unique_policy_families(&document.policies)?;
    Ok(())
}

pub fn decode_policy_document(raw: &[u8]) -> anyhow::Result<PrunePolicyDocument> {
    if raw.is_empty() {
        return Ok(PrunePolicyDocument {
            version: PRUNE_POLICY_DOCUMENT_VERSION,
            policies: Vec::new(),
        });
    }
    let document = PrunePolicyDocument::read_cfg(&mut &*raw, &())
        .context("failed to decode prune policy document")?;
    validate_policy_document(&document)?;
    Ok(document)
}

pub fn encode_policy_document(document: &PrunePolicyDocument) -> anyhow::Result<Vec<u8>> {
    validate_policy_document(document)?;
    Ok(document.encode().to_vec())
}

pub fn compile_payload_regex(raw: &str) -> anyhow::Result<Regex> {
    ensure!(
        !raw.trim().is_empty(),
        "match_key payload_regex must not be empty"
    );
    Regex::new(raw).with_context(|| format!("invalid match_key payload_regex {raw:?}"))
}

fn validate_capture_groups(regex: &Regex, groups: &[Utf8], label: &str) -> anyhow::Result<()> {
    let known: HashSet<&str> = regex.capture_names().flatten().collect();
    for group in groups {
        ensure!(
            known.contains(&**group),
            "{label} references unknown capture group {group:?}"
        );
    }
    Ok(())
}

fn capture_groups_are_unique(groups: &[Utf8]) -> bool {
    let mut seen = HashSet::new();
    groups.iter().all(|group| seen.insert(group))
}

#[cfg(test)]
mod tests {
    use super::{
        decode_policy_document, encode_policy_document, GroupBy, MatchKey, OrderBy, OrderEncoding,
        PrunePolicy, PrunePolicyDocument, RetainPolicy, PRUNE_POLICY_CONTROL_KEY,
    };
    use crate::kv_codec::Utf8;

    fn sample_policy() -> PrunePolicy {
        PrunePolicy {
            match_key: MatchKey {
                reserved_bits: 4,
                prefix: 1,
                payload_regex: Utf8::from(
                    "(?s-u)^(?P<logical>(?:\\x00\\xFF|[^\\x00])*)\\x00\\x00(?P<version>.{8})$",
                ),
            },
            group_by: GroupBy {
                capture_groups: vec![Utf8::from("logical")],
            },
            order_by: Some(OrderBy {
                capture_group: Utf8::from("version"),
                encoding: OrderEncoding::U64Be,
            }),
            retain: RetainPolicy::KeepLatest { count: 10 },
        }
    }

    fn sample_document() -> PrunePolicyDocument {
        PrunePolicyDocument {
            version: 1,
            policies: vec![sample_policy()],
        }
    }

    #[test]
    fn codec_round_trip() {
        let encoded = encode_policy_document(&sample_document()).expect("encode");
        let decoded = decode_policy_document(&encoded).expect("decode");
        assert_eq!(decoded, sample_document());
    }

    #[test]
    fn empty_bytes_means_no_policies() {
        let decoded = decode_policy_document(b"").expect("empty ok");
        assert_eq!(decoded.version, 1);
        assert!(decoded.policies.is_empty());
        assert_eq!(
            PRUNE_POLICY_CONTROL_KEY,
            "manifest/control/compaction-prune-policies"
        );
    }

    #[test]
    fn keep_latest_requires_order_by() {
        let doc = PrunePolicyDocument {
            version: 1,
            policies: vec![PrunePolicy {
                match_key: MatchKey {
                    reserved_bits: 4,
                    prefix: 1,
                    payload_regex: Utf8::from(
                        "(?s-u)^(?P<logical>(?:\\x00\\xFF|[^\\x00])*)\\x00\\x00(?P<version>.{8})$",
                    ),
                },
                group_by: GroupBy {
                    capture_groups: vec![Utf8::from("logical")],
                },
                order_by: None,
                retain: RetainPolicy::KeepLatest { count: 1 },
            }],
        };
        let encoded = encode_policy_document(&doc);
        assert!(encoded.is_err());
        assert!(encoded
            .unwrap_err()
            .to_string()
            .contains("keep_latest requires order_by"));
    }

    #[test]
    fn capture_groups_must_exist() {
        let doc = PrunePolicyDocument {
            version: 1,
            policies: vec![PrunePolicy {
                match_key: MatchKey {
                    reserved_bits: 4,
                    prefix: 1,
                    payload_regex: Utf8::from("(?s)^(?P<logical>.+)$"),
                },
                group_by: GroupBy {
                    capture_groups: vec![Utf8::from("missing")],
                },
                order_by: Some(OrderBy {
                    capture_group: Utf8::from("logical"),
                    encoding: OrderEncoding::BytesAsc,
                }),
                retain: RetainPolicy::KeepLatest { count: 1 },
            }],
        };
        let encoded = encode_policy_document(&doc);
        assert!(encoded.is_err());
        assert!(encoded
            .unwrap_err()
            .to_string()
            .contains("unknown capture group"));
    }
}
