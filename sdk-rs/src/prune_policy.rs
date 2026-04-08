use anyhow::{ensure, Context};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::keys::KeyCodec;

pub const PRUNE_POLICY_CONTROL_KEY: &str = "manifest/control/compaction-prune-policies.yaml";
pub const PRUNE_POLICY_DOCUMENT_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrunePolicy {
    pub match_key: MatchKey,
    #[serde(default)]
    pub group_by: GroupBy,
    #[serde(default)]
    pub order_by: Option<OrderBy>,
    pub retain: RetainPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchKey {
    pub reserved_bits: u8,
    /// Family id in the key's reserved high bits (`KeyCodec`).
    #[serde(alias = "prefix")]
    pub family: u16,
    pub payload_regex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct GroupBy {
    #[serde(default)]
    pub capture_groups: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderBy {
    pub capture_group: String,
    pub encoding: OrderEncoding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderEncoding {
    BytesAsc,
    U64Be,
    I64Be,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RetainPolicy {
    KeepLatest { count: usize },
    GreaterThan { threshold_u64: u64 },
    GreaterThanOrEqual { threshold_u64: u64 },
    DropAll,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrunePolicyDocument {
    #[serde(default = "default_document_version")]
    pub version: u32,
    #[serde(default)]
    pub policies: Vec<PrunePolicy>,
}

const fn default_document_version() -> u32 {
    PRUNE_POLICY_DOCUMENT_VERSION
}

pub fn validate_policy(policy: &PrunePolicy) -> anyhow::Result<()> {
    KeyCodec::new(policy.match_key.reserved_bits, policy.match_key.family)
        .map_err(|e| anyhow::anyhow!("invalid prune policy codec: {e}"))?;
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
            families.insert((policy.match_key.reserved_bits, policy.match_key.family)),
            "duplicate compaction prune policy for reserved_bits={} family={}",
            policy.match_key.reserved_bits,
            policy.match_key.family
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

pub fn parse_policy_document_yaml(raw: &str) -> anyhow::Result<PrunePolicyDocument> {
    if raw.trim().is_empty() {
        return Ok(PrunePolicyDocument {
            version: PRUNE_POLICY_DOCUMENT_VERSION,
            policies: Vec::new(),
        });
    }
    let document: PrunePolicyDocument =
        serde_yaml::from_str(raw).context("failed to parse prune policy YAML")?;
    validate_policy_document(&document)?;
    Ok(document)
}

pub fn encode_policy_document_yaml(document: &PrunePolicyDocument) -> anyhow::Result<String> {
    validate_policy_document(document)?;
    serde_yaml::to_string(document).context("failed to encode prune policy YAML")
}

pub fn compile_payload_regex(raw: &str) -> anyhow::Result<Regex> {
    ensure!(
        !raw.trim().is_empty(),
        "match_key payload_regex must not be empty"
    );
    Regex::new(raw).with_context(|| format!("invalid match_key payload_regex {raw:?}"))
}

fn validate_capture_groups(regex: &Regex, groups: &[String], label: &str) -> anyhow::Result<()> {
    let known: HashSet<&str> = regex.capture_names().flatten().collect();
    for group in groups {
        ensure!(
            known.contains(group.as_str()),
            "{label} references unknown capture group {group:?}"
        );
    }
    Ok(())
}

fn capture_groups_are_unique(groups: &[String]) -> bool {
    let mut seen = HashSet::new();
    groups.iter().all(|group| seen.insert(group))
}

#[cfg(test)]
mod tests {
    use super::{
        encode_policy_document_yaml, parse_policy_document_yaml, GroupBy, MatchKey, OrderBy,
        OrderEncoding, PrunePolicy, PrunePolicyDocument, RetainPolicy,
        PRUNE_POLICY_CONTROL_KEY,
    };

    fn sample_policy() -> PrunePolicy {
        PrunePolicy {
            match_key: MatchKey {
                reserved_bits: 4,
                family: 1,
                payload_regex:
                    "(?s-u)^(?P<logical>(?:\\x00\\xFF|[^\\x00])*)\\x00\\x00(?P<version>.{8})$"
                        .to_string(),
            },
            group_by: GroupBy {
                capture_groups: vec!["logical".to_string()],
            },
            order_by: Some(OrderBy {
                capture_group: "version".to_string(),
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
    fn yaml_round_trip() {
        let yaml = encode_policy_document_yaml(&sample_document()).expect("encode");
        let decoded = parse_policy_document_yaml(&yaml).expect("decode");
        assert_eq!(decoded, sample_document());
    }

    #[test]
    fn empty_yaml_means_no_policies() {
        let decoded = parse_policy_document_yaml("").expect("empty ok");
        assert_eq!(decoded.version, 1);
        assert!(decoded.policies.is_empty());
        assert_eq!(
            PRUNE_POLICY_CONTROL_KEY,
            "manifest/control/compaction-prune-policies.yaml"
        );
    }

    #[test]
    fn keep_latest_requires_order_by() {
        let err = parse_policy_document_yaml(
            r#"
version: 1
policies:
  - match_key:
      reserved_bits: 4
      prefix: 1
      payload_regex: "(?s-u)^(?P<logical>(?:\\x00\\xFF|[^\\x00])*)\\x00\\x00(?P<version>.{8})$"
    group_by:
      capture_groups: ["logical"]
    retain:
      kind: keep_latest
      count: 1
"#,
        )
        .expect_err("keep_latest without order_by should fail");
        assert!(err.to_string().contains("keep_latest requires order_by"));
    }

    #[test]
    fn capture_groups_must_exist() {
        let err = parse_policy_document_yaml(
            r#"
version: 1
policies:
  - match_key:
      reserved_bits: 4
      prefix: 1
      payload_regex: "(?s)^(?P<logical>.+)$"
    group_by:
      capture_groups: ["missing"]
    order_by:
      capture_group: "logical"
      encoding: bytes_asc
    retain:
      kind: keep_latest
      count: 1
"#,
        )
        .expect_err("unknown capture group should fail");
        assert!(err.to_string().contains("unknown capture group"));
    }
}
