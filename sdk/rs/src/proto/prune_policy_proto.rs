//! Parse protobuf prune-policy messages into `prune_policy` domain types.
//!
//! Parsing checks only protobuf shape and numeric width conversions. Call the
//! validation helpers on the parsed output before applying policy effects.

use crate::kv_codec::Utf8;
use crate::match_key::MatchKey;
use crate::prune_policy::{
    GroupBy, KeysScope, OrderBy, OrderEncoding, PolicyScope, PrunePolicy, PrunePolicyDocument,
    RetainPolicy, PRUNE_POLICY_DOCUMENT_VERSION,
};
use crate::store::common::v1::MatchKey as ProtoMatchKey;
use crate::store::compact::v1::{
    policy, policy_retain, KeysScope as ProtoKeysScope, Policy as ProtoPolicy, PolicyOrderBy,
    PolicyOrderEncoding, PruneRequestView,
};
use buffa::MessageView;

fn u8_from_u32(field: &str, v: u32) -> Result<u8, String> {
    u8::try_from(v).map_err(|_| format!("{field} must fit in u8 (got {v})"))
}

fn u16_from_u32(field: &str, v: u32) -> Result<u16, String> {
    u16::try_from(v).map_err(|_| format!("{field} must fit in u16 (got {v})"))
}

fn usize_from_u64(field: &str, v: u64) -> Result<usize, String> {
    usize::try_from(v).map_err(|_| format!("{field} does not fit in usize (got {v})"))
}

fn order_encoding_from_proto(
    enc: &buffa::EnumValue<PolicyOrderEncoding>,
) -> Result<OrderEncoding, String> {
    let Some(known) = enc.as_known() else {
        return Err("order_by.encoding must be a known PolicyOrderEncoding value".to_string());
    };
    match known {
        PolicyOrderEncoding::POLICY_ORDER_ENCODING_BYTES_ASC => Ok(OrderEncoding::BytesAsc),
        PolicyOrderEncoding::POLICY_ORDER_ENCODING_U64_BE => Ok(OrderEncoding::U64Be),
        PolicyOrderEncoding::POLICY_ORDER_ENCODING_I64_BE => Ok(OrderEncoding::I64Be),
    }
}

fn retain_from_proto(kind: &policy_retain::Kind) -> Result<RetainPolicy, String> {
    match kind {
        policy_retain::Kind::KeepLatest(k) => Ok(RetainPolicy::KeepLatest {
            count: usize_from_u64("keep_latest.count", k.count)?,
        }),
        policy_retain::Kind::GreaterThan(g) => Ok(RetainPolicy::GreaterThan {
            threshold: g.threshold,
        }),
        policy_retain::Kind::GreaterThanOrEqual(g) => Ok(RetainPolicy::GreaterThanOrEqual {
            threshold: g.threshold,
        }),
        policy_retain::Kind::DropAll(_) => Ok(RetainPolicy::DropAll),
    }
}

fn match_key_from_proto(mk: &ProtoMatchKey) -> Result<MatchKey, String> {
    Ok(MatchKey {
        reserved_bits: u8_from_u32("match_key.reserved_bits", mk.reserved_bits)?,
        prefix: u16_from_u32("match_key.prefix", mk.prefix)?,
        payload_regex: Utf8::from(mk.payload_regex.clone()),
    })
}

fn order_by_from_proto(o: &PolicyOrderBy) -> Result<OrderBy, String> {
    Ok(OrderBy {
        capture_group: Utf8::from(o.capture_group.clone()),
        encoding: order_encoding_from_proto(&o.encoding)?,
    })
}

fn keys_scope_from_proto(s: &ProtoKeysScope) -> Result<KeysScope, String> {
    let Some(mk) = s.match_key.as_option() else {
        return Err("keys scope match_key is required".to_string());
    };
    let match_key = match_key_from_proto(mk)?;

    let group_by = if let Some(group_by) = s.group_by.as_option() {
        GroupBy {
            capture_groups: group_by
                .capture_groups
                .iter()
                .map(|g| Utf8::from(g.clone()))
                .collect(),
        }
    } else {
        GroupBy::default()
    };

    let order_by = s
        .order_by
        .as_option()
        .map(order_by_from_proto)
        .transpose()?;

    Ok(KeysScope {
        match_key,
        group_by,
        order_by,
    })
}

pub fn parse_prune_policy_from_proto(p: &ProtoPolicy) -> Result<PrunePolicy, String> {
    let Some(scope_proto) = p.scope.as_ref() else {
        return Err("prune policy scope is required".to_string());
    };
    let scope = match scope_proto {
        policy::Scope::Keys(keys) => PolicyScope::Keys(keys_scope_from_proto(keys)?),
        policy::Scope::Sequence(_) => PolicyScope::Sequence,
    };

    let Some(retain_proto) = p.retain.as_option() else {
        return Err("prune policy retain is required".to_string());
    };
    let Some(kind) = retain_proto.kind.as_ref() else {
        return Err("prune policy retain.kind is required".to_string());
    };
    let retain = retain_from_proto(kind)?;

    Ok(PrunePolicy { scope, retain })
}

pub fn validate_prune_policy(policy: &PrunePolicy) -> Result<(), String> {
    crate::prune_policy::validate_policy(policy).map_err(|e| e.to_string())
}

pub fn validate_prune_policy_document(document: &PrunePolicyDocument) -> Result<(), String> {
    crate::prune_policy::validate_policy_document(document).map_err(|e| e.to_string())
}

pub fn prune_policies_to_proto(policies: &[PrunePolicy]) -> Vec<crate::store::compact::v1::Policy> {
    policies.iter().map(prune_policy_to_proto).collect()
}

fn match_key_to_proto(mk: &MatchKey) -> ProtoMatchKey {
    ProtoMatchKey {
        reserved_bits: u32::from(mk.reserved_bits),
        prefix: u32::from(mk.prefix),
        payload_regex: mk.payload_regex.0.clone(),
        ..Default::default()
    }
}

fn keys_scope_to_proto(s: &KeysScope) -> ProtoKeysScope {
    use crate::store::compact::v1::{PolicyGroupBy, PolicyOrderBy};

    let match_key = match_key_to_proto(&s.match_key);
    let group_by = PolicyGroupBy {
        capture_groups: s
            .group_by
            .capture_groups
            .iter()
            .map(|s| s.0.clone())
            .collect(),
        ..Default::default()
    };
    let order_by = s.order_by.as_ref().map(|o| PolicyOrderBy {
        capture_group: o.capture_group.0.clone(),
        encoding: order_encoding_to_proto(&o.encoding).into(),
        ..Default::default()
    });
    ProtoKeysScope {
        match_key: Some(match_key).into(),
        group_by: Some(group_by).into(),
        order_by: order_by.into(),
        ..Default::default()
    }
}

fn prune_policy_to_proto(p: &PrunePolicy) -> crate::store::compact::v1::Policy {
    use crate::store::compact::v1::{
        policy_retain, Policy, PolicyRetain, RetainGreaterThan, RetainGreaterThanOrEqual,
        RetainKeepLatest,
    };

    let retain_kind = match &p.retain {
        RetainPolicy::KeepLatest { count } => {
            policy_retain::Kind::KeepLatest(Box::new(RetainKeepLatest {
                count: *count as u64,
                ..Default::default()
            }))
        }
        RetainPolicy::GreaterThan { threshold } => {
            policy_retain::Kind::GreaterThan(Box::new(RetainGreaterThan {
                threshold: *threshold,
                ..Default::default()
            }))
        }
        RetainPolicy::GreaterThanOrEqual { threshold } => {
            policy_retain::Kind::GreaterThanOrEqual(Box::new(RetainGreaterThanOrEqual {
                threshold: *threshold,
                ..Default::default()
            }))
        }
        RetainPolicy::DropAll => policy_retain::Kind::DropAll(Box::default()),
    };

    let scope = match &p.scope {
        PolicyScope::Keys(s) => policy::Scope::Keys(Box::new(keys_scope_to_proto(s))),
        PolicyScope::Sequence => policy::Scope::Sequence(Box::default()),
    };

    Policy {
        retain: Some(PolicyRetain {
            kind: Some(retain_kind),
            ..Default::default()
        })
        .into(),
        scope: Some(scope),
        ..Default::default()
    }
}

fn order_encoding_to_proto(enc: &OrderEncoding) -> PolicyOrderEncoding {
    match enc {
        OrderEncoding::BytesAsc => PolicyOrderEncoding::POLICY_ORDER_ENCODING_BYTES_ASC,
        OrderEncoding::U64Be => PolicyOrderEncoding::POLICY_ORDER_ENCODING_U64_BE,
        OrderEncoding::I64Be => PolicyOrderEncoding::POLICY_ORDER_ENCODING_I64_BE,
    }
}

/// Parses a `Prune` RPC request into the shared Rust document model (fixed document version).
pub fn parse_prune_policy_document_from_prune_request_view(
    req: &PruneRequestView<'_>,
) -> Result<PrunePolicyDocument, String> {
    let mut policies = Vec::with_capacity(req.policies.len());
    for p in req.policies.iter() {
        policies.push(parse_prune_policy_from_proto(&p.to_owned_message())?);
    }
    Ok(PrunePolicyDocument {
        version: PRUNE_POLICY_DOCUMENT_VERSION,
        policies,
    })
}

/// Parses a `Prune` RPC request and validates the resulting domain document.
pub fn parse_and_validate_policy_document(
    req: &PruneRequestView<'_>,
) -> Result<PrunePolicyDocument, String> {
    let document = parse_prune_policy_document_from_prune_request_view(req)?;
    validate_prune_policy_document(&document)?;
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::kv_codec::Utf8;
    use crate::match_key::MatchKey;
    use crate::prune_policy::{GroupBy, KeysScope, OrderBy, PrunePolicy, RetainPolicy};

    #[test]
    fn owned_proto_policy_round_trips_to_domain_policy() {
        let expected = PrunePolicy {
            scope: PolicyScope::Keys(KeysScope {
                match_key: MatchKey {
                    reserved_bits: 4,
                    prefix: 1,
                    payload_regex: Utf8::from("(?s)^(?P<logical>.*)-(?P<version>.{8})$"),
                },
                group_by: GroupBy {
                    capture_groups: vec![Utf8::from("logical")],
                },
                order_by: Some(OrderBy {
                    capture_group: Utf8::from("version"),
                    encoding: OrderEncoding::U64Be,
                }),
            }),
            retain: RetainPolicy::KeepLatest { count: 2 },
        };
        let proto = prune_policies_to_proto(std::slice::from_ref(&expected))
            .pop()
            .expect("policy");

        let actual = parse_prune_policy_from_proto(&proto).expect("from proto");

        assert_eq!(actual, expected);
    }

    #[test]
    fn parse_and_validate_rejects_invalid_policy_document() {
        use buffa::view::MessageView as _;
        use buffa::Message as _;

        let invalid = PrunePolicy {
            scope: PolicyScope::Sequence,
            retain: RetainPolicy::KeepLatest { count: 0 },
        };
        let request = crate::store::compact::v1::PruneRequest {
            policies: prune_policies_to_proto(&[invalid]),
            ..Default::default()
        };
        let bytes = request.encode_to_vec();
        let view = PruneRequestView::decode_view(&bytes).expect("decode view");

        let err = parse_and_validate_policy_document(&view).expect_err("invalid policy");

        assert!(err.contains("keep_latest count must be > 0"));
    }
}
