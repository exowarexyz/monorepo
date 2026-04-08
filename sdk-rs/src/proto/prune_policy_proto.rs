//! Convert protobuf prune-policy views into `prune_policy` domain types.

use crate::kv_codec::Utf8;
use crate::prune_policy::{
    GroupBy, MatchKey, OrderBy, OrderEncoding, PrunePolicy, PrunePolicyDocument, RetainPolicy,
    PRUNE_POLICY_DOCUMENT_VERSION,
};
use crate::store::compact::v1::{
    policy_retain, PolicyOrderByView, PolicyOrderEncoding, PolicyView, PruneRequestView,
};

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

fn retain_from_view(kind: &policy_retain::KindView<'_>) -> Result<RetainPolicy, String> {
    match kind {
        policy_retain::KindView::KeepLatest(k) => Ok(RetainPolicy::KeepLatest {
            count: usize_from_u64("keep_latest.count", k.count)?,
        }),
        policy_retain::KindView::GreaterThan(g) => Ok(RetainPolicy::GreaterThan {
            threshold: g.threshold,
        }),
        policy_retain::KindView::GreaterThanOrEqual(g) => Ok(RetainPolicy::GreaterThanOrEqual {
            threshold: g.threshold,
        }),
        policy_retain::KindView::DropAll(_) => Ok(RetainPolicy::DropAll),
    }
}

fn prune_policy_from_view(p: &PolicyView<'_>) -> Result<PrunePolicy, String> {
    if !p.match_key.is_set() {
        return Err("prune policy match_key is required".to_string());
    }
    let mk = &*p.match_key;
    let match_key = MatchKey {
        reserved_bits: u8_from_u32("match_key.reserved_bits", mk.reserved_bits)?,
        prefix: u16_from_u32("match_key.prefix", mk.prefix)?,
        payload_regex: Utf8::from(mk.payload_regex),
    };

    let group_by = if p.group_by.is_set() {
        GroupBy {
            capture_groups: p
                .group_by
                .capture_groups
                .iter()
                .map(|s| Utf8::from(&**s))
                .collect(),
        }
    } else {
        GroupBy::default()
    };

    let order_by = if p.order_by.is_set() {
        let o: &PolicyOrderByView<'_> = &p.order_by;
        Some(OrderBy {
            capture_group: Utf8::from(o.capture_group),
            encoding: order_encoding_from_proto(&o.encoding)?,
        })
    } else {
        None
    };

    if !p.retain.is_set() {
        return Err("prune policy retain is required".to_string());
    }
    let retain_view = &*p.retain;
    let Some(kind) = retain_view.kind.as_ref() else {
        return Err("prune policy retain.kind is required".to_string());
    };
    let retain = retain_from_view(kind)?;

    Ok(PrunePolicy {
        match_key,
        group_by,
        order_by,
        retain,
    })
}

pub fn prune_policies_to_proto(policies: &[PrunePolicy]) -> Vec<crate::store::compact::v1::Policy> {
    policies.iter().map(prune_policy_to_proto).collect()
}

fn prune_policy_to_proto(p: &PrunePolicy) -> crate::store::compact::v1::Policy {
    use crate::store::compact::v1::{
        policy_retain, Policy, PolicyGroupBy, PolicyMatchKey, PolicyOrderBy, PolicyRetain,
        RetainGreaterThan, RetainGreaterThanOrEqual, RetainKeepLatest,
    };

    let match_key = PolicyMatchKey {
        reserved_bits: u32::from(p.match_key.reserved_bits),
        prefix: u32::from(p.match_key.prefix),
        payload_regex: p.match_key.payload_regex.0.clone(),
        ..Default::default()
    };
    let group_by = PolicyGroupBy {
        capture_groups: p
            .group_by
            .capture_groups
            .iter()
            .map(|s| s.0.clone())
            .collect(),
        ..Default::default()
    };
    let order_by = p.order_by.as_ref().map(|o| PolicyOrderBy {
        capture_group: o.capture_group.0.clone(),
        encoding: order_encoding_to_proto(&o.encoding).into(),
        ..Default::default()
    });
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
    Policy {
        match_key: Some(match_key).into(),
        group_by: Some(group_by).into(),
        order_by: order_by.into(),
        retain: Some(PolicyRetain {
            kind: Some(retain_kind),
            ..Default::default()
        })
        .into(),
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

/// Converts a `Prune` RPC request into the shared Rust document model (fixed document version).
pub fn prune_policy_document_from_prune_request_view<'a>(
    req: &PruneRequestView<'a>,
) -> Result<PrunePolicyDocument, String> {
    let mut policies = Vec::with_capacity(req.policies.len());
    for p in req.policies.iter() {
        policies.push(prune_policy_from_view(p)?);
    }
    let out = PrunePolicyDocument {
        version: PRUNE_POLICY_DOCUMENT_VERSION,
        policies,
    };
    crate::prune_policy::validate_policy_document(&out).map_err(|e| e.to_string())?;
    Ok(out)
}
