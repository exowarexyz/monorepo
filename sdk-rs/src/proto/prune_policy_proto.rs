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
            threshold_u64: g.threshold_u64,
        }),
        policy_retain::KindView::GreaterThanOrEqual(g) => Ok(RetainPolicy::GreaterThanOrEqual {
            threshold_u64: g.threshold_u64,
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
