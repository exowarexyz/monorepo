use exoware_sdk_rs::kv_codec::Utf8;
use exoware_sdk_rs::prune_policy::{
    GroupBy, MatchKey, OrderBy, OrderEncoding, PrunePolicy, RetainPolicy,
};

use crate::codec::{RESERVED_BITS, UPDATE_FAMILY};

fn update_payload_regex() -> Utf8 {
    Utf8::from("(?s-u)^(?P<logical>(?:\\x00\\xFF|[^\\x00])*)\\x00\\x00(?P<version>.{8})$")
}

/// Build a prune policy that keeps the latest `count` update rows per logical raw
/// key in the standard qmdb update family.
pub fn keep_latest_updates(count: usize) -> PrunePolicy {
    PrunePolicy {
        match_key: MatchKey {
            reserved_bits: RESERVED_BITS,
            prefix: UPDATE_FAMILY,
            payload_regex: update_payload_regex(),
        },
        group_by: GroupBy {
            capture_groups: vec![Utf8::from("logical")],
        },
        order_by: Some(OrderBy {
            capture_group: Utf8::from("version"),
            encoding: OrderEncoding::U64Be,
        }),
        retain: RetainPolicy::KeepLatest { count },
    }
}

/// Build a prune policy that keeps only update rows whose uploaded location is
/// greater than or equal to `min_location`.
pub fn keep_positions_gte(min_location: u64) -> PrunePolicy {
    let mut policy = keep_latest_updates(1);
    policy.retain = RetainPolicy::GreaterThanOrEqual {
        threshold: min_location,
    };
    policy
}

#[cfg(test)]
mod tests {
    use super::{keep_latest_updates, keep_positions_gte};
    use crate::codec::{RESERVED_BITS, UPDATE_FAMILY};
    use exoware_sdk_rs::kv_codec::Utf8;
    use exoware_sdk_rs::prune_policy::{OrderEncoding, RetainPolicy};

    #[test]
    fn keep_latest_updates_matches_update_key_layout() {
        let policy = keep_latest_updates(3);
        assert_eq!(policy.match_key.reserved_bits, RESERVED_BITS);
        assert_eq!(policy.match_key.prefix, UPDATE_FAMILY);
        assert_eq!(
            &*policy.match_key.payload_regex,
            "(?s-u)^(?P<logical>(?:\\x00\\xFF|[^\\x00])*)\\x00\\x00(?P<version>.{8})$"
        );
        assert_eq!(
            policy.group_by.capture_groups,
            vec![Utf8::from("logical")]
        );
        let order_by = policy.order_by.expect("order_by");
        assert_eq!(&*order_by.capture_group, "version");
        assert_eq!(order_by.encoding, OrderEncoding::U64Be);
        assert_eq!(policy.retain, RetainPolicy::KeepLatest { count: 3 });
    }

    #[test]
    fn keep_positions_gte_uses_threshold_retention() {
        let policy = keep_positions_gte(42);
        assert_eq!(
            policy.retain,
            RetainPolicy::GreaterThanOrEqual { threshold: 42 }
        );
        assert_eq!(
            &*policy.order_by.expect("order_by").capture_group,
            "version"
        );
    }
}
