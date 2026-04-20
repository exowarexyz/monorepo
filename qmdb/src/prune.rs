use exoware_sdk_rs::kv_codec::Utf8;
use exoware_sdk_rs::match_key::MatchKey;
use exoware_sdk_rs::prune_policy::{
    GroupBy, KeysScope, OrderBy, OrderEncoding, PolicyScope, PrunePolicy, RetainPolicy,
};

use crate::codec::{RESERVED_BITS, UPDATE_FAMILY};

fn update_payload_regex() -> Utf8 {
    Utf8::from("(?s-u)^(?P<logical>(?:\\x00\\xFF|[^\\x00])*)\\x00\\x00(?P<version>.{8})$")
}

fn base_keys_scope() -> KeysScope {
    KeysScope {
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
    }
}

/// Build a prune policy that keeps the latest `count` update rows per logical raw
/// key in the standard qmdb update family.
pub fn keep_latest_updates(count: usize) -> PrunePolicy {
    PrunePolicy {
        scope: PolicyScope::Keys(base_keys_scope()),
        retain: RetainPolicy::KeepLatest { count },
    }
}

/// Build a prune policy that keeps only update rows whose uploaded location is
/// greater than or equal to `min_location`.
pub fn keep_positions_gte(min_location: u64) -> PrunePolicy {
    PrunePolicy {
        scope: PolicyScope::Keys(base_keys_scope()),
        retain: RetainPolicy::GreaterThanOrEqual {
            threshold: min_location,
        },
    }
}

/// Prune the store's batch log to the last `count` batches. Use with the
/// store's `stream.v1` service when you want to bound replay history.
pub fn keep_latest_batches(count: usize) -> PrunePolicy {
    PrunePolicy {
        scope: PolicyScope::Sequence,
        retain: RetainPolicy::KeepLatest { count },
    }
}

/// Prune all batches older than `min_sequence_number` (keeps sequence numbers >= threshold).
pub fn keep_batches_gte(min_sequence_number: u64) -> PrunePolicy {
    PrunePolicy {
        scope: PolicyScope::Sequence,
        retain: RetainPolicy::GreaterThanOrEqual {
            threshold: min_sequence_number,
        },
    }
}

/// Drop every retained batch. Disables replay + GetBatch entirely.
pub fn drop_all_batches() -> PrunePolicy {
    PrunePolicy {
        scope: PolicyScope::Sequence,
        retain: RetainPolicy::DropAll,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        drop_all_batches, keep_batches_gte, keep_latest_batches, keep_latest_updates,
        keep_positions_gte,
    };
    use crate::codec::{RESERVED_BITS, UPDATE_FAMILY};
    use exoware_sdk_rs::kv_codec::Utf8;
    use exoware_sdk_rs::prune_policy::{OrderEncoding, PolicyScope, RetainPolicy};

    #[test]
    fn keep_latest_updates_matches_update_key_layout() {
        let policy = keep_latest_updates(3);
        let PolicyScope::Keys(scope) = &policy.scope else {
            panic!("expected UserKeys scope");
        };
        assert_eq!(scope.match_key.reserved_bits, RESERVED_BITS);
        assert_eq!(scope.match_key.prefix, UPDATE_FAMILY);
        assert_eq!(
            &*scope.match_key.payload_regex,
            "(?s-u)^(?P<logical>(?:\\x00\\xFF|[^\\x00])*)\\x00\\x00(?P<version>.{8})$"
        );
        assert_eq!(scope.group_by.capture_groups, vec![Utf8::from("logical")]);
        let order_by = scope.order_by.as_ref().expect("order_by");
        assert_eq!(&*order_by.capture_group, "version");
        assert_eq!(order_by.encoding, OrderEncoding::U64Be);
        assert_eq!(policy.retain, RetainPolicy::KeepLatest { count: 3 });
    }

    #[test]
    fn keep_positions_gte_uses_threshold_retention() {
        let policy = keep_positions_gte(42);
        let PolicyScope::Keys(scope) = &policy.scope else {
            panic!("expected UserKeys scope");
        };
        assert_eq!(
            policy.retain,
            RetainPolicy::GreaterThanOrEqual { threshold: 42 }
        );
        assert_eq!(
            &*scope.order_by.as_ref().expect("order_by").capture_group,
            "version"
        );
    }

    #[test]
    fn keep_latest_batches_uses_batch_log_scope() {
        let policy = keep_latest_batches(10);
        assert!(matches!(policy.scope, PolicyScope::Sequence));
        assert_eq!(policy.retain, RetainPolicy::KeepLatest { count: 10 });
    }

    #[test]
    fn keep_batches_gte_uses_batch_log_scope() {
        let policy = keep_batches_gte(123);
        assert!(matches!(policy.scope, PolicyScope::Sequence));
        assert_eq!(
            policy.retain,
            RetainPolicy::GreaterThanOrEqual { threshold: 123 }
        );
    }

    #[test]
    fn drop_all_batches_uses_batch_log_scope() {
        let policy = drop_all_batches();
        assert!(matches!(policy.scope, PolicyScope::Sequence));
        assert_eq!(policy.retain, RetainPolicy::DropAll);
    }
}
