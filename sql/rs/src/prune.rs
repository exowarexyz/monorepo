use exoware_sdk::kv_codec::Utf8;
use exoware_sdk::prune_policy::{
    GroupBy, KeysScope, OrderBy, OrderEncoding, PolicyScope, PrunePolicy, RetainPolicy,
};
use exoware_sdk::selector::Selector;

use crate::codec::primary_key_prefix;

const VERSION_WIDTH_BYTES: usize = 8;
const ORDERED_UTF8_REGEX: &str = r"(?:\x01[\x00-\x02]|[^\x00\x01\xFF])*\x00";

fn keep_latest_versions_with_regex(
    table_prefix: u8,
    min_entity_bytes: usize,
    payload_regex: impl Into<Utf8>,
    count: usize,
) -> Result<PrunePolicy, String> {
    let payload_regex = payload_regex.into();
    if count == 0 {
        return Err("keep_latest_versions count must be > 0".to_string());
    }
    let prefix = primary_key_prefix(table_prefix)?;
    let required_bytes = min_entity_bytes
        .checked_add(VERSION_WIDTH_BYTES)
        .ok_or_else(|| "entity width overflowed when adding version width".to_string())?;
    if required_bytes > prefix.max_payload_len() {
        return Err(format!(
            "entity width {min_entity_bytes} plus version width {VERSION_WIDTH_BYTES} exceeds primary key payload capacity {}",
            prefix.max_payload_len()
        ));
    }

    Ok(PrunePolicy {
        scope: PolicyScope::Keys(KeysScope {
            selector: Selector {
                prefix: prefix.as_bytes().clone(),
                payload_regex,
            },
            group_by: GroupBy {
                capture_groups: vec![Utf8::from("entity")],
            },
            order_by: Some(OrderBy {
                capture_group: Utf8::from("version"),
                encoding: OrderEncoding::U64Be,
            }),
        }),
        retain: RetainPolicy::KeepLatest { count },
    })
}

/// Build a prune policy that keeps the latest `count` versions for each entity
/// in a `exoware-sql` versioned primary-key family with a fixed-width entity key.
///
/// The policy assumes the key layout created by `KvSchema::table_versioned`:
/// `[entity bytes][u64_be version]` under the table's primary-key family.
pub fn keep_latest_versions(
    table_prefix: u8,
    entity_key_width: usize,
    count: usize,
) -> Result<PrunePolicy, String> {
    keep_latest_versions_with_regex(
        table_prefix,
        entity_key_width,
        format!(
            r"(?s-u)^(?P<entity>.{{{entity_key_width}}})(?P<version>.{{{VERSION_WIDTH_BYTES}}})$"
        ),
        count,
    )
}

/// Build a prune policy that keeps the latest `count` versions for each entity
/// in a `exoware-sql` versioned primary-key family whose entity column is `Utf8`.
///
/// `table_versioned()` encodes ordered UTF-8 keys as an escape-aware byte stream
/// terminated by `0x00`, so the entity capture must be length-delimited by that
/// terminator rather than by a caller-provided fixed width.
pub fn keep_latest_versions_utf8(table_prefix: u8, count: usize) -> Result<PrunePolicy, String> {
    keep_latest_versions_with_regex(
        table_prefix,
        1,
        format!(r"(?s-u)^(?P<entity>{ORDERED_UTF8_REGEX})(?P<version>.{{{VERSION_WIDTH_BYTES}}})$"),
        count,
    )
}

#[cfg(test)]
mod tests {
    use super::{keep_latest_versions, keep_latest_versions_utf8, ORDERED_UTF8_REGEX};
    use crate::codec::{encode_primary_key, family_byte};
    use crate::types::{
        KvTableConfig, TableColumnConfig, TableModel, PRIMARY_FAMILY_DISCRIMINATOR,
    };
    use crate::CellValue;
    use datafusion::arrow::datatypes::DataType;
    use exoware_sdk::kv_codec::Utf8;
    use exoware_sdk::prune_policy::{validate_policy, OrderEncoding, PolicyScope, RetainPolicy};
    use exoware_sdk::selector::compile_payload_regex;

    fn keys_scope(policy: &super::PrunePolicy) -> &super::KeysScope {
        match &policy.scope {
            PolicyScope::Keys(s) => s,
            PolicyScope::Sequence => panic!("expected Keys scope"),
        }
    }

    #[test]
    fn keep_latest_versions_builds_expected_policy_for_fixed_width_entity() {
        let policy = keep_latest_versions(3, 32, 1).expect("policy");
        let scope = keys_scope(&policy);
        assert_eq!(
            &scope.selector.prefix[..],
            &[family_byte(3, PRIMARY_FAMILY_DISCRIMINATOR)]
        );
        assert_eq!(
            scope.selector.payload_regex,
            r"(?s-u)^(?P<entity>.{32})(?P<version>.{8})$"
        );
        assert_eq!(scope.group_by.capture_groups, vec![Utf8::from("entity")]);
        assert_eq!(
            &*scope.order_by.as_ref().expect("order_by").capture_group,
            "version"
        );
        assert_eq!(
            scope.order_by.as_ref().expect("order_by").encoding,
            OrderEncoding::U64Be
        );
        assert_eq!(policy.retain, RetainPolicy::KeepLatest { count: 1 });
        validate_policy(&policy).expect("policy should validate");
    }

    #[test]
    fn keep_latest_versions_rejects_zero_count() {
        let err = keep_latest_versions(3, 32, 0).expect_err("zero count should fail");
        assert!(err.contains("count must be > 0"));
    }

    #[test]
    fn keep_latest_versions_rejects_oversized_entity_width() {
        let err = keep_latest_versions(3, 1000, 1).expect_err("oversized entity should fail");
        assert!(err.contains("exceeds primary key payload capacity"));
    }

    #[test]
    fn keep_latest_versions_utf8_builds_expected_policy() {
        let policy = keep_latest_versions_utf8(3, 1).expect("policy");
        let scope = keys_scope(&policy);
        assert_eq!(
            &scope.selector.prefix[..],
            &[family_byte(3, PRIMARY_FAMILY_DISCRIMINATOR)]
        );
        assert_eq!(
            scope.selector.payload_regex,
            format!(r"(?s-u)^(?P<entity>{ORDERED_UTF8_REGEX})(?P<version>.{{8}})$")
        );
        assert_eq!(scope.group_by.capture_groups, vec![Utf8::from("entity")]);
        assert_eq!(
            &*scope.order_by.as_ref().expect("order_by").capture_group,
            "version"
        );
        assert_eq!(
            scope.order_by.as_ref().expect("order_by").encoding,
            OrderEncoding::U64Be
        );
        assert_eq!(policy.retain, RetainPolicy::KeepLatest { count: 1 });
        validate_policy(&policy).expect("policy should validate");
    }

    #[test]
    fn keep_latest_versions_utf8_matches_variable_length_entity_payloads() {
        let policy = keep_latest_versions_utf8(3, 1).expect("policy");
        let scope = keys_scope(&policy);
        let regex = compile_payload_regex(&scope.selector.payload_regex).expect("regex");
        let config = KvTableConfig::new(
            3,
            vec![
                TableColumnConfig::new("entity", DataType::Utf8, false),
                TableColumnConfig::new("version", DataType::UInt64, false),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .expect("config");
        let model = TableModel::from_config(&config).expect("model");
        let short_entity = CellValue::Utf8("a".to_string());
        let long_entity = CellValue::Utf8("alpha\x00beta".to_string());
        let short_key =
            encode_primary_key(3, &[&short_entity, &CellValue::UInt64(1)], &model).expect("key");
        let long_key =
            encode_primary_key(3, &[&long_entity, &CellValue::UInt64(2)], &model).expect("key");
        let prefix = &model.primary_key_prefix;

        for key in [&short_key, &long_key] {
            let payload = prefix.strip(key).expect("payload");
            let captures = regex.captures(&payload).expect("captures");
            assert_eq!(
                captures.get(0).expect("full match").as_bytes(),
                payload.as_ref()
            );
            assert_eq!(
                captures.name("version").expect("version").as_bytes().len(),
                8
            );
            assert!(
                captures
                    .name("entity")
                    .expect("entity")
                    .as_bytes()
                    .ends_with(&[0x00]),
                "ordered UTF-8 entity encoding should include the terminator"
            );
        }
    }
}
