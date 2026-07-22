use exoware_sdk::kv_codec::Utf8;
use exoware_sdk::prune_policy::{
    GroupBy, KeysScope, OrderBy, OrderEncoding, PrunePolicy, RetainPolicy,
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
        scope: KeysScope {
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
        },
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
    use std::collections::HashSet;

    use super::{keep_latest_versions, keep_latest_versions_utf8, ORDERED_UTF8_REGEX};
    use crate::codec::{
        decode_variable_text, encode_primary_key, encode_string_variable, family_byte,
    };
    use crate::types::{
        KvTableConfig, TableColumnConfig, TableModel, PRIMARY_FAMILY_DISCRIMINATOR,
    };
    use crate::CellValue;
    use datafusion::arrow::datatypes::DataType;
    use exoware_sdk::kv_codec::Utf8;
    use exoware_sdk::prune_policy::{validate_policy, OrderEncoding, RetainPolicy};
    use exoware_sdk::selector::compile_payload_regex;

    fn keys_scope(policy: &super::PrunePolicy) -> &super::KeysScope {
        &policy.scope
    }

    fn entity_version_model(entity_type: DataType) -> TableModel {
        let config = KvTableConfig::new(
            3,
            vec![
                TableColumnConfig::new("entity", entity_type, false),
                TableColumnConfig::new("version", DataType::UInt64, false),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .expect("config");
        TableModel::from_config(&config).expect("model")
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

    // The prune regexes re-state the primary-key layout, and enforcement
    // silently retains any row a regex fails to match, so pin regex and codec
    // together: every payload the codec can produce must match in full, with
    // the grouping capture equal to the encoded entity and the order capture
    // equal to the big-endian version.
    #[test]
    fn keep_latest_versions_utf8_matches_variable_length_entity_payloads() {
        let policy = keep_latest_versions_utf8(3, 1).expect("policy");
        let scope = keys_scope(&policy);
        let regex = compile_payload_regex(&scope.selector.payload_regex).expect("regex");
        let model = entity_version_model(DataType::Utf8);
        let prefix = &model.primary_key_prefix;

        // Entities exercising every escape arm: embedded terminator bytes,
        // embedded escape-prefix bytes, and both at the boundaries.
        let entities = [
            "",
            "a",
            "alpha\x00beta",
            "\x01",
            "\x01\x00",
            "a\x01b",
            "trail\x00",
        ];
        // Versions whose big-endian bytes collide with the entity grammar: the
        // 0x00 and 0x01 bytes must neither extend nor truncate the entity
        // capture.
        let versions = [0u64, 1, 0x0100_0000_0000_0000, 0xFF, u64::MAX];

        let mut entity_captures = HashSet::new();
        for entity in entities {
            let mut per_entity = HashSet::new();
            for version in versions {
                let key = encode_primary_key(
                    3,
                    &[
                        &CellValue::Utf8(entity.to_string()),
                        &CellValue::UInt64(version),
                    ],
                    &model,
                )
                .expect("key");
                let payload = prefix.strip(&key).expect("payload");
                let captures = regex.captures(&payload).unwrap_or_else(|| {
                    panic!("regex must match entity {entity:?} at version {version}")
                });
                assert_eq!(
                    captures.get(0).expect("full match").as_bytes(),
                    payload.as_ref()
                );
                let entity_bytes = captures.name("entity").expect("entity").as_bytes();
                assert_eq!(
                    entity_bytes,
                    encode_string_variable(entity).expect("encode").as_slice()
                );
                assert_eq!(decode_variable_text(entity_bytes).as_deref(), Some(entity));
                assert_eq!(
                    captures.name("version").expect("version").as_bytes(),
                    version.to_be_bytes().as_slice()
                );
                per_entity.insert(entity_bytes.to_vec());
            }
            // Grouping correctness: every version of one entity must land in
            // the same group, and no two entities may share a group.
            assert_eq!(per_entity.len(), 1, "one group per entity");
            assert!(
                entity_captures.insert(per_entity.into_iter().next().unwrap()),
                "group for entity {entity:?} must be distinct"
            );
        }
    }

    #[test]
    fn keep_latest_versions_matches_fixed_width_entity_payloads() {
        let policy = keep_latest_versions(3, 8, 1).expect("policy");
        let scope = keys_scope(&policy);
        let regex = compile_payload_regex(&scope.selector.payload_regex).expect("regex");
        let model = entity_version_model(DataType::UInt64);
        let prefix = &model.primary_key_prefix;

        for (entity, version) in [(0u64, 0u64), (42, 7), (42, u64::MAX), (u64::MAX, 1)] {
            let key = encode_primary_key(
                3,
                &[&CellValue::UInt64(entity), &CellValue::UInt64(version)],
                &model,
            )
            .expect("key");
            let payload = prefix.strip(&key).expect("payload");
            let captures = regex.captures(&payload).expect("captures");
            assert_eq!(
                captures.get(0).expect("full match").as_bytes(),
                payload.as_ref()
            );
            assert_eq!(
                captures.name("entity").expect("entity").as_bytes(),
                entity.to_be_bytes().as_slice()
            );
            assert_eq!(
                captures.name("version").expect("version").as_bytes(),
                version.to_be_bytes().as_slice()
            );
            // A truncated row must not match and be silently mis-grouped.
            assert!(!regex.is_match(&payload[..payload.len() - 1]));
        }
    }

    #[test]
    fn keep_latest_versions_utf8_regex_rejects_malformed_payloads() {
        let policy = keep_latest_versions_utf8(3, 1).expect("policy");
        let scope = keys_scope(&policy);
        let regex = compile_payload_regex(&scope.selector.payload_regex).expect("regex");

        // 0xFF cannot appear in an ordered UTF-8 entity encoding.
        let foreign = [&[0xFF, 0x00][..], &[0x11; 8][..]].concat();
        // Escape prefix followed by a byte outside the escape range.
        let broken_escape = [&[0x01, 0x03, 0x00][..], &[0x11; 8][..]].concat();
        // Too short to carry a terminator plus a version.
        let truncated = vec![0x00_u8; 8];
        for payload in [foreign, broken_escape, truncated] {
            assert!(
                !regex.is_match(&payload),
                "regex must reject invalid payload {payload:02X?}"
            );
        }
    }
}
