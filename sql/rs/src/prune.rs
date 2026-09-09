use exoware_sdk::kv_codec::Utf8;
use exoware_sdk::prune_policy::{
    validate_policy, GroupBy, KeysScope, OrderBy, OrderEncoding, PrunePolicy, RetainPolicy,
};
use exoware_sdk::selector::Selector;

use crate::types::ColumnKind;
use crate::KvSchema;

const VERSION_WIDTH_BYTES: usize = 8;
const ORDERED_UTF8_REGEX: &str = r"(?:\x01[\x00-\x02]|[^\x00\x01\xFF])*\x00";

impl KvSchema {
    /// Build a policy that keeps the latest `count` versions of each entity in
    /// an unindexed table with an `(entity, UInt64 version)` primary key.
    ///
    /// The table's schema determines its key prefix and entity encoding. Apply
    /// the policy through the same [`exoware_sdk::PrefixedStoreClient`] used to
    /// create this schema.
    ///
    /// Store pruning does not cascade to secondary indexes. Disable this
    /// primary-row retention policy before adding indexes to the table.
    pub fn keep_latest_versions_policy(
        &self,
        table_name: &str,
        count: usize,
    ) -> Result<PrunePolicy, String> {
        let table = self
            .tables()
            .iter()
            .find(|(name, _)| name == table_name)
            .map(|(_, table)| table)
            .ok_or_else(|| format!("unknown table '{table_name}' for version retention"))?;
        if !table.index_specs.is_empty() {
            return Err(format!(
                "version retention requires an unindexed table; '{table_name}' has secondary indexes"
            ));
        }
        let model = &table.model;
        let [entity, ColumnKind::UInt64] = model.primary_key_kinds.as_slice() else {
            return Err(format!(
                "table '{table_name}' requires an (entity, UInt64 version) primary key for version retention"
            ));
        };
        if model.primary_key_indices[0] == model.primary_key_indices[1] {
            return Err("entity and version must be distinct primary key columns".to_string());
        }
        let entity_regex = match entity.fixed_key_width() {
            Some(width) => format!(".{{{width}}}"),
            None => ORDERED_UTF8_REGEX.to_string(),
        };
        let policy = PrunePolicy {
            scope: KeysScope {
                selector: Selector {
                    prefix: model.primary_key_prefix.as_bytes().clone(),
                    payload_regex: format!(
                        r"(?s-u)^(?P<entity>{entity_regex})(?P<version>.{{{VERSION_WIDTH_BYTES}}})$"
                    )
                    .into(),
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
        };
        validate_policy(&policy).map_err(|e| e.to_string())?;
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::ORDERED_UTF8_REGEX;
    use crate::codec::{
        decode_variable_text, encode_primary_key, encode_string_variable, family_byte,
    };
    use crate::types::{
        KvTableConfig, TableColumnConfig, TableModel, PRIMARY_FAMILY_DISCRIMINATOR,
    };
    use crate::{CellValue, IndexSpec, KvSchema};
    use datafusion::arrow::datatypes::DataType;
    use exoware_sdk::kv_codec::Utf8;
    use exoware_sdk::prune_policy::{validate_policy, OrderEncoding, RetainPolicy};
    use exoware_sdk::selector::compile_payload_regex;
    use exoware_sdk::{StoreClient, StoreKeyPrefix};

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

    fn versioned_schema(entity_type: DataType) -> KvSchema {
        let client =
            StoreClient::new("http://localhost:10000").prefixed(StoreKeyPrefix::identity());
        let mut schema = KvSchema::new(client);
        for i in 0..3 {
            schema = schema
                .table(
                    format!("preceding_{i}"),
                    vec![TableColumnConfig::new("id", DataType::UInt64, false)],
                    vec!["id".to_string()],
                    vec![],
                )
                .expect("preceding table");
        }
        schema
            .table_versioned(
                "documents",
                vec![
                    TableColumnConfig::new("entity", entity_type, false),
                    TableColumnConfig::new("version", DataType::UInt64, false),
                ],
                "entity",
                "version",
                vec![],
            )
            .expect("versioned table")
    }

    fn policy(entity_type: DataType, count: usize) -> Result<super::PrunePolicy, String> {
        versioned_schema(entity_type).keep_latest_versions_policy("documents", count)
    }

    #[test]
    fn keep_latest_versions_builds_expected_policy_for_fixed_width_entity() {
        let policy = policy(DataType::FixedSizeBinary(32), 1).expect("policy");
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
        let err = policy(DataType::FixedSizeBinary(32), 0).expect_err("zero count should fail");
        assert!(err.contains("count must be > 0"));
    }

    #[test]
    fn keep_latest_versions_rejects_unknown_table() {
        let err = versioned_schema(DataType::Utf8)
            .keep_latest_versions_policy("missing", 1)
            .expect_err("unknown table should fail");
        assert!(err.contains("unknown table 'missing'"));
    }

    #[test]
    fn keep_latest_versions_rejects_indexed_tables() {
        let client =
            StoreClient::new("http://localhost:10000").prefixed(StoreKeyPrefix::identity());
        let schema = KvSchema::new(client)
            .table_versioned(
                "documents",
                vec![
                    TableColumnConfig::new("entity", DataType::Utf8, false),
                    TableColumnConfig::new("version", DataType::UInt64, false),
                    TableColumnConfig::new("tag", DataType::Int64, false),
                    TableColumnConfig::new("title", DataType::Utf8, false),
                ],
                "entity",
                "version",
                vec![IndexSpec::lexicographic("tag_idx", vec!["tag".to_string()])
                    .expect("index")
                    .with_cover_columns(vec!["title".to_string()])],
            )
            .expect("indexed table");
        let err = schema
            .keep_latest_versions_policy("documents", 1)
            .expect_err("primary-only pruning would leave secondary entries");
        assert!(err.contains("'documents' has secondary indexes"));
    }

    #[test]
    fn keep_latest_versions_rejects_non_versioned_layouts() {
        for primary_key in [
            vec!["entity"],
            vec!["entity", "version", "tag"],
            vec!["version", "entity"],
            vec!["version", "version"],
        ] {
            let client =
                StoreClient::new("http://localhost:10000").prefixed(StoreKeyPrefix::identity());
            let schema = KvSchema::new(client)
                .table(
                    "documents",
                    vec![
                        TableColumnConfig::new("entity", DataType::Utf8, false),
                        TableColumnConfig::new("version", DataType::UInt64, false),
                        TableColumnConfig::new("tag", DataType::UInt64, false),
                    ],
                    primary_key.iter().map(|name| name.to_string()).collect(),
                    vec![],
                )
                .expect("valid table");
            assert!(
                schema.keep_latest_versions_policy("documents", 1).is_err(),
                "unsupported primary key {primary_key:?}"
            );
        }
    }

    #[test]
    fn duplicate_table_names_cannot_select_a_different_retention_layout() {
        let schema = versioned_schema(DataType::Utf8);
        assert_eq!(schema.table_count(), 4);
        let policy = schema
            .keep_latest_versions_policy("documents", 1)
            .expect("original table policy");
        assert_eq!(policy.scope.selector.prefix.as_ref(), &[family_byte(3, 0)]);
        let err = schema
            .table(
                "documents",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .err()
            .expect("duplicate table name should fail");
        assert_eq!(err, "duplicate table name 'documents'");
    }

    #[test]
    fn keep_latest_versions_utf8_builds_expected_policy() {
        let policy = policy(DataType::Utf8, 1).expect("policy");
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
        let policy = policy(DataType::Utf8, 1).expect("policy");
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
        let policy = policy(DataType::UInt64, 1).expect("policy");
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
        let policy = policy(DataType::Utf8, 1).expect("policy");
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
