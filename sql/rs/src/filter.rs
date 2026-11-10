use crate::{
    aggregate::{
        compile_kv_predicate_constraint, index_row_field_ref, pk_field_ref_for_secondary_index,
    },
    builder::{projected_column_indices, ProjectionSource},
    codec::*,
    predicate::*,
    types::*,
};
use exoware_sdk::{
    keys::{Key, Prefix},
    kv_codec::{eval_predicate, KvPredicate, KvPredicateCheck},
};
use std::{cmp::Ordering, collections::HashMap};

/// A column constraint paired with the location of its value in a decoded row.
#[derive(Debug, Clone)]
pub(crate) enum PredicateAccess {
    /// Read a value decoded from the primary key.
    Pk {
        /// Position in the table's primary-key column order.
        pk_pos: usize,
        /// Condition the decoded value must satisfy.
        constraint: PredicateConstraint,
    },
    /// Read a value from the stored row or a covering index value.
    NonPk {
        /// Position in the table's column order and stored value array.
        col_idx: usize,
        /// Column type and nullability for interpreting the stored value.
        col: ResolvedColumn,
        /// Condition the decoded value must satisfy.
        constraint: PredicateConstraint,
    },
}

/// A constraint on one field's ordered key encoding, compared bytewise.
#[derive(Clone)]
pub(crate) enum EncodedIndexConstraint {
    /// Match these encoded bytes exactly.
    Eq(Vec<u8>),
    /// Match any of these encoded values. An empty list matches nothing.
    In(Vec<Vec<u8>>),
    /// Match the intersection of the lower and upper bounds.
    Range {
        /// Lower encoded bound and whether equality is allowed, or `None` if unbounded.
        min: Option<(Vec<u8>, bool)>,
        /// Upper encoded bound and whether equality is allowed, or `None` if unbounded.
        max: Option<(Vec<u8>, bool)>,
    },
}

/// A constraint on a fixed-width field in a secondary-index key payload.
#[derive(Clone)]
pub(crate) struct EncodedIndexPredicateCheck {
    /// Byte offset from the end of the index prefix to the field's first byte.
    pub(crate) payload_offset: usize,
    /// Number of encoded bytes occupied by the field.
    pub(crate) width: usize,
    /// Condition applied to the field's encoded bytes.
    pub(crate) constraint: EncodedIndexConstraint,
}

/// Candidate filtering through encoded fields of a secondary-index key.
#[derive(Clone)]
pub(crate) struct EncodedIndexPredicatePlan {
    /// Index prefix stripped before applying field offsets.
    pub(crate) prefix: Prefix,
    /// Conditions that must all pass. An empty list imposes no field restrictions.
    pub(crate) checks: Vec<EncodedIndexPredicateCheck>,
    /// Reject every key regardless of the prefix or checks.
    pub(crate) impossible: bool,
}

impl EncodedIndexPredicatePlan {
    pub(crate) fn matches_key(&self, key: &Key) -> bool {
        if self.impossible {
            return false;
        }
        let Ok(payload) = self.prefix.strip(key) else {
            return false;
        };
        for check in &self.checks {
            let Some(field) = payload.get(check.payload_offset..check.payload_offset + check.width)
            else {
                return false;
            };
            if !matches_encoded_constraint(field, &check.constraint) {
                return false;
            }
        }
        true
    }
}

/// A candidate-key filter for the constraints supported by an index layout.
#[derive(Clone)]
pub(crate) enum IndexPredicatePlan {
    /// Compare fixed-width fields directly in a lexicographic index payload.
    Encoded(EncodedIndexPredicatePlan),
    /// Evaluate shared KV field references, including fields in a Z-order index.
    Shared(KvPredicate),
}

impl IndexPredicatePlan {
    pub(crate) const fn is_impossible(&self) -> bool {
        match self {
            Self::Encoded(plan) => plan.impossible,
            Self::Shared(predicate) => predicate.contradiction,
        }
    }

    pub(crate) fn matches_key(&self, key: &Key) -> bool {
        match self {
            Self::Encoded(plan) => plan.matches_key(key),
            Self::Shared(predicate) => eval_predicate(key, None, predicate).unwrap_or(false),
        }
    }
}

/// Result of translating a column constraint into ordered key comparisons.
pub(crate) enum EncodedConstraintCompile {
    /// Encoded comparison available for the column's key representation.
    Encoded(EncodedIndexConstraint),
    /// This constraint requires evaluation outside the encoded comparison.
    Unsupported,
    /// No value of the column's kind can satisfy the constraint.
    Impossible,
}

/// Values needed to project rows and evaluate the scan's column constraints.
#[derive(Debug, Clone)]
pub(crate) struct ScanAccessPlan {
    /// Required key values, indexed by primary-key position.
    pub(crate) required_pk_mask: Vec<bool>,
    /// Required stored values, indexed by table column. Primary-key entries are false.
    pub(crate) required_non_pk_columns: Vec<bool>,
    /// Value sources in output column order, including repeated projections.
    pub(crate) projection_sources: Vec<ProjectionSource>,
    /// Column constraints paired with their value sources, all of which must pass.
    pub(crate) predicate_checks: Vec<PredicateAccess>,
}

impl ScanAccessPlan {
    pub(crate) fn new(
        model: &TableModel,
        projection: &Option<Vec<usize>>,
        predicate: &QueryPredicate,
    ) -> Self {
        let mut required_columns = vec![false; model.columns.len()];
        let projected_cols = projected_column_indices(model, projection);
        let projection_sources = projected_cols
            .iter()
            .map(|&idx| {
                required_columns[idx] = true;
                if let Some(pk_pos) = model.pk_position(idx) {
                    ProjectionSource::Pk {
                        col_idx: idx,
                        pk_pos,
                    }
                } else {
                    ProjectionSource::NonPk {
                        col_idx: idx,
                        col: model.column(idx).clone(),
                    }
                }
            })
            .collect();

        let mut predicate_checks = Vec::with_capacity(predicate.constraints.len());
        for (col_idx, constraint) in &predicate.constraints {
            required_columns[*col_idx] = true;
            if let Some(pk_pos) = model.pk_position(*col_idx) {
                predicate_checks.push(PredicateAccess::Pk {
                    pk_pos,
                    constraint: constraint.clone(),
                });
            } else {
                predicate_checks.push(PredicateAccess::NonPk {
                    col_idx: *col_idx,
                    col: model.column(*col_idx).clone(),
                    constraint: constraint.clone(),
                });
            }
        }

        let required_pk_mask = model
            .primary_key_indices
            .iter()
            .map(|&col_idx| required_columns[col_idx])
            .collect();
        for &col_idx in &model.primary_key_indices {
            required_columns[col_idx] = false;
        }

        Self {
            required_pk_mask,
            required_non_pk_columns: required_columns,
            projection_sources,
            predicate_checks,
        }
    }

    pub(crate) fn compile_index_predicate_plan(
        &self,
        model: &TableModel,
        spec: &ResolvedIndexSpec,
    ) -> IndexPredicatePlan {
        if spec.layout == IndexLayout::ZOrder {
            return IndexPredicatePlan::Shared(self.compile_shared_index_predicate(model, spec));
        }
        if spec
            .key_columns
            .iter()
            .any(|col_idx| model.column(*col_idx).kind == ColumnKind::Utf8)
            || model.primary_key_kinds.contains(&ColumnKind::Utf8)
        {
            return IndexPredicatePlan::Encoded(EncodedIndexPredicatePlan {
                prefix: spec.prefix.clone(),
                checks: Vec::new(),
                impossible: false,
            });
        }
        let mut index_column_offsets: HashMap<usize, usize> = HashMap::new();
        let mut payload_offset = 0usize;
        for col_idx in &spec.key_columns {
            let kind = model.column(*col_idx).kind;
            index_column_offsets.insert(*col_idx, payload_offset);
            payload_offset += kind.key_width();
        }

        let mut pk_offsets = Vec::with_capacity(model.primary_key_kinds.len());
        let mut pk_payload_offset = spec.key_columns_width;
        for kind in &model.primary_key_kinds {
            pk_offsets.push(pk_payload_offset);
            pk_payload_offset += kind.key_width();
        }

        let mut plan = EncodedIndexPredicatePlan {
            prefix: spec.prefix.clone(),
            checks: Vec::new(),
            impossible: false,
        };
        for check in &self.predicate_checks {
            let (payload_offset, kind, constraint) = match check {
                PredicateAccess::Pk { pk_pos, constraint } => (
                    pk_offsets[*pk_pos],
                    model.primary_key_kinds[*pk_pos],
                    constraint,
                ),
                PredicateAccess::NonPk {
                    col_idx,
                    col,
                    constraint,
                } => {
                    let Some(offset) = index_column_offsets.get(col_idx).copied() else {
                        continue;
                    };
                    (offset, col.kind, constraint)
                }
            };
            match compile_encoded_constraint(kind, constraint) {
                EncodedConstraintCompile::Encoded(compiled) => {
                    plan.checks.push(EncodedIndexPredicateCheck {
                        payload_offset,
                        width: kind.key_width(),
                        constraint: compiled,
                    });
                }
                EncodedConstraintCompile::Unsupported => {}
                EncodedConstraintCompile::Impossible => {
                    plan.impossible = true;
                    return IndexPredicatePlan::Encoded(plan);
                }
            }
        }

        IndexPredicatePlan::Encoded(plan)
    }

    pub(crate) fn compile_shared_index_predicate(
        &self,
        model: &TableModel,
        spec: &ResolvedIndexSpec,
    ) -> KvPredicate {
        let mut checks = Vec::with_capacity(self.predicate_checks.len());
        for check in &self.predicate_checks {
            let (field, constraint) = match check {
                PredicateAccess::Pk { pk_pos, constraint } => (
                    pk_field_ref_for_secondary_index(*pk_pos, model, spec),
                    constraint,
                ),
                PredicateAccess::NonPk {
                    col_idx,
                    constraint,
                    ..
                } => {
                    if !spec.key_columns.contains(col_idx) {
                        continue;
                    }
                    (index_row_field_ref(*col_idx, model, spec), constraint)
                }
            };
            let Some(field) = field else { continue };
            checks.push(KvPredicateCheck {
                field,
                constraint: compile_kv_predicate_constraint(constraint),
            });
        }

        KvPredicate {
            checks,
            contradiction: false,
        }
    }

    pub(crate) fn index_covers_required_non_pk(&self, spec: &ResolvedIndexSpec) -> bool {
        self.required_non_pk_columns
            .iter()
            .enumerate()
            .all(|(col_idx, required)| !*required || spec.value_column_mask[col_idx])
    }

    pub(crate) fn predicate_fully_enforced_by_primary_key(&self, model: &TableModel) -> bool {
        let mut enforced_pk_positions = vec![false; model.primary_key_indices.len()];
        let mut prefix_encoded_width = 0usize;

        for (pk_pos, &kind) in model.primary_key_kinds.iter().enumerate() {
            let Some(constraint) = self.predicate_checks.iter().find_map(|check| match check {
                PredicateAccess::Pk {
                    pk_pos: check_pos,
                    constraint,
                } if *check_pos == pk_pos => Some(constraint),
                _ => None,
            }) else {
                break;
            };

            match primary_key_range_constraint_for_prefix(
                model.primary_key_prefix.max_payload_len(),
                prefix_encoded_width,
                kind,
                constraint,
            ) {
                PrimaryKeyRangeConstraint::Point(point) => {
                    enforced_pk_positions[pk_pos] = true;
                    prefix_encoded_width += point.encoded_width;
                }
                PrimaryKeyRangeConstraint::Terminal(_) => {
                    enforced_pk_positions[pk_pos] = true;
                    break;
                }
                PrimaryKeyRangeConstraint::NotEnforced => break,
            }
        }

        self.predicate_checks.iter().all(|check| match check {
            PredicateAccess::Pk { pk_pos, .. } => enforced_pk_positions[*pk_pos],
            PredicateAccess::NonPk { .. } => false,
        })
    }

    /// Whether reading the cross product of primary-key points enforces every constraint.
    ///
    /// Each point fixes every key column to a value its constraint admits, so a row stored
    /// under a point passes every primary-key check. A check on another column needs the row.
    /// The answer holds only for a scan that reads the points and not key ranges.
    pub(crate) fn predicate_fully_enforced_by_primary_key_points(&self) -> bool {
        self.predicate_checks
            .iter()
            .all(|check| matches!(check, PredicateAccess::Pk { .. }))
    }

    /// Whether the key ranges planned for an index are proven to admit only the entries the
    /// predicate accepts.
    ///
    /// The proof is conservative. `true` means the ranges are exact, and `false` means only
    /// that the proof does not cover them. It covers lexicographic indexes. A z-order key
    /// interleaves its columns, and the proof does not analyze its ranges.
    ///
    /// A range bound holds the index key columns and then the primary-key columns, compared as
    /// one tuple. Bounds can therefore fix each leading column to one value and give the next
    /// column an inclusive range. These are the bounds of one of the two ranges for
    /// `a = 7 AND b IN (2, 3) AND c >= 5` on an index over `(a, b, c)` with primary key `(id)`:
    ///
    /// ```text
    ///            index key columns     suffix
    ///           +-----+-----+-----+   +-----+
    ///           |  a  |  b  |  c  |   | id  |
    ///           +-----+-----+-----+   +-----+
    ///   lower      7     2     5        min
    ///   upper      7     2    max       max
    ///           '---- enforced ---'   not enforced
    /// ```
    ///
    /// Here `min` and `max` are the ends of a column's type. An entry with a greater `c` sorts
    /// between the bounds whatever its `id`, so the proof counts no column after that range as
    /// enforced. It accepts a predicate whose every constraint sits in the enforced part and is
    /// one the bounds are known to encode.
    ///
    /// - An index key column encodes a single value, an IN list as one range per value, and an
    ///   inclusive range within its type. A strict float bound admits the bound itself, and a date
    ///   bound that no date can meet is clamped to admit the type's first or last date, so the
    ///   proof accepts neither.
    /// - A primary-key column in the suffix encodes only an `Int64` or `UInt64` range. For any
    ///   other constraint or column type, its bounds span every value of the column.
    /// - A primary-key column that is also an index key column is enforced there. Its suffix
    ///   position repeats that value, and the proof treats the position as fixed only for an
    ///   integer column.
    pub(crate) fn predicate_fully_enforced_by_index_key(
        &self,
        model: &TableModel,
        spec: &ResolvedIndexSpec,
    ) -> bool {
        if spec.layout == IndexLayout::ZOrder {
            return false;
        }
        let constraint_on = |col_idx: usize| {
            let pk_pos = model.pk_position(col_idx);
            self.predicate_checks.iter().find_map(|check| match check {
                PredicateAccess::Pk {
                    pk_pos: check_pos,
                    constraint,
                } if Some(*check_pos) == pk_pos => Some(constraint),
                PredicateAccess::NonPk {
                    col_idx: check_col_idx,
                    constraint,
                    ..
                } if *check_col_idx == col_idx => Some(constraint),
                _ => None,
            })
        };

        // Bounds restrict a column only while every column before it is fixed to one value.
        let mut fixed = true;
        for &col_idx in &spec.key_columns {
            let Some(constraint) = constraint_on(col_idx) else {
                fixed = false;
                continue;
            };
            let kind = model.column(col_idx).kind;

            // Store ranges include their endpoints, so the range for a strict float bound also
            // holds rows equal to the bound.
            let strict = matches!(constraint, PredicateConstraint::FloatRange { min, max }
                if min.is_some_and(|(_, inclusive)| !inclusive)
                    || max.is_some_and(|(_, inclusive)| !inclusive));
            if !fixed
                || strict
                || !matches!(
                    compile_encoded_constraint(kind, constraint),
                    EncodedConstraintCompile::Encoded(_)
                )
            {
                return false;
            }
            fixed = QueryPredicate::constraint_is_point(kind, constraint);
        }

        // The suffix bounds carry integer ranges alone. A suffix position stays fixed for an
        // integer bound to one value, including one value of an IN list on a key column.
        for (&col_idx, &kind) in model
            .primary_key_indices
            .iter()
            .zip(&model.primary_key_kinds)
        {
            let constraint = constraint_on(col_idx);
            let integer = matches!(kind, ColumnKind::Int64 | ColumnKind::UInt64);
            let ranged = matches!(
                constraint,
                Some(
                    PredicateConstraint::IntRange { .. } | PredicateConstraint::UInt64Range { .. }
                )
            );
            if constraint.is_some()
                && !spec.key_columns.contains(&col_idx)
                && !(fixed && integer && ranged)
            {
                return false;
            }
            fixed &= integer
                && constraint.is_some_and(|constraint| {
                    QueryPredicate::constraint_is_point(kind, constraint)
                });
        }

        // No bound holds a column outside the index key and the primary key.
        self.predicate_checks.iter().all(|check| match check {
            PredicateAccess::Pk { .. } => true,
            PredicateAccess::NonPk { col_idx, .. } => spec.key_columns.contains(col_idx),
        })
    }
}

pub(crate) fn matches_encoded_constraint(
    field: &[u8],
    constraint: &EncodedIndexConstraint,
) -> bool {
    match constraint {
        EncodedIndexConstraint::Eq(expected) => field == expected.as_slice(),
        EncodedIndexConstraint::In(values) => {
            values.iter().any(|candidate| field == candidate.as_slice())
        }
        EncodedIndexConstraint::Range { min, max } => {
            if let Some((bound, inclusive)) = min {
                match field.cmp(bound.as_slice()) {
                    Ordering::Less => return false,
                    Ordering::Equal if !inclusive => return false,
                    Ordering::Equal | Ordering::Greater => {}
                }
            }
            if let Some((bound, inclusive)) = max {
                match field.cmp(bound.as_slice()) {
                    Ordering::Greater => return false,
                    Ordering::Equal if !inclusive => return false,
                    Ordering::Equal | Ordering::Less => {}
                }
            }
            true
        }
    }
}

pub(crate) fn compile_encoded_constraint(
    kind: ColumnKind,
    constraint: &PredicateConstraint,
) -> EncodedConstraintCompile {
    match (kind, constraint) {
        (_, PredicateConstraint::IsNotNull) => EncodedConstraintCompile::Unsupported,
        (_, PredicateConstraint::IsNull) => EncodedConstraintCompile::Impossible,
        (ColumnKind::Utf8, PredicateConstraint::StringEq(value)) => {
            match encode_string_variable(value) {
                Ok(bytes) => EncodedConstraintCompile::Encoded(EncodedIndexConstraint::Eq(bytes)),
                Err(_) => EncodedConstraintCompile::Impossible,
            }
        }
        (ColumnKind::Utf8, PredicateConstraint::StringIn(values)) => {
            let mut encoded = Vec::with_capacity(values.len());
            for value in values {
                let Ok(bytes) = encode_string_variable(value) else {
                    continue;
                };
                encoded.push(bytes);
            }
            if encoded.is_empty() {
                EncodedConstraintCompile::Impossible
            } else {
                EncodedConstraintCompile::Encoded(EncodedIndexConstraint::In(encoded))
            }
        }
        (ColumnKind::Boolean, PredicateConstraint::BoolEq(value)) => {
            EncodedConstraintCompile::Encoded(EncodedIndexConstraint::Eq(vec![u8::from(*value)]))
        }
        (
            ColumnKind::Int64 | ColumnKind::Date64 | ColumnKind::Timestamp,
            PredicateConstraint::IntRange { min, max },
        ) => {
            let min = min.map(|v| (encode_i64_ordered(v).to_vec(), true));
            let max = max.map(|v| (encode_i64_ordered(v).to_vec(), true));
            EncodedConstraintCompile::Encoded(EncodedIndexConstraint::Range { min, max })
        }
        (ColumnKind::Int64, PredicateConstraint::IntIn(values)) => {
            let encoded = values
                .iter()
                .map(|v| encode_i64_ordered(*v).to_vec())
                .collect::<Vec<_>>();
            if encoded.is_empty() {
                EncodedConstraintCompile::Impossible
            } else {
                EncodedConstraintCompile::Encoded(EncodedIndexConstraint::In(encoded))
            }
        }
        (ColumnKind::UInt64, PredicateConstraint::UInt64Range { min, max }) => {
            let min = min.map(|v| (v.to_be_bytes().to_vec(), true));
            let max = max.map(|v| (v.to_be_bytes().to_vec(), true));
            EncodedConstraintCompile::Encoded(EncodedIndexConstraint::Range { min, max })
        }
        (ColumnKind::UInt64, PredicateConstraint::UInt64In(values)) => {
            let encoded = values
                .iter()
                .map(|v| v.to_be_bytes().to_vec())
                .collect::<Vec<_>>();
            if encoded.is_empty() {
                EncodedConstraintCompile::Impossible
            } else {
                EncodedConstraintCompile::Encoded(EncodedIndexConstraint::In(encoded))
            }
        }
        (ColumnKind::Date32, PredicateConstraint::IntRange { min, max }) => {
            let min_i32 = match min {
                Some(v) if *v > i64::from(i32::MAX) => return EncodedConstraintCompile::Impossible,
                Some(v) if *v < i64::from(i32::MIN) => i32::MIN,
                Some(v) => *v as i32,
                None => i32::MIN,
            };
            let max_i32 = match max {
                Some(v) if *v < i64::from(i32::MIN) => return EncodedConstraintCompile::Impossible,
                Some(v) if *v > i64::from(i32::MAX) => i32::MAX,
                Some(v) => *v as i32,
                None => i32::MAX,
            };
            if min_i32 > max_i32 {
                return EncodedConstraintCompile::Impossible;
            }
            let min = Some((encode_i32_ordered(min_i32).to_vec(), true));
            let max = Some((encode_i32_ordered(max_i32).to_vec(), true));
            EncodedConstraintCompile::Encoded(EncodedIndexConstraint::Range { min, max })
        }
        (ColumnKind::Float64, PredicateConstraint::FloatRange { min, max }) => {
            let min = min.map(|(v, inclusive)| (encode_f64_ordered(v).to_vec(), inclusive));
            let max = max.map(|(v, inclusive)| (encode_f64_ordered(v).to_vec(), inclusive));
            EncodedConstraintCompile::Encoded(EncodedIndexConstraint::Range { min, max })
        }
        (ColumnKind::Decimal128, PredicateConstraint::Decimal128Range { min, max }) => {
            let min = min.map(|v| (encode_i128_ordered(v).to_vec(), true));
            let max = max.map(|v| (encode_i128_ordered(v).to_vec(), true));
            EncodedConstraintCompile::Encoded(EncodedIndexConstraint::Range { min, max })
        }
        (ColumnKind::Decimal256, PredicateConstraint::Decimal256Range { min, max }) => {
            let min = min.map(|v| (encode_i256_ordered(v).to_vec(), true));
            let max = max.map(|v| (encode_i256_ordered(v).to_vec(), true));
            EncodedConstraintCompile::Encoded(EncodedIndexConstraint::Range { min, max })
        }
        (ColumnKind::FixedSizeBinary(expected), PredicateConstraint::FixedSizeBinaryEq(value)) => {
            if value.len() != expected {
                EncodedConstraintCompile::Impossible
            } else {
                EncodedConstraintCompile::Encoded(EncodedIndexConstraint::Eq(value.clone()))
            }
        }
        (ColumnKind::FixedSizeBinary(expected), PredicateConstraint::FixedSizeBinaryIn(values)) => {
            let encoded = values
                .iter()
                .filter(|v| v.len() == expected)
                .cloned()
                .collect::<Vec<_>>();
            if encoded.is_empty() {
                EncodedConstraintCompile::Impossible
            } else {
                EncodedConstraintCompile::Encoded(EncodedIndexConstraint::In(encoded))
            }
        }
        _ => EncodedConstraintCompile::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::datatypes::DataType;

    #[test]
    fn exclusive_float_bounds_require_recheck() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("x", DataType::Float64, false),
            ],
            vec!["id".into()],
            vec![IndexSpec::new("x_idx", vec!["x".into()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();

        // Store ranges include their endpoints, so only inclusive float bounds are exact.
        for (min, max, exact) in [
            (Some((1.0, false)), None, false),
            (None, Some((1.0, false)), false),
            (Some((1.0, true)), None, true),
            (None, Some((1.0, true)), true),
            (Some((1.0, true)), Some((1.0, true)), true),
            (Some((0.0, false)), Some((1.0, true)), false),
            (Some((0.0, true)), Some((1.0, false)), false),
        ] {
            let mut predicate = QueryPredicate::default();
            predicate
                .constraints
                .insert(1, PredicateConstraint::FloatRange { min, max });
            let access = ScanAccessPlan::new(&model, &None, &predicate);
            assert_eq!(
                access.predicate_fully_enforced_by_index_key(&model, &specs[0]),
                exact,
                "min={min:?}, max={max:?}"
            );
        }
    }

    /// Builds a table with one lexicographic index per list of key columns.
    fn indexed_table(
        columns: &[(&str, DataType)],
        primary_key: &[&str],
        indexes: &[&[&str]],
    ) -> (TableModel, Vec<ResolvedIndexSpec>) {
        let names = |names: &[&str]| {
            names
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>()
        };
        let config = KvTableConfig::new(
            0,
            columns
                .iter()
                .map(|(name, data_type)| TableColumnConfig::new(*name, data_type.clone(), false))
                .collect(),
            names(primary_key),
            indexes
                .iter()
                .map(|keys| IndexSpec::new(keys.join("_"), names(keys)).unwrap())
                .collect(),
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();
        (model, specs)
    }

    fn int_range(min: Option<i64>, max: Option<i64>) -> PredicateConstraint {
        PredicateConstraint::IntRange { min, max }
    }

    fn unsigned_range(min: Option<u64>, max: Option<u64>) -> PredicateConstraint {
        PredicateConstraint::UInt64Range { min, max }
    }

    /// Range bounds fix each leading column of the index key and its primary-key suffix to one
    /// value, bound the next column with an inclusive range, and enforce nothing after it.
    #[test]
    fn index_ranges_are_exact_only_for_what_their_bounds_enforce() {
        use PredicateConstraint::{IntIn, StringEq};
        let is = |value| int_range(Some(value), Some(value));
        let from = |value| int_range(Some(value), None);
        let unsigned_is = |value| unsigned_range(Some(value), Some(value));
        let unsigned_from = |value| unsigned_range(Some(value), None);
        let named = || StringEq("n".into());
        let check =
            |model: &TableModel, spec: &ResolvedIndexSpec, case: &str, constraints, exact| {
                let mut predicate = QueryPredicate::default();
                predicate.constraints.extend::<Vec<_>>(constraints);
                let access = ScanAccessPlan::new(model, &None, &predicate);
                assert_eq!(
                    access.predicate_fully_enforced_by_index_key(model, spec),
                    exact,
                    "{case} on index {}",
                    spec.name
                );
            };

        // Every index key ends with the primary key (id1, id2, name).
        let (model, specs) = indexed_table(
            &[
                ("id1", DataType::Int64),
                ("id2", DataType::UInt64),
                ("name", DataType::Utf8),
                ("tag", DataType::Int64),
                ("day", DataType::Date32),
            ],
            &["id1", "id2", "name"],
            &[&["tag"], &["tag", "id1"], &["day"]],
        );
        let [id1, id2, name, tag, day] = [0, 1, 2, 3, 4];
        let [by_tag, by_tag_id1, by_day] = [&specs[0], &specs[1], &specs[2]];
        for (case, spec, constraints, exact) in [
            ("no constraint", by_tag, vec![], true),
            ("key point", by_tag, vec![(tag, is(7))], true),
            ("key IN list", by_tag, vec![(tag, IntIn(vec![7, 9]))], true),
            ("key range", by_tag, vec![(tag, from(7))], true),
            (
                "first suffix range",
                by_tag,
                vec![(tag, is(7)), (id1, from(5))],
                true,
            ),
            (
                "range after a suffix point",
                by_tag,
                vec![(tag, is(7)), (id1, is(5)), (id2, unsigned_from(2))],
                true,
            ),
            (
                "suffix range under a key IN list",
                by_tag,
                vec![(tag, IntIn(vec![7, 9])), (id1, from(5))],
                true,
            ),
            (
                "key IN list that the suffix repeats",
                by_tag_id1,
                vec![
                    (tag, is(7)),
                    (id1, IntIn(vec![5, 6])),
                    (id2, unsigned_from(2)),
                ],
                true,
            ),
            ("date range", by_day, vec![(day, from(3))], true),
            (
                "suffix range after a free suffix column",
                by_tag,
                vec![(tag, is(7)), (id2, unsigned_from(2))],
                false,
            ),
            (
                "suffix IN list",
                by_tag,
                vec![(tag, is(7)), (id1, IntIn(vec![5, 6]))],
                false,
            ),
            (
                "string suffix column",
                by_tag,
                vec![
                    (tag, is(7)),
                    (id1, is(5)),
                    (id2, unsigned_is(2)),
                    (name, named()),
                ],
                false,
            ),
            (
                "date bound outside the type",
                by_day,
                vec![(day, from(i64::from(i32::MAX) + 1))],
                false,
            ),
        ] {
            check(&model, spec, case, constraints, exact);
        }

        // A string leads the primary-key suffix here. Range bounds never encode it there, even
        // when the index key fixes it.
        let (model, specs) = indexed_table(
            &[
                ("name", DataType::Utf8),
                ("id", DataType::Int64),
                ("tag", DataType::Int64),
            ],
            &["name", "id"],
            &[&["tag", "name"]],
        );
        let [name, id, tag] = [0, 1, 2];
        for (case, spec, constraints, exact) in [
            (
                "string key column that the suffix repeats",
                &specs[0],
                vec![(tag, is(7)), (name, named())],
                true,
            ),
            (
                "range after a repeated string key column",
                &specs[0],
                vec![(tag, is(7)), (name, named()), (id, from(5))],
                false,
            ),
        ] {
            check(&model, spec, case, constraints, exact);
        }
    }

    /// An exact answer must hold against the ranges the planner builds. Over small tables and
    /// every mix of constraints, the ranges admit every matching index entry, and exact ranges
    /// admit no other entry.
    #[test]
    fn exact_index_ranges_admit_only_matching_entries() {
        fn constraints(kind: ColumnKind) -> Vec<PredicateConstraint> {
            use PredicateConstraint::{FloatRange, IntIn, StringEq, StringIn, UInt64In};
            let float = |min, max| FloatRange { min, max };
            match kind {
                ColumnKind::Int64 => vec![
                    int_range(Some(5), Some(5)),
                    int_range(Some(5), None),
                    int_range(Some(4), Some(5)),
                    IntIn(vec![4, 6]),
                ],
                ColumnKind::UInt64 => vec![
                    unsigned_range(Some(2), Some(2)),
                    unsigned_range(None, Some(2)),
                    UInt64In(vec![1, 3]),
                ],
                ColumnKind::Utf8 => vec![
                    StringEq("n".into()),
                    StringEq(String::new()),
                    StringIn(vec![String::new(), "o".into()]),
                ],
                ColumnKind::Float64 => vec![
                    float(Some((1.0, true)), Some((1.0, true))),
                    float(Some((1.0, true)), None),
                    float(Some((1.0, false)), None),
                ],
                ColumnKind::Date32 => vec![
                    int_range(Some(5), Some(5)),
                    int_range(None, Some(5)),
                    int_range(Some(i64::from(i32::MAX) + 1), None),
                ],
                _ => unreachable!("the tables must use only these column kinds"),
            }
        }
        fn values(kind: ColumnKind) -> Vec<CellValue> {
            match kind {
                ColumnKind::Int64 => [4, 5, 6].map(CellValue::Int64).to_vec(),
                ColumnKind::UInt64 => [1, 2, 3].map(CellValue::UInt64).to_vec(),
                ColumnKind::Utf8 => ["", "n", "o"].map(|v| CellValue::Utf8(v.into())).to_vec(),
                ColumnKind::Float64 => [0.5, 1.0, 2.0].map(CellValue::Float64).to_vec(),
                ColumnKind::Date32 => [0, 5, i32::MAX].map(CellValue::Date32).to_vec(),
                _ => unreachable!("the tables must use only these column kinds"),
            }
        }
        /// Returns every way to take one choice per column.
        fn product<T: Clone>(columns: Vec<Vec<T>>) -> Vec<Vec<T>> {
            columns.into_iter().fold(vec![Vec::new()], |rows, choices| {
                let extend = |row: &Vec<T>| {
                    let row = row.clone();
                    choices.iter().map(move |choice| {
                        let mut row = row.clone();
                        row.push(choice.clone());
                        row
                    })
                };
                rows.iter().flat_map(extend).collect()
            })
        }

        // The tables put integers and strings in each position of the index key and of the
        // primary-key suffix, with and without a key column the suffix repeats.
        for (model, specs) in [
            indexed_table(
                &[
                    ("a", DataType::Int64),
                    ("b", DataType::UInt64),
                    ("tag", DataType::Int64),
                    ("label", DataType::Utf8),
                ],
                &["a", "b"],
                &[
                    &["tag"],
                    &["tag", "a"],
                    &["tag", "b"],
                    &["tag", "label"],
                    &["label", "tag"],
                    &["b", "a"],
                ],
            ),
            indexed_table(
                &[
                    ("id", DataType::Int64),
                    ("name", DataType::Utf8),
                    ("version", DataType::UInt64),
                    ("tag", DataType::Int64),
                ],
                &["id", "name", "version"],
                &[
                    &["tag"],
                    &["tag", "id"],
                    &["tag", "name"],
                    &["tag", "version"],
                ],
            ),
            indexed_table(
                &[
                    ("name", DataType::Utf8),
                    ("id", DataType::Int64),
                    ("score", DataType::Float64),
                    ("day", DataType::Date32),
                ],
                &["name", "id"],
                &[&["score"], &["day"], &["day", "score"], &["score", "name"]],
            ),
        ] {
            let kinds = model.columns.iter().map(|col| col.kind);
            let rows = product(kinds.clone().map(values).collect());
            let choices = kinds.enumerate().map(|(idx, kind)| {
                let constrained = constraints(kind).into_iter().map(move |c| Some((idx, c)));
                std::iter::once(None).chain(constrained).collect()
            });
            for chosen in product(choices.collect()) {
                let mut predicate = QueryPredicate::default();
                predicate.constraints.extend(chosen.into_iter().flatten());
                let access = ScanAccessPlan::new(&model, &None, &predicate);
                for spec in &specs {
                    // An index whose ranges cannot be built is never scanned.
                    let prefix_len = predicate.leading_constrained_prefix(&model, spec);
                    let Ok(ranges) = predicate.expand_index_ranges(&model, spec, prefix_len) else {
                        continue;
                    };
                    let exact = access.predicate_fully_enforced_by_index_key(&model, spec);
                    for values in &rows {
                        let row = KvRow {
                            values: values.clone(),
                        };
                        let key =
                            encode_secondary_index_key(model.table_prefix, spec, &model, &row)
                                .unwrap();
                        let admitted = ranges
                            .iter()
                            .any(|range| range.start <= key && key <= range.end);
                        let matches = predicate.matches_row(&row);
                        assert!(
                            admitted || !matches,
                            "index {} must read the matching row {values:?} for {}",
                            spec.name,
                            predicate.describe(&model)
                        );
                        assert!(
                            !exact || matches || !admitted,
                            "index {} is exact for {}, so its ranges must not admit {values:?}",
                            spec.name,
                            predicate.describe(&model)
                        );
                    }
                }
            }
        }
    }
}
