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

    pub(crate) fn predicate_fully_enforced_by_index_key(
        &self,
        model: &TableModel,
        spec: &ResolvedIndexSpec,
    ) -> bool {
        if spec.layout == IndexLayout::ZOrder {
            return false;
        }

        // Key columns bound the scan in order, whether they come from the row value or
        // the primary key, until the first column without a point constraint.
        let mut open_tail = false;
        for col_idx in &spec.key_columns {
            let pk_pos = model.pk_position(*col_idx);
            let Some(constraint) = self.predicate_checks.iter().find_map(|check| match check {
                PredicateAccess::Pk {
                    pk_pos: check_pos,
                    constraint,
                } if Some(*check_pos) == pk_pos => Some(constraint),
                PredicateAccess::NonPk {
                    col_idx: check_col_idx,
                    constraint,
                    ..
                } if check_col_idx == col_idx => Some(constraint),
                _ => None,
            }) else {
                open_tail = true;
                continue;
            };

            // Store ranges include their endpoints, so the range for a strict float bound also
            // holds rows equal to the bound.
            if matches!(constraint, PredicateConstraint::FloatRange { min, max }
                if min.is_some_and(|(_, inclusive)| !inclusive)
                    || max.is_some_and(|(_, inclusive)| !inclusive))
            {
                return false;
            }
            let kind = model.column(*col_idx).kind;
            if matches!(
                compile_encoded_constraint(kind, constraint),
                EncodedConstraintCompile::Unsupported
            ) {
                return false;
            }
            if open_tail {
                return false;
            }
            if !QueryPredicate::constraint_is_point(kind, constraint) {
                open_tail = true;
            }
        }

        // Remaining primary-key constraints are enforced by the appended key suffix only
        // while every key column is fixed to one value.
        self.predicate_checks.iter().all(|check| match check {
            PredicateAccess::Pk { pk_pos, constraint } => {
                spec.key_columns
                    .contains(&model.primary_key_indices[*pk_pos])
                    || (!open_tail
                        && !matches!(
                            compile_encoded_constraint(
                                model.primary_key_kinds[*pk_pos],
                                constraint
                            ),
                            EncodedConstraintCompile::Unsupported
                        ))
            }
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
}
