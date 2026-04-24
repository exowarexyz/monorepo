use std::cmp::Ordering;
use std::collections::HashMap;

use exoware_sdk::keys::{Key, KeyCodec};
use exoware_sdk::kv_codec::{eval_predicate, KvPredicate, KvPredicateCheck, StoredRow};

use crate::aggregate::{
    compile_kv_predicate_constraint, index_row_field_ref, pk_field_ref_for_secondary_index,
};
use crate::builder::{projected_column_indices, ProjectionSource};
use crate::codec::*;
use crate::predicate::*;
use crate::types::*;

#[derive(Debug, Clone)]
pub(crate) enum PredicateAccess {
    Pk {
        pk_pos: usize,
        constraint: PredicateConstraint,
    },
    NonPk {
        col_idx: usize,
        col: ResolvedColumn,
        constraint: PredicateConstraint,
    },
}

#[derive(Clone)]
pub(crate) enum EncodedIndexConstraint {
    Eq(Vec<u8>),
    In(Vec<Vec<u8>>),
    Range {
        min: Option<(Vec<u8>, bool)>,
        max: Option<(Vec<u8>, bool)>,
    },
}

#[derive(Clone)]
pub(crate) struct EncodedIndexPredicateCheck {
    pub(crate) payload_offset: usize,
    pub(crate) width: usize,
    pub(crate) constraint: EncodedIndexConstraint,
}

#[derive(Clone)]
pub(crate) struct EncodedIndexPredicatePlan {
    pub(crate) codec: KeyCodec,
    pub(crate) checks: Vec<EncodedIndexPredicateCheck>,
    pub(crate) impossible: bool,
}

impl EncodedIndexPredicatePlan {
    pub(crate) fn matches_key(&self, key: &Key) -> bool {
        if self.impossible {
            return false;
        }
        for check in &self.checks {
            let Ok(field) = self
                .codec
                .read_payload(key, check.payload_offset, check.width)
            else {
                return false;
            };
            if !matches_encoded_constraint(&field, &check.constraint) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone)]
pub(crate) enum IndexPredicatePlan {
    Encoded(EncodedIndexPredicatePlan),
    Shared(KvPredicate),
}

impl IndexPredicatePlan {
    pub(crate) fn is_impossible(&self) -> bool {
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

pub(crate) enum EncodedConstraintCompile {
    Encoded(EncodedIndexConstraint),
    Unsupported,
    Impossible,
}

#[derive(Clone)]
pub(crate) struct ScanAccessPlan {
    pub(crate) required_pk_mask: Vec<bool>,
    pub(crate) required_non_pk_columns: Vec<bool>,
    pub(crate) projection_sources: Vec<ProjectionSource>,
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

        let mut required_pk_mask = vec![false; model.primary_key_kinds.len()];
        let mut required_non_pk_columns = vec![false; model.columns.len()];
        for (pk_pos, col_idx) in model.primary_key_indices.iter().copied().enumerate() {
            required_pk_mask[pk_pos] = required_columns[col_idx];
        }
        for (col_idx, required) in required_columns.iter().copied().enumerate() {
            if required && model.pk_position(col_idx).is_none() {
                required_non_pk_columns[col_idx] = true;
            }
        }

        Self {
            required_pk_mask,
            required_non_pk_columns,
            projection_sources,
            predicate_checks,
        }
    }

    pub(crate) fn matches_archived_row(
        &self,
        pk_values: &[CellValue],
        archived: &StoredRow,
    ) -> bool {
        for check in &self.predicate_checks {
            match check {
                PredicateAccess::Pk { pk_pos, constraint } => {
                    let Some(value) = pk_values.get(*pk_pos) else {
                        return false;
                    };
                    if !matches_constraint(value, constraint) {
                        return false;
                    }
                }
                PredicateAccess::NonPk {
                    col_idx,
                    col,
                    constraint,
                } => {
                    let stored_opt = archived.values.get(*col_idx).and_then(|v| v.as_ref());
                    if !matches_archived_non_pk_constraint(col, stored_opt, constraint) {
                        return false;
                    }
                }
            }
        }
        true
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
                codec: spec.codec,
                checks: Vec::new(),
                impossible: false,
            });
        }
        let mut index_column_offsets: HashMap<usize, (usize, ColumnKind)> = HashMap::new();
        let mut payload_offset = 0usize;
        for col_idx in &spec.key_columns {
            let kind = model.column(*col_idx).kind;
            index_column_offsets.insert(*col_idx, (payload_offset, kind));
            payload_offset += kind.key_width();
        }

        let mut pk_offsets = Vec::with_capacity(model.primary_key_kinds.len());
        let mut pk_payload_offset = spec.key_columns_width;
        for kind in &model.primary_key_kinds {
            pk_offsets.push(pk_payload_offset);
            pk_payload_offset += kind.key_width();
        }

        let mut plan = EncodedIndexPredicatePlan {
            codec: spec.codec,
            checks: Vec::new(),
            impossible: false,
        };
        for check in &self.predicate_checks {
            match check {
                PredicateAccess::Pk { pk_pos, constraint } => {
                    let kind = model.primary_key_kinds[*pk_pos];
                    let compile = compile_encoded_constraint(kind, constraint);
                    match compile {
                        EncodedConstraintCompile::Encoded(compiled) => {
                            plan.checks.push(EncodedIndexPredicateCheck {
                                payload_offset: pk_offsets[*pk_pos],
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
                PredicateAccess::NonPk {
                    col_idx,
                    col,
                    constraint,
                } => {
                    let Some((offset, _kind)) = index_column_offsets.get(col_idx).copied() else {
                        continue;
                    };
                    let compile = compile_encoded_constraint(col.kind, constraint);
                    match compile {
                        EncodedConstraintCompile::Encoded(compiled) => {
                            plan.checks.push(EncodedIndexPredicateCheck {
                                payload_offset: offset,
                                width: col.kind.key_width(),
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
            match check {
                PredicateAccess::Pk { pk_pos, constraint } => {
                    let Some(compiled_constraint) = compile_kv_predicate_constraint(constraint)
                    else {
                        continue;
                    };
                    let Some(field) = pk_field_ref_for_secondary_index(*pk_pos, model, spec) else {
                        continue;
                    };
                    checks.push(KvPredicateCheck {
                        field,
                        constraint: compiled_constraint,
                    });
                }
                PredicateAccess::NonPk {
                    col_idx,
                    col: _,
                    constraint,
                } => {
                    if !spec.key_columns.contains(col_idx) {
                        continue;
                    }
                    let Some(compiled_constraint) = compile_kv_predicate_constraint(constraint)
                    else {
                        continue;
                    };
                    let Some(field) = index_row_field_ref(*col_idx, model, spec) else {
                        continue;
                    };
                    checks.push(KvPredicateCheck {
                        field,
                        constraint: compiled_constraint,
                    });
                }
            }
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
        self.predicate_checks.iter().all(|check| match check {
            PredicateAccess::Pk { pk_pos, constraint } => {
                let kind = model.primary_key_kinds[*pk_pos];
                !matches!(
                    compile_encoded_constraint(kind, constraint),
                    EncodedConstraintCompile::Unsupported
                )
            }
            PredicateAccess::NonPk { .. } => false,
        })
    }

    pub(crate) fn predicate_fully_enforced_by_index_key(
        &self,
        model: &TableModel,
        spec: &ResolvedIndexSpec,
    ) -> bool {
        if spec.layout == IndexLayout::ZOrder {
            return false;
        }
        let mut open_tail = false;
        for col_idx in &spec.key_columns {
            let Some(constraint) = self.predicate_checks.iter().find_map(|check| match check {
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
        self.predicate_checks.iter().all(|check| match check {
            PredicateAccess::Pk { pk_pos, constraint } => {
                !open_tail
                    && !matches!(
                        compile_encoded_constraint(model.primary_key_kinds[*pk_pos], constraint),
                        EncodedConstraintCompile::Unsupported
                    )
            }
            PredicateAccess::NonPk {
                col_idx,
                col,
                constraint,
            } => {
                spec.key_columns.contains(col_idx)
                    && !matches!(
                        compile_encoded_constraint(col.kind, constraint),
                        EncodedConstraintCompile::Unsupported
                    )
            }
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
        (ColumnKind::Int64, PredicateConstraint::IntRange { min, max }) => {
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
        (ColumnKind::Date64, PredicateConstraint::IntRange { min, max })
        | (ColumnKind::Timestamp, PredicateConstraint::IntRange { min, max }) => {
            let min = min.map(|v| (encode_i64_ordered(v).to_vec(), true));
            let max = max.map(|v| (encode_i64_ordered(v).to_vec(), true));
            EncodedConstraintCompile::Encoded(EncodedIndexConstraint::Range { min, max })
        }
        (ColumnKind::Float64, PredicateConstraint::FloatRange { min, max }) => {
            if min.is_some_and(|(v, _)| v.is_nan()) || max.is_some_and(|(v, _)| v.is_nan()) {
                return EncodedConstraintCompile::Impossible;
            }
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
        (ColumnKind::FixedSizeBinary(expected), PredicateConstraint::FixedBinaryEq(value)) => {
            if value.len() != expected {
                EncodedConstraintCompile::Impossible
            } else {
                EncodedConstraintCompile::Encoded(EncodedIndexConstraint::Eq(value.clone()))
            }
        }
        (ColumnKind::FixedSizeBinary(expected), PredicateConstraint::FixedBinaryIn(values)) => {
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
