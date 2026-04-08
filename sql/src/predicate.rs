use std::collections::HashMap;

use datafusion::arrow::datatypes::i256;
use datafusion::common::{DataFusionError, Result as DataFusionResult, ScalarValue};
use datafusion::logical_expr::{Expr, Operator};
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::kv_codec::{interleave_ordered_key_fields, StoredValue};

use crate::types::*;
use crate::codec::*;

#[derive(Debug, Clone)]
pub(crate) enum PredicateConstraint {
    StringEq(String),
    BoolEq(bool),
    FixedBinaryEq(Vec<u8>),
    IntRange {
        min: Option<i64>,
        max: Option<i64>,
    },
    UInt64Range {
        min: Option<u64>,
        max: Option<u64>,
    },
    FloatRange {
        min: Option<(f64, bool)>,
        max: Option<(f64, bool)>,
    },
    Decimal128Range {
        min: Option<i128>,
        max: Option<i128>,
    },
    Decimal256Range {
        min: Option<i256>,
        max: Option<i256>,
    },
    IsNull,
    IsNotNull,
    StringIn(Vec<String>),
    IntIn(Vec<i64>),
    UInt64In(Vec<u64>),
    FixedBinaryIn(Vec<Vec<u8>>),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct QueryPredicate {
    pub(crate) constraints: HashMap<usize, PredicateConstraint>,
    pub(crate) contradiction: bool,
}

impl QueryPredicate {
    pub(crate) fn from_filters(filters: &[Expr], model: &TableModel) -> Self {
        let mut out = Self::default();
        for expr in filters {
            out.apply_supported_expr(expr, model);
        }
        out
    }

    pub(crate) fn apply_supported_expr(&mut self, expr: &Expr, model: &TableModel) {
        if self.contradiction {
            return;
        }
        match expr {
            // DataFusion can pass unsupported conjunctions through `scan`.
            // Split AND trees and keep only supported sub-predicates for pushdown.
            Expr::BinaryExpr(binary) if binary.op == Operator::And => {
                self.apply_supported_expr(binary.left.as_ref(), model);
                self.apply_supported_expr(binary.right.as_ref(), model);
            }
            _ => {
                if Self::supports_filter(expr, model) {
                    self.apply_expr(expr, model);
                }
            }
        }
    }

    pub(crate) fn in_list_literal_supported(kind: ColumnKind, literal: &ScalarValue) -> bool {
        match kind {
            ColumnKind::Utf8 => scalar_to_string(literal).is_some(),
            ColumnKind::Int64 => scalar_to_i64(literal).is_some(),
            ColumnKind::UInt64 => scalar_to_u64(literal).is_some(),
            ColumnKind::FixedSizeBinary(_) => scalar_to_fixed_binary(literal).is_some(),
            _ => false,
        }
    }

    pub(crate) fn in_list_expr_supported(kind: ColumnKind, expr: &Expr) -> bool {
        extract_literal(expr).is_some_and(|literal| Self::in_list_literal_supported(kind, literal))
    }

    pub(crate) fn supports_filter(expr: &Expr, model: &TableModel) -> bool {
        match expr {
            Expr::BinaryExpr(binary) if binary.op == Operator::And => {
                Self::supports_filter(binary.left.as_ref(), model)
                    && Self::supports_filter(binary.right.as_ref(), model)
            }
            Expr::IsNull(inner) | Expr::IsNotNull(inner) => extract_column_name(inner)
                .and_then(|name| model.columns_by_name.get(name))
                .is_some(),
            Expr::InList(in_list) if !in_list.negated => {
                let Some(col_name) = extract_column_name(&in_list.expr) else {
                    return false;
                };
                let Some(&col_idx) = model.columns_by_name.get(col_name) else {
                    return false;
                };
                let kind = model.columns[col_idx].kind;
                in_list
                    .list
                    .iter()
                    .all(|expr| Self::in_list_expr_supported(kind, expr))
            }
            Expr::BinaryExpr(binary) if binary.op == Operator::Or => {
                extract_or_in_column(expr, model).is_some()
            }
            _ => {
                let Some((column, op, literal)) = parse_simple_comparison(expr) else {
                    return false;
                };
                let Some(col_idx) = model.columns_by_name.get(&column).copied() else {
                    return false;
                };
                let range_ops = matches!(
                    op,
                    Operator::Eq | Operator::Lt | Operator::LtEq | Operator::Gt | Operator::GtEq
                );
                match model.columns[col_idx].kind {
                    ColumnKind::Utf8 => op == Operator::Eq && scalar_to_string(&literal).is_some(),
                    ColumnKind::Boolean => op == Operator::Eq && scalar_to_bool(&literal).is_some(),
                    ColumnKind::Int64 => scalar_to_i64(&literal).is_some() && range_ops,
                    ColumnKind::Float64 => scalar_to_f64(&literal).is_some() && range_ops,
                    ColumnKind::Date32 => scalar_to_date32_i64(&literal).is_some() && range_ops,
                    ColumnKind::Date64 => scalar_to_date64(&literal).is_some() && range_ops,
                    ColumnKind::Timestamp => {
                        scalar_to_timestamp_micros(&literal).is_some() && range_ops
                    }
                    ColumnKind::Decimal128 => scalar_to_i128(&literal).is_some() && range_ops,
                    ColumnKind::UInt64 => scalar_to_u64(&literal).is_some() && range_ops,
                    ColumnKind::FixedSizeBinary(_) => {
                        op == Operator::Eq && scalar_to_fixed_binary(&literal).is_some()
                    }
                    ColumnKind::Decimal256 => scalar_to_i256(&literal).is_some() && range_ops,
                    ColumnKind::List(_) => false,
                }
            }
        }
    }

    pub(crate) fn apply_expr(&mut self, expr: &Expr, model: &TableModel) {
        if self.contradiction {
            return;
        }
        match expr {
            Expr::BinaryExpr(binary) if binary.op == Operator::And => {
                self.apply_expr(binary.left.as_ref(), model);
                self.apply_expr(binary.right.as_ref(), model);
            }
            Expr::IsNull(inner) => {
                if let Some(col_name) = extract_column_name(inner) {
                    if let Some(&col_idx) = model.columns_by_name.get(col_name) {
                        match self.constraints.get(&col_idx) {
                            Some(PredicateConstraint::IsNotNull) => self.contradiction = true,
                            None => {
                                self.constraints
                                    .insert(col_idx, PredicateConstraint::IsNull);
                            }
                            _ => {}
                        }
                    }
                }
            }
            Expr::IsNotNull(inner) => {
                if let Some(col_name) = extract_column_name(inner) {
                    if let Some(&col_idx) = model.columns_by_name.get(col_name) {
                        match self.constraints.get(&col_idx) {
                            Some(PredicateConstraint::IsNull) => self.contradiction = true,
                            None => {
                                self.constraints
                                    .insert(col_idx, PredicateConstraint::IsNotNull);
                            }
                            _ => {}
                        }
                    }
                }
            }
            Expr::InList(in_list) if !in_list.negated => {
                if let Some(col_name) = extract_column_name(&in_list.expr) {
                    self.apply_in_list(col_name, &in_list.list, model);
                }
            }
            Expr::BinaryExpr(binary) if binary.op == Operator::Or => {
                if let Some((col_name, values)) = extract_or_in_column(expr, model) {
                    let fake_list: Vec<Expr> =
                        values.into_iter().map(|v| Expr::Literal(v, None)).collect();
                    self.apply_in_list(&col_name, &fake_list, model);
                }
            }
            _ => {
                let Some((column, op, literal)) = parse_simple_comparison(expr) else {
                    return;
                };
                self.apply_comparison(&column, op, &literal, model);
            }
        }
    }

    pub(crate) fn apply_comparison(
        &mut self,
        column: &str,
        op: Operator,
        literal: &ScalarValue,
        model: &TableModel,
    ) {
        let Some(col_idx) = model.columns_by_name.get(column).copied() else {
            return;
        };
        match model.columns[col_idx].kind {
            ColumnKind::Utf8 => {
                if op != Operator::Eq {
                    return;
                }
                let Some(value) = scalar_to_string(literal) else {
                    self.contradiction = true;
                    return;
                };
                match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::StringEq(existing)) if existing != &value => {
                        self.contradiction = true;
                    }
                    Some(PredicateConstraint::StringEq(_)) | None => {
                        self.constraints
                            .insert(col_idx, PredicateConstraint::StringEq(value));
                    }
                    Some(_) => {
                        self.contradiction = true;
                    }
                }
            }
            ColumnKind::Boolean => {
                if op != Operator::Eq {
                    return;
                }
                let Some(value) = scalar_to_bool(literal) else {
                    self.contradiction = true;
                    return;
                };
                match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::BoolEq(existing)) if *existing != value => {
                        self.contradiction = true;
                    }
                    Some(PredicateConstraint::BoolEq(_)) | None => {
                        self.constraints
                            .insert(col_idx, PredicateConstraint::BoolEq(value));
                    }
                    Some(_) => {
                        self.contradiction = true;
                    }
                }
            }
            ColumnKind::Int64 => {
                let Some(value) = scalar_to_i64(literal) else {
                    self.contradiction = true;
                    return;
                };
                let (mut min, mut max) = match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::IntRange { min, max }) => (*min, *max),
                    Some(_) => {
                        self.contradiction = true;
                        return;
                    }
                    None => (None, None),
                };
                apply_int_constraint(&mut min, &mut max, op, value, &mut self.contradiction);
                self.constraints
                    .insert(col_idx, PredicateConstraint::IntRange { min, max });
            }
            ColumnKind::Float64 => {
                let Some(value) = scalar_to_f64(literal) else {
                    self.contradiction = true;
                    return;
                };
                let (mut lo, mut hi) = match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::FloatRange { min, max }) => (*min, *max),
                    Some(_) => {
                        self.contradiction = true;
                        return;
                    }
                    None => (None, None),
                };
                apply_float_constraint(&mut lo, &mut hi, op, value, &mut self.contradiction);
                self.constraints.insert(
                    col_idx,
                    PredicateConstraint::FloatRange { min: lo, max: hi },
                );
            }
            ColumnKind::Date32 => {
                let Some(value) = scalar_to_date32_i64(literal) else {
                    self.contradiction = true;
                    return;
                };
                let (mut min, mut max) = match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::IntRange { min, max }) => (*min, *max),
                    Some(_) => {
                        self.contradiction = true;
                        return;
                    }
                    None => (None, None),
                };
                apply_int_constraint(&mut min, &mut max, op, value, &mut self.contradiction);
                self.constraints
                    .insert(col_idx, PredicateConstraint::IntRange { min, max });
            }
            ColumnKind::Date64 => {
                let Some(value) = scalar_to_date64(literal) else {
                    self.contradiction = true;
                    return;
                };
                let (mut min, mut max) = match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::IntRange { min, max }) => (*min, *max),
                    Some(_) => {
                        self.contradiction = true;
                        return;
                    }
                    None => (None, None),
                };
                apply_int_constraint(&mut min, &mut max, op, value, &mut self.contradiction);
                self.constraints
                    .insert(col_idx, PredicateConstraint::IntRange { min, max });
            }
            ColumnKind::Timestamp => {
                let Some(value) = timestamp_scalar_to_micros_for_op(literal, op) else {
                    self.contradiction = true;
                    return;
                };
                let (mut min, mut max) = match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::IntRange { min, max }) => (*min, *max),
                    Some(_) => {
                        self.contradiction = true;
                        return;
                    }
                    None => (None, None),
                };
                apply_int_constraint(&mut min, &mut max, op, value, &mut self.contradiction);
                self.constraints
                    .insert(col_idx, PredicateConstraint::IntRange { min, max });
            }
            ColumnKind::Decimal128 => {
                let Some(value) = scalar_to_i128(literal) else {
                    self.contradiction = true;
                    return;
                };
                let (mut min, mut max) = match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::Decimal128Range { min, max }) => (*min, *max),
                    Some(_) => {
                        self.contradiction = true;
                        return;
                    }
                    None => (None, None),
                };
                apply_decimal128_constraint(&mut min, &mut max, op, value, &mut self.contradiction);
                self.constraints
                    .insert(col_idx, PredicateConstraint::Decimal128Range { min, max });
            }
            ColumnKind::UInt64 => {
                let Some(value) = scalar_to_u64(literal) else {
                    self.contradiction = true;
                    return;
                };
                let (mut min, mut max) = match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::UInt64Range { min, max }) => (*min, *max),
                    Some(_) => {
                        self.contradiction = true;
                        return;
                    }
                    None => (None, None),
                };
                apply_u64_constraint(&mut min, &mut max, op, value, &mut self.contradiction);
                self.constraints
                    .insert(col_idx, PredicateConstraint::UInt64Range { min, max });
            }
            ColumnKind::FixedSizeBinary(_) => {
                if op != Operator::Eq {
                    return;
                }
                let Some(value) = scalar_to_fixed_binary(literal) else {
                    self.contradiction = true;
                    return;
                };
                match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::FixedBinaryEq(existing)) if *existing != value => {
                        self.contradiction = true;
                    }
                    Some(PredicateConstraint::FixedBinaryEq(_)) | None => {
                        self.constraints
                            .insert(col_idx, PredicateConstraint::FixedBinaryEq(value));
                    }
                    Some(_) => {
                        self.contradiction = true;
                    }
                }
            }
            ColumnKind::Decimal256 => {
                let Some(value) = scalar_to_i256(literal) else {
                    self.contradiction = true;
                    return;
                };
                let (mut min, mut max) = match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::Decimal256Range { min, max }) => (*min, *max),
                    Some(_) => {
                        self.contradiction = true;
                        return;
                    }
                    None => (None, None),
                };
                apply_i256_constraint(&mut min, &mut max, op, value, &mut self.contradiction);
                self.constraints
                    .insert(col_idx, PredicateConstraint::Decimal256Range { min, max });
            }
            ColumnKind::List(_) => {}
        }
    }

    pub(crate) fn apply_in_list(&mut self, column: &str, list: &[Expr], model: &TableModel) {
        if self.contradiction {
            return;
        }
        let Some(&col_idx) = model.columns_by_name.get(column) else {
            return;
        };
        match model.columns[col_idx].kind {
            ColumnKind::Utf8 => {
                let mut vals: Vec<String> = list
                    .iter()
                    .filter_map(|e| extract_literal(e).and_then(scalar_to_string))
                    .collect();
                if vals.is_empty() {
                    return;
                }
                match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::StringEq(existing)) => {
                        if !vals.contains(existing) {
                            self.contradiction = true;
                        }
                    }
                    Some(PredicateConstraint::StringIn(existing)) => {
                        let intersection: Vec<String> = existing
                            .iter()
                            .filter(|v| vals.contains(v))
                            .cloned()
                            .collect();
                        if intersection.is_empty() {
                            self.contradiction = true;
                        } else {
                            self.constraints
                                .insert(col_idx, PredicateConstraint::StringIn(intersection));
                        }
                    }
                    None => {
                        vals.sort_unstable();
                        vals.dedup();
                        if vals.len() == 1 {
                            self.constraints.insert(
                                col_idx,
                                PredicateConstraint::StringEq(vals.into_iter().next().unwrap()),
                            );
                        } else {
                            self.constraints
                                .insert(col_idx, PredicateConstraint::StringIn(vals));
                        }
                    }
                    _ => self.contradiction = true,
                }
            }
            ColumnKind::Int64 => {
                let mut vals: Vec<i64> = list
                    .iter()
                    .filter_map(|e| extract_literal(e).and_then(scalar_to_i64))
                    .collect();
                if vals.is_empty() {
                    return;
                }
                match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::IntRange { min, max }) => {
                        let mut filtered: Vec<i64> = vals
                            .into_iter()
                            .filter(|v| in_i64_bounds(*v, *min, *max))
                            .collect();
                        filtered.sort_unstable();
                        filtered.dedup();
                        if filtered.is_empty() {
                            self.contradiction = true;
                        } else if filtered.len() == 1 {
                            let v = filtered[0];
                            self.constraints.insert(
                                col_idx,
                                PredicateConstraint::IntRange {
                                    min: Some(v),
                                    max: Some(v),
                                },
                            );
                        } else {
                            self.constraints
                                .insert(col_idx, PredicateConstraint::IntIn(filtered));
                        }
                    }
                    Some(PredicateConstraint::IntIn(existing)) => {
                        let intersection: Vec<i64> = existing
                            .iter()
                            .filter(|v| vals.contains(v))
                            .copied()
                            .collect();
                        if intersection.is_empty() {
                            self.contradiction = true;
                        } else {
                            self.constraints
                                .insert(col_idx, PredicateConstraint::IntIn(intersection));
                        }
                    }
                    None => {
                        vals.sort_unstable();
                        vals.dedup();
                        if vals.len() == 1 {
                            let v = vals[0];
                            self.constraints.insert(
                                col_idx,
                                PredicateConstraint::IntRange {
                                    min: Some(v),
                                    max: Some(v),
                                },
                            );
                        } else {
                            self.constraints
                                .insert(col_idx, PredicateConstraint::IntIn(vals));
                        }
                    }
                    _ => self.contradiction = true,
                }
            }
            ColumnKind::UInt64 => {
                let mut vals: Vec<u64> = list
                    .iter()
                    .filter_map(|e| extract_literal(e).and_then(scalar_to_u64))
                    .collect();
                if vals.is_empty() {
                    self.contradiction = true;
                    return;
                }
                match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::UInt64Range { min, max }) => {
                        let mut filtered: Vec<u64> = vals
                            .into_iter()
                            .filter(|v| in_u64_bounds(*v, *min, *max))
                            .collect();
                        filtered.sort_unstable();
                        filtered.dedup();
                        if filtered.is_empty() {
                            self.contradiction = true;
                        } else if filtered.len() == 1 {
                            let v = filtered[0];
                            self.constraints.insert(
                                col_idx,
                                PredicateConstraint::UInt64Range {
                                    min: Some(v),
                                    max: Some(v),
                                },
                            );
                        } else {
                            self.constraints
                                .insert(col_idx, PredicateConstraint::UInt64In(filtered));
                        }
                    }
                    Some(PredicateConstraint::UInt64In(existing)) => {
                        let intersection: Vec<u64> = existing
                            .iter()
                            .filter(|v| vals.contains(v))
                            .copied()
                            .collect();
                        if intersection.is_empty() {
                            self.contradiction = true;
                        } else {
                            self.constraints
                                .insert(col_idx, PredicateConstraint::UInt64In(intersection));
                        }
                    }
                    None => {
                        vals.sort_unstable();
                        vals.dedup();
                        if vals.len() == 1 {
                            let v = vals[0];
                            self.constraints.insert(
                                col_idx,
                                PredicateConstraint::UInt64Range {
                                    min: Some(v),
                                    max: Some(v),
                                },
                            );
                        } else {
                            self.constraints
                                .insert(col_idx, PredicateConstraint::UInt64In(vals));
                        }
                    }
                    _ => self.contradiction = true,
                }
            }
            ColumnKind::FixedSizeBinary(_) => {
                let mut vals: Vec<Vec<u8>> = list
                    .iter()
                    .filter_map(|e| extract_literal(e).and_then(scalar_to_fixed_binary))
                    .collect();
                if vals.is_empty() {
                    return;
                }
                match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::FixedBinaryEq(existing)) => {
                        if !vals.contains(existing) {
                            self.contradiction = true;
                        }
                    }
                    Some(PredicateConstraint::FixedBinaryIn(existing)) => {
                        let intersection: Vec<Vec<u8>> = existing
                            .iter()
                            .filter(|v| vals.contains(v))
                            .cloned()
                            .collect();
                        if intersection.is_empty() {
                            self.contradiction = true;
                        } else {
                            self.constraints
                                .insert(col_idx, PredicateConstraint::FixedBinaryIn(intersection));
                        }
                    }
                    None => {
                        vals.sort();
                        vals.dedup();
                        if vals.len() == 1 {
                            self.constraints.insert(
                                col_idx,
                                PredicateConstraint::FixedBinaryEq(
                                    vals.into_iter().next().unwrap(),
                                ),
                            );
                        } else {
                            self.constraints
                                .insert(col_idx, PredicateConstraint::FixedBinaryIn(vals));
                        }
                    }
                    _ => self.contradiction = true,
                }
            }
            _ => {}
        }
    }

    pub(crate) fn choose_index_plan(
        &self,
        model: &TableModel,
        specs: &[ResolvedIndexSpec],
    ) -> DataFusionResult<Option<IndexPlan>> {
        if self.contradiction {
            return Ok(None);
        }
        let mut best: Option<IndexPlan> = None;
        for (spec_idx, spec) in specs.iter().enumerate() {
            let (ranges, constrained_prefix_len, constrained_column_count) = match spec.layout {
                IndexLayout::Lexicographic => {
                    let constrained_prefix_len = self.leading_constrained_prefix(model, spec);
                    if constrained_prefix_len == 0 {
                        continue;
                    }
                    let ranges = match self.expand_index_ranges(
                        model.table_prefix,
                        model,
                        spec,
                        constrained_prefix_len,
                    ) {
                        Ok(r) if !r.is_empty() => r,
                        _ => continue,
                    };
                    (
                        ranges,
                        constrained_prefix_len,
                        self.lexicographic_candidate_score(model, spec),
                    )
                }
                IndexLayout::ZOrder => {
                    let constrained_column_count =
                        self.zorder_constrained_column_count(model, spec);
                    if constrained_column_count == 0 {
                        continue;
                    }
                    let ranges =
                        match self.expand_zorder_index_ranges(model.table_prefix, model, spec) {
                            Ok(r) if !r.is_empty() => r,
                            _ => continue,
                        };
                    (ranges, constrained_column_count, constrained_column_count)
                }
            };
            let candidate = IndexPlan {
                spec_idx,
                ranges,
                constrained_prefix_len,
                constrained_column_count,
            };
            match &best {
                None => best = Some(candidate),
                Some(prev)
                    if candidate.constrained_column_count > prev.constrained_column_count =>
                {
                    best = Some(candidate)
                }
                Some(prev)
                    if candidate.constrained_column_count == prev.constrained_column_count
                        && self.index_covers_required_non_pk(model, &specs[candidate.spec_idx])
                        && !self.index_covers_required_non_pk(model, &specs[prev.spec_idx]) =>
                {
                    best = Some(candidate)
                }
                Some(prev)
                    if candidate.constrained_column_count == prev.constrained_column_count
                        && specs[candidate.spec_idx].layout == IndexLayout::Lexicographic
                        && specs[prev.spec_idx].layout == IndexLayout::ZOrder =>
                {
                    best = Some(candidate)
                }
                Some(prev)
                    if candidate.constrained_column_count == prev.constrained_column_count
                        && specs[candidate.spec_idx].layout == specs[prev.spec_idx].layout
                        && candidate.ranges.len() < prev.ranges.len() =>
                {
                    best = Some(candidate)
                }
                _ => {}
            }
        }
        Ok(best)
    }

    pub(crate) fn index_covers_required_non_pk(&self, model: &TableModel, spec: &ResolvedIndexSpec) -> bool {
        self.constraints
            .keys()
            .copied()
            .filter(|col_idx| model.pk_position(*col_idx).is_none())
            .all(|col_idx| spec.value_column_mask[col_idx] || spec.key_columns.contains(&col_idx))
    }

    pub(crate) fn expand_index_ranges(
        &self,
        table_prefix: u8,
        model: &TableModel,
        spec: &ResolvedIndexSpec,
        constrained_prefix_len: usize,
    ) -> Result<Vec<KeyRange>, String> {
        let mut col_values: Vec<(usize, Vec<PredicateConstraint>)> = Vec::new();
        for &col_idx in spec.key_columns.iter().take(constrained_prefix_len) {
            let Some(constraint) = self.constraints.get(&col_idx) else {
                break;
            };
            let singles = match constraint {
                PredicateConstraint::StringIn(vals) => vals
                    .iter()
                    .map(|v| PredicateConstraint::StringEq(v.clone()))
                    .collect(),
                PredicateConstraint::IntIn(vals) => vals
                    .iter()
                    .map(|&v| PredicateConstraint::IntRange {
                        min: Some(v),
                        max: Some(v),
                    })
                    .collect(),
                PredicateConstraint::UInt64In(vals) => vals
                    .iter()
                    .map(|&v| PredicateConstraint::UInt64Range {
                        min: Some(v),
                        max: Some(v),
                    })
                    .collect(),
                PredicateConstraint::FixedBinaryIn(vals) => vals
                    .iter()
                    .map(|v| PredicateConstraint::FixedBinaryEq(v.clone()))
                    .collect(),
                other => vec![other.clone()],
            };
            col_values.push((col_idx, singles));
        }

        let mut combos: Vec<HashMap<usize, PredicateConstraint>> = vec![HashMap::new()];
        for (col_idx, singles) in &col_values {
            let mut next = Vec::new();
            for combo in &combos {
                for single in singles {
                    let mut c = combo.clone();
                    c.insert(*col_idx, single.clone());
                    next.push(c);
                }
            }
            combos = next;
            if combos.len() > 256 {
                return Err("too many index range combinations".to_string());
            }
        }

        let mut ranges = Vec::with_capacity(combos.len());
        let base_constraints = self.constraints.clone();
        for combo in &combos {
            let mut tmp_constraints = base_constraints.clone();
            for (col_idx, constraint) in combo {
                tmp_constraints.insert(*col_idx, constraint.clone());
            }
            let tmp = QueryPredicate {
                constraints: tmp_constraints,
                contradiction: self.contradiction,
            };
            let start = tmp.encode_index_bound_key(
                table_prefix,
                model,
                spec,
                constrained_prefix_len,
                false,
            )?;
            let end = tmp.encode_index_bound_key(
                table_prefix,
                model,
                spec,
                constrained_prefix_len,
                true,
            )?;
            if start <= end {
                ranges.push(KeyRange { start, end });
            }
        }
        Ok(ranges)
    }

    pub(crate) fn leading_constrained_prefix(&self, model: &TableModel, spec: &ResolvedIndexSpec) -> usize {
        let mut count = 0usize;
        for col_idx in &spec.key_columns {
            let Some(constraint) = self.constraints.get(col_idx) else {
                break;
            };
            let constrained = matches!(
                (model.column(*col_idx).kind, constraint),
                (ColumnKind::Utf8, PredicateConstraint::StringEq(_))
                    | (ColumnKind::Utf8, PredicateConstraint::StringIn(_))
                    | (ColumnKind::Boolean, PredicateConstraint::BoolEq(_))
                    | (ColumnKind::Int64, PredicateConstraint::IntRange { .. })
                    | (ColumnKind::Int64, PredicateConstraint::IntIn(_))
                    | (ColumnKind::UInt64, PredicateConstraint::UInt64Range { .. })
                    | (ColumnKind::UInt64, PredicateConstraint::UInt64In(_))
                    | (ColumnKind::Date32, PredicateConstraint::IntRange { .. })
                    | (ColumnKind::Date64, PredicateConstraint::IntRange { .. })
                    | (ColumnKind::Timestamp, PredicateConstraint::IntRange { .. })
                    | (ColumnKind::Float64, PredicateConstraint::FloatRange { .. })
                    | (
                        ColumnKind::FixedSizeBinary(_),
                        PredicateConstraint::FixedBinaryEq(_)
                    )
                    | (
                        ColumnKind::FixedSizeBinary(_),
                        PredicateConstraint::FixedBinaryIn(_)
                    )
                    | (
                        ColumnKind::Decimal128,
                        PredicateConstraint::Decimal128Range { .. }
                    )
                    | (
                        ColumnKind::Decimal256,
                        PredicateConstraint::Decimal256Range { .. }
                    )
            );
            if !constrained {
                break;
            }
            count += 1;
        }
        count
    }

    pub(crate) fn lexicographic_candidate_score(&self, model: &TableModel, spec: &ResolvedIndexSpec) -> usize {
        let mut count = 0usize;
        for col_idx in &spec.key_columns {
            let Some(constraint) = self.constraints.get(col_idx) else {
                break;
            };
            if !Self::constraint_supported_for_zorder(model.column(*col_idx).kind, constraint) {
                break;
            }
            count += 1;
            if !Self::constraint_is_point(model.column(*col_idx).kind, constraint) {
                break;
            }
        }
        count
    }

    pub(crate) fn zorder_constrained_column_count(
        &self,
        model: &TableModel,
        spec: &ResolvedIndexSpec,
    ) -> usize {
        spec.key_columns
            .iter()
            .filter(|col_idx| {
                self.constraints.get(col_idx).is_some_and(|constraint| {
                    Self::constraint_supported_for_zorder(model.column(**col_idx).kind, constraint)
                })
            })
            .count()
    }

    pub(crate) fn constraint_is_point(kind: ColumnKind, constraint: &PredicateConstraint) -> bool {
        match (kind, constraint) {
            (ColumnKind::Utf8, PredicateConstraint::StringEq(_))
            | (ColumnKind::Utf8, PredicateConstraint::StringIn(_))
            | (ColumnKind::Boolean, PredicateConstraint::BoolEq(_))
            | (ColumnKind::FixedSizeBinary(_), PredicateConstraint::FixedBinaryEq(_))
            | (ColumnKind::FixedSizeBinary(_), PredicateConstraint::FixedBinaryIn(_))
            | (ColumnKind::Int64, PredicateConstraint::IntIn(_))
            | (ColumnKind::UInt64, PredicateConstraint::UInt64In(_)) => true,
            (ColumnKind::Int64, PredicateConstraint::IntRange { min, max })
            | (ColumnKind::Date32, PredicateConstraint::IntRange { min, max })
            | (ColumnKind::Date64, PredicateConstraint::IntRange { min, max })
            | (ColumnKind::Timestamp, PredicateConstraint::IntRange { min, max }) => {
                min.is_some() && min == max
            }
            (ColumnKind::UInt64, PredicateConstraint::UInt64Range { min, max }) => {
                min.is_some() && min == max
            }
            (ColumnKind::Float64, PredicateConstraint::FloatRange { min, max }) => {
                matches!((min, max), (Some((lhs, true)), Some((rhs, true))) if lhs == rhs)
            }
            (ColumnKind::Decimal128, PredicateConstraint::Decimal128Range { min, max }) => {
                min.is_some() && min == max
            }
            (ColumnKind::Decimal256, PredicateConstraint::Decimal256Range { min, max }) => {
                min.is_some() && min == max
            }
            _ => false,
        }
    }

    pub(crate) fn constraint_supported_for_zorder(kind: ColumnKind, constraint: &PredicateConstraint) -> bool {
        matches!(
            (kind, constraint),
            (ColumnKind::Utf8, PredicateConstraint::StringEq(_))
                | (ColumnKind::Utf8, PredicateConstraint::StringIn(_))
                | (ColumnKind::Boolean, PredicateConstraint::BoolEq(_))
                | (ColumnKind::Int64, PredicateConstraint::IntRange { .. })
                | (ColumnKind::Int64, PredicateConstraint::IntIn(_))
                | (ColumnKind::UInt64, PredicateConstraint::UInt64Range { .. })
                | (ColumnKind::UInt64, PredicateConstraint::UInt64In(_))
                | (ColumnKind::Date32, PredicateConstraint::IntRange { .. })
                | (ColumnKind::Date64, PredicateConstraint::IntRange { .. })
                | (ColumnKind::Timestamp, PredicateConstraint::IntRange { .. })
                | (ColumnKind::Float64, PredicateConstraint::FloatRange { .. })
                | (
                    ColumnKind::FixedSizeBinary(_),
                    PredicateConstraint::FixedBinaryEq(_)
                )
                | (
                    ColumnKind::FixedSizeBinary(_),
                    PredicateConstraint::FixedBinaryIn(_)
                )
                | (
                    ColumnKind::Decimal128,
                    PredicateConstraint::Decimal128Range { .. }
                )
                | (
                    ColumnKind::Decimal256,
                    PredicateConstraint::Decimal256Range { .. }
                )
        )
    }

    pub(crate) fn expand_zorder_index_ranges(
        &self,
        table_prefix: u8,
        model: &TableModel,
        spec: &ResolvedIndexSpec,
    ) -> Result<Vec<KeyRange>, String> {
        let mut col_values: Vec<(usize, Vec<PredicateConstraint>)> = Vec::new();
        for &col_idx in &spec.key_columns {
            let Some(constraint) = self.constraints.get(&col_idx) else {
                continue;
            };
            if !Self::constraint_supported_for_zorder(model.column(col_idx).kind, constraint) {
                continue;
            }
            let singles = match constraint {
                PredicateConstraint::StringIn(vals) => vals
                    .iter()
                    .map(|v| PredicateConstraint::StringEq(v.clone()))
                    .collect(),
                PredicateConstraint::IntIn(vals) => vals
                    .iter()
                    .map(|&v| PredicateConstraint::IntRange {
                        min: Some(v),
                        max: Some(v),
                    })
                    .collect(),
                PredicateConstraint::UInt64In(vals) => vals
                    .iter()
                    .map(|&v| PredicateConstraint::UInt64Range {
                        min: Some(v),
                        max: Some(v),
                    })
                    .collect(),
                PredicateConstraint::FixedBinaryIn(vals) => vals
                    .iter()
                    .map(|v| PredicateConstraint::FixedBinaryEq(v.clone()))
                    .collect(),
                other => vec![other.clone()],
            };
            col_values.push((col_idx, singles));
        }

        let mut combos: Vec<HashMap<usize, PredicateConstraint>> = vec![HashMap::new()];
        for (col_idx, singles) in &col_values {
            let mut next = Vec::new();
            for combo in &combos {
                for single in singles {
                    let mut c = combo.clone();
                    c.insert(*col_idx, single.clone());
                    next.push(c);
                }
            }
            combos = next;
            if combos.len() > 256 {
                return Err("too many z-order index range combinations".to_string());
            }
        }

        let mut ranges = Vec::with_capacity(combos.len());
        for combo in &combos {
            let mut tmp = self.clone();
            for (col_idx, constraint) in combo {
                tmp.constraints.insert(*col_idx, constraint.clone());
            }
            let start = tmp.encode_zorder_index_bound_key(table_prefix, model, spec, false)?;
            let end = tmp.encode_zorder_index_bound_key(table_prefix, model, spec, true)?;
            if start <= end {
                ranges.push(KeyRange { start, end });
            }
        }
        Ok(ranges)
    }

    pub(crate) fn encode_index_bound_key(
        &self,
        _table_prefix: u8,
        model: &TableModel,
        spec: &ResolvedIndexSpec,
        constrained_prefix_len: usize,
        upper: bool,
    ) -> Result<Key, String> {
        let codec = spec.codec;
        let payload_len = if upper {
            codec.payload_capacity_bytes()
        } else {
            spec.key_columns_width + model.primary_key_width
        };
        let mut key = allocate_codec_key(codec, payload_len)?;
        let mut offset = 0usize;
        for (idx, col_idx) in spec.key_columns.iter().copied().enumerate() {
            let col = model.column(col_idx);
            let use_constraint = idx < constrained_prefix_len;
            match col.kind {
                ColumnKind::Utf8 => {
                    let bytes = if use_constraint {
                        let Some(PredicateConstraint::StringEq(v)) = self.constraints.get(&col_idx)
                        else {
                            return Err(format!("missing string constraint for '{}'", col.name));
                        };
                        encode_string_variable(v)?
                    } else if upper {
                        vec![0xFFu8]
                    } else {
                        vec![STRING_KEY_TERMINATOR]
                    };
                    codec
                        .write_payload(&mut key, offset, &bytes)
                        .map_err(|e| format!("failed to write codec payload: {e}"))?;
                    offset += bytes.len();
                }
                ColumnKind::Boolean => {
                    let value = if use_constraint {
                        let Some(PredicateConstraint::BoolEq(v)) = self.constraints.get(&col_idx)
                        else {
                            return Err(format!("missing bool constraint for '{}'", col.name));
                        };
                        *v
                    } else {
                        upper
                    };
                    codec
                        .write_payload(&mut key, offset, &[u8::from(value)])
                        .map_err(|e| format!("failed to write codec payload: {e}"))?;
                    offset += 1;
                }
                ColumnKind::Int64 => {
                    let value = if use_constraint {
                        let Some(PredicateConstraint::IntRange { min, max }) =
                            self.constraints.get(&col_idx)
                        else {
                            return Err(format!("missing int constraint for '{}'", col.name));
                        };
                        if upper {
                            max.unwrap_or(i64::MAX)
                        } else {
                            min.unwrap_or(i64::MIN)
                        }
                    } else if upper {
                        i64::MAX
                    } else {
                        i64::MIN
                    };
                    codec
                        .write_payload(&mut key, offset, &encode_i64_ordered(value))
                        .map_err(|e| format!("failed to write codec payload: {e}"))?;
                    offset += 8;
                }
                ColumnKind::Float64 => {
                    let value = if use_constraint {
                        let Some(PredicateConstraint::FloatRange { min, max }) =
                            self.constraints.get(&col_idx)
                        else {
                            return Err(format!("missing float constraint for '{}'", col.name));
                        };
                        if upper {
                            max.map(|(v, _)| v).unwrap_or(f64::INFINITY)
                        } else {
                            min.map(|(v, _)| v).unwrap_or(f64::NEG_INFINITY)
                        }
                    } else if upper {
                        f64::INFINITY
                    } else {
                        f64::NEG_INFINITY
                    };
                    codec
                        .write_payload(&mut key, offset, &encode_f64_ordered(value))
                        .map_err(|e| format!("failed to write codec payload: {e}"))?;
                    offset += 8;
                }
                ColumnKind::Date32 => {
                    let raw = if use_constraint {
                        let Some(PredicateConstraint::IntRange { min, max }) =
                            self.constraints.get(&col_idx)
                        else {
                            return Err(format!("missing date32 constraint for '{}'", col.name));
                        };
                        if upper {
                            max.unwrap_or(i32::MAX as i64)
                        } else {
                            min.unwrap_or(i32::MIN as i64)
                        }
                    } else if upper {
                        i32::MAX as i64
                    } else {
                        i32::MIN as i64
                    };
                    let value = raw.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
                    codec
                        .write_payload(&mut key, offset, &encode_i32_ordered(value))
                        .map_err(|e| format!("failed to write codec payload: {e}"))?;
                    offset += 4;
                }
                ColumnKind::Date64 => {
                    let value = if use_constraint {
                        let Some(PredicateConstraint::IntRange { min, max }) =
                            self.constraints.get(&col_idx)
                        else {
                            return Err(format!("missing date64 constraint for '{}'", col.name));
                        };
                        if upper {
                            max.unwrap_or(i64::MAX)
                        } else {
                            min.unwrap_or(i64::MIN)
                        }
                    } else if upper {
                        i64::MAX
                    } else {
                        i64::MIN
                    };
                    codec
                        .write_payload(&mut key, offset, &encode_i64_ordered(value))
                        .map_err(|e| format!("failed to write codec payload: {e}"))?;
                    offset += 8;
                }
                ColumnKind::Timestamp => {
                    let value = if use_constraint {
                        let Some(PredicateConstraint::IntRange { min, max }) =
                            self.constraints.get(&col_idx)
                        else {
                            return Err(format!("missing timestamp constraint for '{}'", col.name));
                        };
                        if upper {
                            max.unwrap_or(i64::MAX)
                        } else {
                            min.unwrap_or(i64::MIN)
                        }
                    } else if upper {
                        i64::MAX
                    } else {
                        i64::MIN
                    };
                    codec
                        .write_payload(&mut key, offset, &encode_i64_ordered(value))
                        .map_err(|e| format!("failed to write codec payload: {e}"))?;
                    offset += 8;
                }
                ColumnKind::Decimal128 => {
                    let value = if use_constraint {
                        let Some(PredicateConstraint::Decimal128Range { min, max }) =
                            self.constraints.get(&col_idx)
                        else {
                            return Err(format!(
                                "missing decimal128 constraint for '{}'",
                                col.name
                            ));
                        };
                        if upper {
                            max.unwrap_or(i128::MAX)
                        } else {
                            min.unwrap_or(i128::MIN)
                        }
                    } else if upper {
                        i128::MAX
                    } else {
                        i128::MIN
                    };
                    codec
                        .write_payload(&mut key, offset, &encode_i128_ordered(value))
                        .map_err(|e| format!("failed to write codec payload: {e}"))?;
                    offset += 16;
                }
                ColumnKind::UInt64 => {
                    let value = if use_constraint {
                        let (lower, upper_bound) = self.uint64_bounds(col_idx);
                        if upper {
                            upper_bound
                        } else {
                            lower
                        }
                    } else if upper {
                        u64::MAX
                    } else {
                        0
                    };
                    codec
                        .write_payload(&mut key, offset, &value.to_be_bytes())
                        .map_err(|e| format!("failed to write codec payload: {e}"))?;
                    offset += 8;
                }
                ColumnKind::Decimal256 => {
                    let value = if use_constraint {
                        let Some(PredicateConstraint::Decimal256Range { min, max }) =
                            self.constraints.get(&col_idx)
                        else {
                            return Err(format!(
                                "missing decimal256 constraint for '{}'",
                                col.name
                            ));
                        };
                        if upper {
                            max.unwrap_or(i256::MAX)
                        } else {
                            min.unwrap_or(i256::MIN)
                        }
                    } else if upper {
                        i256::MAX
                    } else {
                        i256::MIN
                    };
                    codec
                        .write_payload(&mut key, offset, &encode_i256_ordered(value))
                        .map_err(|e| format!("failed to write codec payload: {e}"))?;
                    offset += 32;
                }
                ColumnKind::FixedSizeBinary(n) => {
                    if use_constraint {
                        let Some(PredicateConstraint::FixedBinaryEq(data)) =
                            self.constraints.get(&col_idx)
                        else {
                            return Err(format!(
                                "missing fixed-binary constraint for '{}'",
                                col.name
                            ));
                        };
                        if data.len() > n {
                            return Err(format!(
                                "fixed-binary constraint for '{}' exceeds width {}",
                                col.name, n
                            ));
                        }
                        codec
                            .write_payload(&mut key, offset, data)
                            .map_err(|e| format!("failed to write codec payload: {e}"))?;
                    } else if upper {
                        codec
                            .fill_payload(&mut key, offset, n, 0xFF)
                            .map_err(|e| format!("failed to fill codec payload: {e}"))?;
                    }
                    offset += n;
                }
                ColumnKind::List(_) => unreachable!("list columns cannot be indexed"),
            }
        }

        for (&pk_idx, &pk_kind) in model
            .primary_key_indices
            .iter()
            .zip(model.primary_key_kinds.iter())
        {
            match pk_kind {
                ColumnKind::Int64 => {
                    let (pk_min, pk_max) = self.int_bounds(pk_idx);
                    let pk_bound = if upper {
                        pk_max.unwrap_or(i64::MAX)
                    } else {
                        pk_min.unwrap_or(i64::MIN)
                    };
                    codec
                        .write_payload(&mut key, offset, &encode_i64_ordered(pk_bound))
                        .map_err(|e| format!("failed to write codec payload: {e}"))?;
                    offset += 8;
                }
                ColumnKind::UInt64 => {
                    let (lower, upper_bound) = self.uint64_bounds(pk_idx);
                    let pk_bound = if upper { upper_bound } else { lower };
                    codec
                        .write_payload(&mut key, offset, &pk_bound.to_be_bytes())
                        .map_err(|e| format!("failed to write codec payload: {e}"))?;
                    offset += 8;
                }
                _ => {
                    let w = pk_kind.key_width();
                    if upper {
                        codec
                            .fill_payload(&mut key, offset, w, 0xFF)
                            .map_err(|e| format!("failed to fill codec payload: {e}"))?;
                    }
                    offset += w;
                }
            }
        }
        if upper {
            let remaining = codec.payload_capacity_bytes().saturating_sub(offset);
            codec
                .fill_payload(&mut key, offset, remaining, 0xFF)
                .map_err(|e| format!("failed to fill codec payload: {e}"))?;
        }
        Ok(key.freeze())
    }

    pub(crate) fn encode_zorder_index_bound_key(
        &self,
        _table_prefix: u8,
        model: &TableModel,
        spec: &ResolvedIndexSpec,
        upper: bool,
    ) -> Result<Key, String> {
        let codec = spec.codec;
        let payload_len = if upper {
            codec.payload_capacity_bytes()
        } else {
            spec.key_columns_width + model.primary_key_width
        };
        let mut key = allocate_codec_key(codec, payload_len)?;
        let mut encoded_fields = Vec::with_capacity(spec.key_columns.len());
        for &col_idx in &spec.key_columns {
            let col = model.column(col_idx);
            let bytes = self.ordered_index_bound_bytes_for_column(col_idx, col, upper)?;
            encoded_fields.push(bytes);
        }
        let interleaved = interleave_ordered_key_fields(&encoded_fields);
        let mut offset = 0usize;
        codec
            .write_payload(&mut key, offset, &interleaved)
            .map_err(|e| format!("failed to write codec payload: {e}"))?;
        offset += interleaved.len();
        debug_assert_eq!(offset, spec.key_columns_width);
        for (&pk_idx, &pk_kind) in model
            .primary_key_indices
            .iter()
            .zip(model.primary_key_kinds.iter())
        {
            match pk_kind {
                ColumnKind::Int64 => {
                    let (pk_min, pk_max) = self.int_bounds(pk_idx);
                    let pk_bound = if upper {
                        pk_max.unwrap_or(i64::MAX)
                    } else {
                        pk_min.unwrap_or(i64::MIN)
                    };
                    codec
                        .write_payload(&mut key, offset, &encode_i64_ordered(pk_bound))
                        .map_err(|e| format!("failed to write codec payload: {e}"))?;
                    offset += 8;
                }
                ColumnKind::UInt64 => {
                    let (lower, upper_bound) = self.uint64_bounds(pk_idx);
                    let pk_bound = if upper { upper_bound } else { lower };
                    codec
                        .write_payload(&mut key, offset, &pk_bound.to_be_bytes())
                        .map_err(|e| format!("failed to write codec payload: {e}"))?;
                    offset += 8;
                }
                _ => {
                    let w = pk_kind.key_width();
                    if upper {
                        codec
                            .fill_payload(&mut key, offset, w, 0xFF)
                            .map_err(|e| format!("failed to fill codec payload: {e}"))?;
                    }
                    offset += w;
                }
            }
        }
        if upper {
            let remaining = codec.payload_capacity_bytes().saturating_sub(offset);
            codec
                .fill_payload(&mut key, offset, remaining, 0xFF)
                .map_err(|e| format!("failed to fill codec payload: {e}"))?;
        }
        Ok(key.freeze())
    }

    pub(crate) fn ordered_index_bound_bytes_for_column(
        &self,
        col_idx: usize,
        col: &ResolvedColumn,
        upper: bool,
    ) -> Result<Vec<u8>, String> {
        Ok(match col.kind {
            ColumnKind::Utf8 => {
                if let Some(constraint) = self.constraints.get(&col_idx) {
                    let PredicateConstraint::StringEq(v) = constraint else {
                        return Err(format!("missing string constraint for '{}'", col.name));
                    };
                    encode_string_variable(v)?
                } else if upper {
                    vec![0xFF]
                } else {
                    vec![0x00]
                }
            }
            ColumnKind::Boolean => vec![u8::from(
                self.constraints
                    .get(&col_idx)
                    .and_then(|constraint| match constraint {
                        PredicateConstraint::BoolEq(v) => Some(*v),
                        _ => None,
                    })
                    .unwrap_or(upper),
            )],
            ColumnKind::Int64 => {
                let value = if let Some(constraint) = self.constraints.get(&col_idx) {
                    let PredicateConstraint::IntRange { min, max } = constraint else {
                        return Err(format!("missing int constraint for '{}'", col.name));
                    };
                    if upper {
                        max.unwrap_or(i64::MAX)
                    } else {
                        min.unwrap_or(i64::MIN)
                    }
                } else if upper {
                    i64::MAX
                } else {
                    i64::MIN
                };
                encode_i64_ordered(value).to_vec()
            }
            ColumnKind::Float64 => {
                let value = if let Some(constraint) = self.constraints.get(&col_idx) {
                    let PredicateConstraint::FloatRange { min, max } = constraint else {
                        return Err(format!("missing float constraint for '{}'", col.name));
                    };
                    if upper {
                        max.map(|(v, _)| v).unwrap_or(f64::INFINITY)
                    } else {
                        min.map(|(v, _)| v).unwrap_or(f64::NEG_INFINITY)
                    }
                } else if upper {
                    f64::INFINITY
                } else {
                    f64::NEG_INFINITY
                };
                encode_f64_ordered(value).to_vec()
            }
            ColumnKind::Date32 => {
                let raw = if let Some(constraint) = self.constraints.get(&col_idx) {
                    let PredicateConstraint::IntRange { min, max } = constraint else {
                        return Err(format!("missing date32 constraint for '{}'", col.name));
                    };
                    if upper {
                        max.unwrap_or(i32::MAX as i64)
                    } else {
                        min.unwrap_or(i32::MIN as i64)
                    }
                } else if upper {
                    i32::MAX as i64
                } else {
                    i32::MIN as i64
                };
                encode_i32_ordered(raw.clamp(i32::MIN as i64, i32::MAX as i64) as i32).to_vec()
            }
            ColumnKind::Date64 | ColumnKind::Timestamp => {
                let value = if let Some(constraint) = self.constraints.get(&col_idx) {
                    let PredicateConstraint::IntRange { min, max } = constraint else {
                        return Err(format!("missing int-like constraint for '{}'", col.name));
                    };
                    if upper {
                        max.unwrap_or(i64::MAX)
                    } else {
                        min.unwrap_or(i64::MIN)
                    }
                } else if upper {
                    i64::MAX
                } else {
                    i64::MIN
                };
                encode_i64_ordered(value).to_vec()
            }
            ColumnKind::Decimal128 => {
                let value = if let Some(constraint) = self.constraints.get(&col_idx) {
                    let PredicateConstraint::Decimal128Range { min, max } = constraint else {
                        return Err(format!("missing decimal128 constraint for '{}'", col.name));
                    };
                    if upper {
                        max.unwrap_or(i128::MAX)
                    } else {
                        min.unwrap_or(i128::MIN)
                    }
                } else if upper {
                    i128::MAX
                } else {
                    i128::MIN
                };
                encode_i128_ordered(value).to_vec()
            }
            ColumnKind::UInt64 => {
                let value = if let Some(constraint) = self.constraints.get(&col_idx) {
                    let (lower, upper_bound) = match constraint {
                        PredicateConstraint::UInt64Range { min, max } => {
                            (min.unwrap_or(0), max.unwrap_or(u64::MAX))
                        }
                        _ => return Err(format!("missing uint64 constraint for '{}'", col.name)),
                    };
                    if upper {
                        upper_bound
                    } else {
                        lower
                    }
                } else if upper {
                    u64::MAX
                } else {
                    0
                };
                value.to_be_bytes().to_vec()
            }
            ColumnKind::Decimal256 => {
                let value = if let Some(constraint) = self.constraints.get(&col_idx) {
                    let PredicateConstraint::Decimal256Range { min, max } = constraint else {
                        return Err(format!("missing decimal256 constraint for '{}'", col.name));
                    };
                    if upper {
                        max.unwrap_or(i256::MAX)
                    } else {
                        min.unwrap_or(i256::MIN)
                    }
                } else if upper {
                    i256::MAX
                } else {
                    i256::MIN
                };
                encode_i256_ordered(value).to_vec()
            }
            ColumnKind::FixedSizeBinary(n) => {
                let mut bytes = vec![0u8; n];
                if let Some(constraint) = self.constraints.get(&col_idx) {
                    let PredicateConstraint::FixedBinaryEq(data) = constraint else {
                        return Err(format!(
                            "missing fixed-binary constraint for '{}'",
                            col.name
                        ));
                    };
                    if data.len() > n {
                        return Err(format!(
                            "fixed-binary constraint for '{}' exceeds width {}",
                            col.name, n
                        ));
                    }
                    bytes[..data.len()].copy_from_slice(data);
                } else if upper {
                    bytes.fill(0xFF);
                }
                bytes
            }
            ColumnKind::List(_) => unreachable!("list columns cannot be indexed"),
        })
    }

    pub(crate) fn int_bounds(&self, col_idx: usize) -> (Option<i64>, Option<i64>) {
        match self.constraints.get(&col_idx) {
            Some(PredicateConstraint::IntRange { min, max }) => (*min, *max),
            _ => (None, None),
        }
    }

    pub(crate) fn uint64_bounds(&self, col_idx: usize) -> (u64, u64) {
        match self.constraints.get(&col_idx) {
            Some(PredicateConstraint::UInt64Range { min, max }) => {
                (min.unwrap_or(0), max.unwrap_or(u64::MAX))
            }
            _ => (0, u64::MAX),
        }
    }

    pub(crate) fn primary_key_ranges(&self, model: &TableModel) -> DataFusionResult<Vec<KeyRange>> {
        if self.contradiction {
            return Ok(Vec::new());
        }

        // Walk PK columns left-to-right collecting equality-constrained
        // prefix values. When we hit a range-constrained or unconstrained
        // column, produce the final key range(s).
        let mut prefix_values: Vec<CellValue> = Vec::new();

        for (pos, (&pk_idx, &pk_kind)) in model
            .primary_key_indices
            .iter()
            .zip(model.primary_key_kinds.iter())
            .enumerate()
        {
            match pk_kind {
                ColumnKind::FixedSizeBinary(_) => match self.constraints.get(&pk_idx) {
                    Some(PredicateConstraint::FixedBinaryEq(data)) => {
                        prefix_values.push(CellValue::FixedBinary(data.clone()));
                        continue;
                    }
                    Some(PredicateConstraint::FixedBinaryIn(values)) => {
                        let mut ranges = Vec::with_capacity(values.len());
                        for data in values {
                            let mut lo = prefix_values.clone();
                            lo.push(CellValue::FixedBinary(data.clone()));
                            let refs: Vec<&CellValue> = lo.iter().collect();
                            ranges.push(KeyRange {
                                start: encode_primary_key_bound(
                                    model.table_prefix,
                                    &refs,
                                    model,
                                    false,
                                )
                                .map_err(DataFusionError::Execution)?,
                                end: encode_primary_key_bound(
                                    model.table_prefix,
                                    &refs,
                                    model,
                                    true,
                                )
                                .map_err(DataFusionError::Execution)?,
                            });
                        }
                        return Ok(ranges);
                    }
                    _ => break,
                },
                ColumnKind::Int64 => {
                    if let Some(PredicateConstraint::IntIn(values)) = self.constraints.get(&pk_idx)
                    {
                        let mut ranges = Vec::with_capacity(values.len());
                        for &v in values {
                            let mut lo = prefix_values.clone();
                            lo.push(CellValue::Int64(v));
                            let refs: Vec<&CellValue> = lo.iter().collect();
                            ranges.push(KeyRange {
                                start: encode_primary_key_bound(
                                    model.table_prefix,
                                    &refs,
                                    model,
                                    false,
                                )
                                .map_err(DataFusionError::Execution)?,
                                end: encode_primary_key_bound(
                                    model.table_prefix,
                                    &refs,
                                    model,
                                    true,
                                )
                                .map_err(DataFusionError::Execution)?,
                            });
                        }
                        return Ok(ranges);
                    }
                    let (pk_min, pk_max) = self.int_bounds(pk_idx);
                    if let (Some(lo), Some(hi)) = (pk_min, pk_max) {
                        if lo == hi {
                            prefix_values.push(CellValue::Int64(lo));
                            continue;
                        }
                    }
                    if pk_min.is_none() && pk_max.is_none() && pos == 0 {
                        return Ok(vec![primary_key_prefix_range(model.table_prefix)]);
                    }
                    let mut lo = prefix_values.clone();
                    lo.push(CellValue::Int64(pk_min.unwrap_or(i64::MIN)));
                    let mut hi = prefix_values;
                    hi.push(CellValue::Int64(pk_max.unwrap_or(i64::MAX)));
                    let lo_refs: Vec<&CellValue> = lo.iter().collect();
                    let hi_refs: Vec<&CellValue> = hi.iter().collect();
                    return Ok(vec![KeyRange {
                        start: encode_primary_key_bound(model.table_prefix, &lo_refs, model, false)
                            .map_err(DataFusionError::Execution)?,
                        end: encode_primary_key_bound(model.table_prefix, &hi_refs, model, true)
                            .map_err(DataFusionError::Execution)?,
                    }]);
                }
                ColumnKind::UInt64 => {
                    if let Some(PredicateConstraint::UInt64In(values)) =
                        self.constraints.get(&pk_idx)
                    {
                        let mut ranges = Vec::new();
                        for &v in values {
                            let mut lo = prefix_values.clone();
                            lo.push(CellValue::UInt64(v));
                            let refs: Vec<&CellValue> = lo.iter().collect();
                            ranges.push(KeyRange {
                                start: encode_primary_key_bound(
                                    model.table_prefix,
                                    &refs,
                                    model,
                                    false,
                                )
                                .map_err(DataFusionError::Execution)?,
                                end: encode_primary_key_bound(
                                    model.table_prefix,
                                    &refs,
                                    model,
                                    true,
                                )
                                .map_err(DataFusionError::Execution)?,
                            });
                        }
                        return Ok(ranges);
                    }
                    let (pk_min, pk_max) = match self.constraints.get(&pk_idx) {
                        Some(PredicateConstraint::UInt64Range { min, max }) => (*min, *max),
                        _ => (None, None),
                    };
                    let pk_lower = pk_min.unwrap_or(0);
                    let pk_upper = pk_max.unwrap_or(u64::MAX);
                    if pk_lower > pk_upper {
                        return Ok(Vec::new());
                    }
                    if pk_lower == pk_upper {
                        prefix_values.push(CellValue::UInt64(pk_lower));
                        continue;
                    }
                    if pk_min.is_none() && pk_max.is_none() && pos == 0 {
                        return Ok(vec![primary_key_prefix_range(model.table_prefix)]);
                    }
                    let mut lo = prefix_values.clone();
                    lo.push(CellValue::UInt64(pk_lower));
                    let mut hi = prefix_values;
                    hi.push(CellValue::UInt64(pk_upper));
                    let lo_refs: Vec<&CellValue> = lo.iter().collect();
                    let hi_refs: Vec<&CellValue> = hi.iter().collect();
                    return Ok(vec![KeyRange {
                        start: encode_primary_key_bound(model.table_prefix, &lo_refs, model, false)
                            .map_err(DataFusionError::Execution)?,
                        end: encode_primary_key_bound(model.table_prefix, &hi_refs, model, true)
                            .map_err(DataFusionError::Execution)?,
                    }]);
                }
                ColumnKind::Utf8 => {
                    if let Some(PredicateConstraint::StringEq(s)) = self.constraints.get(&pk_idx) {
                        prefix_values.push(CellValue::Utf8(s.clone()));
                        continue;
                    }
                    break;
                }
                _ => break,
            }
        }

        if prefix_values.is_empty() {
            return Ok(vec![primary_key_prefix_range(model.table_prefix)]);
        }

        let refs: Vec<&CellValue> = prefix_values.iter().collect();
        Ok(vec![KeyRange {
            start: encode_primary_key_bound(model.table_prefix, &refs, model, false)
                .map_err(DataFusionError::Execution)?,
            end: encode_primary_key_bound(model.table_prefix, &refs, model, true)
                .map_err(DataFusionError::Execution)?,
        }])
    }

    #[cfg(test)]
    pub(crate) fn matches_row(&self, row: &KvRow) -> bool {
        if self.contradiction {
            return false;
        }
        for (col_idx, constraint) in &self.constraints {
            let value = row.value_at(*col_idx);
            if !matches_constraint(value, constraint) {
                return false;
            }
        }
        true
    }

    pub(crate) fn describe(&self, model: &TableModel) -> String {
        if self.contradiction {
            return "FALSE".to_string();
        }
        if self.constraints.is_empty() {
            return "<none>".to_string();
        }
        let mut cols = self.constraints.keys().copied().collect::<Vec<_>>();
        cols.sort_unstable();
        cols.into_iter()
            .filter_map(|col_idx| {
                let constraint = self.constraints.get(&col_idx)?;
                Some(format!(
                    "{} {}",
                    model.column(col_idx).name,
                    describe_predicate_constraint(constraint)
                ))
            })
            .collect::<Vec<_>>()
            .join(" AND ")
    }
}

pub(crate) fn describe_predicate_constraint(constraint: &PredicateConstraint) -> String {
    match constraint {
        PredicateConstraint::StringEq(value) => format!("= '{}'", escape_plan_string(value)),
        PredicateConstraint::BoolEq(value) => format!("= {value}"),
        PredicateConstraint::FixedBinaryEq(value) => format!("= 0x{}", hex_preview(value)),
        PredicateConstraint::IntRange { min, max } => {
            describe_integral_range(min.map(|v| v.to_string()), max.map(|v| v.to_string()))
        }
        PredicateConstraint::UInt64Range { min, max } => {
            describe_integral_range(min.map(|v| v.to_string()), max.map(|v| v.to_string()))
        }
        PredicateConstraint::FloatRange { min, max } => describe_float_range(*min, *max),
        PredicateConstraint::Decimal128Range { min, max } => {
            describe_integral_range(min.map(|v| v.to_string()), max.map(|v| v.to_string()))
        }
        PredicateConstraint::Decimal256Range { min, max } => {
            describe_integral_range(min.map(|v| v.to_string()), max.map(|v| v.to_string()))
        }
        PredicateConstraint::IsNull => "IS NULL".to_string(),
        PredicateConstraint::IsNotNull => "IS NOT NULL".to_string(),
        PredicateConstraint::StringIn(values) => describe_in_list(
            values
                .iter()
                .map(|v| format!("'{}'", escape_plan_string(v))),
        ),
        PredicateConstraint::IntIn(values) => {
            describe_in_list(values.iter().map(ToString::to_string))
        }
        PredicateConstraint::UInt64In(values) => {
            describe_in_list(values.iter().map(ToString::to_string))
        }
        PredicateConstraint::FixedBinaryIn(values) => {
            describe_in_list(values.iter().map(|v| format!("0x{}", hex_preview(v))))
        }
    }
}

pub(crate) fn describe_integral_range(min: Option<String>, max: Option<String>) -> String {
    match (min, max) {
        (Some(min), Some(max)) if min == max => format!("= {min}"),
        (Some(min), Some(max)) => format!("BETWEEN {min} AND {max}"),
        (Some(min), None) => format!(">= {min}"),
        (None, Some(max)) => format!("<= {max}"),
        (None, None) => "IS ANY".to_string(),
    }
}

pub(crate) fn describe_float_range(min: Option<(f64, bool)>, max: Option<(f64, bool)>) -> String {
    match (min, max) {
        (Some((min, true)), Some((max, true))) if min == max => format!("= {}", format_float(min)),
        (Some((min, min_inclusive)), Some((max, max_inclusive))) => format!(
            "{} {} AND {} {}",
            if min_inclusive { ">=" } else { ">" },
            format_float(min),
            if max_inclusive { "<=" } else { "<" },
            format_float(max)
        ),
        (Some((min, inclusive)), None) => format!(
            "{} {}",
            if inclusive { ">=" } else { ">" },
            format_float(min)
        ),
        (None, Some((max, inclusive))) => format!(
            "{} {}",
            if inclusive { "<=" } else { "<" },
            format_float(max)
        ),
        (None, None) => "IS ANY".to_string(),
    }
}

pub(crate) fn describe_in_list(values: impl Iterator<Item = String>) -> String {
    let mut values = values.collect::<Vec<_>>();
    let truncated = values.len() > 5;
    if truncated {
        values.truncate(5);
        values.push("...".to_string());
    }
    format!("IN ({})", values.join(", "))
}

pub(crate) fn format_float(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_string()
    } else {
        value.to_string()
    }
}

pub(crate) fn escape_plan_string(value: &str) -> String {
    value.replace('\'', "''")
}

pub(crate) fn hex_preview(bytes: &[u8]) -> String {
    let mut encoded = hex::encode(bytes);
    if encoded.len() > 16 {
        encoded.truncate(16);
        encoded.push_str("...");
    }
    encoded
}

pub(crate) fn matches_constraint(value: &CellValue, constraint: &PredicateConstraint) -> bool {
    match (value, constraint) {
        (CellValue::Null, PredicateConstraint::IsNull) => return true,
        (CellValue::Null, PredicateConstraint::IsNotNull) => return false,
        (_, PredicateConstraint::IsNull) => return false,
        (_, PredicateConstraint::IsNotNull) => return true,
        (CellValue::Null, _) => return false,
        _ => {}
    }
    match (value, constraint) {
        (CellValue::Utf8(v), PredicateConstraint::StringEq(expected)) => v == expected,
        (CellValue::Boolean(v), PredicateConstraint::BoolEq(expected)) => v == expected,
        (CellValue::Int64(v), PredicateConstraint::IntRange { min, max }) => {
            in_i64_bounds(*v, *min, *max)
        }
        (CellValue::Date32(v), PredicateConstraint::IntRange { min, max }) => {
            in_i64_bounds(*v as i64, *min, *max)
        }
        (CellValue::Date64(v), PredicateConstraint::IntRange { min, max }) => {
            in_i64_bounds(*v, *min, *max)
        }
        (CellValue::Timestamp(v), PredicateConstraint::IntRange { min, max }) => {
            in_i64_bounds(*v, *min, *max)
        }
        (CellValue::Float64(v), PredicateConstraint::FloatRange { min, max }) => {
            in_f64_bounds(*v, min, max)
        }
        (CellValue::Decimal128(v), PredicateConstraint::Decimal128Range { min, max }) => {
            in_i128_bounds(*v, *min, *max)
        }
        (CellValue::Utf8(v), PredicateConstraint::StringIn(values)) => {
            values.binary_search(v).is_ok()
        }
        (CellValue::Int64(v), PredicateConstraint::IntIn(values)) => {
            values.binary_search(v).is_ok()
        }
        (CellValue::UInt64(v), PredicateConstraint::UInt64Range { min, max }) => {
            in_u64_bounds(*v, *min, *max)
        }
        (CellValue::UInt64(v), PredicateConstraint::UInt64In(values)) => {
            values.binary_search(v).is_ok()
        }
        (CellValue::FixedBinary(v), PredicateConstraint::FixedBinaryEq(expected)) => v == expected,
        (CellValue::FixedBinary(v), PredicateConstraint::FixedBinaryIn(values)) => {
            values.binary_search(v).is_ok()
        }
        (CellValue::Decimal256(v), PredicateConstraint::Decimal256Range { min, max }) => {
            if let Some(mn) = min {
                if *v < *mn {
                    return false;
                }
            }
            if let Some(mx) = max {
                if *v > *mx {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

pub(crate) fn matches_archived_non_pk_constraint(
    col: &ResolvedColumn,
    stored_opt: Option<&StoredValue>,
    constraint: &PredicateConstraint,
) -> bool {
    match stored_opt {
        None => {
            if !col.nullable {
                return false;
            }
            matches!(constraint, PredicateConstraint::IsNull)
        }
        Some(_) if matches!(constraint, PredicateConstraint::IsNull) => false,
        Some(_) if matches!(constraint, PredicateConstraint::IsNotNull) => true,
        Some(stored) => match (col.kind, stored, constraint) {
            (
                ColumnKind::Utf8,
                StoredValue::Utf8(v),
                PredicateConstraint::StringEq(expected),
            ) => v.as_str() == expected,
            (
                ColumnKind::Utf8,
                StoredValue::Utf8(v),
                PredicateConstraint::StringIn(values),
            ) => values.iter().any(|candidate| candidate == v.as_str()),
            (
                ColumnKind::Boolean,
                StoredValue::Boolean(v),
                PredicateConstraint::BoolEq(expected),
            ) => *v == *expected,
            (
                ColumnKind::Int64,
                StoredValue::Int64(v),
                PredicateConstraint::IntRange { min, max },
            ) => in_i64_bounds(*v, *min, *max),
            (
                ColumnKind::Date32,
                StoredValue::Int64(v),
                PredicateConstraint::IntRange { min, max },
            ) => in_i64_bounds(*v as i32 as i64, *min, *max),
            (
                ColumnKind::Date64,
                StoredValue::Int64(v),
                PredicateConstraint::IntRange { min, max },
            ) => in_i64_bounds(*v, *min, *max),
            (
                ColumnKind::Timestamp,
                StoredValue::Int64(v),
                PredicateConstraint::IntRange { min, max },
            ) => in_i64_bounds(*v, *min, *max),
            (
                ColumnKind::Float64,
                StoredValue::Float64(v),
                PredicateConstraint::FloatRange { min, max },
            ) => in_f64_bounds(*v, min, max),
            (
                ColumnKind::Float64,
                StoredValue::Int64(v),
                PredicateConstraint::FloatRange { min, max },
            ) => in_f64_bounds(*v as f64, min, max),
            (
                ColumnKind::Decimal128,
                StoredValue::Bytes(bytes),
                PredicateConstraint::Decimal128Range { min, max },
            ) => {
                let Ok(arr) = <[u8; 16]>::try_from(bytes.as_slice()) else {
                    return false;
                };
                in_i128_bounds(i128::from_le_bytes(arr), *min, *max)
            }
            (
                ColumnKind::Decimal256,
                StoredValue::Bytes(bytes),
                PredicateConstraint::Decimal256Range { min, max },
            ) => {
                let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                    return false;
                };
                let value = i256::from_le_bytes(arr);
                if let Some(min) = min {
                    if value < *min {
                        return false;
                    }
                }
                if let Some(max) = max {
                    if value > *max {
                        return false;
                    }
                }
                true
            }
            (
                ColumnKind::UInt64,
                StoredValue::UInt64(v),
                PredicateConstraint::UInt64Range { min, max },
            ) => in_u64_bounds(*v, *min, *max),
            (
                ColumnKind::UInt64,
                StoredValue::UInt64(v),
                PredicateConstraint::UInt64In(values),
            ) => values.contains(v),
            (
                ColumnKind::Int64,
                StoredValue::Int64(v),
                PredicateConstraint::IntIn(values),
            ) => values.contains(v),
            (
                ColumnKind::FixedSizeBinary(_),
                StoredValue::Bytes(v),
                PredicateConstraint::FixedBinaryEq(expected),
            ) => v.as_slice() == expected.as_slice(),
            (
                ColumnKind::FixedSizeBinary(_),
                StoredValue::Bytes(v),
                PredicateConstraint::FixedBinaryIn(values),
            ) => values
                .iter()
                .any(|candidate| candidate.as_slice() == v.as_slice()),
            _ => false,
        },
    }
}

pub(crate) fn in_i64_bounds(value: i64, min: Option<i64>, max: Option<i64>) -> bool {
    if let Some(min) = min {
        if value < min {
            return false;
        }
    }
    if let Some(max) = max {
        if value > max {
            return false;
        }
    }
    true
}

pub(crate) fn in_u64_bounds(value: u64, min: Option<u64>, max: Option<u64>) -> bool {
    if let Some(min) = min {
        if value < min {
            return false;
        }
    }
    if let Some(max) = max {
        if value > max {
            return false;
        }
    }
    true
}

pub(crate) fn in_f64_bounds(value: f64, lower: &Option<(f64, bool)>, upper: &Option<(f64, bool)>) -> bool {
    if value.is_nan() {
        return false;
    }
    if let Some((bound, inclusive)) = lower {
        if bound.is_nan() {
            return false;
        }
        if *inclusive {
            if value < *bound {
                return false;
            }
        } else if value <= *bound {
            return false;
        }
    }
    if let Some((bound, inclusive)) = upper {
        if bound.is_nan() {
            return false;
        }
        if *inclusive {
            if value > *bound {
                return false;
            }
        } else if value >= *bound {
            return false;
        }
    }
    true
}

pub(crate) fn apply_int_constraint(
    min: &mut Option<i64>,
    max: &mut Option<i64>,
    op: Operator,
    value: i64,
    contradiction: &mut bool,
) {
    let (new_min, new_max) = match op {
        Operator::Eq => (Some(value), Some(value)),
        Operator::Gt => (value.checked_add(1), None),
        Operator::GtEq => (Some(value), None),
        Operator::Lt => (None, value.checked_sub(1)),
        Operator::LtEq => (None, Some(value)),
        _ => return,
    };

    if (matches!(op, Operator::Gt) && new_min.is_none())
        || (matches!(op, Operator::Lt) && new_max.is_none())
    {
        *contradiction = true;
        return;
    }

    if let Some(new_min) = new_min {
        *min = Some(match *min {
            Some(existing) => existing.max(new_min),
            None => new_min,
        });
    }
    if let Some(new_max) = new_max {
        *max = Some(match *max {
            Some(existing) => existing.min(new_max),
            None => new_max,
        });
    }
    if let (Some(min), Some(max)) = (*min, *max) {
        if min > max {
            *contradiction = true;
        }
    }
}

pub(crate) fn apply_u64_constraint(
    min: &mut Option<u64>,
    max: &mut Option<u64>,
    op: Operator,
    value: u64,
    contradiction: &mut bool,
) {
    let (new_min, new_max) = match op {
        Operator::Eq => (Some(value), Some(value)),
        Operator::Gt => (value.checked_add(1), None),
        Operator::GtEq => (Some(value), None),
        Operator::Lt => (None, value.checked_sub(1)),
        Operator::LtEq => (None, Some(value)),
        _ => return,
    };

    if (matches!(op, Operator::Gt) && new_min.is_none())
        || (matches!(op, Operator::Lt) && new_max.is_none())
    {
        *contradiction = true;
        return;
    }

    if let Some(new_min) = new_min {
        *min = Some(match *min {
            Some(existing) => existing.max(new_min),
            None => new_min,
        });
    }
    if let Some(new_max) = new_max {
        *max = Some(match *max {
            Some(existing) => existing.min(new_max),
            None => new_max,
        });
    }
    if let (Some(min), Some(max)) = (*min, *max) {
        if min > max {
            *contradiction = true;
        }
    }
}

pub(crate) fn apply_float_constraint(
    lo: &mut Option<(f64, bool)>,
    hi: &mut Option<(f64, bool)>,
    op: Operator,
    value: f64,
    contradiction: &mut bool,
) {
    if value.is_nan() {
        *contradiction = true;
        return;
    }
    match op {
        Operator::Eq => {
            merge_float_lower(lo, value, true);
            merge_float_upper(hi, value, true);
        }
        Operator::Gt => merge_float_lower(lo, value, false),
        Operator::GtEq => merge_float_lower(lo, value, true),
        Operator::Lt => merge_float_upper(hi, value, false),
        Operator::LtEq => merge_float_upper(hi, value, true),
        _ => return,
    }
    if let (Some((lo_v, lo_inc)), Some((hi_v, hi_inc))) = (&*lo, &*hi) {
        if lo_v > hi_v || (lo_v == hi_v && !(*lo_inc && *hi_inc)) {
            *contradiction = true;
        }
    }
}

pub(crate) fn merge_float_lower(current: &mut Option<(f64, bool)>, value: f64, inclusive: bool) {
    *current = Some(match *current {
        Some((existing, existing_inc)) => {
            if value > existing {
                (value, inclusive)
            } else if value == existing {
                (value, existing_inc && inclusive)
            } else {
                (existing, existing_inc)
            }
        }
        None => (value, inclusive),
    });
}

pub(crate) fn merge_float_upper(current: &mut Option<(f64, bool)>, value: f64, inclusive: bool) {
    *current = Some(match *current {
        Some((existing, existing_inc)) => {
            if value < existing {
                (value, inclusive)
            } else if value == existing {
                (value, existing_inc && inclusive)
            } else {
                (existing, existing_inc)
            }
        }
        None => (value, inclusive),
    });
}

pub(crate) fn in_i128_bounds(value: i128, min: Option<i128>, max: Option<i128>) -> bool {
    if let Some(min) = min {
        if value < min {
            return false;
        }
    }
    if let Some(max) = max {
        if value > max {
            return false;
        }
    }
    true
}

pub(crate) fn apply_decimal128_constraint(
    min: &mut Option<i128>,
    max: &mut Option<i128>,
    op: Operator,
    value: i128,
    contradiction: &mut bool,
) {
    let (new_min, new_max) = match op {
        Operator::Eq => (Some(value), Some(value)),
        Operator::Gt => (value.checked_add(1), None),
        Operator::GtEq => (Some(value), None),
        Operator::Lt => (None, value.checked_sub(1)),
        Operator::LtEq => (None, Some(value)),
        _ => return,
    };

    if (matches!(op, Operator::Gt) && new_min.is_none())
        || (matches!(op, Operator::Lt) && new_max.is_none())
    {
        *contradiction = true;
        return;
    }

    if let Some(new_min) = new_min {
        *min = Some(match *min {
            Some(existing) => existing.max(new_min),
            None => new_min,
        });
    }
    if let Some(new_max) = new_max {
        *max = Some(match *max {
            Some(existing) => existing.min(new_max),
            None => new_max,
        });
    }
    if let (Some(min), Some(max)) = (*min, *max) {
        if min > max {
            *contradiction = true;
        }
    }
}

pub(crate) fn apply_i256_constraint(
    min: &mut Option<i256>,
    max: &mut Option<i256>,
    op: Operator,
    value: i256,
    contradiction: &mut bool,
) {
    let one = i256::from(1i64);
    let (new_min, new_max) = match op {
        Operator::Eq => (Some(value), Some(value)),
        Operator::Gt => {
            if value == i256::MAX {
                *contradiction = true;
                return;
            }
            (Some(value + one), None)
        }
        Operator::GtEq => (Some(value), None),
        Operator::Lt => {
            if value == i256::MIN {
                *contradiction = true;
                return;
            }
            (None, Some(value - one))
        }
        Operator::LtEq => (None, Some(value)),
        _ => return,
    };

    if let Some(new_min) = new_min {
        *min = Some(match *min {
            Some(existing) if existing > new_min => existing,
            _ => new_min,
        });
    }
    if let Some(new_max) = new_max {
        *max = Some(match *max {
            Some(existing) if existing < new_max => existing,
            _ => new_max,
        });
    }
    if let (Some(mn), Some(mx)) = (*min, *max) {
        if mn > mx {
            *contradiction = true;
        }
    }
}

pub(crate) fn extract_or_in_column(expr: &Expr, model: &TableModel) -> Option<(String, Vec<ScalarValue>)> {
    let mut col_name: Option<String> = None;
    let mut values: Vec<ScalarValue> = Vec::new();
    if !collect_or_equalities(expr, &mut col_name, &mut values) {
        return None;
    }
    let name = col_name?;
    if values.is_empty() {
        return None;
    }
    let &col_idx = model.columns_by_name.get(&name)?;
    let kind = model.columns[col_idx].kind;
    if !values
        .iter()
        .all(|value| QueryPredicate::in_list_literal_supported(kind, value))
    {
        return None;
    }
    Some((name, values))
}

pub(crate) fn collect_or_equalities(
    expr: &Expr,
    col_name: &mut Option<String>,
    values: &mut Vec<ScalarValue>,
) -> bool {
    match expr {
        Expr::BinaryExpr(binary) if binary.op == Operator::Or => {
            collect_or_equalities(&binary.left, col_name, values)
                && collect_or_equalities(&binary.right, col_name, values)
        }
        _ => {
            let Some((column, op, literal)) = parse_simple_comparison(expr) else {
                return false;
            };
            if op != Operator::Eq {
                return false;
            }
            match col_name {
                Some(existing) if *existing != column => false,
                Some(_) => {
                    values.push(literal);
                    true
                }
                None => {
                    *col_name = Some(column);
                    values.push(literal);
                    true
                }
            }
        }
    }
}

pub(crate) fn parse_simple_comparison(expr: &Expr) -> Option<(String, Operator, ScalarValue)> {
    let Expr::BinaryExpr(binary) = expr else {
        return None;
    };
    if !matches!(
        binary.op,
        Operator::Eq | Operator::Lt | Operator::LtEq | Operator::Gt | Operator::GtEq
    ) {
        return None;
    }

    if let (Some(column), Some(literal)) = (
        extract_column_name(binary.left.as_ref()),
        extract_literal(binary.right.as_ref()),
    ) {
        return Some((column.to_string(), binary.op, literal.clone()));
    }
    if let (Some(literal), Some(column)) = (
        extract_literal(binary.left.as_ref()),
        extract_column_name(binary.right.as_ref()),
    ) {
        return Some((
            column.to_string(),
            reverse_operator(binary.op)?,
            literal.clone(),
        ));
    }
    None
}

pub(crate) fn reverse_operator(op: Operator) -> Option<Operator> {
    match op {
        Operator::Eq => Some(Operator::Eq),
        Operator::Lt => Some(Operator::Gt),
        Operator::LtEq => Some(Operator::GtEq),
        Operator::Gt => Some(Operator::Lt),
        Operator::GtEq => Some(Operator::LtEq),
        _ => None,
    }
}

pub(crate) fn extract_column_name(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Column(col) => Some(col.name.as_str()),
        Expr::Cast(cast) => extract_column_name(cast.expr.as_ref()),
        Expr::TryCast(cast) => extract_column_name(cast.expr.as_ref()),
        _ => None,
    }
}

pub(crate) fn extract_literal(expr: &Expr) -> Option<&ScalarValue> {
    match expr {
        Expr::Literal(value, _) => Some(value),
        Expr::Cast(cast) => extract_literal(cast.expr.as_ref()),
        Expr::TryCast(cast) => extract_literal(cast.expr.as_ref()),
        _ => None,
    }
}

pub(crate) fn scalar_to_string(value: &ScalarValue) -> Option<String> {
    match value {
        ScalarValue::Utf8(Some(v))
        | ScalarValue::Utf8View(Some(v))
        | ScalarValue::LargeUtf8(Some(v)) => Some(v.clone()),
        _ => None,
    }
}

pub(crate) fn scalar_to_i64(value: &ScalarValue) -> Option<i64> {
    match value {
        ScalarValue::Int8(Some(v)) => Some(*v as i64),
        ScalarValue::Int16(Some(v)) => Some(*v as i64),
        ScalarValue::Int32(Some(v)) => Some(*v as i64),
        ScalarValue::Int64(Some(v)) => Some(*v),
        ScalarValue::UInt8(Some(v)) => Some(*v as i64),
        ScalarValue::UInt16(Some(v)) => Some(*v as i64),
        ScalarValue::UInt32(Some(v)) => Some(*v as i64),
        ScalarValue::UInt64(Some(v)) => i64::try_from(*v).ok(),
        _ => None,
    }
}

pub(crate) fn scalar_to_u64(value: &ScalarValue) -> Option<u64> {
    match value {
        ScalarValue::Int8(Some(v)) if *v >= 0 => Some(*v as u64),
        ScalarValue::Int16(Some(v)) if *v >= 0 => Some(*v as u64),
        ScalarValue::Int32(Some(v)) if *v >= 0 => Some(*v as u64),
        ScalarValue::Int64(Some(v)) => u64::try_from(*v).ok(),
        ScalarValue::UInt8(Some(v)) => Some(*v as u64),
        ScalarValue::UInt16(Some(v)) => Some(*v as u64),
        ScalarValue::UInt32(Some(v)) => Some(*v as u64),
        ScalarValue::UInt64(Some(v)) => Some(*v),
        _ => None,
    }
}

pub(crate) fn scalar_to_f64(value: &ScalarValue) -> Option<f64> {
    match value {
        ScalarValue::Float32(Some(v)) => Some(*v as f64),
        ScalarValue::Float64(Some(v)) => Some(*v),
        _ => None,
    }
}

pub(crate) fn scalar_to_bool(value: &ScalarValue) -> Option<bool> {
    match value {
        ScalarValue::Boolean(Some(v)) => Some(*v),
        _ => None,
    }
}

pub(crate) fn scalar_to_date32_i64(value: &ScalarValue) -> Option<i64> {
    match value {
        ScalarValue::Date32(Some(v)) => Some(*v as i64),
        _ => None,
    }
}

pub(crate) fn scalar_to_date64(value: &ScalarValue) -> Option<i64> {
    match value {
        ScalarValue::Date64(Some(v)) => Some(*v),
        _ => None,
    }
}

pub(crate) fn scalar_to_timestamp_micros(value: &ScalarValue) -> Option<i64> {
    match value {
        ScalarValue::TimestampSecond(Some(v), _) => v.checked_mul(1_000_000),
        ScalarValue::TimestampMillisecond(Some(v), _) => v.checked_mul(1_000),
        ScalarValue::TimestampMicrosecond(Some(v), _) => Some(*v),
        ScalarValue::TimestampNanosecond(Some(v), _) => Some(v.div_euclid(1_000)),
        _ => None,
    }
}

pub(crate) fn timestamp_scalar_to_micros_for_op(value: &ScalarValue, op: Operator) -> Option<i64> {
    match value {
        ScalarValue::TimestampSecond(Some(v), _) => v.checked_mul(1_000_000),
        ScalarValue::TimestampMillisecond(Some(v), _) => v.checked_mul(1_000),
        ScalarValue::TimestampMicrosecond(Some(v), _) => Some(*v),
        ScalarValue::TimestampNanosecond(Some(v), _) => {
            let micros = v.div_euclid(1_000);
            if v.rem_euclid(1_000) == 0 {
                return Some(micros);
            }
            match op {
                Operator::Eq => None,
                Operator::Gt | Operator::LtEq => Some(micros),
                Operator::GtEq | Operator::Lt => Some(micros + 1),
                _ => None,
            }
        }
        _ => None,
    }
}

pub(crate) fn scalar_to_i128(value: &ScalarValue) -> Option<i128> {
    match value {
        ScalarValue::Decimal128(Some(v), _, _) => Some(*v),
        _ => None,
    }
}

pub(crate) fn scalar_to_fixed_binary(value: &ScalarValue) -> Option<Vec<u8>> {
    match value {
        ScalarValue::FixedSizeBinary(_, Some(v)) => Some(v.clone()),
        ScalarValue::Binary(Some(v)) => Some(v.clone()),
        ScalarValue::LargeBinary(Some(v)) => Some(v.clone()),
        _ => None,
    }
}

pub(crate) fn scalar_to_i256(value: &ScalarValue) -> Option<i256> {
    match value {
        ScalarValue::Decimal256(Some(v), _, _) => Some(*v),
        _ => None,
    }
}

