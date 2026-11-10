use crate::{codec::*, filter::ScanAccessPlan, types::*};
use datafusion::{
    arrow::{array::ArrowNativeTypeOp, datatypes::i256},
    common::{DataFusionError, Result as DataFusionResult, ScalarValue},
    logical_expr::{utils::iter_conjunction, Expr, Operator},
};
use exoware_sdk::{
    keys::{Key, Prefix},
    kv_codec::interleave_ordered_key_fields,
};
use std::collections::HashMap;

/// A supported SQL condition on one column. Value comparisons exclude nulls.
#[derive(Debug, Clone)]
pub(crate) enum PredicateConstraint {
    /// Equality with the supplied UTF-8 value.
    StringEq(String),
    /// Equality with the supplied boolean value.
    BoolEq(bool),
    /// Equality with the supplied fixed-size binary bytes.
    FixedSizeBinaryEq(Vec<u8>),
    /// Inclusive range of signed integers or temporal values. Dates use days (`Date32`)
    /// or milliseconds (`Date64`) since the Unix epoch, and timestamps use microseconds.
    IntRange {
        /// Inclusive lower bound, or `None` if unbounded.
        min: Option<i64>,
        /// Inclusive upper bound, or `None` if unbounded.
        max: Option<i64>,
    },
    /// Inclusive range of unsigned integers.
    UInt64Range {
        /// Inclusive lower bound, or `None` if unbounded.
        min: Option<u64>,
        /// Inclusive upper bound, or `None` if unbounded.
        max: Option<u64>,
    },
    /// Floating-point range with independently inclusive or exclusive endpoints.
    FloatRange {
        /// Lower value and whether equality is allowed, or `None` if unbounded.
        min: Option<(f64, bool)>,
        /// Upper value and whether equality is allowed, or `None` if unbounded.
        max: Option<(f64, bool)>,
    },
    /// Inclusive range of 128-bit decimal coefficients.
    Decimal128Range {
        /// Inclusive lower coefficient, or `None` if unbounded.
        min: Option<i128>,
        /// Inclusive upper coefficient, or `None` if unbounded.
        max: Option<i128>,
    },
    /// Inclusive range of 256-bit decimal coefficients.
    Decimal256Range {
        /// Inclusive lower coefficient, or `None` if unbounded.
        min: Option<i256>,
        /// Inclusive upper coefficient, or `None` if unbounded.
        max: Option<i256>,
    },
    /// Require a null value.
    IsNull,
    /// Require a non-null value.
    IsNotNull,
    /// Membership in the sorted, distinct UTF-8 values.
    StringIn(Vec<String>),
    /// Membership in the sorted, distinct signed integers.
    IntIn(Vec<i64>),
    /// Membership in the sorted, distinct unsigned integers.
    UInt64In(Vec<u64>),
    /// Membership in the sorted, distinct fixed-size binary values.
    FixedSizeBinaryIn(Vec<Vec<u8>>),
}

/// Inclusive bounds for one primary-key field, after any preceding point fields.
#[derive(Debug, Clone)]
pub(crate) struct PrimaryKeyTerminalRange {
    /// First field value included in the scan range.
    lower: CellValue,
    /// Last field value included in the scan range.
    upper: CellValue,
}

/// A single primary-key value that allows range planning to continue to the next field.
#[derive(Debug, Clone)]
pub(crate) struct PrimaryKeyPointConstraint {
    /// Field value appended to the constrained primary-key prefix.
    pub(crate) value: CellValue,
    /// Length in bytes of this value's ordered key encoding.
    pub(crate) encoded_width: usize,
}

/// How a column constraint narrows a lexicographic primary-key scan.
#[derive(Debug, Clone)]
pub(crate) enum PrimaryKeyRangeConstraint {
    /// Extend the point prefix and consider the next primary-key field.
    Point(PrimaryKeyPointConstraint),
    /// Emit these spans and stop extending the prefix. An empty list yields no ranges.
    Terminal(Vec<PrimaryKeyTerminalRange>),
    /// Stop extending the prefix and leave this constraint for row evaluation.
    NotEnforced,
}

const fn primary_key_point(value: CellValue, encoded_width: usize) -> PrimaryKeyRangeConstraint {
    PrimaryKeyRangeConstraint::Point(PrimaryKeyPointConstraint {
        value,
        encoded_width,
    })
}

pub(crate) fn primary_key_range_constraint(
    kind: ColumnKind,
    constraint: &PredicateConstraint,
) -> PrimaryKeyRangeConstraint {
    match (kind, constraint) {
        (ColumnKind::Utf8, PredicateConstraint::StringEq(value)) => {
            match encode_string_variable(value) {
                Ok(encoded) => primary_key_point(CellValue::Utf8(value.clone()), encoded.len()),
                Err(_) => PrimaryKeyRangeConstraint::Terminal(Vec::new()),
            }
        }
        (ColumnKind::Int64, PredicateConstraint::IntRange { min, max }) => {
            let lower = min.unwrap_or(i64::MIN);
            let upper = max.unwrap_or(i64::MAX);
            if lower > upper {
                PrimaryKeyRangeConstraint::Terminal(Vec::new())
            } else if min.is_some() && min == max {
                primary_key_point(CellValue::Int64(lower), kind.key_width())
            } else {
                PrimaryKeyRangeConstraint::Terminal(vec![PrimaryKeyTerminalRange {
                    lower: CellValue::Int64(lower),
                    upper: CellValue::Int64(upper),
                }])
            }
        }
        (ColumnKind::Int64, PredicateConstraint::IntIn(values)) if !values.is_empty() => {
            PrimaryKeyRangeConstraint::Terminal(
                values
                    .iter()
                    .map(|&value| PrimaryKeyTerminalRange {
                        lower: CellValue::Int64(value),
                        upper: CellValue::Int64(value),
                    })
                    .collect(),
            )
        }
        (ColumnKind::UInt64, PredicateConstraint::UInt64Range { min, max }) => {
            let lower = min.unwrap_or(0);
            let upper = max.unwrap_or(u64::MAX);
            if lower > upper {
                PrimaryKeyRangeConstraint::Terminal(Vec::new())
            } else if min.is_some() && min == max {
                primary_key_point(CellValue::UInt64(lower), kind.key_width())
            } else {
                PrimaryKeyRangeConstraint::Terminal(vec![PrimaryKeyTerminalRange {
                    lower: CellValue::UInt64(lower),
                    upper: CellValue::UInt64(upper),
                }])
            }
        }
        (ColumnKind::UInt64, PredicateConstraint::UInt64In(values)) if !values.is_empty() => {
            PrimaryKeyRangeConstraint::Terminal(
                values
                    .iter()
                    .map(|&value| PrimaryKeyTerminalRange {
                        lower: CellValue::UInt64(value),
                        upper: CellValue::UInt64(value),
                    })
                    .collect(),
            )
        }
        (ColumnKind::FixedSizeBinary(expected), PredicateConstraint::FixedSizeBinaryEq(value))
            if value.len() == expected =>
        {
            primary_key_point(CellValue::FixedSizeBinary(value.clone()), expected)
        }
        (ColumnKind::Utf8, PredicateConstraint::StringIn(values)) => {
            PrimaryKeyRangeConstraint::Terminal(
                values
                    .iter()
                    .map(|v| PrimaryKeyTerminalRange {
                        lower: CellValue::Utf8(v.clone()),
                        upper: CellValue::Utf8(v.clone()),
                    })
                    .collect(),
            )
        }
        (ColumnKind::FixedSizeBinary(_), PredicateConstraint::FixedSizeBinaryIn(values)) => {
            PrimaryKeyRangeConstraint::Terminal(
                values
                    .iter()
                    .map(|v| PrimaryKeyTerminalRange {
                        lower: CellValue::FixedSizeBinary(v.clone()),
                        upper: CellValue::FixedSizeBinary(v.clone()),
                    })
                    .collect(),
            )
        }
        _ => PrimaryKeyRangeConstraint::NotEnforced,
    }
}

fn primary_key_value_encoded_width(value: &CellValue, kind: ColumnKind) -> Option<usize> {
    encode_cell_into_ordered_key_bytes(value, kind)
        .ok()
        .map(|encoded| encoded.len())
}

fn primary_key_prefix_width_fits(
    max_payload_len: usize,
    prefix_encoded_width: usize,
    value_encoded_width: usize,
) -> bool {
    prefix_encoded_width
        .checked_add(value_encoded_width)
        .is_some_and(|width| width <= max_payload_len)
}

pub(crate) fn primary_key_range_constraint_for_prefix(
    max_payload_len: usize,
    prefix_encoded_width: usize,
    kind: ColumnKind,
    constraint: &PredicateConstraint,
) -> PrimaryKeyRangeConstraint {
    match primary_key_range_constraint(kind, constraint) {
        PrimaryKeyRangeConstraint::Point(point) => {
            if primary_key_prefix_width_fits(
                max_payload_len,
                prefix_encoded_width,
                point.encoded_width,
            ) {
                PrimaryKeyRangeConstraint::Point(point)
            } else {
                PrimaryKeyRangeConstraint::Terminal(Vec::new())
            }
        }
        PrimaryKeyRangeConstraint::Terminal(spans) => {
            let fitting_spans = spans
                .into_iter()
                .filter(|span| {
                    let Some(lower_width) = primary_key_value_encoded_width(&span.lower, kind)
                    else {
                        return false;
                    };
                    let Some(upper_width) = primary_key_value_encoded_width(&span.upper, kind)
                    else {
                        return false;
                    };
                    primary_key_prefix_width_fits(
                        max_payload_len,
                        prefix_encoded_width,
                        lower_width,
                    ) && primary_key_prefix_width_fits(
                        max_payload_len,
                        prefix_encoded_width,
                        upper_width,
                    )
                })
                .collect();
            PrimaryKeyRangeConstraint::Terminal(fitting_spans)
        }
        PrimaryKeyRangeConstraint::NotEnforced => PrimaryKeyRangeConstraint::NotEnforced,
    }
}

/// Conjunction of supported column constraints extracted from SQL filters.
#[derive(Debug, Clone, Default)]
pub(crate) struct QueryPredicate {
    /// Merged conditions indexed by table column. Missing columns are unconstrained.
    pub(crate) constraints: HashMap<usize, PredicateConstraint>,
    /// A detected contradiction makes the whole predicate match no rows.
    pub(crate) contradiction: bool,
}

impl QueryPredicate {
    pub(crate) fn from_filters(filters: &[Expr], model: &TableModel) -> Self {
        let mut out = Self::default();
        for expr in filters.iter().flat_map(iter_conjunction) {
            if Self::supports_filter(expr, model) {
                out.apply_expr(expr, model);
            }
            if out.contradiction {
                break;
            }
        }
        out
    }

    pub(crate) fn in_list_literal_supported(kind: ColumnKind, literal: &ScalarValue) -> bool {
        if literal.is_null() {
            return true;
        }
        match kind {
            ColumnKind::Utf8 => scalar_to_string(literal).is_some(),
            ColumnKind::Int64 => scalar_to_i64(literal).is_some(),
            ColumnKind::UInt64 => scalar_to_u64(literal).is_some(),
            ColumnKind::FixedSizeBinary(_) => scalar_to_fixed_size_binary(literal).is_some(),
            _ => false,
        }
    }

    pub(crate) fn in_list_expr_supported(kind: ColumnKind, expr: &Expr) -> bool {
        expr.as_literal()
            .is_some_and(|literal| Self::in_list_literal_supported(kind, literal))
    }

    pub(crate) fn supports_filter(expr: &Expr, model: &TableModel) -> bool {
        if parse_boolean_column_predicate(expr, model).is_some() {
            return true;
        }
        match expr {
            Expr::BinaryExpr(binary) if binary.op == Operator::And => {
                Self::supports_filter(binary.left.as_ref(), model)
                    && Self::supports_filter(binary.right.as_ref(), model)
            }
            Expr::IsNull(inner) | Expr::IsNotNull(inner) => inner
                .try_as_col()
                .and_then(|column| model.columns_by_name.get(&column.name))
                .is_some(),
            Expr::InList(in_list) if !in_list.negated => {
                let Some(column) = in_list.expr.try_as_col() else {
                    return false;
                };
                let Some(&col_idx) = model.columns_by_name.get(&column.name) else {
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
                let Some(col_idx) = model.columns_by_name.get(column).copied() else {
                    return false;
                };
                if literal.is_null() {
                    return true;
                }
                let data_type = model.schema.field(col_idx).data_type();
                if literal.data_type() != *data_type
                    && model.columns[col_idx].kind != ColumnKind::Utf8
                {
                    return false;
                }
                let range_ops = matches!(
                    op,
                    Operator::Eq | Operator::Lt | Operator::LtEq | Operator::Gt | Operator::GtEq
                );
                match model.columns[col_idx].kind {
                    ColumnKind::Utf8 => op == Operator::Eq && scalar_to_string(literal).is_some(),
                    ColumnKind::Boolean => op == Operator::Eq && scalar_to_bool(literal).is_some(),
                    kind @ (ColumnKind::Int64
                    | ColumnKind::Date32
                    | ColumnKind::Date64
                    | ColumnKind::Timestamp) => {
                        scalar_to_int_like(kind, literal).is_some() && range_ops
                    }
                    ColumnKind::Float64 => scalar_to_f64(literal).is_some() && range_ops,
                    ColumnKind::Decimal128 => scalar_to_i128(literal).is_some() && range_ops,
                    ColumnKind::UInt64 => scalar_to_u64(literal).is_some() && range_ops,
                    ColumnKind::FixedSizeBinary(_) => {
                        op == Operator::Eq && scalar_to_fixed_size_binary(literal).is_some()
                    }
                    ColumnKind::Decimal256 => scalar_to_i256(literal).is_some() && range_ops,
                    ColumnKind::Binary | ColumnKind::List(_) => false,
                }
            }
        }
    }

    pub(crate) fn apply_expr(&mut self, expr: &Expr, model: &TableModel) {
        if let Some((column, value)) = parse_boolean_column_predicate(expr, model) {
            self.apply_comparison(
                column,
                Operator::Eq,
                &ScalarValue::Boolean(Some(value)),
                model,
            );
            return;
        }
        match expr {
            Expr::IsNull(inner) => {
                if let Some(column) = inner.try_as_col() {
                    if let Some(&col_idx) = model.columns_by_name.get(&column.name) {
                        if !model.column(col_idx).nullable {
                            self.contradiction = true;
                        } else {
                            match self.constraints.get(&col_idx) {
                                Some(PredicateConstraint::IsNotNull) => self.contradiction = true,
                                Some(PredicateConstraint::IsNull) => {}
                                None => {
                                    self.constraints
                                        .insert(col_idx, PredicateConstraint::IsNull);
                                }
                                // Any value-class constraint (StringEq, IntRange, …)
                                // asserts a non-null value, so IS NULL contradicts it.
                                Some(_) => self.contradiction = true,
                            }
                        }
                    }
                }
            }
            Expr::IsNotNull(inner) => {
                if let Some(column) = inner.try_as_col() {
                    if let Some(&col_idx) = model.columns_by_name.get(&column.name) {
                        if model.column(col_idx).nullable {
                            match self.constraints.get(&col_idx) {
                                Some(PredicateConstraint::IsNull) => self.contradiction = true,
                                None => {
                                    self.constraints
                                        .insert(col_idx, PredicateConstraint::IsNotNull);
                                }
                                // Existing value-class constraint already implies
                                // IS NOT NULL; keep the stronger constraint.
                                _ => {}
                            }
                        }
                        // Non-nullable columns: IS NOT NULL is a tautology, drop it.
                    }
                }
            }
            Expr::InList(in_list) if !in_list.negated => {
                if let Some(column) = in_list.expr.try_as_col() {
                    self.apply_in_list(
                        &column.name,
                        in_list.list.iter().filter_map(Expr::as_literal),
                        model,
                    );
                }
            }
            Expr::BinaryExpr(binary) if binary.op == Operator::Or => {
                if let Some((col_name, values)) = extract_or_in_column(expr, model) {
                    self.apply_in_list(&col_name, values.iter(), model);
                }
            }
            _ => {
                let Some((column, op, literal)) = parse_simple_comparison(expr) else {
                    return;
                };
                self.apply_comparison(column, op, literal, model);
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
        if literal.is_null() {
            // `col <op> NULL` is always NULL: no row can satisfy it.
            self.contradiction = true;
            return;
        }
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
                    Some(PredicateConstraint::StringIn(existing)) => {
                        if existing.contains(&value) {
                            self.constraints
                                .insert(col_idx, PredicateConstraint::StringEq(value));
                        } else {
                            self.contradiction = true;
                        }
                    }
                    Some(PredicateConstraint::StringEq(_))
                    | Some(PredicateConstraint::IsNotNull)
                    | None => {
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
                    Some(PredicateConstraint::BoolEq(_))
                    | Some(PredicateConstraint::IsNotNull)
                    | None => {
                        self.constraints
                            .insert(col_idx, PredicateConstraint::BoolEq(value));
                    }
                    Some(_) => {
                        self.contradiction = true;
                    }
                }
            }
            kind @ (ColumnKind::Int64
            | ColumnKind::Date32
            | ColumnKind::Date64
            | ColumnKind::Timestamp) => {
                let Some(value) = scalar_to_int_like(kind, literal) else {
                    self.contradiction = true;
                    return;
                };
                let (mut min, mut max) = match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::IntRange { min, max }) => (*min, *max),
                    Some(PredicateConstraint::IntIn(existing)) if kind == ColumnKind::Int64 => {
                        let filtered = existing
                            .iter()
                            .copied()
                            .filter(|v| ord_satisfies_op(*v, op, value))
                            .collect();
                        self.set_values_constraint(
                            col_idx,
                            filtered,
                            |value| PredicateConstraint::IntRange {
                                min: Some(value),
                                max: Some(value),
                            },
                            PredicateConstraint::IntIn,
                        );
                        return;
                    }
                    Some(PredicateConstraint::IsNotNull) | None => (None, None),
                    Some(_) => {
                        self.contradiction = true;
                        return;
                    }
                };
                apply_integral_constraint(&mut min, &mut max, op, value, &mut self.contradiction);
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
                    Some(PredicateConstraint::IsNotNull) | None => (None, None),
                    Some(_) => {
                        self.contradiction = true;
                        return;
                    }
                };
                apply_float_constraint(&mut lo, &mut hi, op, value, &mut self.contradiction);
                self.constraints.insert(
                    col_idx,
                    PredicateConstraint::FloatRange { min: lo, max: hi },
                );
            }
            ColumnKind::Decimal128 => {
                let Some(value) = scalar_to_i128(literal) else {
                    self.contradiction = true;
                    return;
                };
                let (mut min, mut max) = match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::Decimal128Range { min, max }) => (*min, *max),
                    Some(PredicateConstraint::IsNotNull) | None => (None, None),
                    Some(_) => {
                        self.contradiction = true;
                        return;
                    }
                };
                apply_integral_constraint(&mut min, &mut max, op, value, &mut self.contradiction);
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
                    Some(PredicateConstraint::UInt64In(existing)) => {
                        let filtered = existing
                            .iter()
                            .copied()
                            .filter(|v| ord_satisfies_op(*v, op, value))
                            .collect();
                        self.set_values_constraint(
                            col_idx,
                            filtered,
                            |value| PredicateConstraint::UInt64Range {
                                min: Some(value),
                                max: Some(value),
                            },
                            PredicateConstraint::UInt64In,
                        );
                        return;
                    }
                    Some(PredicateConstraint::IsNotNull) | None => (None, None),
                    Some(_) => {
                        self.contradiction = true;
                        return;
                    }
                };
                apply_integral_constraint(&mut min, &mut max, op, value, &mut self.contradiction);
                self.constraints
                    .insert(col_idx, PredicateConstraint::UInt64Range { min, max });
            }
            ColumnKind::FixedSizeBinary(_) => {
                if op != Operator::Eq {
                    return;
                }
                let Some(value) = scalar_to_fixed_size_binary(literal) else {
                    self.contradiction = true;
                    return;
                };
                match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::FixedSizeBinaryEq(existing))
                        if *existing != value =>
                    {
                        self.contradiction = true;
                    }
                    Some(PredicateConstraint::FixedSizeBinaryIn(existing)) => {
                        if existing.contains(&value) {
                            self.constraints
                                .insert(col_idx, PredicateConstraint::FixedSizeBinaryEq(value));
                        } else {
                            self.contradiction = true;
                        }
                    }
                    Some(PredicateConstraint::FixedSizeBinaryEq(_))
                    | Some(PredicateConstraint::IsNotNull)
                    | None => {
                        self.constraints
                            .insert(col_idx, PredicateConstraint::FixedSizeBinaryEq(value));
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
                    Some(PredicateConstraint::IsNotNull) | None => (None, None),
                    Some(_) => {
                        self.contradiction = true;
                        return;
                    }
                };
                apply_integral_constraint(&mut min, &mut max, op, value, &mut self.contradiction);
                self.constraints
                    .insert(col_idx, PredicateConstraint::Decimal256Range { min, max });
            }
            ColumnKind::Binary | ColumnKind::List(_) => {}
        }
    }

    fn apply_in_list<'a>(
        &mut self,
        column: &str,
        list: impl Iterator<Item = &'a ScalarValue> + Clone,
        model: &TableModel,
    ) {
        let Some(&col_idx) = model.columns_by_name.get(column) else {
            return;
        };

        // Empty membership sets and sets containing only NULL match no rows.
        if list.clone().all(ScalarValue::is_null) {
            self.contradiction = true;
            return;
        }
        match model.columns[col_idx].kind {
            ColumnKind::Utf8 => {
                let values: Vec<_> = list.filter_map(scalar_to_string).collect();
                let values = match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::StringEq(existing)) => {
                        if !values.contains(existing) {
                            self.contradiction = true;
                        }
                        return;
                    }
                    Some(PredicateConstraint::StringIn(existing)) => existing
                        .iter()
                        .filter(|v| values.contains(v))
                        .cloned()
                        .collect(),
                    Some(PredicateConstraint::IsNotNull) | None => values,
                    _ => {
                        self.contradiction = true;
                        return;
                    }
                };
                self.set_values_constraint(
                    col_idx,
                    values,
                    PredicateConstraint::StringEq,
                    PredicateConstraint::StringIn,
                );
            }
            ColumnKind::Int64 => {
                let values: Vec<_> = list.filter_map(scalar_to_i64).collect();
                let values = match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::IntRange { min, max }) => values
                        .into_iter()
                        .filter(|v| in_bounds(*v, *min, *max))
                        .collect(),
                    Some(PredicateConstraint::IntIn(existing)) => existing
                        .iter()
                        .filter(|v| values.contains(v))
                        .copied()
                        .collect(),
                    Some(PredicateConstraint::IsNotNull) | None => values,
                    _ => {
                        self.contradiction = true;
                        return;
                    }
                };
                self.set_values_constraint(
                    col_idx,
                    values,
                    |value| PredicateConstraint::IntRange {
                        min: Some(value),
                        max: Some(value),
                    },
                    PredicateConstraint::IntIn,
                );
            }
            ColumnKind::UInt64 => {
                let values: Vec<_> = list.filter_map(scalar_to_u64).collect();
                let values = match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::UInt64Range { min, max }) => values
                        .into_iter()
                        .filter(|v| in_bounds(*v, *min, *max))
                        .collect(),
                    Some(PredicateConstraint::UInt64In(existing)) => existing
                        .iter()
                        .filter(|v| values.contains(v))
                        .copied()
                        .collect(),
                    Some(PredicateConstraint::IsNotNull) | None => values,
                    _ => {
                        self.contradiction = true;
                        return;
                    }
                };
                self.set_values_constraint(
                    col_idx,
                    values,
                    |value| PredicateConstraint::UInt64Range {
                        min: Some(value),
                        max: Some(value),
                    },
                    PredicateConstraint::UInt64In,
                );
            }
            ColumnKind::FixedSizeBinary(_) => {
                let values: Vec<_> = list.filter_map(scalar_to_fixed_size_binary).collect();
                let values = match self.constraints.get(&col_idx) {
                    Some(PredicateConstraint::FixedSizeBinaryEq(existing)) => {
                        if !values.contains(existing) {
                            self.contradiction = true;
                        }
                        return;
                    }
                    Some(PredicateConstraint::FixedSizeBinaryIn(existing)) => existing
                        .iter()
                        .filter(|v| values.contains(v))
                        .cloned()
                        .collect(),
                    Some(PredicateConstraint::IsNotNull) | None => values,
                    _ => {
                        self.contradiction = true;
                        return;
                    }
                };
                self.set_values_constraint(
                    col_idx,
                    values,
                    PredicateConstraint::FixedSizeBinaryEq,
                    PredicateConstraint::FixedSizeBinaryIn,
                );
            }
            _ => {}
        }
    }

    /// Stores the values sorted and deduplicated. A single value becomes a point constraint,
    /// and an empty set marks a contradiction.
    fn set_values_constraint<T: Ord>(
        &mut self,
        col_idx: usize,
        mut values: Vec<T>,
        point: impl FnOnce(T) -> PredicateConstraint,
        set: impl FnOnce(Vec<T>) -> PredicateConstraint,
    ) {
        values.sort_unstable();
        values.dedup();
        let constraint = match values.len() {
            0 => {
                self.contradiction = true;
                return;
            }
            1 => point(values.pop().unwrap()),
            _ => set(values),
        };
        self.constraints.insert(col_idx, constraint);
    }

    pub(crate) fn choose_index_plan(
        &self,
        model: &TableModel,
        specs: &[ResolvedIndexSpec],
        access_plan: &ScanAccessPlan,
    ) -> Option<IndexPlan> {
        // Skip index selection when no rows can match or primary-key point reads suffice.
        if self.contradiction || self.has_primary_key_points(model) {
            return None;
        }

        // Try each index independently so an unusable range expansion leaves other
        // indexes and primary-key access available.
        let mut best: Option<IndexPlan> = None;
        for (spec_idx, spec) in specs.iter().enumerate() {
            let (ranges, constrained_prefix_len, constrained_column_count) = match spec.layout {
                IndexLayout::Lexicographic => {
                    // Lexicographic bounds require constraints on a leading key prefix.
                    let constrained_prefix_len = self.leading_constrained_prefix(model, spec);
                    if constrained_prefix_len == 0 {
                        continue;
                    }
                    let ranges = match self.expand_index_ranges(model, spec, constrained_prefix_len)
                    {
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
                    // Z-order bounds can use constrained dimensions anywhere in the key.
                    let constrained_column_count =
                        self.zorder_constrained_column_count(model, spec);
                    if constrained_column_count == 0 {
                        continue;
                    }
                    let ranges = match self.expand_zorder_index_ranges(model, spec) {
                        Ok(r) if !r.is_empty() => r,
                        _ => continue,
                    };
                    (ranges, constrained_column_count, constrained_column_count)
                }
            };

            // Keep ranges disjoint so overlapping bounds do not return the same row twice.
            let mut ranges = ranges;
            ranges.sort_by(|left, right| left.start.cmp(&right.start));
            let mut disjoint: Vec<KeyRange> = Vec::with_capacity(ranges.len());
            for range in ranges {
                match disjoint.last_mut() {
                    Some(last) if range.start <= last.end => {
                        if range.end > last.end {
                            last.end = range.end;
                        }
                    }
                    _ => disjoint.push(range),
                }
            }

            // Prefer more constrained columns, then coverage of the required non-primary-key
            // columns, lexicographic layout, and fewer ranges. Equal ranks keep the earlier index.
            let candidate = IndexPlan {
                spec_idx,
                ranges: disjoint,
                constrained_prefix_len,
                constrained_column_count,
            };
            let rank = |plan: &IndexPlan| {
                (
                    plan.constrained_column_count,
                    access_plan.index_covers_required_non_pk(&specs[plan.spec_idx]),
                    specs[plan.spec_idx].layout == IndexLayout::Lexicographic,
                    std::cmp::Reverse(plan.ranges.len()),
                )
            };
            if best
                .as_ref()
                .is_none_or(|previous| rank(&candidate) > rank(previous))
            {
                best = Some(candidate);
            }
        }
        best
    }

    pub(crate) fn expand_index_ranges(
        &self,
        model: &TableModel,
        spec: &ResolvedIndexSpec,
        constrained_prefix_len: usize,
    ) -> Result<Vec<KeyRange>, String> {
        let columns = spec
            .key_columns
            .iter()
            .take(constrained_prefix_len)
            .map_while(|&col_idx| {
                self.constraints
                    .get(&col_idx)
                    .map(|constraint| (col_idx, constraint))
            });
        self.expand_index_range_product(columns, |predicate, prefix_len, upper| {
            predicate.encode_index_bound_key(model, spec, prefix_len, upper)
        })
    }

    /// Encodes key ranges from combinations of membership values on `columns`, omitting
    /// inverted bounds. More than 4096 combinations is an error.
    fn expand_index_range_product<'a>(
        &self,
        columns: impl Iterator<Item = (usize, &'a PredicateConstraint)>,
        encode_bound: impl Fn(&Self, usize, bool) -> Result<Key, String>,
    ) -> Result<Vec<KeyRange>, String> {
        // Build the cross product one column at a time and stop before it exceeds the range
        // budget. Constraints other than membership lists contribute a single choice.
        let mut combos: Vec<HashMap<usize, PredicateConstraint>> = vec![HashMap::new()];
        let mut column_count = 0;
        for (col_idx, constraint) in columns {
            column_count += 1;
            let singles = match constraint {
                PredicateConstraint::StringIn(vals) => vals
                    .iter()
                    .map(|v| PredicateConstraint::StringEq(v.clone()))
                    .collect::<Vec<_>>(),
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
                PredicateConstraint::FixedSizeBinaryIn(vals) => vals
                    .iter()
                    .map(|v| PredicateConstraint::FixedSizeBinaryEq(v.clone()))
                    .collect(),
                other => vec![other.clone()],
            };
            if combos.len().saturating_mul(singles.len()) > 4096 {
                return Err("index range budget exceeded".into());
            }
            let mut next = Vec::with_capacity(combos.len() * singles.len());
            for combo in &combos {
                for single in &singles {
                    let mut overlay = combo.clone();
                    overlay.insert(col_idx, single.clone());
                    next.push(overlay);
                }
            }
            combos = next;
        }

        // Overlay each combination on the whole predicate to retain primary-key suffix constraints.
        // Every combination sets the same columns, so each overlay fully replaces the previous one
        // and one copy of the predicate serves them all. Inverted bounds match no keys and are
        // dropped.
        let mut predicate = self.clone();
        let mut ranges = Vec::with_capacity(combos.len());
        for combo in combos {
            predicate.constraints.extend(combo);
            let start = encode_bound(&predicate, column_count, false)?;
            let end = encode_bound(&predicate, column_count, true)?;
            if start <= end {
                ranges.push(KeyRange { start, end });
            }
        }
        Ok(ranges)
    }

    pub(crate) fn leading_constrained_prefix(
        &self,
        model: &TableModel,
        spec: &ResolvedIndexSpec,
    ) -> usize {
        let mut count = 0usize;
        for col_idx in &spec.key_columns {
            let Some(constraint) = self.constraints.get(col_idx) else {
                break;
            };
            let constrained =
                Self::constraint_bounds_index_key(model.column(*col_idx).kind, constraint);
            if !constrained {
                break;
            }
            count += 1;
        }
        count
    }

    pub(crate) fn lexicographic_candidate_score(
        &self,
        model: &TableModel,
        spec: &ResolvedIndexSpec,
    ) -> usize {
        let mut count = 0usize;
        for col_idx in &spec.key_columns {
            let Some(constraint) = self.constraints.get(col_idx) else {
                break;
            };
            if !Self::constraint_bounds_index_key(model.column(*col_idx).kind, constraint) {
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
                    Self::constraint_bounds_index_key(model.column(**col_idx).kind, constraint)
                })
            })
            .count()
    }

    pub(crate) fn constraint_is_point(kind: ColumnKind, constraint: &PredicateConstraint) -> bool {
        match (kind, constraint) {
            (ColumnKind::Utf8, PredicateConstraint::StringEq(_))
            | (ColumnKind::Utf8, PredicateConstraint::StringIn(_))
            | (ColumnKind::Boolean, PredicateConstraint::BoolEq(_))
            | (ColumnKind::FixedSizeBinary(_), PredicateConstraint::FixedSizeBinaryEq(_))
            | (ColumnKind::FixedSizeBinary(_), PredicateConstraint::FixedSizeBinaryIn(_))
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
                matches!((min, max), (Some((lhs, true)), Some((rhs, true))) if lhs.total_cmp(rhs).is_eq())
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

    pub(crate) const fn constraint_bounds_index_key(
        kind: ColumnKind,
        constraint: &PredicateConstraint,
    ) -> bool {
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
                    PredicateConstraint::FixedSizeBinaryEq(_)
                )
                | (
                    ColumnKind::FixedSizeBinary(_),
                    PredicateConstraint::FixedSizeBinaryIn(_)
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
        model: &TableModel,
        spec: &ResolvedIndexSpec,
    ) -> Result<Vec<KeyRange>, String> {
        let columns = spec.key_columns.iter().filter_map(|&col_idx| {
            let constraint = self.constraints.get(&col_idx)?;
            Self::constraint_bounds_index_key(model.column(col_idx).kind, constraint)
                .then_some((col_idx, constraint))
        });
        self.expand_index_range_product(columns, |predicate, _, upper| {
            predicate.encode_zorder_index_bound_key(model, spec, upper)
        })
    }

    pub(crate) fn encode_index_bound_key(
        &self,
        model: &TableModel,
        spec: &ResolvedIndexSpec,
        constrained_prefix_len: usize,
        upper: bool,
    ) -> Result<Key, String> {
        let prefix = &spec.prefix;
        // Bounds are appended field by field, mirroring how
        // encode_secondary_index_key_with_pk lays rows out; prefix.encode
        // enforces the only real limit (MAX_KEY_LEN) at the end. Pre-sizing
        // from schema width estimates breaks on Utf8 fields, whose constraint
        // encodings are wider or narrower than the estimate: wider overflowed
        // the slot, and narrower left zero padding that sorted the lower bound
        // above rows sitting exactly on it.
        let mut key = Vec::with_capacity(prefix.max_payload_len());
        let unconstrained = Self::default();
        for (idx, col_idx) in spec.key_columns.iter().copied().enumerate() {
            let predicate = if idx < constrained_prefix_len {
                self
            } else {
                &unconstrained
            };
            key.extend_from_slice(&predicate.ordered_index_bound_bytes_for_column(
                col_idx,
                model.column(col_idx),
                upper,
            )?);
        }
        self.finish_index_bound_key(model, prefix, key, upper)
    }

    pub(crate) fn encode_zorder_index_bound_key(
        &self,
        model: &TableModel,
        spec: &ResolvedIndexSpec,
        upper: bool,
    ) -> Result<Key, String> {
        let prefix = &spec.prefix;
        // Bounds are appended field by field, mirroring how
        // encode_secondary_index_key_with_pk lays rows out; prefix.encode
        // enforces the only real limit (MAX_KEY_LEN) at the end. Pre-sizing
        // from schema width estimates breaks on Utf8 fields, whose constraint
        // encodings are wider or narrower than the estimate: wider overflowed
        // the slot, and narrower left zero padding that sorted the lower bound
        // above rows sitting exactly on it.
        let mut key = Vec::with_capacity(prefix.max_payload_len());
        let mut encoded_fields = Vec::with_capacity(spec.key_columns.len());
        for &col_idx in &spec.key_columns {
            let col = model.column(col_idx);
            let bytes = self.ordered_index_bound_bytes_for_column(col_idx, col, upper)?;
            encoded_fields.push(bytes);
        }
        let interleaved = interleave_ordered_key_fields(&encoded_fields);
        key.extend_from_slice(&interleaved);
        debug_assert_eq!(key.len(), spec.key_columns_width);
        self.finish_index_bound_key(model, prefix, key, upper)
    }

    /// Append the primary-key suffix bounds to a partially built index-bound
    /// payload, pad an upper bound to full capacity with 0xFF, and encode the
    /// finished key. Shared by the lexicographic and z-order bound encoders so
    /// the pk-suffix layout cannot drift between them.
    fn finish_index_bound_key(
        &self,
        model: &TableModel,
        prefix: &Prefix,
        mut key: Vec<u8>,
        upper: bool,
    ) -> Result<Key, String> {
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
                    key.extend_from_slice(&encode_i64_ordered(pk_bound));
                }
                ColumnKind::UInt64 => {
                    let (lower, upper_bound) = self.uint64_bounds(pk_idx);
                    let pk_bound = if upper { upper_bound } else { lower };
                    key.extend_from_slice(&pk_bound.to_be_bytes());
                }
                // A Utf8 primary key is variable width: its floor is a bare
                // terminator (a zero-filled width-estimate slot would sort
                // above a row whose key string is empty), and a single 0xFF
                // byte tops every escaped string encoding.
                ColumnKind::Utf8 => key.push(if upper { 0xFF } else { STRING_KEY_TERMINATOR }),
                _ => {
                    let w = pk_kind.key_width();
                    key.resize(key.len() + w, if upper { 0xFF } else { 0x00 });
                }
            }
        }
        if upper && key.len() < prefix.max_payload_len() {
            key.resize(prefix.max_payload_len(), 0xFF);
        }
        prefix
            .encode(&key)
            .map_err(|e| format!("failed to encode index bound key: {e}"))
    }

    pub(crate) fn ordered_index_bound_bytes_for_column(
        &self,
        col_idx: usize,
        col: &ResolvedColumn,
        upper: bool,
    ) -> Result<Vec<u8>, String> {
        let constraint = self.constraints.get(&col_idx);
        Ok(match col.kind {
            ColumnKind::Utf8 => {
                if let Some(constraint) = constraint {
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
                constraint
                    .and_then(|constraint| match constraint {
                        PredicateConstraint::BoolEq(v) => Some(*v),
                        _ => None,
                    })
                    .unwrap_or(upper),
            )],
            ColumnKind::Int64 | ColumnKind::Date64 | ColumnKind::Timestamp => {
                let (min, max) = match constraint {
                    Some(PredicateConstraint::IntRange { min, max }) => (*min, *max),
                    None => (None, None),
                    _ => {
                        let label = if col.kind == ColumnKind::Int64 {
                            "int"
                        } else {
                            "int-like"
                        };
                        return Err(format!("missing {label} constraint for '{}'", col.name));
                    }
                };
                let value = if upper {
                    max.unwrap_or(i64::MAX)
                } else {
                    min.unwrap_or(i64::MIN)
                };
                encode_i64_ordered(value).to_vec()
            }
            ColumnKind::Float64 => {
                let bound = match constraint {
                    Some(PredicateConstraint::FloatRange { min, max }) => {
                        if upper {
                            *max
                        } else {
                            *min
                        }
                    }
                    _ => None,
                };
                bound
                    .map(|(value, _)| encode_f64_ordered(value).to_vec())
                    .unwrap_or_else(|| vec![if upper { 0xff } else { 0 }; 8])
            }
            ColumnKind::Date32 => {
                let (min, max) = match constraint {
                    Some(PredicateConstraint::IntRange { min, max }) => (*min, *max),
                    None => (None, None),
                    _ => return Err(format!("missing date32 constraint for '{}'", col.name)),
                };
                let value = if upper {
                    max.unwrap_or(i64::from(i32::MAX))
                } else {
                    min.unwrap_or(i64::from(i32::MIN))
                };
                encode_i32_ordered(value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32)
                    .to_vec()
            }
            ColumnKind::Decimal128 => {
                let (min, max) = match constraint {
                    Some(PredicateConstraint::Decimal128Range { min, max }) => (*min, *max),
                    None => (None, None),
                    _ => return Err(format!("missing decimal128 constraint for '{}'", col.name)),
                };
                let value = if upper {
                    max.unwrap_or(i128::MAX)
                } else {
                    min.unwrap_or(i128::MIN)
                };
                encode_i128_ordered(value).to_vec()
            }
            ColumnKind::UInt64 => {
                let (min, max) = match constraint {
                    Some(PredicateConstraint::UInt64Range { min, max }) => (*min, *max),
                    None => (None, None),
                    _ => return Err(format!("missing uint64 constraint for '{}'", col.name)),
                };
                let value = if upper {
                    max.unwrap_or(u64::MAX)
                } else {
                    min.unwrap_or(0)
                };
                value.to_be_bytes().to_vec()
            }
            ColumnKind::Decimal256 => {
                let (min, max) = match constraint {
                    Some(PredicateConstraint::Decimal256Range { min, max }) => (*min, *max),
                    None => (None, None),
                    _ => return Err(format!("missing decimal256 constraint for '{}'", col.name)),
                };
                let value = if upper {
                    max.unwrap_or(i256::MAX)
                } else {
                    min.unwrap_or(i256::MIN)
                };
                encode_i256_ordered(value).to_vec()
            }
            ColumnKind::FixedSizeBinary(n) => {
                let mut bytes = vec![0u8; n];
                if let Some(constraint) = constraint {
                    let PredicateConstraint::FixedSizeBinaryEq(data) = constraint else {
                        return Err(format!(
                            "missing fixed-size-binary constraint for '{}'",
                            col.name
                        ));
                    };
                    if data.len() > n {
                        return Err(format!(
                            "fixed-size-binary constraint for '{}' exceeds width {}",
                            col.name, n
                        ));
                    }
                    bytes[..data.len()].copy_from_slice(data);
                } else if upper {
                    bytes.fill(0xFF);
                }
                bytes
            }
            ColumnKind::Binary | ColumnKind::List(_) => {
                unreachable!("binary and list columns cannot be indexed")
            }
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

    fn has_primary_key_points(&self, model: &TableModel) -> bool {
        let mut count = 1usize;
        for (&column, &kind) in model
            .primary_key_indices
            .iter()
            .zip(&model.primary_key_kinds)
        {
            let Some(constraint) = self.constraints.get(&column) else {
                return false;
            };
            if !Self::constraint_is_point(kind, constraint) {
                return false;
            }
            let values = match constraint {
                PredicateConstraint::StringIn(v) => v.len(),
                PredicateConstraint::IntIn(v) => v.len(),
                PredicateConstraint::UInt64In(v) => v.len(),
                PredicateConstraint::FixedSizeBinaryIn(v) => v.len(),
                _ => 1,
            };
            count = count.saturating_mul(values);
            if count > 4096 {
                return false;
            }
        }
        true
    }

    pub(crate) fn primary_key_points(
        &self,
        model: &TableModel,
    ) -> DataFusionResult<Option<Vec<Key>>> {
        if !self.has_primary_key_points(model) {
            return Ok(None);
        }
        let mut keys = vec![Vec::new()];
        for (&column, &kind) in model
            .primary_key_indices
            .iter()
            .zip(&model.primary_key_kinds)
        {
            let Some(constraint) = self.constraints.get(&column) else {
                return Ok(None);
            };
            let values = match constraint {
                PredicateConstraint::StringIn(v) => {
                    v.iter().cloned().map(CellValue::Utf8).collect()
                }
                PredicateConstraint::IntIn(v) => v.iter().copied().map(CellValue::Int64).collect(),
                PredicateConstraint::UInt64In(v) => {
                    v.iter().copied().map(CellValue::UInt64).collect()
                }
                PredicateConstraint::FixedSizeBinaryIn(v) => {
                    v.iter().cloned().map(CellValue::FixedSizeBinary).collect()
                }
                _ => match primary_key_range_constraint(kind, constraint) {
                    PrimaryKeyRangeConstraint::Point(point) => vec![point.value],
                    _ => return Ok(None),
                },
            };
            let mut next = Vec::with_capacity(keys.len() * values.len());
            for prefix in &keys {
                for value in &values {
                    let Ok(bytes) = encode_cell_into_ordered_key_bytes(value, kind) else {
                        continue;
                    };
                    if prefix.len() + bytes.len() <= model.primary_key_prefix.max_payload_len() {
                        let mut key = prefix.clone();
                        key.extend_from_slice(&bytes);
                        next.push(key);
                    }
                }
            }
            keys = next;
        }
        let mut keys = keys
            .into_iter()
            .map(|payload| {
                model
                    .primary_key_prefix
                    .encode(&payload)
                    .map_err(|e| DataFusionError::Execution(e.to_string()))
            })
            .collect::<DataFusionResult<Vec<_>>>()?;
        keys.sort();
        keys.dedup();
        Ok(Some(keys))
    }

    pub(crate) fn primary_key_ranges(
        &self,
        model: &TableModel,
        max_logical_key_len: usize,
    ) -> DataFusionResult<Vec<KeyRange>> {
        if self.contradiction {
            return Ok(Vec::new());
        }
        let Some(max_payload_len) =
            max_logical_key_len.checked_sub(model.primary_key_prefix.as_bytes().len())
        else {
            return Ok(Vec::new());
        };

        let mut prefix_values: Vec<CellValue> = Vec::new();
        let mut prefix_encoded_width = 0usize;

        for (&pk_idx, &pk_kind) in model
            .primary_key_indices
            .iter()
            .zip(model.primary_key_kinds.iter())
        {
            let Some(constraint) = self.constraints.get(&pk_idx) else {
                break;
            };
            match primary_key_range_constraint_for_prefix(
                max_payload_len,
                prefix_encoded_width,
                pk_kind,
                constraint,
            ) {
                PrimaryKeyRangeConstraint::Point(point) => {
                    prefix_encoded_width += point.encoded_width;
                    prefix_values.push(point.value);
                }
                PrimaryKeyRangeConstraint::Terminal(spans) => {
                    let mut ranges = Vec::with_capacity(spans.len());
                    for span in spans {
                        let mut lo = prefix_values.clone();
                        lo.push(span.lower);
                        let mut hi = prefix_values.clone();
                        hi.push(span.upper);
                        let lo_refs: Vec<&CellValue> = lo.iter().collect();
                        let hi_refs: Vec<&CellValue> = hi.iter().collect();
                        ranges.push(KeyRange {
                            start: encode_primary_key_bound(
                                model.table_prefix,
                                &lo_refs,
                                model,
                                false,
                            )
                            .map_err(DataFusionError::Execution)?,
                            end: encode_primary_key_bound(
                                model.table_prefix,
                                &hi_refs,
                                model,
                                true,
                            )
                            .map_err(DataFusionError::Execution)?,
                        });
                    }
                    ranges.sort_by(|lhs, rhs| lhs.start.cmp(&rhs.start));
                    return Ok(ranges);
                }
                PrimaryKeyRangeConstraint::NotEnforced => break,
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
        PredicateConstraint::FixedSizeBinaryEq(value) => format!("= 0x{}", hex_preview(value)),
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
        PredicateConstraint::FixedSizeBinaryIn(values) => {
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
        (Some((min, true)), Some((max, true))) if min.total_cmp(&max).is_eq() => {
            format!("= {}", format_float(min))
        }
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

#[cfg(test)]
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
            in_bounds(*v, *min, *max)
        }
        (CellValue::Date32(v), PredicateConstraint::IntRange { min, max }) => {
            in_bounds(*v as i64, *min, *max)
        }
        (CellValue::Date64(v), PredicateConstraint::IntRange { min, max }) => {
            in_bounds(*v, *min, *max)
        }
        (CellValue::Timestamp(v), PredicateConstraint::IntRange { min, max }) => {
            in_bounds(*v, *min, *max)
        }
        (CellValue::Float64(v), PredicateConstraint::FloatRange { .. }) => {
            match crate::filter::compile_encoded_constraint(ColumnKind::Float64, constraint) {
                crate::filter::EncodedConstraintCompile::Encoded(bound) => {
                    crate::filter::matches_encoded_constraint(&encode_f64_ordered(*v), &bound)
                }
                _ => false,
            }
        }
        (CellValue::Decimal128(v), PredicateConstraint::Decimal128Range { min, max }) => {
            in_bounds(*v, *min, *max)
        }
        (CellValue::Utf8(v), PredicateConstraint::StringIn(values)) => {
            values.binary_search(v).is_ok()
        }
        (CellValue::Int64(v), PredicateConstraint::IntIn(values)) => {
            values.binary_search(v).is_ok()
        }
        (CellValue::UInt64(v), PredicateConstraint::UInt64Range { min, max }) => {
            in_bounds(*v, *min, *max)
        }
        (CellValue::UInt64(v), PredicateConstraint::UInt64In(values)) => {
            values.binary_search(v).is_ok()
        }
        (CellValue::FixedSizeBinary(v), PredicateConstraint::FixedSizeBinaryEq(expected)) => {
            v == expected
        }
        (CellValue::FixedSizeBinary(v), PredicateConstraint::FixedSizeBinaryIn(values)) => {
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

pub(crate) fn in_bounds<T: Ord>(value: T, min: Option<T>, max: Option<T>) -> bool {
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

fn ord_satisfies_op<T: Ord>(value: T, op: Operator, literal: T) -> bool {
    match op {
        Operator::Eq => value == literal,
        Operator::Gt => value > literal,
        Operator::GtEq => value >= literal,
        Operator::Lt => value < literal,
        Operator::LtEq => value <= literal,
        _ => true,
    }
}

pub(crate) fn apply_integral_constraint<T: ArrowNativeTypeOp + Ord>(
    min: &mut Option<T>,
    max: &mut Option<T>,
    op: Operator,
    value: T,
    contradiction: &mut bool,
) {
    let (new_min, new_max) = match op {
        Operator::Eq => (Some(value), Some(value)),
        Operator::Gt => (value.add_checked(T::ONE).ok(), None),
        Operator::GtEq => (Some(value), None),
        Operator::Lt => (None, value.sub_checked(T::ONE).ok()),
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
    // DataFusion normalizes signed zero before comparison, while stored keys preserve its bits
    let lower = if value == 0.0 { -0.0 } else { value };
    let upper = if value == 0.0 { 0.0 } else { value };
    match op {
        Operator::Eq => {
            merge_float_lower(lo, lower, true);
            merge_float_upper(hi, upper, true);
        }
        Operator::Gt => merge_float_lower(lo, upper, false),
        Operator::GtEq => merge_float_lower(lo, lower, true),
        Operator::Lt => merge_float_upper(hi, lower, false),
        Operator::LtEq => merge_float_upper(hi, upper, true),
        _ => return,
    }
    if let (Some((lo_v, lo_inc)), Some((hi_v, hi_inc))) = (&*lo, &*hi) {
        if lo_v.total_cmp(hi_v).is_gt() || (lo_v.total_cmp(hi_v).is_eq() && !(*lo_inc && *hi_inc)) {
            *contradiction = true;
        }
    }
}

pub(crate) fn merge_float_lower(current: &mut Option<(f64, bool)>, value: f64, inclusive: bool) {
    *current = Some(match *current {
        Some((existing, existing_inc)) => {
            if value.total_cmp(&existing).is_gt() {
                (value, inclusive)
            } else if value.total_cmp(&existing).is_eq() {
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
            if value.total_cmp(&existing).is_lt() {
                (value, inclusive)
            } else if value.total_cmp(&existing).is_eq() {
                (value, existing_inc && inclusive)
            } else {
                (existing, existing_inc)
            }
        }
        None => (value, inclusive),
    });
}

pub(crate) fn extract_or_in_column(
    expr: &Expr,
    model: &TableModel,
) -> Option<(String, Vec<ScalarValue>)> {
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
                    values.push(literal.clone());
                    true
                }
                None => {
                    *col_name = Some(column.to_owned());
                    values.push(literal.clone());
                    true
                }
            }
        }
    }
}

fn parse_boolean_column_predicate<'a>(
    expr: &'a Expr,
    model: &TableModel,
) -> Option<(&'a str, bool)> {
    let (column, value) = match expr {
        Expr::Column(column) => (column, true),
        Expr::Not(inner) | Expr::IsFalse(inner) => (inner.try_as_col()?, false),
        Expr::IsTrue(inner) => (inner.try_as_col()?, true),
        _ => return None,
    };
    let col_idx = *model.columns_by_name.get(&column.name)?;
    (model.column(col_idx).kind == ColumnKind::Boolean).then_some((&column.name, value))
}

pub(crate) fn parse_simple_comparison(expr: &Expr) -> Option<(&str, Operator, &ScalarValue)> {
    let Expr::BinaryExpr(binary) = expr else {
        return None;
    };
    if !matches!(
        binary.op,
        Operator::Eq | Operator::Lt | Operator::LtEq | Operator::Gt | Operator::GtEq
    ) {
        return None;
    }

    if let (Some(column), Some(literal)) = (binary.left.try_as_col(), binary.right.as_literal()) {
        return Some((&column.name, binary.op, literal));
    }
    if let (Some(literal), Some(column)) = (binary.left.as_literal(), binary.right.try_as_col()) {
        return Some((&column.name, binary.op.swap()?, literal));
    }
    None
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

pub(crate) const fn scalar_to_f64(value: &ScalarValue) -> Option<f64> {
    match value {
        ScalarValue::Float32(Some(v)) => Some(*v as f64),
        ScalarValue::Float64(Some(v)) => Some(*v),
        _ => None,
    }
}

pub(crate) const fn scalar_to_bool(value: &ScalarValue) -> Option<bool> {
    match value {
        ScalarValue::Boolean(Some(v)) => Some(*v),
        _ => None,
    }
}

fn scalar_to_int_like(kind: ColumnKind, value: &ScalarValue) -> Option<i64> {
    match (kind, value) {
        (ColumnKind::Int64, _) => scalar_to_i64(value),
        (ColumnKind::Date32, ScalarValue::Date32(Some(v))) => Some(i64::from(*v)),
        (ColumnKind::Date64, ScalarValue::Date64(Some(v)))
        | (ColumnKind::Timestamp, ScalarValue::TimestampMicrosecond(Some(v), _)) => Some(*v),
        _ => None,
    }
}

pub(crate) const fn scalar_to_i128(value: &ScalarValue) -> Option<i128> {
    match value {
        ScalarValue::Decimal128(Some(v), _, _) => Some(*v),
        _ => None,
    }
}

pub(crate) fn scalar_to_fixed_size_binary(value: &ScalarValue) -> Option<Vec<u8>> {
    match value {
        ScalarValue::FixedSizeBinary(_, Some(v)) => Some(v.clone()),
        ScalarValue::Binary(Some(v)) => Some(v.clone()),
        ScalarValue::LargeBinary(Some(v)) => Some(v.clone()),
        _ => None,
    }
}

pub(crate) const fn scalar_to_i256(value: &ScalarValue) -> Option<i256> {
    match value {
        ScalarValue::Decimal256(Some(v), _, _) => Some(*v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::logical_expr::col;

    #[test]
    fn boolean_column_predicates_require_boolean_columns() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", datafusion::arrow::datatypes::DataType::Int64, false),
                TableColumnConfig::new("b", datafusion::arrow::datatypes::DataType::Boolean, true),
            ],
            vec!["id".into()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        for (expr, expected) in [
            (col("b"), true),
            (Expr::Not(Box::new(col("b"))), false),
            (col("b").is_true(), true),
            (col("b").is_false(), false),
        ] {
            assert!(QueryPredicate::supports_filter(&expr, &model));
            let predicate = QueryPredicate::from_filters(&[expr], &model);
            assert!(
                matches!(predicate.constraints.get(&1), Some(PredicateConstraint::BoolEq(value)) if *value == expected)
            );
            assert!(!matches_constraint(
                &CellValue::Null,
                &predicate.constraints[&1]
            ));
        }
        for expr in [
            col("id"),
            Expr::Not(Box::new(col("id"))),
            col("b").is_not_true(),
            col("b").is_not_false(),
        ] {
            assert!(!QueryPredicate::supports_filter(&expr, &model));
        }
    }

    #[test]
    fn integral_constraints_preserve_extreme_values() {
        fn check<T: ArrowNativeTypeOp + Ord>(lowest: T, highest: T) {
            for (op, value, expected_min, expected_max, empty) in [
                (Operator::Gt, highest, None, None, true),
                (Operator::Lt, lowest, None, None, true),
                (Operator::Eq, lowest, Some(lowest), Some(lowest), false),
                (Operator::Eq, highest, Some(highest), Some(highest), false),
                (Operator::GtEq, highest, Some(highest), None, false),
                (Operator::LtEq, lowest, None, Some(lowest), false),
            ] {
                let (mut min, mut max, mut contradiction) = (None, None, false);
                apply_integral_constraint(&mut min, &mut max, op, value, &mut contradiction);
                assert_eq!(
                    (min, max, contradiction),
                    (expected_min, expected_max, empty)
                );
            }

            let (mut min, mut max, mut contradiction) = (Some(lowest), Some(highest), false);
            apply_integral_constraint(
                &mut min,
                &mut max,
                Operator::GtEq,
                highest,
                &mut contradiction,
            );
            assert_eq!(
                (min, max, contradiction),
                (Some(highest), Some(highest), false)
            );
            apply_integral_constraint(
                &mut min,
                &mut max,
                Operator::LtEq,
                lowest,
                &mut contradiction,
            );
            assert!(contradiction);
        }

        check(i64::MIN, i64::MAX);
        check(u64::MIN, u64::MAX);
        check(i128::MIN, i128::MAX);
        check(i256::MIN, i256::MAX);
    }
}
