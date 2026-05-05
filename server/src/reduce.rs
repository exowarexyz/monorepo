//! Range aggregation over decoded KV rows (same semantics as the public `Reduce` RPC).

use std::cmp::Ordering;
use std::collections::BTreeMap;

use bytes::Bytes;
use exoware_proto::{
    RangeReduceGroup, RangeReduceOp, RangeReduceRequest, RangeReduceResponse, RangeReduceResult,
};
use exoware_sdk as exoware_proto;
use exoware_sdk::keys::Key;
use exoware_sdk::kv_codec::{
    canonicalize_reduced_group_values, decode_stored_row, encode_reduced_group_key, eval_expr,
    eval_predicate, expr_needs_value, predicate_needs_value, KvReducedValue,
};

#[derive(Debug)]
pub enum RangeError {
    Reduce(String),
}

impl std::fmt::Display for RangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RangeError::Reduce(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for RangeError {}

#[derive(Debug)]
enum ReductionState {
    Count(u64),
    Sum(Option<KvReducedValue>),
    Min(Option<KvReducedValue>),
    Max(Option<KvReducedValue>),
}

#[derive(Debug)]
struct GroupedReductionState {
    group_values: Vec<Option<KvReducedValue>>,
    states: Vec<ReductionState>,
}

#[derive(Debug)]
struct ExtractedReductionRow {
    group_values: Vec<Option<KvReducedValue>>,
    reducer_values: Vec<Option<KvReducedValue>>,
}

impl ReductionState {
    fn from_op(op: RangeReduceOp) -> Self {
        match op {
            RangeReduceOp::CountAll | RangeReduceOp::CountField => Self::Count(0),
            RangeReduceOp::SumField => Self::Sum(None),
            RangeReduceOp::MinField => Self::Min(None),
            RangeReduceOp::MaxField => Self::Max(None),
        }
    }

    fn update(
        &mut self,
        op: RangeReduceOp,
        value: Option<KvReducedValue>,
    ) -> Result<(), RangeError> {
        match (self, op) {
            (Self::Count(count), RangeReduceOp::CountAll) => {
                *count = count.saturating_add(1);
                Ok(())
            }
            (Self::Count(count), RangeReduceOp::CountField) => {
                if value.is_some() {
                    *count = count.saturating_add(1);
                }
                Ok(())
            }
            (Self::Sum(sum), RangeReduceOp::SumField) => {
                let Some(value) = value else {
                    return Ok(());
                };
                match sum {
                    Some(existing) => existing
                        .checked_add_assign(&value)
                        .map_err(RangeError::Reduce),
                    None => {
                        *sum = Some(value);
                        Ok(())
                    }
                }
            }
            (Self::Min(current), RangeReduceOp::MinField) => {
                update_extreme(current, value, Ordering::Less)
            }
            (Self::Max(current), RangeReduceOp::MaxField) => {
                update_extreme(current, value, Ordering::Greater)
            }
            _ => Err(RangeError::Reduce(
                "reduction state/op mismatch".to_string(),
            )),
        }
    }

    fn finish(self) -> Option<KvReducedValue> {
        match self {
            Self::Count(count) => Some(KvReducedValue::UInt64(count)),
            Self::Sum(value) | Self::Min(value) | Self::Max(value) => value,
        }
    }
}

impl GroupedReductionState {
    fn new(group_values: Vec<Option<KvReducedValue>>, request: &RangeReduceRequest) -> Self {
        Self {
            group_values,
            states: request
                .reducers
                .iter()
                .map(|reducer| ReductionState::from_op(reducer.op))
                .collect(),
        }
    }

    fn update(
        &mut self,
        request: &RangeReduceRequest,
        reducer_values: Vec<Option<KvReducedValue>>,
    ) -> Result<(), RangeError> {
        for ((state, reducer), value) in self
            .states
            .iter_mut()
            .zip(request.reducers.iter())
            .zip(reducer_values)
        {
            state.update(reducer.op, value)?;
        }
        Ok(())
    }

    fn finish(self) -> RangeReduceGroup {
        RangeReduceGroup {
            group_values: self.group_values,
            results: self
                .states
                .into_iter()
                .map(|state| RangeReduceResult {
                    value: state.finish(),
                })
                .collect(),
        }
    }
}

fn update_extreme(
    current: &mut Option<KvReducedValue>,
    candidate: Option<KvReducedValue>,
    replace_when: Ordering,
) -> Result<(), RangeError> {
    let Some(candidate) = candidate else {
        return Ok(());
    };
    match current {
        Some(existing) => {
            let ordering = candidate
                .partial_cmp_same_kind(existing)
                .ok_or_else(|| RangeError::Reduce("min/max type mismatch".to_string()))?;
            if ordering == replace_when {
                *current = Some(candidate);
            }
        }
        None => {
            *current = Some(candidate);
        }
    }
    Ok(())
}

fn validate_reduce_request(request: &RangeReduceRequest) -> Result<(), RangeError> {
    if request.reducers.is_empty() && request.group_by.is_empty() {
        return Err(RangeError::Reduce(
            "range reduction request requires at least one reducer or group-by field".to_string(),
        ));
    }
    for reducer in &request.reducers {
        match reducer.op {
            RangeReduceOp::CountAll => {
                if reducer.expr.is_some() {
                    return Err(RangeError::Reduce(
                        "count_all reducer must not specify an expression".to_string(),
                    ));
                }
            }
            RangeReduceOp::CountField
            | RangeReduceOp::SumField
            | RangeReduceOp::MinField
            | RangeReduceOp::MaxField => {
                if reducer.expr.is_none() {
                    return Err(RangeError::Reduce(
                        "expression reducer requires an expression".to_string(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn reduce_row_into_response(
    key: &Key,
    value: &Bytes,
    request: &RangeReduceRequest,
    scalar_states: Option<&mut [ReductionState]>,
    grouped_states: &mut BTreeMap<Vec<u8>, GroupedReductionState>,
) -> Result<(), RangeError> {
    let Some(extracted) = extract_reduce_row(key, value, request)? else {
        return Ok(());
    };

    if request.group_by.is_empty() {
        let Some(states) = scalar_states else {
            return Err(RangeError::Reduce(
                "missing scalar reduction state for non-grouped request".to_string(),
            ));
        };
        for ((state, reducer), value) in states
            .iter_mut()
            .zip(request.reducers.iter())
            .zip(extracted.reducer_values)
        {
            state.update(reducer.op, value)?;
        }
        return Ok(());
    }

    let group_key = encode_reduced_group_key(&extracted.group_values);
    let group = grouped_states
        .entry(group_key)
        .or_insert_with(|| GroupedReductionState::new(extracted.group_values.clone(), request));
    group.update(request, extracted.reducer_values)?;
    Ok(())
}

fn extract_reduce_row(
    key: &Key,
    value: &Bytes,
    request: &RangeReduceRequest,
) -> Result<Option<ExtractedReductionRow>, RangeError> {
    let needs_value = request
        .group_by
        .iter()
        .chain(
            request
                .reducers
                .iter()
                .filter_map(|reducer| reducer.expr.as_ref()),
        )
        .any(expr_needs_value)
        || request.filter.as_ref().is_some_and(predicate_needs_value);
    let decoded = if needs_value {
        match decode_stored_row(value.as_ref()) {
            Ok(row) => Some(row),
            Err(_) => return Ok(None),
        }
    } else {
        None
    };
    let archived = decoded.as_ref();

    if let Some(filter) = &request.filter {
        match eval_predicate(key, archived, filter) {
            Ok(true) => {}
            Ok(false) => return Ok(None),
            Err(_) => return Ok(None),
        }
    }

    let mut group_values = Vec::with_capacity(request.group_by.len());
    for expr in &request.group_by {
        let extracted_value = match eval_expr(key, archived, expr) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        group_values.push(extracted_value);
    }
    canonicalize_reduced_group_values(&mut group_values);

    let mut reducer_values = Vec::with_capacity(request.reducers.len());
    for reducer in &request.reducers {
        let extracted_value = match (&reducer.expr, archived) {
            (None, _) => None,
            (Some(expr), _) => match eval_expr(key, archived, expr) {
                Ok(value) => value,
                Err(_) => return Ok(None),
            },
        };
        reducer_values.push(extracted_value);
    }

    Ok(Some(ExtractedReductionRow {
        group_values,
        reducer_values,
    }))
}

fn finalize_reduce_response(
    scalar_states: Option<Vec<ReductionState>>,
    grouped_states: BTreeMap<Vec<u8>, GroupedReductionState>,
) -> RangeReduceResponse {
    match scalar_states {
        Some(states) => RangeReduceResponse {
            results: states
                .into_iter()
                .map(|state| RangeReduceResult {
                    value: state.finish(),
                })
                .collect(),
            groups: Vec::new(),
        },
        None => RangeReduceResponse {
            results: Vec::new(),
            groups: grouped_states
                .into_values()
                .map(GroupedReductionState::finish)
                .collect(),
        },
    }
}

pub(crate) struct RangeReducer<'a> {
    request: &'a RangeReduceRequest,
    scalar_states: Option<Vec<ReductionState>>,
    grouped_states: BTreeMap<Vec<u8>, GroupedReductionState>,
}

impl<'a> RangeReducer<'a> {
    pub(crate) fn new(request: &'a RangeReduceRequest) -> Result<Self, RangeError> {
        validate_reduce_request(request)?;
        Ok(Self {
            request,
            scalar_states: request.group_by.is_empty().then(|| {
                request
                    .reducers
                    .iter()
                    .map(|reducer| ReductionState::from_op(reducer.op))
                    .collect::<Vec<_>>()
            }),
            grouped_states: BTreeMap::new(),
        })
    }

    pub(crate) fn update(&mut self, key: &Key, value: &Bytes) -> Result<(), RangeError> {
        reduce_row_into_response(
            key,
            value,
            self.request,
            self.scalar_states.as_deref_mut(),
            &mut self.grouped_states,
        )
    }

    pub(crate) fn finish(self) -> RangeReduceResponse {
        finalize_reduce_response(self.scalar_states, self.grouped_states)
    }
}

/// Run a grouped or scalar reduction over materialized rows.
pub fn reduce_over_rows(
    rows: &[(Key, Bytes)],
    request: &RangeReduceRequest,
) -> Result<RangeReduceResponse, RangeError> {
    let mut reducer = RangeReducer::new(request)?;
    for (key, value) in rows {
        reducer.update(key, value)?;
    }
    Ok(reducer.finish())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use commonware_codec::Encode as _;
    use exoware_sdk::keys::Key;
    use exoware_sdk::kv_codec::{
        KvExpr, KvFieldKind, KvFieldRef, KvPredicate, KvPredicateCheck, KvPredicateConstraint,
        KvReducedValue, StoredRow, StoredValue,
    };
    use exoware_sdk::{RangeReduceOp, RangeReduceRequest, RangeReducerSpec};

    use super::{reduce_over_rows, RangeReducer};

    fn make_row(key: &[u8], values: Vec<Option<StoredValue>>) -> (Key, Bytes) {
        let encoded = StoredRow { values }.encode();
        (Key::from(key.to_vec()), encoded)
    }

    fn reducer(op: RangeReduceOp, expr: Option<KvExpr>) -> RangeReducerSpec {
        RangeReducerSpec { op, expr }
    }

    fn int64_value_field(index: u16) -> KvExpr {
        KvExpr::Field(KvFieldRef::Value {
            index,
            kind: KvFieldKind::Int64,
            nullable: true,
        })
    }

    fn float64_value_field(index: u16) -> KvExpr {
        KvExpr::Field(KvFieldRef::Value {
            index,
            kind: KvFieldKind::Float64,
            nullable: true,
        })
    }

    fn utf8_value_field(index: u16) -> KvExpr {
        KvExpr::Field(KvFieldRef::Value {
            index,
            kind: KvFieldKind::Utf8,
            nullable: true,
        })
    }

    fn scalar_request(reducers: Vec<RangeReducerSpec>) -> RangeReduceRequest {
        RangeReduceRequest {
            reducers,
            group_by: Vec::new(),
            filter: None,
        }
    }

    fn result_u64(v: u64) -> Option<KvReducedValue> {
        Some(KvReducedValue::UInt64(v))
    }

    fn result_i64(v: i64) -> Option<KvReducedValue> {
        Some(KvReducedValue::Int64(v))
    }

    fn result_f64(v: f64) -> Option<KvReducedValue> {
        Some(KvReducedValue::Float64(v))
    }

    fn reduce_incrementally(
        rows: &[(Key, Bytes)],
        request: &RangeReduceRequest,
    ) -> super::RangeReduceResponse {
        let mut reducer = RangeReducer::new(request).unwrap();
        for (key, value) in rows {
            reducer.update(key, value).unwrap();
        }
        reducer.finish()
    }

    #[test]
    fn count_all_over_empty_rows() {
        let request = scalar_request(vec![reducer(RangeReduceOp::CountAll, None)]);
        let response = reduce_over_rows(&[], &request).unwrap();
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].value, result_u64(0));
    }

    #[test]
    fn count_all_over_multiple_rows() {
        let rows = vec![
            make_row(b"a", vec![]),
            make_row(b"b", vec![]),
            make_row(b"c", vec![]),
        ];
        let request = scalar_request(vec![reducer(RangeReduceOp::CountAll, None)]);
        let response = reduce_over_rows(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_u64(3));
    }

    #[test]
    fn count_field_skips_nulls() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Int64(1))]),
            make_row(b"b", vec![None]),
            make_row(b"c", vec![Some(StoredValue::Int64(3))]),
        ];
        let request = scalar_request(vec![reducer(
            RangeReduceOp::CountField,
            Some(int64_value_field(0)),
        )]);
        let response = reduce_over_rows(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_u64(2));
    }

    #[test]
    fn sum_int64_values() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Int64(10))]),
            make_row(b"b", vec![Some(StoredValue::Int64(20))]),
            make_row(b"c", vec![Some(StoredValue::Int64(-5))]),
        ];
        let request = scalar_request(vec![reducer(
            RangeReduceOp::SumField,
            Some(int64_value_field(0)),
        )]);
        let response = reduce_over_rows(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_i64(25));
    }

    #[test]
    fn sum_float64_values() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Float64(1.5))]),
            make_row(b"b", vec![Some(StoredValue::Float64(2.5))]),
        ];
        let request = scalar_request(vec![reducer(
            RangeReduceOp::SumField,
            Some(float64_value_field(0)),
        )]);
        let response = reduce_over_rows(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_f64(4.0));
    }

    #[test]
    fn min_selects_smallest() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Int64(30))]),
            make_row(b"b", vec![Some(StoredValue::Int64(10))]),
            make_row(b"c", vec![Some(StoredValue::Int64(20))]),
        ];
        let request = scalar_request(vec![reducer(
            RangeReduceOp::MinField,
            Some(int64_value_field(0)),
        )]);
        let response = reduce_over_rows(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_i64(10));
    }

    #[test]
    fn max_selects_largest() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Int64(30))]),
            make_row(b"b", vec![Some(StoredValue::Int64(10))]),
            make_row(b"c", vec![Some(StoredValue::Int64(50))]),
        ];
        let request = scalar_request(vec![reducer(
            RangeReduceOp::MaxField,
            Some(int64_value_field(0)),
        )]);
        let response = reduce_over_rows(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_i64(50));
    }

    #[test]
    fn grouped_count() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Utf8("x".into()))]),
            make_row(b"b", vec![Some(StoredValue::Utf8("y".into()))]),
            make_row(b"c", vec![Some(StoredValue::Utf8("x".into()))]),
            make_row(b"d", vec![Some(StoredValue::Utf8("y".into()))]),
            make_row(b"e", vec![Some(StoredValue::Utf8("x".into()))]),
        ];
        let request = RangeReduceRequest {
            reducers: vec![reducer(RangeReduceOp::CountAll, None)],
            group_by: vec![utf8_value_field(0)],
            filter: None,
        };
        let response = reduce_over_rows(&rows, &request).unwrap();
        assert!(response.results.is_empty());
        assert_eq!(response.groups.len(), 2);

        let mut counts: Vec<(Option<KvReducedValue>, Option<KvReducedValue>)> = response
            .groups
            .iter()
            .map(|g| (g.group_values[0].clone(), g.results[0].value.clone()))
            .collect();
        counts.sort_by(|a, b| {
            let a_str = match &a.0 {
                Some(KvReducedValue::Utf8(s)) => s.clone(),
                _ => String::new(),
            };
            let b_str = match &b.0 {
                Some(KvReducedValue::Utf8(s)) => s.clone(),
                _ => String::new(),
            };
            a_str.cmp(&b_str)
        });
        assert_eq!(
            counts,
            vec![
                (Some(KvReducedValue::Utf8("x".into())), result_u64(3),),
                (Some(KvReducedValue::Utf8("y".into())), result_u64(2),),
            ]
        );
    }

    #[test]
    fn validates_empty_request() {
        let request = RangeReduceRequest {
            reducers: Vec::new(),
            group_by: Vec::new(),
            filter: None,
        };
        let err = reduce_over_rows(&[], &request).unwrap_err();
        assert!(
            err.to_string().contains("at least one reducer"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn count_all_rejects_expression() {
        let request = scalar_request(vec![reducer(
            RangeReduceOp::CountAll,
            Some(int64_value_field(0)),
        )]);
        let err = reduce_over_rows(&[], &request).unwrap_err();
        assert!(
            err.to_string()
                .contains("count_all reducer must not specify an expression"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn expression_reducer_requires_expression() {
        for op in [
            RangeReduceOp::SumField,
            RangeReduceOp::MinField,
            RangeReduceOp::MaxField,
            RangeReduceOp::CountField,
        ] {
            let request = scalar_request(vec![reducer(op, None)]);
            let err = reduce_over_rows(&[], &request).unwrap_err();
            assert!(
                err.to_string()
                    .contains("expression reducer requires an expression"),
                "op {op:?} should require an expression, got: {err}"
            );
        }
    }

    #[test]
    fn filter_excludes_rows() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Int64(10))]),
            make_row(b"b", vec![Some(StoredValue::Int64(20))]),
            make_row(b"c", vec![Some(StoredValue::Int64(30))]),
        ];
        let request = RangeReduceRequest {
            reducers: vec![reducer(RangeReduceOp::SumField, Some(int64_value_field(0)))],
            group_by: Vec::new(),
            filter: Some(KvPredicate {
                checks: vec![KvPredicateCheck {
                    field: KvFieldRef::Value {
                        index: 0,
                        kind: KvFieldKind::Int64,
                        nullable: false,
                    },
                    constraint: KvPredicateConstraint::IntRange {
                        min: Some(15),
                        max: None,
                    },
                }],
                contradiction: false,
            }),
        };
        let response = reduce_over_rows(&rows, &request).unwrap();
        assert_eq!(response.results[0].value, result_i64(50));
    }

    #[test]
    fn incremental_reducer_matches_materialized_scalar() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Int64(10))]),
            make_row(b"b", vec![None]),
            make_row(b"c", vec![Some(StoredValue::Int64(30))]),
        ];
        let request = scalar_request(vec![
            reducer(RangeReduceOp::CountAll, None),
            reducer(RangeReduceOp::SumField, Some(int64_value_field(0))),
        ]);
        assert_eq!(
            reduce_incrementally(&rows, &request),
            reduce_over_rows(&rows, &request).unwrap()
        );
    }

    #[test]
    fn incremental_reducer_matches_materialized_grouped() {
        let rows = vec![
            make_row(
                b"a",
                vec![
                    Some(StoredValue::Utf8("west".into())),
                    Some(StoredValue::Int64(10)),
                ],
            ),
            make_row(
                b"b",
                vec![
                    Some(StoredValue::Utf8("east".into())),
                    Some(StoredValue::Int64(20)),
                ],
            ),
            make_row(
                b"c",
                vec![
                    Some(StoredValue::Utf8("west".into())),
                    Some(StoredValue::Int64(30)),
                ],
            ),
        ];
        let request = RangeReduceRequest {
            reducers: vec![reducer(RangeReduceOp::SumField, Some(int64_value_field(1)))],
            group_by: vec![utf8_value_field(0)],
            filter: None,
        };
        assert_eq!(
            reduce_incrementally(&rows, &request),
            reduce_over_rows(&rows, &request).unwrap()
        );
    }

    #[test]
    fn incremental_reducer_matches_materialized_filtered() {
        let rows = vec![
            make_row(b"a", vec![Some(StoredValue::Int64(10))]),
            make_row(b"b", vec![Some(StoredValue::Int64(20))]),
            make_row(b"c", vec![Some(StoredValue::Int64(30))]),
        ];
        let request = RangeReduceRequest {
            reducers: vec![reducer(RangeReduceOp::CountAll, None)],
            group_by: Vec::new(),
            filter: Some(KvPredicate {
                checks: vec![KvPredicateCheck {
                    field: KvFieldRef::Value {
                        index: 0,
                        kind: KvFieldKind::Int64,
                        nullable: false,
                    },
                    constraint: KvPredicateConstraint::IntRange {
                        min: Some(20),
                        max: None,
                    },
                }],
                contradiction: false,
            }),
        };
        assert_eq!(
            reduce_incrementally(&rows, &request),
            reduce_over_rows(&rows, &request).unwrap()
        );
    }

    #[test]
    fn mixed_type_min_max_returns_error() {
        use super::ReductionState;

        let mut state = ReductionState::Min(Some(KvReducedValue::Int64(10)));
        let result = state.update(
            RangeReduceOp::MinField,
            Some(KvReducedValue::Utf8("hello".into())),
        );
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("type mismatch"),
            "expected type mismatch error"
        );
    }
}
