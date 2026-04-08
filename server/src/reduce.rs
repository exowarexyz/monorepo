//! Range aggregation over decoded KV rows (same semantics as the public `Reduce` RPC).

use std::cmp::Ordering;
use std::collections::BTreeMap;

use bytes::Bytes;
use exoware_common::keys::Key;
use exoware_common::kv_codec::{
    access_stored_row, canonicalize_reduced_group_values, encode_reduced_group_key, eval_expr,
    eval_predicate, expr_needs_value, predicate_needs_value, KvReducedValue,
};
use exoware_sdk_rs as exoware_proto;
use exoware_proto::{
    RangeReduceGroup, RangeReduceOp, RangeReduceRequest, RangeReduceResponse, RangeReduceResult,
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
                        .map_err(|e| RangeError::Reduce(e)),
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
            .zip(reducer_values.into_iter())
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
            .zip(extracted.reducer_values.into_iter())
        {
            state.update(reducer.op, value)?;
        }
        return Ok(());
    }

    let group_key = encode_reduced_group_key(&extracted.group_values);
    let group_values = extracted.group_values.clone();
    let group = grouped_states
        .entry(group_key)
        .or_insert_with(|| GroupedReductionState::new(group_values, request));
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
    let archived = if needs_value {
        match access_stored_row(value.as_ref()) {
            Ok(archived) => Some(archived),
            Err(_) => return Ok(None),
        }
    } else {
        None
    };

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

/// Run a grouped or scalar reduction over materialized rows.
pub fn reduce_over_rows(
    rows: &[(Key, Bytes)],
    request: &RangeReduceRequest,
) -> Result<RangeReduceResponse, RangeError> {
    validate_reduce_request(request)?;
    let mut scalar_states = request.group_by.is_empty().then(|| {
        request
            .reducers
            .iter()
            .map(|reducer| ReductionState::from_op(reducer.op))
            .collect::<Vec<_>>()
    });
    let mut grouped_states = BTreeMap::<Vec<u8>, GroupedReductionState>::new();

    for (key, value) in rows {
        reduce_row_into_response(
            key,
            value,
            request,
            scalar_states.as_deref_mut(),
            &mut grouped_states,
        )?;
    }

    Ok(finalize_reduce_response(scalar_states, grouped_states))
}
