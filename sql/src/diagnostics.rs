use datafusion::common::Result as DataFusionResult;

use crate::aggregate::{AggregateAccessPath, AggregatePushdownSpec};
use crate::codec::*;
use crate::filter::*;
use crate::predicate::*;
use crate::types::*;

#[derive(Debug, Clone)]
pub(crate) struct AccessPathDiagnostics {
    pub(crate) mode: String,
    pub(crate) predicate: String,
    pub(crate) exact: bool,
    pub(crate) row_recheck: bool,
    pub(crate) full_scan_like: bool,
    pub(crate) range_count: usize,
    pub(crate) constrained_prefix_len: Option<usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct AggregatePushdownDiagnostics {
    pub(crate) grouped: bool,
    pub(crate) seed_job: Option<AccessPathDiagnostics>,
    pub(crate) aggregate_jobs: Vec<AccessPathDiagnostics>,
}

pub(crate) type ChosenAggregateAccessPath =
    (Vec<KeyRange>, AggregateAccessPath, Option<usize>, bool);

#[derive(Debug)]
pub(crate) struct KvAggregateTable {
    pub(crate) spec: AggregatePushdownSpec,
}

pub(crate) enum QueryStatsExplainSurface {
    StreamedRangeDetail,
    RangeReduceDetail,
}

pub(crate) fn format_query_stats_explain(surface: QueryStatsExplainSurface) -> &'static str {
    match surface {
        QueryStatsExplainSurface::StreamedRangeDetail => {
            "streamed_range(detail.extra: server-defined metadata)"
        }
        QueryStatsExplainSurface::RangeReduceDetail => {
            "range_reduce(detail.extra: server-defined metadata)"
        }
    }
}

pub(crate) fn format_access_path_diagnostics(diag: &AccessPathDiagnostics) -> String {
    let constrained_prefix = diag
        .constrained_prefix_len
        .map(|len| format!(", constrained_prefix={len}"))
        .unwrap_or_default();
    format!(
        "mode={}, predicate={}, exact={}, row_recheck={}, ranges={}, full_scan_like={}{}",
        diag.mode,
        diag.predicate,
        diag.exact,
        diag.row_recheck,
        diag.range_count,
        diag.full_scan_like,
        constrained_prefix
    )
}

pub(crate) fn build_scan_access_path_diagnostics(
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
    predicate: &QueryPredicate,
    projection: &Option<Vec<usize>>,
) -> DataFusionResult<AccessPathDiagnostics> {
    if predicate.contradiction {
        return Ok(AccessPathDiagnostics {
            mode: "empty".to_string(),
            predicate: "FALSE".to_string(),
            exact: true,
            row_recheck: false,
            full_scan_like: false,
            range_count: 0,
            constrained_prefix_len: None,
        });
    }

    let access_plan = ScanAccessPlan::new(model, projection, predicate);
    if let Some(index_plan) = predicate.choose_index_plan(model, index_specs)? {
        let spec = &index_specs[index_plan.spec_idx];
        let exact = access_plan.predicate_fully_enforced_by_index_key(model, spec);
        return Ok(AccessPathDiagnostics {
            mode: format!(
                "secondary_index({}, {})",
                spec.name,
                match spec.layout {
                    IndexLayout::Lexicographic => "lexicographic",
                    IndexLayout::ZOrder => "z_order",
                }
            ),
            predicate: predicate.describe(model),
            exact,
            row_recheck: !exact,
            full_scan_like: false,
            range_count: index_plan.ranges.len(),
            constrained_prefix_len: Some(index_plan.constrained_prefix_len),
        });
    }

    let ranges = predicate.primary_key_ranges(model)?;
    let exact = access_plan.predicate_fully_enforced_by_primary_key(model);
    Ok(AccessPathDiagnostics {
        mode: "primary_key".to_string(),
        predicate: predicate.describe(model),
        exact,
        row_recheck: !exact,
        full_scan_like: is_primary_key_full_scan_like(model, &ranges),
        range_count: ranges.len(),
        constrained_prefix_len: None,
    })
}

pub(crate) fn build_aggregate_access_path_diagnostics(
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
    predicate: &QueryPredicate,
    access_path: &AggregateAccessPath,
    ranges: &[KeyRange],
    constrained_prefix_len: Option<usize>,
    exact: bool,
) -> AccessPathDiagnostics {
    AccessPathDiagnostics {
        mode: match access_path {
            AggregateAccessPath::PrimaryKey => "primary_key".to_string(),
            AggregateAccessPath::SecondaryIndex { spec_idx } => {
                let spec = &index_specs[*spec_idx];
                format!(
                    "secondary_index({}, {})",
                    spec.name,
                    match spec.layout {
                        IndexLayout::Lexicographic => "lexicographic",
                        IndexLayout::ZOrder => "z_order",
                    }
                )
            }
        },
        predicate: predicate.describe(model),
        exact,
        row_recheck: !exact,
        full_scan_like: matches!(access_path, AggregateAccessPath::PrimaryKey)
            && is_primary_key_full_scan_like(model, ranges),
        range_count: ranges.len(),
        constrained_prefix_len,
    }
}

pub(crate) fn is_primary_key_full_scan_like(model: &TableModel, ranges: &[KeyRange]) -> bool {
    ranges.len() == 1
        && ranges[0].start == primary_key_prefix_range(model.table_prefix).start
        && ranges[0].end == primary_key_prefix_range(model.table_prefix).end
}
