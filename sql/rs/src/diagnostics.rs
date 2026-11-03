use crate::{aggregate::AggregateAccessPath, codec::*, filter::*, predicate::*, types::*};
use datafusion::common::Result as DataFusionResult;

/// Explain output describing the ranges and predicate coverage of one access path.
#[derive(Debug, Clone)]
pub(crate) struct AccessPathDiagnostics {
    /// Display label for the primary key, a named secondary index, or an empty scan.
    pub(crate) mode: String,
    /// Human-readable description of the supported column constraints.
    pub(crate) predicate: String,
    /// Whether the access path fully enforces the described predicate without a row recheck.
    pub(crate) exact: bool,
    /// Whether the ranges comprise a single scan of the entire primary-key family.
    pub(crate) full_scan_like: bool,
    /// Number of key ranges selected for this access path.
    pub(crate) range_count: usize,
    /// Constrained prefix length for lexicographic indexes or constrained column count
    /// for Z-order indexes. `None` denotes primary-key access or an empty scan.
    pub(crate) constrained_prefix_len: Option<usize>,
}

/// Explain output for the reduce jobs that implement a pushed-down aggregation.
#[derive(Debug, Clone)]
pub(crate) struct AggregatePushdownDiagnostics {
    /// Whether the aggregation has grouping expressions.
    pub(crate) grouped: bool,
    /// Access path for the job that discovers groups, if a separate seed job is needed.
    pub(crate) seed_job: Option<AccessPathDiagnostics>,
    /// Access paths in execution-job order after compatible aggregates are combined.
    pub(crate) aggregate_jobs: Vec<AccessPathDiagnostics>,
}

/// Selected ranges, access path, and optional index constraint count used in diagnostics.
pub(crate) type ChosenAggregateAccessPath = (Vec<KeyRange>, AggregateAccessPath, Option<usize>);

/// Store response surface whose metadata is described in explain output.
pub(crate) enum QueryStatsExplainSurface {
    /// Detail metadata attached to streamed range responses.
    StreamedRangeDetail,
    /// Detail metadata attached to range-reduce responses.
    RangeReduceDetail,
}

pub(crate) const fn format_query_stats_explain(surface: QueryStatsExplainSurface) -> &'static str {
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
        !diag.exact,
        diag.range_count,
        diag.full_scan_like,
        constrained_prefix
    )
}

pub(crate) fn build_scan_access_path_diagnostics(
    model: &TableModel,
    max_logical_key_len: usize,
    index_specs: &[ResolvedIndexSpec],
    predicate: &QueryPredicate,
    access_plan: &ScanAccessPlan,
    index_plan: Option<&IndexPlan>,
    complete_ranges: bool,
) -> DataFusionResult<AccessPathDiagnostics> {
    if predicate.contradiction {
        return Ok(AccessPathDiagnostics {
            mode: "empty".to_string(),
            predicate: "FALSE".to_string(),
            exact: true,
            full_scan_like: false,
            range_count: 0,
            constrained_prefix_len: None,
        });
    }

    if let Some(index_plan) = index_plan {
        let spec = &index_specs[index_plan.spec_idx];
        let exact =
            complete_ranges && access_plan.predicate_fully_enforced_by_index_key(model, spec);
        return Ok(AccessPathDiagnostics {
            mode: secondary_index_mode(spec),
            predicate: predicate.describe(model),
            exact,
            full_scan_like: false,
            range_count: index_plan.ranges.len(),
            constrained_prefix_len: Some(index_plan.constrained_prefix_len),
        });
    }

    let ranges = predicate.primary_key_ranges(model, max_logical_key_len)?;
    let exact = complete_ranges && access_plan.predicate_fully_enforced_by_primary_key(model);
    Ok(AccessPathDiagnostics {
        mode: "primary_key".to_string(),
        predicate: predicate.describe(model),
        exact,
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
                secondary_index_mode(&index_specs[*spec_idx])
            }
        },
        predicate: predicate.describe(model),
        exact,
        full_scan_like: matches!(access_path, AggregateAccessPath::PrimaryKey)
            && is_primary_key_full_scan_like(model, ranges),
        range_count: ranges.len(),
        constrained_prefix_len,
    }
}

fn secondary_index_mode(spec: &ResolvedIndexSpec) -> String {
    let layout = match spec.layout {
        IndexLayout::Lexicographic => "lexicographic",
        IndexLayout::ZOrder => "z_order",
    };
    format!("secondary_index({}, {layout})", spec.name)
}

pub(crate) fn is_primary_key_full_scan_like(model: &TableModel, ranges: &[KeyRange]) -> bool {
    ranges.len() == 1
        && ranges[0].start == primary_key_prefix_range(model.table_prefix).start
        && ranges[0].end == primary_key_prefix_range(model.table_prefix).end
}
