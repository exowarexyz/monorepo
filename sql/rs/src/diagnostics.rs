use crate::{aggregate::AggregateAccessPath, codec::*, filter::*, predicate::*, types::*};
use datafusion::common::Result as DataFusionResult;

/// Explain output describing the ranges and predicate coverage of one access path.
#[derive(Debug, Clone)]
pub(crate) struct AccessPathDiagnostics {
    /// Display label for primary-key ranges, primary-key point reads, a named secondary
    /// index, or an empty scan.
    pub(crate) mode: String,
    /// Human-readable description of the supported column constraints.
    pub(crate) predicate: String,
    /// Whether the access path enforces every filter, so rows need no recheck.
    pub(crate) exact: bool,
    /// Whether the ranges comprise a single scan of the entire primary-key family.
    pub(crate) full_scan_like: bool,
    /// Number of key ranges selected for this access path, or of keys for point reads.
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

/// Escapes a value for one `key=value` line of DataFusion's tree display.
///
/// The tree display reads every line of a node as a separate pair, so a line break inside a
/// value would start another pair. Control characters become escapes and a backslash is
/// doubled, so the value stays on its line and distinct values stay distinct.
pub(crate) fn escape_tree_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            c if c.is_control() => escaped.extend(c.escape_default()),
            c => escaped.push(c),
        }
    }
    escaped
}

/// Returns the name and value of each fact about an access path, in display order.
pub(crate) fn access_path_fields(diag: &AccessPathDiagnostics) -> Vec<(&'static str, String)> {
    let mut fields = vec![
        ("mode", diag.mode.clone()),
        ("predicate", diag.predicate.clone()),
        ("exact", diag.exact.to_string()),
        ("row_recheck", (!diag.exact).to_string()),
        ("ranges", diag.range_count.to_string()),
        ("full_scan_like", diag.full_scan_like.to_string()),
    ];
    if let Some(len) = diag.constrained_prefix_len {
        fields.push(("constrained_prefix", len.to_string()));
    }
    fields
}

pub(crate) fn format_access_path_diagnostics(diag: &AccessPathDiagnostics) -> String {
    access_path_fields(diag)
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
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
    // A contradiction proves the result is empty, so no ranges or row checks are needed.
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

    // Complete primary-key constraints are read directly. Keys too long for the
    // namespace are dropped, as in execution.
    if let Some(mut keys) = predicate.primary_key_points(model)? {
        keys.retain(|key| key.len() <= max_logical_key_len);
        let exact = complete_ranges && access_plan.predicate_fully_enforced_by_primary_key_points();
        return Ok(AccessPathDiagnostics {
            mode: "primary_key_points".to_string(),
            predicate: predicate.describe(model),
            exact,
            full_scan_like: false,
            range_count: keys.len(),
            constrained_prefix_len: None,
        });
    }

    // Use the selected index plan so explain output matches execution. Its ranges
    // are exact only when range extraction supports every filter and the index key
    // enforces every extracted constraint.
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

    // Primary-key scans derive their ranges from the predicate. A single range
    // spanning the entire primary-key family is reported as a full scan.
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
