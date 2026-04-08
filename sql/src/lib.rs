pub mod prune;

use std::{
    any::Any,
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    sync::Arc,
};

use async_trait::async_trait;
use datafusion::arrow::array::{
    new_empty_array, Array, ArrayRef, BooleanArray, BooleanBuilder, Date32Array, Date32Builder,
    Date64Array, Date64Builder, Decimal128Array, Decimal128Builder, Decimal256Array,
    Decimal256Builder, FixedSizeBinaryArray, FixedSizeBinaryBuilder, Float64Array, Float64Builder,
    Int64Array, Int64Builder, LargeStringArray, ListArray, ListBuilder, StringArray, StringBuilder,
    StringViewArray, TimestampMicrosecondArray, TimestampMicrosecondBuilder, UInt64Array,
    UInt64Builder,
};
use datafusion::arrow::compute::cast;
use datafusion::arrow::datatypes::{i256, DataType, Field, Schema, SchemaRef, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::catalog::Session;
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::{DataFusionError, Result as DataFusionResult, ScalarValue, SchemaExt};
use datafusion::datasource::sink::{DataSink, DataSinkExec};
use datafusion::datasource::TableProvider;
use datafusion::datasource::{provider_as_source, source_as_provider};
use datafusion::execution::context::TaskContext;
use datafusion::logical_expr::dml::InsertOp;
use datafusion::logical_expr::{
    Expr, LogicalPlan, LogicalPlanBuilder, Operator, TableProviderFilterPushDown, TableType,
};
use datafusion::optimizer::optimizer::{OptimizerConfig, OptimizerRule};
use datafusion::physical_expr::{EquivalenceProperties, Partitioning};
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::{
    stream::RecordBatchStreamAdapter, DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties,
    SendableRecordBatchStream,
};
use datafusion::prelude::SessionContext;
use exoware_sdk_rs::keys::{Key, KeyCodec, KeyMut};
use exoware_sdk_rs::kv_codec::{
    access_stored_row, canonicalize_reduced_group_values, encode_reduced_group_key, eval_predicate,
    interleave_ordered_key_fields, ArchivedStoredRow, ArchivedStoredValue, KvExpr, KvFieldKind,
    KvFieldRef, KvPredicate, KvPredicateCheck, KvPredicateConstraint, KvReducedValue, StoredRow,
    StoredValue,
};
use exoware_sdk_rs as exoware_proto;
use exoware_proto::to_domain_reduce_response;
use exoware_proto::{
    RangeReduceGroup, RangeReduceOp, RangeReduceRequest, RangeReduceResponse, RangeReduceResult,
    RangeReducerSpec,
};
use exoware_sdk_rs::{SerializableReadSession, StoreClient};
use futures::{SinkExt, TryStreamExt};

const TABLE_PREFIX_BITS: u8 = 4;
const KEY_KIND_BITS: u8 = 1;
const PRIMARY_RESERVED_BITS: u8 = TABLE_PREFIX_BITS + KEY_KIND_BITS;
const INDEX_SLOT_BITS: u8 = 4;
const INDEX_FAMILY_BITS: u8 = TABLE_PREFIX_BITS + KEY_KIND_BITS + INDEX_SLOT_BITS;
const PRIMARY_KEY_BIT_OFFSET: usize = PRIMARY_RESERVED_BITS as usize;
const INDEX_KEY_BIT_OFFSET: usize = INDEX_FAMILY_BITS as usize;
const MAX_TABLES: usize = 1usize << TABLE_PREFIX_BITS;
const MAX_INDEX_SPECS: usize = (1usize << INDEX_SLOT_BITS) - 1;
const STRING_KEY_INLINE_LIMIT: usize = 15;
const STRING_KEY_TERMINATOR: u8 = 0x00;
const STRING_KEY_ESCAPE_PREFIX: u8 = 0x01;
const STRING_KEY_ESCAPE_FF: u8 = 0x02;
const PAGE_SIZE: usize = 1_000;
const BATCH_FLUSH_ROWS: usize = 2_048;
const INDEX_BACKFILL_FLUSH_ENTRIES: usize = 4_096;

fn primary_key_codec(table_prefix: u8) -> Result<KeyCodec, String> {
    if usize::from(table_prefix) >= MAX_TABLES {
        return Err(format!(
            "table prefix {table_prefix} exceeds max {} for codec layout",
            MAX_TABLES - 1
        ));
    }
    KeyCodec::new(
        PRIMARY_RESERVED_BITS,
        u16::from(table_prefix) << KEY_KIND_BITS,
    )
    .map_err(|e| format!("invalid primary key codec: {e}"))
}

fn secondary_index_codec(table_prefix: u8, index_id: u8) -> Result<KeyCodec, String> {
    if usize::from(table_prefix) >= MAX_TABLES {
        return Err(format!(
            "table prefix {table_prefix} exceeds max {} for codec layout",
            MAX_TABLES - 1
        ));
    }
    if index_id == 0 || usize::from(index_id) > MAX_INDEX_SPECS {
        return Err(format!(
            "index id {index_id} exceeds max {} for codec layout",
            MAX_INDEX_SPECS
        ));
    }
    let family = (u16::from(table_prefix) << (KEY_KIND_BITS + INDEX_SLOT_BITS))
        | (1u16 << INDEX_SLOT_BITS)
        | u16::from(index_id);
    KeyCodec::new(INDEX_FAMILY_BITS, family)
        .map_err(|e| format!("invalid secondary index codec: {e}"))
}

fn allocate_codec_key(codec: KeyCodec, payload_len: usize) -> Result<KeyMut, String> {
    let total_len = codec.min_key_len_for_payload(payload_len);
    codec
        .new_key_with_len(total_len)
        .map_err(|e| format!("failed to allocate codec key: {e}"))
}

fn ensure_codec_payload_fits(
    codec: KeyCodec,
    payload_len: usize,
    context: &str,
) -> Result<(), String> {
    let max_payload_len = codec.payload_capacity_bytes();
    if payload_len > max_payload_len {
        return Err(format!(
            "{context} exceeds codec payload capacity {max_payload_len} bytes"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IndexBackfillReport {
    pub scanned_rows: u64,
    pub indexes_backfilled: usize,
    pub index_entries_written: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexBackfillOptions {
    pub row_batch_size: usize,
    pub start_from_primary_key: Option<Key>,
}

impl Default for IndexBackfillOptions {
    fn default() -> Self {
        Self {
            row_batch_size: PAGE_SIZE,
            start_from_primary_key: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexBackfillEvent {
    Started {
        table_name: String,
        indexes_backfilled: usize,
        row_batch_size: usize,
        start_cursor: Key,
    },
    Progress {
        scanned_rows: u64,
        index_entries_written: u64,
        last_scanned_primary_key: Key,
        next_cursor: Option<Key>,
    },
    Completed {
        report: IndexBackfillReport,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListElementKind {
    Int64,
    Float64,
    Boolean,
    Utf8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColumnKind {
    Int64,
    UInt64,
    Float64,
    Boolean,
    Utf8,
    Date32,
    Date64,
    Timestamp,
    Decimal128,
    Decimal256,
    FixedSizeBinary(usize),
    List(ListElementKind),
}

impl ColumnKind {
    fn from_data_type(data_type: &DataType) -> Result<Self, String> {
        match data_type {
            DataType::Int64 => Ok(Self::Int64),
            DataType::UInt64 => Ok(Self::UInt64),
            DataType::Float64 => Ok(Self::Float64),
            DataType::Boolean => Ok(Self::Boolean),
            DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => Ok(Self::Utf8),
            DataType::Date32 => Ok(Self::Date32),
            DataType::Date64 => Ok(Self::Date64),
            DataType::Timestamp(_, _) => Ok(Self::Timestamp),
            DataType::Decimal128(_, _) => Ok(Self::Decimal128),
            DataType::Decimal256(_, _) => Ok(Self::Decimal256),
            DataType::FixedSizeBinary(n) => Ok(Self::FixedSizeBinary(*n as usize)),
            DataType::List(field) | DataType::LargeList(field) => {
                let inner = Self::from_data_type(field.data_type())?;
                let elem = match inner {
                    Self::Int64 => ListElementKind::Int64,
                    Self::Float64 => ListElementKind::Float64,
                    Self::Boolean => ListElementKind::Boolean,
                    Self::Utf8 => ListElementKind::Utf8,
                    _ => {
                        return Err(format!(
                            "unsupported list element type {:?}; \
                             list elements must be Int64, Float64, Boolean, or Utf8",
                            field.data_type()
                        ))
                    }
                };
                Ok(Self::List(elem))
            }
            other => Err(format!(
                "unsupported column type {other:?}; supported: \
                 Int64, UInt64, Float64, Boolean, Utf8, Date32, Date64, Timestamp, \
                 Decimal128, Decimal256, FixedSizeBinary, List"
            )),
        }
    }

    fn fixed_key_width(self) -> Option<usize> {
        match self {
            Self::Int64 => Some(8),
            Self::UInt64 => Some(8),
            Self::Float64 => Some(8),
            Self::Boolean => Some(1),
            Self::Utf8 => None,
            Self::Date32 => Some(4),
            Self::Date64 => Some(8),
            Self::Timestamp => Some(8),
            Self::Decimal128 => Some(16),
            Self::Decimal256 => Some(32),
            Self::FixedSizeBinary(n) => Some(n),
            Self::List(_) => None,
        }
    }

    fn key_width(self) -> usize {
        self.fixed_key_width()
            .unwrap_or(STRING_KEY_INLINE_LIMIT + 1)
    }

    fn indexable(self) -> bool {
        !matches!(self, Self::List(_))
    }
}

#[derive(Debug, Clone)]
pub struct TableColumnConfig {
    pub name: String,
    pub data_type: DataType,
    pub nullable: bool,
}

impl TableColumnConfig {
    pub fn new(name: impl Into<String>, data_type: DataType, nullable: bool) -> Self {
        Self {
            name: name.into(),
            data_type,
            nullable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexLayout {
    Lexicographic,
    ZOrder,
}

#[derive(Debug, Clone)]
pub struct IndexSpec {
    name: String,
    key_columns: Vec<String>,
    cover_columns: Vec<String>,
    layout: IndexLayout,
}

impl IndexSpec {
    #[cfg(test)]
    fn new(name: impl Into<String>, key_columns: Vec<String>) -> Result<Self, String> {
        Self::lexicographic(name, key_columns)
    }

    pub fn lexicographic(
        name: impl Into<String>,
        key_columns: Vec<String>,
    ) -> Result<Self, String> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err("index name must not be empty".to_string());
        }
        if key_columns.is_empty() {
            return Err("key_columns must not be empty".to_string());
        }
        Ok(Self {
            name,
            key_columns,
            cover_columns: Vec::new(),
            layout: IndexLayout::Lexicographic,
        })
    }

    pub fn z_order(name: impl Into<String>, key_columns: Vec<String>) -> Result<Self, String> {
        Self::lexicographic(name, key_columns).map(|spec| spec.with_layout(IndexLayout::ZOrder))
    }

    pub fn with_cover_columns(mut self, cover_columns: Vec<String>) -> Self {
        self.cover_columns = cover_columns;
        self
    }

    pub fn with_layout(mut self, layout: IndexLayout) -> Self {
        self.layout = layout;
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn key_columns(&self) -> &[String] {
        &self.key_columns
    }

    pub fn cover_columns(&self) -> &[String] {
        &self.cover_columns
    }

    pub fn layout(&self) -> &IndexLayout {
        &self.layout
    }
}

pub fn default_orders_index_specs() -> Vec<IndexSpec> {
    vec![IndexSpec::lexicographic(
        "region_customer",
        vec!["region".to_string(), "customer_id".to_string()],
    )
    .expect("default orders index must be valid")]
}

#[derive(Debug, Clone)]
struct KvTableConfig {
    table_prefix: u8,
    columns: Vec<TableColumnConfig>,
    primary_key_columns: Vec<String>,
    index_specs: Vec<IndexSpec>,
}

impl KvTableConfig {
    fn new(
        table_prefix: u8,
        columns: Vec<TableColumnConfig>,
        primary_key_columns: Vec<String>,
        index_specs: Vec<IndexSpec>,
    ) -> Result<Self, String> {
        if usize::from(table_prefix) >= MAX_TABLES {
            return Err(format!(
                "table prefix {table_prefix} exceeds max {} for codec layout",
                MAX_TABLES - 1
            ));
        }
        if columns.is_empty() {
            return Err("table config requires at least one column".to_string());
        }
        if primary_key_columns.is_empty() {
            return Err("primary key must have at least one column".to_string());
        }

        let mut seen = HashSet::new();
        let mut col_kinds = HashMap::new();
        for col in &columns {
            if col.name.trim().is_empty() {
                return Err("column name must not be empty".to_string());
            }
            if !seen.insert(col.name.clone()) {
                return Err(format!("duplicate column '{}'", col.name));
            }
            let kind = ColumnKind::from_data_type(&col.data_type)?;
            col_kinds.insert(col.name.clone(), kind);
        }

        let mut total_pk_width = 0usize;
        for pk_col in &primary_key_columns {
            let kind = col_kinds
                .get(pk_col)
                .ok_or_else(|| format!("primary key column '{pk_col}' not found"))?;
            match kind {
                ColumnKind::Int64
                | ColumnKind::UInt64
                | ColumnKind::Utf8
                | ColumnKind::FixedSizeBinary(_) => {}
                _ => {
                    return Err(format!(
                        "primary key column '{pk_col}' must be Int64, UInt64, Utf8, or FixedSizeBinary"
                    ));
                }
            }
            total_pk_width += kind.key_width();
        }
        if total_pk_width > primary_key_codec(table_prefix)?.payload_capacity_bytes() {
            return Err(format!(
                "composite primary key is too wide ({total_pk_width} bytes) for codec payload"
            ));
        }

        Ok(Self {
            table_prefix,
            columns,
            primary_key_columns,
            index_specs,
        })
    }

    fn to_schema(&self) -> SchemaRef {
        Arc::new(Schema::new(
            self.columns
                .iter()
                .map(|col| {
                    let dt = match &col.data_type {
                        DataType::Timestamp(_, tz) => {
                            DataType::Timestamp(TimeUnit::Microsecond, tz.clone())
                        }
                        DataType::LargeList(field) => DataType::List(field.clone()),
                        other => other.clone(),
                    };
                    Field::new(&col.name, dt, col.nullable)
                })
                .collect::<Vec<_>>(),
        ))
    }
}

#[derive(Debug, Clone)]
struct ResolvedColumn {
    name: String,
    kind: ColumnKind,
    nullable: bool,
}

#[derive(Debug, Clone)]
struct ResolvedIndexSpec {
    id: u8,
    codec: KeyCodec,
    name: String,
    layout: IndexLayout,
    key_columns: Vec<usize>,
    value_column_mask: Vec<bool>,
    key_columns_width: usize,
}

#[derive(Debug, Clone)]
struct TableModel {
    table_prefix: u8,
    primary_key_codec: KeyCodec,
    schema: SchemaRef,
    columns: Vec<ResolvedColumn>,
    columns_by_name: HashMap<String, usize>,
    primary_key_indices: Vec<usize>,
    primary_key_kinds: Vec<ColumnKind>,
    primary_key_width: usize,
}

impl TableModel {
    fn from_config(config: &KvTableConfig) -> Result<Self, String> {
        let schema = config.to_schema();
        let mut columns = Vec::with_capacity(config.columns.len());
        let mut columns_by_name = HashMap::with_capacity(config.columns.len());

        for (idx, col) in config.columns.iter().enumerate() {
            let kind = ColumnKind::from_data_type(&col.data_type)?;
            columns.push(ResolvedColumn {
                name: col.name.clone(),
                kind,
                nullable: col.nullable,
            });
            columns_by_name.insert(col.name.clone(), idx);
        }

        let mut primary_key_indices = Vec::with_capacity(config.primary_key_columns.len());
        let mut primary_key_kinds = Vec::with_capacity(config.primary_key_columns.len());
        let mut primary_key_width = 0usize;
        for pk_col in &config.primary_key_columns {
            let idx = *columns_by_name
                .get(pk_col)
                .ok_or_else(|| format!("primary key column '{pk_col}' not found"))?;
            let kind = columns[idx].kind;
            primary_key_indices.push(idx);
            primary_key_kinds.push(kind);
            primary_key_width += kind.key_width();
        }

        Ok(Self {
            table_prefix: config.table_prefix,
            primary_key_codec: primary_key_codec(config.table_prefix)?,
            schema,
            columns,
            columns_by_name,
            primary_key_indices,
            primary_key_kinds,
            primary_key_width,
        })
    }

    /// Whether a column index is part of the primary key.
    fn is_pk_column(&self, col_idx: usize) -> bool {
        self.primary_key_indices.contains(&col_idx)
    }

    fn pk_position(&self, col_idx: usize) -> Option<usize> {
        self.primary_key_indices
            .iter()
            .position(|&idx| idx == col_idx)
    }

    fn resolve_index_specs(&self, specs: &[IndexSpec]) -> Result<Vec<ResolvedIndexSpec>, String> {
        let mut out = Vec::with_capacity(specs.len());
        let mut names = HashSet::new();

        for (idx, spec) in specs.iter().enumerate() {
            if !names.insert(spec.name.clone()) {
                return Err(format!("duplicate index name '{}'", spec.name));
            }

            let id = u8::try_from(idx + 1).map_err(|_| {
                format!("too many index specs for codec layout (max {MAX_INDEX_SPECS})")
            })?;
            if usize::from(id) > MAX_INDEX_SPECS {
                return Err(format!(
                    "too many index specs for codec layout (max {MAX_INDEX_SPECS})"
                ));
            }
            let mut key_columns = Vec::with_capacity(spec.key_columns.len());
            let mut key_columns_width = 0usize;
            let mut value_column_mask = vec![false; self.columns.len()];
            for col_name in &spec.key_columns {
                let Some(col_idx) = self.columns_by_name.get(col_name).copied() else {
                    return Err(format!(
                        "index '{}' references unknown column '{}'",
                        spec.name, col_name
                    ));
                };
                if !self.columns[col_idx].kind.indexable() {
                    return Err(format!(
                        "index '{}' references non-indexable column '{}'",
                        spec.name, col_name
                    ));
                }
                if self.columns[col_idx].nullable {
                    return Err(format!(
                        "index '{}' references nullable column '{}'; \
                         nullable columns cannot be used in index keys",
                        spec.name, col_name
                    ));
                }
                key_columns.push(col_idx);
                key_columns_width += self.columns[col_idx].kind.key_width();
                if !self.is_pk_column(col_idx) {
                    value_column_mask[col_idx] = true;
                }
            }

            for col_name in &spec.cover_columns {
                let Some(col_idx) = self.columns_by_name.get(col_name).copied() else {
                    return Err(format!(
                        "index '{}' cover list references unknown column '{}'",
                        spec.name, col_name
                    ));
                };
                if self.is_pk_column(col_idx) {
                    return Err(format!(
                        "index '{}' cover column '{}' is a primary key column; \
                         PK columns are always available from key bytes",
                        spec.name, col_name
                    ));
                }
                if !value_column_mask[col_idx] {
                    value_column_mask[col_idx] = true;
                }
            }
            let codec = secondary_index_codec(self.table_prefix, id)?;
            if key_columns_width + self.primary_key_width > codec.payload_capacity_bytes() {
                return Err(format!(
                    "index '{}' key layout too wide for codec payload",
                    spec.name
                ));
            }

            out.push(ResolvedIndexSpec {
                id,
                codec,
                name: spec.name.clone(),
                layout: spec.layout,
                key_columns,
                value_column_mask,
                key_columns_width,
            });
        }

        Ok(out)
    }

    fn column(&self, index: usize) -> &ResolvedColumn {
        &self.columns[index]
    }
}

#[derive(Debug, Clone)]
pub enum CellValue {
    Null,
    Int64(i64),
    UInt64(u64),
    Float64(f64),
    Boolean(bool),
    Date32(i32),
    Date64(i64),
    Timestamp(i64),
    Decimal128(i128),
    Decimal256(i256),
    Utf8(String),
    FixedBinary(Vec<u8>),
    List(Vec<CellValue>),
}

#[derive(Debug, Clone)]
struct KvRow {
    values: Vec<CellValue>,
}

impl KvRow {
    fn primary_key_values(&self, model: &TableModel) -> Vec<&CellValue> {
        model
            .primary_key_indices
            .iter()
            .map(|&idx| &self.values[idx])
            .collect()
    }

    fn value_at(&self, idx: usize) -> &CellValue {
        &self.values[idx]
    }
}

#[derive(Debug, Clone, Default)]
struct DecodedIndexEntry {
    primary_key: Key,
    primary_key_values: Vec<CellValue>,
    values: HashMap<usize, CellValue>,
}

#[derive(Debug, Clone, PartialEq)]
struct KeyRange {
    start: Key,
    end: Key,
}

#[derive(Debug, Clone)]
struct IndexPlan {
    spec_idx: usize,
    ranges: Vec<KeyRange>,
    constrained_prefix_len: usize,
    constrained_column_count: usize,
}

#[derive(Debug, Clone)]
struct KvTable {
    client: StoreClient,
    model: Arc<TableModel>,
    index_specs: Arc<Vec<ResolvedIndexSpec>>,
}

impl KvTable {
    fn new(client: StoreClient, config: KvTableConfig) -> Result<Self, String> {
        let model = Arc::new(TableModel::from_config(&config)?);
        let index_specs = Arc::new(model.resolve_index_specs(&config.index_specs)?);
        Ok(Self {
            client,
            model,
            index_specs,
        })
    }
}

#[derive(Debug)]
struct KvAggregatePushdownRule;

#[derive(Debug, Clone)]
enum AggregateAccessPath {
    PrimaryKey,
    SecondaryIndex { spec_idx: usize },
}

#[derive(Debug, Clone)]
enum AggregateOutputPlan {
    Direct {
        reducer_idx: usize,
        data_type: DataType,
    },
    Avg {
        sum_idx: usize,
        count_idx: usize,
        data_type: DataType,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AggregatePushdownFunction {
    Count,
    Sum,
    Min,
    Max,
    Avg,
}

#[derive(Debug, Clone, PartialEq)]
enum PushdownValueExpr {
    Column(usize),
    Literal(KvReducedValue),
    Add(Box<PushdownValueExpr>, Box<PushdownValueExpr>),
    Sub(Box<PushdownValueExpr>, Box<PushdownValueExpr>),
    Mul(Box<PushdownValueExpr>, Box<PushdownValueExpr>),
    Div(Box<PushdownValueExpr>, Box<PushdownValueExpr>),
    Lower(Box<PushdownValueExpr>),
    DateTruncDay(Box<PushdownValueExpr>),
}

impl PushdownValueExpr {
    fn collect_columns(&self, out: &mut Vec<usize>) {
        match self {
            Self::Column(col_idx) => out.push(*col_idx),
            Self::Literal(_) => {}
            Self::Add(left, right)
            | Self::Sub(left, right)
            | Self::Mul(left, right)
            | Self::Div(left, right) => {
                left.collect_columns(out);
                right.collect_columns(out);
            }
            Self::Lower(inner) | Self::DateTruncDay(inner) => inner.collect_columns(out),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum AggregatePushdownArgument {
    CountAll,
    Expr(PushdownValueExpr),
}

#[derive(Debug, Clone)]
struct NormalizedAggregateExpr {
    func: AggregatePushdownFunction,
    argument: AggregatePushdownArgument,
    filter: Option<Expr>,
}

#[derive(Debug, Clone, PartialEq)]
struct AggregateReduceJob {
    request: RangeReduceRequest,
    ranges: Vec<KeyRange>,
}

#[derive(Debug, Clone)]
struct AggregateExprPlan {
    job: AggregateReduceJob,
    output: AggregateOutputPlan,
}

#[derive(Debug, Clone)]
struct CombinedAggregateJob {
    job: AggregateReduceJob,
    expr_plans: Vec<AggregateOutputPlan>,
}

#[derive(Debug, Clone)]
struct AggregateGroupPlan {
    data_type: DataType,
}

#[derive(Debug, Clone)]
struct AggregatePushdownSpec {
    client: StoreClient,
    group_plans: Vec<AggregateGroupPlan>,
    seed_job: Option<AggregateReduceJob>,
    aggregate_jobs: Vec<CombinedAggregateJob>,
    diagnostics: AggregatePushdownDiagnostics,
    schema: SchemaRef,
}

#[derive(Debug, Clone)]
struct AccessPathDiagnostics {
    mode: String,
    predicate: String,
    exact: bool,
    row_recheck: bool,
    full_scan_like: bool,
    range_count: usize,
    constrained_prefix_len: Option<usize>,
}

#[derive(Debug, Clone)]
struct AggregatePushdownDiagnostics {
    grouped: bool,
    seed_job: Option<AccessPathDiagnostics>,
    aggregate_jobs: Vec<AccessPathDiagnostics>,
}

type ChosenAggregateAccessPath = (Vec<KeyRange>, AggregateAccessPath, Option<usize>, bool);

#[derive(Debug)]
struct KvAggregateTable {
    spec: AggregatePushdownSpec,
}

#[derive(Debug)]
struct KvAggregateExec {
    spec: AggregatePushdownSpec,
    projection: Option<Vec<usize>>,
    projected_schema: SchemaRef,
    properties: PlanProperties,
}

#[derive(Debug)]
struct KvScanExec {
    client: StoreClient,
    model: Arc<TableModel>,
    index_specs: Arc<Vec<ResolvedIndexSpec>>,
    predicate: QueryPredicate,
    limit: Option<usize>,
    projected_schema: SchemaRef,
    projection: Option<Vec<usize>>,
    properties: PlanProperties,
}

impl KvAggregatePushdownRule {
    fn new() -> Self {
        Self
    }

    fn try_rewrite_plan(&self, plan: LogicalPlan) -> DataFusionResult<Transformed<LogicalPlan>> {
        let LogicalPlan::Aggregate(aggregate) = plan else {
            return Ok(Transformed::no(plan));
        };

        let (scan, group_exprs, aggr_exprs) = match aggregate.input.as_ref() {
            LogicalPlan::TableScan(scan) => (
                scan,
                aggregate.group_expr.clone(),
                aggregate.aggr_expr.clone(),
            ),
            LogicalPlan::Projection(projection) => {
                let LogicalPlan::TableScan(scan) = projection.input.as_ref() else {
                    return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate)));
                };
                let group_exprs = match aggregate
                    .group_expr
                    .iter()
                    .map(|expr| inline_projection_aliases(expr, projection))
                    .collect::<DataFusionResult<Vec<_>>>()
                {
                    Ok(exprs) => exprs,
                    Err(_) => return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate))),
                };
                let aggr_exprs = match aggregate
                    .aggr_expr
                    .iter()
                    .map(|expr| inline_projection_aliases(expr, projection))
                    .collect::<DataFusionResult<Vec<_>>>()
                {
                    Ok(exprs) => exprs,
                    Err(_) => return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate))),
                };
                (scan, group_exprs, aggr_exprs)
            }
            _ => return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate))),
        };
        let Ok(provider) = source_as_provider(&scan.source) else {
            return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate)));
        };
        let Some(kv_table) = provider.as_any().downcast_ref::<KvTable>() else {
            return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate)));
        };
        let Some(spec) = try_build_aggregate_pushdown_spec(
            kv_table,
            scan,
            &group_exprs,
            &aggr_exprs,
            &aggregate.schema,
        )?
        else {
            return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate)));
        };

        let table = Arc::new(KvAggregateTable { spec });
        let plan =
            LogicalPlanBuilder::scan(scan.table_name.clone(), provider_as_source(table), None)?
                .build()?;
        Ok(Transformed::yes(plan))
    }
}

fn inline_projection_aliases(
    expr: &Expr,
    projection: &datafusion::logical_expr::logical_plan::Projection,
) -> DataFusionResult<Expr> {
    let alias_map = projection
        .expr
        .iter()
        .zip(projection.schema.fields().iter())
        .map(|(projection_expr, field)| {
            (
                field.name().to_string(),
                strip_alias_expr(projection_expr).clone(),
            )
        })
        .collect::<HashMap<_, _>>();
    Ok(expr
        .clone()
        .transform(|node| {
            if let Expr::Column(column) = &node {
                if column.relation.is_none() {
                    if let Some(replacement) = alias_map.get(&column.name) {
                        return Ok(Transformed::yes(replacement.clone()));
                    }
                }
            }
            Ok(Transformed::no(node))
        })?
        .data)
}

impl OptimizerRule for KvAggregatePushdownRule {
    fn name(&self) -> &str {
        "kv_aggregate_pushdown"
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn OptimizerConfig,
    ) -> DataFusionResult<Transformed<LogicalPlan>> {
        plan.transform_up(|node| self.try_rewrite_plan(node))
    }
}

#[derive(Clone)]
enum PredicateAccess {
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
enum EncodedIndexConstraint {
    Eq(Vec<u8>),
    In(Vec<Vec<u8>>),
    Range {
        min: Option<(Vec<u8>, bool)>,
        max: Option<(Vec<u8>, bool)>,
    },
}

#[derive(Clone)]
struct EncodedIndexPredicateCheck {
    payload_offset: usize,
    width: usize,
    constraint: EncodedIndexConstraint,
}

#[derive(Clone)]
struct EncodedIndexPredicatePlan {
    codec: KeyCodec,
    checks: Vec<EncodedIndexPredicateCheck>,
    impossible: bool,
}

impl EncodedIndexPredicatePlan {
    fn matches_key(&self, key: &Key) -> bool {
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
enum IndexPredicatePlan {
    Encoded(EncodedIndexPredicatePlan),
    Shared(KvPredicate),
}

impl IndexPredicatePlan {
    fn is_impossible(&self) -> bool {
        match self {
            Self::Encoded(plan) => plan.impossible,
            Self::Shared(predicate) => predicate.contradiction,
        }
    }

    fn matches_key(&self, key: &Key) -> bool {
        match self {
            Self::Encoded(plan) => plan.matches_key(key),
            Self::Shared(predicate) => eval_predicate(key, None, predicate).unwrap_or(false),
        }
    }
}

enum EncodedConstraintCompile {
    Encoded(EncodedIndexConstraint),
    Unsupported,
    Impossible,
}

#[derive(Clone)]
struct ScanAccessPlan {
    required_pk_mask: Vec<bool>,
    required_non_pk_columns: Vec<bool>,
    projection_sources: Vec<ProjectionSource>,
    predicate_checks: Vec<PredicateAccess>,
}

impl ScanAccessPlan {
    fn new(
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

    fn matches_archived_row(&self, pk_values: &[CellValue], archived: &ArchivedStoredRow) -> bool {
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

    fn compile_index_predicate_plan(
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

    fn compile_shared_index_predicate(
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

    fn needs_any_pk(mask: &[bool]) -> bool {
        mask.iter().any(|required| *required)
    }

    fn index_covers_required_non_pk(&self, spec: &ResolvedIndexSpec) -> bool {
        self.required_non_pk_columns
            .iter()
            .enumerate()
            .all(|(col_idx, required)| !*required || spec.value_column_mask[col_idx])
    }

    fn predicate_fully_enforced_by_primary_key(&self, model: &TableModel) -> bool {
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

    fn predicate_fully_enforced_by_index_key(
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

fn matches_encoded_constraint(field: &[u8], constraint: &EncodedIndexConstraint) -> bool {
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

fn compile_encoded_constraint(
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

impl KvScanExec {
    fn new(
        client: StoreClient,
        model: Arc<TableModel>,
        index_specs: Arc<Vec<ResolvedIndexSpec>>,
        predicate: QueryPredicate,
        limit: Option<usize>,
        projected_schema: SchemaRef,
        projection: Option<Vec<usize>>,
    ) -> Self {
        let properties = PlanProperties::new(
            EquivalenceProperties::new(projected_schema.clone()),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Bounded,
        );
        Self {
            client,
            model,
            index_specs,
            predicate,
            limit,
            projected_schema,
            projection,
            properties,
        }
    }

    fn plan_diagnostics(&self) -> DataFusionResult<AccessPathDiagnostics> {
        build_scan_access_path_diagnostics(
            &self.model,
            &self.index_specs,
            &self.predicate,
            &self.projection,
        )
    }
}

#[async_trait]
impl TableProvider for KvAggregateTable {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.spec.schema.clone()
    }

    fn table_type(&self) -> TableType {
        TableType::Temporary
    }

    async fn scan(
        &self,
        _state: &dyn Session,
        projection: Option<&Vec<usize>>,
        _filters: &[Expr],
        _limit: Option<usize>,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        let projected_schema = match projection {
            Some(proj) => Arc::new(self.spec.schema.project(proj)?),
            None => self.spec.schema.clone(),
        };
        Ok(Arc::new(KvAggregateExec::new(
            self.spec.clone(),
            projection.cloned(),
            projected_schema,
        )))
    }
}

impl KvAggregateExec {
    fn new(
        spec: AggregatePushdownSpec,
        projection: Option<Vec<usize>>,
        projected_schema: SchemaRef,
    ) -> Self {
        let properties = PlanProperties::new(
            EquivalenceProperties::new(projected_schema.clone()),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Bounded,
        );
        Self {
            spec,
            projection,
            projected_schema,
            properties,
        }
    }
}

impl DisplayAs for KvAggregateExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KvAggregateExec: grouped={}, seed_job={}, aggregate_jobs=[{}], query_stats={}",
            self.spec.diagnostics.grouped,
            self.spec
                .diagnostics
                .seed_job
                .as_ref()
                .map(format_access_path_diagnostics)
                .unwrap_or_else(|| "none".to_string()),
            self.spec
                .diagnostics
                .aggregate_jobs
                .iter()
                .enumerate()
                .map(|(idx, diag)| format!("job{idx}{{{}}}", format_access_path_diagnostics(diag)))
                .collect::<Vec<_>>()
                .join("; "),
            format_query_stats_explain(QueryStatsExplainSurface::RangeReduceHeader)
        )
    }
}

impl ExecutionPlan for KvAggregateExec {
    fn name(&self) -> &str {
        "KvAggregateExec"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.projected_schema.clone()
    }

    fn properties(&self) -> &PlanProperties {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![]
    }

    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        if !children.is_empty() {
            return Err(DataFusionError::Internal(
                "KvAggregateExec has no children".to_string(),
            ));
        }
        Ok(self)
    }

    fn execute(
        &self,
        partition: usize,
        _context: Arc<TaskContext>,
    ) -> DataFusionResult<SendableRecordBatchStream> {
        if partition != 0 {
            return Err(DataFusionError::Internal(format!(
                "KvAggregateExec only supports 1 partition, got {partition}"
            )));
        }

        let (mut tx, rx) = futures::channel::mpsc::channel::<DataFusionResult<RecordBatch>>(1);
        let spec = self.spec.clone();
        let projection = self.projection.clone();
        let projected_schema = self.projected_schema.clone();

        tokio::spawn(async move {
            let batch =
                execute_aggregate_pushdown(spec, projection, projected_schema.clone()).await;
            let _ = tx.send(batch).await;
        });

        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.projected_schema.clone(),
            rx,
        )))
    }
}

impl DisplayAs for KvScanExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.plan_diagnostics() {
            Ok(diag) => write!(
                f,
                "KvScanExec: limit={:?}, {}, query_stats={}",
                self.limit,
                format_access_path_diagnostics(&diag),
                format_query_stats_explain(QueryStatsExplainSurface::StreamedRangeTrailer)
            ),
            Err(err) => write!(
                f,
                "KvScanExec: limit={:?}, diagnostics_error={err}",
                self.limit
            ),
        }
    }
}

#[derive(Clone, Copy)]
enum QueryStatsExplainSurface {
    StreamedRangeTrailer,
    RangeReduceHeader,
}

fn format_query_stats_explain(surface: QueryStatsExplainSurface) -> &'static str {
    match surface {
        QueryStatsExplainSurface::StreamedRangeTrailer => {
            "streamed_range(detail.read_stats: read_bytes=key+value bytes for rows read; ref RocksDB engine)"
        }
        QueryStatsExplainSurface::RangeReduceHeader => {
            "range_reduce(detail.read_stats: read_bytes=key+value bytes for rows read; ref RocksDB engine)"
        }
    }
}

fn format_access_path_diagnostics(diag: &AccessPathDiagnostics) -> String {
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

fn build_scan_access_path_diagnostics(
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

fn build_aggregate_access_path_diagnostics(
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

fn is_primary_key_full_scan_like(model: &TableModel, ranges: &[KeyRange]) -> bool {
    ranges.len() == 1
        && ranges[0].start == primary_key_prefix_range(model.table_prefix).start
        && ranges[0].end == primary_key_prefix_range(model.table_prefix).end
}

impl ExecutionPlan for KvScanExec {
    fn name(&self) -> &str {
        "KvScanExec"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.projected_schema.clone()
    }

    fn properties(&self) -> &PlanProperties {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![]
    }

    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        if !children.is_empty() {
            return Err(DataFusionError::Internal(
                "KvScanExec has no children".to_string(),
            ));
        }
        Ok(self)
    }

    fn execute(
        &self,
        partition: usize,
        _context: Arc<TaskContext>,
    ) -> DataFusionResult<SendableRecordBatchStream> {
        if partition != 0 {
            return Err(DataFusionError::Internal(format!(
                "KvScanExec only supports 1 partition, got {partition}"
            )));
        }

        let (mut tx, rx) = futures::channel::mpsc::channel::<DataFusionResult<RecordBatch>>(2);
        let session = self.client.create_session();
        let model = self.model.clone();
        let index_specs = self.index_specs.clone();
        let predicate = self.predicate.clone();
        let limit = self.limit;
        let projection = self.projection.clone();
        let projected_schema = self.projected_schema.clone();
        let access_plan = Arc::new(ScanAccessPlan::new(&model, &projection, &predicate));

        tokio::spawn(async move {
            let ctx = ScanCtx {
                session: &session,
                model: &model,
                predicate: &predicate,
                projected_schema: &projected_schema,
                access_plan: &access_plan,
            };
            if let Err(e) = stream_kv_scan(&mut tx, &ctx, &index_specs, limit).await {
                let _ = tx.send(Err(e)).await;
            }
        });

        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.projected_schema.clone(),
            rx,
        )))
    }
}

enum ColumnBuilder {
    Int64(Int64Builder),
    UInt64(UInt64Builder),
    Float64(Float64Builder),
    Boolean(BooleanBuilder),
    Date32(Date32Builder),
    Date64(Date64Builder),
    Timestamp(TimestampMicrosecondBuilder),
    Decimal128(Decimal128Builder),
    Decimal256(Decimal256Builder),
    Utf8 {
        builder: StringBuilder,
        target_type: DataType,
    },
    FixedBinary(FixedSizeBinaryBuilder),
    ListInt64(ListBuilder<Int64Builder>),
    ListFloat64(ListBuilder<Float64Builder>),
    ListBoolean(ListBuilder<BooleanBuilder>),
    ListUtf8(ListBuilder<StringBuilder>),
}

impl ColumnBuilder {
    fn append(&mut self, value: &CellValue) -> DataFusionResult<()> {
        match (self, value) {
            (Self::Int64(b), CellValue::Null) => b.append_null(),
            (Self::UInt64(b), CellValue::Null) => b.append_null(),
            (Self::Float64(b), CellValue::Null) => b.append_null(),
            (Self::Boolean(b), CellValue::Null) => b.append_null(),
            (Self::Date32(b), CellValue::Null) => b.append_null(),
            (Self::Date64(b), CellValue::Null) => b.append_null(),
            (Self::Timestamp(b), CellValue::Null) => b.append_null(),
            (Self::Decimal128(b), CellValue::Null) => b.append_null(),
            (Self::Decimal256(b), CellValue::Null) => b.append_null(),
            (Self::Utf8 { builder, .. }, CellValue::Null) => builder.append_null(),
            (Self::FixedBinary(b), CellValue::Null) => b.append_null(),
            (Self::ListInt64(b), CellValue::Null) => b.append_null(),
            (Self::ListFloat64(b), CellValue::Null) => b.append_null(),
            (Self::ListBoolean(b), CellValue::Null) => b.append_null(),
            (Self::ListUtf8(b), CellValue::Null) => b.append_null(),
            (Self::Int64(b), CellValue::Int64(v)) => b.append_value(*v),
            (Self::UInt64(b), CellValue::UInt64(v)) => b.append_value(*v),
            (Self::Float64(b), CellValue::Float64(v)) => b.append_value(*v),
            (Self::Boolean(b), CellValue::Boolean(v)) => b.append_value(*v),
            (Self::Date32(b), CellValue::Date32(v)) => b.append_value(*v),
            (Self::Date64(b), CellValue::Date64(v)) => b.append_value(*v),
            (Self::Timestamp(b), CellValue::Timestamp(v)) => b.append_value(*v),
            (Self::Decimal128(b), CellValue::Decimal128(v)) => b.append_value(*v),
            (Self::Decimal256(b), CellValue::Decimal256(v)) => b.append_value(*v),
            (Self::Utf8 { builder, .. }, CellValue::Utf8(v)) => builder.append_value(v),
            (Self::FixedBinary(b), CellValue::FixedBinary(v)) => {
                b.append_value(v).map_err(|e| {
                    DataFusionError::Execution(format!("FixedBinary append error: {e}"))
                })?
            }
            (Self::ListInt64(b), CellValue::List(items)) => {
                for item in items {
                    match item {
                        CellValue::Int64(v) => b.values().append_value(*v),
                        _ => {
                            return Err(DataFusionError::Execution(
                                "list element type mismatch".into(),
                            ))
                        }
                    }
                }
                b.append(true);
            }
            (Self::ListFloat64(b), CellValue::List(items)) => {
                for item in items {
                    match item {
                        CellValue::Float64(v) => b.values().append_value(*v),
                        _ => {
                            return Err(DataFusionError::Execution(
                                "list element type mismatch".into(),
                            ))
                        }
                    }
                }
                b.append(true);
            }
            (Self::ListBoolean(b), CellValue::List(items)) => {
                for item in items {
                    match item {
                        CellValue::Boolean(v) => b.values().append_value(*v),
                        _ => {
                            return Err(DataFusionError::Execution(
                                "list element type mismatch".into(),
                            ))
                        }
                    }
                }
                b.append(true);
            }
            (Self::ListUtf8(b), CellValue::List(items)) => {
                for item in items {
                    match item {
                        CellValue::Utf8(v) => b.values().append_value(v),
                        _ => {
                            return Err(DataFusionError::Execution(
                                "list element type mismatch".into(),
                            ))
                        }
                    }
                }
                b.append(true);
            }
            _ => {
                return Err(DataFusionError::Execution(
                    "column type mismatch".to_string(),
                ))
            }
        }
        Ok(())
    }

    fn finish(self) -> DataFusionResult<ArrayRef> {
        match self {
            Self::Int64(mut b) => Ok(Arc::new(b.finish())),
            Self::UInt64(mut b) => Ok(Arc::new(b.finish())),
            Self::Float64(mut b) => Ok(Arc::new(b.finish())),
            Self::Boolean(mut b) => Ok(Arc::new(b.finish())),
            Self::Date32(mut b) => Ok(Arc::new(b.finish())),
            Self::Date64(mut b) => Ok(Arc::new(b.finish())),
            Self::Timestamp(mut b) => Ok(Arc::new(b.finish())),
            Self::Decimal128(mut b) => Ok(Arc::new(b.finish())),
            Self::Decimal256(mut b) => Ok(Arc::new(b.finish())),
            Self::Utf8 {
                mut builder,
                target_type,
            } => {
                let array: ArrayRef = Arc::new(builder.finish());
                if target_type == DataType::Utf8 {
                    Ok(array)
                } else {
                    Ok(cast(&array, &target_type)?)
                }
            }
            Self::FixedBinary(mut b) => Ok(Arc::new(b.finish())),
            Self::ListInt64(mut b) => Ok(Arc::new(b.finish())),
            Self::ListFloat64(mut b) => Ok(Arc::new(b.finish())),
            Self::ListBoolean(mut b) => Ok(Arc::new(b.finish())),
            Self::ListUtf8(mut b) => Ok(Arc::new(b.finish())),
        }
    }
}

#[cfg(test)]
fn build_projected_batch(
    rows: &[KvRow],
    model: &TableModel,
    projected_schema: &SchemaRef,
    projection: &Option<Vec<usize>>,
) -> DataFusionResult<RecordBatch> {
    let col_indices = projected_column_indices(model, projection);
    let mut builders: Vec<ColumnBuilder> = col_indices
        .iter()
        .map(|&idx| make_column_builder(model, idx))
        .collect();
    for row in rows {
        for (builder, &col_idx) in builders.iter_mut().zip(col_indices.iter()) {
            builder.append(&row.values[col_idx])?;
        }
    }
    let columns: Vec<ArrayRef> = builders
        .into_iter()
        .map(ColumnBuilder::finish)
        .collect::<DataFusionResult<Vec<_>>>()?;
    Ok(RecordBatch::try_new(projected_schema.clone(), columns)?)
}

fn projected_column_indices(model: &TableModel, projection: &Option<Vec<usize>>) -> Vec<usize> {
    match projection {
        Some(proj) => proj.clone(),
        None => (0..model.columns.len()).collect(),
    }
}

fn make_column_builder(model: &TableModel, idx: usize) -> ColumnBuilder {
    let col = &model.columns[idx];
    match col.kind {
        ColumnKind::Int64 => ColumnBuilder::Int64(Int64Builder::new()),
        ColumnKind::UInt64 => ColumnBuilder::UInt64(UInt64Builder::new()),
        ColumnKind::Float64 => ColumnBuilder::Float64(Float64Builder::new()),
        ColumnKind::Boolean => ColumnBuilder::Boolean(BooleanBuilder::new()),
        ColumnKind::Date32 => ColumnBuilder::Date32(Date32Builder::new()),
        ColumnKind::Date64 => ColumnBuilder::Date64(Date64Builder::new()),
        ColumnKind::Timestamp => {
            let dt = model.schema.field(idx).data_type().clone();
            ColumnBuilder::Timestamp(TimestampMicrosecondBuilder::new().with_data_type(dt))
        }
        ColumnKind::Decimal128 => {
            let dt = model.schema.field(idx).data_type().clone();
            ColumnBuilder::Decimal128(Decimal128Builder::new().with_data_type(dt))
        }
        ColumnKind::Decimal256 => {
            let dt = model.schema.field(idx).data_type().clone();
            ColumnBuilder::Decimal256(Decimal256Builder::new().with_data_type(dt))
        }
        ColumnKind::Utf8 => ColumnBuilder::Utf8 {
            builder: StringBuilder::new(),
            target_type: model.schema.field(idx).data_type().clone(),
        },
        ColumnKind::FixedSizeBinary(n) => {
            ColumnBuilder::FixedBinary(FixedSizeBinaryBuilder::new(n as i32))
        }
        ColumnKind::List(elem) => match elem {
            ListElementKind::Int64 => {
                ColumnBuilder::ListInt64(ListBuilder::new(Int64Builder::new()))
            }
            ListElementKind::Float64 => {
                ColumnBuilder::ListFloat64(ListBuilder::new(Float64Builder::new()))
            }
            ListElementKind::Boolean => {
                ColumnBuilder::ListBoolean(ListBuilder::new(BooleanBuilder::new()))
            }
            ListElementKind::Utf8 => {
                ColumnBuilder::ListUtf8(ListBuilder::new(StringBuilder::new()))
            }
        },
    }
}

fn archived_non_pk_value_is_valid(
    col: &ResolvedColumn,
    stored_opt: Option<&ArchivedStoredValue>,
) -> bool {
    let Some(stored) = stored_opt else {
        return col.nullable;
    };
    match (col.kind, stored) {
        (ColumnKind::Int64, ArchivedStoredValue::Int64(_)) => true,
        (ColumnKind::UInt64, ArchivedStoredValue::UInt64(_)) => true,
        (ColumnKind::Float64, ArchivedStoredValue::Float64(_)) => true,
        (ColumnKind::Float64, ArchivedStoredValue::Int64(_)) => true,
        (ColumnKind::Boolean, ArchivedStoredValue::Boolean(_)) => true,
        (ColumnKind::Date32, ArchivedStoredValue::Int64(_)) => true,
        (ColumnKind::Date64, ArchivedStoredValue::Int64(_)) => true,
        (ColumnKind::Timestamp, ArchivedStoredValue::Int64(_)) => true,
        (ColumnKind::Decimal128, ArchivedStoredValue::Bytes(bytes)) => bytes.as_slice().len() == 16,
        (ColumnKind::Decimal256, ArchivedStoredValue::Bytes(bytes)) => bytes.as_slice().len() == 32,
        (ColumnKind::Utf8, ArchivedStoredValue::Utf8(_)) => true,
        (ColumnKind::FixedSizeBinary(expected), ArchivedStoredValue::Bytes(bytes)) => {
            bytes.as_slice().len() == expected
        }
        (ColumnKind::List(ListElementKind::Int64), ArchivedStoredValue::List(items)) => items
            .iter()
            .all(|item| matches!(item, ArchivedStoredValue::Int64(_))),
        (ColumnKind::List(ListElementKind::Float64), ArchivedStoredValue::List(items)) => {
            items.iter().all(|item| {
                matches!(
                    item,
                    ArchivedStoredValue::Float64(_) | ArchivedStoredValue::Int64(_)
                )
            })
        }
        (ColumnKind::List(ListElementKind::Boolean), ArchivedStoredValue::List(items)) => items
            .iter()
            .all(|item| matches!(item, ArchivedStoredValue::Boolean(_))),
        (ColumnKind::List(ListElementKind::Utf8), ArchivedStoredValue::List(items)) => items
            .iter()
            .all(|item| matches!(item, ArchivedStoredValue::Utf8(_))),
        _ => false,
    }
}

fn append_archived_non_pk_value(
    builder: &mut ColumnBuilder,
    col: &ResolvedColumn,
    stored_opt: Option<&ArchivedStoredValue>,
) -> DataFusionResult<()> {
    let Some(stored) = stored_opt else {
        return builder.append(&CellValue::Null);
    };
    match (builder, col.kind, stored) {
        (ColumnBuilder::Int64(b), ColumnKind::Int64, ArchivedStoredValue::Int64(v)) => {
            b.append_value((*v).into())
        }
        (ColumnBuilder::UInt64(b), ColumnKind::UInt64, ArchivedStoredValue::UInt64(v)) => {
            b.append_value((*v).into())
        }
        (ColumnBuilder::Float64(b), ColumnKind::Float64, ArchivedStoredValue::Float64(v)) => {
            b.append_value((*v).into())
        }
        (ColumnBuilder::Float64(b), ColumnKind::Float64, ArchivedStoredValue::Int64(v)) => {
            b.append_value(i64::from(*v) as f64)
        }
        (ColumnBuilder::Boolean(b), ColumnKind::Boolean, ArchivedStoredValue::Boolean(v)) => {
            b.append_value(*v)
        }
        (ColumnBuilder::Date32(b), ColumnKind::Date32, ArchivedStoredValue::Int64(v)) => {
            b.append_value(i64::from(*v) as i32)
        }
        (ColumnBuilder::Date64(b), ColumnKind::Date64, ArchivedStoredValue::Int64(v)) => {
            b.append_value((*v).into())
        }
        (ColumnBuilder::Timestamp(b), ColumnKind::Timestamp, ArchivedStoredValue::Int64(v)) => {
            b.append_value((*v).into())
        }
        (
            ColumnBuilder::Decimal128(b),
            ColumnKind::Decimal128,
            ArchivedStoredValue::Bytes(bytes),
        ) => {
            let arr: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
                DataFusionError::Execution("invalid Decimal128 byte width".to_string())
            })?;
            b.append_value(i128::from_le_bytes(arr))
        }
        (
            ColumnBuilder::Decimal256(b),
            ColumnKind::Decimal256,
            ArchivedStoredValue::Bytes(bytes),
        ) => {
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                DataFusionError::Execution("invalid Decimal256 byte width".to_string())
            })?;
            b.append_value(i256::from_le_bytes(arr))
        }
        (ColumnBuilder::Utf8 { builder, .. }, ColumnKind::Utf8, ArchivedStoredValue::Utf8(v)) => {
            builder.append_value(v.as_str())
        }
        (
            ColumnBuilder::FixedBinary(b),
            ColumnKind::FixedSizeBinary(_),
            ArchivedStoredValue::Bytes(v),
        ) => b
            .append_value(v.as_slice())
            .map_err(|e| DataFusionError::Execution(format!("FixedBinary append error: {e}")))?,
        (
            ColumnBuilder::ListInt64(b),
            ColumnKind::List(ListElementKind::Int64),
            ArchivedStoredValue::List(items),
        ) => {
            for item in items.iter() {
                let ArchivedStoredValue::Int64(v) = item else {
                    return Err(DataFusionError::Execution(
                        "list element type mismatch".to_string(),
                    ));
                };
                b.values().append_value((*v).into());
            }
            b.append(true);
        }
        (
            ColumnBuilder::ListFloat64(b),
            ColumnKind::List(ListElementKind::Float64),
            ArchivedStoredValue::List(items),
        ) => {
            for item in items.iter() {
                match item {
                    ArchivedStoredValue::Float64(v) => b.values().append_value((*v).into()),
                    ArchivedStoredValue::Int64(v) => b.values().append_value(i64::from(*v) as f64),
                    _ => {
                        return Err(DataFusionError::Execution(
                            "list element type mismatch".to_string(),
                        ))
                    }
                }
            }
            b.append(true);
        }
        (
            ColumnBuilder::ListBoolean(b),
            ColumnKind::List(ListElementKind::Boolean),
            ArchivedStoredValue::List(items),
        ) => {
            for item in items.iter() {
                let ArchivedStoredValue::Boolean(v) = item else {
                    return Err(DataFusionError::Execution(
                        "list element type mismatch".to_string(),
                    ));
                };
                b.values().append_value(*v);
            }
            b.append(true);
        }
        (
            ColumnBuilder::ListUtf8(b),
            ColumnKind::List(ListElementKind::Utf8),
            ArchivedStoredValue::List(items),
        ) => {
            for item in items.iter() {
                let ArchivedStoredValue::Utf8(v) = item else {
                    return Err(DataFusionError::Execution(
                        "list element type mismatch".to_string(),
                    ));
                };
                b.values().append_value(v.as_str());
            }
            b.append(true);
        }
        _ => {
            return Err(DataFusionError::Execution(
                "column type mismatch".to_string(),
            ))
        }
    }
    Ok(())
}

#[derive(Clone)]
enum ProjectionSource {
    Pk { col_idx: usize, pk_pos: usize },
    NonPk { col_idx: usize, col: ResolvedColumn },
}

struct ProjectedBatchBuilder {
    sources: Vec<ProjectionSource>,
    builders: Vec<ColumnBuilder>,
    row_count: usize,
}

impl ProjectedBatchBuilder {
    fn from_access_plan(model: &TableModel, access_plan: &ScanAccessPlan) -> Self {
        let col_indices: Vec<usize> = access_plan
            .projection_sources
            .iter()
            .map(|source| match source {
                ProjectionSource::Pk { col_idx, .. } => *col_idx,
                ProjectionSource::NonPk { col_idx, .. } => *col_idx,
            })
            .collect();
        let builders = col_indices
            .iter()
            .map(|&idx| make_column_builder(model, idx))
            .collect();
        Self {
            sources: access_plan.projection_sources.clone(),
            builders,
            row_count: 0,
        }
    }

    fn append_archived_row(
        &mut self,
        pk_values: &[CellValue],
        archived: &ArchivedStoredRow,
    ) -> DataFusionResult<bool> {
        for source in &self.sources {
            match source {
                ProjectionSource::Pk { pk_pos, .. } => {
                    if pk_values.get(*pk_pos).is_none() {
                        return Ok(false);
                    }
                }
                ProjectionSource::NonPk { col_idx, col } => {
                    let stored_opt = archived.values.get(*col_idx).and_then(|v| v.as_ref());
                    if !archived_non_pk_value_is_valid(col, stored_opt) {
                        return Ok(false);
                    }
                }
            }
        }
        for (builder, source) in self.builders.iter_mut().zip(self.sources.iter()) {
            match source {
                ProjectionSource::Pk { pk_pos, .. } => {
                    let value = pk_values.get(*pk_pos).ok_or_else(|| {
                        DataFusionError::Execution("missing primary key value".to_string())
                    })?;
                    builder.append(value)?;
                }
                ProjectionSource::NonPk { col_idx, col } => {
                    let stored_opt = archived.values.get(*col_idx).and_then(|v| v.as_ref());
                    append_archived_non_pk_value(builder, col, stored_opt)?;
                }
            }
        }
        self.row_count += 1;
        Ok(true)
    }

    fn row_count(&self) -> usize {
        self.row_count
    }

    fn finish(self, projected_schema: &SchemaRef) -> DataFusionResult<RecordBatch> {
        let columns: Vec<ArrayRef> = self
            .builders
            .into_iter()
            .map(ColumnBuilder::finish)
            .collect::<DataFusionResult<Vec<_>>>()?;
        Ok(RecordBatch::try_new(projected_schema.clone(), columns)?)
    }
}

fn register_kv_table(
    ctx: &SessionContext,
    table_name: &str,
    client: StoreClient,
    config: KvTableConfig,
) -> DataFusionResult<()> {
    let table = Arc::new(
        KvTable::new(client, config)
            .map_err(|e| DataFusionError::Execution(format!("invalid table config: {e}")))?,
    );
    let _ = ctx.register_table(table_name, table)?;
    Ok(())
}

pub struct KvSchema {
    client: StoreClient,
    tables: Vec<(String, KvTableConfig)>,
    next_prefix: u8,
}

impl KvSchema {
    pub fn new(client: StoreClient) -> Self {
        Self {
            client,
            tables: Vec::new(),
            next_prefix: 0,
        }
    }

    pub fn table(
        mut self,
        name: impl Into<String>,
        columns: Vec<TableColumnConfig>,
        primary_key_columns: Vec<String>,
        index_specs: Vec<IndexSpec>,
    ) -> Result<Self, String> {
        if self.tables.len() >= MAX_TABLES {
            return Err(format!(
                "too many tables for codec layout (max {MAX_TABLES})"
            ));
        }
        let prefix = self.next_prefix;
        let config = KvTableConfig::new(prefix, columns, primary_key_columns, index_specs)?;
        self.tables.push((name.into(), config));
        self.next_prefix = self.next_prefix.wrapping_add(1);
        Ok(self)
    }

    pub fn orders_table(
        self,
        table_name: impl Into<String>,
        index_specs: Vec<IndexSpec>,
    ) -> Result<Self, String> {
        self.table(
            table_name,
            vec![
                TableColumnConfig::new("region", DataType::Utf8, false),
                TableColumnConfig::new("customer_id", DataType::Int64, false),
                TableColumnConfig::new("order_id", DataType::Int64, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
            ],
            vec!["order_id".to_string()],
            index_specs,
        )
    }

    /// Create a table with a versioned composite primary key.
    ///
    /// The entity column and version column (UInt64) together form the
    /// composite primary key. The entity can be any supported primary-key
    /// type, including variable-length logical keys encoded through the
    /// crate's ordered variable-length `Utf8` mapping.
    ///
    /// Versions sort
    /// numerically via big-endian encoding, so a reverse range scan
    /// from `(entity, V)` downward with LIMIT 1 yields the latest
    /// version <= V. See `examples/versioned_kv.rs` for the basic
    /// query pattern plus an immutable-friendly companion watermark
    /// table pattern for out-of-order batch uploads.
    pub fn table_versioned(
        self,
        name: impl Into<String>,
        columns: Vec<TableColumnConfig>,
        entity_column: impl Into<String>,
        version_column: impl Into<String>,
        index_specs: Vec<IndexSpec>,
    ) -> Result<Self, String> {
        let entity = entity_column.into();
        let version = version_column.into();
        self.table(name, columns, vec![entity, version], index_specs)
    }

    pub fn table_count(&self) -> usize {
        self.tables.len()
    }

    pub fn register_all(self, ctx: &SessionContext) -> DataFusionResult<()> {
        let _ = ctx.remove_optimizer_rule("kv_aggregate_pushdown");
        ctx.add_optimizer_rule(Arc::new(KvAggregatePushdownRule::new()));
        for (name, config) in &self.tables {
            register_kv_table(ctx, name, self.client.clone(), config.clone())?;
        }
        Ok(())
    }

    pub fn batch_writer(&self) -> BatchWriter {
        BatchWriter::new(self.client.clone(), &self.tables)
    }

    /// Backfill secondary index entries after adding new index specs.
    ///
    /// `previous_index_specs` must represent the index list used when existing
    /// rows were written. The current schema's index list must be an append-only
    /// extension of that list (same order/layout for existing indexes, with new
    /// indexes only added at the tail).
    ///
    /// Operational ordering requirement: start writing new rows with the new
    /// index specs before backfilling historical rows, or rows written during
    /// the backfill window may be missing from the new index.
    pub async fn backfill_added_indexes(
        &self,
        table_name: &str,
        previous_index_specs: &[IndexSpec],
    ) -> DataFusionResult<IndexBackfillReport> {
        self.backfill_added_indexes_with_options(
            table_name,
            previous_index_specs,
            IndexBackfillOptions::default(),
        )
        .await
    }

    /// Backfill secondary index entries after adding new index specs, with
    /// configurable row page size for the full-scan read.
    pub async fn backfill_added_indexes_with_options(
        &self,
        table_name: &str,
        previous_index_specs: &[IndexSpec],
        options: IndexBackfillOptions,
    ) -> DataFusionResult<IndexBackfillReport> {
        self.backfill_added_indexes_with_options_and_progress(
            table_name,
            previous_index_specs,
            options,
            None,
        )
        .await
    }

    /// Backfill secondary index entries after adding new index specs, with
    /// configurable row page size for the full-scan read and an optional
    /// progress event channel.
    ///
    /// Progress events are emitted only after buffered ingest writes for the
    /// reported cursor are flushed, so `Progress.next_cursor` can be persisted
    /// and used to resume later.
    pub async fn backfill_added_indexes_with_options_and_progress(
        &self,
        table_name: &str,
        previous_index_specs: &[IndexSpec],
        options: IndexBackfillOptions,
        progress_tx: Option<&tokio::sync::mpsc::UnboundedSender<IndexBackfillEvent>>,
    ) -> DataFusionResult<IndexBackfillReport> {
        if options.row_batch_size == 0 {
            return Err(DataFusionError::Execution(
                "index backfill row_batch_size must be > 0".to_string(),
            ));
        }

        let config = self
            .tables
            .iter()
            .find(|(name, _)| name == table_name)
            .map(|(_, config)| config.clone())
            .ok_or_else(|| {
                DataFusionError::Execution(format!(
                    "unknown table '{table_name}' for index backfill"
                ))
            })?;

        let model = TableModel::from_config(&config)
            .map_err(|e| DataFusionError::Execution(format!("invalid table config: {e}")))?;
        let current_specs = model
            .resolve_index_specs(&config.index_specs)
            .map_err(|e| DataFusionError::Execution(format!("invalid index specs: {e}")))?;
        let previous_specs = model
            .resolve_index_specs(previous_index_specs)
            .map_err(|e| {
                DataFusionError::Execution(format!("invalid previous index specs: {e}"))
            })?;

        if previous_specs.len() > current_specs.len() {
            return Err(DataFusionError::Execution(format!(
                "table '{table_name}' previous index count ({}) exceeds current index count ({})",
                previous_specs.len(),
                current_specs.len()
            )));
        }
        for (idx, previous) in previous_specs.iter().enumerate() {
            let current = &current_specs[idx];
            if !resolved_index_layout_matches(previous, current) {
                return Err(DataFusionError::Execution(format!(
                    "table '{table_name}' index evolution must be append-only; index at position {} changed",
                    idx + 1
                )));
            }
        }

        let full_range = primary_key_prefix_range(model.table_prefix);
        let mut cursor = options
            .start_from_primary_key
            .unwrap_or_else(|| full_range.start.clone());
        if !model.primary_key_codec.matches(&cursor) {
            return Err(DataFusionError::Execution(
                "index backfill start_from_primary_key must use this table's primary-key prefix"
                    .to_string(),
            ));
        }
        if cursor < full_range.start || cursor > full_range.end {
            return Err(DataFusionError::Execution(
                "index backfill start_from_primary_key is outside table key range".to_string(),
            ));
        }

        let new_specs = current_specs[previous_specs.len()..].to_vec();
        if new_specs.is_empty() {
            let report = IndexBackfillReport::default();
            send_backfill_event(
                progress_tx,
                IndexBackfillEvent::Started {
                    table_name: table_name.to_string(),
                    indexes_backfilled: 0,
                    row_batch_size: options.row_batch_size,
                    start_cursor: cursor.clone(),
                },
            );
            send_backfill_event(progress_tx, IndexBackfillEvent::Completed { report });
            return Ok(report);
        }

        let mut report = IndexBackfillReport {
            scanned_rows: 0,
            indexes_backfilled: new_specs.len(),
            index_entries_written: 0,
        };
        let mut pending_keys = Vec::new();
        let mut pending_values = Vec::new();
        let session = self.client.create_session();
        let decode_pk_mask = vec![true; model.primary_key_kinds.len()];
        send_backfill_event(
            progress_tx,
            IndexBackfillEvent::Started {
                table_name: table_name.to_string(),
                indexes_backfilled: new_specs.len(),
                row_batch_size: options.row_batch_size,
                start_cursor: cursor.clone(),
            },
        );

        loop {
            let mut stream = session
                .range_stream(
                    &cursor,
                    &full_range.end,
                    options.row_batch_size,
                    options.row_batch_size,
                )
                .await
                .map_err(|e| DataFusionError::External(Box::new(e)))?;
            let mut last_key = None;
            while let Some(chunk) = stream
                .next_chunk()
                .await
                .map_err(|e| DataFusionError::External(Box::new(e)))?
            {
                for (base_key, base_value) in &chunk {
                    last_key = Some(base_key.clone());
                    let Some(pk_values) = decode_primary_key_selected(
                        model.table_prefix,
                        base_key,
                        &model,
                        &decode_pk_mask,
                    ) else {
                        return Err(DataFusionError::Execution(format!(
                            "invalid primary key while backfilling index (key={})",
                            hex::encode(base_key)
                        )));
                    };
                    let archived = access_stored_row(base_value).map_err(|e| {
                        DataFusionError::Execution(format!(
                            "invalid base row payload while backfilling index (key={}): {e}",
                            hex::encode(base_key)
                        ))
                    })?;
                    if archived.values.len() != model.columns.len() {
                        return Err(DataFusionError::Execution(format!(
                            "invalid base row payload while backfilling index (key={})",
                            hex::encode(base_key)
                        )));
                    }
                    report.scanned_rows += 1;

                    for spec in &new_specs {
                        let index_key = encode_secondary_index_key_from_parts(
                            model.table_prefix,
                            spec,
                            &model,
                            &pk_values,
                            archived,
                        )?;
                        let index_value =
                            encode_secondary_index_value_from_archived(archived, &model, spec)?;
                        pending_keys.push(index_key);
                        pending_values.push(index_value);
                        report.index_entries_written += 1;
                    }

                    if pending_keys.len() >= INDEX_BACKFILL_FLUSH_ENTRIES {
                        flush_ingest_batch(&self.client, &mut pending_keys, &mut pending_values)
                            .await?;
                    }
                }
            }
            let Some(last_key) = last_key else {
                break;
            };

            let next_cursor = if last_key >= full_range.end {
                None
            } else {
                next_key(&last_key)
            };
            if !pending_keys.is_empty() {
                flush_ingest_batch(&self.client, &mut pending_keys, &mut pending_values).await?;
            }
            send_backfill_event(
                progress_tx,
                IndexBackfillEvent::Progress {
                    scanned_rows: report.scanned_rows,
                    index_entries_written: report.index_entries_written,
                    last_scanned_primary_key: last_key,
                    next_cursor: next_cursor.clone(),
                },
            );

            if let Some(next) = next_cursor {
                cursor = next;
            } else {
                break;
            }
        }

        if !pending_keys.is_empty() {
            flush_ingest_batch(&self.client, &mut pending_keys, &mut pending_values).await?;
        }
        send_backfill_event(progress_tx, IndexBackfillEvent::Completed { report });
        Ok(report)
    }
}

fn send_backfill_event(
    progress_tx: Option<&tokio::sync::mpsc::UnboundedSender<IndexBackfillEvent>>,
    event: IndexBackfillEvent,
) {
    if let Some(tx) = progress_tx {
        let _ = tx.send(event);
    }
}

fn resolved_index_layout_matches(
    previous: &ResolvedIndexSpec,
    current: &ResolvedIndexSpec,
) -> bool {
    previous.id == current.id
        && previous.name == current.name
        && previous.layout == current.layout
        && previous.key_columns == current.key_columns
        && previous.value_column_mask == current.value_column_mask
        && previous.key_columns_width == current.key_columns_width
}

#[derive(Debug)]
pub struct TableWriter {
    model: Arc<TableModel>,
    index_specs: Arc<Vec<ResolvedIndexSpec>>,
}

impl TableWriter {
    pub fn encode_row(&self, values: Vec<CellValue>) -> Result<Vec<(Key, Vec<u8>)>, String> {
        let row = KvRow { values };
        if row.values.len() != self.model.columns.len() {
            return Err(format!(
                "expected {} values, got {}",
                self.model.columns.len(),
                row.values.len()
            ));
        }
        let base_key = encode_primary_key_from_row(self.model.table_prefix, &row, &self.model)?;
        let base_value = encode_base_row_value(&row, &self.model).map_err(|e| format!("{e}"))?;
        let mut out = vec![(base_key, base_value)];
        for spec in self.index_specs.iter() {
            let idx_key =
                encode_secondary_index_key(self.model.table_prefix, spec, &self.model, &row)?;
            let idx_value = encode_secondary_index_value(&row, &self.model, spec)
                .map_err(|e| format!("{e}"))?;
            out.push((idx_key, idx_value));
        }
        Ok(out)
    }
}

#[derive(Debug)]
pub struct BatchWriter {
    client: StoreClient,
    tables: HashMap<String, TableWriter>,
    pending_keys: Vec<Key>,
    pending_values: Vec<Vec<u8>>,
}

impl BatchWriter {
    fn new(client: StoreClient, table_configs: &[(String, KvTableConfig)]) -> Self {
        let mut tables = HashMap::new();
        for (name, config) in table_configs {
            let model = Arc::new(
                TableModel::from_config(config).expect("config already validated by KvSchema"),
            );
            let index_specs = Arc::new(
                model
                    .resolve_index_specs(&config.index_specs)
                    .expect("specs already validated by KvSchema"),
            );
            tables.insert(name.clone(), TableWriter { model, index_specs });
        }
        Self {
            client,
            tables,
            pending_keys: Vec::new(),
            pending_values: Vec::new(),
        }
    }

    pub fn insert(
        &mut self,
        table_name: &str,
        values: Vec<CellValue>,
    ) -> Result<&mut Self, String> {
        let writer = self
            .tables
            .get(table_name)
            .ok_or_else(|| format!("unknown table '{table_name}'"))?;
        let entries = writer.encode_row(values)?;
        for (key, value) in entries {
            self.pending_keys.push(key);
            self.pending_values.push(value);
        }
        Ok(self)
    }

    pub fn pending_count(&self) -> usize {
        self.pending_keys.len()
    }

    /// Flush pending rows to ingest and return the post-ingest consistency token.
    pub async fn flush(&mut self) -> DataFusionResult<u64> {
        if self.pending_keys.is_empty() {
            return Ok(0);
        }
        flush_ingest_batch(
            &self.client,
            &mut self.pending_keys,
            &mut self.pending_values,
        )
        .await
    }
}

#[async_trait]
impl TableProvider for KvTable {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.model.schema.clone()
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> DataFusionResult<Vec<TableProviderFilterPushDown>> {
        Ok(filters
            .iter()
            .map(|expr| {
                if QueryPredicate::supports_filter(expr, &self.model) {
                    TableProviderFilterPushDown::Exact
                } else {
                    TableProviderFilterPushDown::Unsupported
                }
            })
            .collect())
    }

    async fn scan(
        &self,
        _state: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        let predicate = QueryPredicate::from_filters(filters, &self.model);
        let projected_schema = match projection {
            Some(proj) => Arc::new(self.model.schema.project(proj)?),
            None => self.model.schema.clone(),
        };
        Ok(Arc::new(KvScanExec::new(
            self.client.clone(),
            self.model.clone(),
            self.index_specs.clone(),
            predicate,
            limit,
            projected_schema,
            projection.cloned(),
        )))
    }

    async fn insert_into(
        &self,
        _state: &dyn Session,
        input: Arc<dyn ExecutionPlan>,
        insert_op: InsertOp,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        self.schema()
            .logically_equivalent_names_and_types(&input.schema())?;
        if insert_op != InsertOp::Append {
            return Err(DataFusionError::NotImplemented(format!(
                "{insert_op} not implemented for kv table"
            )));
        }

        let sink = KvIngestSink::new(
            self.client.clone(),
            self.model.schema.clone(),
            self.model.clone(),
            self.index_specs.clone(),
        );
        Ok(Arc::new(DataSinkExec::new(input, Arc::new(sink), None)))
    }
}

#[derive(Debug)]
struct KvIngestSink {
    client: StoreClient,
    schema: SchemaRef,
    model: Arc<TableModel>,
    index_specs: Arc<Vec<ResolvedIndexSpec>>,
}

impl KvIngestSink {
    fn new(
        client: StoreClient,
        schema: SchemaRef,
        model: Arc<TableModel>,
        index_specs: Arc<Vec<ResolvedIndexSpec>>,
    ) -> Self {
        Self {
            client,
            schema,
            model,
            index_specs,
        }
    }
}

impl DisplayAs for KvIngestSink {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KvIngestSink")
    }
}

#[async_trait]
impl DataSink for KvIngestSink {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> &SchemaRef {
        &self.schema
    }

    async fn write_all(
        &self,
        data: SendableRecordBatchStream,
        _context: &Arc<TaskContext>,
    ) -> DataFusionResult<u64> {
        let mut data = data;
        let mut pending_keys: Vec<Key> = Vec::new();
        let mut pending_values: Vec<Vec<u8>> = Vec::new();
        let mut logical_rows_written = 0u64;

        while let Some(batch) = data.try_next().await? {
            let encoded_entries = encode_insert_entries(&batch, &self.model, &self.index_specs)?;
            logical_rows_written += batch.num_rows() as u64;
            for (key, value) in encoded_entries {
                pending_keys.push(key);
                pending_values.push(value);
            }
        }

        if !pending_keys.is_empty() {
            flush_ingest_batch(&self.client, &mut pending_keys, &mut pending_values).await?;
        }
        Ok(logical_rows_written)
    }
}

fn encode_insert_entries(
    batch: &RecordBatch,
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
) -> DataFusionResult<Vec<(Key, Vec<u8>)>> {
    let mut out = Vec::with_capacity(batch.num_rows() * (1 + index_specs.len()));
    for row_idx in 0..batch.num_rows() {
        let row = extract_row_from_batch(batch, row_idx, model)?;
        let base_key = encode_primary_key_from_row(model.table_prefix, &row, model)
            .map_err(DataFusionError::Execution)?;
        let base_value = encode_base_row_value(&row, model)?;
        out.push((base_key, base_value));

        for spec in index_specs {
            let secondary_key = encode_secondary_index_key(model.table_prefix, spec, model, &row)
                .map_err(DataFusionError::Execution)?;
            let secondary_value = encode_secondary_index_value(&row, model, spec)?;
            out.push((secondary_key, secondary_value));
        }
    }
    Ok(out)
}

fn extract_row_from_batch(
    batch: &RecordBatch,
    row_idx: usize,
    model: &TableModel,
) -> DataFusionResult<KvRow> {
    let mut values = Vec::with_capacity(model.columns.len());
    for col in &model.columns {
        let array = required_column(batch, &col.name)?;
        if col.nullable && array.is_null(row_idx) {
            values.push(CellValue::Null);
            continue;
        }
        let value = match col.kind {
            ColumnKind::Int64 => CellValue::Int64(i64_value_at(array, row_idx, &col.name)?),
            ColumnKind::UInt64 => CellValue::UInt64(uint64_value_at(array, row_idx, &col.name)?),
            ColumnKind::Float64 => CellValue::Float64(f64_value_at(array, row_idx, &col.name)?),
            ColumnKind::Boolean => CellValue::Boolean(bool_value_at(array, row_idx, &col.name)?),
            ColumnKind::Date32 => CellValue::Date32(date32_value_at(array, row_idx, &col.name)?),
            ColumnKind::Date64 => CellValue::Date64(date64_value_at(array, row_idx, &col.name)?),
            ColumnKind::Timestamp => {
                CellValue::Timestamp(timestamp_micros_value_at(array, row_idx, &col.name)?)
            }
            ColumnKind::Decimal128 => {
                CellValue::Decimal128(decimal128_value_at(array, row_idx, &col.name)?)
            }
            ColumnKind::Decimal256 => {
                CellValue::Decimal256(decimal256_value_at(array, row_idx, &col.name)?)
            }
            ColumnKind::Utf8 => CellValue::Utf8(string_value_at(array, row_idx, &col.name)?),
            ColumnKind::FixedSizeBinary(_) => {
                CellValue::FixedBinary(fixed_binary_value_at(array, row_idx, &col.name)?)
            }
            ColumnKind::List(elem) => list_value_at(array, row_idx, &col.name, elem)?,
        };
        values.push(value);
    }
    Ok(KvRow { values })
}

fn encode_base_row_value(row: &KvRow, model: &TableModel) -> DataFusionResult<Vec<u8>> {
    let mut values = Vec::with_capacity(model.columns.len());
    for (idx, col) in model.columns.iter().enumerate() {
        if model.is_pk_column(idx) {
            values.push(None);
            continue;
        }
        values.push(encode_non_pk_cell_value(row.value_at(idx), col)?);
    }
    let stored_row = StoredRow { values };
    rkyv::to_bytes::<rkyv::rancor::Error>(&stored_row)
        .map(|v| v.to_vec())
        .map_err(|e| DataFusionError::Execution(format!("rkyv serialize error: {e}")))
}

fn encode_secondary_index_value(
    row: &KvRow,
    model: &TableModel,
    spec: &ResolvedIndexSpec,
) -> DataFusionResult<Vec<u8>> {
    let mut values = Vec::with_capacity(model.columns.len());
    for (idx, col) in model.columns.iter().enumerate() {
        if model.is_pk_column(idx) || !spec.value_column_mask[idx] {
            values.push(None);
            continue;
        }
        values.push(encode_non_pk_cell_value(row.value_at(idx), col)?);
    }
    let stored_row = StoredRow { values };
    rkyv::to_bytes::<rkyv::rancor::Error>(&stored_row)
        .map(|v| v.to_vec())
        .map_err(|e| DataFusionError::Execution(format!("rkyv serialize error: {e}")))
}

fn encode_secondary_index_value_from_archived(
    archived: &ArchivedStoredRow,
    model: &TableModel,
    spec: &ResolvedIndexSpec,
) -> DataFusionResult<Vec<u8>> {
    if archived.values.len() != model.columns.len() {
        return Err(DataFusionError::Execution(
            "archived row column count mismatch".to_string(),
        ));
    }
    let mut values = Vec::with_capacity(model.columns.len());
    for (idx, col) in model.columns.iter().enumerate() {
        if model.is_pk_column(idx) || !spec.value_column_mask[idx] {
            values.push(None);
            continue;
        }
        let stored_opt = archived.values.get(idx).and_then(|value| value.as_ref());
        if !archived_non_pk_value_is_valid(col, stored_opt) {
            return Err(DataFusionError::Execution(format!(
                "invalid archived value for secondary index column '{}'",
                col.name
            )));
        }
        values.push(owned_stored_value_from_archived(stored_opt)?);
    }
    let stored_row = StoredRow { values };
    rkyv::to_bytes::<rkyv::rancor::Error>(&stored_row)
        .map(|v| v.to_vec())
        .map_err(|e| DataFusionError::Execution(format!("rkyv serialize error: {e}")))
}

fn encode_non_pk_cell_value(
    value: &CellValue,
    col: &ResolvedColumn,
) -> DataFusionResult<Option<StoredValue>> {
    match (col.kind, value) {
        (_, CellValue::Null) => {
            if !col.nullable {
                return Err(DataFusionError::Execution(format!(
                    "column '{}' is not nullable but received NULL",
                    col.name
                )));
            }
            Ok(None)
        }
        (ColumnKind::Int64, CellValue::Int64(v)) => Ok(Some(StoredValue::Int64(*v))),
        (ColumnKind::UInt64, CellValue::UInt64(v)) => Ok(Some(StoredValue::UInt64(*v))),
        (ColumnKind::Float64, CellValue::Float64(v)) => Ok(Some(StoredValue::Float64(*v))),
        (ColumnKind::Boolean, CellValue::Boolean(v)) => Ok(Some(StoredValue::Boolean(*v))),
        (ColumnKind::Date32, CellValue::Date32(v)) => Ok(Some(StoredValue::Int64(*v as i64))),
        (ColumnKind::Date64, CellValue::Date64(v)) => Ok(Some(StoredValue::Int64(*v))),
        (ColumnKind::Timestamp, CellValue::Timestamp(v)) => Ok(Some(StoredValue::Int64(*v))),
        (ColumnKind::Decimal128, CellValue::Decimal128(v)) => {
            Ok(Some(StoredValue::Bytes(v.to_le_bytes().to_vec())))
        }
        (ColumnKind::Decimal256, CellValue::Decimal256(v)) => {
            Ok(Some(StoredValue::Bytes(v.to_le_bytes().to_vec())))
        }
        (ColumnKind::Utf8, CellValue::Utf8(v)) => Ok(Some(StoredValue::Utf8(v.clone()))),
        (ColumnKind::FixedSizeBinary(n), CellValue::FixedBinary(v)) => {
            if v.len() != n {
                return Err(DataFusionError::Execution(format!(
                    "column '{}' expects FixedSizeBinary({n}) value with exactly {n} bytes, got {}",
                    col.name,
                    v.len()
                )));
            }
            Ok(Some(StoredValue::Bytes(v.clone())))
        }
        (ColumnKind::List(elem), CellValue::List(items)) => {
            let mut stored_items = Vec::with_capacity(items.len());
            for item in items {
                let stored_item = match (elem, item) {
                    (ListElementKind::Int64, CellValue::Int64(v)) => StoredValue::Int64(*v),
                    (ListElementKind::Float64, CellValue::Float64(v)) => StoredValue::Float64(*v),
                    (ListElementKind::Boolean, CellValue::Boolean(v)) => StoredValue::Boolean(*v),
                    (ListElementKind::Utf8, CellValue::Utf8(v)) => StoredValue::Utf8(v.clone()),
                    _ => {
                        return Err(DataFusionError::Execution(format!(
                            "column '{}' list element type mismatch (expected {:?}, got {:?})",
                            col.name, elem, item
                        )))
                    }
                };
                stored_items.push(stored_item);
            }
            Ok(Some(StoredValue::List(stored_items)))
        }
        _ => Err(DataFusionError::Execution(format!(
            "column '{}' type mismatch (expected {:?}, got {:?})",
            col.name, col.kind, value
        ))),
    }
}

fn owned_stored_value_from_archived(
    stored_opt: Option<&ArchivedStoredValue>,
) -> DataFusionResult<Option<StoredValue>> {
    let Some(stored) = stored_opt else {
        return Ok(None);
    };
    Ok(Some(match stored {
        ArchivedStoredValue::Int64(v) => StoredValue::Int64((*v).into()),
        ArchivedStoredValue::UInt64(v) => StoredValue::UInt64((*v).into()),
        ArchivedStoredValue::Float64(v) => StoredValue::Float64((*v).into()),
        ArchivedStoredValue::Boolean(v) => StoredValue::Boolean(*v),
        ArchivedStoredValue::Utf8(v) => StoredValue::Utf8(v.as_str().to_string()),
        ArchivedStoredValue::Bytes(v) => StoredValue::Bytes(v.as_slice().to_vec()),
        ArchivedStoredValue::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items.iter() {
                let owned = owned_stored_value_from_archived(Some(item))?.ok_or_else(|| {
                    DataFusionError::Execution(
                        "archived list item unexpectedly decoded as NULL".to_string(),
                    )
                })?;
                out.push(owned);
            }
            StoredValue::List(out)
        }
    }))
}

#[cfg(test)]
fn decode_base_row(pk_values: Vec<CellValue>, value: &[u8], model: &TableModel) -> Option<KvRow> {
    if pk_values.len() != model.primary_key_indices.len() {
        return None;
    }
    let archived = access_stored_row(value).ok()?;
    if archived.values.len() != model.columns.len() {
        return None;
    }
    let mut values = vec![CellValue::Null; model.columns.len()];
    for (pk_pos, pk_value) in pk_values.into_iter().enumerate() {
        let col_idx = *model.primary_key_indices.get(pk_pos)?;
        values[col_idx] = pk_value;
    }

    for (idx, col) in model.columns.iter().enumerate() {
        if model.is_pk_column(idx) {
            continue;
        }
        let Some(stored) = archived.values[idx].as_ref() else {
            if col.nullable {
                continue;
            }
            return None;
        };
        values[idx] = match (col.kind, stored) {
            (ColumnKind::Int64, ArchivedStoredValue::Int64(v)) => CellValue::Int64((*v).into()),
            (ColumnKind::UInt64, ArchivedStoredValue::UInt64(v)) => CellValue::UInt64((*v).into()),
            (ColumnKind::Float64, ArchivedStoredValue::Float64(v)) => {
                CellValue::Float64((*v).into())
            }
            (ColumnKind::Float64, ArchivedStoredValue::Int64(v)) => {
                CellValue::Float64(i64::from(*v) as f64)
            }
            (ColumnKind::Boolean, ArchivedStoredValue::Boolean(v)) => CellValue::Boolean(*v),
            (ColumnKind::Date32, ArchivedStoredValue::Int64(v)) => {
                CellValue::Date32(i64::from(*v) as i32)
            }
            (ColumnKind::Date64, ArchivedStoredValue::Int64(v)) => CellValue::Date64((*v).into()),
            (ColumnKind::Timestamp, ArchivedStoredValue::Int64(v)) => {
                CellValue::Timestamp((*v).into())
            }
            (ColumnKind::Decimal128, ArchivedStoredValue::Bytes(bytes)) => {
                let arr: [u8; 16] = bytes.as_slice().try_into().ok()?;
                CellValue::Decimal128(i128::from_le_bytes(arr))
            }
            (ColumnKind::Decimal256, ArchivedStoredValue::Bytes(bytes)) => {
                let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
                CellValue::Decimal256(i256::from_le_bytes(arr))
            }
            (ColumnKind::Utf8, ArchivedStoredValue::Utf8(v)) => {
                CellValue::Utf8(v.as_str().to_string())
            }
            (ColumnKind::FixedSizeBinary(_), ArchivedStoredValue::Bytes(v)) => {
                CellValue::FixedBinary(v.as_slice().to_vec())
            }
            (ColumnKind::List(elem), ArchivedStoredValue::List(items)) => {
                let mut cells = Vec::with_capacity(items.len());
                for item in items.iter() {
                    cells.push(decode_list_element_archived(elem, item)?);
                }
                CellValue::List(cells)
            }
            _ => return None,
        };
    }
    Some(KvRow { values })
}

fn decode_list_element_archived(
    elem: ListElementKind,
    stored: &ArchivedStoredValue,
) -> Option<CellValue> {
    Some(match (elem, stored) {
        (ListElementKind::Int64, ArchivedStoredValue::Int64(v)) => CellValue::Int64((*v).into()),
        (ListElementKind::Float64, ArchivedStoredValue::Float64(v)) => {
            CellValue::Float64((*v).into())
        }
        (ListElementKind::Float64, ArchivedStoredValue::Int64(v)) => {
            CellValue::Float64(i64::from(*v) as f64)
        }
        (ListElementKind::Boolean, ArchivedStoredValue::Boolean(v)) => CellValue::Boolean(*v),
        (ListElementKind::Utf8, ArchivedStoredValue::Utf8(v)) => {
            CellValue::Utf8(v.as_str().to_string())
        }
        _ => return None,
    })
}

fn required_column<'a>(batch: &'a RecordBatch, name: &str) -> DataFusionResult<&'a ArrayRef> {
    batch.column_by_name(name).ok_or_else(|| {
        DataFusionError::Execution(format!("insert batch is missing required column '{name}'"))
    })
}

fn i64_value_at(array: &ArrayRef, row_idx: usize, column_name: &str) -> DataFusionResult<i64> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array.as_any().downcast_ref::<Int64Array>().ok_or_else(|| {
        DataFusionError::Execution(format!(
            "column '{column_name}' expected Int64, got {:?}",
            array.data_type()
        ))
    })?;
    Ok(values.value(row_idx))
}

fn string_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
) -> DataFusionResult<String> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    if let Some(values) = array.as_any().downcast_ref::<StringArray>() {
        return Ok(values.value(row_idx).to_string());
    }
    if let Some(values) = array.as_any().downcast_ref::<LargeStringArray>() {
        return Ok(values.value(row_idx).to_string());
    }
    if let Some(values) = array.as_any().downcast_ref::<StringViewArray>() {
        return Ok(values.value(row_idx).to_string());
    }
    Err(DataFusionError::Execution(format!(
        "column '{column_name}' expected string, got {:?}",
        array.data_type()
    )))
}

fn f64_value_at(array: &ArrayRef, row_idx: usize, column_name: &str) -> DataFusionResult<f64> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<Float64Array>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected Float64, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

fn bool_value_at(array: &ArrayRef, row_idx: usize, column_name: &str) -> DataFusionResult<bool> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<BooleanArray>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected Boolean, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

fn date32_value_at(array: &ArrayRef, row_idx: usize, column_name: &str) -> DataFusionResult<i32> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<Date32Array>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected Date32, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

fn date64_value_at(array: &ArrayRef, row_idx: usize, column_name: &str) -> DataFusionResult<i64> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<Date64Array>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected Date64, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

fn timestamp_micros_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
) -> DataFusionResult<i64> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected TimestampMicrosecond, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

fn decimal128_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
) -> DataFusionResult<i128> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<Decimal128Array>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected Decimal128, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

fn uint64_value_at(array: &ArrayRef, row_idx: usize, column_name: &str) -> DataFusionResult<u64> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected UInt64, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

fn decimal256_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
) -> DataFusionResult<i256> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<Decimal256Array>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected Decimal256, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx))
}

fn fixed_binary_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
) -> DataFusionResult<Vec<u8>> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let values = array
        .as_any()
        .downcast_ref::<FixedSizeBinaryArray>()
        .ok_or_else(|| {
            DataFusionError::Execution(format!(
                "column '{column_name}' expected FixedSizeBinary, got {:?}",
                array.data_type()
            ))
        })?;
    Ok(values.value(row_idx).to_vec())
}

fn list_value_at(
    array: &ArrayRef,
    row_idx: usize,
    column_name: &str,
    elem: ListElementKind,
) -> DataFusionResult<CellValue> {
    if array.is_null(row_idx) {
        return Err(DataFusionError::Execution(format!(
            "column '{column_name}' cannot be NULL for kv table insert"
        )));
    }
    let list_array = array.as_any().downcast_ref::<ListArray>().ok_or_else(|| {
        DataFusionError::Execution(format!(
            "column '{column_name}' expected List, got {:?}",
            array.data_type()
        ))
    })?;
    let child = list_array.value(row_idx);
    let mut items = Vec::with_capacity(child.len());
    for i in 0..child.len() {
        let item = match elem {
            ListElementKind::Int64 => {
                let arr = child.as_any().downcast_ref::<Int64Array>().ok_or_else(|| {
                    DataFusionError::Execution(format!(
                        "column '{column_name}' list element expected Int64"
                    ))
                })?;
                CellValue::Int64(arr.value(i))
            }
            ListElementKind::Float64 => {
                let arr = child
                    .as_any()
                    .downcast_ref::<Float64Array>()
                    .ok_or_else(|| {
                        DataFusionError::Execution(format!(
                            "column '{column_name}' list element expected Float64"
                        ))
                    })?;
                CellValue::Float64(arr.value(i))
            }
            ListElementKind::Boolean => {
                let arr = child
                    .as_any()
                    .downcast_ref::<BooleanArray>()
                    .ok_or_else(|| {
                        DataFusionError::Execution(format!(
                            "column '{column_name}' list element expected Boolean"
                        ))
                    })?;
                CellValue::Boolean(arr.value(i))
            }
            ListElementKind::Utf8 => {
                let arr = child
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .ok_or_else(|| {
                        DataFusionError::Execution(format!(
                            "column '{column_name}' list element expected Utf8"
                        ))
                    })?;
                CellValue::Utf8(arr.value(i).to_string())
            }
        };
        items.push(item);
    }
    Ok(CellValue::List(items))
}

async fn flush_ingest_batch(
    client: &StoreClient,
    keys: &mut Vec<Key>,
    values: &mut Vec<Vec<u8>>,
) -> DataFusionResult<u64> {
    if keys.is_empty() {
        return Ok(0);
    }
    let refs: Vec<(&Key, &[u8])> = keys
        .iter()
        .zip(values.iter())
        .map(|(key, value)| (key, value.as_slice()))
        .collect();
    let token = client
        .put(&refs)
        .await
        .map_err(|e| DataFusionError::External(Box::new(e)))?;
    keys.clear();
    values.clear();
    Ok(token)
}

#[derive(Debug, Clone)]
enum PredicateConstraint {
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
struct QueryPredicate {
    constraints: HashMap<usize, PredicateConstraint>,
    contradiction: bool,
}

impl QueryPredicate {
    fn from_filters(filters: &[Expr], model: &TableModel) -> Self {
        let mut out = Self::default();
        for expr in filters {
            out.apply_supported_expr(expr, model);
        }
        out
    }

    fn apply_supported_expr(&mut self, expr: &Expr, model: &TableModel) {
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

    fn in_list_literal_supported(kind: ColumnKind, literal: &ScalarValue) -> bool {
        match kind {
            ColumnKind::Utf8 => scalar_to_string(literal).is_some(),
            ColumnKind::Int64 => scalar_to_i64(literal).is_some(),
            ColumnKind::UInt64 => scalar_to_u64(literal).is_some(),
            ColumnKind::FixedSizeBinary(_) => scalar_to_fixed_binary(literal).is_some(),
            _ => false,
        }
    }

    fn in_list_expr_supported(kind: ColumnKind, expr: &Expr) -> bool {
        extract_literal(expr).is_some_and(|literal| Self::in_list_literal_supported(kind, literal))
    }

    fn supports_filter(expr: &Expr, model: &TableModel) -> bool {
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

    fn apply_expr(&mut self, expr: &Expr, model: &TableModel) {
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

    fn apply_comparison(
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

    fn apply_in_list(&mut self, column: &str, list: &[Expr], model: &TableModel) {
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

    fn choose_index_plan(
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

    fn index_covers_required_non_pk(&self, model: &TableModel, spec: &ResolvedIndexSpec) -> bool {
        self.constraints
            .keys()
            .copied()
            .filter(|col_idx| model.pk_position(*col_idx).is_none())
            .all(|col_idx| spec.value_column_mask[col_idx] || spec.key_columns.contains(&col_idx))
    }

    fn expand_index_ranges(
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
        for combo in &combos {
            let mut tmp = self.clone();
            for (col_idx, constraint) in combo {
                tmp.constraints.insert(*col_idx, constraint.clone());
            }
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

    fn leading_constrained_prefix(&self, model: &TableModel, spec: &ResolvedIndexSpec) -> usize {
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

    fn lexicographic_candidate_score(&self, model: &TableModel, spec: &ResolvedIndexSpec) -> usize {
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

    fn zorder_constrained_column_count(
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

    fn constraint_is_point(kind: ColumnKind, constraint: &PredicateConstraint) -> bool {
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

    fn constraint_supported_for_zorder(kind: ColumnKind, constraint: &PredicateConstraint) -> bool {
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

    fn expand_zorder_index_ranges(
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

    fn encode_index_bound_key(
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

    fn encode_zorder_index_bound_key(
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

    fn ordered_index_bound_bytes_for_column(
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

    fn int_bounds(&self, col_idx: usize) -> (Option<i64>, Option<i64>) {
        match self.constraints.get(&col_idx) {
            Some(PredicateConstraint::IntRange { min, max }) => (*min, *max),
            _ => (None, None),
        }
    }

    fn uint64_bounds(&self, col_idx: usize) -> (u64, u64) {
        match self.constraints.get(&col_idx) {
            Some(PredicateConstraint::UInt64Range { min, max }) => {
                (min.unwrap_or(0), max.unwrap_or(u64::MAX))
            }
            _ => (0, u64::MAX),
        }
    }

    fn primary_key_ranges(&self, model: &TableModel) -> DataFusionResult<Vec<KeyRange>> {
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
    fn matches_row(&self, row: &KvRow) -> bool {
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

    fn describe(&self, model: &TableModel) -> String {
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

fn describe_predicate_constraint(constraint: &PredicateConstraint) -> String {
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

fn describe_integral_range(min: Option<String>, max: Option<String>) -> String {
    match (min, max) {
        (Some(min), Some(max)) if min == max => format!("= {min}"),
        (Some(min), Some(max)) => format!("BETWEEN {min} AND {max}"),
        (Some(min), None) => format!(">= {min}"),
        (None, Some(max)) => format!("<= {max}"),
        (None, None) => "IS ANY".to_string(),
    }
}

fn describe_float_range(min: Option<(f64, bool)>, max: Option<(f64, bool)>) -> String {
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

fn describe_in_list(values: impl Iterator<Item = String>) -> String {
    let mut values = values.collect::<Vec<_>>();
    let truncated = values.len() > 5;
    if truncated {
        values.truncate(5);
        values.push("...".to_string());
    }
    format!("IN ({})", values.join(", "))
}

fn format_float(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_string()
    } else {
        value.to_string()
    }
}

fn escape_plan_string(value: &str) -> String {
    value.replace('\'', "''")
}

fn hex_preview(bytes: &[u8]) -> String {
    let mut encoded = hex::encode(bytes);
    if encoded.len() > 16 {
        encoded.truncate(16);
        encoded.push_str("...");
    }
    encoded
}

fn matches_constraint(value: &CellValue, constraint: &PredicateConstraint) -> bool {
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
        (CellValue::Utf8(v), PredicateConstraint::StringIn(values)) => values.contains(v),
        (CellValue::Int64(v), PredicateConstraint::IntIn(values)) => values.contains(v),
        (CellValue::UInt64(v), PredicateConstraint::UInt64Range { min, max }) => {
            in_u64_bounds(*v, *min, *max)
        }
        (CellValue::UInt64(v), PredicateConstraint::UInt64In(values)) => values.contains(v),
        (CellValue::FixedBinary(v), PredicateConstraint::FixedBinaryEq(expected)) => v == expected,
        (CellValue::FixedBinary(v), PredicateConstraint::FixedBinaryIn(values)) => {
            values.contains(v)
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

fn matches_archived_non_pk_constraint(
    col: &ResolvedColumn,
    stored_opt: Option<&ArchivedStoredValue>,
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
                ArchivedStoredValue::Utf8(v),
                PredicateConstraint::StringEq(expected),
            ) => v.as_str() == expected,
            (
                ColumnKind::Utf8,
                ArchivedStoredValue::Utf8(v),
                PredicateConstraint::StringIn(values),
            ) => values.iter().any(|candidate| candidate == v.as_str()),
            (
                ColumnKind::Boolean,
                ArchivedStoredValue::Boolean(v),
                PredicateConstraint::BoolEq(expected),
            ) => *v == *expected,
            (
                ColumnKind::Int64,
                ArchivedStoredValue::Int64(v),
                PredicateConstraint::IntRange { min, max },
            ) => in_i64_bounds((*v).into(), *min, *max),
            (
                ColumnKind::Date32,
                ArchivedStoredValue::Int64(v),
                PredicateConstraint::IntRange { min, max },
            ) => in_i64_bounds(i64::from(*v) as i32 as i64, *min, *max),
            (
                ColumnKind::Date64,
                ArchivedStoredValue::Int64(v),
                PredicateConstraint::IntRange { min, max },
            ) => in_i64_bounds((*v).into(), *min, *max),
            (
                ColumnKind::Timestamp,
                ArchivedStoredValue::Int64(v),
                PredicateConstraint::IntRange { min, max },
            ) => in_i64_bounds((*v).into(), *min, *max),
            (
                ColumnKind::Float64,
                ArchivedStoredValue::Float64(v),
                PredicateConstraint::FloatRange { min, max },
            ) => in_f64_bounds((*v).into(), min, max),
            (
                ColumnKind::Float64,
                ArchivedStoredValue::Int64(v),
                PredicateConstraint::FloatRange { min, max },
            ) => in_f64_bounds(i64::from(*v) as f64, min, max),
            (
                ColumnKind::Decimal128,
                ArchivedStoredValue::Bytes(bytes),
                PredicateConstraint::Decimal128Range { min, max },
            ) => {
                let Ok(arr) = <[u8; 16]>::try_from(bytes.as_slice()) else {
                    return false;
                };
                in_i128_bounds(i128::from_le_bytes(arr), *min, *max)
            }
            (
                ColumnKind::Decimal256,
                ArchivedStoredValue::Bytes(bytes),
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
                ArchivedStoredValue::UInt64(v),
                PredicateConstraint::UInt64Range { min, max },
            ) => in_u64_bounds((*v).into(), *min, *max),
            (
                ColumnKind::UInt64,
                ArchivedStoredValue::UInt64(v),
                PredicateConstraint::UInt64In(values),
            ) => values.iter().any(|candidate| *candidate == u64::from(*v)),
            (
                ColumnKind::Int64,
                ArchivedStoredValue::Int64(v),
                PredicateConstraint::IntIn(values),
            ) => values.iter().any(|candidate| *candidate == i64::from(*v)),
            (
                ColumnKind::FixedSizeBinary(_),
                ArchivedStoredValue::Bytes(v),
                PredicateConstraint::FixedBinaryEq(expected),
            ) => v.as_slice() == expected.as_slice(),
            (
                ColumnKind::FixedSizeBinary(_),
                ArchivedStoredValue::Bytes(v),
                PredicateConstraint::FixedBinaryIn(values),
            ) => values
                .iter()
                .any(|candidate| candidate.as_slice() == v.as_slice()),
            _ => false,
        },
    }
}

fn in_i64_bounds(value: i64, min: Option<i64>, max: Option<i64>) -> bool {
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

fn in_u64_bounds(value: u64, min: Option<u64>, max: Option<u64>) -> bool {
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

fn in_f64_bounds(value: f64, lower: &Option<(f64, bool)>, upper: &Option<(f64, bool)>) -> bool {
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

fn apply_int_constraint(
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

fn apply_u64_constraint(
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

fn apply_float_constraint(
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

fn merge_float_lower(current: &mut Option<(f64, bool)>, value: f64, inclusive: bool) {
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

fn merge_float_upper(current: &mut Option<(f64, bool)>, value: f64, inclusive: bool) {
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

fn in_i128_bounds(value: i128, min: Option<i128>, max: Option<i128>) -> bool {
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

fn apply_decimal128_constraint(
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

fn apply_i256_constraint(
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

fn extract_or_in_column(expr: &Expr, model: &TableModel) -> Option<(String, Vec<ScalarValue>)> {
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

fn collect_or_equalities(
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

fn parse_simple_comparison(expr: &Expr) -> Option<(String, Operator, ScalarValue)> {
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

fn reverse_operator(op: Operator) -> Option<Operator> {
    match op {
        Operator::Eq => Some(Operator::Eq),
        Operator::Lt => Some(Operator::Gt),
        Operator::LtEq => Some(Operator::GtEq),
        Operator::Gt => Some(Operator::Lt),
        Operator::GtEq => Some(Operator::LtEq),
        _ => None,
    }
}

fn extract_column_name(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Column(col) => Some(col.name.as_str()),
        Expr::Cast(cast) => extract_column_name(cast.expr.as_ref()),
        Expr::TryCast(cast) => extract_column_name(cast.expr.as_ref()),
        _ => None,
    }
}

fn extract_literal(expr: &Expr) -> Option<&ScalarValue> {
    match expr {
        Expr::Literal(value, _) => Some(value),
        Expr::Cast(cast) => extract_literal(cast.expr.as_ref()),
        Expr::TryCast(cast) => extract_literal(cast.expr.as_ref()),
        _ => None,
    }
}

fn scalar_to_string(value: &ScalarValue) -> Option<String> {
    match value {
        ScalarValue::Utf8(Some(v))
        | ScalarValue::Utf8View(Some(v))
        | ScalarValue::LargeUtf8(Some(v)) => Some(v.clone()),
        _ => None,
    }
}

fn scalar_to_i64(value: &ScalarValue) -> Option<i64> {
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

fn scalar_to_u64(value: &ScalarValue) -> Option<u64> {
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

fn scalar_to_f64(value: &ScalarValue) -> Option<f64> {
    match value {
        ScalarValue::Float32(Some(v)) => Some(*v as f64),
        ScalarValue::Float64(Some(v)) => Some(*v),
        _ => None,
    }
}

fn scalar_to_bool(value: &ScalarValue) -> Option<bool> {
    match value {
        ScalarValue::Boolean(Some(v)) => Some(*v),
        _ => None,
    }
}

fn scalar_to_date32_i64(value: &ScalarValue) -> Option<i64> {
    match value {
        ScalarValue::Date32(Some(v)) => Some(*v as i64),
        _ => None,
    }
}

fn scalar_to_date64(value: &ScalarValue) -> Option<i64> {
    match value {
        ScalarValue::Date64(Some(v)) => Some(*v),
        _ => None,
    }
}

fn scalar_to_timestamp_micros(value: &ScalarValue) -> Option<i64> {
    match value {
        ScalarValue::TimestampSecond(Some(v), _) => v.checked_mul(1_000_000),
        ScalarValue::TimestampMillisecond(Some(v), _) => v.checked_mul(1_000),
        ScalarValue::TimestampMicrosecond(Some(v), _) => Some(*v),
        ScalarValue::TimestampNanosecond(Some(v), _) => Some(v.div_euclid(1_000)),
        _ => None,
    }
}

fn timestamp_scalar_to_micros_for_op(value: &ScalarValue, op: Operator) -> Option<i64> {
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

fn scalar_to_i128(value: &ScalarValue) -> Option<i128> {
    match value {
        ScalarValue::Decimal128(Some(v), _, _) => Some(*v),
        _ => None,
    }
}

fn scalar_to_fixed_binary(value: &ScalarValue) -> Option<Vec<u8>> {
    match value {
        ScalarValue::FixedSizeBinary(_, Some(v)) => Some(v.clone()),
        ScalarValue::Binary(Some(v)) => Some(v.clone()),
        ScalarValue::LargeBinary(Some(v)) => Some(v.clone()),
        _ => None,
    }
}

fn scalar_to_i256(value: &ScalarValue) -> Option<i256> {
    match value {
        ScalarValue::Decimal256(Some(v), _, _) => Some(*v),
        _ => None,
    }
}

fn primary_key_prefix_range(table_prefix: u8) -> KeyRange {
    let codec = primary_key_codec(table_prefix).expect("table prefix should fit primary key codec");
    let (start, end) = codec.family_bounds();
    KeyRange { start, end }
}

fn encode_i64_ordered(value: i64) -> [u8; 8] {
    ((value as u64) ^ 0x8000_0000_0000_0000).to_be_bytes()
}

fn decode_i64_ordered(bytes: [u8; 8]) -> i64 {
    (u64::from_be_bytes(bytes) ^ 0x8000_0000_0000_0000) as i64
}

fn encode_f64_ordered(value: f64) -> [u8; 8] {
    let bits = value.to_bits();
    let encoded = if bits & 0x8000_0000_0000_0000 != 0 {
        !bits
    } else {
        bits ^ 0x8000_0000_0000_0000
    };
    encoded.to_be_bytes()
}

fn decode_f64_ordered(bytes: [u8; 8]) -> f64 {
    let bits = u64::from_be_bytes(bytes);
    let decoded = if bits & 0x8000_0000_0000_0000 != 0 {
        bits ^ 0x8000_0000_0000_0000
    } else {
        !bits
    };
    f64::from_bits(decoded)
}

fn encode_i32_ordered(value: i32) -> [u8; 4] {
    ((value as u32) ^ 0x8000_0000).to_be_bytes()
}

fn decode_i32_ordered(bytes: [u8; 4]) -> i32 {
    (u32::from_be_bytes(bytes) ^ 0x8000_0000) as i32
}

fn encode_i128_ordered(value: i128) -> [u8; 16] {
    ((value as u128) ^ (1u128 << 127)).to_be_bytes()
}

fn decode_i128_ordered(bytes: [u8; 16]) -> i128 {
    (u128::from_be_bytes(bytes) ^ (1u128 << 127)) as i128
}

fn encode_i256_ordered(value: i256) -> [u8; 32] {
    let mut bytes = value.to_be_bytes();
    bytes[0] ^= 0x80;
    bytes
}

fn decode_i256_ordered(mut bytes: [u8; 32]) -> i256 {
    bytes[0] ^= 0x80;
    i256::from_be_bytes(bytes)
}

fn decode_fixed_text(bytes: &[u8]) -> Option<String> {
    decode_variable_text(bytes)
}

fn encode_string_variable(value: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(value.len() + 1);
    for byte in value.as_bytes() {
        match *byte {
            STRING_KEY_TERMINATOR => {
                out.push(STRING_KEY_ESCAPE_PREFIX);
                out.push(STRING_KEY_TERMINATOR);
            }
            STRING_KEY_ESCAPE_PREFIX => {
                out.push(STRING_KEY_ESCAPE_PREFIX);
                out.push(STRING_KEY_ESCAPE_PREFIX);
            }
            0xFF => {
                out.push(STRING_KEY_ESCAPE_PREFIX);
                out.push(STRING_KEY_ESCAPE_FF);
            }
            other => out.push(other),
        }
    }
    out.push(STRING_KEY_TERMINATOR);
    if out.len() > exoware_sdk_rs::keys::MAX_KEY_LEN {
        return Err(format!(
            "indexed string value '{}' exceeds max encoded key length {}",
            value,
            exoware_sdk_rs::keys::MAX_KEY_LEN
        ));
    }
    Ok(out)
}

fn decode_variable_text(bytes: &[u8]) -> Option<String> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0usize;
    while idx < bytes.len() {
        match bytes[idx] {
            STRING_KEY_TERMINATOR => return String::from_utf8(out).ok(),
            STRING_KEY_ESCAPE_PREFIX => {
                let escaped = *bytes.get(idx + 1)?;
                match escaped {
                    STRING_KEY_TERMINATOR => out.push(STRING_KEY_TERMINATOR),
                    STRING_KEY_ESCAPE_PREFIX => out.push(STRING_KEY_ESCAPE_PREFIX),
                    STRING_KEY_ESCAPE_FF => out.push(0xFF),
                    _ => return None,
                }
                idx += 2;
            }
            byte => {
                out.push(byte);
                idx += 1;
            }
        }
    }
    None
}

fn encode_cell_into_ordered_key_bytes(
    cell: &CellValue,
    kind: ColumnKind,
) -> Result<Vec<u8>, String> {
    if let (ColumnKind::Utf8, CellValue::Utf8(v)) = (kind, cell) {
        return encode_string_variable(v);
    }
    let mut out = vec![0u8; kind.key_width()];
    match (kind, cell) {
        (ColumnKind::Int64, CellValue::Int64(v)) => {
            out.copy_from_slice(&encode_i64_ordered(*v));
            Ok(out)
        }
        (ColumnKind::UInt64, CellValue::UInt64(v)) => {
            out.copy_from_slice(&v.to_be_bytes());
            Ok(out)
        }
        (ColumnKind::Float64, CellValue::Float64(v)) => {
            out.copy_from_slice(&encode_f64_ordered(*v));
            Ok(out)
        }
        (ColumnKind::Boolean, CellValue::Boolean(v)) => {
            out[0] = u8::from(*v);
            Ok(out)
        }
        (ColumnKind::Date32, CellValue::Date32(v)) => {
            out.copy_from_slice(&encode_i32_ordered(*v));
            Ok(out)
        }
        (ColumnKind::Date64, CellValue::Date64(v)) => {
            out.copy_from_slice(&encode_i64_ordered(*v));
            Ok(out)
        }
        (ColumnKind::Timestamp, CellValue::Timestamp(v)) => {
            out.copy_from_slice(&encode_i64_ordered(*v));
            Ok(out)
        }
        (ColumnKind::Decimal128, CellValue::Decimal128(v)) => {
            out.copy_from_slice(&encode_i128_ordered(*v));
            Ok(out)
        }
        (ColumnKind::Decimal256, CellValue::Decimal256(v)) => {
            out.copy_from_slice(&encode_i256_ordered(*v));
            Ok(out)
        }
        (ColumnKind::FixedSizeBinary(n), CellValue::FixedBinary(v)) => {
            if v.len() != n {
                return Err(format!(
                    "FixedSizeBinary({n}) key column requires exactly {n} bytes, got {}",
                    v.len()
                ));
            }
            out.copy_from_slice(v);
            Ok(out)
        }
        _ => Err(format!(
            "type mismatch while encoding key value (expected {kind:?}, got {cell:?})"
        )),
    }
}

fn decode_cell_from_ordered_key_bytes(bytes: &[u8], kind: ColumnKind) -> Option<CellValue> {
    Some(match kind {
        ColumnKind::Int64 => {
            let raw = bytes.try_into().ok()?;
            CellValue::Int64(decode_i64_ordered(raw))
        }
        ColumnKind::UInt64 => {
            let raw = bytes.try_into().ok()?;
            CellValue::UInt64(u64::from_be_bytes(raw))
        }
        ColumnKind::Float64 => {
            let raw = bytes.try_into().ok()?;
            CellValue::Float64(decode_f64_ordered(raw))
        }
        ColumnKind::Boolean => CellValue::Boolean(*bytes.first()? != 0),
        ColumnKind::Utf8 => CellValue::Utf8(decode_fixed_text(bytes)?),
        ColumnKind::Date32 => {
            let raw = bytes.try_into().ok()?;
            CellValue::Date32(decode_i32_ordered(raw))
        }
        ColumnKind::Date64 => {
            let raw = bytes.try_into().ok()?;
            CellValue::Date64(decode_i64_ordered(raw))
        }
        ColumnKind::Timestamp => {
            let raw = bytes.try_into().ok()?;
            CellValue::Timestamp(decode_i64_ordered(raw))
        }
        ColumnKind::Decimal128 => {
            let raw = bytes.try_into().ok()?;
            CellValue::Decimal128(decode_i128_ordered(raw))
        }
        ColumnKind::Decimal256 => {
            let raw = bytes.try_into().ok()?;
            CellValue::Decimal256(decode_i256_ordered(raw))
        }
        ColumnKind::FixedSizeBinary(n) => {
            if bytes.len() != n {
                return None;
            }
            CellValue::FixedBinary(bytes.to_vec())
        }
        ColumnKind::List(_) => return None,
    })
}

fn decode_cell_from_codec_payload(
    codec: KeyCodec,
    key: &Key,
    payload_offset: usize,
    kind: ColumnKind,
) -> Option<CellValue> {
    decode_cell_from_codec_payload_with_len(codec, key, payload_offset, kind).map(|(cell, _)| cell)
}

fn decode_cell_from_codec_payload_with_len(
    codec: KeyCodec,
    key: &Key,
    payload_offset: usize,
    kind: ColumnKind,
) -> Option<(CellValue, usize)> {
    match kind {
        ColumnKind::Utf8 => {
            let mut bytes = Vec::new();
            let mut idx = 0usize;
            let mut escaped = false;
            loop {
                let byte = codec
                    .read_payload(key, payload_offset + idx, 1)
                    .ok()?
                    .into_iter()
                    .next()?;
                bytes.push(byte);
                idx += 1;
                if escaped {
                    escaped = false;
                    continue;
                }
                if byte == STRING_KEY_ESCAPE_PREFIX {
                    escaped = true;
                    continue;
                }
                if byte == STRING_KEY_TERMINATOR {
                    break;
                }
            }
            decode_cell_from_ordered_key_bytes(&bytes, kind).map(|cell| (cell, bytes.len()))
        }
        _ => {
            let bytes = codec
                .read_payload(key, payload_offset, kind.key_width())
                .ok()?;
            decode_cell_from_ordered_key_bytes(&bytes, kind).map(|cell| (cell, kind.key_width()))
        }
    }
}

fn encode_primary_key(
    table_prefix: u8,
    pk_values: &[&CellValue],
    model: &TableModel,
) -> Result<Key, String> {
    if table_prefix != model.table_prefix {
        return Err("table prefix does not match model".to_string());
    }
    let codec = model.primary_key_codec;
    let payload_len = pk_values
        .iter()
        .zip(model.primary_key_kinds.iter())
        .try_fold(0usize, |acc, (val, kind)| {
            encode_cell_into_ordered_key_bytes(val, *kind).map(|encoded| acc + encoded.len())
        })?;
    ensure_codec_payload_fits(codec, payload_len, "primary key payload")?;
    let mut key = allocate_codec_key(codec, payload_len)?;
    let mut payload_offset = 0usize;
    for (val, kind) in pk_values.iter().zip(model.primary_key_kinds.iter()) {
        let encoded = encode_cell_into_ordered_key_bytes(val, *kind)?;
        codec
            .write_payload(&mut key, payload_offset, &encoded)
            .map_err(|e| format!("failed to write codec payload: {e}"))?;
        payload_offset += encoded.len();
    }
    Ok(key.freeze())
}

fn encode_primary_key_from_row(
    table_prefix: u8,
    row: &KvRow,
    model: &TableModel,
) -> Result<Key, String> {
    let vals: Vec<&CellValue> = row.primary_key_values(model);
    encode_primary_key(table_prefix, &vals, model)
}

fn encode_primary_key_bound(
    table_prefix: u8,
    pk_values: &[&CellValue],
    model: &TableModel,
    upper_tail: bool,
) -> Result<Key, String> {
    if table_prefix != model.table_prefix {
        return Err("table prefix does not match model".to_string());
    }
    let codec = model.primary_key_codec;
    let encoded_parts = pk_values
        .iter()
        .zip(model.primary_key_kinds.iter())
        .map(|(val, kind)| encode_cell_into_ordered_key_bytes(val, *kind))
        .collect::<Result<Vec<_>, _>>()?;
    let encoded_width = encoded_parts.iter().map(|part| part.len()).sum::<usize>();
    let payload_len = if upper_tail {
        codec.payload_capacity_bytes()
    } else {
        model.primary_key_width.max(encoded_width)
    };
    let mut key = allocate_codec_key(codec, payload_len)?;
    let mut payload_offset = 0usize;
    for encoded in &encoded_parts {
        codec
            .write_payload(&mut key, payload_offset, encoded)
            .map_err(|e| format!("failed to write codec payload: {e}"))?;
        payload_offset += encoded.len();
    }
    if upper_tail {
        let remaining = codec.payload_capacity_bytes().saturating_sub(encoded_width);
        codec
            .fill_payload(&mut key, encoded_width, remaining, 0xFF)
            .map_err(|e| format!("failed to fill codec payload: {e}"))?;
    }
    Ok(key.freeze())
}

#[cfg(test)]
fn decode_primary_key(table_prefix: u8, key: &Key, model: &TableModel) -> Option<Vec<CellValue>> {
    if table_prefix != model.table_prefix || !model.primary_key_codec.matches(key) {
        return None;
    }
    let mut values = Vec::with_capacity(model.primary_key_kinds.len());
    let mut payload_offset = 0usize;
    for kind in &model.primary_key_kinds {
        let (val, consumed) = decode_cell_from_codec_payload_with_len(
            model.primary_key_codec,
            key,
            payload_offset,
            *kind,
        )?;
        payload_offset += consumed;
        values.push(val);
    }
    Some(values)
}

fn decode_primary_key_selected(
    table_prefix: u8,
    key: &Key,
    model: &TableModel,
    required_pk_mask: &[bool],
) -> Option<Vec<CellValue>> {
    if table_prefix != model.table_prefix || !model.primary_key_codec.matches(key) {
        return None;
    }
    if !ScanAccessPlan::needs_any_pk(required_pk_mask) {
        return Some(Vec::new());
    }
    if required_pk_mask.len() != model.primary_key_kinds.len() {
        return None;
    }
    let mut values = vec![CellValue::Null; model.primary_key_kinds.len()];
    let mut payload_offset = 0usize;
    for (pk_pos, kind) in model.primary_key_kinds.iter().enumerate() {
        let (_, consumed) = decode_cell_from_codec_payload_with_len(
            model.primary_key_codec,
            key,
            payload_offset,
            *kind,
        )?;
        if required_pk_mask[pk_pos] {
            values[pk_pos] = decode_cell_from_codec_payload(
                model.primary_key_codec,
                key,
                payload_offset,
                *kind,
            )?;
        }
        payload_offset += consumed;
    }
    Some(values)
}

fn encode_secondary_index_key(
    table_prefix: u8,
    spec: &ResolvedIndexSpec,
    model: &TableModel,
    row: &KvRow,
) -> Result<Key, String> {
    if table_prefix != model.table_prefix {
        return Err("table prefix does not match model".to_string());
    }
    let codec = spec.codec;
    let mut payload_offset = 0usize;
    let encoded_index_fields = spec
        .key_columns
        .iter()
        .map(|col_idx| {
            let col = model.column(*col_idx);
            encode_cell_into_ordered_key_bytes(row.value_at(*col_idx), col.kind)
                .map_err(|e| format!("index '{}' column '{}': {e}", spec.name, col.name))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let encoded_index_key = match spec.layout {
        IndexLayout::Lexicographic => encoded_index_fields.concat(),
        IndexLayout::ZOrder => interleave_ordered_key_fields(&encoded_index_fields),
    };
    let pk_payload_len = model
        .primary_key_indices
        .iter()
        .zip(model.primary_key_kinds.iter())
        .try_fold(0usize, |acc, (&pk_idx, &pk_kind)| {
            encode_cell_into_ordered_key_bytes(row.value_at(pk_idx), pk_kind)
                .map(|encoded| acc + encoded.len())
        })?;
    let total_payload_len = encoded_index_key.len() + pk_payload_len;
    ensure_codec_payload_fits(
        codec,
        total_payload_len,
        &format!("index '{}' payload", spec.name),
    )?;
    let mut key = allocate_codec_key(codec, total_payload_len)?;
    codec
        .write_payload(&mut key, payload_offset, &encoded_index_key)
        .map_err(|e| format!("failed to write codec payload: {e}"))?;
    payload_offset += encoded_index_key.len();
    debug_assert!(payload_offset <= codec.payload_capacity_bytes());

    for (&pk_idx, &pk_kind) in model
        .primary_key_indices
        .iter()
        .zip(model.primary_key_kinds.iter())
    {
        let encoded = encode_cell_into_ordered_key_bytes(row.value_at(pk_idx), pk_kind)?;
        codec
            .write_payload(&mut key, payload_offset, &encoded)
            .map_err(|e| format!("failed to write codec payload: {e}"))?;
        payload_offset += encoded.len();
    }
    Ok(key.freeze())
}

fn encode_secondary_index_key_from_parts(
    table_prefix: u8,
    spec: &ResolvedIndexSpec,
    model: &TableModel,
    pk_values: &[CellValue],
    archived: &ArchivedStoredRow,
) -> DataFusionResult<Key> {
    if table_prefix != model.table_prefix {
        return Err(DataFusionError::Execution(
            "table prefix does not match model".to_string(),
        ));
    }
    if pk_values.len() != model.primary_key_indices.len() {
        return Err(DataFusionError::Execution(
            "primary key value count does not match model".to_string(),
        ));
    }
    if archived.values.len() != model.columns.len() {
        return Err(DataFusionError::Execution(
            "archived row column count mismatch".to_string(),
        ));
    }

    let codec = spec.codec;
    let mut payload_offset = 0usize;

    let encoded_index_fields = spec
        .key_columns
        .iter()
        .map(|&col_idx| encode_index_column_from_parts(spec, model, col_idx, pk_values, archived))
        .collect::<DataFusionResult<Vec<_>>>()?;
    let encoded_index_key = match spec.layout {
        IndexLayout::Lexicographic => encoded_index_fields.concat(),
        IndexLayout::ZOrder => interleave_ordered_key_fields(&encoded_index_fields),
    };
    let pk_payload_len = model.primary_key_kinds.iter().enumerate().try_fold(
        0usize,
        |acc, (pk_pos, &pk_kind)| {
            let value = pk_values.get(pk_pos).ok_or_else(|| {
                DataFusionError::Execution(
                    "missing primary key value while sizing index key".to_string(),
                )
            })?;
            encode_cell_into_ordered_key_bytes(value, pk_kind)
                .map(|encoded| acc + encoded.len())
                .map_err(DataFusionError::Execution)
        },
    )?;
    let total_payload_len = encoded_index_key.len() + pk_payload_len;
    ensure_codec_payload_fits(
        codec,
        total_payload_len,
        &format!("index '{}' payload", spec.name),
    )
    .map_err(DataFusionError::Execution)?;
    let mut key =
        allocate_codec_key(codec, total_payload_len).map_err(DataFusionError::Execution)?;
    codec
        .write_payload(&mut key, payload_offset, &encoded_index_key)
        .map_err(|e| DataFusionError::Execution(format!("failed to write codec payload: {e}")))?;
    payload_offset += encoded_index_key.len();
    debug_assert!(payload_offset <= codec.payload_capacity_bytes());

    for (pk_pos, &pk_kind) in model.primary_key_kinds.iter().enumerate() {
        let value = pk_values.get(pk_pos).ok_or_else(|| {
            DataFusionError::Execution("missing primary key value while encoding index".to_string())
        })?;
        let encoded = encode_cell_into_ordered_key_bytes(value, pk_kind)
            .map_err(DataFusionError::Execution)?;
        codec
            .write_payload(&mut key, payload_offset, &encoded)
            .map_err(|e| {
                DataFusionError::Execution(format!("failed to write codec payload: {e}"))
            })?;
        payload_offset += encoded.len();
    }
    Ok(key.freeze())
}

fn encode_index_column_from_parts(
    spec: &ResolvedIndexSpec,
    model: &TableModel,
    col_idx: usize,
    pk_values: &[CellValue],
    archived: &ArchivedStoredRow,
) -> DataFusionResult<Vec<u8>> {
    let col = model.column(col_idx);
    if let Some(pk_pos) = model.pk_position(col_idx) {
        let value = pk_values.get(pk_pos).ok_or_else(|| {
            DataFusionError::Execution(format!(
                "missing primary key value for index '{}' column '{}'",
                spec.name, col.name
            ))
        })?;
        return encode_cell_into_ordered_key_bytes(value, col.kind)
            .map_err(DataFusionError::Execution);
    }

    let stored_opt = archived
        .values
        .get(col_idx)
        .and_then(|value| value.as_ref());
    if !archived_non_pk_value_is_valid(col, stored_opt) {
        return Err(DataFusionError::Execution(format!(
            "invalid archived value for index '{}' column '{}'",
            spec.name, col.name
        )));
    }
    let value = cell_value_from_archived_non_pk(col, stored_opt)?.ok_or_else(|| {
        DataFusionError::Execution(format!(
            "index '{}' column '{}' is NULL but key columns must be non-null",
            spec.name, col.name
        ))
    })?;
    encode_cell_into_ordered_key_bytes(&value, col.kind).map_err(DataFusionError::Execution)
}

fn cell_value_from_archived_non_pk(
    col: &ResolvedColumn,
    stored_opt: Option<&ArchivedStoredValue>,
) -> DataFusionResult<Option<CellValue>> {
    let Some(stored) = stored_opt else {
        if col.nullable {
            return Ok(None);
        }
        return Err(DataFusionError::Execution(format!(
            "column '{}' is not nullable but archived value is NULL",
            col.name
        )));
    };
    let value = match (col.kind, stored) {
        (ColumnKind::Int64, ArchivedStoredValue::Int64(v)) => CellValue::Int64((*v).into()),
        (ColumnKind::UInt64, ArchivedStoredValue::UInt64(v)) => CellValue::UInt64((*v).into()),
        (ColumnKind::Float64, ArchivedStoredValue::Float64(v)) => CellValue::Float64((*v).into()),
        (ColumnKind::Float64, ArchivedStoredValue::Int64(v)) => {
            CellValue::Float64(i64::from(*v) as f64)
        }
        (ColumnKind::Boolean, ArchivedStoredValue::Boolean(v)) => CellValue::Boolean(*v),
        (ColumnKind::Date32, ArchivedStoredValue::Int64(v)) => {
            CellValue::Date32(i64::from(*v) as i32)
        }
        (ColumnKind::Date64, ArchivedStoredValue::Int64(v)) => CellValue::Date64((*v).into()),
        (ColumnKind::Timestamp, ArchivedStoredValue::Int64(v)) => CellValue::Timestamp((*v).into()),
        (ColumnKind::Decimal128, ArchivedStoredValue::Bytes(bytes)) => {
            let arr: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
                DataFusionError::Execution(format!(
                    "column '{}' expected Decimal128 archived payload width 16",
                    col.name
                ))
            })?;
            CellValue::Decimal128(i128::from_le_bytes(arr))
        }
        (ColumnKind::Decimal256, ArchivedStoredValue::Bytes(bytes)) => {
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                DataFusionError::Execution(format!(
                    "column '{}' expected Decimal256 archived payload width 32",
                    col.name
                ))
            })?;
            CellValue::Decimal256(i256::from_le_bytes(arr))
        }
        (ColumnKind::Utf8, ArchivedStoredValue::Utf8(v)) => CellValue::Utf8(v.as_str().to_string()),
        (ColumnKind::FixedSizeBinary(expected), ArchivedStoredValue::Bytes(v)) => {
            if v.as_slice().len() != expected {
                return Err(DataFusionError::Execution(format!(
                    "column '{}' expects FixedSizeBinary({expected}) archived payload width {}, got {}",
                    col.name,
                    expected,
                    v.as_slice().len()
                )));
            }
            CellValue::FixedBinary(v.as_slice().to_vec())
        }
        (ColumnKind::List(elem), ArchivedStoredValue::List(items)) => {
            let mut cells = Vec::with_capacity(items.len());
            for item in items.iter() {
                cells.push(decode_list_element_archived(elem, item).ok_or_else(|| {
                    DataFusionError::Execution(format!(
                        "column '{}' list element type mismatch in archived payload",
                        col.name
                    ))
                })?);
            }
            CellValue::List(cells)
        }
        _ => {
            return Err(DataFusionError::Execution(format!(
                "column '{}' archived type mismatch (expected {:?})",
                col.name, col.kind
            )))
        }
    };
    Ok(Some(value))
}

#[cfg(test)]
fn decode_secondary_index_key(
    table_prefix: u8,
    spec: &ResolvedIndexSpec,
    model: &TableModel,
    key: &Key,
) -> Option<DecodedIndexEntry> {
    decode_secondary_index_key_with_masks(table_prefix, spec, model, key, None, None)
}

fn decode_secondary_index_key_with_masks(
    table_prefix: u8,
    spec: &ResolvedIndexSpec,
    model: &TableModel,
    key: &Key,
    required_index_columns: Option<&[bool]>,
    required_pk_mask: Option<&[bool]>,
) -> Option<DecodedIndexEntry> {
    if table_prefix != model.table_prefix || !spec.codec.matches(key) {
        return None;
    }
    let mut decoded = DecodedIndexEntry::default();
    let zorder_fields = if spec.layout == IndexLayout::ZOrder {
        let index_key_bytes = spec
            .codec
            .read_payload(key, 0, spec.key_columns_width)
            .ok()?;
        Some(exoware_sdk_rs::kv_codec::deinterleave_ordered_key_fields(
            &index_key_bytes,
            &spec
                .key_columns
                .iter()
                .map(|col_idx| u8::try_from(model.column(*col_idx).kind.key_width()).ok())
                .collect::<Option<Vec<_>>>()?,
        )?)
    } else {
        None
    };
    let mut payload_offset = 0usize;
    for (key_pos, col_idx) in spec.key_columns.iter().enumerate() {
        let col = model.column(*col_idx);
        let should_decode = required_index_columns
            .and_then(|cols| cols.get(*col_idx))
            .copied()
            .unwrap_or(true);
        if should_decode {
            let cell = if let Some(fields) = &zorder_fields {
                decode_cell_from_ordered_key_bytes(fields.get(key_pos)?, col.kind)?
            } else {
                decode_cell_from_codec_payload_with_len(spec.codec, key, payload_offset, col.kind)?
                    .0
            };
            decoded.values.insert(*col_idx, cell);
        }
        if spec.layout == IndexLayout::Lexicographic {
            let consumed =
                decode_cell_from_codec_payload_with_len(spec.codec, key, payload_offset, col.kind)?
                    .1;
            payload_offset += consumed;
        }
    }
    if let Some(fields) = &zorder_fields {
        payload_offset = fields.iter().map(Vec::len).sum();
    }
    debug_assert!(payload_offset <= spec.codec.payload_capacity_bytes());
    let decode_all_pk = required_pk_mask.is_none();
    let decode_some_pk = required_pk_mask
        .map(ScanAccessPlan::needs_any_pk)
        .unwrap_or(true);
    if decode_all_pk || decode_some_pk {
        decoded.primary_key_values = vec![CellValue::Null; model.primary_key_kinds.len()];
    }
    let mut all_pk_values = Vec::with_capacity(model.primary_key_kinds.len());
    for (pk_pos, kind) in model.primary_key_kinds.iter().enumerate() {
        let should_decode = if decode_all_pk {
            true
        } else {
            required_pk_mask
                .and_then(|mask| mask.get(pk_pos))
                .copied()
                .unwrap_or(false)
        };
        let (val, consumed) =
            decode_cell_from_codec_payload_with_len(spec.codec, key, payload_offset, *kind)?;
        if should_decode {
            decoded.primary_key_values[pk_pos] = val.clone();
        }
        all_pk_values.push(
            decoded
                .primary_key_values
                .get(pk_pos)
                .cloned()
                .unwrap_or(val),
        );
        payload_offset += consumed;
    }
    let pk_refs = all_pk_values.iter().collect::<Vec<_>>();
    decoded.primary_key = match encode_primary_key(table_prefix, &pk_refs, model) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("debug decode_secondary_index_key pk rebuild error: {err}");
            return None;
        }
    };
    Some(decoded)
}

fn decode_secondary_index_primary_key(
    table_prefix: u8,
    spec: &ResolvedIndexSpec,
    model: &TableModel,
    key: &Key,
) -> Option<Key> {
    if table_prefix != model.table_prefix || !spec.codec.matches(key) {
        return None;
    }
    decode_secondary_index_key_with_masks(table_prefix, spec, model, key, Some(&[]), None)
        .map(|decoded| decoded.primary_key)
}

fn next_key(key: &Key) -> Option<Key> {
    exoware_sdk_rs::keys::next_key(key)
}

struct ScanCtx<'a> {
    session: &'a SerializableReadSession,
    model: &'a TableModel,
    predicate: &'a QueryPredicate,
    projected_schema: &'a SchemaRef,
    access_plan: &'a ScanAccessPlan,
}

async fn flush_projected_batch(
    tx: &mut futures::channel::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'_>,
    batch_builder: &mut ProjectedBatchBuilder,
    emitted: &mut usize,
) -> DataFusionResult<bool> {
    let batch_size = batch_builder.row_count();
    if batch_size == 0 {
        return Ok(true);
    }
    let ready = std::mem::replace(
        batch_builder,
        ProjectedBatchBuilder::from_access_plan(ctx.model, ctx.access_plan),
    );
    *emitted += batch_size;
    let batch = ready.finish(ctx.projected_schema)?;
    if tx.send(Ok(batch)).await.is_err() {
        return Ok(false);
    }
    Ok(true)
}

async fn stream_kv_scan(
    tx: &mut futures::channel::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'_>,
    index_specs: &[ResolvedIndexSpec],
    limit: Option<usize>,
) -> DataFusionResult<()> {
    if ctx.predicate.contradiction {
        return Ok(());
    }
    if limit == Some(0) {
        return Ok(());
    }
    let target_rows = limit.unwrap_or(usize::MAX);
    let flush_threshold = limit.unwrap_or(BATCH_FLUSH_ROWS).min(BATCH_FLUSH_ROWS);

    if let Some(plan) = ctx.predicate.choose_index_plan(ctx.model, index_specs)? {
        if !plan.ranges.is_empty()
            && ctx
                .access_plan
                .index_covers_required_non_pk(&index_specs[plan.spec_idx])
        {
            return stream_index_scan(tx, ctx, index_specs, &plan, flush_threshold, target_rows)
                .await;
        }
        if plan.ranges.is_empty() {
            return Ok(());
        }
    }

    let exact = ctx
        .access_plan
        .predicate_fully_enforced_by_primary_key(ctx.model);
    stream_pk_scan(tx, ctx, flush_threshold, target_rows, exact).await
}

async fn stream_pk_scan(
    tx: &mut futures::channel::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'_>,
    flush_threshold: usize,
    target_rows: usize,
    exact: bool,
) -> DataFusionResult<()> {
    let ranges = ctx.predicate.primary_key_ranges(ctx.model)?;
    let mut emitted = 0usize;
    let mut batch_builder = ProjectedBatchBuilder::from_access_plan(ctx.model, ctx.access_plan);

    for range in &ranges {
        if range.start > range.end {
            continue;
        }
        if emitted + batch_builder.row_count() >= target_rows {
            break;
        }
        let remaining = target_rows.saturating_sub(emitted + batch_builder.row_count());
        if remaining == 0 {
            break;
        }
        let raw_limit = if exact { remaining } else { usize::MAX };

        let mut stream = ctx
            .session
            .range_stream(&range.start, &range.end, raw_limit, flush_threshold)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
        while let Some(chunk) = stream
            .next_chunk()
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?
        {
            for (key, value) in &chunk {
                if emitted + batch_builder.row_count() >= target_rows {
                    break;
                }
                let Some(pk) = decode_primary_key_selected(
                    ctx.model.table_prefix,
                    key,
                    ctx.model,
                    &ctx.access_plan.required_pk_mask,
                ) else {
                    continue;
                };
                let Ok(archived) = access_stored_row(value) else {
                    continue;
                };
                if archived.values.len() != ctx.model.columns.len() {
                    continue;
                }
                if !ctx.access_plan.matches_archived_row(&pk, archived) {
                    continue;
                }
                if !batch_builder.append_archived_row(&pk, archived)? {
                    continue;
                }
                if batch_builder.row_count() >= flush_threshold
                    && !flush_projected_batch(tx, ctx, &mut batch_builder, &mut emitted).await?
                {
                    return Ok(());
                }
            }
            if emitted + batch_builder.row_count() >= target_rows {
                break;
            }
        }
    }

    let _ = flush_projected_batch(tx, ctx, &mut batch_builder, &mut emitted).await?;
    Ok(())
}

async fn stream_index_scan(
    tx: &mut futures::channel::mpsc::Sender<DataFusionResult<RecordBatch>>,
    ctx: &ScanCtx<'_>,
    index_specs: &[ResolvedIndexSpec],
    plan: &IndexPlan,
    flush_threshold: usize,
    target_rows: usize,
) -> DataFusionResult<()> {
    let spec = &index_specs[plan.spec_idx];
    let key_predicate_plan = ctx
        .access_plan
        .compile_index_predicate_plan(ctx.model, spec);
    if key_predicate_plan.is_impossible() {
        return Ok(());
    }
    let mut seen: HashSet<Key> = HashSet::new();
    let mut emitted = 0usize;
    let mut batch_builder = ProjectedBatchBuilder::from_access_plan(ctx.model, ctx.access_plan);

    for range in &plan.ranges {
        if emitted + batch_builder.row_count() >= target_rows {
            break;
        }
        let remaining = target_rows.saturating_sub(emitted + batch_builder.row_count());
        if remaining == 0 {
            break;
        }
        let mut stream = ctx
            .session
            .range_stream(&range.start, &range.end, usize::MAX, flush_threshold)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
        while let Some(chunk) = stream
            .next_chunk()
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?
        {
            for (key, index_value) in &chunk {
                if emitted + batch_builder.row_count() >= target_rows {
                    break;
                }
                if !key_predicate_plan.matches_key(key) {
                    continue;
                }
                let Some(primary_key) = decode_secondary_index_primary_key(
                    ctx.model.table_prefix,
                    spec,
                    ctx.model,
                    key,
                ) else {
                    continue;
                };
                if !seen.insert(primary_key.clone()) {
                    continue;
                }
                if index_value.is_empty() {
                    return Err(DataFusionError::Execution(
                        "secondary index entry missing covering payload".to_string(),
                    ));
                }

                let Some(pk_values) = decode_primary_key_selected(
                    ctx.model.table_prefix,
                    &primary_key,
                    ctx.model,
                    &ctx.access_plan.required_pk_mask,
                ) else {
                    continue;
                };
                let archived = access_stored_row(index_value).map_err(|e| {
                    DataFusionError::Execution(format!(
                        "invalid covering index payload for key {}: {e}",
                        hex::encode(key)
                    ))
                })?;
                if archived.values.len() != ctx.model.columns.len() {
                    continue;
                }
                if !ctx.access_plan.matches_archived_row(&pk_values, archived) {
                    continue;
                }
                if !batch_builder.append_archived_row(&pk_values, archived)? {
                    continue;
                }
                if batch_builder.row_count() >= flush_threshold
                    && !flush_projected_batch(tx, ctx, &mut batch_builder, &mut emitted).await?
                {
                    return Ok(());
                }
            }
            if emitted + batch_builder.row_count() >= target_rows {
                break;
            }
        }
    }

    let _ = flush_projected_batch(tx, ctx, &mut batch_builder, &mut emitted).await?;
    Ok(())
}

#[derive(Debug, Clone)]
enum PartialAggregateState {
    Count(u64),
    Sum(Option<KvReducedValue>),
    Min(Option<KvReducedValue>),
    Max(Option<KvReducedValue>),
}

impl PartialAggregateState {
    fn from_op(op: RangeReduceOp) -> Self {
        match op {
            RangeReduceOp::CountAll | RangeReduceOp::CountField => Self::Count(0),
            RangeReduceOp::SumField => Self::Sum(None),
            RangeReduceOp::MinField => Self::Min(None),
            RangeReduceOp::MaxField => Self::Max(None),
        }
    }

    fn merge_partial(
        &mut self,
        op: RangeReduceOp,
        value: Option<&KvReducedValue>,
    ) -> DataFusionResult<()> {
        match (self, op) {
            (Self::Count(total), RangeReduceOp::CountAll | RangeReduceOp::CountField) => {
                let Some(v) = value else {
                    return Err(DataFusionError::Execution(
                        "count reducer returned non-UInt64 partial".to_string(),
                    ));
                };
                let KvReducedValue::UInt64(partial) = v else {
                    return Err(DataFusionError::Execution(
                        "count reducer returned non-UInt64 partial".to_string(),
                    ));
                };
                *total = total.saturating_add(*partial);
                Ok(())
            }
            (Self::Sum(total), RangeReduceOp::SumField) => {
                let Some(value) = value else {
                    return Ok(());
                };
                match total {
                    Some(existing) => existing
                        .checked_add_assign(value)
                        .map_err(DataFusionError::Execution),
                    None => {
                        *total = Some(value.clone());
                        Ok(())
                    }
                }
            }
            (Self::Min(current), RangeReduceOp::MinField) => merge_extreme(current, value, true),
            (Self::Max(current), RangeReduceOp::MaxField) => merge_extreme(current, value, false),
            _ => Err(DataFusionError::Execution(
                "aggregate reducer state/op mismatch".to_string(),
            )),
        }
    }

    fn as_scalar_value(&self, data_type: &DataType) -> DataFusionResult<ScalarValue> {
        match self {
            Self::Count(count) => match data_type {
                DataType::UInt64 => Ok(ScalarValue::UInt64(Some(*count))),
                DataType::Int64 => Ok(ScalarValue::Int64(Some(i64::try_from(*count).map_err(
                    |_| DataFusionError::Execution("count exceeds Int64 range".to_string()),
                )?))),
                _ => Err(DataFusionError::Execution(format!(
                    "unsupported count return type {:?}",
                    data_type
                ))),
            },
            Self::Sum(value) | Self::Min(value) | Self::Max(value) => {
                reduced_value_to_scalar(value.clone(), data_type)
            }
        }
    }
}

fn merge_extreme(
    current: &mut Option<KvReducedValue>,
    value: Option<&KvReducedValue>,
    is_min: bool,
) -> DataFusionResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    match current {
        Some(existing) => {
            let ordering = value.partial_cmp_same_kind(existing).ok_or_else(|| {
                DataFusionError::Execution("aggregate extreme type mismatch".to_string())
            })?;
            if (is_min && ordering == Ordering::Less) || (!is_min && ordering == Ordering::Greater)
            {
                *current = Some(value.clone());
            }
        }
        None => {
            *current = Some(value.clone());
        }
    }
    Ok(())
}

fn reduced_value_to_scalar(
    value: Option<KvReducedValue>,
    data_type: &DataType,
) -> DataFusionResult<ScalarValue> {
    Ok(match (data_type, value) {
        (_, Some(KvReducedValue::Int64(v))) => {
            cast_scalar_value(ScalarValue::Int64(Some(v)), data_type)?
        }
        (_, Some(KvReducedValue::UInt64(v))) => {
            cast_scalar_value(ScalarValue::UInt64(Some(v)), data_type)?
        }
        (_, Some(KvReducedValue::Float64(v))) => {
            cast_scalar_value(ScalarValue::Float64(Some(v)), data_type)?
        }
        (_, Some(KvReducedValue::Boolean(v))) => {
            cast_scalar_value(ScalarValue::Boolean(Some(v)), data_type)?
        }
        (_, Some(KvReducedValue::Utf8(v))) => {
            cast_scalar_value(ScalarValue::Utf8(Some(v)), data_type)?
        }
        (_, Some(KvReducedValue::Date32(v))) => {
            cast_scalar_value(ScalarValue::Date32(Some(v)), data_type)?
        }
        (_, Some(KvReducedValue::Date64(v))) => {
            cast_scalar_value(ScalarValue::Date64(Some(v)), data_type)?
        }
        (DataType::Timestamp(TimeUnit::Microsecond, tz), Some(KvReducedValue::Timestamp(v))) => {
            ScalarValue::TimestampMicrosecond(Some(v), tz.clone())
        }
        (_, Some(KvReducedValue::Timestamp(v))) => {
            cast_scalar_value(ScalarValue::TimestampMicrosecond(Some(v), None), data_type)?
        }
        (_, Some(KvReducedValue::Decimal128(v))) => match data_type {
            DataType::Decimal128(precision, scale) => {
                ScalarValue::Decimal128(Some(v), *precision, *scale)
            }
            _ => {
                return Err(DataFusionError::Execution(format!(
                    "unsupported reduced scalar conversion to {:?}",
                    data_type
                )))
            }
        },
        (_, Some(KvReducedValue::FixedSizeBinary(v))) => cast_scalar_value(
            ScalarValue::FixedSizeBinary(v.len() as i32, Some(v)),
            data_type,
        )?,
        (DataType::Null, None) => ScalarValue::Null,
        (DataType::Int64, None) => ScalarValue::Int64(None),
        (DataType::UInt64, None) => ScalarValue::UInt64(None),
        (DataType::Float64, None) => ScalarValue::Float64(None),
        (DataType::Boolean, None) => ScalarValue::Boolean(None),
        (DataType::Utf8, None) => ScalarValue::Utf8(None),
        (DataType::LargeUtf8, None) => ScalarValue::LargeUtf8(None),
        (DataType::Utf8View, None) => ScalarValue::Utf8View(None),
        (DataType::Date32, None) => ScalarValue::Date32(None),
        (DataType::Date64, None) => ScalarValue::Date64(None),
        (DataType::Timestamp(TimeUnit::Microsecond, tz), None) => {
            ScalarValue::TimestampMicrosecond(None, tz.clone())
        }
        _ => {
            return Err(DataFusionError::Execution(format!(
                "unsupported reduced scalar conversion to {:?}",
                data_type
            )))
        }
    })
}

fn cast_scalar_value(value: ScalarValue, data_type: &DataType) -> DataFusionResult<ScalarValue> {
    if value.data_type() == *data_type {
        return Ok(value);
    }
    let array = value.to_array_of_size(1)?;
    let casted = cast(&array, data_type)?;
    ScalarValue::try_from_array(&casted, 0)
}

#[derive(Debug, Clone)]
struct MergedGroupResponseState {
    group_values: Vec<Option<KvReducedValue>>,
    states: Vec<PartialAggregateState>,
}

#[derive(Debug, Clone)]
struct GroupAccumulatorState {
    group_values: Vec<Option<KvReducedValue>>,
    aggregate_states: Vec<Option<Vec<PartialAggregateState>>>,
}

impl GroupAccumulatorState {
    fn new(group_values: Vec<Option<KvReducedValue>>, aggregate_count: usize) -> Self {
        Self {
            group_values,
            aggregate_states: vec![None; aggregate_count],
        }
    }

    fn merge_expr_results(
        &mut self,
        expr_idx: usize,
        reducers: &[RangeReducerSpec],
        partials: &[RangeReduceResult],
    ) -> DataFusionResult<()> {
        if partials.len() != reducers.len() {
            return Err(DataFusionError::Execution(
                "range reduction response length mismatch".to_string(),
            ));
        }
        let states = self.aggregate_states[expr_idx].get_or_insert_with(|| {
            reducers
                .iter()
                .map(|reducer| PartialAggregateState::from_op(reducer.op))
                .collect::<Vec<_>>()
        });
        for ((state, reducer), partial) in
            states.iter_mut().zip(reducers.iter()).zip(partials.iter())
        {
            state.merge_partial(reducer.op, partial.value.as_ref())?;
        }
        Ok(())
    }
}

async fn execute_aggregate_pushdown(
    spec: AggregatePushdownSpec,
    projection: Option<Vec<usize>>,
    projected_schema: SchemaRef,
) -> DataFusionResult<RecordBatch> {
    let session = spec.client.create_session();
    let mut groups = BTreeMap::<Vec<u8>, GroupAccumulatorState>::new();
    if spec.group_plans.is_empty() {
        groups.insert(
            Vec::new(),
            GroupAccumulatorState::new(Vec::new(), total_aggregate_outputs(&spec.aggregate_jobs)),
        );
    }

    if let Some(seed_job) = &spec.seed_job {
        let response = execute_reduce_job(&session, seed_job).await?;
        if !response.results.is_empty() {
            return Err(DataFusionError::Execution(
                "group seed job returned scalar reductions".to_string(),
            ));
        }
        for group in response.groups {
            let key = encode_reduced_group_key(&group.group_values);
            groups.entry(key).or_insert_with(|| {
                GroupAccumulatorState::new(
                    group.group_values,
                    total_aggregate_outputs(&spec.aggregate_jobs),
                )
            });
        }
    }

    let mut output_base_idx = 0usize;
    for combined_job in &spec.aggregate_jobs {
        let response = execute_reduce_job(&session, &combined_job.job).await?;
        if spec.group_plans.is_empty() {
            if !response.groups.is_empty() {
                return Err(DataFusionError::Execution(
                    "scalar aggregate job returned grouped reductions".to_string(),
                ));
            }
            let group = groups.get_mut(&Vec::new()).ok_or_else(|| {
                DataFusionError::Execution("missing scalar aggregate accumulator".to_string())
            })?;
            for (expr_offset, expr_plan) in combined_job.expr_plans.iter().enumerate() {
                group.merge_expr_results(
                    output_base_idx + expr_offset,
                    reducers_for_output(&combined_job.job.request.reducers, expr_plan),
                    results_for_output(&response.results, expr_plan),
                )?;
            }
        } else {
            if !response.results.is_empty() {
                return Err(DataFusionError::Execution(
                    "grouped aggregate job returned scalar reductions".to_string(),
                ));
            }
            for group_response in &response.groups {
                let key = encode_reduced_group_key(&group_response.group_values);
                let group = groups.entry(key).or_insert_with(|| {
                    GroupAccumulatorState::new(
                        group_response.group_values.clone(),
                        total_aggregate_outputs(&spec.aggregate_jobs),
                    )
                });
                for (expr_offset, expr_plan) in combined_job.expr_plans.iter().enumerate() {
                    group.merge_expr_results(
                        output_base_idx + expr_offset,
                        reducers_for_output(&combined_job.job.request.reducers, expr_plan),
                        results_for_output(&group_response.results, expr_plan),
                    )?;
                }
            }
        }
        output_base_idx += combined_job.expr_plans.len();
    }

    let mut rows = Vec::new();
    for group in groups.into_values() {
        let mut row = Vec::with_capacity(
            spec.group_plans.len() + total_aggregate_outputs(&spec.aggregate_jobs),
        );
        for (idx, group_plan) in spec.group_plans.iter().enumerate() {
            let value = group.group_values.get(idx).cloned().unwrap_or(None);
            row.push(reduced_value_to_scalar(value, &group_plan.data_type)?);
        }
        let mut output_idx = 0usize;
        for combined_job in &spec.aggregate_jobs {
            for expr_plan in &combined_job.expr_plans {
                row.push(finalize_aggregate_output(
                    expr_plan,
                    group.aggregate_states[output_idx].as_deref(),
                    reducers_for_output(&combined_job.job.request.reducers, expr_plan),
                )?);
                output_idx += 1;
            }
        }
        rows.push(row);
    }

    build_projected_record_batch(rows, spec.schema, projection, projected_schema)
}

fn finalize_avg(
    sum_state: &PartialAggregateState,
    count_state: &PartialAggregateState,
    data_type: &DataType,
) -> DataFusionResult<ScalarValue> {
    let PartialAggregateState::Count(count) = count_state else {
        return Err(DataFusionError::Execution(
            "avg count state must be Count".to_string(),
        ));
    };
    if *count == 0 {
        return reduced_value_to_scalar(None, data_type);
    }
    let avg = match sum_state {
        PartialAggregateState::Sum(Some(KvReducedValue::Int64(v))) => *v as f64 / *count as f64,
        PartialAggregateState::Sum(Some(KvReducedValue::UInt64(v))) => *v as f64 / *count as f64,
        PartialAggregateState::Sum(Some(KvReducedValue::Float64(v))) => *v / *count as f64,
        _ => {
            return Err(DataFusionError::Execution(
                "unsupported avg input type for pushdown".to_string(),
            ))
        }
    };
    match data_type {
        DataType::Float64 => Ok(ScalarValue::Float64(Some(avg))),
        _ => Err(DataFusionError::Execution(format!(
            "unsupported avg return type {:?}",
            data_type
        ))),
    }
}

async fn execute_reduce_job(
    session: &SerializableReadSession,
    job: &AggregateReduceJob,
) -> DataFusionResult<RangeReduceResponse> {
    if job.request.group_by.is_empty() {
        let mut states = job
            .request
            .reducers
            .iter()
            .map(|reducer| PartialAggregateState::from_op(reducer.op))
            .collect::<Vec<_>>();
        for range in &job.ranges {
            let response = session
                .range_reduce_response(&range.start, &range.end, &job.request)
                .await
                .map_err(|e| DataFusionError::External(Box::new(e)))?;
            let archived = to_domain_reduce_response(response).map_err(|e| {
                DataFusionError::Execution(format!("range reduction response decode: {e}"))
            })?;
            if !archived.groups.is_empty() {
                return Err(DataFusionError::Execution(
                    "scalar reduction job returned grouped results".to_string(),
                ));
            }
            if archived.results.len() != states.len() {
                return Err(DataFusionError::Execution(
                    "range reduction response length mismatch".to_string(),
                ));
            }
            for ((state, reducer), partial) in states
                .iter_mut()
                .zip(job.request.reducers.iter())
                .zip(archived.results.iter())
            {
                state.merge_partial(reducer.op, partial.value.as_ref())?;
            }
        }
        return Ok(RangeReduceResponse {
            results: states
                .into_iter()
                .map(|state| RangeReduceResult {
                    value: match state {
                        PartialAggregateState::Count(count) => Some(KvReducedValue::UInt64(count)),
                        PartialAggregateState::Sum(value)
                        | PartialAggregateState::Min(value)
                        | PartialAggregateState::Max(value) => value,
                    },
                })
                .collect(),
            groups: Vec::new(),
        });
    }

    let mut groups = BTreeMap::<Vec<u8>, MergedGroupResponseState>::new();
    for range in &job.ranges {
        let response = session
            .range_reduce_response(&range.start, &range.end, &job.request)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
        let archived = to_domain_reduce_response(response).map_err(|e| {
            DataFusionError::Execution(format!("range reduction response decode: {e}"))
        })?;
        if !archived.results.is_empty() {
            return Err(DataFusionError::Execution(
                "grouped reduction job returned scalar results".to_string(),
            ));
        }
        for group in archived.groups {
            merge_domain_group_reduce_response(&mut groups, &job.request.reducers, group)?;
        }
    }
    Ok(RangeReduceResponse {
        results: Vec::new(),
        groups: groups
            .into_values()
            .map(|group| RangeReduceGroup {
                group_values: group.group_values,
                results: group
                    .states
                    .into_iter()
                    .map(|state| RangeReduceResult {
                        value: match state {
                            PartialAggregateState::Count(count) => {
                                Some(KvReducedValue::UInt64(count))
                            }
                            PartialAggregateState::Sum(value)
                            | PartialAggregateState::Min(value)
                            | PartialAggregateState::Max(value) => value,
                        },
                    })
                    .collect(),
            })
            .collect(),
    })
}

fn merge_domain_group_reduce_response(
    groups: &mut BTreeMap<Vec<u8>, MergedGroupResponseState>,
    reducers: &[RangeReducerSpec],
    mut group: RangeReduceGroup,
) -> DataFusionResult<()> {
    if group.results.len() != reducers.len() {
        return Err(DataFusionError::Execution(
            "grouped range reduction response length mismatch".to_string(),
        ));
    }
    canonicalize_reduced_group_values(&mut group.group_values);
    let key = encode_reduced_group_key(&group.group_values);
    let entry = groups
        .entry(key)
        .or_insert_with(|| MergedGroupResponseState {
            group_values: group.group_values.clone(),
            states: reducers
                .iter()
                .map(|reducer| PartialAggregateState::from_op(reducer.op))
                .collect(),
        });
    for ((state, reducer), partial) in entry
        .states
        .iter_mut()
        .zip(reducers.iter())
        .zip(group.results.iter())
    {
        state.merge_partial(reducer.op, partial.value.as_ref())?;
    }
    Ok(())
}

fn finalize_aggregate_output(
    output: &AggregateOutputPlan,
    states: Option<&[PartialAggregateState]>,
    reducers: &[RangeReducerSpec],
) -> DataFusionResult<ScalarValue> {
    let default_states;
    let states = match states {
        Some(states) => states,
        None => {
            default_states = reducers
                .iter()
                .map(|reducer| PartialAggregateState::from_op(reducer.op))
                .collect::<Vec<_>>();
            &default_states
        }
    };
    match output {
        AggregateOutputPlan::Direct {
            reducer_idx,
            data_type,
        } => states[*reducer_idx].as_scalar_value(data_type),
        AggregateOutputPlan::Avg {
            sum_idx,
            count_idx,
            data_type,
        } => finalize_avg(&states[*sum_idx], &states[*count_idx], data_type),
    }
}

fn build_projected_record_batch(
    rows: Vec<Vec<ScalarValue>>,
    full_schema: SchemaRef,
    projection: Option<Vec<usize>>,
    projected_schema: SchemaRef,
) -> DataFusionResult<RecordBatch> {
    let projected_indices = projection.unwrap_or_else(|| (0..full_schema.fields().len()).collect());
    let mut arrays = Vec::with_capacity(projected_indices.len());
    for (projected_pos, idx) in projected_indices.into_iter().enumerate() {
        if rows.is_empty() {
            arrays.push(new_empty_array(
                projected_schema.field(projected_pos).data_type(),
            ));
        } else {
            let values = rows.iter().map(|row| row[idx].clone());
            arrays.push(ScalarValue::iter_to_array(values)?);
        }
    }
    RecordBatch::try_new(projected_schema, arrays).map_err(Into::into)
}

fn total_aggregate_outputs(jobs: &[CombinedAggregateJob]) -> usize {
    jobs.iter().map(|job| job.expr_plans.len()).sum()
}

fn reducers_for_output<'a>(
    reducers: &'a [RangeReducerSpec],
    output: &AggregateOutputPlan,
) -> &'a [RangeReducerSpec] {
    match output {
        AggregateOutputPlan::Direct { reducer_idx, .. } => {
            &reducers[*reducer_idx..*reducer_idx + 1]
        }
        AggregateOutputPlan::Avg {
            sum_idx, count_idx, ..
        } => &reducers[*sum_idx..*count_idx + 1],
    }
}

fn results_for_output<'a>(
    results: &'a [RangeReduceResult],
    output: &AggregateOutputPlan,
) -> &'a [RangeReduceResult] {
    match output {
        AggregateOutputPlan::Direct { reducer_idx, .. } => &results[*reducer_idx..*reducer_idx + 1],
        AggregateOutputPlan::Avg {
            sum_idx, count_idx, ..
        } => &results[*sum_idx..*count_idx + 1],
    }
}

fn rebase_output_plan(output: AggregateOutputPlan, offset: usize) -> AggregateOutputPlan {
    match output {
        AggregateOutputPlan::Direct {
            reducer_idx,
            data_type,
        } => AggregateOutputPlan::Direct {
            reducer_idx: reducer_idx + offset,
            data_type,
        },
        AggregateOutputPlan::Avg {
            sum_idx,
            count_idx,
            data_type,
        } => AggregateOutputPlan::Avg {
            sum_idx: sum_idx + offset,
            count_idx: count_idx + offset,
            data_type,
        },
    }
}

fn combine_aggregate_jobs(exprs: Vec<AggregateExprPlan>) -> Vec<CombinedAggregateJob> {
    let mut combined: Vec<CombinedAggregateJob> = Vec::new();
    for expr in exprs {
        if let Some(existing) = combined
            .iter_mut()
            .find(|candidate| candidate.job == expr.job)
        {
            let offset = existing.job.request.reducers.len();
            let rebased_output = rebase_output_plan(expr.output, offset);
            existing
                .job
                .request
                .reducers
                .extend(expr.job.request.reducers);
            existing.expr_plans.push(rebased_output);
        } else {
            combined.push(CombinedAggregateJob {
                job: expr.job,
                expr_plans: vec![expr.output],
            });
        }
    }
    combined
}

#[derive(Debug, Clone)]
struct CompiledGroupExpr {
    expr: PushdownValueExpr,
    data_type: DataType,
}

fn try_build_aggregate_pushdown_spec(
    table: &KvTable,
    scan: &datafusion::logical_expr::logical_plan::TableScan,
    group_exprs: &[Expr],
    aggr_exprs: &[Expr],
    schema: &datafusion::common::DFSchemaRef,
) -> DataFusionResult<Option<AggregatePushdownSpec>> {
    let mut compiled_group_exprs = Vec::with_capacity(group_exprs.len());
    for (idx, expr) in group_exprs.iter().enumerate() {
        let data_type = schema.field(idx).data_type().clone();
        let compiled_expr = match compile_pushdown_value_expr(expr, &table.model) {
            Ok((compiled_expr, _)) => compiled_expr,
            Err(_) => return Ok(None),
        };
        compiled_group_exprs.push(CompiledGroupExpr {
            expr: compiled_expr,
            data_type,
        });
    }

    let mut aggregate_exprs = Vec::new();
    let mut aggregate_diagnostics = Vec::new();
    let mut has_filtered_aggregate = false;
    for (expr_idx, expr) in aggr_exprs.iter().enumerate() {
        let data_type = schema
            .field(group_exprs.len() + expr_idx)
            .data_type()
            .clone();
        let local_filter = match aggregate_expr_filter(expr, &table.model) {
            Ok(filter) => filter,
            Err(_) => return Ok(None),
        };
        has_filtered_aggregate |= local_filter.is_some();
        let mut filters = scan.filters.clone();
        if let Some(filter) = local_filter {
            if !QueryPredicate::supports_filter(&filter, &table.model) {
                return Ok(None);
            }
            filters.push(filter);
        }
        let Some((job, diagnostics, output)) = build_aggregate_reduce_job(
            table,
            &filters,
            &compiled_group_exprs,
            Some(expr),
            Some(data_type),
        )?
        else {
            return Ok(None);
        };
        let Some(output) = output else {
            return Ok(None);
        };
        aggregate_exprs.push(AggregateExprPlan { job, output });
        aggregate_diagnostics.push(diagnostics);
    }

    if aggregate_exprs.is_empty() {
        return Ok(None);
    }

    let seed_job = if !compiled_group_exprs.is_empty() && has_filtered_aggregate {
        let Some((job, diagnostics, _)) =
            build_aggregate_reduce_job(table, &scan.filters, &compiled_group_exprs, None, None)?
        else {
            return Ok(None);
        };
        Some((job, diagnostics))
    } else {
        None
    };

    Ok(Some(AggregatePushdownSpec {
        client: table.client.clone(),
        group_plans: compiled_group_exprs
            .iter()
            .map(|group| AggregateGroupPlan {
                data_type: group.data_type.clone(),
            })
            .collect(),
        seed_job: seed_job.as_ref().map(|(job, _)| job.clone()),
        aggregate_jobs: combine_aggregate_jobs(aggregate_exprs),
        diagnostics: AggregatePushdownDiagnostics {
            grouped: !compiled_group_exprs.is_empty(),
            seed_job: seed_job.map(|(_, diagnostics)| diagnostics),
            aggregate_jobs: aggregate_diagnostics,
        },
        schema: Arc::new(schema.as_arrow().clone()),
    }))
}

fn build_aggregate_reduce_job(
    table: &KvTable,
    filters: &[Expr],
    group_exprs: &[CompiledGroupExpr],
    aggr_expr: Option<&Expr>,
    data_type: Option<DataType>,
) -> DataFusionResult<
    Option<(
        AggregateReduceJob,
        AccessPathDiagnostics,
        Option<AggregateOutputPlan>,
    )>,
> {
    let predicate = QueryPredicate::from_filters(filters, &table.model);
    let required_projection =
        match reduce_job_required_projection(group_exprs, aggr_expr, &table.model) {
            Ok(required_projection) => required_projection,
            Err(_) => return Ok(None),
        };
    let projection = Some(required_projection);
    let access_plan = ScanAccessPlan::new(&table.model, &projection, &predicate);
    let Some((ranges, access_path, constrained_prefix_len, exact)) =
        choose_aggregate_access_path(table, &predicate, &access_plan)?
    else {
        return Ok(None);
    };
    let Some(group_by) =
        compile_group_exprs(group_exprs, &table.model, &table.index_specs, &access_path)
    else {
        return Ok(None);
    };
    let (reducers, output) = match (aggr_expr, data_type) {
        (Some(expr), Some(data_type)) => match compile_aggregate_expr(
            expr,
            &table.model,
            &table.index_specs,
            &access_path,
            0,
            data_type,
        ) {
            Ok((reducers, output)) => (reducers, Some(output)),
            Err(_) => return Ok(None),
        },
        (None, None) => (Vec::new(), None),
        _ => {
            return Err(DataFusionError::Execution(
                "aggregate reduction job configuration mismatch".to_string(),
            ))
        }
    };
    let diagnostics = build_aggregate_access_path_diagnostics(
        &table.model,
        &table.index_specs,
        &predicate,
        &access_path,
        &ranges,
        constrained_prefix_len,
        exact,
    );
    let filter = if exact {
        None
    } else {
        compile_reduce_filter(&predicate, &table.model, &table.index_specs, &access_path)
    };
    if !exact && filter.is_none() {
        return Ok(None);
    }
    Ok(Some((
        AggregateReduceJob {
            request: RangeReduceRequest {
                reducers,
                group_by,
                filter,
            },
            ranges,
        },
        diagnostics,
        output,
    )))
}

fn choose_aggregate_access_path(
    table: &KvTable,
    predicate: &QueryPredicate,
    access_plan: &ScanAccessPlan,
) -> DataFusionResult<Option<ChosenAggregateAccessPath>> {
    Ok(Some(
        if let Some(index_plan) = predicate.choose_index_plan(&table.model, &table.index_specs)? {
            if !index_plan.ranges.is_empty()
                && access_plan.index_covers_required_non_pk(&table.index_specs[index_plan.spec_idx])
            {
                let exact = access_plan.predicate_fully_enforced_by_index_key(
                    &table.model,
                    &table.index_specs[index_plan.spec_idx],
                );
                (
                    index_plan.ranges,
                    AggregateAccessPath::SecondaryIndex {
                        spec_idx: index_plan.spec_idx,
                    },
                    Some(index_plan.constrained_prefix_len),
                    exact,
                )
            } else if access_plan.predicate_fully_enforced_by_primary_key(&table.model) {
                (
                    predicate.primary_key_ranges(&table.model)?,
                    AggregateAccessPath::PrimaryKey,
                    None,
                    true,
                )
            } else {
                return Ok(None);
            }
        } else if access_plan.predicate_fully_enforced_by_primary_key(&table.model) {
            (
                predicate.primary_key_ranges(&table.model)?,
                AggregateAccessPath::PrimaryKey,
                None,
                true,
            )
        } else {
            return Ok(None);
        },
    ))
}

fn reduce_job_required_projection(
    group_exprs: &[CompiledGroupExpr],
    aggr_expr: Option<&Expr>,
    model: &TableModel,
) -> DataFusionResult<Vec<usize>> {
    let mut cols = group_exprs
        .iter()
        .flat_map(|group| {
            let mut cols = Vec::new();
            group.expr.collect_columns(&mut cols);
            cols
        })
        .collect::<Vec<_>>();
    if let Some(expr) = aggr_expr {
        aggregate_argument_columns(expr, model, &mut cols)?;
    }
    cols.sort_unstable();
    cols.dedup();
    Ok(cols)
}

fn compile_group_exprs(
    group_exprs: &[CompiledGroupExpr],
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
    access_path: &AggregateAccessPath,
) -> Option<Vec<KvExpr>> {
    group_exprs
        .iter()
        .map(|group| compile_reduce_expr(&group.expr, model, index_specs, access_path))
        .collect()
}

fn compile_aggregate_expr(
    expr: &Expr,
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
    access_path: &AggregateAccessPath,
    next_reducer_idx: usize,
    data_type: DataType,
) -> DataFusionResult<(Vec<RangeReducerSpec>, AggregateOutputPlan)> {
    let normalized = normalize_aggregate_expr(expr, model)?;
    match (normalized.func, normalized.argument) {
        (AggregatePushdownFunction::Count, AggregatePushdownArgument::CountAll) => Ok((
            vec![RangeReducerSpec {
                op: RangeReduceOp::CountAll,
                expr: None,
            }],
            AggregateOutputPlan::Direct {
                reducer_idx: next_reducer_idx,
                data_type,
            },
        )),
        (func, AggregatePushdownArgument::Expr(value_expr)) => {
            let compiled_expr = compile_reduce_expr(&value_expr, model, index_specs, access_path)
                .ok_or_else(|| {
                DataFusionError::Execution(
                    "aggregate argument is not available from pushdown access path".to_string(),
                )
            })?;
            match func {
                AggregatePushdownFunction::Count => Ok((
                    vec![RangeReducerSpec {
                        op: RangeReduceOp::CountField,
                        expr: Some(compiled_expr),
                    }],
                    AggregateOutputPlan::Direct {
                        reducer_idx: next_reducer_idx,
                        data_type,
                    },
                )),
                AggregatePushdownFunction::Sum => Ok((
                    vec![RangeReducerSpec {
                        op: RangeReduceOp::SumField,
                        expr: Some(compiled_expr),
                    }],
                    AggregateOutputPlan::Direct {
                        reducer_idx: next_reducer_idx,
                        data_type,
                    },
                )),
                AggregatePushdownFunction::Min => Ok((
                    vec![RangeReducerSpec {
                        op: RangeReduceOp::MinField,
                        expr: Some(compiled_expr),
                    }],
                    AggregateOutputPlan::Direct {
                        reducer_idx: next_reducer_idx,
                        data_type,
                    },
                )),
                AggregatePushdownFunction::Max => Ok((
                    vec![RangeReducerSpec {
                        op: RangeReduceOp::MaxField,
                        expr: Some(compiled_expr),
                    }],
                    AggregateOutputPlan::Direct {
                        reducer_idx: next_reducer_idx,
                        data_type,
                    },
                )),
                AggregatePushdownFunction::Avg => Ok((
                    vec![
                        RangeReducerSpec {
                            op: RangeReduceOp::SumField,
                            expr: Some(compiled_expr.clone()),
                        },
                        RangeReducerSpec {
                            op: RangeReduceOp::CountField,
                            expr: Some(compiled_expr),
                        },
                    ],
                    AggregateOutputPlan::Avg {
                        sum_idx: next_reducer_idx,
                        count_idx: next_reducer_idx + 1,
                        data_type,
                    },
                )),
            }
        }
        (_, AggregatePushdownArgument::CountAll) => Err(DataFusionError::Execution(
            "aggregate pushdown normalized unsupported count-all aggregate".to_string(),
        )),
    }
}

fn strip_alias_expr(expr: &Expr) -> &Expr {
    if let Expr::Alias(alias) = expr {
        return strip_alias_expr(&alias.expr);
    }
    expr
}

fn aggregate_expr_filter(expr: &Expr, model: &TableModel) -> DataFusionResult<Option<Expr>> {
    Ok(normalize_aggregate_expr(expr, model)?.filter)
}

fn aggregate_argument_columns(
    expr: &Expr,
    model: &TableModel,
    out: &mut Vec<usize>,
) -> DataFusionResult<()> {
    match normalize_aggregate_expr(expr, model)?.argument {
        AggregatePushdownArgument::CountAll => {}
        AggregatePushdownArgument::Expr(expr) => expr.collect_columns(out),
    }
    Ok(())
}

fn compile_reduce_filter(
    predicate: &QueryPredicate,
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
    access_path: &AggregateAccessPath,
) -> Option<KvPredicate> {
    if predicate.contradiction {
        return Some(KvPredicate {
            checks: Vec::new(),
            contradiction: true,
        });
    }
    let mut cols = predicate.constraints.keys().copied().collect::<Vec<_>>();
    cols.sort_unstable();
    let mut checks = Vec::with_capacity(cols.len());
    for col_idx in cols {
        checks.push(KvPredicateCheck {
            field: aggregate_field_ref(col_idx, model, index_specs, access_path)?,
            constraint: compile_kv_predicate_constraint(predicate.constraints.get(&col_idx)?)?,
        });
    }
    Some(KvPredicate {
        checks,
        contradiction: false,
    })
}

fn compile_kv_predicate_constraint(
    constraint: &PredicateConstraint,
) -> Option<KvPredicateConstraint> {
    Some(match constraint {
        PredicateConstraint::StringEq(value) => KvPredicateConstraint::StringEq(value.clone()),
        PredicateConstraint::BoolEq(value) => KvPredicateConstraint::BoolEq(*value),
        PredicateConstraint::FixedBinaryEq(value) => {
            KvPredicateConstraint::FixedSizeBinaryEq(value.clone())
        }
        PredicateConstraint::IntRange { min, max } => KvPredicateConstraint::IntRange {
            min: *min,
            max: *max,
        },
        PredicateConstraint::UInt64Range { min, max } => KvPredicateConstraint::UInt64Range {
            min: *min,
            max: *max,
        },
        PredicateConstraint::FloatRange { min, max } => KvPredicateConstraint::FloatRange {
            min: *min,
            max: *max,
        },
        PredicateConstraint::Decimal128Range { min, max } => {
            KvPredicateConstraint::Decimal128Range {
                min: *min,
                max: *max,
            }
        }
        PredicateConstraint::IsNull => KvPredicateConstraint::IsNull,
        PredicateConstraint::IsNotNull => KvPredicateConstraint::IsNotNull,
        PredicateConstraint::StringIn(values) => KvPredicateConstraint::StringIn(values.clone()),
        PredicateConstraint::IntIn(values) => KvPredicateConstraint::IntIn(values.clone()),
        PredicateConstraint::UInt64In(values) => KvPredicateConstraint::UInt64In(values.clone()),
        PredicateConstraint::FixedBinaryIn(values) => {
            KvPredicateConstraint::FixedSizeBinaryIn(values.clone())
        }
        PredicateConstraint::Decimal256Range { .. } => return None,
    })
}

#[allow(deprecated)]
fn is_count_rows_arg(expr: &Expr) -> bool {
    matches!(expr, Expr::Wildcard { .. })
        || matches!(
            strip_aggregate_argument_expr(expr),
            Expr::Literal(value, _) if !value.is_null()
        )
}

fn strip_aggregate_argument_expr(expr: &Expr) -> &Expr {
    match expr {
        Expr::Alias(alias) => strip_aggregate_argument_expr(&alias.expr),
        Expr::Cast(cast) => strip_aggregate_argument_expr(&cast.expr),
        Expr::TryCast(cast) => strip_aggregate_argument_expr(&cast.expr),
        other => other,
    }
}

fn compile_pushdown_value_expr(
    expr: &Expr,
    model: &TableModel,
) -> DataFusionResult<(PushdownValueExpr, KvFieldKind)> {
    match strip_aggregate_argument_expr(expr) {
        Expr::Column(column) => {
            let Some(&col_idx) = model.columns_by_name.get(&column.name) else {
                return Err(DataFusionError::Execution(format!(
                    "unknown pushdown expression column '{}'",
                    column.name
                )));
            };
            let kind = kv_field_kind(model.column(col_idx).kind).ok_or_else(|| {
                DataFusionError::Execution(format!(
                    "pushdown expression does not support column '{}'",
                    column.name
                ))
            })?;
            Ok((PushdownValueExpr::Column(col_idx), kind))
        }
        Expr::Literal(value, _) => scalar_to_reduced_literal(value)
            .ok_or_else(|| {
                DataFusionError::Execution("unsupported pushdown expression literal".to_string())
            })
            .map(|(value, kind)| (PushdownValueExpr::Literal(value), kind)),
        Expr::BinaryExpr(binary) if binary.op == Operator::Plus => {
            let (left, left_kind) = compile_pushdown_value_expr(binary.left.as_ref(), model)?;
            let (right, right_kind) = compile_pushdown_value_expr(binary.right.as_ref(), model)?;
            let kind = infer_pushdown_add_sub_kind(left_kind, right_kind, "addition")?;
            Ok((
                PushdownValueExpr::Add(Box::new(left), Box::new(right)),
                kind,
            ))
        }
        Expr::BinaryExpr(binary) if binary.op == Operator::Minus => {
            let (left, left_kind) = compile_pushdown_value_expr(binary.left.as_ref(), model)?;
            let (right, right_kind) = compile_pushdown_value_expr(binary.right.as_ref(), model)?;
            let kind = infer_pushdown_add_sub_kind(left_kind, right_kind, "subtraction")?;
            Ok((
                PushdownValueExpr::Sub(Box::new(left), Box::new(right)),
                kind,
            ))
        }
        Expr::BinaryExpr(binary) if binary.op == Operator::Multiply => {
            let (left, left_kind) = compile_pushdown_value_expr(binary.left.as_ref(), model)?;
            let (right, right_kind) = compile_pushdown_value_expr(binary.right.as_ref(), model)?;
            let kind = infer_pushdown_mul_kind(left_kind, right_kind)?;
            Ok((
                PushdownValueExpr::Mul(Box::new(left), Box::new(right)),
                kind,
            ))
        }
        Expr::BinaryExpr(binary) if binary.op == Operator::Divide => {
            let (left, left_kind) = compile_pushdown_value_expr(binary.left.as_ref(), model)?;
            let (right, right_kind) = compile_pushdown_value_expr(binary.right.as_ref(), model)?;
            ensure_pushdown_divisor_supported(&right)?;
            let kind = infer_pushdown_div_kind(left_kind, right_kind)?;
            Ok((
                PushdownValueExpr::Div(Box::new(left), Box::new(right)),
                kind,
            ))
        }
        Expr::ScalarFunction(func) => compile_pushdown_scalar_function(func, model),
        _ => Err(DataFusionError::Execution(
            "pushdown expression shape is unsupported".to_string(),
        )),
    }
}

fn compile_pushdown_scalar_function(
    func: &datafusion::logical_expr::expr::ScalarFunction,
    model: &TableModel,
) -> DataFusionResult<(PushdownValueExpr, KvFieldKind)> {
    let func_name = func.name().to_ascii_lowercase();
    match func_name.as_str() {
        "lower" => {
            if func.args.len() != 1 {
                return Err(DataFusionError::Execution(
                    "lower() pushdown requires exactly one argument".to_string(),
                ));
            }
            let (inner, kind) = compile_pushdown_value_expr(&func.args[0], model)?;
            if kind != KvFieldKind::Utf8 {
                return Err(DataFusionError::Execution(
                    "lower() pushdown requires Utf8 input".to_string(),
                ));
            }
            Ok((PushdownValueExpr::Lower(Box::new(inner)), KvFieldKind::Utf8))
        }
        "date_trunc" => {
            if func.args.len() != 2 {
                return Err(DataFusionError::Execution(
                    "date_trunc() pushdown requires exactly two arguments".to_string(),
                ));
            }
            let unit = extract_pushdown_string_literal(&func.args[0]).ok_or_else(|| {
                DataFusionError::Execution(
                    "date_trunc() pushdown requires a string literal unit".to_string(),
                )
            })?;
            if !unit.eq_ignore_ascii_case("day") {
                return Err(DataFusionError::Execution(
                    "date_trunc() pushdown only supports 'day'".to_string(),
                ));
            }
            let (inner, kind) = compile_pushdown_value_expr(&func.args[1], model)?;
            if !matches!(
                kind,
                KvFieldKind::Date32 | KvFieldKind::Date64 | KvFieldKind::Timestamp
            ) {
                return Err(DataFusionError::Execution(
                    "date_trunc('day', ...) pushdown requires Date32/Date64/Timestamp input"
                        .to_string(),
                ));
            }
            Ok((PushdownValueExpr::DateTruncDay(Box::new(inner)), kind))
        }
        _ => Err(DataFusionError::Execution(format!(
            "pushdown expression does not support function '{func_name}'"
        ))),
    }
}

fn infer_pushdown_mul_kind(left: KvFieldKind, right: KvFieldKind) -> DataFusionResult<KvFieldKind> {
    match (left, right) {
        (KvFieldKind::Int64, KvFieldKind::Int64) => Ok(KvFieldKind::Int64),
        (KvFieldKind::UInt64, KvFieldKind::UInt64) => Ok(KvFieldKind::UInt64),
        (KvFieldKind::Float64, KvFieldKind::Float64)
        | (KvFieldKind::Float64, KvFieldKind::Int64)
        | (KvFieldKind::Int64, KvFieldKind::Float64)
        | (KvFieldKind::Float64, KvFieldKind::UInt64)
        | (KvFieldKind::UInt64, KvFieldKind::Float64) => Ok(KvFieldKind::Float64),
        _ => Err(DataFusionError::Execution(
            "pushdown multiplication only supports Int64, UInt64, and Float64".to_string(),
        )),
    }
}

fn infer_pushdown_add_sub_kind(
    left: KvFieldKind,
    right: KvFieldKind,
    op_name: &str,
) -> DataFusionResult<KvFieldKind> {
    match (left, right) {
        (KvFieldKind::Int64, KvFieldKind::Int64) => Ok(KvFieldKind::Int64),
        (KvFieldKind::UInt64, KvFieldKind::UInt64) => Ok(KvFieldKind::UInt64),
        (KvFieldKind::Float64, KvFieldKind::Float64)
        | (KvFieldKind::Float64, KvFieldKind::Int64)
        | (KvFieldKind::Int64, KvFieldKind::Float64)
        | (KvFieldKind::Float64, KvFieldKind::UInt64)
        | (KvFieldKind::UInt64, KvFieldKind::Float64) => Ok(KvFieldKind::Float64),
        _ => Err(DataFusionError::Execution(format!(
            "pushdown {op_name} only supports Int64, UInt64, and Float64"
        ))),
    }
}

fn infer_pushdown_div_kind(left: KvFieldKind, right: KvFieldKind) -> DataFusionResult<KvFieldKind> {
    match (left, right) {
        (KvFieldKind::Int64, KvFieldKind::Int64)
        | (KvFieldKind::UInt64, KvFieldKind::UInt64)
        | (KvFieldKind::Float64, KvFieldKind::Float64)
        | (KvFieldKind::Float64, KvFieldKind::Int64)
        | (KvFieldKind::Int64, KvFieldKind::Float64)
        | (KvFieldKind::Float64, KvFieldKind::UInt64)
        | (KvFieldKind::UInt64, KvFieldKind::Float64) => Ok(KvFieldKind::Float64),
        _ => Err(DataFusionError::Execution(
            "pushdown division only supports Int64, UInt64, and Float64".to_string(),
        )),
    }
}

fn ensure_pushdown_divisor_supported(expr: &PushdownValueExpr) -> DataFusionResult<()> {
    match expr {
        PushdownValueExpr::Literal(KvReducedValue::Int64(v)) if *v != 0 => Ok(()),
        PushdownValueExpr::Literal(KvReducedValue::UInt64(v)) if *v != 0 => Ok(()),
        PushdownValueExpr::Literal(KvReducedValue::Float64(v)) if *v != 0.0 => Ok(()),
        PushdownValueExpr::Literal(_) => Err(DataFusionError::Execution(
            "pushdown division does not support a zero literal divisor".to_string(),
        )),
        _ => Err(DataFusionError::Execution(
            "pushdown division requires a non-zero literal divisor".to_string(),
        )),
    }
}

fn scalar_to_reduced_literal(value: &ScalarValue) -> Option<(KvReducedValue, KvFieldKind)> {
    scalar_to_i64(value)
        .map(|v| (KvReducedValue::Int64(v), KvFieldKind::Int64))
        .or_else(|| scalar_to_u64(value).map(|v| (KvReducedValue::UInt64(v), KvFieldKind::UInt64)))
        .or_else(|| {
            scalar_to_f64(value).map(|v| (KvReducedValue::Float64(v), KvFieldKind::Float64))
        })
        .or_else(|| scalar_to_string(value).map(|v| (KvReducedValue::Utf8(v), KvFieldKind::Utf8)))
        .or_else(|| {
            scalar_to_date32_i64(value)
                .and_then(|v| i32::try_from(v).ok())
                .map(|v| (KvReducedValue::Date32(v), KvFieldKind::Date32))
        })
        .or_else(|| {
            scalar_to_date64(value).map(|v| (KvReducedValue::Date64(v), KvFieldKind::Date64))
        })
        .or_else(|| {
            scalar_to_timestamp_micros(value)
                .map(|v| (KvReducedValue::Timestamp(v), KvFieldKind::Timestamp))
        })
}

fn extract_pushdown_string_literal(expr: &Expr) -> Option<String> {
    match strip_aggregate_argument_expr(expr) {
        Expr::Literal(value, _) => scalar_to_string(value),
        _ => None,
    }
}

fn normalize_aggregate_expr(
    expr: &Expr,
    model: &TableModel,
) -> DataFusionResult<NormalizedAggregateExpr> {
    let expr = strip_alias_expr(expr);
    let Expr::AggregateFunction(agg) = expr else {
        return Err(DataFusionError::Execution(
            "aggregate pushdown only supports aggregate-function expressions".to_string(),
        ));
    };
    if agg.params.distinct || !agg.params.order_by.is_empty() {
        return Err(DataFusionError::Execution(
            "aggregate pushdown does not support DISTINCT/ORDER BY".to_string(),
        ));
    }
    if agg.params.args.len() != 1 {
        return Err(DataFusionError::Execution(
            "aggregate pushdown requires exactly one aggregate argument".to_string(),
        ));
    }

    let explicit_filter = agg
        .params
        .filter
        .as_ref()
        .map(|filter| strip_alias_expr(filter.as_ref()).clone());
    let (func, argument, case_filter) = match agg.func.name().to_ascii_lowercase().as_str() {
        "count" => normalize_count_aggregate_argument(&agg.params.args[0], model)?,
        "sum" => normalize_sum_aggregate_argument(&agg.params.args[0], model)?,
        "min" => normalize_column_or_case_aggregate(
            AggregatePushdownFunction::Min,
            &agg.params.args[0],
            model,
        )?,
        "max" => normalize_column_or_case_aggregate(
            AggregatePushdownFunction::Max,
            &agg.params.args[0],
            model,
        )?,
        "avg" => normalize_column_or_case_aggregate(
            AggregatePushdownFunction::Avg,
            &agg.params.args[0],
            model,
        )?,
        func_name => {
            return Err(DataFusionError::Execution(format!(
                "aggregate pushdown does not support function '{func_name}'"
            )))
        }
    };

    Ok(NormalizedAggregateExpr {
        func,
        argument,
        filter: combine_optional_filters(explicit_filter, case_filter, Operator::And),
    })
}

fn normalize_count_aggregate_argument(
    arg: &Expr,
    model: &TableModel,
) -> DataFusionResult<(
    AggregatePushdownFunction,
    AggregatePushdownArgument,
    Option<Expr>,
)> {
    if is_count_rows_arg(arg) {
        return Ok((
            AggregatePushdownFunction::Count,
            AggregatePushdownArgument::CountAll,
            None,
        ));
    }
    if let Some((argument, filter)) =
        normalize_case_aggregate_argument(AggregatePushdownFunction::Count, arg, model)?
    {
        return Ok((AggregatePushdownFunction::Count, argument, Some(filter)));
    }
    Ok((
        AggregatePushdownFunction::Count,
        AggregatePushdownArgument::Expr(compile_pushdown_value_expr(arg, model)?.0),
        None,
    ))
}

fn normalize_sum_aggregate_argument(
    arg: &Expr,
    model: &TableModel,
) -> DataFusionResult<(
    AggregatePushdownFunction,
    AggregatePushdownArgument,
    Option<Expr>,
)> {
    if let Some((argument, filter)) =
        normalize_case_aggregate_argument(AggregatePushdownFunction::Sum, arg, model)?
    {
        let func = if argument == AggregatePushdownArgument::CountAll {
            AggregatePushdownFunction::Count
        } else {
            AggregatePushdownFunction::Sum
        };
        return Ok((func, argument, Some(filter)));
    }
    Ok((
        AggregatePushdownFunction::Sum,
        AggregatePushdownArgument::Expr(compile_pushdown_value_expr(arg, model)?.0),
        None,
    ))
}

fn normalize_column_or_case_aggregate(
    func: AggregatePushdownFunction,
    arg: &Expr,
    model: &TableModel,
) -> DataFusionResult<(
    AggregatePushdownFunction,
    AggregatePushdownArgument,
    Option<Expr>,
)> {
    if let Some((argument, filter)) = normalize_case_aggregate_argument(func, arg, model)? {
        return Ok((func, argument, Some(filter)));
    }
    Ok((
        func,
        AggregatePushdownArgument::Expr(compile_pushdown_value_expr(arg, model)?.0),
        None,
    ))
}

fn normalize_case_aggregate_argument(
    func: AggregatePushdownFunction,
    arg: &Expr,
    model: &TableModel,
) -> DataFusionResult<Option<(AggregatePushdownArgument, Expr)>> {
    let Expr::Case(case) = strip_aggregate_argument_expr(arg) else {
        return Ok(None);
    };
    if case.when_then_expr.is_empty() {
        return Ok(None);
    }

    let mut argument = None;
    let mut filter = None;
    for (when_expr, then_expr) in &case.when_then_expr {
        let branch_argument = match normalize_case_then_expr(func, then_expr.as_ref(), model) {
            Ok(argument) => argument,
            Err(_) => return Ok(None),
        };
        if let Some(ref current) = argument {
            if current != &branch_argument {
                return Ok(None);
            }
        } else {
            argument = Some(branch_argument);
        }
        let branch_filter = build_case_branch_filter(case.expr.as_deref(), when_expr.as_ref());
        filter = combine_optional_filters(filter, Some(branch_filter), Operator::Or);
    }

    if !case_else_matches_case_aggregate(argument.as_ref(), case.else_expr.as_deref())? {
        return Ok(None);
    }

    match (argument, filter) {
        (Some(argument), Some(filter)) => Ok(Some((argument, filter))),
        _ => Ok(None),
    }
}

fn normalize_case_then_expr(
    func: AggregatePushdownFunction,
    expr: &Expr,
    model: &TableModel,
) -> DataFusionResult<AggregatePushdownArgument> {
    match func {
        AggregatePushdownFunction::Count => {
            if aggregate_non_null_literal(expr).is_some() {
                Ok(AggregatePushdownArgument::CountAll)
            } else if let Ok((compiled_expr, _)) = compile_pushdown_value_expr(expr, model) {
                Ok(AggregatePushdownArgument::Expr(compiled_expr))
            } else {
                Err(DataFusionError::Execution(
                    "count pushdown case branch must yield a supported expression or non-null literal"
                        .to_string(),
                ))
            }
        }
        AggregatePushdownFunction::Sum => {
            if is_integer_one_literal(expr) {
                Ok(AggregatePushdownArgument::CountAll)
            } else if let Ok((compiled_expr, _)) = compile_pushdown_value_expr(expr, model) {
                Ok(AggregatePushdownArgument::Expr(compiled_expr))
            } else {
                Err(DataFusionError::Execution(
                    "sum pushdown case branch must yield a supported expression or literal 1"
                        .to_string(),
                ))
            }
        }
        AggregatePushdownFunction::Min
        | AggregatePushdownFunction::Max
        | AggregatePushdownFunction::Avg => Ok(AggregatePushdownArgument::Expr(
            compile_pushdown_value_expr(expr, model)?.0,
        )),
    }
}

fn case_else_matches_case_aggregate(
    argument: Option<&AggregatePushdownArgument>,
    else_expr: Option<&Expr>,
) -> DataFusionResult<bool> {
    let Some(_argument) = argument else {
        return Ok(false);
    };
    let Some(else_expr) = else_expr else {
        return Ok(true);
    };
    if aggregate_literal(else_expr).is_some_and(ScalarValue::is_null) {
        return Ok(true);
    }
    Ok(false)
}

fn build_case_branch_filter(case_expr: Option<&Expr>, when_expr: &Expr) -> Expr {
    match case_expr {
        Some(base_expr) => Expr::BinaryExpr(datafusion::logical_expr::BinaryExpr {
            left: Box::new(strip_alias_expr(base_expr).clone()),
            op: Operator::Eq,
            right: Box::new(strip_alias_expr(when_expr).clone()),
        }),
        None => strip_alias_expr(when_expr).clone(),
    }
}

fn combine_optional_filters(left: Option<Expr>, right: Option<Expr>, op: Operator) -> Option<Expr> {
    match (left, right) {
        (Some(left), Some(right)) => Some(Expr::BinaryExpr(datafusion::logical_expr::BinaryExpr {
            left: Box::new(left),
            op,
            right: Box::new(right),
        })),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn aggregate_non_null_literal(expr: &Expr) -> Option<&ScalarValue> {
    aggregate_literal(expr).filter(|value| !value.is_null())
}

fn aggregate_literal(expr: &Expr) -> Option<&ScalarValue> {
    match strip_aggregate_argument_expr(expr) {
        Expr::Literal(value, _) => Some(value),
        _ => None,
    }
}

fn is_integer_one_literal(expr: &Expr) -> bool {
    aggregate_literal(expr).is_some_and(|value| {
        matches!(
            value,
            ScalarValue::Int8(Some(1))
                | ScalarValue::Int16(Some(1))
                | ScalarValue::Int32(Some(1))
                | ScalarValue::Int64(Some(1))
                | ScalarValue::UInt8(Some(1))
                | ScalarValue::UInt16(Some(1))
                | ScalarValue::UInt32(Some(1))
                | ScalarValue::UInt64(Some(1))
        )
    })
}

fn aggregate_field_ref(
    col_idx: usize,
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
    access_path: &AggregateAccessPath,
) -> Option<KvFieldRef> {
    match access_path {
        AggregateAccessPath::PrimaryKey => base_row_field_ref(col_idx, model),
        AggregateAccessPath::SecondaryIndex { spec_idx } => {
            index_row_field_ref(col_idx, model, &index_specs[*spec_idx])
        }
    }
}

fn compile_reduce_expr(
    expr: &PushdownValueExpr,
    model: &TableModel,
    index_specs: &[ResolvedIndexSpec],
    access_path: &AggregateAccessPath,
) -> Option<KvExpr> {
    match expr {
        PushdownValueExpr::Column(col_idx) => {
            aggregate_field_ref(*col_idx, model, index_specs, access_path).map(KvExpr::Field)
        }
        PushdownValueExpr::Literal(value) => Some(KvExpr::Literal(value.clone())),
        PushdownValueExpr::Add(left, right) => Some(KvExpr::Add(
            Box::new(compile_reduce_expr(left, model, index_specs, access_path)?),
            Box::new(compile_reduce_expr(right, model, index_specs, access_path)?),
        )),
        PushdownValueExpr::Sub(left, right) => Some(KvExpr::Sub(
            Box::new(compile_reduce_expr(left, model, index_specs, access_path)?),
            Box::new(compile_reduce_expr(right, model, index_specs, access_path)?),
        )),
        PushdownValueExpr::Mul(left, right) => Some(KvExpr::Mul(
            Box::new(compile_reduce_expr(left, model, index_specs, access_path)?),
            Box::new(compile_reduce_expr(right, model, index_specs, access_path)?),
        )),
        PushdownValueExpr::Div(left, right) => Some(KvExpr::Div(
            Box::new(compile_reduce_expr(left, model, index_specs, access_path)?),
            Box::new(compile_reduce_expr(right, model, index_specs, access_path)?),
        )),
        PushdownValueExpr::Lower(inner) => Some(KvExpr::Lower(Box::new(compile_reduce_expr(
            inner,
            model,
            index_specs,
            access_path,
        )?))),
        PushdownValueExpr::DateTruncDay(inner) => Some(KvExpr::DateTruncDay(Box::new(
            compile_reduce_expr(inner, model, index_specs, access_path)?,
        ))),
    }
}

fn base_row_field_ref(col_idx: usize, model: &TableModel) -> Option<KvFieldRef> {
    if let Some(pk_pos) = model.pk_position(col_idx) {
        let bit_offset = PRIMARY_KEY_BIT_OFFSET
            + model.primary_key_kinds[..pk_pos]
                .iter()
                .map(|kind| kind.key_width() * 8)
                .sum::<usize>();
        Some(KvFieldRef::Key {
            bit_offset: u16::try_from(bit_offset).ok()?,
            kind: kv_field_kind(model.column(col_idx).kind)?,
        })
    } else {
        Some(KvFieldRef::Value {
            index: u16::try_from(col_idx).ok()?,
            kind: kv_field_kind(model.column(col_idx).kind)?,
            nullable: model.column(col_idx).nullable,
        })
    }
}

fn pk_field_ref_for_secondary_index(
    pk_pos: usize,
    model: &TableModel,
    spec: &ResolvedIndexSpec,
) -> Option<KvFieldRef> {
    let bit_offset = INDEX_KEY_BIT_OFFSET
        + spec.key_columns_width * 8
        + model.primary_key_kinds[..pk_pos]
            .iter()
            .map(|kind| kind.key_width() * 8)
            .sum::<usize>();
    Some(KvFieldRef::Key {
        bit_offset: u16::try_from(bit_offset).ok()?,
        kind: kv_field_kind(*model.primary_key_kinds.get(pk_pos)?)?,
    })
}

fn index_row_field_ref(
    col_idx: usize,
    model: &TableModel,
    spec: &ResolvedIndexSpec,
) -> Option<KvFieldRef> {
    if let Some(pos) = spec
        .key_columns
        .iter()
        .position(|candidate| *candidate == col_idx)
    {
        return match spec.layout {
            IndexLayout::Lexicographic => {
                let bit_offset = INDEX_KEY_BIT_OFFSET
                    + spec.key_columns[..pos]
                        .iter()
                        .map(|idx| model.column(*idx).kind.key_width() * 8)
                        .sum::<usize>();
                Some(KvFieldRef::Key {
                    bit_offset: u16::try_from(bit_offset).ok()?,
                    kind: kv_field_kind(model.column(col_idx).kind)?,
                })
            }
            IndexLayout::ZOrder => Some(KvFieldRef::ZOrderKey {
                bit_offset: u16::try_from(INDEX_KEY_BIT_OFFSET).ok()?,
                field_position: u8::try_from(pos).ok()?,
                field_widths: spec
                    .key_columns
                    .iter()
                    .map(|idx| u8::try_from(model.column(*idx).kind.key_width()).ok())
                    .collect::<Option<Vec<_>>>()?,
                kind: kv_field_kind(model.column(col_idx).kind)?,
            }),
        };
    }
    if let Some(pk_pos) = model.pk_position(col_idx) {
        return pk_field_ref_for_secondary_index(pk_pos, model, spec);
    }
    if spec.value_column_mask[col_idx] {
        return Some(KvFieldRef::Value {
            index: u16::try_from(col_idx).ok()?,
            kind: kv_field_kind(model.column(col_idx).kind)?,
            nullable: model.column(col_idx).nullable,
        });
    }
    None
}

fn kv_field_kind(kind: ColumnKind) -> Option<KvFieldKind> {
    match kind {
        ColumnKind::Int64 => Some(KvFieldKind::Int64),
        ColumnKind::UInt64 => Some(KvFieldKind::UInt64),
        ColumnKind::Float64 => Some(KvFieldKind::Float64),
        ColumnKind::Boolean => Some(KvFieldKind::Boolean),
        ColumnKind::Utf8 => Some(KvFieldKind::Utf8),
        ColumnKind::Date32 => Some(KvFieldKind::Date32),
        ColumnKind::Date64 => Some(KvFieldKind::Date64),
        ColumnKind::Timestamp => Some(KvFieldKind::Timestamp),
        ColumnKind::FixedSizeBinary(width) => Some(KvFieldKind::FixedSizeBinary(width as u8)),
        ColumnKind::Decimal128 => Some(KvFieldKind::Decimal128),
        ColumnKind::Decimal256 | ColumnKind::List(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ops::Bound::{Included, Unbounded};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::Router;
    use bytes::Bytes;
    use connectrpc::{Chain, ConnectError, ConnectRpcService, Context};
    use exoware_sdk_rs::kv_codec::{eval_expr, expr_needs_value};
    use exoware_proto::connect_compression_registry;
    use exoware_proto::store::ingest::v1::{
        PutResponse as ProtoPutResponse, Service as IngestService,
        ServiceServer as IngestServiceServer,
    };
    use exoware_proto::store::query::v1::RangeEntry as ProtoRangeEntry;
    use exoware_proto::store::query::v1::{
        GetResponse as ProtoGetResponse, RangeFrame as ProtoRangeFrame,
        ReduceResponse as ProtoReduceResponse, Service as QueryService,
        ServiceServer as QueryServiceServer,
    };
    use exoware_proto::{
        parse_range_traversal_direction, to_domain_reduce_request, to_proto_optional_reduced_value,
        to_proto_reduced_value, RangeTraversalDirection, RangeTraversalModeError,
    };
    use exoware_proto::{RangeReduceGroup, RangeReduceResponse, RangeReduceResult};
    use exoware_sdk_rs::RangeMode;
    use futures::{stream, Stream, TryStreamExt};
    use tokio::sync::{mpsc, oneshot, Notify};

    /// Assert EXPLAIN text includes the same `query_stats=...` suffix as [`format_query_stats_explain`].
    fn assert_explain_includes_query_stats_surface(
        explain: &str,
        surface: super::QueryStatsExplainSurface,
    ) {
        let expected = format!("query_stats={}", super::format_query_stats_explain(surface));
        assert!(
            explain.contains(&expected),
            "expected EXPLAIN output to include `{expected}`\n{explain}"
        );
    }

    fn simple_int64_model(prefix: u8) -> TableModel {
        let config = KvTableConfig::new(
            prefix,
            vec![TableColumnConfig::new("id", DataType::Int64, false)],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        TableModel::from_config(&config).unwrap()
    }

    fn codec_payload(codec: KeyCodec, key: &Key, offset: usize, len: usize) -> Vec<u8> {
        codec.read_payload(key, offset, len).expect("codec payload")
    }

    fn primary_payload(model: &TableModel, key: &Key, offset: usize, len: usize) -> Vec<u8> {
        codec_payload(model.primary_key_codec, key, offset, len)
    }

    fn index_payload(spec: &ResolvedIndexSpec, key: &Key, offset: usize, len: usize) -> Vec<u8> {
        codec_payload(spec.codec, key, offset, len)
    }

    fn matches_primary_key(table_prefix: u8, key: &Key) -> bool {
        primary_key_codec(table_prefix)
            .expect("primary codec")
            .matches(key)
    }

    fn matches_secondary_index_key(table_prefix: u8, index_id: u8, key: &Key) -> bool {
        secondary_index_codec(table_prefix, index_id)
            .expect("secondary codec")
            .matches(key)
    }

    fn test_model() -> (TableModel, Vec<ResolvedIndexSpec>) {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("region", DataType::Utf8, false),
                TableColumnConfig::new("customer_id", DataType::Int64, false),
                TableColumnConfig::new("order_id", DataType::Int64, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
            ],
            vec!["order_id".to_string()],
            vec![
                IndexSpec::new(
                    "region_customer",
                    vec!["region".to_string(), "customer_id".to_string()],
                )
                .expect("valid"),
                IndexSpec::new(
                    "status_customer",
                    vec!["status".to_string(), "customer_id".to_string()],
                )
                .expect("valid"),
            ],
        )
        .expect("valid config");
        let model = TableModel::from_config(&config).expect("model");
        let specs = model
            .resolve_index_specs(&config.index_specs)
            .expect("specs");
        (model, specs)
    }

    fn zorder_test_model() -> (TableModel, Vec<ResolvedIndexSpec>) {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("x", DataType::Int64, false),
                TableColumnConfig::new("y", DataType::Int64, false),
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("value", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![
                IndexSpec::new("xy_lex", vec!["x".to_string(), "y".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["value".to_string()]),
                IndexSpec::z_order("xy_z", vec!["x".to_string(), "y".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["value".to_string()]),
            ],
        )
        .expect("valid config");
        let model = TableModel::from_config(&config).expect("model");
        let specs = model
            .resolve_index_specs(&config.index_specs)
            .expect("specs");
        (model, specs)
    }

    #[derive(Clone)]
    struct MockState {
        kv: Arc<Mutex<BTreeMap<Key, Bytes>>>,
        range_calls: Arc<AtomicUsize>,
        range_reduce_calls: Arc<AtomicUsize>,
        sequence_number: Arc<AtomicU64>,
    }

    #[derive(Debug)]
    struct MockGroupedReduceState {
        group_values: Vec<Option<KvReducedValue>>,
        states: Vec<PartialAggregateState>,
    }

    type MockReduceRow = (Vec<Option<KvReducedValue>>, Vec<Option<KvReducedValue>>);

    fn extract_mock_reduce_row(
        key: &Key,
        value: &Bytes,
        request: &RangeReduceRequest,
    ) -> Option<MockReduceRow> {
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
            || request
                .filter
                .as_ref()
                .is_some_and(exoware_sdk_rs::kv_codec::predicate_needs_value);
        let archived = if needs_value {
            access_stored_row(value.as_ref()).ok()
        } else {
            None
        };

        if let Some(filter) = &request.filter {
            if !eval_predicate(key, archived, filter).ok()? {
                return None;
            }
        }

        let mut group_values = Vec::with_capacity(request.group_by.len());
        for expr in &request.group_by {
            let extracted_value = eval_expr(key, archived, expr).ok()?;
            group_values.push(extracted_value);
        }
        canonicalize_reduced_group_values(&mut group_values);

        let mut reducer_values = Vec::with_capacity(request.reducers.len());
        for reducer in &request.reducers {
            let extracted_value = match (&reducer.expr, archived) {
                (None, _) => None,
                (Some(expr), _) => eval_expr(key, archived, expr).ok()?,
            };
            reducer_values.push(extracted_value);
        }

        Some((group_values, reducer_values))
    }

    #[allow(clippy::result_large_err)]
    fn ensure_min_sequence_number(
        token: &Arc<AtomicU64>,
        required: Option<u64>,
    ) -> Result<(), ConnectError> {
        let current = token.load(AtomicOrdering::Relaxed);
        if let Some(required) = required {
            if current < required {
                return Err(ConnectError::aborted(format!(
                    "consistency_not_ready: required={required}, current={current}"
                )));
            }
        }
        Ok(())
    }

    fn proto_range_entries_frame(results: Vec<(Key, Vec<u8>)>) -> ProtoRangeFrame {
        ProtoRangeFrame {
            results: results
                .into_iter()
                .map(|(key, value)| ProtoRangeEntry {
                    key: key.to_vec(),
                    value,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    fn query_detail_trailer_ctx(sequence_number: u64) -> Context {
        let detail = exoware_proto::store::query::v1::Detail {
            sequence_number,
            read_stats: Default::default(),
            ..Default::default()
        };
        exoware_proto::with_query_detail_trailer(Context::default(), &detail)
    }

    #[derive(Clone)]
    struct MockIngestConnect {
        state: MockState,
    }

    impl IngestService for MockIngestConnect {
        async fn put(
            &self,
            ctx: Context,
            request: buffa::view::OwnedView<
                exoware_proto::store::ingest::v1::PutRequestView<'static>,
            >,
        ) -> Result<(ProtoPutResponse, Context), ConnectError> {
            let mut parsed = Vec::<(Key, Bytes)>::new();
            for kv in request.kvs.iter() {
                parsed.push((kv.key.to_vec().into(), Bytes::copy_from_slice(kv.value)));
            }
            let mut guard = self.state.kv.lock().expect("kv mutex poisoned");
            for (key, value) in parsed.iter() {
                guard.insert(key.clone(), value.clone());
            }
            let seq = self
                .state
                .sequence_number
                .fetch_add(1, AtomicOrdering::SeqCst)
                + 1;
            Ok((
                ProtoPutResponse {
                    sequence_number: seq,
                    ..Default::default()
                },
                ctx,
            ))
        }
    }

    #[derive(Clone)]
    struct MockQueryConnect {
        state: MockState,
    }

    impl QueryService for MockQueryConnect {
        async fn get(
            &self,
            _ctx: Context,
            request: buffa::view::OwnedView<
                exoware_proto::store::query::v1::GetRequestView<'static>,
            >,
        ) -> Result<(ProtoGetResponse, Context), ConnectError> {
            ensure_min_sequence_number(&self.state.sequence_number, request.min_sequence_number)?;
            let key: Key = request.key.to_vec().into();
            let guard = self.state.kv.lock().expect("kv mutex poisoned");
            let value = guard.get(&key).cloned();
            let token = self.state.sequence_number.load(AtomicOrdering::Relaxed);
            let detail = exoware_proto::store::query::v1::Detail {
                sequence_number: token,
                read_stats: Default::default(),
                ..Default::default()
            };
            Ok((
                ProtoGetResponse {
                    found: value.is_some(),
                    value: value.map(|v| v.to_vec()),
                    ..Default::default()
                },
                exoware_proto::with_query_detail_response_header(Context::default(), &detail),
            ))
        }

        async fn range(
            &self,
            _ctx: Context,
            request: buffa::view::OwnedView<
                exoware_proto::store::query::v1::RangeRequestView<'static>,
            >,
        ) -> Result<
            (
                Pin<Box<dyn Stream<Item = Result<ProtoRangeFrame, ConnectError>> + Send>>,
                Context,
            ),
            ConnectError,
        > {
            ensure_min_sequence_number(&self.state.sequence_number, request.min_sequence_number)?;
            self.state.range_calls.fetch_add(1, AtomicOrdering::SeqCst);

            let start_key: Key = request.start.to_vec().into();
            let end_key: Key = request.end.to_vec().into();
            let limit = request.limit.map(|v| v as usize).unwrap_or(usize::MAX);
            let batch_size = usize::try_from(request.batch_size).unwrap_or(usize::MAX);
            if batch_size == 0 {
                return Err(ConnectError::invalid_argument(
                    "invalid batch_size: expected positive integer",
                ));
            }

            let mode = match parse_range_traversal_direction(request.mode) {
                Ok(RangeTraversalDirection::Forward) => RangeMode::Forward,
                Ok(RangeTraversalDirection::Reverse) => RangeMode::Reverse,
                Err(RangeTraversalModeError::UnknownWireValue(v)) => {
                    return Err(ConnectError::invalid_argument(format!(
                        "unknown TraversalMode enum value {v}"
                    )));
                }
            };

            let state = self.state.clone();
            let guard = state.kv.lock().expect("kv mutex poisoned");
            // Match `StoreEngine::range_scan`: inclusive [start, end]; empty end = unbounded.
            let range: (std::ops::Bound<&Key>, std::ops::Bound<&Key>) = (
                Included(&start_key),
                if end_key.is_empty() {
                    Unbounded
                } else {
                    Included(&end_key)
                },
            );
            let range_iter = guard.range::<Key, _>(range);
            let iter: Box<dyn Iterator<Item = (&Key, &Bytes)> + Send> = match mode {
                RangeMode::Forward => Box::new(range_iter),
                RangeMode::Reverse => Box::new(range_iter.rev()),
            };
            let mut results: Vec<ProtoRangeEntry> = Vec::new();
            for (key, value) in iter.take(limit) {
                results.push(ProtoRangeEntry {
                    key: key.to_vec(),
                    value: value.to_vec(),
                    ..Default::default()
                });
            }
            drop(guard);
            let token = state.sequence_number.load(AtomicOrdering::Relaxed);
            let batch = batch_size.max(1);
            let mut frames: Vec<Result<ProtoRangeFrame, ConnectError>> = Vec::new();
            for chunk in results.chunks(batch) {
                frames.push(Ok(ProtoRangeFrame {
                    results: chunk.to_vec(),
                    ..Default::default()
                }));
            }
            let detail = exoware_proto::store::query::v1::Detail {
                sequence_number: token,
                read_stats: Default::default(),
                ..Default::default()
            };
            Ok((
                Box::pin(stream::iter(frames)),
                exoware_proto::with_query_detail_trailer(Context::default(), &detail),
            ))
        }

        async fn reduce(
            &self,
            _ctx: Context,
            request: buffa::view::OwnedView<
                exoware_proto::store::query::v1::ReduceRequestView<'static>,
            >,
        ) -> Result<(ProtoReduceResponse, Context), ConnectError> {
            ensure_min_sequence_number(&self.state.sequence_number, request.min_sequence_number)?;
            self.state
                .range_reduce_calls
                .fetch_add(1, AtomicOrdering::SeqCst);
            let owned = request.to_owned_message();
            let start_key: Key = owned.start.clone().into();
            let end_key: Key = owned.end.clone().into();
            let reduce_req = owned
                .params
                .as_option()
                .ok_or_else(|| ConnectError::invalid_argument("missing range reduce params"))?;
            let domain_request =
                to_domain_reduce_request(reduce_req).map_err(ConnectError::invalid_argument)?;

            let state = self.state.clone();
            let guard = state.kv.lock().expect("kv mutex poisoned");
            let mut states = domain_request.group_by.is_empty().then(|| {
                domain_request
                    .reducers
                    .iter()
                    .map(|reducer| PartialAggregateState::from_op(reducer.op))
                    .collect::<Vec<_>>()
            });
            let mut grouped = BTreeMap::<Vec<u8>, MockGroupedReduceState>::new();

            let range: (std::ops::Bound<&Key>, std::ops::Bound<&Key>) = (
                Included(&start_key),
                if end_key.is_empty() {
                    Unbounded
                } else {
                    Included(&end_key)
                },
            );
            for (key, value) in guard.range::<Key, _>(range) {
                let Some((group_values, reducer_values)) =
                    extract_mock_reduce_row(key, value, &domain_request)
                else {
                    continue;
                };
                if domain_request.group_by.is_empty() {
                    let states = states.as_mut().expect("scalar states");
                    for ((state, reducer), value) in states
                        .iter_mut()
                        .zip(domain_request.reducers.iter())
                        .zip(reducer_values.into_iter())
                    {
                        match reducer.op {
                            RangeReduceOp::CountAll => state
                                .merge_partial(reducer.op, Some(&KvReducedValue::UInt64(1)))
                                .map_err(|e| ConnectError::internal(e.to_string()))?,
                            RangeReduceOp::CountField => {
                                let partial =
                                    KvReducedValue::UInt64(if value.is_some() { 1 } else { 0 });
                                state
                                    .merge_partial(reducer.op, Some(&partial))
                                    .map_err(|e| ConnectError::internal(e.to_string()))?
                            }
                            _ => state
                                .merge_partial(reducer.op, value.as_ref())
                                .map_err(|e| ConnectError::internal(e.to_string()))?,
                        }
                    }
                } else {
                    let group_key = encode_reduced_group_key(&group_values);
                    let group =
                        grouped
                            .entry(group_key)
                            .or_insert_with(|| MockGroupedReduceState {
                                group_values: group_values.clone(),
                                states: domain_request
                                    .reducers
                                    .iter()
                                    .map(|reducer| PartialAggregateState::from_op(reducer.op))
                                    .collect(),
                            });
                    for ((state, reducer), value) in group
                        .states
                        .iter_mut()
                        .zip(domain_request.reducers.iter())
                        .zip(reducer_values.into_iter())
                    {
                        match reducer.op {
                            RangeReduceOp::CountAll => state
                                .merge_partial(reducer.op, Some(&KvReducedValue::UInt64(1)))
                                .map_err(|e| ConnectError::internal(e.to_string()))?,
                            RangeReduceOp::CountField => {
                                let partial =
                                    KvReducedValue::UInt64(if value.is_some() { 1 } else { 0 });
                                state
                                    .merge_partial(reducer.op, Some(&partial))
                                    .map_err(|e| ConnectError::internal(e.to_string()))?
                            }
                            _ => state
                                .merge_partial(reducer.op, value.as_ref())
                                .map_err(|e| ConnectError::internal(e.to_string()))?,
                        }
                    }
                }
            }

            let response = if let Some(states) = states {
                RangeReduceResponse {
                    results: states
                        .iter()
                        .map(|state| RangeReduceResult {
                            value: match state {
                                PartialAggregateState::Count(count) => {
                                    Some(KvReducedValue::UInt64(*count))
                                }
                                PartialAggregateState::Sum(value)
                                | PartialAggregateState::Min(value)
                                | PartialAggregateState::Max(value) => value.clone(),
                            },
                        })
                        .collect(),
                    groups: Vec::new(),
                }
            } else {
                RangeReduceResponse {
                    results: Vec::new(),
                    groups: grouped
                        .into_values()
                        .map(|group| RangeReduceGroup {
                            group_values: group.group_values,
                            results: group
                                .states
                                .into_iter()
                                .map(|state| RangeReduceResult {
                                    value: match state {
                                        PartialAggregateState::Count(count) => {
                                            Some(KvReducedValue::UInt64(count))
                                        }
                                        PartialAggregateState::Sum(value)
                                        | PartialAggregateState::Min(value)
                                        | PartialAggregateState::Max(value) => value,
                                    },
                                })
                                .collect(),
                        })
                        .collect(),
                }
            };
            drop(guard);
            let token = state.sequence_number.load(AtomicOrdering::Relaxed);
            let detail = exoware_proto::store::query::v1::Detail {
                sequence_number: token,
                read_stats: Default::default(),
                ..Default::default()
            };
            Ok((
                ProtoReduceResponse {
                    results: response
                        .results
                        .into_iter()
                        .map(
                            |result| exoware_proto::store::query::v1::RangeReduceResult {
                                value: result.value.map(to_proto_reduced_value).into(),
                                ..Default::default()
                            },
                        )
                        .collect(),
                    groups: response
                        .groups
                        .into_iter()
                        .map(|group| {
                            let group_values_present: Vec<bool> =
                                group.group_values.iter().map(|v| v.is_some()).collect();
                            exoware_proto::store::query::v1::RangeReduceGroup {
                                group_values: group
                                    .group_values
                                    .into_iter()
                                    .map(to_proto_optional_reduced_value)
                                    .collect(),
                                group_values_present,
                                results: group
                                    .results
                                    .into_iter()
                                    .map(|result| {
                                        exoware_proto::store::query::v1::RangeReduceResult {
                                            value: result.value.map(to_proto_reduced_value).into(),
                                            ..Default::default()
                                        }
                                    })
                                    .collect(),
                                ..Default::default()
                            }
                        })
                        .collect(),
                    ..Default::default()
                },
                exoware_proto::with_query_detail_response_header(Context::default(), &detail),
            ))
        }
    }

    async fn spawn_mock_server(state: MockState) -> (String, oneshot::Sender<()>) {
        let connect = ConnectRpcService::new(Chain(
            IngestServiceServer::new(MockIngestConnect {
                state: state.clone(),
            }),
            QueryServiceServer::new(MockQueryConnect { state }),
        ))
        .with_compression(connect_compression_registry());
        let app = Router::new().fallback_service(connect);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let addr = listener.local_addr().expect("local addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("mock server should run");
        });
        (format!("http://{addr}"), shutdown_tx)
    }

    fn assert_count_scalar(batch: &RecordBatch, col_idx: usize, row_idx: usize, expected: u64) {
        let scalar = ScalarValue::try_from_array(batch.column(col_idx), row_idx)
            .expect("count scalar should decode");
        match scalar {
            ScalarValue::UInt64(Some(value)) => assert_eq!(value, expected),
            ScalarValue::Int64(Some(value)) => assert_eq!(value, expected as i64),
            other => panic!("unexpected count scalar: {other:?}"),
        }
    }

    async fn explain_plan_rows(ctx: &SessionContext, sql: &str) -> Vec<(String, String)> {
        let batches = ctx
            .sql(&format!("EXPLAIN {sql}"))
            .await
            .expect("explain query")
            .collect()
            .await
            .expect("explain collect");
        let mut rows = Vec::new();
        for batch in batches {
            for row_idx in 0..batch.num_rows() {
                let plan_type = scalar_to_string(
                    &ScalarValue::try_from_array(batch.column(0), row_idx).expect("plan type"),
                )
                .expect("plan type string");
                let plan = scalar_to_string(
                    &ScalarValue::try_from_array(batch.column(1), row_idx).expect("plan"),
                )
                .expect("plan string");
                rows.push((plan_type, plan));
            }
        }
        rows
    }

    fn physical_plan_text(rows: &[(String, String)]) -> String {
        rows.iter()
            .filter(|(plan_type, _)| plan_type.contains("physical_plan"))
            .map(|(_, plan)| plan.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[tokio::test]
    async fn explain_reports_full_scan_like_primary_key_scan() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let explain =
            physical_plan_text(&explain_plan_rows(&ctx, "SELECT id, status FROM orders").await);
        assert!(explain.contains("KvScanExec:"));
        assert!(explain.contains("mode=primary_key"));
        assert!(explain.contains("predicate=<none>"));
        assert!(explain.contains("row_recheck=false"));
        assert!(explain.contains("full_scan_like=true"));
        assert_explain_includes_query_stats_surface(
            &explain,
            super::QueryStatsExplainSurface::StreamedRangeTrailer,
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn explain_reports_secondary_index_scan_and_row_recheck() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let explain = physical_plan_text(
            &explain_plan_rows(
                &ctx,
                "SELECT id, status, amount_cents FROM orders \
                 WHERE status = 'open' AND amount_cents >= 5",
            )
            .await,
        );
        assert!(explain.contains("KvScanExec:"));
        assert!(explain.contains("mode=secondary_index(status_idx, lexicographic)"));
        assert!(explain.contains("predicate=status = 'open' AND amount_cents >= 5"));
        assert!(explain.contains("exact=false"));
        assert!(explain.contains("row_recheck=true"));
        assert!(explain.contains("full_scan_like=false"));

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn explain_reports_zorder_secondary_index_scan() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "points",
                vec![
                    TableColumnConfig::new("x", DataType::Int64, false),
                    TableColumnConfig::new("y", DataType::Int64, false),
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("value", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![
                    IndexSpec::z_order("xy_z", vec!["x".to_string(), "y".to_string()])
                        .expect("valid")
                        .with_cover_columns(vec!["value".to_string()]),
                ],
            )
            .expect("schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let explain = physical_plan_text(
            &explain_plan_rows(
                &ctx,
                "SELECT id, value FROM points \
                 WHERE x >= 1 AND x <= 2 AND y >= 1 AND y <= 2",
            )
            .await,
        );
        assert!(explain.contains("KvScanExec:"));
        assert!(explain.contains("mode=secondary_index(xy_z, z_order)"));
        assert!(explain.contains("exact=false"));
        assert!(explain.contains("row_recheck=true"));

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn explain_reports_aggregate_pushdown_access_path_details() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let explain = physical_plan_text(
            &explain_plan_rows(
                &ctx,
                "SELECT status, SUM(amount_cents) AS total_cents \
                 FROM orders WHERE status = 'open' GROUP BY status",
            )
            .await,
        );
        assert!(explain.contains("KvAggregateExec:"));
        assert!(explain.contains("grouped=true"));
        assert!(explain.contains("job0{mode=secondary_index(status_idx, lexicographic)"));
        assert!(explain.contains("predicate=status = 'open'"));
        assert!(explain.contains("exact=true"));
        assert!(explain.contains("row_recheck=false"));
        assert_explain_includes_query_stats_surface(
            &explain,
            super::QueryStatsExplainSurface::RangeReduceHeader,
        );

        let _ = shutdown_tx.send(());
    }

    #[test]
    fn index_spec_constructor_sets_name_and_keys() {
        let spec = IndexSpec::new(
            "status_customer",
            vec!["status".to_string(), "customer_id".to_string()],
        )
        .expect("valid index spec");
        assert_eq!(spec.name(), "status_customer");
        assert_eq!(spec.key_columns(), &["status", "customer_id"]);
        assert!(spec.cover_columns().is_empty());
    }

    #[test]
    fn index_spec_cover_columns_are_configurable_in_code() {
        let spec = IndexSpec::new("status_customer", vec!["status".to_string()])
            .expect("valid")
            .with_cover_columns(vec!["amount_cents".to_string()]);
        assert_eq!(spec.key_columns(), &["status"]);
        assert_eq!(spec.cover_columns(), &["amount_cents"]);
    }

    #[test]
    fn describe_in_list_places_truncation_ellipsis_inside_parentheses() {
        let rendered = describe_in_list((1..=6).map(|v| v.to_string()));
        assert_eq!(rendered, "IN (1, 2, 3, 4, 5, ...)");
    }

    #[test]
    fn normalize_sum_case_then_one_uses_countall_optimization() {
        let (model, _) = test_model();
        let argument = normalize_case_then_expr(
            AggregatePushdownFunction::Sum,
            &Expr::Literal(ScalarValue::Int64(Some(1)), None),
            &model,
        )
        .expect("normalize");
        assert_eq!(argument, AggregatePushdownArgument::CountAll);
    }

    #[test]
    fn normalize_count_case_then_literal_uses_countall_optimization() {
        use datafusion::logical_expr::col;

        let (model, _) = test_model();
        let case_expr = Expr::Case(datafusion::logical_expr::expr::Case {
            expr: None,
            when_then_expr: vec![(
                Box::new(col("status").eq(Expr::Literal(
                    ScalarValue::Utf8(Some("open".to_string())),
                    None,
                ))),
                Box::new(Expr::Literal(
                    ScalarValue::Utf8(Some("yes".to_string())),
                    None,
                )),
            )],
            else_expr: Some(Box::new(Expr::Literal(ScalarValue::Utf8(None), None))),
        });

        let (func, argument, filter) =
            normalize_count_aggregate_argument(&case_expr, &model).expect("normalize");
        assert_eq!(func, AggregatePushdownFunction::Count);
        assert_eq!(argument, AggregatePushdownArgument::CountAll);
        assert!(filter.is_some());
    }

    #[test]
    fn reduced_value_to_scalar_preserves_timestamp_timezone_label() {
        let tz: Arc<str> = Arc::from("America/New_York");
        let scalar = reduced_value_to_scalar(
            Some(KvReducedValue::Timestamp(1_700_000_000_000_000)),
            &DataType::Timestamp(TimeUnit::Microsecond, Some(tz.clone())),
        )
        .expect("timestamp scalar");
        assert_eq!(
            scalar,
            ScalarValue::TimestampMicrosecond(Some(1_700_000_000_000_000), Some(tz))
        );
    }

    #[test]
    fn index_spec_cover_pk_column_is_rejected() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                .expect("valid")
                .with_cover_columns(vec!["id".to_string()])],
        )
        .expect("valid config");
        let model = TableModel::from_config(&config).expect("model");
        let err = model
            .resolve_index_specs(&config.index_specs)
            .expect_err("covering a PK column must be rejected");
        assert!(err.contains("primary key column"));
    }

    #[test]
    fn access_plan_requires_cover_columns_for_index_scan() {
        let (model, _) = test_model();
        let predicate = QueryPredicate::default();
        let projection = Some(vec![
            *model.columns_by_name.get("order_id").unwrap(),
            *model.columns_by_name.get("amount_cents").unwrap(),
        ]);
        let plan = ScanAccessPlan::new(&model, &projection, &predicate);

        let no_cover = IndexSpec::new("status_idx", vec!["status".to_string()]).unwrap();
        let with_cover = IndexSpec::new("status_idx", vec!["status".to_string()])
            .unwrap()
            .with_cover_columns(vec!["amount_cents".to_string()]);
        let no_cover_resolved = model.resolve_index_specs(&[no_cover]).unwrap();
        let with_cover_resolved = model.resolve_index_specs(&[with_cover]).unwrap();

        assert!(!plan.index_covers_required_non_pk(&no_cover_resolved[0]));
        assert!(plan.index_covers_required_non_pk(&with_cover_resolved[0]));
    }

    #[test]
    fn zorder_shared_predicate_skips_non_compilable_field_refs_without_contradiction() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("big_val", DataType::Decimal256(76, 0), false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::z_order("big_idx", vec!["big_val".to_string()]).expect("valid")],
        )
        .expect("config");
        let model = TableModel::from_config(&config).expect("model");
        let spec = model
            .resolve_index_specs(&config.index_specs)
            .expect("specs")
            .remove(0);
        let plan = ScanAccessPlan {
            required_pk_mask: vec![false],
            required_non_pk_columns: vec![false; model.columns.len()],
            projection_sources: Vec::new(),
            predicate_checks: vec![PredicateAccess::NonPk {
                col_idx: *model.columns_by_name.get("big_val").unwrap(),
                col: model
                    .column(*model.columns_by_name.get("big_val").unwrap())
                    .clone(),
                constraint: PredicateConstraint::IntRange {
                    min: Some(1),
                    max: Some(2),
                },
            }],
        };

        let compiled = plan.compile_index_predicate_plan(&model, &spec);
        assert!(!compiled.is_impossible());
        assert!(compiled.matches_key(&Bytes::from(vec![0u8; exoware_sdk_rs::keys::KEY_SIZE])));
    }

    #[test]
    fn choose_index_plan_prefers_longer_prefix() {
        let (model, specs) = test_model();
        let region_idx = *model.columns_by_name.get("region").unwrap();
        let customer_idx = *model.columns_by_name.get("customer_id").unwrap();
        let mut predicate = QueryPredicate::default();
        predicate.constraints.insert(
            region_idx,
            PredicateConstraint::StringEq("us-east".to_string()),
        );
        predicate.constraints.insert(
            customer_idx,
            PredicateConstraint::IntRange {
                min: Some(10),
                max: Some(20),
            },
        );
        let plan = predicate
            .choose_index_plan(&model, &specs)
            .expect("plan")
            .expect("exists");
        assert_eq!(plan.spec_idx, 0);
        assert_eq!(plan.constrained_prefix_len, 2);
    }

    #[test]
    fn choose_index_plan_prefers_covering_index_when_prefix_strength_ties() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![
                IndexSpec::new("status_plain", vec!["status".to_string()]).expect("valid"),
                IndexSpec::new("status_covering", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()]),
            ],
        )
        .expect("config");
        let model = TableModel::from_config(&config).expect("model");
        let specs = model
            .resolve_index_specs(&config.index_specs)
            .expect("specs");
        let status_idx = *model.columns_by_name.get("status").unwrap();
        let amount_idx = *model.columns_by_name.get("amount_cents").unwrap();
        let mut predicate = QueryPredicate::default();
        predicate.constraints.insert(
            status_idx,
            PredicateConstraint::StringEq("open".to_string()),
        );
        predicate.constraints.insert(
            amount_idx,
            PredicateConstraint::IntRange {
                min: Some(10),
                max: None,
            },
        );

        let plan = predicate
            .choose_index_plan(&model, &specs)
            .expect("plan")
            .expect("exists");
        assert_eq!(specs[plan.spec_idx].name, "status_covering");
    }

    #[test]
    fn choose_index_plan_prefers_zorder_for_multi_column_box_constraints() {
        let (model, specs) = zorder_test_model();
        let x_idx = *model.columns_by_name.get("x").unwrap();
        let y_idx = *model.columns_by_name.get("y").unwrap();
        let mut predicate = QueryPredicate::default();
        predicate.constraints.insert(
            x_idx,
            PredicateConstraint::IntRange {
                min: Some(1),
                max: Some(2),
            },
        );
        predicate.constraints.insert(
            y_idx,
            PredicateConstraint::IntRange {
                min: Some(1),
                max: Some(2),
            },
        );

        let plan = predicate
            .choose_index_plan(&model, &specs)
            .expect("plan")
            .expect("exists");
        assert_eq!(specs[plan.spec_idx].name, "xy_z");
        assert_eq!(specs[plan.spec_idx].layout, IndexLayout::ZOrder);
        assert_eq!(plan.constrained_column_count, 2);
    }

    #[test]
    fn secondary_index_key_round_trip() {
        let (model, specs) = test_model();
        let row = KvRow {
            values: vec![
                CellValue::Utf8("us-east".to_string()),
                CellValue::Int64(42),
                CellValue::Int64(9001),
                CellValue::Int64(1500),
                CellValue::Utf8("open".to_string()),
            ],
        };
        let key = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &row)
            .expect("encode");
        let decoded = decode_secondary_index_key(model.table_prefix, &specs[0], &model, &key)
            .expect("decode");
        let region_idx = *model.columns_by_name.get("region").unwrap();
        let customer_idx = *model.columns_by_name.get("customer_id").unwrap();
        assert!(matches!(
            decoded.values.get(&region_idx),
            Some(CellValue::Utf8(v)) if v == "us-east"
        ));
        assert!(matches!(
            decoded.values.get(&customer_idx),
            Some(CellValue::Int64(v)) if *v == 42
        ));
        assert!(matches!(
            &decoded.primary_key_values[0],
            CellValue::Int64(9001)
        ));
        let expected_pk = encode_primary_key_from_row(model.table_prefix, &row, &model)
            .expect("primary key should encode");
        assert_eq!(decoded.primary_key, expected_pk);
    }

    #[test]
    fn zorder_secondary_index_key_round_trip() {
        let (model, specs) = zorder_test_model();
        let row = KvRow {
            values: vec![
                CellValue::Int64(2),
                CellValue::Int64(1),
                CellValue::Int64(42),
                CellValue::Int64(900),
            ],
        };
        let key = encode_secondary_index_key(model.table_prefix, &specs[1], &model, &row)
            .expect("encode");
        let decoded = decode_secondary_index_key(model.table_prefix, &specs[1], &model, &key)
            .expect("decode");
        let x_idx = *model.columns_by_name.get("x").unwrap();
        let y_idx = *model.columns_by_name.get("y").unwrap();
        assert!(matches!(
            decoded.values.get(&x_idx),
            Some(CellValue::Int64(v)) if *v == 2
        ));
        assert!(matches!(
            decoded.values.get(&y_idx),
            Some(CellValue::Int64(v)) if *v == 1
        ));
        assert!(matches!(
            &decoded.primary_key_values[0],
            CellValue::Int64(42)
        ));
    }

    #[test]
    fn table_config_supports_non_orders_schema() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("tenant", DataType::Utf8, false),
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("score", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new(
                "tenant_score",
                vec!["tenant".to_string(), "score".to_string()],
            )
            .expect("valid")],
        )
        .expect("schema agnostic config should be valid");
        assert_eq!(config.primary_key_columns, vec!["id".to_string()]);
        assert_eq!(config.columns.len(), 3);
    }

    #[test]
    fn table_config_accepts_float64_column() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("price", DataType::Float64, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("Float64 column should be accepted");
        assert_eq!(config.columns.len(), 2);
    }

    #[test]
    fn table_config_accepts_boolean_column() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("active", DataType::Boolean, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("Boolean column should be accepted");
        assert_eq!(config.columns.len(), 2);
    }

    #[test]
    fn build_projected_batch_uses_large_utf8_type() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::LargeUtf8, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let rows = vec![KvRow {
            values: vec![CellValue::Int64(1), CellValue::Utf8("hello".to_string())],
        }];
        let batch = build_projected_batch(&rows, &model, &model.schema, &None).unwrap();
        assert_eq!(batch.column(1).data_type(), &DataType::LargeUtf8);
        let values = batch
            .column(1)
            .as_any()
            .downcast_ref::<LargeStringArray>()
            .expect("must build LargeStringArray");
        assert_eq!(values.value(0), "hello");
    }

    #[test]
    fn build_projected_batch_uses_utf8_view_type() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8View, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let rows = vec![KvRow {
            values: vec![CellValue::Int64(1), CellValue::Utf8("hello".to_string())],
        }];
        let batch = build_projected_batch(&rows, &model, &model.schema, &None).unwrap();
        assert_eq!(batch.column(1).data_type(), &DataType::Utf8View);
        let values = batch
            .column(1)
            .as_any()
            .downcast_ref::<StringViewArray>()
            .expect("must build StringViewArray");
        assert_eq!(values.value(0), "hello");
    }

    #[test]
    fn f64_ordered_encoding_preserves_order() {
        let values = [
            f64::NEG_INFINITY,
            f64::MIN,
            -1000.0,
            -1.0,
            -0.001,
            0.0,
            0.001,
            1.0,
            1000.0,
            f64::MAX,
            f64::INFINITY,
        ];
        let encoded: Vec<[u8; 8]> = values.iter().map(|v| encode_f64_ordered(*v)).collect();
        for i in 0..encoded.len() - 1 {
            assert!(
                encoded[i] < encoded[i + 1],
                "encode_f64_ordered({}) >= encode_f64_ordered({})",
                values[i],
                values[i + 1]
            );
        }
    }

    #[test]
    fn f64_ordered_encoding_round_trip() {
        let values = [
            f64::MIN,
            -42.5,
            -0.0,
            0.0,
            3.125,
            f64::MAX,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ];
        for v in values {
            let encoded = encode_f64_ordered(v);
            let decoded = decode_f64_ordered(encoded);
            assert!(
                v.to_bits() == decoded.to_bits(),
                "round-trip failed for {v}: got {decoded}"
            );
        }
    }

    fn mixed_model() -> (TableModel, Vec<ResolvedIndexSpec>) {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("label", DataType::Utf8, false),
                TableColumnConfig::new("score", DataType::Float64, false),
                TableColumnConfig::new("active", DataType::Boolean, false),
            ],
            vec!["id".to_string()],
            vec![
                IndexSpec::new(
                    "active_score",
                    vec!["active".to_string(), "score".to_string()],
                )
                .expect("valid"),
                IndexSpec::new("label_idx", vec!["label".to_string()]).expect("valid"),
            ],
        )
        .expect("valid config");
        let model = TableModel::from_config(&config).expect("model");
        let specs = model
            .resolve_index_specs(&config.index_specs)
            .expect("specs");
        (model, specs)
    }

    #[test]
    fn secondary_index_key_round_trip_with_float64_and_boolean() {
        let (model, specs) = mixed_model();
        let row = KvRow {
            values: vec![
                CellValue::Int64(100),
                CellValue::Utf8("hello".to_string()),
                CellValue::Float64(3.125),
                CellValue::Boolean(true),
            ],
        };
        let key = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &row)
            .expect("encode");
        let decoded = decode_secondary_index_key(model.table_prefix, &specs[0], &model, &key)
            .expect("decode");
        let active_idx = *model.columns_by_name.get("active").unwrap();
        let score_idx = *model.columns_by_name.get("score").unwrap();
        assert!(matches!(
            decoded.values.get(&active_idx),
            Some(CellValue::Boolean(true))
        ));
        assert!(
            matches!(decoded.values.get(&score_idx), Some(CellValue::Float64(v)) if (*v - 3.125).abs() < f64::EPSILON)
        );
        assert!(matches!(
            &decoded.primary_key_values[0],
            CellValue::Int64(100)
        ));
    }

    #[test]
    fn base_row_round_trip_with_float64_and_boolean() {
        let (model, _specs) = mixed_model();
        let row = KvRow {
            values: vec![
                CellValue::Int64(42),
                CellValue::Utf8("world".to_string()),
                CellValue::Float64(-99.5),
                CellValue::Boolean(false),
            ],
        };
        let encoded = encode_base_row_value(&row, &model).expect("encode");
        let decoded =
            decode_base_row(vec![CellValue::Int64(42)], &encoded, &model).expect("decode");
        assert!(matches!(&decoded.values[0], CellValue::Int64(42)));
        assert!(matches!(&decoded.values[1], CellValue::Utf8(v) if v == "world"));
        assert!(
            matches!(&decoded.values[2], CellValue::Float64(v) if (*v - (-99.5)).abs() < f64::EPSILON)
        );
        assert!(matches!(&decoded.values[3], CellValue::Boolean(false)));
    }

    #[test]
    fn predicate_bool_eq_matches() {
        let (model, _specs) = mixed_model();
        let active_idx = *model.columns_by_name.get("active").unwrap();
        let mut pred = QueryPredicate::default();
        pred.constraints
            .insert(active_idx, PredicateConstraint::BoolEq(true));
        let row_true = KvRow {
            values: vec![
                CellValue::Int64(1),
                CellValue::Utf8("a".to_string()),
                CellValue::Float64(1.0),
                CellValue::Boolean(true),
            ],
        };
        let row_false = KvRow {
            values: vec![
                CellValue::Int64(2),
                CellValue::Utf8("b".to_string()),
                CellValue::Float64(2.0),
                CellValue::Boolean(false),
            ],
        };
        assert!(pred.matches_row(&row_true));
        assert!(!pred.matches_row(&row_false));
    }

    #[test]
    fn predicate_float_range_matches() {
        let (model, _specs) = mixed_model();
        let score_idx = *model.columns_by_name.get("score").unwrap();
        let mut pred = QueryPredicate::default();
        pred.constraints.insert(
            score_idx,
            PredicateConstraint::FloatRange {
                min: Some((2.0, true)),
                max: Some((5.0, false)),
            },
        );
        let make_row = |score: f64| KvRow {
            values: vec![
                CellValue::Int64(1),
                CellValue::Utf8("a".to_string()),
                CellValue::Float64(score),
                CellValue::Boolean(true),
            ],
        };
        assert!(!pred.matches_row(&make_row(1.99)));
        assert!(pred.matches_row(&make_row(2.0)));
        assert!(pred.matches_row(&make_row(3.5)));
        assert!(pred.matches_row(&make_row(4.99)));
        assert!(!pred.matches_row(&make_row(5.0)));
        assert!(!pred.matches_row(&make_row(5.01)));
    }

    #[test]
    fn float_range_rejects_nan_row_value() {
        let constraint = PredicateConstraint::FloatRange {
            min: Some((0.0, true)),
            max: Some((10.0, true)),
        };
        assert!(!matches_constraint(
            &CellValue::Float64(f64::NAN),
            &constraint
        ));
    }

    #[test]
    fn index_plan_with_boolean_prefix() {
        let (model, specs) = mixed_model();
        let active_idx = *model.columns_by_name.get("active").unwrap();
        let mut pred = QueryPredicate::default();
        pred.constraints
            .insert(active_idx, PredicateConstraint::BoolEq(true));
        let plan = pred
            .choose_index_plan(&model, &specs)
            .expect("plan")
            .expect("should find index");
        assert_eq!(plan.spec_idx, 0);
        assert_eq!(plan.constrained_prefix_len, 1);
    }

    #[test]
    fn float_constraint_contradiction() {
        let mut lo: Option<(f64, bool)> = None;
        let mut hi: Option<(f64, bool)> = None;
        let mut contradiction = false;
        apply_float_constraint(&mut lo, &mut hi, Operator::Gt, 10.0, &mut contradiction);
        assert!(!contradiction);
        apply_float_constraint(&mut lo, &mut hi, Operator::Lt, 5.0, &mut contradiction);
        assert!(contradiction);
    }

    #[test]
    fn float_constraint_eq_then_range_contradicts() {
        let mut lo: Option<(f64, bool)> = None;
        let mut hi: Option<(f64, bool)> = None;
        let mut contradiction = false;
        apply_float_constraint(&mut lo, &mut hi, Operator::Eq, 5.0, &mut contradiction);
        assert!(!contradiction);
        apply_float_constraint(&mut lo, &mut hi, Operator::Gt, 5.0, &mut contradiction);
        assert!(contradiction);
    }

    #[test]
    fn float_nan_literal_comparison_marks_contradiction() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("score", DataType::Float64, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::col;
        let filter = col("score").gt(Expr::Literal(ScalarValue::Float64(Some(f64::NAN)), None));
        assert!(QueryPredicate::supports_filter(&filter, &model));

        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(
            pred.contradiction,
            "comparison with NaN literal must produce contradiction"
        );
    }

    #[test]
    fn table_config_accepts_date32_column() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("created", DataType::Date32, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("Date32 column should be accepted");
        assert_eq!(config.columns.len(), 2);
    }

    #[test]
    fn table_config_accepts_timestamp_column() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new(
                    "ts",
                    DataType::Timestamp(TimeUnit::Microsecond, None),
                    false,
                ),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("Timestamp column should be accepted");
        let schema = config.to_schema();
        assert!(matches!(
            schema.field(1).data_type(),
            DataType::Timestamp(TimeUnit::Microsecond, _)
        ));
    }

    #[test]
    fn table_config_normalizes_timestamp_to_microsecond() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new(
                    "ts",
                    DataType::Timestamp(TimeUnit::Nanosecond, None),
                    false,
                ),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("Nanosecond timestamp should be accepted");
        let schema = config.to_schema();
        assert!(matches!(
            schema.field(1).data_type(),
            DataType::Timestamp(TimeUnit::Microsecond, _)
        ));
    }

    #[test]
    fn table_config_accepts_decimal128_column() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("price", DataType::Decimal128(10, 2), false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("Decimal128 column should be accepted");
        assert_eq!(config.columns.len(), 2);
    }

    #[test]
    fn table_config_accepts_list_column() {
        use datafusion::arrow::datatypes::Field;

        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new(
                    "tags",
                    DataType::List(Arc::new(Field::new("item", DataType::Utf8, false))),
                    false,
                ),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("List<Utf8> column should be accepted");
        assert_eq!(config.columns.len(), 2);
    }

    #[test]
    fn list_column_rejected_in_index() {
        use datafusion::arrow::datatypes::Field;

        let result = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new(
                    "tags",
                    DataType::List(Arc::new(Field::new("item", DataType::Utf8, false))),
                    false,
                ),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("tags_idx", vec!["tags".to_string()]).unwrap()],
        );
        assert!(
            result.is_err() || {
                let config = result.unwrap();
                let model = TableModel::from_config(&config).unwrap();
                model.resolve_index_specs(&config.index_specs).is_err()
            }
        );
    }

    #[test]
    fn i32_ordered_encoding_round_trip() {
        let values = [i32::MIN, -1000, -1, 0, 1, 1000, i32::MAX];
        for v in values {
            assert_eq!(decode_i32_ordered(encode_i32_ordered(v)), v);
        }
        let encoded: Vec<[u8; 4]> = values.iter().map(|v| encode_i32_ordered(*v)).collect();
        for i in 0..encoded.len() - 1 {
            assert!(encoded[i] < encoded[i + 1]);
        }
    }

    #[test]
    fn i128_ordered_encoding_round_trip() {
        let values = [i128::MIN, -1, 0, 1, 1234567890123456789, i128::MAX];
        for v in values {
            assert_eq!(decode_i128_ordered(encode_i128_ordered(v)), v);
        }
        let encoded: Vec<[u8; 16]> = values.iter().map(|v| encode_i128_ordered(*v)).collect();
        for i in 0..encoded.len() - 1 {
            assert!(encoded[i] < encoded[i + 1]);
        }
    }

    fn extended_model() -> (TableModel, Vec<ResolvedIndexSpec>) {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("created", DataType::Date32, false),
                TableColumnConfig::new(
                    "ts",
                    DataType::Timestamp(TimeUnit::Microsecond, None),
                    false,
                ),
                TableColumnConfig::new("price", DataType::Decimal128(10, 2), false),
                TableColumnConfig::new("label", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![
                IndexSpec::new(
                    "date_label",
                    vec!["created".to_string(), "label".to_string()],
                )
                .expect("valid"),
                IndexSpec::new("price_idx", vec!["price".to_string()]).expect("valid"),
            ],
        )
        .expect("valid config");
        let model = TableModel::from_config(&config).expect("model");
        let specs = model
            .resolve_index_specs(&config.index_specs)
            .expect("specs");
        (model, specs)
    }

    #[test]
    fn secondary_index_key_round_trip_date32_and_decimal128() {
        let (model, specs) = extended_model();
        let row = KvRow {
            values: vec![
                CellValue::Int64(42),
                CellValue::Date32(19000),
                CellValue::Timestamp(1_700_000_000_000_000),
                CellValue::Decimal128(123456),
                CellValue::Utf8("hello".to_string()),
            ],
        };
        let key = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &row)
            .expect("encode");
        let decoded = decode_secondary_index_key(model.table_prefix, &specs[0], &model, &key)
            .expect("decode");
        let created_idx = *model.columns_by_name.get("created").unwrap();
        let label_idx = *model.columns_by_name.get("label").unwrap();
        assert!(matches!(
            decoded.values.get(&created_idx),
            Some(CellValue::Date32(19000))
        ));
        assert!(matches!(
            decoded.values.get(&label_idx),
            Some(CellValue::Utf8(v)) if v == "hello"
        ));
        assert!(matches!(
            &decoded.primary_key_values[0],
            CellValue::Int64(42)
        ));

        let key2 = encode_secondary_index_key(model.table_prefix, &specs[1], &model, &row)
            .expect("encode");
        let decoded2 = decode_secondary_index_key(model.table_prefix, &specs[1], &model, &key2)
            .expect("decode");
        let price_idx = *model.columns_by_name.get("price").unwrap();
        assert!(matches!(
            decoded2.values.get(&price_idx),
            Some(CellValue::Decimal128(123456))
        ));
        assert!(matches!(
            &decoded2.primary_key_values[0],
            CellValue::Int64(42)
        ));
    }

    #[test]
    fn base_row_round_trip_with_date32_timestamp_decimal128() {
        let (model, _specs) = extended_model();
        let row = KvRow {
            values: vec![
                CellValue::Int64(7),
                CellValue::Date32(19500),
                CellValue::Timestamp(1_700_000_000_000_000),
                CellValue::Decimal128(-9876543),
                CellValue::Utf8("world".to_string()),
            ],
        };
        let encoded = encode_base_row_value(&row, &model).expect("encode");
        let decoded = decode_base_row(vec![CellValue::Int64(7)], &encoded, &model).expect("decode");
        assert!(matches!(&decoded.values[0], CellValue::Int64(7)));
        assert!(matches!(&decoded.values[1], CellValue::Date32(19500)));
        assert!(matches!(
            &decoded.values[2],
            CellValue::Timestamp(1_700_000_000_000_000)
        ));
        assert!(matches!(
            &decoded.values[3],
            CellValue::Decimal128(-9876543)
        ));
        assert!(matches!(&decoded.values[4], CellValue::Utf8(v) if v == "world"));
    }

    #[test]
    fn base_row_round_trip_with_list() {
        use datafusion::arrow::datatypes::Field;

        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new(
                    "tags",
                    DataType::List(Arc::new(Field::new("item", DataType::Utf8, false))),
                    false,
                ),
                TableColumnConfig::new(
                    "scores",
                    DataType::List(Arc::new(Field::new("item", DataType::Int64, false))),
                    false,
                ),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("valid");
        let model = TableModel::from_config(&config).expect("model");
        let row = KvRow {
            values: vec![
                CellValue::Int64(1),
                CellValue::List(vec![
                    CellValue::Utf8("a".to_string()),
                    CellValue::Utf8("b".to_string()),
                ]),
                CellValue::List(vec![CellValue::Int64(10), CellValue::Int64(20)]),
            ],
        };
        let encoded = encode_base_row_value(&row, &model).expect("encode");
        let decoded = decode_base_row(vec![CellValue::Int64(1)], &encoded, &model).expect("decode");
        assert!(matches!(&decoded.values[0], CellValue::Int64(1)));
        match &decoded.values[1] {
            CellValue::List(items) => {
                assert_eq!(items.len(), 2);
                assert!(matches!(&items[0], CellValue::Utf8(v) if v == "a"));
                assert!(matches!(&items[1], CellValue::Utf8(v) if v == "b"));
            }
            _ => panic!("expected List"),
        }
        match &decoded.values[2] {
            CellValue::List(items) => {
                assert_eq!(items.len(), 2);
                assert!(matches!(&items[0], CellValue::Int64(10)));
                assert!(matches!(&items[1], CellValue::Int64(20)));
            }
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn decimal128_constraint_range() {
        let mut min: Option<i128> = None;
        let mut max: Option<i128> = None;
        let mut contradiction = false;
        apply_decimal128_constraint(&mut min, &mut max, Operator::GtEq, 100, &mut contradiction);
        assert!(!contradiction);
        apply_decimal128_constraint(&mut min, &mut max, Operator::LtEq, 200, &mut contradiction);
        assert!(!contradiction);
        assert_eq!(min, Some(100));
        assert_eq!(max, Some(200));
        assert!(in_i128_bounds(150, min, max));
        assert!(!in_i128_bounds(99, min, max));
        assert!(!in_i128_bounds(201, min, max));
    }

    #[test]
    fn decimal256_gt_max_is_contradiction() {
        let mut min: Option<i256> = None;
        let mut max: Option<i256> = None;
        let mut contradiction = false;
        apply_i256_constraint(
            &mut min,
            &mut max,
            Operator::Gt,
            i256::MAX,
            &mut contradiction,
        );
        assert!(contradiction);
        assert_eq!(min, None);
        assert_eq!(max, None);
    }

    #[test]
    fn decimal256_lt_min_is_contradiction() {
        let mut min: Option<i256> = None;
        let mut max: Option<i256> = None;
        let mut contradiction = false;
        apply_i256_constraint(
            &mut min,
            &mut max,
            Operator::Lt,
            i256::MIN,
            &mut contradiction,
        );
        assert!(contradiction);
        assert_eq!(min, None);
        assert_eq!(max, None);
    }

    #[test]
    fn date32_index_bound_clamps_on_i64_overflow() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("created", DataType::Date32, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("created_idx", vec!["created".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();

        let created_idx = *model.columns_by_name.get("created").unwrap();
        let mut pred = QueryPredicate::default();
        pred.constraints.insert(
            created_idx,
            PredicateConstraint::IntRange {
                min: Some(i32::MAX as i64 + 1),
                max: None,
            },
        );

        let start = pred
            .encode_index_bound_key(model.table_prefix, &model, &specs[0], 1, false)
            .unwrap();
        let end = pred
            .encode_index_bound_key(model.table_prefix, &model, &specs[0], 1, true)
            .unwrap();

        assert!(
            start <= end,
            "lower bound must not exceed upper bound (was wrapping via as i32)"
        );

        let encoded_lower = specs[0].codec.read_payload_exact::<4>(&start, 0).unwrap();
        let decoded_lower = decode_i32_ordered(encoded_lower);
        assert_eq!(
            decoded_lower,
            i32::MAX,
            "out-of-range i64 must clamp to i32::MAX, not wrap"
        );
    }

    #[test]
    fn timestamp_nanos_gt_uses_floor_division() {
        let micros = timestamp_scalar_to_micros_for_op(
            &ScalarValue::TimestampNanosecond(Some(-1500), None),
            Operator::Gt,
        )
        .unwrap();
        assert_eq!(micros, -2, "Gt on -1500ns should floor to -2us");

        let mut min: Option<i64> = None;
        let mut max: Option<i64> = None;
        let mut contradiction = false;
        apply_int_constraint(&mut min, &mut max, Operator::Gt, micros, &mut contradiction);
        assert_eq!(min, Some(-1), "Gt(-2us) + 1 = min -1us");

        let row_at_minus_1 = CellValue::Timestamp(-1);
        assert!(matches_constraint(
            &row_at_minus_1,
            &PredicateConstraint::IntRange { min, max }
        ));
    }

    #[test]
    fn timestamp_nanos_lteq_uses_floor_division() {
        let micros = timestamp_scalar_to_micros_for_op(
            &ScalarValue::TimestampNanosecond(Some(-1500), None),
            Operator::LtEq,
        )
        .unwrap();
        assert_eq!(micros, -2, "LtEq on -1500ns should floor to -2us");

        let row_at_minus_1 = CellValue::Timestamp(-1);
        assert!(
            !matches_constraint(
                &row_at_minus_1,
                &PredicateConstraint::IntRange {
                    min: None,
                    max: Some(micros)
                }
            ),
            "-1us (-1000ns) > -1500ns, must not satisfy <= -1500ns"
        );
    }

    #[test]
    fn timestamp_nanos_gteq_uses_ceil_division() {
        let micros = timestamp_scalar_to_micros_for_op(
            &ScalarValue::TimestampNanosecond(Some(-1500), None),
            Operator::GtEq,
        )
        .unwrap();
        assert_eq!(micros, -1, "GtEq on -1500ns should ceil to -1us");
    }

    #[test]
    fn timestamp_nanos_lt_uses_ceil_division() {
        let micros = timestamp_scalar_to_micros_for_op(
            &ScalarValue::TimestampNanosecond(Some(-1500), None),
            Operator::Lt,
        )
        .unwrap();
        assert_eq!(micros, -1, "Lt on -1500ns should ceil to -1us");

        let mut min: Option<i64> = None;
        let mut max: Option<i64> = None;
        let mut contradiction = false;
        apply_int_constraint(&mut min, &mut max, Operator::Lt, micros, &mut contradiction);
        assert_eq!(max, Some(-2), "Lt(-1us) - 1 = max -2us");
    }

    #[test]
    fn timestamp_nanos_eq_non_aligned_is_contradiction() {
        let result = timestamp_scalar_to_micros_for_op(
            &ScalarValue::TimestampNanosecond(Some(-1500), None),
            Operator::Eq,
        );
        assert!(
            result.is_none(),
            "non-aligned ns Eq must produce contradiction"
        );
    }

    #[test]
    fn timestamp_nanos_exact_multiple_is_unchanged() {
        for op in [
            Operator::Eq,
            Operator::Gt,
            Operator::GtEq,
            Operator::Lt,
            Operator::LtEq,
        ] {
            let micros = timestamp_scalar_to_micros_for_op(
                &ScalarValue::TimestampNanosecond(Some(-2000), None),
                op,
            )
            .unwrap();
            assert_eq!(micros, -2, "exact multiple -2000ns = -2us for {op:?}");
        }
    }

    #[test]
    fn float64_index_bounds_include_infinity() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("val", DataType::Float64, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("val_idx", vec!["val".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();

        let pred = QueryPredicate::default();
        let start = pred
            .encode_index_bound_key(model.table_prefix, &model, &specs[0], 0, false)
            .unwrap();
        let end = pred
            .encode_index_bound_key(model.table_prefix, &model, &specs[0], 0, true)
            .unwrap();

        let neg_inf_row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::Float64(f64::NEG_INFINITY)],
        };
        let pos_inf_row = KvRow {
            values: vec![CellValue::Int64(2), CellValue::Float64(f64::INFINITY)],
        };

        let neg_inf_key =
            encode_secondary_index_key(model.table_prefix, &specs[0], &model, &neg_inf_row)
                .unwrap();
        let pos_inf_key =
            encode_secondary_index_key(model.table_prefix, &specs[0], &model, &pos_inf_row)
                .unwrap();

        assert!(
            neg_inf_key >= start,
            "NEG_INFINITY row key must be within scan start bound"
        );
        assert!(
            pos_inf_key <= end,
            "INFINITY row key must be within scan end bound"
        );
    }

    #[test]
    fn distinct_table_prefixes_produce_non_overlapping_pk_ranges() {
        let range_a = primary_key_prefix_range(1);
        let range_b = primary_key_prefix_range(2);
        assert!(
            range_a.end < range_b.start,
            "table prefix 1 pk range must be entirely below table prefix 2"
        );
    }

    #[test]
    fn distinct_table_prefixes_isolate_primary_keys() {
        let model_1 = simple_int64_model(1);
        let model_2 = simple_int64_model(2);
        let pk = CellValue::Int64(42);
        let key_a = encode_primary_key(1, &[&pk], &model_1).expect("pk key encodes");
        let key_b = encode_primary_key(2, &[&pk], &model_2).expect("pk key encodes");
        assert_ne!(key_a, key_b, "same PK under different prefixes must differ");
        assert!(
            decode_primary_key(1, &key_a, &model_1).is_some(),
            "key_a must decode under prefix 1"
        );
        assert!(
            decode_primary_key(2, &key_a, &model_2).is_none(),
            "key_a must NOT decode under prefix 2"
        );
        assert!(
            decode_primary_key(2, &key_b, &model_2).is_some(),
            "key_b must decode under prefix 2"
        );
    }

    #[test]
    fn distinct_table_prefixes_isolate_secondary_keys() {
        let config_a = KvTableConfig::new(
            10,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("name_idx", vec!["name".to_string()]).unwrap()],
        )
        .unwrap();
        let config_b = KvTableConfig::new(
            11,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("name_idx", vec!["name".to_string()]).unwrap()],
        )
        .unwrap();

        let model_a = TableModel::from_config(&config_a).unwrap();
        let specs_a = model_a.resolve_index_specs(&config_a.index_specs).unwrap();
        let model_b = TableModel::from_config(&config_b).unwrap();
        let specs_b = model_b.resolve_index_specs(&config_b.index_specs).unwrap();

        let row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::Utf8("alice".to_string())],
        };
        let key_a =
            encode_secondary_index_key(model_a.table_prefix, &specs_a[0], &model_a, &row).unwrap();
        let key_b =
            encode_secondary_index_key(model_b.table_prefix, &specs_b[0], &model_b, &row).unwrap();

        assert_ne!(
            key_a, key_b,
            "same row under different prefixes must differ"
        );
        assert!(
            decode_secondary_index_key(model_a.table_prefix, &specs_a[0], &model_a, &key_a)
                .is_some()
        );
        assert!(
            decode_secondary_index_key(model_a.table_prefix, &specs_a[0], &model_a, &key_b)
                .is_none(),
            "key from table B must not decode under table A's prefix"
        );
    }

    #[test]
    fn table_prefix_stored_in_model() {
        let config = KvTableConfig::new(
            12,
            vec![TableColumnConfig::new("id", DataType::Int64, false)],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        assert_eq!(model.table_prefix, 12);
    }

    #[test]
    fn codec_layout_exposes_payload_bits_under_reserved_family_bits() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("bucket", DataType::FixedSizeBinary(16), false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("bucket_idx", vec!["bucket".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let spec = model
            .resolve_index_specs(&config.index_specs)
            .unwrap()
            .remove(0);

        let mut current_primary = HashSet::new();
        let mut current_secondary = HashSet::new();

        fn first_twelve_bits_of_key(key: &[u8]) -> u16 {
            let first = u16::from(*key.first().unwrap_or(&0));
            let second = u16::from(*key.get(1).unwrap_or(&0));
            (first << 4) | (second >> 4)
        }

        for first_byte in 0u8..=255 {
            let mut id = vec![0u8; 16];
            id[0] = first_byte;
            let mut bucket = vec![0u8; 16];
            bucket[0] = first_byte;

            let pk = CellValue::FixedBinary(id.clone());
            let current_pk = encode_primary_key(model.table_prefix, &[&pk], &model).unwrap();
            current_primary.insert(first_twelve_bits_of_key(&current_pk));

            let row = KvRow {
                values: vec![
                    CellValue::FixedBinary(id),
                    CellValue::FixedBinary(bucket.clone()),
                ],
            };
            let current_index =
                encode_secondary_index_key(model.table_prefix, &spec, &model, &row).unwrap();
            current_secondary.insert(first_twelve_bits_of_key(&current_index));
        }

        // Primary keys reserve 5 high bits for family, leaving 7 payload bits in the first
        // 12 bits of the physical key. Varying one payload byte therefore spans 2^7 values.
        assert_eq!(current_primary.len(), 128);

        // Secondary index keys reserve 9 high bits for family, leaving 3 payload bits in the
        // first 12 bits. Varying one payload byte therefore spans 2^3 values.
        assert_eq!(current_secondary.len(), 8);
    }

    #[test]
    fn kv_schema_auto_assigns_sequential_prefixes() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "alpha",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap()
            .table(
                "beta",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("name", DataType::Utf8, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap()
            .table(
                "gamma",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();

        assert_eq!(schema.table_count(), 3);
    }

    #[test]
    fn kv_schema_allows_max_codec_table_count_and_rejects_overflow() {
        let client = StoreClient::new("http://localhost:10000");
        let mut schema = KvSchema::new(client);
        for idx in 0..MAX_TABLES {
            schema = schema
                .table(
                    format!("t{idx}"),
                    vec![TableColumnConfig::new("id", DataType::Int64, false)],
                    vec!["id".to_string()],
                    vec![],
                )
                .expect("tables up to codec capacity should be accepted");
        }
        assert_eq!(schema.table_count(), MAX_TABLES);

        let overflow = schema.table(
            "overflow",
            vec![TableColumnConfig::new("id", DataType::Int64, false)],
            vec!["id".to_string()],
            vec![],
        );
        match overflow {
            Ok(_) => panic!("overflow table should be rejected"),
            Err(err) => assert!(
                err.contains(&format!(
                    "too many tables for codec layout (max {MAX_TABLES})"
                )),
                "overflow table should be rejected with codec-capacity error"
            ),
        }
    }

    #[test]
    fn sequential_prefixes_produce_non_overlapping_pk_ranges() {
        let range_a = primary_key_prefix_range(0);
        let range_b = primary_key_prefix_range(1);
        let range_c = primary_key_prefix_range(2);
        assert!(range_a.end < range_b.start);
        assert!(range_b.end < range_c.start);
    }

    #[test]
    fn sequential_prefixes_isolate_primary_keys() {
        let model_0 = simple_int64_model(0);
        let model_1 = simple_int64_model(1);
        let pk = CellValue::Int64(42);
        let key_a = encode_primary_key(0, &[&pk], &model_0).expect("pk key encodes");
        let key_b = encode_primary_key(1, &[&pk], &model_1).expect("pk key encodes");
        assert_ne!(key_a, key_b);
        assert!(decode_primary_key(0, &key_a, &model_0).is_some());
        assert!(decode_primary_key(1, &key_a, &model_1).is_none());
        assert!(decode_primary_key(0, &key_b, &model_0).is_none());
        assert!(decode_primary_key(1, &key_b, &model_1).is_some());
    }

    #[test]
    fn sequential_prefixes_isolate_secondary_keys() {
        let config_a = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("name_idx", vec!["name".to_string()]).unwrap()],
        )
        .unwrap();
        let config_b = KvTableConfig::new(
            1,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("name_idx", vec!["name".to_string()]).unwrap()],
        )
        .unwrap();

        let model_a = TableModel::from_config(&config_a).unwrap();
        let specs_a = model_a.resolve_index_specs(&config_a.index_specs).unwrap();
        let model_b = TableModel::from_config(&config_b).unwrap();
        let specs_b = model_b.resolve_index_specs(&config_b.index_specs).unwrap();

        let row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::Utf8("alice".to_string())],
        };
        let key_a =
            encode_secondary_index_key(model_a.table_prefix, &specs_a[0], &model_a, &row).unwrap();
        let key_b =
            encode_secondary_index_key(model_b.table_prefix, &specs_b[0], &model_b, &row).unwrap();
        assert_ne!(key_a, key_b);
        assert!(
            decode_secondary_index_key(model_a.table_prefix, &specs_a[0], &model_a, &key_b)
                .is_none(),
            "key from prefix 1 must not decode under prefix 0"
        );
    }

    #[tokio::test]
    async fn kv_schema_register_all_enables_join() {
        let ctx = SessionContext::new();
        let client = StoreClient::new("http://localhost:10000");

        let result = KvSchema::new(client)
            .table(
                "customers",
                vec![
                    TableColumnConfig::new("customer_id", DataType::Int64, false),
                    TableColumnConfig::new("name", DataType::Utf8, false),
                ],
                vec!["customer_id".to_string()],
                vec![],
            )
            .unwrap()
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("order_id", DataType::Int64, false),
                    TableColumnConfig::new("customer_id", DataType::Int64, false),
                    TableColumnConfig::new("amount", DataType::Int64, false),
                ],
                vec!["order_id".to_string()],
                vec![IndexSpec::new("cust_idx", vec!["customer_id".to_string()]).unwrap()],
            )
            .unwrap()
            .register_all(&ctx);

        assert!(
            result.is_ok(),
            "register_all must succeed: {:?}",
            result.err()
        );

        let plan = ctx
            .sql(
                "SELECT c.name, o.order_id, o.amount \
                 FROM orders o \
                 JOIN customers c ON o.customer_id = c.customer_id",
            )
            .await;
        assert!(
            plan.is_ok(),
            "JOIN query must plan successfully: {:?}",
            plan.err()
        );
    }

    #[tokio::test]
    async fn kv_schema_three_way_join() {
        let ctx = SessionContext::new();
        let client = StoreClient::new("http://localhost:10000");

        KvSchema::new(client)
            .table(
                "products",
                vec![
                    TableColumnConfig::new("product_id", DataType::Int64, false),
                    TableColumnConfig::new("name", DataType::Utf8, false),
                    TableColumnConfig::new("price", DataType::Int64, false),
                ],
                vec!["product_id".to_string()],
                vec![],
            )
            .unwrap()
            .table(
                "line_items",
                vec![
                    TableColumnConfig::new("item_id", DataType::Int64, false),
                    TableColumnConfig::new("order_id", DataType::Int64, false),
                    TableColumnConfig::new("product_id", DataType::Int64, false),
                    TableColumnConfig::new("qty", DataType::Int64, false),
                ],
                vec!["item_id".to_string()],
                vec![
                    IndexSpec::new("prod_idx", vec!["product_id".to_string()]).unwrap(),
                    IndexSpec::new("order_idx", vec!["order_id".to_string()]).unwrap(),
                ],
            )
            .unwrap()
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("order_id", DataType::Int64, false),
                    TableColumnConfig::new("customer", DataType::Utf8, false),
                ],
                vec!["order_id".to_string()],
                vec![],
            )
            .unwrap()
            .register_all(&ctx)
            .unwrap();

        let plan = ctx
            .sql(
                "SELECT o.customer, p.name, li.qty \
                 FROM line_items li \
                 JOIN products p ON li.product_id = p.product_id \
                 JOIN orders o ON li.order_id = o.order_id",
            )
            .await;
        assert!(plan.is_ok(), "three-way JOIN must plan: {:?}", plan.err());
    }

    #[test]
    fn kv_schema_orders_table_convenience() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .orders_table(
                "my_orders",
                vec![IndexSpec::new(
                    "region_customer",
                    vec!["region".to_string(), "customer_id".to_string()],
                )
                .unwrap()],
            )
            .unwrap();
        assert_eq!(schema.table_count(), 1);
    }

    #[test]
    fn nullable_column_accepted_in_config() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8, true),
            ],
            vec!["id".to_string()],
            vec![],
        );
        assert!(config.is_ok());
    }

    #[test]
    fn nullable_column_rejected_in_index() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8, true),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("name_idx", vec!["name".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let result = model.resolve_index_specs(&config.index_specs);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("nullable"));
    }

    #[test]
    fn base_row_round_trip_with_null() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("label", DataType::Utf8, true),
                TableColumnConfig::new("score", DataType::Int64, true),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::Null, CellValue::Int64(42)],
        };
        let encoded = encode_base_row_value(&row, &model).unwrap();
        let decoded = decode_base_row(vec![CellValue::Int64(1)], &encoded, &model).unwrap();
        assert!(matches!(&decoded.values[0], CellValue::Int64(1)));
        assert!(matches!(&decoded.values[1], CellValue::Null));
        assert!(matches!(&decoded.values[2], CellValue::Int64(42)));
    }

    #[test]
    fn null_does_not_match_equality_constraint() {
        assert!(!matches_constraint(
            &CellValue::Null,
            &PredicateConstraint::StringEq("x".to_string())
        ));
        assert!(!matches_constraint(
            &CellValue::Null,
            &PredicateConstraint::IntRange {
                min: Some(0),
                max: Some(10)
            }
        ));
    }

    #[test]
    fn is_null_constraint_matches() {
        assert!(matches_constraint(
            &CellValue::Null,
            &PredicateConstraint::IsNull
        ));
        assert!(!matches_constraint(
            &CellValue::Utf8("x".to_string()),
            &PredicateConstraint::IsNull
        ));
        assert!(!matches_constraint(
            &CellValue::Null,
            &PredicateConstraint::IsNotNull
        ));
        assert!(matches_constraint(
            &CellValue::Int64(5),
            &PredicateConstraint::IsNotNull
        ));
    }

    #[test]
    fn string_in_constraint_matches() {
        let constraint =
            PredicateConstraint::StringIn(vec!["us-east".to_string(), "us-west".to_string()]);
        assert!(matches_constraint(
            &CellValue::Utf8("us-east".to_string()),
            &constraint,
        ));
        assert!(matches_constraint(
            &CellValue::Utf8("us-west".to_string()),
            &constraint,
        ));
        assert!(!matches_constraint(
            &CellValue::Utf8("eu-central".to_string()),
            &constraint,
        ));
    }

    #[test]
    fn int_in_constraint_matches() {
        let constraint = PredicateConstraint::IntIn(vec![1, 2, 3]);
        assert!(matches_constraint(&CellValue::Int64(1), &constraint));
        assert!(matches_constraint(&CellValue::Int64(3), &constraint));
        assert!(!matches_constraint(&CellValue::Int64(4), &constraint));
    }

    #[test]
    fn in_predicate_generates_multiple_index_ranges() {
        let (model, specs) = test_model();
        let region_idx = *model.columns_by_name.get("region").unwrap();
        let mut pred = QueryPredicate::default();
        pred.constraints.insert(
            region_idx,
            PredicateConstraint::StringIn(vec!["us-east".to_string(), "us-west".to_string()]),
        );
        let plan = pred
            .choose_index_plan(&model, &specs)
            .expect("plan")
            .expect("should find index");
        assert_eq!(plan.ranges.len(), 2);
    }

    #[test]
    fn int_in_generates_multiple_pk_ranges() {
        let (model, _specs) = test_model();
        let mut pred = QueryPredicate::default();
        pred.constraints.insert(
            model.primary_key_indices[0],
            PredicateConstraint::IntIn(vec![100, 200, 300]),
        );
        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert_eq!(ranges.len(), 3);
    }

    #[test]
    fn duplicate_int_in_values_deduplicated() {
        let (model, _specs) = test_model();
        // Use the PK column "order_id" for the IN list
        let filter = Expr::InList(datafusion::logical_expr::expr::InList {
            expr: Box::new(Expr::Column(datafusion::common::Column::new_unqualified(
                "order_id",
            ))),
            list: vec![
                Expr::Literal(ScalarValue::Int64(Some(5)), None),
                Expr::Literal(ScalarValue::Int64(Some(5)), None),
                Expr::Literal(ScalarValue::Int64(Some(10)), None),
            ],
            negated: false,
        });
        let pred = QueryPredicate::from_filters(&[filter], &model);
        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert_eq!(
            ranges.len(),
            2,
            "duplicate IN values must be deduped, producing 2 ranges not 3"
        );
    }

    #[test]
    fn duplicate_uint64_in_values_deduplicated() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::UInt64, false),
                TableColumnConfig::new("name", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let filter = Expr::InList(datafusion::logical_expr::expr::InList {
            expr: Box::new(Expr::Column(datafusion::common::Column::new_unqualified(
                "id",
            ))),
            list: vec![
                Expr::Literal(ScalarValue::UInt64(Some(100)), None),
                Expr::Literal(ScalarValue::UInt64(Some(100)), None),
                Expr::Literal(ScalarValue::UInt64(Some(200)), None),
            ],
            negated: false,
        });
        let pred = QueryPredicate::from_filters(&[filter], &model);
        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert_eq!(
            ranges.len(),
            2,
            "duplicate UInt64 IN values must be deduped"
        );
    }

    #[test]
    fn duplicate_fixed_binary_in_values_deduplicated() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("hash", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("val", DataType::Int64, false),
            ],
            vec!["hash".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let dup_val = vec![0xAA; 16];
        let other_val = vec![0xBB; 16];
        let filter = Expr::InList(datafusion::logical_expr::expr::InList {
            expr: Box::new(Expr::Column(datafusion::common::Column::new_unqualified(
                "hash",
            ))),
            list: vec![
                Expr::Literal(
                    ScalarValue::FixedSizeBinary(16, Some(dup_val.clone())),
                    None,
                ),
                Expr::Literal(ScalarValue::FixedSizeBinary(16, Some(dup_val)), None),
                Expr::Literal(ScalarValue::FixedSizeBinary(16, Some(other_val)), None),
            ],
            negated: false,
        });
        let pred = QueryPredicate::from_filters(&[filter], &model);
        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert_eq!(
            ranges.len(),
            2,
            "duplicate FixedBinary IN values must be deduped"
        );
    }

    #[test]
    fn or_equalities_extracted_as_in_list() {
        let (model, _) = test_model();
        let expr = Expr::BinaryExpr(datafusion::logical_expr::BinaryExpr {
            left: Box::new(Expr::BinaryExpr(datafusion::logical_expr::BinaryExpr {
                left: Box::new(Expr::Column(datafusion::common::Column::new_unqualified(
                    "region",
                ))),
                op: Operator::Eq,
                right: Box::new(Expr::Literal(
                    ScalarValue::Utf8(Some("us-east".to_string())),
                    None,
                )),
            })),
            op: Operator::Or,
            right: Box::new(Expr::BinaryExpr(datafusion::logical_expr::BinaryExpr {
                left: Box::new(Expr::Column(datafusion::common::Column::new_unqualified(
                    "region",
                ))),
                op: Operator::Eq,
                right: Box::new(Expr::Literal(
                    ScalarValue::Utf8(Some("us-west".to_string())),
                    None,
                )),
            })),
        });
        let result = extract_or_in_column(&expr, &model);
        assert!(result.is_some());
        let (col, vals) = result.unwrap();
        assert_eq!(col, "region");
        assert_eq!(vals.len(), 2);
    }

    #[test]
    fn or_equalities_on_float64_are_not_pushdown_supported() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("score", DataType::Float64, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::col;
        let filter = col("score")
            .eq(Expr::Literal(ScalarValue::Float64(Some(1.0)), None))
            .or(col("score").eq(Expr::Literal(ScalarValue::Float64(Some(2.0)), None)));

        assert!(
            !QueryPredicate::supports_filter(&filter, &model),
            "OR-equality pushdown should be disabled for Float64 because apply_in_list cannot enforce it"
        );

        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(!pred.contradiction);
        assert!(
            pred.constraints.is_empty(),
            "unsupported OR predicate must not contribute pushdown constraints"
        );
    }

    #[test]
    fn batch_writer_encodes_rows_across_tables() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "customers",
                vec![
                    TableColumnConfig::new("customer_id", DataType::Int64, false),
                    TableColumnConfig::new("name", DataType::Utf8, false),
                ],
                vec!["customer_id".to_string()],
                vec![],
            )
            .unwrap()
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("order_id", DataType::Int64, false),
                    TableColumnConfig::new("customer_id", DataType::Int64, false),
                    TableColumnConfig::new("amount", DataType::Int64, false),
                ],
                vec!["order_id".to_string()],
                vec![IndexSpec::new("cust_idx", vec!["customer_id".to_string()]).unwrap()],
            )
            .unwrap();

        let mut batch = schema.batch_writer();
        batch
            .insert(
                "customers",
                vec![CellValue::Int64(1), CellValue::Utf8("Alice".to_string())],
            )
            .unwrap();
        batch
            .insert(
                "orders",
                vec![
                    CellValue::Int64(100),
                    CellValue::Int64(1),
                    CellValue::Int64(4999),
                ],
            )
            .unwrap();
        batch
            .insert(
                "orders",
                vec![
                    CellValue::Int64(101),
                    CellValue::Int64(1),
                    CellValue::Int64(2999),
                ],
            )
            .unwrap();

        // 1 customer base row + 2 order base rows + 2 order index rows = 5
        assert_eq!(batch.pending_count(), 5);
    }

    #[test]
    fn batch_writer_rejects_unknown_table() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "t1",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();

        let mut batch = schema.batch_writer();
        let result = batch.insert("nonexistent", vec![CellValue::Int64(1)]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown table"));
    }

    #[test]
    fn batch_writer_rejects_wrong_column_count() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "t1",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("name", DataType::Utf8, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();

        let mut batch = schema.batch_writer();
        let result = batch.insert("t1", vec![CellValue::Int64(1)]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected 2"));
    }

    #[test]
    fn batch_writer_rejects_non_pk_type_mismatch() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "t1",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("amount", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();

        let mut batch = schema.batch_writer();
        let result = batch.insert(
            "t1",
            vec![CellValue::Int64(1), CellValue::Utf8("bad".to_string())],
        );
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("type mismatch"),
            "non-PK schema-invalid values must be rejected at insert-time"
        );
    }

    #[test]
    fn batch_writer_entries_use_distinct_table_prefixes() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "a",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap()
            .table(
                "b",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();

        let mut batch = schema.batch_writer();
        batch.insert("a", vec![CellValue::Int64(42)]).unwrap();
        batch.insert("b", vec![CellValue::Int64(42)]).unwrap();

        assert_eq!(batch.pending_count(), 2);
        assert_ne!(
            batch.pending_keys[0], batch.pending_keys[1],
            "same PK in different tables must produce different keys"
        );
        assert_ne!(
            batch.pending_keys[0][0], batch.pending_keys[1][0],
            "table prefix byte must differ"
        );
    }

    #[test]
    fn batch_writer_supports_nullable_columns() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "t",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("note", DataType::Utf8, true),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();

        let mut batch = schema.batch_writer();
        batch
            .insert("t", vec![CellValue::Int64(1), CellValue::Null])
            .unwrap();
        assert_eq!(batch.pending_count(), 1);
    }

    #[test]
    fn non_nullable_column_rejects_null_in_batch_writer() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table(
                "t",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("name", DataType::Utf8, false),
                    TableColumnConfig::new("note", DataType::Utf8, true),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();

        // NULL in non-nullable column "name" must fail
        let mut batch = schema.batch_writer();
        let result = batch.insert(
            "t",
            vec![
                CellValue::Int64(1),
                CellValue::Null,
                CellValue::Utf8("ok".to_string()),
            ],
        );
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("not nullable"),
            "error should mention non-nullable constraint"
        );

        // NULL in nullable column "note" must succeed
        let mut batch = schema.batch_writer();
        batch
            .insert(
                "t",
                vec![
                    CellValue::Int64(1),
                    CellValue::Utf8("Alice".to_string()),
                    CellValue::Null,
                ],
            )
            .unwrap();
        assert_eq!(batch.pending_count(), 1);

        // All non-null values must succeed
        let mut batch = schema.batch_writer();
        batch
            .insert(
                "t",
                vec![
                    CellValue::Int64(1),
                    CellValue::Utf8("Alice".to_string()),
                    CellValue::Utf8("hello".to_string()),
                ],
            )
            .unwrap();
        assert_eq!(batch.pending_count(), 1);
    }

    #[test]
    fn uint64_column_accepted() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::UInt64, false),
                TableColumnConfig::new("name", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![],
        );
        assert!(config.is_ok());
    }

    #[test]
    fn uint64_primary_key_round_trip() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::UInt64, false),
                TableColumnConfig::new("label", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let row = KvRow {
            values: vec![
                CellValue::UInt64(u64::MAX),
                CellValue::Utf8("max".to_string()),
            ],
        };
        let encoded = encode_base_row_value(&row, &model).unwrap();
        let pk = row
            .primary_key_values(&model)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let decoded = decode_base_row(pk, &encoded, &model).unwrap();
        assert!(matches!(&decoded.values[0], CellValue::UInt64(v) if *v == u64::MAX));
        assert!(matches!(&decoded.values[1], CellValue::Utf8(v) if v == "max"));
    }

    #[test]
    fn string_primary_key_accepted() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("code", DataType::Utf8, false),
                TableColumnConfig::new("value", DataType::Int64, false),
            ],
            vec!["code".to_string()],
            vec![],
        );
        assert!(config.is_ok());
    }

    #[test]
    fn fixed_binary_primary_key_round_trip() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("hash", DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new("amount", DataType::Int64, false),
            ],
            vec!["hash".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let hash_val = vec![0xABu8; 32];
        let row = KvRow {
            values: vec![
                CellValue::FixedBinary(hash_val.clone()),
                CellValue::Int64(100),
            ],
        };
        let encoded = encode_base_row_value(&row, &model).unwrap();
        let pk = row
            .primary_key_values(&model)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let decoded = decode_base_row(pk, &encoded, &model).unwrap();
        assert!(matches!(&decoded.values[0], CellValue::FixedBinary(v) if *v == hash_val));
    }

    #[test]
    fn fixed_binary_key_rejects_wrong_length() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("hash", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("amount", DataType::Int64, false),
            ],
            vec!["hash".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        // Too short (10 bytes for a 16-byte column)
        let short_row = KvRow {
            values: vec![CellValue::FixedBinary(vec![0xAB; 10]), CellValue::Int64(1)],
        };
        let result = encode_primary_key_from_row(model.table_prefix, &short_row, &model);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("requires exactly 16 bytes"),
            "should mention exact width requirement"
        );

        // Too long (20 bytes for a 16-byte column)
        let long_row = KvRow {
            values: vec![CellValue::FixedBinary(vec![0xCD; 20]), CellValue::Int64(2)],
        };
        let result = encode_primary_key_from_row(model.table_prefix, &long_row, &model);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("requires exactly 16 bytes"));

        // Exact length (16 bytes) — must succeed
        let ok_row = KvRow {
            values: vec![CellValue::FixedBinary(vec![0xEF; 16]), CellValue::Int64(3)],
        };
        assert!(encode_primary_key_from_row(model.table_prefix, &ok_row, &model).is_ok());
    }

    #[test]
    fn fixed_binary_index_key_rejects_wrong_length() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("tag", DataType::FixedSizeBinary(8), false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("tag_idx", vec!["tag".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();

        // Wrong length (4 bytes for an 8-byte column)
        let bad_row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::FixedBinary(vec![0x01; 4])],
        };
        let result = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &bad_row);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("requires exactly 8 bytes"));

        // Correct length (8 bytes)
        let ok_row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::FixedBinary(vec![0x02; 8])],
        };
        assert!(encode_secondary_index_key(model.table_prefix, &specs[0], &model, &ok_row).is_ok());
    }

    #[test]
    fn decimal256_column_round_trip() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("balance", DataType::Decimal256(76, 0), false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let big_val = i256::from(123456789012345i64);
        let row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::Decimal256(big_val)],
        };
        let encoded = encode_base_row_value(&row, &model).unwrap();
        let pk = row
            .primary_key_values(&model)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let decoded = decode_base_row(pk, &encoded, &model).unwrap();
        assert!(matches!(&decoded.values[1], CellValue::Decimal256(v) if *v == big_val));
    }

    #[test]
    fn float64_primary_key_rejected() {
        let config = KvTableConfig::new(
            0,
            vec![TableColumnConfig::new("id", DataType::Float64, false)],
            vec!["id".to_string()],
            vec![],
        );
        assert!(config.is_err());
    }

    #[test]
    fn i256_ordered_encoding_round_trip() {
        let values = [
            i256::from_i128(i128::MIN),
            i256::from(-1i64),
            i256::from(0i64),
            i256::from(1i64),
            i256::from_i128(i128::MAX),
        ];
        for v in values {
            assert_eq!(decode_i256_ordered(encode_i256_ordered(v)), v);
        }
        let encoded: Vec<[u8; 32]> = values.iter().map(|v| encode_i256_ordered(*v)).collect();
        for i in 0..encoded.len() - 1 {
            assert!(encoded[i] < encoded[i + 1]);
        }
    }

    #[test]
    fn uint64_primary_key_encode_decode() {
        let config = KvTableConfig::new(
            5,
            vec![
                TableColumnConfig::new("id", DataType::UInt64, false),
                TableColumnConfig::new("name", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let pk = CellValue::UInt64(12345);
        let key = encode_primary_key(5, &[&pk], &model).expect("pk key encodes");
        let decoded = decode_primary_key(5, &key, &model).unwrap();
        assert!(matches!(&decoded[0], CellValue::UInt64(12345)));
    }

    #[test]
    fn utf8_primary_key_encode_decode() {
        let config = KvTableConfig::new(
            3,
            vec![
                TableColumnConfig::new("code", DataType::Utf8, false),
                TableColumnConfig::new("val", DataType::Int64, false),
            ],
            vec!["code".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let pk = CellValue::Utf8("HELLO".to_string());
        let key = encode_primary_key(3, &[&pk], &model).expect("pk key encodes");
        let decoded = decode_primary_key(3, &key, &model).unwrap();
        assert!(matches!(&decoded[0], CellValue::Utf8(v) if v == "HELLO"));
    }

    #[test]
    fn fixed_binary_primary_key_encode_decode() {
        let config = KvTableConfig::new(
            7,
            vec![
                TableColumnConfig::new("hash", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("val", DataType::Int64, false),
            ],
            vec!["hash".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let pk = CellValue::FixedBinary(data.clone());
        let key = encode_primary_key(7, &[&pk], &model).expect("pk key encodes");
        let decoded = decode_primary_key(7, &key, &model).unwrap();
        assert!(matches!(&decoded[0], CellValue::FixedBinary(v) if *v == data));
    }

    #[test]
    fn secondary_index_with_uint64_column() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("counter", DataType::UInt64, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("counter_idx", vec!["counter".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();
        let row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::UInt64(999)],
        };
        let key = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &row).unwrap();
        let decoded =
            decode_secondary_index_key(model.table_prefix, &specs[0], &model, &key).unwrap();
        let counter_idx = *model.columns_by_name.get("counter").unwrap();
        assert!(matches!(
            decoded.values.get(&counter_idx),
            Some(CellValue::UInt64(999))
        ));
        assert!(matches!(
            &decoded.primary_key_values[0],
            CellValue::Int64(1)
        ));
    }

    #[test]
    fn secondary_index_with_decimal256_column() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("big_val", DataType::Decimal256(76, 0), false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("big_idx", vec!["big_val".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();
        let val = i256::from(42i64);
        let row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::Decimal256(val)],
        };
        let key = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &row).unwrap();
        let decoded =
            decode_secondary_index_key(model.table_prefix, &specs[0], &model, &key).unwrap();
        let big_idx = *model.columns_by_name.get("big_val").unwrap();
        assert!(matches!(
            decoded.values.get(&big_idx),
            Some(CellValue::Decimal256(v)) if *v == val
        ));
    }

    // -----------------------------------------------------------------------
    // Composite primary key tests
    // -----------------------------------------------------------------------

    #[test]
    fn composite_pk_config_accepted() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        );
        assert!(config.is_ok());
        let c = config.unwrap();
        assert_eq!(c.primary_key_columns, vec!["entity", "version"]);
    }

    #[test]
    fn composite_pk_rejects_unsupported_type() {
        let result = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new("score", DataType::Float64, false),
            ],
            vec!["entity".to_string(), "score".to_string()],
            vec![],
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("must be Int64") || err.contains("must be"),
            "expected PK type error, got: {err}"
        );
    }

    #[test]
    fn composite_pk_rejects_too_wide() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("big", DataType::FixedSizeBinary(60), false),
                TableColumnConfig::new("ver", DataType::UInt64, false),
            ],
            vec!["big".to_string(), "ver".to_string()],
            vec![],
        )
        .expect("variable-length keys should allow wider composite PKs");
        let model = TableModel::from_config(&config).expect("model");
        assert_eq!(model.primary_key_width, 68);
    }

    #[test]
    fn composite_pk_encode_decode_round_trip() {
        let config = KvTableConfig::new(
            1,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("title", DataType::Utf8, true),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        let entity = vec![0xAA; 32];
        let pk_entity = CellValue::FixedBinary(entity.clone());
        let pk_version = CellValue::UInt64(42);
        let key =
            encode_primary_key(1, &[&pk_entity, &pk_version], &model).expect("pk key encodes");

        let decoded = decode_primary_key(1, &key, &model).unwrap();
        assert_eq!(decoded.len(), 2);
        assert!(matches!(&decoded[0], CellValue::FixedBinary(v) if *v == entity));
        assert!(matches!(&decoded[1], CellValue::UInt64(42)));
    }

    #[test]
    fn composite_pk_version_sort_order() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        let entity = vec![0xBB; 32];
        let pk_entity = CellValue::FixedBinary(entity.clone());

        let key_v1 = encode_primary_key(0, &[&pk_entity, &CellValue::UInt64(1)], &model)
            .expect("pk key encodes");
        let key_v10 = encode_primary_key(0, &[&pk_entity, &CellValue::UInt64(10)], &model)
            .expect("pk key encodes");
        let key_v100 = encode_primary_key(0, &[&pk_entity, &CellValue::UInt64(100)], &model)
            .expect("pk key encodes");

        // Versions must sort numerically (big-endian U64)
        assert!(key_v1 < key_v10);
        assert!(key_v10 < key_v100);
    }

    #[test]
    fn composite_pk_value_excludes_all_pk_columns() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        let row = KvRow {
            values: vec![
                CellValue::FixedBinary(vec![0xCC; 16]),
                CellValue::UInt64(7),
                CellValue::Utf8("hello".to_string()),
            ],
        };
        let encoded = encode_base_row_value(&row, &model).unwrap();
        // Both PK columns should be None in stored value
        let decoded = decode_base_row(
            vec![CellValue::FixedBinary(vec![0xCC; 16]), CellValue::UInt64(7)],
            &encoded,
            &model,
        )
        .unwrap();
        assert!(matches!(&decoded.values[0], CellValue::FixedBinary(v) if v.len() == 16));
        assert!(matches!(&decoded.values[1], CellValue::UInt64(7)));
        assert!(matches!(&decoded.values[2], CellValue::Utf8(v) if v == "hello"));
    }

    #[test]
    fn composite_pk_secondary_index_appends_all_pk_columns() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("tag", DataType::Int64, false),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![IndexSpec::new("tag_idx", vec!["tag".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();

        let entity_data = vec![0xDD; 16];
        let row = KvRow {
            values: vec![
                CellValue::FixedBinary(entity_data.clone()),
                CellValue::UInt64(99),
                CellValue::Int64(42),
            ],
        };
        let key = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &row).unwrap();
        let decoded =
            decode_secondary_index_key(model.table_prefix, &specs[0], &model, &key).unwrap();

        assert_eq!(decoded.primary_key_values.len(), 2);
        assert!(matches!(
            &decoded.primary_key_values[0],
            CellValue::FixedBinary(v) if *v == entity_data
        ));
        assert!(matches!(
            &decoded.primary_key_values[1],
            CellValue::UInt64(99)
        ));
        let tag_idx = *model.columns_by_name.get("tag").unwrap();
        assert!(matches!(
            decoded.values.get(&tag_idx),
            Some(CellValue::Int64(42))
        ));
    }

    #[test]
    fn table_versioned_convenience() {
        let client = StoreClient::new("http://localhost:10000");
        let schema = KvSchema::new(client)
            .table_versioned(
                "documents",
                vec![
                    TableColumnConfig::new("doc_id", DataType::FixedSizeBinary(32), false),
                    TableColumnConfig::new("version", DataType::UInt64, false),
                    TableColumnConfig::new("title", DataType::Utf8, false),
                ],
                "doc_id",
                "version",
                vec![],
            )
            .unwrap();
        assert_eq!(schema.table_count(), 1);
    }

    #[test]
    fn single_column_pk_backward_compat() {
        // Ensure single-column PK still works identically
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8, true),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        assert_eq!(model.primary_key_indices.len(), 1);
        assert_eq!(model.primary_key_indices[0], 0);
        assert_eq!(model.primary_key_width, 8);

        let pk = CellValue::Int64(42);
        let key = encode_primary_key(0, &[&pk], &model).expect("pk key encodes");
        let decoded = decode_primary_key(0, &key, &model).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(matches!(&decoded[0], CellValue::Int64(42)));
    }

    #[test]
    fn partial_prefix_upper_bound_fills_trailing_pk_bytes() {
        // Regression: encode_primary_key_bound with partial prefix must
        // fill 0xFF from the end of the encoded prefix, not from the
        // end of the full PK width. Otherwise trailing PK column bytes
        // stay 0x00, producing an end key that's too low.
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        assert_eq!(model.primary_key_width, 24); // 16 + 8

        let entity = CellValue::FixedBinary(vec![0xAA; 16]);
        // Partial prefix: only entity, no version
        let upper =
            encode_primary_key_bound(0, &[&entity], &model, true).expect("pk bound encodes");

        // Entity bytes must be encoded
        assert_eq!(primary_payload(&model, &upper, 0, 16), vec![0xAA; 16]);
        // Version bytes (8 bytes after entity) MUST be 0xFF, not 0x00
        assert_eq!(
            primary_payload(&model, &upper, 16, 8),
            vec![0xFF; 8],
            "trailing PK column (version) must be 0xFF for upper bound"
        );
        // Everything after PK region also 0xFF
        assert!(primary_payload(
            &model,
            &upper,
            24,
            model.primary_key_codec.payload_capacity_bytes() - 24
        )
        .iter()
        .all(|&b| b == 0xFF));

        // Lower bound: trailing bytes should be 0x00
        let lower =
            encode_primary_key_bound(0, &[&entity], &model, false).expect("pk bound encodes");
        assert_eq!(primary_payload(&model, &lower, 0, 16), vec![0xAA; 16]);
        assert_eq!(
            primary_payload(&model, &lower, 16, 8),
            vec![0x00; 8],
            "trailing PK column (version) must be 0x00 for lower bound"
        );
    }

    // -----------------------------------------------------------------------
    // Composite PK filter pushdown tests
    // -----------------------------------------------------------------------

    #[test]
    fn composite_pk_range_pushdown_entity_eq_version_lte() {
        // PK = (entity: FixedSizeBinary(16), version: UInt64)
        // Query: entity = X'CC..CC' AND version <= 42
        // Should produce a TIGHT range, not a full table scan.
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        // Simulate predicate: entity = X'CC..CC' AND version <= 42
        let mut pred = QueryPredicate::default();
        pred.constraints
            .insert(0, PredicateConstraint::FixedBinaryEq(vec![0xCC; 16]));
        pred.constraints.insert(
            1,
            PredicateConstraint::UInt64Range {
                min: None,
                max: Some(42),
            },
        );

        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert_eq!(ranges.len(), 1, "should produce exactly one range");

        let range = &ranges[0];

        // The start key should encode entity=CC..CC, version=0
        let expected_start = encode_primary_key(
            0,
            &[
                &CellValue::FixedBinary(vec![0xCC; 16]),
                &CellValue::UInt64(0),
            ],
            &model,
        )
        .expect("pk key encodes");
        assert_eq!(
            range.start, expected_start,
            "start should be entity=CC..CC, version=0"
        );

        // The end key should encode entity=CC..CC, version=42, then 0xFF tail
        let expected_end_prefix = encode_primary_key(
            0,
            &[
                &CellValue::FixedBinary(vec![0xCC; 16]),
                &CellValue::UInt64(42),
            ],
            &model,
        )
        .expect("pk key encodes");
        // The end key has 0xFF-filled tail after the PK portion
        assert_eq!(
            primary_payload(&model, &range.end, 0, model.primary_key_width),
            primary_payload(&model, &expected_end_prefix, 0, model.primary_key_width),
            "end prefix should be entity=CC..CC, version=42"
        );
        // Trailing bytes after PK should be 0xFF
        assert!(
            primary_payload(
                &model,
                &range.end,
                model.primary_key_width,
                model.primary_key_codec.payload_capacity_bytes() - model.primary_key_width
            )
            .iter()
            .all(|&b| b == 0xFF),
            "end trailing bytes should be 0xFF"
        );

        // Crucially, the range must NOT be a full table scan
        let full_range = primary_key_prefix_range(0);
        assert_ne!(
            range.start, full_range.start,
            "range must not be a full table scan"
        );
    }

    #[test]
    fn composite_pk_range_pushdown_entity_eq_only() {
        // PK = (entity: FixedSizeBinary(16), version: UInt64)
        // Query: entity = X'DD..DD' (no version constraint)
        // Should still produce a tight entity-prefix range.
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        let mut pred = QueryPredicate::default();
        pred.constraints
            .insert(0, PredicateConstraint::FixedBinaryEq(vec![0xDD; 16]));

        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert_eq!(ranges.len(), 1);

        let range = &ranges[0];
        // Start should have entity=DD..DD, version=0x00..00
        assert_eq!(primary_payload(&model, &range.start, 0, 16), vec![0xDD; 16]);
        // End should have entity=DD..DD, then 0xFF for version + tail
        assert_eq!(primary_payload(&model, &range.end, 0, 16), vec![0xDD; 16]);
        assert!(
            primary_payload(
                &model,
                &range.end,
                16,
                model.primary_key_codec.payload_capacity_bytes() - 16
            )
            .iter()
            .all(|&b| b == 0xFF),
            "after entity bytes, everything should be 0xFF"
        );
    }

    #[test]
    fn fixed_binary_eq_constraint_extracted() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
            ],
            vec!["entity".to_string(), "version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        // Build an equality expression: entity = X'AA..AA'
        use datafusion::logical_expr::col;
        let entity_literal =
            Expr::Literal(ScalarValue::FixedSizeBinary(16, Some(vec![0xAA; 16])), None);
        let filter = col("entity").eq(entity_literal);

        assert!(
            QueryPredicate::supports_filter(&filter, &model),
            "FixedSizeBinary equality should be supported"
        );

        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(
            matches!(
                pred.constraints.get(&0),
                Some(PredicateConstraint::FixedBinaryEq(v)) if *v == vec![0xAA; 16]
            ),
            "should extract FixedBinaryEq constraint"
        );
    }

    #[test]
    fn uint64_range_constraint_extracted() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::col;
        let filter = col("version").lt_eq(Expr::Literal(ScalarValue::UInt64(Some(42)), None));

        assert!(
            QueryPredicate::supports_filter(&filter, &model),
            "UInt64 range should be supported"
        );

        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(
            matches!(
                pred.constraints.get(&0),
                Some(PredicateConstraint::UInt64Range {
                    min: None,
                    max: Some(42)
                })
            ),
            "should extract UInt64Range with max=42"
        );
    }

    #[test]
    fn uint64_range_constraint_supports_values_above_i64_max() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        let threshold = (1u64 << 63) + 5;
        use datafusion::logical_expr::col;
        let filter =
            col("version").gt_eq(Expr::Literal(ScalarValue::UInt64(Some(threshold)), None));

        assert!(QueryPredicate::supports_filter(&filter, &model));

        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(matches!(
            pred.constraints.get(&0),
            Some(PredicateConstraint::UInt64Range {
                min: Some(v),
                max: None
            }) if *v == threshold
        ));
    }

    #[test]
    fn unsupported_uint64_comparison_does_not_force_contradiction() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::col;
        let unsupported = col("version").gt(Expr::Literal(ScalarValue::Int64(Some(-1)), None));

        assert!(
            !QueryPredicate::supports_filter(&unsupported, &model),
            "negative Int64 literal on UInt64 column should not be pushdown-supported"
        );

        let pred = QueryPredicate::from_filters(&[unsupported], &model);
        assert!(
            !pred.contradiction,
            "unsupported filter must not collapse scan to empty result"
        );
        assert!(
            pred.constraints.is_empty(),
            "unsupported filter must not contribute pushed constraints"
        );
    }

    #[test]
    fn unsupported_uint64_comparison_in_and_keeps_supported_sibling() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::col;
        let supported = col("version").gt_eq(Expr::Literal(ScalarValue::UInt64(Some(10)), None));
        let unsupported = col("version").gt(Expr::Literal(ScalarValue::Int64(Some(-1)), None));
        let filter = supported.and(unsupported);

        assert!(
            !QueryPredicate::supports_filter(&filter, &model),
            "mixed AND should not be marked fully pushdown-supported"
        );

        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(!pred.contradiction);
        assert!(matches!(
            pred.constraints.get(&0),
            Some(PredicateConstraint::UInt64Range {
                min: Some(10),
                max: None
            })
        ));
    }

    #[test]
    fn uint64_in_list_pushdown() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::{col, in_list};
        let filter = in_list(
            col("version"),
            vec![
                Expr::Literal(ScalarValue::UInt64(Some(1)), None),
                Expr::Literal(ScalarValue::UInt64(Some(5)), None),
                Expr::Literal(ScalarValue::UInt64(Some(10)), None),
            ],
            false,
        );

        assert!(QueryPredicate::supports_filter(&filter, &model));
        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(
            matches!(pred.constraints.get(&0), Some(PredicateConstraint::UInt64In(v)) if v.len() == 3),
            "should extract UInt64In with 3 values"
        );
    }

    #[test]
    fn uint64_in_list_pushdown_supports_values_above_i64_max() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        let huge = 1u64 << 63;
        use datafusion::logical_expr::{col, in_list};
        let filter = in_list(
            col("version"),
            vec![
                Expr::Literal(ScalarValue::UInt64(Some(1)), None),
                Expr::Literal(ScalarValue::UInt64(Some(huge)), None),
            ],
            false,
        );

        assert!(QueryPredicate::supports_filter(&filter, &model));
        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(matches!(
            pred.constraints.get(&0),
            Some(PredicateConstraint::UInt64In(v)) if v.contains(&huge) && v.len() == 2
        ));
    }

    #[test]
    fn fixed_binary_in_list_pushdown() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("data", DataType::Utf8, true),
            ],
            vec!["entity".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::{col, in_list};
        let filter = in_list(
            col("entity"),
            vec![
                Expr::Literal(ScalarValue::FixedSizeBinary(16, Some(vec![0xAA; 16])), None),
                Expr::Literal(ScalarValue::FixedSizeBinary(16, Some(vec![0xBB; 16])), None),
            ],
            false,
        );

        assert!(QueryPredicate::supports_filter(&filter, &model));
        let pred = QueryPredicate::from_filters(&[filter], &model);
        assert!(
            matches!(
                pred.constraints.get(&0),
                Some(PredicateConstraint::FixedBinaryIn(v)) if v.len() == 2
            ),
            "should extract FixedBinaryIn with 2 values"
        );

        // Verify range generation produces 2 ranges (one per entity)
        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert_eq!(ranges.len(), 2, "should produce one range per entity");
    }

    #[test]
    fn decimal256_range_pushdown() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("big_val", DataType::Decimal256(76, 0), false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("big_idx", vec!["big_val".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        use datafusion::logical_expr::col;
        let filter = col("big_val").gt_eq(Expr::Literal(
            ScalarValue::Decimal256(Some(i256::from(100i64)), 76, 0),
            None,
        ));

        assert!(
            QueryPredicate::supports_filter(&filter, &model),
            "Decimal256 range should be supported"
        );

        let pred = QueryPredicate::from_filters(&[filter], &model);
        let big_idx = *model.columns_by_name.get("big_val").unwrap();
        assert!(
            matches!(
                pred.constraints.get(&big_idx),
                Some(PredicateConstraint::Decimal256Range {
                    min: Some(_),
                    max: None
                })
            ),
            "should extract Decimal256Range with min=100, no max"
        );

        // Verify constraint matching
        let val_in = CellValue::Decimal256(i256::from(200i64));
        let val_out = CellValue::Decimal256(i256::from(50i64));
        let constraint = pred.constraints.get(&big_idx).unwrap();
        assert!(matches_constraint(&val_in, constraint));
        assert!(!matches_constraint(&val_out, constraint));
    }

    #[test]
    fn uint64_constraint_matching_does_not_wrap_large_values() {
        let gt_zero = PredicateConstraint::UInt64Range {
            min: Some(1),
            max: None,
        };
        assert!(matches_constraint(&CellValue::UInt64(1u64 << 63), &gt_zero));
        assert!(!matches_constraint(&CellValue::UInt64(0), &gt_zero));

        let in_list = PredicateConstraint::UInt64In(vec![1, 2, 3]);
        assert!(matches_constraint(&CellValue::UInt64(2), &in_list));
        assert!(!matches_constraint(
            &CellValue::UInt64(1u64 << 63),
            &in_list
        ));
    }

    #[test]
    fn uint64_empty_range_produces_no_pk_ranges() {
        let config = KvTableConfig::new(
            0,
            vec![TableColumnConfig::new("version", DataType::UInt64, false)],
            vec!["version".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let mut pred = QueryPredicate::default();
        pred.constraints.insert(
            0,
            PredicateConstraint::UInt64Range {
                min: Some(10),
                max: Some(9),
            },
        );

        let ranges = pred.primary_key_ranges(&model).unwrap();
        assert!(ranges.is_empty());
    }

    #[test]
    fn utf8_primary_key_encoding_supports_unicode_and_long_values() {
        let config = KvTableConfig::new(
            0,
            vec![TableColumnConfig::new("id", DataType::Utf8, false)],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();

        let row_non_ascii = KvRow {
            values: vec![CellValue::Utf8("naive-cafe-e9".replace("e9", "\u{00E9}"))],
        };
        let key_non_ascii = encode_primary_key_from_row(model.table_prefix, &row_non_ascii, &model)
            .expect("non-ascii PK should encode");
        let decoded_non_ascii = decode_primary_key(model.table_prefix, &key_non_ascii, &model)
            .expect("non-ascii PK should decode");
        assert!(matches!(
            decoded_non_ascii.as_slice(),
            [CellValue::Utf8(value)] if value == "naive-cafe-\u{00E9}"
        ));

        let row_too_long = KvRow {
            values: vec![CellValue::Utf8("abcdefghijklmnopq".to_string())],
        };
        let key_too_long = encode_primary_key_from_row(model.table_prefix, &row_too_long, &model)
            .expect("long UTF-8 PK should encode");
        let decoded_too_long = decode_primary_key(model.table_prefix, &key_too_long, &model)
            .expect("long UTF-8 PK should decode");
        assert!(matches!(
            decoded_too_long.as_slice(),
            [CellValue::Utf8(value)] if value == "abcdefghijklmnopq"
        ));
    }

    #[test]
    fn utf8_primary_key_encodes_at_max_codec_payload_and_rejects_overflow() {
        let config = KvTableConfig::new(
            0,
            vec![TableColumnConfig::new("id", DataType::Utf8, false)],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let max_payload = model.primary_key_codec.payload_capacity_bytes();
        let max_value = "a".repeat(max_payload - 1);
        let overflow_value = "a".repeat(max_payload);

        let key = encode_primary_key_from_row(
            model.table_prefix,
            &KvRow {
                values: vec![CellValue::Utf8(max_value.clone())],
            },
            &model,
        )
        .expect("max-length UTF-8 PK should encode");
        assert_eq!(key.len(), exoware_sdk_rs::keys::MAX_KEY_LEN);
        let decoded = decode_primary_key(model.table_prefix, &key, &model)
            .expect("max-length PK should decode");
        assert!(matches!(
            decoded.as_slice(),
            [CellValue::Utf8(value)] if value == &max_value
        ));

        let err = encode_primary_key_from_row(
            model.table_prefix,
            &KvRow {
                values: vec![CellValue::Utf8(overflow_value)],
            },
            &model,
        )
        .expect_err("UTF-8 PK exceeding codec payload should be rejected");
        assert!(err.contains("primary key payload exceeds codec payload capacity 253 bytes"));
    }

    #[test]
    fn utf8_primary_key_round_trips_embedded_nul() {
        let config = KvTableConfig::new(
            0,
            vec![TableColumnConfig::new("id", DataType::Utf8, false)],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let row = KvRow {
            values: vec![CellValue::Utf8("AB\0CD".to_string())],
        };

        let key = encode_primary_key_from_row(model.table_prefix, &row, &model)
            .expect("embedded NUL in key text must encode");
        let decoded =
            decode_primary_key(model.table_prefix, &key, &model).expect("embedded NUL must decode");
        assert!(matches!(
            decoded.as_slice(),
            [CellValue::Utf8(value)] if value == "AB\0CD"
        ));
    }

    #[test]
    fn utf8_index_key_round_trips_embedded_nul() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("tag", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("tag_idx", vec!["tag".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();
        let row = KvRow {
            values: vec![CellValue::Int64(1), CellValue::Utf8("AB\0CD".to_string())],
        };

        let key = encode_secondary_index_key(model.table_prefix, &specs[0], &model, &row)
            .expect("embedded NUL in index key text must encode");
        let decoded = decode_secondary_index_key(model.table_prefix, &specs[0], &model, &key)
            .expect("embedded NUL index key must decode");
        assert!(matches!(
            decoded.values.get(&1),
            Some(CellValue::Utf8(value)) if value == "AB\0CD"
        ));
    }

    #[test]
    fn secondary_index_with_long_utf8_primary_key_encodes_at_max_payload_and_rejects_overflow() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Utf8, false),
                TableColumnConfig::new("tag", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("tag_idx", vec!["tag".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();
        let spec = &specs[0];
        let max_payload = spec.codec.payload_capacity_bytes();
        let max_tag = "t".to_string();
        let max_id = "i".repeat(max_payload - encode_string_variable(&max_tag).unwrap().len() - 1);
        let overflow_id = format!("{max_id}x");

        let key = encode_secondary_index_key(
            model.table_prefix,
            spec,
            &model,
            &KvRow {
                values: vec![
                    CellValue::Utf8(max_id.clone()),
                    CellValue::Utf8(max_tag.clone()),
                ],
            },
        )
        .expect("secondary key at max payload should encode");
        assert_eq!(key.len(), exoware_sdk_rs::keys::MAX_KEY_LEN);
        let decoded =
            decode_secondary_index_key(model.table_prefix, spec, &model, &key).expect("decode");
        assert!(matches!(
            decoded.values.get(&1),
            Some(CellValue::Utf8(value)) if value == &max_tag
        ));
        assert!(matches!(
            decoded.primary_key_values.as_slice(),
            [CellValue::Utf8(value)] if value == &max_id
        ));

        let err = encode_secondary_index_key(
            model.table_prefix,
            spec,
            &model,
            &KvRow {
                values: vec![CellValue::Utf8(overflow_id), CellValue::Utf8(max_tag)],
            },
        )
        .expect_err("secondary key exceeding max payload should be rejected");
        assert!(err.contains("index 'tag_idx' payload exceeds codec payload capacity 252 bytes"));
    }

    #[test]
    fn secondary_index_from_parts_with_long_utf8_primary_key_rejects_overflow() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Utf8, false),
                TableColumnConfig::new("tag", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("tag_idx", vec!["tag".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();
        let spec = &specs[0];
        let max_payload = spec.codec.payload_capacity_bytes();
        let max_tag = "t".to_string();
        let max_id = "i".repeat(max_payload - encode_string_variable(&max_tag).unwrap().len() - 1);
        let overflow_id = format!("{max_id}x");
        let max_row = KvRow {
            values: vec![
                CellValue::Utf8(max_id.clone()),
                CellValue::Utf8(max_tag.clone()),
            ],
        };
        let encoded_row = encode_base_row_value(&max_row, &model).expect("encode row");
        let archived = access_stored_row(&encoded_row).expect("archive row");

        let key = encode_secondary_index_key_from_parts(
            model.table_prefix,
            spec,
            &model,
            &[CellValue::Utf8(max_id.clone())],
            archived,
        )
        .expect("backfill path should encode max payload");
        assert_eq!(key.len(), exoware_sdk_rs::keys::MAX_KEY_LEN);

        let err = encode_secondary_index_key_from_parts(
            model.table_prefix,
            spec,
            &model,
            &[CellValue::Utf8(overflow_id)],
            archived,
        )
        .expect_err("backfill path overflow should be rejected");
        assert!(err
            .to_string()
            .contains("index 'tag_idx' payload exceeds codec payload capacity 252 bytes"));
    }

    #[test]
    fn primary_key_type_mismatch_returns_error_instead_of_panicking() {
        let config = KvTableConfig::new(
            0,
            vec![TableColumnConfig::new("id", DataType::UInt64, false)],
            vec!["id".to_string()],
            vec![],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let row = KvRow {
            values: vec![CellValue::Int64(7)],
        };

        let err = encode_primary_key_from_row(model.table_prefix, &row, &model)
            .expect_err("mismatched PK type should return an error");
        assert!(err.contains("type mismatch while encoding key value"));
    }

    #[test]
    fn choose_index_plan_uses_fixed_binary_leading_constraint() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("entity", DataType::FixedSizeBinary(16), false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("entity_idx", vec!["entity".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();

        use datafusion::logical_expr::col;
        let filter = col("entity").eq(Expr::Literal(
            ScalarValue::FixedSizeBinary(16, Some(vec![0xAB; 16])),
            None,
        ));
        let pred = QueryPredicate::from_filters(&[filter], &model);
        let plan = pred
            .choose_index_plan(&model, &specs)
            .unwrap()
            .expect("fixed-binary equality should choose an index");

        assert_eq!(plan.constrained_prefix_len, 1);
        assert_eq!(plan.ranges.len(), 1);
        let range = &plan.ranges[0];
        assert_eq!(
            index_payload(&specs[0], &range.start, 0, 16),
            vec![0xAB; 16]
        );
        assert_eq!(index_payload(&specs[0], &range.end, 0, 16), vec![0xAB; 16]);
    }

    #[test]
    fn choose_index_plan_uses_decimal256_leading_constraint() {
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("big_val", DataType::Decimal256(76, 0), false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("big_idx", vec!["big_val".to_string()]).unwrap()],
        )
        .unwrap();
        let model = TableModel::from_config(&config).unwrap();
        let specs = model.resolve_index_specs(&config.index_specs).unwrap();

        use datafusion::logical_expr::col;
        let filter = col("big_val").gt_eq(Expr::Literal(
            ScalarValue::Decimal256(Some(i256::from(100i64)), 76, 0),
            None,
        ));
        let pred = QueryPredicate::from_filters(&[filter], &model);
        let plan = pred
            .choose_index_plan(&model, &specs)
            .unwrap()
            .expect("decimal256 range should choose an index");

        assert_eq!(plan.constrained_prefix_len, 1);
        assert_eq!(plan.ranges.len(), 1);
        let range = &plan.ranges[0];
        assert_eq!(
            index_payload(&specs[0], &range.start, 0, 32),
            encode_i256_ordered(i256::from(100i64)).to_vec()
        );
    }

    #[tokio::test]
    async fn backfill_added_indexes_writes_entries_for_existing_rows() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let seed_schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("seed schema");
        let mut writer = seed_schema.batch_writer();
        for i in 0..6i64 {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(i),
                        CellValue::Utf8(if i % 2 == 0 { "open" } else { "closed" }.to_string()),
                        CellValue::Int64(i * 10),
                    ],
                )
                .expect("seed row");
        }
        writer.flush().await.expect("seed flush");

        {
            let guard = state.kv.lock().expect("kv mutex poisoned");
            let base_rows = guard
                .keys()
                .filter(|key| matches_primary_key(0, key))
                .count();
            let index_rows = guard
                .keys()
                .filter(|key| matches_secondary_index_key(0, 1, key))
                .count();
            assert_eq!(base_rows, 6);
            assert_eq!(index_rows, 0);
        }

        let backfill_schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid index")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("backfill schema");
        let report = backfill_schema
            .backfill_added_indexes_with_options(
                "orders",
                &[],
                IndexBackfillOptions {
                    row_batch_size: 2,
                    start_from_primary_key: None,
                },
            )
            .await
            .expect("backfill should succeed");
        assert_eq!(report.scanned_rows, 6);
        assert_eq!(report.indexes_backfilled, 1);
        assert_eq!(report.index_entries_written, 6);

        {
            let guard = state.kv.lock().expect("kv mutex poisoned");
            let index_rows = guard
                .keys()
                .filter(|key| matches_secondary_index_key(0, 1, key))
                .count();
            assert_eq!(index_rows, 6);
            let (_, sample_value) = guard
                .iter()
                .find(|(key, _)| matches_secondary_index_key(0, 1, key))
                .expect("backfill should create index entry");
            let archived = access_stored_row(sample_value.as_ref())
                .expect("covering value must be valid rkyv");
            assert_eq!(archived.values.len(), 3);
        }

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn backfill_added_indexes_writes_zorder_entries_for_existing_rows() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let seed_schema = KvSchema::new(client.clone())
            .table(
                "points",
                vec![
                    TableColumnConfig::new("x", DataType::Int64, false),
                    TableColumnConfig::new("y", DataType::Int64, false),
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("value", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("seed schema");
        let mut writer = seed_schema.batch_writer();
        for (x, y, id, value) in [(1, 1, 11, 110), (1, 2, 12, 120), (2, 1, 21, 210)] {
            writer
                .insert(
                    "points",
                    vec![
                        CellValue::Int64(x),
                        CellValue::Int64(y),
                        CellValue::Int64(id),
                        CellValue::Int64(value),
                    ],
                )
                .expect("seed row");
        }
        writer.flush().await.expect("seed flush");

        let backfill_schema = KvSchema::new(client.clone())
            .table(
                "points",
                vec![
                    TableColumnConfig::new("x", DataType::Int64, false),
                    TableColumnConfig::new("y", DataType::Int64, false),
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("value", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![
                    IndexSpec::z_order("xy_z", vec!["x".to_string(), "y".to_string()])
                        .expect("valid index")
                        .with_cover_columns(vec!["value".to_string()]),
                ],
            )
            .expect("backfill schema");
        let report = backfill_schema
            .backfill_added_indexes_with_options(
                "points",
                &[],
                IndexBackfillOptions {
                    row_batch_size: 2,
                    start_from_primary_key: None,
                },
            )
            .await
            .expect("backfill should succeed");
        assert_eq!(report.scanned_rows, 3);
        assert_eq!(report.index_entries_written, 3);

        let guard = state.kv.lock().expect("kv mutex poisoned");
        let index_entry = guard
            .keys()
            .find(|key| matches_secondary_index_key(0, 1, key))
            .cloned()
            .expect("z-order backfill should create index entry");
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("x", DataType::Int64, false),
                TableColumnConfig::new("y", DataType::Int64, false),
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("value", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![
                IndexSpec::z_order("xy_z", vec!["x".to_string(), "y".to_string()]).expect("valid"),
            ],
        )
        .expect("config");
        let model = TableModel::from_config(&config).expect("model");
        let spec = model
            .resolve_index_specs(&config.index_specs)
            .expect("specs")
            .remove(0);
        let decoded = decode_secondary_index_key(model.table_prefix, &spec, &model, &index_entry)
            .expect("decode z-order key");
        let x_idx = *model.columns_by_name.get("x").unwrap();
        let y_idx = *model.columns_by_name.get("y").unwrap();
        assert!(matches!(
            decoded.values.get(&x_idx),
            Some(CellValue::Int64(_))
        ));
        assert!(matches!(
            decoded.values.get(&y_idx),
            Some(CellValue::Int64(_))
        ));

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn backfill_added_indexes_requires_append_only_index_evolution() {
        let client = StoreClient::new("http://127.0.0.1:1");
        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![
                    IndexSpec::new("status_idx", vec!["status".to_string()]).expect("valid"),
                    IndexSpec::new("amount_idx", vec!["amount_cents".to_string()]).expect("valid"),
                ],
            )
            .expect("schema");

        let previous_specs =
            vec![IndexSpec::new("amount_idx", vec!["amount_cents".to_string()]).expect("valid")];
        let err = schema
            .backfill_added_indexes("orders", &previous_specs)
            .await
            .expect_err("non-append-only evolution should be rejected");
        assert!(err
            .to_string()
            .contains("index evolution must be append-only"));
    }

    #[tokio::test]
    async fn backfill_added_indexes_is_noop_when_no_new_indexes() {
        let client = StoreClient::new("http://127.0.0.1:1");
        let existing = IndexSpec::new("status_idx", vec!["status".to_string()])
            .expect("valid")
            .with_cover_columns(vec!["amount_cents".to_string()]);
        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![existing.clone()],
            )
            .expect("schema");

        let report = schema
            .backfill_added_indexes("orders", &[existing])
            .await
            .expect("no-op backfill should succeed");
        assert_eq!(report, IndexBackfillReport::default());
    }

    #[tokio::test]
    async fn backfill_added_indexes_rejects_zero_row_batch_size() {
        let client = StoreClient::new("http://127.0.0.1:1");
        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()]).expect("valid")],
            )
            .expect("schema");
        let err = schema
            .backfill_added_indexes_with_options(
                "orders",
                &[],
                IndexBackfillOptions {
                    row_batch_size: 0,
                    start_from_primary_key: None,
                },
            )
            .await
            .expect_err("row_batch_size=0 should fail");
        assert!(err.to_string().contains("row_batch_size must be > 0"));
    }

    #[tokio::test]
    async fn backfill_added_indexes_emits_progress_events() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let seed_schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("seed schema");
        let mut writer = seed_schema.batch_writer();
        for i in 0..5i64 {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(i),
                        CellValue::Utf8("open".to_string()),
                        CellValue::Int64(i * 10),
                    ],
                )
                .expect("seed row");
        }
        writer.flush().await.expect("seed flush");

        let backfill_schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()]).expect("valid")],
            )
            .expect("backfill schema");

        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
        let report = backfill_schema
            .backfill_added_indexes_with_options_and_progress(
                "orders",
                &[],
                IndexBackfillOptions {
                    row_batch_size: 2,
                    start_from_primary_key: None,
                },
                Some(&progress_tx),
            )
            .await
            .expect("backfill should succeed");
        drop(progress_tx);

        let mut saw_started = false;
        let mut saw_completed = false;
        let mut progress_events = 0usize;
        while let Some(event) = progress_rx.recv().await {
            match event {
                IndexBackfillEvent::Started {
                    table_name,
                    indexes_backfilled,
                    row_batch_size,
                    ..
                } => {
                    saw_started = true;
                    assert_eq!(table_name, "orders");
                    assert_eq!(indexes_backfilled, 1);
                    assert_eq!(row_batch_size, 2);
                }
                IndexBackfillEvent::Progress {
                    scanned_rows,
                    index_entries_written,
                    ..
                } => {
                    progress_events += 1;
                    assert!(scanned_rows >= 1);
                    assert_eq!(scanned_rows, index_entries_written);
                }
                IndexBackfillEvent::Completed {
                    report: completed_report,
                } => {
                    saw_completed = true;
                    assert_eq!(completed_report, report);
                }
            }
        }
        assert!(saw_started);
        assert!(saw_completed);
        assert!(progress_events >= 1);

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn backfill_added_indexes_can_resume_from_primary_key() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let seed_schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("seed schema");
        let mut writer = seed_schema.batch_writer();
        for i in 0..6i64 {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(i),
                        CellValue::Utf8("open".to_string()),
                        CellValue::Int64(i * 10),
                    ],
                )
                .expect("seed row");
        }
        writer.flush().await.expect("seed flush");

        let backfill_schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()]).expect("valid")],
            )
            .expect("backfill schema");

        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("valid config");
        let model = TableModel::from_config(&config).expect("model");
        let resume_value = CellValue::Int64(3);
        let resume_key =
            encode_primary_key(model.table_prefix, &[&resume_value], &model).expect("resume key");

        let report = backfill_schema
            .backfill_added_indexes_with_options(
                "orders",
                &[],
                IndexBackfillOptions {
                    row_batch_size: 2,
                    start_from_primary_key: Some(resume_key.clone()),
                },
            )
            .await
            .expect("resume backfill should succeed");
        assert_eq!(report.scanned_rows, 3);
        assert_eq!(report.index_entries_written, 3);

        {
            let guard = state.kv.lock().expect("kv mutex poisoned");
            let index_rows = guard
                .keys()
                .filter(|key| matches_secondary_index_key(0, 1, key))
                .count();
            assert_eq!(index_rows, 3);
        }

        let resume_payload = model
            .primary_key_codec
            .read_payload(&resume_key, 0, model.primary_key_width)
            .expect("resume payload");
        let wrong_prefix = secondary_index_codec(model.table_prefix, 1)
            .expect("secondary codec")
            .encode(&resume_payload)
            .expect("wrong prefix key");
        let err = backfill_schema
            .backfill_added_indexes_with_options(
                "orders",
                &[],
                IndexBackfillOptions {
                    row_batch_size: 2,
                    start_from_primary_key: Some(wrong_prefix),
                },
            )
            .await
            .expect_err("wrong key prefix must be rejected");
        assert!(err.to_string().contains("primary-key prefix"));

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn covering_index_scan_fails_closed_when_covering_payload_missing() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");
        let mut writer = schema.batch_writer();
        for id in 0..4i64 {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8("open".to_string()),
                        CellValue::Int64(id * 10),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        {
            let mut guard = state.kv.lock().expect("kv mutex poisoned");
            let key = guard
                .keys()
                .find(|key| matches_secondary_index_key(0, 1, key))
                .expect("index row should exist")
                .clone();
            guard.insert(key, Bytes::new());
        }

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");
        let df = ctx
            .sql("SELECT amount_cents FROM orders WHERE status = 'open'")
            .await
            .expect("query should plan");
        let err = df
            .collect()
            .await
            .expect_err("missing covering payload must fail closed");
        assert!(err
            .to_string()
            .contains("secondary index entry missing covering payload"));

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn covering_index_scan_fails_closed_when_covering_payload_is_corrupt() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");
        let mut writer = schema.batch_writer();
        for id in 0..4i64 {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8("open".to_string()),
                        CellValue::Int64(id * 10),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        {
            let mut guard = state.kv.lock().expect("kv mutex poisoned");
            let key = guard
                .keys()
                .find(|key| matches_secondary_index_key(0, 1, key))
                .expect("index row should exist")
                .clone();
            guard.insert(key, Bytes::from_static(b"not-rkyv"));
        }

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");
        let df = ctx
            .sql("SELECT amount_cents FROM orders WHERE status = 'open'")
            .await
            .expect("query should plan");
        let err = df
            .collect()
            .await
            .expect_err("corrupt covering payload must fail closed");
        assert!(err.to_string().contains("invalid covering index payload"));

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn backfill_resume_cursor_can_continue_without_skips_or_duplicates() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let seed_schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("seed schema");
        let mut writer = seed_schema.batch_writer();
        for i in 0..8i64 {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(i),
                        CellValue::Utf8("open".to_string()),
                        CellValue::Int64(i * 10),
                    ],
                )
                .expect("seed row");
        }
        writer.flush().await.expect("seed flush");

        let backfill_schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()]).expect("valid")],
            )
            .expect("backfill schema");

        let task_schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()]).expect("valid")],
            )
            .expect("task schema");
        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
        let handle = tokio::spawn(async move {
            task_schema
                .backfill_added_indexes_with_options_and_progress(
                    "orders",
                    &[],
                    IndexBackfillOptions {
                        row_batch_size: 2,
                        start_from_primary_key: None,
                    },
                    Some(&progress_tx),
                )
                .await
        });

        let mut resume_cursor = None;
        while let Some(event) = progress_rx.recv().await {
            if let IndexBackfillEvent::Progress { next_cursor, .. } = event {
                resume_cursor = next_cursor;
                break;
            }
        }
        handle.abort();
        let resume_cursor =
            resume_cursor.expect("first progress event should provide resume cursor");

        let report = backfill_schema
            .backfill_added_indexes_with_options(
                "orders",
                &[],
                IndexBackfillOptions {
                    row_batch_size: 2,
                    start_from_primary_key: Some(resume_cursor),
                },
            )
            .await
            .expect("resume backfill should succeed");
        assert_eq!(report.scanned_rows, 6);

        let guard = state.kv.lock().expect("kv mutex poisoned");
        let base_rows = guard
            .keys()
            .filter(|key| matches_primary_key(0, key))
            .count();
        let index_rows = guard
            .keys()
            .filter(|key| matches_secondary_index_key(0, 1, key))
            .count();
        assert_eq!(base_rows, 8);
        assert_eq!(
            index_rows, 8,
            "resume should backfill each row exactly once"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn concurrent_writes_during_backfill_preserve_index_correctness() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let seed_schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("seed schema");
        let mut seed_writer = seed_schema.batch_writer();
        for i in 0..40i64 {
            seed_writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(i),
                        CellValue::Utf8(if i % 2 == 0 { "open" } else { "closed" }.to_string()),
                        CellValue::Int64(i * 10),
                    ],
                )
                .expect("seed row");
        }
        seed_writer.flush().await.expect("seed flush");

        let backfill_schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("backfill schema");

        let task_schema = KvSchema::new(client.clone())
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("task schema");
        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
        let handle = tokio::spawn(async move {
            task_schema
                .backfill_added_indexes_with_options_and_progress(
                    "orders",
                    &[],
                    IndexBackfillOptions {
                        row_batch_size: 5,
                        start_from_primary_key: None,
                    },
                    Some(&progress_tx),
                )
                .await
        });

        while let Some(event) = progress_rx.recv().await {
            if matches!(event, IndexBackfillEvent::Progress { .. }) {
                break;
            }
        }

        let mut concurrent_writer = backfill_schema.batch_writer();
        for id in [100i64, 101i64] {
            concurrent_writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8("open".to_string()),
                        CellValue::Int64(id * 10),
                    ],
                )
                .expect("concurrent row");
        }
        concurrent_writer.flush().await.expect("concurrent flush");

        let report = handle
            .await
            .expect("backfill task join")
            .expect("backfill result");
        assert!(
            report.scanned_rows >= 40,
            "backfill should at least scan the original historical rows"
        );

        let guard = state.kv.lock().expect("kv mutex poisoned");
        let base_rows = guard
            .keys()
            .filter(|key| matches_primary_key(0, key))
            .count();
        let index_rows = guard
            .keys()
            .filter(|key| matches_secondary_index_key(0, 1, key))
            .count();
        assert_eq!(base_rows, 42);
        assert_eq!(
            index_rows, 42,
            "historical backfill plus concurrent indexed writes should leave one index row per base row"
        );

        let _ = shutdown_tx.send(());
    }

    #[derive(Clone)]
    struct DeferredChunkRangeHarness {
        first_chunk_sent: Arc<Notify>,
        release_second_chunk: Arc<Notify>,
        first_frame: ProtoRangeFrame,
        second_frame: ProtoRangeFrame,
    }

    impl QueryService for DeferredChunkRangeHarness {
        async fn get(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_proto::store::query::v1::GetRequestView<'static>,
            >,
        ) -> Result<(ProtoGetResponse, Context), ConnectError> {
            Err(ConnectError::unimplemented("test harness"))
        }

        async fn range(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_proto::store::query::v1::RangeRequestView<'static>,
            >,
        ) -> Result<
            (
                Pin<Box<dyn Stream<Item = Result<ProtoRangeFrame, ConnectError>> + Send>>,
                Context,
            ),
            ConnectError,
        > {
            let first_chunk_sent = self.first_chunk_sent.clone();
            let release_second_chunk = self.release_second_chunk.clone();
            let first_frame = self.first_frame.clone();
            let second_frame = self.second_frame.clone();
            let stream = stream::try_unfold(0u8, move |state| {
                let first_chunk_sent = first_chunk_sent.clone();
                let release_second_chunk = release_second_chunk.clone();
                let first_frame = first_frame.clone();
                let second_frame = second_frame.clone();
                async move {
                    match state {
                        0 => {
                            first_chunk_sent.notify_one();
                            Ok(Some((first_frame, 1)))
                        }
                        1 => {
                            release_second_chunk.notified().await;
                            Ok(Some((second_frame, 2)))
                        }
                        _ => Ok(None),
                    }
                }
            });
            Ok((Box::pin(stream), query_detail_trailer_ctx(7)))
        }

        async fn reduce(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_proto::store::query::v1::ReduceRequestView<'static>,
            >,
        ) -> Result<(ProtoReduceResponse, Context), ConnectError> {
            Err(ConnectError::unimplemented("test harness"))
        }
    }

    #[derive(Clone)]
    struct ObservedLimitRangeHarness {
        release_second_chunk: Arc<Notify>,
        observed_limit: Arc<AtomicUsize>,
        first_frame: ProtoRangeFrame,
        second_frame: ProtoRangeFrame,
    }

    impl QueryService for ObservedLimitRangeHarness {
        async fn get(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_proto::store::query::v1::GetRequestView<'static>,
            >,
        ) -> Result<(ProtoGetResponse, Context), ConnectError> {
            Err(ConnectError::unimplemented("test harness"))
        }

        async fn range(
            &self,
            _ctx: Context,
            request: buffa::view::OwnedView<
                exoware_proto::store::query::v1::RangeRequestView<'static>,
            >,
        ) -> Result<
            (
                Pin<Box<dyn Stream<Item = Result<ProtoRangeFrame, ConnectError>> + Send>>,
                Context,
            ),
            ConnectError,
        > {
            let limit = request.limit.map(|v| v as usize).unwrap_or(usize::MAX);
            self.observed_limit.store(limit, AtomicOrdering::SeqCst);
            let release_second_chunk = self.release_second_chunk.clone();
            let first_frame = self.first_frame.clone();
            let second_frame = self.second_frame.clone();
            let stream = stream::try_unfold(0u8, move |state| {
                let release_second_chunk = release_second_chunk.clone();
                let first_frame = first_frame.clone();
                let second_frame = second_frame.clone();
                async move {
                    match state {
                        0 => Ok(Some((first_frame, 1))),
                        1 => {
                            if limit > 1 {
                                release_second_chunk.notified().await;
                                Ok(Some((second_frame, 2)))
                            } else {
                                Ok(None)
                            }
                        }
                        2 => Ok(None),
                        _ => Ok(None),
                    }
                }
            });
            Ok((Box::pin(stream), query_detail_trailer_ctx(7)))
        }

        async fn reduce(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_proto::store::query::v1::ReduceRequestView<'static>,
            >,
        ) -> Result<(ProtoReduceResponse, Context), ConnectError> {
            Err(ConnectError::unimplemented("test harness"))
        }
    }

    #[derive(Clone)]
    struct ObservedLimitIndexRangeHarness {
        observed_limit: Arc<AtomicUsize>,
        entries_frame: ProtoRangeFrame,
    }

    impl QueryService for ObservedLimitIndexRangeHarness {
        async fn get(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_proto::store::query::v1::GetRequestView<'static>,
            >,
        ) -> Result<(ProtoGetResponse, Context), ConnectError> {
            Err(ConnectError::unimplemented("test harness"))
        }

        async fn range(
            &self,
            _ctx: Context,
            request: buffa::view::OwnedView<
                exoware_proto::store::query::v1::RangeRequestView<'static>,
            >,
        ) -> Result<
            (
                Pin<Box<dyn Stream<Item = Result<ProtoRangeFrame, ConnectError>> + Send>>,
                Context,
            ),
            ConnectError,
        > {
            let limit = request
                .limit
                .map(|v| {
                    if v == u32::MAX {
                        usize::MAX
                    } else {
                        v as usize
                    }
                })
                .unwrap_or(usize::MAX);
            self.observed_limit.store(limit, AtomicOrdering::SeqCst);
            let entries_frame = self.entries_frame.clone();
            Ok((
                Box::pin(stream::iter(vec![Ok(entries_frame)])),
                query_detail_trailer_ctx(7),
            ))
        }

        async fn reduce(
            &self,
            _ctx: Context,
            _request: buffa::view::OwnedView<
                exoware_proto::store::query::v1::ReduceRequestView<'static>,
            >,
        ) -> Result<(ProtoReduceResponse, Context), ConnectError> {
            Err(ConnectError::unimplemented("test harness"))
        }
    }

    #[tokio::test]
    async fn kv_scan_streaming_range_reads_emit_first_batch_before_full_range_completes() {
        let model = Arc::new(simple_int64_model(0));
        let first_chunk_sent = Arc::new(Notify::new());
        let release_second_chunk = Arc::new(Notify::new());

        let encoded_row = rkyv::to_bytes::<rkyv::rancor::Error>(&StoredRow { values: vec![None] })
            .expect("stored row bytes")
            .to_vec();

        let first_results = {
            let mut results = Vec::with_capacity(BATCH_FLUSH_ROWS);
            for id in 0..BATCH_FLUSH_ROWS {
                let key =
                    encode_primary_key(model.table_prefix, &[&CellValue::Int64(id as i64)], &model)
                        .expect("primary key");
                results.push((key, encoded_row.clone()));
            }
            results
        };
        let first_frame = proto_range_entries_frame(first_results);

        let second_results = {
            let key = encode_primary_key(
                model.table_prefix,
                &[&CellValue::Int64(BATCH_FLUSH_ROWS as i64)],
                &model,
            )
            .expect("primary key");
            vec![(key, encoded_row)]
        };
        let second_frame = proto_range_entries_frame(second_results);

        let harness = DeferredChunkRangeHarness {
            first_chunk_sent: first_chunk_sent.clone(),
            release_second_chunk: release_second_chunk.clone(),
            first_frame,
            second_frame,
        };
        let connect = ConnectRpcService::new(QueryServiceServer::new(harness))
            .with_compression(connect_compression_registry());
        let app = Router::new().fallback_service(connect);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let url = format!("http://{}", listener.local_addr().expect("listener addr"));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });

        let client = StoreClient::new(&url);
        let scan = KvScanExec::new(
            client,
            model.clone(),
            Arc::new(Vec::new()),
            QueryPredicate::default(),
            None,
            model.schema.clone(),
            None,
        );

        let session_ctx = SessionContext::new();
        let mut stream = scan
            .execute(0, session_ctx.task_ctx())
            .expect("scan execute should start");

        tokio::time::timeout(Duration::from_secs(1), first_chunk_sent.notified())
            .await
            .expect("server should send first range frame");
        let first_batch = tokio::time::timeout(Duration::from_millis(200), stream.try_next())
            .await
            .expect("first record batch should arrive before the second stream chunk is released")
            .expect("stream poll should succeed")
            .expect("expected first record batch");
        assert_eq!(first_batch.num_rows(), BATCH_FLUSH_ROWS);

        release_second_chunk.notify_one();

        let second_batch = stream
            .try_next()
            .await
            .expect("second poll should succeed")
            .expect("expected second record batch");
        assert_eq!(second_batch.num_rows(), 1);
        assert!(
            stream
                .try_next()
                .await
                .expect("stream completion poll")
                .is_none(),
            "stream should finish after the second batch"
        );
    }

    #[tokio::test]
    async fn kv_scan_sql_limit_is_pushed_upstream_on_exact_streaming_scan() {
        let release_second_chunk = Arc::new(Notify::new());
        let observed_limit = Arc::new(AtomicUsize::new(0));
        let model = simple_int64_model(0);

        let encoded_row = rkyv::to_bytes::<rkyv::rancor::Error>(&StoredRow { values: vec![None] })
            .expect("stored row bytes")
            .to_vec();

        let first_key = encode_primary_key(model.table_prefix, &[&CellValue::Int64(1)], &model)
            .expect("first primary key");
        let second_key = encode_primary_key(model.table_prefix, &[&CellValue::Int64(2)], &model)
            .expect("second primary key");

        let first_frame = proto_range_entries_frame(vec![(first_key, encoded_row.clone())]);
        let second_frame = proto_range_entries_frame(vec![(second_key, encoded_row)]);

        let harness = ObservedLimitRangeHarness {
            release_second_chunk: release_second_chunk.clone(),
            observed_limit: observed_limit.clone(),
            first_frame,
            second_frame,
        };
        let connect = ConnectRpcService::new(QueryServiceServer::new(harness))
            .with_compression(connect_compression_registry());
        let app = Router::new().fallback_service(connect);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let url = format!("http://{}", listener.local_addr().expect("listener addr"));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });

        let client = StoreClient::new(&url);
        let schema = KvSchema::new(client)
            .table(
                "items",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let batches = tokio::time::timeout(Duration::from_millis(200), async {
            ctx.sql("SELECT id FROM items LIMIT 1")
                .await
                .expect("query")
                .collect()
                .await
                .expect("collect")
        })
        .await
        .expect("query with LIMIT 1 should finish without waiting for a delayed second chunk");

        assert_eq!(
            batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
            1
        );
        assert_eq!(
            observed_limit.load(AtomicOrdering::SeqCst),
            1,
            "exact streaming scan should push SQL LIMIT upstream"
        );
        release_second_chunk.notify_one();
    }

    #[tokio::test]
    async fn kv_scan_index_limit_does_not_push_upstream_when_seen_dedup_can_drop_entries() {
        let observed_limit = Arc::new(AtomicUsize::new(0));
        let config = KvTableConfig::new(
            0,
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                .expect("valid")
                .with_cover_columns(vec!["status".to_string(), "amount_cents".to_string()])],
        )
        .expect("config");
        let model = TableModel::from_config(&config).expect("model");
        let spec = model
            .resolve_index_specs(&config.index_specs)
            .expect("specs")
            .into_iter()
            .next()
            .expect("status index spec");
        let stale_row = KvRow {
            values: vec![
                CellValue::Int64(7),
                CellValue::Utf8("closed".to_string()),
                CellValue::Int64(10),
            ],
        };
        let current_row = KvRow {
            values: vec![
                CellValue::Int64(7),
                CellValue::Utf8("open".to_string()),
                CellValue::Int64(10),
            ],
        };
        let unique_row = KvRow {
            values: vec![
                CellValue::Int64(8),
                CellValue::Utf8("open".to_string()),
                CellValue::Int64(20),
            ],
        };
        let stale_key = encode_secondary_index_key(model.table_prefix, &spec, &model, &stale_row)
            .expect("stale index key");
        let current_key =
            encode_secondary_index_key(model.table_prefix, &spec, &model, &current_row)
                .expect("current index key");
        let unique_key = encode_secondary_index_key(model.table_prefix, &spec, &model, &unique_row)
            .expect("unique index key");
        let stale_payload =
            encode_secondary_index_value(&stale_row, &model, &spec).expect("stale payload");
        let current_payload =
            encode_secondary_index_value(&current_row, &model, &spec).expect("current payload");
        let unique_payload =
            encode_secondary_index_value(&unique_row, &model, &spec).expect("unique payload");

        let entries_frame = proto_range_entries_frame(vec![
            (stale_key, stale_payload),
            (current_key, current_payload),
            (unique_key, unique_payload),
        ]);
        let harness = ObservedLimitIndexRangeHarness {
            observed_limit: observed_limit.clone(),
            entries_frame,
        };
        let connect = ConnectRpcService::new(QueryServiceServer::new(harness))
            .with_compression(connect_compression_registry());
        let app = Router::new().fallback_service(connect);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let url = format!("http://{}", listener.local_addr().expect("listener addr"));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });

        let client = StoreClient::new(&url);
        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["status".to_string(), "amount_cents".to_string()])],
            )
            .expect("schema");
        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let batches = ctx
            .sql(
                "SELECT id, amount_cents \
                 FROM orders \
                 WHERE status IN ('open', 'closed') \
                 LIMIT 2",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(
            batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
            2
        );
        assert_eq!(
            observed_limit.load(AtomicOrdering::SeqCst),
            usize::MAX,
            "index streaming scans should not push SQL LIMIT upstream while seen-dedup can drop duplicate primary keys"
        );
    }

    #[tokio::test]
    async fn zorder_covering_index_scan_filters_false_positive_morton_span_rows() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "points",
                vec![
                    TableColumnConfig::new("x", DataType::Int64, false),
                    TableColumnConfig::new("y", DataType::Int64, false),
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("value", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![
                    IndexSpec::z_order("xy_z", vec!["x".to_string(), "y".to_string()])
                        .expect("valid")
                        .with_cover_columns(vec!["value".to_string()]),
                ],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (x, y, id, value) in [
            (0, 2, 2, 20),
            (1, 1, 11, 110),
            (1, 2, 12, 120),
            (2, 1, 21, 210),
            (2, 2, 22, 220),
            (3, 0, 30, 300),
        ] {
            writer
                .insert(
                    "points",
                    vec![
                        CellValue::Int64(x),
                        CellValue::Int64(y),
                        CellValue::Int64(id),
                        CellValue::Int64(value),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        let batches = ctx
            .sql(
                "SELECT id, value FROM points \
                 WHERE x >= 1 AND x <= 2 AND y >= 1 AND y <= 2 \
                 ORDER BY id",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        let mut rows = Vec::new();
        for batch in &batches {
            let ids = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("id int64");
            let values = batch
                .column(1)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("value int64");
            for row_idx in 0..batch.num_rows() {
                rows.push((ids.value(row_idx), values.value(row_idx)));
            }
        }
        assert_eq!(rows, vec![(11, 110), (12, 120), (21, 210), (22, 220)]);

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_uses_range_reduce_for_supported_global_aggregates() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, status, amount) in [
            (1, "open", 10),
            (2, "closed", 15),
            (3, "open", 30),
            (4, "closed", 40),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let df = ctx
            .sql(
                "SELECT COUNT(*) AS row_count, SUM(amount_cents) AS total_cents, \
                 AVG(amount_cents) AS avg_cents \
                 FROM orders WHERE status = 'open'",
            )
            .await
            .expect("query");
        let batches = df.collect().await.expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        let row_count = ScalarValue::try_from_array(batch.column(0), 0).expect("row_count scalar");
        let total = batch
            .column(1)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("sum int64")
            .value(0);
        let avg = batch
            .column(2)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("avg float64")
            .value(0);
        assert!(matches!(
            row_count,
            ScalarValue::UInt64(Some(2)) | ScalarValue::Int64(Some(2))
        ));
        assert_eq!(total, 40);
        assert_eq!(avg, 20.0);
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "supported aggregate should use range reduction path"
        );

        let _ = shutdown_tx.send(());
    }

    /// Store `/v1/range` is inclusive on both ends; `id <= N` and `BETWEEN` must include the end key.
    #[tokio::test]
    async fn primary_key_inclusive_upper_bound_streaming_scan_uses_range() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "inc_pk",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("amount", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for id in 1i64..=5i64 {
            writer
                .insert(
                    "inc_pk",
                    vec![CellValue::Int64(id), CellValue::Int64(id * 100)],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql("SELECT id FROM inc_pk WHERE id <= 3 ORDER BY id")
            .await
            .expect("lte query")
            .collect()
            .await
            .expect("collect");
        let mut ids = Vec::new();
        for batch in &batches {
            let col = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("id");
            for i in 0..batch.num_rows() {
                ids.push(col.value(i));
            }
        }
        assert_eq!(ids, vec![1, 2, 3], "id <= 3 must include id 3");
        assert!(
            state.range_calls.load(AtomicOrdering::SeqCst) >= 1,
            "PK bounded scan should call range"
        );
        assert_eq!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst),
            0,
            "streaming scan must not use range_reduce"
        );

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql("SELECT id FROM inc_pk WHERE id BETWEEN 2 AND 4 ORDER BY id")
            .await
            .expect("between query")
            .collect()
            .await
            .expect("collect");
        ids.clear();
        for batch in &batches {
            let col = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("id");
            for i in 0..batch.num_rows() {
                ids.push(col.value(i));
            }
        }
        assert_eq!(ids, vec![2, 3, 4], "BETWEEN must include both endpoints");
        assert!(state.range_calls.load(AtomicOrdering::SeqCst) >= 1);
        assert_eq!(state.range_reduce_calls.load(AtomicOrdering::SeqCst), 0);

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn primary_key_inclusive_upper_bound_scalar_aggregates_use_range_reduce() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "inc_pk",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("amount", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for id in 1i64..=5i64 {
            writer
                .insert(
                    "inc_pk",
                    vec![CellValue::Int64(id), CellValue::Int64(id * 100)],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT COUNT(*) AS c, SUM(amount) AS s FROM inc_pk WHERE id <= 3",
            )
            .await
            .expect("lte agg")
            .collect()
            .await
            .expect("collect");
        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        let c = ScalarValue::try_from_array(batch.column(0), 0).expect("count");
        assert!(
            matches!(c, ScalarValue::UInt64(Some(3)) | ScalarValue::Int64(Some(3))),
            "count should include id=3"
        );
        assert_eq!(
            batch
                .column(1)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("sum")
                .value(0),
            100 + 200 + 300
        );
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "scalar aggregate on PK range should use range_reduce"
        );

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql("SELECT SUM(amount) AS s FROM inc_pk WHERE id BETWEEN 2 AND 4")
            .await
            .expect("between agg")
            .collect()
            .await
            .expect("collect");
        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(
            batch
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("sum")
                .value(0),
            200 + 300 + 400
        );
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "BETWEEN aggregate should use range_reduce"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_uses_zorder_index_with_worker_filter() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "points",
                vec![
                    TableColumnConfig::new("x", DataType::Int64, false),
                    TableColumnConfig::new("y", DataType::Int64, false),
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("value", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![
                    IndexSpec::z_order("xy_z", vec!["x".to_string(), "y".to_string()])
                        .expect("valid")
                        .with_cover_columns(vec!["value".to_string()]),
                ],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (x, y, id, value) in [
            (0, 2, 2, 20),
            (1, 1, 11, 110),
            (1, 2, 12, 120),
            (2, 1, 21, 210),
            (2, 2, 22, 220),
            (3, 0, 30, 300),
        ] {
            writer
                .insert(
                    "points",
                    vec![
                        CellValue::Int64(x),
                        CellValue::Int64(y),
                        CellValue::Int64(id),
                        CellValue::Int64(value),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT COUNT(*) AS row_count, SUM(value) AS total_value \
                 FROM points \
                 WHERE x >= 1 AND x <= 2 AND y >= 1 AND y <= 2",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        let row_count = ScalarValue::try_from_array(batch.column(0), 0).expect("row_count scalar");
        let total = batch
            .column(1)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("sum int64")
            .value(0);
        assert!(matches!(
            row_count,
            ScalarValue::UInt64(Some(4)) | ScalarValue::Int64(Some(4))
        ));
        assert_eq!(total, 660);
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "z-order aggregate should use range reduction path"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_avg_merges_sum_and_count_across_multiple_ranges() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, status, amount) in [
            (1, "open", 10),
            (2, "open", 20),
            (3, "closed", 100),
            (4, "pending", 1_000),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT AVG(amount_cents) AS avg_cents \
                 FROM orders \
                 WHERE status IN ('open', 'closed')",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        let avg = batch
            .column(0)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("avg float64")
            .value(0);
        let expected = 130.0 / 3.0;
        assert!(
            (avg - expected).abs() < 1e-12,
            "AVG should merge SUM+COUNT across unequal-count ranges: got {avg}, expected {expected}"
        );
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst),
            2,
            "status IN (...) should expand to two pushed reduction ranges"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_filtered_global_aggregates() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, status, amount) in [
            (1, "open", 10),
            (2, "closed", 15),
            (3, "open", 30),
            (4, "closed", 40),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let query = "SELECT COUNT(*) FILTER (WHERE status = 'open') AS open_count, \
                            COUNT(*) FILTER (WHERE status = 'closed') AS closed_count, \
                            AVG(amount_cents) FILTER (WHERE status = 'closed') AS closed_avg \
                     FROM orders";
        let batches = ctx
            .sql(query)
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_count_scalar(batch, 0, 0, 2);
        assert_count_scalar(batch, 1, 0, 2);
        let closed_avg = batch
            .column(2)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("avg float64")
            .value(0);
        assert_eq!(closed_avg, 27.5);
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 3,
            "filtered aggregate pushdown should use dedicated reduction jobs"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_case_filtered_global_aggregates() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, status, amount) in [
            (1, "open", 10),
            (2, "closed", 15),
            (3, "open", 30),
            (4, "closed", 40),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let query = "SELECT SUM(CASE status WHEN 'open' THEN amount_cents END) AS open_total, \
                            COUNT(CASE status WHEN 'closed' THEN 1 END) AS closed_count, \
                            AVG(CASE WHEN status = 'closed' THEN amount_cents END) AS closed_avg \
                     FROM orders";
        let batches = ctx
            .sql(query)
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(40))
        );
        assert_count_scalar(batch, 1, 0, 2);
        let closed_avg = batch
            .column(2)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("avg float64")
            .value(0);
        assert_eq!(closed_avg, 27.5);
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 3,
            "case-based conditional aggregates should use reduction jobs"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_casted_group_and_aggregate_expressions() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, status, amount) in [
            (1, "open", 10),
            (2, "open", 30),
            (3, "closed", 15),
            (4, "closed", 40),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT CAST(status AS VARCHAR) AS status_text, \
                        SUM(CAST(amount_cents AS DOUBLE)) AS total_cents \
                 FROM orders \
                 GROUP BY CAST(status AS VARCHAR) \
                 ORDER BY status_text",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 2);
        let batch = &batches[0];
        let status = ScalarValue::try_from_array(batch.column(0), 0).expect("status scalar");
        assert_eq!(scalar_to_string(&status).as_deref(), Some("closed"));
        let closed_total = batch
            .column(1)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("sum float64")
            .value(0);
        let open_total = batch
            .column(1)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("sum float64")
            .value(1);
        assert_eq!(closed_total, 55.0);
        assert_eq!(open_total, 40.0);
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "casted grouped aggregates should stay on the reduction path"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_computed_aggregate_inputs() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("price_cents", DataType::Int64, false),
                    TableColumnConfig::new("qty", DataType::Int64, false),
                    TableColumnConfig::new("duration_ms", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, price, qty, duration_ms) in [(1, 10, 2, 500), (2, 15, 3, 2500), (3, 7, 4, 1000)] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Int64(price),
                        CellValue::Int64(qty),
                        CellValue::Int64(duration_ms),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT SUM(price_cents * qty) AS total_revenue, \
                        AVG(duration_ms / 1e3) AS avg_seconds \
                 FROM orders",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(93))
        );
        let avg_seconds = batch
            .column(1)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("avg float64")
            .value(0);
        assert!((avg_seconds - (4.0 / 3.0)).abs() < 1e-12);
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 2,
            "computed aggregate inputs should use reduction jobs"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_add_and_subtract_inputs() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("price_cents", DataType::Int64, false),
                    TableColumnConfig::new("fee_cents", DataType::Int64, false),
                    TableColumnConfig::new("discount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, price, fee, discount) in [(1, 10, 2, 1), (2, 15, 3, 4), (3, 7, 1, 2)] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Int64(price),
                        CellValue::Int64(fee),
                        CellValue::Int64(discount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT SUM(price_cents + fee_cents) AS gross_plus_fee, \
                        SUM(price_cents - discount_cents) AS net_total \
                 FROM orders",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(38))
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(1), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(25))
        );
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 2,
            "add/sub aggregate inputs should use reduction jobs"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_case_filtered_computed_aggregates() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("price_cents", DataType::Int64, false),
                    TableColumnConfig::new("qty", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["price_cents".to_string(), "qty".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, status, price, qty) in [
            (1, "open", 10, 2),
            (2, "closed", 99, 1),
            (3, "open", 15, 3),
            (4, "closed", 7, 4),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(price),
                        CellValue::Int64(qty),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT SUM(CASE WHEN status = 'open' THEN price_cents * qty END) \
                 AS open_revenue \
                 FROM orders",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(65))
        );
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "case-filtered computed aggregate should use reduction jobs"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_does_not_rewrite_sum_case_else_zero_semantics() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("region", DataType::Utf8, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["region".to_string(), "amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, region, status, amount) in [
            (1, "east", "open", 10),
            (2, "east", "closed", 20),
            (3, "west", "closed", 30),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(region.to_string()),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT region, \
                        SUM(CASE WHEN status = 'open' THEN amount_cents ELSE 0 END) AS open_total \
                 FROM orders \
                 GROUP BY region \
                 ORDER BY region",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 2);
        let batch = &batches[0];
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0).expect("region scalar"),
            ScalarValue::Utf8(Some("east".to_string()))
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(1), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(10))
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 1).expect("region scalar"),
            ScalarValue::Utf8(Some("west".to_string()))
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(1), 1).expect("sum scalar"),
            ScalarValue::Int64(Some(0))
        );
        assert_eq!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst),
            0,
            "SUM(CASE ... ELSE 0 END) must not push down because FILTER rewrite changes semantics"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_computed_group_keys() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "events",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("country", DataType::Utf8, false),
                    TableColumnConfig::new(
                        "occurred_at",
                        DataType::Timestamp(TimeUnit::Microsecond, None),
                        false,
                    ),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");

        let day_micros = 86_400_000_000i64;
        let day0 = 1_700_000_000_000_000i64;
        let day1 = day0 + day_micros;
        let day0_bucket = day0.div_euclid(day_micros) * day_micros;
        let day1_bucket = day1.div_euclid(day_micros) * day_micros;
        let mut writer = schema.batch_writer();
        for (id, country, occurred_at, amount) in [
            (1, "East", day0 + 111, 10),
            (2, "east", day0 + 222, 30),
            (3, "West", day1 + 333, 7),
        ] {
            writer
                .insert(
                    "events",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(country.to_string()),
                        CellValue::Timestamp(occurred_at),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT lower(country) AS country_norm, \
                        date_trunc('day', occurred_at) AS day_bucket, \
                        SUM(amount_cents) AS total_cents \
                 FROM events \
                 GROUP BY lower(country), date_trunc('day', occurred_at) \
                 ORDER BY country_norm, day_bucket",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 2);
        let batch = &batches[0];
        assert_eq!(
            scalar_to_string(
                &ScalarValue::try_from_array(batch.column(0), 0).expect("country scalar")
            )
            .as_deref(),
            Some("east")
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(1), 0).expect("day scalar"),
            ScalarValue::TimestampMicrosecond(Some(day0_bucket), None)
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(2), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(40))
        );
        assert_eq!(
            scalar_to_string(
                &ScalarValue::try_from_array(batch.column(0), 1).expect("country scalar")
            )
            .as_deref(),
            Some("west")
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(1), 1).expect("day scalar"),
            ScalarValue::TimestampMicrosecond(Some(day1_bucket), None)
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(2), 1).expect("sum scalar"),
            ScalarValue::Int64(Some(7))
        );
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "computed group keys should use grouped reduction path"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_group_by_queries() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, status, amount) in [
            (1, "open", 10),
            (2, "open", 30),
            (3, "closed", 15),
            (4, "closed", 40),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT status, COUNT(*) AS row_count, SUM(amount_cents) AS total_cents \
                 FROM orders GROUP BY status ORDER BY status",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 2);
        let batch = &batches[0];
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0).expect("status scalar"),
            ScalarValue::Utf8(Some("closed".to_string()))
        );
        assert_count_scalar(batch, 1, 0, 2);
        assert_eq!(
            ScalarValue::try_from_array(batch.column(2), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(55))
        );
        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 1).expect("status scalar"),
            ScalarValue::Utf8(Some("open".to_string()))
        );
        assert_count_scalar(batch, 1, 1, 2);
        assert_eq!(
            ScalarValue::try_from_array(batch.column(2), 1).expect("sum scalar"),
            ScalarValue::Int64(Some(40))
        );
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 2,
            "group-by aggregate should use grouped range reduction path"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_group_by_float_canonicalizes_signed_zero() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "metrics",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("score", DataType::Float64, false),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, score) in [(1, -0.0), (2, 0.0), (3, 1.5)] {
            writer
                .insert(
                    "metrics",
                    vec![CellValue::Int64(id), CellValue::Float64(score)],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT score, COUNT(*) AS row_count \
                 FROM metrics GROUP BY score ORDER BY row_count DESC, score",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 2);
        let batch = &batches[0];
        let top_score = batch
            .column(0)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("score float64")
            .value(0);
        assert_eq!(top_score.to_bits(), 0.0f64.to_bits());
        assert_count_scalar(batch, 1, 0, 2);
        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 1,
            "float group-by aggregate should stay on grouped reduction path"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn aggregate_pushdown_supports_filtered_group_by_queries() {
        let state = MockState {
            kv: Arc::new(Mutex::new(BTreeMap::new())),
            range_calls: Arc::new(AtomicUsize::new(0)),
            range_reduce_calls: Arc::new(AtomicUsize::new(0)),
            sequence_number: Arc::new(AtomicU64::new(0)),
        };
        let (base_url, shutdown_tx) = spawn_mock_server(state.clone()).await;
        let client = StoreClient::new(&base_url);

        let schema = KvSchema::new(client)
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("region", DataType::Utf8, false),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount_cents", DataType::Int64, false),
                ],
                vec!["id".to_string()],
                vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                    .expect("valid")
                    .with_cover_columns(vec!["region".to_string(), "amount_cents".to_string()])],
            )
            .expect("schema");

        let mut writer = schema.batch_writer();
        for (id, region, status, amount) in [
            (1, "east", "open", 10),
            (2, "east", "closed", 20),
            (3, "west", "open", 30),
            (4, "north", "closed", 40),
        ] {
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(id),
                        CellValue::Utf8(region.to_string()),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(amount),
                    ],
                )
                .expect("row");
        }
        writer.flush().await.expect("flush");

        let ctx = SessionContext::new();
        schema.register_all(&ctx).expect("register");

        state.range_calls.store(0, AtomicOrdering::SeqCst);
        state.range_reduce_calls.store(0, AtomicOrdering::SeqCst);

        let batches = ctx
            .sql(
                "SELECT region, \
                        COUNT(*) FILTER (WHERE status = 'open') AS open_count, \
                        SUM(amount_cents) FILTER (WHERE status = 'closed') AS closed_total \
                 FROM orders \
                 GROUP BY region \
                 ORDER BY region",
            )
            .await
            .expect("query")
            .collect()
            .await
            .expect("collect");

        assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 3);
        let batch = &batches[0];

        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 0).expect("region scalar"),
            ScalarValue::Utf8(Some("east".to_string()))
        );
        assert_count_scalar(batch, 1, 0, 1);
        assert_eq!(
            ScalarValue::try_from_array(batch.column(2), 0).expect("sum scalar"),
            ScalarValue::Int64(Some(20))
        );

        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 1).expect("region scalar"),
            ScalarValue::Utf8(Some("north".to_string()))
        );
        assert_count_scalar(batch, 1, 1, 0);
        assert_eq!(
            ScalarValue::try_from_array(batch.column(2), 1).expect("sum scalar"),
            ScalarValue::Int64(Some(40))
        );

        assert_eq!(
            ScalarValue::try_from_array(batch.column(0), 2).expect("region scalar"),
            ScalarValue::Utf8(Some("west".to_string()))
        );
        assert_count_scalar(batch, 1, 2, 1);
        assert_eq!(
            ScalarValue::try_from_array(batch.column(2), 2).expect("sum scalar"),
            ScalarValue::Int64(None)
        );

        assert_eq!(state.range_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(
            state.range_reduce_calls.load(AtomicOrdering::SeqCst) >= 3,
            "filtered group-by aggregate should use grouped reduction plus seed job"
        );

        let _ = shutdown_tx.send(());
    }

    mod e2e {
        use super::*;
        use axum::{routing::get, Router};
        use datafusion::prelude::SessionContext;
        use exoware_sdk_rs::StoreClient;
        use exoware_server::{connect_stack, AppState};
        use exoware_simulator::RocksStore;
        use tempfile::tempdir;

        struct TestServers {
            ingest_url: String,
            query_url: String,
        }

        impl TestServers {
            fn client(&self) -> StoreClient {
                StoreClient::with_split_urls(&self.query_url, &self.ingest_url, &self.query_url)
            }
        }

        async fn spawn_e2e_servers() -> TestServers {
            let dir = tempdir().expect("tempdir");
            let db = RocksStore::open(dir.path()).expect("db");
            let state = AppState::new(std::sync::Arc::new(db));
            let connect = connect_stack(state);
            let app = Router::new()
                .route("/health", get(|| async { "ok" }))
                .fallback_service(connect);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let url = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move {
                axum::serve(listener, app).await.expect("serve");
            });
            for _ in 0..200 {
                if reqwest::get(format!("{url}/health"))
                    .await
                    .ok()
                    .is_some_and(|r| r.status().is_success())
                {
                    return TestServers {
                        ingest_url: url.clone(),
                        query_url: url,
                    };
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            panic!("e2e simulator did not become ready");
        }

        #[tokio::test]
        async fn sql_insert_and_select_through_real_ingest_query_workers() {
            let servers = spawn_e2e_servers().await;
            let client = servers.client();

            let schema = KvSchema::new(client)
                .table(
                    "orders",
                    vec![
                        TableColumnConfig::new("id", DataType::Int64, false),
                        TableColumnConfig::new("status", DataType::Utf8, false),
                        TableColumnConfig::new("amount_cents", DataType::Int64, false),
                    ],
                    vec!["id".to_string()],
                    vec![IndexSpec::new("status_idx", vec!["status".to_string()])
                        .expect("valid")
                        .with_cover_columns(vec!["amount_cents".to_string()])],
                )
                .expect("schema");

            let mut writer = schema.batch_writer();
            for (id, status, amount) in [
                (1i64, "open", 100i64),
                (2, "closed", 200),
                (3, "open", 300),
                (4, "closed", 400),
                (5, "open", 500),
            ] {
                writer
                    .insert(
                        "orders",
                        vec![
                            CellValue::Int64(id),
                            CellValue::Utf8(status.to_string()),
                            CellValue::Int64(amount),
                        ],
                    )
                    .expect("insert row");
            }
            writer.flush().await.expect("flush batch");

            let ctx = SessionContext::new();
            schema.register_all(&ctx).expect("register tables");

            let batches = ctx
                .sql("SELECT id, amount_cents FROM orders ORDER BY id")
                .await
                .expect("full scan query")
                .collect()
                .await
                .expect("collect full scan");
            let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
            assert_eq!(total_rows, 5, "all 5 rows returned from full scan");

            let mut ids = Vec::new();
            let mut amounts = Vec::new();
            for batch in &batches {
                let id_col = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .expect("id column");
                let amt_col = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .expect("amount column");
                for i in 0..batch.num_rows() {
                    ids.push(id_col.value(i));
                    amounts.push(amt_col.value(i));
                }
            }
            assert_eq!(ids, vec![1, 2, 3, 4, 5]);
            assert_eq!(amounts, vec![100, 200, 300, 400, 500]);

            let filtered = ctx
                .sql(
                    "SELECT id, amount_cents FROM orders \
                     WHERE status = 'open' ORDER BY id",
                )
                .await
                .expect("filtered query")
                .collect()
                .await
                .expect("collect filtered");
            let mut filtered_ids = Vec::new();
            let mut filtered_amounts = Vec::new();
            for batch in &filtered {
                let id_col = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .expect("id column");
                let amt_col = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .expect("amount column");
                for i in 0..batch.num_rows() {
                    filtered_ids.push(id_col.value(i));
                    filtered_amounts.push(amt_col.value(i));
                }
            }
            assert_eq!(filtered_ids, vec![1, 3, 5]);
            assert_eq!(filtered_amounts, vec![100, 300, 500]);

            let agg = ctx
                .sql(
                    "SELECT COUNT(*) AS cnt, SUM(amount_cents) AS total \
                     FROM orders WHERE status = 'open'",
                )
                .await
                .expect("aggregate query")
                .collect()
                .await
                .expect("collect aggregate");
            assert_eq!(agg.len(), 1);
            let batch = &agg[0];
            assert_eq!(batch.num_rows(), 1);
            assert_count_scalar(batch, 0, 0, 3);
            let total = ScalarValue::try_from_array(batch.column(1), 0).expect("sum scalar");
            match total {
                ScalarValue::Int64(Some(v)) => assert_eq!(v, 900),
                other => panic!("unexpected sum type: {other:?}"),
            }
        }
    }
}
