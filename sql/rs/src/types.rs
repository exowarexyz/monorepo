use crate::codec::{primary_key_prefix, secondary_index_prefix};
use datafusion::arrow::datatypes::{i256, DataType, Field, Schema, SchemaRef, TimeUnit};
use exoware_sdk::{
    keys::{Key, Prefix},
    PrefixedStoreClient,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

/// Every table/index family is named by a single packed byte
/// `(table_prefix << 4) | discriminator`: the high nibble is the table prefix
/// and the low nibble is the family discriminator. Discriminator `0x0` is the
/// primary-row family and `0x1..=0xF` names secondary index slot
/// `discriminator - 1`. All families of table `t` occupy the contiguous byte
/// range `[t << 4, (t << 4) | 0xF]`; these ranges are pairwise disjoint within
/// and across tables, and the primary discriminator (`0`) sorts below every
/// index family of the same table.
pub(crate) const FAMILY_PREFIX_LEN: usize = 1;
/// Discriminator nibble for a table's primary-row family.
pub(crate) const PRIMARY_FAMILY_DISCRIMINATOR: u8 = 0x00;
/// Byte offset of the first payload byte within a primary/index key, measured
/// from the store-stripped key (i.e. after the family prefix). Both families
/// share the same one-byte prefix, so both offsets are `FAMILY_PREFIX_LEN`.
pub(crate) const PRIMARY_KEY_BYTE_OFFSET: usize = FAMILY_PREFIX_LEN;
pub(crate) const INDEX_KEY_BYTE_OFFSET: usize = FAMILY_PREFIX_LEN;
/// Capacity caps for the packed one-byte family prefix. The table prefix
/// occupies the high nibble and the discriminator the low nibble, giving up to
/// 16 tables and 15 secondary index slots (discriminator `0x0` is reserved for
/// the primary family).
pub(crate) const MAX_TABLES: usize = 16;
pub(crate) const MAX_INDEX_SPECS: usize = 15;
pub(crate) const STRING_KEY_INLINE_LIMIT: usize = 15;
pub(crate) const STRING_KEY_TERMINATOR: u8 = 0x00;
pub(crate) const STRING_KEY_ESCAPE_PREFIX: u8 = 0x01;
pub(crate) const STRING_KEY_ESCAPE_FF: u8 = 0x02;
pub(crate) const PAGE_SIZE: usize = 1_000;
pub(crate) const BATCH_FLUSH_ROWS: usize = 2_048;
pub(crate) const INDEX_BACKFILL_FLUSH_ENTRIES: usize = 4_096;

/// Row and index-entry counts for one completed backfill invocation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IndexBackfillReport {
    /// Primary rows decoded during this invocation, excluding rows before its start cursor.
    pub scanned_rows: u64,
    /// Newly appended index specifications populated by this invocation.
    pub indexes_backfilled: usize,
    /// Secondary entries submitted for ingestion across all newly appended indexes.
    pub index_entries_written: u64,
}

/// Streaming and resume settings for a secondary-index backfill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexBackfillOptions {
    /// Requested maximum rows per response batch. Backfill rejects zero.
    pub row_batch_size: usize,
    /// Inclusive encoded primary-key cursor, including the table family byte and
    /// excluding the client's namespace prefix. `None` starts at the family lower bound.
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

/// Backfill progress with cursors in the client's namespace-relative key space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexBackfillEvent {
    /// Emitted after options and index evolution have been validated.
    Started {
        /// Registered name of the table being scanned.
        table_name: String,
        /// Number of newly appended indexes to populate, possibly zero.
        indexes_backfilled: usize,
        /// Requested maximum rows per streaming response batch.
        row_batch_size: usize,
        /// Inclusive first scan key, including the primary-row family byte.
        start_cursor: Key,
    },
    /// Emitted after entries for a response batch have been flushed to ingestion.
    Progress {
        /// Cumulative primary rows decoded during this invocation.
        scanned_rows: u64,
        /// Cumulative secondary entries submitted for ingestion during this invocation.
        index_entries_written: u64,
        /// Encoded primary key of the final row in this response batch.
        last_scanned_primary_key: Key,
        /// Inclusive resume key after the last scanned key. `None` means no successor
        /// remains within the table's primary-key range.
        next_cursor: Option<Key>,
    },
    /// Emitted when the invocation finishes successfully, including a no-op backfill.
    Completed {
        /// Counts for this invocation.
        report: IndexBackfillReport,
    },
}

/// Scalar element representations supported in stored lists. Elements cannot be null.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListElementKind {
    /// Signed 64-bit integers.
    Int64,
    /// Double-precision floating-point values.
    Float64,
    /// Boolean values.
    Boolean,
    /// UTF-8 strings.
    Utf8,
}

/// Storage representation of a column, independent of Arrow metadata such as decimal scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ColumnKind {
    /// Signed 64-bit integer.
    Int64,
    /// Unsigned 64-bit integer.
    UInt64,
    /// Double-precision floating-point value.
    Float64,
    /// Boolean value.
    Boolean,
    /// UTF-8 string, including Arrow's large and view string types.
    Utf8,
    /// Days since the Unix epoch.
    Date32,
    /// Milliseconds since the Unix epoch.
    Date64,
    /// Microseconds since the Unix epoch. Timezone metadata remains in the schema.
    Timestamp,
    /// Signed 128-bit unscaled decimal integer.
    Decimal128,
    /// Signed 256-bit unscaled decimal integer.
    Decimal256,
    /// Binary value with the declared width in bytes.
    FixedSizeBinary(usize),
    /// Variable-length bytes, supported as values but not index keys.
    Binary,
    /// List of the specified scalar kind, supported as values but not index keys.
    List(ListElementKind),
}

impl ColumnKind {
    pub(crate) fn from_data_type(data_type: &DataType) -> Result<Self, String> {
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
            DataType::Binary | DataType::LargeBinary | DataType::BinaryView => Ok(Self::Binary),
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
                 Decimal128, Decimal256, FixedSizeBinary, Binary, List"
            )),
        }
    }

    pub(crate) const fn fixed_key_width(self) -> Option<usize> {
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
            Self::Binary => None,
            Self::List(_) => None,
        }
    }

    pub(crate) fn key_width(self) -> usize {
        self.fixed_key_width()
            .unwrap_or(STRING_KEY_INLINE_LIMIT + 1)
    }

    pub(crate) const fn indexable(self) -> bool {
        !matches!(self, Self::List(_) | Self::Binary)
    }
}

/// Declared column schema. Table construction validates names and supported storage types.
#[derive(Debug, Clone)]
pub struct TableColumnConfig {
    /// Column name used for schema lookup and primary-key or index references.
    pub name: String,
    /// Arrow type. The table schema normalizes timestamps to microseconds and
    /// large lists to lists while preserving their element field.
    pub data_type: DataType,
    /// Whether row values may be null. Index-key columns must be non-nullable,
    /// and primary-key encoding requires a non-null value even if this is true.
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

/// Encoding of secondary-index key columns before the appended primary key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexLayout {
    /// Concatenate ordered column encodings in the declared key-column order.
    Lexicographic,
    /// Interleave bits of ordered column encodings. Index resolution requires
    /// each key column to have a fixed encoded width.
    ZOrder,
}

/// Named secondary-index definition, resolved against the table when it is built.
#[derive(Debug, Clone)]
pub struct IndexSpec {
    /// Nonempty index name, unique within the table after resolution.
    name: String,
    /// Nonempty ordered column names that determine the index key before its primary-key suffix.
    key_columns: Vec<String>,
    /// Additional non-primary-key columns stored in the index value. An empty
    /// list adds no coverage beyond the non-primary-key index-key columns.
    cover_columns: Vec<String>,
    /// Encoding used for the key columns, independent of the primary-key suffix.
    layout: IndexLayout,
}

impl IndexSpec {
    #[cfg(test)]
    pub(crate) fn new(name: impl Into<String>, key_columns: Vec<String>) -> Result<Self, String> {
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

    pub const fn with_layout(mut self, layout: IndexLayout) -> Self {
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

    pub const fn layout(&self) -> &IndexLayout {
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

/// Table declaration after column and primary-key validation, before index resolution.
#[derive(Debug, Clone)]
pub(crate) struct KvTableConfig {
    /// Table identifier in the high nibble of every family byte, in `0..16`.
    pub(crate) table_prefix: u8,
    /// Nonempty column declarations in schema and row-value order, with unique names.
    pub(crate) columns: Vec<TableColumnConfig>,
    /// Nonempty column names in composite primary-key encoding order.
    pub(crate) primary_key_columns: Vec<String>,
    /// Index declarations in family-discriminator order. Empty disables secondary indexes.
    pub(crate) index_specs: Vec<IndexSpec>,
}

impl KvTableConfig {
    pub(crate) fn new(
        table_prefix: u8,
        columns: Vec<TableColumnConfig>,
        primary_key_columns: Vec<String>,
        index_specs: Vec<IndexSpec>,
    ) -> Result<Self, String> {
        if usize::from(table_prefix) >= MAX_TABLES {
            return Err(format!(
                "table prefix {table_prefix} exceeds max {} for key layout",
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
        if total_pk_width > primary_key_prefix(table_prefix)?.max_payload_len() {
            return Err(format!(
                "composite primary key is too wide ({total_pk_width} bytes) for key payload"
            ));
        }

        Ok(Self {
            table_prefix,
            columns,
            primary_key_columns,
            index_specs,
        })
    }

    pub(crate) fn to_schema(&self) -> SchemaRef {
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

/// Column metadata used by row encoders and decoders.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedColumn {
    /// Column name from the table declaration.
    pub(crate) name: String,
    /// Storage representation corresponding to the declared Arrow type.
    pub(crate) kind: ColumnKind,
    /// Whether the column permits SQL null values.
    pub(crate) nullable: bool,
}

/// Secondary-index layout resolved to positions in the table's column vector.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedIndexSpec {
    /// One-based index position, in `1..=15`, used as the family discriminator.
    pub(crate) id: u8,
    /// Packed table and index family byte, excluding the client's namespace prefix.
    pub(crate) prefix: Prefix,
    /// Unique name used to identify the index within its table.
    pub(crate) name: String,
    /// Encoding of key columns before the primary-key suffix.
    pub(crate) layout: IndexLayout,
    /// Table-column positions in index-key order. Resolution rejects nullable
    /// columns and kinds that cannot be indexed.
    pub(crate) key_columns: Vec<usize>,
    /// Mask in table-column order selecting non-primary-key values stored in the
    /// index payload, including index-key columns and requested cover columns.
    pub(crate) value_column_mask: Vec<bool>,
    /// Sum of reserved key widths in bytes, excluding the family byte and primary key.
    /// This is the encoded length when all key columns have fixed-width kinds.
    pub(crate) key_columns_width: usize,
}

/// Shared schema and key layout for encoding, planning, and reading a table.
#[derive(Debug, Clone)]
pub(crate) struct TableModel {
    /// Table identifier in the high nibble of its family bytes.
    pub(crate) table_prefix: u8,
    /// Primary-row family byte, excluding the client's namespace prefix.
    pub(crate) primary_key_prefix: Prefix,
    /// Arrow schema in table-column order, with normalized timestamp and list types.
    pub(crate) schema: SchemaRef,
    /// Storage metadata in schema and row-value order.
    pub(crate) columns: Vec<ResolvedColumn>,
    /// Column-name lookup yielding zero-based positions in `columns`.
    pub(crate) columns_by_name: HashMap<String, usize>,
    /// Table-column positions in composite primary-key order, not schema order.
    pub(crate) primary_key_indices: Vec<usize>,
    /// Storage kinds in the same order as `primary_key_indices`.
    pub(crate) primary_key_kinds: Vec<ColumnKind>,
    /// Sum of reserved primary-key component widths in bytes, excluding the family byte.
    /// Variable-length string encodings can differ from this reservation.
    pub(crate) primary_key_width: usize,
}

impl TableModel {
    pub(crate) fn from_config(config: &KvTableConfig) -> Result<Self, String> {
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
            primary_key_prefix: primary_key_prefix(config.table_prefix)?,
            schema,
            columns,
            columns_by_name,
            primary_key_indices,
            primary_key_kinds,
            primary_key_width,
        })
    }

    /// Whether a column index is part of the primary key.
    pub(crate) fn is_pk_column(&self, col_idx: usize) -> bool {
        self.primary_key_indices.contains(&col_idx)
    }

    pub(crate) fn pk_position(&self, col_idx: usize) -> Option<usize> {
        self.primary_key_indices
            .iter()
            .position(|&idx| idx == col_idx)
    }

    pub(crate) fn resolve_index_specs(
        &self,
        specs: &[IndexSpec],
    ) -> Result<Vec<ResolvedIndexSpec>, String> {
        let mut out = Vec::with_capacity(specs.len());
        let mut names = HashSet::new();

        for (idx, spec) in specs.iter().enumerate() {
            if !names.insert(spec.name.clone()) {
                return Err(format!("duplicate index name '{}'", spec.name));
            }

            let id = u8::try_from(idx + 1).map_err(|_| {
                format!("too many index specs for key layout (max {MAX_INDEX_SPECS})")
            })?;
            if usize::from(id) > MAX_INDEX_SPECS {
                return Err(format!(
                    "too many index specs for key layout (max {MAX_INDEX_SPECS})"
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
                // Z-order stored keys interleave the actual encoded bytes, but
                // decode and bound construction assume the reserved fixed key
                // width, so a variable-width z-order key column silently
                // matches no rows.
                if spec.layout == IndexLayout::ZOrder
                    && self.columns[col_idx].kind.fixed_key_width().is_none()
                {
                    return Err(format!(
                        "index '{}' z-order key column '{}' must have a \
                         fixed-width kind; variable-width kinds (e.g. Utf8) \
                         cannot be used in z-order index keys",
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
            let prefix = secondary_index_prefix(self.table_prefix, id)?;
            if key_columns_width + self.primary_key_width > prefix.max_payload_len() {
                return Err(format!(
                    "index '{}' key layout too wide for key payload",
                    spec.name
                ));
            }

            out.push(ResolvedIndexSpec {
                id,
                prefix,
                name: spec.name.clone(),
                layout: spec.layout,
                key_columns,
                value_column_mask,
                key_columns_width,
            });
        }

        Ok(out)
    }

    pub(crate) fn column(&self, index: usize) -> &ResolvedColumn {
        &self.columns[index]
    }
}

/// Owned logical cell value. Column metadata supplies nullability, decimal scale,
/// timezone, and fixed binary width when the value is encoded or decoded.
#[derive(Debug, Clone)]
pub enum CellValue {
    /// SQL null, also used as a placeholder for an unselected decoded key component.
    Null,
    /// Signed 64-bit integer.
    Int64(i64),
    /// Unsigned 64-bit integer.
    UInt64(u64),
    /// Double-precision floating-point value.
    Float64(f64),
    /// Boolean value.
    Boolean(bool),
    /// Days since the Unix epoch.
    Date32(i32),
    /// Milliseconds since the Unix epoch.
    Date64(i64),
    /// Microseconds since the Unix epoch.
    Timestamp(i64),
    /// Unscaled decimal integer with precision and scale from the schema.
    Decimal128(i128),
    /// Unscaled decimal integer with precision and scale from the schema.
    Decimal256(i256),
    /// UTF-8 string.
    Utf8(String),
    /// Bytes whose length must match the column's declared fixed width when encoded.
    FixedBinary(Vec<u8>),
    /// Variable-length bytes.
    Binary(Vec<u8>),
    /// Ordered elements. Storage requires non-null elements of the column's scalar list kind.
    List(Vec<Self>),
}

/// Owned row values used by the table's encoders and predicate evaluation.
#[derive(Debug, Clone)]
pub(crate) struct KvRow {
    /// One cell per table column in schema order, including primary-key columns.
    pub(crate) values: Vec<CellValue>,
}

impl KvRow {
    pub(crate) fn primary_key_values(&self, model: &TableModel) -> Vec<&CellValue> {
        model
            .primary_key_indices
            .iter()
            .map(|&idx| &self.values[idx])
            .collect()
    }

    pub(crate) fn value_at(&self, idx: usize) -> &CellValue {
        &self.values[idx]
    }
}

/// Selected column values and primary-row locator decoded from a secondary-index key.
#[derive(Debug, Clone, Default)]
pub(crate) struct DecodedIndexEntry {
    /// Encoded primary-row key with its family byte, excluding the client's namespace prefix.
    pub(crate) primary_key: Key,
    /// Cells in primary-key order. Empty when none were requested, otherwise
    /// unselected positions contain `CellValue::Null` placeholders.
    pub(crate) primary_key_values: Vec<CellValue>,
    /// Selected index-key cells keyed by table-column position, excluding unselected columns.
    pub(crate) values: HashMap<usize, CellValue>,
}

/// Inclusive bounds in encoded key order, including the family byte and excluding
/// the client's namespace prefix. `start > end` represents an empty range.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct KeyRange {
    /// Inclusive lower encoded key.
    pub(crate) start: Key,
    /// Inclusive upper encoded key.
    pub(crate) end: Key,
}

/// Chosen secondary-index scan and the constraint counts used to rank it.
#[derive(Debug, Clone)]
pub(crate) struct IndexPlan {
    /// Zero-based position in the table's resolved index specifications.
    pub(crate) spec_idx: usize,
    /// Inclusive ranges sorted by start key with overlaps merged, so a scan
    /// visits each stored entry at most once.
    pub(crate) ranges: Vec<KeyRange>,
    /// Leading constrained key-column count for lexicographic bounds. For
    /// z-order, the count of constrained dimensions, including non-leading ones.
    pub(crate) constrained_prefix_len: usize,
    /// Ranking score in columns. Lexicographic scoring counts leading point
    /// constraints and at most one following non-point constraint. Z-order scoring
    /// counts all dimensions with supported constraints.
    pub(crate) constrained_column_count: usize,
}

/// DataFusion table provider sharing a resolved schema and its storage namespace.
#[derive(Debug, Clone)]
pub(crate) struct KvTable {
    /// Client whose namespace contains this table's primary rows and index entries.
    pub(crate) client: PrefixedStoreClient,
    /// Shared schema and primary-key layout used by scans and writes.
    pub(crate) model: Arc<TableModel>,
    /// Shared index layouts in family-discriminator order. Empty means no secondary indexes.
    pub(crate) index_specs: Arc<Vec<ResolvedIndexSpec>>,
}

impl KvTable {
    pub(crate) fn new(client: PrefixedStoreClient, config: KvTableConfig) -> Result<Self, String> {
        let model = Arc::new(TableModel::from_config(&config)?);
        let index_specs = Arc::new(model.resolve_index_specs(&config.index_specs)?);
        Ok(Self {
            client,
            model,
            index_specs,
        })
    }
}
