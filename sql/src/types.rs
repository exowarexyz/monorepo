use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use datafusion::arrow::datatypes::{i256, DataType, Field, Schema, SchemaRef, TimeUnit};
use exoware_sdk_rs::keys::{Key, KeyCodec};
use exoware_sdk_rs::StoreClient;

use crate::codec::{primary_key_codec, secondary_index_codec};

pub(crate) const TABLE_PREFIX_BITS: u8 = 4;
pub(crate) const KEY_KIND_BITS: u8 = 1;
pub(crate) const PRIMARY_RESERVED_BITS: u8 = TABLE_PREFIX_BITS + KEY_KIND_BITS;
pub(crate) const INDEX_SLOT_BITS: u8 = 4;
pub(crate) const INDEX_FAMILY_BITS: u8 = TABLE_PREFIX_BITS + KEY_KIND_BITS + INDEX_SLOT_BITS;
pub(crate) const PRIMARY_KEY_BIT_OFFSET: usize = PRIMARY_RESERVED_BITS as usize;
pub(crate) const INDEX_KEY_BIT_OFFSET: usize = INDEX_FAMILY_BITS as usize;
pub(crate) const MAX_TABLES: usize = 1usize << TABLE_PREFIX_BITS;
pub(crate) const MAX_INDEX_SPECS: usize = (1usize << INDEX_SLOT_BITS) - 1;
pub(crate) const STRING_KEY_INLINE_LIMIT: usize = 15;
pub(crate) const STRING_KEY_TERMINATOR: u8 = 0x00;
pub(crate) const STRING_KEY_ESCAPE_PREFIX: u8 = 0x01;
pub(crate) const STRING_KEY_ESCAPE_FF: u8 = 0x02;
pub(crate) const PAGE_SIZE: usize = 1_000;
pub(crate) const BATCH_FLUSH_ROWS: usize = 2_048;
pub(crate) const INDEX_BACKFILL_FLUSH_ENTRIES: usize = 4_096;

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
pub(crate) enum ListElementKind {
    Int64,
    Float64,
    Boolean,
    Utf8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ColumnKind {
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

    pub(crate) fn fixed_key_width(self) -> Option<usize> {
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

    pub(crate) fn key_width(self) -> usize {
        self.fixed_key_width()
            .unwrap_or(STRING_KEY_INLINE_LIMIT + 1)
    }

    pub(crate) fn indexable(self) -> bool {
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
pub(crate) struct KvTableConfig {
    pub(crate) table_prefix: u8,
    pub(crate) columns: Vec<TableColumnConfig>,
    pub(crate) primary_key_columns: Vec<String>,
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

#[derive(Debug, Clone)]
pub(crate) struct ResolvedColumn {
    pub(crate) name: String,
    pub(crate) kind: ColumnKind,
    pub(crate) nullable: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedIndexSpec {
    pub(crate) id: u8,
    pub(crate) codec: KeyCodec,
    pub(crate) name: String,
    pub(crate) layout: IndexLayout,
    pub(crate) key_columns: Vec<usize>,
    pub(crate) value_column_mask: Vec<bool>,
    pub(crate) key_columns_width: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct TableModel {
    pub(crate) table_prefix: u8,
    pub(crate) primary_key_codec: KeyCodec,
    pub(crate) schema: SchemaRef,
    pub(crate) columns: Vec<ResolvedColumn>,
    pub(crate) columns_by_name: HashMap<String, usize>,
    pub(crate) primary_key_indices: Vec<usize>,
    pub(crate) primary_key_kinds: Vec<ColumnKind>,
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

    pub(crate) fn column(&self, index: usize) -> &ResolvedColumn {
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
pub(crate) struct KvRow {
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

#[derive(Debug, Clone, Default)]
pub(crate) struct DecodedIndexEntry {
    pub(crate) primary_key: Key,
    pub(crate) primary_key_values: Vec<CellValue>,
    pub(crate) values: HashMap<usize, CellValue>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct KeyRange {
    pub(crate) start: Key,
    pub(crate) end: Key,
}

#[derive(Debug, Clone)]
pub(crate) struct IndexPlan {
    pub(crate) spec_idx: usize,
    pub(crate) ranges: Vec<KeyRange>,
    pub(crate) constrained_prefix_len: usize,
    pub(crate) constrained_column_count: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct KvTable {
    pub(crate) client: StoreClient,
    pub(crate) model: Arc<TableModel>,
    pub(crate) index_specs: Arc<Vec<ResolvedIndexSpec>>,
}

impl KvTable {
    pub(crate) fn new(client: StoreClient, config: KvTableConfig) -> Result<Self, String> {
        let model = Arc::new(TableModel::from_config(&config)?);
        let index_specs = Arc::new(model.resolve_index_specs(&config.index_specs)?);
        Ok(Self {
            client,
            model,
            index_specs,
        })
    }
}
