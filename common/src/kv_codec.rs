use std::cmp::Ordering;

use crate::keys::{read_bit_be, read_bits_to_bytes, write_bit_be, Key};

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub enum KvFieldKind {
    Int64,
    UInt64,
    Float64,
    Boolean,
    Utf8,
    Date32,
    Date64,
    Timestamp,
    Decimal128,
    FixedSizeBinary(u8),
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub enum KvFieldRef {
    Key {
        bit_offset: u16,
        kind: KvFieldKind,
    },
    ZOrderKey {
        bit_offset: u16,
        field_position: u8,
        field_widths: Vec<u8>,
        kind: KvFieldKind,
    },
    Value {
        index: u16,
        kind: KvFieldKind,
        nullable: bool,
    },
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
#[rkyv(serialize_bounds(
    __S: rkyv::ser::Writer + rkyv::ser::Allocator,
    __S::Error: rkyv::rancor::Source,
))]
#[rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source))]
#[rkyv(bytecheck(bounds(__C: rkyv::validation::ArchiveContext)))]
pub enum KvExpr {
    Field(KvFieldRef),
    Literal(KvReducedValue),
    Add(
        #[rkyv(omit_bounds)] Box<KvExpr>,
        #[rkyv(omit_bounds)] Box<KvExpr>,
    ),
    Sub(
        #[rkyv(omit_bounds)] Box<KvExpr>,
        #[rkyv(omit_bounds)] Box<KvExpr>,
    ),
    Mul(
        #[rkyv(omit_bounds)] Box<KvExpr>,
        #[rkyv(omit_bounds)] Box<KvExpr>,
    ),
    Div(
        #[rkyv(omit_bounds)] Box<KvExpr>,
        #[rkyv(omit_bounds)] Box<KvExpr>,
    ),
    Lower(#[rkyv(omit_bounds)] Box<KvExpr>),
    DateTruncDay(#[rkyv(omit_bounds)] Box<KvExpr>),
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub enum KvPredicateConstraint {
    StringEq(String),
    BoolEq(bool),
    FixedSizeBinaryEq(Vec<u8>),
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
    IsNull,
    IsNotNull,
    StringIn(Vec<String>),
    IntIn(Vec<i64>),
    UInt64In(Vec<u64>),
    FixedSizeBinaryIn(Vec<Vec<u8>>),
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct KvPredicateCheck {
    pub field: KvFieldRef,
    pub constraint: KvPredicateConstraint,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct KvPredicate {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<KvPredicateCheck>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub contradiction: bool,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub enum KvReducedValue {
    Int64(i64),
    UInt64(u64),
    Float64(f64),
    Boolean(bool),
    Utf8(String),
    Date32(i32),
    Date64(i64),
    Timestamp(i64),
    Decimal128(i128),
    FixedSizeBinary(Vec<u8>),
}

impl From<&ArchivedKvReducedValue> for KvReducedValue {
    fn from(value: &ArchivedKvReducedValue) -> Self {
        match value {
            ArchivedKvReducedValue::Int64(v) => Self::Int64((*v).into()),
            ArchivedKvReducedValue::UInt64(v) => Self::UInt64((*v).into()),
            ArchivedKvReducedValue::Float64(v) => Self::Float64((*v).into()),
            ArchivedKvReducedValue::Boolean(v) => Self::Boolean(*v),
            ArchivedKvReducedValue::Utf8(v) => Self::Utf8(v.as_str().to_string()),
            ArchivedKvReducedValue::Date32(v) => Self::Date32((*v).into()),
            ArchivedKvReducedValue::Date64(v) => Self::Date64((*v).into()),
            ArchivedKvReducedValue::Timestamp(v) => Self::Timestamp((*v).into()),
            ArchivedKvReducedValue::Decimal128(v) => Self::Decimal128((*v).into()),
            ArchivedKvReducedValue::FixedSizeBinary(v) => {
                Self::FixedSizeBinary(v.as_slice().to_vec())
            }
        }
    }
}

impl KvReducedValue {
    pub fn checked_add_assign(&mut self, rhs: &Self) -> Result<(), String> {
        match (self, rhs) {
            (Self::Int64(lhs), Self::Int64(rhs)) => {
                *lhs = lhs
                    .checked_add(*rhs)
                    .ok_or_else(|| "Int64 sum overflow".to_string())?;
                Ok(())
            }
            (Self::UInt64(lhs), Self::UInt64(rhs)) => {
                *lhs = lhs
                    .checked_add(*rhs)
                    .ok_or_else(|| "UInt64 sum overflow".to_string())?;
                Ok(())
            }
            (Self::Float64(lhs), Self::Float64(rhs)) => {
                *lhs += *rhs;
                Ok(())
            }
            (Self::Decimal128(lhs), Self::Decimal128(rhs)) => {
                *lhs = lhs
                    .checked_add(*rhs)
                    .ok_or_else(|| "Decimal128 sum overflow".to_string())?;
                Ok(())
            }
            _ => Err("sum type mismatch".to_string()),
        }
    }

    pub fn partial_cmp_same_kind(&self, rhs: &Self) -> Option<Ordering> {
        match (self, rhs) {
            (Self::Int64(lhs), Self::Int64(rhs)) => Some(lhs.cmp(rhs)),
            (Self::UInt64(lhs), Self::UInt64(rhs)) => Some(lhs.cmp(rhs)),
            (Self::Float64(lhs), Self::Float64(rhs)) => Some(lhs.total_cmp(rhs)),
            (Self::Boolean(lhs), Self::Boolean(rhs)) => Some(lhs.cmp(rhs)),
            (Self::Utf8(lhs), Self::Utf8(rhs)) => Some(lhs.cmp(rhs)),
            (Self::Date32(lhs), Self::Date32(rhs)) => Some(lhs.cmp(rhs)),
            (Self::Date64(lhs), Self::Date64(rhs)) => Some(lhs.cmp(rhs)),
            (Self::Timestamp(lhs), Self::Timestamp(rhs)) => Some(lhs.cmp(rhs)),
            (Self::Decimal128(lhs), Self::Decimal128(rhs)) => Some(lhs.cmp(rhs)),
            (Self::FixedSizeBinary(lhs), Self::FixedSizeBinary(rhs)) => Some(lhs.cmp(rhs)),
            _ => None,
        }
    }
}

fn canonicalize_group_float(value: f64) -> f64 {
    if value.is_nan() {
        f64::NAN
    } else if value == 0.0 {
        0.0
    } else {
        value
    }
}

pub fn canonicalize_reduced_group_values(values: &mut [Option<KvReducedValue>]) {
    for value in values {
        if let Some(KvReducedValue::Float64(v)) = value {
            *v = canonicalize_group_float(*v);
        }
    }
}

pub fn encode_reduced_group_key(values: &[Option<KvReducedValue>]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in values {
        match value {
            None => out.push(0),
            Some(KvReducedValue::Int64(v)) => {
                out.push(1);
                out.extend_from_slice(&v.to_be_bytes());
            }
            Some(KvReducedValue::UInt64(v)) => {
                out.push(2);
                out.extend_from_slice(&v.to_be_bytes());
            }
            Some(KvReducedValue::Float64(v)) => {
                out.push(3);
                out.extend_from_slice(&canonicalize_group_float(*v).to_bits().to_be_bytes());
            }
            Some(KvReducedValue::Boolean(v)) => {
                out.push(4);
                out.push(u8::from(*v));
            }
            Some(KvReducedValue::Utf8(v)) => {
                out.push(5);
                let len = u32::try_from(v.len()).unwrap_or(u32::MAX);
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(v.as_bytes());
            }
            Some(KvReducedValue::Date32(v)) => {
                out.push(6);
                out.extend_from_slice(&v.to_be_bytes());
            }
            Some(KvReducedValue::Date64(v)) => {
                out.push(7);
                out.extend_from_slice(&v.to_be_bytes());
            }
            Some(KvReducedValue::Timestamp(v)) => {
                out.push(8);
                out.extend_from_slice(&v.to_be_bytes());
            }
            Some(KvReducedValue::Decimal128(v)) => {
                out.push(9);
                out.extend_from_slice(&v.to_be_bytes());
            }
            Some(KvReducedValue::FixedSizeBinary(v)) => {
                out.push(10);
                let len = u32::try_from(v.len()).unwrap_or(u32::MAX);
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(v);
            }
        }
        out.push(0xFF);
    }
    out
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug))]
#[rkyv(serialize_bounds(
    __S: rkyv::ser::Writer + rkyv::ser::Allocator,
    __S::Error: rkyv::rancor::Source,
))]
#[rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source))]
#[rkyv(bytecheck(bounds(__C: rkyv::validation::ArchiveContext)))]
pub enum StoredValue {
    Int64(i64),
    UInt64(u64),
    Float64(f64),
    Boolean(bool),
    Utf8(String),
    Bytes(Vec<u8>),
    List(#[rkyv(omit_bounds)] Vec<StoredValue>),
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug))]
pub struct StoredRow {
    pub values: Vec<Option<StoredValue>>,
}

pub fn access_stored_row(value: &[u8]) -> Result<&ArchivedStoredRow, rkyv::rancor::Error> {
    rkyv::access::<ArchivedStoredRow, rkyv::rancor::Error>(value)
}

pub fn extract_field(
    key: &Key,
    archived: &ArchivedStoredRow,
    field: &KvFieldRef,
) -> Result<Option<KvReducedValue>, String> {
    match field {
        KvFieldRef::Key { bit_offset, kind } => {
            extract_key_field(key, usize::from(*bit_offset), *kind)
                .map(Some)
                .ok_or_else(|| "invalid key field".to_string())
        }
        KvFieldRef::ZOrderKey {
            bit_offset,
            field_position,
            field_widths,
            kind,
        } => extract_zorder_key_field(
            key,
            usize::from(*bit_offset),
            usize::from(*field_position),
            field_widths,
            *kind,
        )
        .map(Some)
        .ok_or_else(|| "invalid z-order key field".to_string()),
        KvFieldRef::Value {
            index,
            kind,
            nullable,
        } => extract_stored_field(archived, usize::from(*index), *kind, *nullable),
    }
}

pub fn expr_needs_value(expr: &KvExpr) -> bool {
    match expr {
        KvExpr::Field(KvFieldRef::Value { .. }) => true,
        KvExpr::Field(KvFieldRef::Key { .. } | KvFieldRef::ZOrderKey { .. })
        | KvExpr::Literal(_) => false,
        KvExpr::Add(left, right)
        | KvExpr::Sub(left, right)
        | KvExpr::Mul(left, right)
        | KvExpr::Div(left, right) => expr_needs_value(left) || expr_needs_value(right),
        KvExpr::Lower(inner) | KvExpr::DateTruncDay(inner) => expr_needs_value(inner),
    }
}

pub fn eval_expr(
    key: &Key,
    archived: Option<&ArchivedStoredRow>,
    expr: &KvExpr,
) -> Result<Option<KvReducedValue>, String> {
    match expr {
        KvExpr::Field(field) => extract_expr_field(key, archived, field),
        KvExpr::Literal(value) => Ok(Some(value.clone())),
        KvExpr::Add(left, right) => {
            eval_numeric_binary_op(key, archived, left, right, |lhs, rhs| match (lhs, rhs) {
                (KvReducedValue::Int64(lhs), KvReducedValue::Int64(rhs)) => lhs
                    .checked_add(rhs)
                    .map(KvReducedValue::Int64)
                    .ok_or_else(|| "Int64 add overflow".to_string()),
                (KvReducedValue::UInt64(lhs), KvReducedValue::UInt64(rhs)) => lhs
                    .checked_add(rhs)
                    .map(KvReducedValue::UInt64)
                    .ok_or_else(|| "UInt64 add overflow".to_string()),
                (KvReducedValue::Float64(lhs), KvReducedValue::Float64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs + rhs))
                }
                (KvReducedValue::Float64(lhs), KvReducedValue::Int64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs + rhs as f64))
                }
                (KvReducedValue::Int64(lhs), KvReducedValue::Float64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs as f64 + rhs))
                }
                (KvReducedValue::Float64(lhs), KvReducedValue::UInt64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs + rhs as f64))
                }
                (KvReducedValue::UInt64(lhs), KvReducedValue::Float64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs as f64 + rhs))
                }
                _ => Err("unsupported add operand types".to_string()),
            })
        }
        KvExpr::Sub(left, right) => {
            eval_numeric_binary_op(key, archived, left, right, |lhs, rhs| match (lhs, rhs) {
                (KvReducedValue::Int64(lhs), KvReducedValue::Int64(rhs)) => lhs
                    .checked_sub(rhs)
                    .map(KvReducedValue::Int64)
                    .ok_or_else(|| "Int64 subtract overflow".to_string()),
                (KvReducedValue::UInt64(lhs), KvReducedValue::UInt64(rhs)) => lhs
                    .checked_sub(rhs)
                    .map(KvReducedValue::UInt64)
                    .ok_or_else(|| "UInt64 subtract overflow".to_string()),
                (KvReducedValue::Float64(lhs), KvReducedValue::Float64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs - rhs))
                }
                (KvReducedValue::Float64(lhs), KvReducedValue::Int64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs - rhs as f64))
                }
                (KvReducedValue::Int64(lhs), KvReducedValue::Float64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs as f64 - rhs))
                }
                (KvReducedValue::Float64(lhs), KvReducedValue::UInt64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs - rhs as f64))
                }
                (KvReducedValue::UInt64(lhs), KvReducedValue::Float64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs as f64 - rhs))
                }
                _ => Err("unsupported subtract operand types".to_string()),
            })
        }
        KvExpr::Mul(left, right) => {
            eval_numeric_binary_op(key, archived, left, right, |lhs, rhs| match (lhs, rhs) {
                (KvReducedValue::Int64(lhs), KvReducedValue::Int64(rhs)) => lhs
                    .checked_mul(rhs)
                    .map(KvReducedValue::Int64)
                    .ok_or_else(|| "Int64 multiply overflow".to_string()),
                (KvReducedValue::UInt64(lhs), KvReducedValue::UInt64(rhs)) => lhs
                    .checked_mul(rhs)
                    .map(KvReducedValue::UInt64)
                    .ok_or_else(|| "UInt64 multiply overflow".to_string()),
                (KvReducedValue::Float64(lhs), KvReducedValue::Float64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs * rhs))
                }
                (KvReducedValue::Float64(lhs), KvReducedValue::Int64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs * rhs as f64))
                }
                (KvReducedValue::Int64(lhs), KvReducedValue::Float64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs as f64 * rhs))
                }
                (KvReducedValue::Float64(lhs), KvReducedValue::UInt64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs * rhs as f64))
                }
                (KvReducedValue::UInt64(lhs), KvReducedValue::Float64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs as f64 * rhs))
                }
                _ => Err("unsupported multiply operand types".to_string()),
            })
        }
        KvExpr::Div(left, right) => {
            eval_numeric_binary_op(key, archived, left, right, |lhs, rhs| match (lhs, rhs) {
                (_, KvReducedValue::Int64(0)) | (_, KvReducedValue::UInt64(0)) => {
                    Err("division by zero".to_string())
                }
                (_, KvReducedValue::Float64(v)) if v == 0.0 => {
                    Err("division by zero".to_string())
                }
                (KvReducedValue::Int64(lhs), KvReducedValue::Int64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs as f64 / rhs as f64))
                }
                (KvReducedValue::UInt64(lhs), KvReducedValue::UInt64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs as f64 / rhs as f64))
                }
                (KvReducedValue::Float64(lhs), KvReducedValue::Float64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs / rhs))
                }
                (KvReducedValue::Float64(lhs), KvReducedValue::Int64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs / rhs as f64))
                }
                (KvReducedValue::Int64(lhs), KvReducedValue::Float64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs as f64 / rhs))
                }
                (KvReducedValue::Float64(lhs), KvReducedValue::UInt64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs / rhs as f64))
                }
                (KvReducedValue::UInt64(lhs), KvReducedValue::Float64(rhs)) => {
                    Ok(KvReducedValue::Float64(lhs as f64 / rhs))
                }
                _ => Err("unsupported divide operand types".to_string()),
            })
        }
        KvExpr::Lower(inner) => {
            let Some(value) = eval_expr(key, archived, inner)? else {
                return Ok(None);
            };
            match value {
                KvReducedValue::Utf8(value) => Ok(Some(KvReducedValue::Utf8(value.to_lowercase()))),
                _ => Err("lower() requires Utf8 input".to_string()),
            }
        }
        KvExpr::DateTruncDay(inner) => {
            let Some(value) = eval_expr(key, archived, inner)? else {
                return Ok(None);
            };
            const DAY_MILLIS: i64 = 86_400_000;
            const DAY_MICROS: i64 = 86_400_000_000;
            match value {
                KvReducedValue::Date32(days) => Ok(Some(KvReducedValue::Date32(days))),
                KvReducedValue::Date64(millis) => Ok(Some(KvReducedValue::Date64(
                    millis.div_euclid(DAY_MILLIS) * DAY_MILLIS,
                ))),
                KvReducedValue::Timestamp(micros) => Ok(Some(KvReducedValue::Timestamp(
                    micros.div_euclid(DAY_MICROS) * DAY_MICROS,
                ))),
                _ => {
                    Err("date_trunc('day', ...) requires Date32/Date64/Timestamp input".to_string())
                }
            }
        }
    }
}

fn extract_expr_field(
    key: &Key,
    archived: Option<&ArchivedStoredRow>,
    field: &KvFieldRef,
) -> Result<Option<KvReducedValue>, String> {
    match (field, archived) {
        (field, Some(archived)) => extract_field(key, archived, field),
        (KvFieldRef::Key { bit_offset, kind }, None) => {
            extract_key_field(key, usize::from(*bit_offset), *kind)
                .map(Some)
                .ok_or_else(|| "invalid key field".to_string())
        }
        (
            KvFieldRef::ZOrderKey {
                bit_offset,
                field_position,
                field_widths,
                kind,
            },
            None,
        ) => extract_zorder_key_field(
            key,
            usize::from(*bit_offset),
            usize::from(*field_position),
            field_widths,
            *kind,
        )
        .map(Some)
        .ok_or_else(|| "invalid z-order key field".to_string()),
        (KvFieldRef::Value { .. }, None) => Err("value field requires stored row".to_string()),
    }
}

fn eval_numeric_binary_op(
    key: &Key,
    archived: Option<&ArchivedStoredRow>,
    left: &KvExpr,
    right: &KvExpr,
    op: impl FnOnce(KvReducedValue, KvReducedValue) -> Result<KvReducedValue, String> + Copy,
) -> Result<Option<KvReducedValue>, String> {
    let Some(left) = eval_expr(key, archived, left)? else {
        return Ok(None);
    };
    let Some(right) = eval_expr(key, archived, right)? else {
        return Ok(None);
    };
    op(left, right).map(Some)
}

pub fn predicate_needs_value(predicate: &KvPredicate) -> bool {
    predicate
        .checks
        .iter()
        .any(|check| matches!(check.field, KvFieldRef::Value { .. }))
}

pub fn eval_predicate(
    key: &Key,
    archived: Option<&ArchivedStoredRow>,
    predicate: &KvPredicate,
) -> Result<bool, String> {
    if predicate.contradiction {
        return Ok(false);
    }
    for check in &predicate.checks {
        let value = extract_expr_field(key, archived, &check.field)?;
        if !matches_predicate_constraint(value.as_ref(), &check.constraint) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn interleave_ordered_key_fields(fields: &[Vec<u8>]) -> Vec<u8> {
    let total_bits = fields.iter().map(|field| field.len() * 8).sum::<usize>();
    let mut out = vec![0u8; total_bits.div_ceil(8)];
    let max_bits = fields
        .iter()
        .map(|field| field.len() * 8)
        .max()
        .unwrap_or(0);
    let mut out_bit = 0usize;
    for bit_idx in 0..max_bits {
        for field in fields {
            if bit_idx < field.len() * 8 {
                if read_bit_be(field, bit_idx) {
                    write_bit_be(&mut out, out_bit, true);
                }
                out_bit += 1;
            }
        }
    }
    out
}

pub fn deinterleave_ordered_key_fields(
    interleaved: &[u8],
    field_widths: &[u8],
) -> Option<Vec<Vec<u8>>> {
    let total_bits = field_widths
        .iter()
        .map(|width| usize::from(*width) * 8)
        .sum::<usize>();
    if interleaved.len() * 8 != total_bits {
        return None;
    }
    let max_bits = field_widths
        .iter()
        .map(|width| usize::from(*width) * 8)
        .max()
        .unwrap_or(0);
    let mut out = field_widths
        .iter()
        .map(|width| vec![0u8; usize::from(*width)])
        .collect::<Vec<_>>();
    let mut in_bit = 0usize;
    for bit_idx in 0..max_bits {
        for field in &mut out {
            if bit_idx < field.len() * 8 {
                let bit = read_bit_be(interleaved, in_bit);
                write_bit_be(field, bit_idx, bit);
                in_bit += 1;
            }
        }
    }
    Some(out)
}

pub fn extract_key_field(
    key: &Key,
    bit_offset: usize,
    kind: KvFieldKind,
) -> Option<KvReducedValue> {
    let width = key_field_width(kind);
    let bytes = extract_key_bytes(key, bit_offset, width)?;
    decode_ordered_key_field_bytes(&bytes, kind)
}

pub fn extract_zorder_key_field(
    key: &Key,
    bit_offset: usize,
    field_position: usize,
    field_widths: &[u8],
    kind: KvFieldKind,
) -> Option<KvReducedValue> {
    let total_width = field_widths
        .iter()
        .map(|width| usize::from(*width))
        .sum::<usize>();
    let interleaved = extract_key_bytes(key, bit_offset, total_width)?;
    let fields = deinterleave_ordered_key_fields(&interleaved, field_widths)?;
    let bytes = fields.get(field_position)?;
    decode_ordered_key_field_bytes(bytes, kind)
}

fn extract_key_bytes(key: &Key, bit_offset: usize, width: usize) -> Option<Vec<u8>> {
    let end_bit = bit_offset.checked_add(width.checked_mul(8)?)?;
    if end_bit > key.len() * 8 {
        return None;
    }
    if bit_offset.is_multiple_of(8) {
        let byte_offset = bit_offset / 8;
        return Some(key.get(byte_offset..byte_offset + width)?.to_vec());
    }
    let mut out = vec![0u8; width];
    read_bits_to_bytes(key, bit_offset, &mut out, width * 8);
    Some(out)
}

pub fn extract_stored_field(
    archived: &ArchivedStoredRow,
    index: usize,
    kind: KvFieldKind,
    nullable: bool,
) -> Result<Option<KvReducedValue>, String> {
    let stored_opt = archived
        .values
        .get(index)
        .ok_or_else(|| "stored row index out of bounds".to_string())?
        .as_ref();
    let Some(stored) = stored_opt else {
        if nullable {
            return Ok(None);
        }
        return Err("non-nullable field stored as null".to_string());
    };

    let value = match (kind, stored) {
        (KvFieldKind::Int64, ArchivedStoredValue::Int64(v)) => KvReducedValue::Int64((*v).into()),
        (KvFieldKind::UInt64, ArchivedStoredValue::UInt64(v)) => {
            KvReducedValue::UInt64((*v).into())
        }
        (KvFieldKind::Float64, ArchivedStoredValue::Float64(v)) => {
            KvReducedValue::Float64((*v).into())
        }
        (KvFieldKind::Float64, ArchivedStoredValue::Int64(v)) => {
            KvReducedValue::Float64(i64::from(*v) as f64)
        }
        (KvFieldKind::Boolean, ArchivedStoredValue::Boolean(v)) => KvReducedValue::Boolean(*v),
        (KvFieldKind::Utf8, ArchivedStoredValue::Utf8(v)) => {
            KvReducedValue::Utf8(v.as_str().to_string())
        }
        (KvFieldKind::Date32, ArchivedStoredValue::Int64(v)) => {
            KvReducedValue::Date32(i64::from(*v) as i32)
        }
        (KvFieldKind::Date64, ArchivedStoredValue::Int64(v)) => KvReducedValue::Date64((*v).into()),
        (KvFieldKind::Timestamp, ArchivedStoredValue::Int64(v)) => {
            KvReducedValue::Timestamp((*v).into())
        }
        (KvFieldKind::Decimal128, ArchivedStoredValue::Bytes(bytes)) => {
            let raw: [u8; 16] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "invalid Decimal128 byte width".to_string())?;
            KvReducedValue::Decimal128(i128::from_le_bytes(raw))
        }
        (KvFieldKind::FixedSizeBinary(width), ArchivedStoredValue::Bytes(bytes)) => {
            if bytes.as_slice().len() != usize::from(width) {
                return Err("invalid FixedSizeBinary byte width".to_string());
            }
            KvReducedValue::FixedSizeBinary(bytes.as_slice().to_vec())
        }
        _ => return Err("stored field type mismatch".to_string()),
    };
    Ok(Some(value))
}

fn key_field_width(kind: KvFieldKind) -> usize {
    match kind {
        KvFieldKind::Int64
        | KvFieldKind::UInt64
        | KvFieldKind::Float64
        | KvFieldKind::Date64
        | KvFieldKind::Timestamp => 8,
        KvFieldKind::Boolean => 1,
        KvFieldKind::Utf8 => 16,
        KvFieldKind::Date32 => 4,
        KvFieldKind::Decimal128 => 16,
        KvFieldKind::FixedSizeBinary(width) => usize::from(width),
    }
}

fn decode_ordered_key_field_bytes(bytes: &[u8], kind: KvFieldKind) -> Option<KvReducedValue> {
    Some(match kind {
        KvFieldKind::Int64 => {
            let raw = bytes.try_into().ok()?;
            KvReducedValue::Int64(decode_i64_ordered(raw))
        }
        KvFieldKind::UInt64 => {
            let raw = bytes.try_into().ok()?;
            KvReducedValue::UInt64(u64::from_be_bytes(raw))
        }
        KvFieldKind::Float64 => {
            let raw = bytes.try_into().ok()?;
            KvReducedValue::Float64(decode_f64_ordered(raw))
        }
        KvFieldKind::Boolean => KvReducedValue::Boolean(*bytes.first()? != 0),
        KvFieldKind::Utf8 => KvReducedValue::Utf8(decode_fixed_text(bytes)?),
        KvFieldKind::Date32 => {
            let raw = bytes.try_into().ok()?;
            KvReducedValue::Date32(decode_i32_ordered(raw))
        }
        KvFieldKind::Date64 => {
            let raw = bytes.try_into().ok()?;
            KvReducedValue::Date64(decode_i64_ordered(raw))
        }
        KvFieldKind::Timestamp => {
            let raw = bytes.try_into().ok()?;
            KvReducedValue::Timestamp(decode_i64_ordered(raw))
        }
        KvFieldKind::Decimal128 => {
            let raw = bytes.try_into().ok()?;
            KvReducedValue::Decimal128(decode_i128_ordered(raw))
        }
        KvFieldKind::FixedSizeBinary(width) => {
            if bytes.len() != usize::from(width) {
                return None;
            }
            KvReducedValue::FixedSizeBinary(bytes.to_vec())
        }
    })
}

fn matches_predicate_constraint(
    value: Option<&KvReducedValue>,
    constraint: &KvPredicateConstraint,
) -> bool {
    match (value, constraint) {
        (None, KvPredicateConstraint::IsNull) => return true,
        (None, KvPredicateConstraint::IsNotNull) => return false,
        (Some(_), KvPredicateConstraint::IsNull) => return false,
        (Some(_), KvPredicateConstraint::IsNotNull) => return true,
        (None, _) => return false,
        _ => {}
    }
    let value = value.expect("checked above");
    match (value, constraint) {
        (KvReducedValue::Utf8(v), KvPredicateConstraint::StringEq(expected)) => v == expected,
        (KvReducedValue::Boolean(v), KvPredicateConstraint::BoolEq(expected)) => v == expected,
        (KvReducedValue::Int64(v), KvPredicateConstraint::IntRange { min, max }) => {
            in_i64_bounds(*v, *min, *max)
        }
        (KvReducedValue::Date32(v), KvPredicateConstraint::IntRange { min, max }) => {
            in_i64_bounds(*v as i64, *min, *max)
        }
        (KvReducedValue::Date64(v), KvPredicateConstraint::IntRange { min, max }) => {
            in_i64_bounds(*v, *min, *max)
        }
        (KvReducedValue::Timestamp(v), KvPredicateConstraint::IntRange { min, max }) => {
            in_i64_bounds(*v, *min, *max)
        }
        (KvReducedValue::Float64(v), KvPredicateConstraint::FloatRange { min, max }) => {
            in_f64_bounds(*v, min, max)
        }
        (KvReducedValue::Decimal128(v), KvPredicateConstraint::Decimal128Range { min, max }) => {
            in_i128_bounds(*v, *min, *max)
        }
        (KvReducedValue::Utf8(v), KvPredicateConstraint::StringIn(values)) => values.contains(v),
        (KvReducedValue::Int64(v), KvPredicateConstraint::IntIn(values)) => values.contains(v),
        (KvReducedValue::UInt64(v), KvPredicateConstraint::UInt64Range { min, max }) => {
            in_u64_bounds(*v, *min, *max)
        }
        (KvReducedValue::UInt64(v), KvPredicateConstraint::UInt64In(values)) => values.contains(v),
        (
            KvReducedValue::FixedSizeBinary(v),
            KvPredicateConstraint::FixedSizeBinaryEq(expected),
        ) => v == expected,
        (KvReducedValue::FixedSizeBinary(v), KvPredicateConstraint::FixedSizeBinaryIn(values)) => {
            values.contains(v)
        }
        _ => false,
    }
}

fn in_i64_bounds(value: i64, min: Option<i64>, max: Option<i64>) -> bool {
    min.is_none_or(|lower| value >= lower) && max.is_none_or(|upper| value <= upper)
}

fn in_u64_bounds(value: u64, min: Option<u64>, max: Option<u64>) -> bool {
    min.is_none_or(|lower| value >= lower) && max.is_none_or(|upper| value <= upper)
}

fn in_i128_bounds(value: i128, min: Option<i128>, max: Option<i128>) -> bool {
    min.is_none_or(|lower| value >= lower) && max.is_none_or(|upper| value <= upper)
}

fn in_f64_bounds(value: f64, min: &Option<(f64, bool)>, max: &Option<(f64, bool)>) -> bool {
    let lower_ok = match min {
        Some((bound, inclusive)) => {
            if *inclusive {
                value >= *bound
            } else {
                value > *bound
            }
        }
        None => true,
    };
    let upper_ok = match max {
        Some((bound, inclusive)) => {
            if *inclusive {
                value <= *bound
            } else {
                value < *bound
            }
        }
        None => true,
    };
    lower_ok && upper_ok
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn decode_i64_ordered(bytes: [u8; 8]) -> i64 {
    (u64::from_be_bytes(bytes) ^ 0x8000_0000_0000_0000) as i64
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

fn decode_i32_ordered(bytes: [u8; 4]) -> i32 {
    (u32::from_be_bytes(bytes) ^ 0x8000_0000) as i32
}

fn decode_i128_ordered(bytes: [u8; 16]) -> i128 {
    (u128::from_be_bytes(bytes) ^ (1u128 << 127)) as i128
}

fn decode_fixed_text(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end])
        .ok()
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MAX_KEY_LEN;

    #[test]
    fn fixed_utf8_key_round_trip() {
        let mut key = vec![0u8; MAX_KEY_LEN];
        key[4..8].copy_from_slice(b"west");
        let key = Key::from(key);
        let value = extract_key_field(&key, 32, KvFieldKind::Utf8).expect("utf8 field");
        assert_eq!(value, KvReducedValue::Utf8("west".to_string()));
    }

    #[test]
    fn int64_key_round_trip() {
        let mut key = vec![0u8; MAX_KEY_LEN];
        let encoded = ((-42i64 as u64) ^ 0x8000_0000_0000_0000).to_be_bytes();
        key[8..16].copy_from_slice(&encoded);
        let key = Key::from(key);
        let value = extract_key_field(&key, 64, KvFieldKind::Int64).expect("int64 field");
        assert_eq!(value, KvReducedValue::Int64(-42));
    }

    #[test]
    fn stored_decimal128_field_round_trip() {
        let row = StoredRow {
            values: vec![Some(StoredValue::Bytes(123i128.to_le_bytes().to_vec()))],
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&row)
            .expect("row bytes")
            .to_vec();
        let archived = access_stored_row(&bytes).expect("archived row");
        let value = extract_stored_field(archived, 0, KvFieldKind::Decimal128, false)
            .expect("valid field")
            .expect("present field");
        assert_eq!(value, KvReducedValue::Decimal128(123));
    }

    #[test]
    fn non_nullable_missing_field_is_invalid() {
        let row = StoredRow { values: vec![None] };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&row)
            .expect("row bytes")
            .to_vec();
        let archived = access_stored_row(&bytes).expect("archived row");
        let err = extract_stored_field(archived, 0, KvFieldKind::Int64, false)
            .expect_err("missing non-nullable field should fail");
        assert!(err.contains("non-nullable"));
    }

    #[test]
    fn reduced_group_key_canonicalizes_signed_zero_and_nan_payloads() {
        let pos_zero = vec![Some(KvReducedValue::Float64(0.0))];
        let neg_zero = vec![Some(KvReducedValue::Float64(-0.0))];
        assert_eq!(
            encode_reduced_group_key(&pos_zero),
            encode_reduced_group_key(&neg_zero)
        );

        let canonical_nan = vec![Some(KvReducedValue::Float64(f64::NAN))];
        let payload_nan = vec![Some(KvReducedValue::Float64(f64::from_bits(
            0x7ff8_0000_0000_0001,
        )))];
        assert_eq!(
            encode_reduced_group_key(&canonical_nan),
            encode_reduced_group_key(&payload_nan)
        );
    }

    #[test]
    fn float_partial_cmp_same_kind_orders_nan_instead_of_returning_none() {
        let nan = KvReducedValue::Float64(f64::NAN);
        let finite = KvReducedValue::Float64(1.5);

        let ordering = nan
            .partial_cmp_same_kind(&finite)
            .expect("Float64 NaN comparison should stay comparable for MIN/MAX");
        assert_eq!(ordering, f64::NAN.total_cmp(&1.5));
    }

    #[test]
    fn archived_reduced_value_converts_to_owned_for_all_variants() {
        let cases = [
            KvReducedValue::Int64(-42),
            KvReducedValue::UInt64(42),
            KvReducedValue::Float64(-3.25),
            KvReducedValue::Boolean(true),
            KvReducedValue::Utf8("east".to_string()),
            KvReducedValue::Date32(12_345),
            KvReducedValue::Date64(123_456_789),
            KvReducedValue::Timestamp(987_654_321),
            KvReducedValue::Decimal128(-987_654_321_123_456_789),
            KvReducedValue::FixedSizeBinary(vec![0, 1, 2, 3, 4]),
        ];

        for expected in cases {
            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&expected)
                .expect("value bytes")
                .to_vec();
            let archived = rkyv::access::<ArchivedKvReducedValue, rkyv::rancor::Error>(&bytes)
                .expect("archived value");
            assert_eq!(KvReducedValue::from(archived), expected);
        }
    }

    #[test]
    fn eval_expr_multiplies_int64_fields() {
        let key = Key::default();
        let row = StoredRow {
            values: vec![Some(StoredValue::Int64(6)), Some(StoredValue::Int64(7))],
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&row)
            .expect("row bytes")
            .to_vec();
        let archived = access_stored_row(&bytes).expect("archived row");
        let expr = KvExpr::Mul(
            Box::new(KvExpr::Field(KvFieldRef::Value {
                index: 0,
                kind: KvFieldKind::Int64,
                nullable: false,
            })),
            Box::new(KvExpr::Field(KvFieldRef::Value {
                index: 1,
                kind: KvFieldKind::Int64,
                nullable: false,
            })),
        );
        assert_eq!(
            eval_expr(&key, Some(archived), &expr).expect("expr"),
            Some(KvReducedValue::Int64(42))
        );
        assert!(expr_needs_value(&expr));
    }

    #[test]
    fn eval_expr_adds_and_subtracts_numeric_fields() {
        let key = Key::default();
        let row = StoredRow {
            values: vec![Some(StoredValue::Int64(9)), Some(StoredValue::Int64(4))],
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&row)
            .expect("row bytes")
            .to_vec();
        let archived = access_stored_row(&bytes).expect("archived row");

        let add = KvExpr::Add(
            Box::new(KvExpr::Field(KvFieldRef::Value {
                index: 0,
                kind: KvFieldKind::Int64,
                nullable: false,
            })),
            Box::new(KvExpr::Field(KvFieldRef::Value {
                index: 1,
                kind: KvFieldKind::Int64,
                nullable: false,
            })),
        );
        let sub = KvExpr::Sub(
            Box::new(KvExpr::Field(KvFieldRef::Value {
                index: 0,
                kind: KvFieldKind::Int64,
                nullable: false,
            })),
            Box::new(KvExpr::Field(KvFieldRef::Value {
                index: 1,
                kind: KvFieldKind::Int64,
                nullable: false,
            })),
        );

        assert_eq!(
            eval_expr(&key, Some(archived), &add).expect("add expr"),
            Some(KvReducedValue::Int64(13))
        );
        assert_eq!(
            eval_expr(&key, Some(archived), &sub).expect("sub expr"),
            Some(KvReducedValue::Int64(5))
        );
    }

    #[test]
    fn eval_expr_divides_int64_by_float_literal() {
        let key = Key::default();
        let row = StoredRow {
            values: vec![Some(StoredValue::Int64(1_500))],
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&row)
            .expect("row bytes")
            .to_vec();
        let archived = access_stored_row(&bytes).expect("archived row");
        let expr = KvExpr::Div(
            Box::new(KvExpr::Field(KvFieldRef::Value {
                index: 0,
                kind: KvFieldKind::Int64,
                nullable: false,
            })),
            Box::new(KvExpr::Literal(KvReducedValue::Float64(1000.0))),
        );
        assert_eq!(
            eval_expr(&key, Some(archived), &expr).expect("expr"),
            Some(KvReducedValue::Float64(1.5))
        );
    }

    #[test]
    fn eval_expr_lower_and_date_trunc_day() {
        let key = Key::default();
        let ts = 1_706_428_496_123_456i64;
        let day_micros = 86_400_000_000i64;
        let expected_ts = ts.div_euclid(day_micros) * day_micros;
        let row = StoredRow {
            values: vec![
                Some(StoredValue::Utf8("MiXeD".to_string())),
                Some(StoredValue::Int64(ts)),
            ],
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&row)
            .expect("row bytes")
            .to_vec();
        let archived = access_stored_row(&bytes).expect("archived row");

        let lower = KvExpr::Lower(Box::new(KvExpr::Field(KvFieldRef::Value {
            index: 0,
            kind: KvFieldKind::Utf8,
            nullable: false,
        })));
        assert_eq!(
            eval_expr(&key, Some(archived), &lower).expect("lower expr"),
            Some(KvReducedValue::Utf8("mixed".to_string()))
        );

        let trunc = KvExpr::DateTruncDay(Box::new(KvExpr::Field(KvFieldRef::Value {
            index: 1,
            kind: KvFieldKind::Timestamp,
            nullable: false,
        })));
        assert_eq!(
            eval_expr(&key, Some(archived), &trunc).expect("trunc expr"),
            Some(KvReducedValue::Timestamp(expected_ts))
        );
    }

    #[test]
    fn zorder_interleave_round_trips_mixed_width_fields() {
        let fields = vec![vec![0x80, 0x01, 0x02, 0x03], vec![0xAA, 0xBB], vec![0xCC]];
        let interleaved = interleave_ordered_key_fields(&fields);
        let decoded =
            deinterleave_ordered_key_fields(&interleaved, &[4, 2, 1]).expect("deinterleave");
        assert_eq!(decoded, fields);
    }

    #[test]
    fn eval_predicate_supports_zorder_key_fields() {
        let mut key_buf = vec![0u8; 19];
        let x = ((2i64 as u64) ^ 0x8000_0000_0000_0000)
            .to_be_bytes()
            .to_vec();
        let y = ((1i64 as u64) ^ 0x8000_0000_0000_0000)
            .to_be_bytes()
            .to_vec();
        let interleaved = interleave_ordered_key_fields(&[x, y]);
        key_buf[3..3 + interleaved.len()].copy_from_slice(&interleaved);
        let key = Key::from(key_buf);

        let predicate = KvPredicate {
            checks: vec![
                KvPredicateCheck {
                    field: KvFieldRef::ZOrderKey {
                        bit_offset: 24,
                        field_position: 0,
                        field_widths: vec![8, 8],
                        kind: KvFieldKind::Int64,
                    },
                    constraint: KvPredicateConstraint::IntRange {
                        min: Some(1),
                        max: Some(2),
                    },
                },
                KvPredicateCheck {
                    field: KvFieldRef::ZOrderKey {
                        bit_offset: 24,
                        field_position: 1,
                        field_widths: vec![8, 8],
                        kind: KvFieldKind::Int64,
                    },
                    constraint: KvPredicateConstraint::IntRange {
                        min: Some(1),
                        max: Some(2),
                    },
                },
            ],
            contradiction: false,
        };

        assert!(eval_predicate(&key, None, &predicate).expect("predicate eval"));
    }

    #[test]
    fn eval_expr_div_by_negative_zero_is_error() {
        let key = Key::default();
        let expr = KvExpr::Div(
            Box::new(KvExpr::Literal(KvReducedValue::Float64(1.0))),
            Box::new(KvExpr::Literal(KvReducedValue::Float64(-0.0))),
        );
        assert_eq!(
            eval_expr(&key, None, &expr),
            Err("division by zero".to_string())
        );
    }

    #[test]
    fn eval_expr_div_by_positive_zero_is_error() {
        let key = Key::default();
        let expr = KvExpr::Div(
            Box::new(KvExpr::Literal(KvReducedValue::Float64(1.0))),
            Box::new(KvExpr::Literal(KvReducedValue::Float64(0.0))),
        );
        assert_eq!(
            eval_expr(&key, None, &expr),
            Err("division by zero".to_string())
        );
    }

    #[test]
    fn eval_expr_div_int_by_zero_is_error() {
        let key = Key::default();
        let expr = KvExpr::Div(
            Box::new(KvExpr::Literal(KvReducedValue::Int64(10))),
            Box::new(KvExpr::Literal(KvReducedValue::Int64(0))),
        );
        assert_eq!(
            eval_expr(&key, None, &expr),
            Err("division by zero".to_string())
        );
    }
}
