//! Protobuf types and service stubs for the store API (`store.*.v1`).
//!
//! Proto sources: `proto/`. Run `./gen.sh` to regenerate all bindings.

pub mod store {
    pub mod common {
        pub mod v1 {
            #![allow(non_camel_case_types)]
            #![allow(unused_imports)]
            #![allow(clippy::derivable_impls)]
            #![allow(clippy::match_single_binding)]
            include!("../gen/store.v1.common.rs");
        }
    }

    pub mod compact {
        pub mod v1 {
            #![allow(non_camel_case_types)]
            #![allow(unused_imports)]
            #![allow(clippy::derivable_impls)]
            #![allow(clippy::match_single_binding)]
            include!("../gen/store.v1.compact.rs");
        }
    }

    pub mod ingest {
        pub mod v1 {
            #![allow(non_camel_case_types)]
            #![allow(unused_imports)]
            #![allow(clippy::derivable_impls)]
            #![allow(clippy::match_single_binding)]
            include!("../gen/store.v1.ingest.rs");
        }
    }

    pub mod query {
        pub mod v1 {
            #![allow(non_camel_case_types)]
            #![allow(unused_imports)]
            #![allow(clippy::derivable_impls)]
            #![allow(clippy::match_single_binding)]
            include!("../gen/store.v1.query.rs");
        }
    }

    pub mod qmdb {
        pub mod v1 {
            #![allow(non_camel_case_types)]
            #![allow(unused_imports)]
            #![allow(clippy::derivable_impls)]
            #![allow(clippy::match_single_binding)]
            include!("../gen/store.v1.qmdb.rs");
        }
    }

    pub mod stream {
        pub mod v1 {
            #![allow(non_camel_case_types)]
            #![allow(unused_imports)]
            #![allow(clippy::derivable_impls)]
            #![allow(clippy::match_single_binding)]
            include!("../gen/store.v1.stream.rs");
        }
    }
}

pub mod google {
    pub mod rpc {
        #![allow(non_camel_case_types)]
        #![allow(unused_imports)]
        #![allow(clippy::derivable_impls)]
        #![allow(clippy::match_single_binding)]
        include!("../gen/google.rpc.error_details.rs");
    }
}

pub mod common {
    #![allow(non_camel_case_types)]
    #![allow(unused_imports)]
    #![allow(clippy::derivable_impls)]
    #![allow(clippy::match_single_binding)]
    pub use crate::store::common::v1::*;
}

pub mod compact {
    #![allow(non_camel_case_types)]
    #![allow(unused_imports)]
    #![allow(clippy::derivable_impls)]
    #![allow(clippy::match_single_binding)]
    pub use crate::store::compact::v1::*;
}

pub mod ingest {
    #![allow(non_camel_case_types)]
    #![allow(unused_imports)]
    #![allow(clippy::derivable_impls)]
    #![allow(clippy::match_single_binding)]
    pub use crate::store::ingest::v1::*;
}

pub mod query {
    #![allow(non_camel_case_types)]
    #![allow(unused_imports)]
    #![allow(clippy::derivable_impls)]
    #![allow(clippy::match_single_binding)]
    pub use crate::store::query::v1::*;
}

pub mod qmdb {
    #![allow(non_camel_case_types)]
    #![allow(unused_imports)]
    #![allow(clippy::derivable_impls)]
    #![allow(clippy::match_single_binding)]
    pub use crate::store::qmdb::v1::*;
}

pub mod stream {
    #![allow(non_camel_case_types)]
    #![allow(unused_imports)]
    #![allow(clippy::derivable_impls)]
    #![allow(clippy::match_single_binding)]
    pub use crate::store::stream::v1::*;
}

pub mod compression;
mod range_traversal;

pub use compression::{
    connect_compression_registry, PreferZstdHttpClient, EXOWARE_AFFINITY_COOKIE,
};
pub use range_traversal::{
    parse_range_traversal_direction, RangeTraversalDirection, RangeTraversalModeError,
};

use crate::kv_codec::{
    KvExpr, KvFieldKind, KvFieldRef, KvPredicate, KvPredicateCheck, KvPredicateConstraint,
    KvReducedValue,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeReduceOp {
    CountAll,
    CountField,
    SumField,
    MinField,
    MaxField,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RangeReducerSpec {
    pub op: RangeReduceOp,
    pub expr: Option<KvExpr>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RangeReduceRequest {
    pub reducers: Vec<RangeReducerSpec>,
    pub group_by: Vec<KvExpr>,
    pub filter: Option<KvPredicate>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RangeReduceResult {
    pub value: Option<KvReducedValue>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RangeReduceGroup {
    pub group_values: Vec<Option<KvReducedValue>>,
    pub results: Vec<RangeReduceResult>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RangeReduceResponse {
    pub results: Vec<RangeReduceResult>,
    pub groups: Vec<RangeReduceGroup>,
}

fn fixed_size_binary_len(kind: &KvFieldKind) -> u32 {
    match kind {
        KvFieldKind::FixedSizeBinary(len) => u32::from(*len),
        _ => 0,
    }
}

fn proto_field_kind(kind: &KvFieldKind) -> query::KvFieldKind {
    match kind {
        KvFieldKind::Int64 => query::KvFieldKind::KV_FIELD_KIND_INT64,
        KvFieldKind::UInt64 => query::KvFieldKind::KV_FIELD_KIND_UINT64,
        KvFieldKind::Float64 => query::KvFieldKind::KV_FIELD_KIND_FLOAT64,
        KvFieldKind::Boolean => query::KvFieldKind::KV_FIELD_KIND_BOOLEAN,
        KvFieldKind::Utf8 => query::KvFieldKind::KV_FIELD_KIND_UTF8,
        KvFieldKind::Date32 => query::KvFieldKind::KV_FIELD_KIND_DATE32,
        KvFieldKind::Date64 => query::KvFieldKind::KV_FIELD_KIND_DATE64,
        KvFieldKind::Timestamp => query::KvFieldKind::KV_FIELD_KIND_TIMESTAMP,
        KvFieldKind::Decimal128 => query::KvFieldKind::KV_FIELD_KIND_DECIMAL128,
        KvFieldKind::Decimal256 => query::KvFieldKind::KV_FIELD_KIND_DECIMAL256,
        KvFieldKind::FixedSizeBinary(_) => query::KvFieldKind::KV_FIELD_KIND_FIXED_SIZE_BINARY,
    }
}

fn domain_field_kind(
    kind: buffa::EnumValue<query::KvFieldKind>,
    fixed_size_binary_len: u32,
) -> Result<KvFieldKind, String> {
    match kind.as_known() {
        Some(query::KvFieldKind::KV_FIELD_KIND_INT64) => Ok(KvFieldKind::Int64),
        Some(query::KvFieldKind::KV_FIELD_KIND_UINT64) => Ok(KvFieldKind::UInt64),
        Some(query::KvFieldKind::KV_FIELD_KIND_FLOAT64) => Ok(KvFieldKind::Float64),
        Some(query::KvFieldKind::KV_FIELD_KIND_BOOLEAN) => Ok(KvFieldKind::Boolean),
        Some(query::KvFieldKind::KV_FIELD_KIND_UTF8) => Ok(KvFieldKind::Utf8),
        Some(query::KvFieldKind::KV_FIELD_KIND_DATE32) => Ok(KvFieldKind::Date32),
        Some(query::KvFieldKind::KV_FIELD_KIND_DATE64) => Ok(KvFieldKind::Date64),
        Some(query::KvFieldKind::KV_FIELD_KIND_TIMESTAMP) => Ok(KvFieldKind::Timestamp),
        Some(query::KvFieldKind::KV_FIELD_KIND_DECIMAL128) => Ok(KvFieldKind::Decimal128),
        Some(query::KvFieldKind::KV_FIELD_KIND_DECIMAL256) => Ok(KvFieldKind::Decimal256),
        Some(query::KvFieldKind::KV_FIELD_KIND_FIXED_SIZE_BINARY) => {
            let len = u8::try_from(fixed_size_binary_len).map_err(|_| {
                format!("fixed_size_binary_len {fixed_size_binary_len} does not fit in u8")
            })?;
            Ok(KvFieldKind::FixedSizeBinary(len))
        }
        _ => Err("unsupported KvFieldKind".to_string()),
    }
}

pub fn to_proto_reduced_value(value: KvReducedValue) -> query::KvReducedValue {
    let value = match value {
        KvReducedValue::Int64(v) => query::kv_reduced_value::Value::Int64Value(v),
        KvReducedValue::UInt64(v) => query::kv_reduced_value::Value::Uint64Value(v),
        KvReducedValue::Float64(v) => query::kv_reduced_value::Value::Float64Value(v),
        KvReducedValue::Boolean(v) => query::kv_reduced_value::Value::BooleanValue(v),
        KvReducedValue::Utf8(v) => query::kv_reduced_value::Value::Utf8Value(v),
        KvReducedValue::Date32(v) => query::kv_reduced_value::Value::Date32Value(v),
        KvReducedValue::Date64(v) => query::kv_reduced_value::Value::Date64Value(v),
        KvReducedValue::Timestamp(v) => query::kv_reduced_value::Value::TimestampValue(v),
        KvReducedValue::Decimal128(v) => {
            query::kv_reduced_value::Value::Decimal128Value(v.to_be_bytes().to_vec())
        }
        KvReducedValue::Decimal256(v) => {
            query::kv_reduced_value::Value::Decimal256Value(v.to_vec())
        }
        KvReducedValue::FixedSizeBinary(v) => {
            query::kv_reduced_value::Value::FixedSizeBinaryValue(v)
        }
    };
    query::KvReducedValue {
        value: Some(value),
        ..Default::default()
    }
}

pub fn to_proto_optional_reduced_value(value: Option<KvReducedValue>) -> query::KvReducedValue {
    value.map(to_proto_reduced_value).unwrap_or_default()
}

pub fn to_domain_reduced_value(value: &query::KvReducedValue) -> Result<KvReducedValue, String> {
    match value.value.as_ref() {
        Some(query::kv_reduced_value::Value::Int64Value(v)) => Ok(KvReducedValue::Int64(*v)),
        Some(query::kv_reduced_value::Value::Uint64Value(v)) => Ok(KvReducedValue::UInt64(*v)),
        Some(query::kv_reduced_value::Value::Float64Value(v)) => Ok(KvReducedValue::Float64(*v)),
        Some(query::kv_reduced_value::Value::BooleanValue(v)) => Ok(KvReducedValue::Boolean(*v)),
        Some(query::kv_reduced_value::Value::Utf8Value(v)) => Ok(KvReducedValue::Utf8(v.clone())),
        Some(query::kv_reduced_value::Value::Date32Value(v)) => Ok(KvReducedValue::Date32(*v)),
        Some(query::kv_reduced_value::Value::Date64Value(v)) => Ok(KvReducedValue::Date64(*v)),
        Some(query::kv_reduced_value::Value::TimestampValue(v)) => {
            Ok(KvReducedValue::Timestamp(*v))
        }
        Some(query::kv_reduced_value::Value::Decimal128Value(bytes)) => {
            let raw: [u8; 16] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "decimal128 must be exactly 16 bytes".to_string())?;
            Ok(KvReducedValue::Decimal128(i128::from_be_bytes(raw)))
        }
        Some(query::kv_reduced_value::Value::Decimal256Value(bytes)) => {
            let raw: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "decimal256 must be exactly 32 bytes".to_string())?;
            Ok(KvReducedValue::Decimal256(raw))
        }
        Some(query::kv_reduced_value::Value::FixedSizeBinaryValue(v)) => {
            Ok(KvReducedValue::FixedSizeBinary(v.clone()))
        }
        None => Err("missing reduced value".to_string()),
    }
}

/// Like [`to_domain_reduced_value`], but consumes the proto message so `String` / `Vec<u8>` payloads
/// are moved into the domain enum without an extra heap copy.
pub fn to_domain_reduced_value_from_proto(
    mut value: query::KvReducedValue,
) -> Result<KvReducedValue, String> {
    match value.value.take() {
        None => Err("missing reduced value".to_string()),
        Some(query::kv_reduced_value::Value::Int64Value(v)) => Ok(KvReducedValue::Int64(v)),
        Some(query::kv_reduced_value::Value::Uint64Value(v)) => Ok(KvReducedValue::UInt64(v)),
        Some(query::kv_reduced_value::Value::Float64Value(v)) => Ok(KvReducedValue::Float64(v)),
        Some(query::kv_reduced_value::Value::BooleanValue(v)) => Ok(KvReducedValue::Boolean(v)),
        Some(query::kv_reduced_value::Value::Utf8Value(v)) => Ok(KvReducedValue::Utf8(v)),
        Some(query::kv_reduced_value::Value::Date32Value(v)) => Ok(KvReducedValue::Date32(v)),
        Some(query::kv_reduced_value::Value::Date64Value(v)) => Ok(KvReducedValue::Date64(v)),
        Some(query::kv_reduced_value::Value::TimestampValue(v)) => Ok(KvReducedValue::Timestamp(v)),
        Some(query::kv_reduced_value::Value::Decimal128Value(bytes)) => {
            let raw: [u8; 16] = bytes
                .try_into()
                .map_err(|_| "decimal128 must be exactly 16 bytes".to_string())?;
            Ok(KvReducedValue::Decimal128(i128::from_be_bytes(raw)))
        }
        Some(query::kv_reduced_value::Value::Decimal256Value(bytes)) => {
            let raw: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "decimal256 must be exactly 32 bytes".to_string())?;
            Ok(KvReducedValue::Decimal256(raw))
        }
        Some(query::kv_reduced_value::Value::FixedSizeBinaryValue(v)) => {
            Ok(KvReducedValue::FixedSizeBinary(v))
        }
    }
}

fn to_proto_expr(expr: KvExpr) -> query::KvExpr {
    let expr = match expr {
        KvExpr::Field(field) => query::kv_expr::Expr::Field(Box::new(to_proto_field_ref(field))),
        KvExpr::Literal(value) => {
            query::kv_expr::Expr::Literal(Box::new(to_proto_reduced_value(value)))
        }
        KvExpr::Add(left, right) => {
            query::kv_expr::Expr::Add(Box::new(query::kv_expr::BinaryExpr {
                left: Some(to_proto_expr(*left)).into(),
                right: Some(to_proto_expr(*right)).into(),
                ..Default::default()
            }))
        }
        KvExpr::Sub(left, right) => {
            query::kv_expr::Expr::Sub(Box::new(query::kv_expr::BinaryExpr {
                left: Some(to_proto_expr(*left)).into(),
                right: Some(to_proto_expr(*right)).into(),
                ..Default::default()
            }))
        }
        KvExpr::Mul(left, right) => {
            query::kv_expr::Expr::Mul(Box::new(query::kv_expr::BinaryExpr {
                left: Some(to_proto_expr(*left)).into(),
                right: Some(to_proto_expr(*right)).into(),
                ..Default::default()
            }))
        }
        KvExpr::Div(left, right) => {
            query::kv_expr::Expr::Div(Box::new(query::kv_expr::BinaryExpr {
                left: Some(to_proto_expr(*left)).into(),
                right: Some(to_proto_expr(*right)).into(),
                ..Default::default()
            }))
        }
        KvExpr::Lower(inner) => query::kv_expr::Expr::Lower(Box::new(to_proto_expr(*inner))),
        KvExpr::DateTruncDay(inner) => {
            query::kv_expr::Expr::DateTruncDay(Box::new(to_proto_expr(*inner)))
        }
    };
    query::KvExpr {
        expr: Some(expr),
        ..Default::default()
    }
}

fn to_domain_expr(expr: &query::KvExpr) -> Result<KvExpr, String> {
    match expr.expr.as_ref() {
        Some(query::kv_expr::Expr::Field(field)) => Ok(KvExpr::Field(to_domain_field_ref(field)?)),
        Some(query::kv_expr::Expr::Literal(value)) => {
            Ok(KvExpr::Literal(to_domain_reduced_value(value)?))
        }
        Some(query::kv_expr::Expr::Add(binary)) => Ok(KvExpr::Add(
            Box::new(to_domain_expr(
                binary.left.as_option().ok_or("missing add.left")?,
            )?),
            Box::new(to_domain_expr(
                binary.right.as_option().ok_or("missing add.right")?,
            )?),
        )),
        Some(query::kv_expr::Expr::Sub(binary)) => Ok(KvExpr::Sub(
            Box::new(to_domain_expr(
                binary.left.as_option().ok_or("missing sub.left")?,
            )?),
            Box::new(to_domain_expr(
                binary.right.as_option().ok_or("missing sub.right")?,
            )?),
        )),
        Some(query::kv_expr::Expr::Mul(binary)) => Ok(KvExpr::Mul(
            Box::new(to_domain_expr(
                binary.left.as_option().ok_or("missing mul.left")?,
            )?),
            Box::new(to_domain_expr(
                binary.right.as_option().ok_or("missing mul.right")?,
            )?),
        )),
        Some(query::kv_expr::Expr::Div(binary)) => Ok(KvExpr::Div(
            Box::new(to_domain_expr(
                binary.left.as_option().ok_or("missing div.left")?,
            )?),
            Box::new(to_domain_expr(
                binary.right.as_option().ok_or("missing div.right")?,
            )?),
        )),
        Some(query::kv_expr::Expr::Lower(inner)) => {
            Ok(KvExpr::Lower(Box::new(to_domain_expr(inner)?)))
        }
        Some(query::kv_expr::Expr::DateTruncDay(inner)) => {
            Ok(KvExpr::DateTruncDay(Box::new(to_domain_expr(inner)?)))
        }
        None => Err("missing expr".to_string()),
    }
}

fn to_proto_field_ref(field: KvFieldRef) -> query::KvFieldRef {
    let field = match field {
        KvFieldRef::Key { bit_offset, kind } => {
            query::kv_field_ref::Field::Key(Box::new(query::kv_field_ref::KeyField {
                bit_offset: u32::from(bit_offset),
                kind: proto_field_kind(&kind).into(),
                fixed_size_binary_len: fixed_size_binary_len(&kind),
                ..Default::default()
            }))
        }
        KvFieldRef::ZOrderKey {
            bit_offset,
            field_position,
            field_widths,
            kind,
        } => query::kv_field_ref::Field::ZOrderKey(Box::new(query::kv_field_ref::ZOrderKeyField {
            bit_offset: u32::from(bit_offset),
            field_position: u32::from(field_position),
            field_widths: field_widths.into_iter().map(u32::from).collect(),
            kind: proto_field_kind(&kind).into(),
            fixed_size_binary_len: fixed_size_binary_len(&kind),
            ..Default::default()
        })),
        KvFieldRef::Value {
            index,
            kind,
            nullable,
        } => query::kv_field_ref::Field::Value(Box::new(query::kv_field_ref::ValueField {
            index: u32::from(index),
            kind: proto_field_kind(&kind).into(),
            nullable,
            fixed_size_binary_len: fixed_size_binary_len(&kind),
            ..Default::default()
        })),
    };
    query::KvFieldRef {
        field: Some(field),
        ..Default::default()
    }
}

fn to_domain_field_ref(field: &query::KvFieldRef) -> Result<KvFieldRef, String> {
    match field.field.as_ref() {
        Some(query::kv_field_ref::Field::Key(key)) => Ok(KvFieldRef::Key {
            bit_offset: u16::try_from(key.bit_offset)
                .map_err(|_| format!("bit_offset {} does not fit in u16", key.bit_offset))?,
            kind: domain_field_kind(key.kind, key.fixed_size_binary_len)?,
        }),
        Some(query::kv_field_ref::Field::ZOrderKey(key)) => Ok(KvFieldRef::ZOrderKey {
            bit_offset: u16::try_from(key.bit_offset)
                .map_err(|_| format!("bit_offset {} does not fit in u16", key.bit_offset))?,
            field_position: u8::try_from(key.field_position)
                .map_err(|_| format!("field_position {} does not fit in u8", key.field_position))?,
            field_widths: key
                .field_widths
                .iter()
                .map(|width| {
                    u8::try_from(*width)
                        .map_err(|_| format!("field width {width} does not fit in u8"))
                })
                .collect::<Result<Vec<_>, _>>()?,
            kind: domain_field_kind(key.kind, key.fixed_size_binary_len)?,
        }),
        Some(query::kv_field_ref::Field::Value(value)) => Ok(KvFieldRef::Value {
            index: u16::try_from(value.index)
                .map_err(|_| format!("index {} does not fit in u16", value.index))?,
            kind: domain_field_kind(value.kind, value.fixed_size_binary_len)?,
            nullable: value.nullable,
        }),
        None => Err("missing field ref".to_string()),
    }
}

fn to_proto_predicate_constraint(
    constraint: KvPredicateConstraint,
) -> query::KvPredicateConstraint {
    let constraint = match constraint {
        KvPredicateConstraint::StringEq(v) => {
            query::kv_predicate_constraint::Constraint::StringEq(v)
        }
        KvPredicateConstraint::BoolEq(v) => query::kv_predicate_constraint::Constraint::BoolEq(v),
        KvPredicateConstraint::FixedSizeBinaryEq(v) => {
            query::kv_predicate_constraint::Constraint::FixedSizeBinaryEq(v)
        }
        KvPredicateConstraint::IntRange { min, max } => {
            query::kv_predicate_constraint::Constraint::IntRange(Box::new(
                query::kv_predicate_constraint::IntRange {
                    min,
                    max,
                    ..Default::default()
                },
            ))
        }
        KvPredicateConstraint::UInt64Range { min, max } => {
            query::kv_predicate_constraint::Constraint::Uint64Range(Box::new(
                query::kv_predicate_constraint::UInt64Range {
                    min,
                    max,
                    ..Default::default()
                },
            ))
        }
        KvPredicateConstraint::FloatRange { min, max } => {
            query::kv_predicate_constraint::Constraint::FloatRange(Box::new(
                query::kv_predicate_constraint::FloatRange {
                    min: min
                        .map(
                            |(value, inclusive)| query::kv_predicate_constraint::FloatBound {
                                value,
                                inclusive,
                                ..Default::default()
                            },
                        )
                        .into(),
                    max: max
                        .map(
                            |(value, inclusive)| query::kv_predicate_constraint::FloatBound {
                                value,
                                inclusive,
                                ..Default::default()
                            },
                        )
                        .into(),
                    ..Default::default()
                },
            ))
        }
        KvPredicateConstraint::Decimal128Range { min, max } => {
            query::kv_predicate_constraint::Constraint::Decimal128Range(Box::new(
                query::kv_predicate_constraint::Decimal128Range {
                    min: min.map(|v: i128| v.to_be_bytes().to_vec()),
                    max: max.map(|v: i128| v.to_be_bytes().to_vec()),
                    ..Default::default()
                },
            ))
        }
        KvPredicateConstraint::Decimal256Range { min, max } => {
            query::kv_predicate_constraint::Constraint::Decimal256Range(Box::new(
                query::kv_predicate_constraint::Decimal256Range {
                    min: min.map(|v| v.to_vec()),
                    max: max.map(|v| v.to_vec()),
                    ..Default::default()
                },
            ))
        }
        KvPredicateConstraint::IsNull => query::kv_predicate_constraint::Constraint::IsNull(true),
        KvPredicateConstraint::IsNotNull => {
            query::kv_predicate_constraint::Constraint::IsNotNull(true)
        }
        KvPredicateConstraint::StringIn(values) => {
            query::kv_predicate_constraint::Constraint::StringIn(Box::new(
                query::kv_predicate_constraint::StringIn {
                    values,
                    ..Default::default()
                },
            ))
        }
        KvPredicateConstraint::IntIn(values) => query::kv_predicate_constraint::Constraint::IntIn(
            Box::new(query::kv_predicate_constraint::IntIn {
                values,
                ..Default::default()
            }),
        ),
        KvPredicateConstraint::UInt64In(values) => {
            query::kv_predicate_constraint::Constraint::Uint64In(Box::new(
                query::kv_predicate_constraint::UInt64In {
                    values,
                    ..Default::default()
                },
            ))
        }
        KvPredicateConstraint::FixedSizeBinaryIn(values) => {
            query::kv_predicate_constraint::Constraint::FixedSizeBinaryIn(Box::new(
                query::kv_predicate_constraint::FixedSizeBinaryIn {
                    values,
                    ..Default::default()
                },
            ))
        }
    };
    query::KvPredicateConstraint {
        constraint: Some(constraint),
        ..Default::default()
    }
}

fn to_domain_predicate_constraint(
    constraint: &query::KvPredicateConstraint,
) -> Result<KvPredicateConstraint, String> {
    match constraint.constraint.as_ref() {
        Some(query::kv_predicate_constraint::Constraint::StringEq(v)) => {
            Ok(KvPredicateConstraint::StringEq(v.clone()))
        }
        Some(query::kv_predicate_constraint::Constraint::BoolEq(v)) => {
            Ok(KvPredicateConstraint::BoolEq(*v))
        }
        Some(query::kv_predicate_constraint::Constraint::FixedSizeBinaryEq(v)) => {
            Ok(KvPredicateConstraint::FixedSizeBinaryEq(v.clone()))
        }
        Some(query::kv_predicate_constraint::Constraint::IntRange(v)) => {
            Ok(KvPredicateConstraint::IntRange {
                min: v.min,
                max: v.max,
            })
        }
        Some(query::kv_predicate_constraint::Constraint::Uint64Range(v)) => {
            Ok(KvPredicateConstraint::UInt64Range {
                min: v.min,
                max: v.max,
            })
        }
        Some(query::kv_predicate_constraint::Constraint::FloatRange(v)) => {
            Ok(KvPredicateConstraint::FloatRange {
                min: v
                    .min
                    .as_option()
                    .map(|bound| (bound.value, bound.inclusive)),
                max: v
                    .max
                    .as_option()
                    .map(|bound| (bound.value, bound.inclusive)),
            })
        }
        Some(query::kv_predicate_constraint::Constraint::Decimal128Range(v)) => {
            let min = v
                .min
                .as_ref()
                .map(|raw| {
                    let bytes: [u8; 16] = raw
                        .as_slice()
                        .try_into()
                        .map_err(|_| "decimal128 min must be exactly 16 bytes".to_string())?;
                    Ok::<i128, String>(i128::from_be_bytes(bytes))
                })
                .transpose()?;
            let max = v
                .max
                .as_ref()
                .map(|raw| {
                    let bytes: [u8; 16] = raw
                        .as_slice()
                        .try_into()
                        .map_err(|_| "decimal128 max must be exactly 16 bytes".to_string())?;
                    Ok::<i128, String>(i128::from_be_bytes(bytes))
                })
                .transpose()?;
            Ok(KvPredicateConstraint::Decimal128Range { min, max })
        }
        Some(query::kv_predicate_constraint::Constraint::Decimal256Range(v)) => {
            let min = v
                .min
                .as_ref()
                .map(|raw| {
                    let bytes: [u8; 32] = raw
                        .as_slice()
                        .try_into()
                        .map_err(|_| "decimal256 min must be exactly 32 bytes".to_string())?;
                    Ok::<[u8; 32], String>(bytes)
                })
                .transpose()?;
            let max = v
                .max
                .as_ref()
                .map(|raw| {
                    let bytes: [u8; 32] = raw
                        .as_slice()
                        .try_into()
                        .map_err(|_| "decimal256 max must be exactly 32 bytes".to_string())?;
                    Ok::<[u8; 32], String>(bytes)
                })
                .transpose()?;
            Ok(KvPredicateConstraint::Decimal256Range { min, max })
        }
        Some(query::kv_predicate_constraint::Constraint::IsNull(_)) => {
            Ok(KvPredicateConstraint::IsNull)
        }
        Some(query::kv_predicate_constraint::Constraint::IsNotNull(_)) => {
            Ok(KvPredicateConstraint::IsNotNull)
        }
        Some(query::kv_predicate_constraint::Constraint::StringIn(v)) => {
            Ok(KvPredicateConstraint::StringIn(v.values.clone()))
        }
        Some(query::kv_predicate_constraint::Constraint::IntIn(v)) => {
            Ok(KvPredicateConstraint::IntIn(v.values.clone()))
        }
        Some(query::kv_predicate_constraint::Constraint::Uint64In(v)) => {
            Ok(KvPredicateConstraint::UInt64In(v.values.clone()))
        }
        Some(query::kv_predicate_constraint::Constraint::FixedSizeBinaryIn(v)) => {
            Ok(KvPredicateConstraint::FixedSizeBinaryIn(v.values.clone()))
        }
        None => Err("missing predicate constraint".to_string()),
    }
}

pub fn to_proto_reduce_params(request: RangeReduceRequest) -> query::ReduceParams {
    query::ReduceParams {
        reducers: request
            .reducers
            .into_iter()
            .map(|reducer| query::RangeReducerSpec {
                op: match reducer.op {
                    RangeReduceOp::CountAll => query::RangeReduceOp::RANGE_REDUCE_OP_COUNT_ALL,
                    RangeReduceOp::CountField => query::RangeReduceOp::RANGE_REDUCE_OP_COUNT_FIELD,
                    RangeReduceOp::SumField => query::RangeReduceOp::RANGE_REDUCE_OP_SUM_FIELD,
                    RangeReduceOp::MinField => query::RangeReduceOp::RANGE_REDUCE_OP_MIN_FIELD,
                    RangeReduceOp::MaxField => query::RangeReduceOp::RANGE_REDUCE_OP_MAX_FIELD,
                }
                .into(),
                expr: reducer.expr.map(to_proto_expr).into(),
                ..Default::default()
            })
            .collect(),
        group_by: request.group_by.into_iter().map(to_proto_expr).collect(),
        filter: request
            .filter
            .map(|predicate| query::KvPredicate {
                checks: predicate
                    .checks
                    .into_iter()
                    .map(|check| query::KvPredicateCheck {
                        field: Some(to_proto_field_ref(check.field)).into(),
                        constraint: Some(to_proto_predicate_constraint(check.constraint)).into(),
                        ..Default::default()
                    })
                    .collect(),
                contradiction: predicate.contradiction,
                ..Default::default()
            })
            .into(),
        ..Default::default()
    }
}

pub fn to_domain_reduce_request(
    request: &query::ReduceParams,
) -> Result<RangeReduceRequest, String> {
    Ok(RangeReduceRequest {
        reducers: request
            .reducers
            .iter()
            .map(|reducer| {
                let op = match reducer.op.as_known() {
                    Some(query::RangeReduceOp::RANGE_REDUCE_OP_COUNT_ALL) => {
                        RangeReduceOp::CountAll
                    }
                    Some(query::RangeReduceOp::RANGE_REDUCE_OP_COUNT_FIELD) => {
                        RangeReduceOp::CountField
                    }
                    Some(query::RangeReduceOp::RANGE_REDUCE_OP_SUM_FIELD) => {
                        RangeReduceOp::SumField
                    }
                    Some(query::RangeReduceOp::RANGE_REDUCE_OP_MIN_FIELD) => {
                        RangeReduceOp::MinField
                    }
                    Some(query::RangeReduceOp::RANGE_REDUCE_OP_MAX_FIELD) => {
                        RangeReduceOp::MaxField
                    }
                    _ => return Err("unsupported RangeReduceOp".to_string()),
                };
                Ok(RangeReducerSpec {
                    op,
                    expr: reducer.expr.as_option().map(to_domain_expr).transpose()?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        group_by: request
            .group_by
            .iter()
            .map(to_domain_expr)
            .collect::<Result<Vec<_>, _>>()?,
        filter: request
            .filter
            .as_option()
            .map(|predicate| {
                Ok::<KvPredicate, String>(KvPredicate {
                    checks: predicate
                        .checks
                        .iter()
                        .map(|check| {
                            Ok(KvPredicateCheck {
                                field: to_domain_field_ref(
                                    check.field.as_option().ok_or("missing predicate field")?,
                                )?,
                                constraint: to_domain_predicate_constraint(
                                    check
                                        .constraint
                                        .as_option()
                                        .ok_or("missing predicate constraint")?,
                                )?,
                            })
                        })
                        .collect::<Result<Vec<_>, String>>()?,
                    contradiction: predicate.contradiction,
                })
            })
            .transpose()?,
    })
}

fn to_domain_reduced_value_from_view(
    value: &query::KvReducedValueView<'_>,
) -> Result<KvReducedValue, String> {
    match value.value.as_ref() {
        Some(query::kv_reduced_value::ValueView::Int64Value(v)) => Ok(KvReducedValue::Int64(*v)),
        Some(query::kv_reduced_value::ValueView::Uint64Value(v)) => Ok(KvReducedValue::UInt64(*v)),
        Some(query::kv_reduced_value::ValueView::Float64Value(v)) => {
            Ok(KvReducedValue::Float64(*v))
        }
        Some(query::kv_reduced_value::ValueView::BooleanValue(v)) => {
            Ok(KvReducedValue::Boolean(*v))
        }
        Some(query::kv_reduced_value::ValueView::Utf8Value(v)) => {
            Ok(KvReducedValue::Utf8(v.to_string()))
        }
        Some(query::kv_reduced_value::ValueView::Date32Value(v)) => Ok(KvReducedValue::Date32(*v)),
        Some(query::kv_reduced_value::ValueView::Date64Value(v)) => Ok(KvReducedValue::Date64(*v)),
        Some(query::kv_reduced_value::ValueView::TimestampValue(v)) => {
            Ok(KvReducedValue::Timestamp(*v))
        }
        Some(query::kv_reduced_value::ValueView::Decimal128Value(bytes)) => {
            let raw: [u8; 16] = (*bytes)
                .try_into()
                .map_err(|_| "decimal128 must be exactly 16 bytes".to_string())?;
            Ok(KvReducedValue::Decimal128(i128::from_be_bytes(raw)))
        }
        Some(query::kv_reduced_value::ValueView::Decimal256Value(bytes)) => {
            let raw: [u8; 32] = (*bytes)
                .try_into()
                .map_err(|_| "decimal256 must be exactly 32 bytes".to_string())?;
            Ok(KvReducedValue::Decimal256(raw))
        }
        Some(query::kv_reduced_value::ValueView::FixedSizeBinaryValue(v)) => {
            Ok(KvReducedValue::FixedSizeBinary(v.to_vec()))
        }
        None => Err("missing reduced value".to_string()),
    }
}

fn to_domain_expr_from_view(expr: &query::KvExprView<'_>) -> Result<KvExpr, String> {
    match expr.expr.as_ref() {
        Some(query::kv_expr::ExprView::Field(field)) => Ok(KvExpr::Field(
            to_domain_field_ref_from_view(field.as_ref())?,
        )),
        Some(query::kv_expr::ExprView::Literal(value)) => Ok(KvExpr::Literal(
            to_domain_reduced_value_from_view(value.as_ref())?,
        )),
        Some(query::kv_expr::ExprView::Add(binary)) => Ok(KvExpr::Add(
            Box::new(to_domain_expr_from_view(
                binary.left.as_option().ok_or("missing add.left")?,
            )?),
            Box::new(to_domain_expr_from_view(
                binary.right.as_option().ok_or("missing add.right")?,
            )?),
        )),
        Some(query::kv_expr::ExprView::Sub(binary)) => Ok(KvExpr::Sub(
            Box::new(to_domain_expr_from_view(
                binary.left.as_option().ok_or("missing sub.left")?,
            )?),
            Box::new(to_domain_expr_from_view(
                binary.right.as_option().ok_or("missing sub.right")?,
            )?),
        )),
        Some(query::kv_expr::ExprView::Mul(binary)) => Ok(KvExpr::Mul(
            Box::new(to_domain_expr_from_view(
                binary.left.as_option().ok_or("missing mul.left")?,
            )?),
            Box::new(to_domain_expr_from_view(
                binary.right.as_option().ok_or("missing mul.right")?,
            )?),
        )),
        Some(query::kv_expr::ExprView::Div(binary)) => Ok(KvExpr::Div(
            Box::new(to_domain_expr_from_view(
                binary.left.as_option().ok_or("missing div.left")?,
            )?),
            Box::new(to_domain_expr_from_view(
                binary.right.as_option().ok_or("missing div.right")?,
            )?),
        )),
        Some(query::kv_expr::ExprView::Lower(inner)) => Ok(KvExpr::Lower(Box::new(
            to_domain_expr_from_view(inner.as_ref())?,
        ))),
        Some(query::kv_expr::ExprView::DateTruncDay(inner)) => Ok(KvExpr::DateTruncDay(Box::new(
            to_domain_expr_from_view(inner.as_ref())?,
        ))),
        None => Err("missing expr".to_string()),
    }
}

fn to_domain_field_ref_from_view(field: &query::KvFieldRefView<'_>) -> Result<KvFieldRef, String> {
    match field.field.as_ref() {
        Some(query::kv_field_ref::FieldView::Key(key)) => Ok(KvFieldRef::Key {
            bit_offset: u16::try_from(key.bit_offset)
                .map_err(|_| format!("bit_offset {} does not fit in u16", key.bit_offset))?,
            kind: domain_field_kind(key.kind, key.fixed_size_binary_len)?,
        }),
        Some(query::kv_field_ref::FieldView::ZOrderKey(key)) => Ok(KvFieldRef::ZOrderKey {
            bit_offset: u16::try_from(key.bit_offset)
                .map_err(|_| format!("bit_offset {} does not fit in u16", key.bit_offset))?,
            field_position: u8::try_from(key.field_position)
                .map_err(|_| format!("field_position {} does not fit in u8", key.field_position))?,
            field_widths: key
                .field_widths
                .iter()
                .map(|width| {
                    u8::try_from(*width)
                        .map_err(|_| format!("field width {width} does not fit in u8"))
                })
                .collect::<Result<Vec<_>, _>>()?,
            kind: domain_field_kind(key.kind, key.fixed_size_binary_len)?,
        }),
        Some(query::kv_field_ref::FieldView::Value(value)) => Ok(KvFieldRef::Value {
            index: u16::try_from(value.index)
                .map_err(|_| format!("index {} does not fit in u16", value.index))?,
            kind: domain_field_kind(value.kind, value.fixed_size_binary_len)?,
            nullable: value.nullable,
        }),
        None => Err("missing field ref".to_string()),
    }
}

fn to_domain_predicate_constraint_from_view(
    constraint: &query::KvPredicateConstraintView<'_>,
) -> Result<KvPredicateConstraint, String> {
    match constraint.constraint.as_ref() {
        Some(query::kv_predicate_constraint::ConstraintView::StringEq(v)) => {
            Ok(KvPredicateConstraint::StringEq(v.to_string()))
        }
        Some(query::kv_predicate_constraint::ConstraintView::BoolEq(v)) => {
            Ok(KvPredicateConstraint::BoolEq(*v))
        }
        Some(query::kv_predicate_constraint::ConstraintView::FixedSizeBinaryEq(v)) => {
            Ok(KvPredicateConstraint::FixedSizeBinaryEq(v.to_vec()))
        }
        Some(query::kv_predicate_constraint::ConstraintView::IntRange(v)) => {
            Ok(KvPredicateConstraint::IntRange {
                min: v.min,
                max: v.max,
            })
        }
        Some(query::kv_predicate_constraint::ConstraintView::Uint64Range(v)) => {
            Ok(KvPredicateConstraint::UInt64Range {
                min: v.min,
                max: v.max,
            })
        }
        Some(query::kv_predicate_constraint::ConstraintView::FloatRange(v)) => {
            Ok(KvPredicateConstraint::FloatRange {
                min: v
                    .min
                    .as_option()
                    .map(|bound| (bound.value, bound.inclusive)),
                max: v
                    .max
                    .as_option()
                    .map(|bound| (bound.value, bound.inclusive)),
            })
        }
        Some(query::kv_predicate_constraint::ConstraintView::Decimal128Range(v)) => {
            let min = v
                .min
                .as_ref()
                .map(|raw| {
                    let bytes: [u8; 16] = (*raw)
                        .try_into()
                        .map_err(|_| "decimal128 min must be exactly 16 bytes".to_string())?;
                    Ok::<i128, String>(i128::from_be_bytes(bytes))
                })
                .transpose()?;
            let max = v
                .max
                .as_ref()
                .map(|raw| {
                    let bytes: [u8; 16] = (*raw)
                        .try_into()
                        .map_err(|_| "decimal128 max must be exactly 16 bytes".to_string())?;
                    Ok::<i128, String>(i128::from_be_bytes(bytes))
                })
                .transpose()?;
            Ok(KvPredicateConstraint::Decimal128Range { min, max })
        }
        Some(query::kv_predicate_constraint::ConstraintView::Decimal256Range(v)) => {
            let min = v
                .min
                .as_ref()
                .map(|raw| {
                    let bytes: [u8; 32] = (*raw)
                        .try_into()
                        .map_err(|_| "decimal256 min must be exactly 32 bytes".to_string())?;
                    Ok::<[u8; 32], String>(bytes)
                })
                .transpose()?;
            let max = v
                .max
                .as_ref()
                .map(|raw| {
                    let bytes: [u8; 32] = (*raw)
                        .try_into()
                        .map_err(|_| "decimal256 max must be exactly 32 bytes".to_string())?;
                    Ok::<[u8; 32], String>(bytes)
                })
                .transpose()?;
            Ok(KvPredicateConstraint::Decimal256Range { min, max })
        }
        Some(query::kv_predicate_constraint::ConstraintView::IsNull(_)) => {
            Ok(KvPredicateConstraint::IsNull)
        }
        Some(query::kv_predicate_constraint::ConstraintView::IsNotNull(_)) => {
            Ok(KvPredicateConstraint::IsNotNull)
        }
        Some(query::kv_predicate_constraint::ConstraintView::StringIn(v)) => Ok(
            KvPredicateConstraint::StringIn(v.values.iter().map(|s| s.to_string()).collect()),
        ),
        Some(query::kv_predicate_constraint::ConstraintView::IntIn(v)) => Ok(
            KvPredicateConstraint::IntIn(v.values.iter().copied().collect()),
        ),
        Some(query::kv_predicate_constraint::ConstraintView::Uint64In(v)) => Ok(
            KvPredicateConstraint::UInt64In(v.values.iter().copied().collect()),
        ),
        Some(query::kv_predicate_constraint::ConstraintView::FixedSizeBinaryIn(v)) => Ok(
            KvPredicateConstraint::FixedSizeBinaryIn(v.values.iter().map(|b| b.to_vec()).collect()),
        ),
        None => Err("missing predicate constraint".to_string()),
    }
}

fn to_domain_predicate_from_view(
    predicate: &query::KvPredicateView<'_>,
) -> Result<KvPredicate, String> {
    Ok(KvPredicate {
        checks: predicate
            .checks
            .iter()
            .map(|check| {
                Ok(KvPredicateCheck {
                    field: to_domain_field_ref_from_view(
                        check.field.as_option().ok_or("missing predicate field")?,
                    )?,
                    constraint: to_domain_predicate_constraint_from_view(
                        check
                            .constraint
                            .as_option()
                            .ok_or("missing predicate constraint")?,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        contradiction: predicate.contradiction,
    })
}

/// Decode [`RangeReduceRequest`] from a buffa [`ReduceParamsView`](query::ReduceParamsView), without
/// allocating an intermediate owned [`ReduceParams`](query::ReduceParams) via `to_owned_message`.
pub fn to_domain_reduce_request_from_view(
    request: &query::ReduceParamsView<'_>,
) -> Result<RangeReduceRequest, String> {
    Ok(RangeReduceRequest {
        reducers: request
            .reducers
            .iter()
            .map(|reducer| {
                let op = match reducer.op.as_known() {
                    Some(query::RangeReduceOp::RANGE_REDUCE_OP_COUNT_ALL) => {
                        RangeReduceOp::CountAll
                    }
                    Some(query::RangeReduceOp::RANGE_REDUCE_OP_COUNT_FIELD) => {
                        RangeReduceOp::CountField
                    }
                    Some(query::RangeReduceOp::RANGE_REDUCE_OP_SUM_FIELD) => {
                        RangeReduceOp::SumField
                    }
                    Some(query::RangeReduceOp::RANGE_REDUCE_OP_MIN_FIELD) => {
                        RangeReduceOp::MinField
                    }
                    Some(query::RangeReduceOp::RANGE_REDUCE_OP_MAX_FIELD) => {
                        RangeReduceOp::MaxField
                    }
                    _ => return Err("unsupported RangeReduceOp".to_string()),
                };
                Ok(RangeReducerSpec {
                    op,
                    expr: reducer
                        .expr
                        .as_option()
                        .map(to_domain_expr_from_view)
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        group_by: request
            .group_by
            .iter()
            .map(to_domain_expr_from_view)
            .collect::<Result<Vec<_>, _>>()?,
        filter: request
            .filter
            .as_option()
            .map(to_domain_predicate_from_view)
            .transpose()?,
    })
}

pub fn to_proto_reduce_response(
    response: RangeReduceResponse,
) -> (Vec<query::RangeReduceResult>, Vec<query::RangeReduceGroup>) {
    let results = response
        .results
        .into_iter()
        .map(|result| query::RangeReduceResult {
            value: result.value.map(to_proto_reduced_value).into(),
            ..Default::default()
        })
        .collect();
    let groups = response
        .groups
        .into_iter()
        .map(|group| query::RangeReduceGroup {
            group_values: group
                .group_values
                .iter()
                .filter_map(|value: &Option<KvReducedValue>| {
                    value.clone().map(to_proto_reduced_value)
                })
                .collect(),
            group_values_present: group.group_values.iter().map(Option::is_some).collect(),
            results: group
                .results
                .into_iter()
                .map(|result| query::RangeReduceResult {
                    value: result.value.map(to_proto_reduced_value).into(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
        .collect();
    (results, groups)
}

mod range_reduce_response;
pub use range_reduce_response::to_domain_reduce_response;

mod prune_policy_proto;
pub use prune_policy_proto::{
    prune_policies_to_proto, prune_policy_document_from_prune_request_view,
};

mod error_details;
pub use error_details::{
    decode_connect_error, with_bad_request_detail, with_error_info_detail, with_query_detail,
    with_retry_info_detail, DecodedConnectError,
};

mod query_detail_header;
pub use query_detail_header::{
    decode_query_detail_header_value, encode_query_detail_header_value,
    with_query_detail_response_header, with_query_detail_trailer, QUERY_DETAIL_RESPONSE_HEADER,
};

#[cfg(test)]
mod reduce_params_view_tests {
    use buffa::Message;
    use buffa::MessageView as _;

    use super::*;

    #[test]
    fn to_domain_reduce_request_from_view_matches_owned() {
        let proto = query::ReduceParams {
            reducers: vec![query::RangeReducerSpec {
                op: query::RangeReduceOp::RANGE_REDUCE_OP_COUNT_ALL.into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let encoded = proto.encode_to_vec();
        let view = query::ReduceParamsView::decode_view(&encoded).expect("decode view");
        let from_view = to_domain_reduce_request_from_view(&view).expect("from view");
        let from_owned = to_domain_reduce_request(&proto).expect("from owned");
        assert_eq!(from_view, from_owned);
    }
}
