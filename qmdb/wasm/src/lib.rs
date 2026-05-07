use crate::proto::qmdb::v1::{
    current_key_lookup_result, CurrentKeyExclusionProof, CurrentKeyValueProof,
    CurrentKeyValueProofView, CurrentOperationRangeProof, CurrentOperationRangeProofView,
    GetManyResponse, GetManyResponseView, GetRangeResponse, GetRangeResponseView,
    HistoricalMultiProof, HistoricalMultiProofView, HistoricalOperationRangeProof,
    HistoricalOperationRangeProofView,
};
use buffa::MessageView;
use commonware_codec::{Decode, DecodeExt, Encode, FixedSize, RangeCfg, Read};
use commonware_cryptography::{Digest, Sha256};
use commonware_storage::{
    merkle::{self, Location},
    mmb, mmr,
    qmdb::{
        any::{
            ordered::{variable::Operation as OrderedOperation, Update},
            value::VariableEncoding,
        },
        current::ordered::{db::KeyValueProof, ExclusionProof},
        current::proof::{OpsRootWitness, RangeProof},
        verify::{verify_multi_proof, verify_proof},
    },
};
use js_sys::{Array, BigInt, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

pub mod proto {
    pub mod qmdb {
        pub mod v1 {
            #![allow(non_camel_case_types)]
            #![allow(unused_imports)]
            #![allow(clippy::derivable_impls)]
            #![allow(clippy::match_single_binding)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../sdk-rs/src/gen/qmdb.v1.rs"
            ));
        }
    }

    pub mod store {
        pub mod common {
            pub mod v1 {
                #![allow(non_camel_case_types)]
                #![allow(unused_imports)]
                #![allow(clippy::derivable_impls)]
                #![allow(clippy::match_single_binding)]
                include!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../sdk-rs/src/gen/store.v1.common.rs"
                ));
            }
        }
    }
}

const MAX_OPERATION_SIZE: usize = u16::MAX as usize;

enum ExclusionBoundary {
    Span { start: Vec<u8>, end: Vec<u8> },
    Empty,
}

fn op_cfg<F>() -> <OrderedOperation<F, Vec<u8>, Vec<u8>> as Read>::Cfg
where
    F: merkle::Family,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    (
        ((0..=MAX_OPERATION_SIZE).into(), ()),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    )
}

fn js_err(message: impl Into<String>) -> JsValue {
    JsValue::from_str(&message.into())
}

fn decode_digest<D: Digest + DecodeExt<()>>(bytes: &[u8], label: &str) -> Result<D, String> {
    D::decode(bytes).map_err(|err| format!("failed to decode {label}: {err}"))
}

fn proof_digest_cap(encoded_proof: &[u8]) -> usize {
    encoded_proof.len() / commonware_cryptography::sha256::Digest::SIZE + 1
}

fn normalize_family<'a>(family: &'a str, label: &str) -> Result<&'a str, String> {
    match family {
        "mmr" | "mmb" => Ok(family),
        "" => Err(format!("{label} missing Merkle family")),
        other => Err(format!("{label} uses unsupported Merkle family {other}")),
    }
}

fn historical_target_root(
    ops_root: &[u8],
    ops_root_witness: &[u8],
    expected_root: &commonware_cryptography::sha256::Digest,
) -> Result<commonware_cryptography::sha256::Digest, String> {
    match (ops_root.is_empty(), ops_root_witness.is_empty()) {
        (true, true) => Ok(*expected_root),
        (false, false) => {
            let ops_root = decode_digest(ops_root, "historical ops root")?;
            let witness = OpsRootWitness::<commonware_cryptography::sha256::Digest>::decode_cfg(
                ops_root_witness,
                &(),
            )
            .map_err(|err| format!("failed to decode historical ops-root witness: {err}"))?;
            let mut hasher = commonware_storage::qmdb::hasher::<Sha256>();
            if !witness.verify(&mut hasher, &ops_root, expected_root) {
                return Err("historical ops-root witness failed verification".to_string());
            }
            Ok(ops_root)
        }
        _ => Err(
            "historical proof must include both ops_root and ops_root_witness, or neither"
                .to_string(),
        ),
    }
}

fn verify_multi_from_proto<F>(
    proto: &HistoricalMultiProof,
    root: &commonware_cryptography::sha256::Digest,
) -> Result<Vec<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>)>, String>
where
    F: merkle::Family,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    let operations = proto
        .operations
        .iter()
        .map(|operation| {
            Ok((
                Location::new(operation.location),
                OrderedOperation::<F, Vec<u8>, Vec<u8>>::decode_cfg(
                    operation.encoded_operation.as_slice(),
                    &op_cfg::<F>(),
                )
                .map_err(|err| {
                    format!(
                        "failed to decode multi-proof operation at {}: {err}",
                        operation.location
                    )
                })?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let target_root = historical_target_root(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap(&proto.proof);
    let proof = merkle::Proof::<F, commonware_cryptography::sha256::Digest>::decode_cfg(
        proto.proof.as_slice(),
        &max_digests,
    )
    .map_err(|err| format!("failed to decode historical multi proof: {err}"))?;
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    if !verify_multi_proof(&hasher, &proof, &operations, &target_root) {
        return Err("historical multi proof failed verification".to_string());
    }
    Ok(operations)
}

fn verify_operation_range_from_proto<F>(
    proto: &HistoricalOperationRangeProof,
    root: &commonware_cryptography::sha256::Digest,
) -> Result<Vec<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>)>, String>
where
    F: merkle::Family,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    if proto.encoded_operations.is_empty() {
        return Err("historical operation range proof has no operations".to_string());
    }
    let target_root = historical_target_root(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap(&proto.proof);
    let proof = merkle::Proof::<F, commonware_cryptography::sha256::Digest>::decode_cfg(
        proto.proof.as_slice(),
        &max_digests,
    )
    .map_err(|err| format!("failed to decode historical operation range proof: {err}"))?;
    let start = Location::new(proto.start_location);
    let operations = proto
        .encoded_operations
        .iter()
        .enumerate()
        .map(|(offset, bytes)| {
            let offset = u64::try_from(offset)
                .map_err(|err| format!("operation range offset overflow: {err}"))?;
            let location = Location::new(
                proto
                    .start_location
                    .checked_add(offset)
                    .ok_or_else(|| "operation range location overflow".to_string())?,
            );
            let operation = OrderedOperation::<F, Vec<u8>, Vec<u8>>::decode_cfg(
                bytes.as_slice(),
                &op_cfg::<F>(),
            )
            .map_err(|err| {
                format!(
                    "failed to decode operation range entry at {}: {err}",
                    *location
                )
            })?;
            Ok((location, operation))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let ordered_operations = operations
        .iter()
        .map(|(_, operation)| operation.clone())
        .collect::<Vec<_>>();
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    if !verify_proof(&hasher, &proof, start, &ordered_operations, &target_root) {
        return Err("historical operation range proof failed verification".to_string());
    }
    Ok(operations)
}

fn verify_current_operation_range_from_proto<F>(
    proto: &CurrentOperationRangeProof,
    root: &commonware_cryptography::sha256::Digest,
) -> Result<Vec<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>)>, String>
where
    F: merkle::Graftable,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    if proto.encoded_operations.is_empty() {
        return Err("current operation range proof has no operations".to_string());
    }
    if proto.chunks.is_empty() {
        return Err("current operation range proof has no chunks".to_string());
    }
    let max_digests = proof_digest_cap(&proto.proof);
    let proof = RangeProof::<F, commonware_cryptography::sha256::Digest>::decode_cfg(
        proto.proof.as_slice(),
        &max_digests,
    )
    .map_err(|err| format!("failed to decode current operation range proof: {err}"))?;
    let start = Location::new(proto.start_location);
    let operations = proto
        .encoded_operations
        .iter()
        .enumerate()
        .map(|(offset, bytes)| {
            let offset = u64::try_from(offset)
                .map_err(|err| format!("operation range offset overflow: {err}"))?;
            let location = Location::new(
                proto
                    .start_location
                    .checked_add(offset)
                    .ok_or_else(|| "operation range location overflow".to_string())?,
            );
            let operation = OrderedOperation::<F, Vec<u8>, Vec<u8>>::decode_cfg(
                bytes.as_slice(),
                &op_cfg::<F>(),
            )
            .map_err(|err| {
                format!(
                    "failed to decode current operation range entry at {}: {err}",
                    *location
                )
            })?;
            Ok((location, operation))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let ordered_operations = operations
        .iter()
        .map(|(_, operation)| operation.clone())
        .collect::<Vec<_>>();
    let chunks = proto
        .chunks
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            if bytes.len() != 32 {
                return Err(format!(
                    "current operation range chunk {index} has invalid length {}",
                    bytes.len()
                ));
            }
            let mut chunk = [0u8; 32];
            chunk.copy_from_slice(bytes);
            Ok(chunk)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut hasher = Sha256::default();
    if !proof.verify(&mut hasher, start, &ordered_operations, &chunks, root) {
        return Err("current operation range proof failed verification".to_string());
    }
    Ok(operations)
}

fn verify_key_value_from_proto<F>(
    proto: &CurrentKeyValueProof,
    root: &commonware_cryptography::sha256::Digest,
) -> Result<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>), String>
where
    F: merkle::Graftable,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    let operation = OrderedOperation::<F, Vec<u8>, Vec<u8>>::decode_cfg(
        proto.encoded_operation.as_slice(),
        &op_cfg::<F>(),
    )
    .map_err(|err| format!("failed to decode current key-value operation: {err}"))?;
    let OrderedOperation::Update(update) = &operation else {
        return Err("current key-value proof operation must be an update".to_string());
    };
    let max_digests = proof_digest_cap(&proto.proof);
    let proof =
        KeyValueProof::<F, Vec<u8>, commonware_cryptography::sha256::Digest, 32>::decode_cfg(
            proto.proof.as_slice(),
            &(max_digests, ((0..=MAX_OPERATION_SIZE).into(), ())),
        )
        .map_err(|err| format!("failed to decode current key-value proof: {err}"))?;
    if proof.next_key != update.next_key {
        return Err("current key-value proof next_key mismatch".to_string());
    }
    let mut hasher = Sha256::default();
    if !proof.proof.verify(&mut hasher, operation.clone(), root) {
        return Err("current key-value proof failed verification".to_string());
    }
    Ok((proof.proof.loc, operation))
}

fn verify_key_exclusion_from_proto<F>(
    proto: &CurrentKeyExclusionProof,
    requested_key: &[u8],
    current_root: &commonware_cryptography::sha256::Digest,
) -> Result<ExclusionBoundary, String>
where
    F: merkle::Graftable,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    let max_digests = proof_digest_cap(&proto.proof);
    let proof = ExclusionProof::<
        F,
        Vec<u8>,
        VariableEncoding<Vec<u8>>,
        commonware_cryptography::sha256::Digest,
        32,
    >::decode_cfg(
        proto.proof.as_slice(),
        &(
            max_digests,
            op_cfg::<F>(),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
    )
    .map_err(|err| format!("failed to decode current key-exclusion proof: {err}"))?;
    let (op_proof, operation, boundary) = match proof {
        ExclusionProof::KeyValue(op_proof, update) => {
            let span_start = update.key.as_slice();
            let span_end = update.next_key.as_slice();
            if span_start == requested_key {
                return Err("current key-exclusion proof starts at requested key".to_string());
            }
            let in_span = if span_start >= span_end {
                requested_key >= span_start || requested_key < span_end
            } else {
                requested_key >= span_start && requested_key < span_end
            };
            if !in_span {
                return Err("current key-exclusion proof does not cover requested key".to_string());
            }
            let boundary = ExclusionBoundary::Span {
                start: update.key.clone(),
                end: update.next_key.clone(),
            };
            (op_proof, OrderedOperation::Update(update), boundary)
        }
        ExclusionProof::Commit(op_proof, value) => {
            let floor = op_proof.loc;
            (
                op_proof,
                OrderedOperation::CommitFloor(value, floor),
                ExclusionBoundary::Empty,
            )
        }
    };
    let mut hasher = Sha256::default();
    if !op_proof.verify(&mut hasher, operation, current_root) {
        return Err("current key-exclusion proof failed verification".to_string());
    }
    Ok(boundary)
}

fn set_field(target: &Object, key: &str, value: &JsValue) -> Result<(), JsValue> {
    Reflect::set(target, &JsValue::from_str(key), value)
        .map(|_| ())
        .map_err(|err| js_err(format!("set {key}: {:?}", err)))
}

fn bytes_to_js(bytes: &[u8]) -> JsValue {
    let array = Uint8Array::new_with_length(bytes.len() as u32);
    array.copy_from(bytes);
    array.into()
}

fn u64_to_bigint(value: u64) -> Result<JsValue, JsValue> {
    BigInt::new(&JsValue::from_str(&value.to_string()))
        .map(Into::into)
        .map_err(|err| js_err(format!("bigint conversion failed for {value}: {:?}", err)))
}

fn location_to_bigint<F: merkle::Family>(location: Location<F>) -> Result<JsValue, JsValue> {
    u64_to_bigint(*location)
}

fn to_js_operation<F: merkle::Family>(
    operation: OrderedOperation<F, Vec<u8>, Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let object = Object::new();
    match operation {
        OrderedOperation::Update(Update {
            key,
            value,
            next_key,
        }) => {
            set_field(&object, "type", &JsValue::from_str("update"))?;
            set_field(&object, "key", &bytes_to_js(&key))?;
            set_field(&object, "value", &bytes_to_js(&value))?;
            set_field(&object, "nextKey", &bytes_to_js(&next_key))?;
        }
        OrderedOperation::Delete(key) => {
            set_field(&object, "type", &JsValue::from_str("delete"))?;
            set_field(&object, "key", &bytes_to_js(&key))?;
        }
        OrderedOperation::CommitFloor(value, floor_location) => {
            set_field(&object, "type", &JsValue::from_str("commit_floor"))?;
            if let Some(value) = value {
                set_field(&object, "value", &bytes_to_js(&value))?;
            }
            set_field(&object, "floorLocation", &u64_to_bigint(*floor_location)?)?;
        }
    }
    Ok(object.into())
}

fn historical_to_js<F>(
    decoded_operations: Vec<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>)>,
) -> Result<JsValue, JsValue>
where
    F: merkle::Family,
{
    let operations = Array::new();
    for (location, operation) in decoded_operations {
        let entry = Object::new();
        set_field(&entry, "location", &location_to_bigint(location)?)?;
        set_field(&entry, "operation", &to_js_operation(operation)?)?;
        operations.push(&entry.into());
    }
    let verified = Object::new();
    set_field(&verified, "operations", &operations.into())?;
    Ok(verified.into())
}

fn lookup_results_to_js<F>(
    proto: &GetManyResponse,
    current_root: &commonware_cryptography::sha256::Digest,
) -> Result<JsValue, JsValue>
where
    F: merkle::Graftable,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    let results = Array::new();
    for result in &proto.results {
        let entry = Object::new();
        set_field(&entry, "key", &bytes_to_js(&result.key))?;
        match result
            .result
            .as_ref()
            .ok_or_else(|| js_err("getMany result missing hit/miss proof"))?
        {
            current_key_lookup_result::Result::Hit(proof) => {
                let (location, operation) =
                    verify_key_value_from_proto::<F>(proof, current_root).map_err(js_err)?;
                set_field(&entry, "type", &JsValue::from_str("hit"))?;
                set_field(&entry, "location", &location_to_bigint(location)?)?;
                set_field(&entry, "operation", &to_js_operation(operation)?)?;
            }
            current_key_lookup_result::Result::Miss(proof) => {
                verify_key_exclusion_from_proto::<F>(proof, &result.key, current_root)
                    .map_err(js_err)?;
                set_field(&entry, "type", &JsValue::from_str("miss"))?;
            }
        }
        results.push(&entry.into());
    }
    let verified = Object::new();
    set_field(&verified, "results", &results.into())?;
    Ok(verified.into())
}

fn span_contains_key(span_start: &[u8], span_end: &[u8], key: &[u8]) -> bool {
    if span_start >= span_end {
        key >= span_start || key < span_end
    } else {
        key >= span_start && key < span_end
    }
}

fn verify_get_range_from_proto<F>(
    proto: &GetRangeResponse,
    current_root: &commonware_cryptography::sha256::Digest,
    start_key: &[u8],
    end_key: Option<&[u8]>,
) -> Result<JsValue, JsValue>
where
    F: merkle::Graftable,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    let mut decoded = Vec::<(Vec<u8>, Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>)>::new();
    for entry in &proto.entries {
        let proof = entry
            .proof
            .as_option()
            .ok_or_else(|| js_err("getRange entry missing proof"))?;
        let (location, operation) =
            verify_key_value_from_proto::<F>(proof, current_root).map_err(js_err)?;
        let OrderedOperation::Update(update) = &operation else {
            return Err(js_err("getRange entry proof did not verify an update"));
        };
        if update.key.as_slice() != entry.key.as_slice() {
            return Err(js_err("getRange entry key does not match proof operation"));
        }
        decoded.push((entry.key.clone(), location, operation));
    }

    if let Some((first_key, _, _)) = decoded.first() {
        if first_key.as_slice() != start_key {
            let start_proof = proto
                .start_proof
                .as_option()
                .ok_or_else(|| js_err("getRange response missing start boundary proof"))?;
            match verify_key_exclusion_from_proto::<F>(start_proof, start_key, current_root)
                .map_err(js_err)?
            {
                ExclusionBoundary::Span { end, .. } if end.as_slice() == first_key.as_slice() => {}
                ExclusionBoundary::Span { .. } => {
                    return Err(js_err("getRange start boundary does not reach first entry"));
                }
                ExclusionBoundary::Empty => {
                    return Err(js_err(
                        "getRange start boundary proves empty DB with entries",
                    ));
                }
            }
        }
    } else {
        let start_proof = proto
            .start_proof
            .as_option()
            .ok_or_else(|| js_err("empty getRange response missing start boundary proof"))?;
        let boundary = verify_key_exclusion_from_proto::<F>(start_proof, start_key, current_root)
            .map_err(js_err)?;
        match (end_key, boundary) {
            (Some(end_key), ExclusionBoundary::Span { start, end }) => {
                if !span_contains_key(&start, &end, end_key) && end.as_slice() != end_key {
                    return Err(js_err(
                        "empty getRange boundary does not cover requested end",
                    ));
                }
            }
            (None, ExclusionBoundary::Span { end, .. }) if end.as_slice() > start_key => {
                return Err(js_err(
                    "empty unbounded getRange boundary does not reach ordered end",
                ));
            }
            _ => {}
        }
    }

    for pair in decoded.windows(2) {
        let OrderedOperation::Update(left) = &pair[0].2 else {
            return Err(js_err("getRange entry is not an update"));
        };
        if left.next_key.as_slice() != pair[1].0.as_slice() {
            return Err(js_err("getRange entries are not connected by next_key"));
        }
    }

    if proto.has_more {
        let Some((_, _, OrderedOperation::Update(last))) = decoded.last() else {
            return Err(js_err("truncated getRange response has no final entry"));
        };
        if proto.next_start_key.as_slice() != last.next_key.as_slice() {
            return Err(js_err(
                "getRange next_start_key does not match last next_key",
            ));
        }
    } else if let Some((first_key, _, _)) = decoded.first() {
        let Some((last_key, _, OrderedOperation::Update(last))) = decoded.last() else {
            return Err(js_err("getRange final entry is not an update"));
        };
        if let Some(end_key) = end_key {
            if last.next_key.as_slice() != end_key
                && !span_contains_key(last_key, &last.next_key, end_key)
            {
                return Err(js_err("complete getRange response does not reach end_key"));
            }
        } else if last.next_key.as_slice() > first_key.as_slice() {
            return Err(js_err(
                "complete unbounded getRange response does not reach ordered end",
            ));
        }
    }

    let entries = Array::new();
    for (key, location, operation) in decoded {
        let entry = Object::new();
        set_field(&entry, "key", &bytes_to_js(&key))?;
        set_field(&entry, "location", &location_to_bigint(location)?)?;
        set_field(&entry, "operation", &to_js_operation(operation)?)?;
        entries.push(&entry.into());
    }

    let verified = Object::new();
    set_field(&verified, "entries", &entries.into())?;
    set_field(&verified, "hasMore", &JsValue::from_bool(proto.has_more))?;
    set_field(
        &verified,
        "nextStartKey",
        &bytes_to_js(&proto.next_start_key),
    )?;
    Ok(verified.into())
}

fn current_to_js<F>(
    location: Location<F>,
    operation: OrderedOperation<F, Vec<u8>, Vec<u8>>,
) -> Result<JsValue, JsValue>
where
    F: merkle::Family,
{
    let verified = Object::new();
    set_field(&verified, "location", &location_to_bigint(location)?)?;
    set_field(&verified, "operation", &to_js_operation(operation)?)?;
    Ok(verified.into())
}

#[wasm_bindgen]
pub fn verify_historical_multi_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
) -> Result<JsValue, JsValue> {
    let proto = HistoricalMultiProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical multi proof: {err}")))?
        .to_owned_message();
    let root = decode_digest(root, "historical proof root").map_err(js_err)?;
    match normalize_family(merkle_family, "historical multi proof").map_err(js_err)? {
        "mmr" => {
            historical_to_js(verify_multi_from_proto::<mmr::Family>(&proto, &root).map_err(js_err)?)
        }
        "mmb" => {
            historical_to_js(verify_multi_from_proto::<mmb::Family>(&proto, &root).map_err(js_err)?)
        }
        _ => unreachable!("normalize_family only returns supported values"),
    }
}

#[wasm_bindgen]
pub fn verify_historical_operation_range_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
) -> Result<JsValue, JsValue> {
    let proto = HistoricalOperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical operation range proof: {err}")))?
        .to_owned_message();
    let root = decode_digest(root, "historical operation range root").map_err(js_err)?;
    match normalize_family(merkle_family, "historical operation range proof").map_err(js_err)? {
        "mmr" => historical_to_js(
            verify_operation_range_from_proto::<mmr::Family>(&proto, &root).map_err(js_err)?,
        ),
        "mmb" => historical_to_js(
            verify_operation_range_from_proto::<mmb::Family>(&proto, &root).map_err(js_err)?,
        ),
        _ => unreachable!("normalize_family only returns supported values"),
    }
}

#[wasm_bindgen]
pub fn verify_current_operation_range_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
) -> Result<JsValue, JsValue> {
    let proto = CurrentOperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode current operation range proof: {err}")))?
        .to_owned_message();
    let root = decode_digest(root, "current operation range root").map_err(js_err)?;
    match normalize_family(merkle_family, "current operation range proof").map_err(js_err)? {
        "mmr" => historical_to_js(
            verify_current_operation_range_from_proto::<mmr::Family>(&proto, &root)
                .map_err(js_err)?,
        ),
        "mmb" => historical_to_js(
            verify_current_operation_range_from_proto::<mmb::Family>(&proto, &root)
                .map_err(js_err)?,
        ),
        _ => unreachable!("normalize_family only returns supported values"),
    }
}

#[wasm_bindgen]
pub fn verify_current_key_value_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
) -> Result<JsValue, JsValue> {
    let proto = CurrentKeyValueProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode current key-value proof: {err}")))?
        .to_owned_message();
    let root = decode_digest(root, "current root").map_err(js_err)?;
    match normalize_family(merkle_family, "current key-value proof").map_err(js_err)? {
        "mmr" => {
            let (location, operation) =
                verify_key_value_from_proto::<mmr::Family>(&proto, &root).map_err(js_err)?;
            current_to_js(location, operation)
        }
        "mmb" => {
            let (location, operation) =
                verify_key_value_from_proto::<mmb::Family>(&proto, &root).map_err(js_err)?;
            current_to_js(location, operation)
        }
        _ => unreachable!("normalize_family only returns supported values"),
    }
}

#[wasm_bindgen]
pub fn verify_get_many_response(
    bytes: &[u8],
    current_root: &[u8],
    merkle_family: &str,
) -> Result<JsValue, JsValue> {
    let proto = GetManyResponseView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode getMany response: {err}")))?
        .to_owned_message();
    let current_root = decode_digest(current_root, "current root").map_err(js_err)?;
    match normalize_family(merkle_family, "getMany response").map_err(js_err)? {
        "mmr" => lookup_results_to_js::<mmr::Family>(&proto, &current_root),
        "mmb" => lookup_results_to_js::<mmb::Family>(&proto, &current_root),
        _ => unreachable!("normalize_family only returns supported values"),
    }
}

#[wasm_bindgen]
pub fn verify_get_range_response(
    bytes: &[u8],
    current_root: &[u8],
    merkle_family: &str,
    start_key: &[u8],
    end_key: &[u8],
    has_end_key: bool,
) -> Result<JsValue, JsValue> {
    let proto = GetRangeResponseView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode getRange response: {err}")))?
        .to_owned_message();
    let current_root = decode_digest(current_root, "current root").map_err(js_err)?;
    let end_key = has_end_key.then_some(end_key);
    match normalize_family(merkle_family, "getRange response").map_err(js_err)? {
        "mmr" => {
            verify_get_range_from_proto::<mmr::Family>(&proto, &current_root, start_key, end_key)
        }
        "mmb" => {
            verify_get_range_from_proto::<mmb::Family>(&proto, &current_root, start_key, end_key)
        }
        _ => unreachable!("normalize_family only returns supported values"),
    }
}
