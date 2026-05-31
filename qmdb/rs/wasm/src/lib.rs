#![allow(clippy::type_complexity)]

use crate::proto::qmdb::v1::{
    current_key_lookup_result, CurrentKeyExclusionProof, CurrentKeyValueProof,
    CurrentKeyValueProofView, CurrentOperationRangeProof, CurrentOperationRangeProofView,
    GetManyResponse, GetManyResponseView, GetRangeResponse, GetRangeResponseView,
    HistoricalMultiProof, HistoricalMultiProofView, HistoricalOperationRangeProof,
    HistoricalOperationRangeProofView,
};
use buffa::MessageView;
use commonware_codec::{
    Decode, DecodeExt, DecodeRangeExt, Encode, EncodeSize, FixedSize, RangeCfg, Read, Write,
};
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
        verify::{verify_multi_proof, verify_proof_and_pinned_nodes},
    },
};
use js_sys::{Array, BigInt, Object, Reflect, Uint8Array};
use std::collections::BTreeSet;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

pub mod proto;

const MAX_OPERATION_SIZE: usize = u16::MAX as usize;
const KEYLESS_APPEND_CONTEXT: u8 = 1;
const ANY_DELETE_CONTEXT: u8 = 0xD1;
const ANY_UPDATE_CONTEXT: u8 = 0xD2;
const ANY_COMMIT_CONTEXT: u8 = 0xD3;

#[derive(Clone, Copy)]
struct RawOperation<'a>(&'a [u8]);

impl Write for RawOperation<'_> {
    fn write(&self, buf: &mut impl commonware_runtime::BufMut) {
        buf.put_slice(self.0);
    }
}

impl EncodeSize for RawOperation<'_> {
    fn encode_size(&self) -> usize {
        self.0.len()
    }
}

fn encode_vec_key_wire(key: &[u8]) -> Vec<u8> {
    key.encode().to_vec()
}

fn decode_vec_key_wire(encoded_key: &[u8]) -> Result<Vec<u8>, String> {
    Vec::<u8>::decode_range(encoded_key, 0..=MAX_OPERATION_SIZE)
        .map_err(|err| format!("failed to decode QMDB key: {err}"))
}

enum ExclusionBoundary {
    Span { start: Vec<u8>, end: Vec<u8> },
    Empty,
}

type OrderedCurrentDb<F> = commonware_storage::qmdb::current::ordered::variable::Db<
    F,
    commonware_runtime::deterministic::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    commonware_storage::translator::TwoCap,
    32,
    commonware_parallel::Sequential,
>;

fn op_cfg<F>() -> <OrderedOperation<F, Vec<u8>, Vec<u8>> as Read>::Cfg
where
    F: merkle::Graftable,
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

fn historical_target_root<F: merkle::Graftable>(
    ops_root: &[u8],
    ops_root_witness: &[u8],
    expected_root: &commonware_cryptography::sha256::Digest,
) -> Result<commonware_cryptography::sha256::Digest, String> {
    match (ops_root.is_empty(), ops_root_witness.is_empty()) {
        (true, true) => Ok(*expected_root),
        (false, true) => {
            let ops_root = decode_digest(ops_root, "historical ops root")?;
            if ops_root != *expected_root {
                return Err("historical ops root did not match expected root".to_string());
            }
            Ok(ops_root)
        }
        (false, false) => {
            let ops_root = decode_digest(ops_root, "historical ops root")?;
            let witness = OpsRootWitness::<F, commonware_cryptography::sha256::Digest>::decode(
                ops_root_witness,
            )
            .map_err(|err| format!("failed to decode historical ops-root witness: {err}"))?;
            let hasher = commonware_storage::qmdb::hasher::<Sha256>();
            if !witness.verify(&hasher, &ops_root, expected_root) {
                return Err("historical ops-root witness failed verification".to_string());
            }
            Ok(ops_root)
        }
        (true, false) => Err("historical proof missing ops_root for ops_root_witness".to_string()),
    }
}

fn verify_multi_from_proto<F>(
    proto: &HistoricalMultiProof,
    root: &commonware_cryptography::sha256::Digest,
) -> Result<
    (
        commonware_cryptography::sha256::Digest,
        Vec<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>)>,
    ),
    String,
>
where
    F: merkle::Graftable,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    let operations = decode_multi_operations_from_proto::<F>(proto)?;
    let target_root = historical_target_root::<F>(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap(&proto.proof);
    let proof = merkle::Proof::<F, commonware_cryptography::sha256::Digest>::decode_cfg(
        proto.proof.as_ref(),
        &max_digests,
    )
    .map_err(|err| format!("failed to decode historical multi proof: {err}"))?;
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    if !verify_multi_proof(&hasher, &proof, &operations, &target_root) {
        return Err("historical multi proof failed verification".to_string());
    }
    Ok((*root, operations))
}

fn decode_multi_with_embedded_root_from_proto<F>(
    proto: &HistoricalMultiProof,
) -> Result<
    (
        commonware_cryptography::sha256::Digest,
        Vec<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>)>,
    ),
    String,
>
where
    F: merkle::Graftable,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    let operations = decode_multi_operations_from_proto::<F>(proto)?;
    if proto.ops_root.is_empty() {
        return Err("historical multi proof missing embedded ops_root".to_string());
    }
    let ops_root = decode_digest(&proto.ops_root, "historical multi proof ops root")?;
    let max_digests = proof_digest_cap(&proto.proof);
    let proof = merkle::Proof::<F, commonware_cryptography::sha256::Digest>::decode_cfg(
        proto.proof.as_ref(),
        &max_digests,
    )
    .map_err(|err| format!("failed to decode historical multi proof: {err}"))?;
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    if !verify_multi_proof(&hasher, &proof, &operations, &ops_root) {
        return Err("historical multi proof failed verification".to_string());
    }
    if proto.ops_root_witness.is_empty() {
        return Ok((ops_root, operations));
    }
    let witness = OpsRootWitness::<F, commonware_cryptography::sha256::Digest>::decode(
        proto.ops_root_witness.as_ref(),
    )
    .map_err(|err| format!("failed to decode historical multi proof ops-root witness: {err}"))?;
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    Ok((witness.root(&hasher, &ops_root), operations))
}

fn decode_multi_operations_from_proto<F>(
    proto: &HistoricalMultiProof,
) -> Result<Vec<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>)>, String>
where
    F: merkle::Graftable,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    proto
        .operations
        .iter()
        .map(|operation| {
            Ok((
                Location::new(operation.location),
                OrderedOperation::<F, Vec<u8>, Vec<u8>>::decode_cfg(
                    operation.encoded_operation.as_ref(),
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
        .collect()
}

fn verify_operation_range_from_proto<F>(
    proto: &HistoricalOperationRangeProof,
    root: &commonware_cryptography::sha256::Digest,
) -> Result<
    (
        commonware_cryptography::sha256::Digest,
        Vec<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>)>,
    ),
    String,
>
where
    F: merkle::Graftable,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    if proto.encoded_operations.is_empty() {
        return Err("historical operation range proof has no operations".to_string());
    }
    let target_root = historical_target_root::<F>(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap(&proto.proof);
    let proof = merkle::Proof::<F, commonware_cryptography::sha256::Digest>::decode_cfg(
        proto.proof.as_ref(),
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
            let operation =
                OrderedOperation::<F, Vec<u8>, Vec<u8>>::decode_cfg(bytes.as_ref(), &op_cfg::<F>())
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
    let pinned_nodes = proto
        .pinned_nodes
        .iter()
        .map(|bytes| {
            decode_digest::<commonware_cryptography::sha256::Digest>(
                bytes.as_ref(),
                "historical operation range pinned node",
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    if !verify_proof_and_pinned_nodes(
        &hasher,
        &proof,
        start,
        &ordered_operations,
        &pinned_nodes,
        &target_root,
    ) {
        return Err("historical operation range proof failed verification".to_string());
    }
    Ok((*root, operations))
}

fn verify_raw_operation_range_from_proto<F>(
    proto: &HistoricalOperationRangeProof,
    root: &commonware_cryptography::sha256::Digest,
) -> Result<
    (
        commonware_cryptography::sha256::Digest,
        merkle::Proof<F, commonware_cryptography::sha256::Digest>,
        Vec<(Location<F>, Vec<u8>)>,
    ),
    String,
>
where
    F: merkle::Graftable,
{
    if proto.encoded_operations.is_empty() {
        return Err("historical operation range proof has no operations".to_string());
    }
    let target_root = historical_target_root::<F>(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap(&proto.proof);
    let proof = merkle::Proof::<F, commonware_cryptography::sha256::Digest>::decode_cfg(
        proto.proof.as_ref(),
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
            Ok((location, bytes.to_vec()))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let raw_operations = proto
        .encoded_operations
        .iter()
        .map(|bytes| RawOperation(bytes.as_ref()))
        .collect::<Vec<_>>();
    let pinned_nodes = proto
        .pinned_nodes
        .iter()
        .map(|bytes| {
            decode_digest::<commonware_cryptography::sha256::Digest>(
                bytes.as_ref(),
                "historical operation range pinned node",
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    if !verify_proof_and_pinned_nodes(
        &hasher,
        &proof,
        start,
        &raw_operations,
        &pinned_nodes,
        &target_root,
    ) {
        return Err("historical operation range proof failed verification".to_string());
    }
    Ok((*root, proof, operations))
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
        proto.proof.as_ref(),
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
            let operation =
                OrderedOperation::<F, Vec<u8>, Vec<u8>>::decode_cfg(bytes.as_ref(), &op_cfg::<F>())
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
            <[u8; 32]>::decode(bytes.as_ref())
                .map_err(|err| format!("current operation range chunk {index} decode error: {err}"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    if !proof.verify(&hasher, start, &ordered_operations, &chunks, root) {
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
        proto.encoded_operation.as_ref(),
        &op_cfg::<F>(),
    )
    .map_err(|err| format!("failed to decode current key-value operation: {err}"))?;
    let OrderedOperation::Update(update) = &operation else {
        return Err("current key-value proof operation must be an update".to_string());
    };
    let max_digests = proof_digest_cap(&proto.proof);
    let proof =
        KeyValueProof::<F, Vec<u8>, commonware_cryptography::sha256::Digest, 32>::decode_cfg(
            proto.proof.as_ref(),
            &(max_digests, ((0..=MAX_OPERATION_SIZE).into(), ())),
        )
        .map_err(|err| format!("failed to decode current key-value proof: {err}"))?;
    if proof.next_key != update.next_key {
        return Err("current key-value proof next_key mismatch".to_string());
    }
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    if !OrderedCurrentDb::<F>::verify_key_value_proof(
        &hasher,
        update.key.clone(),
        update.value.clone(),
        &proof,
        root,
    ) {
        return Err("current key-value proof failed verification".to_string());
    }
    Ok((proof.proof.loc, operation))
}

fn verify_key_value_for_key_from_proto<F>(
    proto: &CurrentKeyValueProof,
    requested_key: &[u8],
    root: &commonware_cryptography::sha256::Digest,
) -> Result<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>), String>
where
    F: merkle::Graftable,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    let requested_key = decode_vec_key_wire(requested_key)?;
    let (location, operation) = verify_key_value_from_proto::<F>(proto, root)?;
    let OrderedOperation::Update(update) = &operation else {
        return Err("current key-value proof operation must be an update".to_string());
    };
    if update.key.as_slice() != requested_key.as_slice() {
        return Err("current key-value proof key mismatch".to_string());
    }
    Ok((location, operation))
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
        proto.proof.as_ref(),
        &(
            max_digests,
            op_cfg::<F>(),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
    )
    .map_err(|err| format!("failed to decode current key-exclusion proof: {err}"))?;
    let requested_key = decode_vec_key_wire(requested_key)?;
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    if !OrderedCurrentDb::<F>::verify_exclusion_proof(&hasher, &requested_key, &proof, current_root)
    {
        return Err("current key-exclusion proof failed verification".to_string());
    }
    let boundary = match proof {
        ExclusionProof::KeyValue(_, update) => ExclusionBoundary::Span {
            start: update.key,
            end: update.next_key,
        },
        ExclusionProof::Commit(_, _) => ExclusionBoundary::Empty,
    };
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

fn js_key_array_to_vec(keys: Array) -> Result<Vec<Vec<u8>>, JsValue> {
    keys.iter()
        .enumerate()
        .map(|(index, value)| {
            let Some(bytes) = value.dyn_ref::<Uint8Array>() else {
                return Err(js_err(format!(
                    "requested key {index} must be a Uint8Array"
                )));
            };
            Ok(bytes.to_vec())
        })
        .collect()
}

fn validate_requested_keys(requested_keys: &[Vec<u8>]) -> Result<(), String> {
    let mut seen = BTreeSet::<&[u8]>::new();
    for key in requested_keys {
        if !seen.insert(key.as_slice()) {
            return Err("getMany requested duplicate key".to_string());
        }
    }
    Ok(())
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
    root: commonware_cryptography::sha256::Digest,
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
    set_field(&verified, "root", &bytes_to_js(root.as_ref()))?;
    set_field(&verified, "operations", &operations.into())?;
    Ok(verified.into())
}

fn operations_to_js<F>(
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

fn raw_operations_to_js<F>(
    root: commonware_cryptography::sha256::Digest,
    proof_size_bytes: usize,
    raw_operations: Vec<(Location<F>, Vec<u8>)>,
) -> Result<JsValue, JsValue>
where
    F: merkle::Family,
{
    let operations = Array::new();
    for (location, encoded_operation) in raw_operations {
        let entry = Object::new();
        set_field(&entry, "location", &location_to_bigint(location)?)?;
        set_field(&entry, "encodedOperation", &bytes_to_js(&encoded_operation))?;
        operations.push(&entry.into());
    }
    let verified = Object::new();
    set_field(&verified, "root", &bytes_to_js(root.as_ref()))?;
    set_field(&verified, "operations", &operations.into())?;
    set_field(
        &verified,
        "proofSizeBytes",
        &JsValue::from_f64(proof_size_bytes as f64),
    )?;
    Ok(verified.into())
}

fn expected_raw_operation<F>(
    start_location: u64,
    operations: &[(Location<F>, Vec<u8>)],
    expected_location: u64,
    label: &str,
) -> Result<Vec<u8>, String>
where
    F: merkle::Family,
{
    let offset = expected_location
        .checked_sub(start_location)
        .ok_or_else(|| format!("expected {label} location is before proof range"))?;
    let offset = usize::try_from(offset)
        .map_err(|_| format!("expected {label} location does not fit usize"))?;
    let Some((_, operation)) = operations.get(offset) else {
        return Err(format!("expected {label} location is outside proof range"));
    };
    Ok(operation.clone())
}

fn ensure_zero_padding(bytes: &[u8], label: &str) -> Result<(), String> {
    if bytes.iter().any(|byte| *byte != 0) {
        return Err(format!("{label} padding was non-zero"));
    }
    Ok(())
}

fn fixed_keyless_append_value<'a>(
    operation: &'a [u8],
    expected_value: &[u8],
) -> Result<&'a [u8], String> {
    let value_size = expected_value.len();
    let total = 2 + value_size + u64::SIZE;
    if operation.len() != total {
        return Err(format!(
            "fixed keyless operation size {} did not match expected {total}",
            operation.len()
        ));
    }
    if operation[0] != KEYLESS_APPEND_CONTEXT {
        return Err("expected keyless location is not an append".to_string());
    }
    let value_end = 1 + value_size;
    let value = &operation[1..value_end];
    if value != expected_value {
        return Err("keyless append value does not match expected value".to_string());
    }
    ensure_zero_padding(&operation[value_end..], "fixed keyless append")?;
    Ok(value)
}

fn fixed_unordered_update_value<'a>(
    operation: &'a [u8],
    expected_key: &[u8],
    value_size: usize,
) -> Result<&'a [u8], String> {
    let key_size = expected_key.len();
    let update_size = 1 + key_size + value_size;
    let delete_size = 1 + key_size;
    let commit_size = 1 + 1 + value_size + u64::SIZE;
    let total = update_size.max(delete_size).max(commit_size);
    if operation.len() != total {
        return Err(format!(
            "fixed unordered operation size {} did not match expected {total}",
            operation.len()
        ));
    }
    match operation[0] {
        ANY_UPDATE_CONTEXT => {}
        ANY_DELETE_CONTEXT => {
            return Err("expected unordered location is a delete".to_string());
        }
        ANY_COMMIT_CONTEXT => {
            return Err("expected unordered location is a commit".to_string());
        }
        other => {
            return Err(format!(
                "expected unordered location has unsupported operation context {other}"
            ));
        }
    }
    let key_start = 1;
    let key_end = key_start + key_size;
    let value_end = key_end + value_size;
    if &operation[key_start..key_end] != expected_key {
        return Err("unordered update key does not match expected key".to_string());
    }
    ensure_zero_padding(&operation[value_end..], "fixed unordered update")?;
    Ok(&operation[key_end..value_end])
}

fn fixed_keyless_append_to_js<F>(
    root: commonware_cryptography::sha256::Digest,
    proof_size_bytes: usize,
    operation_count: usize,
    location: Location<F>,
    value: &[u8],
) -> Result<JsValue, JsValue>
where
    F: merkle::Family,
{
    let verified = Object::new();
    set_field(&verified, "location", &location_to_bigint(location)?)?;
    set_field(&verified, "value", &bytes_to_js(value))?;
    set_field(&verified, "root", &bytes_to_js(root.as_ref()))?;
    set_field(
        &verified,
        "proofSizeBytes",
        &JsValue::from_f64(proof_size_bytes as f64),
    )?;
    set_field(
        &verified,
        "operationCount",
        &JsValue::from_f64(operation_count as f64),
    )?;
    Ok(verified.into())
}

fn fixed_unordered_update_to_js<F>(
    root: commonware_cryptography::sha256::Digest,
    proof_size_bytes: usize,
    operation_count: usize,
    location: Location<F>,
    key: &[u8],
    value: &[u8],
) -> Result<JsValue, JsValue>
where
    F: merkle::Family,
{
    let verified = Object::new();
    set_field(&verified, "location", &location_to_bigint(location)?)?;
    set_field(&verified, "key", &bytes_to_js(key))?;
    set_field(&verified, "value", &bytes_to_js(value))?;
    set_field(&verified, "root", &bytes_to_js(root.as_ref()))?;
    set_field(
        &verified,
        "proofSizeBytes",
        &JsValue::from_f64(proof_size_bytes as f64),
    )?;
    set_field(
        &verified,
        "operationCount",
        &JsValue::from_f64(operation_count as f64),
    )?;
    Ok(verified.into())
}

fn lookup_results_to_js<F>(
    proto: &GetManyResponse,
    current_root: &commonware_cryptography::sha256::Digest,
    requested_keys: &[Vec<u8>],
) -> Result<JsValue, JsValue>
where
    F: merkle::Graftable,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    validate_requested_keys(requested_keys).map_err(js_err)?;
    if proto.results.len() != requested_keys.len() {
        return Err(js_err(
            "getMany result count does not match requested key count",
        ));
    }
    let results = Array::new();
    for (result, requested_key) in proto.results.iter().zip(requested_keys) {
        if result.key.as_slice() != requested_key.as_slice() {
            return Err(js_err("getMany result key does not match requested key"));
        }
        let decoded_requested_key =
            decode_vec_key_wire(requested_key.as_slice()).map_err(js_err)?;
        let entry = Object::new();
        set_field(&entry, "key", &bytes_to_js(&decoded_requested_key))?;
        match result
            .result
            .as_ref()
            .ok_or_else(|| js_err("getMany result missing hit/miss proof"))?
        {
            current_key_lookup_result::Result::Hit(proof) => {
                let (location, operation) =
                    verify_key_value_for_key_from_proto::<F>(proof, requested_key, current_root)
                        .map_err(js_err)?;
                set_field(&entry, "type", &JsValue::from_str("hit"))?;
                set_field(&entry, "location", &location_to_bigint(location)?)?;
                set_field(&entry, "operation", &to_js_operation(operation)?)?;
            }
            current_key_lookup_result::Result::Miss(proof) => {
                verify_key_exclusion_from_proto::<F>(proof, requested_key, current_root)
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
    let start_key = decode_vec_key_wire(start_key).map_err(js_err)?;
    let end_key = end_key
        .map(|key| decode_vec_key_wire(key).map_err(js_err))
        .transpose()?;
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
        let entry_key = decode_vec_key_wire(entry.key.as_slice()).map_err(js_err)?;
        if update.key.as_slice() != entry_key.as_slice() {
            return Err(js_err("getRange entry key does not match proof operation"));
        }
        decoded.push((entry_key, location, operation));
    }

    if let Some((first_key, _, _)) = decoded.first() {
        if first_key != &start_key {
            let start_proof = proto
                .start_proof
                .as_option()
                .ok_or_else(|| js_err("getRange response missing start boundary proof"))?;
            match verify_key_exclusion_from_proto::<F>(
                start_proof,
                encode_vec_key_wire(&start_key).as_ref(),
                current_root,
            )
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
        let boundary = verify_key_exclusion_from_proto::<F>(
            start_proof,
            encode_vec_key_wire(&start_key).as_ref(),
            current_root,
        )
        .map_err(js_err)?;
        match (end_key.as_ref(), boundary) {
            (Some(end_key), ExclusionBoundary::Span { start, end })
                if !span_contains_key(&start, &end, end_key)
                    && end.as_slice() != end_key.as_slice() =>
            {
                return Err(js_err(
                    "empty getRange boundary does not cover requested end",
                ));
            }
            (None, ExclusionBoundary::Span { end, .. })
                if end.as_slice() > start_key.as_slice() =>
            {
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
        let next_start_key =
            decode_vec_key_wire(proto.next_start_key.as_slice()).map_err(js_err)?;
        if next_start_key.as_slice() != last.next_key.as_slice() {
            return Err(js_err(
                "getRange next_start_key does not match last next_key",
            ));
        }
    } else if let Some((first_key, _, _)) = decoded.first() {
        let Some((last_key, _, OrderedOperation::Update(last))) = decoded.last() else {
            return Err(js_err("getRange final entry is not an update"));
        };
        if let Some(end_key) = end_key.as_ref() {
            if last.next_key.as_slice() != end_key.as_slice()
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
    let next_start_key = if proto.has_more {
        decode_vec_key_wire(proto.next_start_key.as_slice()).map_err(js_err)?
    } else {
        Vec::new()
    };
    set_field(&verified, "nextStartKey", &bytes_to_js(&next_start_key))?;
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
pub fn decode_historical_multi_proof_operations(
    bytes: &[u8],
    merkle_family: &str,
) -> Result<JsValue, JsValue> {
    let proto = HistoricalMultiProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical multi proof: {err}")))?
        .to_owned_message();
    match normalize_family(merkle_family, "historical multi proof").map_err(js_err)? {
        "mmr" => {
            let (root, operations) =
                decode_multi_with_embedded_root_from_proto::<mmr::Family>(&proto)
                    .map_err(js_err)?;
            historical_to_js(root, operations)
        }
        "mmb" => {
            let (root, operations) =
                decode_multi_with_embedded_root_from_proto::<mmb::Family>(&proto)
                    .map_err(js_err)?;
            historical_to_js(root, operations)
        }
        _ => unreachable!("normalize_family only returns supported values"),
    }
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
            let (root, operations) =
                verify_multi_from_proto::<mmr::Family>(&proto, &root).map_err(js_err)?;
            historical_to_js(root, operations)
        }
        "mmb" => {
            let (root, operations) =
                verify_multi_from_proto::<mmb::Family>(&proto, &root).map_err(js_err)?;
            historical_to_js(root, operations)
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
        "mmr" => {
            let (root, operations) =
                verify_operation_range_from_proto::<mmr::Family>(&proto, &root).map_err(js_err)?;
            historical_to_js(root, operations)
        }
        "mmb" => {
            let (root, operations) =
                verify_operation_range_from_proto::<mmb::Family>(&proto, &root).map_err(js_err)?;
            historical_to_js(root, operations)
        }
        _ => unreachable!("normalize_family only returns supported values"),
    }
}

#[wasm_bindgen]
pub fn verify_historical_raw_operation_range_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
) -> Result<JsValue, JsValue> {
    let proto = HistoricalOperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical operation range proof: {err}")))?
        .to_owned_message();
    let root = decode_digest(root, "historical operation range root").map_err(js_err)?;
    match normalize_family(merkle_family, "historical operation range proof").map_err(js_err)? {
        "mmr" => {
            let (root, proof, operations) =
                verify_raw_operation_range_from_proto::<mmr::Family>(&proto, &root)
                    .map_err(js_err)?;
            raw_operations_to_js(root, proof.encode().len(), operations)
        }
        "mmb" => {
            let (root, proof, operations) =
                verify_raw_operation_range_from_proto::<mmb::Family>(&proto, &root)
                    .map_err(js_err)?;
            raw_operations_to_js(root, proof.encode().len(), operations)
        }
        _ => unreachable!("normalize_family only returns supported values"),
    }
}

#[wasm_bindgen]
pub fn verify_historical_fixed_keyless_append_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    expected_location: u64,
    expected_value: &[u8],
) -> Result<JsValue, JsValue> {
    let proto = HistoricalOperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical operation range proof: {err}")))?
        .to_owned_message();
    let root = decode_digest(root, "historical operation range root").map_err(js_err)?;
    match normalize_family(merkle_family, "historical operation range proof").map_err(js_err)? {
        "mmr" => {
            let (root, proof, operations) =
                verify_raw_operation_range_from_proto::<mmr::Family>(&proto, &root)
                    .map_err(js_err)?;
            let operation = expected_raw_operation(
                proto.start_location,
                &operations,
                expected_location,
                "keyless",
            )
            .map_err(js_err)?;
            let value = fixed_keyless_append_value(&operation, expected_value).map_err(js_err)?;
            fixed_keyless_append_to_js(
                root,
                proof.encode().len(),
                operations.len(),
                Location::<mmr::Family>::new(expected_location),
                value,
            )
        }
        "mmb" => {
            let (root, proof, operations) =
                verify_raw_operation_range_from_proto::<mmb::Family>(&proto, &root)
                    .map_err(js_err)?;
            let operation = expected_raw_operation(
                proto.start_location,
                &operations,
                expected_location,
                "keyless",
            )
            .map_err(js_err)?;
            let value = fixed_keyless_append_value(&operation, expected_value).map_err(js_err)?;
            fixed_keyless_append_to_js(
                root,
                proof.encode().len(),
                operations.len(),
                Location::<mmb::Family>::new(expected_location),
                value,
            )
        }
        _ => unreachable!("normalize_family only returns supported values"),
    }
}

#[wasm_bindgen]
pub fn verify_historical_fixed_unordered_update_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    expected_location: u64,
    expected_key: &[u8],
    value_size: usize,
) -> Result<JsValue, JsValue> {
    let proto = HistoricalOperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical operation range proof: {err}")))?
        .to_owned_message();
    let root = decode_digest(root, "historical operation range root").map_err(js_err)?;
    match normalize_family(merkle_family, "historical operation range proof").map_err(js_err)? {
        "mmr" => {
            let (root, proof, operations) =
                verify_raw_operation_range_from_proto::<mmr::Family>(&proto, &root)
                    .map_err(js_err)?;
            let operation = expected_raw_operation(
                proto.start_location,
                &operations,
                expected_location,
                "unordered",
            )
            .map_err(js_err)?;
            let value = fixed_unordered_update_value(&operation, expected_key, value_size)
                .map_err(js_err)?;
            fixed_unordered_update_to_js(
                root,
                proof.encode().len(),
                operations.len(),
                Location::<mmr::Family>::new(expected_location),
                expected_key,
                value,
            )
        }
        "mmb" => {
            let (root, proof, operations) =
                verify_raw_operation_range_from_proto::<mmb::Family>(&proto, &root)
                    .map_err(js_err)?;
            let operation = expected_raw_operation(
                proto.start_location,
                &operations,
                expected_location,
                "unordered",
            )
            .map_err(js_err)?;
            let value = fixed_unordered_update_value(&operation, expected_key, value_size)
                .map_err(js_err)?;
            fixed_unordered_update_to_js(
                root,
                proof.encode().len(),
                operations.len(),
                Location::<mmb::Family>::new(expected_location),
                expected_key,
                value,
            )
        }
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
        "mmr" => operations_to_js(
            verify_current_operation_range_from_proto::<mmr::Family>(&proto, &root)
                .map_err(js_err)?,
        ),
        "mmb" => operations_to_js(
            verify_current_operation_range_from_proto::<mmb::Family>(&proto, &root)
                .map_err(js_err)?,
        ),
        _ => unreachable!("normalize_family only returns supported values"),
    }
}

#[wasm_bindgen]
pub fn encode_vec_key(key: &[u8]) -> Vec<u8> {
    encode_vec_key_wire(key)
}

#[wasm_bindgen]
pub fn verify_current_key_value_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    requested_key: &[u8],
) -> Result<JsValue, JsValue> {
    let proto = CurrentKeyValueProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode current key-value proof: {err}")))?
        .to_owned_message();
    let root = decode_digest(root, "current root").map_err(js_err)?;
    match normalize_family(merkle_family, "current key-value proof").map_err(js_err)? {
        "mmr" => {
            let (location, operation) =
                verify_key_value_for_key_from_proto::<mmr::Family>(&proto, requested_key, &root)
                    .map_err(js_err)?;
            current_to_js(location, operation)
        }
        "mmb" => {
            let (location, operation) =
                verify_key_value_for_key_from_proto::<mmb::Family>(&proto, requested_key, &root)
                    .map_err(js_err)?;
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
    requested_keys: Array,
) -> Result<JsValue, JsValue> {
    let proto = GetManyResponseView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode getMany response: {err}")))?
        .to_owned_message();
    let current_root = decode_digest(current_root, "current root").map_err(js_err)?;
    let requested_keys = js_key_array_to_vec(requested_keys)?;
    match normalize_family(merkle_family, "getMany response").map_err(js_err)? {
        "mmr" => lookup_results_to_js::<mmr::Family>(&proto, &current_root, &requested_keys),
        "mmb" => lookup_results_to_js::<mmb::Family>(&proto, &current_root, &requested_keys),
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_storage::merkle::mem::Mem;
    use commonware_storage::qmdb::{
        any::{
            unordered::{Operation as UnorderedOperation, Update as UnorderedUpdate},
            value::FixedEncoding,
        },
        keyless,
    };

    type TestOperation<F> = OrderedOperation<F, Vec<u8>, Vec<u8>>;

    #[test]
    fn vec_key_wire_bytes_use_commonware_codec_frame() {
        let key = b"alpha".to_vec();
        assert_eq!(
            decode_vec_key_wire(&encode_vec_key_wire(&key)).unwrap(),
            key
        );
        assert!(decode_vec_key_wire(b"alpha").is_err());
    }

    fn sample_operations<F>() -> Vec<TestOperation<F>>
    where
        F: merkle::Graftable,
    {
        [
            (b"a".as_slice(), b"one".as_slice(), b"b".as_slice()),
            (b"b".as_slice(), b"two".as_slice(), b"c".as_slice()),
            (b"c".as_slice(), b"three".as_slice(), b"d".as_slice()),
            (b"d".as_slice(), b"four".as_slice(), b"e".as_slice()),
            (b"e".as_slice(), b"five".as_slice(), b"a".as_slice()),
        ]
        .into_iter()
        .map(|(key, value, next_key)| {
            OrderedOperation::Update(Update {
                key: key.to_vec(),
                value: value.to_vec(),
                next_key: next_key.to_vec(),
            })
        })
        .collect()
    }

    fn historical_range_fixture<F>() -> (
        HistoricalOperationRangeProof,
        Sha256Digest,
        Vec<(Location<F>, TestOperation<F>)>,
    )
    where
        F: merkle::Graftable,
        TestOperation<F>:
            Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
    {
        historical_range_fixture_at::<F>(1, 4)
    }

    fn historical_range_fixture_at<F>(
        start_offset: u64,
        end_offset: u64,
    ) -> (
        HistoricalOperationRangeProof,
        Sha256Digest,
        Vec<(Location<F>, TestOperation<F>)>,
    )
    where
        F: merkle::Graftable,
        TestOperation<F>:
            Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
    {
        let hasher = commonware_storage::qmdb::hasher::<Sha256>();
        let mut merkle = Mem::<F, Sha256Digest>::new();
        let operations = sample_operations::<F>();

        let mut batch = merkle.new_batch();
        for operation in &operations {
            let encoded = operation.encode();
            batch = batch.add(&hasher, &encoded);
        }
        let batch = batch.merkleize(&merkle, &hasher);
        merkle.apply_batch(&batch).unwrap();

        let root = merkle.root(&hasher, 0).unwrap();
        let start = Location::<F>::new(start_offset);
        let end = Location::<F>::new(end_offset);
        let proof = merkle.range_proof(&hasher, start..end, 0).unwrap();
        let pinned_nodes = if start == Location::new(0) {
            Vec::new()
        } else {
            F::nodes_to_pin(start)
                .map(|position| {
                    merkle
                        .get_node(position)
                        .expect("pinned node exists")
                        .encode()
                })
                .collect()
        };
        let proven_operations = operations
            [usize::try_from(start_offset).unwrap()..usize::try_from(end_offset).unwrap()]
            .to_vec();
        let expected = proven_operations
            .iter()
            .cloned()
            .enumerate()
            .map(|(offset, operation)| (Location::new(start_offset + offset as u64), operation))
            .collect();

        (
            HistoricalOperationRangeProof {
                proof: proof.encode(),
                start_location: start_offset,
                encoded_operations: proven_operations
                    .iter()
                    .map(|operation| operation.encode())
                    .collect(),
                ops_root: root.encode(),
                pinned_nodes,
                ..Default::default()
            },
            root,
            expected,
        )
    }

    fn historical_raw_range_fixture_at<F>(
        encoded_operations: &[Vec<u8>],
        start_offset: u64,
        end_offset: u64,
    ) -> (
        HistoricalOperationRangeProof,
        Sha256Digest,
        Vec<(Location<F>, Vec<u8>)>,
    )
    where
        F: merkle::Graftable,
    {
        let hasher = commonware_storage::qmdb::hasher::<Sha256>();
        let mut merkle = Mem::<F, Sha256Digest>::new();

        let mut batch = merkle.new_batch();
        for operation in encoded_operations {
            batch = batch.add(&hasher, operation);
        }
        let batch = batch.merkleize(&merkle, &hasher);
        merkle.apply_batch(&batch).unwrap();

        let root = merkle.root(&hasher, 0).unwrap();
        let start = Location::<F>::new(start_offset);
        let end = Location::<F>::new(end_offset);
        let proof = merkle.range_proof(&hasher, start..end, 0).unwrap();
        let pinned_nodes = if start == Location::new(0) {
            Vec::new()
        } else {
            F::nodes_to_pin(start)
                .map(|position| {
                    merkle
                        .get_node(position)
                        .expect("pinned node exists")
                        .encode()
                })
                .collect()
        };
        let proven_operations = encoded_operations
            [usize::try_from(start_offset).unwrap()..usize::try_from(end_offset).unwrap()]
            .to_vec();
        let expected = proven_operations
            .iter()
            .cloned()
            .enumerate()
            .map(|(offset, operation)| (Location::new(start_offset + offset as u64), operation))
            .collect();

        (
            HistoricalOperationRangeProof {
                proof: proof.encode(),
                start_location: start_offset,
                encoded_operations: proven_operations.into_iter().map(Into::into).collect(),
                ops_root: root.encode(),
                pinned_nodes,
                ..Default::default()
            },
            root,
            expected,
        )
    }

    fn historical_multi_fixture<F>() -> (
        HistoricalMultiProof,
        Sha256Digest,
        Vec<(Location<F>, TestOperation<F>)>,
    )
    where
        F: merkle::Graftable,
        TestOperation<F>:
            Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
    {
        let hasher = commonware_storage::qmdb::hasher::<Sha256>();
        let mut merkle = Mem::<F, Sha256Digest>::new();
        let operations = sample_operations::<F>();

        let mut batch = merkle.new_batch();
        for operation in &operations {
            let encoded = operation.encode();
            batch = batch.add(&hasher, &encoded);
        }
        let batch = batch.merkleize(&merkle, &hasher);
        merkle.apply_batch(&batch).unwrap();

        let root = merkle.root(&hasher, 0).unwrap();
        let locations = vec![
            Location::<F>::new(0),
            Location::<F>::new(2),
            Location::<F>::new(4),
        ];
        let proof = futures::executor::block_on(merkle::verification::multi_proof(
            &merkle,
            0,
            hasher.root_bagging(),
            &locations,
        ))
        .unwrap();
        let expected = locations
            .iter()
            .map(|location| {
                (
                    *location,
                    operations[usize::try_from(location.as_u64()).unwrap()].clone(),
                )
            })
            .collect::<Vec<_>>();

        (
            HistoricalMultiProof {
                proof: proof.encode(),
                operations: expected
                    .iter()
                    .map(
                        |(location, operation)| proto::qmdb::v1::MultiProofOperation {
                            location: location.as_u64(),
                            encoded_operation: operation.encode(),
                            ..Default::default()
                        },
                    )
                    .collect(),
                ops_root: root.encode(),
                ..Default::default()
            },
            root,
            expected,
        )
    }

    #[test]
    fn verifies_historical_operation_range_mmr() {
        let (proto, root, expected) = historical_range_fixture::<mmr::Family>();

        let (verified_root, verified) =
            verify_operation_range_from_proto::<mmr::Family>(&proto, &root).unwrap();

        assert_eq!(verified_root, root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn verifies_historical_operation_range_mmb() {
        let (proto, root, expected) = historical_range_fixture::<mmb::Family>();

        let (verified_root, verified) =
            verify_operation_range_from_proto::<mmb::Family>(&proto, &root).unwrap();

        assert_eq!(verified_root, root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn verifies_raw_historical_operation_range_without_decoding() {
        let (proto, root, expected) = historical_range_fixture::<mmr::Family>();
        let expected = expected
            .into_iter()
            .map(|(location, operation)| (location, operation.encode().to_vec()))
            .collect::<Vec<_>>();

        let (verified_root, _, verified) =
            verify_raw_operation_range_from_proto::<mmr::Family>(&proto, &root).unwrap();

        assert_eq!(verified_root, root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn verifies_fixed_keyless_append_operation() {
        type Operation<F> = keyless::Operation<F, FixedEncoding<Sha256Digest>>;

        let expected_value = Sha256::fill(0x22);
        let operations = vec![
            Operation::<mmr::Family>::Append(Sha256::fill(0x11))
                .encode()
                .to_vec(),
            Operation::<mmr::Family>::Append(expected_value)
                .encode()
                .to_vec(),
            Operation::<mmr::Family>::Append(Sha256::fill(0x33))
                .encode()
                .to_vec(),
        ];
        let (proto, root, _) = historical_raw_range_fixture_at::<mmr::Family>(&operations, 0, 3);
        let (_, proof, verified) =
            verify_raw_operation_range_from_proto::<mmr::Family>(&proto, &root).unwrap();
        let operation =
            expected_raw_operation(proto.start_location, &verified, 1, "keyless").unwrap();

        let value = fixed_keyless_append_value(&operation, expected_value.as_ref()).unwrap();

        assert_eq!(proof.encode().len(), proto.proof.len());
        assert_eq!(value, expected_value.as_ref());
    }

    #[test]
    fn verifies_fixed_unordered_update_operation() {
        type Operation<F> = UnorderedOperation<F, Sha256Digest, FixedEncoding<u64>>;

        let expected_key = Sha256::fill(0x44);
        let expected_value = 7u64;
        let operations = vec![
            Operation::<mmr::Family>::Update(UnorderedUpdate(Sha256::fill(0x11), 1))
                .encode()
                .to_vec(),
            Operation::<mmr::Family>::Update(UnorderedUpdate(expected_key, expected_value))
                .encode()
                .to_vec(),
            Operation::<mmr::Family>::Update(UnorderedUpdate(Sha256::fill(0x33), 3))
                .encode()
                .to_vec(),
        ];
        let (proto, root, _) = historical_raw_range_fixture_at::<mmr::Family>(&operations, 0, 3);
        let (_, _, verified) =
            verify_raw_operation_range_from_proto::<mmr::Family>(&proto, &root).unwrap();
        let operation =
            expected_raw_operation(proto.start_location, &verified, 1, "unordered").unwrap();

        let value =
            fixed_unordered_update_value(&operation, expected_key.as_ref(), u64::SIZE).unwrap();

        assert_eq!(value, expected_value.encode().as_ref());
    }

    #[test]
    fn historical_operation_range_pinned_nodes_match_mmr_start_location() {
        let (zero_start, zero_root, zero_expected) =
            historical_range_fixture_at::<mmr::Family>(0, 3);
        assert!(
            zero_start.pinned_nodes.is_empty(),
            "zero-start MMR ranges must not carry pinned nodes"
        );
        let (_, zero_verified) =
            verify_operation_range_from_proto::<mmr::Family>(&zero_start, &zero_root).unwrap();
        assert_eq!(zero_verified, zero_expected);

        let (nonzero_start, nonzero_root, nonzero_expected) =
            historical_range_fixture_at::<mmr::Family>(1, 4);
        assert!(
            !nonzero_start.pinned_nodes.is_empty(),
            "nonzero-start MMR ranges must carry pinned nodes"
        );
        let (_, nonzero_verified) =
            verify_operation_range_from_proto::<mmr::Family>(&nonzero_start, &nonzero_root)
                .unwrap();
        assert_eq!(nonzero_verified, nonzero_expected);
    }

    #[test]
    fn historical_operation_range_pinned_nodes_match_mmb_start_location() {
        let (zero_start, zero_root, zero_expected) =
            historical_range_fixture_at::<mmb::Family>(0, 3);
        assert!(
            zero_start.pinned_nodes.is_empty(),
            "zero-start MMB ranges must not carry pinned nodes"
        );
        let (_, zero_verified) =
            verify_operation_range_from_proto::<mmb::Family>(&zero_start, &zero_root).unwrap();
        assert_eq!(zero_verified, zero_expected);

        let (nonzero_start, nonzero_root, nonzero_expected) =
            historical_range_fixture_at::<mmb::Family>(1, 4);
        assert!(
            !nonzero_start.pinned_nodes.is_empty(),
            "nonzero-start MMB ranges must carry pinned nodes"
        );
        let (_, nonzero_verified) =
            verify_operation_range_from_proto::<mmb::Family>(&nonzero_start, &nonzero_root)
                .unwrap();
        assert_eq!(nonzero_verified, nonzero_expected);
    }

    #[test]
    fn rejects_historical_operation_range_mmr_without_nonzero_pinned_nodes() {
        let (mut proto, root, _) = historical_range_fixture::<mmr::Family>();
        proto.pinned_nodes.clear();

        let err = verify_operation_range_from_proto::<mmr::Family>(&proto, &root).unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn rejects_historical_operation_range_mmb_without_nonzero_pinned_nodes() {
        let (mut proto, root, _) = historical_range_fixture::<mmb::Family>();
        proto.pinned_nodes.clear();

        let err = verify_operation_range_from_proto::<mmb::Family>(&proto, &root).unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn rejects_historical_operation_range_mmr_with_zero_start_pinned_nodes() {
        let (mut proto, root, _) = historical_range_fixture_at::<mmr::Family>(0, 3);
        proto.pinned_nodes.push(root.encode());

        let err = verify_operation_range_from_proto::<mmr::Family>(&proto, &root).unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn rejects_historical_operation_range_mmb_with_zero_start_pinned_nodes() {
        let (mut proto, root, _) = historical_range_fixture_at::<mmb::Family>(0, 3);
        proto.pinned_nodes.push(root.encode());

        let err = verify_operation_range_from_proto::<mmb::Family>(&proto, &root).unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn rejects_historical_operation_range_mmb_with_tampered_pinned_node() {
        let (mut proto, root, _) = historical_range_fixture::<mmb::Family>();
        let mut pinned_node = proto.pinned_nodes[0].to_vec();
        pinned_node[0] ^= 0x01;
        proto.pinned_nodes[0] = pinned_node.into();

        let err = verify_operation_range_from_proto::<mmb::Family>(&proto, &root).unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn rejects_historical_operation_range_mmb_with_extra_pinned_node() {
        let (mut proto, root, _) = historical_range_fixture::<mmb::Family>();
        proto.pinned_nodes.push(proto.pinned_nodes[0].clone());

        let err = verify_operation_range_from_proto::<mmb::Family>(&proto, &root).unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn decodes_subscribe_multi_proof_without_ops_root_witness() {
        let (proto, ops_root, expected) = historical_multi_fixture::<mmr::Family>();

        let (root, verified) =
            decode_multi_with_embedded_root_from_proto::<mmr::Family>(&proto).unwrap();

        assert_eq!(root, ops_root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn decodes_subscribe_multi_proof_with_ops_root_witness() {
        let (mut proto, ops_root, expected) = historical_multi_fixture::<mmb::Family>();
        let witness = OpsRootWitness::<mmb::Family, Sha256Digest> {
            grafted_root: Sha256::fill(0x11),
            pending_chunk_digest: Some(Sha256::fill(0x22)),
            partial_chunk: Some((13, Sha256::fill(0x33))),
        };
        let hasher = commonware_storage::qmdb::hasher::<Sha256>();
        let current_root = witness.root(&hasher, &ops_root);
        proto.ops_root_witness = witness.encode();

        let (root, verified) =
            decode_multi_with_embedded_root_from_proto::<mmb::Family>(&proto).unwrap();

        assert_eq!(root, current_root);
        assert_ne!(root, ops_root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn rejects_subscribe_multi_proof_missing_ops_root() {
        let (mut proto, _, _) = historical_multi_fixture::<mmr::Family>();
        proto.ops_root.clear();

        let err = decode_multi_with_embedded_root_from_proto::<mmr::Family>(&proto).unwrap_err();

        assert_eq!(err, "historical multi proof missing embedded ops_root");
    }

    #[test]
    fn rejects_historical_operation_range_root_mismatch() {
        let (proto, root, _) = historical_range_fixture::<mmb::Family>();
        let wrong_root = Sha256::fill(0x42);
        assert_ne!(wrong_root, root);

        let err =
            verify_operation_range_from_proto::<mmb::Family>(&proto, &wrong_root).unwrap_err();

        assert_eq!(err, "historical ops root did not match expected root");
    }
}
