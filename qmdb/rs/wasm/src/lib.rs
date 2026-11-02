#![allow(clippy::type_complexity)]

use crate::proto::qmdb::v1::{
    current_key_lookup_result, CurrentKeyExclusionProof, CurrentKeyValueProof,
    CurrentKeyValueProofView, CurrentOperationRangeProof, CurrentOperationRangeProofView,
    GetManyResponse, GetManyResponseView, GetRangeResponse, GetRangeResponseView,
    OperationMultiProof, OperationMultiProofView, OperationRangeProof, OperationRangeProofView,
};
use buffa::MessageView;
use commonware_codec::{
    Copying, Decode, DecodeExt, DecodeRangeExt, Encode, FixedSize, RangeCfg, Read,
};
use commonware_cryptography::{Blake3, Digest, Sha256};
use commonware_storage::{
    merkle::{self, Location},
    mmb, mmr,
    qmdb::{
        any::{
            operation::{
                COMMIT_CONTEXT as FIXED_UNORDERED_COMMIT_CONTEXT,
                DELETE_CONTEXT as FIXED_UNORDERED_DELETE_CONTEXT,
                UPDATE_CONTEXT as FIXED_UNORDERED_UPDATE_CONTEXT,
            },
            ordered::{variable::Operation as OrderedOperation, Update},
            value::VariableEncoding,
        },
        current::{
            ordered::proof::dynamic::{ExclusionProof, KeyValueProof},
            proof::{dynamic::OperationProof, OpsRootWitness, RangeProof},
        },
        keyless::{
            APPEND_CONTEXT as FIXED_KEYLESS_APPEND_CONTEXT,
            COMMIT_CONTEXT as FIXED_KEYLESS_COMMIT_CONTEXT,
        },
        verify::{verify_multi_proof, verify_proof_and_pinned_nodes},
    },
};
use js_sys::{Array, Object, Reflect, Uint8Array};
use std::collections::BTreeSet;
use wasm_bindgen::{prelude::*, JsCast};

pub mod proto;

#[path = "../../src/request.rs"]
mod request;
use request::{validate_key_range, OperationLocations, OperationWindow};

const MAX_OPERATION_SIZE: usize = u16::MAX as usize;

fn decode_vec_key_wire(encoded_key: &[u8]) -> Result<Vec<u8>, String> {
    Vec::<u8>::decode_range(Copying(encoded_key), 0..=MAX_OPERATION_SIZE)
        .map_err(|err| format!("failed to decode QMDB key: {err}"))
}

/// Bitmap chunk geometry shared by every `current` proof checked against one database.
#[derive(Debug)]
struct CurrentProofConfig {
    /// Bytes per activity bitmap chunk. Proofs do not encode it, so it must match the source
    /// database.
    chunk_size: usize,
}

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
    D::decode(Copying(bytes)).map_err(|err| format!("failed to decode {label}: {err}"))
}

fn proof_digest_cap<D: Digest>(encoded_proof: &[u8]) -> usize {
    encoded_proof.len() / <D as FixedSize>::SIZE + 1
}

fn normalize_family<'a>(family: &'a str, label: &str) -> Result<&'a str, String> {
    match family {
        "mmr" | "mmb" => Ok(family),
        "" => Err(format!("{label} missing Merkle family")),
        other => Err(format!("{label} uses unsupported Merkle family {other}")),
    }
}

fn normalize_hash_family<'a>(family: &'a str, label: &str) -> Result<&'a str, String> {
    match family {
        "sha256" | "blake3" => Ok(family),
        "" => Err(format!("{label} missing hash family")),
        other => Err(format!("{label} uses unsupported hash family {other}")),
    }
}

/// Validate the database's chunk size against digest `D`.
fn current_proof_config<D: Digest>(
    chunk_size: usize,
    label: &str,
) -> Result<CurrentProofConfig, String> {
    // Enforce Commonware's `current::Db` chunk constraints for this runtime size.
    if chunk_size == 0 {
        return Err(format!("{label} current chunk size must be non-zero"));
    }
    if !chunk_size.is_power_of_two() {
        return Err(format!("{label} current chunk size must be a power of two"));
    }
    if !chunk_size.is_multiple_of(D::SIZE) {
        return Err(format!(
            "{label} current chunk size must be a multiple of digest size {}",
            D::SIZE
        ));
    }
    Ok(CurrentProofConfig { chunk_size })
}

macro_rules! with_hash_family {
    ($hash_family:expr, $label:expr, $body:block) => {{
        match normalize_hash_family($hash_family, $label).map_err(js_err)? {
            "sha256" => {
                type H = Sha256;
                $body
            }
            "blake3" => {
                type H = Blake3;
                $body
            }
            _ => unreachable!("normalize_hash_family only returns supported values"),
        }
    }};
}

fn operation_target_root<F, H>(
    ops_root: &[u8],
    ops_root_witness: &[u8],
    expected_root: &H::Digest,
) -> Result<H::Digest, String>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
    H::Digest: DecodeExt<()>,
{
    if ops_root.is_empty() {
        return Err("operation proof missing ops_root".to_string());
    }
    let ops_root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
        ops_root,
        "operation-log root",
    )?;
    if ops_root_witness.is_empty() {
        if ops_root != *expected_root {
            return Err("operation-log root did not match expected root".to_string());
        }
        return Ok(ops_root);
    }
    let witness = OpsRootWitness::<F, H::Digest>::decode(Copying(ops_root_witness))
        .map_err(|err| format!("failed to decode operation-log root witness: {err}"))?;
    if !witness.verify::<H>(&ops_root, expected_root) {
        return Err("operation-log root witness failed verification".to_string());
    }
    Ok(ops_root)
}

fn verify_multi_from_proto<F, H>(
    proto: &OperationMultiProof,
    root: &H::Digest,
) -> Result<
    (
        H::Digest,
        Vec<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>)>,
    ),
    String,
>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
    H::Digest: DecodeExt<()>,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    let operations = decode_multi_operations_from_proto::<F>(proto)?;
    let target_root =
        operation_target_root::<F, H>(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof =
        merkle::Proof::<F, H::Digest>::decode_cfg(Copying(proto.proof.as_ref()), &max_digests)
            .map_err(|err| format!("failed to decode operation multi proof: {err}"))?;
    if !verify_multi_proof::<H, _, _>(&proof, &operations, &target_root) {
        return Err("operation multi proof failed verification".to_string());
    }
    Ok((*root, operations))
}

fn decode_multi_with_embedded_root_from_proto<F, H>(
    proto: &OperationMultiProof,
) -> Result<
    (
        Location<F>,
        H::Digest,
        Vec<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>)>,
    ),
    String,
>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
    H::Digest: DecodeExt<()>,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    let operations = decode_multi_operations_from_proto::<F>(proto)?;
    if proto.ops_root.is_empty() {
        return Err("operation multi proof missing embedded ops_root".to_string());
    }
    let ops_root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
        &proto.ops_root,
        "operation multi proof ops root",
    )?;
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof =
        merkle::Proof::<F, H::Digest>::decode_cfg(Copying(proto.proof.as_ref()), &max_digests)
            .map_err(|err| format!("failed to decode operation multi proof: {err}"))?;
    let tip = proof
        .leaves
        .checked_sub(1)
        .ok_or_else(|| "subscription proof has no leaves".to_string())?;
    if !verify_multi_proof::<H, _, _>(&proof, &operations, &ops_root) {
        return Err("operation multi proof failed verification".to_string());
    }
    if proto.ops_root_witness.is_empty() {
        return Ok((tip, ops_root, operations));
    }
    let witness = OpsRootWitness::<F, H::Digest>::decode(Copying(proto.ops_root_witness.as_ref()))
        .map_err(|err| format!("failed to decode operation multi proof ops-root witness: {err}"))?;
    Ok((tip, witness.root::<H>(&ops_root), operations))
}

fn decode_multi_operations_from_proto<F>(
    proto: &OperationMultiProof,
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
                    Copying(operation.encoded_operation.as_ref()),
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

fn verify_operation_range_from_proto<F, H>(
    proto: &OperationRangeProof,
    root: &H::Digest,
    window: OperationWindow,
) -> Result<
    (
        H::Digest,
        Vec<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>)>,
    ),
    String,
>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
    H::Digest: DecodeExt<()>,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    if proto.encoded_operations.is_empty() {
        return Err("operation range proof has no operations".to_string());
    }
    let target_root =
        operation_target_root::<F, H>(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof =
        merkle::Proof::<F, H::Digest>::decode_cfg(Copying(proto.proof.as_ref()), &max_digests)
            .map_err(|err| format!("failed to decode operation range proof: {err}"))?;
    window.validate(
        proto.start_location,
        proto.encoded_operations.len(),
        proof.leaves.as_u64(),
    )?;
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
                Copying(bytes.as_ref()),
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
    let pinned_nodes = proto
        .pinned_nodes
        .iter()
        .map(|bytes| {
            decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
                bytes.as_ref(),
                "operation range pinned node",
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    if !verify_proof_and_pinned_nodes::<H, _, _>(
        &proof,
        start,
        &ordered_operations,
        &pinned_nodes,
        &target_root,
    ) {
        return Err("operation range proof failed verification".to_string());
    }
    Ok((*root, operations))
}

fn verify_raw_operation_range<F, H>(
    proto: &OperationRangeProof,
    root: &H::Digest,
    window: OperationWindow,
) -> Result<(H::Digest, Vec<(Location<F>, Vec<u8>)>), String>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
    H::Digest: DecodeExt<()>,
{
    if proto.encoded_operations.is_empty() {
        return Err("operation range proof has no operations".to_string());
    }
    let target_root =
        operation_target_root::<F, H>(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof =
        merkle::Proof::<F, H::Digest>::decode_cfg(Copying(proto.proof.as_ref()), &max_digests)
            .map_err(|err| format!("failed to decode operation range proof: {err}"))?;
    window.validate(
        proto.start_location,
        proto.encoded_operations.len(),
        proof.leaves.as_u64(),
    )?;
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
    let pinned_nodes = proto
        .pinned_nodes
        .iter()
        .map(|bytes| {
            decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
                bytes.as_ref(),
                "operation range pinned node",
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    if !proof.verify_proof_and_pinned_nodes(
        &commonware_storage::qmdb::hasher::<H>(),
        &proto.encoded_operations,
        start,
        &pinned_nodes,
        &target_root,
    ) {
        return Err("operation range proof failed verification".to_string());
    }
    Ok((*root, operations))
}

/// Verify operations against the current `root` and the exact requested `window`.
fn verify_current_operation_range_from_proto<F, H>(
    proto: &CurrentOperationRangeProof,
    root: &H::Digest,
    config: &CurrentProofConfig,
    window: OperationWindow,
) -> Result<Vec<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>)>, String>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
    H::Digest: DecodeExt<()>,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    // A range proof covers at least one operation and the bitmap chunk holding its activity bit.
    if proto.encoded_operations.is_empty() {
        return Err("current operation range proof has no operations".to_string());
    }
    if proto.chunks.is_empty() {
        return Err("current operation range proof has no chunks".to_string());
    }

    // Bind the proof to the requested window. Its claimed leaf count is authenticated when the
    // root is reconstructed below.
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = RangeProof::<F, H::Digest>::decode_cfg(Copying(proto.proof.as_ref()), &max_digests)
        .map_err(|err| format!("failed to decode current operation range proof: {err}"))?;
    window.validate(
        proto.start_location,
        proto.encoded_operations.len(),
        proof.proof.leaves.as_u64(),
    )?;

    // Decode each operation at its absolute location, rejecting locations that overflow `u64`.
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
                Copying(bytes.as_ref()),
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

    // Commonware checks the chunk count and sizes, then authenticates the operations and their
    // activity chunks against `root`.
    let ordered_operations = operations
        .iter()
        .map(|(_, operation)| operation.clone())
        .collect::<Vec<_>>();
    if !proof.verify_with_chunk_size::<H, _>(
        start,
        &ordered_operations,
        &proto.chunks,
        config.chunk_size,
        root,
    ) {
        return Err("current operation range proof failed verification".to_string());
    }
    Ok(operations)
}

/// Verify an active update against the current `root`.
fn verify_key_value_from_proto<F, H>(
    proto: &CurrentKeyValueProof,
    root: &H::Digest,
    config: &CurrentProofConfig,
) -> Result<(Location<F>, Update<Vec<u8>, VariableEncoding<Vec<u8>>>), String>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
    H::Digest: DecodeExt<()>,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    // Only an update operation can prove that a key has a value.
    let operation = OrderedOperation::<F, Vec<u8>, Vec<u8>>::decode_cfg(
        Copying(proto.encoded_operation.as_ref()),
        &op_cfg::<F>(),
    )
    .map_err(|err| format!("failed to decode current key-value operation: {err}"))?;
    let OrderedOperation::Update(update) = operation else {
        return Err("current key-value proof operation must be an update".to_string());
    };

    // Decode with the source database's chunk size, which the proof does not encode.
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = OperationProof::<F, H::Digest>::decode_cfg(
        Copying(proto.proof.as_ref()),
        &(config.chunk_size, max_digests),
    )
    .map_err(|err| format!("failed to decode current key-value proof: {err}"))?;
    let location = proof.loc;

    // The operation supplies the successor key authenticated with its key, value, and activity bit.
    let proof = KeyValueProof {
        proof,
        next_key: update.next_key.clone(),
    };
    if !proof.verify::<H, VariableEncoding<Vec<u8>>>(update.key.clone(), update.value.clone(), root)
    {
        return Err("current key-value proof failed verification".to_string());
    }
    Ok((location, update))
}

fn verify_key_value_for_key_from_proto<F, H>(
    proto: &CurrentKeyValueProof,
    requested_key: &[u8],
    root: &H::Digest,
    config: &CurrentProofConfig,
) -> Result<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>), String>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
    H::Digest: DecodeExt<()>,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    let requested_key = decode_vec_key_wire(requested_key)?;
    let (location, update) = verify_key_value_from_proto::<F, H>(proto, root, config)?;
    if update.key != requested_key {
        return Err("current key-value proof key mismatch".to_string());
    }
    Ok((location, OrderedOperation::Update(update)))
}

/// Verify that `requested_key` has no active value under `current_root`.
///
/// Returns the successor key that closes the excluding span, or `None` when the proof shows the
/// database has no active keys.
fn verify_key_exclusion_from_proto<F, H>(
    proto: &CurrentKeyExclusionProof,
    requested_key: &[u8],
    current_root: &H::Digest,
    config: &CurrentProofConfig,
) -> Result<Option<Vec<u8>>, String>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
    H::Digest: DecodeExt<()>,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    // Decode with the source database's chunk size, which the proof does not encode.
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = ExclusionProof::<F, Vec<u8>, VariableEncoding<Vec<u8>>, H::Digest>::decode_cfg(
        Copying(proto.proof.as_ref()),
        &(
            (config.chunk_size, max_digests),
            op_cfg::<F>(),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
    )
    .map_err(|err| format!("failed to decode current key-exclusion proof: {err}"))?;

    // A span proof must strictly contain the requested key, and a commit proof must show an empty
    // database. Commonware checks either case and authenticates the anchoring operation.
    let requested_key = decode_vec_key_wire(requested_key)?;
    if !proof.verify::<H>(&requested_key, current_root) {
        return Err("current key-exclusion proof failed verification".to_string());
    }

    // Only a span proof names a successor key.
    Ok(match proof {
        ExclusionProof::KeyValue(_, update) => Some(update.next_key),
        ExclusionProof::Commit(..) => None,
    })
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

fn location_to_bigint<F: merkle::Family>(location: Location<F>) -> JsValue {
    JsValue::from(*location)
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
            set_field(&object, "floorLocation", &JsValue::from(*floor_location))?;
        }
    }
    Ok(object.into())
}

fn operation_proof_to_js<F, D>(
    root: D,
    decoded_operations: Vec<(Location<F>, OrderedOperation<F, Vec<u8>, Vec<u8>>)>,
) -> Result<JsValue, JsValue>
where
    F: merkle::Family,
    D: Digest,
{
    let operations = Array::new();
    for (location, operation) in decoded_operations {
        let entry = Object::new();
        set_field(&entry, "location", &location_to_bigint(location))?;
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
        set_field(&entry, "location", &location_to_bigint(location))?;
        set_field(&entry, "operation", &to_js_operation(operation)?)?;
        operations.push(&entry.into());
    }
    let verified = Object::new();
    set_field(&verified, "operations", &operations.into())?;
    Ok(verified.into())
}

fn raw_operations_to_js<F, D>(
    root: D,
    raw_operations: Vec<(Location<F>, Vec<u8>)>,
) -> Result<JsValue, JsValue>
where
    F: merkle::Family,
    D: Digest,
{
    let operations = Array::new();
    for (location, encoded_operation) in raw_operations {
        let entry = Object::new();
        set_field(&entry, "location", &location_to_bigint(location))?;
        set_field(&entry, "encodedOperation", &bytes_to_js(&encoded_operation))?;
        operations.push(&entry.into());
    }
    let verified = Object::new();
    set_field(&verified, "root", &bytes_to_js(root.as_ref()))?;
    set_field(&verified, "operations", &operations.into())?;
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

// Runtime key and value sizes determine the offsets in Commonware's fixed operation encoding.
struct FixedUnorderedOperationSizes {
    update: usize,
    total: usize,
}

fn checked_fixed_size(parts: &[usize], label: &str) -> Result<usize, String> {
    let mut total = 0usize;
    for part in parts {
        total = total
            .checked_add(*part)
            .ok_or_else(|| format!("{label} fixed operation size overflow"))?;
    }
    Ok(total)
}

fn ensure_supported_operation_size(size: usize, label: &str) -> Result<(), String> {
    if size > MAX_OPERATION_SIZE {
        return Err(format!(
            "{label} fixed operation size {size} exceeds maximum {MAX_OPERATION_SIZE}"
        ));
    }
    Ok(())
}

fn ensure_zero_padding(padding: &[u8], label: &str) -> Result<(), String> {
    if let Some(index) = padding.iter().position(|byte| *byte != 0) {
        return Err(format!("{label} padding byte {index} is non-zero"));
    }
    Ok(())
}

fn fixed_keyless_operation_size(value_size: usize) -> Result<usize, String> {
    let total = checked_fixed_size(&[1, 1, value_size, u64::SIZE], "keyless")?;
    ensure_supported_operation_size(total, "keyless")?;
    Ok(total)
}

fn fixed_keyless_append_value(operation: &[u8], expected_value: &[u8]) -> Result<Vec<u8>, String> {
    let value_size = expected_value.len();
    let total = fixed_keyless_operation_size(value_size)?;
    if operation.len() != total {
        return Err(format!(
            "fixed keyless operation has {} bytes, expected {total}",
            operation.len()
        ));
    }
    match operation.first().copied() {
        Some(FIXED_KEYLESS_APPEND_CONTEXT) => {
            let value_end = 1 + value_size;
            let value = &operation[1..value_end];
            ensure_zero_padding(&operation[value_end..], "fixed keyless append")?;
            if value != expected_value {
                return Err("keyless append value does not match expected value".to_string());
            }
            Ok(value.to_vec())
        }
        Some(FIXED_KEYLESS_COMMIT_CONTEXT) => {
            Err("expected keyless location is not an append".to_string())
        }
        Some(context) => Err(format!("invalid fixed keyless operation context {context}")),
        None => Err("fixed keyless operation is empty".to_string()),
    }
}

fn fixed_unordered_operation_sizes(
    key_size: usize,
    value_size: usize,
) -> Result<FixedUnorderedOperationSizes, String> {
    let delete = checked_fixed_size(&[1, key_size], "unordered delete")?;
    let update = checked_fixed_size(&[1, key_size, value_size], "unordered update")?;
    let commit = checked_fixed_size(&[1, 1, value_size, u64::SIZE], "unordered commit")?;
    let total = delete.max(update).max(commit);
    ensure_supported_operation_size(total, "unordered")?;
    Ok(FixedUnorderedOperationSizes { update, total })
}

fn fixed_unordered_update_value(
    operation: &[u8],
    expected_key: &[u8],
    value_size: usize,
) -> Result<Vec<u8>, String> {
    let sizes = fixed_unordered_operation_sizes(expected_key.len(), value_size)?;
    if operation.len() != sizes.total {
        return Err(format!(
            "fixed unordered operation has {} bytes, expected {}",
            operation.len(),
            sizes.total
        ));
    }
    match operation.first().copied() {
        Some(FIXED_UNORDERED_UPDATE_CONTEXT) => {
            let key_start = 1;
            let key_end = key_start + expected_key.len();
            let value_end = key_end + value_size;
            ensure_zero_padding(&operation[sizes.update..], "fixed unordered update")?;
            if &operation[key_start..key_end] != expected_key {
                return Err("unordered update key does not match expected key".to_string());
            }
            Ok(operation[key_end..value_end].to_vec())
        }
        Some(FIXED_UNORDERED_DELETE_CONTEXT) => {
            Err("expected unordered location is a delete".to_string())
        }
        Some(FIXED_UNORDERED_COMMIT_CONTEXT) => {
            Err("expected unordered location is a commit".to_string())
        }
        Some(context) => Err(format!(
            "invalid fixed unordered operation context {context}"
        )),
        None => Err("fixed unordered operation is empty".to_string()),
    }
}

fn verify_raw_operations<F, H>(
    proto: &OperationMultiProof,
    root: &H::Digest,
    locations: &OperationLocations<'_>,
) -> Result<(H::Digest, Vec<(Location<F>, Vec<u8>)>), String>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
    H::Digest: DecodeExt<()>,
{
    let target_root =
        operation_target_root::<F, H>(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof =
        merkle::Proof::<F, H::Digest>::decode_cfg(Copying(proto.proof.as_ref()), &max_digests)
            .map_err(|err| format!("failed to decode operations multi proof: {err}"))?;
    locations.validate(
        proto.operations.iter().map(|operation| operation.location),
        proof.leaves.as_u64(),
    )?;
    let elements = proto
        .operations
        .iter()
        .map(|operation| {
            (
                operation.encoded_operation.as_ref(),
                Location::<F>::new(operation.location),
            )
        })
        .collect::<Vec<_>>();
    if !proof.verify_multi_inclusion(
        &commonware_storage::qmdb::hasher::<H>(),
        &elements,
        &target_root,
    ) {
        return Err("operations multi proof failed verification".to_string());
    }
    let operations = proto
        .operations
        .iter()
        .map(|operation| {
            (
                Location::new(operation.location),
                operation.encoded_operation.to_vec(),
            )
        })
        .collect();
    Ok((*root, operations))
}

fn decode_operations_proof(bytes: &[u8]) -> Result<OperationMultiProof, JsValue> {
    OperationMultiProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode operations multi proof: {err}")))?
        .to_owned_message()
        .map_err(|err| js_err(format!("materialize operations multi proof: {err}")))
}

/// Split concatenated fixed-size expectations into one slice per location.
fn fixed_size_parts<'a>(
    bytes: &'a [u8],
    size: usize,
    count: usize,
    label: &str,
) -> Result<Vec<&'a [u8]>, String> {
    if size == 0 || Some(bytes.len()) != size.checked_mul(count) {
        return Err(format!(
            "expected {count} {label}s of {size} bytes, got {} bytes",
            bytes.len()
        ));
    }
    Ok(bytes.chunks_exact(size).collect())
}

fn fixed_keyless_appends_to_js<F, D>(
    root: D,
    operations: &[(Location<F>, Vec<u8>)],
    values: &[&[u8]],
) -> Result<JsValue, JsValue>
where
    F: merkle::Family,
    D: Digest,
{
    let appends = Array::new();
    for ((location, operation), expected) in operations.iter().zip(values) {
        let value = fixed_keyless_append_value(operation, expected).map_err(js_err)?;
        let entry = Object::new();
        set_field(&entry, "location", &location_to_bigint(*location))?;
        set_field(&entry, "value", &bytes_to_js(&value))?;
        appends.push(&entry.into());
    }
    let verified = Object::new();
    set_field(&verified, "root", &bytes_to_js(root.as_ref()))?;
    set_field(&verified, "operations", &appends.into())?;
    Ok(verified.into())
}

fn fixed_unordered_updates_to_js<F, D>(
    root: D,
    operations: &[(Location<F>, Vec<u8>)],
    keys: &[&[u8]],
    value_size: usize,
) -> Result<JsValue, JsValue>
where
    F: merkle::Family,
    D: Digest,
{
    let updates = Array::new();
    for ((location, operation), key) in operations.iter().zip(keys) {
        let value = fixed_unordered_update_value(operation, key, value_size).map_err(js_err)?;
        let entry = Object::new();
        set_field(&entry, "location", &location_to_bigint(*location))?;
        set_field(&entry, "key", &bytes_to_js(key))?;
        set_field(&entry, "value", &bytes_to_js(&value))?;
        updates.push(&entry.into());
    }
    let verified = Object::new();
    set_field(&verified, "root", &bytes_to_js(root.as_ref()))?;
    set_field(&verified, "operations", &updates.into())?;
    Ok(verified.into())
}

fn fixed_keyless_append_to_js<F, D>(
    root: D,
    operation_count: usize,
    location: Location<F>,
    value: &[u8],
) -> Result<JsValue, JsValue>
where
    F: merkle::Family,
    D: Digest,
{
    let verified = Object::new();
    set_field(&verified, "location", &location_to_bigint(location))?;
    set_field(&verified, "value", &bytes_to_js(value))?;
    set_field(&verified, "root", &bytes_to_js(root.as_ref()))?;
    set_field(
        &verified,
        "operationCount",
        &JsValue::from_f64(operation_count as f64),
    )?;
    Ok(verified.into())
}

fn fixed_unordered_update_to_js<F, D>(
    root: D,
    operation_count: usize,
    location: Location<F>,
    key: &[u8],
    value: &[u8],
) -> Result<JsValue, JsValue>
where
    F: merkle::Family,
    D: Digest,
{
    let verified = Object::new();
    set_field(&verified, "location", &location_to_bigint(location))?;
    set_field(&verified, "key", &bytes_to_js(key))?;
    set_field(&verified, "value", &bytes_to_js(value))?;
    set_field(&verified, "root", &bytes_to_js(root.as_ref()))?;
    set_field(
        &verified,
        "operationCount",
        &JsValue::from_f64(operation_count as f64),
    )?;
    Ok(verified.into())
}

fn lookup_results_to_js<F, H>(
    proto: &GetManyResponse,
    current_root: &H::Digest,
    requested_keys: &[Vec<u8>],
    config: &CurrentProofConfig,
) -> Result<JsValue, JsValue>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
    H::Digest: DecodeExt<()>,
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
                let (location, operation) = verify_key_value_for_key_from_proto::<F, H>(
                    proof,
                    requested_key,
                    current_root,
                    config,
                )
                .map_err(js_err)?;
                set_field(&entry, "type", &JsValue::from_str("hit"))?;
                set_field(&entry, "location", &location_to_bigint(location))?;
                set_field(&entry, "operation", &to_js_operation(operation)?)?;
            }
            current_key_lookup_result::Result::Miss(proof) => {
                verify_key_exclusion_from_proto::<F, H>(proof, requested_key, current_root, config)
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

fn verify_get_range_from_proto<F, H>(
    proto: &GetRangeResponse,
    current_root: &H::Digest,
    start_key: &[u8],
    end_key: Option<&[u8]>,
    config: &CurrentProofConfig,
    limit: u32,
) -> Result<JsValue, JsValue>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
    H::Digest: DecodeExt<()>,
    OrderedOperation<F, Vec<u8>, Vec<u8>>:
        Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
{
    let start_key_wire = start_key;
    let start_key = decode_vec_key_wire(start_key_wire).map_err(js_err)?;
    let end_key = end_key
        .map(|key| decode_vec_key_wire(key).map_err(js_err))
        .transpose()?;
    let mut decoded = Vec::new();
    for proof in &proto.entries {
        decoded.push(
            verify_key_value_from_proto::<F, H>(proof, current_root, config).map_err(js_err)?,
        );
    }

    let keys = decoded
        .iter()
        .map(|(_, update)| (&update.key, &update.next_key))
        .collect::<Vec<_>>();
    let start_successor = if keys.first().is_none_or(|(key, _)| **key != start_key) {
        let proof = proto
            .start_proof
            .as_option()
            .ok_or_else(|| js_err("key range missing start boundary proof"))?;
        verify_key_exclusion_from_proto::<F, H>(proof, start_key_wire, current_root, config)
            .map_err(js_err)?
    } else {
        None
    };
    let next_start = validate_key_range(
        &start_key,
        end_key.as_ref(),
        limit,
        &keys,
        start_successor.as_ref(),
    )
    .map_err(js_err)?
    .cloned();

    let entries = Array::new();
    for (location, update) in decoded {
        let entry = Object::new();
        set_field(&entry, "key", &bytes_to_js(&update.key))?;
        set_field(&entry, "location", &location_to_bigint(location))?;
        set_field(
            &entry,
            "operation",
            &to_js_operation::<F>(OrderedOperation::Update(update))?,
        )?;
        entries.push(&entry.into());
    }

    let verified = Object::new();
    set_field(&verified, "entries", &entries.into())?;
    set_field(
        &verified,
        "nextStartKey",
        &next_start.map_or(JsValue::NULL, |key| bytes_to_js(&key)),
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
    set_field(&verified, "location", &location_to_bigint(location))?;
    set_field(&verified, "operation", &to_js_operation(operation)?)?;
    Ok(verified.into())
}

#[wasm_bindgen]
pub fn decode_operation_multi_proof_operations(
    bytes: &[u8],
    merkle_family: &str,
    hash_family: &str,
) -> Result<JsValue, JsValue> {
    let proto = OperationMultiProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode operation multi proof: {err}")))?
        .to_owned_message()
        .map_err(|err| js_err(format!("materialize operation multi proof: {err}")))?;
    with_hash_family!(hash_family, "operation multi proof", {
        match normalize_family(merkle_family, "operation multi proof").map_err(js_err)? {
            "mmr" => {
                let (tip, root, operations) =
                    decode_multi_with_embedded_root_from_proto::<mmr::Family, H>(&proto)
                        .map_err(js_err)?;
                let decoded = Object::from(operation_proof_to_js(root, operations)?);
                set_field(&decoded, "tip", &location_to_bigint(tip))?;
                Ok(decoded.into())
            }
            "mmb" => {
                let (tip, root, operations) =
                    decode_multi_with_embedded_root_from_proto::<mmb::Family, H>(&proto)
                        .map_err(js_err)?;
                let decoded = Object::from(operation_proof_to_js(root, operations)?);
                set_field(&decoded, "tip", &location_to_bigint(tip))?;
                Ok(decoded.into())
            }
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

#[wasm_bindgen]
pub fn verify_operation_multi_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    hash_family: &str,
) -> Result<JsValue, JsValue> {
    let proto = OperationMultiProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode operation multi proof: {err}")))?
        .to_owned_message()
        .map_err(|err| js_err(format!("materialize operation multi proof: {err}")))?;
    with_hash_family!(hash_family, "operation multi proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "operation proof root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "operation multi proof").map_err(js_err)? {
            "mmr" => {
                let (root, operations) =
                    verify_multi_from_proto::<mmr::Family, H>(&proto, &root).map_err(js_err)?;
                operation_proof_to_js(root, operations)
            }
            "mmb" => {
                let (root, operations) =
                    verify_multi_from_proto::<mmb::Family, H>(&proto, &root).map_err(js_err)?;
                operation_proof_to_js(root, operations)
            }
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

#[wasm_bindgen]
pub fn verify_operation_range_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    hash_family: &str,
    expected_tip: u64,
    expected_start: u64,
    max_locations: u32,
) -> Result<JsValue, JsValue> {
    let window = OperationWindow::new(expected_tip, expected_start, max_locations)
        .map_err(|err| js_err(err.to_string()))?;
    let proto = OperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode operation range proof: {err}")))?
        .to_owned_message()
        .map_err(|err| js_err(format!("materialize operation range proof: {err}")))?;
    with_hash_family!(hash_family, "operation range proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "operation range root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "operation range proof").map_err(js_err)? {
            "mmr" => {
                let (root, operations) =
                    verify_operation_range_from_proto::<mmr::Family, H>(&proto, &root, window)
                        .map_err(js_err)?;
                operation_proof_to_js(root, operations)
            }
            "mmb" => {
                let (root, operations) =
                    verify_operation_range_from_proto::<mmb::Family, H>(&proto, &root, window)
                        .map_err(js_err)?;
                operation_proof_to_js(root, operations)
            }
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

#[wasm_bindgen]
pub fn verify_raw_operation_range_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    hash_family: &str,
    expected_tip: u64,
    expected_start: u64,
    max_locations: u32,
) -> Result<JsValue, JsValue> {
    let window = OperationWindow::new(expected_tip, expected_start, max_locations)
        .map_err(|err| js_err(err.to_string()))?;
    let proto = OperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode operation range proof: {err}")))?
        .to_owned_message()
        .map_err(|err| js_err(format!("materialize operation range proof: {err}")))?;
    with_hash_family!(hash_family, "operation range proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "operation range root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "operation range proof").map_err(js_err)? {
            "mmr" => {
                let (root, operations) =
                    verify_raw_operation_range::<mmr::Family, H>(&proto, &root, window)
                        .map_err(js_err)?;
                raw_operations_to_js(root, operations)
            }
            "mmb" => {
                let (root, operations) =
                    verify_raw_operation_range::<mmb::Family, H>(&proto, &root, window)
                        .map_err(js_err)?;
                raw_operations_to_js(root, operations)
            }
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn verify_fixed_keyless_append_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    hash_family: &str,
    expected_location: u64,
    expected_value: &[u8],
    expected_tip: u64,
    expected_start: u64,
    max_locations: u32,
) -> Result<JsValue, JsValue> {
    let window = OperationWindow::new(expected_tip, expected_start, max_locations)
        .map_err(|err| js_err(err.to_string()))?;
    let proto = OperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode operation range proof: {err}")))?
        .to_owned_message()
        .map_err(|err| js_err(format!("materialize operation range proof: {err}")))?;
    with_hash_family!(hash_family, "operation range proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "operation range root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "operation range proof").map_err(js_err)? {
            "mmr" => {
                let (root, operations) =
                    verify_raw_operation_range::<mmr::Family, H>(&proto, &root, window)
                        .map_err(js_err)?;
                let operation = expected_raw_operation(
                    proto.start_location,
                    &operations,
                    expected_location,
                    "keyless",
                )
                .map_err(js_err)?;
                let value =
                    fixed_keyless_append_value(&operation, expected_value).map_err(js_err)?;
                fixed_keyless_append_to_js(
                    root,
                    operations.len(),
                    Location::<mmr::Family>::new(expected_location),
                    &value,
                )
            }
            "mmb" => {
                let (root, operations) =
                    verify_raw_operation_range::<mmb::Family, H>(&proto, &root, window)
                        .map_err(js_err)?;
                let operation = expected_raw_operation(
                    proto.start_location,
                    &operations,
                    expected_location,
                    "keyless",
                )
                .map_err(js_err)?;
                let value =
                    fixed_keyless_append_value(&operation, expected_value).map_err(js_err)?;
                fixed_keyless_append_to_js(
                    root,
                    operations.len(),
                    Location::<mmb::Family>::new(expected_location),
                    &value,
                )
            }
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn verify_fixed_unordered_update_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    hash_family: &str,
    expected_location: u64,
    expected_key: &[u8],
    value_size: usize,
    expected_tip: u64,
    expected_start: u64,
    max_locations: u32,
) -> Result<JsValue, JsValue> {
    let window = OperationWindow::new(expected_tip, expected_start, max_locations)
        .map_err(|err| js_err(err.to_string()))?;
    let proto = OperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode operation range proof: {err}")))?
        .to_owned_message()
        .map_err(|err| js_err(format!("materialize operation range proof: {err}")))?;
    with_hash_family!(hash_family, "operation range proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "operation range root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "operation range proof").map_err(js_err)? {
            "mmr" => {
                let (root, operations) =
                    verify_raw_operation_range::<mmr::Family, H>(&proto, &root, window)
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
                    operations.len(),
                    Location::<mmr::Family>::new(expected_location),
                    expected_key,
                    &value,
                )
            }
            "mmb" => {
                let (root, operations) =
                    verify_raw_operation_range::<mmb::Family, H>(&proto, &root, window)
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
                    operations.len(),
                    Location::<mmb::Family>::new(expected_location),
                    expected_key,
                    &value,
                )
            }
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

/// Verify a serialized `qmdb.v1.OperationMultiProof` against `root`, `expected_tip`, and
/// `expected_locations`. Return encoded operations in location order. Locations must be
/// nonempty, strictly ascending, and at most `expected_tip`.
#[wasm_bindgen]
pub fn verify_operations_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    hash_family: &str,
    expected_tip: u64,
    expected_locations: Vec<u64>,
) -> Result<JsValue, JsValue> {
    let locations = OperationLocations::new(expected_tip, &expected_locations)
        .map_err(|err| js_err(err.to_string()))?;
    let proto = decode_operations_proof(bytes)?;
    with_hash_family!(hash_family, "operations multi proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "operations multi proof root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "operations multi proof").map_err(js_err)? {
            "mmr" => {
                let (root, operations) =
                    verify_raw_operations::<mmr::Family, H>(&proto, &root, &locations)
                        .map_err(js_err)?;
                raw_operations_to_js(root, operations)
            }
            "mmb" => {
                let (root, operations) =
                    verify_raw_operations::<mmb::Family, H>(&proto, &root, &locations)
                        .map_err(js_err)?;
                raw_operations_to_js(root, operations)
            }
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

/// Verify fixed keyless appends against `root` at the expected tip and locations.
/// `bytes` encodes a `qmdb.v1.OperationMultiProof`. Locations must be nonempty,
/// strictly ascending, and at most `expected_tip`. `expected_values` concatenates one
/// `value_size`-byte value per location.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn verify_fixed_keyless_append_operations_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    hash_family: &str,
    expected_tip: u64,
    expected_locations: Vec<u64>,
    expected_values: &[u8],
    value_size: usize,
) -> Result<JsValue, JsValue> {
    let locations = OperationLocations::new(expected_tip, &expected_locations)
        .map_err(|err| js_err(err.to_string()))?;
    let values = fixed_size_parts(
        expected_values,
        value_size,
        expected_locations.len(),
        "keyless value",
    )
    .map_err(js_err)?;
    let proto = decode_operations_proof(bytes)?;
    with_hash_family!(hash_family, "operations multi proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "operations multi proof root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "operations multi proof").map_err(js_err)? {
            "mmr" => {
                let (root, operations) =
                    verify_raw_operations::<mmr::Family, H>(&proto, &root, &locations)
                        .map_err(js_err)?;
                fixed_keyless_appends_to_js(root, &operations, &values)
            }
            "mmb" => {
                let (root, operations) =
                    verify_raw_operations::<mmb::Family, H>(&proto, &root, &locations)
                        .map_err(js_err)?;
                fixed_keyless_appends_to_js(root, &operations, &values)
            }
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

/// Verify fixed unordered updates against `root` at the expected tip and locations.
/// `bytes` encodes a `qmdb.v1.OperationMultiProof`. Locations must be nonempty,
/// strictly ascending, and at most `expected_tip`. `expected_keys` concatenates one
/// `key_size`-byte key per location.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn verify_fixed_unordered_update_operations_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    hash_family: &str,
    expected_tip: u64,
    expected_locations: Vec<u64>,
    expected_keys: &[u8],
    key_size: usize,
    value_size: usize,
) -> Result<JsValue, JsValue> {
    let locations = OperationLocations::new(expected_tip, &expected_locations)
        .map_err(|err| js_err(err.to_string()))?;
    let keys = fixed_size_parts(
        expected_keys,
        key_size,
        expected_locations.len(),
        "unordered key",
    )
    .map_err(js_err)?;
    let proto = decode_operations_proof(bytes)?;
    with_hash_family!(hash_family, "operations multi proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "operations multi proof root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "operations multi proof").map_err(js_err)? {
            "mmr" => {
                let (root, operations) =
                    verify_raw_operations::<mmr::Family, H>(&proto, &root, &locations)
                        .map_err(js_err)?;
                fixed_unordered_updates_to_js(root, &operations, &keys, value_size)
            }
            "mmb" => {
                let (root, operations) =
                    verify_raw_operations::<mmb::Family, H>(&proto, &root, &locations)
                        .map_err(js_err)?;
                fixed_unordered_updates_to_js(root, &operations, &keys, value_size)
            }
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn verify_current_operation_range_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    hash_family: &str,
    current_chunk_size: usize,
    expected_tip: u64,
    expected_start: u64,
    max_locations: u32,
) -> Result<JsValue, JsValue> {
    let window = OperationWindow::new(expected_tip, expected_start, max_locations)
        .map_err(|err| js_err(err.to_string()))?;
    let proto = CurrentOperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode current operation range proof: {err}")))?
        .to_owned_message()
        .map_err(|err| js_err(format!("materialize current operation range proof: {err}")))?;
    with_hash_family!(hash_family, "current operation range proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "current operation range root",
        )
        .map_err(js_err)?;
        let config = current_proof_config::<<H as commonware_cryptography::Hasher>::Digest>(
            current_chunk_size,
            "current operation range proof",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "current operation range proof").map_err(js_err)? {
            "mmr" => operations_to_js(
                verify_current_operation_range_from_proto::<mmr::Family, H>(
                    &proto, &root, &config, window,
                )
                .map_err(js_err)?,
            ),
            "mmb" => operations_to_js(
                verify_current_operation_range_from_proto::<mmb::Family, H>(
                    &proto, &root, &config, window,
                )
                .map_err(js_err)?,
            ),
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

#[wasm_bindgen]
pub fn encode_vec_key(key: &[u8]) -> Vec<u8> {
    key.encode().to_vec()
}

#[wasm_bindgen]
pub fn verify_current_key_value_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    hash_family: &str,
    current_chunk_size: usize,
    requested_key: &[u8],
) -> Result<JsValue, JsValue> {
    let proto = CurrentKeyValueProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode current key-value proof: {err}")))?
        .to_owned_message()
        .map_err(|err| js_err(format!("materialize current key-value proof: {err}")))?;
    with_hash_family!(hash_family, "current key-value proof", {
        let root =
            decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(root, "current root")
                .map_err(js_err)?;
        let config = current_proof_config::<<H as commonware_cryptography::Hasher>::Digest>(
            current_chunk_size,
            "current key-value proof",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "current key-value proof").map_err(js_err)? {
            "mmr" => {
                let (location, operation) = verify_key_value_for_key_from_proto::<mmr::Family, H>(
                    &proto,
                    requested_key,
                    &root,
                    &config,
                )
                .map_err(js_err)?;
                current_to_js(location, operation)
            }
            "mmb" => {
                let (location, operation) = verify_key_value_for_key_from_proto::<mmb::Family, H>(
                    &proto,
                    requested_key,
                    &root,
                    &config,
                )
                .map_err(js_err)?;
                current_to_js(location, operation)
            }
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

#[wasm_bindgen]
pub fn verify_get_many_response(
    bytes: &[u8],
    current_root: &[u8],
    merkle_family: &str,
    hash_family: &str,
    current_chunk_size: usize,
    requested_keys: Array,
) -> Result<JsValue, JsValue> {
    let proto = GetManyResponseView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode getMany response: {err}")))?
        .to_owned_message()
        .map_err(|err| js_err(format!("materialize getMany response: {err}")))?;
    let requested_keys = js_key_array_to_vec(requested_keys)?;
    with_hash_family!(hash_family, "getMany response", {
        let current_root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            current_root,
            "current root",
        )
        .map_err(js_err)?;
        let config = current_proof_config::<<H as commonware_cryptography::Hasher>::Digest>(
            current_chunk_size,
            "getMany response",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "getMany response").map_err(js_err)? {
            "mmr" => lookup_results_to_js::<mmr::Family, H>(
                &proto,
                &current_root,
                &requested_keys,
                &config,
            ),
            "mmb" => lookup_results_to_js::<mmb::Family, H>(
                &proto,
                &current_root,
                &requested_keys,
                &config,
            ),
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn verify_get_range_response(
    bytes: &[u8],
    current_root: &[u8],
    merkle_family: &str,
    hash_family: &str,
    current_chunk_size: usize,
    start_key: &[u8],
    end_key: &[u8],
    has_end_key: bool,
    limit: u32,
) -> Result<JsValue, JsValue> {
    let proto = GetRangeResponseView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode getRange response: {err}")))?
        .to_owned_message()
        .map_err(|err| js_err(format!("materialize getRange response: {err}")))?;
    let end_key = has_end_key.then_some(end_key);
    with_hash_family!(hash_family, "getRange response", {
        let current_root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            current_root,
            "current root",
        )
        .map_err(js_err)?;
        let config = current_proof_config::<<H as commonware_cryptography::Hasher>::Digest>(
            current_chunk_size,
            "getRange response",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "getRange response").map_err(js_err)? {
            "mmr" => verify_get_range_from_proto::<mmr::Family, H>(
                &proto,
                &current_root,
                start_key,
                end_key,
                &config,
                limit,
            ),
            "mmb" => verify_get_range_from_proto::<mmb::Family, H>(
                &proto,
                &current_root,
                start_key,
                end_key,
                &config,
                limit,
            ),
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_storage::{
        merkle::mem::Mem,
        qmdb::{
            any::{
                unordered::{Operation as UnorderedOperation, Update as UnorderedUpdate},
                value::FixedEncoding,
            },
            current::{
                grafting::{graftable_chunks, Verifier as GraftingVerifier},
                ordered::proof::constant::ExclusionProof as UpstreamExclusionProof,
                proof::constant::OperationProof as UpstreamOperationProof,
            },
            keyless,
        },
    };
    use commonware_utils::bitmap::Prunable;

    type OrderedVariableOperation<F> = OrderedOperation<F, Vec<u8>, Vec<u8>>;

    #[test]
    fn test_hash_family_validation() {
        assert_eq!(normalize_hash_family("sha256", "proof"), Ok("sha256"));
        assert_eq!(normalize_hash_family("blake3", "proof"), Ok("blake3"));
        assert_eq!(
            normalize_hash_family("crc32c", "proof"),
            Err("proof uses unsupported hash family crc32c".into())
        );
    }

    #[test]
    fn test_vec_key_wire_bytes_use_commonware_codec_frame() {
        let key = b"alpha".to_vec();
        assert_eq!(decode_vec_key_wire(&encode_vec_key(&key)).unwrap(), key);
        assert!(decode_vec_key_wire(b"alpha").is_err());
    }

    fn ordered_variable_operations<F>() -> Vec<OrderedVariableOperation<F>>
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

    fn operation_range_fixture<F>() -> (
        OperationRangeProof,
        Sha256Digest,
        Vec<(Location<F>, OrderedVariableOperation<F>)>,
        OperationWindow,
    )
    where
        F: merkle::Graftable,
        OrderedVariableOperation<F>:
            Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
    {
        operation_range_fixture_at::<F>(1, 4)
    }

    fn operation_range_fixture_at<F>(
        start_offset: u64,
        end_offset: u64,
    ) -> (
        OperationRangeProof,
        Sha256Digest,
        Vec<(Location<F>, OrderedVariableOperation<F>)>,
        OperationWindow,
    )
    where
        F: merkle::Graftable,
        OrderedVariableOperation<F>:
            Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
    {
        operation_range_fixture_at_with_hash::<F, Sha256>(start_offset, end_offset)
    }

    fn operation_range_fixture_at_with_hash<F, H>(
        start_offset: u64,
        end_offset: u64,
    ) -> (
        OperationRangeProof,
        H::Digest,
        Vec<(Location<F>, OrderedVariableOperation<F>)>,
        OperationWindow,
    )
    where
        F: merkle::Graftable,
        H: commonware_cryptography::Hasher,
        H::Digest: Encode,
        OrderedVariableOperation<F>:
            Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
    {
        let operations = ordered_variable_operations::<F>();
        let encoded = operations
            .iter()
            .map(|operation| operation.encode().to_vec())
            .collect::<Vec<_>>();
        let (proto, root, expected, window) =
            raw_operation_range_fixture_at::<F, H>(&encoded, start_offset, end_offset);
        let expected = expected
            .into_iter()
            .map(|(location, _)| (location, operations[*location as usize].clone()))
            .collect();
        (proto, root, expected, window)
    }

    fn raw_operation_range_fixture_at<F, H>(
        encoded_operations: &[Vec<u8>],
        start_offset: u64,
        end_offset: u64,
    ) -> (
        OperationRangeProof,
        H::Digest,
        Vec<(Location<F>, Vec<u8>)>,
        OperationWindow,
    )
    where
        F: merkle::Graftable,
        H: commonware_cryptography::Hasher,
        H::Digest: Encode,
    {
        let hasher = commonware_storage::qmdb::hasher::<H>();
        let mut merkle = Mem::<F, H::Digest>::new();

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
            OperationRangeProof {
                proof: proof.encode(),
                start_location: start_offset,
                encoded_operations: proven_operations.into_iter().map(Into::into).collect(),
                ops_root: root.encode(),
                pinned_nodes,
                ..Default::default()
            },
            root,
            expected,
            OperationWindow::new(
                encoded_operations.len() as u64 - 1,
                start_offset,
                u32::try_from(end_offset - start_offset).unwrap(),
            )
            .unwrap(),
        )
    }

    fn operation_multi_fixture<F>() -> (
        OperationMultiProof,
        Sha256Digest,
        Vec<(Location<F>, OrderedVariableOperation<F>)>,
    )
    where
        F: merkle::Graftable,
        OrderedVariableOperation<F>:
            Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
    {
        let hasher = commonware_storage::qmdb::hasher::<Sha256>();
        let mut merkle = Mem::<F, Sha256Digest>::new();
        let operations = ordered_variable_operations::<F>();

        let mut batch = merkle.new_batch();
        for operation in &operations {
            let encoded = operation.encode();
            batch = batch.add(&hasher, &encoded);
        }
        let batch = batch.merkleize(&merkle, &hasher);
        merkle.apply_batch(&batch).unwrap();

        let root = merkle.root(&hasher, 0).unwrap();
        let locations = vec![Location::<F>::new(0), Location::<F>::new(2)];
        let proof =
            futures::executor::block_on(merkle::verification::multi_proof(&merkle, 0, &locations))
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
            OperationMultiProof {
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
    fn test_verifies_operation_range_mmr() {
        let (proto, root, expected, window) = operation_range_fixture::<mmr::Family>();

        let (verified_root, verified) =
            verify_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root, window)
                .unwrap();

        assert_eq!(verified_root, root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn test_verifies_operation_range_mmb() {
        let (proto, root, expected, window) = operation_range_fixture::<mmb::Family>();

        let (verified_root, verified) =
            verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &root, window)
                .unwrap();

        assert_eq!(verified_root, root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn test_verifies_raw_operation_range_without_decoding() {
        let (proto, root, expected, window) = operation_range_fixture::<mmr::Family>();
        let expected = expected
            .into_iter()
            .map(|(location, operation)| (location, operation.encode().to_vec()))
            .collect::<Vec<_>>();

        let (verified_root, verified) =
            verify_raw_operation_range::<mmr::Family, Sha256>(&proto, &root, window).unwrap();

        assert_eq!(verified_root, root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn test_verifies_operation_range_with_blake3() {
        let (proto, root, expected, window) =
            operation_range_fixture_at_with_hash::<mmr::Family, Blake3>(1, 4);

        let (verified_root, verified) =
            verify_operation_range_from_proto::<mmr::Family, Blake3>(&proto, &root, window)
                .unwrap();

        assert_eq!(verified_root, root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn test_current_proof_config_follows_commonware_chunk_constraints() {
        let config = current_proof_config::<Sha256Digest>(64, "test proof").unwrap();

        assert_eq!(config.chunk_size, 64);
        assert_eq!(
            current_proof_config::<Sha256Digest>(48, "test proof").unwrap_err(),
            "test proof current chunk size must be a power of two"
        );
        assert_eq!(
            current_proof_config::<Sha256Digest>(16, "test proof").unwrap_err(),
            "test proof current chunk size must be a multiple of digest size 32"
        );
    }

    /// Commonware proofs with const chunk size `N` for testing runtime-sized verification.
    struct CurrentFixture<F: merkle::Graftable, const N: usize> {
        /// Operations in location order.
        operations: Vec<OrderedVariableOperation<F>>,

        /// Activity bitmap with one bit per operation.
        status: Prunable<N>,

        /// Operations tree hashed with bitmap chunks grafted in. Proof nodes come from this tree.
        grafted: Mem<F, Sha256Digest>,

        /// Root of the operations tree without activity status.
        ops_root: Sha256Digest,

        /// Current root that binds `ops_root` to the grafted root and trailing chunk digests.
        root: Sha256Digest,
    }

    impl<F: merkle::Graftable, const N: usize> CurrentFixture<F, N> {
        /// Builds `leaves` operations: an inactive update, active updates of keys 1 through
        /// `leaves - 2` whose successors wrap back to key 1, and a final commit.
        fn new(leaves: usize) -> Self {
            // Location 0 holds a superseded update of key 1, so its activity bit is clear.
            let key = |index: usize| (index as u32).to_be_bytes().to_vec();
            let mut operations = (0..leaves - 1)
                .map(|index| {
                    OrderedOperation::Update(Update {
                        key: key(index.max(1)),
                        value: vec![index as u8; 7],
                        next_key: key(if index + 1 == leaves - 1 {
                            1
                        } else {
                            index + 1
                        }),
                    })
                })
                .collect::<Vec<_>>();
            operations.push(OrderedOperation::CommitFloor(None, Location::new(1)));
            Self::from_operations(operations, true)
        }

        /// Builds the database from `operations`, all active except location 0 when
        /// `inactive_first` is set.
        fn from_operations(
            operations: Vec<OrderedVariableOperation<F>>,
            inactive_first: bool,
        ) -> Self {
            let leaves = operations.len();
            let mut status = Prunable::<N>::new();
            for index in 0..leaves {
                status.push(index != 0 || !inactive_first);
            }

            // Graft every chunk that Commonware grafts at this size into the operations tree.
            let chunks = (0..leaves.div_ceil(N * 8))
                .map(|index| status.get_chunk(index).as_slice())
                .collect::<Vec<_>>();
            let complete = leaves as u64 / (N as u64 * 8);
            let graftable =
                graftable_chunks::<F>(leaves as u64, (N * 8).trailing_zeros()).min(complete);
            let grafting =
                GraftingVerifier::<F, Sha256>::new((N * 8).trailing_zeros(), 0, chunks, graftable);

            // Build the plain and grafted trees over the same encoded operations.
            let hasher = commonware_storage::qmdb::hasher::<Sha256>();
            let mut ops_tree = Mem::<F, Sha256Digest>::new();
            let mut grafted = Mem::<F, Sha256Digest>::new();
            let mut ops_batch = ops_tree.new_batch();
            let mut grafted_batch = grafted.new_batch();
            for operation in &operations {
                let encoded = operation.encode();
                ops_batch = ops_batch.add(&hasher, &encoded);
                grafted_batch = grafted_batch.add(&grafting, &encoded);
            }
            ops_tree
                .apply_batch(&ops_batch.merkleize(&ops_tree, &hasher))
                .unwrap();
            grafted
                .apply_batch(&grafted_batch.merkleize(&grafted, &grafting))
                .unwrap();
            let ops_root = ops_tree.root(&hasher, 0).unwrap();

            // A full-range proof carries the pending and partial chunk digests that the current
            // root commits to.
            let proof = RangeProof::build::<Sha256, N>(
                &status,
                merkle::RangePlan::new(
                    Location::new(leaves as u64),
                    Location::new(0)..Location::new(leaves as u64),
                )
                .unwrap(),
                |position| grafted.get_node(position),
                Location::new(0),
                ops_root,
            )
            .unwrap();
            let root = OpsRootWitness::<F, _> {
                grafted_root: grafted.root(&grafting, 0).unwrap(),
                pending_chunk_digest: proof.pending_chunk_digest,
                partial_chunk: proof
                    .partial_chunk_digest
                    .map(|digest| (leaves as u64 % (N as u64 * 8), digest)),
            }
            .root::<Sha256>(&ops_root);
            Self {
                operations,
                status,
                grafted,
                ops_root,
                root,
            }
        }

        /// Builds Commonware's fixed-size operation proof for the operation at `index`.
        fn operation_proof(&self, index: usize) -> UpstreamOperationProof<F, Sha256Digest, N> {
            UpstreamOperationProof::build::<Sha256>(
                &self.status,
                merkle::ElementPlan::new(
                    Location::new(self.operations.len() as u64),
                    Location::new(index as u64),
                )
                .unwrap(),
                |position| self.grafted.get_node(position),
                Location::new(0),
                self.ops_root,
            )
            .unwrap()
        }

        /// Wraps the operation proof for `index` and its encoded operation in the wire message.
        fn key_value(&self, index: usize) -> CurrentKeyValueProof {
            CurrentKeyValueProof {
                proof: self.operation_proof(index).encode(),
                encoded_operation: self.operations[index].encode(),
                ..Default::default()
            }
        }

        /// Wraps an exclusion proof anchored at the update or commit at `index` in the wire
        /// message.
        fn exclusion(&self, index: usize) -> CurrentKeyExclusionProof {
            let proof = match &self.operations[index] {
                OrderedOperation::Update(update) => {
                    UpstreamExclusionProof::KeyValue(self.operation_proof(index), update.clone())
                }
                OrderedOperation::CommitFloor(metadata, _) => UpstreamExclusionProof::<
                    F,
                    Vec<u8>,
                    VariableEncoding<Vec<u8>>,
                    Sha256Digest,
                    N,
                >::Commit(
                    self.operation_proof(index),
                    metadata.clone(),
                ),
                _ => unreachable!(),
            };
            CurrentKeyExclusionProof {
                proof: proof.encode(),
                ..Default::default()
            }
        }

        /// Wraps a range proof over `start..end` and the bitmap chunks covering it in the wire
        /// message.
        fn range(&self, start: usize, end: usize) -> CurrentOperationRangeProof {
            let proof = RangeProof::build::<Sha256, N>(
                &self.status,
                merkle::RangePlan::new(
                    Location::new(self.operations.len() as u64),
                    Location::new(start as u64)..Location::new(end as u64),
                )
                .unwrap(),
                |position| self.grafted.get_node(position),
                Location::new(0),
                self.ops_root,
            )
            .unwrap();
            CurrentOperationRangeProof {
                proof: proof.encode(),
                start_location: start as u64,
                encoded_operations: self.operations[start..end]
                    .iter()
                    .map(Encode::encode)
                    .collect(),
                chunks: (start / (N * 8)..=(end - 1) / (N * 8))
                    .map(|index| self.status.get_chunk(index).to_vec().into())
                    .collect(),
                ..Default::default()
            }
        }
    }

    /// Checks that proofs built with Commonware's const chunk size `N` verify with the
    /// same chunk size supplied at runtime.
    fn assert_current_interoperability<F: merkle::Graftable + PartialEq, const N: usize>() {
        let config = current_proof_config::<Sha256Digest>(N, "test").unwrap();

        // Leaf counts straddle the first chunk boundary and pass the second, so the trailing chunk
        // is partial in some databases and complete in others.
        for leaves in [N * 8 - 1, N * 8, N * 8 + 1, N * 8 + 2, N * 16 + 3] {
            // A range starting just before the first chunk boundary verifies through the tip.
            let fixture = CurrentFixture::<F, N>::new(leaves);
            let start = N * 8 - 2;
            let proto = fixture.range(start, leaves);
            let window =
                OperationWindow::new(leaves as u64 - 1, start as u64, (leaves - start) as u32)
                    .unwrap();
            let verified = verify_current_operation_range_from_proto::<F, Sha256>(
                &proto,
                &fixture.root,
                &config,
                window,
            )
            .unwrap();
            assert_eq!(verified.len(), leaves - start);
            assert_eq!(verified[0].1, fixture.operations[start]);

            // Key-value proofs verify for the first active update and the last update.
            for index in [1, leaves - 2] {
                let requested_key = match &fixture.operations[index] {
                    OrderedOperation::Update(update) => update.key.encode(),
                    _ => unreachable!(),
                };
                let (location, operation) = verify_key_value_for_key_from_proto::<F, Sha256>(
                    &fixture.key_value(index),
                    &requested_key,
                    &fixture.root,
                    &config,
                )
                .unwrap();
                assert_eq!(location, Location::new(index as u64));
                assert_eq!(operation, fixture.operations[index]);
            }
        }
    }

    #[test]
    fn test_current_proofs_interoperate_with_commonware_runtime_chunk_sizes() {
        assert_current_interoperability::<mmr::Family, 32>();
        assert_current_interoperability::<mmb::Family, 32>();
        assert_current_interoperability::<mmr::Family, 128>();
        assert_current_interoperability::<mmb::Family, 128>();
    }

    /// Checks that the current verifiers bind each result to the requested key, root, activity
    /// bit, and window.
    fn assert_current_request_binding<F: merkle::Graftable + PartialEq>() {
        // 515 operations fill one 512-bit chunk and spill into a partial chunk.
        let fixture = CurrentFixture::<F, 64>::new(515);
        let config = current_proof_config::<Sha256Digest>(64, "test").unwrap();

        // A key-value proof fails for another key, for the operations root, and for an inactive
        // operation.
        let hit = fixture.key_value(1);
        let key = 1u32.to_be_bytes().to_vec().encode();
        assert!(verify_key_value_for_key_from_proto::<F, Sha256>(
            &hit,
            &2u32.to_be_bytes().to_vec().encode(),
            &fixture.root,
            &config
        )
        .unwrap_err()
        .contains("key mismatch"));
        assert!(verify_key_value_for_key_from_proto::<F, Sha256>(
            &hit,
            &key,
            &fixture.ops_root,
            &config
        )
        .is_err());
        let inactive = fixture.key_value(0);
        assert!(verify_key_value_for_key_from_proto::<F, Sha256>(
            &inactive,
            &key,
            &fixture.root,
            &config
        )
        .is_err());

        // A range proof verifies only for its exact tip, start, and count.
        let range = fixture.range(0, 2);
        let window = OperationWindow::new(514, 0, 2).unwrap();
        assert!(verify_current_operation_range_from_proto::<F, Sha256>(
            &range,
            &fixture.root,
            &config,
            window
        )
        .is_ok());
        for window in [
            OperationWindow::new(513, 0, 2),
            OperationWindow::new(514, 1, 2),
            OperationWindow::new(514, 0, 3),
        ] {
            assert!(verify_current_operation_range_from_proto::<F, Sha256>(
                &range,
                &fixture.root,
                &config,
                window.unwrap()
            )
            .is_err());
        }

        // A span excludes keys strictly between its key and successor and returns the successor.
        // The span's own key, its successor, and keys outside the span are rejected.
        let span = fixture.exclusion(1);
        let between = vec![0u8, 0, 0, 1, 1].encode();
        assert_eq!(
            verify_key_exclusion_from_proto::<F, Sha256>(&span, &between, &fixture.root, &config)
                .unwrap(),
            Some(2u32.to_be_bytes().to_vec())
        );
        for key in [1u32, 2, 3] {
            assert!(verify_key_exclusion_from_proto::<F, Sha256>(
                &span,
                &key.to_be_bytes().to_vec().encode(),
                &fixture.root,
                &config
            )
            .is_err());
        }

        // The last update's span wraps from the largest key around to the smallest.
        let wrap = fixture.exclusion(513);
        assert!(verify_key_exclusion_from_proto::<F, Sha256>(
            &wrap,
            &0u32.to_be_bytes().to_vec().encode(),
            &fixture.root,
            &config
        )
        .is_ok());

        // A commit proves exclusion only when its floor equals its own location, as it does in a
        // database with no active keys.
        let commit = fixture.exclusion(514);
        assert!(verify_key_exclusion_from_proto::<F, Sha256>(
            &commit,
            &key,
            &fixture.root,
            &config
        )
        .is_err());
        let empty = CurrentFixture::<F, 64>::from_operations(
            vec![OrderedOperation::CommitFloor(
                Some(vec![7]),
                Location::new(0),
            )],
            false,
        );
        assert_eq!(
            verify_key_exclusion_from_proto::<F, Sha256>(
                &empty.exclusion(0),
                &key,
                &empty.root,
                &config
            )
            .unwrap(),
            None
        );

        // A lone empty key is its own successor, so its span excludes every other key.
        let singleton = CurrentFixture::<F, 64>::from_operations(
            vec![
                OrderedOperation::Update(Update {
                    key: Vec::new(),
                    value: Vec::new(),
                    next_key: Vec::new(),
                }),
                OrderedOperation::CommitFloor(None, Location::new(0)),
            ],
            false,
        );
        assert!(verify_key_value_for_key_from_proto::<F, Sha256>(
            &singleton.key_value(0),
            &Vec::<u8>::new().encode(),
            &singleton.root,
            &config,
        )
        .is_ok());
        let exclusion = singleton.exclusion(0);
        assert!(verify_key_exclusion_from_proto::<F, Sha256>(
            &exclusion,
            &Vec::<u8>::new().encode(),
            &singleton.root,
            &config,
        )
        .is_err());
        assert_eq!(
            verify_key_exclusion_from_proto::<F, Sha256>(
                &exclusion,
                &b"absent".to_vec().encode(),
                &singleton.root,
                &config,
            )
            .unwrap(),
            Some(Vec::new())
        );
    }

    #[test]
    fn test_current_proofs_bind_requested_keys_roots_activity_and_windows() {
        assert_current_request_binding::<mmr::Family>();
        assert_current_request_binding::<mmb::Family>();
    }

    /// Checks that malformed wire input and mismatched chunk sizes return errors.
    fn assert_current_malformed_proofs<F: merkle::Graftable>() {
        let fixture = CurrentFixture::<F, 64>::new(515);
        let config = current_proof_config::<Sha256Digest>(64, "test").unwrap();

        // Every strict prefix of a key-value proof or its operation is rejected.
        let hit = fixture.key_value(1);
        for end in 0..hit.proof.len() {
            let mut truncated = hit.clone();
            truncated.proof = hit.proof.slice(..end);
            assert!(
                verify_key_value_from_proto::<F, Sha256>(&truncated, &fixture.root, &config)
                    .is_err()
            );
        }
        for end in 0..hit.encoded_operation.len() {
            let mut truncated = hit.clone();
            truncated.encoded_operation = hit.encoded_operation.slice(..end);
            assert!(
                verify_key_value_from_proto::<F, Sha256>(&truncated, &fixture.root, &config)
                    .is_err()
            );
        }

        // Every strict prefix of a span or commit exclusion proof is rejected.
        let exclusion = fixture.exclusion(1);
        let key = vec![0u8, 0, 0, 1, 1].encode();
        for end in 0..exclusion.proof.len() {
            let mut truncated = exclusion.clone();
            truncated.proof = exclusion.proof.slice(..end);
            assert!(verify_key_exclusion_from_proto::<F, Sha256>(
                &truncated,
                &key,
                &fixture.root,
                &config
            )
            .is_err());
        }
        let commit = CurrentFixture::<F, 64>::from_operations(
            vec![OrderedOperation::CommitFloor(None, Location::new(0))],
            false,
        );
        let commit_proof = commit.exclusion(0);
        for end in 0..commit_proof.proof.len() {
            let mut truncated = commit_proof.clone();
            truncated.proof = commit_proof.proof.slice(..end);
            assert!(verify_key_exclusion_from_proto::<F, Sha256>(
                &truncated,
                &key,
                &commit.root,
                &config
            )
            .is_err());
        }

        // Trailing bytes, a tampered operation, and an unknown exclusion tag are rejected.
        let mut trailing_exclusion = exclusion.clone();
        trailing_exclusion.proof = [exclusion.proof.as_ref(), &[0]].concat().into();
        assert!(verify_key_exclusion_from_proto::<F, Sha256>(
            &trailing_exclusion,
            &key,
            &fixture.root,
            &config
        )
        .is_err());
        let mut tampered = hit.clone();
        let mut operation = tampered.encoded_operation.to_vec();
        *operation.last_mut().unwrap() ^= 1;
        tampered.encoded_operation = operation.into();
        assert!(
            verify_key_value_from_proto::<F, Sha256>(&tampered, &fixture.root, &config).is_err()
        );
        let mut trailing = hit.clone();
        trailing.proof = [hit.proof.as_ref(), &[0]].concat().into();
        assert!(
            verify_key_value_from_proto::<F, Sha256>(&trailing, &fixture.root, &config).is_err()
        );
        let mut invalid_tag = exclusion.clone();
        let mut bytes = invalid_tag.proof.to_vec();
        bytes[0] = 255;
        invalid_tag.proof = bytes.into();
        assert!(verify_key_exclusion_from_proto::<F, Sha256>(
            &invalid_tag,
            &key,
            &fixture.root,
            &config
        )
        .is_err());

        // Every proof path rejects mismatched chunks, overflowing bit widths, and bit widths
        // that reach u64's top bit.
        let range = fixture.range(510, 515);
        let window = OperationWindow::new(514, 510, 5).unwrap();
        let mut wrong_sizes = vec![32, 128, 1usize << (usize::BITS - 1)];
        if let Ok(size) = usize::try_from((1u64 << (u64::BITS - 1)) / u64::from(u8::BITS)) {
            wrong_sizes.push(size);
        }
        for size in wrong_sizes {
            let wrong = CurrentProofConfig { chunk_size: size };
            assert!(verify_key_value_from_proto::<F, Sha256>(&hit, &fixture.root, &wrong).is_err());
            assert!(verify_key_exclusion_from_proto::<F, Sha256>(
                &exclusion,
                &key,
                &fixture.root,
                &wrong
            )
            .is_err());
            assert!(verify_key_exclusion_from_proto::<F, Sha256>(
                &commit_proof,
                &key,
                &commit.root,
                &wrong
            )
            .is_err());
            assert!(verify_current_operation_range_from_proto::<F, Sha256>(
                &range,
                &fixture.root,
                &wrong,
                window
            )
            .is_err());
        }

        // Range proofs reject truncation and a short chunk.
        for end in 0..range.proof.len() {
            let mut truncated = range.clone();
            truncated.proof = range.proof.slice(..end);
            assert!(verify_current_operation_range_from_proto::<F, Sha256>(
                &truncated,
                &fixture.root,
                &config,
                window
            )
            .is_err());
        }
        let mut short_chunk = range.clone();
        short_chunk.chunks[0] = short_chunk.chunks[0].slice(..63);
        assert!(verify_current_operation_range_from_proto::<F, Sha256>(
            &short_chunk,
            &fixture.root,
            &config,
            window
        )
        .is_err());

        // Chunks that differ from the authenticated bitmap, or are missing, are rejected.
        let mut invalid_chunks = range.clone();
        invalid_chunks.chunks[0] = vec![0; 64].into();
        assert!(verify_current_operation_range_from_proto::<F, Sha256>(
            &invalid_chunks,
            &fixture.root,
            &config,
            window
        )
        .is_err());
        invalid_chunks.chunks.clear();
        assert!(verify_current_operation_range_from_proto::<F, Sha256>(
            &invalid_chunks,
            &fixture.root,
            &config,
            window
        )
        .is_err());
    }

    #[test]
    fn test_current_proofs_reject_malformed_wire_and_wrong_chunk_sizes() {
        assert_current_malformed_proofs::<mmr::Family>();
        assert_current_malformed_proofs::<mmb::Family>();

        // Zero, non-power-of-two, and smaller-than-digest sizes fail before proof verification.
        for size in [0, 48, 16] {
            assert!(current_proof_config::<Sha256Digest>(size, "test").is_err());
        }
    }

    #[test]
    fn test_fixed_operation_tags_follow_commonware_encodings() {
        type Keyless<F> = keyless::Operation<F, FixedEncoding<Sha256Digest>>;
        type Unordered<F> = UnorderedOperation<F, Sha256Digest, FixedEncoding<u64>>;

        let value = Sha256::fill(0x22);
        let commit = Keyless::<mmr::Family>::Commit(Some(value), Location::new(3)).encode();
        assert_eq!(
            fixed_keyless_append_value(&commit, value.as_ref()).unwrap_err(),
            "expected keyless location is not an append"
        );

        let key = Sha256::fill(0x44);
        let delete = Unordered::<mmr::Family>::Delete(key).encode();
        assert_eq!(
            fixed_unordered_update_value(&delete, key.as_ref(), u64::SIZE).unwrap_err(),
            "expected unordered location is a delete"
        );
        let commit = Unordered::<mmr::Family>::CommitFloor(Some(7), Location::new(2)).encode();
        assert_eq!(
            fixed_unordered_update_value(&commit, key.as_ref(), u64::SIZE).unwrap_err(),
            "expected unordered location is a commit"
        );
    }

    #[test]
    fn test_verifies_fixed_keyless_append_operation() {
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
        let (proto, root, _, window) =
            raw_operation_range_fixture_at::<mmr::Family, Sha256>(&operations, 0, 3);
        let (_, verified) =
            verify_raw_operation_range::<mmr::Family, Sha256>(&proto, &root, window).unwrap();
        let operation =
            expected_raw_operation(proto.start_location, &verified, 1, "keyless").unwrap();

        let value = fixed_keyless_append_value(&operation, expected_value.as_ref()).unwrap();

        assert_eq!(value.as_slice(), expected_value.as_ref());
    }

    #[test]
    fn test_verifies_fixed_keyless_append_operation_with_runtime_value_size() {
        type Operation<F> = keyless::Operation<F, FixedEncoding<[u8; 16]>>;

        let expected_value = [0x22; 16];
        let operations = vec![
            Operation::<mmr::Family>::Append([0x11; 16])
                .encode()
                .to_vec(),
            Operation::<mmr::Family>::Append(expected_value)
                .encode()
                .to_vec(),
            Operation::<mmr::Family>::Append([0x33; 16])
                .encode()
                .to_vec(),
        ];
        let (proto, root, _, window) =
            raw_operation_range_fixture_at::<mmr::Family, Sha256>(&operations, 0, 3);
        let (_, verified) =
            verify_raw_operation_range::<mmr::Family, Sha256>(&proto, &root, window).unwrap();
        let operation =
            expected_raw_operation(proto.start_location, &verified, 1, "keyless").unwrap();

        let value = fixed_keyless_append_value(&operation, expected_value.as_ref()).unwrap();

        assert_eq!(value.as_slice(), expected_value.as_ref());
    }

    #[test]
    fn test_verifies_fixed_unordered_update_operation() {
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
        let (proto, root, _, window) =
            raw_operation_range_fixture_at::<mmr::Family, Sha256>(&operations, 0, 3);
        let (_, verified) =
            verify_raw_operation_range::<mmr::Family, Sha256>(&proto, &root, window).unwrap();
        let operation =
            expected_raw_operation(proto.start_location, &verified, 1, "unordered").unwrap();

        let value =
            fixed_unordered_update_value(&operation, expected_key.as_ref(), u64::SIZE).unwrap();

        assert_eq!(value.as_slice(), expected_value.encode().as_ref());
    }

    #[test]
    fn test_verifies_fixed_unordered_update_operation_with_runtime_value_size() {
        type Operation<F> = UnorderedOperation<F, Sha256Digest, FixedEncoding<[u8; 16]>>;

        let expected_key = Sha256::fill(0x44);
        let expected_value = [0x77; 16];
        let operations = vec![
            Operation::<mmr::Family>::Update(UnorderedUpdate(Sha256::fill(0x11), [0x01; 16]))
                .encode()
                .to_vec(),
            Operation::<mmr::Family>::Update(UnorderedUpdate(expected_key, expected_value))
                .encode()
                .to_vec(),
            Operation::<mmr::Family>::Update(UnorderedUpdate(Sha256::fill(0x33), [0x03; 16]))
                .encode()
                .to_vec(),
        ];
        let (proto, root, _, window) =
            raw_operation_range_fixture_at::<mmr::Family, Sha256>(&operations, 0, 3);
        let (_, verified) =
            verify_raw_operation_range::<mmr::Family, Sha256>(&proto, &root, window).unwrap();
        let operation =
            expected_raw_operation(proto.start_location, &verified, 1, "unordered").unwrap();

        let value =
            fixed_unordered_update_value(&operation, expected_key.as_ref(), expected_value.len())
                .unwrap();

        assert_eq!(value.as_slice(), expected_value.as_ref());
    }

    #[test]
    fn test_operation_range_pinned_nodes_match_mmr_start_location() {
        let (zero_start, zero_root, zero_expected, window) =
            operation_range_fixture_at::<mmr::Family>(0, 3);
        assert!(
            zero_start.pinned_nodes.is_empty(),
            "zero-start MMR ranges must not carry pinned nodes"
        );
        let (_, zero_verified) = verify_operation_range_from_proto::<mmr::Family, Sha256>(
            &zero_start,
            &zero_root,
            window,
        )
        .unwrap();
        assert_eq!(zero_verified, zero_expected);

        let (nonzero_start, nonzero_root, nonzero_expected, window) =
            operation_range_fixture_at::<mmr::Family>(1, 4);
        assert!(
            !nonzero_start.pinned_nodes.is_empty(),
            "nonzero-start MMR ranges must carry pinned nodes"
        );
        let (_, nonzero_verified) = verify_operation_range_from_proto::<mmr::Family, Sha256>(
            &nonzero_start,
            &nonzero_root,
            window,
        )
        .unwrap();
        assert_eq!(nonzero_verified, nonzero_expected);
    }

    #[test]
    fn test_operation_range_pinned_nodes_match_mmb_start_location() {
        let (zero_start, zero_root, zero_expected, window) =
            operation_range_fixture_at::<mmb::Family>(0, 3);
        assert!(
            zero_start.pinned_nodes.is_empty(),
            "zero-start MMB ranges must not carry pinned nodes"
        );
        let (_, zero_verified) = verify_operation_range_from_proto::<mmb::Family, Sha256>(
            &zero_start,
            &zero_root,
            window,
        )
        .unwrap();
        assert_eq!(zero_verified, zero_expected);

        let (nonzero_start, nonzero_root, nonzero_expected, window) =
            operation_range_fixture_at::<mmb::Family>(1, 4);
        assert!(
            !nonzero_start.pinned_nodes.is_empty(),
            "nonzero-start MMB ranges must carry pinned nodes"
        );
        let (_, nonzero_verified) = verify_operation_range_from_proto::<mmb::Family, Sha256>(
            &nonzero_start,
            &nonzero_root,
            window,
        )
        .unwrap();
        assert_eq!(nonzero_verified, nonzero_expected);
    }

    #[test]
    fn test_rejects_operation_range_mmr_without_nonzero_pinned_nodes() {
        let (mut proto, root, _, window) = operation_range_fixture::<mmr::Family>();
        proto.pinned_nodes.clear();

        let err = verify_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root, window)
            .unwrap_err();

        assert_eq!(err, "operation range proof failed verification");
    }

    #[test]
    fn test_rejects_operation_range_mmb_without_nonzero_pinned_nodes() {
        let (mut proto, root, _, window) = operation_range_fixture::<mmb::Family>();
        proto.pinned_nodes.clear();

        let err = verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &root, window)
            .unwrap_err();

        assert_eq!(err, "operation range proof failed verification");
    }

    #[test]
    fn test_rejects_operation_range_mmr_with_zero_start_pinned_nodes() {
        let (mut proto, root, _, window) = operation_range_fixture_at::<mmr::Family>(0, 3);
        proto.pinned_nodes.push(root.encode());

        let err = verify_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root, window)
            .unwrap_err();

        assert_eq!(err, "operation range proof failed verification");
    }

    #[test]
    fn test_rejects_operation_range_mmb_with_zero_start_pinned_nodes() {
        let (mut proto, root, _, window) = operation_range_fixture_at::<mmb::Family>(0, 3);
        proto.pinned_nodes.push(root.encode());

        let err = verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &root, window)
            .unwrap_err();

        assert_eq!(err, "operation range proof failed verification");
    }

    #[test]
    fn test_rejects_operation_range_mmb_with_tampered_pinned_node() {
        let (mut proto, root, _, window) = operation_range_fixture::<mmb::Family>();
        let mut pinned_node = proto.pinned_nodes[0].to_vec();
        pinned_node[0] ^= 0x01;
        proto.pinned_nodes[0] = pinned_node.into();

        let err = verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &root, window)
            .unwrap_err();

        assert_eq!(err, "operation range proof failed verification");
    }

    #[test]
    fn test_rejects_operation_range_mmb_with_extra_pinned_node() {
        let (mut proto, root, _, window) = operation_range_fixture::<mmb::Family>();
        proto.pinned_nodes.push(proto.pinned_nodes[0].clone());

        let err = verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &root, window)
            .unwrap_err();

        assert_eq!(err, "operation range proof failed verification");
    }

    fn assert_operations_proof_verifies<F>()
    where
        F: merkle::Graftable,
        OrderedVariableOperation<F>:
            Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
    {
        let (proto, ops_root, expected) = operation_multi_fixture::<F>();
        let locations = OperationLocations::new(4, &[0, 2]).unwrap();
        let (root, verified) =
            verify_raw_operations::<F, Sha256>(&proto, &ops_root, &locations).unwrap();
        assert_eq!(root, ops_root);
        assert_eq!(
            verified,
            expected
                .into_iter()
                .map(|(location, operation)| (location, operation.encode().to_vec()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_operations_proof_verifies_requested_locations() {
        assert_operations_proof_verifies::<mmr::Family>();
        assert_operations_proof_verifies::<mmb::Family>();
    }

    #[test]
    fn test_operations_proof_rejects_mismatched_requests_and_tampering() {
        let (proto, ops_root, _) = operation_multi_fixture::<mmr::Family>();
        let verify = |proto: &OperationMultiProof, tip: u64, locations: &[u64], root| {
            let locations = OperationLocations::new(tip, locations).unwrap();
            verify_raw_operations::<mmr::Family, Sha256>(proto, root, &locations)
        };

        assert!(verify(&proto, 5, &[0, 2], &ops_root)
            .unwrap_err()
            .contains("requested tip"));
        assert!(verify(&proto, 3, &[0, 2], &ops_root)
            .unwrap_err()
            .contains("requested tip"));
        for locations in [&[0, 1][..], &[0, 2, 3], &[2]] {
            assert!(verify(&proto, 4, locations, &ops_root)
                .unwrap_err()
                .contains("requested locations"));
        }
        let untrusted = Sha256Digest::from([9u8; 32]);
        assert!(verify(&proto, 4, &[0, 2], &untrusted).is_err());

        let mut tampered = proto.clone();
        let mut bytes = tampered.operations[1].encoded_operation.to_vec();
        *bytes.last_mut().unwrap() ^= 0x01;
        tampered.operations[1].encoded_operation = bytes.into();
        assert!(verify(&tampered, 4, &[0, 2], &ops_root)
            .unwrap_err()
            .contains("failed verification"));

        // A relabeled location that matches the request still fails the proof.
        let mut relabeled = proto;
        relabeled.operations[1].location = 1;
        assert!(verify(&relabeled, 4, &[0, 1], &ops_root)
            .unwrap_err()
            .contains("failed verification"));
    }

    #[test]
    fn test_operations_proof_binds_ops_root_through_witness() {
        let (mut proto, ops_root, _) = operation_multi_fixture::<mmb::Family>();
        let witness = OpsRootWitness::<mmb::Family, Sha256Digest> {
            grafted_root: Sha256::fill(0x11),
            pending_chunk_digest: Some(Sha256::fill(0x22)),
            partial_chunk: Some((13, Sha256::fill(0x33))),
        };
        let current_root = witness.root::<Sha256>(&ops_root);
        proto.ops_root_witness = witness.encode();
        let locations = OperationLocations::new(4, &[0, 2]).unwrap();

        // The trusted root is the current root; the witness binds the ops root to it.
        let (root, _) =
            verify_raw_operations::<mmb::Family, Sha256>(&proto, &current_root, &locations)
                .unwrap();
        assert_eq!(root, current_root);
        assert!(
            verify_raw_operations::<mmb::Family, Sha256>(&proto, &ops_root, &locations)
                .unwrap_err()
                .contains("witness")
        );
    }

    #[test]
    fn test_fixed_size_parts_require_one_part_per_location() {
        assert_eq!(
            fixed_size_parts(&[1, 2, 3, 4], 2, 2, "value").unwrap(),
            vec![&[1, 2][..], &[3, 4][..]]
        );
        assert!(fixed_size_parts(&[1, 2, 3], 2, 2, "value").is_err());
        assert!(fixed_size_parts(&[1, 2, 3, 4], 2, 3, "value").is_err());
        assert!(fixed_size_parts(&[], 0, 2, "value").is_err());
        assert!(fixed_size_parts(&[1], usize::MAX, 2, "value").is_err());
    }

    #[test]
    fn test_decodes_subscribe_multi_proof_without_ops_root_witness() {
        let (proto, ops_root, expected) = operation_multi_fixture::<mmr::Family>();

        let (tip, root, verified) =
            decode_multi_with_embedded_root_from_proto::<mmr::Family, Sha256>(&proto).unwrap();

        assert_eq!(tip, Location::new(4));
        assert_eq!(root, ops_root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn test_decodes_subscribe_multi_proof_with_ops_root_witness() {
        let (mut proto, ops_root, expected) = operation_multi_fixture::<mmb::Family>();
        let witness = OpsRootWitness::<mmb::Family, Sha256Digest> {
            grafted_root: Sha256::fill(0x11),
            pending_chunk_digest: Some(Sha256::fill(0x22)),
            partial_chunk: Some((13, Sha256::fill(0x33))),
        };
        let current_root = witness.root::<Sha256>(&ops_root);
        proto.ops_root_witness = witness.encode();

        let (tip, root, verified) =
            decode_multi_with_embedded_root_from_proto::<mmb::Family, Sha256>(&proto).unwrap();

        assert_eq!(tip, Location::new(4));
        assert_eq!(root, current_root);
        assert_ne!(root, ops_root);
        assert_eq!(verified, expected);
    }

    fn empty_subscription<F: merkle::Graftable>() {
        let hasher = commonware_storage::qmdb::hasher::<Sha256>();
        let root = Mem::<F, Sha256Digest>::new().root(&hasher, 0).unwrap();
        let proof = merkle::Proof::<F, Sha256Digest> {
            leaves: Location::new(0),
            inactive_peaks: 0,
            digests: Vec::new(),
        };
        let proto = OperationMultiProof {
            proof: proof.encode(),
            ops_root: root.encode(),
            ..Default::default()
        };
        assert_eq!(
            decode_multi_with_embedded_root_from_proto::<F, Sha256>(&proto).unwrap_err(),
            "subscription proof has no leaves",
        );
    }

    #[test]
    fn test_subscription_mmr_empty_proof() {
        empty_subscription::<mmr::Family>();
    }

    #[test]
    fn test_subscription_mmb_empty_proof() {
        empty_subscription::<mmb::Family>();
    }

    #[test]
    fn test_rejects_subscribe_multi_proof_missing_ops_root() {
        let (mut proto, _, _) = operation_multi_fixture::<mmr::Family>();
        proto.ops_root.clear();

        let err =
            decode_multi_with_embedded_root_from_proto::<mmr::Family, Sha256>(&proto).unwrap_err();

        assert_eq!(err, "operation multi proof missing embedded ops_root");
    }

    #[test]
    fn test_rejects_operation_range_without_ops_root() {
        let (mut proto, root, _, window) = operation_range_fixture::<mmr::Family>();
        proto.ops_root.clear();

        let err = verify_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root, window)
            .unwrap_err();

        assert_eq!(err, "operation proof missing ops_root");
    }

    #[test]
    fn test_rejects_operation_range_root_mismatch() {
        let (proto, root, _, window) = operation_range_fixture::<mmb::Family>();
        let wrong_root = Sha256::fill(0x42);
        assert_ne!(wrong_root, root);

        let err =
            verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &wrong_root, window)
                .unwrap_err();

        assert_eq!(err, "operation-log root did not match expected root");
    }
}
