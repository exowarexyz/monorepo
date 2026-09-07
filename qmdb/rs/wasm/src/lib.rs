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
    Decode, DecodeExt, DecodeRangeExt, Encode, FixedSize, RangeCfg, Read, ReadExt,
};
use commonware_cryptography::{Blake3, Crc32, Digest, Sha256};
use commonware_storage::{
    merkle::{self, hasher::Hasher as MerkleHasher, Location, PendingChunk},
    mmb, mmr,
    qmdb::{
        any::{
            ordered::{variable::Operation as OrderedOperation, Update},
            value::VariableEncoding,
        },
        current::{
            grafting::{graftable_chunks, Verifier as GraftingVerifier},
            proof::{OpsRootWitness, RangeProof},
        },
        verify::{verify_multi_proof, verify_proof_and_pinned_nodes},
    },
};
use js_sys::{Array, Object, Reflect, Uint8Array};
use std::collections::BTreeSet;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

pub mod proto;

#[path = "../../src/request.rs"]
mod request;
use request::{span_contains, validate_key_range, OperationWindow};

const MAX_OPERATION_SIZE: usize = u16::MAX as usize;

// The WASM API receives raw fixed-operation bytes plus runtime key/value sizes.
// Mirror Commonware's fixed-operation wire tags so verification is not tied to
// one concrete Rust value type.
const FIXED_KEYLESS_COMMIT_CONTEXT: u8 = 0;
const FIXED_KEYLESS_APPEND_CONTEXT: u8 = 1;
const FIXED_UNORDERED_DELETE_CONTEXT: u8 = 0xD1;
const FIXED_UNORDERED_UPDATE_CONTEXT: u8 = 0xD2;
const FIXED_UNORDERED_COMMIT_CONTEXT: u8 = 0xD3;

fn decode_vec_key_wire(encoded_key: &[u8]) -> Result<Vec<u8>, String> {
    Vec::<u8>::decode_range(encoded_key, 0..=MAX_OPERATION_SIZE)
        .map_err(|err| format!("failed to decode QMDB key: {err}"))
}

#[derive(Debug)]
struct CurrentProofConfig {
    chunk_size: usize,
    chunk_bits: u64,
    grafting_height: u32,
}

struct OperationProof<F: merkle::Graftable, D: Digest> {
    loc: Location<F>,
    chunk: Vec<u8>,
    range_proof: RangeProof<F, D>,
}

enum ExclusionProof<F: merkle::Graftable, D: Digest> {
    KeyValue(
        OperationProof<F, D>,
        Update<Vec<u8>, VariableEncoding<Vec<u8>>>,
    ),
    Commit(OperationProof<F, D>, Option<Vec<u8>>),
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
    D::decode(bytes).map_err(|err| format!("failed to decode {label}: {err}"))
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
        "sha256" | "blake3" | "crc32c" => Ok(family),
        "" => Err(format!("{label} missing hash family")),
        other => Err(format!("{label} uses unsupported hash family {other}")),
    }
}

fn current_proof_config<D: Digest>(
    chunk_size: usize,
    label: &str,
) -> Result<CurrentProofConfig, String> {
    if chunk_size == 0 {
        return Err(format!("{label} current chunk size must be non-zero"));
    }
    // These mirror Commonware's `current::Db` const-generic chunk invariants at the WASM boundary.
    if !chunk_size.is_power_of_two() {
        return Err(format!("{label} current chunk size must be a power of two"));
    }
    if !chunk_size.is_multiple_of(D::SIZE) {
        return Err(format!(
            "{label} current chunk size must be a multiple of digest size {}",
            D::SIZE
        ));
    }
    let chunk_bits = chunk_size
        .checked_mul(8)
        .and_then(|bits| u64::try_from(bits).ok())
        .ok_or_else(|| format!("{label} current chunk size is too large"))?;
    Ok(CurrentProofConfig {
        chunk_size,
        chunk_bits,
        grafting_height: chunk_bits.trailing_zeros(),
    })
}

fn get_bit_from_chunk(chunk: &[u8], bit: u64, chunk_bits: u64) -> bool {
    let bit = bit % chunk_bits;
    let byte = (bit / 8) as usize;
    let offset = bit % 8;
    chunk
        .get(byte)
        .map(|byte| (byte & (1 << offset)) != 0)
        .unwrap_or(false)
}

fn verify_current_range<F, H, O>(
    proof: &RangeProof<F, H::Digest>,
    config: &CurrentProofConfig,
    start_loc: Location<F>,
    ops: &[O],
    chunks: &[Vec<u8>],
    root: &H::Digest,
) -> Result<(), String>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
    O: Encode,
{
    if ops.is_empty() || chunks.is_empty() {
        return Err("current proof has empty operations or chunks".to_string());
    }
    let end_loc = start_loc
        .checked_add(ops.len() as u64)
        .ok_or_else(|| "current proof end location overflow".to_string())?;
    let leaves = proof.proof.leaves;
    if end_loc > leaves {
        return Err("current proof range exceeds proof leaves".to_string());
    }
    let start_chunk = *start_loc / config.chunk_bits;
    let end_chunk = (*end_loc - 1) / config.chunk_bits;
    let complete_chunks = *leaves / config.chunk_bits;
    if (end_chunk - start_chunk + 1) != chunks.len() as u64 {
        return Err("current proof chunk metadata length mismatch".to_string());
    }
    for (index, chunk) in chunks.iter().enumerate() {
        if chunk.len() != config.chunk_size {
            return Err(format!(
                "current proof chunk {index} has {} bytes, expected {}",
                chunk.len(),
                config.chunk_size
            ));
        }
    }

    let next_bit = *leaves % config.chunk_bits;
    let has_partial_chunk = next_bit != 0;
    let graftable_chunks =
        graftable_chunks::<F>(*leaves, config.grafting_height).min(complete_chunks);
    let pending_chunks = complete_chunks
        .checked_sub(graftable_chunks)
        .ok_or_else(|| "current proof graftable chunk window underflow".to_string())?;
    if pending_chunks > 1 {
        return Err("current proof has multiple pending chunks".to_string());
    }
    let has_pending_chunk = pending_chunks == 1;
    if proof.pending_chunk_digest.as_ref().is_some() != has_pending_chunk {
        return Err("current proof pending chunk presence mismatch".to_string());
    }

    let chunk_refs = chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let grafting_verifier = GraftingVerifier::<F, H>::new(
        config.grafting_height,
        start_chunk,
        chunk_refs,
        graftable_chunks,
    );

    if has_partial_chunk {
        let Some(last_chunk_digest) = proof.partial_chunk_digest.as_ref() else {
            return Err("current proof missing partial chunk digest".to_string());
        };
        if end_chunk == complete_chunks {
            let last_chunk = chunks.last().expect("chunks non-empty");
            if *last_chunk_digest != grafting_verifier.hash(&[last_chunk.as_slice()]) {
                return Err("current proof partial chunk digest mismatch".to_string());
            }
        }
    } else if proof.partial_chunk_digest.is_some() {
        return Err("current proof has unexpected partial chunk digest".to_string());
    }

    if let Some(pending_digest) = proof.pending_chunk_digest.as_ref() {
        let pending_idx = graftable_chunks;
        if pending_idx >= start_chunk && pending_idx <= end_chunk {
            let local = usize::try_from(pending_idx - start_chunk)
                .map_err(|_| "current proof pending chunk index overflow".to_string())?;
            let Some(pending_chunk) = chunks.get(local) else {
                return Err("current proof pending chunk index out of range".to_string());
            };
            if *pending_digest != grafting_verifier.hash(&[pending_chunk.as_slice()]) {
                return Err("current proof pending chunk digest mismatch".to_string());
            }
        }
    }

    let encoded_ops = ops.iter().map(Encode::encode).collect::<Vec<_>>();
    let merkle_root = proof
        .proof
        .reconstruct_root(&grafting_verifier, &encoded_ops, start_loc)
        .map_err(|_| "current proof failed root reconstruction".to_string())?;
    let partial_chunk = has_partial_chunk.then(|| {
        (
            next_bit,
            *proof.partial_chunk_digest.as_ref().expect("checked above"),
        )
    });
    let witness = OpsRootWitness::<F, H::Digest> {
        grafted_root: merkle_root,
        pending_chunk_digest: proof.pending_chunk_digest.clone(),
        partial_chunk,
    };
    let reconstructed = witness.root::<H>(&proof.ops_root);
    if reconstructed != *root {
        return Err("current proof failed verification".to_string());
    }
    Ok(())
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
            "crc32c" => {
                type H = Crc32;
                $body
            }
            _ => unreachable!("normalize_hash_family only returns supported values"),
        }
    }};
}

fn historical_target_root<F, H>(
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
        return Err("historical proof missing ops_root".to_string());
    }
    let ops_root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
        ops_root,
        "historical ops root",
    )?;
    if ops_root_witness.is_empty() {
        if ops_root != *expected_root {
            return Err("historical ops root did not match expected root".to_string());
        }
        return Ok(ops_root);
    }
    let witness = OpsRootWitness::<F, H::Digest>::decode(ops_root_witness)
        .map_err(|err| format!("failed to decode historical ops-root witness: {err}"))?;
    if !witness.verify::<H>(&ops_root, expected_root) {
        return Err("historical ops-root witness failed verification".to_string());
    }
    Ok(ops_root)
}

fn verify_multi_from_proto<F, H>(
    proto: &HistoricalMultiProof,
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
        historical_target_root::<F, H>(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = merkle::Proof::<F, H::Digest>::decode_cfg(proto.proof.as_ref(), &max_digests)
        .map_err(|err| format!("failed to decode historical multi proof: {err}"))?;
    if !verify_multi_proof::<H, _, _>(&proof, &operations, &target_root) {
        return Err("historical multi proof failed verification".to_string());
    }
    Ok((*root, operations))
}

fn decode_multi_with_embedded_root_from_proto<F, H>(
    proto: &HistoricalMultiProof,
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
    if proto.ops_root.is_empty() {
        return Err("historical multi proof missing embedded ops_root".to_string());
    }
    let ops_root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
        &proto.ops_root,
        "historical multi proof ops root",
    )?;
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = merkle::Proof::<F, H::Digest>::decode_cfg(proto.proof.as_ref(), &max_digests)
        .map_err(|err| format!("failed to decode historical multi proof: {err}"))?;
    if !verify_multi_proof::<H, _, _>(&proof, &operations, &ops_root) {
        return Err("historical multi proof failed verification".to_string());
    }
    if proto.ops_root_witness.is_empty() {
        return Ok((ops_root, operations));
    }
    let witness =
        OpsRootWitness::<F, H::Digest>::decode(proto.ops_root_witness.as_ref()).map_err(|err| {
            format!("failed to decode historical multi proof ops-root witness: {err}")
        })?;
    Ok((witness.root::<H>(&ops_root), operations))
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

fn verify_operation_range_from_proto<F, H>(
    proto: &HistoricalOperationRangeProof,
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
        return Err("historical operation range proof has no operations".to_string());
    }
    let target_root =
        historical_target_root::<F, H>(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = merkle::Proof::<F, H::Digest>::decode_cfg(proto.proof.as_ref(), &max_digests)
        .map_err(|err| format!("failed to decode historical operation range proof: {err}"))?;
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
            decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
                bytes.as_ref(),
                "historical operation range pinned node",
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
        return Err("historical operation range proof failed verification".to_string());
    }
    Ok((*root, operations))
}

fn verify_raw_operation_range<F, H>(
    proto: &HistoricalOperationRangeProof,
    root: &H::Digest,
    window: OperationWindow,
) -> Result<(H::Digest, Vec<(Location<F>, Vec<u8>)>), String>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
    H::Digest: DecodeExt<()>,
{
    if proto.encoded_operations.is_empty() {
        return Err("historical operation range proof has no operations".to_string());
    }
    let target_root =
        historical_target_root::<F, H>(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = merkle::Proof::<F, H::Digest>::decode_cfg(proto.proof.as_ref(), &max_digests)
        .map_err(|err| format!("failed to decode historical operation range proof: {err}"))?;
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
                "historical operation range pinned node",
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
        return Err("historical operation range proof failed verification".to_string());
    }
    Ok((*root, operations))
}

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
    if proto.encoded_operations.is_empty() {
        return Err("current operation range proof has no operations".to_string());
    }
    if proto.chunks.is_empty() {
        return Err("current operation range proof has no chunks".to_string());
    }
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = RangeProof::<F, H::Digest>::decode_cfg(proto.proof.as_ref(), &max_digests)
        .map_err(|err| format!("failed to decode current operation range proof: {err}"))?;
    window.validate(
        proto.start_location,
        proto.encoded_operations.len(),
        proof.proof.leaves.as_u64(),
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
        .map(|bytes| bytes.to_vec())
        .collect::<Vec<_>>();
    verify_current_range::<F, H, _>(&proof, config, start, &ordered_operations, &chunks, root)?;
    Ok(operations)
}

fn read_operation_proof<F, D>(
    buf: &mut &[u8],
    max_digests: usize,
    config: &CurrentProofConfig,
) -> Result<OperationProof<F, D>, String>
where
    F: merkle::Graftable,
    D: Digest + DecodeExt<()>,
{
    let loc = Location::<F>::read(buf)
        .map_err(|err| format!("failed to decode current operation proof location: {err}"))?;
    if buf.len() < config.chunk_size {
        return Err("current operation proof chunk is truncated".to_string());
    }
    let chunk = buf[..config.chunk_size].to_vec();
    *buf = &buf[config.chunk_size..];
    let range_proof = RangeProof::<F, D>::read_cfg(buf, &max_digests)
        .map_err(|err| format!("failed to decode current operation range proof: {err}"))?;
    Ok(OperationProof {
        loc,
        chunk,
        range_proof,
    })
}

fn read_exclusion_proof<F, D>(
    bytes: &[u8],
    max_digests: usize,
    config: &CurrentProofConfig,
) -> Result<ExclusionProof<F, D>, String>
where
    F: merkle::Graftable,
    D: Digest + DecodeExt<()>,
{
    const KEY_VALUE_CONTEXT: u8 = 0;
    const COMMIT_CONTEXT: u8 = 1;

    let mut buf = bytes;
    let tag = u8::read(&mut buf)
        .map_err(|err| format!("failed to decode current key-exclusion proof tag: {err}"))?;
    let proof = read_operation_proof::<F, D>(&mut buf, max_digests, config)?;
    match tag {
        KEY_VALUE_CONTEXT => {
            let update =
                Update::<Vec<u8>, VariableEncoding<Vec<u8>>>::read_cfg(&mut buf, &op_cfg::<F>())
                    .map_err(|err| {
                        format!("failed to decode current key-exclusion update: {err}")
                    })?;
            if !buf.is_empty() {
                return Err("current key-exclusion proof has trailing bytes".to_string());
            }
            Ok(ExclusionProof::KeyValue(proof, update))
        }
        COMMIT_CONTEXT => {
            let value =
                Option::<Vec<u8>>::read_cfg(&mut buf, &((0..=MAX_OPERATION_SIZE).into(), ()))
                    .map_err(|err| {
                        format!("failed to decode current key-exclusion commit value: {err}")
                    })?;
            if !buf.is_empty() {
                return Err("current key-exclusion proof has trailing bytes".to_string());
            }
            Ok(ExclusionProof::Commit(proof, value))
        }
        other => Err(format!(
            "current key-exclusion proof uses invalid tag {other}"
        )),
    }
}

fn verify_operation_proof<F, H>(
    proof: &OperationProof<F, H::Digest>,
    operation: &OrderedOperation<F, Vec<u8>, Vec<u8>>,
    root: &H::Digest,
    config: &CurrentProofConfig,
) -> Result<(), String>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
{
    if !get_bit_from_chunk(&proof.chunk, *proof.loc, config.chunk_bits) {
        return Err("current operation proof is inactive".to_string());
    }
    verify_current_range::<F, H, _>(
        &proof.range_proof,
        config,
        proof.loc,
        std::slice::from_ref(operation),
        std::slice::from_ref(&proof.chunk),
        root,
    )
}

fn verify_key_value_from_proto<F, H>(
    proto: &CurrentKeyValueProof,
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
    let operation = OrderedOperation::<F, Vec<u8>, Vec<u8>>::decode_cfg(
        proto.encoded_operation.as_ref(),
        &op_cfg::<F>(),
    )
    .map_err(|err| format!("failed to decode current key-value operation: {err}"))?;
    let OrderedOperation::Update(_) = &operation else {
        return Err("current key-value proof operation must be an update".to_string());
    };
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let mut buf = proto.proof.as_ref();
    let proof = read_operation_proof::<F, H::Digest>(&mut buf, max_digests, config)?;
    if !buf.is_empty() {
        return Err("current key-value proof has trailing bytes".to_string());
    }
    verify_operation_proof::<F, H>(&proof, &operation, root, config)?;
    Ok((proof.loc, operation))
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
    let (location, operation) = verify_key_value_from_proto::<F, H>(proto, root, config)?;
    let OrderedOperation::Update(update) = &operation else {
        return Err("current key-value proof operation must be an update".to_string());
    };
    if update.key.as_slice() != requested_key.as_slice() {
        return Err("current key-value proof key mismatch".to_string());
    }
    Ok((location, operation))
}

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
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = read_exclusion_proof::<F, H::Digest>(&proto.proof, max_digests, config)?;
    let requested_key = decode_vec_key_wire(requested_key)?;
    match proof {
        ExclusionProof::KeyValue(proof, update) => {
            if update.key == requested_key {
                return Err("current key-exclusion proof proves requested key exists".to_string());
            }
            if !span_contains(&update.key, &update.next_key, &requested_key) {
                return Err(
                    "current key-exclusion proof span does not contain requested key".to_string(),
                );
            }
            let operation = OrderedOperation::Update(update.clone());
            verify_operation_proof::<F, H>(&proof, &operation, current_root, config)?;
            Ok(Some(update.next_key))
        }
        ExclusionProof::Commit(proof, value) => {
            let operation = OrderedOperation::CommitFloor(value, proof.loc);
            verify_operation_proof::<F, H>(&proof, &operation, current_root, config)?;
            Ok(None)
        }
    }
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

fn historical_to_js<F, D>(
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
        let (location, operation) =
            verify_key_value_from_proto::<F, H>(proof, current_root, config).map_err(js_err)?;
        let OrderedOperation::Update(update) = operation else {
            return Err(js_err("getRange entry proof did not verify an update"));
        };
        decoded.push((location, update));
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
pub fn decode_historical_multi_proof_operations(
    bytes: &[u8],
    merkle_family: &str,
    hash_family: &str,
) -> Result<JsValue, JsValue> {
    let proto = HistoricalMultiProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical multi proof: {err}")))?
        .to_owned_message()
        .map_err(|err| js_err(format!("materialize historical multi proof: {err}")))?;
    with_hash_family!(hash_family, "historical multi proof", {
        match normalize_family(merkle_family, "historical multi proof").map_err(js_err)? {
            "mmr" => {
                let (root, operations) =
                    decode_multi_with_embedded_root_from_proto::<mmr::Family, H>(&proto)
                        .map_err(js_err)?;
                historical_to_js(root, operations)
            }
            "mmb" => {
                let (root, operations) =
                    decode_multi_with_embedded_root_from_proto::<mmb::Family, H>(&proto)
                        .map_err(js_err)?;
                historical_to_js(root, operations)
            }
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

#[wasm_bindgen]
pub fn verify_historical_multi_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    hash_family: &str,
) -> Result<JsValue, JsValue> {
    let proto = HistoricalMultiProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical multi proof: {err}")))?
        .to_owned_message()
        .map_err(|err| js_err(format!("materialize historical multi proof: {err}")))?;
    with_hash_family!(hash_family, "historical multi proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "historical proof root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "historical multi proof").map_err(js_err)? {
            "mmr" => {
                let (root, operations) =
                    verify_multi_from_proto::<mmr::Family, H>(&proto, &root).map_err(js_err)?;
                historical_to_js(root, operations)
            }
            "mmb" => {
                let (root, operations) =
                    verify_multi_from_proto::<mmb::Family, H>(&proto, &root).map_err(js_err)?;
                historical_to_js(root, operations)
            }
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

#[wasm_bindgen]
pub fn verify_historical_operation_range_proof(
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
    let proto = HistoricalOperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical operation range proof: {err}")))?
        .to_owned_message()
        .map_err(|err| {
            js_err(format!(
                "materialize historical operation range proof: {err}"
            ))
        })?;
    with_hash_family!(hash_family, "historical operation range proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "historical operation range root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "historical operation range proof").map_err(js_err)? {
            "mmr" => {
                let (root, operations) =
                    verify_operation_range_from_proto::<mmr::Family, H>(&proto, &root, window)
                        .map_err(js_err)?;
                historical_to_js(root, operations)
            }
            "mmb" => {
                let (root, operations) =
                    verify_operation_range_from_proto::<mmb::Family, H>(&proto, &root, window)
                        .map_err(js_err)?;
                historical_to_js(root, operations)
            }
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

#[wasm_bindgen]
pub fn verify_historical_raw_operation_range_proof(
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
    let proto = HistoricalOperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical operation range proof: {err}")))?
        .to_owned_message()
        .map_err(|err| {
            js_err(format!(
                "materialize historical operation range proof: {err}"
            ))
        })?;
    with_hash_family!(hash_family, "historical operation range proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "historical operation range root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "historical operation range proof").map_err(js_err)? {
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
pub fn verify_historical_fixed_keyless_append_proof(
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
    let proto = HistoricalOperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical operation range proof: {err}")))?
        .to_owned_message()
        .map_err(|err| {
            js_err(format!(
                "materialize historical operation range proof: {err}"
            ))
        })?;
    with_hash_family!(hash_family, "historical operation range proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "historical operation range root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "historical operation range proof").map_err(js_err)? {
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
pub fn verify_historical_fixed_unordered_update_proof(
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
    let proto = HistoricalOperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical operation range proof: {err}")))?
        .to_owned_message()
        .map_err(|err| {
            js_err(format!(
                "materialize historical operation range proof: {err}"
            ))
        })?;
    with_hash_family!(hash_family, "historical operation range proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "historical operation range root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "historical operation range proof").map_err(js_err)? {
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
    use commonware_storage::merkle::mem::Mem;
    use commonware_storage::qmdb::{
        any::{
            unordered::{Operation as UnorderedOperation, Update as UnorderedUpdate},
            value::FixedEncoding,
        },
        current::{
            ordered::ExclusionProof as UpstreamExclusionProof,
            proof::OperationProof as UpstreamOperationProof,
        },
        keyless,
    };

    type TestOperation<F> = OrderedOperation<F, Vec<u8>, Vec<u8>>;

    #[test]
    fn vec_key_wire_bytes_use_commonware_codec_frame() {
        let key = b"alpha".to_vec();
        assert_eq!(decode_vec_key_wire(&encode_vec_key(&key)).unwrap(), key);
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
        OperationWindow,
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
        OperationWindow,
    )
    where
        F: merkle::Graftable,
        TestOperation<F>:
            Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
    {
        historical_range_fixture_at_with_hash::<F, Sha256>(start_offset, end_offset)
    }

    fn historical_range_fixture_at_with_hash<F, H>(
        start_offset: u64,
        end_offset: u64,
    ) -> (
        HistoricalOperationRangeProof,
        H::Digest,
        Vec<(Location<F>, TestOperation<F>)>,
        OperationWindow,
    )
    where
        F: merkle::Graftable,
        H: commonware_cryptography::Hasher,
        H::Digest: Encode,
        TestOperation<F>:
            Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
    {
        let operations = sample_operations::<F>();
        let encoded = operations
            .iter()
            .map(|operation| operation.encode().to_vec())
            .collect::<Vec<_>>();
        let (proto, root, expected, window) =
            historical_raw_range_fixture_at::<F, H>(&encoded, start_offset, end_offset);
        let expected = expected
            .into_iter()
            .map(|(location, _)| (location, operations[*location as usize].clone()))
            .collect();
        (proto, root, expected, window)
    }

    fn historical_raw_range_fixture_at<F, H>(
        encoded_operations: &[Vec<u8>],
        start_offset: u64,
        end_offset: u64,
    ) -> (
        HistoricalOperationRangeProof,
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
            OperationWindow::new(
                encoded_operations.len() as u64 - 1,
                start_offset,
                u32::try_from(end_offset - start_offset).unwrap(),
            )
            .unwrap(),
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
        let (proto, root, expected, window) = historical_range_fixture::<mmr::Family>();

        let (verified_root, verified) =
            verify_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root, window)
                .unwrap();

        assert_eq!(verified_root, root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn verifies_historical_operation_range_mmb() {
        let (proto, root, expected, window) = historical_range_fixture::<mmb::Family>();

        let (verified_root, verified) =
            verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &root, window)
                .unwrap();

        assert_eq!(verified_root, root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn verifies_raw_historical_operation_range_without_decoding() {
        let (proto, root, expected, window) = historical_range_fixture::<mmr::Family>();
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
    fn verifies_historical_operation_range_with_blake3() {
        let (proto, root, expected, window) =
            historical_range_fixture_at_with_hash::<mmr::Family, Blake3>(1, 4);

        let (verified_root, verified) =
            verify_operation_range_from_proto::<mmr::Family, Blake3>(&proto, &root, window)
                .unwrap();

        assert_eq!(verified_root, root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn current_proof_config_follows_commonware_chunk_constraints() {
        let config = current_proof_config::<Sha256Digest>(64, "test proof").unwrap();

        assert_eq!(config.chunk_size, 64);
        assert_eq!(config.chunk_bits, 512);
        assert_eq!(config.grafting_height, 9);
        assert_eq!(
            current_proof_config::<Sha256Digest>(48, "test proof").unwrap_err(),
            "test proof current chunk size must be a power of two"
        );
        assert_eq!(
            current_proof_config::<Sha256Digest>(16, "test proof").unwrap_err(),
            "test proof current chunk size must be a multiple of digest size 32"
        );
    }

    fn synthetic_operation_proof<F, const N: usize>(
        pending_chunk_digest: F::PendingChunk<Sha256Digest>,
    ) -> UpstreamOperationProof<F, Sha256Digest, N>
    where
        F: merkle::Graftable,
    {
        UpstreamOperationProof {
            loc: Location::new(9),
            chunk: core::array::from_fn(|index| index as u8),
            range_proof: RangeProof {
                proof: merkle::Proof {
                    leaves: Location::new(21),
                    inactive_peaks: 1,
                    digests: vec![Sha256::fill(0xA1), Sha256::fill(0xA2)],
                },
                pending_chunk_digest,
                partial_chunk_digest: Some(Sha256::fill(0xB3)),
                ops_root: Sha256::fill(0xC4),
            },
        }
    }

    // The WASM readers mirror Commonware's proof encodings with a runtime chunk size, so an
    // upstream layout or tag change must fail here rather than in the browser
    fn assert_current_proofs_decode<F, const N: usize>(
        pending_chunk_digest: F::PendingChunk<Sha256Digest>,
    ) where
        F: merkle::Graftable + PartialEq,
    {
        let config = current_proof_config::<Sha256Digest>(N, "test").unwrap();
        let expected = synthetic_operation_proof::<F, N>(pending_chunk_digest);
        let update = Update::<Vec<u8>, VariableEncoding<Vec<u8>>> {
            key: b"k1".to_vec(),
            value: b"v1".to_vec(),
            next_key: b"k2".to_vec(),
        };
        let assert_proof = |decoded: &OperationProof<F, Sha256Digest>| {
            assert_eq!(decoded.loc, expected.loc);
            assert_eq!(decoded.chunk, expected.chunk.to_vec());
            assert_eq!(decoded.range_proof, expected.range_proof);
        };

        let key_value = UpstreamExclusionProof::<
            F,
            Vec<u8>,
            VariableEncoding<Vec<u8>>,
            Sha256Digest,
            N,
        >::KeyValue(expected.clone(), update.clone())
        .encode();
        match read_exclusion_proof::<F, Sha256Digest>(
            &key_value,
            proof_digest_cap::<Sha256Digest>(&key_value),
            &config,
        )
        .unwrap()
        {
            ExclusionProof::KeyValue(decoded, decoded_update) => {
                assert_proof(&decoded);
                assert_eq!(decoded_update, update);
            }
            ExclusionProof::Commit(..) => panic!("key-value exclusion proof decoded as a commit"),
        }

        let commit = UpstreamExclusionProof::<F, Vec<u8>, VariableEncoding<Vec<u8>>, Sha256Digest, N>::Commit(
            expected.clone(),
            Some(b"meta".to_vec()),
        )
        .encode();
        match read_exclusion_proof::<F, Sha256Digest>(
            &commit,
            proof_digest_cap::<Sha256Digest>(&commit),
            &config,
        )
        .unwrap()
        {
            ExclusionProof::Commit(decoded, value) => {
                assert_proof(&decoded);
                assert_eq!(value, Some(b"meta".to_vec()));
            }
            ExclusionProof::KeyValue(..) => panic!("commit exclusion proof decoded as a key-value"),
        }

        let encoded = expected.encode();
        let mut buf = encoded.as_ref();
        let decoded = read_operation_proof::<F, Sha256Digest>(
            &mut buf,
            proof_digest_cap::<Sha256Digest>(&encoded),
            &config,
        )
        .unwrap();
        assert!(buf.is_empty());
        assert_proof(&decoded);
    }

    #[test]
    fn decodes_commonware_current_proofs_for_mmr() {
        assert_current_proofs_decode::<mmr::Family, 32>(merkle::Unused);
    }

    #[test]
    fn decodes_commonware_current_proofs_for_mmb() {
        assert_current_proofs_decode::<mmb::Family, 32>(Some(Sha256::fill(0xD5)));
    }

    #[test]
    fn fixed_operation_tags_follow_commonware_encodings() {
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
        let (proto, root, _, window) =
            historical_raw_range_fixture_at::<mmr::Family, Sha256>(&operations, 0, 3);
        let (_, verified) =
            verify_raw_operation_range::<mmr::Family, Sha256>(&proto, &root, window).unwrap();
        let operation =
            expected_raw_operation(proto.start_location, &verified, 1, "keyless").unwrap();

        let value = fixed_keyless_append_value(&operation, expected_value.as_ref()).unwrap();

        assert_eq!(value.as_slice(), expected_value.as_ref());
    }

    #[test]
    fn verifies_fixed_keyless_append_operation_with_runtime_value_size() {
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
            historical_raw_range_fixture_at::<mmr::Family, Sha256>(&operations, 0, 3);
        let (_, verified) =
            verify_raw_operation_range::<mmr::Family, Sha256>(&proto, &root, window).unwrap();
        let operation =
            expected_raw_operation(proto.start_location, &verified, 1, "keyless").unwrap();

        let value = fixed_keyless_append_value(&operation, expected_value.as_ref()).unwrap();

        assert_eq!(value.as_slice(), expected_value.as_ref());
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
        let (proto, root, _, window) =
            historical_raw_range_fixture_at::<mmr::Family, Sha256>(&operations, 0, 3);
        let (_, verified) =
            verify_raw_operation_range::<mmr::Family, Sha256>(&proto, &root, window).unwrap();
        let operation =
            expected_raw_operation(proto.start_location, &verified, 1, "unordered").unwrap();

        let value =
            fixed_unordered_update_value(&operation, expected_key.as_ref(), u64::SIZE).unwrap();

        assert_eq!(value.as_slice(), expected_value.encode().as_ref());
    }

    #[test]
    fn verifies_fixed_unordered_update_operation_with_runtime_value_size() {
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
            historical_raw_range_fixture_at::<mmr::Family, Sha256>(&operations, 0, 3);
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
    fn historical_operation_range_pinned_nodes_match_mmr_start_location() {
        let (zero_start, zero_root, zero_expected, window) =
            historical_range_fixture_at::<mmr::Family>(0, 3);
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
            historical_range_fixture_at::<mmr::Family>(1, 4);
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
    fn historical_operation_range_pinned_nodes_match_mmb_start_location() {
        let (zero_start, zero_root, zero_expected, window) =
            historical_range_fixture_at::<mmb::Family>(0, 3);
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
            historical_range_fixture_at::<mmb::Family>(1, 4);
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
    fn rejects_historical_operation_range_mmr_without_nonzero_pinned_nodes() {
        let (mut proto, root, _, window) = historical_range_fixture::<mmr::Family>();
        proto.pinned_nodes.clear();

        let err = verify_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root, window)
            .unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn rejects_historical_operation_range_mmb_without_nonzero_pinned_nodes() {
        let (mut proto, root, _, window) = historical_range_fixture::<mmb::Family>();
        proto.pinned_nodes.clear();

        let err = verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &root, window)
            .unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn rejects_historical_operation_range_mmr_with_zero_start_pinned_nodes() {
        let (mut proto, root, _, window) = historical_range_fixture_at::<mmr::Family>(0, 3);
        proto.pinned_nodes.push(root.encode());

        let err = verify_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root, window)
            .unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn rejects_historical_operation_range_mmb_with_zero_start_pinned_nodes() {
        let (mut proto, root, _, window) = historical_range_fixture_at::<mmb::Family>(0, 3);
        proto.pinned_nodes.push(root.encode());

        let err = verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &root, window)
            .unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn rejects_historical_operation_range_mmb_with_tampered_pinned_node() {
        let (mut proto, root, _, window) = historical_range_fixture::<mmb::Family>();
        let mut pinned_node = proto.pinned_nodes[0].to_vec();
        pinned_node[0] ^= 0x01;
        proto.pinned_nodes[0] = pinned_node.into();

        let err = verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &root, window)
            .unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn rejects_historical_operation_range_mmb_with_extra_pinned_node() {
        let (mut proto, root, _, window) = historical_range_fixture::<mmb::Family>();
        proto.pinned_nodes.push(proto.pinned_nodes[0].clone());

        let err = verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &root, window)
            .unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn decodes_subscribe_multi_proof_without_ops_root_witness() {
        let (proto, ops_root, expected) = historical_multi_fixture::<mmr::Family>();

        let (root, verified) =
            decode_multi_with_embedded_root_from_proto::<mmr::Family, Sha256>(&proto).unwrap();

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
        let current_root = witness.root::<Sha256>(&ops_root);
        proto.ops_root_witness = witness.encode();

        let (root, verified) =
            decode_multi_with_embedded_root_from_proto::<mmb::Family, Sha256>(&proto).unwrap();

        assert_eq!(root, current_root);
        assert_ne!(root, ops_root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn rejects_subscribe_multi_proof_missing_ops_root() {
        let (mut proto, _, _) = historical_multi_fixture::<mmr::Family>();
        proto.ops_root.clear();

        let err =
            decode_multi_with_embedded_root_from_proto::<mmr::Family, Sha256>(&proto).unwrap_err();

        assert_eq!(err, "historical multi proof missing embedded ops_root");
    }

    #[test]
    fn rejects_historical_operation_range_without_ops_root() {
        let (mut proto, root, _, window) = historical_range_fixture::<mmr::Family>();
        proto.ops_root.clear();

        let err = verify_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root, window)
            .unwrap_err();

        assert_eq!(err, "historical proof missing ops_root");
    }

    #[test]
    fn rejects_historical_operation_range_root_mismatch() {
        let (proto, root, _, window) = historical_range_fixture::<mmb::Family>();
        let wrong_root = Sha256::fill(0x42);
        assert_ne!(wrong_root, root);

        let err =
            verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &wrong_root, window)
                .unwrap_err();

        assert_eq!(err, "historical ops root did not match expected root");
    }
}
