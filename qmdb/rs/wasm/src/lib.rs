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
    types::lazy::Lazy, Decode, DecodeExt, DecodeRangeExt, Encode, FixedSize, RangeCfg, Read,
    ReadExt,
};
use commonware_cryptography::{Blake3, Crc32, Digest, Sha256};
use commonware_storage::{
    merkle::{self, hasher::Hasher as MerkleHasher, Location, PendingChunk, Position},
    mmb, mmr,
    qmdb::{
        any::{
            ordered::{variable::Operation as OrderedOperation, Update},
            value::VariableEncoding,
        },
        current::proof::{OpsRootWitness, RangeProof},
        verify::{verify_multi_proof, verify_proof_and_pinned_nodes},
    },
};
use js_sys::{Array, BigInt, Object, Reflect, Uint8Array};
use std::{cmp::Ordering, collections::BTreeSet, marker::PhantomData};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

pub mod proto;

const MAX_OPERATION_SIZE: usize = u16::MAX as usize;
// The WASM API receives raw fixed-operation bytes plus runtime key/value sizes.
// Mirror Commonware's fixed-operation wire tags so verification is not tied to
// one concrete Rust value type.
const FIXED_KEYLESS_COMMIT_CONTEXT: u8 = 0;
const FIXED_KEYLESS_APPEND_CONTEXT: u8 = 1;
const FIXED_UNORDERED_DELETE_CONTEXT: u8 = 0xD1;
const FIXED_UNORDERED_UPDATE_CONTEXT: u8 = 0xD2;
const FIXED_UNORDERED_COMMIT_CONTEXT: u8 = 0xD3;

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

fn graftable_chunks<F: merkle::Graftable>(ops_leaves: u64, grafting_height: u32) -> u64 {
    let pos = F::subtree_root_position(Location::<F>::new(0), grafting_height);
    let birth_chunk_0 = F::peak_birth_size(pos, grafting_height);
    if ops_leaves < birth_chunk_0 {
        return 0;
    }
    let chunk_size = 1u64 << grafting_height;
    (ops_leaves - birth_chunk_0) / chunk_size + 1
}

#[derive(Clone)]
struct GraftingVerifier<'a, F: merkle::Graftable, H: commonware_cryptography::Hasher> {
    hasher: merkle::hasher::Standard<H>,
    grafting_height: u32,
    chunks: Vec<&'a [u8]>,
    start_chunk_index: u64,
    graftable_chunks: u64,
    _family: PhantomData<F>,
}

impl<'a, F: merkle::Graftable, H: commonware_cryptography::Hasher> GraftingVerifier<'a, F, H> {
    fn new(
        root_hasher: &merkle::hasher::Standard<H>,
        config: &CurrentProofConfig,
        chunks: Vec<&'a [u8]>,
        start_chunk_index: u64,
        graftable_chunks: u64,
    ) -> Self {
        Self {
            hasher: merkle::hasher::Standard::new(root_hasher.root_bagging()),
            grafting_height: config.grafting_height,
            chunks,
            start_chunk_index,
            graftable_chunks,
            _family: PhantomData,
        }
    }
}

impl<F: merkle::Graftable, H: commonware_cryptography::Hasher> MerkleHasher<F>
    for GraftingVerifier<'_, F, H>
{
    type Digest = H::Digest;

    fn hash<'a>(&self, parts: impl IntoIterator<Item = &'a [u8]>) -> H::Digest {
        self.hasher.hash(parts)
    }

    fn root_bagging(&self) -> merkle::Bagging {
        <merkle::hasher::Standard<H> as MerkleHasher<F>>::root_bagging(&self.hasher)
    }

    fn node_digest(
        &self,
        pos: Position<F>,
        left_digest: &H::Digest,
        right_digest: &H::Digest,
    ) -> H::Digest {
        match F::pos_to_height(pos).cmp(&self.grafting_height) {
            Ordering::Less | Ordering::Greater => {
                self.hasher.node_digest(pos, left_digest, right_digest)
            }
            Ordering::Equal => {
                let ops_subtree_root = self.hasher.node_digest(pos, left_digest, right_digest);
                let loc = F::leftmost_leaf(pos, self.grafting_height);
                let chunk_idx = *loc >> self.grafting_height;
                if chunk_idx >= self.graftable_chunks {
                    return ops_subtree_root;
                }
                let Some(local) = chunk_idx
                    .checked_sub(self.start_chunk_index)
                    .filter(|&local| local < self.chunks.len() as u64)
                    .map(|local| local as usize)
                else {
                    return ops_subtree_root;
                };
                let chunk = self.chunks[local];
                if chunk.iter().all(|byte| *byte == 0) {
                    ops_subtree_root
                } else {
                    self.hash([chunk, ops_subtree_root.as_ref()])
                }
            }
        }
    }
}

fn combine_current_roots<H: commonware_cryptography::Hasher>(
    hasher: &merkle::hasher::Standard<H>,
    ops_root: &H::Digest,
    grafted_root: &H::Digest,
    pending: Option<&H::Digest>,
    partial: Option<(u64, &H::Digest)>,
) -> H::Digest {
    match (pending, partial) {
        (None, None) => hasher.hash([ops_root.as_ref(), grafted_root.as_ref()]),
        (Some(pending), None) => {
            hasher.hash([ops_root.as_ref(), grafted_root.as_ref(), pending.as_ref()])
        }
        (None, Some((next_bit, partial))) => {
            let next_bit = next_bit.to_be_bytes();
            hasher.hash([
                ops_root.as_ref(),
                grafted_root.as_ref(),
                next_bit.as_slice(),
                partial.as_ref(),
            ])
        }
        (Some(pending), Some((next_bit, partial))) => {
            let next_bit = next_bit.to_be_bytes();
            hasher.hash([
                ops_root.as_ref(),
                grafted_root.as_ref(),
                pending.as_ref(),
                next_bit.as_slice(),
                partial.as_ref(),
            ])
        }
    }
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
    root_hasher: &merkle::hasher::Standard<H>,
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
        root_hasher,
        config,
        chunk_refs,
        start_chunk,
        graftable_chunks,
    );

    if has_partial_chunk {
        let Some(last_chunk_digest) = proof.partial_chunk_digest.as_ref() else {
            return Err("current proof missing partial chunk digest".to_string());
        };
        if end_chunk == complete_chunks {
            let last_chunk = chunks.last().expect("chunks non-empty");
            if *last_chunk_digest != grafting_verifier.hash([last_chunk.as_slice()]) {
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
            if *pending_digest != grafting_verifier.hash([pending_chunk.as_slice()]) {
                return Err("current proof pending chunk digest mismatch".to_string());
            }
        }
    }

    let encoded_ops = ops.iter().map(Encode::encode).collect::<Vec<_>>();
    let merkle_root = proof
        .proof
        .reconstruct_root(&grafting_verifier, &encoded_ops, start_loc)
        .map_err(|_| "current proof failed root reconstruction".to_string())?;
    let partial = has_partial_chunk.then(|| {
        (
            next_bit,
            proof.partial_chunk_digest.as_ref().expect("checked above"),
        )
    });
    let reconstructed = combine_current_roots(
        root_hasher,
        &proof.ops_root,
        &merkle_root,
        proof.pending_chunk_digest.as_ref(),
        partial,
    );
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
    match (ops_root.is_empty(), ops_root_witness.is_empty()) {
        (true, true) => Ok(*expected_root),
        (false, true) => {
            let ops_root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
                ops_root,
                "historical ops root",
            )?;
            if ops_root != *expected_root {
                return Err("historical ops root did not match expected root".to_string());
            }
            Ok(ops_root)
        }
        (false, false) => {
            let ops_root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
                ops_root,
                "historical ops root",
            )?;
            let witness = OpsRootWitness::<F, H::Digest>::decode(ops_root_witness)
                .map_err(|err| format!("failed to decode historical ops-root witness: {err}"))?;
            let hasher = commonware_storage::qmdb::hasher::<H>();
            if !witness.verify(&hasher, &ops_root, expected_root) {
                return Err("historical ops-root witness failed verification".to_string());
            }
            Ok(ops_root)
        }
        (true, false) => Err("historical proof missing ops_root for ops_root_witness".to_string()),
    }
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
    let hasher = commonware_storage::qmdb::hasher::<H>();
    if !verify_multi_proof(&hasher, &proof, &operations, &target_root) {
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
    let hasher = commonware_storage::qmdb::hasher::<H>();
    if !verify_multi_proof(&hasher, &proof, &operations, &ops_root) {
        return Err("historical multi proof failed verification".to_string());
    }
    if proto.ops_root_witness.is_empty() {
        return Ok((ops_root, operations));
    }
    let witness =
        OpsRootWitness::<F, H::Digest>::decode(proto.ops_root_witness.as_ref()).map_err(|err| {
            format!("failed to decode historical multi proof ops-root witness: {err}")
        })?;
    let hasher = commonware_storage::qmdb::hasher::<H>();
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

fn verify_operation_range_from_proto<F, H>(
    proto: &HistoricalOperationRangeProof,
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
    if proto.encoded_operations.is_empty() {
        return Err("historical operation range proof has no operations".to_string());
    }
    let target_root =
        historical_target_root::<F, H>(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = merkle::Proof::<F, H::Digest>::decode_cfg(proto.proof.as_ref(), &max_digests)
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
            decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
                bytes.as_ref(),
                "historical operation range pinned node",
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    let hasher = commonware_storage::qmdb::hasher::<H>();
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

fn verify_raw_operation_range_from_proto<F, H>(
    proto: &HistoricalOperationRangeProof,
    root: &H::Digest,
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
        .map(|bytes| {
            // Preserve the exact operation encoding used as a Merkle leaf.
            // Decoding as Vec<u8>/Bytes would reinterpret these bytes as a length-prefixed value.
            Lazy::<Vec<u8>>::deferred(&mut bytes.as_ref(), ((0..=MAX_OPERATION_SIZE).into(), ()))
        })
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
    let hasher = commonware_storage::qmdb::hasher::<H>();
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
    Ok((*root, operations))
}

fn verify_current_operation_range_from_proto<F, H>(
    proto: &CurrentOperationRangeProof,
    root: &H::Digest,
    config: &CurrentProofConfig,
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
    let hasher = commonware_storage::qmdb::hasher::<H>();
    verify_current_range::<F, H, _>(
        &proof,
        &hasher,
        config,
        start,
        &ordered_operations,
        &chunks,
        root,
    )?;
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

fn read_key_value_proof<F, D>(
    bytes: &[u8],
    max_digests: usize,
    config: &CurrentProofConfig,
) -> Result<(OperationProof<F, D>, Vec<u8>), String>
where
    F: merkle::Graftable,
    D: Digest + DecodeExt<()>,
{
    let mut buf = bytes;
    let proof = read_operation_proof::<F, D>(&mut buf, max_digests, config)?;
    let next_key = Vec::<u8>::read_cfg(&mut buf, &((0..=MAX_OPERATION_SIZE).into(), ()))
        .map_err(|err| format!("failed to decode current key-value proof next_key: {err}"))?;
    if !buf.is_empty() {
        return Err("current key-value proof has trailing bytes".to_string());
    }
    Ok((proof, next_key))
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
    let hasher = commonware_storage::qmdb::hasher::<H>();
    verify_current_range::<F, H, _>(
        &proof.range_proof,
        &hasher,
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
    let OrderedOperation::Update(update) = &operation else {
        return Err("current key-value proof operation must be an update".to_string());
    };
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let (proof, next_key) =
        read_key_value_proof::<F, H::Digest>(&proto.proof, max_digests, config)?;
    if next_key != update.next_key {
        return Err("current key-value proof next_key mismatch".to_string());
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
) -> Result<ExclusionBoundary, String>
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
            if !span_contains_key(&update.key, &update.next_key, &requested_key) {
                return Err(
                    "current key-exclusion proof span does not contain requested key".to_string(),
                );
            }
            let operation = OrderedOperation::Update(update.clone());
            verify_operation_proof::<F, H>(&proof, &operation, current_root, config)?;
            Ok(ExclusionBoundary::Span {
                start: update.key,
                end: update.next_key,
            })
        }
        ExclusionProof::Commit(proof, value) => {
            let operation = OrderedOperation::CommitFloor(value, proof.loc);
            verify_operation_proof::<F, H>(&proof, &operation, current_root, config)?;
            Ok(ExclusionBoundary::Empty)
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
        set_field(&entry, "location", &location_to_bigint(location)?)?;
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

fn fixed_keyless_append_value<F>(operation: &[u8], expected_value: &[u8]) -> Result<Vec<u8>, String>
where
    F: merkle::Family,
{
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

fn fixed_unordered_update_value<F>(
    operation: &[u8],
    expected_key: &[u8],
    value_size: usize,
) -> Result<Vec<u8>, String>
where
    F: merkle::Family,
{
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
    set_field(&verified, "location", &location_to_bigint(location)?)?;
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
    set_field(&verified, "location", &location_to_bigint(location)?)?;
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
                set_field(&entry, "location", &location_to_bigint(location)?)?;
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

fn span_contains_key(span_start: &[u8], span_end: &[u8], key: &[u8]) -> bool {
    if span_start >= span_end {
        key >= span_start || key < span_end
    } else {
        key >= span_start && key < span_end
    }
}

fn verify_get_range_from_proto<F, H>(
    proto: &GetRangeResponse,
    current_root: &H::Digest,
    start_key: &[u8],
    end_key: Option<&[u8]>,
    config: &CurrentProofConfig,
) -> Result<JsValue, JsValue>
where
    F: merkle::Graftable,
    H: commonware_cryptography::Hasher,
    H::Digest: DecodeExt<()>,
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
            verify_key_value_from_proto::<F, H>(proof, current_root, config).map_err(js_err)?;
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
            match verify_key_exclusion_from_proto::<F, H>(
                start_proof,
                encode_vec_key_wire(&start_key).as_ref(),
                current_root,
                config,
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
        let boundary = verify_key_exclusion_from_proto::<F, H>(
            start_proof,
            encode_vec_key_wire(&start_key).as_ref(),
            current_root,
            config,
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
    hash_family: &str,
) -> Result<JsValue, JsValue> {
    let proto = HistoricalMultiProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical multi proof: {err}")))?
        .to_owned_message();
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
        .to_owned_message();
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
) -> Result<JsValue, JsValue> {
    let proto = HistoricalOperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical operation range proof: {err}")))?
        .to_owned_message();
    with_hash_family!(hash_family, "historical operation range proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "historical operation range root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "historical operation range proof").map_err(js_err)? {
            "mmr" => {
                let (root, operations) =
                    verify_operation_range_from_proto::<mmr::Family, H>(&proto, &root)
                        .map_err(js_err)?;
                historical_to_js(root, operations)
            }
            "mmb" => {
                let (root, operations) =
                    verify_operation_range_from_proto::<mmb::Family, H>(&proto, &root)
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
) -> Result<JsValue, JsValue> {
    let proto = HistoricalOperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical operation range proof: {err}")))?
        .to_owned_message();
    with_hash_family!(hash_family, "historical operation range proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "historical operation range root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "historical operation range proof").map_err(js_err)? {
            "mmr" => {
                let (root, operations) =
                    verify_raw_operation_range_from_proto::<mmr::Family, H>(&proto, &root)
                        .map_err(js_err)?;
                raw_operations_to_js(root, operations)
            }
            "mmb" => {
                let (root, operations) =
                    verify_raw_operation_range_from_proto::<mmb::Family, H>(&proto, &root)
                        .map_err(js_err)?;
                raw_operations_to_js(root, operations)
            }
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
}

#[wasm_bindgen]
pub fn verify_historical_fixed_keyless_append_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    hash_family: &str,
    expected_location: u64,
    expected_value: &[u8],
) -> Result<JsValue, JsValue> {
    let proto = HistoricalOperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical operation range proof: {err}")))?
        .to_owned_message();
    with_hash_family!(hash_family, "historical operation range proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "historical operation range root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "historical operation range proof").map_err(js_err)? {
            "mmr" => {
                let (root, operations) =
                    verify_raw_operation_range_from_proto::<mmr::Family, H>(&proto, &root)
                        .map_err(js_err)?;
                let operation = expected_raw_operation(
                    proto.start_location,
                    &operations,
                    expected_location,
                    "keyless",
                )
                .map_err(js_err)?;
                let value = fixed_keyless_append_value::<mmr::Family>(&operation, expected_value)
                    .map_err(js_err)?;
                fixed_keyless_append_to_js(
                    root,
                    operations.len(),
                    Location::<mmr::Family>::new(expected_location),
                    &value,
                )
            }
            "mmb" => {
                let (root, operations) =
                    verify_raw_operation_range_from_proto::<mmb::Family, H>(&proto, &root)
                        .map_err(js_err)?;
                let operation = expected_raw_operation(
                    proto.start_location,
                    &operations,
                    expected_location,
                    "keyless",
                )
                .map_err(js_err)?;
                let value = fixed_keyless_append_value::<mmb::Family>(&operation, expected_value)
                    .map_err(js_err)?;
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
pub fn verify_historical_fixed_unordered_update_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    hash_family: &str,
    expected_location: u64,
    expected_key: &[u8],
    value_size: usize,
) -> Result<JsValue, JsValue> {
    let proto = HistoricalOperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical operation range proof: {err}")))?
        .to_owned_message();
    with_hash_family!(hash_family, "historical operation range proof", {
        let root = decode_digest::<<H as commonware_cryptography::Hasher>::Digest>(
            root,
            "historical operation range root",
        )
        .map_err(js_err)?;
        match normalize_family(merkle_family, "historical operation range proof").map_err(js_err)? {
            "mmr" => {
                let (root, operations) =
                    verify_raw_operation_range_from_proto::<mmr::Family, H>(&proto, &root)
                        .map_err(js_err)?;
                let operation = expected_raw_operation(
                    proto.start_location,
                    &operations,
                    expected_location,
                    "unordered",
                )
                .map_err(js_err)?;
                let value = fixed_unordered_update_value::<mmr::Family>(
                    &operation,
                    expected_key,
                    value_size,
                )
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
                    verify_raw_operation_range_from_proto::<mmb::Family, H>(&proto, &root)
                        .map_err(js_err)?;
                let operation = expected_raw_operation(
                    proto.start_location,
                    &operations,
                    expected_location,
                    "unordered",
                )
                .map_err(js_err)?;
                let value = fixed_unordered_update_value::<mmb::Family>(
                    &operation,
                    expected_key,
                    value_size,
                )
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
pub fn verify_current_operation_range_proof(
    bytes: &[u8],
    root: &[u8],
    merkle_family: &str,
    hash_family: &str,
    current_chunk_size: usize,
) -> Result<JsValue, JsValue> {
    let proto = CurrentOperationRangeProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode current operation range proof: {err}")))?
        .to_owned_message();
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
                verify_current_operation_range_from_proto::<mmr::Family, H>(&proto, &root, &config)
                    .map_err(js_err)?,
            ),
            "mmb" => operations_to_js(
                verify_current_operation_range_from_proto::<mmb::Family, H>(&proto, &root, &config)
                    .map_err(js_err)?,
            ),
            _ => unreachable!("normalize_family only returns supported values"),
        }
    })
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
    hash_family: &str,
    current_chunk_size: usize,
    requested_key: &[u8],
) -> Result<JsValue, JsValue> {
    let proto = CurrentKeyValueProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode current key-value proof: {err}")))?
        .to_owned_message();
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
        .to_owned_message();
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
pub fn verify_get_range_response(
    bytes: &[u8],
    current_root: &[u8],
    merkle_family: &str,
    hash_family: &str,
    current_chunk_size: usize,
    start_key: &[u8],
    end_key: &[u8],
    has_end_key: bool,
) -> Result<JsValue, JsValue> {
    let proto = GetRangeResponseView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode getRange response: {err}")))?
        .to_owned_message();
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
            ),
            "mmb" => verify_get_range_from_proto::<mmb::Family, H>(
                &proto,
                &current_root,
                start_key,
                end_key,
                &config,
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
        historical_range_fixture_at_with_hash::<F, Sha256>(start_offset, end_offset)
    }

    fn historical_range_fixture_at_with_hash<F, H>(
        start_offset: u64,
        end_offset: u64,
    ) -> (
        HistoricalOperationRangeProof,
        H::Digest,
        Vec<(Location<F>, TestOperation<F>)>,
    )
    where
        F: merkle::Graftable,
        H: commonware_cryptography::Hasher,
        H::Digest: Encode,
        TestOperation<F>:
            Decode + Encode + Read<Cfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>,
    {
        let hasher = commonware_storage::qmdb::hasher::<H>();
        let mut merkle = Mem::<F, H::Digest>::new();
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
            verify_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root).unwrap();

        assert_eq!(verified_root, root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn verifies_historical_operation_range_mmb() {
        let (proto, root, expected) = historical_range_fixture::<mmb::Family>();

        let (verified_root, verified) =
            verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &root).unwrap();

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

        let (verified_root, verified) =
            verify_raw_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root).unwrap();

        assert_eq!(verified_root, root);
        assert_eq!(verified, expected);
    }

    #[test]
    fn verifies_historical_operation_range_with_blake3() {
        let (proto, root, expected) =
            historical_range_fixture_at_with_hash::<mmr::Family, Blake3>(1, 4);

        let (verified_root, verified) =
            verify_operation_range_from_proto::<mmr::Family, Blake3>(&proto, &root).unwrap();

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

    #[test]
    fn current_root_combine_matches_commonware_witness_layout() {
        let hasher = commonware_storage::qmdb::hasher::<Sha256>();
        let ops_root = Sha256::fill(0x10);
        let witness = OpsRootWitness::<mmb::Family, Sha256Digest> {
            grafted_root: Sha256::fill(0x11),
            pending_chunk_digest: Some(Sha256::fill(0x12)),
            partial_chunk: Some((13, Sha256::fill(0x13))),
        };
        let partial = witness
            .partial_chunk
            .as_ref()
            .map(|(next_bit, digest)| (*next_bit, digest));

        let combined = combine_current_roots(
            &hasher,
            &ops_root,
            &witness.grafted_root,
            witness.pending_chunk_digest.as_ref(),
            partial,
        );

        assert_eq!(combined, witness.root(&hasher, &ops_root));
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
        let (_, verified) =
            verify_raw_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root).unwrap();
        let operation =
            expected_raw_operation(proto.start_location, &verified, 1, "keyless").unwrap();

        let value =
            fixed_keyless_append_value::<mmr::Family>(&operation, expected_value.as_ref()).unwrap();

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
        let (proto, root, _) = historical_raw_range_fixture_at::<mmr::Family>(&operations, 0, 3);
        let (_, verified) =
            verify_raw_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root).unwrap();
        let operation =
            expected_raw_operation(proto.start_location, &verified, 1, "keyless").unwrap();

        let value =
            fixed_keyless_append_value::<mmr::Family>(&operation, expected_value.as_ref()).unwrap();

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
        let (proto, root, _) = historical_raw_range_fixture_at::<mmr::Family>(&operations, 0, 3);
        let (_, verified) =
            verify_raw_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root).unwrap();
        let operation =
            expected_raw_operation(proto.start_location, &verified, 1, "unordered").unwrap();

        let value = fixed_unordered_update_value::<mmr::Family>(
            &operation,
            expected_key.as_ref(),
            u64::SIZE,
        )
        .unwrap();

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
        let (proto, root, _) = historical_raw_range_fixture_at::<mmr::Family>(&operations, 0, 3);
        let (_, verified) =
            verify_raw_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root).unwrap();
        let operation =
            expected_raw_operation(proto.start_location, &verified, 1, "unordered").unwrap();

        let value = fixed_unordered_update_value::<mmr::Family>(
            &operation,
            expected_key.as_ref(),
            expected_value.len(),
        )
        .unwrap();

        assert_eq!(value.as_slice(), expected_value.as_ref());
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
            verify_operation_range_from_proto::<mmr::Family, Sha256>(&zero_start, &zero_root)
                .unwrap();
        assert_eq!(zero_verified, zero_expected);

        let (nonzero_start, nonzero_root, nonzero_expected) =
            historical_range_fixture_at::<mmr::Family>(1, 4);
        assert!(
            !nonzero_start.pinned_nodes.is_empty(),
            "nonzero-start MMR ranges must carry pinned nodes"
        );
        let (_, nonzero_verified) =
            verify_operation_range_from_proto::<mmr::Family, Sha256>(&nonzero_start, &nonzero_root)
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
            verify_operation_range_from_proto::<mmb::Family, Sha256>(&zero_start, &zero_root)
                .unwrap();
        assert_eq!(zero_verified, zero_expected);

        let (nonzero_start, nonzero_root, nonzero_expected) =
            historical_range_fixture_at::<mmb::Family>(1, 4);
        assert!(
            !nonzero_start.pinned_nodes.is_empty(),
            "nonzero-start MMB ranges must carry pinned nodes"
        );
        let (_, nonzero_verified) =
            verify_operation_range_from_proto::<mmb::Family, Sha256>(&nonzero_start, &nonzero_root)
                .unwrap();
        assert_eq!(nonzero_verified, nonzero_expected);
    }

    #[test]
    fn rejects_historical_operation_range_mmr_without_nonzero_pinned_nodes() {
        let (mut proto, root, _) = historical_range_fixture::<mmr::Family>();
        proto.pinned_nodes.clear();

        let err =
            verify_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root).unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn rejects_historical_operation_range_mmb_without_nonzero_pinned_nodes() {
        let (mut proto, root, _) = historical_range_fixture::<mmb::Family>();
        proto.pinned_nodes.clear();

        let err =
            verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &root).unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn rejects_historical_operation_range_mmr_with_zero_start_pinned_nodes() {
        let (mut proto, root, _) = historical_range_fixture_at::<mmr::Family>(0, 3);
        proto.pinned_nodes.push(root.encode());

        let err =
            verify_operation_range_from_proto::<mmr::Family, Sha256>(&proto, &root).unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn rejects_historical_operation_range_mmb_with_zero_start_pinned_nodes() {
        let (mut proto, root, _) = historical_range_fixture_at::<mmb::Family>(0, 3);
        proto.pinned_nodes.push(root.encode());

        let err =
            verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &root).unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn rejects_historical_operation_range_mmb_with_tampered_pinned_node() {
        let (mut proto, root, _) = historical_range_fixture::<mmb::Family>();
        let mut pinned_node = proto.pinned_nodes[0].to_vec();
        pinned_node[0] ^= 0x01;
        proto.pinned_nodes[0] = pinned_node.into();

        let err =
            verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &root).unwrap_err();

        assert_eq!(err, "historical operation range proof failed verification");
    }

    #[test]
    fn rejects_historical_operation_range_mmb_with_extra_pinned_node() {
        let (mut proto, root, _) = historical_range_fixture::<mmb::Family>();
        proto.pinned_nodes.push(proto.pinned_nodes[0].clone());

        let err =
            verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &root).unwrap_err();

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
        let hasher = commonware_storage::qmdb::hasher::<Sha256>();
        let current_root = witness.root(&hasher, &ops_root);
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
    fn rejects_historical_operation_range_root_mismatch() {
        let (proto, root, _) = historical_range_fixture::<mmb::Family>();
        let wrong_root = Sha256::fill(0x42);
        assert_ne!(wrong_root, root);

        let err = verify_operation_range_from_proto::<mmb::Family, Sha256>(&proto, &wrong_root)
            .unwrap_err();

        assert_eq!(err, "historical ops root did not match expected root");
    }
}
