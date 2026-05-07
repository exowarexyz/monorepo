use crate::proto::qmdb::v1::{
    CurrentKeyValueProof, CurrentKeyValueProofView, GetManyResponse, GetManyResponseView,
    HistoricalMultiProof, HistoricalMultiProofView,
};
use buffa::MessageView;
use commonware_codec::{Decode, DecodeExt, Encode, FixedSize, RangeCfg, Read};
use commonware_cryptography::{Digest, Sha256};
use commonware_storage::{
    merkle::{self, Location},
    mmb, mmr,
    qmdb::{
        any::ordered::{variable::Operation as OrderedOperation, Update},
        current::proof::OperationProof as CurrentOperationProof,
        verify::verify_multi_proof,
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

type ShaDigest = commonware_cryptography::sha256::Digest;
type DecodedOperation<F> = OrderedOperation<F, Vec<u8>, Vec<u8>>;
type OperationReadCfg = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()));
type MultiProofOperations<F> = Vec<(Location<F>, DecodedOperation<F>)>;

fn op_cfg<F>() -> <DecodedOperation<F> as Read>::Cfg
where
    F: merkle::Family,
    DecodedOperation<F>: Read<Cfg = OperationReadCfg>,
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
    encoded_proof.len() / ShaDigest::SIZE + 1
}

fn normalize_family<'a>(family: &'a str, label: &str) -> Result<&'a str, String> {
    match family {
        "mmr" | "mmb" => Ok(family),
        "" => Err(format!("{label} missing Merkle family")),
        other => Err(format!("{label} uses unsupported Merkle family {other}")),
    }
}

fn verify_multi_from_proto<F>(
    proto: &HistoricalMultiProof,
    root: &ShaDigest,
) -> Result<MultiProofOperations<F>, String>
where
    F: merkle::Family,
    DecodedOperation<F>: Decode + Encode + Read<Cfg = OperationReadCfg>,
{
    let operations = proto
        .operations
        .iter()
        .map(|operation| {
            Ok((
                Location::new(operation.location),
                DecodedOperation::<F>::decode_cfg(
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
    let max_digests = proof_digest_cap(&proto.proof);
    let proof = merkle::Proof::<F, ShaDigest>::decode_cfg(proto.proof.as_slice(), &max_digests)
        .map_err(|err| format!("failed to decode historical multi proof: {err}"))?;
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    if !verify_multi_proof(&hasher, &proof, &operations, root) {
        return Err("historical multi proof failed verification".to_string());
    }
    Ok(operations)
}

fn verify_key_value_from_proto<F>(
    proto: &CurrentKeyValueProof,
    root: &ShaDigest,
) -> Result<(Location<F>, DecodedOperation<F>), String>
where
    F: merkle::Graftable,
    DecodedOperation<F>: Decode + Encode + Read<Cfg = OperationReadCfg>,
{
    let operation =
        DecodedOperation::<F>::decode_cfg(proto.encoded_operation.as_slice(), &op_cfg::<F>())
            .map_err(|err| format!("failed to decode current key-value operation: {err}"))?;
    let OrderedOperation::Update(_) = &operation else {
        return Err("current key-value proof operation must be an update".to_string());
    };
    let max_digests = proof_digest_cap(&proto.proof);
    let proof =
        CurrentOperationProof::<F, ShaDigest, 32>::decode_cfg(proto.proof.as_slice(), &max_digests)
            .map_err(|err| format!("failed to decode current key-value proof: {err}"))?;
    let mut hasher = Sha256::default();
    if !proof.verify(&mut hasher, operation.clone(), root) {
        return Err("current key-value proof failed verification".to_string());
    }
    Ok((proof.loc, operation))
}

fn verify_get_many_from_proto<F>(
    proto: &GetManyResponse,
    current_root: &ShaDigest,
) -> Result<MultiProofOperations<F>, String>
where
    F: merkle::Graftable,
    DecodedOperation<F>: Decode + Encode + Read<Cfg = OperationReadCfg>,
{
    let historical = proto
        .proof
        .as_option()
        .ok_or_else(|| "getMany response missing historical proof".to_string())?;
    if proto.current_proof.is_empty() {
        return Err("getMany response missing current anchor proof".to_string());
    }
    let max_digests = proof_digest_cap(&proto.current_proof);
    let current_proof = CurrentOperationProof::<F, ShaDigest, 32>::decode_cfg(
        proto.current_proof.as_slice(),
        &max_digests,
    )
    .map_err(|err| format!("failed to decode current anchor proof: {err}"))?;
    let anchor = historical
        .operations
        .iter()
        .find(|operation| operation.location == *current_proof.loc)
        .ok_or_else(|| {
            format!(
                "current anchor location {} is absent from historical proof operations",
                *current_proof.loc
            )
        })?;
    let anchor_operation =
        DecodedOperation::<F>::decode_cfg(anchor.encoded_operation.as_slice(), &op_cfg::<F>())
            .map_err(|err| {
                format!(
                    "failed to decode current anchor operation at {}: {err}",
                    anchor.location
                )
            })?;
    let mut hasher = Sha256::default();
    if !current_proof.verify(&mut hasher, anchor_operation, current_root) {
        return Err("current anchor proof failed verification".to_string());
    }
    verify_multi_from_proto::<F>(historical, &current_proof.range_proof.ops_root)
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

fn to_js_operation<F: merkle::Family>(operation: DecodedOperation<F>) -> Result<JsValue, JsValue> {
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

fn historical_to_js<F>(decoded_operations: MultiProofOperations<F>) -> Result<JsValue, JsValue>
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

fn current_to_js<F>(
    location: Location<F>,
    operation: DecodedOperation<F>,
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
        "mmr" => historical_to_js(
            verify_get_many_from_proto::<mmr::Family>(&proto, &current_root).map_err(js_err)?,
        ),
        "mmb" => historical_to_js(
            verify_get_many_from_proto::<mmb::Family>(&proto, &current_root).map_err(js_err)?,
        ),
        _ => unreachable!("normalize_family only returns supported values"),
    }
}
