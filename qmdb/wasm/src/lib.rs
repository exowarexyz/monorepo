use crate::proto::store::qmdb::v1::{
    CurrentKeyValueProof, CurrentKeyValueProofView, HistoricalMultiProof, HistoricalMultiProofView,
};
use buffa::MessageView;
use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_cryptography::{Digest, Sha256};
use commonware_storage::{
    mmr::{self, Location, StandardHasher},
    qmdb::{
        any::ordered::{variable::Operation as OrderedOperation, Update},
        current::proof::{
            OperationProof as CurrentOperationProof, RangeProof as CurrentRangeProof,
        },
        verify::verify_multi_proof,
    },
};
use js_sys::{Array, BigInt, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

pub mod proto {
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

        pub mod qmdb {
            pub mod v1 {
                #![allow(non_camel_case_types)]
                #![allow(unused_imports)]
                #![allow(clippy::derivable_impls)]
                #![allow(clippy::match_single_binding)]
                include!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../sdk-rs/src/gen/store.v1.qmdb.rs"
                ));
            }
        }
    }
}

const MAX_OPERATION_SIZE: usize = u16::MAX as usize;

type DecodedOperation = OrderedOperation<Vec<u8>, Vec<u8>>;
type MultiProofOperations = Vec<(Location, DecodedOperation)>;

#[derive(Clone)]
struct RawMmrProof<D: Digest> {
    leaves: Location,
    digests: Vec<D>,
}

fn op_cfg() -> <OrderedOperation<Vec<u8>, Vec<u8>> as Read>::Cfg {
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

fn raw_mmr_from_proto<D: Digest + DecodeExt<()>>(
    proto: &crate::proto::store::qmdb::v1::MmrProof,
) -> Result<RawMmrProof<D>, String> {
    Ok(RawMmrProof {
        leaves: Location::new(proto.leaves),
        digests: proto
            .digests
            .iter()
            .map(|digest| decode_digest(digest, "mmr proof digest"))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

impl<D: Digest + Clone> From<&RawMmrProof<D>> for mmr::Proof<D> {
    fn from(value: &RawMmrProof<D>) -> Self {
        Self {
            leaves: value.leaves,
            digests: value.digests.clone(),
        }
    }
}

fn verify_multi_from_proto(
    proto: &HistoricalMultiProof,
) -> Result<(Vec<u8>, MultiProofOperations), String> {
    let proof = proto
        .proof
        .as_option()
        .ok_or_else(|| "historical multi proof missing mmr proof".to_string())?;
    let root = decode_digest(&proto.root, "historical multi proof root")?;
    let operations = proto
        .operations
        .iter()
        .map(|operation| {
            Ok((
                Location::new(operation.location),
                OrderedOperation::<Vec<u8>, Vec<u8>>::decode_cfg(
                    operation.encoded_operation.as_slice(),
                    &op_cfg(),
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
    let mmr_proof = raw_mmr_from_proto(proof)?;
    let mut hasher = StandardHasher::<Sha256>::new();
    if !verify_multi_proof(
        &mut hasher,
        &mmr::Proof::from(&mmr_proof),
        &operations,
        &root,
    ) {
        return Err("historical multi proof failed verification".to_string());
    }
    Ok((root.encode().to_vec(), operations))
}

fn verify_key_value_from_proto(
    proto: &CurrentKeyValueProof,
) -> Result<(Vec<u8>, Location, DecodedOperation), String> {
    let range_proof = proto
        .range_proof
        .as_option()
        .ok_or_else(|| "current key-value proof missing range proof".to_string())?;
    let mmr_proof = range_proof
        .proof
        .as_option()
        .ok_or_else(|| "current range proof missing mmr proof".to_string())?;
    let root = decode_digest(&proto.root, "current key-value proof root")?;
    let location = Location::new(proto.location);
    let chunk: [u8; 32] = proto
        .chunk
        .as_slice()
        .try_into()
        .map_err(|_| format!("invalid chunk length {}, expected 32", proto.chunk.len()))?;
    let operation = OrderedOperation::<Vec<u8>, Vec<u8>>::decode_cfg(
        proto.encoded_operation.as_slice(),
        &op_cfg(),
    )
    .map_err(|err| {
        format!(
            "failed to decode current key-value operation at {}: {err}",
            proto.location
        )
    })?;
    let OrderedOperation::Update(_) = &operation else {
        return Err("current key-value proof operation must be an update".to_string());
    };
    let proof = CurrentOperationProof {
        loc: location,
        chunk,
        range_proof: CurrentRangeProof {
            proof: mmr::Proof::from(&raw_mmr_from_proto(mmr_proof)?),
            partial_chunk_digest: range_proof
                .partial_chunk_digest
                .as_ref()
                .map(|digest| decode_digest(digest, "current range partial chunk digest"))
                .transpose()?,
            ops_root: decode_digest(&range_proof.ops_root, "current range ops root")?,
        },
    };
    let mut hasher = Sha256::default();
    if !proof.verify(&mut hasher, operation.clone(), &root) {
        return Err("current key-value proof failed verification".to_string());
    }
    Ok((root.encode().to_vec(), location, operation))
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

fn location_to_bigint(location: Location) -> Result<JsValue, JsValue> {
    u64_to_bigint(*location)
}

fn to_js_operation(operation: OrderedOperation<Vec<u8>, Vec<u8>>) -> Result<JsValue, JsValue> {
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

#[wasm_bindgen]
pub fn verify_historical_multi_proof(bytes: &[u8]) -> Result<JsValue, JsValue> {
    let proto = HistoricalMultiProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode historical multi proof: {err}")))?
        .to_owned_message();
    let (root, decoded_operations) = verify_multi_from_proto(&proto).map_err(js_err)?;
    let operations = Array::new();
    for (location, operation) in decoded_operations {
        let entry = Object::new();
        set_field(&entry, "location", &location_to_bigint(location)?)?;
        set_field(&entry, "operation", &to_js_operation(operation)?)?;
        operations.push(&entry.into());
    }
    let verified = Object::new();
    set_field(&verified, "root", &bytes_to_js(&root))?;
    set_field(&verified, "operations", &operations.into())?;
    Ok(verified.into())
}

#[wasm_bindgen]
pub fn verify_current_key_value_proof(bytes: &[u8]) -> Result<JsValue, JsValue> {
    let proto = CurrentKeyValueProofView::decode_view(bytes)
        .map_err(|err| js_err(format!("decode current key-value proof: {err}")))?
        .to_owned_message();
    let (root, location, operation) = verify_key_value_from_proto(&proto).map_err(js_err)?;
    let verified = Object::new();
    set_field(&verified, "root", &bytes_to_js(&root))?;
    set_field(&verified, "location", &location_to_bigint(location)?)?;
    set_field(&verified, "operation", &to_js_operation(operation)?)?;
    Ok(verified.into())
}
