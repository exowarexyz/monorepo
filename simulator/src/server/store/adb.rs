use crate::server::store::{
    decode_base64_param, Entry, Error, State, KEY_NAMESPACE_PREFIX, POS_NAMESPACE_PREFIX,
};
use axum::{
    body::Bytes,
    extract::{Query, State as AxumState},
    response::Json,
};
use commonware_storage::mmr::verification::Proof;
use exoware_sdk_rs::store::adb;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

/// Query parameters for the `get` endpoint.
#[derive(Deserialize)]
pub(super) struct GetParams {
    /// The key whose value we are fetching.
    key: String,
    /// The MMR size to verify the proof against.
    size: u64,
}

/// Represents an adb key's value and its position in the MMR.
#[derive(Serialize, Deserialize)]
struct Value {
    value: Vec<u8>,
    position: u64,
}

impl Value {
    fn deserialize(value: &[u8]) -> Result<Self, Error> {
        Ok(bincode::deserialize::<Value>(value)?)
    }
    fn serialize(&self) -> Result<Vec<u8>, Error> {
        Ok(bincode::serialize(self)?)
    }
}

/// Retrieves a value from the store by its key along with a verifiable proof. Request will fail if
/// any of the digests required to construct the proof are not (yet) in the store.
pub(super) async fn get(
    AxumState(state): AxumState<State>,
    Query(params): Query<GetParams>,
) -> Result<Json<adb::GetResultPayload>, Error> {
    // Decode the base64 key
    debug!(
        operation = "get",
        key = %params.key,
        size = %params.size,
        "processing get request"
    );

    let decoded_key = decode_base64_param(&params.key, "key")?;

    // Apply the key namespace prefix since this is a regular key, not a position.
    let mut db_key = vec![KEY_NAMESPACE_PREFIX];
    db_key.extend_from_slice(&decoded_key);

    // Fetch the key's value from the kv store.
    let Some(entry) = Entry::read(&state.db, &db_key)? else {
        debug!(
            operation = "get",
            key = %params.key,
            "key not found in database"
        );
        return Err(Error::NotFound);
    };
    let value = Value::deserialize(&entry.value)?;

    // Now fetch the proof data from the kv store.  We are assuming Sha256 (or actually any 32 byte)
    // digests.
    let proof_indices =
        Proof::<commonware_cryptography::sha256::Digest>::nodes_required_for_range_proof(
            params.size,
            value.position,
            value.position,
        );

    let mut proof_data = Vec::with_capacity(proof_indices.len());

    // Fetch the proof nodes from the database, returning MissingData error if
    // any node is not found.
    for node_index in &proof_indices {
        let mut node_key = vec![POS_NAMESPACE_PREFIX];
        node_key.extend_from_slice(&node_index.to_be_bytes());
        let Some(entry) = Entry::read(&state.db, &node_key)? else {
            error!(
                operation = "get",
                key = %params.key,
                node_index = node_index,
                "proof node not found in database"
            );
            return Err(Error::MissingData(format!(
                "Proof node {node_index} not found in KV store",
            )));
        };

        if entry.value.len() != 32 {
            error!(
                operation = "get",
                key = %params.key,
                node_index = node_index,
                "proof node is not a 32-byte hash"
            );
            return Err(Error::Internal(format!(
                "Proof node {node_index} is not a 32-byte hash"
            )));
        }
        proof_data.extend(entry.value);
    }

    Ok(Json(adb::GetResultPayload {
        value: value.value,
        position: value.position,
        proof_data,
    }))
}

/// Query parameters for the `set_key` endpoint.  Value is raw bytes passed in the request body.
#[derive(Deserialize)]
pub(super) struct SetKeyParams {
    /// The key whose value we are setting.
    key: String,
    /// The current position of the this value in the MMR.
    position: u64,
}

/// TODO: rate limiting & key/value size limiting like in kv::set?
pub(super) async fn set_key(
    AxumState(state): AxumState<State>,
    Query(params): Query<SetKeyParams>,
    value: Bytes,
) -> Result<(), Error> {
    // Decode the base64 key
    let decoded_key = decode_base64_param(&params.key, "key")?;

    let value = Value {
        value: value.to_vec(),
        position: params.position,
    };
    let entry = Entry::new(value.serialize()?);
    let mut db_key = vec![KEY_NAMESPACE_PREFIX];
    db_key.extend_from_slice(&decoded_key);
    entry.write(&state.db, &db_key)?;

    debug!(
        operation = "set_key",
        key = %params.key,
        "set_key request completed successfully"
    );
    Ok(())
}

/// Query parameters for the `set_node_digest` endpoint.  Value is raw bytes passed in the request body.
#[derive(Deserialize)]
pub(super) struct SetNodeDigest {
    /// The position of the node whose digest we are setting.
    position: u64,
}

/// TODO: rate limiting & key/value size limiting like in kv::set?
pub(super) async fn set_node_digest(
    AxumState(state): AxumState<State>,
    Query(params): Query<SetNodeDigest>,
    value: Bytes,
) -> Result<(), Error> {
    if value.len() != 32 {
        return Err(Error::InvalidBody(format!(
            "Node digest must be 32 bytes, got {}",
            value.len()
        )));
    }

    let entry = Entry::new(value.into());
    let mut node_key = vec![POS_NAMESPACE_PREFIX];
    node_key.extend_from_slice(&params.position.to_be_bytes());
    entry.write(&state.db, &node_key)?;

    debug!(
        operation = "set_node_digest",
        position = %params.position,
        "set_node_digest request completed successfully"
    );
    Ok(())
}
