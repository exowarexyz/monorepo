//! Verifying client for unordered QMDB.

use std::collections::BTreeMap;
use std::fmt::Display;

use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::Graftable,
    qmdb::{
        any::{
            unordered,
            value::{ValueEncoding, VariableEncoding},
        },
        operation::Key as QmdbKey,
    },
};
use connectrpc::client::{ClientConfig, ClientTransport};
use exoware_sdk::proto::PreferZstdHttpClient;
use http_body::Body;

use crate::proof::VerifiedKeyValue;
use crate::service::proto::qmdb::v1::{
    current_key_lookup_result, CurrentKeyLookupResult, CurrentKeyValueProof,
};
use crate::QmdbError;

use super::rpc::verify::verify_key_value_from_proto;
use super::rpc::{CurrentOperationClient, KeyLookupClient, OperationLogClient};

/// Verifies unordered `KeyLookupService` responses: hits only, in request
/// order.
pub struct UnorderedLookupVerifier<F, H, K, V, const N: usize, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Read,
{
    op_cfg: <unordered::Operation<F, K, E> as Read>::Cfg,
    _marker: std::marker::PhantomData<(H, V)>,
}

impl<F, H, K, V, const N: usize, E> UnorderedLookupVerifier<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Read,
{
    pub fn new(op_cfg: <unordered::Operation<F, K, E> as Read>::Cfg) -> Self {
        Self {
            op_cfg,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, H, K, V, const N: usize, E> super::rpc::LookupVerifier
    for UnorderedLookupVerifier<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Decode + Encode + Read,
{
    type Digest = H::Digest;
    type Hit = VerifiedKeyValue<H::Digest, unordered::Operation<F, K, E>, F>;
    type Lookup = Self::Hit;

    fn verify_get(
        &self,
        requested_key: &[u8],
        proof: &CurrentKeyValueProof,
        root: &H::Digest,
    ) -> Result<Self::Hit, QmdbError> {
        let verified = verify_key_value_from_proto::<F, H, unordered::Operation<F, K, E>, N>(
            proof,
            root,
            &self.op_cfg,
        )?;
        if !matches!(&verified.operation, unordered::Operation::Update(update) if update.0.encode().as_ref() == requested_key)
        {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
        Ok(verified)
    }

    fn verify_get_many(
        &self,
        requested_keys: &[Vec<u8>],
        results: &[CurrentKeyLookupResult],
        root: &H::Digest,
    ) -> Result<Vec<Self::Lookup>, QmdbError> {
        let requested = requested_keys
            .iter()
            .enumerate()
            .map(|(index, key)| (key.as_slice(), index))
            .collect::<BTreeMap<&[u8], usize>>();
        let mut last_index = None;
        results
            .iter()
            .map(|result| {
                let verified = match result.result.as_ref() {
                    Some(current_key_lookup_result::Result::Hit(proof)) => {
                        verify_key_value_from_proto::<F, H, unordered::Operation<F, K, E>, N>(
                            proof,
                            root,
                            &self.op_cfg,
                        )?
                    }
                    Some(current_key_lookup_result::Result::Miss(_)) => {
                        return Err(QmdbError::CorruptData(
                            "unordered get_many response must not include miss proofs".to_string(),
                        ));
                    }
                    None => {
                        return Err(QmdbError::CorruptData(
                            "qmdb get_many result missing hit proof".to_string(),
                        ));
                    }
                };
                let unordered::Operation::Update(update) = &verified.operation else {
                    return Err(QmdbError::ProofVerification {
                        kind: crate::ProofKind::CurrentKeyValue,
                    });
                };
                let key = update.0.encode();
                let Some(&request_index) = requested.get(key.as_ref()) else {
                    return Err(QmdbError::ProofVerification {
                        kind: crate::ProofKind::CurrentKeyValue,
                    });
                };
                if last_index.is_some_and(|last| request_index <= last) {
                    return Err(QmdbError::ProofVerification {
                        kind: crate::ProofKind::CurrentKeyValue,
                    });
                }
                last_index = Some(request_index);
                Ok(verified)
            })
            .collect()
    }
}

/// Verifying client for an unordered-QMDB endpoint: key lookups (hits only),
/// current operation ranges, and the operation log.
pub struct Unordered<
    T,
    F: Graftable,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    unordered::Operation<F, K, E>: Encode + Read,
{
    pub key_lookup: KeyLookupClient<T, UnorderedLookupVerifier<F, H, K, V, N, E>>,
    pub current_operation: CurrentOperationClient<T, F, H, unordered::Operation<F, K, E>, N>,
    pub operation_log: OperationLogClient<T, F, H, unordered::Operation<F, K, E>>,
}

impl<F, H, K, V, const N: usize, E> Unordered<PreferZstdHttpClient, F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Decode + Encode + Read,
{
    pub fn plaintext(base: &str, op_cfg: <unordered::Operation<F, K, E> as Read>::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, F, H, K, V, const N: usize, E> Unordered<T, F, H, K, V, N, E>
where
    T: ClientTransport + Clone,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Decode + Encode + Read,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        op_cfg: <unordered::Operation<F, K, E> as Read>::Cfg,
    ) -> Self {
        Self {
            key_lookup: KeyLookupClient::new(
                transport.clone(),
                config.clone(),
                UnorderedLookupVerifier::new(op_cfg.clone()),
            ),
            current_operation: CurrentOperationClient::new(
                transport.clone(),
                config.clone(),
                op_cfg.clone(),
            ),
            operation_log: OperationLogClient::new(transport, config, op_cfg),
        }
    }
}
