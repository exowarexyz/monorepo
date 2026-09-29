//! Verifying client for `qmdb.v1.KeyLookupService`.

use std::collections::BTreeSet;
use std::fmt::Display;
use std::sync::Arc;

use bytes::Bytes;
use connectrpc::client::{ClientConfig, ClientTransport};
use http_body::Body;

use crate::service::proto::qmdb::v1::{
    CurrentKeyLookupResult, CurrentKeyValueProof, GetManyRequest, GetRequest,
    KeyLookupServiceClient,
};
use crate::QmdbError;

use super::connect_error_to_qmdb;

/// Kind-specific verification of `KeyLookupService` responses.
///
/// Ordered QMDB proves both hits and misses; unordered QMDB proves hits only.
pub trait LookupVerifier {
    type Digest;
    /// Verified `Get` result.
    type Hit;
    /// Verified `GetMany` result.
    type Lookup;

    /// Verify a `Get` proof for `requested_key` against `root`.
    fn verify_get(
        &self,
        requested_key: &[u8],
        proof: &CurrentKeyValueProof,
        root: &Self::Digest,
    ) -> Result<Self::Hit, QmdbError>;

    /// Verify `GetMany` results for distinct `requested_keys` against `root`.
    fn verify_get_many(
        &self,
        requested_keys: &[Vec<u8>],
        results: &[CurrentKeyLookupResult],
        root: &Self::Digest,
    ) -> Result<Vec<Self::Lookup>, QmdbError>;
}

/// Client for `qmdb.v1.KeyLookupService`, verifying responses with `L`.
pub struct KeyLookupClient<T, L> {
    rpc: KeyLookupServiceClient<T>,
    verifier: Arc<L>,
}

impl<T: Clone, L> Clone for KeyLookupClient<T, L> {
    fn clone(&self) -> Self {
        Self {
            rpc: self.rpc.clone(),
            verifier: self.verifier.clone(),
        }
    }
}

impl<T, L> KeyLookupClient<T, L>
where
    T: ClientTransport,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    L: LookupVerifier,
{
    pub fn new(transport: T, config: ClientConfig, verifier: L) -> Self {
        Self::from_service_client(KeyLookupServiceClient::new(transport, config), verifier)
    }

    pub fn from_service_client(rpc: KeyLookupServiceClient<T>, verifier: L) -> Self {
        Self {
            rpc,
            verifier: Arc::new(verifier),
        }
    }

    pub async fn get(
        &self,
        request: GetRequest,
        expected_root: &L::Digest,
    ) -> Result<L::Hit, QmdbError> {
        let requested_key = request.key.clone();
        let response = self
            .rpc
            .get(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        let proof = response
            .proof
            .as_option()
            .ok_or_else(|| QmdbError::CorruptData("qmdb get response missing proof".to_string()))?;
        self.verifier
            .verify_get(&requested_key, proof, expected_root)
    }

    pub async fn get_many(
        &self,
        request: GetManyRequest,
        expected_root: &L::Digest,
    ) -> Result<Vec<L::Lookup>, QmdbError> {
        let requested_keys = request.keys.clone();
        let mut requested = BTreeSet::<&[u8]>::new();
        for key in &requested_keys {
            if !requested.insert(key.as_ref()) {
                return Err(QmdbError::DuplicateRequestedKey { key: key.clone() });
            }
        }
        let response = self
            .rpc
            .get_many(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        self.verifier
            .verify_get_many(&requested_keys, &response.results, expected_root)
    }
}
