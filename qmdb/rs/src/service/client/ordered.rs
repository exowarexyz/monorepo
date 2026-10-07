//! Verifying client for ordered QMDB.

use std::fmt::Display;

use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_cryptography::Hasher;
use commonware_storage::merkle::Location;
use commonware_storage::qmdb::sync::Target as SyncTarget;
use commonware_storage::{
    merkle::Graftable,
    qmdb::{
        any::{
            ordered,
            value::{ValueEncoding, VariableEncoding},
        },
        current::ordered::ExclusionProof,
        operation::Key as QmdbKey,
    },
};
use commonware_utils::range::NonEmptyRange;
use connectrpc::client::{ClientConfig, ClientTransport};
use exoware_sdk::proto::PreferZstdHttpClient;
use http_body::Body;

use super::rpc::OperationLogSubscription;
use crate::proof::{VerifiedCurrentRange, VerifiedKeyRange, VerifiedOperationRange};
use crate::service::proto::qmdb::v1::{
    GetCurrentOperationRangeRequest, GetManyRequest, GetOperationRangeRequest, GetRangeRequest,
    GetRequest, SubscribeRequest,
};

use crate::proof::{VerifiedKeyLookup, VerifiedKeyValue};
use crate::service::proto::qmdb::v1::{
    current_key_lookup_result, CurrentKeyLookupResult, CurrentKeyValueProof,
};
use crate::QmdbError;

use super::rpc::verify::{verify_key_exclusion_from_proto, verify_key_value_from_proto};
use super::rpc::{CurrentOperationClient, KeyLookupClient, KeyRangeClient, OperationLogClient};

/// Verifies ordered `KeyLookupService` responses: hits and exclusion-proven
/// misses.
pub struct OrderedLookupVerifier<F, H, K, V, const N: usize, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Read,
    ordered::Update<K, E>: Read,
{
    op_cfg: <ordered::Operation<F, K, E> as Read>::Cfg,
    update_cfg: <ordered::Update<K, E> as Read>::Cfg,
    key_cfg: K::Cfg,
    value_cfg: V::Cfg,
    _marker: std::marker::PhantomData<H>,
}

impl<F, H, K, V, const N: usize, E> OrderedLookupVerifier<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Decode + Encode + Read,
    ordered::Update<K, E>: Read,
    ExclusionProof<F, K, E, H::Digest, N>:
        Read<Cfg = (usize, <ordered::Update<K, E> as Read>::Cfg, V::Cfg)>,
{
    pub fn new(
        op_cfg: <ordered::Operation<F, K, E> as Read>::Cfg,
        update_cfg: <ordered::Update<K, E> as Read>::Cfg,
        key_cfg: K::Cfg,
        value_cfg: V::Cfg,
    ) -> Self {
        Self {
            op_cfg,
            update_cfg,
            key_cfg,
            value_cfg,
            _marker: std::marker::PhantomData,
        }
    }

    fn decode_requested_key(&self, key: &[u8]) -> Result<K, QmdbError> {
        K::decode_cfg(key, &self.key_cfg).map_err(|err| {
            QmdbError::CorruptData(format!("failed to decode requested QMDB key: {err}"))
        })
    }

    fn verify_hit(
        &self,
        requested_key: &K,
        proof: &CurrentKeyValueProof,
        root: &H::Digest,
        label: &str,
    ) -> Result<VerifiedKeyValue<H::Digest, ordered::Operation<F, K, E>, F>, QmdbError> {
        let verified = verify_key_value_from_proto::<F, H, ordered::Operation<F, K, E>, N>(
            proof,
            root,
            &self.op_cfg,
        )?;
        let ordered::Operation::Update(update) = &verified.operation else {
            return Err(QmdbError::CorruptData(format!(
                "{label} proof did not verify an update"
            )));
        };
        if update.key != *requested_key {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
        Ok(verified)
    }
}

impl<F, H, K, V, const N: usize, E> super::rpc::LookupVerifier
    for OrderedLookupVerifier<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Decode + Encode + Read,
    ordered::Update<K, E>: Read,
    ExclusionProof<F, K, E, H::Digest, N>:
        Read<Cfg = (usize, <ordered::Update<K, E> as Read>::Cfg, V::Cfg)>,
{
    type Digest = H::Digest;
    type Hit = VerifiedKeyValue<H::Digest, ordered::Operation<F, K, E>, F>;
    type Lookup = VerifiedKeyLookup<H::Digest, K, V, F, E>;

    fn verify_get(
        &self,
        requested_key: &[u8],
        proof: &CurrentKeyValueProof,
        root: &H::Digest,
    ) -> Result<Self::Hit, QmdbError> {
        let requested_key = self.decode_requested_key(requested_key)?;
        self.verify_hit(&requested_key, proof, root, "qmdb get")
    }

    fn verify_get_many(
        &self,
        requested_keys: &[Vec<u8>],
        results: &[CurrentKeyLookupResult],
        root: &H::Digest,
    ) -> Result<Vec<Self::Lookup>, QmdbError> {
        if results.len() != requested_keys.len() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
        results
            .iter()
            .zip(requested_keys.iter())
            .map(|(result, requested_key)| {
                let decoded_requested_key = self.decode_requested_key(requested_key)?;
                match result.result.as_ref() {
                    Some(current_key_lookup_result::Result::Hit(proof)) => {
                        Ok(VerifiedKeyLookup::Hit(self.verify_hit(
                            &decoded_requested_key,
                            proof,
                            root,
                            "qmdb get_many hit",
                        )?))
                    }
                    Some(current_key_lookup_result::Result::Miss(proof)) => {
                        verify_key_exclusion_from_proto::<F, H, K, V, N, E>(
                            proof,
                            requested_key.as_slice(),
                            root,
                            &self.update_cfg,
                            &self.key_cfg,
                            &self.value_cfg,
                        )?;
                        Ok(VerifiedKeyLookup::Miss {
                            key: decoded_requested_key,
                        })
                    }
                    None => Err(QmdbError::CorruptData(
                        "qmdb get_many result missing hit/miss proof".to_string(),
                    )),
                }
            })
            .collect()
    }
}

/// Verifying client for an ordered-QMDB endpoint: key lookups, key ranges,
/// current operation ranges, and the operation log.
pub struct Ordered<
    T,
    F: Graftable,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    ordered::Operation<F, K, E>: Encode + Read,
    ordered::Update<K, E>: Read,
{
    key_lookup: KeyLookupClient<T, OrderedLookupVerifier<F, H, K, V, N, E>>,
    key_range: KeyRangeClient<T, F, H, K, V, N, E>,
    current_operation: CurrentOperationClient<T, F, H, ordered::Operation<F, K, E>, N>,
    operation_log: OperationLogClient<T, F, H, ordered::Operation<F, K, E>>,
}

impl<F, H, K, V, const N: usize, E> Ordered<PreferZstdHttpClient, F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Decode + Encode + Read,
    ordered::Update<K, E>: Read,
    ExclusionProof<F, K, E, H::Digest, N>:
        Read<Cfg = (usize, <ordered::Update<K, E> as Read>::Cfg, V::Cfg)>,
{
    pub fn plaintext(
        base: &str,
        op_cfg: <ordered::Operation<F, K, E> as Read>::Cfg,
        update_cfg: <ordered::Update<K, E> as Read>::Cfg,
        key_cfg: K::Cfg,
        value_cfg: V::Cfg,
    ) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
            update_cfg,
            key_cfg,
            value_cfg,
        )
    }
}

impl<T, F, H, K, V, const N: usize, E> Ordered<T, F, H, K, V, N, E>
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
    ordered::Operation<F, K, E>: Decode + Encode + Read,
    ordered::Update<K, E>: Read,
    ExclusionProof<F, K, E, H::Digest, N>:
        Read<Cfg = (usize, <ordered::Update<K, E> as Read>::Cfg, V::Cfg)>,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        op_cfg: <ordered::Operation<F, K, E> as Read>::Cfg,
        update_cfg: <ordered::Update<K, E> as Read>::Cfg,
        key_cfg: K::Cfg,
        value_cfg: V::Cfg,
    ) -> Self {
        Self {
            key_lookup: KeyLookupClient::new(
                transport.clone(),
                config.clone(),
                OrderedLookupVerifier::new(
                    op_cfg.clone(),
                    update_cfg.clone(),
                    key_cfg.clone(),
                    value_cfg.clone(),
                ),
            ),
            key_range: KeyRangeClient::new(
                transport.clone(),
                config.clone(),
                op_cfg.clone(),
                update_cfg,
                key_cfg,
                value_cfg,
            ),
            current_operation: CurrentOperationClient::new(
                transport.clone(),
                config.clone(),
                op_cfg.clone(),
            ),
            operation_log: OperationLogClient::new(transport, config, op_cfg),
        }
    }

    /// Verified current-state proof for `key` at `tip`.
    pub async fn get(
        &self,
        tip: Location<F>,
        key: &K,
        min_sequence_number: Option<u64>,
        root: &H::Digest,
    ) -> Result<VerifiedKeyValue<H::Digest, ordered::Operation<F, K, E>, F>, QmdbError> {
        self.key_lookup
            .get(
                GetRequest {
                    key: key.encode().to_vec(),
                    tip: tip.as_u64(),
                    min_sequence_number,
                    ..Default::default()
                },
                root,
            )
            .await
    }

    /// Verified current-state lookups for `keys`: a hit with its value proof,
    /// or a miss proven by exclusion, in request order.
    pub async fn get_many(
        &self,
        tip: Location<F>,
        keys: &[K],
        min_sequence_number: Option<u64>,
        root: &H::Digest,
    ) -> Result<Vec<VerifiedKeyLookup<H::Digest, K, V, F, E>>, QmdbError> {
        self.key_lookup
            .get_many(
                GetManyRequest {
                    keys: keys.iter().map(|key| key.encode().to_vec()).collect(),
                    tip: tip.as_u64(),
                    min_sequence_number,
                    ..Default::default()
                },
                root,
            )
            .await
    }

    /// Verified ordered current-state range for `[start_key, end_key)`, at most
    /// `limit` entries.
    pub async fn get_range(
        &self,
        tip: Location<F>,
        start_key: K,
        end_key: Option<K>,
        limit: u32,
        min_sequence_number: Option<u64>,
        root: &H::Digest,
    ) -> Result<VerifiedKeyRange<H::Digest, K, V, F, E>, QmdbError> {
        self.key_range
            .get_range(
                GetRangeRequest {
                    start_key: start_key.encode().to_vec(),
                    end_key: end_key.map(|key| key.encode().to_vec()),
                    limit,
                    tip: tip.as_u64(),
                    min_sequence_number,
                    ..Default::default()
                },
                root,
            )
            .await
    }

    /// Verified current-state operations and bitmap chunks for
    /// `[start_location, start_location + max_locations)`, capped at `tip`.
    pub async fn current_operation_range(
        &self,
        tip: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
        root: &H::Digest,
    ) -> Result<VerifiedCurrentRange<H::Digest, ordered::Operation<F, K, E>, N, F>, QmdbError> {
        self.current_operation
            .get_current_operation_range(
                GetCurrentOperationRangeRequest {
                    tip: tip.as_u64(),
                    start_location: start_location.as_u64(),
                    max_locations,
                    min_sequence_number,
                    ..Default::default()
                },
                root,
            )
            .await
    }

    /// Commonware sync target for `range`, authenticated against the trusted
    /// current `root`.
    pub async fn current_sync_target(
        &self,
        range: NonEmptyRange<Location<F>>,
        root: &H::Digest,
    ) -> Result<SyncTarget<F, H::Digest>, QmdbError> {
        self.operation_log.current_sync_target(range, root).await
    }

    /// Verified contiguous operations `[start_location, start_location + max_locations)`,
    /// capped at `tip`.
    pub async fn operation_range(
        &self,
        tip: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
        root: &H::Digest,
    ) -> Result<VerifiedOperationRange<H::Digest, ordered::Operation<F, K, E>, F>, QmdbError> {
        self.operation_log
            .get_operation_range(
                GetOperationRangeRequest {
                    tip: tip.as_u64(),
                    start_location: start_location.as_u64(),
                    max_locations,
                    min_sequence_number,
                    ..Default::default()
                },
                root,
            )
            .await
    }

    /// Subscribe to proof-carrying batches of the operation log.
    pub async fn subscribe(
        &self,
        request: SubscribeRequest,
    ) -> Result<
        OperationLogSubscription<T::ResponseBody, F, H, ordered::Operation<F, K, E>>,
        QmdbError,
    > {
        self.operation_log.subscribe(request).await
    }
}
