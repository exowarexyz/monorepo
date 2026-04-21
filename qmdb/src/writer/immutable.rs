//! Single-writer helper for the immutable QMDB variant (authenticated,
//! single-Set-per-key semantics).

use std::marker::PhantomData;

use commonware_codec::{Codec, Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::mmr::{Location, Position};
use commonware_storage::qmdb::immutable::Operation as ImmutableOperation;
use commonware_utils::Array;
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::StoreClient;

use crate::auth::{
    build_auth_immutable_upload_rows, encode_auth_node_key, encode_auth_watermark_key,
    load_auth_peaks, read_latest_auth_watermark, AuthenticatedBackendNamespace,
};
use crate::codec::mmr_size_for_watermark;
use crate::core::extend_mmr_from_peaks;
use crate::error::QmdbError;
use crate::writer::core::{Cache, WriterCore};
use crate::UploadReceipt;

const NAMESPACE: AuthenticatedBackendNamespace = AuthenticatedBackendNamespace::Immutable;

#[derive(Clone, Debug)]
pub struct BuiltImmutableUpload<D> {
    pub rows: Vec<(Key, Vec<u8>)>,
    pub new_peaks: Vec<(Position, u32, D)>,
    pub new_ops_size: Position,
    pub new_root: D,
    pub latest_location: Location,
    pub operation_count: u32,
    pub keyed_operation_count: u32,
    pub includes_watermark: bool,
}

pub fn build_immutable_upload<H, K, V>(
    peaks: Vec<(Position, u32, H::Digest)>,
    prev_ops_size: Position,
    latest_location: Location,
    ops: &[ImmutableOperation<K, V>],
    watermark_at: Option<Location>,
) -> Result<BuiltImmutableUpload<H::Digest>, QmdbError>
where
    H: Hasher,
    K: Array + Codec + Clone + AsRef<[u8]>,
    V: Codec + Clone + Send + Sync,
    ImmutableOperation<K, V>: Encode,
{
    if ops.is_empty() {
        return Err(QmdbError::EmptyBatch);
    }
    let prepared = build_auth_immutable_upload_rows(latest_location, ops)?;
    let ext = extend_mmr_from_peaks::<H, _>(peaks, prev_ops_size, prepared.op_bytes())?;
    let keyed_operation_count = prepared.keyed_operation_count;
    let mut rows = prepared.into_all_rows();
    for (pos, digest) in &ext.new_nodes {
        rows.push((
            encode_auth_node_key(NAMESPACE, *pos),
            digest.as_ref().to_vec(),
        ));
    }
    if let Some(loc) = watermark_at {
        rows.push((encode_auth_watermark_key(NAMESPACE, loc), Vec::new()));
    }
    Ok(BuiltImmutableUpload {
        rows,
        new_peaks: ext.peaks,
        new_ops_size: ext.size,
        new_root: ext.root,
        latest_location,
        operation_count: ops.len() as u32,
        keyed_operation_count,
        includes_watermark: watermark_at.is_some(),
    })
}

/// Sole-writer immutable QMDB helper. Pipelining, flushing, failure, and
/// sole-writer contract are identical to
/// [`KeylessWriter`](crate::KeylessWriter) — see its docs for details.
pub struct ImmutableWriter<H: Hasher, K: Array + Codec, V: Codec + Clone + Send + Sync> {
    client: StoreClient,
    core: WriterCore<H::Digest>,
    _marker: PhantomData<(K, V)>,
}

impl<H, K, V> ImmutableWriter<H, K, V>
where
    H: Hasher,
    K: Array + Codec + Clone + AsRef<[u8]>,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    K::Cfg: Clone,
    ImmutableOperation<K, V>: Encode + Decode<Cfg = V::Cfg> + Clone,
{
    /// Construct a writer and bootstrap its in-memory state from the store
    /// in one step.
    pub async fn new(client: StoreClient) -> Result<Self, QmdbError> {
        let writer = Self {
            client,
            core: WriterCore::new(),
            _marker: PhantomData,
        };
        writer.bootstrap().await?;
        Ok(writer)
    }

    /// Re-read the store's latest watermark + peaks into local state.
    /// Call after a poisoned error to reset the writer before resuming.
    pub async fn bootstrap(&self) -> Result<(), QmdbError> {
        let session = self.client.create_session();
        let latest = read_latest_auth_watermark(&session, NAMESPACE).await?;
        let ops_size = match latest {
            Some(w) => mmr_size_for_watermark(w)?,
            None => Position::new(0),
        };
        let peaks = load_auth_peaks::<H>(&session, NAMESPACE, ops_size).await?;
        let next_location = latest.map_or(Location::new(0), |w| w + 1);
        self.core
            .install(Cache {
                peaks,
                ops_size,
                next_location,
                latest_published: latest,
                latest_dispatched: latest,
                pending: std::collections::VecDeque::new(),
                latest_contiguous_acked: latest,
            })
            .await;
        Ok(())
    }

    pub async fn latest_published_watermark(&self) -> Option<Location> {
        self.core.latest_published().await
    }

    pub async fn upload_and_publish(
        &self,
        ops: &[ImmutableOperation<K, V>],
    ) -> Result<UploadReceipt, QmdbError> {
        let begin = self.core.begin(ops.len() as u64).await?;
        let built = build_immutable_upload::<H, K, V>(
            begin.peaks,
            begin.ops_size,
            begin.latest_location,
            ops,
            begin.watermark_at,
        )?;
        self.core
            .advance(crate::writer::core::BatchAdvance {
                new_peaks: built.new_peaks,
                new_ops_size: built.new_ops_size,
                latest_location: built.latest_location,
                watermark_at: begin.watermark_at,
                dispatch_id: begin.dispatch_id,
            })
            .await;

        let refs: Vec<(&Key, &[u8])> = built.rows.iter().map(|(k, v)| (k, v.as_slice())).collect();
        match self.client.ingest().put(&refs).await {
            Ok(_) => {
                self.core.ack_success(begin.dispatch_id).await;
                Ok(UploadReceipt {
                    latest_location: built.latest_location,
                    writer_location_watermark: begin.watermark_at,
                })
            }
            Err(err) => {
                let msg = format!(
                    "immutable upload ending at {} failed: {err}",
                    built.latest_location
                );
                self.core.ack_failure(msg).await;
                Err(QmdbError::Client(err))
            }
        }
    }

    pub async fn flush(&self) -> Result<(), QmdbError> {
        self.core.await_drain().await;
        let Some(target) = self.core.pending_watermark().await? else {
            return Ok(());
        };
        let key = encode_auth_watermark_key(NAMESPACE, target);
        let empty: &[u8] = &[];
        self.client
            .ingest()
            .put(&[(&key, empty)])
            .await
            .map_err(QmdbError::Client)?;
        self.core.mark_watermark_published(target).await;
        Ok(())
    }
}

impl<H, K, V> std::fmt::Debug for ImmutableWriter<H, K, V>
where
    H: Hasher,
    K: Array + Codec,
    V: Codec + Clone + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImmutableWriter").finish_non_exhaustive()
    }
}
