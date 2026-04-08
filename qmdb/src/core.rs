use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::{atomic::AtomicU64, Arc};
use std::time::Duration;

use commonware_codec::{Codec, Encode, Read as CodecRead};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::mmr::{
    self, iterator::PeakIterator, Location, Position, StandardHasher,
};
use commonware_storage::qmdb::{
    any::ordered::variable::Operation as QmdbOperation,
    any::unordered::variable::Operation as UnorderedQmdbOperation,
    operation::Key as QmdbKey,
};
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::{ClientError, RangeMode, SerializableReadSession, StoreClient};

use crate::codec::{
    decode_digest, decode_operation_location_key, decode_update_location, decode_watermark_location,
    encode_chunk_key, encode_current_meta_key, encode_grafted_node_key, encode_node_key,
    encode_operation_key, encode_presence_key, encode_update_key, encode_watermark_key,
    ensure_encoded_value_size, mmr_size_for_watermark, UpdateRow, WATERMARK_CODEC,
};
use crate::error::QmdbError;
use crate::VersionedValue;

const POST_INGEST_QUERY_RETRY_MAX_ATTEMPTS: usize = 6;
const POST_INGEST_QUERY_RETRY_INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const POST_INGEST_QUERY_RETRY_MAX_BACKOFF: Duration = Duration::from_millis(1_000);

pub(crate) async fn wait_until_query_visible_sequence(
    visible_sequence: Option<&Arc<AtomicU64>>,
    token: u64,
) -> Result<(), QmdbError> {
    let Some(seq) = visible_sequence else {
        return Ok(());
    };
    if token == 0 {
        return Ok(());
    }
    use std::sync::atomic::Ordering;
    for _ in 0..10_000 {
        if seq.load(Ordering::Relaxed) >= token {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    Err(QmdbError::CorruptData(
        "timed out waiting for query worker visible_sequence to catch ingest consistency token"
            .to_string(),
    ))
}

pub(crate) fn is_transient_post_ingest_query_error(err: &QmdbError) -> bool {
    match err {
        QmdbError::Client(ClientError::Http(_)) => true,
        QmdbError::Client(err) => err.rpc_code().is_some_and(|code| {
            matches!(
                code,
                connectrpc::ErrorCode::Aborted
                    | connectrpc::ErrorCode::ResourceExhausted
                    | connectrpc::ErrorCode::Unavailable
            )
        }),
        _ => false,
    }
}

pub(crate) fn post_ingest_query_retry_backoff(attempt: usize) -> Duration {
    let exponent = (attempt.saturating_sub(1)).min(20) as u32;
    let factor = 1u128 << exponent;
    let base_ms = POST_INGEST_QUERY_RETRY_INITIAL_BACKOFF.as_millis();
    let capped_ms = base_ms
        .saturating_mul(factor)
        .min(POST_INGEST_QUERY_RETRY_MAX_BACKOFF.as_millis());
    Duration::from_millis(capped_ms.min(u64::MAX as u128) as u64)
}

pub(crate) async fn retry_transient_post_ingest_query<F, Fut, T>(mut op: F) -> Result<T, QmdbError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, QmdbError>>,
{
    let mut attempt = 1usize;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err)
                if attempt < POST_INGEST_QUERY_RETRY_MAX_ATTEMPTS
                    && is_transient_post_ingest_query_error(&err) =>
            {
                tokio::time::sleep(post_ingest_query_retry_backoff(attempt)).await;
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HistoricalOpsClientCore<'a, D: Digest, K: Codec, V: Codec> {
    pub(crate) client: &'a StoreClient,
    pub(crate) query_visible_sequence: Option<&'a Arc<AtomicU64>>,
    pub(crate) update_row_cfg: (K::Cfg, V::Cfg),
    pub(crate) _marker: PhantomData<(D, K, V)>,
}

impl<'a, D: Digest, K: Codec, V: Codec> HistoricalOpsClientCore<'a, D, K, V> {
    pub(crate) async fn sync_after_ingest(&self) -> Result<(), QmdbError> {
        let token = self.client.sequence_number();
        wait_until_query_visible_sequence(self.query_visible_sequence, token).await
    }

    pub(crate) async fn writer_location_watermark(&self) -> Result<Option<Location>, QmdbError> {
        retry_transient_post_ingest_query(|| {
            let session = self.client.create_session();
            async move { self.read_latest_watermark(&session).await }
        })
        .await
    }

    pub(crate) async fn read_latest_watermark(
        &self,
        session: &SerializableReadSession,
    ) -> Result<Option<Location>, QmdbError> {
        let (start, end) = WATERMARK_CODEC.prefix_bounds();
        let rows = session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        match rows.into_iter().next() {
            Some((key, _)) => Ok(Some(decode_watermark_location(&key)?)),
            None => Ok(None),
        }
    }

    pub(crate) async fn require_published_watermark(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
    ) -> Result<(), QmdbError> {
        let available = self
            .read_latest_watermark(session)
            .await?
            .unwrap_or(Location::new(0));
        let watermark_exists = session
            .get(&encode_watermark_key(watermark))
            .await?
            .is_some();
        if available < watermark
            || (!watermark_exists
                && available == Location::new(0)
                && watermark == Location::new(0))
        {
            return Err(QmdbError::WatermarkTooLow {
                requested: watermark,
                available,
            });
        }
        Ok(())
    }

    pub(crate) async fn require_batch_boundary(
        &self,
        session: &SerializableReadSession,
        location: Location,
    ) -> Result<(), QmdbError> {
        if session
            .get(&encode_presence_key(location))
            .await?
            .is_some()
        {
            Ok(())
        } else {
            Err(QmdbError::CurrentProofRequiresBatchBoundary { location })
        }
    }

    pub(crate) async fn load_latest_update_row(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        key: &[u8],
    ) -> Result<Option<(Key, Vec<u8>)>, QmdbError> {
        let start = encode_update_key(key, Location::new(0))?;
        let end = encode_update_key(key, watermark)?;
        let rows = session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        Ok(rows
            .into_iter()
            .next()
            .map(|(key, value)| (key, value.to_vec())))
    }

    pub(crate) async fn append_encoded_ops_nodes_incrementally<H: Hasher<Digest = D>>(
        &self,
        session: &SerializableReadSession,
        previous_ops_size: Position,
        encoded_operations: &[Vec<u8>],
        rows: &mut Vec<(Key, Vec<u8>)>,
    ) -> Result<(Position, BTreeMap<Position, D>, D), QmdbError> {
        let mut peaks = Vec::<(Position, u32, D)>::new();
        for (peak_pos, height) in PeakIterator::new(previous_ops_size) {
            let Some(bytes) = session.get(&encode_node_key(peak_pos)).await? else {
                return Err(QmdbError::CorruptData(format!(
                    "missing prior ops peak node at position {peak_pos}"
                )));
            };
            peaks.push((
                peak_pos,
                height,
                decode_digest(bytes.as_ref(), format!("prior ops peak node at {peak_pos}"))?,
            ));
        }

        let mut current_size = previous_ops_size;
        let mut overlay = BTreeMap::<Position, D>::new();
        let mut hasher = StandardHasher::<H>::new();
        for encoded in encoded_operations {
            ensure_encoded_value_size(encoded.len())?;
            let leaf_pos = current_size;
            let leaf_digest = mmr::hasher::Hasher::leaf_digest(&mut hasher, leaf_pos, encoded);
            overlay.insert(leaf_pos, leaf_digest);
            rows.push((encode_node_key(leaf_pos), leaf_digest.as_ref().to_vec()));
            current_size = Position::new(*current_size + 1);

            let mut carry_pos = leaf_pos;
            let mut carry_digest = leaf_digest;
            let mut carry_height = 0u32;
            while peaks
                .last()
                .is_some_and(|(_, height, _)| *height == carry_height)
            {
                let (_, _, left_digest) = peaks.pop().expect("peak exists");
                let parent_pos = current_size;
                let parent_digest = mmr::hasher::Hasher::node_digest(
                    &mut hasher,
                    parent_pos,
                    &left_digest,
                    &carry_digest,
                );
                overlay.insert(parent_pos, parent_digest);
                rows.push((encode_node_key(parent_pos), parent_digest.as_ref().to_vec()));
                current_size = Position::new(*current_size + 1);
                carry_pos = parent_pos;
                carry_digest = parent_digest;
                carry_height += 1;
            }
            peaks.push((carry_pos, carry_height, carry_digest));
        }

        let leaves = Location::try_from(current_size)
            .map_err(|e| QmdbError::CorruptData(format!("invalid incremental ops size: {e}")))?;
        let ops_root = mmr::hasher::Hasher::root(
            &mut hasher,
            leaves,
            peaks.iter().map(|(_, _, digest)| digest),
        );
        Ok((current_size, overlay, ops_root))
    }

    pub(crate) async fn compute_ops_root<H: Hasher<Digest = D>>(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
    ) -> Result<D, QmdbError> {
        let size = mmr_size_for_watermark(watermark)?;
        let leaves = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        let mut peaks = Vec::new();
        for (peak_pos, _) in PeakIterator::new(size) {
            let Some(bytes) = session.get(&encode_node_key(peak_pos)).await? else {
                return Err(QmdbError::CorruptData(format!(
                    "missing MMR peak node at position {peak_pos}"
                )));
            };
            peaks.push(decode_digest(
                bytes.as_ref(),
                format!("MMR peak node at position {peak_pos}"),
            )?);
        }
        let mut hasher = StandardHasher::<H>::new();
        Ok(mmr::hasher::Hasher::root(&mut hasher, leaves, peaks.iter()))
    }

    pub(crate) async fn load_operation_bytes_at(
        &self,
        session: &SerializableReadSession,
        location: Location,
    ) -> Result<Vec<u8>, QmdbError> {
        let Some(bytes) = session.get(&encode_operation_key(location)).await? else {
            return Err(QmdbError::CorruptData(format!(
                "missing operation row at location {location}"
            )));
        };
        Ok(bytes.to_vec())
    }

    pub(crate) async fn load_operation_bytes_range(
        &self,
        session: &SerializableReadSession,
        start_location: Location,
        end_location_exclusive: Location,
    ) -> Result<Vec<Vec<u8>>, QmdbError> {
        if start_location >= end_location_exclusive {
            return Ok(Vec::new());
        }
        let start = encode_operation_key(start_location);
        let end = encode_operation_key(end_location_exclusive - 1);
        let rows = session
            .range(
                &start,
                &end,
                (*end_location_exclusive - *start_location) as usize,
            )
            .await?;
        if rows.len() != (*end_location_exclusive - *start_location) as usize {
            return Err(QmdbError::CorruptData(format!(
                "expected {} operation rows in location range [{start_location}, {end_location_exclusive}), found {}",
                *end_location_exclusive - *start_location,
                rows.len()
            )));
        }
        let mut encoded = Vec::with_capacity(rows.len());
        for (offset, (key, value)) in rows.into_iter().enumerate() {
            let expected_location = start_location + offset as u64;
            let location = decode_operation_location_key(&key)?;
            if location != expected_location {
                return Err(QmdbError::CorruptData(format!(
                    "operation row order mismatch: expected {expected_location}, got {location}"
                )));
            }
            encoded.push(value.to_vec());
        }
        Ok(encoded)
    }

    pub(crate) async fn query_many_at<Q: AsRef<[u8]>>(
        &self,
        keys: &[Q],
        max_location: Location,
    ) -> Result<Vec<Option<VersionedValue<K, V>>>, QmdbError> {
        let session = self.client.create_session();
        self.require_published_watermark(&session, max_location)
            .await?;

        let futs = keys.iter().map(|key| {
            let key_bytes = key.as_ref();
            async {
                let Some((row_key, row_value)) = self
                    .load_latest_update_row(&session, max_location, key_bytes)
                    .await?
                else {
                    return Ok(None);
                };
                let location = decode_update_location(&row_key)?;
                let decoded = <UpdateRow<K, V> as CodecRead>::read_cfg(
                    &mut row_value.as_ref(),
                    &self.update_row_cfg,
                )
                .map_err(|e| QmdbError::CorruptData(format!("update row decode: {e}")))?;
                Ok(Some(VersionedValue {
                    key: decoded.key,
                    location,
                    value: decoded.value,
                }))
            }
        });
        futures::future::join_all(futs)
            .await
            .into_iter()
            .collect()
    }

    pub(crate) async fn publish_writer_location_watermark_with_encoded_ops<
        H: Hasher<Digest = D>,
    >(
        &self,
        session: &SerializableReadSession,
        latest_watermark: Option<Location>,
        location: Location,
        encoded_delta_ops: &[Vec<u8>],
        kind: &str,
    ) -> Result<Location, QmdbError> {
        let previous_ops_size = match latest_watermark {
            Some(previous) => mmr_size_for_watermark(previous)?,
            None => Position::new(0),
        };
        let mut rows = Vec::<(Key, Vec<u8>)>::new();
        self.append_encoded_ops_nodes_incrementally::<H>(
            session,
            previous_ops_size,
            encoded_delta_ops,
            &mut rows,
        )
        .await?;
        rows.push((encode_watermark_key(location), Vec::new()));
        let refs = rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;
        let visible = self.writer_location_watermark().await?;
        if visible < Some(location) {
            return Err(QmdbError::CorruptData(format!(
                "{kind} watermark publish did not become query-visible: requested={location}, visible={visible:?}"
            )));
        }
        Ok(location)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedUpload {
    pub(crate) operation_count: u32,
    pub(crate) keyed_operation_count: u32,
    pub(crate) rows: Vec<(Key, Vec<u8>)>,
}

impl PreparedUpload {
    pub(crate) fn build<K: QmdbKey + Codec, V: Codec + Clone + Send + Sync>(
        latest_location: Location,
        operations: &[QmdbOperation<K, V>],
    ) -> Result<Self, QmdbError>
    where
        QmdbOperation<K, V>: Encode,
    {
        use commonware_storage::qmdb::any::ordered::Update as QmdbUpdate;
        Self::build_from_ops(latest_location, operations, |op| match op {
            QmdbOperation::Update(QmdbUpdate {
                key,
                value,
                next_key: _,
            }) => Some((key, Some(value))),
            QmdbOperation::Delete(key) => Some((key, None)),
            QmdbOperation::CommitFloor(_, _) => None,
        })
    }

    pub(crate) fn build_unordered<K: QmdbKey + Codec, V: Codec + Clone + Send + Sync>(
        latest_location: Location,
        operations: &[UnorderedQmdbOperation<K, V>],
    ) -> Result<Self, QmdbError>
    where
        UnorderedQmdbOperation<K, V>: Encode,
    {
        use commonware_storage::qmdb::any::unordered::Update as UnorderedUpdate;
        Self::build_from_ops(latest_location, operations, |op| match op {
            UnorderedQmdbOperation::Update(UnorderedUpdate(key, value)) => {
                Some((key, Some(value)))
            }
            UnorderedQmdbOperation::Delete(key) => Some((key, None)),
            UnorderedQmdbOperation::CommitFloor(_, _) => None,
        })
    }

    fn build_from_ops<Op: Encode, K: AsRef<[u8]> + Encode + Clone, V: Encode + Clone>(
        latest_location: Location,
        operations: &[Op],
        extract_keyed: impl Fn(&Op) -> Option<(&K, Option<&V>)>,
    ) -> Result<Self, QmdbError> {
        let mut rows = Vec::<(Key, Vec<u8>)>::with_capacity(operations.len() * 2 + 1);
        let mut keyed_operation_count = 0u32;
        let count_u64 = operations.len() as u64;
        let Some(start_location) = latest_location
            .checked_add(1)
            .and_then(|n| n.checked_sub(count_u64))
        else {
            return Err(QmdbError::InvalidLocationRange {
                start_location: Location::new(0),
                latest_location,
                count: operations.len(),
            });
        };

        for (index, op) in operations.iter().enumerate() {
            let location = start_location + index as u64;
            let encoded = op.encode().to_vec();
            ensure_encoded_value_size(encoded.len())?;
            rows.push((encode_operation_key(location), encoded));

            if let Some((key, value)) = extract_keyed(op) {
                keyed_operation_count += 1;
                let update_row = UpdateRow {
                    key: key.clone(),
                    value: value.cloned(),
                };
                rows.push((
                    encode_update_key(key.as_ref(), location)?,
                    update_row.encode().to_vec(),
                ));
            }
        }

        let operation_count = u32::try_from(operations.len()).map_err(|_| {
            QmdbError::CorruptData("operation count does not fit in u32".to_string())
        })?;
        rows.push((encode_presence_key(latest_location), Vec::new()));

        Ok(Self {
            operation_count,
            keyed_operation_count,
            rows,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedCurrentBoundaryUpload {
    pub(crate) rows: Vec<(Key, Vec<u8>)>,
}

impl PreparedCurrentBoundaryUpload {
    pub(crate) fn build<D: Digest, const N: usize>(
        latest_location: Location,
        current_boundary: &crate::CurrentBoundaryState<D, N>,
    ) -> Result<Self, QmdbError> {
        let mut rows = Vec::with_capacity(
            1 + current_boundary.chunks.len() + current_boundary.grafted_nodes.len(),
        );
        rows.push((
            encode_current_meta_key(latest_location),
            current_boundary.root.as_ref().to_vec(),
        ));
        for &(chunk_index, chunk) in &current_boundary.chunks {
            rows.push((
                encode_chunk_key(chunk_index, latest_location),
                chunk.to_vec(),
            ));
        }
        for &(grafted_position, digest) in &current_boundary.grafted_nodes {
            rows.push((
                encode_grafted_node_key(grafted_position, latest_location),
                digest.as_ref().to_vec(),
            ));
        }
        Ok(Self { rows })
    }
}
