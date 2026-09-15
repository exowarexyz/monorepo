use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use commonware_codec::DecodeExt;
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::merkle::{hasher::Hasher as _, Family, Graftable, Location, Position};
use commonware_storage::qmdb::current::proof::OpsRootWitness;
use exoware_sdk::{keys::Key, SerializableReadSession};

use crate::auth::load_auth_operation_bytes_range;
use crate::codec::{
    decode_digest, encode_node_key, encode_operation_key, encode_ops_root_witness_key,
    merkle_size_for_watermark, op_count_for_watermark,
};
use crate::prefetch::{range_positions, PrefetchedMerkleStorage};
use crate::proof::{build_operation_range_checkpoint, OperationRangeCheckpoint};
use crate::read_cache::{ReadCache, RootContext};
use crate::QmdbError;

pub(crate) struct RangeRead<'a, F: Graftable, D: Digest> {
    cache: &'a Arc<ReadCache<F, D>>,
    storage: PrefetchedMerkleStorage<'a, F, D>,
    watermark: Location<F>,
    start: Location<F>,
    end: Location<F>,
    rows: HashMap<Key, Bytes>,
    operations: Result<Vec<Vec<u8>>, QmdbError>,
    witness: Result<Option<OpsRootWitness<F, D>>, QmdbError>,
    context: RootContext<D>,
}

impl<'a, F: Graftable, D: Digest> RangeRead<'a, F, D> {
    pub(crate) async fn load<H, Fut>(
        session: &'a SerializableReadSession,
        cache: &'a Arc<ReadCache<F, D>>,
        watermark: Location<F>,
        start: Location<F>,
        end: Location<F>,
        with_witness: bool,
        resolve_inactive_peaks: impl FnOnce(Bytes) -> Fut,
    ) -> Result<Self, QmdbError>
    where
        H: Hasher<Digest = D>,
        Fut: Future<Output = Result<usize, QmdbError>>,
    {
        let size = merkle_size_for_watermark(watermark)?;
        let positions = range_positions(watermark, start, end)?;
        let context = cache.cached_context(watermark);
        let witness = with_witness.then(|| cache.witness(watermark)).flatten();
        let mut keys = BTreeSet::new();
        if context.is_none() {
            keys.insert(encode_operation_key(watermark));
        }
        if *end - *start == 1 {
            keys.insert(encode_operation_key(start));
        }
        if with_witness && witness.is_none() {
            keys.insert(encode_ops_root_witness_key(watermark));
        }

        let metadata = async {
            let (rows, nodes) = fetch_rows(session, cache, &positions, keys).await?;

            // Fetch each request's rows before coalescing metadata work so a cold watermark
            // does not add another network phase for followers.
            let (context, context_guard) = match context {
                Some(context) => (Some(context), None),
                None => cache.context(watermark).await,
            };
            let context = match context {
                Some(context) => context,
                None => {
                    let operation =
                        rows.get(&encode_operation_key(watermark)).ok_or_else(|| {
                            QmdbError::CorruptData(format!(
                                "missing operation row at location {watermark}"
                            ))
                        })?;
                    let inactive_peaks = resolve_inactive_peaks(operation.clone()).await?;
                    RootContext {
                        root: Self::root::<H>(&nodes, watermark, inactive_peaks)?,
                        inactive_peaks,
                    }
                }
            };
            let witness = witness
                .or_else(|| rows.get(&encode_ops_root_witness_key(watermark)).cloned())
                .map(|bytes| {
                    let witness =
                        OpsRootWitness::<F, D>::decode(bytes.as_ref()).map_err(|error| {
                            QmdbError::CorruptData(format!(
                                "current ops-root witness at {watermark} decode error: {error}"
                            ))
                        })?;
                    cache.put_witness(watermark, bytes);
                    Ok(witness)
                })
                .transpose();

            // Published metadata is immutable. Share it without waiting for this request's
            // operation scan or proof, which each caller still verifies independently.
            cache.put_context(watermark, context);
            drop(context_guard);
            Ok::<_, QmdbError>((rows, nodes, context, witness))
        };

        // Both reads inherit the publication check's observed floor. Interpret range errors
        // after inactivity metadata and root peaks, regardless of completion order.
        let ((rows, nodes, context, witness), operations) = futures::try_join!(metadata, async {
            let operations = if *end - *start > 1 {
                load_auth_operation_bytes_range(session, start, end).await
            } else {
                Ok(Vec::new())
            };
            Ok::<_, QmdbError>(operations)
        })?;
        Ok(Self {
            cache,
            storage: PrefetchedMerkleStorage::new(session, size, nodes),
            watermark,
            start,
            end,
            rows,
            operations,
            witness,
            context,
        })
    }

    fn operation_at(&self, location: Location<F>) -> Result<&[u8], QmdbError> {
        self.rows
            .get(&encode_operation_key(location))
            .map(Bytes::as_ref)
            .ok_or_else(|| {
                QmdbError::CorruptData(format!("missing operation row at location {location}"))
            })
    }

    fn root<H: Hasher<Digest = D>>(
        nodes: &BTreeMap<Position<F>, Option<Bytes>>,
        watermark: Location<F>,
        inactive_peaks: usize,
    ) -> Result<D, QmdbError> {
        let size = merkle_size_for_watermark(watermark)?;
        let mut peaks = Vec::new();
        for (position, _) in F::peaks(size) {
            let bytes = nodes
                .get(&position)
                .and_then(Option::as_ref)
                .ok_or_else(|| {
                    QmdbError::CorruptData(format!(
                        "missing Merkle peak node at position {position}"
                    ))
                })?;
            peaks.push(decode_digest::<D>(
                bytes,
                format_args!("Merkle peak node at position {position}"),
            )?);
        }
        commonware_storage::qmdb::hasher::<H>()
            .root(
                op_count_for_watermark(watermark)?,
                inactive_peaks,
                peaks.iter(),
            )
            .map_err(|error| QmdbError::CommonwareMerkle(error.to_string()))
    }

    pub(crate) async fn checkpoint<H: Hasher<Digest = D>>(
        self,
    ) -> Result<OperationRangeCheckpoint<D, F>, QmdbError> {
        let operations = if *self.end - *self.start == 1 {
            vec![self.operation_at(self.start)?.to_vec()]
        } else {
            self.operations?
        };
        let result = build_operation_range_checkpoint::<F, H, _>(
            &self.storage,
            self.watermark,
            self.start,
            self.end,
            self.context.root,
            self.context.inactive_peaks,
            operations,
        )
        .await;
        let mut checkpoint = result.map_err(|error| {
            self.storage
                .take_error()
                .map(QmdbError::Client)
                .unwrap_or(error)
        })?;
        checkpoint.ops_root_witness = self.witness?;
        self.cache.put_nodes(self.storage.node_rows());
        Ok(checkpoint)
    }
}

async fn fetch_rows<F: Family, D: Digest>(
    session: &SerializableReadSession,
    cache: &Arc<ReadCache<F, D>>,
    positions: &[Position<F>],
    mut keys: BTreeSet<Key>,
) -> Result<(HashMap<Key, Bytes>, BTreeMap<Position<F>, Option<Bytes>>), QmdbError> {
    let mut nodes = BTreeMap::new();
    let mut rows = HashMap::new();
    let mut remaining = positions.to_vec();
    loop {
        let reservation = cache.reserve(&remaining);
        nodes.extend(
            reservation
                .hits
                .iter()
                .map(|(&position, bytes)| (position, Some(bytes.clone()))),
        );
        for &position in &reservation.owned {
            keys.insert(encode_node_key(position));
        }
        let keys = std::mem::take(&mut keys).into_iter().collect::<Vec<_>>();
        if !keys.is_empty() {
            let refs = keys.iter().collect::<Vec<_>>();
            rows.extend(
                session
                    .get_many(&refs, u32::try_from(keys.len()).unwrap_or(u32::MAX))
                    .await?
                    .collect()
                    .await?,
            );
        }
        let mut positive = Vec::new();
        for &position in &reservation.owned {
            let bytes = rows.get(&encode_node_key(position)).cloned();
            if let Some(bytes) = &bytes {
                positive.push((position, bytes.clone()));
            }
            nodes.insert(position, bytes);
        }
        let pending = reservation.complete(positive);
        nodes.extend(
            pending
                .wait()
                .await
                .into_iter()
                .map(|(position, bytes)| (position, Some(bytes))),
        );
        remaining.retain(|position| !nodes.contains_key(position));
        if remaining.is_empty() {
            return Ok((rows, nodes));
        }
    }
}
