//! Ordered QMDB E2E: run a local Commonware ordered DB, upload its
//! operations + current boundary state to a live store stack, then
//! verify roots and proofs match.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use commonware_codec::Encode;
use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::journal::contiguous::fixed::Config as FixedJournalConfig;
use commonware_storage::merkle::{mmb, mmr, Family, Graftable, Location, Proof};
use commonware_storage::qmdb::any::ordered::fixed::Operation as FixedQmdbOperation;
use commonware_storage::qmdb::any::ordered::variable::Operation as QmdbOperation;
use commonware_storage::qmdb::any::value::FixedEncoding;
use commonware_storage::qmdb::current::ordered::fixed::Db as LocalFixedQmdbDb;
use commonware_storage::qmdb::current::ordered::variable::Db as LocalQmdbDb;
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::MAX_OPERATION_SIZE;
use exoware_qmdb::{recover_boundary_state, CurrentBoundaryState, OrderedClient, OrderedWriter};
use exoware_sdk::{PrefixedStoreClient, StoreClient};

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchOperation<F> = QmdbOperation<F, Vec<u8>, Vec<u8>>;
type FixedBatchOperation<F> = FixedQmdbOperation<F, Digest, Digest>;
type TestOrderedClient<F> = OrderedClient<F, Sha256, Vec<u8>, Vec<u8>, N>;
type TestOrderedWriter<F> = OrderedWriter<F, Sha256, Vec<u8>, Vec<u8>, N>;
type FixedTestOrderedClient<F> = OrderedClient<F, Sha256, Digest, Digest, N, FixedEncoding<Digest>>;
type FixedTestOrderedWriter<F> = OrderedWriter<F, Sha256, Digest, Digest, N, FixedEncoding<Digest>>;
type LocalDb<F> = LocalQmdbDb<
    F,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    N,
    commonware_parallel::Sequential,
>;

type FixedLocalDb<F> = LocalFixedQmdbDb<
    F,
    cw_tokio::Context,
    Digest,
    Digest,
    Sha256,
    TwoCap,
    N,
    commonware_parallel::Sequential,
>;

async fn boundary_from_local_db<F>(
    db: &LocalDb<F>,
    previous_operations: Option<&[BatchOperation<F>]>,
    operations: &[BatchOperation<F>],
) -> CurrentBoundaryState<Digest, N, F>
where
    F: Graftable,
    BatchOperation<F>: commonware_codec::Codec,
{
    let ops_root_hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let ops_root_witness = db
        .ops_root_witness(&ops_root_hasher)
        .await
        .expect("ops root witness");
    recover_boundary_state::<F, Sha256, _, N, _, _>(
        previous_operations,
        operations,
        db.root(),
        0,
        ops_root_witness,
        |location| async move {
            let hasher = commonware_storage::qmdb::hasher::<Sha256>();
            let (proof, mut proof_ops, mut chunks) = db
                .range_proof(&hasher, location, NZU64!(1))
                .await
                .map_err(|error| {
                    exoware_qmdb::QmdbError::CorruptData(format!(
                        "local current range proof at {location}: {error}"
                    ))
                })?;
            proof_ops.pop().ok_or_else(|| {
                exoware_qmdb::QmdbError::CorruptData(format!(
                    "local current range proof at {location} returned no operations"
                ))
            })?;
            let chunk = chunks.pop().ok_or_else(|| {
                exoware_qmdb::QmdbError::CorruptData(format!(
                    "local current range proof at {location} returned no chunks"
                ))
            })?;
            Ok((proof, chunk))
        },
    )
    .await
    .expect("recover_boundary_state")
}

async fn mirror_local<F>(client: &StoreClient, local: &LocalReference<F>)
where
    F: Graftable,
    BatchOperation<F>:
        commonware_codec::Codec + commonware_codec::Encode + commonware_codec::Decode,
{
    let writer: TestOrderedWriter<F> =
        TestOrderedWriter::fresh(PrefixedStoreClient::empty(client.clone()));
    common::commit_ordered_upload(client, &writer, &local.operations, &local.current_boundary)
        .await
        .expect("commit upload");
}

async fn boundary_from_fixed_local_db<F>(
    db: &FixedLocalDb<F>,
    previous_operations: Option<&[FixedBatchOperation<F>]>,
    operations: &[FixedBatchOperation<F>],
) -> CurrentBoundaryState<Digest, N, F>
where
    F: Graftable,
    FixedBatchOperation<F>: commonware_codec::CodecFixed<Cfg = ()> + Send + Sync,
{
    let ops_root_hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let ops_root_witness = db
        .ops_root_witness(&ops_root_hasher)
        .await
        .expect("fixed ops root witness");
    recover_boundary_state::<F, Sha256, _, N, _, _>(
        previous_operations,
        operations,
        db.root(),
        0,
        ops_root_witness,
        |location| async move {
            let hasher = commonware_storage::qmdb::hasher::<Sha256>();
            let (proof, mut proof_ops, mut chunks) = db
                .range_proof(&hasher, location, NZU64!(1))
                .await
                .map_err(|error| {
                    exoware_qmdb::QmdbError::CorruptData(format!(
                        "local fixed current range proof at {location}: {error}"
                    ))
                })?;
            proof_ops.pop().ok_or_else(|| {
                exoware_qmdb::QmdbError::CorruptData(format!(
                    "local fixed current range proof at {location} returned no operations"
                ))
            })?;
            let chunk = chunks.pop().ok_or_else(|| {
                exoware_qmdb::QmdbError::CorruptData(format!(
                    "local fixed current range proof at {location} returned no chunks"
                ))
            })?;
            Ok((proof, chunk))
        },
    )
    .await
    .expect("recover fixed boundary state")
}

fn op_cfg<F: Family>() -> <BatchOperation<F> as commonware_codec::Read>::Cfg {
    (
        ((0..=MAX_OPERATION_SIZE).into(), ()),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    )
}

fn update_row_cfg() -> (
    <Vec<u8> as commonware_codec::Read>::Cfg,
    <Vec<u8> as commonware_codec::Read>::Cfg,
) {
    (
        ((0..=MAX_OPERATION_SIZE).into(), ()),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    )
}

fn fixed_update_row_cfg() -> (
    <Digest as commonware_codec::Read>::Cfg,
    <Digest as commonware_codec::Read>::Cfg,
) {
    ((), ())
}

struct LocalReference<F: Graftable> {
    latest_location: Location<F>,
    operations: Vec<BatchOperation<F>>,
    current_boundary: CurrentBoundaryState<Digest, N, F>,
    values: std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

struct ChunkSizedLocalReference<F: Graftable, const M: usize> {
    latest_location: Location<F>,
    operations: Vec<BatchOperation<F>>,
    current_boundary: CurrentBoundaryState<Digest, M, F>,
}

struct FixedLocalReference<F: Graftable> {
    latest_location: Location<F>,
    operations: Vec<FixedBatchOperation<F>>,
    current_boundary: CurrentBoundaryState<Digest, N, F>,
    values: std::collections::BTreeMap<Vec<u8>, Option<Digest>>,
}

async fn build_local_db<F>() -> LocalReference<F>
where
    F: Graftable,
    BatchOperation<F>: commonware_codec::Codec + Clone,
{
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg =
                common::ordered_variable_config("ordered", page_cache, op_cfg::<F>(), NZU64!(8));
            let mut db: LocalDb<F> = LocalDb::init(context.child("qmdb"), cfg)
                .await
                .expect("init");

            let finalized = {
                let batch = db
                    .new_batch()
                    .write(b"alpha".to_vec(), Some(b"one".to_vec()))
                    .write(b"beta".to_vec(), Some(b"two".to_vec()));
                batch
                    .merkleize(&db, None::<Vec<u8>>)
                    .await
                    .expect("merkleize")
            };
            db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (Proof<F, Digest>, Vec<BatchOperation<F>>) = db
                .ops_historical_proof(latest + 1, Location::<F>::new(0), n)
                .await
                .expect("proof");

            let boundary = boundary_from_local_db(&db, None, &ops).await;

            let mut values = std::collections::BTreeMap::new();
            values.insert(
                b"alpha".to_vec(),
                db.get(&b"alpha".to_vec()).await.expect("get"),
            );
            values.insert(
                b"beta".to_vec(),
                db.get(&b"beta".to_vec()).await.expect("get"),
            );

            db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            LocalReference {
                latest_location: latest,
                operations: ops,
                current_boundary: boundary,
                values,
            }
        })
    })
    .await
    .expect("join")
}

async fn boundary_from_local_db_with_chunk_size<F, const M: usize>(
    db: &LocalQmdbDb<
        F,
        cw_tokio::Context,
        Vec<u8>,
        Vec<u8>,
        Sha256,
        TwoCap,
        M,
        commonware_parallel::Sequential,
    >,
    previous_operations: Option<&[BatchOperation<F>]>,
    operations: &[BatchOperation<F>],
) -> CurrentBoundaryState<Digest, M, F>
where
    F: Graftable,
    BatchOperation<F>: commonware_codec::Codec,
{
    let ops_root_hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let ops_root_witness = db
        .ops_root_witness(&ops_root_hasher)
        .await
        .expect("ops root witness");
    recover_boundary_state::<F, Sha256, _, M, _, _>(
        previous_operations,
        operations,
        db.root(),
        0,
        ops_root_witness,
        |location| async move {
            let hasher = commonware_storage::qmdb::hasher::<Sha256>();
            let (proof, mut proof_ops, mut chunks) = db
                .range_proof(&hasher, location, NZU64!(1))
                .await
                .map_err(|error| {
                    exoware_qmdb::QmdbError::CorruptData(format!(
                        "local current range proof at {location}: {error}"
                    ))
                })?;
            proof_ops.pop().ok_or_else(|| {
                exoware_qmdb::QmdbError::CorruptData(format!(
                    "local current range proof at {location} returned no operations"
                ))
            })?;
            let chunk = chunks.pop().ok_or_else(|| {
                exoware_qmdb::QmdbError::CorruptData(format!(
                    "local current range proof at {location} returned no chunks"
                ))
            })?;
            Ok((proof, chunk))
        },
    )
    .await
    .expect("recover boundary state")
}

async fn build_local_db_with_write_count<F, const M: usize>(
    prefix: &'static str,
    write_count: usize,
) -> ChunkSizedLocalReference<F, M>
where
    F: Graftable,
    BatchOperation<F>: commonware_codec::Codec + Clone,
{
    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = common::ordered_variable_config(prefix, page_cache, op_cfg::<F>(), NZU64!(8));
            let mut db: LocalQmdbDb<
                F,
                cw_tokio::Context,
                Vec<u8>,
                Vec<u8>,
                Sha256,
                TwoCap,
                M,
                commonware_parallel::Sequential,
            > = LocalQmdbDb::init(context.child(prefix), cfg)
                .await
                .expect("init");

            let finalized = {
                let mut batch = db.new_batch();
                for index in 0..write_count {
                    batch = batch.write(
                        format!("k-{index:08}").into_bytes(),
                        Some(format!("v-{index:08}").into_bytes()),
                    );
                }
                batch
                    .merkleize(&db, None::<Vec<u8>>)
                    .await
                    .expect("merkleize")
            };
            db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (Proof<F, Digest>, Vec<BatchOperation<F>>) = db
                .ops_historical_proof(latest + 1, Location::<F>::new(0), n)
                .await
                .expect("proof");

            let boundary = boundary_from_local_db_with_chunk_size::<F, M>(&db, None, &ops).await;

            db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            ChunkSizedLocalReference {
                latest_location: latest,
                operations: ops,
                current_boundary: boundary,
            }
        })
    })
    .await
    .expect("join")
}

async fn build_fixed_local_db<F>() -> FixedLocalReference<F>
where
    F: Graftable,
    FixedBatchOperation<F>: commonware_codec::CodecFixed<Cfg = ()> + Clone + Send + Sync,
{
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = commonware_storage::qmdb::current::Config {
                merkle_config: common::merkle_config("ordered_fixed", page_cache.clone()),
                journal_config: FixedJournalConfig {
                    partition: "ordered_fixed_log".to_string(),
                    items_per_blob: NZU64!(8),
                    page_cache,
                    write_buffer: NZUsize!(1024),
                },
                grafted_metadata_partition: "ordered_fixed_grafted_metadata".to_string(),
                translator: TwoCap,
            };
            let mut db: FixedLocalDb<F> = FixedLocalDb::init(context.child("ordered_fixed"), cfg)
                .await
                .expect("init fixed");

            let alpha = Sha256::fill(0xA1);
            let beta = Sha256::fill(0xB2);
            let one = Sha256::fill(0x01);
            let two = Sha256::fill(0x02);
            let finalized = {
                let batch = db
                    .new_batch()
                    .write(alpha, Some(one))
                    .write(beta, Some(two));
                batch
                    .merkleize(&db, None::<Digest>)
                    .await
                    .expect("fixed merkleize")
            };
            db.apply_batch(finalized).await.expect("apply fixed");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (Proof<F, Digest>, Vec<FixedBatchOperation<F>>) = db
                .ops_historical_proof(latest + 1, Location::<F>::new(0), n)
                .await
                .expect("fixed proof");

            let boundary = boundary_from_fixed_local_db(&db, None, &ops).await;

            let mut values = std::collections::BTreeMap::new();
            values.insert(
                alpha.as_ref().to_vec(),
                db.get(&alpha).await.expect("get alpha"),
            );
            values.insert(
                beta.as_ref().to_vec(),
                db.get(&beta).await.expect("get beta"),
            );

            db.sync().await.expect("sync fixed");
            db.destroy().await.expect("destroy fixed");

            FixedLocalReference {
                latest_location: latest,
                operations: ops,
                current_boundary: boundary,
                values,
            }
        })
    })
    .await
    .expect("join")
}

#[tokio::test]
async fn ordered_round_trip() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db::<mmr::Family>().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::<mmr::Family>::new(
        PrefixedStoreClient::empty(client.clone()),
        op_cfg::<mmr::Family>(),
        update_row_cfg(),
    );
    let watermark = c.writer_location_watermark().await.expect("watermark");
    assert_eq!(watermark, Some(local.latest_location));

    let queried = c
        .query_many_at(
            &[b"alpha".as_slice(), b"beta".as_slice()],
            local.latest_location,
        )
        .await
        .expect("query_many_at");
    assert_eq!(
        queried[0].as_ref().and_then(|v| v.value.clone()),
        local.values[b"alpha".as_slice()]
    );
    assert_eq!(
        queried[1].as_ref().and_then(|v| v.value.clone()),
        local.values[b"beta".as_slice()]
    );

    let proof = c
        .operation_range_proof(
            local.latest_location,
            Location::<mmr::Family>::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("proof");
    assert_eq!(proof.operations, local.operations);
}

#[tokio::test]
async fn ordered_mmb_round_trip() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db::<mmb::Family>().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::<mmb::Family>::new(
        PrefixedStoreClient::empty(client.clone()),
        op_cfg::<mmb::Family>(),
        update_row_cfg(),
    );
    let watermark = c.writer_location_watermark().await.expect("watermark");
    assert_eq!(watermark, Some(local.latest_location));

    let range = c
        .operation_range_proof(
            local.latest_location,
            Location::<mmb::Family>::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("operation range proof");
    assert_eq!(range.operations, local.operations);

    let current = c
        .current_operation_range_proof(
            local.latest_location,
            Location::<mmb::Family>::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("current operation range proof");
    assert_eq!(current.operations, local.operations);

    let key_proof = c
        .key_value_proof_at(local.latest_location, b"alpha".as_slice())
        .await
        .expect("key_value_proof_at");
    match &key_proof.operation {
        QmdbOperation::Update(update) => {
            assert_eq!(update.key, b"alpha".to_vec());
            assert_eq!(update.value, b"one".to_vec());
        }
        _ => panic!("expected Update operation"),
    }
}

#[tokio::test]
async fn ordered_mmb_multi_peak_grafted_chunk_round_trip() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db_with_write_count::<mmb::Family, N>("ordered_mmb_grafted", 767).await;
    assert!(
        local.current_boundary.grafted_nodes.len() >= 2,
        "test must cross a grafted chunk boundary"
    );

    let writer: OrderedWriter<mmb::Family, Sha256, Vec<u8>, Vec<u8>, N> =
        OrderedWriter::fresh(PrefixedStoreClient::empty(client.clone()));
    common::commit_ordered_upload(&client, &writer, &local.operations, &local.current_boundary)
        .await
        .expect("commit upload");

    let c: OrderedClient<mmb::Family, Sha256, Vec<u8>, Vec<u8>, N> = OrderedClient::new(
        PrefixedStoreClient::empty(client.clone()),
        op_cfg::<mmb::Family>(),
        update_row_cfg(),
    );
    let current = c
        .current_operation_range_proof(
            local.latest_location,
            Location::<mmb::Family>::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("current operation range proof");
    assert_eq!(current.operations, local.operations);

    let key = b"k-00000007".to_vec();
    let key_proof = c
        .key_value_proof_at(local.latest_location, key.as_slice())
        .await
        .expect("key_value_proof_at");
    assert_eq!(key_proof.root, local.current_boundary.root);
    match &key_proof.operation {
        QmdbOperation::Update(update) => {
            assert_eq!(update.key, key);
            assert_eq!(update.value, b"v-00000007".to_vec());
        }
        _ => panic!("expected Update operation"),
    }
}

async fn assert_incremental_seed_batches_keep_current_proofs_verifiable<F>(
    partition_prefix: &'static str,
) where
    F: Graftable + Send + Sync + 'static,
    BatchOperation<F>:
        commonware_codec::Codec + commonware_codec::Encode + commonware_codec::Decode + Clone,
{
    let (_dir, _server, client) = common::local_store_client().await;
    let (uploads, latest_location, latest_key, expected_root, expected_active) =
        tokio::task::spawn_blocking(move || {
            cw_tokio::Runner::default().start(|context| async move {
                use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
                let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
                let cfg = common::ordered_variable_config(
                    partition_prefix,
                    page_cache,
                    op_cfg::<F>(),
                    NZU64!(8),
                );
                let mut db: LocalDb<F> = LocalQmdbDb::init(context.child(partition_prefix), cfg)
                    .await
                    .expect("init");

                let mut previous_ops = Vec::<BatchOperation<F>>::new();
                let mut uploads =
                    Vec::<(Vec<BatchOperation<F>>, CurrentBoundaryState<Digest, N, F>)>::new();
                let mut expected_active = BTreeMap::<Vec<u8>, Vec<u8>>::new();
                let mut counter = 0u64;

                for _ in 0..80 {
                    let finalized = {
                        let mut batch = db.new_batch();
                        for offset in 0..3u64 {
                            let key = format!("k-{:08x}", counter + offset).into_bytes();
                            let value = format!("v-{:08x}", counter + offset).into_bytes();
                            expected_active.insert(key.clone(), value.clone());
                            batch = batch.write(key, Some(value));
                        }
                        if counter >= 3 {
                            let rewrite_key = format!("k-{:08x}", counter - 3).into_bytes();
                            let rewrite_value = format!("v-{:08x}-r", counter).into_bytes();
                            expected_active.insert(rewrite_key.clone(), rewrite_value.clone());
                            batch = batch.write(rewrite_key, Some(rewrite_value));
                        }
                        if counter >= 6 && counter.is_multiple_of(12) {
                            let delete_key = format!("k-{:08x}", counter - 6).into_bytes();
                            expected_active.remove(&delete_key);
                            batch = batch.write(delete_key, None);
                        }
                        counter += 3;
                        batch
                            .merkleize(&db, None::<Vec<u8>>)
                            .await
                            .expect("merkleize")
                    };
                    db.apply_batch(finalized).await.expect("apply");

                    let latest = db.bounds().await.end - 1;
                    let count = NonZeroU64::new(*latest + 1).expect("non-zero op count");
                    let (_proof, cumulative_ops) = db
                        .ops_historical_proof(latest + 1, Location::<F>::new(0), count)
                        .await
                        .expect("historical proof");
                    let previous_slice = if previous_ops.is_empty() {
                        None
                    } else {
                        Some(previous_ops.as_slice())
                    };
                    let boundary =
                        boundary_from_local_db(&db, previous_slice, &cumulative_ops).await;
                    let delta = cumulative_ops[previous_ops.len()..].to_vec();
                    uploads.push((delta, boundary));
                    previous_ops = cumulative_ops;
                }

                let latest_location = db.bounds().await.end - 1;
                let latest_key = format!("k-{:08x}", counter - 3).into_bytes();
                let expected_root = db.root();
                db.destroy().await.expect("destroy");
                (
                    uploads,
                    latest_location,
                    latest_key,
                    expected_root,
                    expected_active,
                )
            })
        })
        .await
        .expect("join");

    let writer: TestOrderedWriter<F> =
        TestOrderedWriter::fresh(PrefixedStoreClient::empty(client.clone()));
    for (delta, boundary) in &uploads {
        common::commit_ordered_upload(&client, &writer, delta, boundary)
            .await
            .expect("commit upload");
    }

    let c: TestOrderedClient<F> = OrderedClient::new(
        PrefixedStoreClient::empty(client.clone()),
        op_cfg::<F>(),
        update_row_cfg(),
    );
    let key_proof = c
        .key_value_proof_at(latest_location, latest_key.as_slice())
        .await
        .expect("latest key proof");
    assert_eq!(key_proof.root, expected_root);
    match &key_proof.operation {
        QmdbOperation::Update(update) => {
            assert_eq!(update.key, latest_key);
        }
        _ => panic!("expected Update operation"),
    }

    let mut sample_keys = BTreeSet::new();
    sample_keys.extend(expected_active.keys().take(24).cloned());
    sample_keys.extend(expected_active.keys().rev().take(8).cloned());
    for key in sample_keys {
        let expected_value = expected_active
            .get(&key)
            .expect("sample key must be active");
        let proof = c
            .key_value_proof_at(latest_location, key.as_slice())
            .await
            .unwrap_or_else(|error| panic!("active key proof for {key:?}: {error:?}"));
        assert_eq!(proof.root, expected_root);
        match &proof.operation {
            QmdbOperation::Update(update) => {
                assert_eq!(update.key, key);
                assert_eq!(update.value, *expected_value);
            }
            _ => panic!("expected Update operation"),
        }
    }

    let raw_range = c
        .key_range_proof_raw_at(
            latest_location,
            b"k-00000000".to_vec(),
            Some(b"k-00000020".to_vec()),
            10,
        )
        .await
        .expect("old-key range proof");
    let expected_range_keys = expected_active
        .range(b"k-00000000".to_vec()..b"k-00000020".to_vec())
        .take(10)
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    assert_eq!(raw_range.entries.len(), expected_range_keys.len());
    for (entry, expected_key) in raw_range.entries.iter().zip(expected_range_keys) {
        assert_eq!(entry.key, expected_key.encode().to_vec());
        assert!(entry.proof.verify::<Sha256>());
    }
}

#[tokio::test]
async fn ordered_mmb_incremental_seed_batches_keep_current_proofs_verifiable() {
    assert_incremental_seed_batches_keep_current_proofs_verifiable::<mmb::Family>(
        "ordered_mmb_incremental_seed",
    )
    .await;
}

#[tokio::test]
async fn ordered_mmb_persistent_interleaved_seed_batches_keep_current_proofs_verifiable() {
    let (_dir, _server, client) = common::local_store_client().await;
    let storage_dir = tempfile::tempdir().expect("tempdir");
    let storage_path = storage_dir.path().to_owned();
    let store = client.clone();

    let (latest_location, expected_root, expected_ops_root) =
        tokio::task::spawn_blocking(move || {
            cw_tokio::Runner::new(cw_tokio::Config::new().with_storage_directory(storage_path))
                .start(|context| async move {
                    use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
                    let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
                    let cfg = common::ordered_variable_config(
                        "ordered_mmb_persistent_interleaved_seed",
                        page_cache,
                        op_cfg::<mmb::Family>(),
                        NZU64!(8),
                    );
                    let mut db: LocalDb<mmb::Family> = LocalQmdbDb::init(context.child("db"), cfg)
                        .await
                        .expect("init");
                    let writer = TestOrderedWriter::<mmb::Family>::fresh(
                        PrefixedStoreClient::empty(store.clone()),
                    );
                    let mut previous_ops = Vec::<BatchOperation<mmb::Family>>::new();
                    let mut counter = 0u64;

                    for _ in 0..2 {
                        let finalized = {
                            let mut batch = db.new_batch();
                            for offset in 0..3u64 {
                                let key = format!("k-{:08x}", counter + offset).into_bytes();
                                let value = format!("v-{:08x}", counter + offset).into_bytes();
                                batch = batch.write(key, Some(value));
                            }
                            if counter >= 3 {
                                let rewrite_key = format!("k-{:08x}", counter - 3).into_bytes();
                                let rewrite_value = format!("v-{:08x}-r", counter).into_bytes();
                                batch = batch.write(rewrite_key, Some(rewrite_value));
                            }
                            counter += 3;
                            batch
                                .merkleize(&db, None::<Vec<u8>>)
                                .await
                                .expect("merkleize")
                        };
                        db.apply_batch(finalized).await.expect("apply");
                        db.sync().await.expect("sync");

                        let latest = db.bounds().await.end - 1;
                        let count = NonZeroU64::new(*latest + 1).expect("non-zero op count");
                        let (proof, cumulative_ops) = db
                            .ops_historical_proof(
                                latest + 1,
                                Location::<mmb::Family>::new(0),
                                count,
                            )
                            .await
                            .expect("historical proof");
                        let hasher = commonware_storage::qmdb::hasher::<Sha256>();
                        assert!(commonware_storage::qmdb::verify_proof(
                            &hasher,
                            &proof,
                            Location::<mmb::Family>::new(0),
                            &cumulative_ops,
                            &db.ops_root()
                        ));
                        let previous_slice = if previous_ops.is_empty() {
                            None
                        } else {
                            Some(previous_ops.as_slice())
                        };
                        let boundary =
                            boundary_from_local_db(&db, previous_slice, &cumulative_ops).await;
                        let delta = cumulative_ops[previous_ops.len()..].to_vec();
                        common::commit_ordered_upload(&store, &writer, &delta, &boundary)
                            .await
                            .expect("commit upload");
                        previous_ops = cumulative_ops;
                    }

                    let latest_location = db.bounds().await.end - 1;
                    let expected_root = db.root();
                    let expected_ops_root = db.ops_root();
                    db.sync().await.expect("sync");
                    (latest_location, expected_root, expected_ops_root)
                })
        })
        .await
        .expect("join");

    let c: TestOrderedClient<mmb::Family> = OrderedClient::new(
        PrefixedStoreClient::empty(client.clone()),
        op_cfg::<mmb::Family>(),
        update_row_cfg(),
    );
    assert_eq!(
        c.current_root_at(latest_location)
            .await
            .expect("current root"),
        expected_root
    );
    assert_eq!(
        c.root_at(latest_location).await.expect("ops root"),
        expected_ops_root
    );
    let proof = c
        .key_value_proof_at(latest_location, b"k-00000005".as_slice())
        .await
        .expect("key proof");
    assert_eq!(proof.root, expected_root);
}

#[tokio::test]
async fn ordered_mmr_incremental_seed_batches_keep_current_proofs_verifiable() {
    assert_incremental_seed_batches_keep_current_proofs_verifiable::<mmr::Family>(
        "ordered_mmr_incremental_seed",
    )
    .await;
}

#[tokio::test]
async fn ordered_fixed_round_trip() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_fixed_local_db::<mmr::Family>().await;

    let writer: FixedTestOrderedWriter<mmr::Family> =
        FixedTestOrderedWriter::fresh(PrefixedStoreClient::empty(client.clone()));
    common::commit_ordered_upload(&client, &writer, &local.operations, &local.current_boundary)
        .await
        .expect("commit fixed upload");

    let c = FixedTestOrderedClient::<mmr::Family>::new(
        PrefixedStoreClient::empty(client.clone()),
        (),
        fixed_update_row_cfg(),
    );
    let watermark = c.writer_location_watermark().await.expect("watermark");
    assert_eq!(watermark, Some(local.latest_location));

    let keys: Vec<Vec<u8>> = local.values.keys().cloned().collect();
    let queried = c
        .query_many_at(&keys, local.latest_location)
        .await
        .expect("fixed query_many_at");
    for (key, value) in keys.iter().zip(queried.iter()) {
        assert_eq!(
            value.as_ref().and_then(|value| value.value),
            local.values[key.as_slice()]
        );
    }

    let range = c
        .operation_range_proof(
            local.latest_location,
            Location::<mmr::Family>::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("fixed operation range proof");
    assert_eq!(range.operations, local.operations);

    let current = c
        .current_operation_range_proof(
            local.latest_location,
            Location::<mmr::Family>::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("fixed current operation range proof");
    assert_eq!(current.operations, local.operations);

    let alpha = Sha256::fill(0xA1);
    let one = Sha256::fill(0x01);
    let key_proof = c
        .key_value_proof_at(local.latest_location, alpha.as_ref())
        .await
        .expect("fixed key_value_proof_at");
    match &key_proof.operation {
        FixedQmdbOperation::Update(update) => {
            assert_eq!(update.key, alpha);
            assert_eq!(update.value, one);
        }
        _ => panic!("expected fixed Update operation"),
    }
}

#[tokio::test]
async fn current_root_at() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db::<mmr::Family>().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::<mmr::Family>::new(
        PrefixedStoreClient::empty(client.clone()),
        op_cfg::<mmr::Family>(),
        update_row_cfg(),
    );
    let root = c
        .current_root_at(local.latest_location)
        .await
        .expect("current_root_at");
    assert!(!root.as_ref().iter().all(|&b| b == 0));
}

#[tokio::test]
async fn current_operation_range_proof() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db::<mmr::Family>().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::<mmr::Family>::new(
        PrefixedStoreClient::empty(client.clone()),
        op_cfg::<mmr::Family>(),
        update_row_cfg(),
    );
    let proof = c
        .current_operation_range_proof(
            local.latest_location,
            Location::<mmr::Family>::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("current_operation_range_proof");
    assert_eq!(proof.operations, local.operations);
}

#[tokio::test]
async fn key_value_proof() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db::<mmr::Family>().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::<mmr::Family>::new(
        PrefixedStoreClient::empty(client.clone()),
        op_cfg::<mmr::Family>(),
        update_row_cfg(),
    );
    let result = c
        .key_value_proof_at(local.latest_location, b"alpha".as_slice())
        .await
        .expect("key_value_proof_at");
    match &result.operation {
        QmdbOperation::Update(u) => {
            assert_eq!(u.key, b"alpha".to_vec());
            assert_eq!(u.value, b"one".to_vec());
        }
        _ => panic!("expected Update operation"),
    }
}

#[tokio::test]
async fn multi_proof() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db::<mmr::Family>().await;

    mirror_local(&client, &local).await;

    let c = TestOrderedClient::<mmr::Family>::new(
        PrefixedStoreClient::empty(client.clone()),
        op_cfg::<mmr::Family>(),
        update_row_cfg(),
    );
    let result = c
        .multi_proof_at(
            local.latest_location,
            &[b"alpha".as_slice(), b"beta".as_slice()],
        )
        .await
        .expect("multi_proof_at");
    assert_eq!(result.operations.len(), 2);
}
