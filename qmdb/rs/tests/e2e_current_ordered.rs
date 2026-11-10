//! Current ordered QMDB E2E: run a local Commonware current ordered DB,
//! upload each batch's publication to a live store stack, then verify
//! roots and proofs match.

mod common;

use commonware_cryptography::Sha256;
use commonware_macros::boxed;
use commonware_parallel::Sequential;
use commonware_runtime::{tokio as cw_tokio, Runner as _};
use commonware_storage::{
    journal::contiguous::fixed::Config as FixedJournalConfig,
    merkle::{mmb, mmr, Family, Graftable, Location, Position, Proof},
    qmdb::{
        any::ordered::{
            fixed::{Operation as FixedQmdbOperation, Update as FixedQmdbUpdate},
            variable::{Operation as QmdbOperation, Update as QmdbUpdate},
        },
        current::{
            batch::MerkleizedBatch,
            ordered::{
                fixed::Db as LocalFixedQmdbDb, proof::constant::ExclusionProof,
                variable::Db as LocalQmdbDb,
            },
        },
        operation::Operation as _,
        value::FixedEncoding,
    },
    translator::TwoCap,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::{
    adapter::upload::{
        prepare_publication, stage_authenticated_range, stage_watermark, Publication,
    },
    proof::KeyLookupProof,
    ProofKind, QmdbError, MAX_OPERATION_SIZE,
};
use exoware_sdk::StoreClient;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
    sync::Arc,
};

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchOperation<F> = QmdbOperation<F, Vec<u8>, Vec<u8>>;
type FixedBatchOperation<F> = FixedQmdbOperation<F, Digest, Digest>;
type BatchPublication<F, const M: usize> = Publication<F, Digest, QmdbUpdate<Vec<u8>, Vec<u8>>, M>;
type FixedBatchPublication<F> = Publication<F, Digest, FixedQmdbUpdate<Digest, Digest>, N>;
type VariableClient<F> = exoware_qmdb::adapter::Ordered<F, Sha256, Vec<u8>, Vec<u8>, N>;
type FixedClient<F> =
    exoware_qmdb::adapter::Ordered<F, Sha256, Digest, Digest, N, FixedEncoding<Digest>>;
type VariableDb<F> =
    LocalQmdbDb<F, cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap, N, Sequential>;
type VariableBatch<F> = MerkleizedBatch<F, Digest, QmdbUpdate<Vec<u8>, Vec<u8>>, N, Sequential>;

type FixedDb<F> =
    LocalFixedQmdbDb<F, cw_tokio::Context, Digest, Digest, Sha256, TwoCap, N, Sequential>;

async fn upload_source<F>(store_client: &StoreClient, source: &VariableSource<F>)
where
    F: Graftable,
    BatchOperation<F>: commonware_codec::Codec,
{
    let upload_client = store_client.unprefixed();
    common::commit_publications(&upload_client, &source.publications)
        .await
        .expect("commit upload");
}

fn op_cfg<F: Family>() -> <BatchOperation<F> as commonware_codec::Read>::Cfg {
    (
        ((0..=MAX_OPERATION_SIZE).into(), ()),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    )
}

fn key_cfg() -> <Vec<u8> as commonware_codec::Read>::Cfg {
    ((0..=MAX_OPERATION_SIZE).into(), ())
}

struct VariableSource<F: Graftable> {
    latest_location: Location<F>,
    operations: Vec<BatchOperation<F>>,
    publications: Vec<BatchPublication<F, N>>,
    values: std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

struct ChunkSizedVariableSource<F: Graftable, const M: usize> {
    latest_location: Location<F>,
    operations: Vec<BatchOperation<F>>,
    root: Digest,
    publications: Vec<BatchPublication<F, M>>,
}

struct FixedSource<F: Graftable> {
    latest_location: Location<F>,
    operations: Vec<FixedBatchOperation<F>>,
    publications: Vec<FixedBatchPublication<F>>,
    values: std::collections::BTreeMap<Vec<u8>, Option<Digest>>,
}

async fn build_variable_source<F>() -> VariableSource<F>
where
    F: Graftable,
    BatchOperation<F>: commonware_codec::Codec + Clone,
{
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::new(NZU16!(64), NZUsize!(8));
            let cfg = common::current_variable_config(
                "current_ordered_variable_source",
                page_cache,
                op_cfg::<F>(),
                NZU64!(8),
            );
            let mut db: VariableDb<F> =
                VariableDb::init(context.child("current_ordered_variable_source"), cfg, None)
                    .await
                    .expect("init");

            let finalized = {
                let batch = db
                    .new_batch()
                    .write(b"alpha".to_vec(), Some(b"one".to_vec()))
                    .write(b"beta".to_vec(), Some(b"two".to_vec()));
                batch.merkleize(&db).await.expect("merkleize")
            };
            let publications = vec![
                Publication::initial(&db).expect("initial publication must be readable"),
                Publication::from_batch(&finalized, &db).expect("publication must be readable"),
            ];
            db = db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (Proof<F, Digest>, Vec<BatchOperation<F>>) = db
                .ops_historical_proof(latest + 1, Location::<F>::new(0), n)
                .await
                .expect("proof");

            let mut values = std::collections::BTreeMap::new();
            values.insert(
                b"alpha".to_vec(),
                db.get(&b"alpha".to_vec()).await.expect("get"),
            );
            values.insert(
                b"beta".to_vec(),
                db.get(&b"beta".to_vec()).await.expect("get"),
            );

            db = db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            VariableSource {
                latest_location: latest,
                operations: ops,
                publications,
                values,
            }
        })
    })
    .await
    .expect("join")
}

async fn build_variable_source_with_write_count<F, const M: usize>(
    partition_prefix: &'static str,
    write_count: usize,
) -> ChunkSizedVariableSource<F, M>
where
    F: Graftable,
    BatchOperation<F>: commonware_codec::Codec + Clone,
{
    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::new(NZU16!(64), NZUsize!(8));
            let cfg = common::current_variable_config(
                partition_prefix,
                page_cache,
                op_cfg::<F>(),
                NZU64!(8),
            );
            let mut db: LocalQmdbDb<
                F,
                cw_tokio::Context,
                Vec<u8>,
                Vec<u8>,
                Sha256,
                TwoCap,
                M,
                Sequential,
            > = LocalQmdbDb::init(context.child(partition_prefix), cfg, None)
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
                batch.merkleize(&db).await.expect("merkleize")
            };
            let publications = vec![
                Publication::initial(&db).expect("initial publication must be readable"),
                Publication::from_batch(&finalized, &db).expect("publication must be readable"),
            ];
            db = db.apply_batch(finalized).await.expect("apply");

            let root = db.root();
            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (Proof<F, Digest>, Vec<BatchOperation<F>>) = db
                .ops_historical_proof(latest + 1, Location::<F>::new(0), n)
                .await
                .expect("proof");

            db = db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");

            ChunkSizedVariableSource {
                latest_location: latest,
                operations: ops,
                root,
                publications,
            }
        })
    })
    .await
    .expect("join")
}

async fn build_fixed_source<F>() -> FixedSource<F>
where
    F: Graftable,
    FixedBatchOperation<F>: commonware_codec::CodecFixed<Cfg = ()> + Clone + Send + Sync,
{
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::new(NZU16!(64), NZUsize!(8));
            let cfg = commonware_storage::qmdb::current::Config {
                merkle: common::merkle_config("current_ordered_fixed_source", page_cache.clone()),
                log: FixedJournalConfig {
                    partition: "current_ordered_fixed_source-log".to_string(),
                    items_per_blob: NZU64!(8),
                    page_cache,
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                },
                grafted_metadata_partition: "current_ordered_fixed_source-grafted-metadata"
                    .to_string(),
                translator: TwoCap,
                init_cache: None,
                init_buffer: NZUsize!(1 << 21),
                init_concurrency: (),
            };
            let mut db: FixedDb<F> =
                FixedDb::init(context.child("current_ordered_fixed_source"), cfg, None)
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
                batch.merkleize(&db).await.expect("fixed merkleize")
            };
            let publications = vec![
                Publication::initial(&db).expect("initial publication must be readable"),
                Publication::from_batch(&finalized, &db).expect("publication must be readable"),
            ];
            db = db.apply_batch(finalized).await.expect("apply fixed");

            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (Proof<F, Digest>, Vec<FixedBatchOperation<F>>) = db
                .ops_historical_proof(latest + 1, Location::<F>::new(0), n)
                .await
                .expect("fixed proof");

            let mut values = std::collections::BTreeMap::new();
            values.insert(
                alpha.as_ref().to_vec(),
                db.get(&alpha).await.expect("get alpha"),
            );
            values.insert(
                beta.as_ref().to_vec(),
                db.get(&beta).await.expect("get beta"),
            );

            db = db.sync().await.expect("sync fixed");
            db.destroy().await.expect("destroy fixed");

            FixedSource {
                latest_location: latest,
                operations: ops,
                publications,
                values,
            }
        })
    })
    .await
    .expect("join")
}

#[tokio::test]
async fn test_ordered_round_trip() {
    let store_client = common::local_store_client().await;
    let source = build_variable_source::<mmr::Family>().await;

    upload_source(&store_client, &source).await;

    let qmdb_client = VariableClient::<mmr::Family>::new(
        store_client.unprefixed(),
        op_cfg::<mmr::Family>(),
        key_cfg(),
    );
    let watermark = qmdb_client
        .latest_published_watermark()
        .await
        .expect("watermark");
    assert_eq!(watermark, Some(source.latest_location));

    let queried = qmdb_client
        .get_many_at(
            source.latest_location,
            &[b"alpha".to_vec(), b"beta".to_vec()],
            None,
        )
        .await
        .expect("get_many_at");
    assert_eq!(
        queried[0].as_ref().and_then(|v| v.value.clone()),
        source.values[b"alpha".as_slice()]
    );
    assert_eq!(
        queried[1].as_ref().and_then(|v| v.value.clone()),
        source.values[b"beta".as_slice()]
    );

    let proof = qmdb_client
        .operation_range(
            source.latest_location,
            Location::<mmr::Family>::new(0),
            source.operations.len() as u32,
            None,
        )
        .await
        .expect("proof");
    assert_eq!(proof.operations, source.operations);
}

#[tokio::test]
async fn test_ordered_mmb_round_trip() {
    let store_client = common::local_store_client().await;
    let source = build_variable_source::<mmb::Family>().await;

    upload_source(&store_client, &source).await;

    let qmdb_client = VariableClient::<mmb::Family>::new(
        store_client.unprefixed(),
        op_cfg::<mmb::Family>(),
        key_cfg(),
    );
    let watermark = qmdb_client
        .latest_published_watermark()
        .await
        .expect("watermark");
    assert_eq!(watermark, Some(source.latest_location));

    let range = qmdb_client
        .operation_range(
            source.latest_location,
            Location::<mmb::Family>::new(0),
            source.operations.len() as u32,
            None,
        )
        .await
        .expect("operation range proof");
    assert_eq!(range.operations, source.operations);

    let current = qmdb_client
        .current_operation_range(
            source.latest_location,
            Location::<mmb::Family>::new(0),
            source.operations.len() as u32,
            None,
        )
        .await
        .expect("current operation range proof");
    assert_eq!(current.operations, source.operations);

    let key_proof = qmdb_client
        .get(source.latest_location, &b"alpha".to_vec(), None)
        .await
        .expect("get");
    match &key_proof.operation {
        QmdbOperation::Update(update) => {
            assert_eq!(update.key, b"alpha".to_vec());
            assert_eq!(update.value, b"one".to_vec());
        }
        _ => panic!("expected Update operation"),
    }
}

#[tokio::test]
async fn test_ordered_mmb_multi_peak_grafted_chunk_round_trip() {
    let store_client = common::local_store_client().await;
    let source = build_variable_source_with_write_count::<mmb::Family, N>(
        "current_ordered_variable_mmb_grafted_source",
        767,
    )
    .await;
    assert!(
        source
            .publications
            .last()
            .expect("source publications must not be empty")
            .grafted_nodes
            .len()
            >= 2,
        "test must cross a grafted chunk boundary"
    );

    let upload_client = store_client.unprefixed();
    common::commit_publications(&upload_client, &source.publications)
        .await
        .expect("commit upload");

    let qmdb_client: exoware_qmdb::adapter::Ordered<mmb::Family, Sha256, Vec<u8>, Vec<u8>, N> =
        exoware_qmdb::adapter::Ordered::new(
            store_client.unprefixed(),
            op_cfg::<mmb::Family>(),
            key_cfg(),
        );
    let current = qmdb_client
        .current_operation_range(
            source.latest_location,
            Location::<mmb::Family>::new(0),
            source.operations.len() as u32,
            None,
        )
        .await
        .expect("current operation range proof");
    assert_eq!(current.operations, source.operations);

    let key = b"k-00000007".to_vec();
    let key_proof = qmdb_client
        .get(source.latest_location, &key, None)
        .await
        .expect("get");
    assert_eq!(key_proof.root, source.root);
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
    BatchOperation<F>: commonware_codec::Codec + Clone,
{
    let store_client = common::local_store_client().await;
    let (publications, latest_location, latest_key, expected_root, expected_active) =
        tokio::task::spawn_blocking(move || {
            cw_tokio::Runner::default().start(|context| async move {
                use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
                let page_cache = CacheRef::new(NZU16!(64), NZUsize!(8));
                let cfg = common::current_variable_config(
                    partition_prefix,
                    page_cache,
                    op_cfg::<F>(),
                    NZU64!(8),
                );
                let mut db: VariableDb<F> =
                    LocalQmdbDb::init(context.child(partition_prefix), cfg, None)
                        .await
                        .expect("init");

                let mut publications =
                    vec![Publication::initial(&db).expect("initial publication must be readable")];
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
                        batch.merkleize(&db).await.expect("merkleize")
                    };
                    publications.push(
                        Publication::from_batch(&finalized, &db)
                            .expect("publication must be readable"),
                    );
                    db = db.apply_batch(finalized).await.expect("apply");
                }

                let latest_location = db.bounds().end - 1;
                let latest_key = format!("k-{:08x}", counter - 3).into_bytes();
                let expected_root = db.root();
                db.destroy().await.expect("destroy");
                (
                    publications,
                    latest_location,
                    latest_key,
                    expected_root,
                    expected_active,
                )
            })
        })
        .await
        .expect("join");

    let upload_client = store_client.unprefixed();
    for publication in &publications {
        common::commit_publications(&upload_client, std::slice::from_ref(publication))
            .await
            .expect("commit upload");
    }

    let qmdb_client: VariableClient<F> =
        exoware_qmdb::adapter::Ordered::new(store_client.unprefixed(), op_cfg::<F>(), key_cfg());
    let key_proof = qmdb_client
        .get(latest_location, &latest_key, None)
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
        let proof = qmdb_client
            .get(latest_location, &key, None)
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

    let range = qmdb_client
        .get_range(
            latest_location,
            b"k-00000000".to_vec(),
            Some(b"k-00000020".to_vec()),
            10,
            None,
        )
        .await
        .expect("old-key range proof");
    let expected_range_keys = expected_active
        .range(b"k-00000000".to_vec()..b"k-00000020".to_vec())
        .take(10)
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    assert_eq!(range.entries.len(), expected_range_keys.len());
    for (entry, expected_key) in range.entries.iter().zip(expected_range_keys) {
        assert_eq!(entry.operation.key(), Some(&expected_key));
    }
}

#[tokio::test]
async fn test_ordered_mmb_incremental_seed_batches_keep_current_proofs_verifiable() {
    assert_incremental_seed_batches_keep_current_proofs_verifiable::<mmb::Family>(
        "current_ordered_variable_mmb_incremental_seed_source",
    )
    .await;
}

#[tokio::test]
async fn test_ordered_mmb_persistent_interleaved_seed_batches_keep_current_proofs_verifiable() {
    let store_client = common::local_store_client().await;
    let storage_dir = tempfile::tempdir().expect("tempdir");
    let storage_path = storage_dir.path().to_owned();
    let store = store_client.clone();

    let (latest_location, expected_root, expected_ops_root) =
        tokio::task::spawn_blocking(move || {
            cw_tokio::Runner::new(cw_tokio::Config::new().with_storage_directory(storage_path))
                .start(|context| async move {
                    use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
                    let page_cache = CacheRef::new(NZU16!(64), NZUsize!(8));
                    let cfg = common::current_variable_config(
                        "current_ordered_variable_mmb_persistent_seed_source",
                        page_cache,
                        op_cfg::<mmb::Family>(),
                        NZU64!(8),
                    );
                    let mut db: VariableDb<mmb::Family> = LocalQmdbDb::init(
                        context.child("current_ordered_variable_mmb_persistent_seed_source"),
                        cfg,
                        None,
                    )
                    .await
                    .expect("init");
                    let upload_client = store.unprefixed();
                    let initial =
                        Publication::initial(&db).expect("initial publication must be readable");
                    common::commit_publications(&upload_client, &[initial])
                        .await
                        .expect("initial upload must succeed");
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
                            batch.merkleize(&db).await.expect("merkleize")
                        };
                        let publication = Publication::from_batch(&finalized, &db)
                            .expect("publication must be readable");
                        db = db.apply_batch(finalized).await.expect("apply");
                        db = db.sync().await.expect("sync");
                        common::commit_publications(&upload_client, &[publication])
                            .await
                            .expect("commit upload");
                    }

                    let latest_location = db.bounds().end - 1;
                    let expected_root = db.root();
                    let expected_ops_root = db.ops_root();
                    db.sync().await.expect("sync");
                    (latest_location, expected_root, expected_ops_root)
                })
        })
        .await
        .expect("join");

    let qmdb_client: VariableClient<mmb::Family> = exoware_qmdb::adapter::Ordered::new(
        store_client.unprefixed(),
        op_cfg::<mmb::Family>(),
        key_cfg(),
    );
    assert_eq!(
        qmdb_client
            .root_at(latest_location, None)
            .await
            .expect("current root"),
        expected_root
    );
    assert_eq!(
        qmdb_client
            .ops_root_at(latest_location, None)
            .await
            .expect("ops root"),
        expected_ops_root
    );
    let proof = qmdb_client
        .get(latest_location, &b"k-00000005".to_vec(), None)
        .await
        .expect("key proof");
    assert_eq!(proof.root, expected_root);
}

#[tokio::test]
async fn test_ordered_mmr_incremental_seed_batches_keep_current_proofs_verifiable() {
    assert_incremental_seed_batches_keep_current_proofs_verifiable::<mmr::Family>(
        "current_ordered_variable_mmr_incremental_seed_source",
    )
    .await;
}

#[tokio::test]
async fn test_ordered_fixed_round_trip() {
    let store_client = common::local_store_client().await;
    let source = build_fixed_source::<mmr::Family>().await;

    let upload_client = store_client.unprefixed();
    common::commit_publications(&upload_client, &source.publications)
        .await
        .expect("commit fixed upload");

    let qmdb_client = FixedClient::<mmr::Family>::new(store_client.unprefixed(), (), ());
    let watermark = qmdb_client
        .latest_published_watermark()
        .await
        .expect("watermark");
    assert_eq!(watermark, Some(source.latest_location));

    let keys = source
        .values
        .keys()
        .map(|key| {
            commonware_codec::DecodeExt::decode(commonware_codec::Copying(key.as_slice()))
                .expect("digest key")
        })
        .collect::<Vec<commonware_cryptography::sha256::Digest>>();
    let queried = qmdb_client
        .get_many_at(source.latest_location, &keys, None)
        .await
        .expect("fixed get_many_at");
    for (key, value) in keys.iter().zip(queried.iter()) {
        assert_eq!(
            value.as_ref().and_then(|value| value.value),
            source.values[key.as_ref()]
        );
    }

    let range = qmdb_client
        .operation_range(
            source.latest_location,
            Location::<mmr::Family>::new(0),
            source.operations.len() as u32,
            None,
        )
        .await
        .expect("fixed operation range proof");
    assert_eq!(range.operations, source.operations);

    let current = qmdb_client
        .current_operation_range(
            source.latest_location,
            Location::<mmr::Family>::new(0),
            source.operations.len() as u32,
            None,
        )
        .await
        .expect("fixed current operation range proof");
    assert_eq!(current.operations, source.operations);

    let alpha = Sha256::fill(0xA1);
    let one = Sha256::fill(0x01);
    let key_proof = qmdb_client
        .get(source.latest_location, &alpha, None)
        .await
        .expect("fixed get");
    match &key_proof.operation {
        FixedQmdbOperation::Update(update) => {
            assert_eq!(update.key, alpha);
            assert_eq!(update.value, one);
        }
        _ => panic!("expected fixed Update operation"),
    }
}

#[tokio::test]
async fn test_root_at_returns_current_root() {
    let store_client = common::local_store_client().await;
    let source = build_variable_source::<mmr::Family>().await;

    upload_source(&store_client, &source).await;

    let qmdb_client = VariableClient::<mmr::Family>::new(
        store_client.unprefixed(),
        op_cfg::<mmr::Family>(),
        key_cfg(),
    );
    let root = qmdb_client
        .root_at(source.latest_location, None)
        .await
        .expect("root_at");
    let publication = source
        .publications
        .last()
        .expect("source must hold a publication");
    assert_eq!(root, publication.root);
}

#[tokio::test]
async fn test_current_operation_range_proof() {
    let store_client = common::local_store_client().await;
    let source = build_variable_source::<mmr::Family>().await;

    upload_source(&store_client, &source).await;

    let qmdb_client = VariableClient::<mmr::Family>::new(
        store_client.unprefixed(),
        op_cfg::<mmr::Family>(),
        key_cfg(),
    );
    let proof = qmdb_client
        .current_operation_range(
            source.latest_location,
            Location::<mmr::Family>::new(0),
            source.operations.len() as u32,
            None,
        )
        .await
        .expect("current_operation_range");
    assert_eq!(proof.operations, source.operations);
}

#[tokio::test]
async fn test_key_value_proof() {
    let store_client = common::local_store_client().await;
    let source = build_variable_source::<mmr::Family>().await;

    upload_source(&store_client, &source).await;

    let qmdb_client = VariableClient::<mmr::Family>::new(
        store_client.unprefixed(),
        op_cfg::<mmr::Family>(),
        key_cfg(),
    );
    let result = qmdb_client
        .get(source.latest_location, &b"alpha".to_vec(), None)
        .await
        .expect("get");
    match &result.operation {
        QmdbOperation::Update(u) => {
            assert_eq!(u.key, b"alpha".to_vec());
            assert_eq!(u.value, b"one".to_vec());
        }
        _ => panic!("expected Update operation"),
    }
}

async fn assert_point_proof_reads_bounded_bitmap_chunks<F: Graftable>() {
    let (query, store_client, servers) = common::counting_store().await;
    let source = build_variable_source_with_write_count::<F, N>(
        "current_ordered_variable_bounded_bitmap_source",
        2048,
    )
    .await;
    assert!(source.operations.len() / (N * 8) > 3);
    let upload_client = store_client.unprefixed();
    common::commit_publications(&upload_client, &source.publications)
        .await
        .unwrap();
    let qmdb_client: VariableClient<F> =
        exoware_qmdb::adapter::Ordered::new(store_client.unprefixed(), op_cfg::<F>(), key_cfg());
    query.bitmap_chunks.lock().unwrap().clear();
    let proof = qmdb_client
        .get(source.latest_location, &b"k-00000007".to_vec(), None)
        .await
        .unwrap();
    assert_eq!(proof.root, source.root);
    let chunks = query.bitmap_chunks.lock().unwrap().clone();
    assert!(
        chunks.len() <= 3,
        "point proof fetched unrelated bitmap chunks: {chunks:?}"
    );
    for server in servers {
        server.abort();
    }
}

#[tokio::test]
async fn test_ordered_mmr_point_proof_reads_bounded_bitmap_chunks() {
    assert_point_proof_reads_bounded_bitmap_chunks::<mmr::Family>().await;
}

#[tokio::test]
async fn test_ordered_mmb_point_proof_reads_bounded_bitmap_chunks() {
    assert_point_proof_reads_bounded_bitmap_chunks::<mmb::Family>().await;
}

#[tokio::test]
async fn test_ordered_mmr_exclusion_proof_reads_one_update_page() {
    let (query, store_client, servers) = common::counting_store().await;
    let write_count = 2048;
    let source = build_variable_source_with_write_count::<mmr::Family, N>(
        "current_ordered_variable_bounded_update_walk_source",
        write_count,
    )
    .await;
    let upload_client = store_client.unprefixed();
    common::commit_publications(&upload_client, &source.publications)
        .await
        .unwrap();
    let qmdb_client: VariableClient<mmr::Family> = exoware_qmdb::adapter::Ordered::new(
        store_client.unprefixed(),
        op_cfg::<mmr::Family>(),
        key_cfg(),
    );

    // The probe sits near the top of the index, so a walk that read past its
    // predecessor would read thousands of rows below it
    let missing = b"k-00002040x".to_vec();
    query.reset_update_reads();
    let mut lookups = qmdb_client
        .get_many_proofs(source.latest_location, std::slice::from_ref(&missing), None)
        .await
        .unwrap();
    let (scans, rows) = query.update_reads();
    let Some(KeyLookupProof::Miss(proof)) = lookups.pop() else {
        panic!("missing key should be a miss");
    };
    assert_eq!(proof.root, source.root);
    assert!(proof.verify::<Sha256>());
    let ExclusionProof::KeyValue(_, update) = &proof.proof else {
        panic!("missing key should be covered by an active key");
    };
    assert_eq!(update.key, b"k-00002040".to_vec());
    assert_eq!(update.next_key, b"k-00002041".to_vec());
    // One scan looks up the probe itself, and the walk reads one first page
    assert_eq!(
        (scans, rows),
        (1 + 1, 128),
        "exclusion proof read {rows} of {write_count} update rows"
    );
    for server in servers {
        server.abort();
    }
}

async fn assert_current_boundaries_survive_coalesced_publication<F>()
where
    F: Graftable,
    BatchOperation<F>: commonware_codec::Codec + Clone,
{
    use exoware_sdk::StoreWriteBatch;

    let (initial_root, prepared_initial, prepared) = tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};

            // Prepare each publication from its encoding, as a deferred writer would.
            let prepare = |publication: &BatchPublication<F, N>| {
                let decoded = common::round_trip_publication(publication, op_cfg::<F>());
                prepare_publication::<F, Sha256, _, _, N>(&decoded, &publication.root, &Sequential)
                    .expect("decoded publication must verify")
            };

            let page_cache = CacheRef::new(NZU16!(64), NZUsize!(8));
            let cfg = common::current_variable_config(
                "current_ordered_variable_coalesced_source",
                page_cache,
                op_cfg::<F>(),
                NZU64!(8),
            );
            let mut db: VariableDb<F> = VariableDb::init(
                context.child("current_ordered_variable_coalesced_source"),
                cfg,
                None,
            )
            .await
            .expect("init source current DB");
            let initial = Publication::initial(&db).expect("initial publication must be readable");
            let prepared_initial = prepare(&initial);

            // Merkleize the second batch as a child of the first and read both publications
            // while neither batch is applied.
            let mut batches: Vec<(Arc<VariableBatch<F>>, _, _)> = Vec::new();
            for (batch_index, value) in [b"one".to_vec(), b"updated".to_vec()]
                .into_iter()
                .enumerate()
            {
                let mut batch = match batches.last() {
                    Some((parent, _, _)) => parent.new_batch::<Sha256>(),
                    None => db.new_batch(),
                }
                .write(b"alpha".to_vec(), Some(value.clone()))
                .write(b"beta".to_vec(), Some(b"stable".to_vec()));
                for index in 0..300 {
                    let index = batch_index * 300 + index;
                    batch = batch.write(
                        format!("k-{index:08}").into_bytes(),
                        Some(format!("v-{index:08}").into_bytes()),
                    );
                }
                let batch = batch.merkleize(&db).await.expect("merkleize source batch");
                let publication =
                    Publication::from_batch(&batch, &db).expect("publication must be readable");
                batches.push((batch, publication, value));
            }

            // Apply the batches in order and check each publication against the database its
            // batch produces.
            let mut prepared = Vec::new();
            for (batch_index, (batch, publication, value)) in batches.into_iter().enumerate() {
                db = db.apply_batch(batch).await.expect("apply source batch");
                let end = db.bounds().end;
                assert_eq!(publication.root, db.root());
                assert!(*end / (N * 8) as u64 > *publication.start_location / (N * 8) as u64);
                assert_eq!(
                    db.get(&b"alpha".to_vec()).await.unwrap(),
                    Some(value.clone())
                );
                if batch_index == 1 {
                    assert!(!publication.pinned_nodes.is_empty());
                    assert!(!publication.grafted_nodes.is_empty());
                }
                prepared.push((end - 1, publication.root, value, prepare(&publication)));
            }

            // A database with applied batches has no initial publication.
            assert!(matches!(
                Publication::initial(&db),
                Err(QmdbError::CorruptData(_))
            ));
            db.destroy().await.expect("destroy source DB");
            (initial.root, prepared_initial, prepared)
        })
    })
    .await
    .expect("join source DB");

    let store_client = common::local_store_client().await;
    let upload_client = store_client.unprefixed();
    let qmdb_client: VariableClient<F> =
        exoware_qmdb::adapter::Ordered::new(upload_client.clone(), op_cfg::<F>(), key_cfg());
    let mut batch = StoreWriteBatch::new();
    stage_authenticated_range(&upload_client, prepared_initial, &mut batch)
        .expect("initial publication must stage without publishing");
    batch
        .commit(&store_client)
        .await
        .expect("initial publication must persist");
    let mut expected = Vec::new();
    for (latest, root, value, range) in prepared {
        let mut batch = StoreWriteBatch::new();
        stage_authenticated_range(&upload_client, range, &mut batch)
            .expect("stage current range without publishing");
        batch
            .commit(&store_client)
            .await
            .expect("persist current range");
        expected.push((latest, root, value));
    }
    assert_eq!(
        qmdb_client.latest_published_watermark().await.unwrap(),
        None
    );
    for (tip, _, _) in &expected {
        assert!(matches!(
            qmdb_client.root_at(*tip, None).await,
            Err(exoware_qmdb::QmdbError::NoPublishedWatermark { tip: requested })
                if requested == tip.as_u64()
        ));
    }

    // Publish once after both prefixes and their versioned current-state rows are durable.
    let latest = expected.last().unwrap().0;
    let mut watermark = StoreWriteBatch::new();
    stage_watermark(&upload_client, latest, &mut watermark).expect("stage final watermark");
    watermark
        .commit(&store_client)
        .await
        .expect("publish final watermark");
    assert_eq!(
        qmdb_client.latest_published_watermark().await.unwrap(),
        Some(latest)
    );
    assert_eq!(
        qmdb_client.root_at(Location::new(0), None).await.unwrap(),
        initial_root
    );

    for (tip, expected_root, expected_value) in expected {
        let root = qmdb_client
            .root_at(tip, None)
            .await
            .unwrap_or_else(|error| panic!("current root at uploaded tip {tip}: {error}"));
        assert_eq!(root, expected_root);
        let proof = qmdb_client
            .get(tip, &b"alpha".to_vec(), None)
            .await
            .unwrap_or_else(|error| panic!("current proof at uploaded tip {tip}: {error}"));
        assert_eq!(proof.root, expected_root);
        match proof.operation {
            BatchOperation::Update(update) => {
                assert_eq!(update.key, b"alpha".to_vec());
                assert_eq!(update.value, expected_value);
            }
            _ => panic!("expected alpha's update operation"),
        }
    }
}

#[tokio::test]
async fn test_ordered_mmr_current_boundaries_survive_coalesced_publication() {
    assert_current_boundaries_survive_coalesced_publication::<mmr::Family>().await;
}

#[tokio::test]
async fn test_ordered_mmb_current_boundaries_survive_coalesced_publication() {
    assert_current_boundaries_survive_coalesced_publication::<mmb::Family>().await;
}

/// Store requests `operation` makes.
#[boxed]
async fn store_calls<T>(
    query: &common::CountingQuery,
    operation: impl std::future::Future<Output = Result<T, exoware_qmdb::QmdbError>>,
) -> common::StoreCalls {
    query.take_calls();
    operation.await.unwrap();
    query.take_calls()
}

#[tokio::test]
async fn test_ordered_current_proofs_store_calls() {
    let (query, store_client, servers) = common::counting_store().await;
    let source = build_variable_source_with_write_count::<mmr::Family, N>(
        "current_ordered_variable_store_calls_source",
        300,
    )
    .await;
    common::commit_publications(&store_client.unprefixed(), &source.publications)
        .await
        .unwrap();
    // A new client starts with an empty read cache
    let new_client = || async {
        let client: VariableClient<mmr::Family> = exoware_qmdb::adapter::Ordered::new(
            store_client.unprefixed(),
            op_cfg::<mmr::Family>(),
            key_cfg(),
        );
        client.latest_published_watermark().await.unwrap();
        client
    };
    let client = new_client().await;
    let tip = source.latest_location;

    let key = |index: usize| format!("k-{index:08}").into_bytes();
    let present = [key(7), key(150), key(290)];
    let missing = b"k-00000150x".to_vec();
    let calls = |get, get_many, range| common::StoreCalls {
        get,
        get_many,
        range,
    };
    // The first proof loads the tip; later ones read only their own rows and nodes
    assert_eq!(
        store_calls(&query, client.get_proof(tip, &key(7), None)).await,
        calls(0, 2, 3),
    );
    assert_eq!(
        store_calls(&query, client.get_proof(tip, &key(7), None)).await,
        calls(0, 1, 2),
    );
    assert_eq!(
        store_calls(&query, client.get_many_proofs(tip, &present, None)).await,
        calls(0, 3, 6),
    );
    assert_eq!(
        store_calls(
            &query,
            client.get_many_proofs(tip, std::slice::from_ref(&missing), None),
        )
        .await,
        calls(0, 1, 3),
    );
    assert_eq!(
        store_calls(&query, client.get_range_proof(tip, key(10), None, 5, None)).await,
        calls(0, 5, 6),
    );
    assert_eq!(
        store_calls(
            &query,
            client.current_operation_range_proof(tip, tip - 4, 4, None),
        )
        .await,
        calls(0, 1, 2),
    );

    // Requests proving several keys load a cold tip once
    assert_eq!(
        store_calls(
            &query,
            new_client().await.get_many_proofs(tip, &present, None)
        )
        .await,
        calls(0, 4, 7),
    );
    assert_eq!(
        store_calls(
            &query,
            new_client()
                .await
                .get_range_proof(tip, key(10), None, 5, None),
        )
        .await,
        calls(0, 6, 7),
    );
    for server in servers {
        server.abort();
    }
}

#[tokio::test]
async fn test_ordered_current_proof_reads_overlap() {
    let (query, store_client, servers) = common::counting_store().await;
    let source = build_variable_source_with_write_count::<mmr::Family, N>(
        "current_ordered_variable_overlap_source",
        300,
    )
    .await;
    common::commit_publications(&store_client.unprefixed(), &source.publications)
        .await
        .unwrap();
    let client: VariableClient<mmr::Family> = exoware_qmdb::adapter::Ordered::new(
        store_client.unprefixed(),
        op_cfg::<mmr::Family>(),
        key_cfg(),
    );
    let tip = source.latest_location;
    let key = b"k-00000007".to_vec();
    // Load the tip first, so the gated reads are the proof's own
    let warm = client.get_proof(tip, &key, None).await.unwrap();
    assert_eq!(warm.root, source.root);
    let deadline = std::time::Duration::from_secs(10);

    // A key proof reads its operation row and nodes while reading its chunk
    query.require_overlap(exoware_qmdb::CHUNK_FAMILY);
    let proof = tokio::time::timeout(deadline, client.get_proof(tip, &key, None))
        .await
        .expect("operation batch and chunk read must overlap")
        .unwrap();
    assert!(proof.verify::<Sha256>());

    // A range proof reads its nodes while scanning its operations
    query.require_overlap(common::OPERATION_FAMILY);
    let range = tokio::time::timeout(
        deadline,
        client.current_operation_range_proof(tip, tip - 4, 4, None),
    )
    .await
    .expect("node batch and operation scan must overlap")
    .unwrap();
    assert!(range.verify::<Sha256>());
    for server in servers {
        server.abort();
    }
}

#[tokio::test]
async fn test_prepare_publication_rejects_unbound_publications() {
    // Read the initial publication and the publication of one source batch that is never
    // applied.
    let (initial, publication) = tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};
            let page_cache = CacheRef::new(NZU16!(64), NZUsize!(8));
            let cfg = common::current_variable_config(
                "current_ordered_variable_publication_source",
                page_cache,
                op_cfg::<mmr::Family>(),
                NZU64!(8),
            );
            let db: VariableDb<mmr::Family> = VariableDb::init(
                context.child("current_ordered_variable_publication_source"),
                cfg,
                None,
            )
            .await
            .expect("source database must initialize");
            let initial = Publication::initial(&db).expect("initial publication must be readable");
            let batch = db
                .new_batch()
                .write(b"alpha".to_vec(), Some(b"one".to_vec()))
                .write(b"beta".to_vec(), Some(b"two".to_vec()))
                .merkleize(&db)
                .await
                .expect("source batch must merkleize");
            let publication =
                Publication::from_batch(&batch, &db).expect("publication must be readable");
            db.destroy().await.expect("source destroy must succeed");
            (initial, publication)
        })
    })
    .await
    .expect("source task must complete");

    // The unmodified publication prepares rows spanning exactly the batch's operations.
    let root = publication.root;
    let prepare = |publication: &_, root: &Digest| {
        prepare_publication::<mmr::Family, Sha256, _, _, N>(publication, root, &Sequential)
    };
    let prepared = prepare(&publication, &root).expect("source publication must verify");
    assert_eq!(prepared.start_location(), publication.start_location);
    assert_eq!(
        prepared.latest_location(),
        publication.start_location + (publication.operations.len() as u64 - 1)
    );

    // A root other than the publication's is rejected.
    assert!(matches!(
        prepare(&publication, &Sha256::fill(0xEE)),
        Err(QmdbError::ProofVerification {
            kind: ProofKind::Publication
        })
    ));

    // A publication whose root is not the trusted root is rejected, although its witness binds
    // the rebuilt operation-log root to the trusted root.
    let mut rerooted = publication.clone();
    rerooted.root = Sha256::fill(0xEE);
    assert!(matches!(
        prepare(&rerooted, &root),
        Err(QmdbError::ProofVerification {
            kind: ProofKind::Publication
        })
    ));

    // Reordered operations rebuild a different operation-log root, which the witness does not
    // bind to the publication's root.
    let mut reordered = publication.clone();
    let mut operations = reordered.operations.as_ref().clone();
    operations.swap(0, 1);
    reordered.operations = Arc::new(operations);
    assert!(matches!(
        prepare(&reordered, &root),
        Err(QmdbError::ProofVerification {
            kind: ProofKind::Publication
        })
    ));

    // The initial commit followed by the batch's operations rebuilds the batch's operation-log
    // root from an empty frontier, and is rejected for holding two commits.
    let mut glued = publication.clone();
    glued.start_location = Location::new(0);
    glued.pinned_nodes = Vec::new();
    let mut operations = initial.operations.as_ref().clone();
    operations.extend(publication.operations.iter().cloned());
    glued.operations = Arc::new(operations);
    assert!(matches!(
        prepare(&glued, &root),
        Err(QmdbError::CorruptData(message))
            if message == "publication must not contain a commit before its last operation"
    ));

    // A publication that does not end at a commit is rejected, whether it holds operations or
    // not.
    let mut uncommitted = publication.clone();
    let mut operations = uncommitted.operations.as_ref().clone();
    operations.pop();
    uncommitted.operations = Arc::new(operations);
    let mut empty = publication.clone();
    empty.operations = Arc::new(Vec::new());
    for incomplete in [&uncommitted, &empty] {
        assert!(matches!(
            prepare(incomplete, &root),
            Err(QmdbError::CorruptData(message)) if message == "publication must end at a commit"
        ));
    }

    // A grafted node below the grafting height is rejected.
    let mut low_graft = publication.clone();
    low_graft.grafted_nodes = vec![(Position::new(0), root)];
    assert!(matches!(
        prepare(&low_graft, &root),
        Err(QmdbError::CorruptData(_))
    ));

    // A decoded grafted node too close to the family's node limit to convert is rejected.
    let mut high_graft = publication.clone();
    high_graft.grafted_nodes = vec![(Position::new(*mmr::Family::MAX_NODES - 1), root)];
    let high_graft = common::round_trip_publication(&high_graft, op_cfg::<mmr::Family>());
    assert!(matches!(
        prepare(&high_graft, &root),
        Err(QmdbError::CorruptData(_))
    ));

    // A witness that does not bind the rebuilt operation-log root to the publication's root
    // fails publication verification.
    let mut unbound = publication;
    unbound.ops_root_witness.grafted_root = Sha256::fill(0xEE);
    assert!(matches!(
        prepare(&unbound, &root),
        Err(QmdbError::ProofVerification {
            kind: ProofKind::Publication
        })
    ));
}
