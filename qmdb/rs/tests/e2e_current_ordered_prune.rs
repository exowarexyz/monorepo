//! Ordered current-batch publications across local bitmap-chunk pruning.
//!
//! Remote current roots must match the source at every batch's watermark. Remote proofs
//! must match it at the initial commit, at the first watermark merkleized over pruned
//! chunks, at the last watermark, and at historical watermarks for keys that later
//! batches expire.

mod common;

use commonware_cryptography::Sha256;
use commonware_runtime::{
    buffer::paged::CacheRef, tokio as cw_tokio, Runner as _, Supervisor as _,
};
use commonware_storage::{
    merkle::{mmr, Location},
    qmdb::{
        any::ordered::variable::{Operation as OrderedOp, Update as OrderedUpdate},
        current::ordered::variable::Db as LocalOrderedDb,
        operation::Operation as _,
    },
    translator::TwoCap,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::{adapter::upload::Publication, MAX_OPERATION_SIZE};

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type Db = LocalOrderedDb<
    mmr::Family,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    N,
    commonware_parallel::Sequential,
>;
type OrderedPublication = Publication<mmr::Family, Digest, OrderedUpdate<Vec<u8>, Vec<u8>>, N>;

/// Each batch appends 3 fresh writes and rewrites the key 3 counter-positions
/// behind. With `N = 32` a bitmap chunk spans 256 bits, so 150 batches prune
/// chunk 0 and publish later batches over a pruned bitmap.
const BATCHES: u64 = 150;

struct BatchOutcome {
    watermark: Location<mmr::Family>,
    root: Digest,
    publication: OrderedPublication,
}

struct ExpiredKeySnapshot {
    watermark: Location<mmr::Family>,
    root: Digest,
    key: Vec<u8>,
    value: Vec<u8>,
}

#[tokio::test]
async fn test_mirror_ordered_prune_past_chunk_zero() {
    let store_client = common::local_store_client().await;

    // Phase 1 (blocking tokio runtime): drive the local QMDB through BATCHES
    // batches, capturing the initial publication and each batch's publication
    // and root, including after chunk 0 has been pruned.
    let (initial, batches, first_pruned, expired_key_snapshot) =
        tokio::task::spawn_blocking(move || {
            cw_tokio::Runner::default().start(move |context| async move {
                let page_cache = CacheRef::new(NZU16!(64), NZUsize!(8));
                let cfg = common::current_variable_config(
                    "current_ordered_variable_mmr_pruned_source",
                    page_cache,
                    (
                        ((0..=MAX_OPERATION_SIZE).into(), ()),
                        ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ),
                    NZU64!(8),
                );
                let mut db: Db = Db::init(
                    context.child("current_ordered_variable_mmr_pruned_source"),
                    cfg,
                    None,
                )
                .await
                .expect("init");
                let initial =
                    Publication::initial(&db).expect("initial publication must be readable");

                let mut counter: u64 = 0;
                let mut batches: Vec<BatchOutcome> = Vec::with_capacity(BATCHES as usize);
                let mut expired_key_snapshot = None;

                for _ in 0..BATCHES {
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
                        if counter == 12 {
                            batch = batch.write(b"k-00000006".to_vec(), None);
                        }
                        counter += 3;
                        batch.merkleize(&db).await.expect("merkleize")
                    };
                    let publication = Publication::from_batch(&finalized, &db)
                        .expect("publication must be readable");
                    db = db.apply_batch(finalized).await.expect("apply");

                    // Prune the operation log, bitmap, and grafted nodes as far as the sync
                    // boundary permits.
                    let prune_boundary = db.sync_boundary();
                    db = db.prune(prune_boundary).await.expect("prune current");

                    let latest = db.bounds().end - 1;
                    if counter == 9 {
                        expired_key_snapshot = Some(ExpiredKeySnapshot {
                            watermark: latest,
                            root: db.root(),
                            key: b"k-00000006".to_vec(),
                            value: b"v-00000006".to_vec(),
                        });
                    }
                    batches.push(BatchOutcome {
                        watermark: latest,
                        root: db.root(),
                        publication,
                    });
                }

                // The source must merkleize a batch over pruned bitmap chunks, or no
                // publication comes from a pruned source.
                let first_pruned = batches
                    .iter()
                    .position(|outcome| outcome.publication.pruned_chunks > 0)
                    .expect("source must merkleize a batch over pruned bitmap chunks");

                db = db.sync().await.expect("sync");
                db.destroy().await.expect("destroy");
                (
                    initial,
                    batches,
                    first_pruned,
                    expired_key_snapshot.expect("expired key snapshot"),
                )
            })
        })
        .await
        .expect("join");

    // Phase 2: upload each publication to the remote store and read it back
    // through an ordered reader.
    let upload_client = store_client.unprefixed();
    let qmdb_client: exoware_qmdb::adapter::Ordered<mmr::Family, Sha256, Vec<u8>, Vec<u8>, N> =
        exoware_qmdb::adapter::Ordered::new(
            store_client.unprefixed(),
            (
                ((0..=MAX_OPERATION_SIZE).into(), ()),
                ((0..=MAX_OPERATION_SIZE).into(), ()),
            ),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        );

    // The initial publication serves current reads at location 0 before any batch.
    common::commit_publications(&upload_client, std::slice::from_ref(&initial))
        .await
        .expect("initial upload must succeed");
    assert_eq!(
        qmdb_client
            .root_at(Location::new(0))
            .await
            .expect("root at the initial commit must load"),
        initial.root
    );
    let initial_range = qmdb_client
        .current_operation_range(Location::new(0), Location::new(0), 1, None)
        .await
        .expect("operation range at the initial commit must verify");
    assert_eq!(initial_range.root, initial.root);
    assert_eq!(initial_range.operations, *initial.operations);

    // The remote root at each batch's watermark must equal the source root.
    for outcome in &batches {
        common::commit_publications(&upload_client, std::slice::from_ref(&outcome.publication))
            .await
            .expect("upload");
        let remote_root = qmdb_client
            .root_at(outcome.watermark)
            .await
            .expect("root_at");
        assert_eq!(
            remote_root, outcome.root,
            "remote current_root disagrees with local at watermark {}",
            outcome.watermark
        );
    }

    // At the first watermark merkleized over pruned chunks and at the last
    // watermark, a key the batch wrote and the batch's own operations must
    // verify against the source root.
    for index in [first_pruned, batches.len() - 1] {
        let outcome = &batches[index];
        let key = format!("k-{:08x}", 3 * index).into_bytes();
        let value = format!("v-{:08x}", 3 * index).into_bytes();
        let key_proof = qmdb_client
            .get(outcome.watermark, &key, None)
            .await
            .expect("key written at a pruned watermark must verify");
        assert_eq!(key_proof.root, outcome.root);
        match &key_proof.operation {
            OrderedOp::Update(update) => {
                assert_eq!(update.key, key);
                assert_eq!(update.value, value);
            }
            _ => panic!("a key written at a pruned watermark must read as an Update operation"),
        }
        let publication = &outcome.publication;
        let range = qmdb_client
            .current_operation_range(
                outcome.watermark,
                publication.start_location,
                publication.operations.len() as u32,
                None,
            )
            .await
            .expect("operations appended at a pruned watermark must verify");
        assert_eq!(range.root, outcome.root);
        assert_eq!(range.operations, *publication.operations);
    }

    // The first batch's watermark must keep its root after every later batch is
    // published.
    let first = &batches[0];
    let remote_root_old = qmdb_client
        .root_at(first.watermark)
        .await
        .expect("root_at (old watermark)");
    assert_eq!(
        remote_root_old, first.root,
        "remote current_root at first watermark disagrees with local root"
    );

    // `k-00000006` is present at the captured old watermark, then rewritten
    // and deleted by later batches. Verifying it after all uploads proves
    // historical current-state proofs use the requested watermark's root and
    // update index, not the final active-key set.
    let expired_key_proof = qmdb_client
        .get(
            expired_key_snapshot.watermark,
            &expired_key_snapshot.key,
            None,
        )
        .await
        .expect("old watermark proof for later-expired key");
    assert_eq!(expired_key_proof.root, expired_key_snapshot.root);
    match &expired_key_proof.operation {
        OrderedOp::Update(update) => {
            assert_eq!(update.key, expired_key_snapshot.key);
            assert_eq!(update.value, expired_key_snapshot.value);
        }
        _ => panic!("expected Update operation for old expired-key proof"),
    }

    // The expired key must be inactive at the final watermark.
    let final_watermark = batches.last().expect("at least one batch").watermark;
    let latest_err = qmdb_client
        .get(final_watermark, &expired_key_snapshot.key, None)
        .await
        .expect_err("expired key should be inactive at final watermark");
    match latest_err {
        exoware_qmdb::QmdbError::KeyNotActive { .. }
        | exoware_qmdb::QmdbError::ProofKeyNotFound { .. } => {}
        other => panic!("unexpected final expired-key error: {other:?}"),
    }

    // A range read at the first watermark must verify against that watermark's root.
    let old_range = qmdb_client
        .get_range(
            first.watermark,
            b"k-00000000".to_vec(),
            Some(b"k-00000001".to_vec()),
            10,
            None,
        )
        .await
        .expect("old watermark range proof");
    assert_eq!(old_range.entries.len(), 1);
    let entry = &old_range.entries[0];
    assert_eq!(entry.operation.key(), Some(&b"k-00000000".to_vec()));
    assert_eq!(entry.root, first.root);
}
