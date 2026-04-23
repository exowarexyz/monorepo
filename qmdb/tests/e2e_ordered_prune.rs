//! Regression for the ordered current-boundary recovery path across local
//! bitmap-chunk pruning. Drives enough batches that the local
//! `current::ordered::Db` prunes its first bitmap chunk (locations 0..=255
//! fall below the inactivity floor), and verifies:
//!
//! 1. `recover_boundary_state` no longer requests a range proof at the
//!    previous batch's `CommitFloor` location, so the writer does not panic
//!    with `operation pruned: Location(255)` once chunk 0 is pruned.
//! 2. The remote `current_root_at` matches the local root at every batch
//!    boundary, including old watermarks where the stored bitmap chunk still
//!    carries an unmasked stale `CommitFloor` bit. The server-side masking in
//!    `load_bitmap_chunk` folds that bit to 0 at read time.

mod common;

use std::num::NonZeroU64;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::{buffer::paged::CacheRef, Metrics as _, Runner as _};
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::{
    any::ordered::variable::Operation as OrderedOp,
    current::{ordered::variable::Db as LocalOrderedDb, VariableConfig as OrderedVariableConfig},
    store::LogStore as _,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use store_qmdb::{
    recover_boundary_state, CurrentBoundaryState, OrderedClient, OrderedWriter, MAX_OPERATION_SIZE,
};

const N: usize = 32;
type Digest = commonware_cryptography::sha256::Digest;
type BatchOp = OrderedOp<Vec<u8>, Vec<u8>>;
type LocalDb = LocalOrderedDb<cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap, N>;

/// Each batch appends 3 fresh writes and rewrites the key 3 counter-positions
/// behind. With `N = 32` the bitmap chunk spans 256 bits; the inactivity floor
/// crosses 256 after roughly ~85 batches, so 150 comfortably forces chunk 0 to
/// be pruned (and then exercises several more post-prune batches).
const BATCHES: u64 = 150;

struct BatchOutcome {
    watermark: Location,
    root: Digest,
    delta_ops: Vec<BatchOp>,
    boundary: CurrentBoundaryState<Digest, N>,
}

async fn boundary_from_db(
    db: &LocalDb,
    previous_ops: Option<&[BatchOp]>,
    operations: &[BatchOp],
) -> CurrentBoundaryState<Digest, N> {
    recover_boundary_state::<Sha256, _, _, N, _, _>(
        previous_ops,
        operations,
        db.root(),
        |location| async move {
            let mut hasher = Sha256::default();
            let (proof, mut proof_ops, mut chunks) = db
                .range_proof(&mut hasher, location, NZU64!(1))
                .await
                .map_err(|e| {
                    store_qmdb::QmdbError::CorruptData(format!(
                        "local current range proof at {location}: {e}"
                    ))
                })?;
            proof_ops.pop().ok_or_else(|| {
                store_qmdb::QmdbError::CorruptData(format!(
                    "local current range proof at {location} returned no ops"
                ))
            })?;
            let chunk = chunks.pop().ok_or_else(|| {
                store_qmdb::QmdbError::CorruptData(format!(
                    "local current range proof at {location} returned no chunks"
                ))
            })?;
            Ok((proof.proof, chunk))
        },
    )
    .await
    .expect("recover_boundary_state")
}

#[tokio::test]
async fn mirror_ordered_prune_past_chunk_zero() {
    let (_dir, _server, client) = common::local_store_client().await;

    // Phase 1 (blocking tokio runtime): drive the local QMDB through BATCHES
    // batches, capturing each batch's delta, root, and boundary delta. The
    // boundary recovery must not panic even once chunk 0 has been pruned.
    let (batches, chunk_zero_pruned) = tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(move |context| async move {
            let cfg = OrderedVariableConfig {
                mmr_journal_partition: "prune-mmr-journal".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                mmr_metadata_partition: "prune-mmr-metadata".into(),
                log_partition: "prune-log".into(),
                log_write_buffer: NZUsize!(1024),
                log_compression: None,
                log_codec_config: (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                log_items_per_blob: NZU64!(8),
                grafted_mmr_metadata_partition: "prune-grafted-metadata".into(),
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };
            let mut db: LocalDb = LocalDb::init(context.with_label("db"), cfg)
                .await
                .expect("init");

            let mut previous_ops: Vec<BatchOp> = Vec::new();
            let mut counter: u64 = 0;
            let mut batches: Vec<BatchOutcome> = Vec::with_capacity(BATCHES as usize);

            for _ in 0..BATCHES {
                let finalized = {
                    let mut batch = db.new_batch();
                    for offset in 0..3u64 {
                        let key = format!("k-{:08x}", counter + offset).into_bytes();
                        let value = format!("v-{:08x}", counter + offset).into_bytes();
                        batch.write(key, Some(value));
                    }
                    if counter >= 3 {
                        let rewrite_key = format!("k-{:08x}", counter - 3).into_bytes();
                        let rewrite_value = format!("v-{:08x}-r", counter).into_bytes();
                        batch.write(rewrite_key, Some(rewrite_value));
                    }
                    counter += 3;
                    batch.merkleize(None::<Vec<u8>>).await.expect("merkleize")
                };
                db.apply_batch(finalized.finalize()).await.expect("apply");

                let latest = db.bounds().await.end - 1;
                let total = NonZeroU64::new(*latest + 1).expect("non-zero");
                let (_proof, cumulative) = db
                    .ops_historical_proof(latest + 1, Location::new(0), total)
                    .await
                    .expect("ops_historical_proof");
                let previous_slice = if previous_ops.is_empty() {
                    None
                } else {
                    Some(previous_ops.as_slice())
                };
                let boundary = boundary_from_db(&db, previous_slice, &cumulative).await;
                let delta_ops: Vec<BatchOp> = cumulative[previous_ops.len()..].to_vec();
                batches.push(BatchOutcome {
                    watermark: latest,
                    root: db.root(),
                    delta_ops,
                    boundary,
                });
                previous_ops = cumulative;
            }

            // Probe whether the bitmap-level chunk 0 has been pruned by
            // asking for a range proof at Location(0); this is exactly the
            // failure mode `current::Db` exhibits once the inactivity floor
            // crosses the first chunk boundary.
            let chunk_zero_pruned = {
                let mut hasher = Sha256::default();
                match db.range_proof(&mut hasher, Location::new(0), NZU64!(1)).await {
                    Err(e) => e.to_string().contains("operation pruned"),
                    Ok(_) => false,
                }
            };
            db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");
            (batches, chunk_zero_pruned)
        })
    })
    .await
    .expect("join");

    // The bitmap-level chunk 0 must be pruned by the time we stop, otherwise
    // we are not exercising the failure mode this regression covers.
    assert!(
        chunk_zero_pruned,
        "expected local DB to prune bitmap chunk 0; test did not exercise the failure mode"
    );

    // Phase 2: mirror each batch to the remote store and verify current_root
    // agrees with the local root at THAT batch's watermark. For batches
    // uploaded after chunk 0's last republish, the stored chunk 0 payload on
    // the remote still carries the bit of the CommitFloor that was current
    // when it was last published; the server-side masking in
    // `load_bitmap_chunk` must fold that bit to 0 for the root recomputation
    // to match.
    let writer: OrderedWriter<Sha256, Vec<u8>, Vec<u8>, N> = OrderedWriter::empty(client.clone());
    let reader: OrderedClient<Sha256, Vec<u8>, Vec<u8>, N> = OrderedClient::from_client(
        client.clone(),
        (
            ((0..=MAX_OPERATION_SIZE).into(), ()),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
        (
            ((0..=MAX_OPERATION_SIZE).into(), ()),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
    );

    for outcome in &batches {
        writer
            .upload_and_publish(&outcome.delta_ops, &outcome.boundary)
            .await
            .expect("upload");
        let remote_root = reader
            .current_root_at(outcome.watermark)
            .await
            .expect("current_root_at");
        assert_eq!(
            remote_root, outcome.root,
            "remote current_root disagrees with local at watermark {}",
            outcome.watermark
        );
    }

    // Spot-check that old watermarks still verify: re-query the very first
    // batch's watermark after all later batches have been published. This
    // hits `load_bitmap_chunk` for chunk 0 at an old watermark whose stored
    // value predates every subsequent CommitFloor, forcing the mask path.
    let first = &batches[0];
    let remote_root_old = reader
        .current_root_at(first.watermark)
        .await
        .expect("current_root_at (old watermark)");
    assert_eq!(
        remote_root_old, first.root,
        "remote current_root at first watermark disagrees with local root"
    );
}
