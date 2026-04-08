//! Ordered QMDB E2E: run a local Commonware ordered DB, upload its
//! operations + current boundary state to a live store stack, then
//! verify roots and proofs match.

mod common;

use std::num::NonZeroU64;

use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::{
    current::{ordered::variable::Db as LocalQmdbDb, VariableConfig},
    store::LogStore as _,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use store_qmdb::MAX_OPERATION_SIZE;
use store_qmdb::{
    build_current_boundary_state, BatchOperation, CurrentBoundaryState, OrderedClient,
    BITMAP_CHUNK_BYTES,
};

use common::retry;

type Digest = commonware_cryptography::sha256::Digest;
type BatchProof = commonware_storage::mmr::Proof<Digest>;
type LocalDb = LocalQmdbDb<
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    commonware_cryptography::Sha256,
    TwoCap,
    BITMAP_CHUNK_BYTES,
>;

struct LocalReference {
    latest_location: Location,
    operations: Vec<BatchOperation>,
    current_boundary: CurrentBoundaryState,
    values: std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

async fn build_local_db() -> LocalReference {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
            let cfg = VariableConfig {
                mmr_journal_partition: "mmr-journal".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                mmr_metadata_partition: "mmr-metadata".into(),
                log_partition: "log".into(),
                log_write_buffer: NZUsize!(1024),
                log_compression: None,
                log_codec_config: (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                log_items_per_blob: NZU64!(8),
                grafted_mmr_metadata_partition: "grafted-metadata".into(),
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };
            let mut db: LocalDb = LocalDb::init(context.with_label("qmdb"), cfg)
                .await
                .expect("init");

            let finalized = {
                let mut batch = db.new_batch();
                batch.write(b"alpha".to_vec(), Some(b"one".to_vec()));
                batch.write(b"beta".to_vec(), Some(b"two".to_vec()));
                batch.merkleize(None::<Vec<u8>>).await.expect("merkleize")
            };
            db.apply_batch(finalized.finalize()).await.expect("apply");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops): (BatchProof, Vec<BatchOperation>) = db
                .ops_historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");

            let boundary = build_current_boundary_state(None, &ops).await;

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

#[tokio::test]
async fn ordered_round_trip() {
    let (_dir, _server, client) = common::local_store_client().await;
    let local = build_local_db().await;

    retry(
        || {
            let c = OrderedClient::from_client(client.clone());
            let ops = local.operations.clone();
            let loc = local.latest_location;
            async move { c.upload_operations(loc, &ops).await.map(|_| ()) }
        },
        "upload_operations",
    )
    .await;

    retry(
        || {
            let c = OrderedClient::from_client(client.clone());
            let boundary = local.current_boundary.clone();
            let loc = local.latest_location;
            async move { c.upload_current_boundary_state(loc, &boundary).await }
        },
        "upload_current_boundary_state",
    )
    .await;

    retry(
        || {
            let c = OrderedClient::from_client(client.clone());
            let loc = local.latest_location;
            async move { c.publish_writer_location_watermark(loc).await.map(|_| ()) }
        },
        "publish_watermark",
    )
    .await;

    let c = OrderedClient::from_client(client.clone());
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
            Location::new(0),
            local.operations.len() as u32,
        )
        .await
        .expect("proof");
    assert!(proof.verify(), "proof must verify");
    assert_eq!(proof.operations, local.operations);
}
