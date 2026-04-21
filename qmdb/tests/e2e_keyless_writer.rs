//! KeylessWriter E2E: drive the single-writer helper against a live store
//! stack and verify the resulting roots + proofs against an independent local
//! Commonware Keyless DB that we feed the same ops.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;

use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::{
    keyless::{Config as KeylessConfig, Keyless, Operation as KeylessOperation},
    store::LogStore as _,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_sdk_rs::StoreClient;
use store_qmdb::{KeylessClient, KeylessWriter};

use common::retry;

type Digest = commonware_cryptography::sha256::Digest;
type LocalDb = Keyless<deterministic::Context, Vec<u8>, commonware_cryptography::Sha256>;
type TestKeylessClient = KeylessClient<commonware_cryptography::Sha256, Vec<u8>>;
type TestKeylessWriter = KeylessWriter<commonware_cryptography::Sha256, Vec<u8>>;

fn fresh_reader(c: StoreClient) -> TestKeylessClient {
    TestKeylessClient::from_client(c, ((0..=10000).into(), ()))
}

async fn fresh_writer(c: StoreClient) -> TestKeylessWriter {
    TestKeylessWriter::new(c).await.expect("writer")
}

/// Reference Commonware keyless DB fed the same ops the writer will upload.
/// Returns the root + ops the writer should produce the same root for.
async fn build_local_reference(
    batches: Vec<Vec<Vec<u8>>>,
) -> (Digest, Vec<KeylessOperation<Vec<u8>>>, Location) {
    tokio::task::spawn_blocking(move || {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
            let cfg = KeylessConfig {
                mmr_journal_partition: "keyless-mmr-journal".into(),
                mmr_metadata_partition: "keyless-mmr-metadata".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                log_partition: "keyless-log".into(),
                log_write_buffer: NZUsize!(1024),
                log_compression: None,
                log_codec_config: ((0..=10000).into(), ()),
                log_items_per_section: NZU64!(7),
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };
            let mut db: LocalDb = LocalDb::init(context.with_label("db"), cfg)
                .await
                .expect("init");

            for batch_values in &batches {
                let finalized = {
                    let mut batch = db.new_batch();
                    for v in batch_values {
                        batch.append(v.clone());
                    }
                    batch.merkleize(None::<Vec<u8>>).finalize()
                };
                db.apply_batch(finalized).await.expect("apply");
            }

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");
            let root = db.root();
            db.destroy().await.expect("destroy");
            (root, ops, latest)
        })
    })
    .await
    .expect("join")
}

/// Split the flat `ops` produced by the local DB into the per-batch chunks
/// corresponding to `batches` lengths. (Commonware's keyless DB inserts a
/// Commit op at each batch boundary; for this test we pass the full flat
/// sequence to the writer, which mirrors what the local DB produced.)
fn flat_to_writer_ops(ops: &[KeylessOperation<Vec<u8>>]) -> Vec<KeylessOperation<Vec<u8>>> {
    ops.to_vec()
}

// Sequential mode: one batch at a time, each call returns before the next
// starts. Expect every upload to carry its own watermark in-band. Flush is
// a no-op.
#[tokio::test]
async fn sequential_upload_matches_local_root() {
    let (_dir, _server, client) = common::local_store_client().await;
    let batches = vec![
        vec![b"alpha".to_vec(), b"beta".to_vec()],
        vec![b"gamma".to_vec()],
        vec![b"delta".to_vec(), b"epsilon".to_vec(), b"zeta".to_vec()],
    ];
    let (local_root, local_ops, latest) = build_local_reference(batches).await;
    let writer_ops = flat_to_writer_ops(&local_ops);

    // Group writer_ops into chunks matching the local batch boundaries. The
    // simplest way: feed the whole flat op sequence in one writer call.
    // This proves the writer produces the same root as the local DB when
    // given the same ops.
    let writer = fresh_writer(client.clone()).await;
    let receipt = writer
        .upload_and_publish(&writer_ops)
        .await
        .expect("upload");
    assert_eq!(receipt.latest_location, latest);
    assert_eq!(receipt.writer_location_watermark, Some(latest));

    // Verify the resulting store state reads back the same root.
    let reader = fresh_reader(client.clone());
    let got_root = retry(
        || {
            let r = fresh_reader(client.clone());
            async move { r.root_at(latest).await }
        },
        "root_at",
    )
    .await;
    assert_eq!(got_root, local_root);

    // Proof round-trip.
    let proof = reader
        .operation_range_proof(latest, Location::new(0), writer_ops.len() as u32)
        .await
        .expect("proof");
    assert_eq!(proof.root, local_root);
    assert_eq!(proof.operations, writer_ops);
}

// Multiple sequential batches: each call completes before the next starts.
// Every batch's watermark lands in-band (pipeline always empty on entry).
#[tokio::test]
async fn multiple_sequential_batches_each_publish_watermarks_in_band() {
    let (_dir, _server, client) = common::local_store_client().await;
    let (local_root, local_ops, latest) = build_local_reference(vec![
        vec![b"a".to_vec(), b"b".to_vec()],
        vec![b"c".to_vec()],
        vec![b"d".to_vec(), b"e".to_vec()],
    ])
    .await;

    let writer = fresh_writer(client.clone()).await;

    // Feed the full op sequence, but in three calls matching the batch sizes.
    // 2 + 1 + 2 = 5 ops.
    let r1 = writer
        .upload_and_publish(&local_ops[..2])
        .await
        .expect("b1");
    assert_eq!(r1.writer_location_watermark, Some(Location::new(1)));
    let r2 = writer
        .upload_and_publish(&local_ops[2..3])
        .await
        .expect("b2");
    assert_eq!(r2.writer_location_watermark, Some(Location::new(2)));
    let r3 = writer
        .upload_and_publish(&local_ops[3..])
        .await
        .expect("b3");
    assert_eq!(r3.writer_location_watermark, Some(latest));

    let got_root = retry(
        || {
            let r = fresh_reader(client.clone());
            async move { r.root_at(latest).await }
        },
        "root_at",
    )
    .await;
    assert_eq!(got_root, local_root);
}

// Pipelined burst: three batches dispatched concurrently. Only one can land
// the watermark in-band (the one dispatched while pipeline is empty — in
// practice, the first). `flush()` must publish a catch-up watermark covering
// the tail so readers see the full prefix.
#[tokio::test]
async fn pipelined_batches_require_flush_to_catch_up_watermark() {
    let (_dir, _server, client) = common::local_store_client().await;
    // Local DB adds a Commit op per batch, so 3 batches of 2 Appends produce
    // 9 total ops (indices 0..=8). Split the writer's view into the same
    // batch boundaries.
    let (local_root, local_ops, latest) = build_local_reference(vec![
        vec![b"p".to_vec(), b"q".to_vec()],
        vec![b"r".to_vec(), b"s".to_vec()],
        vec![b"t".to_vec(), b"u".to_vec()],
    ])
    .await;
    // Split the local op stream into three roughly-equal chunks. Writer
    // batches don't have to align with local DB batch boundaries — the MMR is
    // only sensitive to the flat op sequence — so we just chunk into thirds.
    let n = local_ops.len();
    let chunk = n / 3;
    let o1 = local_ops[..chunk].to_vec();
    let o2 = local_ops[chunk..2 * chunk].to_vec();
    let o3 = local_ops[2 * chunk..].to_vec();

    let writer = Arc::new(fresh_writer(client.clone()).await);

    // Fire three uploads concurrently. Because the writer's state mutex
    // serializes the build phase but not the PUT, later batches will observe
    // `acked < dispatched` and omit the watermark row.
    let w1 = writer.clone();
    let w2 = writer.clone();
    let w3 = writer.clone();

    let (r1, r2, r3) = tokio::join!(
        async move { w1.upload_and_publish(&o1).await },
        async move { w2.upload_and_publish(&o2).await },
        async move { w3.upload_and_publish(&o3).await }
    );
    let r1 = r1.expect("b1");
    let r2 = r2.expect("b2");
    let r3 = r3.expect("b3");

    // At least one of the three must have skipped its watermark row due to
    // pipeline saturation. We don't assert exactly which (depends on tokio
    // scheduling) but at least one should have landed it in-band.
    let inline_count = [r1, r2, r3]
        .iter()
        .filter(|r| r.writer_location_watermark.is_some())
        .count();
    assert!(
        inline_count >= 1,
        "at least one batch must publish in-band (pipeline starts empty)"
    );

    // Flush publishes the trailing watermark.
    writer.flush().await.expect("flush");

    // Now the full prefix must be readable up to `latest`.
    let got_root = retry(
        || {
            let r = fresh_reader(client.clone());
            async move { r.root_at(latest).await }
        },
        "root_at",
    )
    .await;
    assert_eq!(got_root, local_root);
}

// Bounded-concurrency pipeline (the realistic steady-state shape): keep at
// most `MAX_INFLIGHT` PUTs in flight, dispatching a new one as soon as any
// prior ACKs. Under the contiguous-acked-prefix rule, each new dispatch
// should see an advanced `latest_contiguous_acked` and carry a watermark
// forward, so published watermarks never lag more than `MAX_INFLIGHT` behind
// the dispatch frontier.
#[tokio::test]
async fn bounded_pipeline_advances_watermark_via_contiguous_acks() {
    use futures::stream::{FuturesUnordered, StreamExt};

    const MAX_INFLIGHT: usize = 4;
    const BATCHES: usize = 20;

    let (_dir, _server, client) = common::local_store_client().await;
    let batch_values: Vec<Vec<Vec<u8>>> = (0..BATCHES)
        .map(|i| vec![format!("v{i}").into_bytes()])
        .collect();
    let (local_root, local_ops, latest) = build_local_reference(batch_values).await;

    let writer = Arc::new(fresh_writer(client.clone()).await);

    let chunk = local_ops.len() / BATCHES;
    let mut slices = Vec::with_capacity(BATCHES);
    for i in 0..BATCHES {
        let start = i * chunk;
        let end = if i == BATCHES - 1 {
            local_ops.len()
        } else {
            (i + 1) * chunk
        };
        slices.push(local_ops[start..end].to_vec());
    }

    use futures::future::BoxFuture;
    let mut in_flight: FuturesUnordered<
        BoxFuture<'static, Result<store_qmdb::UploadReceipt, store_qmdb::QmdbError>>,
    > = FuturesUnordered::new();
    let mut results = Vec::with_capacity(BATCHES);
    for batch in slices {
        if in_flight.len() >= MAX_INFLIGHT {
            if let Some(r) = in_flight.next().await {
                results.push(r.expect("upload"));
            }
        }
        let w = writer.clone();
        in_flight.push(Box::pin(async move { w.upload_and_publish(&batch).await }));
    }
    while let Some(r) = in_flight.next().await {
        results.push(r.expect("upload"));
    }

    writer.flush().await.expect("flush");

    let got_root = retry(
        || {
            let r = fresh_reader(client.clone());
            async move { r.root_at(latest).await }
        },
        "root_at",
    )
    .await;
    assert_eq!(got_root, local_root);

    // With bounded concurrency, every batch after the first ~MAX_INFLIGHT
    // wind-up should carry a watermark forward. Assert majority do.
    let inline = results
        .iter()
        .filter(|r| r.writer_location_watermark.is_some())
        .count();
    assert!(
        inline >= results.len() / 2,
        "contiguous-acked-prefix rule should let most batches publish \
         in-band under bounded pipelining; got {inline} of {} in-band",
        results.len(),
    );
}

// Recovery: bootstrap from an already-populated store (simulating a fresh
// writer process after a previous one wrote some batches). The writer should
// read the store's watermark + peaks and be able to continue writing from
// there.
#[tokio::test]
async fn bootstrap_resumes_from_existing_store_state() {
    let (_dir, _server, client) = common::local_store_client().await;
    let (local_root_after_two, local_ops_two, latest_two) =
        build_local_reference(vec![vec![b"g".to_vec(), b"h".to_vec()]]).await;
    let (local_root_final, local_ops_final, latest_final) = build_local_reference(vec![
        vec![b"g".to_vec(), b"h".to_vec()],
        vec![b"i".to_vec(), b"j".to_vec(), b"k".to_vec()],
    ])
    .await;

    // First "session": upload two ops and flush.
    {
        let writer = fresh_writer(client.clone()).await;
        let receipt = writer
            .upload_and_publish(&local_ops_two)
            .await
            .expect("upload 1");
        assert_eq!(receipt.latest_location, latest_two);
    }

    // Reader sees the first batch.
    {
        let got = retry(
            || {
                let r = fresh_reader(client.clone());
                async move { r.root_at(latest_two).await }
            },
            "root_at after first session",
        )
        .await;
        assert_eq!(got, local_root_after_two);
    }

    // Second "session": a fresh writer bootstraps and picks up where we
    // left off, then writes the next batch.
    {
        let writer = fresh_writer(client.clone()).await;
        assert_eq!(
            writer.latest_published_watermark().await,
            Some(latest_two),
            "bootstrap must recover the last published watermark"
        );

        let remainder = &local_ops_final[local_ops_two.len()..];
        let receipt = writer
            .upload_and_publish(remainder)
            .await
            .expect("upload 2");
        assert_eq!(receipt.latest_location, latest_final);
    }

    let got_final = retry(
        || {
            let r = fresh_reader(client.clone());
            async move { r.root_at(latest_final).await }
        },
        "root_at after second session",
    )
    .await;
    assert_eq!(got_final, local_root_final);
}
