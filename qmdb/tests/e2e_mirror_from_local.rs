//! Mirror-from-local E2E: drives a local Commonware QMDB as the authoritative
//! source of truth and uses the corresponding `*Writer` to push the full
//! state into an Exoware store. Exercises all four variants in the canonical
//! "caller owns durability" shape:
//!
//!   1. Apply batches to the local Db.
//!   2. Pull ops via `historical_proof` (or `ops_historical_proof` for
//!      ordered).
//!   3. Feed to `*Writer::upload_and_publish`.
//!   4. Verify the remote root matches the local root.
//!   5. Simulate a restart: create a fresh writer, which auto-bootstraps from
//!      the store's last watermark. Apply more local batches, resume the
//!      writer from `watermark + 1`, verify again.

mod common;

use std::num::NonZeroU64;

use commonware_cryptography::Sha256;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Metrics as _, Runner as _};
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::{
    any::{unordered::variable::Db as LocalUnorderedDb, VariableConfig as UnorderedVariableConfig},
    current::{ordered::variable::Db as LocalOrderedDb, VariableConfig as OrderedVariableConfig},
    immutable::{Config as ImmutableConfig, Immutable, Operation as ImmutableOperation},
    keyless::{Config as KeylessConfig, Keyless, Operation as KeylessOperation},
    store::LogStore as _,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use store_qmdb::{
    build_current_boundary_state, CurrentBoundaryState, ImmutableClient, ImmutableWriter,
    KeylessClient, KeylessWriter, OrderedClient, OrderedWriter, UnorderedClient, UnorderedWriter,
    MAX_OPERATION_SIZE,
};

type Digest = commonware_cryptography::sha256::Digest;

// -------------------- Keyless --------------------

#[tokio::test]
async fn mirror_keyless_from_local() {
    let (_dir, _server, client) = common::local_store_client().await;

    // Session 1: apply one batch locally, mirror.
    let (ops1, latest1, root1) = run_keyless_local(vec![vec![
        b"alpha".to_vec(),
        b"beta".to_vec(),
        b"gamma".to_vec(),
    ]])
    .await;
    let writer: KeylessWriter<Sha256, Vec<u8>> =
        KeylessWriter::new(client.clone()).await.expect("writer");
    writer.upload_and_publish(&ops1).await.expect("upload 1");
    let reader: KeylessClient<Sha256, Vec<u8>> =
        KeylessClient::from_client(client.clone(), ((0..=MAX_OPERATION_SIZE).into(), ()));
    assert_eq!(
        reader.root_at(latest1).await.expect("root_at 1"),
        root1,
        "remote root must match local (after batch 1)"
    );

    // Session 2: fresh writer bootstraps from the store's state, picks up
    // where we left off. Apply another batch locally; caller slices the
    // delta off using the recovered watermark.
    let (ops_total, latest2, root2) = run_keyless_local(vec![
        vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()],
        vec![b"delta".to_vec(), b"epsilon".to_vec()],
    ])
    .await;
    let writer2: KeylessWriter<Sha256, Vec<u8>> =
        KeylessWriter::new(client.clone()).await.expect("writer 2");
    let recovered = writer2
        .latest_published_watermark()
        .await
        .expect("bootstrap found watermark");
    assert_eq!(recovered, latest1);
    let delta = &ops_total[ops1.len()..];
    writer2.upload_and_publish(delta).await.expect("upload 2");
    assert_eq!(
        reader.root_at(latest2).await.expect("root_at 2"),
        root2,
        "remote root must match local (after batch 2)"
    );
}

async fn run_keyless_local(
    batches: Vec<Vec<Vec<u8>>>,
) -> (Vec<KeylessOperation<Vec<u8>>>, Location, Digest) {
    tokio::task::spawn_blocking(move || {
        deterministic::Runner::default().start(|context| async move {
            let cfg = KeylessConfig {
                mmr_journal_partition: "mirror-keyless-mmr-journal".into(),
                mmr_metadata_partition: "mirror-keyless-mmr-metadata".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                log_partition: "mirror-keyless-log".into(),
                log_write_buffer: NZUsize!(1024),
                log_compression: None,
                log_codec_config: ((0..=MAX_OPERATION_SIZE).into(), ()),
                log_items_per_section: NZU64!(7),
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };
            let mut db: Keyless<deterministic::Context, Vec<u8>, Sha256> =
                Keyless::init(context.with_label("db"), cfg)
                    .await
                    .expect("init");
            for batch in batches {
                let finalized = {
                    let mut b = db.new_batch();
                    for v in batch {
                        b.append(v);
                    }
                    b.merkleize(None::<Vec<u8>>).finalize()
                };
                db.apply_batch(finalized).await.expect("apply");
            }
            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("historical_proof");
            let root = db.root();
            db.destroy().await.expect("destroy");
            (ops, latest, root)
        })
    })
    .await
    .expect("join")
}

// -------------------- Unordered --------------------

type UnorderedOp = commonware_storage::qmdb::any::unordered::variable::Operation<Vec<u8>, Vec<u8>>;

#[tokio::test]
async fn mirror_unordered_from_local() {
    let (_dir, _server, client) = common::local_store_client().await;

    let (ops1, latest1, root1) = run_unordered_local(vec![vec![
        (b"alpha".to_vec(), Some(b"one".to_vec())),
        (b"beta".to_vec(), Some(b"two".to_vec())),
    ]])
    .await;
    let writer: UnorderedWriter<Sha256, Vec<u8>, Vec<u8>> =
        UnorderedWriter::new(client.clone()).await.expect("writer");
    writer.upload_and_publish(&ops1).await.expect("upload 1");
    let reader: UnorderedClient<Sha256, Vec<u8>, Vec<u8>> = UnorderedClient::from_client(
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
    assert_eq!(
        reader.root_at(latest1).await.expect("root_at 1"),
        root1,
        "remote root must match local (after batch 1)"
    );

    let (ops_total, latest2, root2) = run_unordered_local(vec![
        vec![
            (b"alpha".to_vec(), Some(b"one".to_vec())),
            (b"beta".to_vec(), Some(b"two".to_vec())),
        ],
        vec![
            (b"alpha".to_vec(), Some(b"one-updated".to_vec())),
            (b"gamma".to_vec(), Some(b"three".to_vec())),
        ],
    ])
    .await;
    let writer2: UnorderedWriter<Sha256, Vec<u8>, Vec<u8>> = UnorderedWriter::new(client.clone())
        .await
        .expect("writer 2");
    assert_eq!(
        writer2.latest_published_watermark().await,
        Some(latest1),
        "bootstrap must recover last watermark"
    );
    let delta = &ops_total[ops1.len()..];
    writer2.upload_and_publish(delta).await.expect("upload 2");
    assert_eq!(
        reader.root_at(latest2).await.expect("root_at 2"),
        root2,
        "remote root must match local (after batch 2)"
    );
}

type UnorderedBatch = Vec<(Vec<u8>, Option<Vec<u8>>)>;

async fn run_unordered_local(batches: Vec<UnorderedBatch>) -> (Vec<UnorderedOp>, Location, Digest) {
    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            let cfg = UnorderedVariableConfig {
                mmr_journal_partition: "mirror-unordered-mmr-journal".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                mmr_metadata_partition: "mirror-unordered-mmr-metadata".into(),
                log_partition: "mirror-unordered-log".into(),
                log_write_buffer: NZUsize!(1024),
                log_compression: None,
                log_codec_config: (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                log_items_per_blob: NZU64!(8),
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };
            let mut db: LocalUnorderedDb<cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap> =
                LocalUnorderedDb::init(context.with_label("db"), cfg)
                    .await
                    .expect("init");
            for batch in batches {
                let finalized = {
                    let mut b = db.new_batch();
                    for (k, v) in batch {
                        b.write(k, v);
                    }
                    b.merkleize(None::<Vec<u8>>).await.expect("merkleize")
                };
                db.apply_batch(finalized.finalize()).await.expect("apply");
            }
            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("historical_proof");
            let root = db.root();
            db.destroy().await.expect("destroy");
            (ops, latest, root)
        })
    })
    .await
    .expect("join")
}

// -------------------- Immutable --------------------

type ImmK = FixedBytes<32>;

#[tokio::test]
async fn mirror_immutable_from_local() {
    let (_dir, _server, client) = common::local_store_client().await;

    let (ops1, latest1, root1) = run_immutable_local(vec![vec![
        (FixedBytes::new([0x11; 32]), b"one".to_vec()),
        (FixedBytes::new([0x22; 32]), b"two".to_vec()),
    ]])
    .await;
    let writer: ImmutableWriter<Sha256, ImmK, Vec<u8>> =
        ImmutableWriter::new(client.clone()).await.expect("writer");
    writer.upload_and_publish(&ops1).await.expect("upload 1");
    let reader: ImmutableClient<Sha256, ImmK, Vec<u8>> = ImmutableClient::from_client(
        client.clone(),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
        ((), ((0..=MAX_OPERATION_SIZE).into(), ())),
    );
    assert_eq!(
        reader.root_at(latest1).await.expect("root_at 1"),
        root1,
        "remote root must match local (after batch 1)"
    );

    let (ops_total, latest2, root2) = run_immutable_local(vec![
        vec![
            (FixedBytes::new([0x11; 32]), b"one".to_vec()),
            (FixedBytes::new([0x22; 32]), b"two".to_vec()),
        ],
        vec![(FixedBytes::new([0x33; 32]), b"three".to_vec())],
    ])
    .await;
    let writer2: ImmutableWriter<Sha256, ImmK, Vec<u8>> = ImmutableWriter::new(client.clone())
        .await
        .expect("writer 2");
    assert_eq!(
        writer2.latest_published_watermark().await,
        Some(latest1),
        "bootstrap must recover last watermark"
    );
    let delta = &ops_total[ops1.len()..];
    writer2.upload_and_publish(delta).await.expect("upload 2");
    assert_eq!(
        reader.root_at(latest2).await.expect("root_at 2"),
        root2,
        "remote root must match local (after batch 2)"
    );
}

async fn run_immutable_local(
    batches: Vec<Vec<(ImmK, Vec<u8>)>>,
) -> (Vec<ImmutableOperation<ImmK, Vec<u8>>>, Location, Digest) {
    tokio::task::spawn_blocking(move || {
        deterministic::Runner::default().start(|context| async move {
            let cfg = ImmutableConfig {
                mmr_journal_partition: "mirror-immutable-mmr-journal".into(),
                mmr_metadata_partition: "mirror-immutable-mmr-metadata".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                log_partition: "mirror-immutable-log".into(),
                log_items_per_section: NZU64!(5),
                log_compression: None,
                log_codec_config: ((0..=MAX_OPERATION_SIZE).into(), ()),
                log_write_buffer: NZUsize!(1024),
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };
            let mut db: Immutable<deterministic::Context, ImmK, Vec<u8>, Sha256, TwoCap> =
                Immutable::init(context.with_label("db"), cfg)
                    .await
                    .expect("init");
            for batch in batches {
                let finalized = {
                    let mut b = db.new_batch();
                    for (k, v) in batch {
                        b.set(k, v);
                    }
                    b.merkleize(None::<Vec<u8>>).finalize()
                };
                db.apply_batch(finalized).await.expect("apply");
            }
            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("historical_proof");
            let root = db.root();
            db.destroy().await.expect("destroy");
            (ops, latest, root)
        })
    })
    .await
    .expect("join")
}

// -------------------- Ordered (with current boundary) --------------------

const N: usize = 32;
type OrderedOp = commonware_storage::qmdb::any::ordered::variable::Operation<Vec<u8>, Vec<u8>>;

#[tokio::test]
async fn mirror_ordered_from_local() {
    let (_dir, _server, client) = common::local_store_client().await;

    let (ops1, latest1, root1, boundary1) = run_ordered_local(vec![vec![
        (b"alpha".to_vec(), Some(b"one".to_vec())),
        (b"beta".to_vec(), Some(b"two".to_vec())),
    ]])
    .await;
    let writer: OrderedWriter<Sha256, Vec<u8>, Vec<u8>, N> =
        OrderedWriter::new(client.clone()).await.expect("writer");
    writer
        .upload_and_publish(&ops1, &boundary1)
        .await
        .expect("upload 1");

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
    assert_eq!(
        reader.current_root_at(latest1).await.expect("root_at 1"),
        root1,
        "remote root must match local (after batch 1)"
    );

    // Second session: compute the per-batch boundary delta for the new batch
    // (passing the previous cumulative ops in so `build_current_boundary_state`
    // only emits rows that actually changed — matching what the writer needs).
    let (ops_total, latest2, root2, _boundary2_full) = run_ordered_local(vec![
        vec![
            (b"alpha".to_vec(), Some(b"one".to_vec())),
            (b"beta".to_vec(), Some(b"two".to_vec())),
        ],
        vec![(b"alpha".to_vec(), Some(b"one-updated".to_vec()))],
    ])
    .await;
    let boundary_delta =
        build_current_boundary_state::<Sha256, _, _, N>(Some(ops1.as_slice()), &ops_total).await;

    let writer2: OrderedWriter<Sha256, Vec<u8>, Vec<u8>, N> =
        OrderedWriter::new(client.clone()).await.expect("writer 2");
    assert_eq!(
        writer2.latest_published_watermark().await,
        Some(latest1),
        "bootstrap must recover last watermark"
    );
    let delta_ops = &ops_total[ops1.len()..];
    writer2
        .upload_and_publish(delta_ops, &boundary_delta)
        .await
        .expect("upload 2");
    assert_eq!(
        reader.current_root_at(latest2).await.expect("root_at 2"),
        root2,
        "remote root must match local (after batch 2)"
    );
}

type OrderedBatch = Vec<(Vec<u8>, Option<Vec<u8>>)>;

async fn run_ordered_local(
    batches: Vec<OrderedBatch>,
) -> (
    Vec<OrderedOp>,
    Location,
    Digest,
    CurrentBoundaryState<Digest, N>,
) {
    let batches_clone = batches.clone();
    let (ops, latest, root) = tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            let cfg = OrderedVariableConfig {
                mmr_journal_partition: "mirror-ordered-mmr-journal".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                mmr_metadata_partition: "mirror-ordered-mmr-metadata".into(),
                log_partition: "mirror-ordered-log".into(),
                log_write_buffer: NZUsize!(1024),
                log_compression: None,
                log_codec_config: (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                log_items_per_blob: NZU64!(8),
                grafted_mmr_metadata_partition: "mirror-ordered-grafted-metadata".into(),
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };
            let mut db: LocalOrderedDb<cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap, N> =
                LocalOrderedDb::init(context.with_label("db"), cfg)
                    .await
                    .expect("init");
            for batch in batches_clone {
                let finalized = {
                    let mut b = db.new_batch();
                    for (k, v) in batch {
                        b.write(k, v);
                    }
                    b.merkleize(None::<Vec<u8>>).await.expect("merkleize")
                };
                db.apply_batch(finalized.finalize()).await.expect("apply");
            }
            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .ops_historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("ops_historical_proof");
            let root = db.root();
            db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");
            (ops, latest, root)
        })
    })
    .await
    .expect("join");
    let boundary = build_current_boundary_state::<Sha256, _, _, N>(None, &ops).await;
    (ops, latest, root, boundary)
}
