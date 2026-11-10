//! Mirror local Commonware QMDB operations into an Exoware store and verify
//! the remote roots against the independent local roots across two batches.
//! Current ordered fixtures upload each batch's publication, and the other
//! fixtures authenticate each complete operation prefix.

mod common;

use commonware_cryptography::Sha256;
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, tokio as cw_tokio, Runner as _, Supervisor as _,
};
use commonware_storage::{
    merkle::{mmr, Location},
    qmdb::{
        any::{
            ordered::variable::Update as OrderedUpdate, unordered::variable::Db as LocalUnorderedDb,
        },
        current::ordered::variable::Db as LocalOrderedDb,
        immutable::variable::{Db as Immutable, Operation as ImmutableOperation},
        keyless::variable::{Db as Keyless, Operation as KeylessOperation},
    },
    translator::TwoCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use exoware_qmdb::{adapter::upload::Publication, MAX_OPERATION_SIZE};
use std::num::NonZeroU64;

type Digest = commonware_cryptography::sha256::Digest;

// -------------------- Keyless --------------------

#[tokio::test]
async fn test_mirror_keyless_from_local() {
    let store_client = common::local_store_client().await;

    // Apply one batch locally and upload its authenticated operation prefix
    let (ops1, latest1, root1) = build_keyless_source(vec![vec![
        b"alpha".to_vec(),
        b"beta".to_vec(),
        b"gamma".to_vec(),
    ]])
    .await;
    let upload_client = store_client.unprefixed();
    common::commit_operations::<mmr::Family, _>(
        &upload_client,
        &ops1,
        &((0..=MAX_OPERATION_SIZE).into(), ()),
    )
    .await
    .expect("upload 1");
    let qmdb_client: exoware_qmdb::adapter::Keyless<mmr::Family, Sha256, Vec<u8>> =
        exoware_qmdb::adapter::Keyless::new(
            store_client.unprefixed(),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        );
    assert_eq!(
        qmdb_client.root_at(latest1).await.expect("root_at 1"),
        root1,
        "remote root must match local (after batch 1)"
    );

    // Upload the complete operation prefix after a second local batch
    let (ops_total, latest2, root2) = build_keyless_source(vec![
        vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()],
        vec![b"delta".to_vec(), b"epsilon".to_vec()],
    ])
    .await;
    common::commit_operations::<mmr::Family, _>(
        &upload_client,
        &ops_total,
        &((0..=MAX_OPERATION_SIZE).into(), ()),
    )
    .await
    .expect("upload 2");
    assert_eq!(
        qmdb_client.root_at(latest2).await.expect("root_at 2"),
        root2,
        "remote root must match local (after batch 2)"
    );
}

async fn build_keyless_source(
    batches: Vec<Vec<Vec<u8>>>,
) -> (
    Vec<KeylessOperation<mmr::Family, Vec<u8>>>,
    Location<mmr::Family>,
    Digest,
) {
    tokio::task::spawn_blocking(move || {
        deterministic::Runner::default().start(|context| async move {
            let page_cache = CacheRef::new(NZU16!(64), NZUsize!(8));
            let cfg = common::keyless_variable_config(
                "keyless_variable_full_mmr_mirror_source",
                page_cache,
                ((0..=MAX_OPERATION_SIZE).into(), ()),
                NZU64!(7),
            );
            let mut db: Keyless<
                mmr::Family,
                deterministic::Context,
                Vec<u8>,
                Sha256,
                commonware_parallel::Sequential,
            > = Keyless::init(
                context.child("keyless_variable_full_mmr_mirror_source"),
                cfg,
                None,
            )
            .await
            .expect("init");
            for batch in batches {
                let finalized = {
                    let mut b = db.new_batch();
                    for v in batch {
                        b = b.append(v);
                    }
                    b.merkleize(&db).await.expect("merkleize")
                };
                db = db.apply_batch(finalized).await.expect("apply");
            }
            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_, ops) = db
                .historical_proof(latest + 1, Location::<mmr::Family>::new(0), n)
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

type UnorderedOp =
    commonware_storage::qmdb::any::unordered::variable::Operation<mmr::Family, Vec<u8>, Vec<u8>>;

#[tokio::test]
async fn test_mirror_unordered_from_local() {
    let store_client = common::local_store_client().await;

    let (ops1, latest1, root1) = build_any_unordered_source(vec![vec![
        (b"alpha".to_vec(), Some(b"one".to_vec())),
        (b"beta".to_vec(), Some(b"two".to_vec())),
    ]])
    .await;
    let upload_client = store_client.unprefixed();
    common::commit_operations::<mmr::Family, _>(
        &upload_client,
        &ops1,
        &(
            ((0..=MAX_OPERATION_SIZE).into(), ()),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
    )
    .await
    .expect("upload 1");
    let qmdb_client: exoware_qmdb::adapter::Unordered<mmr::Family, Sha256, Vec<u8>, Vec<u8>, N> =
        exoware_qmdb::adapter::Unordered::new(
            store_client.unprefixed(),
            (
                ((0..=MAX_OPERATION_SIZE).into(), ()),
                ((0..=MAX_OPERATION_SIZE).into(), ()),
            ),
        );
    assert_eq!(
        qmdb_client.root_at(latest1).await.expect("root_at 1"),
        root1,
        "remote root must match local (after batch 1)"
    );

    let (ops_total, latest2, root2) = build_any_unordered_source(vec![
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
    common::commit_operations::<mmr::Family, _>(
        &upload_client,
        &ops_total,
        &(
            ((0..=MAX_OPERATION_SIZE).into(), ()),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
    )
    .await
    .expect("upload 2");
    assert_eq!(
        qmdb_client.root_at(latest2).await.expect("root_at 2"),
        root2,
        "remote root must match local (after batch 2)"
    );
}

type UnorderedBatch = Vec<(Vec<u8>, Option<Vec<u8>>)>;

async fn build_any_unordered_source(
    batches: Vec<UnorderedBatch>,
) -> (Vec<UnorderedOp>, Location<mmr::Family>, Digest) {
    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            let page_cache = CacheRef::new(NZU16!(64), NZUsize!(8));
            let cfg = common::any_variable_config(
                "any_unordered_variable_mmr_mirror_source",
                page_cache,
                (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                NZU64!(8),
            );
            let mut db: LocalUnorderedDb<
                mmr::Family,
                cw_tokio::Context,
                Vec<u8>,
                Vec<u8>,
                Sha256,
                TwoCap,
                commonware_parallel::Sequential,
            > = LocalUnorderedDb::init(
                context.child("any_unordered_variable_mmr_mirror_source"),
                cfg,
                None,
            )
            .await
            .expect("init");
            for batch in batches {
                let finalized = {
                    let mut b = db.new_batch();
                    for (k, v) in batch {
                        b = b.write(k, v);
                    }
                    b.merkleize(&db).await.expect("merkleize")
                };
                db = db.apply_batch(finalized).await.expect("apply");
            }
            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_, ops) = db
                .historical_proof(latest + 1, Location::<mmr::Family>::new(0), n)
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
async fn test_mirror_immutable_from_local() {
    let store_client = common::local_store_client().await;

    let (ops1, latest1, root1) = build_immutable_source(vec![vec![
        (FixedBytes::new([0x11; 32]), b"one".to_vec()),
        (FixedBytes::new([0x22; 32]), b"two".to_vec()),
    ]])
    .await;
    let upload_client = store_client.unprefixed();
    common::commit_operations::<mmr::Family, _>(
        &upload_client,
        &ops1,
        &((), ((0..=MAX_OPERATION_SIZE).into(), ())),
    )
    .await
    .expect("upload 1");
    let qmdb_client: exoware_qmdb::adapter::Immutable<mmr::Family, Sha256, ImmK, Vec<u8>> =
        exoware_qmdb::adapter::Immutable::new(
            store_client.unprefixed(),
            ((), ((0..=MAX_OPERATION_SIZE).into(), ())),
        );
    assert_eq!(
        qmdb_client.root_at(latest1).await.expect("root_at 1"),
        root1,
        "remote root must match local (after batch 1)"
    );

    let (ops_total, latest2, root2) = build_immutable_source(vec![
        vec![
            (FixedBytes::new([0x11; 32]), b"one".to_vec()),
            (FixedBytes::new([0x22; 32]), b"two".to_vec()),
        ],
        vec![(FixedBytes::new([0x33; 32]), b"three".to_vec())],
    ])
    .await;
    common::commit_operations::<mmr::Family, _>(
        &upload_client,
        &ops_total,
        &((), ((0..=MAX_OPERATION_SIZE).into(), ())),
    )
    .await
    .expect("upload 2");
    assert_eq!(
        qmdb_client.root_at(latest2).await.expect("root_at 2"),
        root2,
        "remote root must match local (after batch 2)"
    );
}

async fn build_immutable_source(
    batches: Vec<Vec<(ImmK, Vec<u8>)>>,
) -> (
    Vec<ImmutableOperation<mmr::Family, ImmK, Vec<u8>>>,
    Location<mmr::Family>,
    Digest,
) {
    tokio::task::spawn_blocking(move || {
        deterministic::Runner::default().start(|context| async move {
            let page_cache = CacheRef::new(NZU16!(64), NZUsize!(8));
            let cfg = common::immutable_variable_config(
                "immutable_variable_full_mmr_mirror_source",
                page_cache,
                ((), ((0..=MAX_OPERATION_SIZE).into(), ())),
                NZU64!(5),
            );
            let mut db: Immutable<
                mmr::Family,
                deterministic::Context,
                ImmK,
                Vec<u8>,
                Sha256,
                TwoCap,
                commonware_parallel::Sequential,
            > = Immutable::init(
                context.child("immutable_variable_full_mmr_mirror_source"),
                cfg,
                None,
            )
            .await
            .expect("init");
            for batch in batches {
                let finalized = {
                    let mut b = db.new_batch();
                    for (k, v) in batch {
                        b = b.set(k, v);
                    }
                    b.merkleize(&db).await.expect("merkleize")
                };
                db = db.apply_batch(finalized).await.expect("apply");
            }
            let latest = db.bounds().end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_, ops) = db
                .historical_proof(latest + 1, Location::<mmr::Family>::new(0), n)
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

// -------------------- Current ordered (publications) --------------------

const N: usize = 32;
type OrderedPublication = Publication<mmr::Family, Digest, OrderedUpdate<Vec<u8>, Vec<u8>>, N>;

#[tokio::test]
async fn test_mirror_ordered_from_local() {
    let store_client = common::local_store_client().await;

    let (latest1, root1, publications1) = build_current_ordered_source(vec![vec![
        (b"alpha".to_vec(), Some(b"one".to_vec())),
        (b"beta".to_vec(), Some(b"two".to_vec())),
    ]])
    .await;
    let upload_client = store_client.unprefixed();
    common::commit_publications(&upload_client, &publications1)
        .await
        .expect("upload 1");

    let qmdb_client: exoware_qmdb::adapter::Ordered<mmr::Family, Sha256, Vec<u8>, Vec<u8>, N> =
        exoware_qmdb::adapter::Ordered::new(
            store_client.unprefixed(),
            (
                ((0..=MAX_OPERATION_SIZE).into(), ()),
                ((0..=MAX_OPERATION_SIZE).into(), ()),
            ),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        );
    assert_eq!(
        qmdb_client.root_at(latest1).await.expect("root_at 1"),
        root1,
        "remote root must match local (after batch 1)"
    );

    // Rebuild the same history plus one batch, then upload only the new batch's publication.
    let (latest2, root2, publications2) = build_current_ordered_source(vec![
        vec![
            (b"alpha".to_vec(), Some(b"one".to_vec())),
            (b"beta".to_vec(), Some(b"two".to_vec())),
        ],
        vec![(b"alpha".to_vec(), Some(b"one-updated".to_vec()))],
    ])
    .await;
    assert_eq!(
        publications2[publications1.len() - 1].root,
        root1,
        "rebuilt history must match the uploaded one"
    );
    common::commit_publications(&upload_client, &publications2[publications1.len()..])
        .await
        .expect("upload 2");
    assert_eq!(
        qmdb_client.root_at(latest2).await.expect("root_at 2"),
        root2,
        "remote root must match local (after batch 2)"
    );
}

type OrderedBatch = Vec<(Vec<u8>, Option<Vec<u8>>)>;

/// Apply `batches` to a new source, returning its tip, root, and publications starting with the
/// initial commit's.
async fn build_current_ordered_source(
    batches: Vec<OrderedBatch>,
) -> (Location<mmr::Family>, Digest, Vec<OrderedPublication>) {
    tokio::task::spawn_blocking(move || {
        cw_tokio::Runner::default().start(|context| async move {
            let page_cache = CacheRef::new(NZU16!(64), NZUsize!(8));
            let cfg = common::current_variable_config(
                "current_ordered_variable_mmr_mirror_source",
                page_cache,
                (
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ((0..=MAX_OPERATION_SIZE).into(), ()),
                ),
                NZU64!(8),
            );
            let mut db: LocalOrderedDb<
                mmr::Family,
                cw_tokio::Context,
                Vec<u8>,
                Vec<u8>,
                Sha256,
                TwoCap,
                N,
                commonware_parallel::Sequential,
            > = LocalOrderedDb::init(
                context.child("current_ordered_variable_mmr_mirror_source"),
                cfg,
                None,
            )
            .await
            .expect("init");
            let mut publications =
                vec![Publication::initial(&db).expect("initial publication must be readable")];
            for batch in batches {
                let finalized = {
                    let mut b = db.new_batch();
                    for (k, v) in batch {
                        b = b.write(k, v);
                    }
                    b.merkleize(&db).await.expect("merkleize")
                };
                publications.push(
                    Publication::from_batch(&finalized, &db).expect("publication must be readable"),
                );
                db = db.apply_batch(finalized).await.expect("apply");
            }
            let latest = db.bounds().end - 1;
            let root = db.root();
            db = db.sync().await.expect("sync");
            db.destroy().await.expect("destroy");
            (latest, root, publications)
        })
    })
    .await
    .expect("join")
}
