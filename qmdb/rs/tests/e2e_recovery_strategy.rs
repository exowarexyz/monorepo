mod common;

use std::num::{NonZeroU64, NonZeroUsize};

use commonware_codec::{Codec, Read as CodecRead};
use commonware_parallel::Strategy as _;
use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::merkle::{mmb, mmr, Family, Graftable, Location};
use commonware_storage::qmdb::any::value::VariableEncoding;
use commonware_storage::qmdb::keyless::variable::{Db as Keyless, Operation as KeylessOperation};
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::{KeylessClient, KeylessWriter};
use exoware_sdk::{PrefixedStoreClient, StoreClient};

use common::retry;

type Digest = commonware_cryptography::sha256::Digest;
type LocalDb<F> = Keyless<
    F,
    deterministic::Context,
    Vec<u8>,
    commonware_cryptography::Sha256,
    commonware_parallel::Sequential,
>;
type TestKeylessClient<F> = KeylessClient<F, commonware_cryptography::Sha256, Vec<u8>>;
type SequentialWriter<F> = KeylessWriter<F, commonware_cryptography::Sha256, Vec<u8>>;
type RayonWriter<F> = KeylessWriter<
    F,
    commonware_cryptography::Sha256,
    Vec<u8>,
    VariableEncoding<Vec<u8>>,
    commonware_parallel::Manual<commonware_parallel::Rayon>,
>;

fn fresh_keyless<F: Graftable>(client: StoreClient) -> TestKeylessClient<F> {
    TestKeylessClient::new(
        PrefixedStoreClient::empty(client),
        ((0..=10_000).into(), ()),
    )
}

fn rayon_strategy() -> commonware_parallel::Manual<commonware_parallel::Rayon> {
    commonware_parallel::Rayon::new(NonZeroUsize::new(4).expect("non-zero thread count"))
        .expect("construct Rayon strategy")
        .manual()
}

struct LocalReference<F: Family> {
    latest_location: Location<F>,
    operations: Vec<KeylessOperation<F, Vec<u8>>>,
    continuation_operations: Vec<KeylessOperation<F, Vec<u8>>>,
    continued_latest_location: Location<F>,
    continued_root: Digest,
}

async fn build_local_reference<F: Graftable>() -> LocalReference<F>
where
    KeylessOperation<F, Vec<u8>>: Codec<Cfg = <Vec<u8> as CodecRead>::Cfg> + Clone,
{
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};

            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let config = common::keyless_config(
                "keyless_recovery_strategy",
                page_cache,
                ((0..=10_000).into(), ()),
                NZU64!(7),
            );
            let mut db: LocalDb<F> = LocalDb::init(context.child("db"), config)
                .await
                .expect("init local keyless DB");

            let initial = db
                .new_batch()
                .append(b"first-value".to_vec())
                .append(b"second-value".to_vec())
                .append(b"third-value".to_vec())
                .append(b"fourth-value".to_vec())
                .append(b"fifth-value".to_vec())
                .append(b"sixth-value".to_vec())
                .append(b"seventh-value".to_vec())
                .merkleize(&db, None::<Vec<u8>>, db.inactivity_floor_loc())
                .await;
            (db, _) = db.apply_batch(initial).await.expect("apply initial batch");

            let checkpoint_batch = db
                .new_batch()
                .append(b"eighth-value".to_vec())
                .merkleize(&db, None::<Vec<u8>>, db.bounds().end - 1)
                .await;
            (db, _) = db
                .apply_batch(checkpoint_batch)
                .await
                .expect("apply checkpoint batch");

            let latest_location = db.bounds().end - 1;
            let count = NonZeroU64::new(*latest_location + 1).expect("nonzero operation count");
            let (_, operations) = db
                .historical_proof(latest_location + 1, Location::<F>::new(0), count)
                .await
                .expect("checkpoint historical proof");

            let continuation = db
                .new_batch()
                .append(b"ninth-value".to_vec())
                .merkleize(&db, None::<Vec<u8>>, db.bounds().end - 1)
                .await;
            (db, _) = db
                .apply_batch(continuation)
                .await
                .expect("apply continuation batch");

            let continued_latest_location = db.bounds().end - 1;
            let count = NonZeroU64::new(*continued_latest_location + 1)
                .expect("nonzero continued operation count");
            let (_, all_operations) = db
                .historical_proof(continued_latest_location + 1, Location::<F>::new(0), count)
                .await
                .expect("continued historical proof");
            let continuation_operations = all_operations[operations.len()..].to_vec();
            let continued_root = db.root();
            db.destroy().await.expect("destroy local keyless DB");

            LocalReference {
                latest_location,
                operations,
                continuation_operations,
                continued_latest_location,
                continued_root,
            }
        })
    })
    .await
    .expect("join local keyless task")
}

async fn recovery_strategy_round_trip<F: Graftable>()
where
    KeylessOperation<F, Vec<u8>>: Codec<Cfg = <Vec<u8> as CodecRead>::Cfg> + Clone,
{
    let client = common::local_store_client().await;
    let local = build_local_reference::<F>().await;

    let writer = SequentialWriter::<F>::fresh(PrefixedStoreClient::empty(client.clone()));
    common::commit_keyless_upload(&writer, &local.operations)
        .await
        .expect("commit checkpoint upload");

    let checkpoint = retry(
        || {
            let reader = fresh_keyless::<F>(client.clone());
            let latest_location = local.latest_location;
            async move {
                reader
                    .operation_range_checkpoint(latest_location, latest_location, 1)
                    .await
            }
        },
        "suffix checkpoint",
    )
    .await;
    assert_eq!(checkpoint.start_location, local.latest_location);
    assert_ne!(checkpoint.start_location, Location::new(0));
    assert!(!checkpoint.pinned_nodes.is_empty());
    assert!(checkpoint.proof.inactive_peaks > 0);

    let reader = fresh_keyless::<F>(client.clone());
    let strategy = rayon_strategy();
    let recovered = reader
        .recover_writer_state_with_strategy(&strategy)
        .await
        .expect("recover with Rayon");
    let sequential = reader
        .recover_writer_state()
        .await
        .expect("recover sequentially");
    assert_eq!(recovered.peaks, sequential.peaks);
    assert_eq!(recovered.ops_size, sequential.ops_size);
    assert_eq!(recovered.next_location, sequential.next_location);
    assert_eq!(recovered.next_location, local.latest_location + 1);

    let resumed = RayonWriter::<F>::new_with_strategy(
        PrefixedStoreClient::empty(client.clone()),
        recovered,
        strategy,
    );
    let receipt = common::commit_keyless_upload(&resumed, &local.continuation_operations)
        .await
        .expect("commit continued upload");
    assert_eq!(receipt.latest_location, local.continued_latest_location);

    let continued_root = retry(
        || {
            let reader = fresh_keyless::<F>(client.clone());
            let latest_location = local.continued_latest_location;
            async move { reader.root_at(latest_location).await }
        },
        "continued root_at",
    )
    .await;
    assert_eq!(continued_root, local.continued_root);
}

#[tokio::test]
async fn parallel_recovery_round_trip_mmr() {
    recovery_strategy_round_trip::<mmr::Family>().await;
}

#[tokio::test]
async fn parallel_recovery_round_trip_mmb() {
    recovery_strategy_round_trip::<mmb::Family>().await;
}
