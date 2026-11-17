//! Current-state proof reads (ordered GetRange, ordered and unordered GetMany) against a
//! store that delays every query, so the time mostly counts serial store round trips.
//!
//! `QMDB_PROOF_BENCH_DELAY_MS` sets the delay (default 10). `QMDB_PROOF_BENCH_RUNS` sets
//! the runs per case (default 5, at least 1). Each line reports the median time and the
//! fewest and most store queries one call sent. Each run uses a new client, so no read is
//! cached.

#[allow(dead_code, unused_imports)]
#[path = "../tests/common/mod.rs"]
mod common;

use common::CountingQuery;
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_runtime::{
    buffer::paged::CacheRef, tokio as cw_tokio, Runner as _, Supervisor as _,
};
use commonware_storage::{
    merkle::{mmr, Location, Proof},
    qmdb::{
        any::{ordered::variable::Operation as OrderedOperation, unordered::variable::Operation},
        current::{ordered::variable::Db as OrderedDb, unordered::variable::Db as UnorderedDb},
    },
    translator::TwoCap,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::{
    adapter::upload::recover_boundary_state, proof::RawKeyLookupProof, CurrentBoundaryState,
    MAX_OPERATION_SIZE,
};
use exoware_sdk::{PrefixedStoreClient, StoreClient};
use std::{
    num::NonZeroU64,
    sync::Arc,
    time::{Duration, Instant},
};

const N: usize = 32;
const KEYS: usize = 2048;
const BATCH: usize = 100;
const FIRST: usize = 500;

type Family = mmr::Family;
type Digest = commonware_cryptography::sha256::Digest;
type OrderedOp = OrderedOperation<Family, Vec<u8>, Vec<u8>>;
type UnorderedOp = Operation<Family, Digest, Vec<u8>>;
type OrderedClient = exoware_qmdb::adapter::Ordered<Family, Sha256, Vec<u8>, Vec<u8>, N>;
type UnorderedClient = exoware_qmdb::adapter::Unordered<Family, Sha256, Digest, Vec<u8>, N>;
type OrderedSourceDb = OrderedDb<
    Family,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    N,
    commonware_parallel::Sequential,
>;
type UnorderedSourceDb = UnorderedDb<
    Family,
    cw_tokio::Context,
    Digest,
    Vec<u8>,
    Sha256,
    TwoCap,
    N,
    commonware_parallel::Sequential,
>;

/// A store whose writes are immediate and whose queries each wait `delay`.
async fn delayed_store(delay: Duration) -> (Arc<CountingQuery>, StoreClient) {
    let (query, client, _servers) = common::counting_store().await;
    query.set_delay(delay);
    (query, client)
}

fn bytes_cfg() -> <Vec<u8> as commonware_codec::Read>::Cfg {
    ((0..=MAX_OPERATION_SIZE).into(), ())
}

fn ordered_key(index: usize) -> Vec<u8> {
    format!("k-{index:08}").into_bytes()
}

fn unordered_key(index: usize) -> Digest {
    Sha256::hash(&[&(index as u64).to_be_bytes()])
}

/// Operations and boundary state of a source database holding `KEYS` keys.
struct Source<Op> {
    latest: Location<Family>,
    operations: Vec<Op>,
    boundary: CurrentBoundaryState<Digest, N, Family>,
}

async fn ordered_source() -> Source<OrderedOp> {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            let cfg = common::current_variable_config(
                "proof_reads_ordered",
                CacheRef::new(NZU16!(64), NZUsize!(8)),
                (bytes_cfg(), bytes_cfg()),
                NZU64!(8),
            );
            let mut db = OrderedSourceDb::init(context.child("proof_reads_ordered"), cfg, None)
                .await
                .unwrap();
            let mut batch = db.new_batch();
            for index in 0..KEYS {
                batch = batch.write(ordered_key(index), Some(vec![0x5a; 32]));
            }
            let batch = batch
                .merkleize(
                    &db,
                    None::<Vec<u8>>,
                    &mut commonware_storage::qmdb::floor::Proportional,
                )
                .await
                .unwrap();
            db = db.apply_batch(batch).await.unwrap();
            let latest = db.bounds().end - 1;
            let count = NonZeroU64::new(*latest + 1).unwrap();
            let (_, operations): (Proof<Family, Digest>, Vec<OrderedOp>) = db
                .ops_historical_proof(latest + 1, Location::new(0), count)
                .await
                .unwrap();
            let witness = db.ops_root_witness().await.unwrap();
            let boundary = recover_boundary_state::<Family, Sha256, _, N, _, _>(
                None,
                &operations,
                db.root(),
                0,
                witness,
                |location| common::current_proof_chunk(db.range_proof(location, NZU64!(1))),
            )
            .await
            .unwrap();
            db.destroy().await.unwrap();
            Source {
                latest,
                operations,
                boundary,
            }
        })
    })
    .await
    .unwrap()
}

async fn unordered_source() -> Source<UnorderedOp> {
    tokio::task::spawn_blocking(|| {
        cw_tokio::Runner::default().start(|context| async move {
            let cfg = common::current_variable_config(
                "proof_reads_unordered",
                CacheRef::new(NZU16!(64), NZUsize!(8)),
                ((), bytes_cfg()),
                NZU64!(8),
            );
            let mut db = UnorderedSourceDb::init(context.child("proof_reads_unordered"), cfg, None)
                .await
                .unwrap();
            let mut batch = db.new_batch();
            for index in 0..KEYS {
                batch = batch.write(unordered_key(index), Some(vec![0x5a; 32]));
            }
            let batch = batch
                .merkleize(
                    &db,
                    None::<Vec<u8>>,
                    &mut commonware_storage::qmdb::floor::Proportional,
                )
                .await
                .unwrap();
            db = db.apply_batch(batch).await.unwrap();
            let latest = db.bounds().end - 1;
            let count = NonZeroU64::new(*latest + 1).unwrap();
            let (_, operations): (Proof<Family, Digest>, Vec<UnorderedOp>) = db
                .ops_historical_proof(latest + 1, Location::new(0), count)
                .await
                .unwrap();
            let witness = db.ops_root_witness().await.unwrap();
            let boundary = recover_boundary_state::<Family, Sha256, _, N, _, _>(
                None,
                &operations,
                db.root(),
                0,
                witness,
                |location| common::current_proof_chunk(db.range_proof(location, NZU64!(1))),
            )
            .await
            .unwrap();
            db.destroy().await.unwrap();
            Source {
                latest,
                operations,
                boundary,
            }
        })
    })
    .await
    .unwrap()
}

/// Times one call per run on a client from `client` and prints the median and the
/// fewest and most queries one call sent.
async fn measure<C, Fut>(
    name: &str,
    runs: usize,
    query: &CountingQuery,
    client: impl Fn() -> C,
    call: impl Fn(C) -> Fut,
) where
    Fut: std::future::Future<Output = ()>,
{
    let mut times = Vec::with_capacity(runs);
    let mut queries = Vec::with_capacity(runs);
    for _ in 0..runs {
        let client = client();
        query.take_calls();
        let start = Instant::now();
        call(client).await;
        times.push(start.elapsed());
        let calls = query.take_calls();
        queries.push(calls.get + calls.get_many + calls.range);
    }
    times.sort();
    queries.sort();
    println!(
        "case={name} median_ms={:.1} min_ms={:.1} max_ms={:.1} min_queries={} max_queries={}",
        times[runs / 2].as_secs_f64() * 1e3,
        times[0].as_secs_f64() * 1e3,
        times[runs - 1].as_secs_f64() * 1e3,
        queries[0],
        queries[runs - 1],
    );
}

async fn run(delay: Duration, runs: usize) {
    let (ordered_query, ordered_store) = delayed_store(delay).await;
    let source = ordered_source().await;
    common::commit_current_operations(
        &PrefixedStoreClient::empty(ordered_store.clone()),
        &source.operations,
        &(bytes_cfg(), bytes_cfg()),
        &source.boundary,
    )
    .await
    .unwrap();
    let latest = source.latest;
    let new_ordered = || {
        OrderedClient::new(
            PrefixedStoreClient::empty(ordered_store.clone()),
            (bytes_cfg(), bytes_cfg()),
            bytes_cfg(),
        )
    };
    let hits: Vec<Vec<u8>> = (0..BATCH).map(|i| ordered_key(FIRST + 7 * i)).collect();
    let misses: Vec<Vec<u8>> = (0..BATCH)
        .map(|i| format!("k-{:08}x", FIRST + 7 * i).into_bytes())
        .collect();
    let one = vec![ordered_key(FIRST)];

    // A start key that is stored needs no start proof. One just below it does.
    let range = |start: Vec<u8>, start_proof: bool| {
        move |client: OrderedClient| {
            let start = start.clone();
            async move {
                let proof = client
                    .get_range_raw(latest, start, None, BATCH as u32, None)
                    .await
                    .unwrap();
                assert_eq!(proof.entries.len(), BATCH);
                assert_eq!(proof.start_proof.is_some(), start_proof);
            }
        }
    };
    let absent_start = format!("k-{:08}x", FIRST - 1).into_bytes();
    let get_many = |keys: &[Vec<u8>], hit: bool| {
        let keys = keys.to_vec();
        move |client: OrderedClient| {
            let keys = keys.clone();
            async move {
                let proofs = client.get_many_raw(latest, &keys, None).await.unwrap();
                assert_eq!(proofs.len(), keys.len());
                assert!(proofs
                    .iter()
                    .all(|proof| matches!(proof, RawKeyLookupProof::Hit(_)) == hit));
            }
        }
    };

    let query = &ordered_query;
    measure(
        "ordered_get_range_100",
        runs,
        query,
        new_ordered,
        range(ordered_key(FIRST), false),
    )
    .await;
    measure(
        "ordered_get_range_100_absent_start",
        runs,
        query,
        new_ordered,
        range(absent_start, true),
    )
    .await;
    measure(
        "ordered_get_many_100_hits",
        runs,
        query,
        new_ordered,
        get_many(&hits, true),
    )
    .await;
    measure(
        "ordered_get_many_100_misses",
        runs,
        query,
        new_ordered,
        get_many(&misses, false),
    )
    .await;
    measure(
        "ordered_get_many_1_hit",
        runs,
        query,
        new_ordered,
        get_many(&one, true),
    )
    .await;

    let (unordered_query, unordered_store) = delayed_store(delay).await;
    let source = unordered_source().await;
    common::commit_current_operations(
        &PrefixedStoreClient::empty(unordered_store.clone()),
        &source.operations,
        &((), bytes_cfg()),
        &source.boundary,
    )
    .await
    .unwrap();
    let latest = source.latest;
    let keys: Vec<Digest> = (0..BATCH).map(|i| unordered_key(FIRST + 7 * i)).collect();
    measure(
        "unordered_get_many_100_hits",
        runs,
        &unordered_query,
        || {
            UnorderedClient::new(
                PrefixedStoreClient::empty(unordered_store.clone()),
                ((), bytes_cfg()),
            )
        },
        |client: UnorderedClient| {
            let keys = keys.clone();
            async move {
                let proofs = client.get_many_raw(latest, &keys, None).await.unwrap();
                assert_eq!(proofs.len(), keys.len());
            }
        },
    )
    .await;
}

fn main() {
    let env = |name: &str, default: u64| {
        std::env::var(name)
            .ok()
            .map_or(default, |value| value.parse().unwrap())
    };
    let delay = Duration::from_millis(env("QMDB_PROOF_BENCH_DELAY_MS", 10));
    let runs = env("QMDB_PROOF_BENCH_RUNS", 5) as usize;
    assert!(runs > 0, "QMDB_PROOF_BENCH_RUNS must be at least 1");
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(delay, runs));
}
