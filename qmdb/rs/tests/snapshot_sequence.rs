//! Regression for carrying the observed Store sequence across QMDB reads.

#[allow(dead_code)]
mod common;

use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroU64;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use bytes::Bytes;
use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::merkle::{mmr, Location};
use commonware_storage::qmdb::immutable::variable::{
    Db as Immutable, Operation as ImmutableOperation,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::{ImmutableClient, QmdbError};
use exoware_sdk::{PrefixedStoreClient, RetryConfig, StoreClient, StoreWriteBatch};
use exoware_server::{Query, QueryExtra, QueryResult, RangeScan, RangeScanBatch, Sequence};

type Family = mmr::Family;
type Operation = ImmutableOperation<Family, Vec<u8>, Vec<u8>>;
type Db = Immutable<
    Family,
    deterministic::Context,
    Vec<u8>,
    Vec<u8>,
    commonware_cryptography::Sha256,
    TwoCap,
    commonware_parallel::Sequential,
>;
type Client = ImmutableClient<Family, commonware_cryptography::Sha256, Vec<u8>, Vec<u8>>;

fn operation_cfg() -> <Operation as commonware_codec::Read>::Cfg {
    (((0..=10_000).into(), ()), ((0..=10_000).into(), ()))
}

async fn build_two_publications() -> (Vec<Operation>, Vec<Operation>) {
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};

            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let config = common::immutable_variable_config(
                "snapshot_sequence_source",
                page_cache,
                operation_cfg(),
                NZU64!(8),
            );
            let mut db: Db = Db::init(context.child("snapshot_sequence_source"), config)
                .await
                .expect("initialize source QMDB");

            let first = db.new_batch().set(b"key".to_vec(), b"old".to_vec());
            let first = first
                .merkleize(&db, None::<Vec<u8>>, db.inactivity_floor_loc())
                .await;
            (db, _) = db.apply_batch(first).await.expect("apply old value");
            let first_end = db.bounds().end;
            let (_, first_operations) = db
                .historical_proof(
                    first_end,
                    Location::new(0),
                    NonZeroU64::new(*first_end).unwrap(),
                )
                .await
                .expect("read first publication");

            let second = db.new_batch().set(b"key".to_vec(), b"new".to_vec());
            let second = second
                .merkleize(&db, None::<Vec<u8>>, db.inactivity_floor_loc())
                .await;
            (db, _) = db.apply_batch(second).await.expect("apply new value");
            let full_end = db.bounds().end;
            let (_, all_operations) = db
                .historical_proof(
                    full_end,
                    Location::new(0),
                    NonZeroU64::new(*full_end).unwrap(),
                )
                .await
                .expect("read both publications");

            db.destroy().await.expect("destroy source QMDB");
            (first_operations, all_operations)
        })
    })
    .await
    .expect("join source QMDB task")
}

fn snapshot_rows(operations: &[Operation]) -> BTreeMap<Bytes, Bytes> {
    let staging_client = PrefixedStoreClient::empty(StoreClient::new("http://127.0.0.1:1"));
    let (_, prepared) =
        common::prepare_operations::<Family, Operation>(operations, &operation_cfg());
    let latest = prepared.latest_location();
    let mut batch = StoreWriteBatch::new();
    exoware_qmdb::stage_authenticated_range(&staging_client, prepared, &mut batch)
        .expect("stage authenticated range");
    exoware_qmdb::stage_watermark(&staging_client, latest, &mut batch)
        .expect("stage publication watermark");
    batch.entries().iter().cloned().collect()
}

struct MapSnapshot {
    sequence: u64,
    rows: BTreeMap<Bytes, Bytes>,
}

struct MapCursor {
    sequence: u64,
    rows: VecDeque<(Bytes, Bytes)>,
}

impl RangeScan for MapCursor {
    fn sequence_number(&self) -> u64 {
        self.sequence
    }

    async fn next_batch(&mut self, max_items: usize) -> Result<RangeScanBatch, String> {
        Ok(RangeScanBatch {
            rows: (0..max_items)
                .map_while(|_| self.rows.pop_front())
                .collect(),
            extra: QueryExtra::default(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RoutedRead {
    replica: &'static str,
    sequence: u64,
}

struct LoadBalancedQuery {
    old: MapSnapshot,
    new: MapSnapshot,
    calls: AtomicUsize,
    reads: Mutex<Vec<RoutedRead>>,
}

impl LoadBalancedQuery {
    fn route(&self) -> &MapSnapshot {
        let first = self.calls.fetch_add(1, Ordering::SeqCst) == 0;
        let (replica, snapshot) = if first {
            ("new", &self.new)
        } else {
            ("old", &self.old)
        };
        self.reads.lock().unwrap().push(RoutedRead {
            replica,
            sequence: snapshot.sequence,
        });
        snapshot
    }
}

impl Sequence for LoadBalancedQuery {
    fn current_sequence(&self) -> u64 {
        101
    }
}

impl Query for LoadBalancedQuery {
    type RangeScan = MapCursor;

    async fn get(&self, key: Bytes) -> Result<QueryResult<Option<Bytes>>, String> {
        let snapshot = self.route();
        Ok(QueryResult {
            value: snapshot.rows.get(&key).cloned(),
            sequence_number: snapshot.sequence,
            extra: QueryExtra::default(),
        })
    }

    async fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Result<Self::RangeScan, String> {
        let snapshot = self.route();
        let mut rows = snapshot
            .rows
            .range(start.clone()..)
            .take_while(|(key, _)| end.is_empty() || *key <= &end)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        if !forward {
            rows.reverse();
        }
        rows.truncate(limit);
        Ok(MapCursor {
            sequence: snapshot.sequence,
            rows: rows.into(),
        })
    }

    async fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> Result<QueryResult<Vec<(Bytes, Option<Bytes>)>>, String> {
        let snapshot = self.route();
        Ok(QueryResult {
            value: keys
                .into_iter()
                .map(|key| {
                    let value = snapshot.rows.get(&key).cloned();
                    (key, value)
                })
                .collect(),
            sequence_number: snapshot.sequence,
            extra: QueryExtra::default(),
        })
    }
}

#[tokio::test]
async fn backend_snapshot_sequence_fences_following_qmdb_reads() {
    let (first_operations, all_operations) = build_two_publications().await;

    let query = Arc::new(LoadBalancedQuery {
        old: MapSnapshot {
            sequence: 100,
            rows: snapshot_rows(&first_operations),
        },
        new: MapSnapshot {
            sequence: 101,
            rows: snapshot_rows(&all_operations),
        },
        calls: AtomicUsize::new(0),
        reads: Mutex::new(Vec::new()),
    });
    let (server, query_url) = common::spawn_connect_service(exoware_server::query_service(
        exoware_server::QueryState::new(query.clone()),
    ))
    .await;
    let store_client = StoreClient::builder()
        .url(&query_url)
        .query_url(&query_url)
        .retry_config(RetryConfig::disabled())
        .build()
        .unwrap();
    let qmdb = Client::new(PrefixedStoreClient::empty(store_client), operation_cfg());
    let watermark = Location::new((all_operations.len() - 1) as u64);

    let error = qmdb
        .get_at(&b"key".to_vec(), watermark)
        .await
        .expect_err("returned sequence 100 must not serve a session that observed sequence 101");
    assert!(
        matches!(error, QmdbError::Client(ref error) if error.rpc_code() == Some(connectrpc::ErrorCode::Aborted)),
        "expected ABORTED from the stale replica, got {error:?}"
    );
    assert_eq!(
        *query.reads.lock().unwrap(),
        [
            RoutedRead {
                replica: "new",
                sequence: 101,
            },
            RoutedRead {
                replica: "old",
                sequence: 100,
            },
        ]
    );

    server.abort();
}
