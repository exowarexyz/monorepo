//! Publication evidence and replica freshness across QMDB reads.

#[allow(dead_code)]
mod common;

use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroU64;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

use bytes::Bytes;
use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::merkle::{mmr, Location};
use commonware_storage::qmdb::any::value::VariableEncoding;
use commonware_storage::qmdb::immutable::variable::{
    Db as Immutable, Operation as ImmutableOperation,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::proto::qmdb::v1::GetOperationRangeRequest;
use exoware_qmdb::{immutable_operation_log_connect_stack, ImmutableClient, QmdbError};
use exoware_sdk::{PrefixedStoreClient, RetryConfig, StoreClient, StoreWriteBatch};
use exoware_server::{
    Query, QueryExtra, QueryResult, RangeScan, RangeScanBatch, RangeScanResult, Sequence,
};

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

fn publication_key() -> Bytes {
    let store = PrefixedStoreClient::empty(StoreClient::new("http://127.0.0.1:1"));
    let mut batch = StoreWriteBatch::new();
    exoware_qmdb::stage_watermark(&store, Location::<Family>::new(0), &mut batch).unwrap();
    batch.entries()[0].0.clone()
}

struct MapSnapshot {
    sequence: u64,
    rows: BTreeMap<Bytes, Bytes>,
}

struct MapCursor {
    rows: VecDeque<(Bytes, Bytes)>,
    fail_at_end: bool,
}

impl RangeScan for MapCursor {
    async fn next_batch(&mut self, max_items: usize) -> Result<RangeScanBatch, String> {
        if self.rows.is_empty() && self.fail_at_end {
            return Err("publication scan failed after its row".to_string());
        }
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
    new_reads: AtomicUsize,
    fail_range_at_end: AtomicBool,
    publication_reads: AtomicUsize,
    publication_key: Bytes,
    reads: Mutex<Vec<RoutedRead>>,
}

impl LoadBalancedQuery {
    fn route(&self) -> &MapSnapshot {
        let first =
            self.calls.fetch_add(1, Ordering::SeqCst) < self.new_reads.load(Ordering::SeqCst);
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
    ) -> Result<RangeScanResult<Self::RangeScan>, String> {
        let publication = start <= self.publication_key && self.publication_key <= end;
        if publication {
            self.publication_reads.fetch_add(1, Ordering::SeqCst);
        }
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
        Ok(RangeScanResult {
            scan: MapCursor {
                rows: rows.into(),
                fail_at_end: publication && self.fail_range_at_end.load(Ordering::SeqCst),
            },
            sequence_number: snapshot.sequence,
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
async fn cached_publication_fences_dependent_reads() {
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
        new_reads: AtomicUsize::new(1),
        fail_range_at_end: AtomicBool::new(false),
        publication_reads: AtomicUsize::new(0),
        publication_key: publication_key(),
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
    let store_client = PrefixedStoreClient::empty(store_client);
    let qmdb = Client::new(store_client, operation_cfg());
    let watermark = Location::new((all_operations.len() - 1) as u64);

    let error = qmdb
        .get_at(&b"key".to_vec(), watermark)
        .await
        .expect_err("replica 100 cannot satisfy publication evidence from sequence 101");
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

    query.new_reads.store(usize::MAX, Ordering::SeqCst);
    let value = qmdb
        .get_at(&b"key".to_vec(), watermark)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(value.value, Some(b"new".to_vec()));
    let (expected_root, _) =
        common::prepare_operations::<Family, Operation>(&all_operations, &operation_cfg());
    let cloned = qmdb.clone();
    assert_eq!(cloned.root_at(watermark).await.unwrap(), expected_root);
    let checkpoint = qmdb
        .operation_range_checkpoint(watermark, Location::new(0), 1)
        .await
        .unwrap();
    assert_eq!(checkpoint.root, expected_root);
    assert!(checkpoint.verify::<commonware_cryptography::Sha256>());
    assert_eq!(query.publication_reads.load(Ordering::SeqCst), 1);

    let previous_watermark = Location::new((first_operations.len() - 1) as u64);
    let previous = qmdb
        .get_at(&b"key".to_vec(), previous_watermark)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(previous.value, Some(b"old".to_vec()));
    let (previous_root, _) =
        common::prepare_operations::<Family, Operation>(&first_operations, &operation_cfg());
    let checkpoint = qmdb
        .operation_range_checkpoint(previous_watermark, Location::new(0), 1)
        .await
        .unwrap();
    assert_eq!(checkpoint.root, previous_root);
    assert!(checkpoint.verify::<commonware_cryptography::Sha256>());
    assert_eq!(query.publication_reads.load(Ordering::SeqCst), 1);

    query.new_reads.store(0, Ordering::SeqCst);
    let previous = qmdb.get_at(&b"key".to_vec(), previous_watermark).await;
    assert!(
        matches!(previous, Err(QmdbError::Client(ref error)) if error.rpc_code() == Some(connectrpc::ErrorCode::Aborted)),
        "the greatest cached publication conservatively requires sequence 101"
    );
    assert_eq!(query.publication_reads.load(Ordering::SeqCst), 1);

    assert_eq!(
        qmdb.latest_published_watermark().await.unwrap(),
        Some(watermark),
        "refreshing against a lagging replica must preserve the greatest known publication"
    );
    assert_eq!(query.publication_reads.load(Ordering::SeqCst), 2);

    server.abort();
}

#[tokio::test]
async fn rpc_reads_do_not_inherit_previous_request_observations() {
    let (first_operations, all_operations) = build_two_publications().await;
    let watermark = (first_operations.len() - 1) as u64;
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
        new_reads: AtomicUsize::new(0),
        fail_range_at_end: AtomicBool::new(false),
        publication_reads: AtomicUsize::new(0),
        publication_key: publication_key(),
        reads: Mutex::new(Vec::new()),
    });
    let (store_server, query_url) = common::spawn_connect_service(exoware_server::query_service(
        exoware_server::QueryState::new(query.clone()),
    ))
    .await;
    let store = PrefixedStoreClient::empty(
        StoreClient::builder()
            .url(&query_url)
            .retry_config(RetryConfig::disabled())
            .build()
            .unwrap(),
    );
    let (qmdb_server, qmdb_url) =
        common::spawn_connect_service(immutable_operation_log_connect_stack::<
            Family,
            commonware_cryptography::Sha256,
            Vec<u8>,
            Vec<u8>,
            VariableEncoding<Vec<u8>>,
        >(store, operation_cfg()))
        .await;
    let rpc = common::operation_log_rpc_client(&qmdb_url);
    let request = |min_sequence_number| GetOperationRangeRequest {
        tip: watermark,
        start_location: 0,
        max_locations: 1,
        min_sequence_number,
        ..Default::default()
    };

    let warm = rpc
        .get_operation_range(request(None))
        .await
        .unwrap()
        .into_owned();
    assert_eq!(warm.sequence_number, 100);
    query.new_reads.store(usize::MAX, Ordering::SeqCst);
    let first = rpc
        .get_operation_range(request(None))
        .await
        .unwrap()
        .into_owned();
    assert_eq!(first.sequence_number, 101);
    query.new_reads.store(0, Ordering::SeqCst);
    let second = rpc
        .get_operation_range(request(Some(0)))
        .await
        .unwrap()
        .into_owned();
    assert_eq!(second.sequence_number, 100);
    assert_eq!(query.publication_reads.load(Ordering::SeqCst), 1);
    let error = rpc
        .get_operation_range(request(Some(101)))
        .await
        .expect_err("explicit floor must reject the older replica");
    assert_eq!(error.code, connectrpc::ErrorCode::Aborted);

    qmdb_server.abort();
    store_server.abort();
}

#[tokio::test]
async fn publication_lookup_propagates_errors_after_the_watermark_frame() {
    let (operations, _) = build_two_publications().await;
    let rows = snapshot_rows(&operations);
    let query = Arc::new(LoadBalancedQuery {
        old: MapSnapshot {
            sequence: 100,
            rows: rows.clone(),
        },
        new: MapSnapshot {
            sequence: 101,
            rows,
        },
        calls: AtomicUsize::new(0),
        new_reads: AtomicUsize::new(usize::MAX),
        fail_range_at_end: AtomicBool::new(true),
        publication_reads: AtomicUsize::new(0),
        publication_key: publication_key(),
        reads: Mutex::new(Vec::new()),
    });
    let (server, url) = common::spawn_connect_service(exoware_server::query_service(
        exoware_server::QueryState::new(query.clone()),
    ))
    .await;
    let store = PrefixedStoreClient::empty(
        StoreClient::builder()
            .url(&url)
            .retry_config(RetryConfig::disabled())
            .build()
            .unwrap(),
    );
    let client = Client::new(store, operation_cfg());

    let error = client
        .latest_published_watermark()
        .await
        .expect_err("a watermark frame does not hide a later scan error");
    assert!(
        matches!(error, QmdbError::Client(ref error) if error.rpc_code() == Some(connectrpc::ErrorCode::Internal)),
        "expected the terminal scan error, got {error:?}"
    );
    assert_eq!(query.calls.load(Ordering::SeqCst), 1);
    query.fail_range_at_end.store(false, Ordering::SeqCst);
    query.new_reads.store(0, Ordering::SeqCst);
    let watermark = Location::new((operations.len() - 1) as u64);
    assert_eq!(
        client
            .get_at(&b"key".to_vec(), watermark)
            .await
            .unwrap()
            .unwrap()
            .value,
        Some(b"old".to_vec())
    );
    assert_eq!(
        query.publication_reads.load(Ordering::SeqCst),
        2,
        "failed publication lookup must not populate the cache"
    );
    server.abort();
}
