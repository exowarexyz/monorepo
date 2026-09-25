use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use commonware_cryptography::Sha256;
use commonware_storage::merkle::mmr;
use commonware_utils::sequence::FixedBytes;
use connectrpc::client::{BoxFuture, ClientBody, ClientTransport};
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::{PrefixedStoreClient, RetryConfig, StoreClient, StoreWriteBatch};
use tokio::sync::{mpsc, Semaphore};

use crate::{ImmutableClient, KeylessClient, OrderedClient, UnorderedClient, MAX_OPERATION_SIZE};

#[derive(Clone)]
struct CountRequests {
    calls: Arc<AtomicUsize>,
    origin: Option<Arc<std::sync::Mutex<String>>>,
    inner: PreferZstdHttpClient,
}

impl ClientTransport for CountRequests {
    type ResponseBody = <PreferZstdHttpClient as ClientTransport>::ResponseBody;
    type Error = <PreferZstdHttpClient as ClientTransport>::Error;

    fn send(
        &self,
        mut request: axum::http::Request<ClientBody>,
    ) -> BoxFuture<'static, Result<axum::http::Response<Self::ResponseBody>, Self::Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(origin) = &self.origin {
            *request.uri_mut() = format!(
                "{}{}",
                origin.lock().unwrap(),
                request.uri().path_and_query().unwrap()
            )
            .parse()
            .unwrap();
        }
        self.inner.send(request)
    }
}

#[derive(Clone)]
struct GateRequests {
    calls: Arc<AtomicUsize>,
    started: mpsc::UnboundedSender<usize>,
    permits: Arc<Semaphore>,
    origin: Arc<std::sync::Mutex<String>>,
    inner: PreferZstdHttpClient,
}

impl ClientTransport for GateRequests {
    type ResponseBody = <PreferZstdHttpClient as ClientTransport>::ResponseBody;
    type Error = <PreferZstdHttpClient as ClientTransport>::Error;

    fn send(
        &self,
        mut request: axum::http::Request<ClientBody>,
    ) -> BoxFuture<'static, Result<axum::http::Response<Self::ResponseBody>, Self::Error>> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.started.send(call).unwrap();
        *request.uri_mut() = format!(
            "{}{}",
            self.origin.lock().unwrap(),
            request.uri().path_and_query().unwrap()
        )
        .parse()
        .unwrap();
        let permits = self.permits.clone();
        let inner = self.inner.clone();
        Box::pin(async move {
            permits.acquire_owned().await.unwrap().forget();
            inner.send(request).await
        })
    }
}

fn gated_session(
    url: &str,
) -> (
    ReadSession,
    Arc<Semaphore>,
    mpsc::UnboundedReceiver<usize>,
    Arc<std::sync::Mutex<String>>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let permits = Arc::new(Semaphore::new(0));
    let (started, starts) = mpsc::unbounded_channel();
    let origin = Arc::new(std::sync::Mutex::new(url.to_string()));
    let raw = StoreClient::builder()
        .url(url)
        .client_transport(GateRequests {
            calls,
            started,
            permits: permits.clone(),
            origin: origin.clone(),
            inner: PreferZstdHttpClient::plaintext(),
        })
        .retry_config(RetryConfig::disabled())
        .build()
        .unwrap();
    (
        ReadSession::fixed(PrefixedStoreClient::empty(raw), None),
        permits,
        starts,
        origin,
    )
}

fn assert_pending<T>(poll: std::task::Poll<T>) {
    assert!(poll.is_pending());
}

#[tokio::test]
async fn publication_cache_distinguishes_absent_from_zero_and_keeps_smaller_publications() {
    let (_server, url) = exoware_simulator::open_temp().await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let raw = StoreClient::builder()
        .url(&url)
        .client_transport(CountRequests {
            calls: calls.clone(),
            origin: None,
            inner: PreferZstdHttpClient::plaintext(),
        })
        .retry_config(RetryConfig::disabled())
        .build()
        .unwrap();
    let store = PrefixedStoreClient::empty(raw.clone());
    let session = ReadSession::fixed(store.clone(), None);
    let mut sequence = 0;

    for (published, accepted) in [
        (None, [false, false, false, false, false]),
        (Some(0), [false, true, false, false, false]),
        (Some(5), [false, true, true, true, false]),
    ] {
        if let Some(published) = published {
            let mut batch = StoreWriteBatch::new();
            crate::stage_watermark(&store, Location::<mmr::Family>::new(published), &mut batch)
                .unwrap();
            sequence = batch.commit(&raw).await.unwrap();
        }
        let cache = PublicationCache::<mmr::Family>::default();
        for (requested, accepted) in [6, 0, 3, 5, 6].into_iter().zip(accepted) {
            calls.store(0, Ordering::SeqCst);
            let watermark = Location::<mmr::Family>::new(requested);
            let result = cache.require(&session, watermark).await;
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(!accepted));
            if accepted {
                let resolved = result.unwrap();
                assert_eq!(resolved.location, watermark);
                assert_eq!(resolved.sequence_number, sequence);
            } else {
                assert!(matches!(
                    result,
                    Err(QmdbError::WatermarkTooLow { requested: actual, available })
                        if actual == requested && available == published.unwrap_or(0)
                ));
            }
            assert_eq!(session.min_sequence_number(), None);
        }
    }
}

#[tokio::test]
async fn publication_cache_coalesces_misses_and_refreshes_without_data_observations() {
    let (_server, url) = exoware_simulator::open_temp().await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let raw = StoreClient::builder()
        .url(&url)
        .client_transport(CountRequests {
            calls: calls.clone(),
            origin: None,
            inner: PreferZstdHttpClient::plaintext(),
        })
        .retry_config(RetryConfig::disabled())
        .build()
        .unwrap();
    let store = PrefixedStoreClient::empty(raw.clone());
    let cache = Arc::new(PublicationCache::<mmr::Family>::default());
    let first = Location::new(5);
    let second = Location::new(10);
    let mut batch = StoreWriteBatch::new();
    crate::stage_watermark(&store, first, &mut batch).unwrap();
    let first_sequence = batch.commit(&raw).await.unwrap();

    calls.store(0, Ordering::SeqCst);
    let readers = (0..32).map(|_| {
        let cache = cache.clone();
        let session = ReadSession::fixed(store.clone(), None);
        async move {
            let resolved = cache.require(&session, first).await.unwrap();
            (resolved, session.evaluated_sequence())
        }
    });
    let mut observed_reads = 0;
    for (resolved, observed) in futures::future::join_all(readers).await {
        assert_eq!(resolved.location, first);
        assert_eq!(resolved.sequence_number, first_sequence);
        if let Some(sequence) = observed {
            assert_eq!(sequence, first_sequence);
            observed_reads += 1;
        }
    }
    assert_eq!(observed_reads, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut batch = StoreWriteBatch::new();
    crate::stage_watermark(&store, second, &mut batch).unwrap();
    let second_sequence = batch.commit(&raw).await.unwrap();
    let session = ReadSession::fixed(store.clone(), None);
    calls.store(0, Ordering::SeqCst);
    assert_eq!(
        cache
            .require(&session, first)
            .await
            .unwrap()
            .sequence_number,
        first_sequence
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(cache.refresh(&session).await.unwrap(), Some(second));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let historical_session = ReadSession::fixed(store.clone(), None);
    let historical = cache.require(&historical_session, first).await.unwrap();
    assert_eq!(historical.location, first);
    assert_eq!(historical.sequence_number, second_sequence);
    assert_eq!(historical_session.evaluated_sequence(), None);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let unrelated_key = Key::from_static(b"unrelated");
    let mut batch = StoreWriteBatch::new();
    batch
        .push(&store, &unrelated_key, b"value".as_slice())
        .unwrap();
    let data_sequence = batch.commit(&raw).await.unwrap();
    session.get(&unrelated_key).await.unwrap();
    assert_eq!(session.evaluated_sequence(), Some(data_sequence));
    calls.store(0, Ordering::SeqCst);
    assert_eq!(
        cache
            .require(&session, second)
            .await
            .unwrap()
            .sequence_number,
        second_sequence
    );
    let caller = ReadSession::fixed(store.clone(), Some(data_sequence));
    let resolved = cache.require(&caller, first).await.unwrap();
    assert_eq!(resolved.location, first);
    assert_eq!(resolved.sequence_number, second_sequence);
    assert_eq!(caller.evaluated_sequence(), None);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(cache.refresh(&session).await.unwrap(), Some(second));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        cache
            .require(&session, second)
            .await
            .unwrap()
            .sequence_number,
        second_sequence
    );

    let corrupt = WATERMARK_PREFIX.encode(&[255]).unwrap();
    let mut batch = StoreWriteBatch::new();
    batch.push(&store, &corrupt, b"".as_slice()).unwrap();
    batch.commit(&raw).await.unwrap();
    calls.store(0, Ordering::SeqCst);
    assert!(matches!(
        cache.refresh(&session).await,
        Err(QmdbError::CorruptData(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        cache
            .require(&session, second)
            .await
            .unwrap()
            .sequence_number,
        second_sequence
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn client_resolvers_keep_cached_publication_evidence_with_a_higher_caller_floor() {
    let (_server, url) = exoware_simulator::open_temp().await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let raw = StoreClient::builder()
        .url(&url)
        .client_transport(CountRequests {
            calls: calls.clone(),
            origin: None,
            inner: PreferZstdHttpClient::plaintext(),
        })
        .retry_config(RetryConfig::disabled())
        .build()
        .unwrap();
    let store = PrefixedStoreClient::empty(raw.clone());
    let watermark = Location::<mmr::Family>::new(5);
    let mut batch = StoreWriteBatch::new();
    crate::stage_watermark(&store, watermark, &mut batch).unwrap();
    let publication_sequence = batch.commit(&raw).await.unwrap();

    let ordered: OrderedClient<mmr::Family, Sha256, Vec<u8>, Vec<u8>, 32> = OrderedClient::new(
        store.clone(),
        (
            ((0..=MAX_OPERATION_SIZE).into(), ()),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    );
    let unordered: UnorderedClient<mmr::Family, Sha256, Vec<u8>, Vec<u8>> = UnorderedClient::new(
        store.clone(),
        (
            ((0..=MAX_OPERATION_SIZE).into(), ()),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        ),
    );
    let immutable: ImmutableClient<mmr::Family, Sha256, FixedBytes<32>, Vec<u8>> =
        ImmutableClient::new(store.clone(), ((), ((0..=MAX_OPERATION_SIZE).into(), ())));
    let keyless: KeylessClient<mmr::Family, Sha256, Vec<u8>> =
        KeylessClient::new(store.clone(), ((0..=MAX_OPERATION_SIZE).into(), ()));

    macro_rules! warm_resolver {
        ($client:expr) => {{
            let result = $client.resolve_watermark(watermark, None).await.unwrap();
            assert_eq!(result.location, watermark);
            assert_eq!(result.sequence_number, publication_sequence);
        }};
    }
    warm_resolver!(ordered);
    warm_resolver!(unordered);
    warm_resolver!(immutable);
    warm_resolver!(keyless);

    let mut batch = StoreWriteBatch::new();
    batch
        .push(&store, &Key::from_static(b"unrelated"), b"value".as_slice())
        .unwrap();
    let caller_floor = batch.commit(&raw).await.unwrap();
    assert!(caller_floor > publication_sequence);
    calls.store(0, Ordering::SeqCst);

    macro_rules! check_resolver {
        ($client:expr) => {{
            let result = $client
                .resolve_watermark(watermark, Some(caller_floor))
                .await
                .unwrap();
            assert_eq!(result.location, watermark);
            assert_eq!(result.sequence_number, publication_sequence);

            let cached = $client.resolve_watermark(watermark, None).await.unwrap();
            assert_eq!(cached.location, watermark);
            assert_eq!(cached.sequence_number, publication_sequence);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }};
    }
    check_resolver!(ordered);
    check_resolver!(unordered);
    check_resolver!(immutable);
    check_resolver!(keyless);
}

#[tokio::test]
async fn publication_cache_hits_bypass_blocked_miss_and_refresh() {
    let (_server, url) = exoware_simulator::open_temp().await.unwrap();
    let raw = StoreClient::new(&url);
    let store = PrefixedStoreClient::empty(raw.clone());
    let covered = Location::<mmr::Family>::new(5);
    let mut batch = StoreWriteBatch::new();
    crate::stage_watermark(&store, covered, &mut batch).unwrap();
    let sequence = batch.commit(&raw).await.unwrap();

    let (session, permits, mut starts, _) = gated_session(&url);
    let cache = PublicationCache::<mmr::Family>::default();
    {
        let _gate = cache.refresh_gate.lock().await;
        cache.remember(Some(covered), sequence);
    }

    let miss = cache.require(&session, Location::new(10));
    tokio::pin!(miss);
    assert_pending(futures::poll!(&mut miss));
    assert_eq!(starts.try_recv().unwrap(), 1);

    let hit = cache.require(&session, covered);
    tokio::pin!(hit);
    let hit = futures::poll!(&mut hit);
    assert_eq!(
        hit.map(|result| result.unwrap().sequence_number),
        std::task::Poll::Ready(sequence)
    );

    permits.add_permits(1);
    assert!(matches!(
        miss.await,
        Err(QmdbError::WatermarkTooLow {
            requested: 10,
            available: 5
        })
    ));

    let refresh = cache.refresh(&session);
    tokio::pin!(refresh);
    assert_pending(futures::poll!(&mut refresh));
    assert_eq!(starts.try_recv().unwrap(), 2);

    let hit = cache.require(&session, covered);
    tokio::pin!(hit);
    let hit = futures::poll!(&mut hit);
    assert_eq!(
        hit.map(|result| result.unwrap().sequence_number),
        std::task::Poll::Ready(sequence)
    );

    permits.add_permits(1);
    assert_eq!(refresh.await.unwrap(), Some(covered));
}

#[tokio::test]
async fn publication_cache_cancelled_lookup_releases_gate_and_waiter_retries() {
    let (_server, url) = exoware_simulator::open_temp().await.unwrap();
    let raw = StoreClient::new(&url);
    let store = PrefixedStoreClient::empty(raw.clone());
    let watermark = Location::<mmr::Family>::new(5);
    let mut batch = StoreWriteBatch::new();
    crate::stage_watermark(&store, watermark, &mut batch).unwrap();
    let sequence = batch.commit(&raw).await.unwrap();

    let (session, permits, mut starts, _) = gated_session(&url);
    let cache = PublicationCache::<mmr::Family>::default();
    let mut first = Box::pin(cache.require(&session, watermark));
    assert_pending(futures::poll!(&mut first));
    assert_eq!(starts.try_recv().unwrap(), 1);

    let mut waiter = Box::pin(cache.require(&session, watermark));
    assert_pending(futures::poll!(&mut waiter));
    assert!(starts.try_recv().is_err());

    drop(first);
    assert_pending(futures::poll!(&mut waiter));
    assert_eq!(starts.try_recv().unwrap(), 2);

    permits.add_permits(1);
    assert_eq!(waiter.await.unwrap().sequence_number, sequence);
}

#[tokio::test]
async fn publication_cache_failed_lookup_preserves_evidence_and_allows_retry() {
    let (_bad_server, bad_url) = exoware_simulator::open_temp().await.unwrap();
    let bad_raw = StoreClient::new(&bad_url);
    let bad_store = PrefixedStoreClient::empty(bad_raw.clone());
    let covered = Location::<mmr::Family>::new(5);
    let mut batch = StoreWriteBatch::new();
    crate::stage_watermark(&bad_store, covered, &mut batch).unwrap();
    let covered_sequence = batch.commit(&bad_raw).await.unwrap();
    let corrupt = WATERMARK_PREFIX.encode(&[255]).unwrap();
    let mut batch = StoreWriteBatch::new();
    batch.push(&bad_store, &corrupt, b"".as_slice()).unwrap();
    batch.commit(&bad_raw).await.unwrap();

    let (_good_server, good_url) = exoware_simulator::open_temp().await.unwrap();
    let good_raw = StoreClient::new(&good_url);
    let good_store = PrefixedStoreClient::empty(good_raw.clone());
    let requested = Location::<mmr::Family>::new(10);
    let mut batch = StoreWriteBatch::new();
    crate::stage_watermark(&good_store, requested, &mut batch).unwrap();
    let requested_sequence = batch.commit(&good_raw).await.unwrap();

    let (session, permits, mut starts, origin) = gated_session(&bad_url);
    let cache = PublicationCache::<mmr::Family>::default();
    {
        let _gate = cache.refresh_gate.lock().await;
        cache.remember(Some(covered), covered_sequence);
    }

    let failed = cache.require(&session, requested);
    tokio::pin!(failed);
    assert_pending(futures::poll!(&mut failed));
    assert_eq!(starts.try_recv().unwrap(), 1);
    permits.add_permits(1);
    assert!(matches!(failed.await, Err(QmdbError::CorruptData(_))));
    assert_eq!(
        cache
            .require(&session, covered)
            .await
            .unwrap()
            .sequence_number,
        covered_sequence
    );

    *origin.lock().unwrap() = good_url;
    let retry = cache.require(&session, requested);
    tokio::pin!(retry);
    assert_pending(futures::poll!(&mut retry));
    assert_eq!(starts.try_recv().unwrap(), 2);
    permits.add_permits(1);
    assert_eq!(retry.await.unwrap().sequence_number, requested_sequence);
}

#[tokio::test]
async fn publication_lookups_respect_sdk_retry_budget() {
    let (_server, url) = exoware_simulator::open_temp().await.unwrap();
    for attempts in [1, 2] {
        let calls = Arc::new(AtomicUsize::new(0));
        let raw = StoreClient::builder()
            .url(&url)
            .client_transport(CountRequests {
                calls: calls.clone(),
                origin: None,
                inner: PreferZstdHttpClient::plaintext(),
            })
            .retry_config(
                RetryConfig::disabled()
                    .with_max_attempts(attempts)
                    .with_initial_backoff(std::time::Duration::ZERO),
            )
            .build()
            .unwrap();
        let session = ReadSession::fixed(PrefixedStoreClient::empty(raw), Some(1));
        let cache = PublicationCache::<mmr::Family>::default();

        let error = cache.refresh(&session).await.unwrap_err();
        assert!(matches!(error, QmdbError::Client(ref error)
            if error.rpc_code() == Some(connectrpc::ErrorCode::Aborted)));
        assert_eq!(calls.load(Ordering::SeqCst), attempts);
        assert!(cache.published.load().is_none());

        calls.store(0, Ordering::SeqCst);
        let error = cache.require(&session, Location::new(0)).await.unwrap_err();
        assert!(matches!(error, QmdbError::Client(ref error)
            if error.rpc_code() == Some(connectrpc::ErrorCode::Aborted)));
        assert_eq!(calls.load(Ordering::SeqCst), attempts);
        assert!(cache.published.load().is_none());
    }
}

#[tokio::test]
async fn publication_cache_keeps_sequence_paired_with_greatest_watermark() {
    let cache = PublicationCache::<mmr::Family>::default();
    let _gate = cache.refresh_gate.lock().await;
    for (location, sequence, expected_location, expected_sequence) in [
        (Some(5), 100, 5, 100),
        (Some(3), 200, 5, 100),
        (None, 300, 5, 100),
        (Some(5), 150, 5, 100),
        (Some(5), 90, 5, 90),
        (Some(8), 110, 8, 110),
    ] {
        cache.remember(location.map(Location::new), sequence);
        let published = cache.published.load();
        let known = published.as_ref().unwrap();
        assert_eq!(known.location.as_u64(), expected_location);
        assert_eq!(known.sequence_number, expected_sequence);
    }
}

#[tokio::test]
async fn publication_cache_refresh_preserves_evidence_on_lagging_and_empty_replicas() {
    let (_new_server, new_url) = exoware_simulator::open_temp().await.unwrap();
    let (_old_server, old_url) = exoware_simulator::open_temp().await.unwrap();
    let (_empty_server, empty_url) = exoware_simulator::open_temp().await.unwrap();
    let mut publication_sequence = 0;
    for (url, watermark, writes) in [
        (&new_url, Some(5), 2),
        (&old_url, Some(3), 3),
        (&empty_url, None, 4),
    ] {
        let raw = StoreClient::new(url);
        let store = PrefixedStoreClient::empty(raw.clone());
        let mut batch = StoreWriteBatch::new();
        if let Some(watermark) = watermark {
            crate::stage_watermark(&store, Location::<mmr::Family>::new(watermark), &mut batch)
                .unwrap();
        } else {
            batch
                .push(&store, &Key::from_static(b"unrelated"), b"value".as_slice())
                .unwrap();
        }
        for _ in 0..writes {
            let sequence = batch.commit(&raw).await.unwrap();
            if watermark == Some(5) {
                publication_sequence = sequence;
            }
        }
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let origin = Arc::new(std::sync::Mutex::new(new_url.clone()));
    let raw = StoreClient::builder()
        .url(&new_url)
        .client_transport(CountRequests {
            calls: calls.clone(),
            origin: Some(origin.clone()),
            inner: PreferZstdHttpClient::plaintext(),
        })
        .retry_config(RetryConfig::disabled())
        .build()
        .unwrap();
    let session = ReadSession::fixed(PrefixedStoreClient::empty(raw), None);
    let cache = PublicationCache::<mmr::Family>::default();
    let watermark = Location::new(5);
    assert_eq!(cache.refresh(&session).await.unwrap(), Some(watermark));

    for replica in [&old_url, &empty_url] {
        *origin.lock().unwrap() = replica.clone();
        calls.store(0, Ordering::SeqCst);
        assert_eq!(cache.refresh(&session).await.unwrap(), Some(watermark));
        assert_eq!(
            cache
                .require(&session, watermark)
                .await
                .unwrap()
                .sequence_number,
            publication_sequence
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            cache.require(&session, Location::new(10)).await,
            Err(QmdbError::WatermarkTooLow {
                requested: 10,
                available: 5
            })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    let raw = StoreClient::new(&new_url);
    let store = PrefixedStoreClient::empty(raw.clone());
    let mut batch = StoreWriteBatch::new();
    crate::stage_watermark(&store, Location::<mmr::Family>::new(10), &mut batch).unwrap();
    let next_sequence = batch.commit(&raw).await.unwrap();
    *origin.lock().unwrap() = new_url;
    calls.store(0, Ordering::SeqCst);
    assert_eq!(
        cache
            .require(&session, Location::new(10))
            .await
            .unwrap()
            .sequence_number,
        next_sequence
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
