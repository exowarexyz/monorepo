//! Key pruning by policy document, and its composition with log retention.

use crate::{
    support::{
        apply_prune, commit, family_key, family_policy, fresh, get_value, has_batch, reopen, row,
        set_retention, version_policy, version_policy_with_encoding, versioned_key,
        versioned_key_in, VERSION_REGEX,
    },
    Backend,
};
use bytes::Bytes;
use exoware_sdk::{
    prune_policy::{OrderEncoding, RetainPolicy},
    retention::RetentionPolicy,
};
use exoware_server::{Log, Sequence};

/// Prefix byte of a key family beside the prune family.
const OTHER_PREFIX: u8 = 2;

/// Commits one batch with a row per key, each valued by its key.
async fn commit_keys<B: Backend>(backend: &B, store: &B::Store, keys: &[Bytes]) -> u64 {
    commit(
        backend,
        store,
        keys.iter().map(|key| (key.clone(), key.clone())).collect(),
    )
    .await
}

/// Asserts that every key in `kept` still reads as its own value and every key in `deleted`
/// reads as absent.
async fn assert_present<B: Backend>(store: &B::Store, kept: &[&Bytes], deleted: &[&Bytes]) {
    for key in kept {
        assert_eq!(
            get_value(store, key).await.as_ref(),
            Some(*key),
            "{key:?} must be kept"
        );
    }
    for key in deleted {
        assert!(
            get_value(store, key).await.is_none(),
            "{key:?} must be deleted"
        );
    }
}

pub async fn keys_drop_all_deletes_matching_family_keys<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let a1 = versioned_key(b"a", 1);
    let b1 = versioned_key(b"b", 1);
    commit(
        backend,
        &store,
        vec![
            (a1.clone(), Bytes::from_static(b"a1")),
            (b1.clone(), Bytes::from_static(b"b1")),
            row(b"raw", b"raw"),
        ],
    )
    .await;

    apply_prune(&store, &[version_policy(RetainPolicy::DropAll)]).await;

    assert!(get_value(&store, &a1).await.is_none());
    assert!(get_value(&store, &b1).await.is_none());
    assert_eq!(
        get_value(&store, b"raw").await.as_deref(),
        Some(b"raw".as_slice())
    );
    backend.close(store).await;
}

pub async fn keys_keep_latest_deletes_old_versions_without_advancing_sequence<B: Backend>(
    backend: &B,
) {
    let (_location, store) = fresh(backend).await;
    let v1 = versioned_key(b"row", 1);
    let v2 = versioned_key(b"row", 2);
    let v3 = versioned_key(b"row", 3);
    let initial_sequence = commit(
        backend,
        &store,
        vec![
            (v1.clone(), Bytes::from_static(b"v1")),
            (v2.clone(), Bytes::from_static(b"v2")),
            (v3.clone(), Bytes::from_static(b"v3")),
        ],
    )
    .await;

    apply_prune(
        &store,
        &[version_policy(RetainPolicy::KeepLatest { count: 1 })],
    )
    .await;

    assert!(get_value(&store, &v1).await.is_none());
    assert!(get_value(&store, &v2).await.is_none());
    assert_eq!(
        get_value(&store, &v3).await.as_deref(),
        Some(b"v3".as_slice())
    );
    assert_eq!(store.current_sequence(), initial_sequence);
    assert!(store
        .get_batch(initial_sequence + 1)
        .await
        .expect("get_batch must succeed")
        .is_none());
    backend.close(store).await;
}

pub async fn key_prune_is_idempotent_when_reapplied<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let v1 = versioned_key(b"row", 1);
    let v2 = versioned_key(b"row", 2);
    let v3 = versioned_key(b"row", 3);
    let initial_sequence = commit(
        backend,
        &store,
        vec![
            (v1.clone(), Bytes::from_static(b"v1")),
            (v2.clone(), Bytes::from_static(b"v2")),
            (v3.clone(), Bytes::from_static(b"v3")),
        ],
    )
    .await;
    let policy = version_policy(RetainPolicy::KeepLatest { count: 1 });

    apply_prune(&store, std::slice::from_ref(&policy)).await;
    let sequence_after_first_prune = store.current_sequence();
    apply_prune(&store, &[policy]).await;

    assert!(get_value(&store, &v1).await.is_none());
    assert!(get_value(&store, &v2).await.is_none());
    assert_eq!(
        get_value(&store, &v3).await.as_deref(),
        Some(b"v3".as_slice())
    );
    assert_eq!(sequence_after_first_prune, initial_sequence);
    assert_eq!(store.current_sequence(), sequence_after_first_prune);
    assert!(store
        .get_batch(sequence_after_first_prune + 1)
        .await
        .expect("get_batch must succeed")
        .is_none());
    backend.close(store).await;
}

pub async fn keys_threshold_retains_greater_than_or_equal_versions<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let v3 = versioned_key(b"row", 3);
    let v4 = versioned_key(b"row", 4);
    let v5 = versioned_key(b"row", 5);
    commit(
        backend,
        &store,
        vec![
            (v3.clone(), Bytes::from_static(b"v3")),
            (v4.clone(), Bytes::from_static(b"v4")),
            (v5.clone(), Bytes::from_static(b"v5")),
        ],
    )
    .await;

    apply_prune(
        &store,
        &[version_policy(RetainPolicy::GreaterThanOrEqual {
            threshold: 4,
        })],
    )
    .await;

    assert!(get_value(&store, &v3).await.is_none());
    assert_eq!(
        get_value(&store, &v4).await.as_deref(),
        Some(b"v4".as_slice())
    );
    assert_eq!(
        get_value(&store, &v5).await.as_deref(),
        Some(b"v5".as_slice())
    );
    backend.close(store).await;
}

pub async fn keys_threshold_greater_than_is_strict<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let versions: Vec<_> = (3..=5)
        .map(|version| versioned_key(b"row", version))
        .collect();
    commit_keys(backend, &store, &versions).await;

    apply_prune(
        &store,
        &[version_policy(RetainPolicy::GreaterThan { threshold: 4 })],
    )
    .await;

    assert_present::<B>(&store, &[&versions[2]], &[&versions[0], &versions[1]]).await;
    backend.close(store).await;
}

pub async fn keys_prune_retains_per_group<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let a: Vec<_> = (1..=3)
        .map(|version| versioned_key(b"a", version))
        .collect();
    let b: Vec<_> = (4..=6)
        .map(|version| versioned_key(b"b", version))
        .collect();

    // A family key the payload regex does not match, and a key outside the family.
    let loose = family_key(b"loose");
    let outside = Bytes::from_static(b"outside");
    let mut keys = [a.clone(), b.clone()].concat();
    keys.extend([loose.clone(), outside.clone()]);
    commit_keys(backend, &store, &keys).await;

    // Grouped by logical name, each group keeps its own two newest versions.
    apply_prune(
        &store,
        &[version_policy(RetainPolicy::KeepLatest { count: 2 })],
    )
    .await;
    assert_present::<B>(
        &store,
        &[&a[1], &a[2], &b[1], &b[2], &loose, &outside],
        &[&a[0], &b[0]],
    )
    .await;

    // Without grouping, the matching keys form one group that keeps its newest version.
    apply_prune(
        &store,
        &[family_policy(
            VERSION_REGEX,
            &[],
            Some(("version", OrderEncoding::U64Be)),
            RetainPolicy::KeepLatest { count: 1 },
        )],
    )
    .await;
    assert_present::<B>(&store, &[&b[2], &loose, &outside], &[&a[1], &a[2], &b[1]]).await;
    backend.close(store).await;
}

/// A document applies each of its policies. Validation rejects a document with two policies over
/// nested prefixes, so the policies select disjoint keys and their order cannot change the result.
pub async fn keys_prune_applies_every_policy_of_a_document<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let family: Vec<_> = (1..=2)
        .map(|version| versioned_key(b"row", version))
        .collect();
    let other: Vec<_> = (4..=5)
        .map(|version| versioned_key_in(OTHER_PREFIX, b"row", version))
        .collect();
    let outside = Bytes::from_static(b"outside");
    let mut keys = [family.clone(), other.clone()].concat();
    keys.push(outside.clone());
    let sequence = commit_keys(backend, &store, &keys).await;

    let mut keep_latest = version_policy(RetainPolicy::KeepLatest { count: 1 });
    keep_latest.scope.selector.prefix = Bytes::from(vec![OTHER_PREFIX]);
    apply_prune(
        &store,
        &[version_policy(RetainPolicy::DropAll), keep_latest],
    )
    .await;

    assert_present::<B>(
        &store,
        &[&other[1], &outside],
        &[&family[0], &family[1], &other[0]],
    )
    .await;
    assert_eq!(store.current_sequence(), sequence);
    backend.close(store).await;
}

pub async fn keys_prune_orders_versions_by_each_encoding<B: Backend>(backend: &B) {
    // The same eight bytes are the largest u64_be version and the i64_be version -1.
    let small = versioned_key(b"row", 1);
    let large = versioned_key(b"row", u64::MAX);
    for (encoding, newest, oldest) in [
        (OrderEncoding::U64Be, &large, &small),
        (OrderEncoding::I64Be, &small, &large),
    ] {
        let (_location, store) = fresh(backend).await;
        commit_keys(backend, &store, &[small.clone(), large.clone()]).await;
        apply_prune(
            &store,
            &[version_policy_with_encoding(
                RetainPolicy::KeepLatest { count: 1 },
                encoding,
            )],
        )
        .await;
        assert_present::<B>(&store, &[newest], &[oldest]).await;
        backend.close(store).await;
    }

    // bytes_asc compares the captured bytes, so the version "9" is newer than "10".
    let (_location, store) = fresh(backend).await;
    let nine = family_key(b"row/9");
    let ten = family_key(b"row/10");
    commit_keys(backend, &store, &[nine.clone(), ten.clone()]).await;
    apply_prune(
        &store,
        &[family_policy(
            "(?s-u)^(?P<logical>[^/]*)/(?P<version>.*)$",
            &["logical"],
            Some(("version", OrderEncoding::BytesAsc)),
            RetainPolicy::KeepLatest { count: 1 },
        )],
    )
    .await;
    assert_present::<B>(&store, &[&nine], &[&ten]).await;
    backend.close(store).await;
}

/// Key pruning and log retention target different data and compose. The prune deletes current
/// rows, retention trims log batches, and neither advances the ingest frontier.
pub async fn keys_prune_and_retention_compose<B: Backend>(backend: &B) {
    let (location, store) = fresh(backend).await;
    let v1 = versioned_key(b"row", 1);
    let v2 = versioned_key(b"row", 2);
    let v3 = versioned_key(b"row", 3);
    commit(
        backend,
        &store,
        vec![(v1.clone(), Bytes::from_static(b"v1"))],
    )
    .await;
    commit(
        backend,
        &store,
        vec![(v2.clone(), Bytes::from_static(b"v2"))],
    )
    .await;
    let last = commit(
        backend,
        &store,
        vec![(v3.clone(), Bytes::from_static(b"v3"))],
    )
    .await;

    // The prune keeps only the newest key version and retention only the newest log batch.
    apply_prune(
        &store,
        &[version_policy(RetainPolicy::KeepLatest { count: 1 })],
    )
    .await;
    assert_eq!(
        set_retention(&store, Some(RetentionPolicy::KeepLatest { count: 1 })).await,
        Some(last)
    );

    assert!(get_value(&store, &v1).await.is_none());
    assert!(get_value(&store, &v2).await.is_none());
    assert_eq!(
        get_value(&store, &v3).await.as_deref(),
        Some(b"v3".as_slice())
    );
    assert!(!has_batch(&store, last - 2).await);
    assert!(!has_batch(&store, last - 1).await);
    assert!(has_batch(&store, last).await);
    assert_eq!(store.current_sequence(), last);

    // A reopen brings back neither the pruned rows nor the evicted log batches, and keeps the
    // frontier.
    let store = reopen(backend, store, &location).await;
    assert_eq!(store.current_sequence(), last);
    assert!(get_value(&store, &v1).await.is_none());
    assert!(get_value(&store, &v2).await.is_none());
    assert_eq!(
        get_value(&store, &v3).await.as_deref(),
        Some(b"v3".as_slice())
    );
    assert!(!has_batch(&store, last - 1).await);
    assert!(has_batch(&store, last).await);
    backend.close(store).await;
}

pub async fn key_pruned_state_survives_reopen_when_versions_share_a_batch<B: Backend>(backend: &B) {
    let (location, store) = fresh(backend).await;
    let v1 = versioned_key(b"row", 1);
    let v2 = versioned_key(b"row", 2);
    let v3 = versioned_key(b"row", 3);

    // All versions land in one batch, so one retained log batch holds the pruned keys.
    commit(
        backend,
        &store,
        vec![
            (v1.clone(), Bytes::from_static(b"v1")),
            (v2.clone(), Bytes::from_static(b"v2")),
            (v3.clone(), Bytes::from_static(b"v3")),
        ],
    )
    .await;

    apply_prune(
        &store,
        &[version_policy(RetainPolicy::KeepLatest { count: 1 })],
    )
    .await;
    assert!(get_value(&store, &v1).await.is_none());
    assert!(get_value(&store, &v2).await.is_none());

    // The log still holds the pruned keys, and a reopen must not bring them back.
    let store = reopen(backend, store, &location).await;
    assert!(get_value(&store, &v1).await.is_none());
    assert!(get_value(&store, &v2).await.is_none());
    assert_eq!(
        get_value(&store, &v3).await.as_deref(),
        Some(b"v3".as_slice())
    );
    backend.close(store).await;
}
