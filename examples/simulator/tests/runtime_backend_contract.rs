#![cfg(feature = "commonware-runtime-backend")]

use std::sync::Arc;

use bytes::Bytes;
use commonware_runtime::{deterministic, Metrics as _, Runner as _};
use exoware_sdk::{
    keys::{Key, KeyCodec},
    kv_codec::Utf8,
    match_key::MatchKey,
    prune_policy::{
        GroupBy, KeysScope, PolicyScope, PrunePolicy, RetainPolicy, PRUNE_POLICY_DOCUMENT_VERSION,
    },
};
use exoware_server::{AppState, Ingest, Log, Prune, Query, RangeScan, Sequence};
use exoware_simulator::{RuntimeKvBackend, RuntimeKvConfig, Store};

const PARTITION: &str = "simulator_store";
const STATE_BLOB: &[u8] = b"state";

fn runtime_config() -> RuntimeKvConfig {
    RuntimeKvConfig {
        partition: PARTITION.to_string(),
        name: STATE_BLOB.to_vec(),
    }
}

fn key(bytes: &[u8]) -> Key {
    Bytes::copy_from_slice(bytes)
}

async fn collect_range<B>(
    store: &Store<B>,
    start: &[u8],
    end: &[u8],
    limit: usize,
    forward: bool,
) -> Vec<(Bytes, Bytes)>
where
    B: exoware_simulator::KvBackend,
{
    let mut cursor = store
        .range_scan(
            Bytes::copy_from_slice(start),
            Bytes::copy_from_slice(end),
            limit,
            forward,
        )
        .await
        .expect("range scan");
    let mut rows = Vec::new();
    loop {
        let batch = cursor.next_batch(usize::MAX).await.expect("range batch");
        if batch.rows.is_empty() {
            break;
        }
        rows.extend(batch.rows);
    }
    rows
}

#[test]
fn runtime_backend_store_contract_and_reinit() {
    deterministic::Runner::default().start(|context| async move {
        let backend = RuntimeKvBackend::init(context.with_label("store"), runtime_config())
            .await
            .expect("runtime backend");
        let store = Store::new(backend);

        let seq = store
            .put_batch(vec![
                (Bytes::from_static(b"a"), Bytes::from_static(b"1")),
                (Bytes::from_static(b"b"), Bytes::new()),
                (Bytes::from_static(b"c"), Bytes::from_static(b"3")),
            ])
            .await
            .expect("put");
        assert_eq!(seq, 1);

        let got = store.get(Bytes::from_static(b"b")).await.expect("get").0;
        assert_eq!(got, Some(Vec::new()));

        let many = store
            .get_many(vec![
                Bytes::from_static(b"a"),
                Bytes::from_static(b"missing"),
                Bytes::from_static(b"c"),
            ])
            .await
            .expect("get_many")
            .0;
        assert_eq!(many[0], (b"a".to_vec(), Some(b"1".to_vec())));
        assert_eq!(many[1], (b"missing".to_vec(), None));
        assert_eq!(many[2], (b"c".to_vec(), Some(b"3".to_vec())));

        let forward = collect_range(&store, b"a", b"c", usize::MAX, true).await;
        let forward_keys: Vec<&[u8]> = forward.iter().map(|(k, _)| k.as_ref()).collect();
        assert_eq!(forward_keys, vec![b"a".as_slice(), b"b", b"c"]);

        let reverse = collect_range(&store, b"a", b"c", 2, false).await;
        let reverse_keys: Vec<&[u8]> = reverse.iter().map(|(k, _)| k.as_ref()).collect();
        assert_eq!(reverse_keys, vec![b"c".as_slice(), b"b"]);

        drop(store);

        let reopened_backend =
            RuntimeKvBackend::init(context.with_label("store_reopen"), runtime_config())
                .await
                .expect("reopen runtime backend");
        let reopened = Store::new(reopened_backend);
        assert_eq!(reopened.current_sequence(), 1);
        assert_eq!(
            reopened
                .get(Bytes::from_static(b"a"))
                .await
                .expect("get after reopen")
                .0
                .as_deref(),
            Some(b"1".as_slice())
        );
        assert_eq!(
            reopened
                .put_batch(vec![(Bytes::from_static(b"d"), Bytes::from_static(b"4"))])
                .await
                .expect("put after reopen"),
            2
        );
    });
}

#[test]
fn runtime_backend_batch_log_and_prune_contracts() {
    deterministic::Runner::default().start(|context| async move {
        let backend = RuntimeKvBackend::init(context.with_label("store"), runtime_config())
            .await
            .expect("runtime backend");
        let store = Store::new(backend);

        let codec = KeyCodec::new(4, 1);
        let encoded = |logical: &[u8]| -> Bytes {
            Bytes::copy_from_slice(codec.encode(logical).expect("encode key").as_ref())
        };
        let old = encoded(b"row-old");
        let new = encoded(b"row-new");

        let seq1 = store
            .put_batch(vec![(old.clone(), Bytes::from_static(b"old"))])
            .await
            .expect("put old");
        let seq2 = store
            .put_batch(vec![(new.clone(), Bytes::from_static(b"new"))])
            .await
            .expect("put new");
        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(
            store.get_batch(1).await.expect("batch 1"),
            Some(vec![(old.clone(), Bytes::from_static(b"old"))])
        );

        let key_policy = PrunePolicy {
            scope: PolicyScope::Keys(KeysScope {
                match_key: MatchKey {
                    reserved_bits: 4,
                    prefix: 1,
                    payload_regex: Utf8::from("(?s-u)^row-old$"),
                },
                group_by: GroupBy::default(),
                order_by: None,
            }),
            retain: RetainPolicy::DropAll,
        };
        store
            .apply_prune_policies(exoware_sdk::prune_policy::PrunePolicyDocument {
                version: PRUNE_POLICY_DOCUMENT_VERSION,
                policies: vec![key_policy],
            })
            .await
            .expect("key prune");
        assert!(store.get(old.clone()).await.expect("old get").0.is_none());
        assert_eq!(
            store.get(new.clone()).await.expect("new get").0.as_deref(),
            Some(b"new".as_slice())
        );

        let sequence_policy = PrunePolicy {
            scope: PolicyScope::Sequence,
            retain: RetainPolicy::KeepLatest { count: 1 },
        };
        store
            .apply_prune_policies(exoware_sdk::prune_policy::PrunePolicyDocument {
                version: PRUNE_POLICY_DOCUMENT_VERSION,
                policies: vec![sequence_policy],
            })
            .await
            .expect("sequence prune");
        assert!(store
            .get_batch(1)
            .await
            .expect("batch 1 after prune")
            .is_none());
        assert!(store
            .get_batch(2)
            .await
            .expect("batch 2 after prune")
            .is_none());
        assert!(store
            .get_batch(3)
            .await
            .expect("empty prune batch")
            .is_some());
    });
}

#[test]
fn in_process_store_client_uses_sdk_without_http() {
    deterministic::Runner::default().start(|context| async move {
        let backend = RuntimeKvBackend::init(context.with_label("store"), runtime_config())
            .await
            .expect("runtime backend");
        let store = Arc::new(Store::new(backend));
        let state = AppState::new(store);
        let client = exoware_server::in_process::store_client(state);

        let client_key = key(b"client-key");
        let seq = client
            .ingest()
            .put(&[(&client_key, b"value")])
            .await
            .expect("sdk put");
        assert_eq!(seq, 1);
        assert_eq!(
            client
                .query()
                .get(&client_key)
                .await
                .expect("sdk get")
                .as_deref(),
            Some(b"value".as_slice())
        );

        let rows = client
            .query()
            .range(&key(b"client-"), &key(b"client-key"), 10)
            .await
            .expect("sdk range");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0.as_ref(), b"client-key");

        client
            .compact()
            .prune(&[PrunePolicy {
                scope: PolicyScope::Keys(KeysScope {
                    match_key: MatchKey {
                        reserved_bits: 0,
                        prefix: 0,
                        payload_regex: Utf8::from("(?s-u)^client-key$"),
                    },
                    group_by: GroupBy::default(),
                    order_by: None,
                }),
                retain: RetainPolicy::DropAll,
            }])
            .await
            .expect("sdk prune");
        assert!(client
            .query()
            .get(&client_key)
            .await
            .expect("sdk get pruned")
            .is_none());
    });
}
