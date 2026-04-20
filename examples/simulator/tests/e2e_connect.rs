use bytes::Bytes;
use commonware_codec::Encode;
use connectrpc::client::ClientConfig;
use exoware_sdk_rs::common::MatchKey as ProtoMatchKey;
use exoware_sdk_rs::compact::{
    policy, policy_retain, KeysScope as ProtoKeysScope, Policy, PolicyGroupBy, PolicyOrderBy,
    PolicyOrderEncoding, PolicyRetain, PruneRequest, RetainGreaterThan, RetainKeepLatest,
    ServiceClient as CompactServiceClient,
};
use exoware_sdk_rs::keys::{Key, KeyCodec};
use exoware_sdk_rs::kv_codec::{
    KvExpr, KvFieldKind, KvFieldRef, KvReducedValue, StoredRow, StoredValue,
};
use exoware_sdk_rs::match_key::MatchKey as DomainMatchKey;
use exoware_sdk_rs::prune_policy;
use exoware_sdk_rs::{
    connect_compression_registry, PreferZstdHttpClient, RangeMode, RangeReduceOp,
    RangeReduceRequest, RangeReducerSpec, RetryConfig, StoreClient,
};
use tempfile::tempdir;

async fn spawn_client() -> (tokio::task::JoinHandle<()>, StoreClient, String) {
    let dir = tempdir().expect("tempdir");
    let dir_path = dir.path().to_owned();
    let _dir = dir;
    let (handle, url) = exoware_simulator::spawn_for_test(&dir_path)
        .await
        .expect("spawn_for_test");
    let client = StoreClient::builder()
        .url(&url)
        .retry_config(RetryConfig::disabled())
        .build()
        .expect("build client");
    (handle, client, url)
}

fn key(b: &[u8]) -> Key {
    Bytes::copy_from_slice(b)
}

// -- put + get --

#[tokio::test]
async fn put_and_get_round_trip() {
    let (_h, client, _url) = spawn_client().await;
    let k = key(b"hello");
    let v = b"world";
    let seq = client.put(&[(&k, v)]).await.expect("put");
    assert!(seq > 0);

    let got = client.get(&k).await.expect("get");
    assert_eq!(got.as_deref(), Some(v.as_slice()));
}

#[tokio::test]
async fn get_missing_key_returns_none() {
    let (_h, client, _url) = spawn_client().await;
    let got = client.get(&key(b"nope")).await.expect("get");
    assert!(got.is_none());
}

#[tokio::test]
async fn put_overwrites_value() {
    let (_h, client, _url) = spawn_client().await;
    let k = key(b"k");
    client.put(&[(&k, b"v1")]).await.expect("put1");
    let seq2 = client.put(&[(&k, b"v2")]).await.expect("put2");
    let got = client
        .get_with_min_sequence_number(&k, seq2)
        .await
        .expect("get");
    assert_eq!(got.as_deref(), Some(b"v2".as_slice()));
}

// -- get_many --

#[tokio::test]
async fn get_many_returns_found_and_missing() {
    let (_h, client, _url) = spawn_client().await;
    let ka = key(b"a");
    let kb = key(b"b");
    let kc = key(b"c");
    client.put(&[(&ka, b"1"), (&kc, b"3")]).await.expect("put");

    let stream = client
        .get_many(&[&ka, &kb, &kc], 100)
        .await
        .expect("get_many");
    let map = stream.collect().await.expect("collect");
    assert_eq!(map.get(&ka).map(|v| v.as_ref()), Some(b"1".as_slice()));
    assert!(!map.contains_key(&kb));
    assert_eq!(map.get(&kc).map(|v| v.as_ref()), Some(b"3".as_slice()));
}

// -- range --

#[tokio::test]
async fn range_forward() {
    let (_h, client, _url) = spawn_client().await;
    let ka = key(b"ra");
    let kb = key(b"rb");
    let kc = key(b"rc");
    client
        .put(&[(&ka, b"1"), (&kb, b"2"), (&kc, b"3")])
        .await
        .expect("put");

    let rows = client
        .range(&key(b"ra"), &key(b"rc"), 100)
        .await
        .expect("range");
    let keys: Vec<&[u8]> = rows.iter().map(|(k, _)| k.as_ref()).collect();
    assert_eq!(keys, vec![b"ra".as_slice(), b"rb", b"rc"]);
}

#[tokio::test]
async fn range_reverse() {
    let (_h, client, _url) = spawn_client().await;
    let ka = key(b"sa");
    let kb = key(b"sb");
    let kc = key(b"sc");
    client
        .put(&[(&ka, b"1"), (&kb, b"2"), (&kc, b"3")])
        .await
        .expect("put");

    let rows = client
        .range_with_mode(&key(b"sa"), &key(b"sc"), 100, RangeMode::Reverse)
        .await
        .expect("range_reverse");
    let keys: Vec<&[u8]> = rows.iter().map(|(k, _)| k.as_ref()).collect();
    assert_eq!(keys, vec![b"sc".as_slice(), b"sb", b"sa"]);
}

#[tokio::test]
async fn range_with_limit() {
    let (_h, client, _url) = spawn_client().await;
    let ka = key(b"la");
    let kb = key(b"lb");
    let kc = key(b"lc");
    client
        .put(&[(&ka, b"1"), (&kb, b"2"), (&kc, b"3")])
        .await
        .expect("put");

    let rows = client
        .range(&key(b"la"), &key(b"lc"), 2)
        .await
        .expect("range");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0.as_ref(), b"la");
    assert_eq!(rows[1].0.as_ref(), b"lb");
}

#[tokio::test]
async fn range_empty_result() {
    let (_h, client, _url) = spawn_client().await;
    let rows = client
        .range(&key(b"zzz_no"), &key(b"zzz_nz"), 100)
        .await
        .expect("range");
    assert!(rows.is_empty());
}

// -- reduce (count_all) --

#[tokio::test]
async fn reduce_count_all() {
    let (_h, client, _url) = spawn_client().await;
    let ka = key(b"ca");
    let kb = key(b"cb");
    let kc = key(b"cc");
    client
        .put(&[(&ka, b"1"), (&kb, b"2"), (&kc, b"3")])
        .await
        .expect("put");

    let request = RangeReduceRequest {
        reducers: vec![RangeReducerSpec {
            op: RangeReduceOp::CountAll,
            expr: None,
        }],
        group_by: vec![],
        filter: None,
    };
    let results = client
        .range_reduce(&key(b"ca"), &key(b"cc"), &request)
        .await
        .expect("reduce");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], Some(KvReducedValue::UInt64(3)));
}

// -- reduce (sum of uint64 field) --

#[tokio::test]
async fn reduce_sum_int64() {
    let (_h, client, _url) = spawn_client().await;
    let ka = key(b"ua");
    let kb = key(b"ub");
    let kc = key(b"uc");
    let encode_row = |v: i64| -> Vec<u8> {
        StoredRow {
            values: vec![Some(StoredValue::Int64(v))],
        }
        .encode()
        .to_vec()
    };
    client
        .put(&[
            (&ka, encode_row(10).as_slice()),
            (&kb, encode_row(20).as_slice()),
            (&kc, encode_row(30).as_slice()),
        ])
        .await
        .expect("put");

    let request = RangeReduceRequest {
        reducers: vec![RangeReducerSpec {
            op: RangeReduceOp::SumField,
            expr: Some(KvExpr::Field(KvFieldRef::Value {
                index: 0,
                kind: KvFieldKind::Int64,
                nullable: true,
            })),
        }],
        group_by: vec![],
        filter: None,
    };
    let results = client
        .range_reduce(&key(b"ua"), &key(b"uc"), &request)
        .await
        .expect("reduce");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], Some(KvReducedValue::Int64(60)));
}

// -- prune via compact ServiceClient --

#[tokio::test]
async fn prune_drop_all_removes_keys() {
    let (_h, client, url) = spawn_client().await;

    let codec = KeyCodec::new(4, 1);
    let ka = codec.encode(b"aaa").expect("encode key a");
    let kb = codec.encode(b"bbb").expect("encode key b");
    let kc = codec.encode(b"ccc").expect("encode key c");
    client
        .put(&[(&ka, b"va"), (&kb, b"vb"), (&kc, b"vc")])
        .await
        .expect("put");

    // Verify keys exist
    assert!(client.get(&ka).await.expect("get a").is_some());

    let compact_config = ClientConfig::new(url.parse::<http::Uri>().unwrap())
        .compression(connect_compression_registry());
    let compact_client =
        CompactServiceClient::new(PreferZstdHttpClient::plaintext(), compact_config);
    compact_client
        .prune(PruneRequest {
            policies: vec![Policy {
                scope: Some(policy::Scope::Keys(Box::new(ProtoKeysScope {
                    match_key: Some(ProtoMatchKey {
                        reserved_bits: 4,
                        prefix: 1,
                        payload_regex: "(?s-u)^.*$".to_string(),
                        ..Default::default()
                    })
                    .into(),
                    group_by: Some(PolicyGroupBy {
                        capture_groups: vec![],
                        ..Default::default()
                    })
                    .into(),
                    order_by: Default::default(),
                    ..Default::default()
                }))),
                retain: Some(PolicyRetain {
                    kind: Some(policy_retain::Kind::DropAll(Box::default())),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }],
            ..Default::default()
        })
        .await
        .expect("prune");

    // All keys in this prefix should be gone
    assert!(client.get(&ka).await.expect("get a").is_none());
    assert!(client.get(&kb).await.expect("get b").is_none());
    assert!(client.get(&kc).await.expect("get c").is_none());
}

// -- sequence number tracking --

#[tokio::test]
async fn sequence_number_advances() {
    let (_h, client, _url) = spawn_client().await;
    let k1 = key(b"s1");
    let k2 = key(b"s2");
    let seq1 = client.put(&[(&k1, b"v1")]).await.expect("put1");
    let seq2 = client.put(&[(&k2, b"v2")]).await.expect("put2");
    assert!(seq2 > seq1);
    assert!(client.sequence_number() >= seq2);
}

// -- health --

#[tokio::test]
async fn health_endpoint() {
    let (_h, client, _url) = spawn_client().await;
    assert!(client.health().await.expect("health"));
}

// -- batch put multiple keys --

#[tokio::test]
async fn put_batch_multiple_keys() {
    let (_h, client, _url) = spawn_client().await;
    let ka = key(b"ba");
    let kb = key(b"bb");
    let kc = key(b"bc");
    client
        .put(&[(&ka, b"1"), (&kb, b"2"), (&kc, b"3")])
        .await
        .expect("put batch");

    assert_eq!(
        client.get(&ka).await.expect("get a").as_deref(),
        Some(b"1".as_slice())
    );
    assert_eq!(
        client.get(&kb).await.expect("get b").as_deref(),
        Some(b"2".as_slice())
    );
    assert_eq!(
        client.get(&kc).await.expect("get c").as_deref(),
        Some(b"3".as_slice())
    );
}

// -- range stream --

#[tokio::test]
async fn range_stream_collects_all() {
    let (_h, client, _url) = spawn_client().await;
    let ka = key(b"xa");
    let kb = key(b"xb");
    let kc = key(b"xc");
    let kd = key(b"xd");
    client
        .put(&[(&ka, b"1"), (&kb, b"2"), (&kc, b"3"), (&kd, b"4")])
        .await
        .expect("put");

    let stream = client
        .range_stream(&key(b"xa"), &key(b"xd"), 100, 2)
        .await
        .expect("range_stream");
    let rows = stream.collect().await.expect("collect");
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0].0.as_ref(), b"xa");
    assert_eq!(rows[3].0.as_ref(), b"xd");
}

// -- min_sequence_number consistency --

#[tokio::test]
async fn get_with_min_sequence_number() {
    let (_h, client, _url) = spawn_client().await;
    let k = key(b"msn");
    let seq = client.put(&[(&k, b"val")]).await.expect("put");
    let got = client
        .get_with_min_sequence_number(&k, seq)
        .await
        .expect("get with min seq");
    assert_eq!(got.as_deref(), Some(b"val".as_slice()));
}

// -- prune keep_latest --

#[tokio::test]
async fn prune_keep_latest_retains_newest() {
    let (_h, client, url) = spawn_client().await;

    let codec = KeyCodec::new(4, 2);
    // Keys: prefix(4bits,family=2) + logical(3 bytes) + \x00\x00 + version(8 bytes big-endian u64)
    // This matches the regex: ^(?P<logical>.{3})\x00\x00(?P<version>.{8})$
    let make_key = |logical: &[u8; 3], version: u64| -> Key {
        let mut payload = Vec::with_capacity(3 + 2 + 8);
        payload.extend_from_slice(logical);
        payload.extend_from_slice(&[0x00, 0x00]);
        payload.extend_from_slice(&version.to_be_bytes());
        codec.encode(&payload).expect("encode key")
    };

    let k_a1 = make_key(b"aaa", 1);
    let k_a2 = make_key(b"aaa", 2);
    let k_a3 = make_key(b"aaa", 3);
    let k_b1 = make_key(b"bbb", 1);

    client
        .put(&[
            (&k_a1, b"a-v1"),
            (&k_a2, b"a-v2"),
            (&k_a3, b"a-v3"),
            (&k_b1, b"b-v1"),
        ])
        .await
        .expect("put");

    let compact_config = ClientConfig::new(url.parse::<http::Uri>().unwrap())
        .compression(connect_compression_registry());
    let compact_client =
        CompactServiceClient::new(PreferZstdHttpClient::plaintext(), compact_config);
    compact_client
        .prune(PruneRequest {
            policies: vec![Policy {
                scope: Some(policy::Scope::Keys(Box::new(ProtoKeysScope {
                    match_key: Some(ProtoMatchKey {
                        reserved_bits: 4,
                        prefix: 2,
                        payload_regex: "(?s-u)^(?P<logical>.{3})\\x00\\x00(?P<version>.{8})$"
                            .to_string(),
                        ..Default::default()
                    })
                    .into(),
                    group_by: Some(PolicyGroupBy {
                        capture_groups: vec!["logical".to_string()],
                        ..Default::default()
                    })
                    .into(),
                    order_by: Some(PolicyOrderBy {
                        capture_group: "version".to_string(),
                        encoding: PolicyOrderEncoding::POLICY_ORDER_ENCODING_U64_BE.into(),
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                }))),
                retain: Some(PolicyRetain {
                    kind: Some(policy_retain::Kind::KeepLatest(Box::new(
                        RetainKeepLatest {
                            count: 1,
                            ..Default::default()
                        },
                    ))),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }],
            ..Default::default()
        })
        .await
        .expect("prune keep_latest");

    // Only the newest version of group "aaa" (version=3) should survive
    assert!(client.get(&k_a1).await.expect("get a1").is_none());
    assert!(client.get(&k_a2).await.expect("get a2").is_none());
    assert_eq!(
        client.get(&k_a3).await.expect("get a3").as_deref(),
        Some(b"a-v3".as_slice())
    );
    // Group "bbb" has only 1 entry, which is its latest -- should survive
    assert_eq!(
        client.get(&k_b1).await.expect("get b1").as_deref(),
        Some(b"b-v1".as_slice())
    );
}

// -- reduce count_field, min_field, max_field --

#[tokio::test]
async fn reduce_count_min_max_field() {
    let (_h, client, _url) = spawn_client().await;
    let encode_row = |v: i64| -> Vec<u8> {
        StoredRow {
            values: vec![Some(StoredValue::Int64(v))],
        }
        .encode()
        .to_vec()
    };
    client
        .put(&[
            (&key(b"fa"), encode_row(10).as_slice()),
            (&key(b"fb"), encode_row(30).as_slice()),
            (&key(b"fc"), encode_row(20).as_slice()),
        ])
        .await
        .expect("put");

    let field = KvExpr::Field(KvFieldRef::Value {
        index: 0,
        kind: KvFieldKind::Int64,
        nullable: true,
    });
    let request = RangeReduceRequest {
        reducers: vec![
            RangeReducerSpec {
                op: RangeReduceOp::CountField,
                expr: Some(field.clone()),
            },
            RangeReducerSpec {
                op: RangeReduceOp::MinField,
                expr: Some(field.clone()),
            },
            RangeReducerSpec {
                op: RangeReduceOp::MaxField,
                expr: Some(field),
            },
        ],
        group_by: vec![],
        filter: None,
    };
    let results = client
        .range_reduce(&key(b"fa"), &key(b"fc"), &request)
        .await
        .expect("reduce");
    assert_eq!(results.len(), 3);
    assert_eq!(results[0], Some(KvReducedValue::UInt64(3)));
    assert_eq!(results[1], Some(KvReducedValue::Int64(10)));
    assert_eq!(results[2], Some(KvReducedValue::Int64(30)));
}

// -- reduce with group_by --

#[tokio::test]
async fn reduce_grouped_count() {
    let (_h, client, _url) = spawn_client().await;
    let codec = KeyCodec::new(4, 1);
    let encode_row = |v: i64| -> Vec<u8> {
        StoredRow {
            values: vec![Some(StoredValue::Int64(v))],
        }
        .encode()
        .to_vec()
    };
    let ka1 = codec.encode(b"a\x01").expect("encode");
    let ka2 = codec.encode(b"a\x02").expect("encode");
    let kb1 = codec.encode(b"b\x01").expect("encode");

    client
        .put(&[
            (&ka1, encode_row(1).as_slice()),
            (&ka2, encode_row(2).as_slice()),
            (&kb1, encode_row(3).as_slice()),
        ])
        .await
        .expect("put");

    let request = RangeReduceRequest {
        reducers: vec![RangeReducerSpec {
            op: RangeReduceOp::CountAll,
            expr: None,
        }],
        group_by: vec![KvExpr::Field(KvFieldRef::Key {
            bit_offset: 4 + 1,
            kind: KvFieldKind::FixedSizeBinary(1),
        })],
        filter: None,
    };
    let response = client
        .range_reduce_response(&ka1, &kb1, &request)
        .await
        .expect("reduce");
    assert_eq!(response.groups.len(), 2);
}

// -- prune via StoreClient::prune() --

#[tokio::test]
async fn store_client_prune_drop_all() {
    let (_h, client, _url) = spawn_client().await;

    let codec = KeyCodec::new(4, 5);
    let ka = codec.encode(b"pa").expect("encode");
    let kb = codec.encode(b"pb").expect("encode");
    client
        .put(&[(&ka, b"v1"), (&kb, b"v2")])
        .await
        .expect("put");
    assert!(client.get(&ka).await.expect("get").is_some());

    client
        .prune(&[prune_policy::PrunePolicy {
            scope: prune_policy::PolicyScope::Keys(prune_policy::KeysScope {
                match_key: DomainMatchKey {
                    reserved_bits: 4,
                    prefix: 5,
                    payload_regex: ".*".into(),
                },
                group_by: prune_policy::GroupBy::default(),
                order_by: None,
            }),
            retain: prune_policy::RetainPolicy::DropAll,
        }])
        .await
        .expect("prune");

    assert!(client.get(&ka).await.expect("get").is_none());
    assert!(client.get(&kb).await.expect("get").is_none());
}

// -- prune with GreaterThan retain --

#[tokio::test]
async fn prune_greater_than_retains_above_threshold() {
    let (_h, client, url) = spawn_client().await;

    let codec = KeyCodec::new(4, 3);
    let make_key = |logical: &[u8; 2], version: u64| -> Key {
        let mut payload = Vec::with_capacity(2 + 8);
        payload.extend_from_slice(logical);
        payload.extend_from_slice(&version.to_be_bytes());
        codec.encode(&payload).expect("encode")
    };

    let k_a10 = make_key(b"aa", 10);
    let k_a20 = make_key(b"aa", 20);
    let k_a30 = make_key(b"aa", 30);

    client
        .put(&[(&k_a10, b"v10"), (&k_a20, b"v20"), (&k_a30, b"v30")])
        .await
        .expect("put");

    let compact_config = ClientConfig::new(url.parse::<http::Uri>().unwrap())
        .compression(connect_compression_registry());
    let compact_client =
        CompactServiceClient::new(PreferZstdHttpClient::plaintext(), compact_config);
    compact_client
        .prune(PruneRequest {
            policies: vec![Policy {
                scope: Some(policy::Scope::Keys(Box::new(ProtoKeysScope {
                    match_key: Some(ProtoMatchKey {
                        reserved_bits: 4,
                        prefix: 3,
                        payload_regex: "(?s-u)^(?P<logical>.{2})(?P<version>.{8})$".to_string(),
                        ..Default::default()
                    })
                    .into(),
                    group_by: Some(PolicyGroupBy {
                        capture_groups: vec!["logical".to_string()],
                        ..Default::default()
                    })
                    .into(),
                    order_by: Some(PolicyOrderBy {
                        capture_group: "version".to_string(),
                        encoding: PolicyOrderEncoding::POLICY_ORDER_ENCODING_U64_BE.into(),
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                }))),
                retain: Some(PolicyRetain {
                    kind: Some(policy_retain::Kind::GreaterThan(Box::new(
                        RetainGreaterThan {
                            threshold: 15,
                            ..Default::default()
                        },
                    ))),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }],
            ..Default::default()
        })
        .await
        .expect("prune greater_than");

    assert!(client.get(&k_a10).await.expect("get a10").is_none());
    assert!(client.get(&k_a20).await.expect("get a20").is_some());
    assert!(client.get(&k_a30).await.expect("get a30").is_some());
}
