//! Immutable QMDB ConnectRPC e2e: streamed range checkpoints plus client-side
//! validation of tampered proofs.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::immutable::{
    Config as ImmutableConfig, Immutable, Operation as ImmutableOperation,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use exoware_sdk_rs::proto::PreferZstdHttpClient;
use exoware_sdk_rs::store::qmdb::v1::SubscribeRequest as ProtoSubscribeRequest;
use exoware_sdk_rs::StoreClient;
use store_qmdb::{
    immutable_range_connect_stack, ImmutableClient, ImmutableRangeConnectClient, ImmutableWriter,
    QmdbError, RangeSubscribeProof,
};

type Digest = commonware_cryptography::sha256::Digest;
type LocalDb = Immutable<
    deterministic::Context,
    FixedBytes<32>,
    Vec<u8>,
    commonware_cryptography::Sha256,
    TwoCap,
>;
type TestImmutableClient =
    ImmutableClient<commonware_cryptography::Sha256, FixedBytes<32>, Vec<u8>>;
type BatchOperation = ImmutableOperation<FixedBytes<32>, Vec<u8>>;

async fn spawn_qmdb_server(
    client: Arc<TestImmutableClient>,
) -> (tokio::task::JoinHandle<()>, String) {
    common::spawn_range_service(immutable_range_connect_stack(client)).await
}

fn validated_client(
    base: &str,
) -> ImmutableRangeConnectClient<
    PreferZstdHttpClient,
    commonware_cryptography::Sha256,
    FixedBytes<32>,
    Vec<u8>,
> {
    ImmutableRangeConnectClient::plaintext(base, ((0..=10000).into(), ()))
}

struct LocalBatch {
    operations: Vec<BatchOperation>,
    root: Digest,
}

async fn build_local_batch() -> LocalBatch {
    tokio::task::spawn_blocking(|| {
        deterministic::Runner::default().start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
            let cfg = ImmutableConfig {
                mmr_journal_partition: "immutable-mmr-journal".into(),
                mmr_metadata_partition: "immutable-mmr-metadata".into(),
                mmr_items_per_blob: NZU64!(8),
                mmr_write_buffer: NZUsize!(1024),
                log_partition: "immutable-log".into(),
                log_items_per_section: NZU64!(5),
                log_compression: None,
                log_codec_config: ((0..=10000).into(), ()),
                log_write_buffer: NZUsize!(1024),
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            };
            let mut db: LocalDb = LocalDb::init(context.with_label("db"), cfg)
                .await
                .expect("init");

            let key_a = FixedBytes::new([0x11; 32]);
            let key_b = FixedBytes::new([0x22; 32]);
            let finalized = {
                let mut batch = db.new_batch();
                batch.set(key_a, b"alpha".to_vec());
                batch.set(key_b, b"beta".to_vec());
                batch.merkleize(None::<Vec<u8>>).finalize()
            };
            db.apply_batch(finalized).await.expect("apply");

            let latest = db.bounds().await.end - 1;
            let n = NonZeroU64::new(*latest + 1).unwrap();
            let (_proof, ops) = db
                .historical_proof(latest + 1, Location::new(0), n)
                .await
                .expect("proof");
            let root = db.root();
            db.destroy().await.expect("destroy");

            LocalBatch {
                operations: ops,
                root,
            }
        })
    })
    .await
    .expect("join")
}

async fn upload_and_publish(client: &StoreClient, batch: &LocalBatch) {
    let writer: ImmutableWriter<commonware_cryptography::Sha256, FixedBytes<32>, Vec<u8>> =
        ImmutableWriter::empty(client.clone());
    writer
        .upload_and_publish(&batch.operations)
        .await
        .expect("upload_and_publish");
}

#[tokio::test]
async fn immutable_connect_subscribe_emits_verifiable_multi_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    let immutable_client = Arc::new(TestImmutableClient::from_client(
        store_client.clone(),
        ((0..=10000).into(), ()),
        ((), ((0..=10000).into(), ())),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(immutable_client).await;
    let client = validated_client(&qmdb_url);

    let mut stream = client
        .subscribe(ProtoSubscribeRequest::default())
        .await
        .expect("subscribe");

    tokio::time::sleep(Duration::from_millis(50)).await;
    upload_and_publish(&store_client, &local).await;

    let frame: RangeSubscribeProof<Digest, BatchOperation> =
        tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .expect("timeout")
            .expect("stream result")
            .expect("stream frame");

    assert!(frame.resume_sequence_number > 0);
    assert_eq!(frame.root, local.root);
    let expected: Vec<(Location, BatchOperation)> = local
        .operations
        .iter()
        .enumerate()
        .map(|(i, op)| (Location::new(i as u64), op.clone()))
        .collect();
    assert_eq!(frame.operations, expected);
}

#[tokio::test]
async fn immutable_connect_client_rejects_invalid_streamed_proof() {
    let (_dir, _store_server, store_client) = common::local_store_client().await;
    let local = build_local_batch().await;
    upload_and_publish(&store_client, &local).await;

    let immutable_client = Arc::new(TestImmutableClient::from_client(
        store_client.clone(),
        ((0..=10000).into(), ()),
        ((), ((0..=10000).into(), ())),
    ));
    let (_qmdb_server, qmdb_url) = spawn_qmdb_server(immutable_client).await;
    let rpc = common::rpc_client(&qmdb_url);
    let mut raw_stream = rpc
        .subscribe(ProtoSubscribeRequest {
            since_sequence_number: Some(1),
            ..Default::default()
        })
        .await
        .expect("subscribe");
    let raw_response = raw_stream
        .message()
        .await
        .expect("stream result")
        .expect("stream frame")
        .to_owned_message();

    let (_static_server, static_url) =
        common::spawn_static_range_service(common::StaticRangeService {
            subscribe_response: common::tamper_subscribe_response(raw_response),
        })
        .await;
    let client = validated_client(&static_url);
    let mut stream = client
        .subscribe(ProtoSubscribeRequest::default())
        .await
        .expect("subscribe");

    let err = stream
        .message()
        .await
        .expect_err("tampered streamed proof should fail");
    assert!(matches!(
        err,
        QmdbError::ProofVerification {
            kind: store_qmdb::ProofKind::BatchMulti
        }
    ));
}
