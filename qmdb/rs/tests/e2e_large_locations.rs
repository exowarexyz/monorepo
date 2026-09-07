//! Small batches over a caller-trusted pruned frontier exercise absolute location widths

mod common;

use std::sync::Arc;

use buffa::Message as _;
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_storage::merkle::{
    hasher::Hasher as _, mem::Mem, mmb, mmr, Graftable, Location, Position,
};
use commonware_storage::qmdb::{
    keyless::variable::Operation,
    sync::{Request, Response, Source as _},
};
use exoware_qmdb::proto::qmdb::v1::GetOperationRangeRequest;
use exoware_qmdb::{
    keyless_operation_log_connect_stack, KeylessClient, KeylessWriter, OperationLogClient,
    OperationLogSyncResolver, WriterState,
};
use exoware_sdk::{PrefixedStoreClient, StoreBatchUpload, StoreWriteBatch};

async fn check_large_frontier<F: Graftable + PartialEq>(family: &str, start: u64) {
    let store = common::local_store_client().await;
    let client = PrefixedStoreClient::empty(store.clone());
    let start = Location::<F>::new(start);
    let previous_size = Position::try_from(start).unwrap();
    // Opaque digests stand for a trusted pruned history, not four billion generated operations
    let peaks = F::peaks(previous_size)
        .enumerate()
        .map(|(index, (position, height))| (position, height, Sha256::fill(index as u8)))
        .collect::<Vec<_>>();
    let pins = peaks
        .iter()
        .map(|(_, _, digest)| *digest)
        .collect::<Vec<_>>();
    let reference = Mem::<F, Digest>::from_components(Vec::new(), start, pins).unwrap();
    let mut seed = StoreWriteBatch::new();
    for (position, _, digest) in &peaks {
        // Raw node rows are the node family byte then the big-endian position
        let mut key = vec![exoware_qmdb::NODE_FAMILY];
        key.extend_from_slice(&position.as_u64().to_be_bytes());
        seed.push(&client, &Bytes::from(key), digest.encode())
            .unwrap();
    }
    seed.commit(&store).await.unwrap();

    let operations: Vec<Operation<F, Vec<u8>>> = vec![
        Operation::Append(b"left".to_vec()),
        Operation::Append(b"right".to_vec()),
        Operation::Commit(None, start),
    ];
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let digests = operations.iter().enumerate().map(|(offset, operation)| {
        let position = Position::try_from(start + offset as u64).unwrap();
        hasher.leaf_digest(position, operation.encode().as_ref())
    });
    let reference_batch = reference
        .new_batch()
        .add_leaf_digests(digests)
        .merkleize(&reference, &hasher);
    let end = start + operations.len() as u64;
    let expected_root = reference_batch
        .root(&reference, &hasher, F::inactive_peaks(end, start))
        .unwrap();
    let writer: KeylessWriter<F, Sha256, Vec<u8>> = KeylessWriter::new(
        client.clone(),
        WriterState {
            peaks,
            ops_size: previous_size,
            next_location: start,
        },
    );
    let upload = writer.prepare_upload(operations.clone()).await.unwrap();
    let receipt = writer.commit_upload(upload).await.unwrap();
    assert_eq!(receipt.latest_location, end - 1);

    let config = ((0..=10000).into(), ());
    let reader = Arc::new(KeylessClient::<F, Sha256, Vec<u8>>::new(client, config));
    let state = reader.recover_writer_state().await.unwrap();
    assert_eq!(state.next_location, end);
    assert_eq!(state.ops_size, reference_batch.size());
    let (server, url) =
        common::spawn_connect_service(keyless_operation_log_connect_stack(reader)).await;
    let request = GetOperationRangeRequest {
        tip: (end - 1).as_u64(),
        start_location: start.as_u64(),
        max_locations: 10,
        ..Default::default()
    };
    let raw = common::operation_log_rpc_client(&url)
        .get_operation_range(request.clone())
        .await
        .unwrap()
        .into_view()
        .to_owned_message();
    let fixture = format!(
        "{}\n{}\n",
        hex::encode(expected_root),
        hex::encode(raw.proof.as_option().unwrap().encode_to_vec())
    );
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../ts/test/fixtures/{family}-{}.txt",
        start.as_u64()
    ));
    // The same proof bytes exercise the generated WASM exports in the browser client tests.
    // Set UPDATE_FIXTURES=1 to rewrite them after an intentional encoding change.
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        std::fs::write(&fixture_path, &fixture).unwrap();
    }
    assert_eq!(std::fs::read_to_string(fixture_path).unwrap(), fixture);
    let rpc = OperationLogClient::<_, F, Sha256, Operation<F, Vec<u8>>>::plaintext(&url, config);
    let verified = rpc
        .get_operation_range(request, &expected_root)
        .await
        .unwrap();
    assert_eq!(verified.start_location, start);
    assert_eq!(
        verified.operations,
        operations
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, operation)| (start + index as u64, operation))
            .collect::<Vec<_>>()
    );
    let resolver =
        OperationLogSyncResolver::<_, F, Sha256, Operation<F, Vec<u8>>>::plaintext(&url, config);
    let target = resolver
        .target_range(start, end, &expected_root)
        .await
        .unwrap();
    let (response, _) = resolver
        .serve(Request::Operations {
            size: end,
            start,
            max_ops: std::num::NonZeroU64::MAX,
        })
        .await
        .unwrap();
    let Response::Operations {
        proof,
        operations: received,
    } = response
    else {
        panic!("expected operation batch")
    };
    let encoded = received.iter().map(Encode::encode).collect::<Vec<_>>();
    assert!(proof.verify_range_inclusion(&hasher, &encoded, start, &target.root));
    assert_eq!(received, operations);
    server.abort();
}

#[tokio::test]
async fn mmr_store_and_sync_cross_u32_locations() {
    check_large_frontier::<mmr::Family>("mmr", u32::MAX as u64 - 1).await;
    check_large_frontier::<mmr::Family>("mmr", (1u64 << 53) + 1).await;
}

#[tokio::test]
async fn mmb_store_and_sync_cross_u32_locations() {
    check_large_frontier::<mmb::Family>("mmb", u32::MAX as u64 - 1).await;
    check_large_frontier::<mmb::Family>("mmb", (1u64 << 53) + 1).await;
}
