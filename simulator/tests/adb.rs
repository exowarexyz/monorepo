use axum::http::StatusCode;
use exoware_sdk_rs::Error as SdkError;
use exoware_simulator::{server::store::KEY_NAMESPACE_PREFIX, testing::with_server};

#[tokio::test]
async fn test_adb_store_basic() {
    with_server(true, 0, 0, |client| async move {
        let adb = client.store().adb();
        let key = b"key";

        // Try to fetch a key from an empty adb.
        let res = adb.get(key, 1).await.unwrap();
        assert!(res.is_none());

        // Set the adb key's value.
        let value = b"value";
        adb.set_key(key, 0, value.to_vec()).await.unwrap();

        // Fetch the key's value assuming mmr size of 1.
        let res = adb.get(key, 1).await.unwrap().unwrap();
        // Proof data should be empty since there are no ancestor nodes yet.
        assert_eq!(res.proof_data.len(), 0);
        assert_eq!(res.value, value.to_vec());

        // See if we can retrieve the value using the kv store API. This requires we prefix the key
        // appropriately.
        let mut db_key = vec![KEY_NAMESPACE_PREFIX];
        db_key.extend_from_slice(key);

        let kv = client.store().kv();
        let res = kv.get(&db_key).await.unwrap();
        assert!(res.is_some());

        // Try to fetch the key from the adb assuming an mmr size of 3. This should fail because
        // the proof data would require the digest of the ancestor to be present.
        let res = adb.get(key, 3).await;
        assert!(matches!(
            res,
            Err(SdkError::Http(StatusCode::INTERNAL_SERVER_ERROR))
        ));

        // Insert the ancestor digest.
        let dummy_digest = [1u8; 32];
        adb.set_node_digest(1, dummy_digest).await.unwrap();

        // Fetch the key's value assuming mmr size of 3. This should succeed because the ancestor
        // digest is now present.
        let res = adb.get(key, 3).await.unwrap().unwrap();
        assert_eq!(res.proof_data.len(), 32);
        assert_eq!(res.value, value.to_vec());
    })
    .await;
}
