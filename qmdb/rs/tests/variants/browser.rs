/// Compare a native Connect proof with the bytes verified by the browser matrix
pub fn assert_fixture(
    case_name: &str,
    expected_root: &commonware_cryptography::sha256::Digest,
    request: &exoware_qmdb::service::proto::qmdb::v1::GetOperationRangeRequest,
    response: &exoware_qmdb::service::proto::qmdb::v1::GetOperationRangeResponse,
    expected_operations: &[Vec<u8>],
) {
    use buffa::Message as _;

    let name = case_name
        .strip_prefix("test_")
        .expect("structured test name");
    assert!(name.ends_with("_mmr") || name.ends_with("_mmb"));
    let proof = response
        .proof
        .as_option()
        .expect("Connect operation range proof");
    assert!(
        request.start_location > 0,
        "fixture must exercise pinned history"
    );
    assert_eq!(proof.start_location, request.start_location);
    assert!(!proof.pinned_nodes.is_empty(), "fixture must include pins");
    assert_eq!(
        proof
            .encoded_operations
            .iter()
            .map(|bytes| bytes.to_vec())
            .collect::<Vec<_>>(),
        expected_operations,
    );
    assert_eq!(
        !proof.ops_root_witness.is_empty(),
        name.starts_with("current_"),
        "current fixtures must authenticate their operation root witness",
    );
    assert_eq!(
        request.start_location + expected_operations.len() as u64,
        request.tip + 1,
        "fixture must reach its source tip",
    );

    // Root, exact request, wire proof, then the independently encoded source operations
    let fixture = format!(
        "{}\n{} {} {}\n{}\n{}\n",
        hex::encode(expected_root),
        request.tip,
        request.start_location,
        request.max_locations,
        hex::encode(proof.encode_to_vec()),
        expected_operations
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ts/test/fixtures/variants")
        .join(format!("{name}.txt"));
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        std::fs::create_dir_all(fixture_path.parent().unwrap()).unwrap();
        std::fs::write(&fixture_path, &fixture).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(&fixture_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", fixture_path.display())),
        fixture,
        "browser fixture {name} must match the native source proof",
    );
}

/// Bind browser current-query fixtures to native responses and source-state expectations
pub fn assert_current_fixture(
    name: &str,
    root: &commonware_cryptography::sha256::Digest,
    chunk_size: usize,
    request: &impl buffa::Message,
    response: &impl buffa::Message,
    expected: &[String],
) {
    let fixture = format!(
        "{}\n{chunk_size}\n{}\n{}\n{}\n",
        hex::encode(root),
        hex::encode(request.encode_to_vec()),
        hex::encode(response.encode_to_vec()),
        expected.join("\n")
    );
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ts/test/fixtures/current")
        .join(format!("{name}.txt"));
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &fixture).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
        fixture
    );
}

/// Browser fixtures for `GetOperations`, each with locations chosen for what its
/// TypeScript test checks: raw scattered locations including the tip in each
/// family and with a current witness, then fixed keyless appends and fixed
/// unordered updates.
const OPERATIONS_FIXTURES: &[(&str, &[u64])] = &[
    (
        "any_unordered_variable_variable_keys_variable_values_mmr",
        &[1, 5, 10],
    ),
    (
        "any_unordered_variable_variable_keys_variable_values_mmb",
        &[1, 5, 10],
    ),
    (
        "current_unordered_variable_variable_keys_variable_values_mmr",
        &[1, 5, 10],
    ),
    ("keyless_fixed_full_fixed_values_mmr", &[9, 10]),
    ("any_unordered_fixed_fixed_keys_fixed_values_mmr", &[6, 9]),
];

/// Verify `GetOperations` natively at scattered locations of `tip`, then bind
/// the named browser fixture for this case when one is listed.
pub async fn assert_operations<F, Op>(
    case_name: &str,
    url: &str,
    client: &exoware_qmdb::service::client::rpc::OperationLogClient<
        exoware_sdk::proto::PreferZstdHttpClient,
        F,
        commonware_cryptography::Sha256,
        Op,
    >,
    trusted_root: &commonware_cryptography::sha256::Digest,
    operations: &[Op],
    is_final: bool,
) where
    F: commonware_storage::merkle::Graftable,
    Op: commonware_codec::Decode
        + commonware_codec::Encode
        + commonware_codec::Read
        + Clone
        + std::fmt::Debug
        + PartialEq,
{
    use buffa::Message as _;
    use exoware_qmdb::service::proto::qmdb::v1::GetOperationsRequest;

    let tip = operations.len() as u64 - 1;
    let verify = |locations: Vec<u64>| async move {
        let request = GetOperationsRequest {
            tip,
            locations: locations.clone(),
            ..Default::default()
        };
        let verified = client
            .get_operations(request.clone(), trusted_root)
            .await
            .expect("verify GetOperations against the trusted root");
        assert_eq!(verified.root, *trusted_root);
        assert_eq!(
            verified.operations,
            locations
                .iter()
                .map(|&location| (
                    commonware_storage::merkle::Location::new(location),
                    operations[location as usize].clone()
                ))
                .collect::<Vec<_>>()
        );
        request
    };
    let mut scattered = vec![0, tip / 2, tip];
    scattered.dedup();
    verify(scattered).await;

    let name = case_name
        .strip_prefix("test_")
        .expect("structured test name");
    let Some(&(_, locations)) = OPERATIONS_FIXTURES.iter().find(|(case, _)| *case == name) else {
        return;
    };
    if !is_final {
        return;
    }
    let request = verify(locations.to_vec()).await;
    let response = crate::common::operation_log_rpc_client(url)
        .get_operations(request.clone())
        .await
        .expect("operations fixture proof")
        .into_view()
        .to_owned_message();
    let proof = response.proof.as_option().expect("operations proof");
    assert_eq!(
        !proof.ops_root_witness.is_empty(),
        name.starts_with("current_"),
        "current fixtures must authenticate their operation root witness",
    );

    // Root, exact request, wire proof, then the independently encoded operations
    let fixture = format!(
        "{}\n{} {}\n{}\n{}\n",
        hex::encode(trusted_root),
        request.tip,
        locations
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(","),
        hex::encode(proof.encode_to_vec()),
        locations
            .iter()
            .map(|&location| hex::encode(operations[location as usize].encode()))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ts/test/fixtures/operations")
        .join(format!("{name}.txt"));
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        std::fs::create_dir_all(fixture_path.parent().unwrap()).unwrap();
        std::fs::write(&fixture_path, &fixture).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(&fixture_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", fixture_path.display())),
        fixture,
        "browser operations fixture {name} must match the native source proof",
    );
}
