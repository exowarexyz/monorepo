use commonware_cryptography::Sha256;
use commonware_storage::merkle::{mmr, Location, Proof};
use commonware_storage::qmdb::keyless::variable::Operation as KeylessOperation;
use exoware_qmdb::{QmdbError, WriterState};

type Family = mmr::Family;
type Digest = commonware_cryptography::sha256::Digest;
type Operation = KeylessOperation<Family, Vec<u8>>;

fn operations(count: usize) -> Vec<Operation> {
    let mut operations = Vec::with_capacity(count);
    for i in 0..count - 1 {
        operations.push(Operation::Append(format!("value-{i}").into_bytes()));
    }
    operations.push(Operation::Commit(None, Location::new(0)));
    operations
}

fn proof(leaves: u64) -> Proof<Family, Digest> {
    Proof {
        leaves: Location::new(leaves),
        inactive_peaks: 0,
        digests: Vec::new(),
    }
}

#[test]
fn from_proof_accepts_consistent_watermark() {
    let operations = operations(8);
    let state = WriterState::from_proof::<Sha256, _>(
        Location::new(7),
        Location::new(0),
        &proof(8),
        &operations,
    )
    .expect("consistent watermark");

    assert_eq!(state.next_location, Location::new(8));
}

#[test]
fn from_proof_rejects_inconsistent_watermarks() {
    let operations = operations(8);

    for watermark in [5, 10] {
        let error = WriterState::from_proof::<Sha256, _>(
            Location::new(watermark),
            Location::new(0),
            &proof(8),
            &operations,
        )
        .expect_err("inconsistent watermark");

        assert!(matches!(
            error,
            QmdbError::CorruptData(message) if message.starts_with("proof watermark implies")
        ));
    }
}
