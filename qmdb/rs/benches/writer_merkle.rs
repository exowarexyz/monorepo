use std::num::NonZeroUsize;
use std::time::Duration;

use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_storage::merkle::{mmr, Location, Position};
use commonware_storage::qmdb::{any::value::VariableEncoding, keyless::variable::Operation};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use exoware_qmdb::{build_keyless_upload, build_keyless_upload_with_strategy};

type Family = mmr::Family;
type Value = Vec<u8>;
type Encoding = VariableEncoding<Value>;
type BatchOperation = Operation<Family, Value>;

struct Frontier {
    peaks: Vec<(Position<Family>, u32, Digest)>,
    size: Position<Family>,
    next_location: Location<Family>,
}

fn operations(count: usize, value_size: usize) -> Vec<BatchOperation> {
    assert!(count > 0);

    let mut operations = Vec::with_capacity(count);
    for index in 0..count - 1 {
        let mut value = vec![0u8; value_size];
        value[..8].copy_from_slice(&(index as u64).to_be_bytes());
        operations.push(BatchOperation::Append(value));
    }
    operations.push(BatchOperation::Commit(None, Location::new(0)));
    operations
}

fn frontier() -> Frontier {
    let operations = operations(1_024, 64);
    let latest_location = Location::new(operations.len() as u64 - 1);
    let built = build_keyless_upload::<Family, Sha256, Value, Encoding>(
        Vec::new(),
        Position::new(0),
        latest_location,
        &operations,
        None,
    )
    .expect("build benchmark frontier");

    Frontier {
        peaks: built.new_peaks,
        size: built.new_ops_size,
        next_location: latest_location + 1,
    }
}

fn bench_strategy<S: Strategy>(
    bencher: &mut criterion::Bencher<'_>,
    frontier: &Frontier,
    operations: &[BatchOperation],
    strategy: &S,
) {
    let latest_location = frontier.next_location + operations.len() as u64 - 1;
    bencher.iter_batched(
        || frontier.peaks.clone(),
        |peaks| {
            build_keyless_upload_with_strategy::<Family, Sha256, Value, Encoding, S>(
                peaks,
                frontier.size,
                latest_location,
                operations,
                None,
                strategy,
            )
            .expect("build benchmark batch")
        },
        BatchSize::SmallInput,
    );
}

fn writer_merkle(criterion: &mut Criterion) {
    let frontier = frontier();
    let available = std::thread::available_parallelism()
        .map(NonZeroUsize::get)
        .unwrap_or(1);
    let mut worker_counts = vec![1, 2, 4, 8, available];
    worker_counts.retain(|workers| *workers <= available);
    worker_counts.sort_unstable();
    worker_counts.dedup();

    let mut group = criterion.benchmark_group("qmdb_writer_merkle");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(20));

    for count in [100_000usize, 196_000, 256_000] {
        let operations = operations(count, 64);
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::new("sequential", count),
            &operations,
            |bencher, operations| {
                bench_strategy(bencher, &frontier, operations, &Sequential);
            },
        );

        for workers in &worker_counts {
            let strategy = Rayon::new(NonZeroUsize::new(*workers).expect("non-zero workers"))
                .expect("construct Rayon strategy")
                .manual();
            group.bench_with_input(
                BenchmarkId::new(format!("rayon-{workers}"), count),
                &operations,
                |bencher, operations| {
                    bench_strategy(bencher, &frontier, operations, &strategy);
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, writer_merkle);
criterion_main!(benches);
