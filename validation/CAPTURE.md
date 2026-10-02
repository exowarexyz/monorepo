# Captured workloads

`exoware_validation::capture` records issued key/value batches and extends them into
additional passes. It preserves batch boundaries, relative issue times, key/value
lengths, and bytes outside declared patches. It reproduces ingest shape. It does not rebuild
valid application state, proofs, signatures, or query results.

The library works without the CLI or SDK dependency. Downstream crates can depend on
`exoware-validation` with `default-features = false`.

## Profile

A profile declares literal physical key prefixes and fixed byte patches. The
producer assigns each row its family ID before recording. This small profile
covers publication target rows whose keys contain a height and whose values
contain a block digest.

```json
{
  "version": 1,
  "domains": {
    "height": { "kind": "numeric", "width": 8 },
    "block_digest": { "kind": "identity", "width": 32 }
  },
  "families": [
    {
      "id": 0,
      "name": "publication_target",
      "key_prefix_hex": "04",
      "fresh_key": 0,
      "patches": [
        { "target": "key", "offset": { "start": 1 }, "domain": "height" },
        { "target": "value", "offset": { "start": 0 }, "domain": "block_digest" }
      ]
    }
  ]
}
```

Numeric domains support widths of 1, 2, 4, or 8 bytes. Every occurrence in a named
domain contributes to its capture span, computed as `maximum - minimum + 1`. Pass
`p` adds `p * span` to each original coordinate. `endian` defaults to `"big"` and can
be `"little"`.

An identity domain declares the width of an opaque identifier patch. A patch
selects bytes within a key or value and need not cover the whole field. Identity
widths range from 1 through 32 bytes. `endian` applies only to numeric domains and
is ignored for identity domains.

Each identity patch receives deterministic pseudorandom bytes derived from the
seed, absolute pass, event index, row index, and patch index. Equal captured
identifiers are replaced independently, even in the same domain. Generation does
not preserve references or check for collisions. Generated digest bytes are
placeholders, not hashes of generated content.

`{"start": n}` starts at byte `n`. `{"end": n}` starts `n` bytes before the end.
For an eight byte domain, `{"end": 8}` selects the final eight bytes. `fresh_key`
is the zero-based index of the designated key patch. Numeric patches shift keys
into disjoint pass ranges. Identity patches provide no uniqueness guarantee.
Valid unused families and domains are allowed. Unused domains do not reduce
generation capacity.

Patches must fit their rows, avoid overlapping each other, and preserve the declared
prefix. Overlapping family prefixes require the same key transformations and
freshness patch. There are no value-tag selectors or variable field decoders.

Pass zero returns the exact captured rows. Every later pass derives from those
originals. Duplicate physical keys are accepted and preserved in pass zero. Later
passes apply the declared patches to every occurrence. Numeric patches can retain
duplicates within a pass, and identity patches do not guarantee uniqueness.
`validate_passes` checks the pass range against numeric capacity before
generation or replay. `max_pass` is limited only by patched numeric fields and is
`u64::MAX` when no numeric field limits it. Identity fields have no exhaustion
limit.

## Record and generate

Save the profile above as `publication-profile.json`. This example records two small
publication submissions. A real producer supplies its already encoded physical keys
and values at the logical issue boundary.

```rust
use std::{collections::BTreeMap, time::{Duration, Instant}};

use bytes::Bytes;
use exoware_validation::capture::{FileGenerator, Limits, Profile, Recorder, Row};

fn example() -> anyhow::Result<()> {
    let profile: Profile = serde_json::from_slice(
        &std::fs::read("publication-profile.json")?,
    )?;
    let source = BTreeMap::from([("producer_revision".into(), "example".into())]);
    let started = Instant::now();
    let mut recorder = Recorder::start(
        "capture-run",
        profile,
        source,
        Limits {
            max_bytes: 64 * 1024 * 1024,
            max_queued_bytes: 16 * 1024 * 1024,
            queue_batches: 32,
        },
    )?;
    let statistics = recorder.statistics();

    for height in 1_u64..=2 {
        let mut key = vec![0x04];
        key.extend_from_slice(&height.to_be_bytes());
        let accepted = recorder.record(vec![Row {
            family: 0,
            key: key.into(),
            value: Bytes::from(vec![height as u8; 32]),
        }])?;
        if !accepted {
            break;
        }
    }

    recorder.finish(started.elapsed() + Duration::from_nanos(1))?;
    assert!(statistics.snapshot().published);

    let mut generator = FileGenerator::open("capture-run", 7)?;
    generator.validate_passes(0, 3)?;
    let original = generator.next_batch(0)?.unwrap();
    generator.rewind()?;
    let extended = generator.next_batch(1)?.unwrap();
    assert_eq!(original.rows[0].key.len(), extended.rows[0].key.len());
    assert_ne!(original.rows[0].key, extended.rows[0].key);
    Ok(())
}
```

`record` accepts a whole batch or returns `false` when the remaining byte budget
cannot fit it. Budget exhaustion permanently stops acceptance, and `finish` can
publish the accepted prefix. A batch larger than the entire budget is an error.
Queue saturation, writer failure, or malformed rows invalidate the capture. The
caller controls when to stop. `finish` drains accepted batches and publishes the
completed artifact. Its repeat period must be positive and greater than every
recorded offset. Dropping a recorder closes its queue without waiting for disk I/O
and leaves an incomplete artifact that readers reject. Call `finish` from a
blocking context when recording inside an async application.

`Recorder::statistics` returns a cloneable handle. Consumers can retain it separately
from the recorder and call `snapshot` during recording, finalization, and after
`finish` consumes the recorder. Export the snapshots through the application's
metrics system. The library does not require a metrics backend.

| Measurement | Meaning |
| --- | --- |
| `queued_batches`, `peak_queued_batches` | Accepted batches not yet started by the writer, including the receive handoff. |
| `writer_active` | The writer holds a batch and its memory reservation. |
| `outstanding_bytes`, `peak_outstanding_bytes` | Accounted bytes across accepted queued and writer-held batches. |
| `accepted_batches` | Successful batch admissions. |
| `processed_batches`, `processed_rows`, `processed_bytes` | Successfully serialized batches, rows, and binary row-record bytes. Bytes exclude event JSON and other metadata. |
| `processing_ns` | Cumulative batch validation, serialization, hashing, and buffered-write time. Excludes queue waits and finalization. |
| `final_flush_ns`, `final_sync_ns` | Cumulative payload-buffer finalization and payload-file sync time. |
| `publication_ns` | Time writing and syncing the profile, manifest, and capture directory during publication. |
| `queue_overflows`, `byte_budget_overflows` | Batch-count and queued-byte admission failures. |
| `writer_failures`, `publication_failures` | Background writer failures and final publication failures. |
| `published` | Successful publication of the completed capture. |

Derive throughput from changes in processed counters over elapsed wall time.
Processing and finalization durations include failed attempts. Processed bytes may
still be buffered and do not imply durability. The receive handoff can temporarily
make `queued_batches` exceed the channel's waiting-slot limit by one. Counters are
updated at batch and finalization boundaries, with no per-row atomic operations.
Custom owners supplied through `Bytes::from_owner` must not panic when dropped.
Rust's channel cleanup can otherwise abandon queued payloads, leaving their memory
and gauges retained after writer failure.

`Recorder::start` validates profile declarations before creating the output
directory. Generation checks observed patch layouts and numeric capacity.
Duplicates are neither rejected nor removed.

Generation has no persistent runtime state, generated identity inventory, or
resume mechanism. The caller chooses the seed and absolute pass range and owns
dataset isolation. Reusing inputs produces the same keys. A different seed changes
identity bytes but does not isolate numeric keys. Use a clean dataset or coordinate
pass ranges yourself.

## Artifact and memory

A bundle is a new directory containing four files.

| File | Contents |
| --- | --- |
| `manifest.json` | Format version, completion flag, source metadata, repeat period, counts, and SHA-256 checksums of the other files. |
| `profile.json` | The versioned declarative profile. |
| `events.json` | A JSON array with one record per batch, containing its `offset_ns` and `row_count`. |
| `rows.bin` | Rows in event order. Each row has a little-endian `u32` family ID, `u64` key length, `u64` value length, then raw key and value bytes. |

`offset_ns` is the batch's issue time in nanoseconds since recording began.
`row_count` assigns the next rows in `rows.bin` to that batch. The binary file
contains individual rows without batch boundaries or timestamps, so replay needs
both files to reconstruct the recorded batches and schedule.

The manifest is published after the payload files are flushed. Existing directories
are not overwritten. Keys may contain up to 254 bytes. Events and batches must be
nonempty, offsets cannot decrease, and each offset must precede the repeat period.
Reads verify completion, versions, checksums, counts, lengths, and trailing bytes.
`Bundle` validation checks structure. `Generator` validates profiles, patch
layouts, and numeric capacity.

The recorder streams both rows and event metadata. `max_bytes` bounds the accepted
capture size using 20 bytes per row and 16 bytes per event, plus raw keys and values.
It excludes JSON and profile metadata. `queue_batches` bounds waiting batches, and
the writer can hold one additional batch. `max_queued_bytes` independently bounds
outstanding key/value bytes and row-container storage, including the batch held by
the writer. Capacity is released after its row references are dropped. Exceeding
either queue limit invalidates the capture. These are accounting limits, not exact
process-memory limits. Shared `Bytes` slices can retain larger backing allocations.
The writer also holds two fixed 1 MiB buffers, one per payload file. These buffers
combine small writes before checksum updates and are outside the queued-byte budget.

`FileGenerator::open` scans the complete artifact before returning. It checks
checksums, structure, and patch layouts, and computes numeric bounds without
retaining all rows or events. `next_batch(pass)` reads and transforms the next
whole batch. `rewind` starts another pass from the captured originals. Keep all
capture files unchanged while a reader is open. The scan and each complete pass
read the payload once. The eager `Bundle::read` and `Generator` APIs remain
available for callers that want to keep a small capture in memory.

Replay and inspect use `FileGenerator`. Replay holds up to `--buffer-batches`
prepared batches, one batch being prepared, one waiting in the scheduler, and up
to `--concurrency` admitted
requests. The default preparation buffer is 16 batches. One complete batch must
fit in memory, and generation and SDK encoding can temporarily need additional
buffers. Memory therefore depends on batch sizes and configured concurrency,
not just the number of buffers. Profile and manifest metadata remain in memory.

## Inspect and replay

Inspect validates the bundle and profile and prints source metadata, family sizes,
event count, repeat period, and maximum pass. The synthetic fixture example provides
a small bundle for trying the commands on an isolated dataset.

```bash
cargo run -p exoware-validation --no-default-features --example capture_fixture -- ./sample
cargo run -p exoware-validation -- inspect --capture ./sample --seed 7
cargo run -p exoware-validation -- replay --capture ./sample --url http://localhost:10000 --seed 7 --start-pass 0 --passes 10 --speed 1 --concurrency 16 --buffer-batches 16 --max-lag-ms 1000 --request-timeout-ms 30000 --output replay-report.json
```

Replay validates the complete capture and pass range before writes. It fills its
bounded preparation buffer before starting the replay clock. It sends one streaming RPC containing one or more messages per
captured batch using the physical keys without adding a namespace. Due times use
the captured offsets and repeat period, divided by `--speed`. `--concurrency` bounds
in-flight requests across pass boundaries. `--duration-secs` stops new issuance and
drains requests already admitted. Reading or generation that cannot keep pace
causes schedule lag. Dispatch time and lag are measured when the request task
starts issuing through the SDK. The request timeout covers SDK preparation, upload,
and response. A response completed after the deadline is recorded as a timeout,
even if synchronous work delayed the timer. A timed-out write may have reached the
server. Compression defaults to `none`. `zstd` is optional.

The SDK frames and compresses transport messages. Each captured batch remains one
complete write. Oversized writes fail rather than splitting into separate commits.

Replay never retries requests. A request failure, timeout, or schedule lag beyond
`--max-lag-ms` stops issuance, drains admitted requests, writes the requested report,
and returns a failure. Without `--output`, replay retains counters and the first
error, with no request history. `--output` must name a new file so opening a report cannot truncate an input
artifact or an earlier result. With `--output`, a bounded writer queue streams
request records into the JSON report as requests complete. A slow report writer
can contribute to schedule lag. Report format version 2 keeps `run.requests` and
adds `issued`, `succeeded`, and `failed` counters to `run`. Request records are in
completion order. Use their pass and event identifiers to recover capture order.
Records include row count, logical bytes, due time, dispatch time, completion time,
sequence number, and error. The JSON document is complete only after replay drains
its requests and finishes writing the summary. Output errors make replay fail.
