use super::stats::{elapsed_ns, Statistics};
use super::{Batch, Bundle, Profile, Row};
use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};

pub(super) const VERSION: u32 = 1;
pub(super) const ROW_HEADER_BYTES: u64 = 20;
pub(super) const EVENT_HEADER_BYTES: u64 = 16;
const PAYLOAD_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub(super) version: u32,
    pub(super) complete: bool,
    pub(super) source: BTreeMap<String, String>,
    pub(super) repeat_period_ns: u64,
    pub(super) event_count: u64,
    pub(super) row_count: u64,
    pub(super) profile_sha256: String,
    pub(super) events_sha256: String,
    pub(super) rows_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Event {
    pub(super) offset_ns: u64,
    pub(super) row_count: u64,
}

pub(super) struct Spool {
    event_count: u64,
    row_count: u64,
    last_offset_ns: u64,
    events_sha256: String,
    rows_sha256: String,
}

struct ChecksummedFile {
    file: File,
    digest: Sha256,
}

impl Write for ChecksummedFile {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let written = self.file.write(bytes)?;
        self.digest.update(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

struct PayloadWriter {
    writer: BufWriter<ChecksummedFile>,
}

impl Write for PayloadWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.writer.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

impl PayloadWriter {
    fn new(path: &Path) -> Result<Self> {
        Ok(Self {
            writer: BufWriter::with_capacity(
                PAYLOAD_BUFFER_BYTES,
                ChecksummedFile {
                    file: create_file(path)?,
                    digest: Sha256::new(),
                },
            ),
        })
    }

    fn finish(mut self, statistics: &Statistics) -> Result<String> {
        let started = Instant::now();
        let flushed = self.flush();
        let elapsed = elapsed_ns(started);
        statistics.update(|snapshot| {
            snapshot.final_flush_ns = snapshot.final_flush_ns.saturating_add(elapsed);
        });
        flushed?;
        let writer = self
            .writer
            .into_inner()
            .map_err(|error| error.into_error())?;
        let started = Instant::now();
        let synced = writer.file.sync_all();
        let elapsed = elapsed_ns(started);
        statistics.update(|snapshot| {
            snapshot.final_sync_ns = snapshot.final_sync_ns.saturating_add(elapsed);
        });
        synced?;
        Ok(hex::encode(writer.digest.finalize()))
    }
}

pub(super) struct RowWriter {
    rows: PayloadWriter,
    events: PayloadWriter,
    event_count: u64,
    row_count: u64,
    last_offset_ns: u64,
    statistics: Statistics,
}

fn create_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create {}", path.display()))
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_payload(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = create_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn encoded_size(rows: &[Row]) -> Result<u64> {
    ensure!(!rows.is_empty(), "capture batch must contain rows");
    rows.iter().try_fold(EVENT_HEADER_BYTES, |total, row| {
        ensure!(row.key.len() <= 254, "capture key exceeds 254 bytes");
        let key = u64::try_from(row.key.len())?;
        let value = u64::try_from(row.value.len())?;
        total
            .checked_add(ROW_HEADER_BYTES)
            .and_then(|size| size.checked_add(key))
            .and_then(|size| size.checked_add(value))
            .ok_or_else(|| anyhow!("capture encoded size overflow"))
    })
}

impl RowWriter {
    pub(super) fn new(path: &Path) -> Result<Self> {
        Self::with_statistics(path, Statistics::default())
    }

    pub(super) fn with_statistics(path: &Path, statistics: Statistics) -> Result<Self> {
        fs::create_dir(path).with_context(|| format!("create capture {}", path.display()))?;
        let rows = PayloadWriter::new(&path.join("rows.bin"))?;
        let mut events = PayloadWriter::new(&path.join("events.json"))?;
        events.write_all(b"[")?;
        Ok(Self {
            rows,
            events,
            event_count: 0,
            row_count: 0,
            last_offset_ns: 0,
            statistics,
        })
    }

    pub(super) fn batch(&mut self, batch: &Batch) -> Result<()> {
        let started = Instant::now();
        let result = self.write_batch(batch);
        let elapsed = elapsed_ns(started);
        self.statistics.update(|snapshot| {
            snapshot.processing_ns = snapshot.processing_ns.saturating_add(elapsed);
            if let Ok(bytes) = result {
                snapshot.processed_batches = snapshot.processed_batches.saturating_add(1);
                snapshot.processed_rows = snapshot
                    .processed_rows
                    .saturating_add(batch.rows.len() as u64);
                snapshot.processed_bytes = snapshot.processed_bytes.saturating_add(bytes);
            }
        });
        result.map(|_| ())
    }

    fn write_batch(&mut self, batch: &Batch) -> Result<u64> {
        let size = encoded_size(&batch.rows)?;
        ensure!(
            batch.offset_ns >= self.last_offset_ns,
            "capture offsets decrease"
        );
        let row_count = u64::try_from(batch.rows.len())?;
        let total_rows = self
            .row_count
            .checked_add(row_count)
            .context("capture row count overflow")?;
        let event_count = self
            .event_count
            .checked_add(1)
            .context("capture event count overflow")?;
        for row in &batch.rows {
            let mut header = [0; ROW_HEADER_BYTES as usize];
            header[..4].copy_from_slice(&row.family.to_le_bytes());
            header[4..12].copy_from_slice(&u64::try_from(row.key.len())?.to_le_bytes());
            header[12..].copy_from_slice(&u64::try_from(row.value.len())?.to_le_bytes());
            self.rows.write_all(&header)?;
            self.rows.write_all(&row.key)?;
            self.rows.write_all(&row.value)?;
        }
        if self.event_count > 0 {
            self.events.write_all(b",")?;
        }
        serde_json::to_writer(
            &mut self.events,
            &Event {
                offset_ns: batch.offset_ns,
                row_count,
            },
        )?;
        self.event_count = event_count;
        self.row_count = total_rows;
        self.last_offset_ns = batch.offset_ns;
        Ok(size - EVENT_HEADER_BYTES)
    }

    pub(super) fn finish(mut self) -> Result<Spool> {
        let started = Instant::now();
        let closed = self.events.write_all(b"]");
        let elapsed = elapsed_ns(started);
        self.statistics.update(|snapshot| {
            snapshot.final_flush_ns = snapshot.final_flush_ns.saturating_add(elapsed);
        });
        closed?;
        Ok(Spool {
            event_count: self.event_count,
            row_count: self.row_count,
            last_offset_ns: self.last_offset_ns,
            rows_sha256: self.rows.finish(&self.statistics)?,
            events_sha256: self.events.finish(&self.statistics)?,
        })
    }
}

pub(super) fn publish(
    path: &Path,
    profile: &Profile,
    source: BTreeMap<String, String>,
    repeat_period_ns: u64,
    spool: Spool,
) -> Result<()> {
    ensure!(repeat_period_ns > 0, "repeat period must be positive");
    ensure!(spool.event_count > 0, "capture must contain batches");
    ensure!(
        spool.last_offset_ns < repeat_period_ns,
        "repeat period must exceed every offset"
    );

    let profile = serde_json::to_vec(profile)?;
    write_payload(&path.join("profile.json"), &profile)?;
    let manifest = Manifest {
        version: VERSION,
        complete: true,
        source,
        repeat_period_ns,
        event_count: spool.event_count,
        row_count: spool.row_count,
        profile_sha256: digest(&profile),
        events_sha256: spool.events_sha256,
        rows_sha256: spool.rows_sha256,
    };

    // The manifest is the publication boundary after every payload is durable.
    let manifest_path = path.join("manifest.json");
    let mut manifest_file = create_file(&manifest_path)?;
    let result = (|| {
        manifest_file.write_all(&serde_json::to_vec(&manifest)?)?;
        manifest_file.sync_all()?;
        File::open(path)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(manifest_path);
    }
    result
}

fn payload(path: &Path, expected: &str) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    ensure!(
        digest(&bytes) == expected,
        "checksum mismatch for {}",
        path.display()
    );
    Ok(bytes)
}

fn take<'a>(remaining: &mut &'a [u8], count: usize) -> Result<&'a [u8]> {
    ensure!(count <= remaining.len(), "truncated row data");
    let (taken, rest) = remaining.split_at(count);
    *remaining = rest;
    Ok(taken)
}

fn u64_field(remaining: &mut &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(take(remaining, 8)?.try_into()?))
}

impl Bundle {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.repeat_period_ns > 0, "repeat period must be positive");
        ensure!(!self.batches.is_empty(), "capture must contain batches");
        let mut previous = 0;
        let mut total = 0u64;
        for batch in &self.batches {
            ensure!(batch.offset_ns >= previous, "capture offsets decrease");
            ensure!(
                batch.offset_ns < self.repeat_period_ns,
                "repeat period must exceed every offset"
            );
            previous = batch.offset_ns;
            total = total
                .checked_add(encoded_size(&batch.rows)?)
                .ok_or_else(|| anyhow!("capture encoded size overflow"))?;
        }
        Ok(())
    }

    pub fn write(&self, path: impl AsRef<Path>) -> Result<()> {
        self.validate()?;
        self.profile.validate()?;

        let path = path.as_ref();
        let mut writer = RowWriter::new(path)?;
        for batch in &self.batches {
            writer.batch(batch)?;
        }
        publish(
            path,
            &self.profile,
            self.source.clone(),
            self.repeat_period_ns,
            writer.finish()?,
        )
    }

    /// Loads the payloads and decoded batches into memory bounded by artifact size.
    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let manifest: Manifest = serde_json::from_slice(&fs::read(path.join("manifest.json"))?)?;
        ensure!(manifest.version == VERSION, "unsupported capture version");
        ensure!(manifest.complete, "capture is incomplete");
        let profile: Profile = serde_json::from_slice(&payload(
            &path.join("profile.json"),
            &manifest.profile_sha256,
        )?)?;
        let events: Vec<Event> = serde_json::from_slice(&payload(
            &path.join("events.json"),
            &manifest.events_sha256,
        )?)?;
        ensure!(
            u64::try_from(events.len())? == manifest.event_count,
            "event count mismatch"
        );
        let data = Bytes::from(payload(&path.join("rows.bin"), &manifest.rows_sha256)?);
        ensure!(
            manifest.row_count <= u64::try_from(data.len())? / ROW_HEADER_BYTES,
            "row count exceeds payload"
        );
        let mut remaining = data.as_ref();
        let mut row_count = 0u64;
        let mut batches = Vec::with_capacity(events.len());
        for event in events {
            ensure!(
                event.row_count <= u64::try_from(remaining.len())? / ROW_HEADER_BYTES,
                "row count exceeds remaining payload"
            );
            row_count = row_count
                .checked_add(event.row_count)
                .ok_or_else(|| anyhow!("row count overflow"))?;
            let mut rows = Vec::with_capacity(usize::try_from(event.row_count)?);
            for _ in 0..event.row_count {
                let family = u32::from_le_bytes(take(&mut remaining, 4)?.try_into()?);
                let key_len = usize::try_from(u64_field(&mut remaining)?)?;
                let value_len = usize::try_from(u64_field(&mut remaining)?)?;
                ensure!(key_len <= 254, "capture key exceeds 254 bytes");
                let length = key_len
                    .checked_add(value_len)
                    .ok_or_else(|| anyhow!("row length overflow"))?;
                ensure!(length <= remaining.len(), "truncated row data");

                // Slices retain the one payload allocation instead of duplicating row bytes.
                let start = data.len() - remaining.len();
                let key = data.slice(start..start + key_len);
                let value = data.slice(start + key_len..start + length);
                take(&mut remaining, length)?;
                rows.push(Row { family, key, value });
            }
            batches.push(Batch {
                offset_ns: event.offset_ns,
                rows,
            });
        }
        ensure!(row_count == manifest.row_count, "row count mismatch");
        if !remaining.is_empty() {
            bail!("trailing row data");
        }
        let bundle = Self {
            profile,
            source: manifest.source,
            repeat_period_ns: manifest.repeat_period_ns,
            batches,
        };
        bundle.validate()?;
        Ok(bundle)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use tempfile::tempdir;

    pub(in crate::capture) fn profile() -> Profile {
        serde_json::from_str(r#"{"version":1,"domains":{"id":{"kind":"numeric","width":1}},"families":[{"id":7,"name":"rows","key_prefix_hex":"","fresh_key":0,"patches":[{"target":"key","offset":{"start":0},"domain":"id"}]}]}"#).unwrap()
    }

    pub(in crate::capture) fn row(byte: u8) -> Row {
        Row {
            family: 7,
            key: Bytes::from(vec![byte]),
            value: Bytes::from_static(b"value"),
        }
    }

    fn bundle() -> Bundle {
        Bundle {
            profile: profile(),
            source: BTreeMap::from([("revision".into(), "fixture".into())]),
            repeat_period_ns: 10,
            batches: vec![
                Batch {
                    offset_ns: 0,
                    rows: vec![row(1), row(2)],
                },
                Batch {
                    offset_ns: 0,
                    rows: vec![row(3)],
                },
                Batch {
                    offset_ns: 9,
                    rows: vec![row(4)],
                },
            ],
        }
    }

    fn update_manifest(path: &Path, update: impl FnOnce(&mut Manifest)) {
        let manifest_path = path.join("manifest.json");
        let mut manifest: Manifest =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        update(&mut manifest);
        fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    }

    #[test]
    fn round_trip_preserves_batches_source_and_profile() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        let expected = bundle();
        expected.write(&path).unwrap();
        let actual = Bundle::read(&path).unwrap();
        assert_eq!(actual.batches, expected.batches);
        assert_eq!(actual.profile, expected.profile);
        assert_eq!(actual.source, expected.source);
        assert_eq!(actual.repeat_period_ns, expected.repeat_period_ns);
        assert!(expected.write(&path).is_err());
        assert_eq!(Bundle::read(&path).unwrap().batches, expected.batches);
    }

    #[test]
    fn row_bytes_and_checksums_match_v1_across_buffer_boundaries() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        let mut capture = bundle();
        capture.batches[0].rows[0].value = Bytes::from(vec![1; PAYLOAD_BUFFER_BYTES - 64]);
        capture.batches[0].rows[1].value = Bytes::from(vec![2; PAYLOAD_BUFFER_BYTES + 17]);
        capture.batches[1].rows[0].value = Bytes::new();
        let mut expected = Vec::new();
        for batch in &capture.batches {
            for row in &batch.rows {
                expected.extend_from_slice(&row.family.to_le_bytes());
                expected.extend_from_slice(&(row.key.len() as u64).to_le_bytes());
                expected.extend_from_slice(&(row.value.len() as u64).to_le_bytes());
                expected.extend_from_slice(&row.key);
                expected.extend_from_slice(&row.value);
            }
        }

        capture.write(&path).unwrap();
        assert_eq!(fs::read(path.join("rows.bin")).unwrap(), expected);
        let manifest: Manifest =
            serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest.rows_sha256, digest(&expected));
        assert_eq!(Bundle::read(&path).unwrap().batches, capture.batches);
    }

    #[test]
    fn rows_and_v1_event_array_stream_before_finalization() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        let mut writer = RowWriter::new(&path).unwrap();
        let mut expected_events = Vec::new();
        let mut batches = Vec::new();
        let count = 32768;
        for offset_ns in 0..count {
            let batch = Batch {
                offset_ns,
                rows: vec![row(1), row(1)],
            };
            writer.batch(&batch).unwrap();
            expected_events.push(Event {
                offset_ns,
                row_count: 2,
            });
            batches.push(batch);
        }
        assert!(fs::metadata(path.join("rows.bin")).unwrap().len() > 0);
        let partial_events = fs::read(path.join("events.json")).unwrap();
        assert!(partial_events.starts_with(b"["));
        assert!(!partial_events.ends_with(b"]"));
        assert!(!path.join("manifest.json").exists());
        let spool = writer.finish().unwrap();
        assert_eq!(spool.event_count, count);
        assert_eq!(spool.row_count, count * 2);
        assert_eq!(spool.last_offset_ns, count - 1);
        let expected_events = serde_json::to_vec(&expected_events).unwrap();
        assert_eq!(fs::read(path.join("events.json")).unwrap(), expected_events);
        assert_eq!(spool.events_sha256, digest(&expected_events));
        let rows = fs::read(path.join("rows.bin")).unwrap();
        assert_eq!(spool.rows_sha256, digest(&rows));
        publish(&path, &profile(), BTreeMap::new(), count, spool).unwrap();
        assert_eq!(Bundle::read(&path).unwrap().batches, batches);
    }

    #[test]
    fn payload_write_failure_leaves_capture_incomplete() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        let mut writer = RowWriter::new(&path).unwrap();
        writer.rows.writer = BufWriter::with_capacity(
            0,
            ChecksummedFile {
                file: File::open(path.join("rows.bin")).unwrap(),
                digest: Sha256::new(),
            },
        );
        assert!(writer
            .batch(&Batch {
                offset_ns: 0,
                rows: vec![row(1)]
            })
            .is_err());
        drop(writer);
        assert!(!path.join("manifest.json").exists());
        assert!(Bundle::read(&path).is_err());
    }

    #[test]
    fn buffered_payload_errors_prevent_finalization() {
        for name in ["rows.bin", "events.json"] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("capture");
            let mut writer = RowWriter::new(&path).unwrap();
            let readonly = File::open(path.join(name)).unwrap();
            match name {
                "rows.bin" => writer.rows.writer.get_mut().file = readonly,
                "events.json" => writer.events.writer.get_mut().file = readonly,
                _ => unreachable!(),
            }
            writer
                .batch(&Batch {
                    offset_ns: 0,
                    rows: vec![row(1)],
                })
                .unwrap();
            assert!(writer.finish().is_err());
            assert!(!path.join("manifest.json").exists());
            assert!(Bundle::read(&path).is_err());
        }
    }

    #[test]
    fn every_payload_checksum_is_required() {
        for name in ["profile.json", "events.json", "rows.bin"] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("capture");
            bundle().write(&path).unwrap();
            let payload_path = path.join(name);
            let mut bytes = fs::read(&payload_path).unwrap();
            bytes[0] ^= 1;
            fs::write(payload_path, bytes).unwrap();
            assert!(Bundle::read(&path)
                .unwrap_err()
                .to_string()
                .contains("checksum"));
        }
    }

    #[test]
    fn checksummed_corrupt_lengths_truncation_and_trailing_data_are_rejected() {
        for mutation in 0..5 {
            let temp = tempdir().unwrap();
            let path = temp.path().join("capture");
            bundle().write(&path).unwrap();
            let rows_path = path.join("rows.bin");
            let mut bytes = fs::read(&rows_path).unwrap();
            match mutation {
                0 => bytes[12..20].copy_from_slice(&u64::MAX.to_le_bytes()),
                1 => bytes[4..12].copy_from_slice(&u64::MAX.to_le_bytes()),
                2 => {
                    bytes.pop();
                }
                3 => bytes.push(0),
                4 => bytes.truncate(19),
                _ => unreachable!(),
            }
            fs::write(rows_path, &bytes).unwrap();
            update_manifest(&path, |manifest| manifest.rows_sha256 = digest(&bytes));
            assert!(Bundle::read(&path).is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn counts_version_and_completion_are_required() {
        for mutation in 0..5 {
            let temp = tempdir().unwrap();
            let path = temp.path().join("capture");
            bundle().write(&path).unwrap();
            update_manifest(&path, |manifest| match mutation {
                0 => manifest.event_count += 1,
                1 => manifest.row_count -= 1,
                2 => manifest.row_count = u64::MAX,
                3 => manifest.version = 2,
                4 => manifest.complete = false,
                _ => unreachable!(),
            });
            assert!(Bundle::read(&path).is_err());
        }
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        bundle().write(&path).unwrap();
        let bytes = br#"[{"offset_ns":0,"row_count":18446744073709551615}]"#;
        fs::write(path.join("events.json"), bytes).unwrap();
        update_manifest(&path, |manifest| {
            manifest.event_count = 1;
            manifest.events_sha256 = digest(bytes);
        });
        assert!(Bundle::read(&path).is_err());
    }

    #[test]
    fn structural_validation_rejects_invalid_capture_shapes() {
        for mutation in 0..7 {
            let mut invalid = bundle();
            match mutation {
                0 => invalid.batches.clear(),
                1 => invalid.batches[0].rows.clear(),
                2 => invalid.repeat_period_ns = 0,
                3 => invalid.batches[2].offset_ns = 10,
                4 => invalid.batches[0].offset_ns = 1,
                5 => invalid.batches[0].rows[0].key = Bytes::from(vec![0; 255]),
                6 => invalid.repeat_period_ns = 9,
                _ => unreachable!(),
            }
            assert!(invalid.validate().is_err());
        }
        assert!(bundle().validate().is_ok());
    }

    #[test]
    fn write_validates_declarations_without_changing_structural_validation() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        let mut invalid = bundle();
        invalid.profile.version = 2;
        assert!(invalid.validate().is_ok());
        assert!(invalid.write(&path).is_err());
        assert!(!path.exists());
    }
}
