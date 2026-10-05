use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom},
    path::Path,
};

use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{
    bundle::{encoded_size, Event, Manifest, ROW_HEADER_BYTES, VERSION},
    generate::{Preparation, PreparedGenerator},
    Batch, Profile, Row,
};

/// Capture contents must remain unchanged until this generator is dropped.
pub struct FileGenerator {
    manifest: Manifest,
    prepared: PreparedGenerator,
    stream: BatchReader,
    last_offset_ns: u64,
    capture_sha256: String,
}

impl FileGenerator {
    /// Validates every payload and row before making batches available.
    pub fn open(path: impl AsRef<Path>, seed: u64) -> Result<Self> {
        let path = path.as_ref();
        let manifest_bytes = fs::read(path.join("manifest.json"))?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
        ensure!(manifest.version == VERSION, "unsupported capture version");
        ensure!(manifest.complete, "capture is incomplete");
        ensure!(
            manifest.repeat_period_ns > 0,
            "repeat period must be positive"
        );
        ensure!(manifest.event_count > 0, "capture must contain batches");
        let profile_bytes = fs::read(path.join("profile.json"))?;
        ensure!(
            hex::encode(Sha256::digest(&profile_bytes)) == manifest.profile_sha256,
            "profile.json checksum mismatch"
        );
        let profile: Profile = serde_json::from_slice(&profile_bytes)?;
        let mut preparation = Preparation::new(profile)?;
        let events = File::open(path.join("events.json"))?;
        let rows = File::open(path.join("rows.bin"))?;
        let mut stream = BatchReader::new(events, rows)?;
        let mut last_offset_ns = 0;
        let mut encoded_bytes = 0u64;
        while let Some(batch) = stream.next(&manifest)? {
            preparation.observe(&batch)?;
            last_offset_ns = batch.offset_ns;
            encoded_bytes = encoded_bytes
                .checked_add(encoded_size(&batch.rows)?)
                .context("capture encoded size overflow")?;
        }
        stream.verify_hashes(&manifest)?;
        stream.rewind()?;
        Ok(Self {
            manifest,
            prepared: preparation.finish(seed),
            stream,
            last_offset_ns,
            capture_sha256: hex::encode(Sha256::digest(&manifest_bytes)),
        })
    }

    pub fn profile(&self) -> &Profile {
        self.prepared.profile()
    }

    pub fn max_pass(&self) -> u64 {
        self.prepared.max_pass()
    }

    pub fn source(&self) -> &BTreeMap<String, String> {
        &self.manifest.source
    }

    pub fn repeat_period_ns(&self) -> u64 {
        self.manifest.repeat_period_ns
    }

    pub fn event_count(&self) -> u64 {
        self.manifest.event_count
    }

    pub fn last_offset_ns(&self) -> u64 {
        self.last_offset_ns
    }

    pub fn capture_sha256(&self) -> &str {
        &self.capture_sha256
    }

    pub fn validate_passes(&self, start: u64, count: u64) -> Result<()> {
        self.prepared.validate_passes(start, count)
    }

    pub fn next_batch(&mut self, absolute_pass: u64) -> Result<Option<Batch>> {
        self.validate_passes(absolute_pass, 1)?;
        let event = self.stream.event_count;
        self.stream
            .next(&self.manifest)?
            .map(|batch| self.prepared.transform(batch, event, absolute_pass))
            .transpose()
    }

    pub fn rewind(&mut self) -> Result<()> {
        self.stream.rewind()
    }
}

struct PayloadReader {
    file: File,
    hash: Option<Sha256>,
}

impl PayloadReader {
    fn new(file: File) -> Self {
        Self {
            file,
            hash: Some(Sha256::new()),
        }
    }

    fn verify_hash(&mut self, expected: &str, name: &str) -> Result<()> {
        let hash = self
            .hash
            .take()
            .context("payload checksum already finalized")?;
        ensure!(
            hex::encode(hash.finalize()) == expected,
            "{name} checksum mismatch"
        );
        Ok(())
    }
}

impl Read for PayloadReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = self.file.read(buffer)?;
        if let Some(hash) = &mut self.hash {
            hash.update(&buffer[..length]);
        }
        Ok(length)
    }
}

impl Seek for PayloadReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

struct BatchReader {
    events: EventReader,
    rows: BufReader<PayloadReader>,
    remaining: u64,
    event_count: u64,
    row_count: u64,
    previous_offset: u64,
}

impl BatchReader {
    fn new(events: File, rows: File) -> Result<Self> {
        let remaining = rows.metadata()?.len();
        Ok(Self {
            events: EventReader::new(events)?,
            rows: BufReader::new(PayloadReader::new(rows)),
            remaining,
            event_count: 0,
            row_count: 0,
            previous_offset: 0,
        })
    }

    fn verify_hashes(&mut self, manifest: &Manifest) -> Result<()> {
        self.events
            .reader
            .get_mut()
            .verify_hash(&manifest.events_sha256, "events.json")?;
        self.rows
            .get_mut()
            .verify_hash(&manifest.rows_sha256, "rows.bin")
    }

    fn rewind(&mut self) -> Result<()> {
        self.events.rewind()?;
        self.rows.get_mut().hash = None;
        self.rows.rewind()?;
        self.remaining = self.rows.get_ref().file.metadata()?.len();
        self.event_count = 0;
        self.row_count = 0;
        self.previous_offset = 0;
        Ok(())
    }

    fn next(&mut self, manifest: &Manifest) -> Result<Option<Batch>> {
        let Some(event) = self.events.next()? else {
            ensure!(
                self.event_count == manifest.event_count,
                "event count mismatch"
            );
            ensure!(self.row_count == manifest.row_count, "row count mismatch");
            ensure!(self.remaining == 0, "trailing row data");
            return Ok(None);
        };
        ensure!(
            self.event_count < manifest.event_count,
            "event count mismatch"
        );
        ensure!(event.row_count > 0, "capture batch must contain rows");
        ensure!(
            event.offset_ns >= self.previous_offset,
            "capture offsets decrease"
        );
        ensure!(
            event.offset_ns < manifest.repeat_period_ns,
            "repeat period must exceed every offset"
        );
        ensure!(
            event.row_count <= self.remaining / ROW_HEADER_BYTES,
            "row count exceeds remaining payload"
        );
        let row_count = self
            .row_count
            .checked_add(event.row_count)
            .context("row count overflow")?;
        ensure!(row_count <= manifest.row_count, "row count mismatch");
        let mut rows = Vec::new();
        for _ in 0..event.row_count {
            ensure!(self.remaining >= ROW_HEADER_BYTES, "truncated row header");
            let mut header = [0; ROW_HEADER_BYTES as usize];
            self.rows.read_exact(&mut header)?;
            self.remaining -= ROW_HEADER_BYTES;
            let family = u32::from_le_bytes(header[..4].try_into()?);
            let key_len = u64::from_le_bytes(header[4..12].try_into()?);
            let value_len = u64::from_le_bytes(header[12..].try_into()?);
            ensure!(key_len <= 254, "capture key exceeds 254 bytes");
            let length = key_len
                .checked_add(value_len)
                .context("row length overflow")?;
            ensure!(length <= self.remaining, "truncated row data");
            let key_len = usize::try_from(key_len)?;
            let value_len = usize::try_from(value_len)?;
            let key = read_bytes(&mut self.rows, key_len)?.into();
            let value = read_bytes(&mut self.rows, value_len)?.into();
            self.remaining -= length;
            rows.push(Row { family, key, value });
        }
        self.row_count = row_count;
        self.event_count += 1;
        self.previous_offset = event.offset_ns;
        Ok(Some(Batch {
            offset_ns: event.offset_ns,
            rows,
        }))
    }
}

fn read_bytes(reader: &mut impl Read, length: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    bytes.resize(length, 0);
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

struct EventReader {
    reader: BufReader<PayloadReader>,
    first: bool,
    finished: bool,
}

impl EventReader {
    fn new(file: File) -> Result<Self> {
        let mut reader = Self {
            reader: BufReader::new(PayloadReader::new(file)),
            first: true,
            finished: false,
        };
        reader.start()?;
        Ok(reader)
    }

    fn rewind(&mut self) -> Result<()> {
        self.reader.get_mut().hash = None;
        self.reader.rewind()?;
        self.first = true;
        self.finished = false;
        self.start()
    }

    fn start(&mut self) -> Result<()> {
        ensure!(self.peek()? == Some(b'['), "events must be a JSON array");
        self.reader.consume(1);
        Ok(())
    }

    fn peek(&mut self) -> Result<Option<u8>> {
        loop {
            let buffer = self.reader.fill_buf()?;
            let Some(&byte) = buffer.first() else {
                return Ok(None);
            };
            if matches!(byte, b' ' | b'\n' | b'\r' | b'\t') {
                self.reader.consume(1);
            } else {
                return Ok(Some(byte));
            }
        }
    }

    fn next(&mut self) -> Result<Option<Event>> {
        if self.finished {
            return Ok(None);
        }
        if self.peek()? == Some(b']') {
            self.reader.consume(1);
            ensure!(self.peek()?.is_none(), "trailing event data");
            self.finished = true;
            return Ok(None);
        }
        if !self.first {
            ensure!(self.peek()? == Some(b','), "missing event separator");
            self.reader.consume(1);
        }
        ensure!(self.peek()? == Some(b'{'), "expected event object");
        let event =
            Event::deserialize(&mut serde_json::Deserializer::from_reader(&mut self.reader))?;
        self.first = false;
        Ok(Some(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{Bundle, Domain, Endian, Family, Generator, Offset, Patch, Target};
    use bytes::Bytes;
    use std::io::Write;
    use tempfile::tempdir;

    fn fixture() -> Bundle {
        let patches = vec![
            Patch {
                target: Target::Key,
                offset: Offset::Start(1),
                domain: "number".into(),
                endian: Endian::Big,
            },
            Patch {
                target: Target::Value,
                offset: Offset::Start(0),
                domain: "identity".into(),
                endian: Endian::Big,
            },
            Patch {
                target: Target::Value,
                offset: Offset::End(2),
                domain: "number".into(),
                endian: Endian::Little,
            },
        ];
        let mut families = vec![Family {
            id: 7,
            name: "first".into(),
            key_prefix_hex: "aa".into(),
            fresh_key: 0,
            patches,
        }];
        let mut other = families[0].clone();
        other.id = 8;
        other.name = "second".into();
        families.push(other);
        let row = Row {
            family: 7,
            key: Bytes::from_static(&[0xaa, 0, 1]),
            value: Bytes::from([vec![7; 32], vec![8; 16_384], vec![1, 0]].concat()),
        };
        let mut tail = row.clone();
        tail.family = 8;
        tail.value = Bytes::from([vec![7; 32], 500u16.to_le_bytes().to_vec()].concat());
        Bundle {
            profile: Profile {
                version: 1,
                domains: BTreeMap::from([
                    ("number".into(), Domain::Numeric { width: 2 }),
                    ("identity".into(), Domain::Identity { width: 32 }),
                ]),
                families,
            },
            source: BTreeMap::from([("revision".into(), "reader-fixture".into())]),
            repeat_period_ns: 100,
            batches: vec![
                Batch {
                    offset_ns: 3,
                    rows: vec![row.clone(), row.clone()],
                },
                Batch {
                    offset_ns: 3,
                    rows: vec![row],
                },
                Batch {
                    offset_ns: 99,
                    rows: vec![tail],
                },
            ],
        }
    }

    fn rehash(path: &Path, name: &str, field: &str) {
        let manifest_path = path.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest[field] = hex::encode(Sha256::digest(fs::read(path.join(name)).unwrap())).into();
        fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    }

    #[test]
    fn streaming_matches_eager_with_duplicates_references_and_rewinds() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        let capture = fixture();
        capture.write(&path).unwrap();
        let eager = Generator::new(capture.clone(), 123).unwrap();
        let mut file = FileGenerator::open(&path, 123).unwrap();
        assert_eq!(file.profile(), &capture.profile);
        assert_eq!(file.max_pass(), eager.max_pass());
        assert_eq!(file.source(), &capture.source);
        assert_eq!(file.repeat_period_ns(), 100);
        assert_eq!(file.event_count(), 3);
        assert_eq!(file.last_offset_ns(), 99);
        assert_eq!(
            file.capture_sha256(),
            hex::encode(Sha256::digest(
                fs::read(path.join("manifest.json")).unwrap()
            ))
        );
        assert_eq!(eager.max_pass(), (u16::MAX as u64 - 500) / 500);
        assert!(file.validate_passes(0, 0).is_err());
        assert!(file.validate_passes(u64::MAX, 2).is_err());
        assert!(file.validate_passes(eager.max_pass(), 2).is_err());
        assert!(file.next_batch(eager.max_pass() + 1).is_err());
        for pass in [0, 7, eager.max_pass(), 0, 7] {
            file.validate_passes(pass, 1).unwrap();
            for event in 0..capture.batches.len() {
                let batch = file.next_batch(pass).unwrap().unwrap();
                assert_eq!(batch, eager.batch(event, pass).unwrap());
                for row in batch.rows {
                    assert!(row.key.is_unique());
                    assert!(row.value.is_unique());
                }
            }
            assert!(file.next_batch(pass).unwrap().is_none());
            assert!(file.next_batch(pass).unwrap().is_none());
            file.rewind().unwrap();
        }
        let retained = file.next_batch(7).unwrap().unwrap();
        file.rewind().unwrap();
        assert_eq!(retained, file.next_batch(7).unwrap().unwrap());
        assert!(retained.rows[0].key.is_unique());
    }

    #[test]
    fn streaming_preserves_identity_golden_vector() {
        let mut capture = fixture();
        capture.profile.domains.remove("number");
        capture.profile.families.truncate(1);
        capture.profile.families[0].patches = vec![Patch {
            target: Target::Key,
            offset: Offset::Start(1),
            domain: "identity".into(),
            endian: Endian::Big,
        }];
        capture.batches.truncate(1);
        capture.batches[0].rows.truncate(1);
        capture.batches[0].rows[0].key = Bytes::from([vec![0xaa], vec![0; 32]].concat());
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        capture.write(&path).unwrap();
        let mut file = FileGenerator::open(&path, 123).unwrap();
        let batch = file.next_batch(7).unwrap().unwrap();
        assert_eq!(
            hex::encode(&batch.rows[0].key[1..]),
            "70cb8253153104dd954a3ebbfbb864312c4de857c9062650ac70b65aeb67686a"
        );
    }

    #[test]
    fn corrupt_final_rows_fail_during_open() {
        for mutation in 0..6 {
            let temp = tempdir().unwrap();
            let path = temp.path().join("capture");
            fixture().write(&path).unwrap();
            let rows_path = path.join("rows.bin");
            let mut rows = fs::read(&rows_path).unwrap();
            let last = rows.len() - (ROW_HEADER_BYTES as usize + 3 + 34);
            match mutation {
                0 => rows[last..last + 4].copy_from_slice(&99u32.to_le_bytes()),
                1 => rows[last + 4..last + 12].copy_from_slice(&u64::MAX.to_le_bytes()),
                2 => rows[last + 12..last + 20].copy_from_slice(&u64::MAX.to_le_bytes()),
                3 => {
                    rows.pop();
                }
                4 => rows.push(0),
                5 => rows[last + 20] = 0xbb,
                _ => unreachable!(),
            }
            fs::write(rows_path, rows).unwrap();
            rehash(&path, "rows.bin", "rows_sha256");
            assert!(
                FileGenerator::open(&path, 0).is_err(),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn every_hash_is_checked_before_replay() {
        for name in ["profile.json", "events.json", "rows.bin"] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("capture");
            fixture().write(&path).unwrap();
            let mut payload = fs::read(path.join(name)).unwrap();
            if name == "rows.bin" {
                *payload.last_mut().unwrap() ^= 1;
            } else {
                payload.push(b' ');
            }
            fs::write(path.join(name), payload).unwrap();
            let error = FileGenerator::open(&path, 0).err().unwrap();
            assert!(error.to_string().contains("checksum"), "{error}");
        }
    }

    #[test]
    fn malformed_event_tails_and_counts_fail_during_open() {
        for mutation in 0..11 {
            let temp = tempdir().unwrap();
            let path = temp.path().join("capture");
            fixture().write(&path).unwrap();
            let events_path = path.join("events.json");
            let mut events: serde_json::Value =
                serde_json::from_slice(&fs::read(&events_path).unwrap()).unwrap();
            match mutation {
                0 => events[2]["row_count"] = u64::MAX.into(),
                1 => events[2]["row_count"] = 0.into(),
                2 => events[2]["offset_ns"] = 2.into(),
                3 => events[2]["offset_ns"] = 100.into(),
                4 => {
                    events.as_array_mut().unwrap().pop();
                }
                5 => {
                    let extra = events[2].clone();
                    events.as_array_mut().unwrap().push(extra);
                }
                6 => events[2]["unknown"] = 1.into(),
                _ => (),
            }
            let mut bytes = serde_json::to_vec(&events).unwrap();
            match mutation {
                7 => {
                    bytes.pop();
                }
                8 => bytes.extend_from_slice(b" garbage"),
                9 => {
                    bytes.pop();
                    bytes.extend_from_slice(b",]");
                }
                10 => {
                    bytes.pop();
                    bytes.extend_from_slice(b",{\"offset_ns\":99,\"row_count\":");
                }
                _ => (),
            }
            fs::write(events_path, bytes).unwrap();
            rehash(&path, "events.json", "events_sha256");
            assert!(
                FileGenerator::open(&path, 0).is_err(),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn invalid_manifests_and_profile_declarations_fail_during_open() {
        for mutation in 0..10 {
            let temp = tempdir().unwrap();
            let path = temp.path().join("capture");
            fixture().write(&path).unwrap();
            let manifest_path = path.join("manifest.json");
            let mut manifest: serde_json::Value =
                serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
            match mutation {
                0 => manifest["version"] = 2.into(),
                1 => manifest["complete"] = false.into(),
                2 => manifest["repeat_period_ns"] = 0.into(),
                3 => manifest["event_count"] = 0.into(),
                4 => manifest["event_count"] = 4.into(),
                5 => manifest["row_count"] = 3.into(),
                6 => manifest["row_count"] = u64::MAX.into(),
                _ => (),
            }
            fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
            if mutation >= 7 {
                let profile_path = path.join("profile.json");
                let mut profile = fixture().profile;
                match mutation {
                    7 => profile.version = 2,
                    8 => {
                        profile
                            .domains
                            .insert("unused".into(), Domain::Numeric { width: 3 });
                    }
                    9 => {
                        profile.families[0].patches[0].domain = "missing".into();
                    }
                    _ => unreachable!(),
                }
                fs::write(profile_path, serde_json::to_vec(&profile).unwrap()).unwrap();
                rehash(&path, "profile.json", "profile_sha256");
            }
            assert!(FileGenerator::open(path, 0).is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn final_row_patch_bounds_are_preflighted() {
        let mut capture = fixture();
        capture.batches[2].rows[0].value = Bytes::from_static(&[0; 1]);
        let temp = tempdir().unwrap();
        let path = temp.path().join("capture");
        capture.write(&path).unwrap();
        assert!(FileGenerator::open(path, 0).is_err());
    }

    #[test]
    fn event_metadata_is_consumed_incrementally() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("events.json");
        let mut writer = std::io::BufWriter::new(File::create(&path).unwrap());
        writer.write_all(b"[\n").unwrap();
        for index in 0..50_000u64 {
            if index != 0 {
                writer.write_all(b",\n").unwrap();
            }
            write!(writer, "{{\"offset_ns\":{index},\"row_count\":1}}").unwrap();
        }
        writer.write_all(b"\n]\t").unwrap();
        writer.flush().unwrap();
        let expected = hex::encode(Sha256::digest(fs::read(&path).unwrap()));
        let mut reader = EventReader::new(File::open(path).unwrap()).unwrap();
        assert_eq!(reader.next().unwrap().unwrap().offset_ns, 0);
        assert!(
            reader.reader.get_mut().stream_position().unwrap() <= reader.reader.capacity() as u64
        );
        for index in 1..50_000 {
            assert_eq!(reader.next().unwrap().unwrap().offset_ns, index);
        }
        assert!(reader.next().unwrap().is_none());
        reader
            .reader
            .get_mut()
            .verify_hash(&expected, "events.json")
            .unwrap();
        reader.rewind().unwrap();
        assert_eq!(reader.next().unwrap().unwrap().offset_ns, 0);
    }
}
