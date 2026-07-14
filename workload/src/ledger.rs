use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context};
use exoware_sdk::keys::{validate_key_size, Key};

use crate::record::Record;

// Keep acknowledged append latency bounded while limiting the verifier's
// journal tail to a small, fixed number of records.
pub(crate) const OVERLAP_LEDGER_SNAPSHOT_INTERVAL: u64 = 1_024;

const JOURNAL_HEADER: &str = "exoware-overlap-ledger-journal-v1";

/// Persisted record of successful overlap-writer keys.
///
/// The verifier uses this file to check exactly the keys that were confirmed
/// written while another process may still be appending new data.
#[derive(Debug)]
pub struct OverlapLedger {
    pub namespace: u64,
    pub successful_writes: u64,
    pub sequence_number: u64,
    pub records: Vec<Record>,
}

/// Checks ledger self-consistency before verifier queries the store.
pub fn validate_overlap_ledger(ledger: &OverlapLedger) -> anyhow::Result<()> {
    ensure!(
        ledger.successful_writes >= ledger.records.len() as u64,
        "overlap ledger successful_writes {} is smaller than record_count {}",
        ledger.successful_writes,
        ledger.records.len()
    );

    let mut seen = HashSet::with_capacity(ledger.records.len());
    for record in &ledger.records {
        ensure!(
            seen.insert(record.key.clone()),
            "overlap ledger contains duplicate key {}",
            hex_encode(&record.key)
        );
    }
    Ok(())
}

/// Writes an overlap-ledger snapshot with a temporary file and atomic rename.
///
/// The rename keeps readers from observing a torn replacement after a process
/// stops, but neither the temporary file nor its parent directory is synced;
/// this is not a durability guarantee across a host or VM crash.
pub fn write_overlap_ledger(
    path: impl AsRef<Path>,
    namespace: u64,
    successful_writes: u64,
    sequence_number: u64,
    records: &[Record],
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let mut body = String::new();
    body.push_str("exoware-overlap-ledger-v1\n");
    body.push_str(&format!("namespace {namespace}\n"));
    body.push_str(&format!("successful_writes {successful_writes}\n"));
    body.push_str(&format!("sequence_number {sequence_number}\n"));
    body.push_str(&format!("record_count {}\n", records.len()));
    for record in records {
        body.push_str("record ");
        body.push_str(&hex_encode(&record.key));
        body.push(' ');
        body.push_str(&hex_encode(&record.value));
        body.push('\n');
    }

    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, body).with_context(|| {
        format!(
            "failed to write temporary overlap ledger {}",
            temp_path.display()
        )
    })?;
    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to atomically publish overlap ledger {}",
            path.display()
        )
    })?;
    Ok(())
}

/// Publishes a snapshot and starts a journal bound to that exact snapshot.
///
/// A verifier can race this two-file handoff: it either merges a journal whose
/// header matches the snapshot it read, or uses that snapshot alone.
pub(crate) fn checkpoint_overlap_ledger(
    path: impl AsRef<Path>,
    namespace: u64,
    successful_writes: u64,
    sequence_number: u64,
    records: &[Record],
) -> anyhow::Result<()> {
    let path = path.as_ref();
    write_overlap_ledger(path, namespace, successful_writes, sequence_number, records)?;
    reset_overlap_ledger_journal(path, namespace, successful_writes, sequence_number)
}

/// Appends one acknowledged write after the most recent snapshot checkpoint.
pub(crate) fn append_overlap_ledger_record(
    path: impl AsRef<Path>,
    successful_writes: u64,
    sequence_number: u64,
    record: &Record,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let journal_path = overlap_ledger_journal_path(path);
    let mut journal = OpenOptions::new()
        .append(true)
        .open(&journal_path)
        .with_context(|| {
            format!(
                "failed to open overlap ledger journal {} for append",
                journal_path.display()
            )
        })?;
    writeln!(
        journal,
        "record {successful_writes} {sequence_number} {} {}",
        hex_encode(&record.key),
        hex_encode(&record.value)
    )
    .with_context(|| {
        format!(
            "failed to append overlap ledger journal {}",
            journal_path.display()
        )
    })
}

/// Reads and validates the overlap-ledger text format.
pub fn read_overlap_ledger(path: impl AsRef<Path>) -> anyhow::Result<OverlapLedger> {
    let path = path.as_ref();
    let body = fs::read_to_string(path)
        .with_context(|| format!("failed to read overlap ledger file {}", path.display()))?;
    let mut lines = body.lines();
    let version = lines.next().context("missing overlap ledger header")?;
    ensure!(
        version == "exoware-overlap-ledger-v1",
        "unsupported overlap ledger header `{version}`"
    );

    let namespace = parse_prefixed_u64(
        lines
            .next()
            .context("missing overlap ledger namespace line")?,
        "namespace ",
    )?;
    let successful_writes = parse_prefixed_u64(
        lines
            .next()
            .context("missing overlap ledger successful_writes line")?,
        "successful_writes ",
    )?;
    let sequence_number = parse_prefixed_u64(
        lines
            .next()
            .context("missing overlap ledger sequence_number line")?,
        "sequence_number ",
    )?;
    let record_count = parse_prefixed_u64(
        lines
            .next()
            .context("missing overlap ledger record_count line")?,
        "record_count ",
    )? as usize;

    let mut records = Vec::with_capacity(record_count);
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let tag = parts.next().context("missing overlap ledger record tag")?;
        ensure!(tag == "record", "unexpected overlap ledger tag `{tag}`");
        let key_hex = parts.next().context("missing overlap ledger key hex")?;
        let value_hex = parts.next().context("missing overlap ledger value hex")?;
        ensure!(
            parts.next().is_none(),
            "unexpected trailing fields in overlap ledger record line"
        );
        records.push(Record {
            key: decode_hex_key(key_hex)?,
            value: decode_hex_bytes(value_hex)?,
        });
    }

    ensure!(
        records.len() == record_count,
        "overlap ledger declared {record_count} records but parsed {}",
        records.len()
    );
    let mut ledger = OverlapLedger {
        namespace,
        successful_writes,
        sequence_number,
        records,
    };
    merge_overlap_ledger_journal(path, &mut ledger)?;
    Ok(ledger)
}

/// Encodes bytes as lowercase hexadecimal for report and error text.
pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn overlap_ledger_journal_path(path: &Path) -> PathBuf {
    let mut journal = path.as_os_str().to_os_string();
    journal.push(".journal");
    PathBuf::from(journal)
}

fn reset_overlap_ledger_journal(
    path: &Path,
    namespace: u64,
    successful_writes: u64,
    sequence_number: u64,
) -> anyhow::Result<()> {
    let journal_path = overlap_ledger_journal_path(path);
    let body = format!(
        "{JOURNAL_HEADER}\nnamespace {namespace}\nsnapshot_successful_writes {successful_writes}\nsnapshot_sequence_number {sequence_number}\n"
    );
    let temp_path = journal_path.with_extension("tmp");
    fs::write(&temp_path, body).with_context(|| {
        format!(
            "failed to write temporary overlap ledger journal {}",
            temp_path.display()
        )
    })?;
    fs::rename(&temp_path, &journal_path).with_context(|| {
        format!(
            "failed to publish overlap ledger journal {}",
            journal_path.display()
        )
    })
}

fn merge_overlap_ledger_journal(path: &Path, ledger: &mut OverlapLedger) -> anyhow::Result<()> {
    let journal_path = overlap_ledger_journal_path(path);
    let body = match fs::read_to_string(&journal_path) {
        Ok(body) => body,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "failed to read overlap ledger journal {}",
                    journal_path.display()
                )
            });
        }
    };

    // A writer appends one newline-terminated record at a time. A concurrent
    // reader ignores only an incomplete final write and retains the complete prefix.
    let mut lines = body
        .split_inclusive('\n')
        .filter_map(|line| line.strip_suffix('\n'));
    let header = lines
        .next()
        .context("missing overlap ledger journal header")?;
    ensure!(
        header == JOURNAL_HEADER,
        "unsupported overlap ledger journal header `{header}`"
    );
    let namespace = parse_prefixed_u64(
        lines
            .next()
            .context("missing overlap ledger journal namespace line")?,
        "namespace ",
    )?;
    let snapshot_successful_writes = parse_prefixed_u64(
        lines
            .next()
            .context("missing overlap ledger journal snapshot_successful_writes line")?,
        "snapshot_successful_writes ",
    )?;
    let snapshot_sequence_number = parse_prefixed_u64(
        lines
            .next()
            .context("missing overlap ledger journal snapshot_sequence_number line")?,
        "snapshot_sequence_number ",
    )?;

    // Snapshot and journal are separately published. Ignoring a journal from
    // either side of a checkpoint preserves the complete snapshot the verifier read.
    if namespace != ledger.namespace
        || snapshot_successful_writes != ledger.successful_writes
        || snapshot_sequence_number != ledger.sequence_number
    {
        return Ok(());
    }

    let mut previous_successful_writes = ledger.successful_writes;
    let mut previous_sequence_number = ledger.sequence_number;
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let tag = parts
            .next()
            .context("missing overlap ledger journal record tag")?;
        ensure!(
            tag == "record",
            "unexpected overlap ledger journal tag `{tag}`"
        );
        let successful_writes = parse_journal_u64(
            parts
                .next()
                .context("missing overlap ledger journal successful_writes")?,
            "successful_writes",
        )?;
        let sequence_number = parse_journal_u64(
            parts
                .next()
                .context("missing overlap ledger journal sequence_number")?,
            "sequence_number",
        )?;
        let key_hex = parts
            .next()
            .context("missing overlap ledger journal key hex")?;
        let value_hex = parts
            .next()
            .context("missing overlap ledger journal value hex")?;
        ensure!(
            parts.next().is_none(),
            "unexpected trailing fields in overlap ledger journal record line"
        );
        ensure!(
            successful_writes == previous_successful_writes.saturating_add(1),
            "overlap ledger journal successful_writes {successful_writes} does not follow {previous_successful_writes}"
        );
        ensure!(
            sequence_number >= previous_sequence_number,
            "overlap ledger journal sequence_number {sequence_number} is below {previous_sequence_number}"
        );

        ledger.records.push(Record {
            key: decode_hex_key(key_hex)?,
            value: decode_hex_bytes(value_hex)?,
        });
        ledger.successful_writes = successful_writes;
        ledger.sequence_number = sequence_number;
        previous_successful_writes = successful_writes;
        previous_sequence_number = sequence_number;
    }
    Ok(())
}

fn parse_prefixed_u64(line: &str, prefix: &str) -> anyhow::Result<u64> {
    let raw = line
        .strip_prefix(prefix)
        .with_context(|| format!("expected prefix `{prefix}` in overlap ledger line `{line}`"))?;
    raw.parse::<u64>()
        .with_context(|| format!("invalid integer `{raw}` in overlap ledger line `{line}`"))
}

fn parse_journal_u64(raw: &str, name: &str) -> anyhow::Result<u64> {
    raw.parse::<u64>()
        .with_context(|| format!("invalid overlap ledger journal {name} `{raw}`"))
}

fn decode_hex_key(hex_str: &str) -> anyhow::Result<Key> {
    let bytes = decode_hex_bytes(hex_str)?;
    validate_key_size(bytes.len()).context("decoded key length is invalid")?;
    Ok(Key::from(bytes))
}

fn decode_hex_bytes(hex_str: &str) -> anyhow::Result<Vec<u8>> {
    hex::decode(hex_str).with_context(|| format!("invalid hex string `{hex_str}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::keyspace::{Keyspace, DEFAULT_KEY_LEN};
    use crate::value::overlap_value_for_index;

    fn overlap_records(namespace: u64, keys: u64) -> Vec<Record> {
        let keyspace = Keyspace::from_u64_namespace(namespace, DEFAULT_KEY_LEN).unwrap();
        (0..keys)
            .map(|i| Record {
                key: keyspace.inserted_key(i).unwrap(),
                value: overlap_value_for_index(namespace, i),
            })
            .collect()
    }

    #[test]
    fn overlap_ledger_validation_rejects_duplicate_keys() {
        let keyspace = Keyspace::from_u64_namespace(7, DEFAULT_KEY_LEN).unwrap();
        let key = keyspace.inserted_key(0).unwrap();
        let err = validate_overlap_ledger(&OverlapLedger {
            namespace: 7,
            successful_writes: 2,
            sequence_number: 10,
            records: vec![
                Record {
                    key: key.clone(),
                    value: b"a".to_vec(),
                },
                Record {
                    key,
                    value: b"b".to_vec(),
                },
            ],
        })
        .expect_err("duplicate overlap ledger keys must be rejected");
        assert!(err.to_string().contains("duplicate key"));
    }

    #[test]
    fn overlap_ledger_validation_rejects_record_count_above_successful_writes() {
        let records = overlap_records(9, 2);
        let err = validate_overlap_ledger(&OverlapLedger {
            namespace: 9,
            successful_writes: 1,
            sequence_number: 3,
            records,
        })
        .expect_err("successful_writes must cover persisted record count");
        assert!(err.to_string().contains("successful_writes"));
    }

    #[test]
    fn overlap_ledger_round_trips_text_format() {
        let ledger = OverlapLedger {
            namespace: 42,
            successful_writes: 9,
            sequence_number: 1234,
            records: overlap_records(42, 3),
        };
        let path = std::env::temp_dir().join(format!(
            "exoware-overlap-ledger-test-{}.txt",
            std::process::id()
        ));
        write_overlap_ledger(
            &path,
            ledger.namespace,
            ledger.successful_writes,
            ledger.sequence_number,
            &ledger.records,
        )
        .unwrap();
        let decoded = read_overlap_ledger(&path).unwrap();
        assert_eq!(decoded.namespace, ledger.namespace);
        assert_eq!(decoded.successful_writes, ledger.successful_writes);
        assert_eq!(decoded.sequence_number, ledger.sequence_number);
        assert_eq!(decoded.records.len(), ledger.records.len());
        for (actual, expected) in decoded.records.iter().zip(ledger.records.iter()) {
            assert_eq!(actual.key, expected.key);
            assert_eq!(actual.value, expected.value);
        }
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn overlap_ledger_merges_journal_tail_without_rewriting_snapshot() {
        let mut records = overlap_records(42, 2);
        let path = std::env::temp_dir().join(format!(
            "exoware-overlap-ledger-journal-test-{}.txt",
            std::process::id()
        ));
        checkpoint_overlap_ledger(&path, 42, 2, 10, &records).unwrap();
        let snapshot = std::fs::read_to_string(&path).unwrap();

        let appended = overlap_records(42, 3).pop().unwrap();
        append_overlap_ledger_record(&path, 3, 11, &appended).unwrap();
        records.push(appended);

        assert_eq!(std::fs::read_to_string(&path).unwrap(), snapshot);
        let mut journal = std::fs::OpenOptions::new()
            .append(true)
            .open(overlap_ledger_journal_path(&path))
            .unwrap();
        journal.write_all(b"record 4 12").unwrap();
        let decoded = read_overlap_ledger(&path).unwrap();
        assert_eq!(decoded.successful_writes, 3);
        assert_eq!(decoded.sequence_number, 11);
        assert_eq!(decoded.records.len(), 3);
        assert_eq!(decoded.records[2].key, records[2].key);
        assert_eq!(decoded.records[2].value, records[2].value);

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(overlap_ledger_journal_path(&path)).ok();
    }

    #[test]
    fn overlap_ledger_ignores_journal_from_adjacent_checkpoint() {
        let mut records = overlap_records(42, 2);
        let path = std::env::temp_dir().join(format!(
            "exoware-overlap-ledger-journal-transition-test-{}.txt",
            std::process::id()
        ));
        checkpoint_overlap_ledger(&path, 42, 2, 10, &records).unwrap();

        let appended = overlap_records(42, 3).pop().unwrap();
        append_overlap_ledger_record(&path, 3, 11, &appended).unwrap();
        records.push(appended);

        // This simulates a verifier observing the new snapshot before the
        // writer atomically resets the journal for that checkpoint.
        write_overlap_ledger(&path, 42, 3, 11, &records).unwrap();
        let decoded = read_overlap_ledger(&path).unwrap();
        assert_eq!(decoded.successful_writes, 3);
        assert_eq!(decoded.sequence_number, 11);
        assert_eq!(decoded.records.len(), 3);

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(overlap_ledger_journal_path(&path)).ok();
    }
}
