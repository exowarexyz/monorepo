use std::collections::HashSet;
use std::fs;

use anyhow::{ensure, Context};
use exoware_sdk::keys::{validate_key_size, Key};

use crate::record::Record;

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

/// Writes the overlap ledger with a temporary file and atomic rename.
pub fn write_overlap_ledger(path: &str, ledger: &OverlapLedger) -> anyhow::Result<()> {
    let mut body = String::new();
    body.push_str("exoware-overlap-ledger-v1\n");
    body.push_str(&format!("namespace {}\n", ledger.namespace));
    body.push_str(&format!("successful_writes {}\n", ledger.successful_writes));
    body.push_str(&format!("sequence_number {}\n", ledger.sequence_number));
    body.push_str(&format!("record_count {}\n", ledger.records.len()));
    for record in &ledger.records {
        body.push_str("record ");
        body.push_str(&hex_encode(&record.key));
        body.push(' ');
        body.push_str(&hex_encode(&record.value));
        body.push('\n');
    }

    let temp_path = format!("{path}.tmp");
    fs::write(&temp_path, body)
        .with_context(|| format!("failed to write temporary overlap ledger {temp_path}"))?;
    fs::rename(&temp_path, path)
        .with_context(|| format!("failed to atomically publish overlap ledger {path}"))?;
    Ok(())
}

/// Reads and validates the overlap-ledger text format.
pub fn read_overlap_ledger(path: &str) -> anyhow::Result<OverlapLedger> {
    let body = fs::read_to_string(path)
        .with_context(|| format!("failed to read overlap ledger file {path}"))?;
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
    Ok(OverlapLedger {
        namespace,
        successful_writes,
        sequence_number,
        records,
    })
}

/// Encodes bytes as lowercase hexadecimal for report and error text.
pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn parse_prefixed_u64(line: &str, prefix: &str) -> anyhow::Result<u64> {
    let raw = line
        .strip_prefix(prefix)
        .with_context(|| format!("expected prefix `{prefix}` in overlap ledger line `{line}`"))?;
    raw.parse::<u64>()
        .with_context(|| format!("invalid integer `{raw}` in overlap ledger line `{line}`"))
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
        write_overlap_ledger(path.to_str().unwrap(), &ledger).unwrap();
        let decoded = read_overlap_ledger(path.to_str().unwrap()).unwrap();
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
}
