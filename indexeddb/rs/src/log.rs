//! The retained batch log and its retention rule.

use crate::{
    idb::{self, Read, Write, LOG, META, RETENTION, SEQUENCE},
    store::{run, IndexedDbStore},
};
use buffa::{
    encoding::{skip_field, Tag},
    Message as _,
};
use exoware_sdk::{
    limits::{MAX_KEY_LEN, MAX_PUT_ENTRIES, MAX_RESPONSE_MESSAGE_BYTES},
    log::retention::v1::RetentionPolicy as StoredRule,
    parse_retention_policy_from_proto,
    retention::{validate_retention_policy, RetentionPolicy},
    retention_policy_to_proto,
    stream::GetResponse,
};
use exoware_server::{CompiledMatchers, FilteredBatch, Log, LogBatch, Retention};
use js_sys::Array;
use std::future::Future;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{IdbKeyRange, IdbObjectStore};

/// Longest retention row of the layout. No writer stores a longer row, and a reader treats a
/// longer one as corruption. The longest rule takes 13 bytes in its shortest encoding, and the
/// bound leaves room for the longer encodings of a rule that an encoder may produce.
const MAX_RULE_LEN: usize = 1024;

/// Decodes the retention row of `meta`. An absent row means no rule is installed.
///
/// A row that is too long for a rule, that does not decode or that the request path would
/// refuse is corruption, and the operation that reads it fails.
pub(crate) fn rule(stored: &JsValue) -> Result<Option<RetentionPolicy>, String> {
    if stored.is_undefined() {
        return Ok(None);
    }
    let stored = idb::bounded(stored, MAX_RULE_LEN, "retention rule")?.copy();
    let rule = StoredRule::decode_from_slice(&stored)
        .map_err(|error| format!("stored retention rule does not decode: {error}"))?;
    let rule = parse_retention_policy_from_proto(&rule)
        .map_err(|error| format!("stored retention rule is invalid: {error}"))?;
    validate_retention_policy(&rule)
        .map_err(|error| format!("stored retention rule is invalid: {error}"))?;
    Ok(Some(rule))
}

/// The lowest sequence number a rule keeps when the frontier is `sequence`, at most one above
/// the frontier.
const fn cutoff(rule: &RetentionPolicy, sequence: u64) -> u64 {
    let lowest_kept = match rule {
        RetentionPolicy::KeepLatest { count } => sequence.saturating_sub(*count).saturating_add(1),
        RetentionPolicy::GreaterThan { threshold } => threshold.saturating_add(1),
        RetentionPolicy::GreaterThanOrEqual { threshold } => *threshold,
        RetentionPolicy::DropAll => sequence.saturating_add(1),
    };
    let above_frontier = sequence.saturating_add(1);
    if lowest_kept < above_frontier {
        lowest_kept
    } else {
        above_frontier
    }
}

/// The log keys a rule evicts when the frontier is `sequence`, or `None` when it evicts none.
pub(crate) fn evicted(
    rule: &RetentionPolicy,
    sequence: u64,
) -> Result<Option<IdbKeyRange>, String> {
    let cutoff = cutoff(rule, sequence);
    if cutoff <= 1 {
        return Ok(None);
    }
    IdbKeyRange::upper_bound_with_open(&idb::sequence_key(cutoff), true)
        .map(Some)
        .map_err(idb::describe)
}

/// The log keys a rule keeps when the frontier is `sequence`, or `None` when it keeps all.
fn kept(rule: &RetentionPolicy, sequence: u64) -> Result<Option<IdbKeyRange>, String> {
    let cutoff = cutoff(rule, sequence);
    if cutoff <= 1 {
        return Ok(None);
    }
    IdbKeyRange::lower_bound(&idb::sequence_key(cutoff))
        .map(Some)
        .map_err(idb::describe)
}

/// Fails for a log key that no committed batch can have. The layout numbers batches from 1
/// to the sequence row.
fn committed(sequence_number: u64, frontier: u64) -> Result<(), String> {
    if (1..=frontier).contains(&sequence_number) {
        return Ok(());
    }
    Err(format!(
        "log holds batch {sequence_number} outside the committed batches 1 to {frontier}"
    ))
}

/// The lowest sequence number among the log keys in `range`, or in the whole log.
async fn oldest(
    log: &IdbObjectStore,
    range: Option<&IdbKeyRange>,
    frontier: u64,
) -> Result<Option<u64>, String> {
    let range = range.map_or(JsValue::NULL, JsValue::from);
    let keys: Array = idb::request(log.get_all_keys_with_key_and_limit(&range, 1))
        .await?
        .unchecked_into();
    if keys.length() == 0 {
        return Ok(None);
    }
    let oldest = idb::sequence(&keys.get(0))?;
    committed(oldest, frontier)?;
    Ok(Some(oldest))
}

/// Field number of the entries in a stored batch, the message `log.stream.v1.GetResponse`.
const ENTRIES_FIELD: u32 = 2;

/// Fails for an encoded batch that holds more than `limit` entries.
///
/// An entry takes as little as two bytes in a row and many times that once it is decoded, so
/// the entries are counted on the encoded bytes. The scan reads the tag of every top level
/// field and skips the field's contents without allocating.
fn entries_within(sequence_number: u64, mut encoded: &[u8], limit: usize) -> Result<(), String> {
    let malformed = |error| format!("log batch {sequence_number} does not decode: {error}");
    let mut entries = 0usize;
    while !encoded.is_empty() {
        let tag = Tag::decode(&mut encoded).map_err(malformed)?;
        if tag.field_number() == ENTRIES_FIELD {
            entries += 1;
            if entries > limit {
                return Err(format!(
                    "log batch {sequence_number} holds more than {limit} entries"
                ));
            }
        }
        skip_field(tag, &mut encoded).map_err(malformed)?;
    }
    Ok(())
}

/// Decodes the log row stored under `sequence_number` and checks it against the layout. A row
/// must be a batch that was committed, carry the number of its key and hold an entry, and no
/// key in it may be longer than [`MAX_KEY_LEN`] bytes.
///
/// The work a row can cause is bounded before it is done. The row is copied out of JS only
/// if it is no longer than the longest batch the decoder accepts, so every batch another
/// writer of the layout may store stays readable. It is decoded only if it holds no more
/// entries than one Put may carry, and the decoder keeps at most a million fields it does
/// not know.
///
/// Readers trust what the log serves. Subscribers receive the entries under the number that
/// was asked for, and a Get forwards the stored bytes. A row that fails here is corruption.
fn batch(
    sequence_number: u64,
    frontier: u64,
    stored: &JsValue,
) -> Result<(LogBatch, GetResponse), String> {
    committed(sequence_number, frontier)?;
    let stored = idb::bounded(stored, MAX_RESPONSE_MESSAGE_BYTES, "log batch")?.copy();
    entries_within(sequence_number, &stored, MAX_PUT_ENTRIES)?;
    let batch = LogBatch::from_response_bytes(sequence_number, stored);
    let response = batch.decode_response()?;
    if response.sequence_number != sequence_number {
        return Err(format!(
            "log batch {sequence_number} carries sequence number {}",
            response.sequence_number
        ));
    }
    if response.entries.is_empty() {
        return Err(format!("log batch {sequence_number} has no entries"));
    }
    if let Some(entry) = response
        .entries
        .iter()
        .find(|entry| entry.key.len() > MAX_KEY_LEN)
    {
        return Err(format!(
            "log batch {sequence_number} holds a key of {} bytes, more than the {MAX_KEY_LEN} \
             bytes a key can be",
            entry.key.len()
        ));
    }
    Ok((batch, response))
}

impl IndexedDbStore {
    /// Reads one batch as stored and as decoded, or `None` when the log does not hold it.
    fn read_batch(
        &self,
        sequence_number: u64,
    ) -> impl Future<Output = Result<Option<(LogBatch, GetResponse)>, String>> + Send {
        let inner = self.inner.clone();
        run(move || async move {
            let read = Read::begin(&inner.db, &[LOG, META])?;
            let sequence = idb::request(read.store(META)?.get(&idb::key(SEQUENCE)));
            let stored = idb::request(read.store(LOG)?.get(&idb::sequence_key(sequence_number)));
            let (sequence, stored) = (idb::frontier(&sequence.await?)?, stored.await?);

            // The frontier moves before the answer, so a caller that asks for it after a miss
            // can tell a batch that was never written from one that was evicted.
            inner.observe(sequence);
            if stored.is_undefined() {
                return Ok(None);
            }
            batch(sequence_number, sequence, &stored).map(Some)
        })
    }
}

impl Log for IndexedDbStore {
    fn get_batch(
        &self,
        sequence_number: u64,
    ) -> impl Future<Output = Result<Option<LogBatch>, String>> + Send {
        let read = self.read_batch(sequence_number);
        async move { Ok(read.await?.map(|(batch, _)| batch)) }
    }

    /// Filters the entries the read already decoded for its checks.
    fn get_batch_filtered(
        &self,
        sequence_number: u64,
        matchers: &CompiledMatchers,
    ) -> impl Future<Output = Result<Option<FilteredBatch>, String>> + Send {
        let read = self.read_batch(sequence_number);
        async move {
            Ok(read.await?.map(|(_, response)| {
                let mut entries = response.entries;
                entries.retain(|entry| matchers.matches(&entry.key, &entry.value));
                FilteredBatch::from_entries(entries)
            }))
        }
    }

    fn oldest_retained_batch(&self) -> impl Future<Output = Result<Option<u64>, String>> + Send {
        let inner = self.inner.clone();
        run(move || async move {
            let read = Read::begin(&inner.db, &[LOG, META])?;
            let sequence = idb::request(read.store(META)?.get(&idb::key(SEQUENCE)));
            let sequence = idb::frontier(&sequence.await?)?;
            let oldest = oldest(&read.store(LOG)?, None, sequence).await?;
            inner.observe(sequence);
            Ok(oldest)
        })
    }
}

impl Retention for IndexedDbStore {
    fn set_retention(
        &self,
        policy: Option<RetentionPolicy>,
    ) -> impl Future<Output = Result<Option<u64>, String>> + Send {
        let inner = self.inner.clone();
        run(move || async move {
            let rule = policy
                .as_ref()
                .map(|policy| idb::value(&retention_policy_to_proto(policy).encode_to_vec()));
            let rule_row = idb::key(RETENTION);

            let write = Write::begin(&inner.db, &[LOG, META])?;
            let (log, meta) = (write.store(LOG)?, write.store(META)?);
            let sequence = idb::frontier(&idb::request(meta.get(&idb::key(SEQUENCE))).await?)?;
            let (evicted, kept) = match &policy {
                Some(policy) => (evicted(policy, sequence)?, kept(policy, sequence)?),
                None => (None, None),
            };

            // The answer is the lowest batch the rule keeps. It is read and checked before
            // the first write, like everything else that can fail.
            let oldest = oldest(&log, kept.as_ref(), sequence).await?;

            match &rule {
                Some(rule) => idb::placed(meta.put_with_key(rule, &rule_row))?,
                None => idb::placed(meta.delete(&rule_row))?,
            };
            if let Some(evicted) = &evicted {
                idb::placed(log.delete(evicted))?;
            }
            write.finish().await?;
            inner.observe(sequence);
            Ok(oldest)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exoware_sdk::common::kv::v1::Entry;

    #[test]
    fn entries_are_counted_on_the_encoded_batch() {
        let batch = |entries: usize| {
            let entry = Entry {
                key: b"k".to_vec(),
                ..Default::default()
            };
            GetResponse {
                sequence_number: 7,
                entries: vec![entry; entries],
                ..Default::default()
            }
            .encode_to_vec()
        };
        assert_eq!(entries_within(7, &batch(0), 0), Ok(()));
        assert_eq!(entries_within(7, &batch(3), 3), Ok(()));
        let refused = entries_within(7, &batch(4), 3).unwrap_err();
        assert!(refused.contains("more than 3 entries"), "{refused}");

        // A field that is not an entry does not count as one.
        let mut other_fields = batch(3);
        other_fields.extend_from_slice(&[0x78, 0x00, 0x78, 0x00]);
        assert_eq!(entries_within(7, &other_fields, 3), Ok(()));

        // A batch that ends inside a field is malformed.
        let cut = batch(3);
        assert!(entries_within(7, &cut[..cut.len() - 1], 3).is_err());
    }

    #[test]
    fn cutoff_is_the_lowest_kept_sequence_capped_above_the_frontier() {
        let keep = |count| RetentionPolicy::KeepLatest { count };
        let above = |threshold| RetentionPolicy::GreaterThan { threshold };
        let at_least = |threshold| RetentionPolicy::GreaterThanOrEqual { threshold };
        for (rule, sequence, expected) in [
            (keep(1), 0, 1),
            (keep(1), 5, 5),
            (keep(3), 5, 3),
            (keep(9), 5, 1),
            (keep(u64::MAX), u64::MAX, 1),
            (above(0), 5, 1),
            (above(2), 5, 3),
            (above(5), 5, 6),
            (above(9), 5, 6),
            (above(u64::MAX), u64::MAX, u64::MAX),
            (at_least(0), 5, 0),
            (at_least(4), 5, 4),
            (at_least(9), 5, 6),
            (RetentionPolicy::DropAll, 0, 1),
            (RetentionPolicy::DropAll, 5, 6),
            (RetentionPolicy::DropAll, u64::MAX, u64::MAX),
        ] {
            assert_eq!(cutoff(&rule, sequence), expected, "{rule:?} at {sequence}");
        }
    }
}
