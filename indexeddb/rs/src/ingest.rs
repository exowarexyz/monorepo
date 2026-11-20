//! Put, from the decoded request to the committed batch.

use crate::{
    idb::{self, Failure, Write, KV, LOG, META, RETENTION, SEQUENCE},
    log,
    store::{run, IndexedDbStore, Inner},
};
use bytes::Bytes;
use exoware_sdk::limits::{put_encoded_len, PutTooLarge, MAX_PUT_ENTRIES, MAX_VALUE_LEN};
use exoware_server::{
    ingest::{ByteLease, DecodeBuffers, PutChunk},
    validate_put_entry, Ingest, IngestError, IngestLimits, LogBatch, PutError, PutInput,
    StreamNotifier,
};
use std::sync::Arc;

/// The entry limits of the Store API. The layout lets no writer store an entry beyond them,
/// so a batch is held to them whatever limits the request path was given.
const STORE_LIMITS: IngestLimits = IngestLimits {
    max_entries: MAX_PUT_ENTRIES,
    max_value_len: MAX_VALUE_LEN,
};

/// The rejection for a batch larger than the store accepts.
pub(crate) fn over_limit(max_batch_bytes: usize) -> IngestError {
    IngestError::ResourceExhausted {
        message: format!("put exceeds the store's batch limit of {max_batch_bytes} bytes"),
    }
}

/// The entries of one Put while its request is still being read.
#[derive(Default)]
struct Batch {
    /// The entries in request order, sharing the buffers of the decoded chunks.
    rows: Vec<(Bytes, Bytes)>,
    /// Encoded length of the entries, counted against the store's batch limit.
    encoded_len: usize,
    /// Memory the commit will need beyond the decoded chunks, charged to the request.
    reserved: Option<ByteLease>,
}

impl Batch {
    /// Adds the entries of one decoded chunk, or says why the batch cannot grow.
    fn append(
        &mut self,
        chunk: &PutChunk,
        input: &PutInput,
        max_batch_bytes: usize,
    ) -> Result<(), PutError> {
        let count = chunk.ranges().len();
        if count > MAX_PUT_ENTRIES.saturating_sub(self.rows.len()) {
            return Err(IngestError::PutTooLarge(PutTooLarge {
                entries: self.rows.len() + count,
                max_entries: MAX_PUT_ENTRIES,
            })
            .into());
        }
        for (offset, (key, value)) in chunk.entries().enumerate() {
            validate_put_entry(self.rows.len() + offset, key, value, STORE_LIMITS)?;
        }
        let chunk_len = put_encoded_len(chunk.entries());
        if chunk_len > max_batch_bytes.saturating_sub(self.encoded_len) {
            return Err(over_limit(max_batch_bytes).into());
        }

        // The commit encodes the batch once more for the log and keeps two handles per row.
        let bytes = chunk_len.saturating_add(count.saturating_mul(size_of::<(Bytes, Bytes)>()));
        match &mut self.reserved {
            Some(lease) => lease.try_extend(bytes)?,
            None => self.reserved = Some(input.reserve_bytes(bytes)?),
        }

        // Rows share the chunk's buffer, and the buffer carries the chunk's own reservation.
        self.encoded_len += chunk_len;
        self.rows.extend(chunk.ranges().iter().map(|entry| {
            (
                chunk.data.slice(entry.key.clone()),
                chunk.data.slice(entry.value.clone()),
            )
        }));
        Ok(())
    }
}

impl Ingest for IndexedDbStore {
    async fn put(&self, input: &mut PutInput) -> Result<u64, PutError> {
        let mut batch = Some(Batch::default());
        while let Some(chunk) = input.next_batch(DecodeBuffers::default()).await? {
            // A rejected input is still read to its end, so it can report the first error in
            // the order the contract defines.
            let Some(accepted) = batch.as_mut() else {
                continue;
            };
            if let Err(error) = accepted.append(&chunk, input, self.inner.config.max_batch_bytes) {
                input.reject(error);
                batch = None;
            }
        }
        input.finish().await?;
        input.check_deadline()?;
        let Some(Batch { rows, reserved, .. }) = batch else {
            return Err(IngestError::Internal {
                message: "put was rejected without an error".to_string(),
            }
            .into());
        };

        let admission = (input.request_lease(), reserved);
        let notifier = input.notifier();
        let inner = self.inner.clone();
        let committed = run(move || async move {
            // The task holds the admission until the transaction of the batch completed or
            // aborted, and it notifies subscribers itself, so a caller that stops waiting
            // loses nothing.
            let _admission = admission;
            Ok(commit(inner, rows, notifier).await)
        })
        .await
        .map_err(|message| IngestError::Internal { message })?;
        Ok(committed?)
    }
}

/// Commits one batch, then publishes its sequence number to the frontier, to other
/// connections, to the notifier of the request and to the store's watcher.
pub(crate) async fn commit(
    inner: Arc<Inner>,
    rows: Vec<(Bytes, Bytes)>,
    notifier: Option<Arc<dyn StreamNotifier>>,
) -> Result<u64, IngestError> {
    let sequence = write(&inner, rows).await.map_err(|failure| {
        if failure.out_of_space {
            IngestError::ResourceExhausted {
                message: "store is out of space".to_string(),
            }
        } else {
            IngestError::Internal {
                message: failure.message,
            }
        }
    })?;
    inner.observe(sequence);
    inner.announce(sequence);
    for notifier in notifier.into_iter().chain(inner.watcher()) {
        notifier.advance(sequence);
    }
    Ok(sequence)
}

/// Writes the rows, the log batch and the new sequence number in one transaction, and trims
/// the log under the installed retention rule.
async fn write(inner: &Inner, rows: Vec<(Bytes, Bytes)>) -> Result<u64, Failure> {
    // Every JS value is built and every stored row is read and checked before the first
    // write. From the first write to the last, only calls that place a request remain, and a
    // failed call drops the guard and so aborts the transaction.
    let entries: Vec<_> = rows
        .iter()
        .map(|(key, value)| (idb::key(key), idb::value(value)))
        .collect();
    let sequence_row = idb::key(SEQUENCE);

    let write = Write::begin(&inner.db, &[KV, LOG, META])?;
    let (kv, log, meta) = (write.store(KV)?, write.store(LOG)?, write.store(META)?);
    let sequence = idb::request(meta.get(&sequence_row));
    let rule = idb::request(meta.get(&idb::key(RETENTION)));
    let (sequence, rule) = (idb::frontier(&sequence.await?)?, log::rule(&rule.await?)?);
    let next = sequence
        .checked_add(1)
        .ok_or_else(|| "sequence numbers are exhausted".to_string())?;
    let batch = idb::value(&LogBatch::from_entries(next, rows).into_response_bytes());
    let batch_key = idb::sequence_key(next);
    let next_sequence = idb::value(&next.to_be_bytes());
    let evicted = match &rule {
        Some(rule) => log::evicted(rule, next)?,
        None => None,
    };

    for (key, value) in &entries {
        idb::placed(kv.put_with_key(value, key))?;
    }
    idb::placed(log.put_with_key(&batch, &batch_key))?;
    idb::placed(meta.put_with_key(&next_sequence, &sequence_row))?;
    if let Some(evicted) = &evicted {
        idb::placed(log.delete(evicted))?;
    }
    write.finish().await?;
    Ok(next)
}
