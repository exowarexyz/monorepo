use commonware_codec::Encode;
use commonware_consensus::simplex::types::{Finalization, Notarization};
use commonware_consensus::{Epochable, Heightable, Viewable};
use commonware_cryptography::{Digest, Digestible};
use exoware_sdk::{
    store::simplex::v1::{BlockKind as ProtoBlockKind, CertifiedBlock as ProtoCertifiedBlock},
    Key, KeyCodec, StoreBatchUpload, StoreClient, StoreWriteBatch,
};
use futures::future::BoxFuture;

const DIGEST_LEN: usize = 32;
const BLOCK_KEY_LEN: usize = 33;
const RESERVED_BITS: u8 = 4;
pub const FINALIZED_BLOCK_HEIGHT_FAMILY: u16 = 12;
pub const CERTIFIED_BLOCK_VIEW_FAMILY: u16 = 13;
pub const CERTIFIED_BLOCK_FAMILY: u16 = 14;
const BLOCK_FAMILY: u16 = 15;
const FINALIZED_BLOCK_HEIGHT_KEY_CODEC: KeyCodec =
    KeyCodec::new(RESERVED_BITS, FINALIZED_BLOCK_HEIGHT_FAMILY);
const CERTIFIED_BLOCK_VIEW_KEY_CODEC: KeyCodec =
    KeyCodec::new(RESERVED_BITS, CERTIFIED_BLOCK_VIEW_FAMILY);
const CERTIFIED_BLOCK_KEY_CODEC: KeyCodec = KeyCodec::new(RESERVED_BITS, CERTIFIED_BLOCK_FAMILY);
const BLOCK_KEY_CODEC: KeyCodec = KeyCodec::new(RESERVED_BITS, BLOCK_FAMILY);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockKind {
    Notarized,
    Finalized,
}

impl BlockKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Notarized => "notarized",
            Self::Finalized => "finalized",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRecord {
    pub kind: BlockKind,
    pub epoch: u64,
    pub view: u64,
    pub height: u64,
    pub block_digest: Vec<u8>,
    pub encoded_certificate: Vec<u8>,
    pub block_key: Vec<u8>,
    pub block_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingEntry {
    key: Key,
    value: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum SimplexError {
    #[error("store error: {0}")]
    Store(String),
    #[error("block digest does not match certificate proposal payload")]
    DigestMismatch,
    #[error("digest length must be {expected}, got {got}")]
    DigestLength { expected: usize, got: usize },
}

fn fixed_digest(bytes: Vec<u8>) -> Result<Vec<u8>, SimplexError> {
    if bytes.len() != DIGEST_LEN {
        return Err(SimplexError::DigestLength {
            expected: DIGEST_LEN,
            got: bytes.len(),
        });
    }
    Ok(bytes)
}

pub fn block_key(block_digest: &[u8]) -> Result<Key, SimplexError> {
    let digest = fixed_digest(block_digest.to_vec())?;
    BLOCK_KEY_CODEC
        .encode(&digest)
        .map_err(|e| SimplexError::Store(e.to_string()))
}

fn block_kind_key_byte(kind: BlockKind) -> u8 {
    match kind {
        BlockKind::Notarized => 0,
        BlockKind::Finalized => 1,
    }
}

fn proto_block_kind(kind: BlockKind) -> ProtoBlockKind {
    match kind {
        BlockKind::Notarized => ProtoBlockKind::BLOCK_KIND_NOTARIZED,
        BlockKind::Finalized => ProtoBlockKind::BLOCK_KIND_FINALIZED,
    }
}

pub fn certified_block_key(record: &BlockRecord) -> Result<Key, SimplexError> {
    let digest = fixed_digest(record.block_digest.clone())?;
    let mut payload = Vec::with_capacity(1 + 8 + 8 + 8 + digest.len());
    payload.push(block_kind_key_byte(record.kind));
    payload.extend_from_slice(&record.epoch.to_be_bytes());
    payload.extend_from_slice(&record.view.to_be_bytes());
    payload.extend_from_slice(&record.height.to_be_bytes());
    payload.extend_from_slice(&digest);
    CERTIFIED_BLOCK_KEY_CODEC
        .encode(&payload)
        .map_err(|e| SimplexError::Store(e.to_string()))
}

pub fn certified_block_view_key(record: &BlockRecord) -> Result<Key, SimplexError> {
    let digest = fixed_digest(record.block_digest.clone())?;
    let mut payload = Vec::with_capacity(1 + 8 + 8 + 8 + digest.len());
    payload.push(block_kind_key_byte(record.kind));
    payload.extend_from_slice(&record.epoch.to_be_bytes());
    payload.extend_from_slice(&record.view.to_be_bytes());
    payload.extend_from_slice(&record.height.to_be_bytes());
    payload.extend_from_slice(&digest);
    CERTIFIED_BLOCK_VIEW_KEY_CODEC
        .encode(&payload)
        .map_err(|e| SimplexError::Store(e.to_string()))
}

pub fn finalized_block_height_key(record: &BlockRecord) -> Result<Option<Key>, SimplexError> {
    if record.kind != BlockKind::Finalized {
        return Ok(None);
    }
    let digest = fixed_digest(record.block_digest.clone())?;
    let mut payload = Vec::with_capacity(8 + 8 + 8 + digest.len());
    payload.extend_from_slice(&record.epoch.to_be_bytes());
    payload.extend_from_slice(&record.height.to_be_bytes());
    payload.extend_from_slice(&record.view.to_be_bytes());
    payload.extend_from_slice(&digest);
    FINALIZED_BLOCK_HEIGHT_KEY_CODEC
        .encode(&payload)
        .map(Some)
        .map_err(|e| SimplexError::Store(e.to_string()))
}

fn certified_block_value(record: BlockRecord) -> Result<Vec<u8>, SimplexError> {
    use buffa::Message;

    let block_digest = fixed_digest(record.block_digest)?;
    let block_key = if record.block_key.is_empty() {
        block_key(&block_digest)?.to_vec()
    } else {
        record.block_key
    };
    if block_key.len() != BLOCK_KEY_LEN {
        return Err(SimplexError::DigestLength {
            expected: BLOCK_KEY_LEN,
            got: block_key.len(),
        });
    }
    Ok(ProtoCertifiedBlock {
        kind: proto_block_kind(record.kind).into(),
        epoch: record.epoch,
        view: record.view,
        height: record.height,
        block_digest,
        encoded_certificate: record.encoded_certificate,
        block_key,
        block_size: record.block_size,
        ..Default::default()
    }
    .encode_to_vec())
}

#[derive(Debug)]
pub struct SimplexStoreWriter {
    client: StoreClient,
    pending_certificates: Vec<PendingEntry>,
    pending_indexes: Vec<PendingEntry>,
    pending_raw_blocks: Vec<PendingEntry>,
    failed_prepared: std::sync::Mutex<Vec<PreparedSimplexStoreBatch>>,
}

pub type SimplexWriter = SimplexStoreWriter;

#[derive(Debug)]
#[must_use]
pub struct PreparedSimplexStoreBatch {
    certificates: Vec<PendingEntry>,
    indexes: Vec<PendingEntry>,
    raw_blocks: Vec<PendingEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimplexStoreReceipt {
    pub certificate_count: usize,
    pub index_count: usize,
    pub raw_block_count: usize,
    pub store_sequence_number: u64,
}

impl SimplexStoreWriter {
    pub fn new(client: StoreClient) -> Self {
        Self {
            client,
            pending_certificates: Vec::new(),
            pending_indexes: Vec::new(),
            pending_raw_blocks: Vec::new(),
            failed_prepared: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn insert_notarized<S, D, B>(
        &mut self,
        proof: &Notarization<S, D>,
        block: &B,
    ) -> Result<&mut Self, SimplexError>
    where
        S: commonware_cryptography::certificate::Scheme,
        D: Digest,
        B: Digestible<Digest = D> + Heightable + Encode,
        Notarization<S, D>: Encode + Epochable + Viewable,
    {
        let digest = block.digest();
        if proof.proposal.payload != digest {
            return Err(SimplexError::DigestMismatch);
        }
        let encoded_block = block.encode().to_vec();
        let key = block_key(&digest.encode().to_vec())?;
        self.insert_block_record(BlockRecord {
            kind: BlockKind::Notarized,
            epoch: proof.epoch().get(),
            view: proof.view().get(),
            height: block.height().get(),
            block_digest: digest.encode().to_vec(),
            encoded_certificate: proof.encode().to_vec(),
            block_key: key.to_vec(),
            block_size: encoded_block.len() as u64,
        })?;
        self.stage_raw_block(digest.encode().to_vec(), encoded_block)?;
        Ok(self)
    }

    pub fn insert_finalized<S, D, B>(
        &mut self,
        proof: &Finalization<S, D>,
        block: &B,
    ) -> Result<&mut Self, SimplexError>
    where
        S: commonware_cryptography::certificate::Scheme,
        D: Digest,
        B: Digestible<Digest = D> + Heightable + Encode,
        Finalization<S, D>: Encode + Epochable + Viewable,
    {
        let digest = block.digest();
        if proof.proposal.payload != digest {
            return Err(SimplexError::DigestMismatch);
        }
        let encoded_block = block.encode().to_vec();
        let key = block_key(&digest.encode().to_vec())?;
        self.insert_block_record(BlockRecord {
            kind: BlockKind::Finalized,
            epoch: proof.epoch().get(),
            view: proof.view().get(),
            height: block.height().get(),
            block_digest: digest.encode().to_vec(),
            encoded_certificate: proof.encode().to_vec(),
            block_key: key.to_vec(),
            block_size: encoded_block.len() as u64,
        })?;
        self.stage_raw_block(digest.encode().to_vec(), encoded_block)?;
        Ok(self)
    }

    fn stage_raw_block(
        &mut self,
        block_digest: Vec<u8>,
        encoded_block: Vec<u8>,
    ) -> Result<Key, SimplexError> {
        let key = block_key(&block_digest)?;
        if !self.pending_raw_blocks.iter().any(|block| block.key == key) {
            self.pending_raw_blocks.push(PendingEntry {
                key: key.clone(),
                value: encoded_block,
            });
        }
        Ok(key)
    }

    pub fn insert_block_record(&mut self, record: BlockRecord) -> Result<&mut Self, SimplexError> {
        let key = certified_block_key(&record)?;
        let view_key = certified_block_view_key(&record)?;
        let height_key = finalized_block_height_key(&record)?;
        let value = certified_block_value(record)?;
        self.pending_certificates.push(PendingEntry {
            key,
            value: value.clone(),
        });
        self.pending_indexes.push(PendingEntry {
            key: view_key,
            value: value.clone(),
        });
        if let Some(key) = height_key {
            self.pending_indexes.push(PendingEntry { key, value });
        }
        Ok(self)
    }

    pub fn pending_count(&self) -> usize {
        self.pending_certificates.len()
            + self.pending_indexes.len()
            + self.pending_raw_blocks.len()
            + self
                .failed_prepared
                .lock()
                .expect("failed prepared mutex poisoned")
                .iter()
                .map(|prepared| {
                    prepared.certificates.len() + prepared.indexes.len() + prepared.raw_blocks.len()
                })
                .sum::<usize>()
    }

    pub async fn flush_with_receipt(
        &mut self,
    ) -> Result<Option<SimplexStoreReceipt>, SimplexError> {
        let Some(prepared) = self.prepare_flush()? else {
            return Ok(None);
        };
        StoreBatchUpload::commit_upload(self, &self.client, prepared)
            .await
            .map(Some)
    }

    pub async fn flush(&mut self) -> Result<u64, SimplexError> {
        Ok(self
            .flush_with_receipt()
            .await?
            .map(|receipt| receipt.store_sequence_number)
            .unwrap_or(0))
    }

    pub fn prepare_flush(&mut self) -> Result<Option<PreparedSimplexStoreBatch>, SimplexError> {
        if let Some(prepared) = self.take_failed_prepared() {
            return Ok(Some(prepared));
        }
        if self.pending_certificates.is_empty()
            && self.pending_indexes.is_empty()
            && self.pending_raw_blocks.is_empty()
        {
            return Ok(None);
        }
        Ok(Some(PreparedSimplexStoreBatch {
            certificates: std::mem::take(&mut self.pending_certificates),
            indexes: std::mem::take(&mut self.pending_indexes),
            raw_blocks: std::mem::take(&mut self.pending_raw_blocks),
        }))
    }

    fn mark_persisted(
        &self,
        prepared: PreparedSimplexStoreBatch,
        sequence_number: u64,
    ) -> SimplexStoreReceipt {
        SimplexStoreReceipt {
            certificate_count: prepared.certificates.len(),
            index_count: prepared.indexes.len(),
            raw_block_count: prepared.raw_blocks.len(),
            store_sequence_number: sequence_number,
        }
    }

    fn mark_failed(&self, prepared: PreparedSimplexStoreBatch) {
        self.failed_prepared
            .lock()
            .expect("failed prepared mutex poisoned")
            .push(prepared);
    }

    fn take_failed_prepared(&self) -> Option<PreparedSimplexStoreBatch> {
        self.failed_prepared
            .lock()
            .expect("failed prepared mutex poisoned")
            .pop()
    }
}

impl StoreBatchUpload for SimplexStoreWriter {
    type Prepared = PreparedSimplexStoreBatch;
    type Receipt = SimplexStoreReceipt;
    type Error = SimplexError;

    fn stage_upload(
        &self,
        prepared: &Self::Prepared,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error> {
        for entry in prepared
            .certificates
            .iter()
            .chain(prepared.indexes.iter())
            .chain(prepared.raw_blocks.iter())
        {
            batch
                .push(&self.client, &entry.key, &entry.value)
                .map_err(|e| SimplexError::Store(e.to_string()))?;
        }
        Ok(())
    }

    fn commit_error(&self, error: exoware_sdk::ClientError) -> Self::Error {
        SimplexError::Store(error.to_string())
    }

    fn mark_upload_persisted<'a>(
        &'a self,
        prepared: Self::Prepared,
        sequence_number: u64,
    ) -> BoxFuture<'a, Self::Receipt>
    where
        Self: Sync + 'a,
        Self::Prepared: 'a,
    {
        Box::pin(async move { self.mark_persisted(prepared, sequence_number) })
    }

    fn mark_upload_failed<'a>(
        &'a self,
        prepared: Self::Prepared,
        error: String,
    ) -> BoxFuture<'a, ()>
    where
        Self: Sync + 'a,
        Self::Prepared: 'a,
    {
        Box::pin(async move {
            let _ = error;
            self.mark_failed(prepared);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certified_block_record_uses_short_stream_key() {
        let record = BlockRecord {
            kind: BlockKind::Finalized,
            epoch: 1,
            view: 2,
            height: 3,
            block_digest: vec![0x11; DIGEST_LEN],
            encoded_certificate: vec![0x22; 512],
            block_key: Vec::new(),
            block_size: 128,
        };
        let key = certified_block_key(&record).expect("certified block key");
        let view_key = certified_block_view_key(&record).expect("certified block view key");
        let height_key = finalized_block_height_key(&record)
            .expect("finalized block height key")
            .expect("height key");
        assert!(key.len() <= 64, "unexpected key length {}", key.len());
        assert!(
            view_key.len() <= 64,
            "unexpected view key length {}",
            view_key.len()
        );
        assert!(
            height_key.len() <= 64,
            "unexpected height key length {}",
            height_key.len()
        );

        let mut writer = SimplexStoreWriter::new(StoreClient::new("http://127.0.0.1:0"));
        writer
            .insert_block_record(record)
            .expect("insert certified block");
        assert_eq!(writer.pending_count(), 3);
    }
}
