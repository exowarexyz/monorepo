use commonware_codec::Encode;
use commonware_consensus::simplex::types::{Activity, Attributable, Finalization, Notarization};
use commonware_consensus::{Epochable, Heightable, Viewable};
use commonware_cryptography::{Digest, Digestible, Hasher, Sha256};
use datafusion::arrow::datatypes::DataType;
use exoware_sdk::{Key, KeyCodec, StoreBatchUpload, StoreClient, StoreWriteBatch};
use exoware_sql::{
    BatchReceipt, BatchWriter, CellValue, IndexSpec, KvSchema, PreparedBatch, TableColumnConfig,
};
use futures::future::BoxFuture;

pub const SIGNED_ACTIVITY_TABLE: &str = "simplex_signed_activity";
pub const CERTIFICATE_ACTIVITY_TABLE: &str = "simplex_certificate_activity";
pub const BLOCK_TABLE: &str = "simplex_blocks";

const DIGEST_LEN: i32 = 32;
const BLOCK_KEY_LEN: i32 = 33;
const RESERVED_BITS: u8 = 4;
const BLOCK_FAMILY: u16 = 15;
const BLOCK_KEY_CODEC: KeyCodec = KeyCodec::new(RESERVED_BITS, BLOCK_FAMILY);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityKind {
    Notarize,
    Notarization,
    Certification,
    Nullify,
    Nullification,
    Finalize,
    Finalization,
    ConflictingNotarize,
    ConflictingFinalize,
    NullifyFinalize,
}

impl ActivityKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Notarize => "notarize",
            Self::Notarization => "notarization",
            Self::Certification => "certification",
            Self::Nullify => "nullify",
            Self::Nullification => "nullification",
            Self::Finalize => "finalize",
            Self::Finalization => "finalization",
            Self::ConflictingNotarize => "conflicting_notarize",
            Self::ConflictingFinalize => "conflicting_finalize",
            Self::NullifyFinalize => "nullify_finalize",
        }
    }
}

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
pub struct ActivityRecord {
    pub kind: ActivityKind,
    pub epoch: u64,
    pub view: u64,
    pub signer: Option<u64>,
    pub proposal_digest: Option<Vec<u8>>,
    pub encoded_activity: Vec<u8>,
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
struct PendingBlock {
    key: Key,
    value: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum SimplexError {
    #[error("sql error: {0}")]
    Sql(String),
    #[error("block digest does not match certificate proposal payload")]
    DigestMismatch,
    #[error("digest length must be {expected}, got {got}")]
    DigestLength { expected: usize, got: usize },
}

fn fixed_digest(bytes: Vec<u8>) -> Result<Vec<u8>, SimplexError> {
    if bytes.len() != DIGEST_LEN as usize {
        return Err(SimplexError::DigestLength {
            expected: DIGEST_LEN as usize,
            got: bytes.len(),
        });
    }
    Ok(bytes)
}

pub fn block_key(block_digest: &[u8]) -> Result<Key, SimplexError> {
    let digest = fixed_digest(block_digest.to_vec())?;
    BLOCK_KEY_CODEC
        .encode(&digest)
        .map_err(|e| SimplexError::Sql(e.to_string()))
}

fn activity_kind<S, D>(activity: &Activity<S, D>) -> ActivityKind
where
    S: commonware_cryptography::certificate::Scheme,
    D: Digest,
{
    match activity {
        Activity::Notarize(_) => ActivityKind::Notarize,
        Activity::Notarization(_) => ActivityKind::Notarization,
        Activity::Certification(_) => ActivityKind::Certification,
        Activity::Nullify(_) => ActivityKind::Nullify,
        Activity::Nullification(_) => ActivityKind::Nullification,
        Activity::Finalize(_) => ActivityKind::Finalize,
        Activity::Finalization(_) => ActivityKind::Finalization,
        Activity::ConflictingNotarize(_) => ActivityKind::ConflictingNotarize,
        Activity::ConflictingFinalize(_) => ActivityKind::ConflictingFinalize,
        Activity::NullifyFinalize(_) => ActivityKind::NullifyFinalize,
    }
}

fn activity_signer<S, D>(activity: &Activity<S, D>) -> Option<u64>
where
    S: commonware_cryptography::certificate::Scheme,
    D: Digest,
{
    let signer = match activity {
        Activity::Notarize(v) => v.signer(),
        Activity::Nullify(v) => v.signer(),
        Activity::Finalize(v) => v.signer(),
        Activity::ConflictingNotarize(v) => v.signer(),
        Activity::ConflictingFinalize(v) => v.signer(),
        Activity::NullifyFinalize(v) => v.signer(),
        Activity::Notarization(_)
        | Activity::Certification(_)
        | Activity::Nullification(_)
        | Activity::Finalization(_) => return None,
    };
    let signer: usize = signer.into();
    Some(signer as u64)
}

fn activity_proposal_digest<S, D>(activity: &Activity<S, D>) -> Option<Vec<u8>>
where
    S: commonware_cryptography::certificate::Scheme,
    D: Digest,
{
    let digest = match activity {
        Activity::Notarize(v) => v.proposal.payload.encode().to_vec(),
        Activity::Notarization(v) => v.proposal.payload.encode().to_vec(),
        Activity::Certification(v) => v.proposal.payload.encode().to_vec(),
        Activity::Finalize(v) => v.proposal.payload.encode().to_vec(),
        Activity::Finalization(v) => v.proposal.payload.encode().to_vec(),
        Activity::Nullify(_)
        | Activity::Nullification(_)
        | Activity::ConflictingNotarize(_)
        | Activity::ConflictingFinalize(_)
        | Activity::NullifyFinalize(_) => return None,
    };
    Some(digest)
}

fn activity_id(kind: ActivityKind, epoch: u64, view: u64, encoded_activity: &[u8]) -> String {
    format!(
        "{}:{:020}:{:020}:{}",
        kind.as_str(),
        epoch,
        view,
        hex::encode(Sha256::hash(encoded_activity))
    )
}

pub fn schema(client: StoreClient) -> Result<KvSchema, String> {
    let digest_type = DataType::FixedSizeBinary(DIGEST_LEN);
    let block_key_type = DataType::FixedSizeBinary(BLOCK_KEY_LEN);
    KvSchema::new(client)
        .table(
            SIGNED_ACTIVITY_TABLE,
            vec![
                TableColumnConfig::new("activity_id", DataType::Utf8, false),
                TableColumnConfig::new("kind", DataType::Utf8, false),
                TableColumnConfig::new("epoch", DataType::UInt64, false),
                TableColumnConfig::new("view", DataType::UInt64, false),
                TableColumnConfig::new("signer", DataType::UInt64, false),
                TableColumnConfig::new("proposal_digest", digest_type.clone(), true),
                TableColumnConfig::new("encoded_activity_hex", DataType::Utf8, false),
            ],
            vec!["activity_id".to_string()],
            vec![
                IndexSpec::lexicographic(
                    "signed_activity_kind_view",
                    vec!["kind".to_string(), "epoch".to_string(), "view".to_string()],
                )?,
                IndexSpec::lexicographic(
                    "signed_activity_signer_view",
                    vec![
                        "signer".to_string(),
                        "epoch".to_string(),
                        "view".to_string(),
                    ],
                )?,
            ],
        )?
        .table(
            CERTIFICATE_ACTIVITY_TABLE,
            vec![
                TableColumnConfig::new("activity_id", DataType::Utf8, false),
                TableColumnConfig::new("kind", DataType::Utf8, false),
                TableColumnConfig::new("epoch", DataType::UInt64, false),
                TableColumnConfig::new("view", DataType::UInt64, false),
                TableColumnConfig::new("proposal_digest", digest_type.clone(), true),
                TableColumnConfig::new("encoded_activity_hex", DataType::Utf8, false),
            ],
            vec!["activity_id".to_string()],
            vec![IndexSpec::lexicographic(
                "certificate_activity_kind_view",
                vec!["kind".to_string(), "epoch".to_string(), "view".to_string()],
            )?],
        )?
        .table(
            BLOCK_TABLE,
            vec![
                TableColumnConfig::new("block_id", DataType::Utf8, false),
                TableColumnConfig::new("kind", DataType::Utf8, false),
                TableColumnConfig::new("epoch", DataType::UInt64, false),
                TableColumnConfig::new("view", DataType::UInt64, false),
                TableColumnConfig::new("height", DataType::UInt64, false),
                TableColumnConfig::new("block_digest", digest_type, false),
                TableColumnConfig::new("encoded_certificate_hex", DataType::Utf8, false),
                TableColumnConfig::new("block_key", block_key_type, false),
                TableColumnConfig::new("block_size", DataType::UInt64, false),
            ],
            vec!["block_id".to_string()],
            vec![
                IndexSpec::lexicographic(
                    "blocks_kind_view",
                    vec!["kind".to_string(), "view".to_string()],
                )?,
                IndexSpec::lexicographic("blocks_height", vec!["height".to_string()])?,
            ],
        )
}

#[derive(Debug)]
pub struct SimplexWriter {
    client: StoreClient,
    inner: BatchWriter,
    pending_blocks: Vec<PendingBlock>,
    failed_prepared: std::sync::Mutex<Vec<PreparedSimplexBatch>>,
}

#[derive(Debug)]
#[must_use]
pub struct PreparedSimplexBatch {
    sql: Option<PreparedBatch>,
    blocks: Vec<PendingBlock>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimplexReceipt {
    pub sql: Option<BatchReceipt>,
    pub block_count: usize,
    pub store_sequence_number: u64,
}

impl SimplexWriter {
    pub fn new(client: StoreClient) -> Result<Self, String> {
        Ok(Self {
            inner: schema(client.clone())?.batch_writer(),
            client,
            pending_blocks: Vec::new(),
            failed_prepared: std::sync::Mutex::new(Vec::new()),
        })
    }

    pub fn insert_activity<S, D>(
        &mut self,
        activity: &Activity<S, D>,
    ) -> Result<&mut Self, SimplexError>
    where
        S: commonware_cryptography::certificate::Scheme,
        D: Digest,
        Activity<S, D>: Encode + Epochable + Viewable,
    {
        let encoded = activity.encode().to_vec();
        let record = ActivityRecord {
            kind: activity_kind(activity),
            epoch: activity.epoch().get(),
            view: activity.view().get(),
            signer: activity_signer(activity),
            proposal_digest: activity_proposal_digest(activity),
            encoded_activity: encoded,
        };
        self.insert_activity_record(record)
    }

    pub fn insert_activity_record(
        &mut self,
        record: ActivityRecord,
    ) -> Result<&mut Self, SimplexError> {
        let digest = record
            .proposal_digest
            .map(fixed_digest)
            .transpose()?
            .map(CellValue::FixedBinary)
            .unwrap_or(CellValue::Null);
        let id = activity_id(
            record.kind,
            record.epoch,
            record.view,
            &record.encoded_activity,
        );
        self.inner
            .insert(
                if record.signer.is_some() {
                    SIGNED_ACTIVITY_TABLE
                } else {
                    CERTIFICATE_ACTIVITY_TABLE
                },
                match record.signer {
                    Some(signer) => vec![
                        CellValue::Utf8(id),
                        CellValue::Utf8(record.kind.as_str().to_string()),
                        CellValue::UInt64(record.epoch),
                        CellValue::UInt64(record.view),
                        CellValue::UInt64(signer),
                        digest,
                        CellValue::Utf8(hex::encode(record.encoded_activity)),
                    ],
                    None => vec![
                        CellValue::Utf8(id),
                        CellValue::Utf8(record.kind.as_str().to_string()),
                        CellValue::UInt64(record.epoch),
                        CellValue::UInt64(record.view),
                        digest,
                        CellValue::Utf8(hex::encode(record.encoded_activity)),
                    ],
                },
            )
            .map_err(SimplexError::Sql)?;
        Ok(self)
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
        self.pending_blocks.push(PendingBlock {
            key: key.clone(),
            value: encoded_block,
        });
        Ok(key)
    }

    pub fn insert_block_record(&mut self, record: BlockRecord) -> Result<&mut Self, SimplexError> {
        let block_digest = fixed_digest(record.block_digest)?;
        let block_key = if record.block_key.is_empty() {
            block_key(&block_digest)?.to_vec()
        } else {
            record.block_key
        };
        if block_key.len() != BLOCK_KEY_LEN as usize {
            return Err(SimplexError::DigestLength {
                expected: BLOCK_KEY_LEN as usize,
                got: block_key.len(),
            });
        }
        let id = format!(
            "{}:{:020}:{:020}:{}",
            record.kind.as_str(),
            record.height,
            record.view,
            hex::encode(&block_digest)
        );
        self.inner
            .insert(
                BLOCK_TABLE,
                vec![
                    CellValue::Utf8(id),
                    CellValue::Utf8(record.kind.as_str().to_string()),
                    CellValue::UInt64(record.epoch),
                    CellValue::UInt64(record.view),
                    CellValue::UInt64(record.height),
                    CellValue::FixedBinary(block_digest),
                    CellValue::Utf8(hex::encode(record.encoded_certificate)),
                    CellValue::FixedBinary(block_key),
                    CellValue::UInt64(record.block_size),
                ],
            )
            .map_err(SimplexError::Sql)?;
        Ok(self)
    }

    pub fn pending_count(&self) -> usize {
        self.inner.pending_count()
            + self.pending_blocks.len()
            + self
                .failed_prepared
                .lock()
                .expect("failed prepared mutex poisoned")
                .iter()
                .map(|prepared| prepared.blocks.len())
                .sum::<usize>()
    }

    pub async fn flush_with_receipt(&mut self) -> Result<Option<SimplexReceipt>, SimplexError> {
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

    pub fn prepare_flush(&mut self) -> Result<Option<PreparedSimplexBatch>, SimplexError> {
        if let Some(prepared) = self.take_failed_prepared() {
            return Ok(Some(prepared));
        }
        let sql = self
            .inner
            .prepare_flush()
            .map_err(|e| SimplexError::Sql(e.to_string()))?;
        let blocks = std::mem::take(&mut self.pending_blocks);
        if sql.is_none() && blocks.is_empty() {
            return Ok(None);
        }
        Ok(Some(PreparedSimplexBatch { sql, blocks }))
    }

    fn mark_persisted(
        &self,
        prepared: PreparedSimplexBatch,
        sequence_number: u64,
    ) -> SimplexReceipt {
        let block_count = prepared.blocks.len();
        let sql = prepared
            .sql
            .map(|prepared| self.inner.mark_flush_persisted(prepared, sequence_number));
        SimplexReceipt {
            sql,
            block_count,
            store_sequence_number: sequence_number,
        }
    }

    fn mark_failed(&self, prepared: PreparedSimplexBatch) {
        self.failed_prepared
            .lock()
            .expect("failed prepared mutex poisoned")
            .push(prepared);
    }

    fn take_failed_prepared(&self) -> Option<PreparedSimplexBatch> {
        self.failed_prepared
            .lock()
            .expect("failed prepared mutex poisoned")
            .pop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_builds_sql_server() {
        let client = StoreClient::new("http://127.0.0.1:0");
        let schema = schema(client).expect("simplex schema");
        let _server = exoware_sql::SqlServer::new(schema).expect("sql server");
    }

    #[test]
    fn long_signed_activity_uses_short_primary_key() {
        let client = StoreClient::new("http://127.0.0.1:0");
        let mut writer = SimplexWriter::new(client).expect("writer");
        writer
            .insert_activity_record(ActivityRecord {
                kind: ActivityKind::Notarize,
                epoch: 0,
                view: 1,
                signer: Some(2),
                proposal_digest: Some(vec![0; DIGEST_LEN as usize]),
                encoded_activity: vec![0xAB; 512],
            })
            .expect("insert signed activity");
    }

    #[test]
    fn long_certificate_activity_uses_short_primary_key() {
        let client = StoreClient::new("http://127.0.0.1:0");
        let mut writer = SimplexWriter::new(client).expect("writer");
        writer
            .insert_activity_record(ActivityRecord {
                kind: ActivityKind::Notarization,
                epoch: 0,
                view: 1,
                signer: None,
                proposal_digest: Some(vec![0; DIGEST_LEN as usize]),
                encoded_activity: vec![0xCD; 512],
            })
            .expect("insert certificate activity");
    }
}

impl StoreBatchUpload for SimplexWriter {
    type Prepared = PreparedSimplexBatch;
    type Receipt = SimplexReceipt;
    type Error = SimplexError;

    fn stage_upload(
        &self,
        prepared: &Self::Prepared,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error> {
        if let Some(sql) = &prepared.sql {
            self.inner
                .stage_upload(sql, batch)
                .map_err(|e| SimplexError::Sql(e.to_string()))?;
        }
        for block in &prepared.blocks {
            batch
                .push(&self.client, &block.key, &block.value)
                .map_err(|e| SimplexError::Sql(e.to_string()))?;
        }
        Ok(())
    }

    fn commit_error(&self, error: exoware_sdk::ClientError) -> Self::Error {
        SimplexError::Sql(error.to_string())
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
