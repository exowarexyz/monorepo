use crate::{
    error::SimplexError,
    keys,
    types::{encode_block_data, BlockData, Finalized, Notarized, UploadReceipt, UploadSummary},
};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_consensus::Block;
use commonware_cryptography::{certificate, Digest};
use exoware_sdk::{
    keys::Key, ClientError, PrefixedStoreClient, StoreWriteBatch, StoreWriteBatchUpload,
};
use futures::future::BoxFuture;

#[derive(Clone, Debug)]
pub struct PreparedEntry {
    pub key: Key,
    pub value: Bytes,
}

#[derive(Clone, Debug, Default)]
#[must_use]
pub struct PreparedUpload {
    entries: Vec<PreparedEntry>,
    summary: UploadSummary,
}

impl PreparedUpload {
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub const fn summary(&self) -> UploadSummary {
        self.summary
    }

    pub fn entries(&self) -> &[PreparedEntry] {
        &self.entries
    }

    pub fn extend(&mut self, other: Self) {
        self.summary.headers += other.summary.headers;
        self.summary.blocks += other.summary.blocks;
        self.summary.notarizations += other.summary.notarizations;
        self.summary.finalizations += other.summary.finalizations;
        self.summary.finalization_height_indexes += other.summary.finalization_height_indexes;
        self.entries.extend(other.entries);
    }

    fn push(&mut self, key: Key, value: Bytes) {
        self.entries.push(PreparedEntry { key, value });
    }
}

/// Store-backed writer for Commonware Simplex blocks and certificates.
///
/// The writer stores header and block rows by digest. It stores notarizations
/// and finalizations by round, and it also stores finalizations by block height.
#[derive(Clone, Debug)]
pub struct SimplexWriter {
    store: PrefixedStoreClient,
}

impl SimplexWriter {
    /// Build a writer over `store`'s namespace prefix.
    pub const fn new(store: PrefixedStoreClient) -> Self {
        Self { store }
    }

    pub fn into_store(self) -> PrefixedStoreClient {
        self.store
    }

    pub fn prepare_header<B>(&self, header: &B) -> PreparedUpload
    where
        B: Block,
    {
        let mut prepared = PreparedUpload::new();
        prepared.summary.headers = 1;
        prepared.push(keys::header_by_digest(&header.digest()), header.encode());
        prepared
    }

    pub fn prepare_block<B>(&self, header: &B, body: impl Into<Bytes>) -> PreparedUpload
    where
        B: Block,
    {
        let body = body.into();
        let mut prepared = self.prepare_header(header);
        prepared.summary.blocks = 1;
        prepared.push(
            keys::block_by_digest(&header.digest()),
            encode_block_data(header, &body),
        );
        prepared
    }

    pub fn prepare_block_data<B>(&self, data: &BlockData<B>) -> PreparedUpload
    where
        B: Block,
    {
        self.prepare_block(&data.header, data.body.clone())
    }

    pub fn prepare_notarized<B, S, D>(
        &self,
        notarized: &Notarized<B, S, D>,
    ) -> Result<PreparedUpload, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
    {
        if notarized.notarization.proposal.payload != notarized.header.digest() {
            return Err(SimplexError::CertificateHeaderMismatch);
        }

        let mut prepared = self.prepare_header(&notarized.header);
        let encoded = notarized.encode();
        prepared.summary.notarizations = 1;
        prepared.push(
            keys::notarization_by_round(notarized.notarization.round()),
            encoded,
        );
        Ok(prepared)
    }

    pub fn prepare_finalized<B, S, D>(
        &self,
        finalized: &Finalized<B, S, D>,
    ) -> Result<PreparedUpload, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
    {
        if finalized.finalization.proposal.payload != finalized.header.digest() {
            return Err(SimplexError::CertificateHeaderMismatch);
        }

        let mut prepared = self.prepare_header(&finalized.header);
        let encoded = finalized.encode();
        prepared.summary.finalizations = 1;
        prepared.summary.finalization_height_indexes = 1;
        prepared.push(
            keys::finalization_by_round(finalized.finalization.round()),
            encoded.clone(),
        );
        prepared.push(
            keys::finalization_by_height(finalized.header.height()),
            encoded,
        );
        Ok(prepared)
    }

    pub async fn upload_header<B>(&self, header: &B) -> Result<UploadReceipt, SimplexError>
    where
        B: Block,
    {
        let prepared = self.prepare_header(header);
        self.commit_upload(prepared).await
    }

    pub async fn upload_block<B>(
        &self,
        header: &B,
        body: impl Into<Bytes>,
    ) -> Result<UploadReceipt, SimplexError>
    where
        B: Block,
    {
        let prepared = self.prepare_block(header, body);
        self.commit_upload(prepared).await
    }

    pub async fn upload_notarized<B, S, D>(
        &self,
        notarized: &Notarized<B, S, D>,
    ) -> Result<UploadReceipt, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
    {
        let prepared = self.prepare_notarized(notarized)?;
        self.commit_upload(prepared).await
    }

    pub async fn upload_finalized<B, S, D>(
        &self,
        finalized: &Finalized<B, S, D>,
    ) -> Result<UploadReceipt, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
    {
        let prepared = self.prepare_finalized(finalized)?;
        self.commit_upload(prepared).await
    }
}

impl StoreWriteBatchUpload for SimplexWriter {
    type Prepared = PreparedUpload;
    type Receipt = UploadReceipt;
    type Error = SimplexError;

    fn store(&self) -> &PrefixedStoreClient {
        &self.store
    }

    fn stage_upload(
        &self,
        prepared: &mut Self::Prepared,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error> {
        if prepared.is_empty() {
            return Err(SimplexError::EmptyUpload);
        }
        for entry in prepared.entries() {
            batch.push(&self.store, &entry.key, entry.value.clone())?;
        }
        Ok(())
    }

    fn commit_error(&self, error: ClientError) -> Self::Error {
        SimplexError::Client(error)
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
        Box::pin(async move {
            UploadReceipt {
                store_sequence_number: sequence_number,
                summary: prepared.summary(),
            }
        })
    }

    fn mark_upload_failed<'a>(
        &'a self,
        _prepared: Self::Prepared,
        _error: String,
    ) -> BoxFuture<'a, ()>
    where
        Self: Sync + 'a,
        Self::Prepared: 'a,
    {
        Box::pin(async {})
    }
}
