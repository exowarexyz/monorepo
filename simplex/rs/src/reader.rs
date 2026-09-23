use bytes::Bytes;
use commonware_codec::Decode;
use commonware_consensus::Block;
use commonware_cryptography::{certificate, Digest};
use exoware_sdk::keys::Key;
use exoware_sdk::{PrefixedStoreClient, RangeMode, ReadSession};

use crate::error::SimplexError;
use crate::keys::{self, RecordKind};
use crate::types::{BlockData, Finalized, Notarized};

/// Session-backed reader for Commonware Simplex blocks and certificates.
///
/// Typed reads decode artifacts and validate their index bindings. Callers
/// remain responsible for verifying certificate signatures.
#[derive(Clone, Debug)]
pub struct SimplexReader {
    session: ReadSession,
}

impl SimplexReader {
    /// Build a reader with a fresh monotonic session and no initial minimum.
    pub fn new(store: PrefixedStoreClient) -> Self {
        Self::with_session(ReadSession::monotonic(store, None))
    }

    /// Build a reader with the supplied Store read policy.
    pub const fn with_session(session: ReadSession) -> Self {
        Self { session }
    }

    /// Derive a reader whose Store reads require at least `sequence`.
    pub fn with_min_sequence_number(&self, sequence: u64) -> Self {
        Self::with_session(self.session.with_min_sequence_number(sequence))
    }

    /// Return the minimum Store sequence required by subsequent reads.
    pub fn min_sequence_number(&self) -> Option<u64> {
        self.session.min_sequence_number()
    }

    /// Return the highest Store sequence observed by this reader's session.
    pub fn evaluated_sequence(&self) -> Option<u64> {
        self.session.evaluated_sequence()
    }

    pub async fn get_header_raw<D: Digest>(
        &self,
        digest: &D,
    ) -> Result<Option<Bytes>, SimplexError> {
        self.get_raw(keys::header_by_digest(digest)).await
    }

    pub async fn get_block_raw<D: Digest>(
        &self,
        digest: &D,
    ) -> Result<Option<Bytes>, SimplexError> {
        self.get_raw(keys::block_by_digest(digest)).await
    }

    pub async fn get_notarized_by_round_raw(
        &self,
        round: commonware_consensus::types::Round,
    ) -> Result<Option<Bytes>, SimplexError> {
        self.get_raw(keys::notarization_by_round(round)).await
    }

    pub async fn get_finalized_by_round_raw(
        &self,
        round: commonware_consensus::types::Round,
    ) -> Result<Option<Bytes>, SimplexError> {
        self.get_raw(keys::finalization_by_round(round)).await
    }

    pub async fn get_finalized_by_height_raw(
        &self,
        height: commonware_consensus::types::Height,
    ) -> Result<Option<Bytes>, SimplexError> {
        self.get_raw(keys::finalized_by_height(height)).await
    }

    pub async fn latest_finalized_raw(&self) -> Result<Option<Bytes>, SimplexError> {
        Ok(self.latest_finalized_row().await?.map(|(_, value)| value))
    }

    pub async fn get_header<B, D>(
        &self,
        digest: &D,
        cfg: &<B as commonware_codec::Read>::Cfg,
    ) -> Result<Option<B>, SimplexError>
    where
        B: Block<Digest = D>,
        D: Digest,
    {
        self.decode_indexed(self.get_header_raw(digest).await?, cfg, |value: &B| {
            value.digest() == *digest
        })
    }

    pub async fn get_block<B, D>(
        &self,
        digest: &D,
        cfg: &<BlockData<B> as commonware_codec::Read>::Cfg,
    ) -> Result<Option<BlockData<B>>, SimplexError>
    where
        B: Block<Digest = D>,
        D: Digest,
    {
        self.decode_indexed(
            self.get_block_raw(digest).await?,
            cfg,
            |value: &BlockData<B>| value.header.digest() == *digest,
        )
    }

    pub async fn get_notarized_by_round<B, S, D>(
        &self,
        round: commonware_consensus::types::Round,
        cfg: &<Notarized<B, S, D> as commonware_codec::Read>::Cfg,
    ) -> Result<Option<Notarized<B, S, D>>, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
        <S::Certificate as commonware_codec::Read>::Cfg: Clone,
    {
        self.decode_indexed(
            self.get_notarized_by_round_raw(round).await?,
            cfg,
            |value: &Notarized<B, S, D>| value.proof.round() == round,
        )
    }

    pub async fn get_finalized_by_height<B, S, D>(
        &self,
        height: commonware_consensus::types::Height,
        cfg: &<Finalized<B, S, D> as commonware_codec::Read>::Cfg,
    ) -> Result<Option<Finalized<B, S, D>>, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
        <S::Certificate as commonware_codec::Read>::Cfg: Clone,
    {
        self.decode_indexed(
            self.get_finalized_by_height_raw(height).await?,
            cfg,
            |value: &Finalized<B, S, D>| value.header.height() == height,
        )
    }

    pub async fn get_finalized_by_round<B, S, D>(
        &self,
        round: commonware_consensus::types::Round,
        cfg: &<Finalized<B, S, D> as commonware_codec::Read>::Cfg,
    ) -> Result<Option<Finalized<B, S, D>>, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
        <S::Certificate as commonware_codec::Read>::Cfg: Clone,
    {
        self.decode_indexed(
            self.get_finalized_by_round_raw(round).await?,
            cfg,
            |value: &Finalized<B, S, D>| value.proof.round() == round,
        )
    }

    pub async fn latest_finalized<B, S, D>(
        &self,
        cfg: &<Finalized<B, S, D> as commonware_codec::Read>::Cfg,
    ) -> Result<Option<Finalized<B, S, D>>, SimplexError>
    where
        B: Block<Digest = D>,
        S: certificate::Scheme,
        D: Digest,
        <S::Certificate as commonware_codec::Read>::Cfg: Clone,
    {
        let Some((key, value)) = self.latest_finalized_row().await? else {
            return Ok(None);
        };
        let height =
            keys::finalized_height_from_key(&key).ok_or(SimplexError::RecordKeyMismatch)?;
        self.decode_indexed(Some(value), cfg, |value: &Finalized<B, S, D>| {
            value.header.height() == height
        })
    }

    async fn get_raw(&self, key: Key) -> Result<Option<Bytes>, SimplexError> {
        Ok(self.session.get(&key).await?)
    }

    async fn latest_finalized_row(&self) -> Result<Option<(Key, Bytes)>, SimplexError> {
        let (start, end) = keys::range_for_kind(RecordKind::FinalizedByHeight);
        let rows = self
            .session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        Ok(rows.into_iter().next())
    }

    fn decode_indexed<T: Decode>(
        &self,
        value: Option<Bytes>,
        cfg: &T::Cfg,
        matches: impl FnOnce(&T) -> bool,
    ) -> Result<Option<T>, SimplexError> {
        let Some(bytes) = value else {
            return Ok(None);
        };
        let decoded = T::decode_cfg(bytes, cfg)?;
        if !matches(&decoded) {
            return Err(SimplexError::RecordKeyMismatch);
        }
        Ok(Some(decoded))
    }
}
