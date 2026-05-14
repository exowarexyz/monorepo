use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_consensus::{simplex::types, Block};
use commonware_cryptography::{certificate, Digest};

/// A Simplex notarization plus the block whose digest was notarized.
#[derive(Clone, Debug)]
pub struct Notarized<B, S: certificate::Scheme, D: Digest> {
    pub proof: types::Notarization<S, D>,
    pub block: B,
}

impl<B, S, D> PartialEq for Notarized<B, S, D>
where
    B: PartialEq,
    S: certificate::Scheme,
    D: Digest,
{
    fn eq(&self, other: &Self) -> bool {
        self.proof == other.proof && self.block == other.block
    }
}

impl<B, S, D> Eq for Notarized<B, S, D>
where
    B: Eq,
    S: certificate::Scheme,
    D: Digest,
{
}

impl<B, S, D> Notarized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
{
    pub fn new(proof: types::Notarization<S, D>, block: B) -> Result<Self, Error> {
        if proof.proposal.payload != block.digest() {
            return Err(Error::Invalid(
                "exoware_simplex::Notarized",
                "proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

impl<B, S, D> Write for Notarized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl<B, S, D> Read for Notarized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
    <S::Certificate as Read>::Cfg: Clone,
{
    type Cfg = (<S::Certificate as Read>::Cfg, <B as Read>::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proof = types::Notarization::<S, D>::read_cfg(buf, &cfg.0)?;
        let block = B::read_cfg(buf, &cfg.1)?;
        Self::new(proof, block)
    }
}

impl<B, S, D> EncodeSize for Notarized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
{
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

/// A Simplex finalization plus the block whose digest was finalized.
#[derive(Clone, Debug)]
pub struct Finalized<B, S: certificate::Scheme, D: Digest> {
    pub proof: types::Finalization<S, D>,
    pub block: B,
}

impl<B, S, D> PartialEq for Finalized<B, S, D>
where
    B: PartialEq,
    S: certificate::Scheme,
    D: Digest,
{
    fn eq(&self, other: &Self) -> bool {
        self.proof == other.proof && self.block == other.block
    }
}

impl<B, S, D> Eq for Finalized<B, S, D>
where
    B: Eq,
    S: certificate::Scheme,
    D: Digest,
{
}

impl<B, S, D> Finalized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
{
    pub fn new(proof: types::Finalization<S, D>, block: B) -> Result<Self, Error> {
        if proof.proposal.payload != block.digest() {
            return Err(Error::Invalid(
                "exoware_simplex::Finalized",
                "proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

impl<B, S, D> Write for Finalized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl<B, S, D> Read for Finalized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
    <S::Certificate as Read>::Cfg: Clone,
{
    type Cfg = (<S::Certificate as Read>::Cfg, <B as Read>::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proof = types::Finalization::<S, D>::read_cfg(buf, &cfg.0)?;
        let block = B::read_cfg(buf, &cfg.1)?;
        Self::new(proof, block)
    }
}

impl<B, S, D> EncodeSize for Finalized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
{
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UploadSummary {
    pub blocks: usize,
    pub notarizations: usize,
    pub finalizations: usize,
    pub finalized_height_indexes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadReceipt {
    pub store_sequence_number: u64,
    pub summary: UploadSummary,
}
