use bytes::{Buf, BufMut, Bytes, BytesMut};
use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_consensus::{simplex::types, Block};
use commonware_cryptography::{certificate, Digest};

const HEADER_LENGTH_BYTES: usize = 4;

fn write_block_data<B>(header: &B, body: &[u8], buf: &mut impl BufMut)
where
    B: Write + EncodeSize,
{
    let mut header_bytes = BytesMut::with_capacity(header.encode_size());
    header.write(&mut header_bytes);
    let header_len =
        u32::try_from(header_bytes.len()).expect("header block encoding exceeds u32 length");
    buf.put_u32(header_len);
    buf.put_slice(&header_bytes);
    buf.put_slice(body);
}

pub fn encode_block_data<B>(header: &B, body: &[u8]) -> Bytes
where
    B: Write + EncodeSize,
{
    let mut buf = BytesMut::with_capacity(HEADER_LENGTH_BYTES + header.encode_size() + body.len());
    write_block_data(header, body, &mut buf);
    buf.freeze()
}

/// Simplex header bytes plus arbitrary body bytes that ride with them.
///
/// The header portion is the only part covered by the certificate digest.
/// The body portion can carry transactions or other non-certified data that
/// should be fetched and streamed with the header bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockData<B> {
    pub header: B,
    pub body: Bytes,
}

impl<B> BlockData<B> {
    pub fn new(header: B) -> Self {
        Self {
            header,
            body: Bytes::new(),
        }
    }

    pub fn with_body(header: B, body: impl Into<Bytes>) -> Self {
        Self {
            header,
            body: body.into(),
        }
    }
}

impl<B> Write for BlockData<B>
where
    B: Write + EncodeSize,
{
    fn write(&self, buf: &mut impl BufMut) {
        write_block_data(&self.header, &self.body, buf);
    }
}

impl<B> Read for BlockData<B>
where
    B: Read,
{
    type Cfg = <B as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        if buf.remaining() < HEADER_LENGTH_BYTES {
            return Err(Error::Invalid(
                "exoware_simplex::BlockData",
                "missing header length",
            ));
        }
        let header_len = buf.get_u32() as usize;
        if buf.remaining() < header_len {
            return Err(Error::Invalid(
                "exoware_simplex::BlockData",
                "header length exceeds remaining bytes",
            ));
        }
        let mut header_bytes = buf.copy_to_bytes(header_len);
        let header = B::read_cfg(&mut header_bytes, cfg)?;
        if header_bytes.has_remaining() {
            return Err(Error::Invalid(
                "exoware_simplex::BlockData",
                "header bytes contain trailing data",
            ));
        }
        let body = buf.copy_to_bytes(buf.remaining());
        Ok(Self { header, body })
    }
}

impl<B> EncodeSize for BlockData<B>
where
    B: EncodeSize,
{
    fn encode_size(&self) -> usize {
        HEADER_LENGTH_BYTES + self.header.encode_size() + self.body.len()
    }
}

/// A Simplex notarization plus header bytes and body bytes for the digest.
#[derive(Clone, Debug)]
pub struct Notarized<B, S: certificate::Scheme, D: Digest> {
    pub proof: types::Notarization<S, D>,
    pub header: B,
    pub body: Bytes,
}

impl<B, S, D> PartialEq for Notarized<B, S, D>
where
    B: PartialEq,
    S: certificate::Scheme,
    D: Digest,
{
    fn eq(&self, other: &Self) -> bool {
        self.proof == other.proof && self.header == other.header && self.body == other.body
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
    pub fn new(proof: types::Notarization<S, D>, header: B) -> Result<Self, Error> {
        Self::with_body(proof, header, Bytes::new())
    }

    pub fn with_body(
        proof: types::Notarization<S, D>,
        header: B,
        body: impl Into<Bytes>,
    ) -> Result<Self, Error> {
        if proof.proposal.payload != header.digest() {
            return Err(Error::Invalid(
                "exoware_simplex::Notarized",
                "proof payload does not match header digest",
            ));
        }
        Ok(Self {
            proof,
            header,
            body: body.into(),
        })
    }

    pub fn block_data(&self) -> BlockData<B>
    where
        B: Clone,
    {
        BlockData::with_body(self.header.clone(), self.body.clone())
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
        write_block_data(&self.header, &self.body, buf);
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
        let data = BlockData::<B>::read_cfg(buf, &cfg.1)?;
        Self::with_body(proof, data.header, data.body)
    }
}

impl<B, S, D> EncodeSize for Notarized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
{
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + HEADER_LENGTH_BYTES + self.header.encode_size() + self.body.len()
    }
}

/// A Simplex finalization plus header bytes and body bytes for the digest.
#[derive(Clone, Debug)]
pub struct Finalized<B, S: certificate::Scheme, D: Digest> {
    pub proof: types::Finalization<S, D>,
    pub header: B,
    pub body: Bytes,
}

impl<B, S, D> PartialEq for Finalized<B, S, D>
where
    B: PartialEq,
    S: certificate::Scheme,
    D: Digest,
{
    fn eq(&self, other: &Self) -> bool {
        self.proof == other.proof && self.header == other.header && self.body == other.body
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
    pub fn new(proof: types::Finalization<S, D>, header: B) -> Result<Self, Error> {
        Self::with_body(proof, header, Bytes::new())
    }

    pub fn with_body(
        proof: types::Finalization<S, D>,
        header: B,
        body: impl Into<Bytes>,
    ) -> Result<Self, Error> {
        if proof.proposal.payload != header.digest() {
            return Err(Error::Invalid(
                "exoware_simplex::Finalized",
                "proof payload does not match header digest",
            ));
        }
        Ok(Self {
            proof,
            header,
            body: body.into(),
        })
    }

    pub fn block_data(&self) -> BlockData<B>
    where
        B: Clone,
    {
        BlockData::with_body(self.header.clone(), self.body.clone())
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
        write_block_data(&self.header, &self.body, buf);
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
        let data = BlockData::<B>::read_cfg(buf, &cfg.1)?;
        Self::with_body(proof, data.header, data.body)
    }
}

impl<B, S, D> EncodeSize for Finalized<B, S, D>
where
    B: Block<Digest = D>,
    S: certificate::Scheme,
    D: Digest,
{
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + HEADER_LENGTH_BYTES + self.header.encode_size() + self.body.len()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UploadSummary {
    pub headers: usize,
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
