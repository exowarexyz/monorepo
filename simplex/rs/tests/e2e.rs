use bytes::{Buf, BufMut, Bytes, BytesMut};
use commonware_codec::{Decode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::{
    simplex::types::{Finalization, Finalize, Notarization, Notarize, Proposal},
    types::{Epoch, Height, Round, View},
    Block as ConsensusBlock, CertifiableBlock, Heightable,
};
use commonware_cryptography::{
    certificate::mocks::Fixture, ed25519, sha256, Digest as _, Digestible, Hasher, Sha256, Signer,
};
use commonware_parallel::Sequential;
use exoware_sdk::{RetryConfig, StoreBatchUpload, StoreClient};
use exoware_simplex::{BlockData, Finalized, Notarized, SimplexClient};
use rand::{rngs::StdRng, SeedableRng};

const NAMESPACE: &[u8] = b"_EXOWARE_SIMPLEX_TEST";

type Scheme = commonware_consensus::simplex::scheme::ed25519::Scheme;
type Sha256Digest = sha256::Digest;
type PublicKey = ed25519::PublicKey;
type Context = commonware_consensus::simplex::types::Context<Sha256Digest, PublicKey>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct TestBlock {
    context: Context,
    parent: Sha256Digest,
    height: Height,
    payload: Vec<u8>,
    digest: Sha256Digest,
}

impl TestBlock {
    fn new(height: u64, payload: &[u8]) -> Self {
        let context = Context {
            round: Round::new(Epoch::zero(), View::new(height)),
            leader: ed25519::PrivateKey::from_seed(0).public_key(),
            parent: (View::new(height.saturating_sub(1)), Sha256Digest::EMPTY),
        };
        let parent = Sha256Digest::EMPTY;
        let mut block = Self {
            context,
            parent,
            height: Height::new(height),
            payload: payload.to_vec(),
            digest: Sha256Digest::EMPTY,
        };
        block.digest = block.compute_digest();
        block
    }

    fn compute_digest(&self) -> Sha256Digest {
        let mut header = BytesMut::with_capacity(self.encode_size());
        self.write(&mut header);
        let mut hasher = Sha256::new();
        hasher.update(&header);
        hasher.finalize()
    }
}

impl Write for TestBlock {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.payload.write(buf);
    }
}

impl Read for TestBlock {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_payload_len: &Self::Cfg) -> Result<Self, Error> {
        let context = Context::read(buf)?;
        let parent = Sha256Digest::read(buf)?;
        let height = Height::read(buf)?;
        let payload = Vec::<u8>::read_cfg(buf, &((..=*max_payload_len).into(), ()))?;
        let mut block = Self {
            context,
            parent,
            height,
            payload,
            digest: Sha256Digest::EMPTY,
        };
        block.digest = block.compute_digest();
        Ok(block)
    }
}

impl EncodeSize for TestBlock {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.payload.encode_size()
    }
}

impl Digestible for TestBlock {
    type Digest = Sha256Digest;

    fn digest(&self) -> Self::Digest {
        self.digest
    }
}

impl Heightable for TestBlock {
    fn height(&self) -> Height {
        self.height
    }
}

impl ConsensusBlock for TestBlock {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl CertifiableBlock for TestBlock {
    type Context = Context;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

async fn local_store_client() -> (tempfile::TempDir, tokio::task::JoinHandle<()>, StoreClient) {
    let dir = tempfile::tempdir().expect("tempdir");
    let (handle, url) = exoware_simulator::spawn_for_test(dir.path())
        .await
        .expect("spawn simulator");
    let client = StoreClient::builder()
        .url(&url)
        .retry_config(RetryConfig::disabled())
        .build()
        .expect("store client");
    (dir, handle, client)
}

fn schemes() -> Vec<Scheme> {
    let mut rng = StdRng::seed_from_u64(7);
    let Fixture { schemes, .. } =
        commonware_consensus::simplex::scheme::ed25519::fixture(&mut rng, NAMESPACE, 4);
    schemes
}

fn proposal(block: &TestBlock) -> Proposal<Sha256Digest> {
    Proposal::new(block.context.round, block.context.parent.0, block.digest())
}

fn notarized(block: TestBlock, schemes: &[Scheme]) -> Notarized<TestBlock, Scheme, Sha256Digest> {
    let proposal = proposal(&block);
    let votes: Vec<_> = schemes
        .iter()
        .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
        .collect();
    let proof =
        Notarization::from_notarizes(&schemes[0], &votes, &Sequential).expect("notarization");
    Notarized::new(proof, block).expect("notarized")
}

fn finalized(block: TestBlock, schemes: &[Scheme]) -> Finalized<TestBlock, Scheme, Sha256Digest> {
    let proposal = proposal(&block);
    let votes: Vec<_> = schemes
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("finalize"))
        .collect();
    let proof =
        Finalization::from_finalizes(&schemes[0], &votes, &Sequential).expect("finalization");
    Finalized::new(proof, block).expect("finalized")
}

fn finalized_with_body(
    block: TestBlock,
    body: Bytes,
    schemes: &[Scheme],
) -> Finalized<TestBlock, Scheme, Sha256Digest> {
    let proposal = proposal(&block);
    let votes: Vec<_> = schemes
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("finalize"))
        .collect();
    let proof =
        Finalization::from_finalizes(&schemes[0], &votes, &Sequential).expect("finalization");
    Finalized::with_body(proof, block, body).expect("finalized")
}

#[tokio::test]
async fn uploads_and_reads_notarized_and_finalized_blocks() {
    let (_dir, _handle, store) = local_store_client().await;
    let simplex = SimplexClient::from_client(store);
    let schemes = schemes();

    let block1 = TestBlock::new(1, b"notarized");
    let notarized = notarized(block1.clone(), &schemes);
    let receipt = simplex
        .upload_notarized(&notarized)
        .await
        .expect("upload notarized");
    assert_eq!(receipt.summary.headers, 1);
    assert_eq!(receipt.summary.blocks, 1);
    assert_eq!(receipt.summary.notarizations, 1);

    let got_header = simplex
        .get_header::<TestBlock, Sha256Digest>(&block1.digest(), &1024)
        .await
        .expect("get header")
        .expect("header exists");
    assert_eq!(got_header, block1);

    let got_block = simplex
        .get_block::<TestBlock, Sha256Digest>(&block1.digest(), &1024)
        .await
        .expect("get full block")
        .expect("full block exists");
    assert_eq!(got_block, BlockData::new(block1.clone()));

    let got_notarized = simplex
        .get_notarized::<TestBlock, Scheme, Sha256Digest>(View::new(1), &(10, 1024))
        .await
        .expect("get notarized")
        .expect("notarized exists");
    assert_eq!(got_notarized, notarized);

    let block2 = TestBlock::new(2, b"finalized");
    let finalized = finalized_with_body(
        block2.clone(),
        Bytes::from_static(b"finalized transaction body"),
        &schemes,
    );
    let receipt = simplex
        .upload_finalized(&finalized)
        .await
        .expect("upload finalized");
    assert_eq!(receipt.summary.headers, 1);
    assert_eq!(receipt.summary.blocks, 1);
    assert_eq!(receipt.summary.finalizations, 1);
    assert_eq!(receipt.summary.finalized_height_indexes, 1);

    let got_block = simplex
        .get_block::<TestBlock, Sha256Digest>(&block2.digest(), &1024)
        .await
        .expect("get full block")
        .expect("full block exists");
    assert_eq!(got_block.header, block2);
    assert_eq!(
        got_block.body,
        Bytes::from_static(b"finalized transaction body")
    );

    let got_finalized = simplex
        .get_finalized_by_height::<TestBlock, Scheme, Sha256Digest>(Height::new(2), &(10, 1024))
        .await
        .expect("get finalized")
        .expect("finalized exists");
    assert_eq!(got_finalized, finalized);

    let got_finalized = simplex
        .get_finalized_by_view::<TestBlock, Scheme, Sha256Digest>(View::new(2), &(10, 1024))
        .await
        .expect("get finalized by view")
        .expect("finalized by view exists");
    assert_eq!(got_finalized, finalized);

    let latest = simplex
        .latest_finalized::<TestBlock, Scheme, Sha256Digest>(&(10, 1024))
        .await
        .expect("latest finalized")
        .expect("latest exists");
    assert_eq!(latest, finalized);
}

#[tokio::test]
async fn prepared_uploads_can_share_one_store_batch() {
    let (_dir, _handle, store) = local_store_client().await;
    let simplex = SimplexClient::from_client(store.clone());
    let schemes = schemes();

    let first = finalized(TestBlock::new(10, b"first"), &schemes);
    let second = finalized(TestBlock::new(11, b"second"), &schemes);

    let mut prepared = simplex.prepare_finalized(&first).expect("first");
    prepared.extend(simplex.prepare_finalized(&second).expect("second"));

    let receipt = simplex
        .commit_upload(&store, prepared)
        .await
        .expect("commit combined");
    assert_eq!(receipt.summary.headers, 2);
    assert_eq!(receipt.summary.blocks, 2);
    assert_eq!(receipt.summary.finalizations, 2);

    let latest = simplex
        .latest_finalized_raw()
        .await
        .expect("latest finalized")
        .expect("latest exists");
    let latest = Finalized::<TestBlock, Scheme, Sha256Digest>::decode_cfg(latest, &(10, 1024))
        .expect("decode latest");
    assert_eq!(latest, second);
}
