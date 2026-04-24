use bytes::{Buf, BufMut};
use clap::{Parser, Subcommand};
use commonware_codec::{varint::UInt, Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::vrf as bls12381_threshold,
        types::{Finalization, Finalize, Notarization, Notarize, Proposal},
    },
    types::{Epoch, Height, Round, View},
    Heightable,
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    certificate::mocks::Fixture,
    ed25519,
    sha256::Digest as Sha256Digest,
    Digestible, Hasher, Sha256,
};
use commonware_parallel::Sequential;
use exoware_sdk::StoreClient;
use exoware_simplex::SimplexStoreWriter;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use tracing::info;

type PublicKey = ed25519::PublicKey;
type Scheme = bls12381_threshold::Scheme<PublicKey, MinSig>;
type Identity = <MinSig as Variant>::Public;

#[derive(Parser, Debug)]
#[command(name = "simplex", version, about = "Simplex demo seed writer.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Seed {
        #[arg(long)]
        store_url: String,
        #[arg(long, default_value_t = 2)]
        interval_secs: u64,
        #[arg(long, default_value_t = 7)]
        rng_seed: u64,
        #[arg(long)]
        namespace: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DemoBlock {
    height: Height,
    view: View,
    parent: Sha256Digest,
    payload: Vec<u8>,
    digest: Sha256Digest,
}

impl DemoBlock {
    fn new(height: Height, view: View, parent: Sha256Digest) -> Self {
        let payload = format!(
            "simplex demo block height={} view={} parent={}",
            height.get(),
            view.get(),
            hex::encode(parent)
        )
        .into_bytes();
        let mut digest_input = Vec::with_capacity(16 + parent.len() + payload.len());
        digest_input.extend_from_slice(&height.get().to_be_bytes());
        digest_input.extend_from_slice(&view.get().to_be_bytes());
        digest_input.extend_from_slice(parent.as_ref());
        digest_input.extend_from_slice(&payload);
        let digest = Sha256::hash(&digest_input);
        Self {
            height,
            view,
            parent,
            payload,
            digest,
        }
    }
}

impl Heightable for DemoBlock {
    fn height(&self) -> Height {
        self.height
    }
}

impl Digestible for DemoBlock {
    type Digest = Sha256Digest;

    fn digest(&self) -> Self::Digest {
        self.digest
    }
}

impl Write for DemoBlock {
    fn write(&self, writer: &mut impl BufMut) {
        self.height.write(writer);
        self.view.write(writer);
        self.parent.write(writer);
        UInt(self.payload.len() as u64).write(writer);
        writer.put_slice(&self.payload);
    }
}

impl Read for DemoBlock {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let height = Height::read(reader)?;
        let view = View::read(reader)?;
        let parent = Sha256Digest::read(reader)?;
        let len = UInt::<u64>::read(reader)?.0 as usize;
        if reader.remaining() < len {
            return Err(Error::EndOfBuffer);
        }
        let mut payload = vec![0; len];
        reader.copy_to_slice(&mut payload);
        let mut digest_input = Vec::with_capacity(16 + parent.as_ref().len() + payload.len());
        digest_input.extend_from_slice(&height.get().to_be_bytes());
        digest_input.extend_from_slice(&view.get().to_be_bytes());
        digest_input.extend_from_slice(parent.as_ref());
        digest_input.extend_from_slice(&payload);
        let digest = Sha256::hash(&digest_input);
        Ok(Self {
            height,
            view,
            parent,
            payload,
            digest,
        })
    }
}

impl EncodeSize for DemoBlock {
    fn encode_size(&self) -> usize {
        self.height.encode_size()
            + self.view.encode_size()
            + self.parent.encode_size()
            + UInt(self.payload.len() as u64).encode_size()
            + self.payload.len()
    }
}

fn generated_namespace() -> String {
    format!("simplex-demo-{:016x}", rand::thread_rng().next_u64())
}

fn committee(seed: u64, namespace: &[u8]) -> (Vec<Scheme>, Identity) {
    let mut rng = StdRng::seed_from_u64(seed);
    let Fixture { schemes, .. } = bls12381_threshold::fixture::<MinSig, _>(&mut rng, namespace, 4);
    let identity = *schemes[0].identity();
    (schemes, identity)
}

async fn seed(
    store_url: &str,
    interval_secs: u64,
    rng_seed: u64,
    namespace: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = StoreClient::new(store_url);
    let mut writer = SimplexStoreWriter::new(client);
    let namespace = namespace.unwrap_or_else(generated_namespace);
    let (schemes, identity) = committee(rng_seed, namespace.as_bytes());

    println!("simplex_identity=0x{}", hex::encode(identity.encode()));
    println!("simplex_namespace={namespace}");

    info!(store_url, interval_secs, namespace, "starting simplex seed");
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut parent = Sha256::hash(b"simplex-demo-genesis");
    let mut parent_view = View::new(0);
    let mut height = 1u64;

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                info!("ctrl-c received, shutting down");
                break;
            }
            _ = ticker.tick() => {}
        }

        let block = DemoBlock::new(Height::new(height), View::new(height), parent);
        let proposal = Proposal::new(
            Round::new(Epoch::zero(), block.view),
            parent_view,
            block.digest(),
        );

        let notarizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("sign notarize"))
            .collect();
        let notarization =
            Notarization::from_notarizes(&schemes[0], &notarizes, &Sequential).expect("notarize");
        writer.insert_notarized(&notarization, &block)?;

        let finalizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("sign finalize"))
            .collect();
        let finalization =
            Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).expect("finalize");
        writer.insert_finalized(&finalization, &block)?;

        if let Some(receipt) = writer.flush_with_receipt().await? {
            println!(
                "sequence={} height={} view={} digest=0x{} certificates={} indexes={} raw_blocks={}",
                receipt.store_sequence_number,
                height,
                block.view.get(),
                hex::encode(block.digest()),
                receipt.certificate_count,
                receipt.index_count,
                receipt.raw_block_count
            );
        }

        parent = block.digest();
        parent_view = block.view;
        height = height.saturating_add(1);
    }

    Ok(())
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    init_tracing();
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Seed {
            store_url,
            interval_secs,
            rng_seed,
            namespace,
        } => seed(&store_url, interval_secs, rng_seed, namespace).await,
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("simplex failed: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}
