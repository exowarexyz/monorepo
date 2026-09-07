use std::{future::Future, marker::PhantomData, num::NonZeroUsize, time::Duration};

use bytes::Bytes;
use commonware_consensus::marshal::resolver::handler::{self, Annotation, Key as MarshalKey};
use commonware_cryptography::{Digest, PublicKey};
use commonware_resolver::opaque;
use commonware_runtime::{Clock, Metrics, Spawner};

use crate::SimplexClient;

const RETRY_DELAY: Duration = Duration::from_millis(50);

#[derive(Clone)]
struct MarshalFetcher<D: Digest> {
    client: SimplexClient,
    _marker: PhantomData<D>,
}

impl<D: Digest> MarshalFetcher<D> {
    const fn new(client: SimplexClient) -> Self {
        Self {
            client,
            _marker: PhantomData,
        }
    }
}

impl<D> opaque::Fetcher for MarshalFetcher<D>
where
    D: Digest + Send + 'static,
{
    type Key = MarshalKey<D>;
    type Value = Bytes;

    fn fetch(&self, key: Self::Key) -> impl Future<Output = Option<Self::Value>> + Send {
        let client = self.client.clone();
        async move {
            match fetch_value(&client, key).await {
                Ok(value) => value,
                Err(error) => {
                    tracing::debug!(%error, "failed to resolve marshal value");
                    None
                }
            }
        }
    }
}

/// Initialize a store-backed resolver and its receiver for Commonware marshal requests.
pub fn init_marshal_resolver<E, D, P>(
    context: E,
    mailbox_size: NonZeroUsize,
    client: SimplexClient,
) -> (
    handler::Receiver<D>,
    opaque::Resolver<MarshalKey<D>, Annotation, P>,
)
where
    E: Clock + Metrics + Spawner,
    D: Digest + Send + 'static,
    P: PublicKey,
{
    let (receiver, handler) = handler::init(context.child("handler"), mailbox_size);
    let resolver = opaque::init(
        context.child("opaque"),
        MarshalFetcher::new(client),
        handler,
        mailbox_size,
        RETRY_DELAY,
    );
    (receiver, resolver)
}

async fn fetch_value<D: Digest>(
    client: &SimplexClient,
    key: MarshalKey<D>,
) -> Result<Option<Bytes>, crate::SimplexError> {
    match key {
        MarshalKey::Block(commitment) => client.get_header_raw(&commitment).await,
        MarshalKey::Finalized { height } => client.get_finalized_by_height_raw(height).await,
        MarshalKey::Notarized { round } => client.get_notarized_by_round_raw(round).await,
    }
}
