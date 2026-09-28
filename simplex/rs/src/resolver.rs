use std::{marker::PhantomData, num::NonZeroUsize, time::Duration};

use bytes::Bytes;
use commonware_consensus::marshal::resolver::handler::{self, Annotation, Key as MarshalKey};
use commonware_cryptography::{Digest, PublicKey};
use commonware_resolver::opaque;
use commonware_runtime::{Clock, Metrics, Spawner};

use crate::SimplexReader;

const RETRY_DELAY: Duration = Duration::from_millis(50);

#[derive(Clone)]
struct MarshalFetcher<D: Digest> {
    reader: SimplexReader,
    _marker: PhantomData<D>,
}

impl<D> opaque::Fetcher for MarshalFetcher<D>
where
    D: Digest + Send + 'static,
{
    type Key = MarshalKey<D>;
    type Value = Bytes;

    async fn fetch(&self, key: Self::Key) -> Option<Self::Value> {
        let result = match key {
            MarshalKey::Block(commitment) => self.reader.get_header_raw(&commitment).await,
            MarshalKey::Finalized { height } => {
                self.reader.get_finalized_by_height_raw(height).await
            }
            MarshalKey::Notarized { round } => self.reader.get_notarized_by_round_raw(round).await,
        };
        match result {
            Ok(value) => value,
            Err(error) => {
                tracing::debug!(%error, "failed to resolve marshal value");
                None
            }
        }
    }
}

/// Initialize a store-backed resolver and its receiver for Commonware marshal requests.
pub fn init_marshal_resolver<E, D, P>(
    context: E,
    mailbox_size: NonZeroUsize,
    reader: SimplexReader,
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
        MarshalFetcher {
            reader,
            _marker: PhantomData,
        },
        handler,
        mailbox_size,
        RETRY_DELAY,
    );
    (receiver, resolver)
}
