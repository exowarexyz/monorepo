use std::{future::Future, marker::PhantomData, num::NonZeroUsize, time::Duration};

use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_consensus::marshal::resolver::handler::{
    self, Annotation, Handler as MarshalHandler, Key as MarshalKey,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_resolver::{opaque, Fetch, Resolver, TargetedResolver};
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::vec::NonEmptyVec;

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

/// Store-backed resolver for Commonware marshal requests.
///
/// Unlike the P2P resolver, this resolves marshal backfill requests directly
/// from an Exoware Simplex store and delivers responses into Marshal's local
/// resolver handler.
#[derive(Clone)]
pub struct MarshalResolver<D: Digest, P: PublicKey> {
    client: SimplexClient,
    inner: opaque::Resolver<MarshalKey<D>, Annotation, P>,
}

impl<D, P> MarshalResolver<D, P>
where
    D: Digest + Send + 'static,
    P: PublicKey,
{
    pub fn init<E>(
        context: E,
        mailbox_size: NonZeroUsize,
        client: SimplexClient,
    ) -> (handler::Receiver<D>, Self)
    where
        E: Clock + Metrics + Spawner,
    {
        let (receiver, handler) = handler::init(context.child("handler"), mailbox_size);
        (receiver, Self::new(context, mailbox_size, client, handler))
    }

    pub fn new<E>(
        context: E,
        mailbox_size: NonZeroUsize,
        client: SimplexClient,
        handler: MarshalHandler<D>,
    ) -> Self
    where
        E: Clock + Metrics + Spawner,
    {
        let fetcher = MarshalFetcher::new(client.clone());
        let inner = opaque::init(
            context.child("opaque"),
            fetcher,
            handler,
            mailbox_size,
            RETRY_DELAY,
        );
        Self { client, inner }
    }

    pub const fn client(&self) -> &SimplexClient {
        &self.client
    }

    pub fn into_client(self) -> SimplexClient {
        self.client
    }
}

impl<D, P> Resolver for MarshalResolver<D, P>
where
    D: Digest + Send + 'static,
    P: PublicKey,
{
    type Key = MarshalKey<D>;
    type Subscriber = Annotation;

    fn fetch<F>(&mut self, key: F) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        self.inner.fetch(key)
    }

    fn fetch_all<F>(&mut self, keys: Vec<F>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        self.inner.fetch_all(keys)
    }

    fn retain(
        &mut self,
        predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        self.inner.retain(predicate)
    }
}

impl<D, P> TargetedResolver for MarshalResolver<D, P>
where
    D: Digest + Send + 'static,
    P: PublicKey,
{
    type PublicKey = P;

    fn fetch_targeted(
        &mut self,
        key: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        self.inner.fetch_targeted(key, targets)
    }

    fn fetch_all_targeted<F>(&mut self, keys: Vec<(F, NonEmptyVec<Self::PublicKey>)>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        self.inner.fetch_all_targeted(keys)
    }
}

async fn fetch_value<D: Digest>(
    client: &SimplexClient,
    key: MarshalKey<D>,
) -> Result<Option<Bytes>, crate::SimplexError> {
    match key {
        MarshalKey::Block(commitment) => client.get_header_raw(&commitment).await,
        MarshalKey::Finalized { height } => client.get_finalized_by_height_raw(height).await,
        MarshalKey::Notarized { round } => client.get_notarized_raw(round.view()).await,
    }
}
