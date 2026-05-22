use std::{
    collections::BTreeMap,
    marker::PhantomData,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_consensus::marshal::resolver::handler::{
    self, Annotation, Handler as MarshalHandler, Key as MarshalKey,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_resolver::{Consumer, Delivery, Fetch, Resolver};
use commonware_runtime::Metrics;
use commonware_utils::vec::NonEmptyVec;

use crate::SimplexClient;

const RETRY_DELAY: Duration = Duration::from_millis(50);

/// Store-backed resolver for Commonware marshal requests.
///
/// Unlike the P2P resolver, this resolves marshal backfill requests directly
/// from an Exoware Simplex store and delivers responses into Marshal's local
/// resolver handler.
#[derive(Clone)]
pub struct MarshalResolver<D: Digest, P: PublicKey> {
    client: SimplexClient,
    handler: MarshalHandler<D>,
    pending: Arc<Mutex<BTreeMap<MarshalKey<D>, Vec<Annotation>>>>,
    _marker: PhantomData<P>,
}

impl<D, P> MarshalResolver<D, P>
where
    D: Digest,
    P: PublicKey,
{
    pub fn init(
        metrics: impl Metrics,
        mailbox_size: NonZeroUsize,
        client: SimplexClient,
    ) -> (handler::Receiver<D>, Self) {
        let (receiver, handler) = handler::init(metrics, mailbox_size);
        (receiver, Self::new(client, handler))
    }

    pub fn new(client: SimplexClient, handler: MarshalHandler<D>) -> Self {
        Self {
            client,
            handler,
            pending: Arc::default(),
            _marker: PhantomData,
        }
    }

    pub const fn client(&self) -> &SimplexClient {
        &self.client
    }

    pub fn into_client(self) -> SimplexClient {
        self.client
    }

    fn retain_subscribers(
        &self,
        predicate: impl Fn(&MarshalKey<D>, &Annotation) -> bool,
    ) -> Feedback {
        let mut pending = self.pending.lock().expect("marshal resolver pending lock");
        pending.retain(|key, subscribers| {
            subscribers.retain(|subscriber| predicate(key, subscriber));
            !subscribers.is_empty()
        });
        Feedback::Ok
    }
}

impl<D, P> MarshalResolver<D, P>
where
    D: Digest + Send + 'static,
    P: PublicKey + Send + 'static,
{
    fn fetch_one(&mut self, fetch: Fetch<MarshalKey<D>, Annotation>) -> Feedback {
        let mut pending = self.pending.lock().expect("marshal resolver pending lock");
        let should_spawn = match pending.entry(fetch.key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(vec![fetch.subscriber]);
                true
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let subscribers = entry.get_mut();
                if !subscribers.contains(&fetch.subscriber) {
                    subscribers.push(fetch.subscriber);
                }
                false
            }
        };
        drop(pending);

        if !should_spawn {
            return Feedback::Ok;
        }

        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            self.pending
                .lock()
                .expect("marshal resolver pending lock")
                .remove(&fetch.key);
            return Feedback::Closed;
        };

        let resolver = self.clone();
        handle.spawn(async move {
            resolver.resolve(fetch.key).await;
        });
        Feedback::Ok
    }

    async fn resolve(self, key: MarshalKey<D>) {
        let value = loop {
            if !self
                .pending
                .lock()
                .expect("marshal resolver pending lock")
                .contains_key(&key)
            {
                return;
            }

            match self.fetch_value(key).await {
                Ok(Some(value)) => break value,
                Ok(None) => tokio::time::sleep(RETRY_DELAY).await,
                Err(error) => {
                    tracing::debug!(%error, "failed to resolve marshal value");
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        };

        let subscribers = self
            .pending
            .lock()
            .expect("marshal resolver pending lock")
            .remove(&key)
            .and_then(|subscribers| NonEmptyVec::try_from(subscribers).ok());
        let Some(subscribers) = subscribers else {
            return;
        };

        let mut handler = self.handler.clone();
        let accepted = handler
            .deliver(Delivery { key, subscribers }, value)
            .await
            .unwrap_or(false);
        if !accepted {
            tracing::debug!(?key, "marshal rejected resolved value");
        }
    }

    async fn fetch_value(&self, key: MarshalKey<D>) -> Result<Option<Bytes>, crate::SimplexError> {
        match key {
            MarshalKey::Block(commitment) => self.client.get_header_raw(&commitment).await,
            MarshalKey::Finalized { height } => {
                self.client.get_finalized_by_height_raw(height).await
            }
            MarshalKey::Notarized { round } => self.client.get_notarized_raw(round.view()).await,
        }
    }
}

impl<D, P> Resolver for MarshalResolver<D, P>
where
    D: Digest + Send + 'static,
    P: PublicKey + Send + 'static,
{
    type Key = MarshalKey<D>;
    type Subscriber = Annotation;
    type PublicKey = P;

    fn fetch<F>(&mut self, key: F) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        self.fetch_one(key.into())
    }

    fn fetch_all<F>(&mut self, keys: Vec<F>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        let mut feedback = Feedback::Ok;
        for key in keys {
            if !self.fetch_one(key.into()).accepted() {
                feedback = Feedback::Closed;
            }
        }
        feedback
    }

    fn fetch_targeted(
        &mut self,
        key: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        _targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        self.fetch(key)
    }

    fn fetch_all_targeted<F>(&mut self, keys: Vec<(F, NonEmptyVec<Self::PublicKey>)>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        self.fetch_all(keys.into_iter().map(|(key, _targets)| key).collect())
    }

    fn retain(
        &mut self,
        predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        self.retain_subscribers(predicate)
    }
}
