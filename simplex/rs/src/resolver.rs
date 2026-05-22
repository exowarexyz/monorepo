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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_actor::Feedback;
    use commonware_consensus::{
        marshal::resolver::handler::{Finalized as FinalizedAnnotation, Request},
        types::Height,
    };
    use commonware_cryptography::{
        ed25519,
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_runtime::{
        telemetry::metrics::{Metric, Registered, Registration},
        Metrics, Name, Supervisor,
    };
    use commonware_utils::NZUsize;
    use exoware_sdk::{RetryConfig, StoreClient};
    use std::fmt;

    type PublicKey = ed25519::PublicKey;

    #[derive(Clone, Copy, Debug, Default)]
    struct TestMetrics;

    impl Supervisor for TestMetrics {
        fn name(&self) -> Name {
            Name::default()
        }

        fn child(&self, _label: &'static str) -> Self {
            Self
        }

        fn with_attribute(self, _key: &'static str, _value: impl fmt::Display) -> Self {
            self
        }
    }

    impl Metrics for TestMetrics {
        fn register<N: Into<String>, H: Into<String>, M: Metric>(
            &self,
            _name: N,
            _help: H,
            metric: M,
        ) -> Registered<M> {
            Registered::with_registration(metric, Registration::from(()))
        }

        fn encode(&self) -> String {
            String::new()
        }
    }

    fn unavailable_client() -> SimplexClient {
        let store = StoreClient::builder()
            .url("http://127.0.0.1:9")
            .retry_config(RetryConfig::disabled())
            .build()
            .expect("store client");
        SimplexClient::from_client(store)
    }

    #[tokio::test]
    async fn duplicate_same_key_fetches_share_pending_request_and_retain_cancels() {
        let (_receiver, mut resolver) = MarshalResolver::<Sha256Digest, PublicKey>::init(
            TestMetrics,
            NZUsize!(10),
            unavailable_client(),
        );
        let commitment = Sha256::fill(0x42);
        let finalized_height = Height::new(7);
        let certified_height = Height::new(8);
        let key = MarshalKey::Block(commitment);
        let finalized = Annotation::Finalized(FinalizedAnnotation::ByHeight {
            height: finalized_height,
        });
        let certified = Annotation::Certified {
            height: certified_height,
        };

        assert_eq!(
            resolver.fetch(Request::finalized_block_by_height(
                commitment,
                finalized_height
            )),
            Feedback::Ok
        );
        assert_eq!(
            resolver.fetch(Request::finalized_block_by_height(
                commitment,
                finalized_height
            )),
            Feedback::Ok
        );
        assert_eq!(
            resolver.fetch(Request::certified_block(commitment, certified_height)),
            Feedback::Ok
        );

        {
            let pending = resolver
                .pending
                .lock()
                .expect("marshal resolver pending lock");
            assert_eq!(pending.len(), 1);
            assert_eq!(
                pending.get(&key).expect("pending key"),
                &vec![finalized, certified]
            );
        }

        assert_eq!(
            resolver
                .retain(move |request, subscriber| { *request == key && *subscriber == certified }),
            Feedback::Ok
        );
        {
            let pending = resolver
                .pending
                .lock()
                .expect("marshal resolver pending lock");
            assert_eq!(pending.len(), 1);
            assert_eq!(pending.get(&key).expect("pending key"), &vec![certified]);
        }

        assert_eq!(resolver.retain(|_, _| false), Feedback::Ok);
        assert!(resolver
            .pending
            .lock()
            .expect("marshal resolver pending lock")
            .is_empty());
    }
}
