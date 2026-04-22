use async_trait::async_trait;
use bytes::Bytes;
use exoware_qmdb_core::read_store::{
    ReadSession, ReadStore, ReadSubscription, SubscriptionEntry, SubscriptionFrame,
};
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::stream_filter::StreamFilter;
use exoware_sdk_rs::{
    ClientError, RangeMode, SerializableReadSession, StoreClient, StreamSubscription,
};

#[derive(Clone, Debug)]
pub struct SdkReadStore {
    client: StoreClient,
}

impl SdkReadStore {
    pub fn new(client: StoreClient) -> Self {
        Self { client }
    }
}

struct SdkReadSession {
    session: SerializableReadSession,
}

#[async_trait]
impl ReadSession for SdkReadSession {
    async fn get(&self, key: &Key) -> Result<Option<Bytes>, ClientError> {
        self.session.get(key).await
    }

    async fn get_many(
        &self,
        keys: &[&Key],
        batch_size: u32,
    ) -> Result<std::collections::HashMap<Key, Bytes>, ClientError> {
        self.session
            .get_many(keys, batch_size)
            .await?
            .collect()
            .await
    }

    async fn range(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.session.range(start, end, limit).await
    }

    async fn range_with_mode(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.session.range_with_mode(start, end, limit, mode).await
    }
}

struct SdkReadSubscription {
    subscription: StreamSubscription,
}

#[async_trait]
impl ReadSubscription for SdkReadSubscription {
    async fn next(&mut self) -> Result<Option<SubscriptionFrame>, ClientError> {
        self.subscription.next().await.map(|frame| {
            frame.map(|frame| SubscriptionFrame {
                sequence_number: frame.sequence_number,
                entries: frame
                    .entries
                    .into_iter()
                    .map(|entry| SubscriptionEntry {
                        key: entry.key,
                        value: entry.value,
                    })
                    .collect(),
            })
        })
    }
}

#[async_trait]
impl ReadStore for SdkReadStore {
    fn create_session(&self) -> Box<dyn ReadSession> {
        Box::new(SdkReadSession {
            session: self.client.create_session(),
        })
    }

    fn create_session_with_sequence(&self, sequence: u64) -> Box<dyn ReadSession> {
        Box::new(SdkReadSession {
            session: self.client.create_session_with_sequence(sequence),
        })
    }

    async fn subscribe(
        &self,
        filter: StreamFilter,
        since: Option<u64>,
    ) -> Result<Box<dyn ReadSubscription>, ClientError> {
        Ok(Box::new(SdkReadSubscription {
            subscription: self.client.stream().subscribe(filter, since).await?,
        }))
    }
}
