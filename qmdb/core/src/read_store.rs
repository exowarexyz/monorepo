use async_trait::async_trait;
use bytes::Bytes;
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::stream_filter::StreamFilter;
use exoware_sdk_rs::{ClientError, RangeMode};

#[derive(Clone, Debug)]
pub struct SubscriptionEntry {
    pub key: Key,
    pub value: Bytes,
}

#[derive(Clone, Debug)]
pub struct SubscriptionFrame {
    pub sequence_number: u64,
    pub entries: Vec<SubscriptionEntry>,
}

#[async_trait]
pub trait ReadSession: Send + Sync {
    async fn get(&self, key: &Key) -> Result<Option<Bytes>, ClientError>;

    async fn get_many(
        &self,
        keys: &[&Key],
        batch_size: u32,
    ) -> Result<std::collections::HashMap<Key, Bytes>, ClientError>;

    async fn range(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
    ) -> Result<Vec<(Key, Bytes)>, ClientError>;

    async fn range_with_mode(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
    ) -> Result<Vec<(Key, Bytes)>, ClientError>;
}

#[async_trait]
pub trait ReadSubscription: Send {
    async fn next(&mut self) -> Result<Option<SubscriptionFrame>, ClientError>;
}

#[async_trait]
pub trait ReadStore: Send + Sync {
    fn create_session(&self) -> Box<dyn ReadSession>;

    fn create_session_with_sequence(&self, sequence: u64) -> Box<dyn ReadSession>;

    async fn subscribe(
        &self,
        filter: StreamFilter,
        since: Option<u64>,
    ) -> Result<Box<dyn ReadSubscription>, ClientError>;
}
