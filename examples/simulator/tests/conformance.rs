//! Runs the Store conformance suite against RocksStore.

use bytes::Bytes;
use exoware_conformance::Backend;
use exoware_server::IngestError;
use exoware_simulator::RocksStore;
use std::{
    future::{ready, Future},
    time::Duration,
};
use tempfile::TempDir;

/// RocksStore in a temporary directory that the location owns.
struct RocksBackend;

impl Backend for RocksBackend {
    type Store = RocksStore;
    type Location = TempDir;

    fn location(&self) -> TempDir {
        tempfile::tempdir().expect("a temporary directory must be created")
    }

    fn open(&self, location: &TempDir) -> impl Future<Output = RocksStore> {
        ready(RocksStore::open(location.path(), None).expect("the store must open"))
    }

    // The database closes when its last store handle and last cursor drop. The cases drop every
    // other handle and every cursor before they close a store.
    fn close(&self, store: RocksStore) -> impl Future<Output = ()> {
        drop(store);
        ready(())
    }

    fn put_batch(
        &self,
        store: &RocksStore,
        rows: Vec<(Bytes, Bytes)>,
    ) -> impl Future<Output = Result<u64, IngestError>> {
        store.put_batch(rows)
    }

    fn pause(&self) -> impl Future<Output = ()> {
        tokio::time::sleep(Duration::from_millis(5))
    }
}

exoware_conformance::tests!(#[tokio::test], RocksBackend);
