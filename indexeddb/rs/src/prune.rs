//! Prune policies applied to the current rows.

use crate::{
    idb::{self, Budget, Write, KV},
    store::{run, IndexedDbStore},
};
use bytes::Bytes;
use exoware_sdk::prune_policy::PrunePolicyDocument;
use exoware_server::{Prune, PruneSelection};
use std::{collections::BTreeSet, future::Future};

impl Prune for IndexedDbStore {
    /// Applies the document in one transaction. Policies run in order and each one sees the
    /// deletions of the ones before it. A document that reports a failure has deleted nothing.
    ///
    /// The memory the document holds for the keys it selects counts against
    /// [`crate::Config::max_query_bytes`], and a document that needs more fails.
    fn apply_prune_policies(
        &self,
        document: PrunePolicyDocument,
    ) -> impl Future<Output = Result<(), String>> + Send {
        let inner = self.inner.clone();
        run(move || async move {
            let write = Write::begin(&inner.db, &[KV])?;
            let kv = write.store(KV)?;

            // Every policy selects before the first delete is placed, so a document that
            // fails at any policy has placed nothing. A policy skips the keys that earlier
            // policies delete, so it sees the rows as they will be after those policies.
            let mut deleted = BTreeSet::<Bytes>::new();
            let mut budget = Budget::new(inner.config.max_query_bytes);
            for policy in &document.policies {
                let mut selection = PruneSelection::new(policy)?;
                let (start, end) = selection.bounds();
                if let Some(range) = idb::key_range(&start, &end)? {
                    idb::walk(kv.open_key_cursor_with_range(&range), |cursor| {
                        // The copy of a key is counted before it is made. Once the key is
                        // offered, the count follows what the selection reports it holds,
                        // and for a policy that groups by many captures that is far more
                        // than the key. The selection allocates for a key before that count
                        // is checked, and the length limit on a stored key bounds what one
                        // key can make it allocate.
                        let key = idb::stored_key(cursor)?;
                        let copy = key.len();
                        budget.admit(copy)?;
                        let key = key.copy();
                        let held = selection.retained_bytes();
                        if !deleted.contains(&key) {
                            selection.push(key);
                        }
                        budget.release(copy);
                        budget.admit(selection.retained_bytes() - held)?;
                        Ok(true)
                    })
                    .await?;
                }

                // Once the selection finishes, only the keys it deletes stay counted.
                budget.release(selection.retained_bytes());
                for key in selection.finish()? {
                    budget.row(key.len())?;
                    deleted.insert(key);
                }
            }

            // Every key is converted before the first delete, so from the first delete to the
            // last only calls that place a request remain.
            let deleted: Vec<_> = deleted.iter().map(|key| idb::key(key)).collect();
            for key in &deleted {
                idb::placed(kv.delete(key))?;
            }
            write.finish().await?;
            Ok(())
        })
    }
}
