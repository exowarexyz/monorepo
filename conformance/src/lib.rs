//! Conformance cases for Store backends.
//!
//! Every backend that serves the Store API through [`exoware_server::StoreEngine`] must pass the
//! same cases. A harness implements [`Backend`] for its store and expands [`tests!`] with the
//! test attribute of its runner. That yields one test function per case, so every runner reports
//! a failure under the name of its case.
//!
//! The cases assert what the backend traits and the Store API promise, and they accept what the
//! contract leaves to each backend. Concurrent writes may share one sequence number, a prune
//! document may apply atomically or policy by policy, and a cursor may fill each pull with
//! anything from one row to the number asked for. An installed retention rule must take effect
//! before the write that triggers it returns, on every write path. Every batch and scan in the
//! cases stays far below one MiB, so a backend may run them with size limits that low.
//!
//! The library starts no runtime, thread or timer and touches no file system. It waits only
//! through [`Backend::pause`], so it builds for `wasm32-unknown-unknown` and runs on any
//! executor. The [`harness`] module exposes the helpers the cases use, for backend tests of
//! their own.

use bytes::Bytes;
use std::future::Future;

pub mod cases;
pub mod harness;
mod rpc;
mod support;

/// A store implementation under test, with the operations the cases need beyond the backend
/// traits.
pub trait Backend {
    /// The backend under test.
    type Store: exoware_server::StoreEngine + Clone;

    /// Where one store's data lives.
    type Location;

    /// A location that holds no data yet.
    fn location(&self) -> Self::Location;

    /// Opens the store at a location, creating it when it holds no data.
    fn open(&self, location: &Self::Location) -> impl Future<Output = Self::Store>;

    /// Releases everything the handle holds, so the location can be opened again.
    fn close(&self, store: Self::Store) -> impl Future<Output = ()>;

    /// Commits one batch the way [`exoware_server::Ingest::put`] does and returns its sequence
    /// number. It rejects an empty batch without consuming a sequence number, and it applies the
    /// installed retention rule before it returns.
    fn put_batch(
        &self,
        store: &Self::Store,
        rows: Vec<(Bytes, Bytes)>,
    ) -> impl Future<Output = Result<u64, exoware_server::IngestError>>;

    /// Lets background work of the backend make progress before the caller looks again.
    fn pause(&self) -> impl Future<Output = ()>;
}

/// Expands to one test function per case in [`cases`].
///
/// The first argument is the test attribute of the runner and the second an expression that
/// builds the [`Backend`]. Each generated function is named after its case and awaits
/// `cases::<case>(&backend)`.
///
/// # Examples
///
/// ```ignore
/// exoware_conformance::tests!(#[tokio::test], RocksBackend);
/// ```
#[macro_export]
macro_rules! tests {
    (#[$attribute:meta], $backend:expr) => {
        $crate::tests!(
            @cases #[$attribute], $backend,
            // Point reads and range cursors.
            get_returns_none_for_missing_key
            get_returns_value_after_put
            get_many_returns_found_and_missing
            get_many_preserves_input_order_and_duplicates
            empty_key_and_empty_value_are_stored
            empty_queries_report_snapshot_sequence
            range_scan_inclusive_end_includes_end_key
            range_scan_empty_end_is_unbounded_above
            range_scan_forward_respects_limit
            range_scan_returns_empty_when_no_keys_match
            range_scan_limit_zero_returns_empty
            range_scan_reverse_returns_descending_order
            range_scan_reverse_respects_limit
            range_scan_reverse_unbounded_end
            range_scan_single_key
            range_scan_start_above_end_is_empty
            range_scan_limits_around_the_row_count
            range_scan_covers_a_key_and_its_extensions
            range_scan_pulls_page_through_the_range
            snapshot_sequence_and_rows_survive_writes_between_pages
            snapshot_rows_survive_a_prune_between_pulls
            queries_match_their_batch_sequence_during_commits
            rpc_range_frames_share_one_sequence

            // Writes.
            put_batch_returns_monotonic_sequence_numbers
            sequence_persists_across_reopen
            put_batch_duplicates_last_wins_and_log_keeps_all
            put_batch_rejects_an_empty_batch
            concurrent_put_batches_log_every_entry_once
            ingest_put_commits_and_notifies
            ingest_put_survives_cancellation_after_acceptance
            rpc_put_identity_body
            rpc_put_body_in_many_frames
            rpc_put_rejections_come_from_the_server

            // Sequence log, retention and reopen.
            log_get_batch_returns_entries_in_order
            log_batch_above_the_frontier_is_not_found
            log_evicted_batch_reports_the_oldest_retained
            rpc_subscribe_replays_matching_entries
            retention_keep_latest_tracks_frontier_continuously
            retention_greater_than_and_greater_than_or_equal_thresholds
            retention_drop_all_keeps_log_empty_as_batches_arrive
            retention_clear_stops_enforcement
            retention_drop_all_survives_reopen
            retention_rule_survives_reopen
            reopen_preserves_frontier_rows_log_and_oldest_retained

            // Key pruning.
            keys_drop_all_deletes_matching_family_keys
            keys_keep_latest_deletes_old_versions_without_advancing_sequence
            key_prune_is_idempotent_when_reapplied
            keys_threshold_retains_greater_than_or_equal_versions
            keys_threshold_greater_than_is_strict
            keys_prune_retains_per_group
            keys_prune_applies_every_policy_of_a_document
            keys_prune_orders_versions_by_each_encoding
            keys_prune_and_retention_compose
            key_pruned_state_survives_reopen_when_versions_share_a_batch

            // Reductions.
            rpc_reduce_counts_sums_and_groups
        );
    };
    (@cases #[$attribute:meta], $backend:expr, $($case:ident)*) => {
        $(
            #[$attribute]
            async fn $case() {
                $crate::cases::$case(&$backend).await
            }
        )*
    };
}
