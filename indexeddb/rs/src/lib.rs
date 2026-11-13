//! Serve the Exoware Store from IndexedDB in a browser page.
//!
//! [`IndexedDbStore`] implements the backend traits of `exoware-server` on one IndexedDB
//! database, so the server's own request handling (validation, Put decoding, Reduce, stream
//! filtering) answers the complete Store API inside a page. The database follows the shared
//! layout document, `../README.md`, so every implementation of the store that follows it can
//! open the same database.
//!
//! # Use
//!
//! ```no_run
//! use exoware_indexeddb::{Config, IndexedDbStore};
//! use exoware_server::{connect_stack, AppState};
//! use std::sync::Arc;
//!
//! # async fn serve() -> Result<(), String> {
//! let store = IndexedDbStore::open("my-app", Config::default()).await?;
//! let state = AppState::new(Arc::new(store.clone()));
//! // Wake live subscribers for every batch committed to the database.
//! store.watch(state.stream.clone());
//! // A tower service. Call it with requests held in memory.
//! let api = connect_stack(state);
//! # drop(api);
//! # Ok(())
//! # }
//! ```
//!
//! The traits can also be called directly, and [`IndexedDbStore::put_batch`] commits rows
//! without a request. The notifier passed to [`IndexedDbStore::watch`] hears of those commits
//! too.
//!
//! # How it works
//!
//! - Every operation is one IndexedDB transaction with the scope and durability the layout
//!   document gives it. Writes ask for strict durability and report success only after the
//!   transaction completed. A write that reports a failure has written nothing. Until a write
//!   reports, its outcome is unknown, and if the page or the instance goes away first, the
//!   write was committed in full or not at all.
//! - Every transaction runs to completion in a task the store starts. The future a trait
//!   method returns waits for that task's result, so it is Send, and dropping it does not stop
//!   the transaction. A Put whose request was read in full and accepted commits and notifies
//!   subscribers even when its caller went away.
//! - IndexedDB commits the requests a transaction placed once none are pending. A write
//!   transaction therefore aborts unless its operation placed every request, and every read
//!   and check that can fail comes before the first write.
//! - A row read from the database is checked against the layout before it is used. A
//!   sequence row, a retention rule, a log batch or a key that breaks the layout fails the
//!   operation that reads it.
//! - A query reads its sequence number and all of its rows in one readonly transaction and
//!   serves them from memory, because a consistent view exists only inside a transaction.
//! - [`exoware_server::Sequence::current_sequence`] is kept in memory and never runs ahead of
//!   the database. It is the highest sequence number this store committed or read, and it
//!   reaches another connection's commit when the layout's notification arrives or when this
//!   store next runs an operation other than a prune.
//!
//! # Limits
//!
//! - A Put larger than [`Config::max_batch_bytes`] and a query that holds more than
//!   [`Config::max_query_bytes`] are rejected. Both default to 64 MiB. The query limit also
//!   bounds the rows a Reduce reads and what a prune holds for the keys it selects. The
//!   backend traits report these failures as text, so a query or prune over the limit
//!   reaches a client as an internal error.
//! - The store writes no row beyond the limits of the Store API, whatever the request stack
//!   in front of it allows. [`IndexedDbStore::open`] refuses a batch limit above 256 MiB,
//!   and a Put with more than 2,000,000 entries or with a value above 32 MiB is refused.
//! - If another page's notification is lost, for example because that page went away right
//!   after its commit, a query that asks for that sequence number is refused until this
//!   store hears of a later commit or runs an operation other than a prune.
//! - IndexedDB orders transactions whose scopes overlap. A long query or prune delays
//!   writers in every page that shares the database, and a writer delays readers.
//! - The store runs on the event loop of its page or worker. Decoding a large Put, placing
//!   its writes and running a Reduce do not yield.
//! - A panic ends the WebAssembly instance, even inside a Reduce kernel. A native server
//!   reports a Reduce kernel panic as an error. Committed data is not affected.
//! - The complete request stack with Reduce links DataFusion and is a large module. A page
//!   that calls the traits directly links only what it uses.
//! - The Rust `StoreClient` of `exoware-sdk` does not build for `wasm32` yet, so Rust code in
//!   a page reaches the store through the traits or the request stack.
//! - The store handle is Send and Sync only because JS values are Send and Sync on builds
//!   without the `atomics` target feature, so a build with that feature is refused.
//! - A browser can replace a damaged database with an empty one without an error. See
//!   [`IndexedDbStore::created`].

#[cfg(target_feature = "atomics")]
compile_error!("exoware-indexeddb requires a build without the atomics target feature");

mod idb;
mod ingest;
mod log;
mod prune;
mod query;
mod store;

pub use query::IndexedDbRangeScan;
pub use store::{Config, IndexedDbStore};
