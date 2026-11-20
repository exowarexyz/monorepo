//! The store handle, its limits, and how a database is opened.

use crate::{
    idb::{self, Read, KV, LOG, META, SEQUENCE},
    ingest,
};
use bytes::Bytes;
use exoware_sdk::limits::{
    put_entry_encoded_len, PutTooLarge, MAX_KEY_LEN, MAX_PUT_ENTRIES, MAX_REQUEST_MESSAGE_BYTES,
    MAX_VALUE_LEN,
};
use exoware_server::{IngestError, Sequence, StreamNotifier};
use futures::channel::oneshot;
use js_sys::Reflect;
use std::{
    cell::Cell,
    future::Future,
    rc::Rc,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, PoisonError, Weak,
    },
};
use wasm_bindgen::{closure::Closure, JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use web_sys::{
    BroadcastChannel, Event, IdbDatabase, IdbFactory, IdbRequest, IdbVersionChangeEvent,
    MessageEvent,
};

/// Version of the database layout this crate reads and writes.
const LAYOUT_VERSION: u32 = 1;

/// Limits of one store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Largest batch one Put may carry, counted as its encoded entries.
    ///
    /// The limit is at most 256 MiB ([`MAX_REQUEST_MESSAGE_BYTES`]), the largest batch of the
    /// Store API. The layout lets no writer store a larger log batch, so
    /// [`IndexedDbStore::open`] refuses a higher limit.
    ///
    /// A Put writes its payload twice in one transaction, as rows and as the log batch, and
    /// Chrome fails a transaction that carries several hundred MiB of values. The page also
    /// holds the request, the rows and the encoded batch at the same time.
    pub max_batch_bytes: usize,
    /// Most bytes of rows one query may hold in memory. A row counts its key, its value and
    /// 64 bytes for the handles that carry them.
    ///
    /// A query reads its whole answer inside one transaction, because IndexedDB keeps a
    /// consistent view only while a transaction is live, and an answer that would hold more
    /// fails. The limit also bounds the rows a Reduce reads. A prune counts against it the
    /// keys it deletes and, while a policy selects, what that policy's selection holds.
    pub max_query_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_batch_bytes: 64 * 1024 * 1024,
            max_query_bytes: 64 * 1024 * 1024,
        }
    }
}

/// State shared by every clone of a store and by the tasks it starts.
pub(crate) struct Inner {
    /// The connection every operation runs its transaction on.
    pub(crate) db: IdbDatabase,
    /// The limits the store was opened with.
    pub(crate) config: Config,
    /// Whether opening this connection created the database.
    created: bool,
    /// Highest sequence number this connection read from or committed to the database.
    frontier: AtomicU64,
    /// The layout's notification channel of this database.
    channel: BroadcastChannel,
    /// The notifier registered through [`IndexedDbStore::watch`].
    watcher: Mutex<Option<Arc<dyn StreamNotifier>>>,
}

impl Inner {
    /// Raises the frontier to a sequence number read from or committed to the database.
    pub(crate) fn observe(&self, sequence: u64) {
        self.frontier.fetch_max(sequence, Ordering::AcqRel);
    }

    /// Tells other connections to the database that this one committed `sequence`.
    pub(crate) fn announce(&self, sequence: u64) {
        let _ = self
            .channel
            .post_message(&idb::value(&sequence.to_be_bytes()));
    }

    /// Returns the registered notifier, if any.
    pub(crate) fn watcher(&self) -> Option<Arc<dyn StreamNotifier>> {
        self.watcher
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Stops listening and closes the database to new transactions. The channel stays open,
    /// because a transaction that is still running announces its commit when it completes.
    fn close(&self) {
        self.channel.set_onmessage(None);
        self.db.close();
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.close();
        self.channel.close();
    }
}

/// Runs one operation to completion in a task of its own and hands its result to the caller.
///
/// The task owns the operation's transaction and callbacks. IndexedDB accepts a request into
/// a transaction only right after the transaction is created or while one of its request
/// events is delivered, so the next request cannot wait for the caller's executor, and a
/// caller that goes away must not cut the chain of requests short. The returned future only
/// waits for the result, so it is Send.
pub(crate) async fn run<T, F, Fut>(operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, String>> + 'static,
{
    let (sender, receiver) = oneshot::channel();
    spawn_local(async move {
        let _ = sender.send(operation().await);
    });
    receiver
        .await
        .unwrap_or_else(|_| Err("store task ended before it reported a result".to_string()))
}

/// The Exoware Store on one IndexedDB database.
///
/// Clones share one connection. The connection closes when the last clone and the last
/// running operation are gone, or when [`Self::close`] is called.
#[derive(Clone)]
pub struct IndexedDbStore {
    pub(crate) inner: Arc<Inner>,
}

impl IndexedDbStore {
    /// Opens the database `name` of the page's origin, creating it when it does not exist.
    ///
    /// Fails without changing anything when `config` sets a batch limit above the largest
    /// batch of the Store API, when the database has another layout version or other object
    /// stores, or when its sequence row is malformed.
    pub fn open(name: &str, config: Config) -> impl Future<Output = Result<Self, String>> + Send {
        let name = name.to_owned();
        run(move || open(name, config))
    }

    /// Whether this open created the database.
    ///
    /// A browser can replace a damaged database with an empty one without reporting an error,
    /// and sequence numbers then start again from zero. A caller that expected existing data
    /// learns of the loss here.
    pub fn created(&self) -> bool {
        self.inner.created
    }

    /// Tells `notifier` of new batches in the database.
    ///
    /// The notifier advances to each batch this store commits, through [`Self::put_batch`] or
    /// a request, and to the database's sequence number whenever another connection announces
    /// a commit on the layout's notification channel. Pass the stream hub of the server state
    /// so live subscribers wake for writes from this store and from other pages, workers or
    /// store implementations on the same database.
    pub fn watch(&self, notifier: Arc<dyn StreamNotifier>) {
        *self
            .inner
            .watcher
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(notifier);
    }

    /// Closes the connection. Running transactions finish, other connections still hear of
    /// their commits, and later operations fail.
    pub fn close(&self) {
        self.inner.close();
    }

    /// Commits one batch and returns its sequence number.
    ///
    /// A later entry for a key wins, and the log batch keeps every entry in order. A batch
    /// that a Put request could not carry is refused: an empty one, or one whose entry count,
    /// keys, values or size exceed the limits of the request path.
    pub fn put_batch(
        &self,
        rows: Vec<(Bytes, Bytes)>,
    ) -> impl Future<Output = Result<u64, IngestError>> + Send {
        let inner = self.inner.clone();
        async move {
            admit(&rows, inner.config.max_batch_bytes)?;
            run(move || async move { Ok(ingest::commit(inner, rows, None).await) })
                .await
                .map_err(|message| IngestError::Internal { message })?
        }
    }
}

/// Checks a batch that did not come through the request path against the limits of that path.
fn admit(rows: &[(Bytes, Bytes)], max_batch_bytes: usize) -> Result<(), IngestError> {
    let refused = |message: String| IngestError::Internal { message };
    if rows.is_empty() {
        return Err(refused("cannot ingest an empty batch".to_string()));
    }
    if rows.len() > MAX_PUT_ENTRIES {
        return Err(PutTooLarge {
            entries: rows.len(),
            max_entries: MAX_PUT_ENTRIES,
        }
        .into());
    }

    // Entries may share one buffer, so their encoded lengths can add up to more than `usize`
    // holds. Counting the room left down stops at the first entry that does not fit.
    let mut room = max_batch_bytes;
    for (key, value) in rows {
        if key.len() > MAX_KEY_LEN {
            return Err(refused(format!(
                "key of {} bytes exceeds the limit of {MAX_KEY_LEN}",
                key.len()
            )));
        }
        if value.len() > MAX_VALUE_LEN {
            return Err(refused(format!(
                "value of {} bytes exceeds the limit of {MAX_VALUE_LEN}",
                value.len()
            )));
        }
        room = room
            .checked_sub(put_entry_encoded_len(key, value))
            .ok_or_else(|| ingest::over_limit(max_batch_bytes))?;
    }
    Ok(())
}

impl Sequence for IndexedDbStore {
    /// Returns the highest sequence number this store committed or read, a lower bound of the
    /// database's sequence row. Another connection's commit raises it when its notification
    /// arrives or when this store next runs an operation other than a prune.
    fn current_sequence(&self) -> u64 {
        self.inner.frontier.load(Ordering::Acquire)
    }
}

async fn open(name: String, config: Config) -> Result<IndexedDbStore, String> {
    if config.max_batch_bytes > MAX_REQUEST_MESSAGE_BYTES {
        return Err(format!(
            "Config::max_batch_bytes is {} bytes, more than the {MAX_REQUEST_MESSAGE_BYTES} \
             bytes of the largest batch the Store API allows",
            config.max_batch_bytes
        ));
    }
    let factory: IdbFactory = Reflect::get(&js_sys::global(), &JsValue::from_str("indexedDB"))
        .map_err(idb::describe)?
        .dyn_into()
        .map_err(|_| "IndexedDB is not available in this context".to_string())?;
    let request = factory
        .open_with_u32(&name, LAYOUT_VERSION)
        .map_err(idb::describe)?;
    let created = Rc::new(Cell::new(false));
    let on_upgrade = {
        let (request, created) = (request.clone(), created.clone());
        Closure::<dyn FnMut(IdbVersionChangeEvent)>::new(move |event: IdbVersionChangeEvent| {
            // The layout defines one upgrade step, from a database that did not exist.
            if event.old_version() != 0.0 {
                return;
            }
            let Ok(db) = request.result() else {
                return;
            };
            let db: IdbDatabase = db.unchecked_into();
            for store in [KV, LOG, META] {
                if db.create_object_store(store).is_err() {
                    // Aborting the upgrade fails the open and leaves no partial layout.
                    if let Some(upgrade) = request.transaction() {
                        let _ = upgrade.abort();
                    }
                    return;
                }
            }
            created.set(true);
        })
    };
    request.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));
    let opened = idb::request(Ok(IdbRequest::from(request.clone()))).await;
    request.set_onupgradeneeded(None);
    drop(on_upgrade);
    let db: IdbDatabase = opened?.unchecked_into();

    // Another context that deletes or upgrades the database waits until this connection
    // closes, so the connection closes itself when asked. The callback finds the connection
    // through the event and holds nothing itself, so the connection and the callback it
    // holds are freed together.
    let on_version_change = Closure::<dyn FnMut(Event)>::new(|event: Event| {
        if let Some(db) = event.target() {
            db.unchecked_into::<IdbDatabase>().close();
        }
    })
    .into_js_value();
    db.set_onversionchange(Some(on_version_change.unchecked_ref()));

    match connect(&name, &db).await {
        Ok((frontier, channel)) => {
            let inner = Arc::new(Inner {
                db,
                config,
                created: created.get(),
                frontier: AtomicU64::new(frontier),
                channel,
                watcher: Mutex::new(None),
            });
            let on_message = hint_receiver(Arc::downgrade(&inner));
            inner
                .channel
                .set_onmessage(Some(on_message.unchecked_ref()));
            Ok(IndexedDbStore { inner })
        }
        Err(error) => {
            db.close();
            Err(error)
        }
    }
}

/// Checks the layout of an open database, reads its frontier, and joins its channel.
async fn connect(name: &str, db: &IdbDatabase) -> Result<(u64, BroadcastChannel), String> {
    let stores = db.object_store_names();
    if stores.length() != 3 || [KV, LOG, META].iter().any(|store| !stores.contains(store)) {
        return Err(format!(
            "database {name:?} does not have the object stores of the Store layout"
        ));
    }
    let frontier = read_frontier(db).await?;
    let channel = BroadcastChannel::new(&format!("exoware-store:{name}")).map_err(idb::describe)?;
    Ok((frontier, channel))
}

/// Reads the sequence row in a transaction of its own.
async fn read_frontier(db: &IdbDatabase) -> Result<u64, String> {
    let read = Read::begin(db, &[META])?;
    idb::frontier(&idb::request(read.store(META)?.get(&idb::key(SEQUENCE))).await?)
}

/// Builds the channel callback that reacts to another connection's commit.
///
/// A message is only a hint that the sequence row moved. The callback reads the row, raises
/// the frontier, and wakes the watcher. The value in the message is never used.
fn hint_receiver(inner: Weak<Inner>) -> JsValue {
    Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        if !is_hint(&event.data()) {
            return;
        }
        let Some(inner) = inner.upgrade() else {
            return;
        };
        spawn_local(async move {
            let Ok(sequence) = read_frontier(&inner.db).await else {
                return;
            };
            inner.observe(sequence);
            if let Some(watcher) = inner.watcher() {
                watcher.advance(sequence);
            }
        });
    })
    .into_js_value()
}

/// Whether a channel message has the shape of a commit notification, eight bytes.
fn is_hint(data: &JsValue) -> bool {
    idb::Stored::new(data).is_ok_and(|message| message.len() == 8)
}
