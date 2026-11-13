//! IndexedDB plumbing shared by every operation.
//!
//! Everything here runs inside the task of one operation. The futures hold JS callbacks and are
//! not Send. [`crate::store::run`] hands their results to the store's callers.

use bytes::Bytes;
use exoware_sdk::limits::MAX_KEY_LEN;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use js_sys::{Array, ArrayBuffer, Object, Reflect, Uint8Array};
use std::{cell::RefCell, future::Future, pin::Pin, rc::Rc};
use wasm_bindgen::{closure::Closure, prelude::wasm_bindgen, JsCast, JsValue};
use web_sys::{
    DomException, IdbCursor, IdbDatabase, IdbKeyRange, IdbObjectStore, IdbRequest, IdbTransaction,
};

/// Object store of current rows, keyed by Store key.
pub(crate) const KV: &str = "kv";

/// Object store of retained batches, keyed by big endian sequence number.
pub(crate) const LOG: &str = "log";

/// Object store of the sequence and retention rows.
pub(crate) const META: &str = "meta";

/// Key of the row in `meta` that holds the last committed sequence number.
pub(crate) const SEQUENCE: &[u8] = b"sequence";

/// Key of the row in `meta` that holds the retention rule.
pub(crate) const RETENTION: &[u8] = b"retention";

/// Name of the error IndexedDB reports when a commit does not fit the origin's quota.
const QUOTA_EXCEEDED: &str = "QuotaExceededError";

/// Memory a row holds beyond its key and value bytes, for the handles and allocations that
/// carry them.
const ROW_OVERHEAD: usize = 64;

/// Why a transaction or one of its requests failed.
#[derive(Debug)]
pub(crate) struct Failure {
    /// The error text the caller receives.
    pub(crate) message: String,
    /// Whether IndexedDB reported that the origin's quota had no room for the write.
    pub(crate) out_of_space: bool,
}

impl Failure {
    fn exception(exception: &DomException) -> Self {
        Self {
            message: format!("{}: {}", exception.name(), exception.message()),
            out_of_space: exception.name() == QUOTA_EXCEEDED,
        }
    }

    fn js(error: JsValue) -> Self {
        match error.dyn_into::<DomException>() {
            Ok(exception) => Self::exception(&exception),
            Err(other) => format!("{other:?}").into(),
        }
    }
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            message,
            out_of_space: false,
        }
    }
}

impl From<Failure> for String {
    fn from(failure: Failure) -> Self {
        failure.message
    }
}

/// Renders a JS error value as text.
pub(crate) fn describe(error: JsValue) -> String {
    match error.dyn_into::<DomException>() {
        Ok(exception) => Failure::exception(&exception).message,
        Err(other) => format!("{other:?}"),
    }
}

/// Copies bytes into a JS array whose buffer holds exactly those bytes.
///
/// IndexedDB stores the whole buffer behind a view, so a view of WebAssembly memory must never
/// reach it.
pub(crate) fn value(bytes: &[u8]) -> Uint8Array {
    Uint8Array::from(bytes)
}

/// Copies key bytes into an `ArrayBuffer` of exactly that length, the key form of the layout.
pub(crate) fn key(bytes: &[u8]) -> JsValue {
    value(bytes).buffer().into()
}

/// The key of a sequence number in the log.
pub(crate) fn sequence_key(sequence: u64) -> JsValue {
    key(&sequence.to_be_bytes())
}

/// A stored byte string that is still in JS, so its length can be checked before it is copied.
pub(crate) struct Stored(Uint8Array);

impl Stored {
    /// Accepts both forms a writer of the layout may store, an `ArrayBuffer` and a
    /// `Uint8Array`.
    pub(crate) fn new(stored: &JsValue) -> Result<Self, String> {
        if let Some(buffer) = stored.dyn_ref::<ArrayBuffer>() {
            return Ok(Self(Uint8Array::new(buffer)));
        }
        if let Some(view) = stored.dyn_ref::<Uint8Array>() {
            return Ok(Self(view.clone()));
        }
        Err("stored row is not a byte string".to_string())
    }

    pub(crate) fn len(&self) -> usize {
        self.0.byte_length() as usize
    }

    pub(crate) fn copy(&self) -> Bytes {
        Bytes::from(self.0.to_vec())
    }
}

/// Takes a stored byte string that can be at most `limit` bytes long, and refuses a longer
/// one before it is copied out of JS.
pub(crate) fn bounded(stored: &JsValue, limit: usize, what: &str) -> Result<Stored, String> {
    let stored = Stored::new(stored)?;
    if stored.len() > limit {
        return Err(format!(
            "stored {what} is {} bytes long, more than the {limit} bytes it can be",
            stored.len()
        ));
    }
    Ok(stored)
}

/// The key a cursor is at, still in JS.
///
/// A Store key is at most [`MAX_KEY_LEN`] bytes long, so a longer stored key is corruption and
/// fails the read before it is copied.
pub(crate) fn stored_key(cursor: &IdbCursor) -> Result<Stored, String> {
    bounded(&cursor.key().map_err(describe)?, MAX_KEY_LEN, "key")
}

/// Decodes a big endian sequence number.
pub(crate) fn sequence(stored: &JsValue) -> Result<u64, String> {
    let stored = Stored::new(stored)?;
    let mut raw = [0u8; 8];
    if stored.len() != raw.len() {
        return Err("stored sequence number is not 8 bytes".to_string());
    }
    stored.0.copy_to(&mut raw);
    Ok(u64::from_be_bytes(raw))
}

/// Counts the bytes of rows one operation holds in memory against a limit.
pub(crate) struct Budget {
    limit: usize,
    held: usize,
}

impl Budget {
    pub(crate) const fn new(limit: usize) -> Self {
        Self { limit, held: 0 }
    }

    /// Counts `bytes` more, or fails when they do not fit. A caller counts what it is about to
    /// copy out of JS before it copies.
    pub(crate) fn admit(&mut self, bytes: usize) -> Result<(), String> {
        match self.held.checked_add(bytes) {
            Some(held) if held <= self.limit => {
                self.held = held;
                Ok(())
            }
            _ => Err(format!(
                "operation needs more than the store's limit of {} bytes of rows in memory",
                self.limit
            )),
        }
    }

    /// Counts one more row with `bytes` of key and value, and returns what it counted.
    pub(crate) fn row(&mut self, bytes: usize) -> Result<usize, String> {
        let counted = bytes.saturating_add(ROW_OVERHEAD);
        self.admit(counted).map(|()| counted)
    }

    /// Gives back bytes that are no longer held.
    pub(crate) const fn release(&mut self, bytes: usize) {
        self.held = self.held.saturating_sub(bytes);
    }
}

/// Decodes the sequence row of `meta`. An absent row means nothing was ever written.
pub(crate) fn frontier(stored: &JsValue) -> Result<u64, String> {
    if stored.is_undefined() {
        return Ok(0);
    }
    sequence(stored)
}

/// The inclusive key range `[start, end]`, unbounded above when `end` is empty.
///
/// Returns `None` for a range that holds no key. IndexedDB refuses to build such a range.
pub(crate) fn key_range(start: &[u8], end: &[u8]) -> Result<Option<IdbKeyRange>, String> {
    if end.is_empty() {
        return IdbKeyRange::lower_bound(&key(start))
            .map(Some)
            .map_err(describe);
    }
    if start > end {
        return Ok(None);
    }
    IdbKeyRange::bound(&key(start), &key(end))
        .map(Some)
        .map_err(describe)
}

type Handler = Closure<dyn FnMut()>;

/// Two callbacks installed on a request or a transaction.
///
/// The target calls its callbacks for as long as they are installed, and a call to one that
/// was freed raises an error in the page. Dropping this detaches the callbacks before it frees
/// them, so an event that fires later finds no callback.
struct Listeners<T> {
    target: T,
    detach: fn(&T),
    _callbacks: [Handler; 2],
}

impl<T> Drop for Listeners<T> {
    fn drop(&mut self) {
        (self.detach)(&self.target);
    }
}

impl Listeners<IdbRequest> {
    fn on_request(request: &IdbRequest, success: Handler, error: Handler) -> Self {
        request.set_onsuccess(Some(success.as_ref().unchecked_ref()));
        request.set_onerror(Some(error.as_ref().unchecked_ref()));
        Self {
            target: request.clone(),
            detach: |request| {
                request.set_onsuccess(None);
                request.set_onerror(None);
            },
            _callbacks: [success, error],
        }
    }
}

impl Listeners<IdbTransaction> {
    fn on_transaction(transaction: &IdbTransaction, complete: Handler, abort: Handler) -> Self {
        transaction.set_oncomplete(Some(complete.as_ref().unchecked_ref()));
        transaction.set_onabort(Some(abort.as_ref().unchecked_ref()));
        Self {
            target: transaction.clone(),
            detach: |transaction| {
                transaction.set_oncomplete(None);
                transaction.set_onabort(None);
            },
            _callbacks: [complete, abort],
        }
    }
}

/// Resolves with the request's result when its success or error event fires.
///
/// The callbacks are installed before this returns, so the request may complete before the
/// future is first polled. The error event keeps its default action, so a failed request
/// aborts its transaction.
pub(crate) fn request(
    request: Result<IdbRequest, JsValue>,
) -> impl Future<Output = Result<JsValue, String>> {
    let armed = request.map_err(describe).map(|request| {
        let (sender, receiver) = oneshot::channel();
        let sender = Rc::new(RefCell::new(Some(sender)));
        let on_success = {
            let (request, sender) = (request.clone(), sender.clone());
            Handler::new(move || {
                if let Some(sender) = sender.borrow_mut().take() {
                    let _ = sender.send(request.result().map_err(describe));
                }
            })
        };
        let on_error = {
            let request = request.clone();
            Handler::new(move || {
                if let Some(sender) = sender.borrow_mut().take() {
                    let _ = sender.send(Err(request_error(&request)));
                }
            })
        };
        (
            receiver,
            Listeners::on_request(&request, on_success, on_error),
        )
    });
    async move {
        let (receiver, _listeners) = armed?;
        receiver
            .await
            .unwrap_or_else(|_| Err("request ended without an event".to_string()))
    }
}

fn request_error(request: &IdbRequest) -> String {
    match request.error() {
        Ok(Some(exception)) => Failure::exception(&exception).message,
        Ok(None) => "request failed".to_string(),
        Err(error) => describe(error),
    }
}

#[wasm_bindgen]
extern "C" {
    /// `IDBDatabase`, declared here for the one method below.
    #[wasm_bindgen(js_name = IDBDatabase)]
    type Database;

    /// `IDBDatabase.transaction(names, mode, options)`. The options carry the durability
    /// hint, and web-sys exposes that argument only to builds that enable its unstable APIs.
    #[wasm_bindgen(method, catch, js_name = transaction)]
    fn transaction_with_options(
        this: &Database,
        stores: &Array,
        mode: &str,
        options: &Object,
    ) -> Result<IdbTransaction, JsValue>;
}

/// Starts a transaction on `stores`, readwrite with strict durability when `write` is set
/// and readonly otherwise.
fn begin(db: &IdbDatabase, stores: &[&str], write: bool) -> Result<IdbTransaction, String> {
    let names = Array::new();
    for store in stores {
        names.push(&JsValue::from_str(store));
    }
    let options = Object::new();
    let mode = if write {
        Reflect::set(&options, &"durability".into(), &"strict".into()).map_err(describe)?;
        "readwrite"
    } else {
        "readonly"
    };
    db.unchecked_ref::<Database>()
        .transaction_with_options(&names, mode, &options)
        .map_err(describe)
}

fn object_store(transaction: &IdbTransaction, name: &str) -> Result<IdbObjectStore, String> {
    transaction.object_store(name).map_err(describe)
}

/// A readonly transaction. Its reads see one state of the database.
pub(crate) struct Read(IdbTransaction);

impl Read {
    pub(crate) fn begin(db: &IdbDatabase, stores: &[&str]) -> Result<Self, String> {
        begin(db, stores, false).map(Self)
    }

    pub(crate) fn store(&self, name: &str) -> Result<IdbObjectStore, String> {
        object_store(&self.0, name)
    }
}

/// Resolves when a transaction has committed or aborted.
type Outcome = Pin<Box<dyn Future<Output = Result<(), Failure>>>>;

/// A readwrite transaction with strict durability that aborts unless it is finished.
///
/// IndexedDB commits the requests a transaction placed once none are pending, so an operation
/// that stops between its first and last write would commit part of itself. Dropping this
/// guard before [`Self::finish`] aborts the transaction.
pub(crate) struct Write {
    transaction: IdbTransaction,
    outcome: Option<Outcome>,
}

impl Write {
    pub(crate) fn begin(db: &IdbDatabase, stores: &[&str]) -> Result<Self, String> {
        let transaction = begin(db, stores, true)?;
        let outcome = Box::pin(outcome(&transaction));
        Ok(Self {
            transaction,
            outcome: Some(outcome),
        })
    }

    pub(crate) fn store(&self, name: &str) -> Result<IdbObjectStore, String> {
        object_store(&self.transaction, name)
    }

    /// Declares that every request of the operation was placed and waits for the commit.
    pub(crate) async fn finish(mut self) -> Result<(), Failure> {
        match self.outcome.take() {
            Some(outcome) => outcome.await,
            None => Err("transaction already finished".to_string().into()),
        }
    }
}

impl Drop for Write {
    fn drop(&mut self) {
        if self.outcome.is_some() {
            // A transaction that already committed or aborted has nothing to undo, and its
            // abort fails harmlessly.
            let _ = self.transaction.abort();
        }
    }
}

/// Resolves when the transaction completes or aborts.
fn outcome(transaction: &IdbTransaction) -> impl Future<Output = Result<(), Failure>> {
    let (sender, receiver) = oneshot::channel();
    let sender = Rc::new(RefCell::new(Some(sender)));
    let on_complete = {
        let sender = sender.clone();
        Handler::new(move || {
            if let Some(sender) = sender.borrow_mut().take() {
                let _ = sender.send(Ok(()));
            }
        })
    };
    let on_abort = {
        let transaction = transaction.clone();
        Handler::new(move || {
            if let Some(sender) = sender.borrow_mut().take() {
                let failure = match transaction.error() {
                    Some(exception) => Failure::exception(&exception),
                    None => "transaction aborted".to_string().into(),
                };
                let _ = sender.send(Err(failure));
            }
        })
    };
    let listeners = Listeners::on_transaction(transaction, on_complete, on_abort);
    async move {
        let _listeners = listeners;
        receiver
            .await
            .unwrap_or_else(|_| Err("transaction ended without an event".to_string().into()))
    }
}

/// Converts a failed call that places a request.
pub(crate) fn placed<T>(result: Result<T, JsValue>) -> Result<T, Failure> {
    result.map_err(Failure::js)
}

/// Walks a cursor request inside its transaction.
///
/// `visit` sees every position in turn and says whether the walk goes on to the next one.
pub(crate) async fn walk(
    request: Result<IdbRequest, JsValue>,
    mut visit: impl FnMut(&IdbCursor) -> Result<bool, String>,
) -> Result<(), String> {
    let request = request.map_err(describe)?;
    let (sender, mut events) = mpsc::unbounded::<Result<JsValue, String>>();
    let on_success = {
        let (request, sender) = (request.clone(), sender.clone());
        Handler::new(move || {
            let _ = sender.unbounded_send(request.result().map_err(describe));
        })
    };
    let on_error = {
        let request = request.clone();
        Handler::new(move || {
            let _ = sender.unbounded_send(Err(request_error(&request)));
        })
    };
    let _listeners = Listeners::on_request(&request, on_success, on_error);

    loop {
        let event = events
            .next()
            .await
            .ok_or_else(|| "cursor ended without an event".to_string())??;
        if event.is_null() {
            return Ok(());
        }
        let cursor: IdbCursor = event.unchecked_into();
        if !visit(&cursor)? {
            return Ok(());
        }
        cursor.continue_().map_err(describe)?;
    }
}
