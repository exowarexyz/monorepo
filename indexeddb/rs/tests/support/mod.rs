//! Helpers shared by the browser tests. They give raw IndexedDB access, call recording,
//! failure injection, and the conformance backend of the IndexedDB store.
#![allow(dead_code)]

use bytes::Bytes;
use exoware_conformance::{harness::row, Backend};
use exoware_indexeddb::{Config, IndexedDbStore};
use exoware_server::{IngestError, LogBatch};
use futures::future::{select, Either};
use std::{future::Future, pin::pin};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(inline_js = r#"
const transaction = IDBDatabase.prototype.transaction;
const methods = {
    get: IDBObjectStore.prototype.get,
    put: IDBObjectStore.prototype.put,
    delete: IDBObjectStore.prototype.delete,
    getAllKeys: IDBObjectStore.prototype.getAllKeys,
};
let recorded = [];
const set = Uint8Array.prototype.set;
let copies = [];

// Errors the page reports because nothing caught them.
const unhandled = [];
self.addEventListener("error", (event) => unhandled.push("error: " + event.message));
self.addEventListener("unhandledrejection", (event) =>
    unhandled.push("unhandled rejection: " + event.reason)
);

function kind(value) {
    return Object.prototype.toString.call(value).slice(8, -1);
}

function settled(request) {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

function committed(tx) {
    return new Promise((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onabort = () => reject(tx.error);
    });
}

async function connect(name) {
    return settled(indexedDB.open(name));
}

// Records every transaction and every get, put, delete and getAllKeys until restore() is
// called.
export function record() {
    recorded = [];
    IDBDatabase.prototype.transaction = function (stores, mode, options) {
        const durability = options ? options.durability : undefined;
        recorded.push("transaction " + [].concat(stores).join(",") + " " + mode + " " + durability);
        return transaction.call(this, stores, mode, options);
    };
    for (const name of Object.keys(methods)) {
        IDBObjectStore.prototype[name] = function (...args) {
            const key = name === "put" ? args[1] : args[0];
            recorded.push(name + " " + this.name + " " + kind(key));
            return methods[name].apply(this, args);
        };
    }
}

// Makes the nth call of an object store method, counted from this call, throw.
export function fail(method, nth) {
    let calls = 0;
    IDBObjectStore.prototype[method] = function (...args) {
        calls += 1;
        if (calls === nth) {
            throw new DOMException("injected failure", "DataError");
        }
        return methods[method].apply(this, args);
    };
}

// Calls hook with the transaction of the nth put, counted from this call, right after that
// put is placed.
function after_put(nth, hook) {
    let calls = 0;
    IDBObjectStore.prototype.put = function (...args) {
        const request = methods.put.apply(this, args);
        calls += 1;
        if (calls === nth) {
            hook(this.transaction);
        }
        return request;
    };
}

// Aborts the transaction of the nth put, counted from this call, right after that put is
// placed.
export function abort_after_put(nth) {
    after_put(nth, (tx) => tx.abort());
}

// Aborts the transaction of the nth put, counted from this call, right after that put is
// placed, and makes it report the error a browser gives a transaction that does not fit the
// origin's quota. Where the browser defines a QuotaExceededError class, as Chrome does, the
// error is an instance of that DOMException subclass.
export function abort_over_quota_after_put(nth) {
    after_put(nth, (tx) => {
        tx.abort();
        const error =
            typeof QuotaExceededError === "function"
                ? new QuotaExceededError("injected quota failure")
                : new DOMException("injected quota failure", "QuotaExceededError");
        Object.defineProperty(tx, "error", { value: error });
    });
}

// Calls hook right after the nth put, counted from this call, is placed.
export function call_after_put(nth, hook) {
    after_put(nth, () => hook());
}

// Makes the next get of an object store answer with a given value in place of the stored one.
export function answer_next_get(store, value) {
    const get = IDBObjectStore.prototype.get;
    IDBObjectStore.prototype.get = function (...args) {
        const request = get.apply(this, args);
        if (this.name === store) {
            IDBObjectStore.prototype.get = get;
            Object.defineProperty(request, "result", { value });
        }
        return request;
    };
}

// Records the length of every byte string that is copied into the memory of the WebAssembly
// instance until copied() is called.
export function record_copies_into(memory) {
    copies = [];
    Uint8Array.prototype.set = function (source, ...rest) {
        if (this.buffer === memory.buffer) {
            copies.push(source.length);
        }
        return set.call(this, source, ...rest);
    };
}

// Stops recording copies and returns the lengths that were recorded.
export function copied() {
    delete Uint8Array.prototype.set;
    return Uint32Array.from(copies.splice(0));
}

// Removes every hook and returns what record() collected.
export function restore() {
    IDBDatabase.prototype.transaction = transaction;
    for (const name of Object.keys(methods)) {
        IDBObjectStore.prototype[name] = methods[name];
    }
    const lines = recorded;
    recorded = [];
    return lines;
}

// Returns the errors nothing caught since the last call.
export function uncaught() {
    return unhandled.splice(0);
}

export async function raw_create(name, version, stores) {
    const request = indexedDB.open(name, version);
    request.onupgradeneeded = () => {
        for (const store of stores) {
            request.result.createObjectStore(store);
        }
    };
    (await settled(request)).close();
}

export async function raw_put(name, store, key, value) {
    const db = await connect(name);
    const tx = db.transaction([store], "readwrite");
    tx.objectStore(store).put(value, key);
    await committed(tx);
    db.close();
}

// Commits one row as a batch the way a writer does, in one transaction, and posts no
// notification. With evict_below the transaction also removes the older log batches.
export async function raw_commit(name, sequence, key, value, batch, evict_below) {
    const db = await connect(name);
    const tx = db.transaction(["kv", "log", "meta"], "readwrite");
    tx.objectStore("kv").put(value, key);
    tx.objectStore("log").put(batch, sequence);
    tx.objectStore("meta").put(new Uint8Array(sequence), new TextEncoder().encode("sequence").buffer);
    if (evict_below !== undefined) {
        tx.objectStore("log").delete(IDBKeyRange.upperBound(evict_below, true));
    }
    await committed(tx);
    db.close();
}

export async function raw_get(name, store, key) {
    const db = await connect(name);
    const value = await settled(db.transaction([store]).objectStore(store).get(key));
    db.close();
    return value;
}

export async function raw_keys(name, store) {
    const db = await connect(name);
    const keys = await settled(db.transaction([store]).objectStore(store).getAllKeys());
    db.close();
    return keys;
}

export async function raw_describe(name) {
    const db = await connect(name);
    const described = db.version + " " + Array.from(db.objectStoreNames).join(",");
    db.close();
    return described;
}

export async function raw_delete(name) {
    await settled(indexedDB.deleteDatabase(name));
}

// A byte string that holds a prefix followed by a number of copies of a unit.
export function repeated(prefix, unit, count) {
    const row = new Uint8Array(prefix.length + unit.length * count);
    row.set(prefix);
    const total = unit.length * count;
    for (let filled = 0; filled < total; ) {
        if (filled === 0) {
            row.set(unit, prefix.length);
            filled = unit.length;
        } else {
            const step = Math.min(filled, total - filled);
            row.copyWithin(prefix.length + filled, prefix.length, prefix.length + step);
            filled += step;
        }
    }
    return row;
}

// A view of the bytes at offset two of a larger buffer.
export function offset_view(bytes) {
    const buffer = new Uint8Array(bytes.length + 5);
    buffer.set(bytes, 2);
    return new Uint8Array(buffer.buffer, 2, bytes.length);
}

export function post_hint(name, message) {
    const channel = new BroadcastChannel("exoware-store:" + name);
    channel.postMessage(message);
    channel.close();
}

export function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
"#)]
extern "C" {
    pub fn record();
    pub fn fail(method: &str, nth: u32);
    pub fn abort_after_put(nth: u32);
    pub fn abort_over_quota_after_put(nth: u32);
    pub fn call_after_put(nth: u32, hook: &js_sys::Function);
    pub fn answer_next_get(store: &str, value: JsValue);
    fn record_copies_into(memory: JsValue);
    pub fn copied() -> Vec<u32>;
    pub fn restore() -> Vec<String>;
    pub fn uncaught() -> Vec<String>;
    #[wasm_bindgen(catch)]
    pub async fn raw_create(name: &str, version: u32, stores: Vec<String>) -> Result<(), JsValue>;
    #[wasm_bindgen(catch)]
    pub async fn raw_put(
        name: &str,
        store: &str,
        key: JsValue,
        value: JsValue,
    ) -> Result<(), JsValue>;
    #[wasm_bindgen(catch)]
    async fn raw_commit(
        name: &str,
        sequence: JsValue,
        key: JsValue,
        value: JsValue,
        batch: JsValue,
        evict_below: JsValue,
    ) -> Result<(), JsValue>;
    #[wasm_bindgen(catch)]
    pub async fn raw_get(name: &str, store: &str, key: JsValue) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(catch)]
    pub async fn raw_keys(name: &str, store: &str) -> Result<js_sys::Array, JsValue>;
    #[wasm_bindgen(catch)]
    pub async fn raw_describe(name: &str) -> Result<String, JsValue>;
    #[wasm_bindgen(catch)]
    pub async fn raw_delete(name: &str) -> Result<(), JsValue>;
    pub fn repeated(prefix: &[u8], unit: &[u8], count: u32) -> js_sys::Uint8Array;
    pub fn offset_view(bytes: &[u8]) -> js_sys::Uint8Array;
    pub fn post_hint(name: &str, message: JsValue);
    pub async fn sleep(ms: u32);
}

/// A database name no other test uses.
pub fn database(tag: &str) -> String {
    format!(
        "exoware-{tag}-{}-{}",
        js_sys::Date::now(),
        js_sys::Math::random()
    )
}

/// Opens a store with the default limits.
pub async fn open(name: &str) -> IndexedDbStore {
    IndexedDbStore::open(name, Config::default()).await.unwrap()
}

/// An exact-length binary key, the form the layout uses.
pub fn js_key(bytes: &[u8]) -> JsValue {
    js_sys::Uint8Array::from(bytes).buffer().into()
}

/// A byte string as a `Uint8Array`, the form the engine writes values in.
pub fn js_value(bytes: &[u8]) -> JsValue {
    js_sys::Uint8Array::from(bytes).into()
}

/// The key of a sequence number in the log.
pub fn be64(sequence: u64) -> JsValue {
    js_key(&sequence.to_be_bytes())
}

/// The key of the row that [`silent_commit`] writes. Its value is the sequence number of the
/// batch as eight bytes.
pub const SILENT_KEY: &[u8] = b"quiet";

/// Commits the batch after `sequence` the way a writer does, with its row, the log batch and
/// the sequence number in one transaction, but without the notification. With `evict` the
/// transaction also removes every older batch from the log. Returns the new sequence number.
pub async fn silent_commit(name: &str, sequence: &mut u64, evict: bool) -> u64 {
    *sequence += 1;
    let value = sequence.to_be_bytes();
    let batch = LogBatch::from_entries(*sequence, vec![row(SILENT_KEY, &value)]);
    let evict_below = if evict {
        be64(*sequence)
    } else {
        JsValue::UNDEFINED
    };
    raw_commit(
        name,
        be64(*sequence),
        js_key(SILENT_KEY),
        js_value(&value),
        js_value(&batch.into_response_bytes()),
        evict_below,
    )
    .await
    .unwrap();
    *sequence
}

/// Records the length of every byte string the engine copies out of JS until [`copied`] is
/// called.
pub fn record_copies() {
    record_copies_into(wasm_bindgen::memory());
}

/// The lines of a recording that name a transaction.
pub fn transactions(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .filter(|line| line.starts_with("transaction "))
        .map(String::as_str)
        .collect()
}

/// How many lines of a recording start with `call`.
pub fn placed(lines: &[String], call: &str) -> usize {
    lines.iter().filter(|line| line.starts_with(call)).count()
}

/// Asserts that the page reported no uncaught error since the last check. The events that
/// follow an aborted transaction arrive a little later, so this waits for them first.
pub async fn assert_nothing_uncaught() {
    sleep(20).await;
    assert_eq!(uncaught(), Vec::<String>::new());
}

/// Waits for a future for at most `ms` milliseconds.
pub async fn within<T>(ms: u32, future: impl Future<Output = T>) -> Option<T> {
    match select(pin!(future), pin!(sleep(ms))).await {
        Either::Left((output, _)) => Some(output),
        Either::Right(_) => None,
    }
}

/// Stores on databases of the test page's origin.
pub struct IndexedDbBackend;

impl Backend for IndexedDbBackend {
    type Store = IndexedDbStore;
    type Location = String;

    fn location(&self) -> String {
        database("conformance")
    }

    async fn open(&self, location: &String) -> IndexedDbStore {
        open(location).await
    }

    async fn close(&self, store: IndexedDbStore) {
        store.close();
    }

    async fn put_batch(
        &self,
        store: &IndexedDbStore,
        rows: Vec<(Bytes, Bytes)>,
    ) -> Result<u64, IngestError> {
        store.put_batch(rows).await
    }

    async fn pause(&self) {
        sleep(5).await;
    }
}
