/**
 * An Exoware Store in the browser, kept in IndexedDB.
 *
 * `openIndexedDbStore` returns the handlers of the Store services and an in-process transport
 * over them, so `new Client(store.transport)` gives the same client that talks to a server.
 */
export {
    openIndexedDbStore,
    deleteIndexedDbStore,
    type IndexedDbStore,
    type IndexedDbStoreOptions,
} from './store.js';
