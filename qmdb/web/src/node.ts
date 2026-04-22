import {
  configureInitializedWasmBindingsLoader,
  type WasmConstructors,
} from './runtime.js';
import * as wasmBindings from '../pkg-node/exoware_qmdb_web.js';

configureInitializedWasmBindingsLoader(async () => wasmBindings as WasmConstructors);

export * from './runtime.js';
