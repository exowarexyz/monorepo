import {
  configureWasmBindingsLoader,
  configureWasmSourceLoader,
  type WasmBindings,
} from './runtime.js';

configureWasmBindingsLoader(async () =>
  // @ts-expect-error wasm-pack does not emit a sibling declaration for the generated bindings module.
  (await import('../pkg/exoware_qmdb_web_bg.js')) as WasmBindings,
);

configureWasmSourceLoader(async () => {
  const wasmUrl = new URL('../pkg/exoware_qmdb_web_bg.wasm', import.meta.url);
  const response = await fetch(wasmUrl);
  if (!response.ok) {
    throw new Error(`failed to load qmdb wasm: ${response.status} ${response.statusText}`);
  }
  return await response.arrayBuffer();
});

export * from './runtime.js';
