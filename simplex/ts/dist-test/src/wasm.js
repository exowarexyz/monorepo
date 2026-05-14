import initWasm, * as wasm from './generated/wasm/exoware_simplex_wasm.js';
import { createCommonwareSimplexVerifier, } from './client.js';
let wasmReady;
export function ensureCommonwareSimplexWasm(initInput) {
    return (wasmReady ??= initWasm(initInput));
}
export async function createCommonwareWasmSimplexVerifier(options, initInput) {
    await ensureCommonwareSimplexWasm(initInput);
    return createCommonwareSimplexVerifier(wasm, options);
}
