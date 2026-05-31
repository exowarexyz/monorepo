import initWasm, * as wasm from './generated/wasm/exoware_simplex_wasm.js';
import {
  createSimplexVerifier,
  type VerifiedSimplexCertificate,
  type SimplexVerifierOptions,
  type SimplexCertificateVerifier,
} from './client.js';

let wasmReady: Promise<unknown> | undefined;
type InitWasmInput = Parameters<typeof initWasm>[0];

export function ensureSimplexWasm(initInput?: InitWasmInput): Promise<unknown> {
  return (wasmReady ??= initWasm(initInput));
}

export async function createWasmSimplexVerifier(
  options: SimplexVerifierOptions,
  initInput?: InitWasmInput,
): Promise<
  SimplexCertificateVerifier<
    VerifiedSimplexCertificate,
    VerifiedSimplexCertificate
  >
> {
  await ensureSimplexWasm(initInput);
  return createSimplexVerifier(wasm, options);
}
