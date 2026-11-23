import initWasm, * as wasm from './generated/wasm/exoware_simplex_wasm.js';
import {
  createWasmSimplexCertificateVerifier,
  type VerifiedSimplexCertificate,
  type SimplexCertificateVerifierOptions,
  type SimplexCertificateVerifier,
} from './verification.js';

let wasmReady: Promise<unknown> | undefined;
type InitWasmInput = Parameters<typeof initWasm>[0];

export function ensureSimplexWasm(initInput?: InitWasmInput): Promise<unknown> {
  return (wasmReady ??= initWasm(initInput));
}

export async function loadWasmSimplexCertificateVerifier(
  options: SimplexCertificateVerifierOptions,
  initInput?: InitWasmInput,
): Promise<
  SimplexCertificateVerifier<
    VerifiedSimplexCertificate,
    VerifiedSimplexCertificate
  >
> {
  await ensureSimplexWasm(initInput);
  return createWasmSimplexCertificateVerifier(wasm, options);
}
