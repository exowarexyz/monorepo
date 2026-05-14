import initWasm, * as wasm from './generated/wasm/exoware_simplex_wasm.js';
import {
  createCommonwareSimplexVerifier,
  type CommonwareVerifiedSimplexCertificate,
  type CommonwareSimplexVerifierOptions,
  type SimplexCertificateVerifier,
} from './client.js';

let wasmReady: Promise<unknown> | undefined;
type InitWasmInput = Parameters<typeof initWasm>[0];

export function ensureCommonwareSimplexWasm(initInput?: InitWasmInput): Promise<unknown> {
  return (wasmReady ??= initWasm(initInput));
}

export async function createCommonwareWasmSimplexVerifier(
  options: CommonwareSimplexVerifierOptions,
  initInput?: InitWasmInput,
): Promise<
  SimplexCertificateVerifier<
    CommonwareVerifiedSimplexCertificate,
    CommonwareVerifiedSimplexCertificate
  >
> {
  await ensureCommonwareSimplexWasm(initInput);
  return createCommonwareSimplexVerifier(wasm, options);
}
