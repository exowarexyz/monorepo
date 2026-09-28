import { copyBytes } from './encoding.js';
import type {
  SimplexCertificateVerifier,
  SimplexFinalizationVerificationContext,
  SimplexNotarizationVerificationContext,
} from './verification.js';

export async function verifyNotarization<TNotarization, TFinalization>(
  verifier: SimplexCertificateVerifier<TNotarization, TFinalization>,
  bytes: Uint8Array,
  context: SimplexNotarizationVerificationContext,
): Promise<TNotarization> {
  const verified = await verifier.verifyNotarization(copyBytes(bytes), context);
  if (!verified) {
    throw new Error('simplex notarization verification failed');
  }
  return verified;
}

export async function verifyFinalization<TNotarization, TFinalization>(
  verifier: SimplexCertificateVerifier<TNotarization, TFinalization>,
  bytes: Uint8Array,
  context: SimplexFinalizationVerificationContext,
): Promise<TFinalization> {
  const verified = await verifier.verifyFinalization(copyBytes(bytes), context);
  if (!verified) {
    throw new Error('simplex finalization verification failed');
  }
  return verified;
}
