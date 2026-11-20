import { copyBytes } from './encoding.js';
import type {
  SimplexCertificateVerifier,
  SimplexFinalizationVerificationContext,
  SimplexNotarizationVerificationContext,
} from './verification.js';

export async function verifyNotarized<TNotarization, TFinalization>(
  verifier: SimplexCertificateVerifier<TNotarization, TFinalization>,
  bytes: Uint8Array,
  context: SimplexNotarizationVerificationContext,
): Promise<TNotarization> {
  const verified = await verifier.verifyNotarized(copyBytes(bytes), context);
  if (!verified) {
    throw new Error('simplex notarization verification failed');
  }
  return verified;
}

export async function verifyFinalized<TNotarization, TFinalization>(
  verifier: SimplexCertificateVerifier<TNotarization, TFinalization>,
  bytes: Uint8Array,
  context: SimplexFinalizationVerificationContext,
): Promise<TFinalization> {
  const verified = await verifier.verifyFinalized(copyBytes(bytes), context);
  if (!verified) {
    throw new Error('simplex finalization verification failed');
  }
  return verified;
}
