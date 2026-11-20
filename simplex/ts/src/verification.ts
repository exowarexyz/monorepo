import { copyBytes, toSimplexBytes, type BytesLike } from './encoding.js';

export type MaybePromise<T> = T | Promise<T>;

export interface SimplexVerificationContext {
  key: Uint8Array;
  raw: Uint8Array;
  source: 'get' | 'stream';
}

export interface SimplexNotarizationVerificationContext extends SimplexVerificationContext {
  kind: 'notarization';
  epoch: bigint;
  view: bigint;
}

export type SimplexFinalizationVerificationContext = SimplexVerificationContext & {
  kind: 'finalization';
} & (
  | { index: 'round'; epoch: bigint; view: bigint }
  | { index: 'height' | 'latest'; height: bigint }
);

export interface SimplexCertificateVerifier<TNotarization = unknown, TFinalization = unknown> {
  verifyNotarized(
    bytes: Uint8Array,
    context: SimplexNotarizationVerificationContext,
  ): MaybePromise<TNotarization | null | undefined | false>;
  verifyFinalized(
    bytes: Uint8Array,
    context: SimplexFinalizationVerificationContext,
  ): MaybePromise<TFinalization | null | undefined | false>;
}

export type SimplexScheme =
  | 'ed25519'
  | 'secp256r1'
  | 'bls12381-multisig-min-pk'
  | 'bls12381-multisig-min-sig'
  | 'bls12381-threshold-standard-min-pk'
  | 'bls12381-threshold-standard-min-sig'
  | 'bls12381-threshold-vrf-min-pk'
  | 'bls12381-threshold-vrf-min-sig';

export type SimplexPayloadKind =
  | 'sha256'
  | 'blake3'
  | 'transcript-summary'
  | 'coding-commitment';

export type SimplexIdentity = 'ed25519' | 'secp256r1';

/**
 * Signature-verified certificate fields. `header` holds the bytes stored after
 * the certificate, and results returned by
 * `createWasmSimplexCertificateVerifier` have also passed `verifyHeader`.
 */
export interface VerifiedSimplexCertificate {
  epoch: bigint;
  scheme: SimplexScheme;
  view: bigint;
  parent: bigint;
  payload: Uint8Array;
  certificate: Uint8Array;
  header: Uint8Array;
}

export type SimplexCertificateVerificationContext =
  | SimplexNotarizationVerificationContext
  | SimplexFinalizationVerificationContext;

export interface SimplexHeaderVerification {
  certificate: VerifiedSimplexCertificate;
  context: SimplexCertificateVerificationContext;
  raw: Uint8Array;
  payload: Uint8Array;
  header: Uint8Array;
}

export interface SimplexBlockVerification {
  certificate: VerifiedSimplexCertificate;
  context: SimplexCertificateVerificationContext;
  raw: Uint8Array;
  payload: Uint8Array;
  header: Uint8Array;
  body: Uint8Array;
}

export type SimplexHeaderVerifier = (
  verification: SimplexHeaderVerification,
) => MaybePromise<boolean | null | undefined>;

export type SimplexBlockVerifier = (
  verification: SimplexBlockVerification,
) => MaybePromise<boolean | null | undefined>;

export interface SimplexWasmHeaderVerifierModule {
  verify_header: (
    payload: Uint8Array,
    header: Uint8Array,
  ) => boolean | null | undefined;
}

export interface SimplexWasmBlockVerifierModule {
  verify_block: (
    payload: Uint8Array,
    header: Uint8Array,
    body: Uint8Array,
  ) => boolean | null | undefined;
}

export interface SimplexCertificateVerifierOptions {
  scheme: SimplexScheme;
  payloadKind: SimplexPayloadKind;
  identity: SimplexIdentity;
  namespace: BytesLike;
  verificationMaterial: BytesLike;
  verifyHeader: SimplexHeaderVerifier;
}

export interface SimplexWasmCertificateVerifierModule {
  verify_notarized: (
    payloadKind: string,
    identity: string,
    scheme: string,
    namespace: Uint8Array,
    verificationMaterial: Uint8Array,
    bytes: Uint8Array,
  ) => unknown;
  verify_finalized: (
    payloadKind: string,
    identity: string,
    scheme: string,
    namespace: Uint8Array,
    verificationMaterial: Uint8Array,
    bytes: Uint8Array,
  ) => unknown;
}

/**
 * Adapts an application WASM check of `header` against `payload`. The check
 * receives no verification context, so it cannot match the header's height to
 * `context.height`.
 */
export function createWasmSimplexHeaderVerifier(
  module: SimplexWasmHeaderVerifierModule,
): SimplexHeaderVerifier {
  if (!module.verify_header) {
    throw new Error('simplex WASM header verifier missing verify_header');
  }
  return ({ payload, header }) =>
    module.verify_header(copyBytes(payload), copyBytes(header)) === true;
}

/** Adapts an application WASM check of `header` and `body` against `payload`. */
export function createWasmSimplexBlockVerifier(
  module: SimplexWasmBlockVerifierModule,
): SimplexBlockVerifier {
  if (!module.verify_block) {
    throw new Error('simplex WASM block verifier missing verify_block');
  }
  return ({ payload, header, body }) =>
    module.verify_block(copyBytes(payload), copyBytes(header), copyBytes(body)) === true;
}

/**
 * Builds a certificate verifier from the bundled WASM module. It checks
 * signatures and, for round reads, the signed epoch and view. `verifyHeader`
 * must authenticate `header` against `payload` and, for height and latest
 * reads, match the header's height to `context.height`.
 */
export function createWasmSimplexCertificateVerifier(
  module: SimplexWasmCertificateVerifierModule,
  options: SimplexCertificateVerifierOptions,
): SimplexCertificateVerifier<VerifiedSimplexCertificate, VerifiedSimplexCertificate> {
  const namespace = toSimplexBytes(options.namespace);
  const verificationMaterial = toSimplexBytes(options.verificationMaterial);
  if (!module.verify_notarized || !module.verify_finalized) {
    throw new Error('simplex WASM certificate verifier missing verify_notarized or verify_finalized');
  }
  return {
    verifyNotarized: (bytes, context) => {
      const scheme = options.scheme;
      return normalizeAndVerifyCertificate(
        module.verify_notarized(
          options.payloadKind,
          options.identity,
          scheme,
          copyBytes(namespace),
          copyBytes(verificationMaterial),
          copyBytes(bytes),
        ),
        scheme,
        bytes,
        context,
        options.verifyHeader,
      );
    },
    verifyFinalized: (bytes, context) => {
      const scheme = options.scheme;
      return normalizeAndVerifyCertificate(
        module.verify_finalized(
          options.payloadKind,
          options.identity,
          scheme,
          copyBytes(namespace),
          copyBytes(verificationMaterial),
          copyBytes(bytes),
        ),
        scheme,
        bytes,
        context,
        options.verifyHeader,
      );
    },
  };
}

async function normalizeAndVerifyCertificate(
  value: unknown,
  scheme: SimplexScheme,
  raw: Uint8Array,
  context: SimplexCertificateVerificationContext,
  verifyHeader: SimplexHeaderVerifier,
): Promise<VerifiedSimplexCertificate | null> {
  const certificate = normalizeVerifiedCertificate(value, scheme);
  if (!certificate) {
    return null;
  }
  if (context.kind === 'notarization' || context.index === 'round') {
    if (certificate.view !== context.view || certificate.epoch !== context.epoch) {
      return null;
    }
  }
  const verified = await verifyHeader({
    certificate,
    context,
    raw: copyBytes(raw),
    payload: copyBytes(certificate.payload),
    header: copyBytes(certificate.header),
  });
  return verified ? certificate : null;
}

function normalizeVerifiedCertificate(
  value: unknown,
  scheme: SimplexScheme,
): VerifiedSimplexCertificate | null {
  if (!value) {
    return null;
  }
  if (typeof value !== 'object') {
    throw new Error('simplex verifier returned a non-object certificate');
  }
  const record = value as Record<string, unknown>;
  return {
    scheme,
    epoch: u64FromUnknown(record.epoch, 'epoch'),
    view: u64FromUnknown(record.view, 'view'),
    parent: u64FromUnknown(record.parent, 'parent'),
    payload: bytesFromUnknown(record.payload, 'payload'),
    certificate: bytesFromUnknown(record.certificate, 'certificate'),
    header: bytesFromUnknown(record.header, 'header'),
  };
}

function u64FromUnknown(value: unknown, field: string): bigint {
  if (typeof value !== 'bigint' || value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`simplex verifier returned invalid ${field}`);
  }
  return value;
}

function bytesFromUnknown(value: unknown, field: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return copyBytes(value);
  }
  if (
    Array.isArray(value) &&
    value.every((item) => Number.isInteger(item) && item >= 0 && item <= 0xff)
  ) {
    return Uint8Array.from(value);
  }
  throw new Error(`simplex verifier returned invalid ${field} bytes`);
}
