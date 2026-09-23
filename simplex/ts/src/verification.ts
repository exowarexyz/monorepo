import { copyBytes, toSimplexBytes, type BytesLike } from './encoding.js';

export type MaybePromise<T> = T | Promise<T>;

export interface SimplexVerificationContext {
  key: Uint8Array;
  value: Uint8Array;
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
  verifyNotarization(
    bytes: Uint8Array,
    context: SimplexNotarizationVerificationContext,
  ): MaybePromise<TNotarization | null | undefined | false>;
  verifyFinalization(
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

export type SimplexPayload =
  | 'sha256'
  | 'blake3'
  | 'transcript-summary'
  | 'coding-commitment';

export type SimplexIdentity = 'ed25519' | 'secp256r1';

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

export interface SimplexVerifierOptions {
  scheme: SimplexScheme;
  payload: SimplexPayload;
  identity: SimplexIdentity;
  namespace: BytesLike;
  verificationMaterial: BytesLike;
  verifyHeader?: SimplexHeaderVerifier;
}

export interface SimplexPayloadWasmVerifierModule {
  verify_notarized_payload: (
    payload: string,
    identity: string,
    scheme: string,
    namespace: Uint8Array,
    verificationMaterial: Uint8Array,
    bytes: Uint8Array,
  ) => unknown;
  verify_finalized_payload: (
    payload: string,
    identity: string,
    scheme: string,
    namespace: Uint8Array,
    verificationMaterial: Uint8Array,
    bytes: Uint8Array,
  ) => unknown;
}

export function createWasmSimplexHeaderVerifier(
  module: SimplexWasmHeaderVerifierModule,
): SimplexHeaderVerifier {
  if (!module.verify_header) {
    throw new Error('simplex WASM header verifier missing verify_header');
  }
  return ({ payload, header }) =>
    module.verify_header(copyBytes(payload), copyBytes(header)) === true;
}

export function createWasmSimplexBlockVerifier(
  module: SimplexWasmBlockVerifierModule,
): SimplexBlockVerifier {
  if (!module.verify_block) {
    throw new Error('simplex WASM block verifier missing verify_block');
  }
  return ({ payload, header, body }) =>
    module.verify_block(copyBytes(payload), copyBytes(header), copyBytes(body)) === true;
}

export function createSimplexVerifier(
  module: SimplexPayloadWasmVerifierModule,
  options: SimplexVerifierOptions,
): SimplexCertificateVerifier<VerifiedSimplexCertificate, VerifiedSimplexCertificate> {
  const namespace = toSimplexBytes(options.namespace);
  const verificationMaterial = toSimplexBytes(options.verificationMaterial);
  if (!module.verify_notarized_payload || !module.verify_finalized_payload) {
    throw new Error('simplex WASM verifier missing payload support');
  }
  return {
    verifyNotarization: (bytes, context) => {
      const scheme = options.scheme;
      return normalizeAndVerifyCertificate(
        module.verify_notarized_payload(
          options.payload,
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
    verifyFinalization: (bytes, context) => {
      const scheme = options.scheme;
      return normalizeAndVerifyCertificate(
        module.verify_finalized_payload(
          options.payload,
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
  verifyHeader?: SimplexHeaderVerifier,
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
  if (verifyHeader) {
    const verified = await verifyHeader({
      certificate,
      context,
      raw: copyBytes(raw),
      payload: copyBytes(certificate.payload),
      header: copyBytes(certificate.header),
    });
    if (!verified) {
      return null;
    }
  }
  return certificate;
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
