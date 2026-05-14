import {
  Client,
  StoreClient,
  StoreWriteBatch,
  TraversalMode,
  type ClientOptions as SdkClientOptions,
  type StoreBatchEntry,
} from '@exowarexyz/sdk';

export type BytesLike = Uint8Array | string;
export type U64Like = bigint | number | string;

export const FORMAT_VERSION = 0;

export enum SimplexRecordKind {
  HeaderByDigest = 0x10,
  BlockByDigest = 0x11,
  NotarizationByView = 0x20,
  FinalizationByView = 0x30,
  FinalizedByHeight = 0x31,
}

export interface PreparedSimplexEntry {
  key: Uint8Array;
  value: Uint8Array;
}

export interface SimplexUploadSummary {
  headers: number;
  blocks: number;
  notarizations: number;
  finalizations: number;
  finalizedHeightIndexes: number;
}

export interface SimplexUploadReceipt {
  storeSequenceNumber: bigint;
  summary: SimplexUploadSummary;
}

export interface PreparedSimplexUpload {
  entries: PreparedSimplexEntry[];
  summary: SimplexUploadSummary;
}

export interface HeaderUpload {
  digest: BytesLike;
  header: BytesLike;
}

export interface BlockUpload extends HeaderUpload {
  body?: BytesLike;
}

export interface NotarizationUpload {
  view: U64Like;
  notarized: BytesLike;
  header?: BytesLike;
  digest?: BytesLike;
  body?: BytesLike;
}

export interface FinalizationUpload {
  view: U64Like;
  height: U64Like;
  finalized: BytesLike;
  header?: BytesLike;
  digest?: BytesLike;
  body?: BytesLike;
}

export type MaybePromise<T> = T | Promise<T>;

export interface SimplexVerificationContext {
  key: Uint8Array;
  value: Uint8Array;
  source: 'get' | 'stream';
}

export interface SimplexNotarizationVerificationContext extends SimplexVerificationContext {
  kind: 'notarization';
  view: bigint;
}

export interface SimplexFinalizationVerificationContext extends SimplexVerificationContext {
  kind: 'finalization';
  index: 'view' | 'height' | 'latest';
  view?: bigint;
  height?: bigint;
}

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

export interface SimplexWasmVerifierModule<TNotarization = unknown, TFinalization = unknown> {
  parse_notarized?: (verificationKey: Uint8Array, bytes: Uint8Array) => TNotarization | null | undefined | false;
  parse_finalized?: (verificationKey: Uint8Array, bytes: Uint8Array) => TFinalization | null | undefined | false;
  verify_notarized?: (verificationKey: Uint8Array, bytes: Uint8Array) => TNotarization | null | undefined | false;
  verify_finalized?: (verificationKey: Uint8Array, bytes: Uint8Array) => TFinalization | null | undefined | false;
}

export type CommonwareSimplexScheme =
  | 'ed25519'
  | 'secp256r1'
  | 'bls12381-multisig-min-pk'
  | 'bls12381-multisig-min-sig'
  | 'bls12381-threshold-standard-min-pk'
  | 'bls12381-threshold-standard-min-sig'
  | 'bls12381-threshold-vrf-min-pk'
  | 'bls12381-threshold-vrf-min-sig';

export interface CommonwareVerifiedSimplexCertificate {
  scheme: CommonwareSimplexScheme;
  view: bigint;
  parent: bigint;
  payload: Uint8Array;
  certificate: Uint8Array;
  header: Uint8Array;
  body: Uint8Array;
}

export type CommonwareSimplexCertificateVerificationContext =
  | SimplexNotarizationVerificationContext
  | SimplexFinalizationVerificationContext;

export interface CommonwareSimplexHeaderVerification {
  certificate: CommonwareVerifiedSimplexCertificate;
  context: CommonwareSimplexCertificateVerificationContext;
  raw: Uint8Array;
  payload: Uint8Array;
  header: Uint8Array;
}

export interface CommonwareSimplexBlockVerification {
  certificate: CommonwareVerifiedSimplexCertificate;
  context: CommonwareSimplexCertificateVerificationContext;
  raw: Uint8Array;
  payload: Uint8Array;
  header: Uint8Array;
  body: Uint8Array;
}

export type CommonwareSimplexHeaderVerifier = (
  verification: CommonwareSimplexHeaderVerification,
) => MaybePromise<boolean | null | undefined>;

export type CommonwareSimplexBlockVerifier = (
  verification: CommonwareSimplexBlockVerification,
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

export interface CommonwareSimplexVerifierOptions {
  scheme: CommonwareSimplexScheme;
  namespace: BytesLike;
  verificationMaterial: BytesLike;
  verifyHeader?: CommonwareSimplexHeaderVerifier;
  verifyBlock?: CommonwareSimplexBlockVerifier;
}

export interface CommonwareSimplexWasmVerifierModule {
  verify_notarized_commonware: (
    scheme: string,
    namespace: Uint8Array,
    verificationMaterial: Uint8Array,
    bytes: Uint8Array,
  ) => unknown;
  verify_finalized_commonware: (
    scheme: string,
    namespace: Uint8Array,
    verificationMaterial: Uint8Array,
    bytes: Uint8Array,
  ) => unknown;
}

export type SimplexClientOptions<TNotarization = unknown, TFinalization = unknown> =
  SdkClientOptions & {
    verifier?: SimplexCertificateVerifier<TNotarization, TFinalization>;
  };

export interface SimplexBlockData {
  header: Uint8Array;
  body: Uint8Array;
}

export interface RawSimplexHeaderEntry {
  type: 'header';
  kind: SimplexRecordKind.HeaderByDigest;
  key: Uint8Array;
  digest: Uint8Array;
  header: Uint8Array;
}

export interface RawSimplexBlockEntry extends SimplexBlockData {
  type: 'block';
  kind: SimplexRecordKind.BlockByDigest;
  key: Uint8Array;
  digest: Uint8Array;
  raw: Uint8Array;
}

export interface RawSimplexNotarizationEntry {
  type: 'notarization';
  kind: SimplexRecordKind.NotarizationByView;
  key: Uint8Array;
  view: bigint;
  notarized: Uint8Array;
}

export interface RawSimplexFinalizationByViewEntry {
  type: 'finalization';
  kind: SimplexRecordKind.FinalizationByView;
  index: 'view';
  key: Uint8Array;
  view: bigint;
  finalized: Uint8Array;
}

export interface RawSimplexFinalizationByHeightEntry {
  type: 'finalization';
  kind: SimplexRecordKind.FinalizedByHeight;
  index: 'height';
  key: Uint8Array;
  height: bigint;
  finalized: Uint8Array;
}

export type RawSimplexStreamEntry =
  | RawSimplexHeaderEntry
  | RawSimplexBlockEntry
  | RawSimplexNotarizationEntry
  | RawSimplexFinalizationByViewEntry
  | RawSimplexFinalizationByHeightEntry;

export type RawSimplexCertificateStreamEntry =
  | RawSimplexNotarizationEntry
  | RawSimplexFinalizationByViewEntry
  | RawSimplexFinalizationByHeightEntry;

export type VerifiedSimplexCertificateStreamEntry<TNotarization, TFinalization> =
  | (Omit<RawSimplexNotarizationEntry, 'notarized'> & {
      raw: Uint8Array;
      certificate: TNotarization;
    })
  | (Omit<RawSimplexFinalizationByViewEntry, 'finalized'> & {
      raw: Uint8Array;
      certificate: TFinalization;
    })
  | (Omit<RawSimplexFinalizationByHeightEntry, 'finalized'> & {
      raw: Uint8Array;
      certificate: TFinalization;
    });

export interface SimplexStreamBatch<TEntry> {
  sequenceNumber: bigint;
  entries: TEntry[];
}

export interface SimplexStreamOptions {
  sinceSequenceNumber?: bigint;
}

export interface SimplexCertificateStreamOptions extends SimplexStreamOptions {
  includeFinalizedByHeight?: boolean;
}

const STREAM_PAYLOAD_REGEX = '(?s-u).*';
const HEADER_LENGTH_BYTES = 4;

function copyBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

export function hexToBytes(value: string): Uint8Array {
  const trimmed = value.trim();
  const body = trimmed.startsWith('0x') || trimmed.startsWith('0X') ? trimmed.slice(2) : trimmed;
  if (body.length === 0) {
    return new Uint8Array();
  }
  if (body.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(body)) {
    throw new Error('expected an even-length hex string');
  }
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(body.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(value: Uint8Array): string {
  return Array.from(value)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export function toSimplexBytes(value: BytesLike): Uint8Array {
  return typeof value === 'string' ? hexToBytes(value) : copyBytes(value);
}

export function encodeSimplexBlockData(
  header: BytesLike,
  body: BytesLike = new Uint8Array(),
): Uint8Array {
  const headerBytes = toSimplexBytes(header);
  const bodyBytes = toSimplexBytes(body);
  if (headerBytes.byteLength > 0xffff_ffff) {
    throw new RangeError('header simplex block exceeds u32 length');
  }
  const out = new Uint8Array(
    HEADER_LENGTH_BYTES + headerBytes.byteLength + bodyBytes.byteLength,
  );
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(
    0,
    headerBytes.byteLength,
    false,
  );
  out.set(headerBytes, HEADER_LENGTH_BYTES);
  out.set(bodyBytes, HEADER_LENGTH_BYTES + headerBytes.byteLength);
  return out;
}

export function decodeSimplexBlockData(value: BytesLike): SimplexBlockData {
  const bytes = toSimplexBytes(value);
  if (bytes.byteLength < HEADER_LENGTH_BYTES) {
    throw new Error('simplex block data is missing header length');
  }
  const headerLength = new DataView(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength,
  ).getUint32(0, false);
  const remaining = bytes.byteLength - HEADER_LENGTH_BYTES;
  if (headerLength > remaining) {
    throw new Error('simplex block header length exceeds block data length');
  }
  const headerStart = HEADER_LENGTH_BYTES;
  const bodyStart = headerStart + headerLength;
  return {
    header: bytes.slice(headerStart, bodyStart),
    body: bytes.slice(bodyStart),
  };
}

export function normalizeU64(value: U64Like): bigint {
  const bigintValue = typeof value === 'bigint' ? value : BigInt(value);
  if (bigintValue < 0n || bigintValue > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError(`u64 out of range: ${value}`);
  }
  return bigintValue;
}

function u64Bytes(value: U64Like): Uint8Array {
  let remaining = normalizeU64(value);
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

function keyFromParts(kind: SimplexRecordKind, suffix: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + suffix.length);
  out[0] = FORMAT_VERSION;
  out[1] = kind;
  out.set(suffix, 2);
  return out;
}

export function headerByDigestKey(digest: BytesLike): Uint8Array {
  return keyFromParts(SimplexRecordKind.HeaderByDigest, toSimplexBytes(digest));
}

export function blockByDigestKey(digest: BytesLike): Uint8Array {
  return keyFromParts(SimplexRecordKind.BlockByDigest, toSimplexBytes(digest));
}

export function notarizationByViewKey(view: U64Like): Uint8Array {
  return keyFromParts(SimplexRecordKind.NotarizationByView, u64Bytes(view));
}

export function finalizationByViewKey(view: U64Like): Uint8Array {
  return keyFromParts(SimplexRecordKind.FinalizationByView, u64Bytes(view));
}

export function finalizedByHeightKey(height: U64Like): Uint8Array {
  return keyFromParts(SimplexRecordKind.FinalizedByHeight, u64Bytes(height));
}

export function rangeForKind(kind: SimplexRecordKind): { start: Uint8Array; end: Uint8Array } {
  return {
    start: new Uint8Array([FORMAT_VERSION, kind]),
    end: new Uint8Array([FORMAT_VERSION, kind + 1]),
  };
}

export function createWasmSimplexVerifier<TNotarization = unknown, TFinalization = unknown>(
  module: SimplexWasmVerifierModule<TNotarization, TFinalization>,
  verificationKey: BytesLike,
): SimplexCertificateVerifier<TNotarization, TFinalization> {
  const key = toSimplexBytes(verificationKey);
  const verifyNotarized = module.verify_notarized ?? module.parse_notarized;
  const verifyFinalized = module.verify_finalized ?? module.parse_finalized;
  if (!verifyNotarized) {
    throw new Error('simplex WASM verifier missing verify_notarized/parse_notarized');
  }
  if (!verifyFinalized) {
    throw new Error('simplex WASM verifier missing verify_finalized/parse_finalized');
  }
  return {
    verifyNotarization: (bytes) => verifyNotarized(copyBytes(key), copyBytes(bytes)),
    verifyFinalization: (bytes) => verifyFinalized(copyBytes(key), copyBytes(bytes)),
  };
}

export function createWasmSimplexHeaderVerifier(
  module: SimplexWasmHeaderVerifierModule,
): CommonwareSimplexHeaderVerifier {
  if (!module.verify_header) {
    throw new Error('simplex WASM header verifier missing verify_header');
  }
  return ({ payload, header }) =>
    module.verify_header(copyBytes(payload), copyBytes(header)) === true;
}

export function createWasmSimplexBlockVerifier(
  module: SimplexWasmBlockVerifierModule,
): CommonwareSimplexBlockVerifier {
  if (!module.verify_block) {
    throw new Error('simplex WASM block verifier missing verify_block');
  }
  return ({ payload, header, body }) =>
    module.verify_block(copyBytes(payload), copyBytes(header), copyBytes(body)) === true;
}

export function createCommonwareSimplexVerifier(
  module: CommonwareSimplexWasmVerifierModule,
  options: CommonwareSimplexVerifierOptions,
): SimplexCertificateVerifier<CommonwareVerifiedSimplexCertificate, CommonwareVerifiedSimplexCertificate> {
  const namespace = toSimplexBytes(options.namespace);
  const verificationMaterial = toSimplexBytes(options.verificationMaterial);
  return {
    verifyNotarization: (bytes, context) =>
      normalizeAndVerifyCommonwareCertificate(
        module.verify_notarized_commonware(
          options.scheme,
          copyBytes(namespace),
          copyBytes(verificationMaterial),
          copyBytes(bytes),
        ),
        bytes,
        context,
        options.verifyHeader,
        options.verifyBlock,
      ),
    verifyFinalization: (bytes, context) =>
      normalizeAndVerifyCommonwareCertificate(
        module.verify_finalized_commonware(
          options.scheme,
          copyBytes(namespace),
          copyBytes(verificationMaterial),
          copyBytes(bytes),
        ),
        bytes,
        context,
        options.verifyHeader,
        options.verifyBlock,
      ),
  };
}

async function normalizeAndVerifyCommonwareCertificate(
  value: unknown,
  raw: Uint8Array,
  context: CommonwareSimplexCertificateVerificationContext,
  verifyHeader?: CommonwareSimplexHeaderVerifier,
  verifyBlock?: CommonwareSimplexBlockVerifier,
): Promise<CommonwareVerifiedSimplexCertificate | null> {
  const certificate = normalizeCommonwareVerifiedCertificate(value);
  if (!certificate) {
    return null;
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
  if (verifyBlock) {
    const verified = await verifyBlock({
      certificate,
      context,
      raw: copyBytes(raw),
      payload: copyBytes(certificate.payload),
      header: copyBytes(certificate.header),
      body: copyBytes(certificate.body),
    });
    if (!verified) {
      return null;
    }
  }
  return certificate;
}

function normalizeCommonwareVerifiedCertificate(
  value: unknown,
): CommonwareVerifiedSimplexCertificate | null {
  if (!value) {
    return null;
  }
  if (typeof value !== 'object') {
    throw new Error('simplex Commonware verifier returned a non-object certificate');
  }
  const record = value as Record<string, unknown>;
  return {
    scheme: commonwareSchemeFromUnknown(record.scheme),
    view: u64FromUnknown(record.view, 'view'),
    parent: u64FromUnknown(record.parent, 'parent'),
    payload: bytesFromUnknown(record.payload, 'payload'),
    certificate: bytesFromUnknown(record.certificate, 'certificate'),
    header: bytesFromUnknown(record.header, 'header'),
    body: bytesFromUnknown(record.body, 'body'),
  };
}

function commonwareSchemeFromUnknown(value: unknown): CommonwareSimplexScheme {
  switch (value) {
    case 'ed25519':
    case 'secp256r1':
    case 'bls12381-multisig-min-pk':
    case 'bls12381-multisig-min-sig':
    case 'bls12381-threshold-standard-min-pk':
    case 'bls12381-threshold-standard-min-sig':
    case 'bls12381-threshold-vrf-min-pk':
    case 'bls12381-threshold-vrf-min-sig':
      return value;
    default:
      throw new Error(`simplex Commonware verifier returned unsupported scheme ${String(value)}`);
  }
}

function u64FromUnknown(value: unknown, field: string): bigint {
  if (typeof value === 'bigint') {
    return value;
  }
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
    return BigInt(value);
  }
  if (typeof value === 'string' && /^[0-9]+$/.test(value)) {
    return BigInt(value);
  }
  throw new Error(`simplex Commonware verifier returned invalid ${field}`);
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
  throw new Error(`simplex Commonware verifier returned invalid ${field} bytes`);
}

function emptySummary(): SimplexUploadSummary {
  return {
    headers: 0,
    blocks: 0,
    notarizations: 0,
    finalizations: 0,
    finalizedHeightIndexes: 0,
  };
}

function prepared(entries: PreparedSimplexEntry[], summary: SimplexUploadSummary): PreparedSimplexUpload {
  return { entries, summary };
}

function mergePrepared(items: PreparedSimplexUpload[]): PreparedSimplexUpload {
  const summary = emptySummary();
  const entries: PreparedSimplexEntry[] = [];
  for (const item of items) {
    summary.headers += item.summary.headers;
    summary.blocks += item.summary.blocks;
    summary.notarizations += item.summary.notarizations;
    summary.finalizations += item.summary.finalizations;
    summary.finalizedHeightIndexes += item.summary.finalizedHeightIndexes;
    entries.push(...item.entries);
  }
  return { entries, summary };
}

function u64FromKey(key: Uint8Array): bigint {
  if (key.length !== 10) {
    throw new Error(`invalid simplex u64 key length ${key.length}`);
  }
  let value = 0n;
  for (let i = 2; i < 10; i++) {
    value = (value << 8n) | BigInt(key[i]);
  }
  return value;
}

function streamMatchKind(kind: SimplexRecordKind) {
  return {
    reservedBits: 16,
    prefix: (FORMAT_VERSION << 8) | kind,
    payloadRegex: STREAM_PAYLOAD_REGEX,
  };
}

function normalizeKinds(kinds: SimplexRecordKind | readonly SimplexRecordKind[]): SimplexRecordKind[] {
  return typeof kinds === 'number' ? [kinds] : [...kinds];
}

function decodeRawStreamEntry(key: Uint8Array, value: Uint8Array): RawSimplexStreamEntry {
  if (key.length < 2 || key[0] !== FORMAT_VERSION) {
    throw new Error('invalid simplex stream key');
  }
  const kind = key[1] as SimplexRecordKind;
  switch (kind) {
    case SimplexRecordKind.HeaderByDigest:
      return {
        type: 'header',
        kind,
        key,
        digest: key.slice(2),
        header: value,
      };
    case SimplexRecordKind.BlockByDigest: {
      const block = decodeSimplexBlockData(value);
      return {
        type: 'block',
        kind,
        key,
        digest: key.slice(2),
        raw: value,
        header: block.header,
        body: block.body,
      };
    }
    case SimplexRecordKind.NotarizationByView:
      return {
        type: 'notarization',
        kind,
        key,
        view: u64FromKey(key),
        notarized: value,
      };
    case SimplexRecordKind.FinalizationByView:
      return {
        type: 'finalization',
        kind,
        index: 'view',
        key,
        view: u64FromKey(key),
        finalized: value,
      };
    case SimplexRecordKind.FinalizedByHeight:
      return {
        type: 'finalization',
        kind,
        index: 'height',
        key,
        height: u64FromKey(key),
        finalized: value,
      };
    default:
      throw new Error(`unknown simplex stream kind ${kind}`);
  }
}

export class SimplexClient<TNotarization = unknown, TFinalization = unknown> {
  private readonly store: StoreClient;
  private readonly verifier?: SimplexCertificateVerifier<TNotarization, TFinalization>;

  constructor(baseUrl: string, options?: SimplexClientOptions<TNotarization, TFinalization>);
  constructor(
    store: StoreClient,
    options?: { verifier?: SimplexCertificateVerifier<TNotarization, TFinalization> },
  );
  constructor(
    baseUrlOrStore: string | StoreClient,
    options: SimplexClientOptions<TNotarization, TFinalization> = {},
  ) {
    const { verifier, ...clientOptions } = options;
    this.verifier = verifier;
    this.store =
      typeof baseUrlOrStore === 'string'
        ? new Client(baseUrlOrStore, clientOptions).store()
        : baseUrlOrStore;
  }

  prepareHeader(input: HeaderUpload): PreparedSimplexUpload {
    const header = toSimplexBytes(input.header);
    return prepared(
      [
        {
          key: headerByDigestKey(input.digest),
          value: header,
        },
      ],
      { ...emptySummary(), headers: 1 },
    );
  }

  prepareBlock(input: BlockUpload): PreparedSimplexUpload {
    const header = toSimplexBytes(input.header);
    const body = input.body === undefined ? new Uint8Array() : toSimplexBytes(input.body);
    return prepared(
      [
        {
          key: headerByDigestKey(input.digest),
          value: header,
        },
        {
          key: blockByDigestKey(input.digest),
          value: encodeSimplexBlockData(header, body),
        },
      ],
      { ...emptySummary(), headers: 1, blocks: 1 },
    );
  }

  prepareNotarization(input: NotarizationUpload): PreparedSimplexUpload {
    const entries: PreparedSimplexUpload[] = [];
    if (
      input.header !== undefined ||
      input.digest !== undefined ||
      input.body !== undefined
    ) {
      if (input.header === undefined || input.digest === undefined) {
        throw new Error('header and digest must be provided together');
      }
      entries.push(
        this.prepareBlock({
          header: input.header,
          digest: input.digest,
          body: input.body,
        }),
      );
    }
    entries.push(
      prepared(
        [
          {
            key: notarizationByViewKey(input.view),
            value: toSimplexBytes(input.notarized),
          },
        ],
        { ...emptySummary(), notarizations: 1 },
      ),
    );
    return mergePrepared(entries);
  }

  prepareFinalization(input: FinalizationUpload): PreparedSimplexUpload {
    const entries: PreparedSimplexUpload[] = [];
    if (
      input.header !== undefined ||
      input.digest !== undefined ||
      input.body !== undefined
    ) {
      if (input.header === undefined || input.digest === undefined) {
        throw new Error('header and digest must be provided together');
      }
      entries.push(
        this.prepareBlock({
          header: input.header,
          digest: input.digest,
          body: input.body,
        }),
      );
    }
    const finalized = toSimplexBytes(input.finalized);
    entries.push(
      prepared(
        [
          {
            key: finalizationByViewKey(input.view),
            value: finalized,
          },
          {
            key: finalizedByHeightKey(input.height),
            value: copyBytes(finalized),
          },
        ],
        { ...emptySummary(), finalizations: 1, finalizedHeightIndexes: 1 },
      ),
    );
    return mergePrepared(entries);
  }

  stageUpload(upload: PreparedSimplexUpload, batch = new StoreWriteBatch()): StoreWriteBatch {
    if (upload.entries.length === 0) {
      throw new Error('simplex upload contains no rows');
    }
    for (const entry of upload.entries) {
      batch.push(this.store, entry.key, entry.value);
    }
    return batch;
  }

  async uploadPrepared(upload: PreparedSimplexUpload): Promise<SimplexUploadReceipt> {
    const sequence = await this.stageUpload(upload).commit(this.store);
    return {
      storeSequenceNumber: sequence,
      summary: upload.summary,
    };
  }

  async uploadHeader(input: HeaderUpload): Promise<SimplexUploadReceipt> {
    return this.uploadPrepared(this.prepareHeader(input));
  }

  async uploadBlock(input: BlockUpload): Promise<SimplexUploadReceipt> {
    return this.uploadPrepared(this.prepareBlock(input));
  }

  async uploadNotarization(input: NotarizationUpload): Promise<SimplexUploadReceipt> {
    return this.uploadPrepared(this.prepareNotarization(input));
  }

  async uploadFinalization(input: FinalizationUpload): Promise<SimplexUploadReceipt> {
    return this.uploadPrepared(this.prepareFinalization(input));
  }

  async getHeader(digest: BytesLike): Promise<Uint8Array | null> {
    return this.getHeaderRaw(digest);
  }

  async getHeaderRaw(digest: BytesLike): Promise<Uint8Array | null> {
    return this.getRaw(headerByDigestKey(digest));
  }

  async getBlock(digest: BytesLike): Promise<SimplexBlockData | null> {
    const raw = await this.getBlockRaw(digest);
    return raw === null ? null : decodeSimplexBlockData(raw);
  }

  async getBlockRaw(digest: BytesLike): Promise<Uint8Array | null> {
    return this.getRaw(blockByDigestKey(digest));
  }

  async getNotarization(view: U64Like): Promise<TNotarization | null> {
    const key = notarizationByViewKey(view);
    const raw = await this.getRaw(key);
    if (raw === null) {
      return null;
    }
    return this.verifyNotarization(raw, {
      kind: 'notarization',
      source: 'get',
      key,
      value: raw,
      view: normalizeU64(view),
    });
  }

  async getNotarizationRaw(view: U64Like): Promise<Uint8Array | null> {
    return this.getRaw(notarizationByViewKey(view));
  }

  async getFinalizationByView(view: U64Like): Promise<TFinalization | null> {
    const key = finalizationByViewKey(view);
    const raw = await this.getRaw(key);
    if (raw === null) {
      return null;
    }
    return this.verifyFinalization(raw, {
      kind: 'finalization',
      index: 'view',
      source: 'get',
      key,
      value: raw,
      view: normalizeU64(view),
    });
  }

  async getFinalizationByViewRaw(view: U64Like): Promise<Uint8Array | null> {
    return this.getRaw(finalizationByViewKey(view));
  }

  async getFinalizationByHeight(height: U64Like): Promise<TFinalization | null> {
    const key = finalizedByHeightKey(height);
    const raw = await this.getRaw(key);
    if (raw === null) {
      return null;
    }
    return this.verifyFinalization(raw, {
      kind: 'finalization',
      index: 'height',
      source: 'get',
      key,
      value: raw,
      height: normalizeU64(height),
    });
  }

  async getFinalizationByHeightRaw(height: U64Like): Promise<Uint8Array | null> {
    return this.getRaw(finalizedByHeightKey(height));
  }

  async latestFinalization(): Promise<TFinalization | null> {
    const range = rangeForKind(SimplexRecordKind.FinalizedByHeight);
    const result = await this.store.query(
      range.start,
      range.end,
      1,
      4096,
      TraversalMode.REVERSE,
    );
    const row = result.results[0];
    if (!row) {
      return null;
    }
    return this.verifyFinalization(row.value, {
      kind: 'finalization',
      index: 'latest',
      source: 'get',
      key: row.key,
      value: row.value,
      height: u64FromKey(row.key),
    });
  }

  async latestFinalizationRaw(): Promise<Uint8Array | null> {
    const range = rangeForKind(SimplexRecordKind.FinalizedByHeight);
    const result = await this.store.query(
      range.start,
      range.end,
      1,
      4096,
      TraversalMode.REVERSE,
    );
    return result.results[0]?.value ?? null;
  }

  async *subscribeRaw(
    kinds: SimplexRecordKind | readonly SimplexRecordKind[],
    options: SimplexStreamOptions = {},
    callOptions?: Parameters<StoreClient['subscribe']>[1],
  ): AsyncIterable<SimplexStreamBatch<RawSimplexStreamEntry>> {
    const stream = this.store.subscribe(
      {
        matchKeys: normalizeKinds(kinds).map(streamMatchKind),
        ...(options.sinceSequenceNumber !== undefined
          ? { sinceSequenceNumber: options.sinceSequenceNumber }
          : {}),
      },
      callOptions,
    );
    for await (const batch of stream) {
      yield {
        sequenceNumber: batch.sequenceNumber,
        entries: batch.entries.map((entry: StoreBatchEntry) =>
          decodeRawStreamEntry(entry.key, entry.value),
        ),
      };
    }
  }

  async *subscribeBlocks(
    options: SimplexStreamOptions = {},
    callOptions?: Parameters<StoreClient['subscribe']>[1],
  ): AsyncIterable<SimplexStreamBatch<RawSimplexBlockEntry>> {
    for await (const batch of this.subscribeRaw(SimplexRecordKind.BlockByDigest, options, callOptions)) {
      yield {
        sequenceNumber: batch.sequenceNumber,
        entries: batch.entries.flatMap((entry) => (entry.type === 'block' ? [entry] : [])),
      };
    }
  }

  async *subscribeHeaders(
    options: SimplexStreamOptions = {},
    callOptions?: Parameters<StoreClient['subscribe']>[1],
  ): AsyncIterable<SimplexStreamBatch<RawSimplexHeaderEntry>> {
    for await (const batch of this.subscribeRaw(SimplexRecordKind.HeaderByDigest, options, callOptions)) {
      yield {
        sequenceNumber: batch.sequenceNumber,
        entries: batch.entries.flatMap((entry) => (entry.type === 'header' ? [entry] : [])),
      };
    }
  }

  async *subscribeCertificatesRaw(
    options: SimplexCertificateStreamOptions = {},
    callOptions?: Parameters<StoreClient['subscribe']>[1],
  ): AsyncIterable<SimplexStreamBatch<RawSimplexCertificateStreamEntry>> {
    const kinds = [
      SimplexRecordKind.NotarizationByView,
      SimplexRecordKind.FinalizationByView,
      ...(options.includeFinalizedByHeight ? [SimplexRecordKind.FinalizedByHeight] : []),
    ];
    for await (const batch of this.subscribeRaw(kinds, options, callOptions)) {
      yield {
        sequenceNumber: batch.sequenceNumber,
        entries: batch.entries.flatMap((entry) =>
          entry.type === 'header' || entry.type === 'block' ? [] : [entry],
        ),
      };
    }
  }

  async *subscribeCertificates(
    options: SimplexCertificateStreamOptions = {},
    callOptions?: Parameters<StoreClient['subscribe']>[1],
  ): AsyncIterable<SimplexStreamBatch<VerifiedSimplexCertificateStreamEntry<TNotarization, TFinalization>>> {
    for await (const batch of this.subscribeCertificatesRaw(options, callOptions)) {
      const entries: VerifiedSimplexCertificateStreamEntry<TNotarization, TFinalization>[] = [];
      for (const entry of batch.entries) {
        if (entry.type === 'notarization') {
          const certificate = await this.verifyNotarization(entry.notarized, {
            kind: 'notarization',
            source: 'stream',
            key: entry.key,
            value: entry.notarized,
            view: entry.view,
          });
          entries.push({
            type: 'notarization',
            kind: entry.kind,
            key: entry.key,
            view: entry.view,
            raw: entry.notarized,
            certificate,
          });
        } else if (entry.index === 'view') {
          const certificate = await this.verifyFinalization(entry.finalized, {
            kind: 'finalization',
            index: 'view',
            source: 'stream',
            key: entry.key,
            value: entry.finalized,
            view: entry.view,
          });
          entries.push({
            type: 'finalization',
            kind: entry.kind,
            index: 'view',
            key: entry.key,
            view: entry.view,
            raw: entry.finalized,
            certificate,
          });
        } else {
          const certificate = await this.verifyFinalization(entry.finalized, {
            kind: 'finalization',
            index: 'height',
            source: 'stream',
            key: entry.key,
            value: entry.finalized,
            height: entry.height,
          });
          entries.push({
            type: 'finalization',
            kind: entry.kind,
            index: 'height',
            key: entry.key,
            height: entry.height,
            raw: entry.finalized,
            certificate,
          });
        }
      }
      yield {
        sequenceNumber: batch.sequenceNumber,
        entries,
      };
    }
  }

  private async getRaw(key: Uint8Array): Promise<Uint8Array | null> {
    const result = await this.store.get(key);
    return result?.value ?? null;
  }

  private requireVerifier(): SimplexCertificateVerifier<TNotarization, TFinalization> {
    if (!this.verifier) {
      throw new Error('simplex certificate read requires a configured verifier; use the *Raw method for unverified bytes');
    }
    return this.verifier;
  }

  private async verifyNotarization(
    bytes: Uint8Array,
    context: SimplexNotarizationVerificationContext,
  ): Promise<TNotarization> {
    const verified = await this.requireVerifier().verifyNotarization(copyBytes(bytes), context);
    if (!verified) {
      throw new Error('simplex notarization verification failed');
    }
    return verified;
  }

  private async verifyFinalization(
    bytes: Uint8Array,
    context: SimplexFinalizationVerificationContext,
  ): Promise<TFinalization> {
    const verified = await this.requireVerifier().verifyFinalization(copyBytes(bytes), context);
    if (!verified) {
      throw new Error('simplex finalization verification failed');
    }
    return verified;
  }
}
