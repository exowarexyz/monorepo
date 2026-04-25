import { fromBinary } from '@bufbuild/protobuf';
import type { CallOptions } from '@connectrpc/connect';
import {
  Client,
  SimplexBlockKind,
  SimplexCertifiedBlockSchema,
  StoreClient,
  StoreKeyPrefix,
  TraversalMode,
  type ClientOptions as SdkClientOptions,
  type SimplexCertifiedBlock,
} from '@exowarexyz/sdk';
import initWasm, {
  verify_certified_block,
} from './generated/wasm/exoware_simplex_wasm.js';

export type BytesLike = Uint8Array | string;

export interface WasmCertifiedBlockVerifierOptions {
  identity: BytesLike;
  namespace?: BytesLike;
}

export interface SimplexClientOptions extends SdkClientOptions {
  storeUrl?: string;
  verifier?: CertifiedBlockVerifier;
  identity?: BytesLike;
  namespace?: BytesLike;
}

export interface CertifiedBlockFrame {
  sequenceNumber: bigint;
  kind: 'notarized' | 'finalized';
  epoch: bigint;
  view: bigint;
  height: bigint;
  blockDigest: Uint8Array;
  encodedCertificate: Uint8Array;
  blockKey: Uint8Array;
  blockSize: bigint;
  encodedBlock: Uint8Array;
}

export type CertifiedBlockVerifier = (frame: Omit<CertifiedBlockFrame, 'sequenceNumber'>) =>
  | boolean
  | Promise<boolean>;

export interface SimplexSubscribeRequest {
  kind?: 'notarized' | 'finalized';
  sinceSequenceNumber?: bigint;
}

export interface SimplexLookupOptions {
  epoch?: bigint;
  verifier?: CertifiedBlockVerifier;
}

const DEFAULT_NAMESPACE = new TextEncoder().encode('_ALTO');
export const SIMPLEX_CERTIFIED_BLOCK_RESERVED_BITS = 4;
export const SIMPLEX_FINALIZED_BLOCK_HEIGHT_FAMILY = 12;
export const SIMPLEX_CERTIFIED_BLOCK_VIEW_FAMILY = 13;
export const SIMPLEX_CERTIFIED_BLOCK_FAMILY = 14;
export const SIMPLEX_RAW_BLOCK_FAMILY = 15;
const FINALIZED_BLOCK_HEIGHT_PREFIX = new StoreKeyPrefix(
  SIMPLEX_CERTIFIED_BLOCK_RESERVED_BITS,
  SIMPLEX_FINALIZED_BLOCK_HEIGHT_FAMILY,
);
const CERTIFIED_BLOCK_VIEW_PREFIX = new StoreKeyPrefix(
  SIMPLEX_CERTIFIED_BLOCK_RESERVED_BITS,
  SIMPLEX_CERTIFIED_BLOCK_VIEW_FAMILY,
);
const CERTIFIED_BLOCK_PREFIX = new StoreKeyPrefix(
  SIMPLEX_CERTIFIED_BLOCK_RESERVED_BITS,
  SIMPLEX_CERTIFIED_BLOCK_FAMILY,
);
const RAW_BLOCK_PREFIX = new StoreKeyPrefix(
  SIMPLEX_CERTIFIED_BLOCK_RESERVED_BITS,
  SIMPLEX_RAW_BLOCK_FAMILY,
);
const STREAM_PAYLOAD_REGEX = '(?s-u).*';
const U64_MAX = (1n << 64n) - 1n;
let wasmReady: Promise<unknown> | undefined;

function ensureWasm(): Promise<unknown> {
  return wasmReady ?? (wasmReady = initWasm());
}

function toTextBytes(value: BytesLike): Uint8Array {
  return typeof value === 'string' ? new TextEncoder().encode(value) : value;
}

export function hexToBytes(hex: string): Uint8Array {
  const trimmed = hex.trim();
  const normalized = trimmed.startsWith('0x') || trimmed.startsWith('0X')
    ? trimmed.slice(2)
    : trimmed;
  if (normalized.length % 2 !== 0) {
    throw new Error(`invalid hex length ${normalized.length}`);
  }
  if (normalized.length > 0 && !/^[0-9a-fA-F]+$/.test(normalized)) {
    throw new Error('invalid hex string');
  }
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function identityToBytes(value: BytesLike): Uint8Array {
  return typeof value === 'string' ? hexToBytes(value) : value;
}

function sdkOptions(options: SimplexClientOptions): SdkClientOptions {
  const {
    storeUrl: _storeUrl,
    verifier: _verifier,
    identity: _identity,
    namespace: _namespace,
    ...sdk
  } = options;
  return sdk;
}

export function wasmCertifiedBlockVerifier(
  options: WasmCertifiedBlockVerifierOptions,
): CertifiedBlockVerifier {
  const identity = identityToBytes(options.identity);
  const namespace = options.namespace ? toTextBytes(options.namespace) : DEFAULT_NAMESPACE;
  return async (frame) => {
    await ensureWasm();
    return verify_certified_block(
      frame.kind,
      namespace,
      identity,
      frame.encodedCertificate,
      frame.blockDigest,
    );
  };
}

function frameKindFromProto(kind: SimplexBlockKind): CertifiedBlockFrame['kind'] {
  switch (kind) {
    case SimplexBlockKind.NOTARIZED:
      return 'notarized';
    case SimplexBlockKind.FINALIZED:
      return 'finalized';
    default:
      throw new Error(`unexpected simplex block kind ${kind}`);
  }
}

function keyByteForFrameKind(kind: CertifiedBlockFrame['kind']): number {
  return kind === 'notarized' ? 0 : 1;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  for (let i = 0; i < left.byteLength; i++) {
    if (left[i] !== right[i]) {
      return false;
    }
  }
  return true;
}

function u64Bytes(value: bigint, label: string): Uint8Array {
  if (value < 0n || value > U64_MAX) {
    throw new RangeError(`${label} must fit in uint64`);
  }
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function incrementBytes(value: Uint8Array): Uint8Array | undefined {
  const out = new Uint8Array(value);
  for (let i = out.byteLength - 1; i >= 0; i--) {
    if (out[i] !== 0xff) {
      out[i] += 1;
      out.fill(0, i + 1);
      return out;
    }
  }
  return undefined;
}

function exactPrefixRange(
  prefix: StoreKeyPrefix,
  payloadPrefix: Uint8Array,
): { start: Uint8Array; end: Uint8Array } {
  const end = incrementBytes(payloadPrefix);
  if (!end) {
    throw new RangeError('lookup prefix upper bound overflow');
  }
  return prefix.encodeRange(payloadPrefix, end);
}

function expectedBlockKey(blockDigest: Uint8Array): Uint8Array {
  return RAW_BLOCK_PREFIX.encodeKey(blockDigest);
}

function certifiedBlockFromValue(value: Uint8Array): Omit<CertifiedBlockFrame, 'sequenceNumber'> {
  const decoded = fromBinary(
    SimplexCertifiedBlockSchema as unknown as Parameters<typeof fromBinary>[0],
    value,
  ) as SimplexCertifiedBlock;
  return {
    kind: frameKindFromProto(decoded.kind),
    epoch: decoded.epoch,
    view: decoded.view,
    height: decoded.height,
    blockDigest: decoded.blockDigest,
    encodedCertificate: decoded.encodedCertificate,
    blockKey: decoded.blockKey,
    blockSize: decoded.blockSize,
    encodedBlock: new Uint8Array(),
  };
}

function certifiedBlockRange(
  kind?: CertifiedBlockFrame['kind'],
): { start: Uint8Array; end: Uint8Array } {
  if (!kind) {
    return CERTIFIED_BLOCK_PREFIX.prefixBounds();
  }
  const start = new Uint8Array([keyByteForFrameKind(kind)]);
  const end = new Uint8Array([keyByteForFrameKind(kind) + 1]);
  return CERTIFIED_BLOCK_PREFIX.encodeRange(start, end);
}

function certifiedBlockViewRange(
  kind: CertifiedBlockFrame['kind'],
  epoch: bigint,
  view: bigint,
): { start: Uint8Array; end: Uint8Array } {
  return exactPrefixRange(
    CERTIFIED_BLOCK_VIEW_PREFIX,
    concatBytes(
      new Uint8Array([keyByteForFrameKind(kind)]),
      u64Bytes(epoch, 'epoch'),
      u64Bytes(view, 'view'),
    ),
  );
}

function finalizedBlockHeightRange(
  epoch: bigint,
  height: bigint,
): { start: Uint8Array; end: Uint8Array } {
  return exactPrefixRange(
    FINALIZED_BLOCK_HEIGHT_PREFIX,
    concatBytes(u64Bytes(epoch, 'epoch'), u64Bytes(height, 'height')),
  );
}

export class SimplexClient {
  private readonly store: StoreClient;
  private readonly verifier?: CertifiedBlockVerifier;

  constructor(baseUrl: string, options: SimplexClientOptions = {}) {
    const sdk = sdkOptions(options);
    this.store = new Client(options.storeUrl ?? baseUrl, sdk).store();
    this.verifier = options.verifier ?? (
      options.identity
        ? wasmCertifiedBlockVerifier({
            identity: options.identity,
            namespace: options.namespace,
          })
        : undefined
    );
  }

  async health(): Promise<boolean> {
    await this.store.query(undefined, undefined, 1);
    return true;
  }

  private async hydrateAndVerify(
    partial: Omit<CertifiedBlockFrame, 'sequenceNumber'>,
    sequenceNumber: bigint,
    verifier: CertifiedBlockVerifier,
  ): Promise<CertifiedBlockFrame> {
    const expectedKey = expectedBlockKey(partial.blockDigest);
    if (!bytesEqual(partial.blockKey, expectedKey)) {
      throw new Error(
        `simplex block key ${bytesToHex(partial.blockKey)} does not match digest ${bytesToHex(partial.blockDigest)}`,
      );
    }
    const block = await this.store.get(
      partial.blockKey,
      sequenceNumber > 0n ? sequenceNumber : undefined,
    );
    if (!block) {
      throw new Error(
        `simplex block ${bytesToHex(partial.blockDigest)} missing at ${bytesToHex(partial.blockKey)}`,
      );
    }
    const candidate = {
      ...partial,
      encodedBlock: block.value,
    };
    if (!(await verifier(candidate))) {
      throw new Error(
        `simplex ${candidate.kind} certificate failed verification for block ${bytesToHex(candidate.blockDigest)}`,
      );
    }
    return {
      sequenceNumber,
      ...candidate,
    };
  }

  private async queryOneCertifiedBlock(
    range: { start: Uint8Array; end: Uint8Array },
    verifier: CertifiedBlockVerifier,
  ): Promise<CertifiedBlockFrame | undefined> {
    const result = await this.store.query(
      range.start,
      range.end,
      1,
      4096,
      TraversalMode.REVERSE,
    );
    const item = result.results[0];
    if (!item) {
      return undefined;
    }
    return this.hydrateAndVerify(certifiedBlockFromValue(item.value), 0n, verifier);
  }

  async *subscribeCertifiedBlocks(
    request: SimplexSubscribeRequest,
    verifier?: CertifiedBlockVerifier,
    options?: CallOptions,
  ): AsyncIterable<CertifiedBlockFrame> {
    const resolvedVerifier = verifier ?? this.verifier;
    if (!resolvedVerifier) {
      throw new Error('simplex certificate verifier is required');
    }
    const stream = this.store.subscribe(
      {
        matchKeys: [
          {
            reservedBits: SIMPLEX_CERTIFIED_BLOCK_RESERVED_BITS,
            prefix: SIMPLEX_CERTIFIED_BLOCK_FAMILY,
            payloadRegex: STREAM_PAYLOAD_REGEX,
          },
        ],
        sinceSequenceNumber: request.sinceSequenceNumber,
      },
      options,
    );

    for await (const batch of stream) {
      for (const entry of batch.entries) {
        const partial = certifiedBlockFromValue(entry.value);
        if (request.kind && partial.kind !== request.kind) {
          continue;
        }
        yield await this.hydrateAndVerify(partial, batch.sequenceNumber, resolvedVerifier);
      }
    }
  }

  async latestCertifiedBlock(
    kind: 'notarized' | 'finalized',
    verifier?: CertifiedBlockVerifier,
  ): Promise<CertifiedBlockFrame | undefined> {
    const resolvedVerifier = verifier ?? this.verifier;
    if (!resolvedVerifier) {
      throw new Error('simplex certificate verifier is required');
    }
    const range = certifiedBlockRange(kind);
    return this.queryOneCertifiedBlock(range, resolvedVerifier);
  }

  async certifiedBlockByView(
    kind: 'notarized' | 'finalized',
    view: bigint,
    options: SimplexLookupOptions = {},
  ): Promise<CertifiedBlockFrame | undefined> {
    const resolvedVerifier = options.verifier ?? this.verifier;
    if (!resolvedVerifier) {
      throw new Error('simplex certificate verifier is required');
    }
    const epoch = options.epoch ?? 0n;
    const frame = await this.queryOneCertifiedBlock(
      certifiedBlockViewRange(kind, epoch, view),
      resolvedVerifier,
    );
    if (frame && (frame.kind !== kind || frame.epoch !== epoch || frame.view !== view)) {
      throw new Error('simplex certified block response does not match view query');
    }
    return frame;
  }

  async notarizedBlockByView(
    view: bigint,
    options: SimplexLookupOptions = {},
  ): Promise<CertifiedBlockFrame | undefined> {
    return this.certifiedBlockByView('notarized', view, options);
  }

  async finalizedBlockByView(
    view: bigint,
    options: SimplexLookupOptions = {},
  ): Promise<CertifiedBlockFrame | undefined> {
    return this.certifiedBlockByView('finalized', view, options);
  }

  async finalizedBlockByHeight(
    height: bigint,
    options: SimplexLookupOptions = {},
  ): Promise<CertifiedBlockFrame | undefined> {
    const resolvedVerifier = options.verifier ?? this.verifier;
    if (!resolvedVerifier) {
      throw new Error('simplex certificate verifier is required');
    }
    const epoch = options.epoch ?? 0n;
    const frame = await this.queryOneCertifiedBlock(
      finalizedBlockHeightRange(epoch, height),
      resolvedVerifier,
    );
    if (frame && (frame.kind !== 'finalized' || frame.epoch !== epoch || frame.height !== height)) {
      throw new Error('simplex finalized block response does not match height query');
    }
    return frame;
  }
}
