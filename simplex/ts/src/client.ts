import type { CallOptions } from '@connectrpc/connect';
import {
  Client,
  StoreClient,
  type ClientOptions as SdkClientOptions,
} from '@exowarexyz/sdk';
import {
  SqlClient,
  type DecodedRow,
} from '@exowarexyz/sql';
import initWasm, {
  verify_certified_block,
} from './generated/wasm/exoware_simplex_wasm.js';

export type BytesLike = Uint8Array | string;

export interface WasmCertifiedBlockVerifierOptions {
  identity: BytesLike;
  namespace?: BytesLike;
}

export interface SimplexClientOptions extends SdkClientOptions {
  sqlUrl?: string;
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
  encodedBlock: Uint8Array;
}

export type CertifiedBlockVerifier = (frame: Omit<CertifiedBlockFrame, 'sequenceNumber'>) =>
  | boolean
  | Promise<boolean>;

export interface SimplexSubscribeRequest {
  kind?: 'notarized' | 'finalized';
  sinceSequenceNumber?: bigint;
}

const DEFAULT_NAMESPACE = new TextEncoder().encode('_ALTO');
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
    sqlUrl: _sqlUrl,
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

function requireBigInt(row: DecodedRow, column: string): bigint {
  const value = row.values[column];
  if (typeof value !== 'bigint') {
    throw new Error(`simplex row column ${column} must be bigint`);
  }
  return value;
}

function requireString(row: DecodedRow, column: string): string {
  const value = row.values[column];
  if (typeof value !== 'string') {
    throw new Error(`simplex row column ${column} must be string`);
  }
  return value;
}

function requireBytes(row: DecodedRow, column: string): Uint8Array {
  const value = row.values[column];
  if (!(value instanceof Uint8Array)) {
    throw new Error(`simplex row column ${column} must be bytes`);
  }
  return value;
}

function certifiedBlockFromRow(row: DecodedRow): Omit<CertifiedBlockFrame, 'sequenceNumber'> {
  const kind = requireString(row, 'kind');
  if (kind !== 'notarized' && kind !== 'finalized') {
    throw new Error(`unexpected simplex block kind ${kind}`);
  }
  return {
    kind,
    epoch: requireBigInt(row, 'epoch'),
    view: requireBigInt(row, 'view'),
    height: requireBigInt(row, 'height'),
    blockDigest: requireBytes(row, 'block_digest'),
    encodedCertificate: hexToBytes(requireString(row, 'encoded_certificate_hex')),
    blockKey: requireBytes(row, 'block_key'),
    encodedBlock: new Uint8Array(),
  };
}

function whereFor(request: SimplexSubscribeRequest): string {
  return request.kind ? `kind = '${request.kind}'` : '';
}

export class SimplexClient {
  private readonly sql: SqlClient;
  private readonly store: StoreClient;
  private readonly verifier?: CertifiedBlockVerifier;

  constructor(baseUrl: string, options: SimplexClientOptions = {}) {
    const sdk = sdkOptions(options);
    this.sql = new SqlClient(options.sqlUrl ?? baseUrl, sdk);
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

  async *subscribeCertifiedBlocks(
    request: SimplexSubscribeRequest,
    verifier?: CertifiedBlockVerifier,
    options?: CallOptions,
  ): AsyncIterable<CertifiedBlockFrame> {
    const resolvedVerifier = verifier ?? this.verifier;
    if (!resolvedVerifier) {
      throw new Error('simplex certificate verifier is required');
    }
    const stream = this.sql.subscribe(
      {
        table: 'simplex_blocks',
        whereSql: whereFor(request),
        sinceSequenceNumber: request.sinceSequenceNumber,
      },
      options,
    );

    for await (const frame of stream) {
      for (const row of frame.rows) {
        const partial = certifiedBlockFromRow(row);
        const block = await this.store.get(partial.blockKey, frame.sequenceNumber);
        if (!block) {
          throw new Error(
            `simplex block ${bytesToHex(partial.blockDigest)} missing at ${bytesToHex(partial.blockKey)}`,
          );
        }
        const candidate = {
          ...partial,
          encodedBlock: block.value,
        };
        if (!(await resolvedVerifier(candidate))) {
          throw new Error(
            `simplex ${candidate.kind} certificate failed verification for block ${bytesToHex(candidate.blockDigest)}`,
          );
        }
        yield {
          sequenceNumber: frame.sequenceNumber,
          ...candidate,
        };
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
    const result = await this.sql.query(
      `SELECT * FROM simplex_blocks WHERE kind = '${kind}' ORDER BY epoch DESC, view DESC LIMIT 1`,
    );
    const row = result.rows[0];
    if (!row) {
      return undefined;
    }
    const partial = certifiedBlockFromRow(row);
    const block = await this.store.get(partial.blockKey);
    if (!block) {
      throw new Error(
        `simplex block ${bytesToHex(partial.blockDigest)} missing at ${bytesToHex(partial.blockKey)}`,
      );
    }
    const candidate = {
      ...partial,
      encodedBlock: block.value,
    };
    if (!(await resolvedVerifier(candidate))) {
      throw new Error(
        `simplex ${candidate.kind} certificate failed verification for block ${bytesToHex(candidate.blockDigest)}`,
      );
    }
    return {
      sequenceNumber: 0n,
      ...candidate,
    };
  }
}
