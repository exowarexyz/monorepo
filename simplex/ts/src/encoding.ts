export type BytesLike = Uint8Array | string;
export type U64Like = bigint | number | string;

export enum SimplexRecordKind {
  HeaderByDigest = 1,
  BlockByDigest = 2,
  NotarizationByRound = 3,
  FinalizationByRound = 4,
  FinalizedByHeight = 5,
}

export interface SimplexBlockData {
  header: Uint8Array;
  body: Uint8Array;
}

const HEADER_LENGTH_BYTES = 4;

export function copyBytes(bytes: Uint8Array): Uint8Array {
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
  const headerBytes = typeof header === 'string' ? hexToBytes(header) : header;
  const bodyBytes = typeof body === 'string' ? hexToBytes(body) : body;
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
  const bigintValue = typeof value === 'number'
    ? safeIntegerToBigInt(value)
    : typeof value === 'bigint'
      ? value
      : BigInt(value);
  if (bigintValue < 0n || bigintValue > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError(`u64 out of range: ${value}`);
  }
  return bigintValue;
}

function safeIntegerToBigInt(value: number): bigint {
  if (!Number.isSafeInteger(value)) {
    throw new RangeError(`u64 number must be a safe integer: ${value}`);
  }
  return BigInt(value);
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
  const out = new Uint8Array(1 + suffix.length);
  out[0] = kind;
  out.set(suffix, 1);
  return out;
}

export function headerByDigestKey(digest: BytesLike): Uint8Array {
  return keyFromParts(SimplexRecordKind.HeaderByDigest, toSimplexBytes(digest));
}

export function blockByDigestKey(digest: BytesLike): Uint8Array {
  return keyFromParts(SimplexRecordKind.BlockByDigest, toSimplexBytes(digest));
}

function roundKey(kind: SimplexRecordKind, epoch: U64Like, view: U64Like): Uint8Array {
  const suffix = new Uint8Array(16);
  suffix.set(u64Bytes(epoch));
  suffix.set(u64Bytes(view), 8);
  return keyFromParts(kind, suffix);
}

export function notarizationByRoundKey(epoch: U64Like, view: U64Like): Uint8Array {
  return roundKey(SimplexRecordKind.NotarizationByRound, epoch, view);
}

export function finalizationByRoundKey(epoch: U64Like, view: U64Like): Uint8Array {
  return roundKey(SimplexRecordKind.FinalizationByRound, epoch, view);
}

export function finalizedByHeightKey(height: U64Like): Uint8Array {
  return keyFromParts(SimplexRecordKind.FinalizedByHeight, u64Bytes(height));
}

export function rangeForKind(kind: SimplexRecordKind): { start: Uint8Array; end: Uint8Array } {
  return {
    start: new Uint8Array([kind]),
    end: new Uint8Array([kind + 1]),
  };
}

function u64At(bytes: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let i = offset; i < offset + 8; i++) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return value;
}

export function roundFromKey(key: Uint8Array): { epoch: bigint; view: bigint } {
  if (key.length !== 17) {
    throw new Error(`invalid simplex round key length ${key.length}`);
  }
  return { epoch: u64At(key, 1), view: u64At(key, 9) };
}

export function u64FromKey(key: Uint8Array): bigint {
  if (key.length !== 9) {
    throw new Error(`invalid simplex u64 key length ${key.length}`);
  }
  return u64At(key, 1);
}
