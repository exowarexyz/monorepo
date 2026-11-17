import initWasm, {
  type InitInput,
  verify_fixed_keyless_append_operations_proof,
  verify_fixed_keyless_append_proof,
  verify_fixed_unordered_update_operations_proof,
  verify_fixed_unordered_update_proof,
  verify_operation_range_proof,
  verify_operations_proof,
  verify_raw_operation_range_proof,
} from './generated/wasm/exoware_qmdb_wasm.js';

export type BytesLike = Uint8Array | string;
export type MerkleFamily = 'mmr' | 'mmb';
export type HashFamily = 'sha256' | 'blake3';

export type OrderedOperation =
  | {
      type: 'update';
      key: Uint8Array;
      value: Uint8Array;
      nextKey: Uint8Array;
    }
  | {
      type: 'delete';
      key: Uint8Array;
    }
  | {
      type: 'commit_floor';
      value?: Uint8Array;
      floorLocation: bigint;
    };

export interface LocatedOrderedOperation {
  location: bigint;
  operation: OrderedOperation;
}

export interface VerifiedOperationMultiProof {
  /** The trusted root supplied to verification. */
  root: Uint8Array;
  operations: LocatedOrderedOperation[];
  proofSizeBytes: number;
}

/** The `min(maxLocations, tip - startLocation + 1)` operations from `startLocation` at `tip`. */
export interface OperationRangeContext {
  tip: bigint;
  startLocation: bigint;
  maxLocations: number;
}

/** A nonempty set of `locations`, strictly ascending and each at most `tip`. */
export interface OperationsContext {
  tip: bigint;
  locations: readonly bigint[];
}

/** The tip location of a multi-proof whose locations come from its expectations. */
export interface OperationsTipContext {
  tip: bigint;
}

export interface LocatedRawOperation {
  location: bigint;
  encodedOperation: Uint8Array;
}

export interface VerifiedRawOperationRangeProof {
  root: Uint8Array;
  operations: LocatedRawOperation[];
  proofSizeBytes: number;
}

/** Operations in request order. `root` is the trusted root supplied to verification. */
export interface VerifiedRawOperationsProof {
  root: Uint8Array;
  operations: LocatedRawOperation[];
  proofSizeBytes: number;
}

export interface VerifiedFixedKeylessAppend {
  location: bigint;
  value: Uint8Array;
}

/** Appends in ascending location order. `root` is as in {@link VerifiedRawOperationsProof}. */
export interface VerifiedFixedKeylessAppendsProof {
  root: Uint8Array;
  operations: VerifiedFixedKeylessAppend[];
  proofSizeBytes: number;
}

export interface VerifiedFixedUnorderedUpdate {
  location: bigint;
  key: Uint8Array;
  value: Uint8Array;
}

/** Updates in ascending location order. `root` is as in {@link VerifiedRawOperationsProof}. */
export interface VerifiedFixedUnorderedUpdatesProof {
  root: Uint8Array;
  operations: VerifiedFixedUnorderedUpdate[];
  proofSizeBytes: number;
}

export interface VerifiedFixedKeylessAppendProof {
  location: bigint;
  value: Uint8Array;
  root: Uint8Array;
  proofSizeBytes: number;
  operationCount: number;
}

export interface VerifiedFixedUnorderedUpdateProof {
  location: bigint;
  key: Uint8Array;
  value: Uint8Array;
  root: Uint8Array;
  proofSizeBytes: number;
  operationCount: number;
}

/** Merkle and hash families used by the source database. */
export interface QmdbProofVerifierOptions {
  /** Merkle family of the source database. Defaults to `mmr`. */
  merkleFamily?: MerkleFamily;

  /** Hash family of the source database. Defaults to `sha256`. */
  hashFamily?: HashFamily;
}

/**
 * Initialize the shared WASM module with the first call's input.
 * All calls share its promise, including initialization failures.
 */
export function initQmdbWasm(moduleOrPath?: InitInput | Promise<InitInput>): Promise<void> {
  return (wasmReady ??= initWasm(
    moduleOrPath === undefined ? undefined : { module_or_path: moduleOrPath },
  ).then(() => {}));
}

// Shared by every verifier and client so the module is instantiated once.
let wasmReady: Promise<void> | undefined;

export function toBytes(value: BytesLike): Uint8Array {
  return typeof value === 'string' ? new TextEncoder().encode(value) : value;
}

export function assertMerkleFamily(value: MerkleFamily, label: string): void {
  if (value !== 'mmr' && value !== 'mmb') {
    throw new Error(`${label} unsupported Merkle family ${String(value)}`);
  }
}

export function assertHashFamily(value: HashFamily, label: string): void {
  if (value !== 'sha256' && value !== 'blake3') {
    throw new Error(`${label} unsupported hash family ${String(value)}`);
  }
}

export function assertU32(value: number, label: string, nonzero = false): void {
  if (!Number.isInteger(value) || value < (nonzero ? 1 : 0) || value > 0xffff_ffff) {
    throw new Error(`${label} must fit in ${nonzero ? 'a positive' : 'an unsigned'} 32-bit integer`);
  }
}

export function assertU64(value: bigint, label: string): void {
  if (typeof value !== 'bigint' || value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`${label} must be an unsigned 64-bit bigint`);
  }
}

/** Reject a range window that no response can serve, before any proof is decoded. */
export function assertOperationWindow(request: OperationRangeContext): void {
  // The proven log holds `tip + 1` operations, so that count must fit in 64 bits.
  assertU64(request.tip, 'tip');
  if (request.tip === 0xffff_ffff_ffff_ffffn) {
    throw new Error('operation tip overflow');
  }

  // The window must start at or below the tip and cover at least one location.
  assertU64(request.startLocation, 'startLocation');
  assertU32(request.maxLocations, 'maxLocations', true);
  if (request.startLocation > request.tip) {
    throw new Error('invalid operation window');
  }
}

/** Reject a location set that no response can serve, before any proof is decoded. */
export function assertOperationLocations(request: OperationsContext): void {
  // The proven log holds `tip + 1` operations, so that count must fit in 64 bits.
  assertU64(request.tip, 'tip');
  if (request.tip === 0xffff_ffff_ffff_ffffn) {
    throw new Error('operation tip overflow');
  }

  // Locations must be a nonempty, strictly ascending set at or below the tip.
  const { locations } = request;
  if (locations.length === 0) {
    throw new Error('operations request must contain at least one location');
  }
  locations.forEach((location, index) => {
    assertU64(location, 'location');
    if (index > 0 && location <= locations[index - 1]) {
      throw new Error('operations request locations must be strictly ascending');
    }
  });
  if (locations[locations.length - 1] > request.tip) {
    throw new Error('operations request location is above tip');
  }
}

/** Pack equal-size expectations by ascending location after validating them at `tip`. */
export function fixedOperationExpectations(
  expected: readonly { location: bigint; bytes: Uint8Array }[],
  label: string,
  tip: bigint,
): { locations: bigint[]; bytes: Uint8Array; size: number } {
  // Multi-proof locations must be strictly ascending, so sort before validation.
  const sorted = [...expected].sort((a, b) =>
    a.location < b.location ? -1 : a.location > b.location ? 1 : 0,
  );
  const locations = sorted.map(({ location }) => location);
  assertOperationLocations({ tip, locations });

  // WASM receives every expectation in one buffer of equal-size entries.
  const size = sorted[0]?.bytes.length ?? 0;
  if (size === 0 || sorted.some(({ bytes }) => bytes.length !== size)) {
    throw new Error(`expected ${label}s must be non-empty and equal in size`);
  }
  const bytes = new Uint8Array(size * sorted.length);
  sorted.forEach((entry, index) => bytes.set(entry.bytes, index * size));
  return { locations, bytes, size };
}

/**
 * Verify operation-log membership against a trusted root and expected request context.
 *
 * Range and single-operation methods accept serialized `OperationRangeProof` protobuf
 * messages. `verifyOperations` and the `*Many` methods accept serialized `OperationMultiProof`
 * protobuf messages.
 *
 * Unordered updates prove log membership, not that a value is the latest for its key.
 */
export class QmdbProofVerifier {
  private readonly merkleFamily: MerkleFamily;
  private readonly hashFamily: HashFamily;

  constructor(options: QmdbProofVerifierOptions = {}) {
    const { merkleFamily = 'mmr', hashFamily = 'sha256' } = options;
    assertMerkleFamily(merkleFamily, 'qmdb proof verifier');
    assertHashFamily(hashFamily, 'qmdb proof verifier');
    this.merkleFamily = merkleFamily;
    this.hashFamily = hashFamily;
  }

  /** Verify the requested window of encoded operations. */
  async verifyOperationRange(
    proofBytes: Uint8Array,
    request: OperationRangeContext,
    expectedRoot: BytesLike,
  ): Promise<VerifiedRawOperationRangeProof> {
    assertOperationWindow(request);
    await initQmdbWasm();

    const verified = verify_raw_operation_range_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      request.tip,
      request.startLocation,
      request.maxLocations,
    ) as Omit<VerifiedRawOperationRangeProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

  /** Verify and decode the requested window of variable-length ordered operations. */
  async verifyOrderedOperationRange(
    proofBytes: Uint8Array,
    request: OperationRangeContext,
    expectedRoot: BytesLike,
  ): Promise<VerifiedOperationMultiProof> {
    assertOperationWindow(request);
    await initQmdbWasm();

    const verified = verify_operation_range_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      request.tip,
      request.startLocation,
      request.maxLocations,
    ) as Omit<VerifiedOperationMultiProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

  /** Verify an append of `expectedValue` at `expectedLocation`. */
  async verifyFixedKeylessAppend(
    proofBytes: Uint8Array,
    request: OperationRangeContext,
    expectedRoot: BytesLike,
    expectedLocation: bigint,
    expectedValue: BytesLike,
  ): Promise<VerifiedFixedKeylessAppendProof> {
    assertU64(expectedLocation, 'expectedLocation');
    assertOperationWindow(request);
    await initQmdbWasm();

    const verified = verify_fixed_keyless_append_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      expectedLocation,
      toBytes(expectedValue),
      request.tip,
      request.startLocation,
      request.maxLocations,
    ) as Omit<VerifiedFixedKeylessAppendProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

  /** Verify an update of `expectedKey` at `expectedLocation` and return its value. */
  async verifyFixedUnorderedUpdate(
    proofBytes: Uint8Array,
    request: OperationRangeContext,
    expectedRoot: BytesLike,
    expectedLocation: bigint,
    expectedKey: BytesLike,
    valueSize: number,
  ): Promise<VerifiedFixedUnorderedUpdateProof> {
    assertU64(expectedLocation, 'expectedLocation');
    assertU32(valueSize, 'valueSize');
    assertOperationWindow(request);
    await initQmdbWasm();

    const verified = verify_fixed_unordered_update_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      expectedLocation,
      toBytes(expectedKey),
      valueSize,
      request.tip,
      request.startLocation,
      request.maxLocations,
    ) as Omit<VerifiedFixedUnorderedUpdateProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

  /** Verify exactly the requested operation locations. */
  async verifyOperations(
    proofBytes: Uint8Array,
    request: OperationsContext,
    expectedRoot: BytesLike,
  ): Promise<VerifiedRawOperationsProof> {
    assertOperationLocations(request);
    await initQmdbWasm();

    const verified = verify_operations_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      request.tip,
      BigUint64Array.from(request.locations),
    ) as Omit<VerifiedRawOperationsProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

  /** Verify that each expected value was appended at its location. */
  async verifyFixedKeylessAppendMany(
    proofBytes: Uint8Array,
    request: OperationsTipContext,
    expectedRoot: BytesLike,
    expected: readonly { location: bigint; value: BytesLike }[],
  ): Promise<VerifiedFixedKeylessAppendsProof> {
    const { locations, bytes, size } = fixedOperationExpectations(
      expected.map(({ location, value }) => ({ location, bytes: toBytes(value) })),
      'value',
      request.tip,
    );
    await initQmdbWasm();

    const verified = verify_fixed_keyless_append_operations_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      request.tip,
      BigUint64Array.from(locations),
      bytes,
      size,
    ) as Omit<VerifiedFixedKeylessAppendsProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

  /** Verify that each expected key was updated at its location. */
  async verifyFixedUnorderedUpdateMany(
    proofBytes: Uint8Array,
    request: OperationsTipContext,
    expectedRoot: BytesLike,
    expected: readonly { location: bigint; key: BytesLike }[],
    valueSize: number,
  ): Promise<VerifiedFixedUnorderedUpdatesProof> {
    assertU32(valueSize, 'valueSize');
    const { locations, bytes, size } = fixedOperationExpectations(
      expected.map(({ location, key }) => ({ location, bytes: toBytes(key) })),
      'key',
      request.tip,
    );
    await initQmdbWasm();

    const verified = verify_fixed_unordered_update_operations_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      request.tip,
      BigUint64Array.from(locations),
      bytes,
      size,
      valueSize,
    ) as Omit<VerifiedFixedUnorderedUpdatesProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }
}
