import initWasm, {
  type InitInput,
  verify_historical_fixed_keyless_append_operations_proof,
  verify_historical_fixed_keyless_append_proof,
  verify_historical_fixed_unordered_update_operations_proof,
  verify_historical_fixed_unordered_update_proof,
  verify_historical_operation_range_proof,
  verify_historical_operations_proof,
  verify_historical_raw_operation_range_proof,
} from './generated/wasm/exoware_qmdb_wasm.js';

export type BytesLike = Uint8Array | string;
export type MerkleFamily = 'mmr' | 'mmb';
export type HashFamily = 'sha256' | 'blake3' | 'crc32c';

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

export interface VerifiedHistoricalMultiProof {
  /**
   * The trusted root supplied to verification. For current-boundary-backed
   * proofs this is the current/global root; for operation-log-only proofs this
   * is the operation-log root.
   */
  root: Uint8Array;
  operations: LocatedOrderedOperation[];
  proofSizeBytes: number;
}

export interface OperationRangeContext {
  tip: bigint;
  startLocation: bigint;
  maxLocations: number;
}

/** Operations at `locations`, strictly ascending and each at most `tip`. */
export interface OperationsContext {
  tip: bigint;
  locations: readonly bigint[];
}

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

/**
 * Operations in request order. `root` is the trusted root supplied to
 * verification; for current-boundary endpoints an ops-root witness binds the
 * proven operation-log root to it.
 */
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

export interface QmdbProofVerifierOptions {
  merkleFamily?: MerkleFamily;
  hashFamily?: HashFamily;
}

/**
 * Initialize the shared WASM instance while fetching proofs. Subsequent calls
 * share the first initialization, including its optional module input.
 */
export function initQmdbWasm(moduleOrPath?: InitInput | Promise<InitInput>): Promise<void> {
  return (wasmReady ??= initWasm(
    moduleOrPath === undefined ? undefined : { module_or_path: moduleOrPath },
  ).then(() => {}));
}

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
  if (value !== 'sha256' && value !== 'blake3' && value !== 'crc32c') {
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

export function assertOperationWindow(request: OperationRangeContext): void {
  assertU64(request.tip, 'tip');
  if (request.tip === 0xffff_ffff_ffff_ffffn) {
    throw new Error('operation tip overflow');
  }
  assertU64(request.startLocation, 'startLocation');
  assertU32(request.maxLocations, 'maxLocations', true);
  if (request.startLocation > request.tip) {
    throw new Error('invalid operation window');
  }
}

const MAX_REQUESTED_LOCATIONS = 1024;

export function assertOperationsRequest(request: OperationsContext): void {
  assertU64(request.tip, 'tip');
  if (request.tip === 0xffff_ffff_ffff_ffffn) {
    throw new Error('operation tip overflow');
  }
  const { locations } = request;
  if (locations.length === 0 || locations.length > MAX_REQUESTED_LOCATIONS) {
    throw new Error(`operations request must have 1 to ${MAX_REQUESTED_LOCATIONS} locations`);
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

/** Sort expectations by location and concatenate their equal-size bytes. */
export function fixedOperationExpectations(
  expected: readonly { location: bigint; bytes: Uint8Array }[],
  label: string,
  tip: bigint,
): { locations: bigint[]; bytes: Uint8Array; size: number } {
  const sorted = [...expected].sort((a, b) =>
    a.location < b.location ? -1 : a.location > b.location ? 1 : 0,
  );
  const locations = sorted.map(({ location }) => location);
  assertOperationsRequest({ tip, locations });
  const size = sorted[0]?.bytes.length ?? 0;
  if (size === 0 || sorted.some(({ bytes }) => bytes.length !== size)) {
    throw new Error(`expected ${label}s must be non-empty and equal in size`);
  }
  const bytes = new Uint8Array(size * sorted.length);
  sorted.forEach((entry, index) => bytes.set(entry.bytes, index * size));
  return { locations, bytes, size };
}

/**
 * Verifies raw HistoricalOperationRangeProof and HistoricalMultiProof protobufs.
 * Roots and request context must come from an authenticated source. Unordered
 * updates prove historical membership, not that a value is the latest for its key.
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

  /** Verify raw operations in a HistoricalOperationRangeProof. */
  async verifyOperationRange(
    proofBytes: Uint8Array,
    request: OperationRangeContext,
    expectedRoot: BytesLike,
  ): Promise<VerifiedRawOperationRangeProof> {
    assertOperationWindow(request);
    await initQmdbWasm();
    const verified = verify_historical_raw_operation_range_proof(
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

  /** Verify and decode a range of variable-length ordered operations. */
  async verifyOrderedOperationRange(
    proofBytes: Uint8Array,
    request: OperationRangeContext,
    expectedRoot: BytesLike,
  ): Promise<VerifiedHistoricalMultiProof> {
    assertOperationWindow(request);
    await initQmdbWasm();
    const verified = verify_historical_operation_range_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      request.tip,
      request.startLocation,
      request.maxLocations,
    ) as Omit<VerifiedHistoricalMultiProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

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
    const verified = verify_historical_fixed_keyless_append_proof(
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
    const verified = verify_historical_fixed_unordered_update_proof(
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

  /** Verify exactly the requested locations in a HistoricalMultiProof. */
  async verifyOperations(
    proofBytes: Uint8Array,
    request: OperationsContext,
    expectedRoot: BytesLike,
  ): Promise<VerifiedRawOperationsProof> {
    assertOperationsRequest(request);
    await initQmdbWasm();
    const verified = verify_historical_operations_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      request.tip,
      BigUint64Array.from(request.locations),
    ) as Omit<VerifiedRawOperationsProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

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
    const verified = verify_historical_fixed_keyless_append_operations_proof(
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
    const verified = verify_historical_fixed_unordered_update_operations_proof(
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
