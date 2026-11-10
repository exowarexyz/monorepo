import { create, toBinary, type MessageInitShape } from '@bufbuild/protobuf';
import {
  createClient,
  type CallOptions,
  type Client as ConnectClient,
} from '@connectrpc/connect';
import {
  createTransport,
  type StoreClientOptions,
} from '@exowarexyz/sdk';
import {
  GetManyRequestSchema,
  GetRequestSchema,
} from './generated/proto/qmdb/v1/key_lookup_pb.js';
import { GetRangeRequestSchema } from './generated/proto/qmdb/v1/key_range_pb.js';
import {
  GetOperationRangeRequestSchema,
  GetOperationsRequestSchema,
  SubscribeRequestSchema,
} from './generated/proto/qmdb/v1/operation_log_pb.js';
import { GetCurrentOperationRangeRequestSchema } from './generated/proto/qmdb/v1/current_operation_pb.js';
import {
  ProofBytesCurrentOperationService,
  ProofBytesKeyLookupService,
  ProofBytesOperationLogService,
  ProofBytesOrderedKeyRangeService,
} from './proof-bytes.js';
import {
  FilterSchema,
  type Filter,
} from './generated/proto/common/v1/kv_pb.js';
import {
  decode_operation_multi_proof_operations,
  encode_vec_key,
  verify_current_operation_range_proof,
  verify_key_value_proof,
  verify_key_lookup_proof,
  verify_key_range_proof,
} from './generated/wasm/exoware_qmdb_wasm.js';

import {
  initQmdbWasm,
  QmdbProofVerifier,
  toBytes,
  assertMerkleFamily,
  assertHashFamily,
  assertU32,
  assertU64,
  assertOperationWindow,
  assertOperationLocations,
  fixedOperationExpectations,
  type BytesLike,
  type MerkleFamily,
  type HashFamily,
  type OrderedOperation,
  type LocatedOrderedOperation,
  type VerifiedOrderedOperationRange,
  type VerifiedRawOperationRange,
  type VerifiedRawOperations,
  type VerifiedFixedKeylessAppends,
  type VerifiedFixedUnorderedUpdates,
  type VerifiedFixedKeylessAppend,
  type VerifiedFixedUnorderedUpdate,
  type OperationRangeContext,
  type OperationsContext,
  type OperationsTipContext,
} from './verification.js';

export type {
  BytesLike,
  MerkleFamily,
  HashFamily,
  OrderedOperation,
  LocatedOrderedOperation,
  VerifiedOrderedOperationRange,
  LocatedRawOperation,
  VerifiedRawOperationRange,
  VerifiedRawOperations,
  FixedKeylessAppend,
  VerifiedFixedKeylessAppends,
  FixedUnorderedUpdate,
  VerifiedFixedUnorderedUpdates,
  VerifiedFixedKeylessAppend,
  VerifiedFixedUnorderedUpdate,
} from './verification.js';

export interface OperationRangeRequest extends OperationRangeContext {
  minSequenceNumber?: bigint;
}

export interface OperationsRequest extends OperationsContext {
  minSequenceNumber?: bigint;
}

export interface OperationsTipRequest extends OperationsTipContext {
  minSequenceNumber?: bigint;
}

export interface VerifiedCurrentOperationRange {
  operations: LocatedOrderedOperation[];
  proofSizeBytes: number;
}

export interface VerifiedKeyValue {
  location: bigint;
  operation: OrderedOperation;
  proofSizeBytes: number;
}

export type VerifiedKeyLookup =
  | {
      type: 'hit';
      key: Uint8Array;
      location: bigint;
      operation: OrderedOperation;
    }
  | {
      type: 'miss';
      key: Uint8Array;
    };

export interface VerifiedKeyLookups {
  results: VerifiedKeyLookup[];
  proofSizeBytes: number;
}

export interface VerifiedKeyRangeEntry {
  key: Uint8Array;
  location: bigint;
  operation: OrderedOperation;
}

export interface VerifiedKeyRange {
  entries: VerifiedKeyRangeEntry[];
  nextStartKey: Uint8Array | null;
  proofSizeBytes: number;
}

/**
 * One subscription frame. Its operations are decoded and internally consistent
 * but not yet checked against a trusted root. Compare `root` with the trusted
 * root for `tip` before using them. `root` is decoded from the frame's proof.
 * When the proof includes an ops-root witness, it is the current root
 * reconstructed from that witness. Otherwise it is the embedded operation-log
 * root.
 */
export interface OrderedSubscribeFrame {
  resumeSequenceNumber: bigint;
  tip: bigint;
  root: Uint8Array;
  operations: LocatedOrderedOperation[];
  proofSizeBytes: number;
}

/**
 * The qmdb clients always use binary protobuf and ignore `useBinaryFormat`.
 * They hand each proof to wasm as the bytes that arrived, which JSON can't
 * carry.
 */
export type QmdbOrderedClientOptions = StoreClientOptions & {
  merkleFamily?: MerkleFamily;
  hashFamily?: HashFamily;
  currentChunkSize?: number;
};

/** Always uses binary protobuf, like {@link QmdbOrderedClientOptions}. */
export type QmdbLogClientOptions = StoreClientOptions & {
  merkleFamily?: MerkleFamily;
  hashFamily?: HashFamily;
};

function keyId(key: Uint8Array): string {
  return Array.from(key).join(',');
}

function assertDistinctKeys(keys: readonly Uint8Array[]): void {
  const seen = new Set<string>();
  for (const key of keys) {
    const id = keyId(key);
    if (seen.has(id)) {
      throw new Error('qmdb getMany duplicate key');
    }
    seen.add(id);
  }
}

function assertOptionalMinSequenceNumber(minSequenceNumber?: bigint): void {
  if (minSequenceNumber !== undefined) {
    assertU64(minSequenceNumber, 'minSequenceNumber');
  }
}

/** Maximum number of locations in a `GetOperations` RPC. */
const MAX_REQUESTED_LOCATIONS = 1024;

function assertOperationsRequestSize(locationCount: number): void {
  if (locationCount > MAX_REQUESTED_LOCATIONS) {
    throw new Error(`operations request must have at most ${MAX_REQUESTED_LOCATIONS} locations`);
  }
}

export function matchExact(bytes: BytesLike): Filter {
  return create(FilterSchema, {
    kind: {
      case: 'exact',
      value: toBytes(bytes),
    },
  });
}

export function matchPrefix(prefix: BytesLike): Filter {
  return create(FilterSchema, {
    kind: {
      case: 'prefix',
      value: toBytes(prefix),
    },
  });
}

export function matchRegex(regex: string): Filter {
  return create(FilterSchema, {
    kind: {
      case: 'regex',
      value: regex,
    },
  });
}

function binaryTransport(baseUrl: string, options: StoreClientOptions) {
  return createTransport(baseUrl, { ...options, useBinaryFormat: true });
}

/**
 * A proof arrives as one entry per occurrence of its field. Protobuf merges the
 * occurrences into one message, which is the same as parsing their bytes joined
 * (see `proof-bytes.ts`), so this joins them. A missing proof has no entries. No
 * real proof encodes to zero bytes, because every proof message carries a
 * non-empty inner `proof` field.
 */
function requireProof(parts: Uint8Array[], rpc: string): Uint8Array {
  const proof = parts.length === 1 ? parts[0] : joinBytes(parts);
  if (proof.length === 0) {
    throw new Error(`qmdb ${rpc} response missing proof`);
  }
  return proof;
}

function joinBytes(parts: Uint8Array[]): Uint8Array {
  const joined = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return joined;
}

async function operationRangeProofBytes(
  operationLog: ConnectClient<typeof ProofBytesOperationLogService>,
  request: OperationRangeRequest,
  options?: CallOptions,
): Promise<Uint8Array> {
  const response = await operationLog.getOperationRange(
    create(GetOperationRangeRequestSchema, request),
    options,
  );
  return requireProof(response.proof, 'getOperationRange');
}

async function operationsProofBytes(
  operationLog: ConnectClient<typeof ProofBytesOperationLogService>,
  request: OperationsRequest,
  options?: CallOptions,
): Promise<Uint8Array> {
  const response = await operationLog.getOperations(
    create(GetOperationsRequestSchema, {
      tip: request.tip,
      locations: [...request.locations],
      minSequenceNumber: request.minSequenceNumber,
    }),
    options,
  );
  return requireProof(response.proof, 'getOperations');
}

export class QmdbLogClient {
  private readonly operationLog: ConnectClient<typeof ProofBytesOperationLogService>;
  private readonly verifier: QmdbProofVerifier;

  constructor(baseUrl: string, options: QmdbLogClientOptions = {}) {
    const {
      merkleFamily = 'mmr',
      hashFamily = 'sha256',
      ...transportOptions
    } = options;
    this.verifier = new QmdbProofVerifier({ merkleFamily, hashFamily });
    this.operationLog = createClient(
      ProofBytesOperationLogService,
      binaryTransport(baseUrl, transportOptions),
    );
  }

  async operationRange(
    request: OperationRangeRequest,
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedRawOperationRange> {
    assertOperationWindow(request);
    assertOptionalMinSequenceNumber(request.minSequenceNumber);
    const [, proofBytes] = await Promise.all([
      initQmdbWasm(),
      operationRangeProofBytes(this.operationLog, request, options),
    ]);
    return this.verifier.verifyRawOperationRange(proofBytes, request, expectedRoot);
  }

  async getFixedKeylessAppend(
    request: OperationRangeRequest,
    expectedRoot: BytesLike,
    expectedLocation: bigint,
    expectedValue: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedFixedKeylessAppend> {
    assertU64(expectedLocation, 'expectedLocation');
    assertOperationWindow(request);
    assertOptionalMinSequenceNumber(request.minSequenceNumber);
    const [, proofBytes] = await Promise.all([
      initQmdbWasm(),
      operationRangeProofBytes(this.operationLog, request, options),
    ]);
    return this.verifier.verifyFixedKeylessAppend(
      proofBytes,
      request,
      expectedRoot,
      expectedLocation,
      expectedValue,
    );
  }

  async getFixedUnorderedUpdate(
    request: OperationRangeRequest,
    expectedRoot: BytesLike,
    expectedLocation: bigint,
    expectedKey: BytesLike,
    valueSize: number,
    options?: CallOptions,
  ): Promise<VerifiedFixedUnorderedUpdate> {
    assertU64(expectedLocation, 'expectedLocation');
    assertU32(valueSize, 'valueSize');
    assertOperationWindow(request);
    assertOptionalMinSequenceNumber(request.minSequenceNumber);
    const [, proofBytes] = await Promise.all([
      initQmdbWasm(),
      operationRangeProofBytes(this.operationLog, request, options),
    ]);
    return this.verifier.verifyFixedUnorderedUpdate(
      proofBytes,
      request,
      expectedRoot,
      expectedLocation,
      expectedKey,
      valueSize,
    );
  }

  /** Fetch and verify the raw operations at `request.locations` of one tip. */
  async operations(
    request: OperationsRequest,
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedRawOperations> {
    assertOperationsRequestSize(request.locations.length);
    assertOperationLocations(request);
    assertOptionalMinSequenceNumber(request.minSequenceNumber);
    const [, proofBytes] = await Promise.all([
      initQmdbWasm(),
      operationsProofBytes(this.operationLog, request, options),
    ]);
    return this.verifier.verifyRawOperations(proofBytes, request, expectedRoot);
  }

  /** Verify that each expected value was appended at its location, in one proof. */
  async getFixedKeylessAppends(
    request: OperationsTipRequest,
    expectedRoot: BytesLike,
    expected: readonly { location: bigint; value: BytesLike }[],
    options?: CallOptions,
  ): Promise<VerifiedFixedKeylessAppends> {
    assertOperationsRequestSize(expected.length);
    const { locations } = fixedOperationExpectations(
      expected.map(({ location, value }) => ({ location, bytes: toBytes(value) })),
      'value',
      request.tip,
    );
    const operations = { ...request, locations };
    assertOptionalMinSequenceNumber(request.minSequenceNumber);
    const [, proofBytes] = await Promise.all([
      initQmdbWasm(),
      operationsProofBytes(this.operationLog, operations, options),
    ]);
    return this.verifier.verifyFixedKeylessAppends(
      proofBytes,
      request,
      expectedRoot,
      expected,
    );
  }

  /** Verify that each expected key was updated at its location, in one proof. */
  async getFixedUnorderedUpdates(
    request: OperationsTipRequest,
    expectedRoot: BytesLike,
    expected: readonly { location: bigint; key: BytesLike }[],
    valueSize: number,
    options?: CallOptions,
  ): Promise<VerifiedFixedUnorderedUpdates> {
    assertOperationsRequestSize(expected.length);
    assertU32(valueSize, 'valueSize');
    const { locations } = fixedOperationExpectations(
      expected.map(({ location, key }) => ({ location, bytes: toBytes(key) })),
      'key',
      request.tip,
    );
    const operations = { ...request, locations };
    assertOptionalMinSequenceNumber(request.minSequenceNumber);
    const [, proofBytes] = await Promise.all([
      initQmdbWasm(),
      operationsProofBytes(this.operationLog, operations, options),
    ]);
    return this.verifier.verifyFixedUnorderedUpdates(
      proofBytes,
      request,
      expectedRoot,
      expected,
      valueSize,
    );
  }
}

export class QmdbOrderedClient {
  private readonly lookup: ConnectClient<typeof ProofBytesKeyLookupService>;
  private readonly orderedRange: ConnectClient<typeof ProofBytesOrderedKeyRangeService>;
  private readonly operationLog: ConnectClient<typeof ProofBytesOperationLogService>;
  private readonly currentOperation: ConnectClient<typeof ProofBytesCurrentOperationService>;
  private readonly merkleFamily: MerkleFamily;
  private readonly hashFamily: HashFamily;
  private readonly currentChunkSize: number;
  private readonly verifier: QmdbProofVerifier;

  constructor(baseUrl: string, options: QmdbOrderedClientOptions = {}) {
    const {
      merkleFamily = 'mmr',
      hashFamily = 'sha256',
      currentChunkSize = 32,
      ...transportOptions
    } = options;
    assertMerkleFamily(merkleFamily, 'qmdb client');
    assertHashFamily(hashFamily, 'qmdb client');
    assertU32(currentChunkSize, 'qmdb client current chunk size', true);
    this.merkleFamily = merkleFamily;
    this.hashFamily = hashFamily;
    this.currentChunkSize = currentChunkSize;
    this.verifier = new QmdbProofVerifier({ merkleFamily, hashFamily });
    const transport = binaryTransport(baseUrl, transportOptions);
    this.lookup = createClient(ProofBytesKeyLookupService, transport);
    this.orderedRange = createClient(ProofBytesOrderedKeyRangeService, transport);
    this.operationLog = createClient(ProofBytesOperationLogService, transport);
    this.currentOperation = createClient(ProofBytesCurrentOperationService, transport);
  }

  async get(
    request: { key: BytesLike; tip: bigint; minSequenceNumber?: bigint },
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedKeyValue> {
    const { tip, minSequenceNumber } = request;
    assertOptionalMinSequenceNumber(minSequenceNumber);
    await initQmdbWasm();
    const requestedKey = encode_vec_key(toBytes(request.key));
    const response = await this.lookup.get(
      create(GetRequestSchema, {
        key: requestedKey,
        tip,
        ...(minSequenceNumber !== undefined ? { minSequenceNumber } : {}),
      }),
      options,
    );
    const proofBytes = requireProof(response.proof, 'get');
    const verified = verify_key_value_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      this.currentChunkSize,
      requestedKey,
    ) as Omit<VerifiedKeyValue, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

  async getMany(
    request: { keys: readonly BytesLike[]; tip: bigint; minSequenceNumber?: bigint },
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedKeyLookups> {
    const { tip, minSequenceNumber } = request;
    assertOptionalMinSequenceNumber(minSequenceNumber);
    await initQmdbWasm();
    const requestedKeys = request.keys.map((key) => encode_vec_key(toBytes(key)));
    assertDistinctKeys(requestedKeys);
    const response = await this.lookup.getMany(
      create(GetManyRequestSchema, {
        keys: requestedKeys,
        tip,
        ...(minSequenceNumber !== undefined ? { minSequenceNumber } : {}),
      }),
      options,
    );
    // The results arrive as views into the response, so this is one flat copy.
    const proofBytes = toBinary(ProofBytesKeyLookupService.method.getMany.output, response);
    const verified = verify_key_lookup_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      this.currentChunkSize,
      requestedKeys,
    ) as Omit<VerifiedKeyLookups, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

  async getRange(
    request: {
      startKey: BytesLike;
      endKey?: BytesLike;
      limit: number;
      tip: bigint;
      minSequenceNumber?: bigint;
    },
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedKeyRange> {
    assertU32(request.limit, 'limit', true);
    assertOptionalMinSequenceNumber(request.minSequenceNumber);
    await initQmdbWasm();
    const startKey = encode_vec_key(toBytes(request.startKey));
    const endKey =
      request.endKey === undefined
        ? undefined
        : encode_vec_key(toBytes(request.endKey));
    const response = await this.orderedRange.getRange(
      create(GetRangeRequestSchema, {
        startKey,
        ...(endKey === undefined ? {} : { endKey }),
        limit: request.limit,
        tip: request.tip,
        ...(request.minSequenceNumber !== undefined
          ? { minSequenceNumber: request.minSequenceNumber }
          : {}),
      }),
      options,
    );
    // As in getMany, the entries and start proof arrive as views, so this is one flat copy.
    const proofBytes = toBinary(ProofBytesOrderedKeyRangeService.method.getRange.output, response);
    const verified = verify_key_range_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      this.currentChunkSize,
      startKey,
      endKey ?? new Uint8Array(),
      endKey !== undefined,
      request.limit,
    ) as Omit<VerifiedKeyRange, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

  async *subscribe(
    filters: {
      keyFilters?: MessageInitShape<typeof FilterSchema>[];
      valueFilters?: MessageInitShape<typeof FilterSchema>[];
      sinceSequenceNumber?: bigint;
    },
    options?: CallOptions,
  ): AsyncIterable<OrderedSubscribeFrame> {
    await initQmdbWasm();
    const stream = this.operationLog.subscribe(
      create(SubscribeRequestSchema, {
        keyFilters: filters.keyFilters ?? [],
        valueFilters: filters.valueFilters ?? [],
        ...(filters.sinceSequenceNumber !== undefined
          ? { sinceSequenceNumber: filters.sinceSequenceNumber }
          : {}),
      }),
      options,
    );
    for await (const frame of stream) {
      const proofBytes = requireProof(frame.proof, 'subscribe');
      const decoded = decode_operation_multi_proof_operations(
        proofBytes,
        this.merkleFamily,
        this.hashFamily,
      ) as Omit<OrderedSubscribeFrame, 'resumeSequenceNumber' | 'proofSizeBytes'>;
      yield {
        resumeSequenceNumber: frame.resumeSequenceNumber,
        ...decoded,
        proofSizeBytes: proofBytes.length,
      };
    }
  }

  async operationRange(
    request: OperationRangeRequest,
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedOrderedOperationRange> {
    assertOperationWindow(request);
    assertOptionalMinSequenceNumber(request.minSequenceNumber);
    const [, proofBytes] = await Promise.all([
      initQmdbWasm(),
      operationRangeProofBytes(this.operationLog, request, options),
    ]);
    return this.verifier.verifyOrderedOperationRange(proofBytes, request, expectedRoot);
  }

  async currentOperationRange(
    request: OperationRangeRequest,
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedCurrentOperationRange> {
    assertOperationWindow(request);
    assertOptionalMinSequenceNumber(request.minSequenceNumber);
    await initQmdbWasm();
    const response = await this.currentOperation.getCurrentOperationRange(
      create(GetCurrentOperationRangeRequestSchema, request),
      options,
    );
    const proofBytes = requireProof(response.proof, 'getCurrentOperationRange');
    const verified = verify_current_operation_range_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      this.currentChunkSize,
      request.tip,
      request.startLocation,
      request.maxLocations,
    ) as Omit<VerifiedCurrentOperationRange, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }
}
