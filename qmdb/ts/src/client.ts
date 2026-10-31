import { create, toBinary, type MessageInitShape } from '@bufbuild/protobuf';
import {
  createClient,
  type CallOptions,
  type Client as ConnectClient,
} from '@connectrpc/connect';
import {
  createTransport,
  type ClientOptions as SdkClientOptions,
} from '@exowarexyz/sdk';
import {
  CurrentKeyValueProofSchema,
  CurrentOperationRangeProofSchema,
  HistoricalMultiProofSchema,
  HistoricalOperationRangeProofSchema,
} from './generated/proto/qmdb/v1/proof_pb.js';
import {
  KeyLookupService,
  GetManyRequestSchema,
  GetManyResponseSchema,
  GetRequestSchema,
} from './generated/proto/qmdb/v1/key_lookup_pb.js';
import {
  OrderedKeyRangeService,
  GetRangeRequestSchema,
  GetRangeResponseSchema,
} from './generated/proto/qmdb/v1/key_range_pb.js';
import {
  OperationLogService,
  GetOperationRangeRequestSchema,
  GetOperationsRequestSchema,
  SubscribeRequestSchema,
} from './generated/proto/qmdb/v1/operation_log_pb.js';
import {
  CurrentOperationService,
  GetCurrentOperationRangeRequestSchema,
} from './generated/proto/qmdb/v1/current_operation_pb.js';
import {
  FilterSchema,
  type Filter,
} from './generated/proto/common/v1/kv_pb.js';
import {
  decode_historical_multi_proof_operations,
  encode_vec_key,
  verify_current_operation_range_proof,
  verify_current_key_value_proof,
  verify_get_many_response,
  verify_get_range_response,
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
  assertOperationsRequest,
  fixedOperationExpectations,
  type BytesLike,
  type MerkleFamily,
  type HashFamily,
  type OrderedOperation,
  type LocatedOrderedOperation,
  type VerifiedHistoricalMultiProof,
  type VerifiedRawOperationRangeProof,
  type VerifiedRawOperationsProof,
  type VerifiedFixedKeylessAppendsProof,
  type VerifiedFixedUnorderedUpdatesProof,
  type VerifiedFixedKeylessAppendProof,
  type VerifiedFixedUnorderedUpdateProof,
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
  VerifiedHistoricalMultiProof,
  LocatedRawOperation,
  VerifiedRawOperationRangeProof,
  VerifiedRawOperationsProof,
  VerifiedFixedKeylessAppend,
  VerifiedFixedKeylessAppendsProof,
  VerifiedFixedUnorderedUpdate,
  VerifiedFixedUnorderedUpdatesProof,
  VerifiedFixedKeylessAppendProof,
  VerifiedFixedUnorderedUpdateProof,
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

export interface DecodedHistoricalMultiProof {
  /**
   * The root decoded from a subscribe proof. When the proof includes an
   * ops-root witness this is the current/global root reconstructed from that
   * witness; otherwise it is the embedded operation-log root. Callers must
   * compare this value against their trusted root for the frame tip.
   */
  root: Uint8Array;
  operations: LocatedOrderedOperation[];
  proofSizeBytes: number;
}

export interface VerifiedCurrentOperationRangeProof {
  operations: LocatedOrderedOperation[];
  proofSizeBytes: number;
}

export interface VerifiedCurrentKeyValue {
  location: bigint;
  operation: OrderedOperation;
}

export interface VerifiedCurrentKeyValueProof extends VerifiedCurrentKeyValue {
  proofSizeBytes: number;
}

export type VerifiedCurrentKeyLookupResult =
  | ({
      type: 'hit';
      key: Uint8Array;
    } & VerifiedCurrentKeyValue)
  | {
      type: 'miss';
      key: Uint8Array;
    };

export interface VerifiedCurrentKeyLookupProof {
  results: VerifiedCurrentKeyLookupResult[];
  proofSizeBytes: number;
}

export interface VerifiedCurrentKeyRangeEntry {
  key: Uint8Array;
  location: bigint;
  operation: OrderedOperation;
}

export interface VerifiedCurrentKeyRangeProof {
  entries: VerifiedCurrentKeyRangeEntry[];
  nextStartKey: Uint8Array | null;
  proofSizeBytes: number;
}

export interface OrderedSubscribeProof {
  resumeSequenceNumber: bigint;
  tip: bigint;
  proof: DecodedHistoricalMultiProof;
}

export type OrderedQmdbClientOptions = SdkClientOptions & {
  merkleFamily?: MerkleFamily;
  hashFamily?: HashFamily;
  currentChunkSize?: number;
};

export type QmdbOperationLogClientOptions = SdkClientOptions & {
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

async function operationRangeProofBytes(
  operationLog: ConnectClient<typeof OperationLogService>,
  request: OperationRangeRequest,
  options?: CallOptions,
): Promise<Uint8Array> {
  const response = await operationLog.getOperationRange(
    create(GetOperationRangeRequestSchema, request),
    options,
  );
  if (!response.proof) {
    throw new Error('qmdb getOperationRange response missing proof');
  }
  return toBinary(HistoricalOperationRangeProofSchema, response.proof);
}

async function operationsProofBytes(
  operationLog: ConnectClient<typeof OperationLogService>,
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
  if (!response.proof) {
    throw new Error('qmdb getOperations response missing proof');
  }
  return toBinary(HistoricalMultiProofSchema, response.proof);
}

export class QmdbOperationLogClient {
  private readonly operationLog: ConnectClient<typeof OperationLogService>;
  private readonly verifier: QmdbProofVerifier;

  constructor(baseUrl: string, options: QmdbOperationLogClientOptions = {}) {
    const {
      merkleFamily = 'mmr',
      hashFamily = 'sha256',
      ...transportOptions
    } = options;
    this.verifier = new QmdbProofVerifier({ merkleFamily, hashFamily });
    this.operationLog = createClient(
      OperationLogService,
      createTransport(baseUrl, transportOptions),
    );
  }

  async getOperationRange(
    request: OperationRangeRequest,
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedRawOperationRangeProof> {
    assertOperationWindow(request);
    assertOptionalMinSequenceNumber(request.minSequenceNumber);
    const [, proofBytes] = await Promise.all([
      initQmdbWasm(),
      operationRangeProofBytes(this.operationLog, request, options),
    ]);
    return this.verifier.verifyOperationRange(proofBytes, request, expectedRoot);
  }

  async getFixedKeylessAppend(
    request: OperationRangeRequest,
    expectedRoot: BytesLike,
    expectedLocation: bigint,
    expectedValue: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedFixedKeylessAppendProof> {
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
  ): Promise<VerifiedFixedUnorderedUpdateProof> {
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
  async getOperations(
    request: OperationsRequest,
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedRawOperationsProof> {
    assertOperationsRequest(request);
    assertOptionalMinSequenceNumber(request.minSequenceNumber);
    const [, proofBytes] = await Promise.all([
      initQmdbWasm(),
      operationsProofBytes(this.operationLog, request, options),
    ]);
    return this.verifier.verifyOperations(proofBytes, request, expectedRoot);
  }

  /** Verify that each expected value was appended at its location, in one proof. */
  async getFixedKeylessAppendMany(
    request: OperationsTipRequest,
    expectedRoot: BytesLike,
    expected: readonly { location: bigint; value: BytesLike }[],
    options?: CallOptions,
  ): Promise<VerifiedFixedKeylessAppendsProof> {
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
    return this.verifier.verifyFixedKeylessAppendMany(
      proofBytes,
      request,
      expectedRoot,
      expected,
    );
  }

  /** Verify that each expected key was updated at its location, in one proof. */
  async getFixedUnorderedUpdateMany(
    request: OperationsTipRequest,
    expectedRoot: BytesLike,
    expected: readonly { location: bigint; key: BytesLike }[],
    valueSize: number,
    options?: CallOptions,
  ): Promise<VerifiedFixedUnorderedUpdatesProof> {
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
    return this.verifier.verifyFixedUnorderedUpdateMany(
      proofBytes,
      request,
      expectedRoot,
      expected,
      valueSize,
    );
  }
}

export class OrderedQmdbClient {
  private readonly lookup: ConnectClient<typeof KeyLookupService>;
  private readonly orderedRange: ConnectClient<typeof OrderedKeyRangeService>;
  private readonly operationLog: ConnectClient<typeof OperationLogService>;
  private readonly currentOperation: ConnectClient<typeof CurrentOperationService>;
  private readonly merkleFamily: MerkleFamily;
  private readonly hashFamily: HashFamily;
  private readonly currentChunkSize: number;
  private readonly verifier: QmdbProofVerifier;

  constructor(baseUrl: string, options: OrderedQmdbClientOptions = {}) {
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
    const transport = createTransport(baseUrl, transportOptions);
    this.lookup = createClient(KeyLookupService, transport);
    this.orderedRange = createClient(OrderedKeyRangeService, transport);
    this.operationLog = createClient(OperationLogService, transport);
    this.currentOperation = createClient(CurrentOperationService, transport);
  }

  async get(
    key: BytesLike,
    tip: bigint,
    expectedRoot: BytesLike,
    minSequenceNumber?: bigint,
    options?: CallOptions,
  ): Promise<VerifiedCurrentKeyValueProof> {
    assertOptionalMinSequenceNumber(minSequenceNumber);
    await initQmdbWasm();
    const requestedKey = encode_vec_key(toBytes(key));
    const response = await this.lookup.get(
      create(GetRequestSchema, {
        key: requestedKey,
        tip,
        ...(minSequenceNumber !== undefined ? { minSequenceNumber } : {}),
      }),
      options,
    );
    if (!response.proof) {
      throw new Error('qmdb get response missing proof');
    }
    const proofBytes = toBinary(CurrentKeyValueProofSchema, response.proof);
    const verified = verify_current_key_value_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      this.currentChunkSize,
      requestedKey,
    ) as Omit<VerifiedCurrentKeyValueProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

  async getMany(
    keys: BytesLike[],
    tip: bigint,
    expectedRoot: BytesLike,
    minSequenceNumber?: bigint,
    options?: CallOptions,
  ): Promise<VerifiedCurrentKeyLookupProof> {
    assertOptionalMinSequenceNumber(minSequenceNumber);
    await initQmdbWasm();
    const requestedKeys = keys.map((key) => encode_vec_key(toBytes(key)));
    assertDistinctKeys(requestedKeys);
    const response = await this.lookup.getMany(
      create(GetManyRequestSchema, {
        keys: requestedKeys,
        tip,
        ...(minSequenceNumber !== undefined ? { minSequenceNumber } : {}),
      }),
      options,
    );
    const proofBytes = toBinary(GetManyResponseSchema, response);
    const verified = verify_get_many_response(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      this.currentChunkSize,
      requestedKeys,
    ) as Omit<VerifiedCurrentKeyLookupProof, 'proofSizeBytes'>;
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
  ): Promise<VerifiedCurrentKeyRangeProof> {
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
    const proofBytes = toBinary(GetRangeResponseSchema, response);
    const verified = verify_get_range_response(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      this.currentChunkSize,
      startKey,
      endKey ?? new Uint8Array(),
      endKey !== undefined,
      request.limit,
    ) as Omit<VerifiedCurrentKeyRangeProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

  async *subscribe(
    filters: {
      keyFilters?: MessageInitShape<typeof FilterSchema>[];
      valueFilters?: MessageInitShape<typeof FilterSchema>[];
      sinceSequenceNumber?: bigint;
    },
    options?: CallOptions,
  ): AsyncIterable<OrderedSubscribeProof> {
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
      if (!frame.proof) {
        throw new Error('qmdb subscribe response missing proof');
      }
      const proofBytes = toBinary(HistoricalMultiProofSchema, frame.proof);
      const { tip, ...proof } = decode_historical_multi_proof_operations(
        proofBytes,
        this.merkleFamily,
        this.hashFamily,
      ) as Omit<DecodedHistoricalMultiProof, 'proofSizeBytes'> & { tip: bigint };
      yield {
        resumeSequenceNumber: frame.resumeSequenceNumber,
        tip,
        proof: { ...proof, proofSizeBytes: proofBytes.length },
      };
    }
  }

  async getOperationRange(
    request: OperationRangeRequest,
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedHistoricalMultiProof> {
    assertOperationWindow(request);
    assertOptionalMinSequenceNumber(request.minSequenceNumber);
    const [, proofBytes] = await Promise.all([
      initQmdbWasm(),
      operationRangeProofBytes(this.operationLog, request, options),
    ]);
    return this.verifier.verifyOrderedOperationRange(proofBytes, request, expectedRoot);
  }

  async getCurrentOperationRange(
    request: OperationRangeRequest,
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedCurrentOperationRangeProof> {
    assertOperationWindow(request);
    assertOptionalMinSequenceNumber(request.minSequenceNumber);
    await initQmdbWasm();
    const response = await this.currentOperation.getCurrentOperationRange(
      create(GetCurrentOperationRangeRequestSchema, request),
      options,
    );
    if (!response.proof) {
      throw new Error('qmdb getCurrentOperationRange response missing proof');
    }
    const proofBytes = toBinary(CurrentOperationRangeProofSchema, response.proof);
    const verified = verify_current_operation_range_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      this.currentChunkSize,
      request.tip,
      request.startLocation,
      request.maxLocations,
    ) as Omit<VerifiedCurrentOperationRangeProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }
}
