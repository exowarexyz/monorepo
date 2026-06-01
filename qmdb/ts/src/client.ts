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
  SubscribeRequestSchema,
} from './generated/proto/qmdb/v1/operation_log_pb.js';
import {
  CurrentOperationService,
  GetCurrentOperationRangeRequestSchema,
} from './generated/proto/qmdb/v1/current_operation_pb.js';
import {
  BytesFilterSchema,
  type BytesFilter,
} from './generated/proto/store/v1/common_pb.js';
import initWasm, {
  decode_historical_multi_proof_operations,
  encode_vec_key,
  verify_current_operation_range_proof,
  verify_current_key_value_proof,
  verify_get_many_response,
  verify_get_range_response,
  verify_historical_fixed_keyless_append_proof,
  verify_historical_fixed_unordered_update_proof,
  verify_historical_operation_range_proof,
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

export interface OperationRangeRequest {
  tip: bigint;
  startLocation: bigint;
  maxLocations: number;
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
  hasMore: boolean;
  nextStartKey: Uint8Array;
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

let wasmReady: Promise<unknown> | undefined;

function ensureWasm(): Promise<unknown> {
  return (wasmReady ??= initWasm());
}

function toBytes(value: BytesLike): Uint8Array {
  return typeof value === 'string' ? new TextEncoder().encode(value) : value;
}

function copyBytes(value: BytesLike): Uint8Array {
  return new Uint8Array(toBytes(value));
}

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

function assertMerkleFamily(value: MerkleFamily, label: string): void {
  if (value !== 'mmr' && value !== 'mmb') {
    throw new Error(`${label} unsupported Merkle family ${String(value)}`);
  }
}

function assertHashFamily(value: HashFamily, label: string): void {
  if (value !== 'sha256' && value !== 'blake3' && value !== 'crc32c') {
    throw new Error(`${label} unsupported hash family ${String(value)}`);
  }
}

function assertCurrentChunkSize(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} current chunk size must be a positive integer`);
  }
}

export function matchExact(bytes: BytesLike): BytesFilter {
  return create(BytesFilterSchema, {
    kind: {
      case: 'exact',
      value: toBytes(bytes),
    },
  });
}

export function matchPrefix(prefix: BytesLike): BytesFilter {
  return create(BytesFilterSchema, {
    kind: {
      case: 'prefix',
      value: toBytes(prefix),
    },
  });
}

export function matchRegex(regex: string): BytesFilter {
  return create(BytesFilterSchema, {
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

export class QmdbOperationLogClient {
  private readonly operationLog: ConnectClient<typeof OperationLogService>;
  private readonly merkleFamily: MerkleFamily;
  private readonly hashFamily: HashFamily;

  constructor(baseUrl: string, options: QmdbOperationLogClientOptions = {}) {
    const {
      merkleFamily = 'mmr',
      hashFamily = 'sha256',
      ...transportOptions
    } = options;
    assertMerkleFamily(merkleFamily, 'qmdb operation log client');
    assertHashFamily(hashFamily, 'qmdb operation log client');
    this.merkleFamily = merkleFamily;
    this.hashFamily = hashFamily;
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
    await ensureWasm();
    const proofBytes = await operationRangeProofBytes(
      this.operationLog,
      request,
      options,
    );
    const verified = verify_historical_raw_operation_range_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
    ) as Omit<VerifiedRawOperationRangeProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

  async getFixedKeylessAppend(
    request: OperationRangeRequest,
    expectedRoot: BytesLike,
    expectedLocation: bigint,
    expectedValue: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedFixedKeylessAppendProof> {
    await ensureWasm();
    const proofBytes = await operationRangeProofBytes(
      this.operationLog,
      request,
      options,
    );
    const verified = verify_historical_fixed_keyless_append_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      expectedLocation,
      toBytes(expectedValue),
    ) as Omit<VerifiedFixedKeylessAppendProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

  async getFixedUnorderedUpdate(
    request: OperationRangeRequest,
    expectedRoot: BytesLike,
    expectedLocation: bigint,
    expectedKey: BytesLike,
    valueSize: number,
    options?: CallOptions,
  ): Promise<VerifiedFixedUnorderedUpdateProof> {
    await ensureWasm();
    const proofBytes = await operationRangeProofBytes(
      this.operationLog,
      request,
      options,
    );
    const verified = verify_historical_fixed_unordered_update_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
      expectedLocation,
      toBytes(expectedKey),
      valueSize,
    ) as Omit<VerifiedFixedUnorderedUpdateProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
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

  constructor(baseUrl: string, options: OrderedQmdbClientOptions = {}) {
    const {
      merkleFamily = 'mmr',
      hashFamily = 'sha256',
      currentChunkSize = 32,
      ...transportOptions
    } = options;
    assertMerkleFamily(merkleFamily, 'qmdb client');
    assertHashFamily(hashFamily, 'qmdb client');
    assertCurrentChunkSize(currentChunkSize, 'qmdb client');
    this.merkleFamily = merkleFamily;
    this.hashFamily = hashFamily;
    this.currentChunkSize = currentChunkSize;
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
    options?: CallOptions,
  ): Promise<VerifiedCurrentKeyValueProof> {
    await ensureWasm();
    const requestedKey = encode_vec_key(copyBytes(key));
    const response = await this.lookup.get(
      create(GetRequestSchema, {
        key: requestedKey,
        tip,
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
    options?: CallOptions,
  ): Promise<VerifiedCurrentKeyLookupProof> {
    await ensureWasm();
    const requestedKeys = keys.map((key) => encode_vec_key(copyBytes(key)));
    assertDistinctKeys(requestedKeys);
    const response = await this.lookup.getMany(
      create(GetManyRequestSchema, {
        keys: requestedKeys,
        tip,
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
    },
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedCurrentKeyRangeProof> {
    await ensureWasm();
    const startKey = encode_vec_key(copyBytes(request.startKey));
    const endKey =
      request.endKey === undefined
        ? undefined
        : encode_vec_key(copyBytes(request.endKey));
    const response = await this.orderedRange.getRange(
      create(GetRangeRequestSchema, {
        startKey,
        ...(endKey === undefined ? {} : { endKey }),
        limit: request.limit,
        tip: request.tip,
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
    ) as Omit<VerifiedCurrentKeyRangeProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

  async *subscribe(
    filters: {
      keyFilters?: MessageInitShape<typeof BytesFilterSchema>[];
      valueFilters?: MessageInitShape<typeof BytesFilterSchema>[];
      sinceSequenceNumber?: bigint;
    },
    options?: CallOptions,
  ): AsyncIterable<OrderedSubscribeProof> {
    await ensureWasm();
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
      const proof = decode_historical_multi_proof_operations(
        proofBytes,
        this.merkleFamily,
        this.hashFamily,
      ) as Omit<DecodedHistoricalMultiProof, 'proofSizeBytes'>;
      yield {
        resumeSequenceNumber: frame.resumeSequenceNumber,
        tip: frame.tip,
        proof: { ...proof, proofSizeBytes: proofBytes.length },
      };
    }
  }

  async getOperationRange(
    request: OperationRangeRequest,
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedHistoricalMultiProof> {
    await ensureWasm();
    const proofBytes = await operationRangeProofBytes(
      this.operationLog,
      request,
      options,
    );
    const verified = verify_historical_operation_range_proof(
      proofBytes,
      toBytes(expectedRoot),
      this.merkleFamily,
      this.hashFamily,
    ) as Omit<VerifiedHistoricalMultiProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }

  async getCurrentOperationRange(
    request: {
      tip: bigint;
      startLocation: bigint;
      maxLocations: number;
    },
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedCurrentOperationRangeProof> {
    await ensureWasm();
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
    ) as Omit<VerifiedCurrentOperationRangeProof, 'proofSizeBytes'>;
    return { ...verified, proofSizeBytes: proofBytes.length };
  }
}
