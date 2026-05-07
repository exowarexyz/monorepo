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
  CurrentOperationService,
  GetCurrentOperationRangeRequestSchema,
  GetManyRequestSchema,
  GetManyResponseSchema,
  GetOperationRangeRequestSchema,
  GetRangeRequestSchema,
  GetRangeResponseSchema,
  GetRequestSchema,
  HistoricalMultiProofSchema,
  HistoricalOperationRangeProofSchema,
  KeyLookupService,
  OperationLogService,
  OrderedKeyRangeService,
  SubscribeRequestSchema,
} from './generated/proto/qmdb/v1/qmdb_pb.js';
import {
  BytesFilterSchema,
  type BytesFilter,
} from './generated/proto/store/v1/common_pb.js';
import initWasm, {
  verify_current_operation_range_proof,
  verify_current_key_value_proof,
  verify_get_many_response,
  verify_get_range_response,
  verify_historical_multi_proof,
  verify_historical_operation_range_proof,
} from './generated/wasm/exoware_qmdb_wasm.js';

export type BytesLike = Uint8Array | string;
export type MerkleFamily = 'mmr' | 'mmb';

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
  operations: LocatedOrderedOperation[];
}

export interface VerifiedCurrentOperationRangeProof {
  operations: LocatedOrderedOperation[];
}

export interface VerifiedCurrentKeyValueProof {
  location: bigint;
  operation: OrderedOperation;
}

export type VerifiedCurrentKeyLookupResult =
  | ({
      type: 'hit';
      key: Uint8Array;
    } & VerifiedCurrentKeyValueProof)
  | {
      type: 'miss';
      key: Uint8Array;
    };

export interface VerifiedCurrentKeyLookupProof {
  results: VerifiedCurrentKeyLookupResult[];
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
}

export interface OrderedSubscribeProof {
  resumeSequenceNumber: bigint;
  tip: bigint;
  proof: VerifiedHistoricalMultiProof;
}

export type TrustedRootResolver = (tip: bigint) => BytesLike | Promise<BytesLike>;

export type OrderedQmdbClientOptions = SdkClientOptions & {
  merkleFamily?: MerkleFamily;
};

let wasmReady: Promise<unknown> | undefined;

function ensureWasm(): Promise<unknown> {
  return (wasmReady ??= initWasm());
}

function toBytes(value: BytesLike): Uint8Array {
  return typeof value === 'string' ? new TextEncoder().encode(value) : value;
}

function assertMerkleFamily(value: MerkleFamily, label: string): void {
  if (value !== 'mmr' && value !== 'mmb') {
    throw new Error(`${label} unsupported Merkle family ${String(value)}`);
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

export class OrderedQmdbClient {
  private readonly lookup: ConnectClient<typeof KeyLookupService>;
  private readonly orderedRange: ConnectClient<typeof OrderedKeyRangeService>;
  private readonly operationLog: ConnectClient<typeof OperationLogService>;
  private readonly currentOperation: ConnectClient<typeof CurrentOperationService>;
  private readonly merkleFamily: MerkleFamily;

  constructor(baseUrl: string, options: OrderedQmdbClientOptions = {}) {
    const { merkleFamily = 'mmr', ...transportOptions } = options;
    assertMerkleFamily(merkleFamily, 'qmdb client');
    this.merkleFamily = merkleFamily;
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
    const response = await this.lookup.get(
      create(GetRequestSchema, {
        key: toBytes(key),
        tip,
      }),
      options,
    );
    if (!response.proof) {
      throw new Error('qmdb get response missing proof');
    }
    const verified = verify_current_key_value_proof(
      toBinary(CurrentKeyValueProofSchema, response.proof),
      toBytes(expectedRoot),
      this.merkleFamily,
    ) as VerifiedCurrentKeyValueProof;
    return verified;
  }

  async getMany(
    keys: BytesLike[],
    tip: bigint,
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedCurrentKeyLookupProof> {
    await ensureWasm();
    const response = await this.lookup.getMany(
      create(GetManyRequestSchema, {
        keys: keys.map((key) => toBytes(key)),
        tip,
      }),
      options,
    );
    const verified = verify_get_many_response(
      toBinary(GetManyResponseSchema, response),
      toBytes(expectedRoot),
      this.merkleFamily,
    ) as VerifiedCurrentKeyLookupProof;
    return verified;
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
    const startKey = toBytes(request.startKey);
    const endKey =
      request.endKey === undefined ? undefined : toBytes(request.endKey);
    const response = await this.orderedRange.getRange(
      create(GetRangeRequestSchema, {
        startKey,
        ...(endKey === undefined ? {} : { endKey }),
        limit: request.limit,
        tip: request.tip,
      }),
      options,
    );
    const verified = verify_get_range_response(
      toBinary(GetRangeResponseSchema, response),
      toBytes(expectedRoot),
      this.merkleFamily,
      startKey,
      endKey ?? new Uint8Array(),
      endKey !== undefined,
    ) as VerifiedCurrentKeyRangeProof;
    return verified;
  }

  async *subscribe(
    filters: {
      keyFilters?: MessageInitShape<typeof BytesFilterSchema>[];
      valueFilters?: MessageInitShape<typeof BytesFilterSchema>[];
      sinceSequenceNumber?: bigint;
    },
    rootForTip: TrustedRootResolver,
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
      const root = toBytes(await rootForTip(frame.tip));
      const proof = verify_historical_multi_proof(
        toBinary(HistoricalMultiProofSchema, frame.proof),
        root,
        this.merkleFamily,
      ) as VerifiedHistoricalMultiProof;
      yield {
        resumeSequenceNumber: frame.resumeSequenceNumber,
        tip: frame.tip,
        proof,
      };
    }
  }

  async getOperationRange(
    request: {
      tip: bigint;
      startLocation: bigint;
      maxLocations: number;
    },
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedHistoricalMultiProof> {
    await ensureWasm();
    const response = await this.operationLog.getOperationRange(
      create(GetOperationRangeRequestSchema, request),
      options,
    );
    if (!response.proof) {
      throw new Error('qmdb getOperationRange response missing proof');
    }
    return verify_historical_operation_range_proof(
      toBinary(HistoricalOperationRangeProofSchema, response.proof),
      toBytes(expectedRoot),
      this.merkleFamily,
    ) as VerifiedHistoricalMultiProof;
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
    return verify_current_operation_range_proof(
      toBinary(CurrentOperationRangeProofSchema, response.proof),
      toBytes(expectedRoot),
      this.merkleFamily,
    ) as VerifiedCurrentOperationRangeProof;
  }
}
