import { create, toBinary, type MessageInitShape } from '@bufbuild/protobuf';
import {
  createClient,
  type CallOptions,
  type Client as ConnectClient,
} from '@connectrpc/connect';
import {
  BytesFilterSchema,
  CurrentKeyValueProofSchema,
  HistoricalMultiProofSchema,
  OrderedService,
  QmdbGetManyRequestSchema,
  QmdbGetRequestSchema,
  QmdbSubscribeRequestSchema,
  RangeService,
  createTransport,
  type BytesFilter,
  type ClientOptions as SdkClientOptions,
} from '@exowarexyz/sdk';
import initWasm, {
  verify_current_key_value_proof,
  verify_historical_multi_proof,
} from './generated/wasm/exoware_qmdb_wasm.js';

export type BytesLike = Uint8Array | string;

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
  root: Uint8Array;
  operations: LocatedOrderedOperation[];
}

export interface VerifiedCurrentKeyValueProof {
  root: Uint8Array;
  location: bigint;
  operation: OrderedOperation;
}

export interface OrderedSubscribeProof {
  resumeSequenceNumber: bigint;
  proof: VerifiedHistoricalMultiProof;
}

export type OrderedQmdbClientOptions = SdkClientOptions;

let wasmReady: Promise<unknown> | undefined;

function ensureWasm(): Promise<unknown> {
  if (!wasmReady) {
    wasmReady = initWasm();
  }
  return wasmReady;
}

function toBytes(value: BytesLike): Uint8Array {
  return typeof value === 'string' ? new TextEncoder().encode(value) : value;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function assertRootMatches(actual: Uint8Array, expected: BytesLike, label: string): void {
  const expectedBytes = toBytes(expected);
  if (!bytesEqual(actual, expectedBytes)) {
    throw new Error(
      `${label} root mismatch: expected 0x${hex(expectedBytes)}, got 0x${hex(actual)}`,
    );
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
  private readonly rpc: ConnectClient<typeof OrderedService>;
  private readonly range: ConnectClient<typeof RangeService>;

  constructor(baseUrl: string, options: OrderedQmdbClientOptions = {}) {
    const transport = createTransport(baseUrl, options);
    this.rpc = createClient(OrderedService, transport);
    this.range = createClient(RangeService, transport);
  }

  async get(
    key: BytesLike,
    tip: bigint,
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedCurrentKeyValueProof> {
    await ensureWasm();
    const response = await this.rpc.get(
      create(QmdbGetRequestSchema, {
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
    ) as VerifiedCurrentKeyValueProof;
    assertRootMatches(verified.root, expectedRoot, 'qmdb get');
    return verified;
  }

  async getMany(
    keys: BytesLike[],
    tip: bigint,
    expectedRoot: BytesLike,
    options?: CallOptions,
  ): Promise<VerifiedHistoricalMultiProof> {
    await ensureWasm();
    const response = await this.rpc.getMany(
      create(QmdbGetManyRequestSchema, {
        keys: keys.map((key) => toBytes(key)),
        tip,
      }),
      options,
    );
    if (!response.proof) {
      throw new Error('qmdb getMany response missing proof');
    }
    const verified = verify_historical_multi_proof(
      toBinary(HistoricalMultiProofSchema, response.proof),
    ) as VerifiedHistoricalMultiProof;
    assertRootMatches(verified.root, expectedRoot, 'qmdb getMany');
    return verified;
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
    const stream = this.range.subscribe(
      create(QmdbSubscribeRequestSchema, {
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
      yield {
        resumeSequenceNumber: frame.resumeSequenceNumber,
        proof: verify_historical_multi_proof(
          toBinary(HistoricalMultiProofSchema, frame.proof),
        ) as VerifiedHistoricalMultiProof,
      };
    }
  }
}
