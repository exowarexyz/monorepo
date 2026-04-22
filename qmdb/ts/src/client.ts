import { create, toBinary, type MessageInitShape } from '@bufbuild/protobuf';
import {
  createClient,
  type CallOptions,
  type Client as ConnectClient,
} from '@connectrpc/connect';
import {
  BytesMatchKeySchema,
  CurrentKeyValueProofSchema,
  HistoricalMultiProofSchema,
  OrderedService,
  QmdbGetManyRequestSchema,
  QmdbGetRequestSchema,
  QmdbSubscribeRequestSchema,
  createTransport,
  type BytesMatchKey,
  type ClientOptions as SdkClientOptions,
} from 'exoware-sdk-ts';
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

export function matchExact(key: BytesLike): BytesMatchKey {
  return create(BytesMatchKeySchema, {
    kind: {
      case: 'exact',
      value: toBytes(key),
    },
  });
}

export function matchPrefix(prefix: BytesLike): BytesMatchKey {
  return create(BytesMatchKeySchema, {
    kind: {
      case: 'prefix',
      value: toBytes(prefix),
    },
  });
}

export function matchRegex(regex: string): BytesMatchKey {
  return create(BytesMatchKeySchema, {
    kind: {
      case: 'regex',
      value: regex,
    },
  });
}

export class OrderedQmdbClient {
  private readonly rpc: ConnectClient<typeof OrderedService>;

  constructor(baseUrl: string, options: OrderedQmdbClientOptions = {}) {
    const transport = createTransport(baseUrl, options);
    this.rpc = createClient(OrderedService, transport);
  }

  async get(
    key: BytesLike,
    root: Uint8Array,
    options?: CallOptions,
  ): Promise<VerifiedCurrentKeyValueProof> {
    await ensureWasm();
    const response = await this.rpc.get(
      create(QmdbGetRequestSchema, {
        key: toBytes(key),
        root,
      }),
      options,
    );
    if (!response.proof) {
      throw new Error('qmdb get response missing proof');
    }
    return verify_current_key_value_proof(
      toBinary(CurrentKeyValueProofSchema, response.proof),
    ) as VerifiedCurrentKeyValueProof;
  }

  async getMany(
    keys: BytesLike[],
    root: Uint8Array,
    options?: CallOptions,
  ): Promise<VerifiedHistoricalMultiProof> {
    await ensureWasm();
    const response = await this.rpc.getMany(
      create(QmdbGetManyRequestSchema, {
        keys: keys.map((key) => toBytes(key)),
        root,
      }),
      options,
    );
    if (!response.proof) {
      throw new Error('qmdb getMany response missing proof');
    }
    return verify_historical_multi_proof(
      toBinary(HistoricalMultiProofSchema, response.proof),
    ) as VerifiedHistoricalMultiProof;
  }

  async *subscribe(
    matchKeys: MessageInitShape<typeof BytesMatchKeySchema>[],
    sinceSequenceNumber?: bigint,
    options?: CallOptions,
  ): AsyncIterable<OrderedSubscribeProof> {
    await ensureWasm();
    const stream = this.rpc.subscribe(
      create(QmdbSubscribeRequestSchema, {
        matchKeys,
        ...(sinceSequenceNumber !== undefined ? { sinceSequenceNumber } : {}),
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
