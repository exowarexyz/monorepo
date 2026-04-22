declare module '../pkg/exoware_qmdb_web_bg.js' {
  export function __wbg_set_wasm(wasm: unknown): void;

  export class QmdbBatchStream {
    free(): void;
    next(): Promise<any>;
  }

  export class OrderedQmdbClient {
    constructor(adapter: any);
    free(): void;
    rootAt(watermark: bigint): Promise<any>;
    operationRangeProof(
      watermark: bigint,
      start_location: bigint,
      max_locations: number,
    ): Promise<any>;
    streamBatches(since?: bigint | null): Promise<QmdbBatchStream>;
  }

  export class UnorderedQmdbClient {
    constructor(adapter: any);
    free(): void;
    rootAt(watermark: bigint): Promise<any>;
    operationRangeProof(
      watermark: bigint,
      start_location: bigint,
      max_locations: number,
    ): Promise<any>;
    streamBatches(since?: bigint | null): Promise<QmdbBatchStream>;
  }

  export class ImmutableQmdbClient {
    constructor(adapter: any, key_size_bytes: number);
    free(): void;
    writerLocationWatermark(): Promise<any>;
    rootAt(watermark: bigint): Promise<any>;
    getAt(key: Uint8Array, watermark: bigint): Promise<any>;
    operationRangeProof(
      watermark: bigint,
      start_location: bigint,
      max_locations: number,
    ): Promise<any>;
    streamBatches(since?: bigint | null): Promise<QmdbBatchStream>;
  }

  export class KeylessQmdbClient {
    constructor(adapter: any);
    free(): void;
    rootAt(watermark: bigint): Promise<any>;
    operationRangeProof(
      watermark: bigint,
      start_location: bigint,
      max_locations: number,
    ): Promise<any>;
    streamBatches(since?: bigint | null): Promise<QmdbBatchStream>;
  }
}
