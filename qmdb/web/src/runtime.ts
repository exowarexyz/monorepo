import {
  StoreClient,
  StoreStreamClient,
  TraversalMode,
  type MatchKey,
  type StreamBatch,
  type StreamBatchEntry,
} from 'exoware-sdk-ts';

export type QmdbStreamVariant = 'ordered' | 'unordered' | 'immutable' | 'keyless';
export type QmdbEntryFamily = 'op' | 'presence' | 'watermark';
export type QmdbRangeMode = 'forward' | 'reverse';

export interface QmdbReadAdapter {
  get(
    key: Uint8Array,
    minSequenceNumber?: bigint,
  ): Promise<Uint8Array | null | undefined>;
  getMany(
    keys: Uint8Array[],
    batchSize: number,
    minSequenceNumber?: bigint,
  ): Promise<Array<{ key: Uint8Array; value: Uint8Array }>>;
  range(
    start: Uint8Array,
    end: Uint8Array,
    limit: number,
    mode: QmdbRangeMode,
    minSequenceNumber?: bigint,
  ): Promise<Array<{ key: Uint8Array; value: Uint8Array }>>;
  subscribe(
    matchKeys: MatchKey[],
    sinceSequenceNumber?: bigint,
  ):
    | Promise<AsyncIterator<StreamBatch> | AsyncIterable<StreamBatch>>
    | AsyncIterator<StreamBatch>
    | AsyncIterable<StreamBatch>;
}

export interface DecodedQmdbEntry extends StreamBatchEntry {
  variant: QmdbStreamVariant;
  family: QmdbEntryFamily;
  location: bigint;
}

export interface DecodedQmdbBatch {
  sequenceNumber: bigint;
  entries: DecodedQmdbEntry[];
  unmatchedEntryCount: number;
}

export interface QmdbVersionedValue {
  key: Uint8Array;
  location: bigint;
  value?: Uint8Array | null;
}

export interface QmdbOperationRange<TOp> {
  resumeSequenceNumber?: bigint;
  watermark: bigint;
  root: Uint8Array;
  startLocation: bigint;
  operations: TOp[];
}

export type OrderedQmdbOperation =
  | { kind: 'delete'; key: Uint8Array }
  | { kind: 'update'; key: Uint8Array; value: Uint8Array; nextKey: Uint8Array }
  | { kind: 'commitFloor'; metadata?: Uint8Array | null; inactivityFloor: bigint };

export type UnorderedQmdbOperation =
  | { kind: 'delete'; key: Uint8Array }
  | { kind: 'update'; key: Uint8Array; value: Uint8Array }
  | { kind: 'commitFloor'; metadata?: Uint8Array | null; inactivityFloor: bigint };

export type ImmutableQmdbOperation =
  | { kind: 'set'; key: Uint8Array; value: Uint8Array }
  | { kind: 'commit'; metadata?: Uint8Array | null };

export type KeylessQmdbOperation =
  | { kind: 'append'; value: Uint8Array }
  | { kind: 'commit'; metadata?: Uint8Array | null };

export type VerifiedQmdbBatch =
  | QmdbOperationRange<OrderedQmdbOperation>
  | QmdbOperationRange<UnorderedQmdbOperation>
  | QmdbOperationRange<ImmutableQmdbOperation>
  | QmdbOperationRange<KeylessQmdbOperation>;

type RawRange<TOp> = {
  resumeSequenceNumber?: bigint | null;
  watermark: bigint;
  root: Uint8Array;
  startLocation: bigint;
  operations: TOp[];
};

type WasmBatchStreamLike = {
  free(): void;
  next(): Promise<any>;
};

type WasmOrderedClientLike = {
  free(): void;
  rootAt(watermark: bigint): Promise<any>;
  operationRangeProof(watermark: bigint, startLocation: bigint, maxLocations: number): Promise<any>;
  streamBatches(since?: bigint | null): Promise<WasmBatchStreamLike>;
};

type WasmUnorderedClientLike = {
  free(): void;
  rootAt(watermark: bigint): Promise<any>;
  operationRangeProof(watermark: bigint, startLocation: bigint, maxLocations: number): Promise<any>;
  streamBatches(since?: bigint | null): Promise<WasmBatchStreamLike>;
};

type WasmImmutableClientLike = {
  free(): void;
  writerLocationWatermark(): Promise<any>;
  rootAt(watermark: bigint): Promise<any>;
  getAt(key: Uint8Array, watermark: bigint): Promise<any>;
  operationRangeProof(watermark: bigint, startLocation: bigint, maxLocations: number): Promise<any>;
  streamBatches(since?: bigint | null): Promise<WasmBatchStreamLike>;
};

type WasmKeylessClientLike = {
  free(): void;
  rootAt(watermark: bigint): Promise<any>;
  operationRangeProof(watermark: bigint, startLocation: bigint, maxLocations: number): Promise<any>;
  streamBatches(since?: bigint | null): Promise<WasmBatchStreamLike>;
};

export type WasmConstructors = {
  OrderedQmdbClient: new (adapter: any) => WasmOrderedClientLike;
  UnorderedQmdbClient: new (adapter: any) => WasmUnorderedClientLike;
  ImmutableQmdbClient: new (adapter: any, keySizeBytes: number) => WasmImmutableClientLike;
  KeylessQmdbClient: new (adapter: any) => WasmKeylessClientLike;
};
export type WasmBindings = WasmConstructors & {
  __wbg_set_wasm(wasm: unknown): void;
};

const RESERVED_BITS = 4;
const UNAUTHENTICATED_REGEX = '(?s-u)^.{8}$';
const AUTH_OP_PREFIX = 0x9;
const AUTH_PRESENCE_PREFIX = 0xc;
const AUTH_WATERMARK_PREFIX = 0xb;
const OP_PREFIX = 0x4;
const PRESENCE_PREFIX = 0x2;
const WATERMARK_PREFIX = 0x3;
const WASM_IMPORT_MODULE = './exoware_qmdb_web_bg.js';
let wasmSourceLoader: (() => Promise<BufferSource>) | null = null;
let wasmBindingsLoader: (() => Promise<WasmBindings>) | null = null;
let initializedWasmBindingsLoader: (() => Promise<WasmConstructors>) | null = null;
let wasmBindingsReady: Promise<WasmBindings> | null = null;
let wasmReady: Promise<WasmConstructors> | null = null;

async function loadWasmBindings(): Promise<WasmBindings> {
  if (wasmBindingsReady === null) {
    const loadBindings = wasmBindingsLoader ?? (async () =>
      // @ts-expect-error wasm-pack does not emit a sibling declaration for the generated bindings module.
      (await import('../pkg/exoware_qmdb_web_bg.js')) as WasmBindings);
    wasmBindingsReady = loadBindings();
  }
  return wasmBindingsReady;
}

export function configureWasmBindingsLoader(loader: () => Promise<WasmBindings>): void {
  wasmBindingsLoader = loader;
  initializedWasmBindingsLoader = null;
  wasmBindingsReady = null;
  wasmReady = null;
}

export function configureInitializedWasmBindingsLoader(
  loader: () => Promise<WasmConstructors>,
): void {
  initializedWasmBindingsLoader = loader;
  wasmBindingsLoader = null;
  wasmBindingsReady = null;
  wasmReady = null;
}

export function configureWasmSourceLoader(loader: () => Promise<BufferSource>): void {
  wasmSourceLoader = loader;
  wasmReady = null;
}

async function ensureWasmReady(): Promise<WasmConstructors> {
  if (wasmReady === null) {
    wasmReady = (async () => {
      if (initializedWasmBindingsLoader !== null) {
        return await initializedWasmBindingsLoader();
      }
      if (wasmSourceLoader === null) {
        throw new Error('qmdb wasm source loader is not configured');
      }
      const wasmBindings = await loadWasmBindings();
      const source = await wasmSourceLoader();
      const { instance } = await WebAssembly.instantiate(source, {
        [WASM_IMPORT_MODULE]: wasmBindings,
      } as WebAssembly.Imports);
      const wasm = instance.exports;
      wasmBindings.__wbg_set_wasm(wasm);
      (wasm as unknown as { __wbindgen_start: () => void }).__wbindgen_start();
      return wasmBindings;
    })();
  }
  return wasmReady;
}

function namespaceTagForVariant(variant: QmdbStreamVariant): number | null {
  switch (variant) {
    case 'immutable':
      return 1;
    case 'keyless':
      return 2;
    case 'ordered':
    case 'unordered':
      return null;
  }
}

function prefixForFamily(variant: QmdbStreamVariant, family: QmdbEntryFamily): number {
  if (variant === 'immutable' || variant === 'keyless') {
    switch (family) {
      case 'op':
        return AUTH_OP_PREFIX;
      case 'presence':
        return AUTH_PRESENCE_PREFIX;
      case 'watermark':
        return AUTH_WATERMARK_PREFIX;
    }
  }

  switch (family) {
    case 'op':
      return OP_PREFIX;
    case 'presence':
      return PRESENCE_PREFIX;
    case 'watermark':
      return WATERMARK_PREFIX;
  }
}

function payloadRegexForVariant(variant: QmdbStreamVariant): string {
  const namespaceTag = namespaceTagForVariant(variant);
  if (namespaceTag === null) {
    return UNAUTHENTICATED_REGEX;
  }
  return `(?s-u)^\\x${namespaceTag.toString(16).padStart(2, '0')}.{8}$`;
}

function readBit(bytes: Uint8Array, bitIndex: number): number {
  const byteIndex = Math.floor(bitIndex / 8);
  const bitOffset = 7 - (bitIndex % 8);
  return (bytes[byteIndex]! >> bitOffset) & 1;
}

function writeBit(bytes: Uint8Array, bitIndex: number, bit: number): void {
  const byteIndex = Math.floor(bitIndex / 8);
  const bitOffset = 7 - (bitIndex % 8);
  bytes[byteIndex] = bytes[byteIndex]! | (bit << bitOffset);
}

function readPrefix(key: Uint8Array, reservedBits: number): number {
  let prefix = 0;
  for (let i = 0; i < reservedBits; i += 1) {
    prefix = (prefix << 1) | readBit(key, i);
  }
  return prefix;
}

function readPayload(key: Uint8Array, reservedBits: number, payloadLength: number): Uint8Array | null {
  const payloadBits = payloadLength * 8;
  if ((key.length * 8) - reservedBits < payloadBits) {
    return null;
  }

  const out = new Uint8Array(payloadLength);
  for (let i = 0; i < payloadBits; i += 1) {
    writeBit(out, i, readBit(key, reservedBits + i));
  }
  return out;
}

function decodeU64(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

function decodeFamilyAndLocation(
  variant: QmdbStreamVariant,
  key: Uint8Array,
): { family: QmdbEntryFamily; location: bigint } | null {
  const prefix = readPrefix(key, RESERVED_BITS);
  const namespaceTag = namespaceTagForVariant(variant);

  if (namespaceTag === null) {
    const family =
      prefix === OP_PREFIX ? 'op' : prefix === PRESENCE_PREFIX ? 'presence' : prefix === WATERMARK_PREFIX ? 'watermark' : null;
    if (family === null) {
      return null;
    }
    const payload = readPayload(key, RESERVED_BITS, 8);
    if (payload === null) {
      return null;
    }
    return { family, location: decodeU64(payload) };
  }

  const family =
    prefix === AUTH_OP_PREFIX ? 'op' : prefix === AUTH_PRESENCE_PREFIX ? 'presence' : prefix === AUTH_WATERMARK_PREFIX ? 'watermark' : null;
  if (family === null) {
    return null;
  }
  const payload = readPayload(key, RESERVED_BITS, 9);
  if (payload === null || payload[0] !== namespaceTag) {
    return null;
  }
  return { family, location: decodeU64(payload.slice(1)) };
}

function resolveAdapter(
  adapterOrStore: QmdbReadAdapter | StoreClient,
  stream?: StoreStreamClient,
): QmdbReadAdapter {
  if (stream === undefined) {
    return adapterOrStore as QmdbReadAdapter;
  }
  return createSdkReadAdapter(adapterOrStore as StoreClient, stream);
}

function normalizeRange<TOp>(value: RawRange<TOp>): QmdbOperationRange<TOp> {
  return {
    resumeSequenceNumber: value.resumeSequenceNumber ?? undefined,
    watermark: value.watermark,
    root: value.root,
    startLocation: value.startLocation,
    operations: value.operations,
  };
}

async function* streamFromWasm<TOp>(
  stream: WasmBatchStreamLike,
): AsyncGenerator<QmdbOperationRange<TOp>, void, void> {
  try {
    for (;;) {
      const next = (await stream.next()) as RawRange<TOp> | undefined;
      if (next === undefined) {
        return;
      }
      yield normalizeRange(next);
    }
  } finally {
    stream.free();
  }
}

export function createSdkReadAdapter(
  store: StoreClient,
  stream: StoreStreamClient,
): QmdbReadAdapter {
  return {
    async get(key, minSequenceNumber) {
      const result = await store.get(key, minSequenceNumber);
      return result?.value ?? null;
    },

    async getMany(keys, batchSize, minSequenceNumber) {
      const results = await store.getMany(keys, batchSize, undefined, minSequenceNumber);
      return results.flatMap((result) =>
        result.value === undefined ? [] : [{ key: result.key, value: result.value }],
      );
    },

    async range(start, end, limit, mode, minSequenceNumber) {
      const traversalMode =
        mode === 'reverse' ? TraversalMode.REVERSE : TraversalMode.FORWARD;
      const batchSize = limit > 0 ? Math.min(limit, 4096) : 4096;
      const result = await store.query(
        start,
        end,
        limit,
        batchSize,
        traversalMode,
        minSequenceNumber,
      );
      return result.results;
    },

    subscribe(matchKeys, sinceSequenceNumber) {
      return stream.subscribe(matchKeys, sinceSequenceNumber);
    },
  };
}

export class OrderedQmdbClient {
  private readonly adapter: QmdbReadAdapter;
  private inner: WasmOrderedClientLike | null = null;

  constructor(adapter: QmdbReadAdapter);
  constructor(store: StoreClient, stream: StoreStreamClient);
  constructor(adapterOrStore: QmdbReadAdapter | StoreClient, stream?: StoreStreamClient) {
    this.adapter = resolveAdapter(adapterOrStore, stream);
  }

  free(): void {
    this.inner?.free();
    this.inner = null;
  }

  private async wasm(): Promise<WasmOrderedClientLike> {
    const wasmBindings = await ensureWasmReady();
    if (this.inner === null) {
      this.inner = new wasmBindings.OrderedQmdbClient(this.adapter);
    }
    return this.inner;
  }

  async rootAt(watermark: bigint): Promise<Uint8Array> {
    return (await (await this.wasm()).rootAt(watermark)) as Uint8Array;
  }

  async operationRangeProof(
    watermark: bigint,
    startLocation: bigint,
    maxLocations: number,
  ): Promise<QmdbOperationRange<OrderedQmdbOperation>> {
    return normalizeRange(
      (await (await this.wasm()).operationRangeProof(
        watermark,
        startLocation,
        maxLocations,
      )) as RawRange<OrderedQmdbOperation>,
    );
  }

  async *streamBatches(
    since?: bigint,
  ): AsyncGenerator<QmdbOperationRange<OrderedQmdbOperation>, void, void> {
    yield* streamFromWasm(await (await this.wasm()).streamBatches(since));
  }
}

export class UnorderedQmdbClient {
  private readonly adapter: QmdbReadAdapter;
  private inner: WasmUnorderedClientLike | null = null;

  constructor(adapter: QmdbReadAdapter);
  constructor(store: StoreClient, stream: StoreStreamClient);
  constructor(adapterOrStore: QmdbReadAdapter | StoreClient, stream?: StoreStreamClient) {
    this.adapter = resolveAdapter(adapterOrStore, stream);
  }

  free(): void {
    this.inner?.free();
    this.inner = null;
  }

  private async wasm(): Promise<WasmUnorderedClientLike> {
    const wasmBindings = await ensureWasmReady();
    if (this.inner === null) {
      this.inner = new wasmBindings.UnorderedQmdbClient(this.adapter);
    }
    return this.inner;
  }

  async rootAt(watermark: bigint): Promise<Uint8Array> {
    return (await (await this.wasm()).rootAt(watermark)) as Uint8Array;
  }

  async operationRangeProof(
    watermark: bigint,
    startLocation: bigint,
    maxLocations: number,
  ): Promise<QmdbOperationRange<UnorderedQmdbOperation>> {
    return normalizeRange(
      (await (await this.wasm()).operationRangeProof(
        watermark,
        startLocation,
        maxLocations,
      )) as RawRange<UnorderedQmdbOperation>,
    );
  }

  async *streamBatches(
    since?: bigint,
  ): AsyncGenerator<QmdbOperationRange<UnorderedQmdbOperation>, void, void> {
    yield* streamFromWasm(await (await this.wasm()).streamBatches(since));
  }
}

export class ImmutableQmdbClient {
  private readonly adapter: QmdbReadAdapter;
  private readonly keySizeBytes: number;
  private inner: WasmImmutableClientLike | null = null;

  constructor(adapter: QmdbReadAdapter, keySizeBytes: number);
  constructor(store: StoreClient, stream: StoreStreamClient, keySizeBytes: number);
  constructor(
    adapterOrStore: QmdbReadAdapter | StoreClient,
    streamOrKeySizeBytes: StoreStreamClient | number,
    maybeKeySizeBytes?: number,
  ) {
    if (typeof streamOrKeySizeBytes === 'number') {
      this.adapter = resolveAdapter(adapterOrStore);
      this.keySizeBytes = streamOrKeySizeBytes;
      return;
    }
    if (maybeKeySizeBytes === undefined) {
      throw new Error('immutable QMDB requires keySizeBytes');
    }
    this.adapter = resolveAdapter(adapterOrStore, streamOrKeySizeBytes);
    this.keySizeBytes = maybeKeySizeBytes;
  }

  free(): void {
    this.inner?.free();
    this.inner = null;
  }

  private async wasm(): Promise<WasmImmutableClientLike> {
    const wasmBindings = await ensureWasmReady();
    if (this.inner === null) {
      this.inner = new wasmBindings.ImmutableQmdbClient(this.adapter, this.keySizeBytes);
    }
    return this.inner;
  }

  async writerLocationWatermark(): Promise<bigint | undefined> {
    const watermark = (await (await this.wasm()).writerLocationWatermark()) as bigint | undefined | null;
    return watermark ?? undefined;
  }

  async rootAt(watermark: bigint): Promise<Uint8Array> {
    return (await (await this.wasm()).rootAt(watermark)) as Uint8Array;
  }

  async getAt(key: Uint8Array, watermark: bigint): Promise<QmdbVersionedValue | null> {
    return (((await (await this.wasm()).getAt(
      key,
      watermark,
    )) as QmdbVersionedValue | null | undefined) ?? null);
  }

  async operationRangeProof(
    watermark: bigint,
    startLocation: bigint,
    maxLocations: number,
  ): Promise<QmdbOperationRange<ImmutableQmdbOperation>> {
    return normalizeRange(
      (await (await this.wasm()).operationRangeProof(
        watermark,
        startLocation,
        maxLocations,
      )) as RawRange<ImmutableQmdbOperation>,
    );
  }

  async *streamBatches(
    since?: bigint,
  ): AsyncGenerator<QmdbOperationRange<ImmutableQmdbOperation>, void, void> {
    yield* streamFromWasm(await (await this.wasm()).streamBatches(since));
  }
}

export class KeylessQmdbClient {
  private readonly adapter: QmdbReadAdapter;
  private inner: WasmKeylessClientLike | null = null;

  constructor(adapter: QmdbReadAdapter);
  constructor(store: StoreClient, stream: StoreStreamClient);
  constructor(adapterOrStore: QmdbReadAdapter | StoreClient, stream?: StoreStreamClient) {
    this.adapter = resolveAdapter(adapterOrStore, stream);
  }

  free(): void {
    this.inner?.free();
    this.inner = null;
  }

  private async wasm(): Promise<WasmKeylessClientLike> {
    const wasmBindings = await ensureWasmReady();
    if (this.inner === null) {
      this.inner = new wasmBindings.KeylessQmdbClient(this.adapter);
    }
    return this.inner;
  }

  async rootAt(watermark: bigint): Promise<Uint8Array> {
    return (await (await this.wasm()).rootAt(watermark)) as Uint8Array;
  }

  async operationRangeProof(
    watermark: bigint,
    startLocation: bigint,
    maxLocations: number,
  ): Promise<QmdbOperationRange<KeylessQmdbOperation>> {
    return normalizeRange(
      (await (await this.wasm()).operationRangeProof(
        watermark,
        startLocation,
        maxLocations,
      )) as RawRange<KeylessQmdbOperation>,
    );
  }

  async *streamBatches(
    since?: bigint,
  ): AsyncGenerator<QmdbOperationRange<KeylessQmdbOperation>, void, void> {
    yield* streamFromWasm(await (await this.wasm()).streamBatches(since));
  }
}

export function qmdbMatchKeysForVariant(variant: QmdbStreamVariant): MatchKey[] {
  const payloadRegex = payloadRegexForVariant(variant);
  return ['op', 'presence', 'watermark'].map((family) => ({
    reservedBits: RESERVED_BITS,
    prefix: prefixForFamily(variant, family as QmdbEntryFamily),
    payloadRegex,
  })) as MatchKey[];
}

export function decodeQmdbEntry(
  variant: QmdbStreamVariant,
  entry: StreamBatchEntry,
): DecodedQmdbEntry | null {
  const decoded = decodeFamilyAndLocation(variant, entry.key);
  if (decoded === null) {
    return null;
  }
  return {
    variant,
    family: decoded.family,
    location: decoded.location,
    key: entry.key,
    value: entry.value,
  };
}

export function decodeQmdbBatch(
  variant: QmdbStreamVariant,
  batch: StreamBatch,
): DecodedQmdbBatch {
  const entries: DecodedQmdbEntry[] = [];
  let unmatchedEntryCount = 0;

  for (const entry of batch.entries) {
    const decoded = decodeQmdbEntry(variant, entry);
    if (decoded === null) {
      unmatchedEntryCount += 1;
      continue;
    }
    entries.push(decoded);
  }

  return {
    sequenceNumber: batch.sequenceNumber,
    entries,
    unmatchedEntryCount,
  };
}

export async function* subscribeDecodedQmdbBatches(
  client: StoreStreamClient,
  variant: QmdbStreamVariant,
  sinceSequenceNumber?: bigint,
): AsyncGenerator<DecodedQmdbBatch, void, void> {
  for await (const batch of client.subscribe(qmdbMatchKeysForVariant(variant), sinceSequenceNumber)) {
    yield decodeQmdbBatch(variant, batch);
  }
}
