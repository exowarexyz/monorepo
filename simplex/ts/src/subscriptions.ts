import { StoreClient, type StoreBatchEntry } from '@exowarexyz/sdk';

import {
  decodeSimplexBlockData,
  roundFromKey,
  SimplexRecordKind,
  u64FromKey,
} from './encoding.js';
import {
  type SimplexCertificateVerifier,
  type SimplexFinalizationVerificationContext,
  type SimplexNotarizationVerificationContext,
} from './verification.js';

export interface RawSimplexHeaderEntry {
  type: 'header';
  key: Uint8Array;
  digest: Uint8Array;
  header: Uint8Array;
}

export interface RawSimplexBlockEntry {
  type: 'block';
  key: Uint8Array;
  digest: Uint8Array;
  raw: Uint8Array;
  header: Uint8Array;
  body: Uint8Array;
}

export interface RawSimplexNotarizationEntry {
  type: 'notarization';
  epoch: bigint;
  key: Uint8Array;
  view: bigint;
  notarized: Uint8Array;
}

export interface RawSimplexFinalizationByRoundEntry {
  type: 'finalization';
  index: 'round';
  epoch: bigint;
  key: Uint8Array;
  view: bigint;
  finalized: Uint8Array;
}

export interface RawSimplexFinalizationByHeightEntry {
  type: 'finalization';
  index: 'height';
  key: Uint8Array;
  height: bigint;
  finalized: Uint8Array;
}

export type RawSimplexStreamEntry =
  | RawSimplexHeaderEntry
  | RawSimplexBlockEntry
  | RawSimplexNotarizationEntry
  | RawSimplexFinalizationByRoundEntry
  | RawSimplexFinalizationByHeightEntry;

export type RawSimplexCertificateStreamEntry =
  | RawSimplexNotarizationEntry
  | RawSimplexFinalizationByRoundEntry
  | RawSimplexFinalizationByHeightEntry;

export type VerifiedSimplexCertificateStreamEntry<TNotarization, TFinalization> =
  | (Omit<RawSimplexNotarizationEntry, 'notarized'> & {
      raw: Uint8Array;
      certificate: TNotarization;
    })
  | (Omit<RawSimplexFinalizationByRoundEntry, 'finalized'> & {
      raw: Uint8Array;
      certificate: TFinalization;
    })
  | (Omit<RawSimplexFinalizationByHeightEntry, 'finalized'> & {
      raw: Uint8Array;
      certificate: TFinalization;
    });

export interface SimplexStreamBatch<TEntry> {
  sequenceNumber: bigint;
  entries: TEntry[];
}

export interface SimplexStreamOptions {
  sinceSequenceNumber?: bigint;
}

export interface SimplexCertificateStreamOptions extends SimplexStreamOptions {
  includeFinalizedByHeight?: boolean;
}

export interface SimplexSubscriptionsOptions<TNotarization = unknown, TFinalization = unknown> {
  verifier?: SimplexCertificateVerifier<TNotarization, TFinalization>;
}

export class SimplexSubscriptions<TNotarization = unknown, TFinalization = unknown> {
  private readonly verifier?: SimplexCertificateVerifier<TNotarization, TFinalization>;

  constructor(
    private readonly store: StoreClient,
    options: SimplexSubscriptionsOptions<TNotarization, TFinalization> = {},
  ) {
    this.verifier = options.verifier;
  }

  async *subscribeRaw(
    kinds: SimplexRecordKind | readonly SimplexRecordKind[],
    options: SimplexStreamOptions = {},
    callOptions?: Parameters<StoreClient['subscribe']>[1],
  ): AsyncIterable<SimplexStreamBatch<RawSimplexStreamEntry>> {
    const stream = this.store.subscribe(
      {
        selectors: normalizeKinds(kinds).map(streamMatchKind),
        ...(options.sinceSequenceNumber !== undefined
          ? { sinceSequenceNumber: options.sinceSequenceNumber }
          : {}),
      },
      callOptions,
    );
    for await (const batch of stream) {
      yield {
        sequenceNumber: batch.sequenceNumber,
        entries: batch.entries.map((entry: StoreBatchEntry) =>
          decodeRawStreamEntry(entry.key, entry.value),
        ),
      };
    }
  }

  async *subscribeBlocks(
    options: SimplexStreamOptions = {},
    callOptions?: Parameters<StoreClient['subscribe']>[1],
  ): AsyncIterable<SimplexStreamBatch<RawSimplexBlockEntry>> {
    for await (const batch of this.subscribeRaw(SimplexRecordKind.BlockByDigest, options, callOptions)) {
      yield {
        sequenceNumber: batch.sequenceNumber,
        entries: batch.entries.flatMap((entry) => (entry.type === 'block' ? [entry] : [])),
      };
    }
  }

  async *subscribeHeaders(
    options: SimplexStreamOptions = {},
    callOptions?: Parameters<StoreClient['subscribe']>[1],
  ): AsyncIterable<SimplexStreamBatch<RawSimplexHeaderEntry>> {
    for await (const batch of this.subscribeRaw(SimplexRecordKind.HeaderByDigest, options, callOptions)) {
      yield {
        sequenceNumber: batch.sequenceNumber,
        entries: batch.entries.flatMap((entry) => (entry.type === 'header' ? [entry] : [])),
      };
    }
  }

  async *subscribeCertificatesRaw(
    options: SimplexCertificateStreamOptions = {},
    callOptions?: Parameters<StoreClient['subscribe']>[1],
  ): AsyncIterable<SimplexStreamBatch<RawSimplexCertificateStreamEntry>> {
    const kinds = [
      SimplexRecordKind.NotarizationByRound,
      SimplexRecordKind.FinalizationByRound,
      ...(options.includeFinalizedByHeight ? [SimplexRecordKind.FinalizedByHeight] : []),
    ];
    for await (const batch of this.subscribeRaw(kinds, options, callOptions)) {
      yield {
        sequenceNumber: batch.sequenceNumber,
        entries: batch.entries.flatMap((entry) =>
          entry.type === 'header' || entry.type === 'block' ? [] : [entry],
        ),
      };
    }
  }

  async *subscribeCertificates(
    options: SimplexCertificateStreamOptions = {},
    callOptions?: Parameters<StoreClient['subscribe']>[1],
  ): AsyncIterable<SimplexStreamBatch<VerifiedSimplexCertificateStreamEntry<TNotarization, TFinalization>>> {
    for await (const batch of this.subscribeCertificatesRaw(options, callOptions)) {
      const verifier = this.requireVerifier();
      const entries: VerifiedSimplexCertificateStreamEntry<TNotarization, TFinalization>[] = [];
      for (const entry of batch.entries) {
        if (entry.type === 'notarization') {
          const { notarized, ...event } = entry;
          const { type: _type, ...fields } = event;
          const certificate = await verifyNotarization(verifier, notarized, {
            kind: 'notarization',
            source: 'stream',
            ...fields,
            value: notarized,
          });
          entries.push({ ...event, raw: notarized, certificate });
        } else {
          const { finalized, ...event } = entry;
          const { type: _type, ...fields } = event;
          const certificate = await verifyFinalization(verifier, finalized, {
            kind: 'finalization',
            source: 'stream',
            ...fields,
            value: finalized,
          });
          entries.push({ ...event, raw: finalized, certificate });
        }
      }
      yield { sequenceNumber: batch.sequenceNumber, entries };
    }
  }

  private requireVerifier(): SimplexCertificateVerifier<TNotarization, TFinalization> {
    if (!this.verifier) {
      throw new Error('simplex certificate read requires a configured verifier; use subscribeCertificatesRaw for unverified bytes');
    }
    return this.verifier;
  }
}

const STREAM_PAYLOAD_REGEX = '(?s-u).*';

function streamMatchKind(kind: SimplexRecordKind) {
  return { prefix: new Uint8Array([kind]), payloadRegex: STREAM_PAYLOAD_REGEX };
}

function normalizeKinds(kinds: SimplexRecordKind | readonly SimplexRecordKind[]): SimplexRecordKind[] {
  return typeof kinds === 'number' ? [kinds] : [...kinds];
}

function decodeRawStreamEntry(key: Uint8Array, value: Uint8Array): RawSimplexStreamEntry {
  if (key.length === 0) {
    throw new Error('invalid simplex stream key');
  }
  const kind = key[0] as SimplexRecordKind;
  switch (kind) {
    case SimplexRecordKind.HeaderByDigest:
      return { type: 'header', key, digest: key.slice(1), header: value };
    case SimplexRecordKind.BlockByDigest: {
      const block = decodeSimplexBlockData(value);
      return {
        type: 'block',
        key,
        digest: key.slice(1),
        raw: value,
        header: block.header,
        body: block.body,
      };
    }
    case SimplexRecordKind.NotarizationByRound:
      return { type: 'notarization', key, ...roundFromKey(key), notarized: value };
    case SimplexRecordKind.FinalizationByRound:
      return { type: 'finalization', index: 'round', key, ...roundFromKey(key), finalized: value };
    case SimplexRecordKind.FinalizedByHeight:
      return { type: 'finalization', index: 'height', key, height: u64FromKey(key), finalized: value };
    default:
      throw new Error(`unknown simplex stream kind ${kind}`);
  }
}

async function verifyNotarization<TNotarization, TFinalization>(
  verifier: SimplexCertificateVerifier<TNotarization, TFinalization>,
  bytes: Uint8Array,
  context: SimplexNotarizationVerificationContext,
): Promise<TNotarization> {
  const verified = await verifier.verifyNotarization(bytes.slice(), context);
  if (!verified) {
    throw new Error('simplex notarization verification failed');
  }
  return verified;
}

async function verifyFinalization<TNotarization, TFinalization>(
  verifier: SimplexCertificateVerifier<TNotarization, TFinalization>,
  bytes: Uint8Array,
  context: SimplexFinalizationVerificationContext,
): Promise<TFinalization> {
  const verified = await verifier.verifyFinalization(bytes.slice(), context);
  if (!verified) {
    throw new Error('simplex finalization verification failed');
  }
  return verified;
}
