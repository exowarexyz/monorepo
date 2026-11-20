import { PrefixedStoreClient, type StoreBatchEntry } from '@exowarexyz/sdk';

import { verifyNotarized, verifyFinalized } from './certificate-verification.js';
import {
  decodeSimplexBlockData,
  roundFromKey,
  SimplexRecordKind,
  u64FromKey,
} from './encoding.js';
import type { SimplexCertificateVerifier } from './verification.js';

export interface RawSimplexHeaderEntry {
  kind: 'header';
  key: Uint8Array;
  digest: Uint8Array;
  raw: Uint8Array;
}

export interface RawSimplexBlockEntry {
  kind: 'block';
  key: Uint8Array;
  digest: Uint8Array;
  raw: Uint8Array;
  header: Uint8Array;
  body: Uint8Array;
}

export interface RawSimplexNotarizationEntry {
  kind: 'notarization';
  epoch: bigint;
  key: Uint8Array;
  view: bigint;
  raw: Uint8Array;
}

export interface RawSimplexFinalizationByRoundEntry {
  kind: 'finalization';
  index: 'round';
  epoch: bigint;
  key: Uint8Array;
  view: bigint;
  raw: Uint8Array;
}

export interface RawSimplexFinalizationByHeightEntry {
  kind: 'finalization';
  index: 'height';
  key: Uint8Array;
  height: bigint;
  raw: Uint8Array;
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
  | (RawSimplexNotarizationEntry & { certificate: TNotarization })
  | (RawSimplexFinalizationByRoundEntry & { certificate: TFinalization })
  | (RawSimplexFinalizationByHeightEntry & { certificate: TFinalization });

export interface SimplexStreamBatch<TEntry> {
  sequenceNumber: bigint;
  entries: TEntry[];
}

export interface SimplexStreamOptions {
  sinceSequenceNumber?: bigint;
}

export interface SimplexCertificateStreamOptions extends SimplexStreamOptions {
  includeFinalizationByHeight?: boolean;
}

export class SimplexSubscriptions {
  constructor(private readonly store: PrefixedStoreClient) {}

  async *subscribeRaw(
    kinds: SimplexRecordKind | readonly SimplexRecordKind[],
    options: SimplexStreamOptions = {},
    callOptions?: Parameters<PrefixedStoreClient['subscribe']>[1],
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
    callOptions?: Parameters<PrefixedStoreClient['subscribe']>[1],
  ): AsyncIterable<SimplexStreamBatch<RawSimplexBlockEntry>> {
    for await (const batch of this.subscribeRaw(SimplexRecordKind.BlockByDigest, options, callOptions)) {
      yield {
        sequenceNumber: batch.sequenceNumber,
        entries: batch.entries.flatMap((entry) => (entry.kind === 'block' ? [entry] : [])),
      };
    }
  }

  async *subscribeHeaders(
    options: SimplexStreamOptions = {},
    callOptions?: Parameters<PrefixedStoreClient['subscribe']>[1],
  ): AsyncIterable<SimplexStreamBatch<RawSimplexHeaderEntry>> {
    for await (const batch of this.subscribeRaw(SimplexRecordKind.HeaderByDigest, options, callOptions)) {
      yield {
        sequenceNumber: batch.sequenceNumber,
        entries: batch.entries.flatMap((entry) => (entry.kind === 'header' ? [entry] : [])),
      };
    }
  }

  async *subscribeCertificatesRaw(
    options: SimplexCertificateStreamOptions = {},
    callOptions?: Parameters<PrefixedStoreClient['subscribe']>[1],
  ): AsyncIterable<SimplexStreamBatch<RawSimplexCertificateStreamEntry>> {
    const kinds = [
      SimplexRecordKind.NotarizationByRound,
      SimplexRecordKind.FinalizationByRound,
      ...(options.includeFinalizationByHeight ? [SimplexRecordKind.FinalizationByHeight] : []),
    ];
    for await (const batch of this.subscribeRaw(kinds, options, callOptions)) {
      yield {
        sequenceNumber: batch.sequenceNumber,
        entries: batch.entries.flatMap((entry) =>
          entry.kind === 'header' || entry.kind === 'block' ? [] : [entry],
        ),
      };
    }
  }

  async *subscribeCertificates<TNotarization, TFinalization>(
    verifier: SimplexCertificateVerifier<TNotarization, TFinalization>,
    options: SimplexCertificateStreamOptions = {},
    callOptions?: Parameters<PrefixedStoreClient['subscribe']>[1],
  ): AsyncIterable<SimplexStreamBatch<VerifiedSimplexCertificateStreamEntry<TNotarization, TFinalization>>> {
    for await (const batch of this.subscribeCertificatesRaw(options, callOptions)) {
      const entries: VerifiedSimplexCertificateStreamEntry<TNotarization, TFinalization>[] = [];
      for (const entry of batch.entries) {
        if (entry.kind === 'notarization') {
          const certificate = await verifyNotarized(verifier, entry.raw, {
            ...entry,
            source: 'stream',
          });
          entries.push({ ...entry, certificate });
        } else {
          const certificate = await verifyFinalized(verifier, entry.raw, {
            ...entry,
            source: 'stream',
          });
          entries.push({ ...entry, certificate });
        }
      }
      yield { sequenceNumber: batch.sequenceNumber, entries };
    }
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
      return { kind: 'header', key, digest: key.slice(1), raw: value };
    case SimplexRecordKind.BlockByDigest: {
      const block = decodeSimplexBlockData(value);
      return {
        kind: 'block',
        key,
        digest: key.slice(1),
        raw: value,
        header: block.header,
        body: block.body,
      };
    }
    case SimplexRecordKind.NotarizationByRound:
      return { kind: 'notarization', key, ...roundFromKey(key), raw: value };
    case SimplexRecordKind.FinalizationByRound:
      return { kind: 'finalization', index: 'round', key, ...roundFromKey(key), raw: value };
    case SimplexRecordKind.FinalizationByHeight:
      return { kind: 'finalization', index: 'height', key, height: u64FromKey(key), raw: value };
    default:
      throw new Error(`unknown simplex stream kind ${kind}`);
  }
}
