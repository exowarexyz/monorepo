import { ReadSession, RangeMode, type PrefixedStoreClient } from '@exowarexyz/sdk';

import { verifyNotarized, verifyFinalized } from './certificate-verification.js';
import {
  blockByDigestKey,
  finalizationByHeightKey,
  finalizationByRoundKey,
  headerByDigestKey,
  normalizeU64,
  notarizationByRoundKey,
  rangeForKind,
  SimplexRecordKind,
  u64FromKey,
  type BytesLike,
  type U64Like,
} from './encoding.js';
import type { SimplexCertificateVerifier } from './verification.js';

type CallOptions = Parameters<ReadSession['get']>[1];

/**
 * Session-backed reader for Simplex records. Certificate reads take the
 * verifier that checks them, and their `*Raw` twins return unverified bytes.
 */
export class SimplexReader {
  private session: ReadSession;

  /** Start a fresh monotonic session over `store` with no initial minimum. */
  constructor(store: PrefixedStoreClient) {
    this.session = ReadSession.monotonic(store);
  }

  /** Use an existing session's policy and shared observations. */
  static withSession(session: ReadSession): SimplexReader {
    const reader = Object.create(SimplexReader.prototype) as SimplexReader;
    reader.session = session;
    return reader;
  }

  minSequenceNumber(): bigint | undefined {
    return this.session.minSequenceNumber();
  }

  evaluatedSequence(): bigint | undefined {
    return this.session.evaluatedSequence();
  }

  clone(): SimplexReader {
    return SimplexReader.withSession(this.session.clone());
  }

  withMinSequenceNumber(minSequenceNumber: bigint): SimplexReader {
    return SimplexReader.withSession(this.session.withMinSequenceNumber(minSequenceNumber));
  }

  /** Read stored header bytes, which stay unauthenticated until the caller verifies them. */
  async getHeaderRaw(
    digest: BytesLike,
    options?: CallOptions,
  ): Promise<Uint8Array | null> {
    return this.getRaw(headerByDigestKey(digest), options);
  }

  /**
   * Read stored block bytes, which stay unauthenticated until the caller verifies
   * them. `decodeSimplexBlockData` splits them into header and body.
   */
  async getBlockRaw(
    digest: BytesLike,
    options?: CallOptions,
  ): Promise<Uint8Array | null> {
    return this.getRaw(blockByDigestKey(digest), options);
  }

  async getNotarizedByRound<TNotarization>(
    verifier: SimplexCertificateVerifier<TNotarization, unknown>,
    epoch: U64Like,
    view: U64Like,
    options?: CallOptions,
  ): Promise<TNotarization | null> {
    const key = notarizationByRoundKey(epoch, view);
    const raw = await this.getRaw(key, options);
    if (raw === null) {
      return null;
    }
    return verifyNotarized(verifier, raw, {
      kind: 'notarization',
      source: 'get',
      key,
      raw,
      epoch: normalizeU64(epoch),
      view: normalizeU64(view),
    });
  }

  async getNotarizedByRoundRaw(
    epoch: U64Like,
    view: U64Like,
    options?: CallOptions,
  ): Promise<Uint8Array | null> {
    return this.getRaw(notarizationByRoundKey(epoch, view), options);
  }

  async getFinalizedByRound<TFinalization>(
    verifier: SimplexCertificateVerifier<unknown, TFinalization>,
    epoch: U64Like,
    view: U64Like,
    options?: CallOptions,
  ): Promise<TFinalization | null> {
    const key = finalizationByRoundKey(epoch, view);
    const raw = await this.getRaw(key, options);
    if (raw === null) {
      return null;
    }
    return verifyFinalized(verifier, raw, {
      kind: 'finalization',
      index: 'round',
      source: 'get',
      key,
      raw,
      epoch: normalizeU64(epoch),
      view: normalizeU64(view),
    });
  }

  async getFinalizedByRoundRaw(
    epoch: U64Like,
    view: U64Like,
    options?: CallOptions,
  ): Promise<Uint8Array | null> {
    return this.getRaw(finalizationByRoundKey(epoch, view), options);
  }

  async getFinalizedByHeight<TFinalization>(
    verifier: SimplexCertificateVerifier<unknown, TFinalization>,
    height: U64Like,
    options?: CallOptions,
  ): Promise<TFinalization | null> {
    const key = finalizationByHeightKey(height);
    const raw = await this.getRaw(key, options);
    if (raw === null) {
      return null;
    }
    return verifyFinalized(verifier, raw, {
      kind: 'finalization',
      index: 'height',
      source: 'get',
      key,
      raw,
      height: normalizeU64(height),
    });
  }

  async getFinalizedByHeightRaw(
    height: U64Like,
    options?: CallOptions,
  ): Promise<Uint8Array | null> {
    return this.getRaw(finalizationByHeightKey(height), options);
  }

  async latestFinalized<TFinalization>(
    verifier: SimplexCertificateVerifier<unknown, TFinalization>,
    options?: CallOptions,
  ): Promise<TFinalization | null> {
    const row = await this.latestFinalizedRow(options);
    if (!row) {
      return null;
    }
    return verifyFinalized(verifier, row.value, {
      kind: 'finalization',
      index: 'latest',
      source: 'get',
      key: row.key,
      raw: row.value,
      height: u64FromKey(row.key),
    });
  }

  async latestFinalizedRaw(options?: CallOptions): Promise<Uint8Array | null> {
    return (await this.latestFinalizedRow(options))?.value ?? null;
  }

  private async latestFinalizedRow(
    options?: CallOptions,
  ): Promise<{ key: Uint8Array; value: Uint8Array } | null> {
    const range = rangeForKind(SimplexRecordKind.FinalizationByHeight);
    const result = await this.session.range(
      range.start,
      range.end,
      1,
      4096,
      RangeMode.REVERSE,
      options,
    );
    return result.results[0] ?? null;
  }

  private async getRaw(
    key: Uint8Array,
    options?: CallOptions,
  ): Promise<Uint8Array | null> {
    const result = await this.session.get(key, options);
    return result?.value ?? null;
  }
}
