import { ReadSession, TraversalMode, type StoreClient } from '@exowarexyz/sdk';

import {
  blockByDigestKey,
  copyBytes,
  decodeSimplexBlockData,
  finalizationByRoundKey,
  finalizedByHeightKey,
  headerByDigestKey,
  normalizeU64,
  notarizationByRoundKey,
  rangeForKind,
  SimplexRecordKind,
  u64FromKey,
  type BytesLike,
  type SimplexBlockData,
  type U64Like,
} from './encoding.js';
import {
  type SimplexCertificateVerifier,
  type SimplexFinalizationVerificationContext,
  type SimplexNotarizationVerificationContext,
} from './verification.js';

export interface SimplexReaderOptions<TNotarization = unknown, TFinalization = unknown> {
  verifier?: SimplexCertificateVerifier<TNotarization, TFinalization>;
}

type ReadCallOptions = Parameters<ReadSession['get']>[1];

export class SimplexReader<TNotarization = unknown, TFinalization = unknown> {
  private readonly session: ReadSession;
  private readonly verifier?: SimplexCertificateVerifier<TNotarization, TFinalization>;

  /** A Store client starts a fresh monotonic session with no initial minimum. */
  constructor(
    store: StoreClient | ReadSession,
    options: SimplexReaderOptions<TNotarization, TFinalization> = {},
  ) {
    this.session = store instanceof ReadSession ? store : ReadSession.monotonic(store);
    this.verifier = options.verifier;
  }

  /** Use an existing session's policy and shared observations. */
  static withSession<TNotarization = unknown, TFinalization = unknown>(
    session: ReadSession,
    options: SimplexReaderOptions<TNotarization, TFinalization> = {},
  ): SimplexReader<TNotarization, TFinalization> {
    return new SimplexReader(session, options);
  }

  minSequenceNumber(): bigint | undefined {
    return this.session.minSequenceNumber();
  }

  evaluatedSequence(): bigint | undefined {
    return this.session.evaluatedSequence();
  }

  clone(): SimplexReader<TNotarization, TFinalization> {
    return SimplexReader.withSession(this.session.clone(), { verifier: this.verifier });
  }

  withMinSequenceNumber(sequence: bigint): SimplexReader<TNotarization, TFinalization> {
    return SimplexReader.withSession(this.session.withMinSequenceNumber(sequence), {
      verifier: this.verifier,
    });
  }

  async getHeader(
    digest: BytesLike,
    callOptions?: ReadCallOptions,
  ): Promise<Uint8Array | null> {
    return this.getHeaderRaw(digest, callOptions);
  }

  async getHeaderRaw(
    digest: BytesLike,
    callOptions?: ReadCallOptions,
  ): Promise<Uint8Array | null> {
    return this.getRaw(headerByDigestKey(digest), callOptions);
  }

  async getBlock(
    digest: BytesLike,
    callOptions?: ReadCallOptions,
  ): Promise<SimplexBlockData | null> {
    const raw = await this.getBlockRaw(digest, callOptions);
    return raw === null ? null : decodeSimplexBlockData(raw);
  }

  async getBlockRaw(
    digest: BytesLike,
    callOptions?: ReadCallOptions,
  ): Promise<Uint8Array | null> {
    return this.getRaw(blockByDigestKey(digest), callOptions);
  }

  async getNotarizationByRound(
    epoch: U64Like,
    view: U64Like,
    callOptions?: ReadCallOptions,
  ): Promise<TNotarization | null> {
    const verifier = this.requireVerifier();
    const key = notarizationByRoundKey(epoch, view);
    const raw = await this.getRaw(key, callOptions);
    if (raw === null) {
      return null;
    }
    return this.verifyNotarization(verifier, raw, {
      kind: 'notarization',
      source: 'get',
      key,
      value: raw,
      epoch: normalizeU64(epoch),
      view: normalizeU64(view),
    });
  }

  async getNotarizationByRoundRaw(
    epoch: U64Like,
    view: U64Like,
    callOptions?: ReadCallOptions,
  ): Promise<Uint8Array | null> {
    return this.getRaw(notarizationByRoundKey(epoch, view), callOptions);
  }

  async getFinalizationByRound(
    epoch: U64Like,
    view: U64Like,
    callOptions?: ReadCallOptions,
  ): Promise<TFinalization | null> {
    const verifier = this.requireVerifier();
    const key = finalizationByRoundKey(epoch, view);
    const raw = await this.getRaw(key, callOptions);
    if (raw === null) {
      return null;
    }
    return this.verifyFinalization(verifier, raw, {
      kind: 'finalization',
      index: 'round',
      source: 'get',
      key,
      value: raw,
      epoch: normalizeU64(epoch),
      view: normalizeU64(view),
    });
  }

  async getFinalizationByRoundRaw(
    epoch: U64Like,
    view: U64Like,
    callOptions?: ReadCallOptions,
  ): Promise<Uint8Array | null> {
    return this.getRaw(finalizationByRoundKey(epoch, view), callOptions);
  }

  async getFinalizationByHeight(
    height: U64Like,
    callOptions?: ReadCallOptions,
  ): Promise<TFinalization | null> {
    const verifier = this.requireVerifier();
    const key = finalizedByHeightKey(height);
    const raw = await this.getRaw(key, callOptions);
    if (raw === null) {
      return null;
    }
    return this.verifyFinalization(verifier, raw, {
      kind: 'finalization',
      index: 'height',
      source: 'get',
      key,
      value: raw,
      height: normalizeU64(height),
    });
  }

  async getFinalizationByHeightRaw(
    height: U64Like,
    callOptions?: ReadCallOptions,
  ): Promise<Uint8Array | null> {
    return this.getRaw(finalizedByHeightKey(height), callOptions);
  }

  async latestFinalization(callOptions?: ReadCallOptions): Promise<TFinalization | null> {
    const verifier = this.requireVerifier();
    const row = await this.latestFinalizedRow(callOptions);
    if (!row) {
      return null;
    }
    return this.verifyFinalization(verifier, row.value, {
      kind: 'finalization',
      index: 'latest',
      source: 'get',
      key: row.key,
      value: row.value,
      height: u64FromKey(row.key),
    });
  }

  async latestFinalizationRaw(callOptions?: ReadCallOptions): Promise<Uint8Array | null> {
    return (await this.latestFinalizedRow(callOptions))?.value ?? null;
  }

  private async latestFinalizedRow(
    callOptions?: ReadCallOptions,
  ): Promise<{ key: Uint8Array; value: Uint8Array } | null> {
    const range = rangeForKind(SimplexRecordKind.FinalizedByHeight);
    const result = await this.session.query(
      range.start,
      range.end,
      1,
      4096,
      TraversalMode.REVERSE,
      callOptions,
    );
    return result.results[0] ?? null;
  }

  private async getRaw(
    key: Uint8Array,
    callOptions?: ReadCallOptions,
  ): Promise<Uint8Array | null> {
    const result = await this.session.get(key, callOptions);
    return result?.value ?? null;
  }

  private requireVerifier(): SimplexCertificateVerifier<TNotarization, TFinalization> {
    if (!this.verifier) {
      throw new Error('simplex certificate read requires a configured verifier; use the *Raw method for unverified bytes');
    }
    return this.verifier;
  }

  private async verifyNotarization(
    verifier: SimplexCertificateVerifier<TNotarization, TFinalization>,
    bytes: Uint8Array,
    context: SimplexNotarizationVerificationContext,
  ): Promise<TNotarization> {
    const verified = await verifier.verifyNotarization(copyBytes(bytes), context);
    if (!verified) {
      throw new Error('simplex notarization verification failed');
    }
    return verified;
  }

  private async verifyFinalization(
    verifier: SimplexCertificateVerifier<TNotarization, TFinalization>,
    bytes: Uint8Array,
    context: SimplexFinalizationVerificationContext,
  ): Promise<TFinalization> {
    const verified = await verifier.verifyFinalization(copyBytes(bytes), context);
    if (!verified) {
      throw new Error('simplex finalization verification failed');
    }
    return verified;
  }
}
