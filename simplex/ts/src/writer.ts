import { PrefixedStoreClient, StoreWriteBatch } from '@exowarexyz/sdk';

import {
  blockByDigestKey,
  copyBytes,
  encodeSimplexBlockData,
  finalizationByHeightKey,
  finalizationByRoundKey,
  headerByDigestKey,
  notarizationByRoundKey,
  toSimplexBytes,
  type BytesLike,
  type U64Like,
} from './encoding.js';

export interface PreparedEntry {
  key: Uint8Array;
  value: Uint8Array;
}

export interface UploadSummary {
  headers: number;
  blocks: number;
  notarizations: number;
  finalizations: number;
  finalizationHeightIndexes: number;
}

export interface UploadReceipt {
  storeSequenceNumber: bigint;
  summary: UploadSummary;
}

export interface PreparedUpload {
  entries: PreparedEntry[];
  summary: UploadSummary;
}

export interface HeaderUpload {
  digest: BytesLike;
  header: BytesLike;
}

export interface BlockUpload extends HeaderUpload {
  body: BytesLike;
}

/** A notarization artifact and the header it certifies. */
export interface NotarizedUpload extends HeaderUpload {
  epoch: U64Like;
  view: U64Like;
  notarized: BytesLike;
}

/** A finalization artifact and the header it certifies. */
export interface FinalizedUpload extends HeaderUpload {
  epoch: U64Like;
  view: U64Like;
  height: U64Like;
  finalized: BytesLike;
}

/**
 * Store-backed writer for Simplex blocks and certificates. Certificate uploads
 * also store the header by digest.
 */
export class SimplexWriter {
  constructor(private readonly store: PrefixedStoreClient) {}

  /** Throws `RangeError` when the digest or header is empty. */
  prepareHeader(input: HeaderUpload): PreparedUpload {
    const digest = toSimplexBytes(input.digest);
    const header = toSimplexBytes(input.header);
    if (digest.byteLength === 0 || header.byteLength === 0) {
      throw new RangeError('simplex header upload requires a non-empty digest and header');
    }
    return {
      entries: [{ key: headerByDigestKey(digest), value: header }],
      summary: { ...emptySummary(), headers: 1 },
    };
  }

  prepareBlock(input: BlockUpload): PreparedUpload {
    const prepared = this.prepareHeader(input);
    const [headerEntry] = prepared.entries;
    return {
      entries: [
        headerEntry,
        {
          key: blockByDigestKey(input.digest),
          value: encodeSimplexBlockData(headerEntry.value, input.body),
        },
      ],
      summary: { ...prepared.summary, blocks: 1 },
    };
  }

  prepareNotarized(input: NotarizedUpload): PreparedUpload {
    const prepared = this.prepareHeader(input);
    return {
      entries: [
        ...prepared.entries,
        {
          key: notarizationByRoundKey(input.epoch, input.view),
          value: toSimplexBytes(input.notarized),
        },
      ],
      summary: { ...prepared.summary, notarizations: 1 },
    };
  }

  prepareFinalized(input: FinalizedUpload): PreparedUpload {
    const prepared = this.prepareHeader(input);
    const finalized = toSimplexBytes(input.finalized);
    return {
      entries: [
        ...prepared.entries,
        {
          key: finalizationByRoundKey(input.epoch, input.view),
          value: copyBytes(finalized),
        },
        { key: finalizationByHeightKey(input.height), value: finalized },
      ],
      summary: { ...prepared.summary, finalizations: 1, finalizationHeightIndexes: 1 },
    };
  }

  stageUpload(upload: PreparedUpload, batch = new StoreWriteBatch()): StoreWriteBatch {
    if (upload.entries.length === 0) {
      throw new Error('simplex upload contains no rows');
    }
    for (const entry of upload.entries) {
      batch.push(this.store, entry.key, entry.value);
    }
    return batch;
  }

  async commitUpload(upload: PreparedUpload): Promise<UploadReceipt> {
    const sequence = await this.store.putPrepared(this.stageUpload(upload));
    return { storeSequenceNumber: sequence, summary: upload.summary };
  }

  async uploadHeader(input: HeaderUpload): Promise<UploadReceipt> {
    return this.commitUpload(this.prepareHeader(input));
  }

  async uploadBlock(input: BlockUpload): Promise<UploadReceipt> {
    return this.commitUpload(this.prepareBlock(input));
  }

  async uploadNotarized(input: NotarizedUpload): Promise<UploadReceipt> {
    return this.commitUpload(this.prepareNotarized(input));
  }

  async uploadFinalized(input: FinalizedUpload): Promise<UploadReceipt> {
    return this.commitUpload(this.prepareFinalized(input));
  }
}

function emptySummary(): UploadSummary {
  return {
    headers: 0,
    blocks: 0,
    notarizations: 0,
    finalizations: 0,
    finalizationHeightIndexes: 0,
  };
}
