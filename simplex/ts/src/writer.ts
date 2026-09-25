import { StoreClient, StoreWriteBatch } from '@exowarexyz/sdk';

import {
  blockByDigestKey,
  copyBytes,
  encodeSimplexBlockData,
  finalizationByRoundKey,
  finalizedByHeightKey,
  headerByDigestKey,
  notarizationByRoundKey,
  toSimplexBytes,
  type BytesLike,
  type U64Like,
} from './encoding.js';

export interface PreparedSimplexEntry {
  key: Uint8Array;
  value: Uint8Array;
}

export interface SimplexUploadSummary {
  headers: number;
  blocks: number;
  notarizations: number;
  finalizations: number;
  finalizedHeightIndexes: number;
}

export interface SimplexUploadReceipt {
  storeSequenceNumber: bigint;
  summary: SimplexUploadSummary;
}

export interface PreparedSimplexUpload {
  entries: PreparedSimplexEntry[];
  summary: SimplexUploadSummary;
}

export interface HeaderUpload {
  digest: BytesLike;
  header: BytesLike;
}

export interface BlockUpload extends HeaderUpload {
  body?: BytesLike;
}

export interface NotarizationUpload {
  epoch: U64Like;
  view: U64Like;
  notarized: BytesLike;
}

export interface FinalizationUpload {
  epoch: U64Like;
  view: U64Like;
  height: U64Like;
  finalized: BytesLike;
}

export class SimplexWriter {
  constructor(private readonly store: StoreClient) {}

  prepareHeader(input: HeaderUpload): PreparedSimplexUpload {
    const header = toSimplexBytes(input.header);
    return {
      entries: [{ key: headerByDigestKey(input.digest), value: header }],
      summary: { ...emptySummary(), headers: 1 },
    };
  }

  prepareBlock(input: BlockUpload): PreparedSimplexUpload {
    const header = toSimplexBytes(input.header);
    return {
      entries: [
        { key: headerByDigestKey(input.digest), value: header },
        {
          key: blockByDigestKey(input.digest),
          value: encodeSimplexBlockData(header, input.body),
        },
      ],
      summary: { ...emptySummary(), headers: 1, blocks: 1 },
    };
  }

  prepareNotarization(input: NotarizationUpload): PreparedSimplexUpload {
    return {
      entries: [{
        key: notarizationByRoundKey(input.epoch, input.view),
        value: toSimplexBytes(input.notarized),
      }],
      summary: { ...emptySummary(), notarizations: 1 },
    };
  }

  prepareFinalization(input: FinalizationUpload): PreparedSimplexUpload {
    const finalized = toSimplexBytes(input.finalized);
    return {
      entries: [
        {
          key: finalizationByRoundKey(input.epoch, input.view),
          value: copyBytes(finalized),
        },
        { key: finalizedByHeightKey(input.height), value: finalized },
      ],
      summary: { ...emptySummary(), finalizations: 1, finalizedHeightIndexes: 1 },
    };
  }

  stageUpload(upload: PreparedSimplexUpload, batch = new StoreWriteBatch()): StoreWriteBatch {
    if (upload.entries.length === 0) {
      throw new Error('simplex upload contains no rows');
    }
    for (const entry of upload.entries) {
      batch.push(this.store, entry.key, entry.value);
    }
    return batch;
  }

  async uploadPrepared(upload: PreparedSimplexUpload): Promise<SimplexUploadReceipt> {
    const sequence = await this.stageUpload(upload).commit(this.store);
    return { storeSequenceNumber: sequence, summary: upload.summary };
  }

  async uploadHeader(input: HeaderUpload): Promise<SimplexUploadReceipt> {
    return this.uploadPrepared(this.prepareHeader(input));
  }

  async uploadBlock(input: BlockUpload): Promise<SimplexUploadReceipt> {
    return this.uploadPrepared(this.prepareBlock(input));
  }

  async uploadNotarization(input: NotarizationUpload): Promise<SimplexUploadReceipt> {
    return this.uploadPrepared(this.prepareNotarization(input));
  }

  async uploadFinalization(input: FinalizationUpload): Promise<SimplexUploadReceipt> {
    return this.uploadPrepared(this.prepareFinalization(input));
  }
}

function emptySummary(): SimplexUploadSummary {
  return {
    headers: 0,
    blocks: 0,
    notarizations: 0,
    finalizations: 0,
    finalizedHeightIndexes: 0,
  };
}
