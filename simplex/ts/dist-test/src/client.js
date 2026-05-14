import { Client, StoreWriteBatch, TraversalMode, } from '@exowarexyz/sdk';
export const FORMAT_VERSION = 0;
export var SimplexRecordKind;
(function (SimplexRecordKind) {
    SimplexRecordKind[SimplexRecordKind["HeaderByDigest"] = 16] = "HeaderByDigest";
    SimplexRecordKind[SimplexRecordKind["BlockByDigest"] = 17] = "BlockByDigest";
    SimplexRecordKind[SimplexRecordKind["NotarizationByView"] = 32] = "NotarizationByView";
    SimplexRecordKind[SimplexRecordKind["FinalizationByView"] = 48] = "FinalizationByView";
    SimplexRecordKind[SimplexRecordKind["FinalizedByHeight"] = 49] = "FinalizedByHeight";
})(SimplexRecordKind || (SimplexRecordKind = {}));
const STREAM_PAYLOAD_REGEX = '(?s-u).*';
const HEADER_LENGTH_BYTES = 4;
function copyBytes(bytes) {
    return new Uint8Array(bytes);
}
export function hexToBytes(value) {
    const trimmed = value.trim();
    const body = trimmed.startsWith('0x') || trimmed.startsWith('0X') ? trimmed.slice(2) : trimmed;
    if (body.length === 0) {
        return new Uint8Array();
    }
    if (body.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(body)) {
        throw new Error('expected an even-length hex string');
    }
    const out = new Uint8Array(body.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = Number.parseInt(body.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}
export function bytesToHex(value) {
    return Array.from(value)
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');
}
export function toSimplexBytes(value) {
    return typeof value === 'string' ? hexToBytes(value) : copyBytes(value);
}
export function encodeSimplexBlockData(header, body = new Uint8Array()) {
    const headerBytes = toSimplexBytes(header);
    const bodyBytes = toSimplexBytes(body);
    if (headerBytes.byteLength > 0xffff_ffff) {
        throw new RangeError('header simplex block exceeds u32 length');
    }
    const out = new Uint8Array(HEADER_LENGTH_BYTES + headerBytes.byteLength + bodyBytes.byteLength);
    new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(0, headerBytes.byteLength, false);
    out.set(headerBytes, HEADER_LENGTH_BYTES);
    out.set(bodyBytes, HEADER_LENGTH_BYTES + headerBytes.byteLength);
    return out;
}
export function decodeSimplexBlockData(value) {
    const bytes = toSimplexBytes(value);
    if (bytes.byteLength < HEADER_LENGTH_BYTES) {
        throw new Error('simplex block data is missing header length');
    }
    const headerLength = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, false);
    const remaining = bytes.byteLength - HEADER_LENGTH_BYTES;
    if (headerLength > remaining) {
        throw new Error('simplex block header length exceeds block data length');
    }
    const headerStart = HEADER_LENGTH_BYTES;
    const bodyStart = headerStart + headerLength;
    return {
        header: bytes.slice(headerStart, bodyStart),
        body: bytes.slice(bodyStart),
    };
}
export function normalizeU64(value) {
    const bigintValue = typeof value === 'bigint' ? value : BigInt(value);
    if (bigintValue < 0n || bigintValue > 0xffffffffffffffffn) {
        throw new RangeError(`u64 out of range: ${value}`);
    }
    return bigintValue;
}
function u64Bytes(value) {
    let remaining = normalizeU64(value);
    const out = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) {
        out[i] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return out;
}
function keyFromParts(kind, suffix) {
    const out = new Uint8Array(2 + suffix.length);
    out[0] = FORMAT_VERSION;
    out[1] = kind;
    out.set(suffix, 2);
    return out;
}
export function headerByDigestKey(digest) {
    return keyFromParts(SimplexRecordKind.HeaderByDigest, toSimplexBytes(digest));
}
export function blockByDigestKey(digest) {
    return keyFromParts(SimplexRecordKind.BlockByDigest, toSimplexBytes(digest));
}
export function notarizationByViewKey(view) {
    return keyFromParts(SimplexRecordKind.NotarizationByView, u64Bytes(view));
}
export function finalizationByViewKey(view) {
    return keyFromParts(SimplexRecordKind.FinalizationByView, u64Bytes(view));
}
export function finalizedByHeightKey(height) {
    return keyFromParts(SimplexRecordKind.FinalizedByHeight, u64Bytes(height));
}
export function rangeForKind(kind) {
    return {
        start: new Uint8Array([FORMAT_VERSION, kind]),
        end: new Uint8Array([FORMAT_VERSION, kind + 1]),
    };
}
export function createWasmSimplexVerifier(module, verificationKey) {
    const key = toSimplexBytes(verificationKey);
    const verifyNotarized = module.verify_notarized ?? module.parse_notarized;
    const verifyFinalized = module.verify_finalized ?? module.parse_finalized;
    if (!verifyNotarized) {
        throw new Error('simplex WASM verifier missing verify_notarized/parse_notarized');
    }
    if (!verifyFinalized) {
        throw new Error('simplex WASM verifier missing verify_finalized/parse_finalized');
    }
    return {
        verifyNotarization: (bytes) => verifyNotarized(copyBytes(key), copyBytes(bytes)),
        verifyFinalization: (bytes) => verifyFinalized(copyBytes(key), copyBytes(bytes)),
    };
}
export function createWasmSimplexHeaderVerifier(module) {
    if (!module.verify_header) {
        throw new Error('simplex WASM header verifier missing verify_header');
    }
    return ({ payload, header }) => module.verify_header(copyBytes(payload), copyBytes(header)) === true;
}
export function createWasmSimplexBlockVerifier(module) {
    if (!module.verify_block) {
        throw new Error('simplex WASM block verifier missing verify_block');
    }
    return ({ payload, header, body }) => module.verify_block(copyBytes(payload), copyBytes(header), copyBytes(body)) === true;
}
export function createCommonwareSimplexVerifier(module, options) {
    const namespace = toSimplexBytes(options.namespace);
    const verificationMaterial = toSimplexBytes(options.verificationMaterial);
    return {
        verifyNotarization: (bytes, context) => normalizeAndVerifyCommonwareCertificate(module.verify_notarized_commonware(options.scheme, copyBytes(namespace), copyBytes(verificationMaterial), copyBytes(bytes)), bytes, context, options.verifyHeader, options.verifyBlock),
        verifyFinalization: (bytes, context) => normalizeAndVerifyCommonwareCertificate(module.verify_finalized_commonware(options.scheme, copyBytes(namespace), copyBytes(verificationMaterial), copyBytes(bytes)), bytes, context, options.verifyHeader, options.verifyBlock),
    };
}
async function normalizeAndVerifyCommonwareCertificate(value, raw, context, verifyHeader, verifyBlock) {
    const certificate = normalizeCommonwareVerifiedCertificate(value);
    if (!certificate) {
        return null;
    }
    if (verifyHeader) {
        const verified = await verifyHeader({
            certificate,
            context,
            raw: copyBytes(raw),
            payload: copyBytes(certificate.payload),
            header: copyBytes(certificate.header),
        });
        if (!verified) {
            return null;
        }
    }
    if (verifyBlock) {
        const verified = await verifyBlock({
            certificate,
            context,
            raw: copyBytes(raw),
            payload: copyBytes(certificate.payload),
            header: copyBytes(certificate.header),
            body: copyBytes(certificate.body),
        });
        if (!verified) {
            return null;
        }
    }
    return certificate;
}
function normalizeCommonwareVerifiedCertificate(value) {
    if (!value) {
        return null;
    }
    if (typeof value !== 'object') {
        throw new Error('simplex Commonware verifier returned a non-object certificate');
    }
    const record = value;
    return {
        scheme: commonwareSchemeFromUnknown(record.scheme),
        view: u64FromUnknown(record.view, 'view'),
        parent: u64FromUnknown(record.parent, 'parent'),
        payload: bytesFromUnknown(record.payload, 'payload'),
        certificate: bytesFromUnknown(record.certificate, 'certificate'),
        header: bytesFromUnknown(record.header, 'header'),
        body: bytesFromUnknown(record.body, 'body'),
    };
}
function commonwareSchemeFromUnknown(value) {
    switch (value) {
        case 'ed25519':
        case 'secp256r1':
        case 'bls12381-multisig-min-pk':
        case 'bls12381-multisig-min-sig':
        case 'bls12381-threshold-standard-min-pk':
        case 'bls12381-threshold-standard-min-sig':
        case 'bls12381-threshold-vrf-min-pk':
        case 'bls12381-threshold-vrf-min-sig':
            return value;
        default:
            throw new Error(`simplex Commonware verifier returned unsupported scheme ${String(value)}`);
    }
}
function u64FromUnknown(value, field) {
    if (typeof value === 'bigint') {
        return value;
    }
    if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
        return BigInt(value);
    }
    if (typeof value === 'string' && /^[0-9]+$/.test(value)) {
        return BigInt(value);
    }
    throw new Error(`simplex Commonware verifier returned invalid ${field}`);
}
function bytesFromUnknown(value, field) {
    if (value instanceof Uint8Array) {
        return copyBytes(value);
    }
    if (Array.isArray(value) &&
        value.every((item) => Number.isInteger(item) && item >= 0 && item <= 0xff)) {
        return Uint8Array.from(value);
    }
    throw new Error(`simplex Commonware verifier returned invalid ${field} bytes`);
}
function emptySummary() {
    return {
        headers: 0,
        blocks: 0,
        notarizations: 0,
        finalizations: 0,
        finalizedHeightIndexes: 0,
    };
}
function prepared(entries, summary) {
    return { entries, summary };
}
function mergePrepared(items) {
    const summary = emptySummary();
    const entries = [];
    for (const item of items) {
        summary.headers += item.summary.headers;
        summary.blocks += item.summary.blocks;
        summary.notarizations += item.summary.notarizations;
        summary.finalizations += item.summary.finalizations;
        summary.finalizedHeightIndexes += item.summary.finalizedHeightIndexes;
        entries.push(...item.entries);
    }
    return { entries, summary };
}
function u64FromKey(key) {
    if (key.length !== 10) {
        throw new Error(`invalid simplex u64 key length ${key.length}`);
    }
    let value = 0n;
    for (let i = 2; i < 10; i++) {
        value = (value << 8n) | BigInt(key[i]);
    }
    return value;
}
function streamMatchKind(kind) {
    return {
        reservedBits: 16,
        prefix: (FORMAT_VERSION << 8) | kind,
        payloadRegex: STREAM_PAYLOAD_REGEX,
    };
}
function normalizeKinds(kinds) {
    return typeof kinds === 'number' ? [kinds] : [...kinds];
}
function decodeRawStreamEntry(key, value) {
    if (key.length < 2 || key[0] !== FORMAT_VERSION) {
        throw new Error('invalid simplex stream key');
    }
    const kind = key[1];
    switch (kind) {
        case SimplexRecordKind.HeaderByDigest:
            return {
                type: 'header',
                kind,
                key,
                digest: key.slice(2),
                header: value,
            };
        case SimplexRecordKind.BlockByDigest: {
            const block = decodeSimplexBlockData(value);
            return {
                type: 'block',
                kind,
                key,
                digest: key.slice(2),
                raw: value,
                header: block.header,
                body: block.body,
            };
        }
        case SimplexRecordKind.NotarizationByView:
            return {
                type: 'notarization',
                kind,
                key,
                view: u64FromKey(key),
                notarized: value,
            };
        case SimplexRecordKind.FinalizationByView:
            return {
                type: 'finalization',
                kind,
                index: 'view',
                key,
                view: u64FromKey(key),
                finalized: value,
            };
        case SimplexRecordKind.FinalizedByHeight:
            return {
                type: 'finalization',
                kind,
                index: 'height',
                key,
                height: u64FromKey(key),
                finalized: value,
            };
        default:
            throw new Error(`unknown simplex stream kind ${kind}`);
    }
}
export class SimplexClient {
    store;
    verifier;
    constructor(baseUrlOrStore, options = {}) {
        const { verifier, ...clientOptions } = options;
        this.verifier = verifier;
        this.store =
            typeof baseUrlOrStore === 'string'
                ? new Client(baseUrlOrStore, clientOptions).store()
                : baseUrlOrStore;
    }
    prepareHeader(input) {
        const header = toSimplexBytes(input.header);
        return prepared([
            {
                key: headerByDigestKey(input.digest),
                value: header,
            },
        ], { ...emptySummary(), headers: 1 });
    }
    prepareBlock(input) {
        const header = toSimplexBytes(input.header);
        const body = input.body === undefined ? new Uint8Array() : toSimplexBytes(input.body);
        return prepared([
            {
                key: headerByDigestKey(input.digest),
                value: header,
            },
            {
                key: blockByDigestKey(input.digest),
                value: encodeSimplexBlockData(header, body),
            },
        ], { ...emptySummary(), headers: 1, blocks: 1 });
    }
    prepareNotarization(input) {
        const entries = [];
        if (input.header !== undefined ||
            input.digest !== undefined ||
            input.body !== undefined) {
            if (input.header === undefined || input.digest === undefined) {
                throw new Error('header and digest must be provided together');
            }
            entries.push(this.prepareBlock({
                header: input.header,
                digest: input.digest,
                body: input.body,
            }));
        }
        entries.push(prepared([
            {
                key: notarizationByViewKey(input.view),
                value: toSimplexBytes(input.notarized),
            },
        ], { ...emptySummary(), notarizations: 1 }));
        return mergePrepared(entries);
    }
    prepareFinalization(input) {
        const entries = [];
        if (input.header !== undefined ||
            input.digest !== undefined ||
            input.body !== undefined) {
            if (input.header === undefined || input.digest === undefined) {
                throw new Error('header and digest must be provided together');
            }
            entries.push(this.prepareBlock({
                header: input.header,
                digest: input.digest,
                body: input.body,
            }));
        }
        const finalized = toSimplexBytes(input.finalized);
        entries.push(prepared([
            {
                key: finalizationByViewKey(input.view),
                value: finalized,
            },
            {
                key: finalizedByHeightKey(input.height),
                value: copyBytes(finalized),
            },
        ], { ...emptySummary(), finalizations: 1, finalizedHeightIndexes: 1 }));
        return mergePrepared(entries);
    }
    stageUpload(upload, batch = new StoreWriteBatch()) {
        if (upload.entries.length === 0) {
            throw new Error('simplex upload contains no rows');
        }
        for (const entry of upload.entries) {
            batch.push(this.store, entry.key, entry.value);
        }
        return batch;
    }
    async uploadPrepared(upload) {
        const sequence = await this.stageUpload(upload).commit(this.store);
        return {
            storeSequenceNumber: sequence,
            summary: upload.summary,
        };
    }
    async uploadHeader(input) {
        return this.uploadPrepared(this.prepareHeader(input));
    }
    async uploadBlock(input) {
        return this.uploadPrepared(this.prepareBlock(input));
    }
    async uploadNotarization(input) {
        return this.uploadPrepared(this.prepareNotarization(input));
    }
    async uploadFinalization(input) {
        return this.uploadPrepared(this.prepareFinalization(input));
    }
    async getHeader(digest) {
        return this.getHeaderRaw(digest);
    }
    async getHeaderRaw(digest) {
        return this.getRaw(headerByDigestKey(digest));
    }
    async getBlock(digest) {
        const raw = await this.getBlockRaw(digest);
        return raw === null ? null : decodeSimplexBlockData(raw);
    }
    async getBlockRaw(digest) {
        return this.getRaw(blockByDigestKey(digest));
    }
    async getNotarization(view) {
        const key = notarizationByViewKey(view);
        const raw = await this.getRaw(key);
        if (raw === null) {
            return null;
        }
        return this.verifyNotarization(raw, {
            kind: 'notarization',
            source: 'get',
            key,
            value: raw,
            view: normalizeU64(view),
        });
    }
    async getNotarizationRaw(view) {
        return this.getRaw(notarizationByViewKey(view));
    }
    async getFinalizationByView(view) {
        const key = finalizationByViewKey(view);
        const raw = await this.getRaw(key);
        if (raw === null) {
            return null;
        }
        return this.verifyFinalization(raw, {
            kind: 'finalization',
            index: 'view',
            source: 'get',
            key,
            value: raw,
            view: normalizeU64(view),
        });
    }
    async getFinalizationByViewRaw(view) {
        return this.getRaw(finalizationByViewKey(view));
    }
    async getFinalizationByHeight(height) {
        const key = finalizedByHeightKey(height);
        const raw = await this.getRaw(key);
        if (raw === null) {
            return null;
        }
        return this.verifyFinalization(raw, {
            kind: 'finalization',
            index: 'height',
            source: 'get',
            key,
            value: raw,
            height: normalizeU64(height),
        });
    }
    async getFinalizationByHeightRaw(height) {
        return this.getRaw(finalizedByHeightKey(height));
    }
    async latestFinalization() {
        const range = rangeForKind(SimplexRecordKind.FinalizedByHeight);
        const result = await this.store.query(range.start, range.end, 1, 4096, TraversalMode.REVERSE);
        const row = result.results[0];
        if (!row) {
            return null;
        }
        return this.verifyFinalization(row.value, {
            kind: 'finalization',
            index: 'latest',
            source: 'get',
            key: row.key,
            value: row.value,
            height: u64FromKey(row.key),
        });
    }
    async latestFinalizationRaw() {
        const range = rangeForKind(SimplexRecordKind.FinalizedByHeight);
        const result = await this.store.query(range.start, range.end, 1, 4096, TraversalMode.REVERSE);
        return result.results[0]?.value ?? null;
    }
    async *subscribeRaw(kinds, options = {}, callOptions) {
        const stream = this.store.subscribe({
            matchKeys: normalizeKinds(kinds).map(streamMatchKind),
            ...(options.sinceSequenceNumber !== undefined
                ? { sinceSequenceNumber: options.sinceSequenceNumber }
                : {}),
        }, callOptions);
        for await (const batch of stream) {
            yield {
                sequenceNumber: batch.sequenceNumber,
                entries: batch.entries.map((entry) => decodeRawStreamEntry(entry.key, entry.value)),
            };
        }
    }
    async *subscribeBlocks(options = {}, callOptions) {
        for await (const batch of this.subscribeRaw(SimplexRecordKind.BlockByDigest, options, callOptions)) {
            yield {
                sequenceNumber: batch.sequenceNumber,
                entries: batch.entries.flatMap((entry) => (entry.type === 'block' ? [entry] : [])),
            };
        }
    }
    async *subscribeHeaders(options = {}, callOptions) {
        for await (const batch of this.subscribeRaw(SimplexRecordKind.HeaderByDigest, options, callOptions)) {
            yield {
                sequenceNumber: batch.sequenceNumber,
                entries: batch.entries.flatMap((entry) => (entry.type === 'header' ? [entry] : [])),
            };
        }
    }
    async *subscribeCertificatesRaw(options = {}, callOptions) {
        const kinds = [
            SimplexRecordKind.NotarizationByView,
            SimplexRecordKind.FinalizationByView,
            ...(options.includeFinalizedByHeight ? [SimplexRecordKind.FinalizedByHeight] : []),
        ];
        for await (const batch of this.subscribeRaw(kinds, options, callOptions)) {
            yield {
                sequenceNumber: batch.sequenceNumber,
                entries: batch.entries.flatMap((entry) => entry.type === 'header' || entry.type === 'block' ? [] : [entry]),
            };
        }
    }
    async *subscribeCertificates(options = {}, callOptions) {
        for await (const batch of this.subscribeCertificatesRaw(options, callOptions)) {
            const entries = [];
            for (const entry of batch.entries) {
                if (entry.type === 'notarization') {
                    const certificate = await this.verifyNotarization(entry.notarized, {
                        kind: 'notarization',
                        source: 'stream',
                        key: entry.key,
                        value: entry.notarized,
                        view: entry.view,
                    });
                    entries.push({
                        type: 'notarization',
                        kind: entry.kind,
                        key: entry.key,
                        view: entry.view,
                        raw: entry.notarized,
                        certificate,
                    });
                }
                else if (entry.index === 'view') {
                    const certificate = await this.verifyFinalization(entry.finalized, {
                        kind: 'finalization',
                        index: 'view',
                        source: 'stream',
                        key: entry.key,
                        value: entry.finalized,
                        view: entry.view,
                    });
                    entries.push({
                        type: 'finalization',
                        kind: entry.kind,
                        index: 'view',
                        key: entry.key,
                        view: entry.view,
                        raw: entry.finalized,
                        certificate,
                    });
                }
                else {
                    const certificate = await this.verifyFinalization(entry.finalized, {
                        kind: 'finalization',
                        index: 'height',
                        source: 'stream',
                        key: entry.key,
                        value: entry.finalized,
                        height: entry.height,
                    });
                    entries.push({
                        type: 'finalization',
                        kind: entry.kind,
                        index: 'height',
                        key: entry.key,
                        height: entry.height,
                        raw: entry.finalized,
                        certificate,
                    });
                }
            }
            yield {
                sequenceNumber: batch.sequenceNumber,
                entries,
            };
        }
    }
    async getRaw(key) {
        const result = await this.store.get(key);
        return result?.value ?? null;
    }
    requireVerifier() {
        if (!this.verifier) {
            throw new Error('simplex certificate read requires a configured verifier; use the *Raw method for unverified bytes');
        }
        return this.verifier;
    }
    async verifyNotarization(bytes, context) {
        const verified = await this.requireVerifier().verifyNotarization(copyBytes(bytes), context);
        if (!verified) {
            throw new Error('simplex notarization verification failed');
        }
        return verified;
    }
    async verifyFinalization(bytes, context) {
        const verified = await this.requireVerifier().verifyFinalization(copyBytes(bytes), context);
        if (!verified) {
            throw new Error('simplex finalization verification failed');
        }
        return verified;
    }
}
