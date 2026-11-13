/**
 * The retention rule of the log, with its stored form, the cutoff it implies, and the
 * SetRetention handler. A Put applies the installed rule inside its own transaction with the
 * helpers here.
 */

import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import {
    RetentionPolicySchema,
    type RetentionPolicy,
    type SetRetentionRequest,
    type SetRetentionResponseSchema,
} from '../gen/ts/log/v1/retention_pb.js';
import type { MessageInitShape } from '@bufbuild/protobuf';
import { invalidArgument, metadataCorrupt } from './errors.js';
import {
    LOG,
    MAX_SEQUENCE,
    META,
    RETENTION_KEY,
    RETENTION_SCOPE,
    logKeysBelow,
    oldestRetained,
    ownedBuffer,
    readSequence,
    settle,
    storedMetaBytes,
    write,
} from './idb.js';

/** A validated retention rule, holding only the fields the rule defines. */
export type RetentionRule =
    | { case: 'keepLatest'; value: { count: bigint } }
    | { case: 'greaterThan'; value: { threshold: bigint } }
    | { case: 'greaterThanOrEqual'; value: { threshold: bigint } }
    | { case: 'dropAll'; value: Record<string, never> };

/** Validates a policy message and reduces it to its rule. */
export function retentionRule(policy: RetentionPolicy): RetentionRule {
    const { kind } = policy;
    switch (kind.case) {
        case 'keepLatest':
            if (kind.value.count === 0n) throw invalidArgument('keep_latest count must be > 0');
            return { case: 'keepLatest', value: { count: kind.value.count } };
        case 'greaterThan':
        case 'greaterThanOrEqual':
            return { case: kind.case, value: { threshold: kind.value.threshold } };
        case 'dropAll':
            return { case: 'dropAll', value: {} };
        default:
            throw invalidArgument('retention policy kind is required');
    }
}

/**
 * The lowest sequence number that `rule` keeps when the store is at `sequence`, at most one above
 * `sequence`. Every batch below it is evicted.
 */
export function retentionCutoff(rule: RetentionRule, sequence: bigint): bigint {
    const next = sequence < MAX_SEQUENCE ? sequence + 1n : MAX_SEQUENCE;
    let lowestKept: bigint;
    switch (rule.case) {
        case 'keepLatest':
            lowestKept = (sequence > rule.value.count ? sequence - rule.value.count : 0n) + 1n;
            break;
        case 'greaterThan':
            lowestKept = rule.value.threshold < MAX_SEQUENCE ? rule.value.threshold + 1n : MAX_SEQUENCE;
            break;
        case 'greaterThanOrEqual':
            lowestKept = rule.value.threshold;
            break;
        case 'dropAll':
            lowestKept = next;
            break;
    }
    return lowestKept < next ? lowestKept : next;
}

/**
 * Longest stored rule in bytes, as the database layout sets it. A reader accepts every valid
 * encoding of a rule up to this length. The rule that this store writes takes 13 bytes at most.
 */
const MAX_STORED_RULE_BYTES = 1024;

/**
 * Reads the installed rule, undefined when none is installed. A row longer than the layout allows,
 * or one that does not decode to a valid rule, is corrupt metadata. The length is checked before
 * the row is copied or decoded. Fields that the rule does not define are dropped.
 */
export async function readRetentionRule(meta: IDBObjectStore): Promise<RetentionRule | undefined> {
    const stored = await settle(meta.get(RETENTION_KEY));
    if (stored === undefined) return undefined;
    const bytes = storedMetaBytes(stored, MAX_STORED_RULE_BYTES);
    try {
        return retentionRule(fromBinary(RetentionPolicySchema, bytes, { readUnknownFields: false }));
    } catch {
        throw metadataCorrupt();
    }
}

/**
 * The SetRetention handler. In one transaction it installs or clears the rule and applies an
 * installed rule to the log once. The answer is the lowest sequence number still in the log,
 * which the transaction reads and checks before it places its first write.
 */
export function setRetentionHandler(db: IDBDatabase) {
    return async (
        request: SetRetentionRequest,
    ): Promise<MessageInitShape<typeof SetRetentionResponseSchema>> => {
        const rule = request.policy === undefined ? undefined : retentionRule(request.policy);
        const encoded = rule === undefined
            ? undefined
            : ownedBuffer(toBinary(RetentionPolicySchema, create(RetentionPolicySchema, { kind: rule })));
        const oldest = await write(db, RETENTION_SCOPE, async (tx) => {
            const meta = tx.objectStore(META);
            const log = tx.objectStore(LOG);
            const sequence = await readSequence(meta);
            const cutoff = rule === undefined ? 0n : retentionCutoff(rule, sequence);
            const oldest = await oldestRetained(log, sequence, cutoff);

            let last: IDBRequest;
            if (rule === undefined || encoded === undefined) {
                last = meta.delete(RETENTION_KEY);
            } else {
                last = meta.put(encoded, RETENTION_KEY);
                const evicted = logKeysBelow(cutoff);
                if (evicted !== undefined) last = log.delete(evicted);
            }
            await settle(last);
            return oldest;
        });
        return oldest === undefined ? {} : { oldestRetainedSequence: oldest };
    };
}
