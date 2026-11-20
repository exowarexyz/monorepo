/**
 * The Prune handler. It deletes current rows by policy. The whole request is one transaction over
 * the rows, so it applies completely or not at all and no other operation sees it half done.
 *
 * The transaction first selects the keys to delete for every policy and only then places deletes.
 * The keys it holds while it selects and the matcher of the policy it scans are charged to the
 * query budget, so a selection that is too large fails before anything is deleted.
 *
 * A call that is canceled while the keys are selected ends the transaction at the next key and
 * deletes nothing. A cancellation that arrives once the first delete is placed does not stop the
 * Prune.
 */

import type { MessageInitShape } from '@bufbuild/protobuf';
import { Code, ConnectError, type HandlerContext } from '@connectrpc/connect';
import {
    PolicyOrderEncoding,
    type Policy,
    type PruneRequest,
    type PruneResponseSchema,
} from '../gen/ts/store/v1/prune_pb.js';
import { MAX_KEY_LEN } from '../limits.js';
import { canceled, fieldError, invalidArgument, quoted } from './errors.js';
import { KV, PRUNE_SCOPE, REQUEST_CHUNK, exactBuffer, rowKey, settle, walk, write } from './idb.js';
import { QueryBudget, ROW_OVERHEAD_BYTES } from './query.js';
import type { Regex, RegexCaptures, RegexCapturer } from './regex.js';
import { KeySelector, checkSelectorPrefix } from './selector.js';

/**
 * Maximum number of policies in one request. Each policy compiles a pattern and is compared with
 * every other policy, so the count bounds the work a request can ask for before it reads a row.
 */
export const MAX_PRUNE_POLICIES = 256;

type Retain =
    | { case: 'keepLatest'; count: bigint }
    | { case: 'greaterThan' | 'greaterThanOrEqual'; threshold: bigint }
    | { case: 'dropAll' };

interface OrderBy {
    captureGroup: string;
    encoding: PolicyOrderEncoding;
}

/** The fields of a policy that has every required part. */
interface PolicyShape {
    prefix: Uint8Array;
    payloadRegex: string;
    groupBy: string[];
    orderBy: OrderBy | undefined;
    retain: Retain;
}

interface CompiledPolicy extends Omit<PolicyShape, 'prefix' | 'payloadRegex'> {
    selector: KeySelector;
}

/**
 * The value a key is ordered by. It is the decoded integer for an integer encoding and the
 * captured bytes otherwise.
 */
type OrderValue = bigint | Uint8Array;

interface Candidate {
    key: Uint8Array;
    order: OrderValue;
}

const NO_BYTES = new Uint8Array(0);

function shapeOf(policy: Policy): PolicyShape {
    const { keys, retain } = policy;
    if (keys === undefined) throw invalidArgument('prune policy keys scope is required');
    if (keys.selector === undefined) throw invalidArgument('keys scope selector is required');
    const orderBy = keys.orderBy;
    if (orderBy !== undefined && PolicyOrderEncoding[orderBy.encoding] === undefined) {
        throw invalidArgument('order_by.encoding must be a known PolicyOrderEncoding value');
    }
    if (retain === undefined) throw invalidArgument('prune policy retain is required');
    let kept: Retain;
    switch (retain.kind.case) {
        case 'keepLatest':
            kept = { case: 'keepLatest', count: retain.kind.value.count };
            break;
        case 'greaterThan':
        case 'greaterThanOrEqual':
            kept = { case: retain.kind.case, threshold: retain.kind.value.threshold };
            break;
        case 'dropAll':
            kept = { case: 'dropAll' };
            break;
        default:
            throw invalidArgument('prune policy retain.kind is required');
    }
    return {
        prefix: keys.selector.prefix,
        payloadRegex: keys.selector.payloadRegex,
        groupBy: keys.groupBy?.captureGroups ?? [],
        orderBy: orderBy && { captureGroup: orderBy.captureGroup, encoding: orderBy.encoding },
        retain: kept,
    };
}

function compile(shape: PolicyShape): CompiledPolicy {
    checkSelectorPrefix(shape.prefix, () => 'invalid selector prefix');
    const selector = new KeySelector(shape);
    const { groupBy, orderBy, retain } = shape;
    const checkGroup = (name: string, label: string) => {
        if (!selector.regex.hasGroup(name)) {
            throw invalidArgument(`${label} references unknown capture group Utf8(${quoted(name)})`);
        }
    };
    for (const name of groupBy) checkGroup(name, 'group_by capture_groups');
    if (new Set(groupBy).size !== groupBy.length) {
        throw invalidArgument('group_by capture_groups must not contain duplicates');
    }
    if (orderBy !== undefined) checkGroup(orderBy.captureGroup, 'order_by capture_group');
    if (retain.case === 'keepLatest') {
        if (retain.count === 0n) throw invalidArgument('keep_latest count must be > 0');
        if (orderBy === undefined) throw invalidArgument('keep_latest requires order_by to be configured');
    } else if (retain.case !== 'dropAll') {
        if (orderBy === undefined) {
            throw invalidArgument('threshold retention requires order_by to be configured');
        }
        if (orderBy.encoding !== PolicyOrderEncoding.U64_BE) {
            throw invalidArgument('threshold retention currently requires order_by.encoding = u64_be');
        }
    }
    return { selector, groupBy, orderBy, retain };
}

function isPrefixOf(prefix: Uint8Array, bytes: Uint8Array): boolean {
    return prefix.byteLength <= bytes.byteLength && prefix.every((byte, i) => bytes[i] === byte);
}

/**
 * Validates the request in the order the Rust server does. After the number of policies come the
 * shape of every policy, each policy, and then the rule that no two selector prefixes overlap. Two
 * prefixes overlap when one is a prefix of the other, and then two policies could apply to one row.
 */
function compilePolicies(request: PruneRequest): CompiledPolicy[] {
    if (request.policies.length === 0) {
        throw fieldError(
            'store.prune',
            'policies',
            'at least one policy is required',
            'INVALID_PRUNE_REQUEST',
            'prune request must contain at least one policy',
        );
    }
    if (request.policies.length > MAX_PRUNE_POLICIES) {
        throw new ConnectError(
            `prune request has ${request.policies.length} policies, more than the ${MAX_PRUNE_POLICIES} this store accepts`,
            Code.ResourceExhausted,
        );
    }
    const policies = request.policies.map(shapeOf).map(compile);
    for (const [index, { selector }] of policies.entries()) {
        for (const seen of policies.slice(0, index)) {
            const other = seen.selector.prefix;
            if (isPrefixOf(selector.prefix, other) || isPrefixOf(other, selector.prefix)) {
                throw invalidArgument(
                    `overlapping compaction prune policies for key prefixes [${other.join(', ')}] and [${selector.prefix.join(', ')}]`,
                );
            }
        }
    }
    return policies;
}

/**
 * The identity of a key's group as a map key, undefined when a group_by capture is missing. Each
 * capture adds its length and then its bytes, one character each, so distinct lists of captures
 * give distinct identities.
 */
function groupOf(captures: RegexCaptures, groupBy: readonly string[]): string | undefined {
    let group = '';
    for (const name of groupBy) {
        const bytes = captures.named(name);
        if (bytes === undefined) return undefined;
        group += String.fromCharCode(bytes.byteLength, ...bytes);
    }
    return group;
}

function integerOf(bytes: Uint8Array, encoding: PolicyOrderEncoding): bigint {
    // A capture that is not 8 bytes long orders as 0.
    if (bytes.byteLength !== 8) return 0n;
    const view = new DataView(bytes.buffer, bytes.byteOffset, 8);
    return encoding === PolicyOrderEncoding.I64_BE ? view.getBigInt64(0) : view.getBigUint64(0);
}

function orderOf(captures: RegexCaptures, orderBy: OrderBy | undefined): OrderValue {
    const bytes = (orderBy && captures.named(orderBy.captureGroup)) ?? NO_BYTES;
    if (orderBy === undefined || orderBy.encoding === PolicyOrderEncoding.BYTES_ASC) return bytes;
    return integerOf(bytes, orderBy.encoding);
}

function compareOrder(a: OrderValue, b: OrderValue): number {
    if (typeof a === 'bigint' || typeof b === 'bigint') return a < b ? -1 : a > b ? 1 : 0;
    const shared = Math.min(a.byteLength, b.byteLength);
    for (let i = 0; i < shared; i++) {
        if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.byteLength - b.byteLength;
}

/** The keys of one group that the policy deletes. */
function doomed(group: Candidate[], retain: Retain): Candidate[] {
    // The sort is stable, so keys with equal order values stay in key order.
    group.sort((a, b) => compareOrder(a.order, b.order));
    switch (retain.case) {
        case 'keepLatest':
            return BigInt(group.length) <= retain.count ? [] : group.slice(0, group.length - Number(retain.count));
        case 'greaterThan':
            return group.filter(({ order }) => (order as bigint) <= retain.threshold);
        case 'greaterThanOrEqual':
            return group.filter(({ order }) => (order as bigint) < retain.threshold);
        case 'dropAll':
            return group;
    }
}

/**
 * A matcher that records the groups a policy reads. A typed array that the engine fails to
 * allocate makes the request RESOURCE_EXHAUSTED.
 */
function capturerOf(regex: Regex, names: readonly string[]): RegexCapturer {
    try {
        return regex.capturer(names);
    } catch (error) {
        if (!(error instanceof RangeError)) throw error;
        throw new ConnectError('prune pattern needs more memory than is available', Code.ResourceExhausted);
    }
}

/**
 * Scans the keys under the policy's prefix and returns the keys that the policy does not retain.
 * The matcher is charged to `budget` before it is built and released once the keys are selected,
 * so the budget holds one matcher at a time. Every key that joins a group is charged with its
 * order value, and every new group is charged for its identity. These charges stay until the
 * request ends. The scan fails at the next key once `signal` has aborted.
 */
async function select(
    kv: IDBObjectStore,
    policy: CompiledPolicy,
    budget: QueryBudget,
    signal: AbortSignal,
): Promise<Uint8Array[]> {
    const { selector, groupBy, orderBy, retain } = policy;
    const names = orderBy === undefined ? groupBy : [...groupBy, orderBy.captureGroup];
    const matcherBytes = selector.regex.capturerBytes(names);
    budget.charge(matcherBytes);
    const matcher = capturerOf(selector.regex, names);

    // Every key under the prefix lies between the prefix itself and the prefix padded with 0xff to
    // the longest key length.
    const upper = new Uint8Array(MAX_KEY_LEN).fill(0xff);
    upper.set(selector.prefix);
    const keys = IDBKeyRange.bound(exactBuffer(selector.prefix), upper.buffer);

    const groups = new Map<string, Candidate[]>();
    await walk(kv.openKeyCursor(keys), (cursor) => {
        if (signal.aborted) throw canceled(signal);
        const key = rowKey(cursor.key);
        const payload = selector.payload(key);
        if (payload === undefined) return true;
        const captures = matcher.captures(payload);
        if (captures === null) return true;

        // A key whose match leaves a group_by capture out belongs to no group.
        const group = groupOf(captures, groupBy);
        if (group === undefined) return true;
        const order = orderOf(captures, orderBy);
        const orderBytes = typeof order === 'bigint' ? 8 : order.byteLength;
        budget.charge(key.byteLength + orderBytes + ROW_OVERHEAD_BYTES);
        const members = groups.get(group);
        if (members === undefined) {
            budget.charge(group.length);
            groups.set(group, [{ key, order }]);
        } else {
            members.push({ key, order });
        }
        return true;
    });

    const selected: Uint8Array[] = [];
    for (const group of groups.values()) {
        for (const { key } of doomed(group, retain)) selected.push(key);
    }
    budget.release(matcherBytes);
    return selected;
}

/** Places the deletes of every selected key, a chunk at a time. */
async function deleteKeys(kv: IDBObjectStore, selections: readonly Uint8Array[][]): Promise<void> {
    let last: IDBRequest | undefined;
    let placed = 0;
    for (const keys of selections) {
        for (const key of keys) {
            last = kv.delete(key.buffer as ArrayBuffer);
            if (++placed % REQUEST_CHUNK === 0) {
                await settle(last);
                last = undefined;
            }
        }
    }
    if (last !== undefined) await settle(last);
}

/** The Prune handler. The keys a request selects count against a budget of `maxQueryBytes`. */
export function pruneHandler(db: IDBDatabase, maxQueryBytes: number) {
    return async (
        request: PruneRequest,
        context: HandlerContext,
    ): Promise<MessageInitShape<typeof PruneResponseSchema>> => {
        const policies = compilePolicies(request);
        const { signal } = context;
        if (signal.aborted) throw canceled(signal);
        await write(db, PRUNE_SCOPE, async (tx) => {
            const kv = tx.objectStore(KV);
            const budget = new QueryBudget(maxQueryBytes, 'prune selection');
            const selections: Uint8Array[][] = [];
            for (const policy of policies) selections.push(await select(kv, policy, budget, signal));

            // The last point where a cancellation stops the Prune. The scan of a policy without
            // keys visits none and so cannot see one.
            if (signal.aborted) throw canceled(signal);
            await deleteKeys(kv, selections);
        });
        return {};
    };
}
