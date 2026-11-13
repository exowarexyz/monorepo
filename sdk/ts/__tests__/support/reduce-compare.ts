/**
 * Comparison of the answers of two stores to one Reduce request.
 *
 * An answer is the frames a store delivered and the error that ended the call, if any. The
 * comparison covers what the service defines.
 *
 * - Groups are compared as a multiset. The order of groups is not part of the contract.
 * - A NaN is compared by its bits. A request can also make a NaN whose sign and payload the
 *   service does not define, by an invalid operation such as 0/0 or by an operation on two NaNs.
 *   The evaluator tells which requests do. In those alone a NaN equals any NaN, and what depends
 *   on such a NaN is compared only as far as it is defined. A MIN or MAX without group_by over
 *   an arithmetic expression may be NaN on one side and a number on the other, because the sign
 *   of a NaN decides the end of the total order it lies at. Groups keyed by such a NaN of an
 *   arithmetic expression are merged when they differ only in its bits, and compared by their
 *   other keys and their counts.
 * - Error codes must agree. Error messages and details are compared and reported separately. A
 *   request without group_by delivers no frame before an error.
 * - Groups delivered before an error that ends a stream of frames are not compared.
 * - The store under test may answer UNIMPLEMENTED for the classes of expressions that it
 *   documents, where the class fits the request and the reference does not reject the request as
 *   invalid.
 */
import { create, toBinary } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import { BadRequestSchema, ErrorInfoSchema } from '../../src/gen/ts/google/rpc/error_details_pb';
import {
    RangeReduceOp,
    ReduceResponseSchema,
    type KvExpr,
    type KvReducedValue,
    type RangeReduceGroup,
    type ReduceRequest,
    type ReduceResponse,
} from '../../src/gen/ts/store/v1/query_pb';
import { details, hex } from './contract';

/** The answer of a store: the frames it delivered and the error that ended the call, if any. */
export interface Outcome {
    frames: ReduceResponse[];
    error?: ConnectError;
}

/** Drains the frames of a call into an answer. */
export async function answer(frames: AsyncIterable<ReduceResponse>): Promise<Outcome> {
    const outcome: Outcome = { frames: [] };
    try {
        for await (const frame of frames) outcome.frames.push(frame);
    } catch (error) {
        outcome.error = ConnectError.from(error);
    }
    return outcome;
}

/** Whether an expression, or an expression inside it, is of the given case. */
function holds(expr: KvExpr | undefined, kind: KvExpr['expr']['case']): boolean {
    if (expr === undefined) return false;
    const e = expr.expr;
    if (e.case === kind) return true;
    switch (e.case) {
        case 'add': case 'sub': case 'mul': case 'div': return holds(e.value.left, kind) || holds(e.value.right, kind);
        case 'lower': case 'dateTruncDay': case 'castFloat64': return holds(e.value, kind);
        default: return false;
    }
}

/**
 * The classes of expressions for which the store under test answers UNIMPLEMENTED, as its README
 * lists them. Each class is keyed by its message up to the first colon and maps to a test of
 * whether the class fits a request and the rest of the message. date_trunc_day over a string
 * needs a date_trunc_day in the request. Mixed units must name two operands of different units
 * after the colon, a timestamp or duration of microseconds and one of nanoseconds.
 */
const UNIMPLEMENTED_CLASSES: Record<string, (request: ReduceRequest, operands: string) => boolean> = {
    'date_trunc_day over a string is not implemented': (request) =>
        [...(request.params?.groupBy ?? []), ...(request.params?.reducers ?? []).map((reducer) => reducer.expr)]
            .some((expr) => holds(expr, 'dateTruncDay')),
    'timestamp and duration arithmetic with mixed units is not implemented': (_, operands) => {
        const units = [...operands.matchAll(/\((\u00b5s|ns)\)/g)].map((match) => match[1]);
        return units.length === 2 && units[0] !== units[1];
    },
};

/** How the answers of two stores to one request compare. */
export interface Comparison {
    /**
     * How the answers compare. outside means that the store under test answered UNIMPLEMENTED
     * for one of its documented classes, that the class fits the request and that the reference
     * did not reject the request as invalid.
     */
    status: 'identical' | 'different' | 'outside';
    /** What differs, the UNIMPLEMENTED message for outside, or empty when nothing differs. */
    detail: string;
    /** Both failed with the same code and different messages or details. */
    textDiffers: boolean;
    /**
     * Part of the answer was compared only as far as it is defined, because it depended on a NaN
     * without a defined sign and payload or came in frames before an error.
     */
    limited: boolean;
}

function fromBytes(bytes: Uint8Array, bits: number, littleEndian: boolean): bigint {
    let value = 0n;
    for (const byte of littleEndian ? Array.from(bytes).reverse() : bytes) value = (value << 8n) | BigInt(byte);
    return BigInt.asIntN(bits, value);
}

const view = new DataView(new ArrayBuffer(8));
const NAN = 'f64:NaN';

/**
 * A value as text of its variant and content. A decimal shows its unscaled integer. Every NaN
 * renders the same unless nanBits asks for its bits.
 */
export function render(value: KvReducedValue | undefined, nanBits = false): string {
    if (value === undefined) return 'NULL';
    const v = value.value;
    switch (v.case) {
        case 'int64Value': return 'i64:' + v.value;
        case 'uint64Value': return 'u64:' + v.value;
        case 'float64Value':
            if (Number.isNaN(v.value) && !nanBits) return NAN;
            view.setFloat64(0, v.value);
            return 'f64:' + (Object.is(v.value, -0) ? '-0' : v.value) + '/' + view.getBigUint64(0).toString(16);
        case 'booleanValue': return 'bool:' + v.value;
        case 'utf8Value': return 'utf8:' + JSON.stringify(v.value);
        case 'date32Value': return 'date32:' + v.value;
        case 'date64Value': return 'date64:' + v.value;
        case 'timestampValue': return 'ts:' + v.value;
        case 'decimal128Value': return 'd128:' + fromBytes(v.value, 128, false);
        case 'decimal256Value': return 'd256:' + fromBytes(v.value, 256, true);
        case 'fixedSizeBinaryValue': return 'fsb:' + hex(v.value);
        default: return 'unset';
    }
}

/** The keys of a group in group_by order, NULL included. nanBits is as in render. */
export function renderKeys(group: RangeReduceGroup, nanBits = false): string[] {
    let dense = 0;
    return group.groupValuesPresent.map((present) => (present ? render(group.groupValues[dense++], nanBits) : 'NULL'));
}

export const renderResults = (results: { value?: KvReducedValue }[], nanBits = false): string[] =>
    results.map((result) => render(result.value, nanBits));

/** The parts of an error that the comparison checks. */
export interface ErrorDescription {
    code: string;
    message: string;
    /** Field and description of the BadRequest violation of an INVALID_ARGUMENT. */
    field?: string;
    description?: string;
    /** Reason, domain and metadata of its ErrorInfo. */
    reason?: string;
    domain?: string;
    metadata?: Record<string, string>;
}

/** The parts of an error that the comparison checks, with the metadata in a fixed order. */
export function describeError(error: ConnectError): ErrorDescription {
    const violation = details(error, BadRequestSchema)[0]?.fieldViolations[0];
    const info = details(error, ErrorInfoSchema)[0];
    return {
        code: Code[error.code],
        message: error.rawMessage,
        ...(violation === undefined ? {} : { field: violation.field, description: violation.description }),
        // The entries of the metadata map have no order on the wire.
        ...(info === undefined ? {} : { reason: info.reason, domain: info.domain, metadata: Object.fromEntries(Object.entries(info.metadata).sort()) }),
    };
}

/** An error as one line of its code, its message and its BadRequest description. */
export function showError(error: ConnectError): string {
    const { code, message, description } = describeError(error);
    return code + ' [' + message + ']' + (description === undefined ? '' : ' [' + description + ']');
}

/** Whether an expression holds an arithmetic operation, also below a function. */
function containsArithmetic(expr: KvExpr | undefined): boolean {
    if (expr === undefined) return false;
    const e = expr.expr;
    switch (e.case) {
        case 'add': case 'sub': case 'mul': case 'div': return true;
        case 'lower': case 'dateTruncDay': case 'castFloat64': return containsArithmetic(e.value);
        default: return false;
    }
}

/** The most groups that a frame may carry. */
const FRAME_GROUPS = 4096;

/** The first way in which the frames of a successful answer break the framing rules. */
function frameProblem(request: ReduceRequest, frames: ReduceResponse[], smallGroups: boolean): string | undefined {
    const reducers = request.params?.reducers.length ?? 0;
    if (frames.some((frame) => frame.detail === undefined)) return 'a frame without detail';
    if (new Set(frames.map((frame) => frame.detail?.sequenceNumber)).size > 1) return 'frames with different sequence numbers';
    if ((request.params?.groupBy.length ?? 0) === 0) {
        if (frames.length !== 1) return 'a request without group_by must return one frame, got ' + frames.length;
        if (frames[0].groups.length !== 0) return 'a request without group_by returned groups';
        if (frames[0].results.length !== reducers) return 'expected ' + reducers + ' results, got ' + frames[0].results.length;
        return undefined;
    }
    if (frames.some((frame) => frame.results.length !== 0)) return 'a request with group_by returned results outside groups';
    const groups = frames.reduce((count, frame) => count + frame.groups.length, 0);
    if (frames.some((frame) => frame.groups.length > FRAME_GROUPS)) return 'a frame with more than ' + FRAME_GROUPS + ' groups';
    if (groups === 0 ? frames.length !== 1 : frames.some((frame) => frame.groups.length === 0)) return 'a frame without groups';
    const expected = Math.max(1, Math.ceil(groups / FRAME_GROUPS));
    if (smallGroups && frames.length !== expected) return groups + ' groups in ' + frames.length + ' frames, expected ' + expected;
    for (const frame of frames) {
        for (const group of frame.groups) {
            if (group.results.length !== reducers) return 'a group with ' + group.results.length + ' results, expected ' + reducers;
            if (group.groupValuesPresent.length !== request.params?.groupBy.length) return 'a group with the wrong number of keys';
        }
    }
    return undefined;
}

/**
 * The first difference in the results or groups, and whether part of them was compared only as
 * far as it is defined.
 */
interface Part {
    detail?: string;
    limited: boolean;
}

/** Compares the results of a request without group_by. unspecifiedNaN is as in CompareOptions. */
function compareScalar(request: ReduceRequest, expected: string[], actual: string[], unspecifiedNaN: boolean): Part {
    let limited = false;
    for (let i = 0; i < expected.length; i++) {
        if (expected[i] === actual[i]) continue;
        const reducer = request.params?.reducers[i];
        const extremum = reducer?.op === RangeReduceOp.MIN_FIELD || reducer?.op === RangeReduceOp.MAX_FIELD;
        const floats = expected[i].startsWith('f64:') && actual[i].startsWith('f64:');
        const oneIsNaN = expected[i] === NAN || actual[i] === NAN;
        if (unspecifiedNaN && extremum && floats && oneIsNaN && containsArithmetic(reducer?.expr)) {
            limited = true;
            continue;
        }
        return { detail: 'result ' + i + ': expected [' + expected.join(', ') + '] got [' + actual.join(', ') + ']', limited };
    }
    return { limited };
}

/** The first difference between two group indexes, each mapping a key to the text of its groups. */
function groupDifference(expected: Map<string, string>, actual: Map<string, string>): string | undefined {
    for (const [key, value] of expected) {
        if (!actual.has(key)) return 'group (' + key + ') is missing';
        if (actual.get(key) !== value) return 'group (' + key + '): expected [' + value + '] got [' + actual.get(key) + ']';
    }
    for (const key of actual.keys()) if (!expected.has(key)) return 'unexpected group (' + key + ')';
    return undefined;
}

/** Compares the groups of a request with group_by. unspecifiedNaN is as in CompareOptions. */
function compareGroups(request: ReduceRequest, expected: RangeReduceGroup[], actual: RangeReduceGroup[], unspecifiedNaN: boolean): Part {
    const computed = (request.params?.groupBy ?? []).map(containsArithmetic);
    const counts = (request.params?.reducers ?? []).map((reducer) =>
        reducer.op === RangeReduceOp.COUNT_ALL || reducer.op === RangeReduceOp.COUNT_FIELD);

    // Indexes groups by key. A key maps to the sorted results of the groups that share it. Where
    // the bits of a NaN key are not defined, the groups that differ in nothing else are merged,
    // and a merged key maps to the sums of its counts.
    const index = (groups: RangeReduceGroup[]) => {
        const exact = new Map<string, string[]>();
        const merged = new Map<string, bigint[]>();
        for (const group of groups) {
            const keys = renderKeys(group, !unspecifiedNaN);
            const key = keys.join(' | ');
            if (unspecifiedNaN && keys.some((part, k) => part === NAN && computed[k])) {
                const sums = merged.get(key) ?? counts.map(() => 0n);
                group.results.forEach((result, i) => {
                    if (counts[i] && result.value?.value.case === 'uint64Value') sums[i] += result.value.value.value;
                });
                merged.set(key, sums);
                continue;
            }
            const results = renderResults(group.results, !unspecifiedNaN).join(', ');
            const list = exact.get(key);
            if (list === undefined) exact.set(key, [results]);
            else list.push(results);
        }
        const texts = <T>(map: Map<string, T[]>, show: (items: T[]) => string) =>
            new Map([...map].map(([key, items]): [string, string] => [key, show(items)]));
        return {
            exact: texts(exact, (results) => results.sort().join(' ; ')),
            merged: texts(merged, (sums) => sums.map((sum, i) => (counts[i] ? 'count ' + sum : 'not compared')).join(', ')),
        };
    };
    const want = index(expected);
    const got = index(actual);
    const limited = want.merged.size > 0 || got.merged.size > 0;
    return { detail: groupDifference(want.exact, got.exact) ?? groupDifference(want.merged, got.merged), limited };
}

/** What compare needs to know beyond the two answers. */
export interface CompareOptions {
    /**
     * Whether the request made a NaN whose sign and payload the service does not define, as the
     * evaluator reports it for the rows of the request.
     */
    unspecifiedNaN: boolean;
    /**
     * Whether no group approaches the byte target of a frame, so that the number of frames
     * follows from the number of groups. Defaults to true.
     */
    smallGroups?: boolean;
}

/** Compares the answer of the store under test with the answer of the reference store. */
export function compare(request: ReduceRequest, expected: Outcome, actual: Outcome, options: CompareOptions): Comparison {
    const result = (status: Comparison['status'], detail = '', textDiffers = false, limited = false): Comparison =>
        ({ status, detail, textDiffers, limited });
    const grouped = (request.params?.groupBy.length ?? 0) > 0;
    if (actual.error?.code === Code.Unimplemented) {
        const message = actual.error.rawMessage;
        const [name, ...rest] = message.split(':');
        if (!Object.hasOwn(UNIMPLEMENTED_CLASSES, name) || !UNIMPLEMENTED_CLASSES[name](request, rest.join(':'))) {
            return result('different', 'UNIMPLEMENTED for an expression outside the documented classes: ' + message);
        }
        if (expected.error?.code === Code.InvalidArgument) {
            return result('different', 'expected ' + showError(expected.error) + ' got ' + showError(actual.error));
        }
        return result('outside', message);
    }
    if (expected.error !== undefined || actual.error !== undefined) {
        if (expected.error === undefined || actual.error === undefined) {
            return result('different', 'expected ' + (expected.error ? showError(expected.error) : 'success')
                + ' got ' + (actual.error ? showError(actual.error) : 'success'));
        }
        const want = describeError(expected.error);
        const got = describeError(actual.error);
        if (want.code !== got.code) return result('different', 'expected ' + showError(expected.error) + ' got ' + showError(actual.error));
        const framed = expected.frames.length > 0 || actual.frames.length > 0;
        if (framed && !grouped) return result('different', 'a request without group_by delivered a frame before its error');
        const textDiffers = JSON.stringify(want) !== JSON.stringify(got);
        const detail = textDiffers ? 'expected ' + showError(expected.error) + ' got ' + showError(actual.error) : '';
        return result('identical', detail, textDiffers, framed);
    }
    for (const [name, frames] of [['reference', expected.frames], ['store under test', actual.frames]] as const) {
        const problem = frameProblem(request, frames, options.smallGroups ?? true);
        if (problem !== undefined) return result('different', name + ': ' + problem);
    }
    const nanBits = !options.unspecifiedNaN;
    const outcome = grouped
        ? compareGroups(request, expected.frames.flatMap((frame) => frame.groups), actual.frames.flatMap((frame) => frame.groups),
            options.unspecifiedNaN)
        : compareScalar(request, renderResults(expected.frames[0].results, nanBits), renderResults(actual.frames[0].results, nanBits),
            options.unspecifiedNaN);
    return result(outcome.detail === undefined ? 'identical' : 'different', outcome.detail, false, outcome.limited);
}

/**
 * The first difference between two answers that one implementation gave to one request over the
 * same rows, or undefined when there is none. Such answers must have the same error with the same
 * text and details, and the same bytes in the results and groups of every frame.
 */
export function exactDifference(a: Outcome, b: Outcome): string | undefined {
    const [errorA, errorB] = [a, b].map(({ error }) => (error === undefined ? 'success' : JSON.stringify(describeError(error))));
    if (errorA !== errorB) return errorA + ' against ' + errorB;
    if (a.frames.length !== b.frames.length) return a.frames.length + ' frames against ' + b.frames.length;
    const body = ({ results, groups }: ReduceResponse) => hex(toBinary(ReduceResponseSchema, create(ReduceResponseSchema, { results, groups })));
    const frame = a.frames.findIndex((_, i) => body(a.frames[i]) !== body(b.frames[i]));
    return frame < 0 ? undefined : 'frame ' + frame + ' differs';
}
