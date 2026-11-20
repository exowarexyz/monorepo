/**
 * The evaluator of store.query.v1 Reduce.
 *
 * It computes the answer of a Reduce request from the rows of the requested range and needs no
 * database. A store validates the envelope of a request, plans it, feeds the rows of the range
 * to a run in key order and sends the frames of the run:
 *
 *     validateReduceEnvelope(request);
 *     const run = new ReduceRun(planReduce(request), { maxStateBytes });
 *     for (const [key, value] of rows) run.push(key, value);
 *     run.finish();
 *     for (const frame of run.frames(sequenceNumber)) send(frame);
 *
 * Values, errors and their order follow the service definition. Every failure is a ConnectError.
 * The bytes of the request and of the stored rows bound every recursion and allocation.
 */
import { create, toBinary } from '@bufbuild/protobuf';
import {
    RangeReduceGroupSchema,
    RangeReduceOp,
    ReduceResponseSchema,
    type RangeReduceGroup,
    type ReduceRequest,
    type ReduceResponse,
} from '../../gen/ts/store/v1/query_pb.js';
import { checkKeyLength, fieldError } from '../errors.js';
import { Aggregation, checkReducer, type Reducer } from './aggregate.js';
import { decodeStoredRow, extractField } from './codec.js';
import {
    chargedSize,
    checkNesting,
    columnsOf,
    convertExpr,
    COUNT_ALL_ARGUMENT,
    materializationBytes,
    Planner,
    type Expr,
    type Node,
} from './expr.js';
import { unspecifiedNaNs } from './float.js';
import { convertPredicate, evalPredicate, predicateNeedsValue, type Predicate } from './predicate.js';
import { INVALID_REDUCE_PARAMS, invalidParams, QUERY_DOMAIN, type Field, type Value } from './types.js';

/**
 * The rows of the range are consumed in chunks of this many rows. An input batch never spans two
 * chunks.
 */
const SCAN_CHUNK_ROWS = 4096;

/**
 * The byte budget of one input batch by the size formula of the plan. A single larger row is a
 * batch of its own.
 */
const INPUT_BATCH_BYTES = 16 * 1024 * 1024;

// Maximum number of groups in one frame, and the byte size a frame aims to stay below.
const FRAME_GROUPS = 4096;
const FRAME_BYTES = 16 * 1024 * 1024;

/**
 * Bounds the nesting of every expression of a request. `params` lies at depth 1 below the
 * request.
 */
function checkRequestNesting(request: ReduceRequest): void {
    for (const reducer of request.params?.reducers ?? []) {
        if (reducer.expr !== undefined) checkNesting(reducer.expr, 3);
    }
    for (const expr of request.params?.groupBy ?? []) checkNesting(expr, 2);
}

/**
 * Checks what can be checked before the request meets the database: the nesting of the message,
 * the length of the range bounds and the presence of a reducer or a group_by. Throws
 * INVALID_ARGUMENT for the first violation in that order.
 */
export function validateReduceEnvelope(request: ReduceRequest): void {
    checkRequestNesting(request);
    checkKeyLength(QUERY_DOMAIN, 'start', request.start);
    checkKeyLength(QUERY_DOMAIN, 'end', request.end);
    const params = request.params;
    if (params === undefined || (params.reducers.length === 0 && params.groupBy.length === 0)) {
        throw fieldError(QUERY_DOMAIN, 'params', 'at least one reducer or group_by field is required',
            INVALID_REDUCE_PARAMS, 'reduce request must specify at least one reducer or group_by');
    }
}

/** A request after conversion and typing, ready to run over the rows of its range. */
export interface ReducePlan {
    /**
     * The fields that expressions read, in the order of their first use. They are the columns of
     * an input batch.
     */
    readonly fields: readonly Field[];
    /** The typed group_by expressions, in request order. */
    readonly groupBy: readonly Node[];
    /** The planned reducers, in request order. */
    readonly reducers: readonly Reducer[];
    /** The request filter. A row it rejects is dropped before its columns are read. */
    readonly filter: Predicate | undefined;
    /** The FILTERs of the reducers that have one, in reducer order. */
    readonly masks: readonly Predicate[];
    /**
     * Whether any column or predicate reads the stored row. A request over key fields alone never
     * decodes stored rows.
     */
    readonly needsValue: boolean;
    /**
     * Per column, the copies of its values that expressions materialize, for the input byte
     * budget.
     */
    readonly fieldCopies: readonly number[];
    /** The bytes of literals that expressions materialize per row, for the input byte budget. */
    readonly literalBytes: number;
}

/**
 * Converts and plans a request that passed validateReduceEnvelope. The nesting bound that the
 * envelope check enforces also bounds the recursion of conversion and planning. Typing is static,
 * so the outcome does not depend on the stored rows.
 *
 * Throws INVALID_ARGUMENT for params that cannot be converted, checked or typed, INTERNAL for
 * date_trunc_day over a type that is neither a timestamp, a date nor a string, and UNIMPLEMENTED
 * for an otherwise valid request that holds an expression the service defines and this evaluator
 * does not compute.
 *
 * Conversion covers the whole request before any typing: reducers in order (op, expr, filter), then
 * group_by, then the request filter. Next each reducer is checked for the expression its op
 * requires. Typing then visits group_by in order and each reducer in order.
 */
export function planReduce(request: ReduceRequest): ReducePlan {
    const params = request.params;
    const converted = (params?.reducers ?? []).map((reducer) => {
        if (!(reducer.op in RangeReduceOp)) throw invalidParams('unsupported RangeReduceOp');
        const expr = reducer.expr === undefined ? undefined : convertExpr(reducer.expr);
        const filter = reducer.filter === undefined ? undefined : convertPredicate(reducer.filter);
        return { op: reducer.op, expr, filter };
    });
    const groupExprs = (params?.groupBy ?? []).map(convertExpr);
    const filter = params?.filter === undefined ? undefined : convertPredicate(params.filter);

    const args: Expr[] = converted.map((reducer) => {
        if (reducer.op === RangeReduceOp.COUNT_ALL) {
            if (reducer.expr !== undefined) throw invalidParams('count_all reducer must not specify an expression');
            return COUNT_ALL_ARGUMENT;
        }
        if (reducer.expr === undefined) throw invalidParams('expression reducer requires an expression');
        return reducer.expr;
    });

    const planner = new Planner();
    const groupBy = groupExprs.map((expr) => planner.plan(expr));
    const masks: Predicate[] = [];
    const reducers = converted.map((reducer, i): Reducer => {
        const argument = planner.plan(args[i]);
        checkReducer(reducer.op, argument.type);
        const mask = reducer.filter === undefined ? -1 : masks.push(reducer.filter) - 1;
        return { op: reducer.op, argument, columns: [...columnsOf(argument)], mask };
    });

    if (planner.unimplemented !== undefined) throw planner.unimplemented;

    // A bare field shares its column. Every other expression materializes its operands.
    const fieldCopies = planner.fields.map(() => 0);
    let literalBytes = 0;
    for (const expr of [...groupExprs, ...args]) {
        if (expr.k !== 'field') literalBytes += materializationBytes(expr, planner, fieldCopies, 1);
    }
    const needsValue = planner.fields.some((field) => field.src === 'value')
        || (filter !== undefined && predicateNeedsValue(filter))
        || masks.some(predicateNeedsValue);
    return { fields: planner.fields, groupBy, reducers, filter, masks, needsValue, fieldCopies, literalBytes };
}

/**
 * Runs one planned request over the rows of its range.
 *
 * push takes the rows in key order. finish ends the input. frames then yields the response. push
 * and finish throw the ConnectError of the first failure: FAILED_PRECONDITION for a row that does
 * not decode or does not fit a field reference and for an expression that fails on a value,
 * INTERNAL for date_trunc_day of a timestamp whose day cannot be represented, RESOURCE_EXHAUSTED
 * when the aggregation state and the expression results of the batch being evaluated together
 * exceed maxStateBytes. A run that threw is finished.
 *
 * Rows are evaluated in input batches, and the batch boundaries can change the result. A Float64
 * SUM without group_by adds each batch in lanes. An expression over literals alone is evaluated
 * once per batch, so it can fail the request even for a batch whose rows the request filter all
 * rejected.
 *
 * A batch holds the rows of one chunk of SCAN_CHUNK_ROWS scanned rows that passed the filter. It
 * ends early when the next row would take its size by the plan's formula past INPUT_BATCH_BYTES.
 */
export class ReduceRun {
    private readonly aggregation: Aggregation;
    private columns: (Value | null)[][];
    private masks: boolean[][];

    // Rows of the current chunk scanned so far, and the rows and bytes of the batch being built.
    private scanned = 0;
    private rows = 0;
    private bytes = 0;

    private unspecified = false;

    constructor(private readonly plan: ReducePlan, options: { maxStateBytes: number }) {
        this.aggregation = new Aggregation(plan.groupBy, plan.reducers, options.maxStateBytes);
        this.columns = plan.fields.map(() => []);
        this.masks = plan.masks.map(() => []);
    }

    /**
     * Adds the next row of the range. The stored row is decoded only when the plan reads it, and
     * then before the request filter, so a row that does not decode fails the request even when the
     * filter would reject it. A row the filter rejects is not checked any further.
     */
    push(key: Uint8Array, value: Uint8Array): void {
        const { plan } = this;
        const stored = plan.needsValue ? decodeStoredRow(value) : null;
        this.scanned++;
        if (plan.filter === undefined || evalPredicate(key, stored, plan.filter)) {
            const values = plan.fields.map((field) => extractField(key, stored, field));
            const masks = plan.masks.map((predicate) => evalPredicate(key, stored, predicate));
            let bytes = plan.literalBytes + masks.length;
            values.forEach((cell, i) => {
                bytes += chargedSize(cell) * (plan.fieldCopies[i] + 1);
            });
            if (this.rows > 0 && this.bytes + bytes > INPUT_BATCH_BYTES) this.evaluateBatch();
            values.forEach((cell, i) => this.columns[i].push(cell));
            masks.forEach((mask, i) => this.masks[i].push(mask));
            this.rows++;
            this.bytes += bytes;
        }
        if (this.scanned === SCAN_CHUNK_ROWS) this.endChunk();
    }

    /** Ends the input. A range without rows evaluates nothing. */
    finish(): void {
        if (this.scanned > 0) this.endChunk();
    }

    /** Ends the chunk and evaluates its batch, even when no row of the chunk passed the filter. */
    private endChunk(): void {
        this.scanned = 0;
        this.evaluateBatch();
    }

    private evaluateBatch(): void {
        const batch = { rows: this.rows, columns: this.columns, masks: this.masks };
        this.columns = this.plan.fields.map(() => []);
        this.masks = this.plan.masks.map(() => []);
        this.rows = 0;
        this.bytes = 0;
        const before = unspecifiedNaNs();
        this.aggregation.consume(batch);
        if (unspecifiedNaNs() !== before) this.unspecified = true;
    }

    /**
     * Whether the rows so far produced a NaN whose sign and payload the service does not define, by
     * an invalid operation such as 0/0 or by an operation on two NaNs. What the sign or payload of
     * such a NaN decides is then not defined either: the choice of a MIN or MAX without group_by
     * that it takes part in, and the identity of a group that it keys.
     */
    get unspecifiedNaN(): boolean {
        return this.unspecified;
    }

    /**
     * The response after finish. Every frame's detail holds only the given sequence number. A
     * request without group_by yields one frame with one result per reducer. A request with
     * group_by yields its groups in frames of at most FRAME_GROUPS groups and, by an estimate of
     * their encoded size, at most FRAME_BYTES. A larger group goes alone in its frame, and a
     * request without groups yields one frame without groups.
     *
     * A result or group key of a type the wire cannot carry throws FAILED_PRECONDITION when its
     * frame is built, after the frames before it.
     */
    *frames(sequenceNumber: bigint): Iterable<ReduceResponse> {
        const frame = (init: { results?: ReturnType<Aggregation['results']>; groups?: RangeReduceGroup[] }) =>
            create(ReduceResponseSchema, { ...init, detail: { sequenceNumber } });
        if (this.plan.groupBy.length === 0) {
            yield frame({ results: this.aggregation.results() });
            return;
        }
        let groups: RangeReduceGroup[] = [];
        let bytes = 0;
        let emitted = false;
        for (const init of this.aggregation.wireGroups()) {
            const group = create(RangeReduceGroupSchema, init);
            const size = toBinary(RangeReduceGroupSchema, group).length + 16;
            if (groups.length > 0 && bytes + size > FRAME_BYTES) {
                yield frame({ groups });
                emitted = true;
                groups = [];
                bytes = 0;
            }
            groups.push(group);
            bytes += size;
            if (groups.length === FRAME_GROUPS) {
                yield frame({ groups });
                emitted = true;
                groups = [];
                bytes = 0;
            }
        }
        if (groups.length > 0 || !emitted) yield frame({ groups });
    }
}
