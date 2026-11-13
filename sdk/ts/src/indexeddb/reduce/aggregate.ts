import type { MessageInitShape } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import {
    RangeReduceOp,
    type KvReducedValueSchema,
    type RangeReduceGroupSchema,
    type RangeReduceResultSchema,
} from '../../gen/ts/store/v1/query_pb.js';
import { writeBigEndian } from './codec.js';
import { chargedSize, evaluate, type Batch, type Node } from './expr.js';
import * as float from './float.js';
import { executionError, invalidParams, typeName, UINT64, type Datum, type Type, type Value } from './types.js';

/** One reducer of a plan. */
export interface Reducer {
    readonly op: RangeReduceOp;
    readonly argument: Node;
    /** The plan columns the argument reads. */
    readonly columns: readonly number[];
    /** The position of the reducer's FILTER among the masks of a batch, or -1 without one. */
    readonly mask: number;
}

/** The rows of one batch that passed the request filter, with one mask per reducer FILTER. */
export interface InputBatch extends Batch {
    readonly masks: readonly (readonly boolean[])[];
}

/** Rejects a SUM over a type that has no sum. Every other reducer accepts every type. */
export function checkReducer(op: RangeReduceOp, argument: Type): void {
    if (op !== RangeReduceOp.SUM_FIELD) return;
    switch (argument.t) {
        case 'i64': case 'u64': case 'f64': case 'dec': case 'dur': case 'interval': return;
        default: throw invalidParams('Execution error: [return_type] SUM not supported for ' + typeName(argument));
    }
}

/**
 * The bytes a request may hold at one time, as aggregation state and as the expression results of
 * the batch that is being evaluated. Passing the limit fails the request with RESOURCE_EXHAUSTED.
 */
class MemoryBudget {
    private used = 0;

    constructor(private readonly max: number) {}

    /** Charges bytes that the request starts to hold. `held` names them in the error. */
    charge(bytes: number, held: 'state' | 'batch'): void {
        this.used += bytes;
        if (this.used > this.max) {
            throw new ConnectError(
                'reduce ' + held + " exceeds the store's query memory limit of " + this.max + ' bytes',
                Code.ResourceExhausted,
            );
        }
    }

    /** Releases bytes that the request has dropped. */
    release(bytes: number): void {
        this.used -= bytes;
    }
}

/**
 * The bytes, as chargedSize counts them, that evaluating an expression adds to what the request
 * holds. A field shares the column of the input batch and a literal is part of the plan, so neither
 * adds any.
 */
function producedBytes(node: Node, datum: Datum): number {
    if (node.k === 'column' || node.k === 'literal') return 0;
    if (datum.scalar) return chargedSize(datum.value);
    let bytes = 0;
    for (const value of datum.values) bytes += chargedSize(value);
    return bytes;
}

/** Orders two strings by code point, so they compare as their UTF-8 bytes do. */
function compareText(a: string, b: string): number {
    const length = Math.min(a.length, b.length);
    for (let i = 0; i < length; i++) {
        let x = a.charCodeAt(i);
        let y = b.charCodeAt(i);
        if (x === y) continue;

        // A surrogate encodes a code point above 0xffff and sorts after every unit from 0xe000 up.
        if (x >= 0xd800 && y >= 0xd800) {
            x += x >= 0xe000 ? -0x800 : 0x2000;
            y += y >= 0xe000 ? -0x800 : 0x2000;
        }
        return x - y;
    }
    return a.length - b.length;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
    const length = Math.min(a.length, b.length);
    for (let i = 0; i < length; i++) if (a[i] !== b[i]) return a[i] - b[i];
    return a.length - b.length;
}

/** The order MIN and MAX use for every type but Float64. */
function compareValues(a: Value, b: Value): number {
    if (typeof a === 'string') return compareText(a, b as string);
    if (a instanceof Uint8Array) return compareBytes(a, b as Uint8Array);
    if (typeof a === 'boolean') return Number(a) - Number(b);
    return a < (b as bigint) ? -1 : a > (b as bigint) ? 1 : 0;
}

/** What the accumulators of one reducer share. */
interface Shape {
    readonly op: RangeReduceOp;
    readonly type: Type;
    /** Whether the request has a group_by. Float64 sums and extrema differ with and without one. */
    readonly grouped: boolean;
    readonly budget: MemoryBudget;
}

/** The state of one reducer for one group, or for the whole range without group_by. */
class Accumulator {
    private count = 0n;
    private value: Value | null = null;
    /**
     * The running Float64 extremum with group_by. It starts at the largest finite value for MIN and
     * at the smallest for MAX.
     */
    private current = 0n;

    constructor(private readonly shape: Shape) {
        if (shape.grouped && shape.type.t === 'f64') {
            this.current = shape.op === RangeReduceOp.MIN_FIELD ? float.F64_MAX : float.F64_MIN;
        }
    }

    /** Folds in the argument of one contributing row. Rows arrive in key order. */
    add(value: Value | null): void {
        if (value === null) return;
        const { op, type, grouped } = this.shape;
        switch (op) {
            case RangeReduceOp.COUNT_ALL:
            case RangeReduceOp.COUNT_FIELD:
                this.count++;
                return;
            case RangeReduceOp.SUM_FIELD: {
                // Integer and decimal sums wrap at their word. A Float64 sum starts at +0.
                const sum = (this.value ?? 0n) as bigint;
                const addend = value as bigint;
                if (type.t === 'f64') this.value = float.add(sum, addend);
                else if (type.t === 'u64') this.value = BigInt.asUintN(64, sum + addend);
                else this.value = BigInt.asIntN(type.t === 'dec' ? type.w : 64, sum + addend);
                return;
            }
            default: {
                const max = op === RangeReduceOp.MAX_FIELD;
                if (type.t !== 'f64') {
                    const order = this.value === null ? 0 : compareValues(value, this.value);
                    if (this.value === null || (max ? order > 0 : order < 0)) this.replace(value);
                    return;
                }
                const bits = value as bigint;
                if (!grouped) {
                    // Without group_by the extremum follows the total order and keeps the bits
                    // of the chosen value.
                    if (this.value === null) this.value = bits;
                    else {
                        const key = float.totalOrderKey(bits);
                        const held = float.totalOrderKey(this.value as bigint);
                        if (max ? key > held : key < held) this.value = bits;
                    }
                    return;
                }

                // With group_by a NaN replaces the current value, and the next value replaces a
                // NaN. Other values compare numerically with the current value.
                if (float.isNaNBits(bits) || float.isNaNBits(this.current)) this.current = bits;
                else {
                    const x = float.fromBits(bits);
                    const held = float.fromBits(this.current);
                    if (max ? x > held : x < held) this.current = bits;
                }
                this.value = this.current;
            }
        }
    }

    /**
     * Folds in the argument values of one batch without group_by. The rows that the reducer's
     * FILTER rejects are already removed.
     */
    addBatch(datum: Datum, rows: number): void {
        const { op, type } = this.shape;
        if (datum.scalar && (op === RangeReduceOp.COUNT_ALL || op === RangeReduceOp.COUNT_FIELD)) {
            if (datum.value !== null) this.count += BigInt(rows);
            return;
        }
        const values = datum.scalar ? new Array<Value | null>(rows).fill(datum.value) : datum.values;
        if (op === RangeReduceOp.SUM_FIELD && type.t === 'f64') {
            const sum = float.sumBatch(values as readonly (bigint | null)[]);
            if (sum !== null) this.value = float.add((this.value ?? 0n) as bigint, sum);
            return;
        }
        for (const value of values) this.add(value);
    }

    private replace(value: Value): void {
        if (typeof value === 'string' || value instanceof Uint8Array) {
            this.shape.budget.charge(chargedSize(value) - chargedSize(this.value), 'state');
        }
        this.value = value;
    }

    result(): Value | null {
        const { op } = this.shape;
        return op === RangeReduceOp.COUNT_ALL || op === RangeReduceOp.COUNT_FIELD ? this.count : this.value;
    }
}

interface Group {
    readonly keys: readonly (Value | null)[];
    readonly accumulators: readonly Accumulator[];
}

const HEX = Array.from({ length: 256 }, (_, byte) => byte.toString(16).padStart(2, '0'));

/** A string that is equal for two group key values exactly when they are the same key. */
function keyIdentity(value: Value | null): string {
    if (value === null) return 'N';
    if (typeof value === 'bigint') return 'i' + value;
    if (typeof value === 'string') return 's' + value.length + ':' + value;
    if (typeof value === 'boolean') return value ? 't' : 'f';
    let hex = 'b';
    for (const byte of value) hex += HEX[byte];
    return hex;
}

/**
 * The value of a result or group key on the wire, or undefined for NULL. Decimal128 is 16 bytes big
 * endian and Decimal256 is 32 bytes little endian. A nanosecond timestamp is truncated toward zero
 * to microseconds. A duration or an interval has no wire form and fails the request.
 */
function toWire(type: Type, value: Value | null): MessageInitShape<typeof KvReducedValueSchema> | undefined {
    if (value === null) return undefined;
    switch (type.t) {
        case 'i64': return { value: { case: 'int64Value', value: value as bigint } };
        case 'u64': return { value: { case: 'uint64Value', value: value as bigint } };
        case 'f64': return { value: { case: 'float64Value', value: float.fromBits(value as bigint) } };
        case 'bool': return { value: { case: 'booleanValue', value: value as boolean } };
        case 'utf8': return { value: { case: 'utf8Value', value: value as string } };
        case 'bin': return { value: { case: 'fixedSizeBinaryValue', value: value as Uint8Array } };
        case 'date32': return { value: { case: 'date32Value', value: Number(value) } };
        case 'date64': return { value: { case: 'date64Value', value: value as bigint } };
        case 'ts': {
            const micros = type.unit === 'ns' ? (value as bigint) / 1000n : (value as bigint);
            return { value: { case: 'timestampValue', value: micros } };
        }
        case 'dec':
            return type.w === 128
                ? { value: { case: 'decimal128Value', value: writeBigEndian(value as bigint, 16) } }
                : { value: { case: 'decimal256Value', value: writeBigEndian(value as bigint, 32).reverse() } };
        default: throw executionError('unsupported native Reduce result type');
    }
}

/**
 * The aggregation state of one request.
 *
 * Without group_by each reducer first drops the rows its FILTER rejects and then evaluates its
 * argument on the rest. With group_by all keys and then all arguments are evaluated on every row
 * of a batch before the FILTERs apply, so an error in a rejected row still fails the request.
 * Groups are kept in the order their first row arrived.
 *
 * The results of a batch's expressions count against the memory budget while they are held. With
 * group_by that is every key and argument of the batch at once, and without group_by one argument
 * at a time.
 */
export class Aggregation {
    private readonly shapes: readonly Shape[];
    private readonly scalars: readonly Accumulator[];
    private readonly groups = new Map<string, Group>();
    private readonly budget: MemoryBudget;

    constructor(
        private readonly groupBy: readonly Node[],
        private readonly reducers: readonly Reducer[],
        maxStateBytes: number,
    ) {
        const grouped = groupBy.length > 0;
        const budget = new MemoryBudget(maxStateBytes);
        this.budget = budget;
        this.shapes = reducers.map((reducer) => ({ op: reducer.op, type: reducer.argument.type, grouped, budget }));
        this.scalars = grouped ? [] : this.shapes.map((shape) => new Accumulator(shape));
    }

    consume(batch: InputBatch): void {
        if (this.groupBy.length === 0) this.consumeScalar(batch);
        else this.consumeGrouped(batch);
    }

    private consumeScalar(batch: InputBatch): void {
        this.reducers.forEach((reducer, i) => {
            let input: Batch = batch;
            if (reducer.mask >= 0) {
                const mask = batch.masks[reducer.mask];
                const columns: (Value | null)[][] = [];
                for (const index of reducer.columns) columns[index] = batch.columns[index].filter((_, row) => mask[row]);
                let rows = 0;
                for (const kept of mask) if (kept) rows++;
                input = { rows, columns };
            }
            const { datum, bytes } = this.compute(reducer.argument, input);
            this.scalars[i].addBatch(datum, input.rows);
            this.budget.release(bytes);
        });
    }

    /**
     * Evaluates an expression over a batch and counts its result against the budget, so that a
     * request fails before it computes a further result. Returns the result with the bytes to
     * release once it is dropped.
     */
    private compute(node: Node, batch: Batch): { datum: Datum; bytes: number } {
        const datum = evaluate(node, batch);
        const bytes = producedBytes(node, datum);
        this.budget.charge(bytes, 'batch');
        return { datum, bytes };
    }

    private consumeGrouped(batch: InputBatch): void {
        const keys = this.groupBy.map((node) => this.compute(node, batch));
        const values = this.reducers.map((reducer) => this.compute(reducer.argument, batch));

        // Rows join the group of their keys. A Float64 key of -0 is the key +0.
        const groups: Group[] = [];
        for (let row = 0; row < batch.rows; row++) {
            const rowKeys = keys.map(({ datum }, k) => {
                const key = datum.scalar ? datum.value : datum.values[row];
                return key === float.NEGATIVE_ZERO && this.groupBy[k].type.t === 'f64' ? 0n : key;
            });
            const identity = rowKeys.map(keyIdentity).join('|');
            let group = this.groups.get(identity);
            if (group === undefined) {
                // A group is charged a fixed size per key and per reducer, plus the bytes of its
                // text and binary keys.
                const fixed = 48 * this.reducers.length;
                this.budget.charge(rowKeys.reduce((bytes: number, key) => bytes + chargedSize(key), fixed), 'state');
                group = { keys: rowKeys, accumulators: this.shapes.map((shape) => new Accumulator(shape)) };
                this.groups.set(identity, group);
            }
            groups.push(group);
        }

        this.reducers.forEach((reducer, i) => {
            const { datum } = values[i];
            const mask = reducer.mask >= 0 ? batch.masks[reducer.mask] : undefined;
            for (let row = 0; row < batch.rows; row++) {
                if (mask !== undefined && !mask[row]) continue;
                groups[row].accumulators[i].add(datum.scalar ? datum.value : datum.values[row]);
            }
        });
        for (const { bytes } of [...keys, ...values]) this.budget.release(bytes);
    }

    private result(accumulator: Accumulator, i: number): MessageInitShape<typeof RangeReduceResultSchema> {
        const { op, argument } = this.reducers[i];
        const counts = op === RangeReduceOp.COUNT_ALL || op === RangeReduceOp.COUNT_FIELD;
        return { value: toWire(counts ? UINT64 : argument.type, accumulator.result()) };
    }

    /** The results of a request without group_by, one per reducer. */
    results(): MessageInitShape<typeof RangeReduceResultSchema>[] {
        return this.scalars.map((accumulator, i) => this.result(accumulator, i));
    }

    /**
     * The groups in the order their first row arrived. Each group is converted to wire values only
     * when the iteration reaches it.
     */
    *wireGroups(): Iterable<MessageInitShape<typeof RangeReduceGroupSchema>> {
        for (const group of this.groups.values()) {
            const groupValues: MessageInitShape<typeof KvReducedValueSchema>[] = [];
            const groupValuesPresent = group.keys.map((key, k) => {
                const value = toWire(this.groupBy[k].type, key);
                if (value !== undefined) groupValues.push(value);
                return value !== undefined;
            });
            const results = group.accumulators.map((accumulator, i) => this.result(accumulator, i));
            yield { groupValues, groupValuesPresent, results };
        }
    }
}
