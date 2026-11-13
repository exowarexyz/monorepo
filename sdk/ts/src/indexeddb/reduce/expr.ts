import { type ConnectError } from '@connectrpc/connect';
import type { KvExpr, KvReducedValue } from '../../gen/ts/store/v1/query_pb.js';
import { convertField, readBigEndian, readLittleEndian, utf8Length } from './codec.js';
import { decimalKernel, decimalToFloat, pow10 } from './decimal.js';
import * as float from './float.js';
import { toLowercase } from './lowercase.js';
import {
    checkedCounts,
    date64Difference,
    dateWithInterval,
    daysToInterval,
    toNanoTimestamps,
    truncateToDay,
    unsignedDays,
} from './temporal.js';
import {
    arrowError,
    BINARY,
    BOOLEAN,
    coerceBinary,
    DATE32,
    DATE64,
    decimal,
    fieldIdentity,
    FLOAT64,
    I64_MIN,
    INT64,
    internalError,
    INTERVAL,
    invalidParams,
    kindType,
    OP_SYMBOLS,
    planError,
    sameType,
    timestamp,
    typeName,
    UINT64,
    unimplemented,
    UTF8,
    type Datum,
    type DecimalType,
    type Field,
    type Op,
    type Type,
    type Unit,
    type Value,
} from './types.js';

/** The largest depth of a message in a request, counted in messages below the request itself. */
const MAX_NESTING = 100;

const nestingError = (): ConnectError => invalidParams('request nesting exceeds ' + MAX_NESTING + ' messages');

/**
 * Throws when a message of the expression lies deeper than MAX_NESTING. `depth` is the depth of the
 * expression message itself. The walk stops at the first message beyond the limit, so its own
 * recursion is bounded, and so is every later walk over an expression that passed it.
 */
export function checkNesting(message: KvExpr, depth: number): void {
    const expr = message.expr;
    let deepest = depth;
    switch (expr.case) {
        case 'field': deepest = depth + (expr.value.field.case === undefined ? 1 : 2); break;
        case 'literal': deepest = depth + 1; break;
        case 'add': case 'sub': case 'mul': case 'div': deepest = depth + 1; break;
    }
    if (deepest > MAX_NESTING) throw nestingError();
    switch (expr.case) {
        case 'add': case 'sub': case 'mul': case 'div':
            if (expr.value.left !== undefined) checkNesting(expr.value.left, depth + 2);
            if (expr.value.right !== undefined) checkNesting(expr.value.right, depth + 2);
            break;
        case 'lower': case 'dateTruncDay': case 'castFloat64':
            checkNesting(expr.value, depth + 1);
            break;
    }
}

/** An expression of a request after conversion and before typing. */
export type Expr =
    | { readonly k: 'field'; readonly field: Field }
    | { readonly k: 'literal'; readonly type: Type; readonly value: Value }
    | { readonly k: 'binary'; readonly op: Op; readonly left: Expr; readonly right: Expr }
    | { readonly k: 'lower' | 'truncate' | 'cast'; readonly child: Expr };

/** The argument of COUNT_ALL. A literal true is never NULL, so COUNT over it counts rows. */
export const COUNT_ALL_ARGUMENT: Expr = { k: 'literal', type: BOOLEAN, value: true };

/**
 * Converts a literal. A Decimal128 is 16 bytes big endian and a Decimal256 is 32 bytes little
 * endian.
 */
function convertLiteral(message: KvReducedValue): Expr {
    const v = message.value;
    switch (v.case) {
        case 'int64Value': return { k: 'literal', type: INT64, value: v.value };
        case 'uint64Value': return { k: 'literal', type: UINT64, value: v.value };
        case 'float64Value': return { k: 'literal', type: FLOAT64, value: float.toBits(v.value) };
        case 'booleanValue': return { k: 'literal', type: BOOLEAN, value: v.value };
        case 'utf8Value': return { k: 'literal', type: UTF8, value: v.value };
        case 'date32Value': return { k: 'literal', type: DATE32, value: BigInt(v.value) };
        case 'date64Value': return { k: 'literal', type: DATE64, value: v.value };
        case 'timestampValue': return { k: 'literal', type: timestamp('us'), value: v.value };
        case 'decimal128Value':
            if (v.value.length !== 16) throw invalidParams('decimal128 must be exactly 16 bytes');
            return { k: 'literal', type: decimal(128, 38, 0), value: BigInt.asIntN(128, readBigEndian(v.value)) };
        case 'decimal256Value':
            if (v.value.length !== 32) throw invalidParams('decimal256 must be exactly 32 bytes');
            return { k: 'literal', type: decimal(256, 76, 0), value: BigInt.asIntN(256, readLittleEndian(v.value)) };
        case 'fixedSizeBinaryValue': return { k: 'literal', type: BINARY, value: v.value };
        default: throw invalidParams('missing reduced value');
    }
}

/**
 * Converts an expression depth first and left before right. The caller must have bounded its
 * nesting with checkNesting.
 */
export function convertExpr(message: KvExpr): Expr {
    const expr = message.expr;
    switch (expr.case) {
        case 'field': return { k: 'field', field: convertField(expr.value) };
        case 'literal': return convertLiteral(expr.value);
        case 'add': case 'sub': case 'mul': case 'div': {
            if (expr.value.left === undefined) throw invalidParams('missing ' + expr.case + '.left');
            const left = convertExpr(expr.value.left);
            if (expr.value.right === undefined) throw invalidParams('missing ' + expr.case + '.right');
            return { k: 'binary', op: expr.case, left, right: convertExpr(expr.value.right) };
        }
        case 'lower': return { k: 'lower', child: convertExpr(expr.value) };
        case 'dateTruncDay': return { k: 'truncate', child: convertExpr(expr.value) };
        case 'castFloat64': return { k: 'cast', child: convertExpr(expr.value) };
        default: throw invalidParams('missing expr');
    }
}

type BinaryKernel = (left: Value, right: Value) => Value;
type UnaryKernel = (value: Value) => Value;

/** A typed expression ready to run over batches. Kernels see only non-NULL operands. */
export type Node =
    | { readonly k: 'column'; readonly type: Type; readonly index: number }
    | { readonly k: 'literal'; readonly type: Type; readonly value: Value }
    | {
        readonly k: 'binary';
        readonly type: Type;
        readonly left: Node;
        readonly right: Node;
        readonly kernel: BinaryKernel;
    }
    | { readonly k: 'map'; readonly type: Type; readonly child: Node; readonly kernel: UnaryKernel }
    | { readonly k: 'nanos'; readonly type: Type; readonly child: Node }
    | { readonly k: 'truncate'; readonly type: Type; readonly child: Node; readonly unit: Unit };

const integers = (f: (l: bigint, r: bigint) => bigint): BinaryKernel => f as BinaryKernel;
const integer = (f: (value: bigint) => bigint): UnaryKernel => f as UnaryKernel;

/**
 * Integer arithmetic. Addition, subtraction and multiplication wrap. Division truncates toward zero
 * and fails on a zero divisor and on overflow.
 */
function integerKernel(op: Op, unsigned: boolean): (l: bigint, r: bigint) => bigint {
    const wrap = unsigned ? (v: bigint) => BigInt.asUintN(64, v) : (v: bigint) => BigInt.asIntN(64, v);
    switch (op) {
        case 'add': return (l, r) => wrap(l + r);
        case 'sub': return (l, r) => wrap(l - r);
        case 'mul': return (l, r) => wrap(l * r);
        case 'div': return (l, r) => {
            if (r === 0n) throw arrowError('Divide by zero error');
            if (!unsigned && l === I64_MIN && r === -1n) {
                throw arrowError('Arithmetic overflow: Overflow happened on: ' + l + ' / ' + r);
            }
            return l / r;
        };
    }
}

/**
 * The kernel of an operator over operand types that coerceBinary produced. Returns undefined for an
 * interval paired with an interval or a timestamp. This evaluator does not compute those.
 */
function binaryKernel(op: Op, left: Type, right: Type, result: Type): BinaryKernel | undefined {
    const isDate = (type: Type) => type.t === 'date32' || type.t === 'date64';
    if (left.t === 'i64' && right.t === 'i64') return integers(integerKernel(op, false));
    if (left.t === 'u64' && right.t === 'u64') return integers(integerKernel(op, true));
    if (left.t === 'f64') return integers(float[op]);
    if (left.t === 'dec') return integers(decimalKernel(op, left, right as DecimalType, result as DecimalType));
    if (left.t === 'date32' && right.t === 'date32') return integers((l, r) => l - r);
    if (left.t === 'date64' && right.t === 'date64') return integers(date64Difference);
    if (isDate(left) && right.t === 'interval') return integers(dateWithInterval(op, left.t === 'date64'));
    if (left.t === 'interval' && isDate(right)) {
        const kernel = dateWithInterval(op, right.t === 'date64');
        return integers((nanos, date) => kernel(date, nanos));
    }
    if ((left.t === 'ts' && (right.t === 'ts' || right.t === 'dur')) || (left.t === 'dur' && right.t === 'dur')) {
        return integers(checkedCounts(op));
    }
    if (left.t === 'dur' && right.t === 'ts') {
        const kernel = checkedCounts(op);
        return integers((span, time) => kernel(time, span));
    }
    return undefined;
}

const DAY_MILLIS = 86_400_000n;

/**
 * The elementwise conversion between two types, for the pairs that operand coercion and
 * cast_float64 use. Returns undefined for any other pair.
 */
function castKernel(from: Type, to: Type): UnaryKernel | undefined {
    if (to.t === 'f64') {
        switch (from.t) {
            case 'i64': case 'u64': case 'ts': case 'dur': return integer((value) => float.toBits(Number(value)));
            case 'bool': return (value) => float.toBits(value === true ? 1 : 0);
            case 'utf8': return (value) => {
                const bits = float.parseFloat64(value as string);
                if (bits === undefined) {
                    throw arrowError("Cast error: Cannot cast string '" + value + "' to value of Float64 type");
                }
                return bits;
            };
            case 'dec': return integer(decimalToFloat(from));
        }
    }
    if (to.t === 'dec') {
        if (from.t === 'i64' || from.t === 'u64') return (value) => value;
        if (from.t === 'dec') {
            const factor = pow10(to.s - from.s);
            return integer((value) => value * factor);
        }
    }
    if (to.t === 'date64' && from.t === 'date32') return integer((value) => value * DAY_MILLIS);
    return undefined;
}

/** The name of a type in the error of a function that does not accept it. */
function logicalName(type: Type): string {
    if (type.t === 'dec') return 'Decimal(' + type.p + ', ' + type.s + ')';
    return type.t === 'date32' || type.t === 'date64' ? 'Date' : typeName(type);
}

const BINARY_HINT = '\n\nHint: Binary types are not automatically coerced to String. '
    + 'Use CAST(column AS VARCHAR) to convert Binary data to String.';

const requiresButReceived = (name: string, what: string, type: Type): string =>
    "Function '" + name + "' requires " + what + ', but received ' + logicalName(type)
    + ' (DataType: ' + typeName(type) + ').' + (type.t === 'bin' ? BINARY_HINT : '');

/**
 * Types the expressions of one request and numbers the fields they read. Two references are one
 * column only when all their properties are equal.
 */
export class Planner {
    readonly fields: Field[] = [];
    private readonly columns = new Map<string, number>();
    /**
     * The first unsupported cast_float64 of the expression being planned. It is reported after the
     * expression is typed.
     */
    private unsupportedCast: ConnectError | undefined;
    /** Whether the expression being planned holds a Date64 literal of the smallest value. */
    private holdsMinDate64 = false;
    private notComputed: ConnectError | undefined;

    /**
     * The UNIMPLEMENTED error of the first expression that the service defines and this evaluator
     * does not compute. Planning still types such an expression and goes on, so every other error
     * of the request takes precedence and a request answers UNIMPLEMENTED only when it is otherwise
     * valid.
     */
    get unimplemented(): ConnectError | undefined {
        return this.notComputed;
    }

    /** The column of a field that an earlier plan call numbered. */
    columnOf(field: Field): number {
        return this.columns.get(fieldIdentity(field)) as number;
    }

    /**
     * Plans one group_by expression or reducer argument. All operand typing errors of the
     * expression come before an unsupported cast_float64 inside it. A Date64 literal of the
     * smallest value is accepted only as the whole expression.
     */
    plan(expr: Expr): Node {
        this.unsupportedCast = undefined;
        this.holdsMinDate64 = false;
        const node = this.type(expr);
        if (this.unsupportedCast !== undefined) throw this.unsupportedCast;
        if (this.holdsMinDate64 && expr.k !== 'literal') {
            throw invalidParams('a date64 literal of ' + I64_MIN + ' is not supported inside an expression');
        }
        return node;
    }

    private type(expr: Expr): Node {
        switch (expr.k) {
            case 'field': {
                const identity = fieldIdentity(expr.field);
                let index = this.columns.get(identity);
                if (index === undefined) {
                    index = this.fields.length;
                    this.fields.push(expr.field);
                    this.columns.set(identity, index);
                }
                return { k: 'column', type: kindType(expr.field.kind), index };
            }
            case 'literal':
                if (expr.type.t === 'date64' && expr.value === I64_MIN) this.holdsMinDate64 = true;
                return expr;
            case 'binary': {
                const left = this.type(expr.left);
                return this.binary(expr.op, left, this.type(expr.right));
            }
            case 'lower': {
                const child = this.type(expr.child);
                if (child.type.t !== 'utf8') throw planError(requiresButReceived('lower', 'String', child.type));
                return { k: 'map', type: UTF8, child, kernel: (value) => toLowercase(value as string) };
            }
            case 'truncate': {
                const child = this.type(expr.child);
                const type = child.type;
                if (type.t === 'ts') return { k: 'truncate', type, child, unit: type.unit };
                if (type.t === 'date32' || type.t === 'date64') {
                    const nanos = timestamp('ns');
                    return { k: 'truncate', type: nanos, child: { k: 'nanos', type: nanos, child }, unit: 'ns' };
                }
                if (type.t === 'utf8') {
                    this.notComputed ??= unimplemented('date_trunc_day over a string is not implemented');
                    return { k: 'truncate', type: timestamp('ns'), child, unit: 'ns' };
                }
                throw internalError("Function 'date_trunc' failed to match any signature, errors: Error during planning: "
                    + requiresButReceived('date_trunc', 'Timestamp', type) + ',Error during planning: '
                    + requiresButReceived('date_trunc', 'Time', type));
            }
            case 'cast': {
                const child = this.type(expr.child);
                if (child.type.t === 'f64') return child;
                const kernel = castKernel(child.type, FLOAT64);
                if (kernel === undefined) {
                    this.unsupportedCast ??= invalidParams('This feature is not implemented: Unsupported CAST from '
                        + typeName(child.type) + ' to Float64');
                }
                return { k: 'map', type: FLOAT64, child, kernel: kernel ?? ((value) => value) };
            }
        }
    }

    private binary(op: Op, left: Node, right: Node): Node {
        const types = coerceBinary(left.type, op, right.type);

        // An interval operand can only come from durations of two units. A number beside it fails
        // planning because it does not convert to an interval.
        for (const [span, other] of [[left.type, right.type], [right.type, left.type]]) {
            const number = other.t === 'i64' || other.t === 'u64' || other.t === 'f64';
            if (span.t === 'interval' && number) {
                throw planError('Cannot automatically convert ' + typeName(other) + ' to Interval(MonthDayNano)');
            }
        }
        const l = this.coerce(left, types.left);
        const r = this.coerce(right, types.right);
        const kernel = l === undefined || r === undefined ? undefined : binaryKernel(op, types.left, types.right, types.result);
        if (kernel === undefined) {
            this.notComputed ??= unimplemented('timestamp and duration arithmetic with mixed units is not implemented: '
                + typeName(left.type) + ' ' + OP_SYMBOLS[op] + ' ' + typeName(right.type));
        }

        // Without a kernel the node only carries its type to the expressions around it.
        return { k: 'binary', type: types.result, left: l ?? left, right: r ?? right, kernel: kernel ?? ((value) => value) };
    }

    /**
     * Converts an operand to the type coerceBinary chose for it. Returns undefined for a conversion
     * this evaluator does not compute: a duration that would have to change its unit or become an
     * interval.
     */
    private coerce(node: Node, target: Type): Node | undefined {
        const from = node.type;
        if (sameType(from, target)) return node;

        // An integer is a number of days. An unsigned one must first fit the signed range.
        if (target.t === 'interval' && from.t === 'i64') {
            return { k: 'map', type: INTERVAL, child: node, kernel: integer(daysToInterval) };
        }
        if (target.t === 'interval' && from.t === 'u64') {
            const signed: Node = { k: 'map', type: INT64, child: node, kernel: integer(unsignedDays) };
            return { k: 'map', type: INTERVAL, child: signed, kernel: integer(daysToInterval) };
        }
        if (target.t === 'ts' && target.unit === 'ns' && (from.t === 'date32' || from.t === 'date64' || from.t === 'ts')) {
            return { k: 'nanos', type: target, child: node };
        }
        const numeric = from.t === 'i64' || from.t === 'u64' || from.t === 'dec';
        const convertible = (numeric && (target.t === 'f64' || target.t === 'dec')) || target.t === 'date64';
        const kernel = convertible ? castKernel(from, target) : undefined;
        return kernel === undefined ? undefined : { k: 'map', type: target, child: node, kernel };
    }
}

/** The plan columns an expression reads. */
export function columnsOf(node: Node, into: Set<number> = new Set()): Set<number> {
    switch (node.k) {
        case 'column': into.add(node.index); break;
        case 'literal': break;
        case 'binary':
            columnsOf(node.left, into);
            columnsOf(node.right, into);
            break;
        default: columnsOf(node.child, into);
    }
    return into;
}

/**
 * The bytes that the budgets charge for one value: 48 plus the UTF-8 length of text or the length
 * of binary.
 */
export function chargedSize(value: Value | null): number {
    return 48 + (typeof value === 'string' ? utf8Length(value) : value instanceof Uint8Array ? value.length : 0);
}

/**
 * Adds what an expression contributes to the input byte budget of a row and returns its literal
 * bytes. A literal costs its size per copy. A field adds `copies` to the count of its column in
 * `fieldCopies`. lower multiplies the copies below it by 12, since lowering grows text at most
 * twelvefold in UTF-8.
 */
export function materializationBytes(expr: Expr, planner: Planner, fieldCopies: number[], copies: number): number {
    switch (expr.k) {
        case 'field':
            fieldCopies[planner.columnOf(expr.field)] += copies;
            return 0;
        case 'literal': return chargedSize(expr.value) * copies;
        case 'binary':
            return materializationBytes(expr.left, planner, fieldCopies, copies)
                + materializationBytes(expr.right, planner, fieldCopies, copies);
        case 'lower': return materializationBytes(expr.child, planner, fieldCopies, copies * 12);
        default: return materializationBytes(expr.child, planner, fieldCopies, copies);
    }
}

/** The rows of one input batch, column by column. */
export interface Batch {
    readonly rows: number;
    readonly columns: readonly (readonly (Value | null)[])[];
}

const mapDatum = (datum: Datum, kernel: UnaryKernel): Datum => (datum.scalar
    ? { scalar: true, value: datum.value === null ? null : kernel(datum.value) }
    : { scalar: false, values: datum.values.map((value) => (value === null ? null : kernel(value))) });

/**
 * Applies a kernel where both operands are non-NULL. Two scalars give a scalar, computed once
 * for the batch. A NULL scalar makes every row NULL without running the kernel.
 */
function applyBinary(left: Datum, right: Datum, kernel: BinaryKernel, rows: number): Datum {
    const nulls = () => new Array<null>(rows).fill(null);
    if (left.scalar) {
        const l = left.value;
        if (right.scalar) {
            const r = right.value;
            return { scalar: true, value: l === null || r === null ? null : kernel(l, r) };
        }
        const values = l === null ? nulls() : right.values.map((r) => (r === null ? null : kernel(l, r)));
        return { scalar: false, values };
    }
    if (right.scalar) {
        const r = right.value;
        const values = r === null ? nulls() : left.values.map((l) => (l === null ? null : kernel(l, r)));
        return { scalar: false, values };
    }
    const rights = right.values;
    return {
        scalar: false,
        values: left.values.map((l, i) => {
            const r = rights[i];
            return l === null || r === null ? null : kernel(l, r);
        }),
    };
}

/**
 * Evaluates an expression over one batch, column at a time. A node runs over the whole batch after
 * its children, the left child first, and the first failing row in row order raises the error. A
 * subtree without fields evaluates to a scalar once per batch, even for a batch without rows.
 */
export function evaluate(node: Node, batch: Batch): Datum {
    switch (node.k) {
        case 'column': return { scalar: false, values: batch.columns[node.index] };
        case 'literal': return { scalar: true, value: node.value };
        case 'binary': {
            const left = evaluate(node.left, batch);
            return applyBinary(left, evaluate(node.right, batch), node.kernel, batch.rows);
        }
        case 'map': return mapDatum(evaluate(node.child, batch), node.kernel);
        case 'nanos': return toNanoTimestamps(evaluate(node.child, batch), node.child.type);
        case 'truncate': return truncateToDay(evaluate(node.child, batch), node.unit);
    }
}
