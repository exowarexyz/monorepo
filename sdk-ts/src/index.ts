export { Client, type ClientOptions, type RetryConfig } from './client.js';
export { StoreClient, TraversalMode, type GetResult, type GetManyResultItem, type QueryResult, type QueryResultItem, type ReduceParams, type ReduceResponse } from './store.js';
export { ExowareError, HttpError } from './error.js';
export {
    RangeReduceOp,
    ReduceParamsSchema,
    RangeReducerSpecSchema,
    KvExprSchema,
    KvFieldRefSchema,
    KvFieldRef_ValueFieldSchema,
    KvFieldRef_KeyFieldSchema,
    KvReducedValueSchema,
} from './gen/ts/store/v1/query_pb.js';
export type {
    RangeReducerSpec,
    KvExpr,
    KvFieldRef,
    KvFieldRef_ValueField,
    KvFieldRef_KeyField,
    KvReducedValue,
    RangeReduceResult,
    RangeReduceGroup,
} from './gen/ts/store/v1/query_pb.js';
