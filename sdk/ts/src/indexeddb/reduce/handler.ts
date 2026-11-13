/**
 * Reduce over the rows of the store.
 *
 * A Reduce reads the sequence number and every row of its range in one readonly transaction, so the
 * answer is the state of the store at that sequence number. The rows go to a ReduceRun, and the run
 * evaluates them in input batches and folds each batch into the aggregation state.
 *
 * At any time a Reduce holds the input batch it is gathering, the expression results of the
 * batch it is evaluating and the aggregation state. The store's query memory limit bounds the
 * results and the state together. The frames are built after the transaction has ended.
 */

import type { HandlerContext } from '@connectrpc/connect';
import type { ReduceRequest, ReduceResponse } from '../../gen/ts/store/v1/query_pb.js';
import { canceled } from '../errors.js';
import { keyRange, scanRows, snapshot } from '../query.js';
import { planReduce, ReduceRun, validateReduceEnvelope } from './index.js';

/**
 * Builds the Reduce handler. Its checks run in the order in which their failures take precedence.
 * The envelope comes first and needs no transaction. Inside the transaction the check of
 * minSequenceNumber comes before planning, so a request that is both stale and invalid in its
 * params answers ABORTED. A call that is canceled while its range is read ends the transaction at
 * the next row.
 */
export function reduceHandler(db: IDBDatabase, maxQueryBytes: number) {
    return async function* (request: ReduceRequest, context: HandlerContext): AsyncGenerator<ReduceResponse> {
        validateReduceEnvelope(request);
        const { signal } = context;
        const keys = keyRange(request.start, request.end);
        const { sequenceNumber, result } = await snapshot(db, request.minSequenceNumber, async (kv) => {
            const run = new ReduceRun(planReduce(request), { maxStateBytes: maxQueryBytes });
            if (keys !== undefined) {
                await scanRows(kv, keys, 'next', (key, value) => {
                    if (signal.aborted) throw canceled(signal);
                    run.push(key, value);
                    return true;
                });
            }
            run.finish();
            return run;
        });
        yield* result.frames(sequenceNumber);
    };
}
