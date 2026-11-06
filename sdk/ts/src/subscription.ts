import { Code, ConnectError, type CallOptions } from '@connectrpc/connect';
import type { SubscribeRequest, SubscribeResponse } from './gen/ts/log/v1/stream_pb.js';

/**
 * Controls how Store subscriptions resume after a disconnect.
 *
 * An outage starts when a subscription opens or its stream ends, and lasts until the next frame
 * arrives. `outageBudgetMs` bounds one outage, including backoff and opens that hang. Use
 * `Infinity` to retry without a bound. When `enabled` is false, a subscription makes one attempt
 * and ends or fails with its stream.
 */
export type SubscriptionRetryConfig = {
    enabled: boolean;
    outageBudgetMs: number;
    initialBackoffMs: number;
    maxBackoffMs: number;
};

const DEFAULT_SUBSCRIPTION_RETRY_CONFIG: Readonly<SubscriptionRetryConfig> = Object.freeze({
    enabled: true,
    outageBudgetMs: 60_000,
    initialBackoffMs: 100,
    maxBackoffMs: 2_000,
});

export function normalizeSubscriptionRetry(
    config: Partial<SubscriptionRetryConfig> = {},
): Readonly<SubscriptionRetryConfig> {
    // A field set to undefined is unset, so it keeps its default like a missing one.
    const given = Object.fromEntries(
        Object.entries(config).filter(([, value]) => value !== undefined),
    ) as Partial<SubscriptionRetryConfig>;
    const merged = { ...DEFAULT_SUBSCRIPTION_RETRY_CONFIG, ...given };
    if (typeof merged.enabled !== 'boolean') {
        throw new TypeError('subscription retry enabled must be a boolean');
    }
    if (typeof merged.outageBudgetMs !== 'number' || !(merged.outageBudgetMs > 0)) {
        throw new RangeError('subscription outageBudgetMs must be a positive number or Infinity');
    }
    for (const name of ['initialBackoffMs', 'maxBackoffMs'] as const) {
        const value = merged[name];
        if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
            throw new RangeError(`subscription ${name} must be a nonnegative finite number`);
        }
    }
    return Object.freeze({
        enabled: merged.enabled,
        outageBudgetMs: merged.outageBudgetMs,
        initialBackoffMs: merged.initialBackoffMs,
        maxBackoffMs: Math.max(merged.maxBackoffMs, merged.initialBackoffMs),
    });
}

export type OpenSubscription = (
    request: SubscribeRequest,
    options: CallOptions,
) => AsyncIterable<SubscribeResponse>;

const MAX_U64 = (1n << 64n) - 1n;

// setTimeout fires immediately for delays above this, so longer waits are re-armed in steps.
const MAX_TIMER_MS = 2_147_483_647;

// Codes a reconnect can plausibly fix. Fetch reports a reset or truncated stream as Unknown.
const RESUMABLE_CODES = new Set<Code>([
    Code.Unavailable,
    Code.Aborted,
    Code.ResourceExhausted,
    Code.Internal,
    Code.Unknown,
]);

function isResumable(err: unknown): boolean {
    return err instanceof ConnectError && RESUMABLE_CODES.has(err.code);
}

function backoffDelay(failures: number, config: SubscriptionRetryConfig): number {
    const exponent = Math.min(failures - 1, 30);
    const cap = Math.min(config.initialBackoffMs * 2 ** exponent, config.maxBackoffMs);
    return cap / 2 + (cap / 2) * Math.random();
}

function canceled(signal: AbortSignal): ConnectError {
    return ConnectError.from(signal.reason, Code.Canceled);
}

/** Calls `fire` once `at` is reached and returns a function that cancels it. */
function scheduleAt(at: number, fire: () => void): () => void {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const arm = () => {
        const remaining = at - performance.now();
        if (remaining <= 0) {
            timer = undefined;
            fire();
            return;
        }

        // Timers can fire early, so wake and recheck instead of trusting one delay.
        timer = setTimeout(arm, Math.min(Math.ceil(remaining), MAX_TIMER_MS));
    };
    arm();
    return () => clearTimeout(timer);
}

/** Settles with `promise`, or rejects with the signal's reason if it aborts first. */
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
    return new Promise((resolve, reject) => {
        const onAbort = () => reject(signal.reason);
        if (signal.aborted) {
            onAbort();
        } else {
            signal.addEventListener('abort', onAbort, { once: true });
        }
        promise.then(
            (value) => {
                signal.removeEventListener('abort', onAbort);
                resolve(value);
            },
            (err) => {
                signal.removeEventListener('abort', onAbort);
                reject(err);
            },
        );
    });
}

function sleepUntil(at: number, signal: AbortSignal | undefined): Promise<void> {
    return new Promise((resolve, reject) => {
        if (signal?.aborted) {
            reject(canceled(signal));
            return;
        }
        const onAbort = () => {
            cancel();
            reject(canceled(signal!));
        };
        signal?.addEventListener('abort', onAbort, { once: true });
        const cancel = scheduleAt(at, () => {
            signal?.removeEventListener('abort', onAbort);
            resolve();
        });
    });
}

/**
 * Yields every frame of a subscription in sequence order, reopening the stream after resumable
 * failures. Frames with no entries are yielded too, because callers may filter entries further.
 */
export async function* resumeSubscription(
    open: OpenSubscription,
    request: SubscribeRequest,
    config: SubscriptionRetryConfig,
    options: CallOptions = {},
): AsyncGenerator<SubscribeResponse> {
    const caller = options.signal;
    const since = request.sinceSequenceNumber;

    // The next sequence the caller has not seen. It stays unset for a live-only request until the
    // first frame, because reopening without a position could skip batches.
    let cursor = since !== undefined && since > 0n ? since : undefined;

    let inOutage = true;
    let deadline = performance.now() + config.outageBudgetMs;
    let failures = 0;
    let lastFailure: unknown;

    for (;;) {
        if (caller?.aborted) throw canceled(caller);

        const attempt = new AbortController();
        const abortAttempt = () => attempt.abort(caller?.reason);
        caller?.addEventListener('abort', abortAttempt, { once: true });

        let budgetSpent = false;
        let cancelBudget = config.enabled && Number.isFinite(deadline)
            ? scheduleAt(deadline, () => {
                budgetSpent = true;
                attempt.abort();
            })
            : undefined;

        let iterator: AsyncIterator<SubscribeResponse> | undefined;
        let pending = false;
        try {
            const attemptRequest = cursor === undefined || cursor === since
                ? request
                : { ...request, sinceSequenceNumber: cursor };
            iterator = open(attemptRequest, { ...options, signal: attempt.signal })[
                Symbol.asyncIterator
            ]();
            for (;;) {
                pending = true;
                const result = await untilAborted(iterator.next(), attempt.signal);
                pending = false;
                if (result.done) break;

                const frame = result.value;

                // Any frame proves the stream is healthy, including the checkpoint that reopens
                // one sequence below the cursor. Only a frame that moves the cursor restarts the
                // backoff, so a failure that keeps recurring after the checkpoint keeps backing off.
                inOutage = false;
                lastFailure = undefined;
                cancelBudget?.();
                cancelBudget = undefined;

                if (cursor !== undefined && frame.sequenceNumber < cursor) continue;
                failures = 0;

                // A cursor past u64 marks that no later batch can exist.
                cursor = frame.sequenceNumber + 1n;
                yield frame;
            }

            if (!config.enabled || (cursor !== undefined && cursor > MAX_U64)) return;
            if (cursor === undefined) {
                throw new ConnectError(
                    'subscription ended before its first frame, so it cannot resume without skipping batches',
                    Code.Unavailable,
                );
            }
        } catch (err) {
            if (caller?.aborted) throw canceled(caller);
            if (budgetSpent && inOutage) throw lastFailure ?? outageBudgetExceeded();

            // A deadline that fired just as a frame arrived only interrupted a healthy stream.
            if (!budgetSpent) {
                if (!config.enabled || !isResumable(err) || cursor === undefined) throw err;
                lastFailure = err;
            }

            // Nothing can follow the last representable sequence, so there is nothing to resume.
            if (cursor! > MAX_U64) throw err;
        } finally {
            cancelBudget?.();
            caller?.removeEventListener('abort', abortAttempt);
            attempt.abort();

            // Stopping iteration still closes an iterable that supports it, as a plain for await
            // would. A pending next() may never settle on a stalled stream, so the close is only
            // awaited when the iterator is idle.
            const closing = iterator?.return?.();
            if (pending) {
                closing?.catch(() => {});
            } else {
                await closing?.catch(() => {});
            }
        }

        if (!inOutage) {
            inOutage = true;
            deadline = performance.now() + config.outageBudgetMs;
        }
        failures++;
        const retryAt = Math.min(performance.now() + backoffDelay(failures, config), deadline);
        await sleepUntil(retryAt, caller);
        if (performance.now() >= deadline) throw lastFailure ?? outageBudgetExceeded();
    }
}

function outageBudgetExceeded(): ConnectError {
    return new ConnectError(
        'subscription could not resume within its outage budget',
        Code.DeadlineExceeded,
    );
}
