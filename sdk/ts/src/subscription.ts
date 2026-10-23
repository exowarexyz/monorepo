import { Code, ConnectError, type CallOptions } from '@connectrpc/connect';
import type { SubscribeResponse } from './gen/ts/log/v1/stream_pb.js';
import { ErrorInfoSchema } from './gen/ts/google/rpc/error_details_pb.js';

export interface SubscriptionRetryConfig {
    enabled?: boolean;
    budgetMs?: number | null;
    initialBackoffMs?: number;
    maxBackoffMs?: number;
}

export function normalizeSubscriptionRetryConfig(
    config: SubscriptionRetryConfig = {},
): Readonly<Required<SubscriptionRetryConfig>> {
    const normalized = {
        enabled: config.enabled ?? true,
        budgetMs: config.budgetMs === undefined ? 60_000 : config.budgetMs,
        initialBackoffMs: config.initialBackoffMs ?? 100,
        maxBackoffMs: config.maxBackoffMs ?? 2_000,
    };
    if (typeof normalized.enabled !== 'boolean') {
        throw new TypeError('subscription retry enabled must be a boolean');
    }
    for (const [name, value] of Object.entries(normalized)) {
        if (name !== 'enabled' && value !== null && (typeof value !== 'number' || !Number.isFinite(value) || value < 0)) {
            throw new RangeError(`${name} must be a finite nonnegative number`);
        }
    }
    return Object.freeze(normalized);
}

const RETRYABLE_CODES = new Set([
    Code.Aborted,
    Code.Unavailable,
    Code.ResourceExhausted,
    Code.Unknown,
    Code.Internal,
    Code.DeadlineExceeded,
]);

function retryable(error: unknown): boolean {
    let found = false;
    const seen = new Set<unknown>();
    while (error instanceof Error && !seen.has(error)) {
        seen.add(error);
        if (error instanceof ConnectError) {
            if (!RETRYABLE_CODES.has(error.code) || error.findDetails(ErrorInfoSchema).some(
                (detail) => detail.reason === 'BATCH_EVICTED',
            )) return false;
            found = true;
        }
        error = error.cause;
    }
    return found;
}

function abortError(signal: AbortSignal): unknown {
    return signal.reason instanceof ConnectError
        ? signal.reason
        : ConnectError.from(signal.reason, Code.Canceled);
}

function abortable<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
    return new Promise((resolve, reject) => {
        const abort = () => reject(abortError(signal));
        if (signal.aborted) {
            void operation.catch(() => {});
            reject(abortError(signal));
            return;
        }
        signal.addEventListener('abort', abort, { once: true });
        operation.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
    });
}

// Long configured budgets must not overflow JavaScript's signed 32-bit timer delay.
function atDeadline(deadline: number, expire: () => void): () => void {
    let timer: ReturnType<typeof setTimeout>;
    const wake = () => {
        const remaining = deadline - performance.now();
        if (remaining <= 0) {
            expire();
        } else {
            timer = setTimeout(wake, Math.min(Math.ceil(remaining), 2_147_483_647));
        }
    };
    wake();
    return () => clearTimeout(timer);
}

function waitUntil(deadline: number, signal: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
        let cancel = () => {};
        const abort = () => {
            cancel();
            signal.removeEventListener('abort', abort);
            reject(abortError(signal));
        };
        if (signal.aborted) {
            abort();
            return;
        }
        signal.addEventListener('abort', abort, { once: true });

        // Even an explicit zero backoff must yield so cancellation and budget timers can run.
        cancel = atDeadline(Math.max(deadline, performance.now() + 1), () => {
            signal.removeEventListener('abort', abort);
            resolve();
        });
    });
}

export function resumableSubscription<T>(
    open: (since: bigint | undefined, options: CallOptions) => AsyncIterable<SubscribeResponse>,
    since: bigint | undefined,
    config: SubscriptionRetryConfig | undefined,
    options: CallOptions | undefined,
    deliver: (frame: SubscribeResponse) => T | undefined,
): AsyncIterableIterator<T> {
    const policy = normalizeSubscriptionRetryConfig(config);
    const lifetime = new AbortController();
    let stopped = false;
    const iterator = (async function* (): AsyncGenerator<T> {
        let nextSince = since !== undefined && since > 0n ? since : undefined;
        let outageStarted: number | undefined = performance.now();
        let failures = 0;
        let lastError: unknown;
        const callerAbort = () => lifetime.abort(ConnectError.from(options?.signal?.reason, Code.Canceled));
        options?.signal?.addEventListener('abort', callerAbort, { once: true });
        if (options?.signal?.aborted) callerAbort();
        try {
            for (;;) {
                if (lifetime.signal.aborted) throw abortError(lifetime.signal);
                const attempt = new AbortController();
                const abort = () => attempt.abort(lifetime.signal.reason);
                lifetime.signal.addEventListener('abort', abort, { once: true });
                let expired = false;
                let cancelOutage = () => {};
                let deadline: number | undefined;
                const exhausted = () => new ConnectError(
                    'subscription outage budget exhausted', Code.DeadlineExceeded,
                    undefined, undefined, lastError,
                );
                if (policy.enabled && policy.budgetMs !== null && outageStarted !== undefined) {
                    deadline = outageStarted + policy.budgetMs;
                    cancelOutage = atDeadline(deadline, () => {
                        expired = true;
                        attempt.abort(exhausted());
                    });
                }
                let stream: AsyncIterator<SubscribeResponse> | undefined;
                try {
                    if (attempt.signal.aborted) throw abortError(attempt.signal);
                    if (failures > 0) {
                        const backoff = Math.min(
                            policy.initialBackoffMs * 2 ** Math.min(failures - 1, 52),
                            policy.maxBackoffMs,
                        );
                        await waitUntil(performance.now() + backoff * (0.5 + 0.5 * Math.random()), attempt.signal);
                    }
                    if (attempt.signal.aborted) throw abortError(attempt.signal);

                    // Connect's timeout also bounds healthy response bodies. Subscriptions
                    // use the outage budget and caller cancellation instead.
                    stream = open(nextSince, {
                        ...options,
                        timeoutMs: undefined,
                        signal: attempt.signal,
                    })[
                        Symbol.asyncIterator
                    ]();
                    for (;;) {
                        const frame = await abortable(stream.next(), attempt.signal);
                        if (attempt.signal.aborted) throw abortError(attempt.signal);
                        if (frame.done) {
                            if (!policy.enabled) return;
                            throw new ConnectError('subscription closed before cancellation', Code.Unavailable);
                        }

                        // Progress first observed after the budget elapsed does not revive the
                        // outage, even when the timer callback has not run yet.
                        if (deadline !== undefined && performance.now() >= deadline) {
                            expired = true;
                            throw exhausted();
                        }
                        cancelOutage();
                        outageStarted = undefined;
                        deadline = undefined;
                        failures = 0;
                        lastError = undefined;
                        const sequence = frame.value.sequenceNumber;
                        if (policy.enabled && nextSince !== undefined && sequence < nextSince) continue;

                        // Checkpoints prove resume progress without advancing a read session's floor.
                        nextSince = sequence + 1n;
                        const value = deliver(frame.value);
                        if (value !== undefined) yield value;
                    }
                } catch (error) {
                    if (stopped) return;
                    if (lifetime.signal.aborted) throw abortError(lifetime.signal);
                    if (expired) throw error;
                    if (!policy.enabled || nextSince === undefined || !retryable(error)) {
                        throw error;
                    }
                    if (nextSince > (1n << 64n) - 1n) throw error;
                    outageStarted ??= performance.now();
                    lastError = error;
                    failures++;
                } finally {
                    cancelOutage();
                    lifetime.signal.removeEventListener('abort', abort);
                    attempt.abort();

                    // A transport may ignore cancellation while next() is pending. Closing it must
                    // not keep the public iterator's return() waiting indefinitely.
                    try {
                        void Promise.resolve(stream?.return?.()).catch(() => {});
                    } catch {
                        // Cleanup cannot replace the failure that determines whether resume is safe.
                    }
                }
            }
        } finally {
            options?.signal?.removeEventListener('abort', callerAbort);
        }
    })();
    return {
        [Symbol.asyncIterator]() { return this; },
        next: () => iterator.next(),
        return: () => {
            stopped = true;
            lifetime.abort(new ConnectError('subscription stopped', Code.Canceled));
            return iterator.return(undefined);
        },
        throw: (error?: unknown) => {
            lifetime.abort(new ConnectError('subscription stopped', Code.Canceled));
            return iterator.throw(error);
        },
    };
}
