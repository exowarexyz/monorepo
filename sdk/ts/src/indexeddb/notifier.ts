import { canceled, storeClosed } from './errors.js';

interface Waiter {
    wake(): void;
    fail(error: Error): void;
}

/**
 * Wakes subscribers that have read everything in the log. A wake is only a hint to read again.
 *
 * A subscriber takes a `mark` before it reads and waits with `after(mark)` when the read found
 * nothing. A wake that arrives between the two is not lost, because it moves the notifier past
 * the mark.
 */
export class Notifier {
    private wakes = 0;
    private latest = 0n;
    private closed = false;
    private readonly waiters = new Set<Waiter>();

    /** The current position in the sequence of wakes. */
    mark(): number {
        return this.wakes;
    }

    /**
     * The highest sequence number this connection committed. It only helps a Put guess the size of
     * its log row. It is never stored and never taken for the store's sequence number.
     */
    get hint(): bigint {
        return this.latest;
    }

    /** Subscribers waiting for a wake. */
    get waiting(): number {
        return this.waiters.size;
    }

    /**
     * Wakes every waiting subscriber. `committed` is the sequence number of a batch this
     * connection wrote.
     */
    wake(committed?: bigint): void {
        if (committed !== undefined && committed > this.latest) this.latest = committed;
        this.wakes++;
        this.drain((waiter) => waiter.wake());
    }

    /**
     * Resolves once a wake has arrived after `mark`. Rejects with the call's error when `signal`
     * aborts and with UNAVAILABLE when the store closes. Either way no waiter stays registered.
     */
    after(mark: number, signal: AbortSignal): Promise<void> {
        if (this.closed) return Promise.reject(storeClosed());
        if (signal.aborted) return Promise.reject(canceled(signal));
        if (mark !== this.wakes) return Promise.resolve();
        return new Promise((resolve, reject) => {
            const abort = () => {
                this.waiters.delete(waiter);
                reject(canceled(signal));
            };
            const waiter: Waiter = {
                wake: () => {
                    signal.removeEventListener('abort', abort);
                    resolve();
                },
                fail: (error) => {
                    signal.removeEventListener('abort', abort);
                    reject(error);
                },
            };
            signal.addEventListener('abort', abort, { once: true });
            this.waiters.add(waiter);
        });
    }

    /** Fails every waiting subscriber and every later wait with UNAVAILABLE. */
    close(): void {
        this.closed = true;
        this.drain((waiter) => waiter.fail(storeClosed()));
    }

    private drain(each: (waiter: Waiter) => void): void {
        const waiters = [...this.waiters];
        this.waiters.clear();
        waiters.forEach(each);
    }
}
