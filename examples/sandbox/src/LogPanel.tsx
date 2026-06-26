import { useEffect, useRef, useState } from 'react';
import { type StoreBatch, type StoreClient } from '@exowarexyz/sdk';
import { isNetworkError } from './clientErrors';
import { formatBytesValue, formatKeyPreview } from './format';

const MAX_LOG_EVENTS = 10;

interface NotificationFn {
  (type: 'success' | 'error', title: string, message: string): void;
}

function parseOptionalBigInt(value: string) {
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }
  return BigInt(trimmed);
}

function maxPrefixForReservedBits(reservedBits: number): number {
  return reservedBits === 0 ? 0 : 2 ** reservedBits - 1;
}

function renderBatch(batch: StoreBatch) {
  return (
    <div className="result fade-in">
      <h4>Batch {batch.sequenceNumber.toString()}</h4>
      <p><strong>Entries:</strong> {batch.entries.length}</p>
      {batch.entries.length > 0 ? (
        <div className="result-list">
          {batch.entries.map((entry, index) => (
            <div key={`${batch.sequenceNumber}-${index}`} className="result-row">
              <strong>{formatKeyPreview(entry.key)}</strong>
              <span>{formatBytesValue(entry.value)}</span>
            </div>
          ))}
        </div>
      ) : (
        <p>No entries</p>
      )}
    </div>
  );
}

export function LogPanel({
  client,
  showNotification,
  onConnectionLost,
  onConnectionRestored,
}: {
  client: StoreClient | null;
  showNotification: NotificationFn;
  onConnectionLost: () => void;
  onConnectionRestored: () => void;
}) {
  const [batchSequenceNumber, setBatchSequenceNumber] = useState('');
  const [batchResult, setBatchResult] = useState<StoreBatch | null>(null);
  const [batchNotFound, setBatchNotFound] = useState(false);
  const [streamReservedBits, setStreamReservedBits] = useState('0');
  const [streamPrefix, setStreamPrefix] = useState('0');
  const [streamPayloadRegex, setStreamPayloadRegex] = useState('(?s-u)^.*$');
  const [streamValueRegex, setStreamValueRegex] = useState('');
  const [streamSinceSequenceNumber, setStreamSinceSequenceNumber] = useState('');
  const [streamEvents, setStreamEvents] = useState<StoreBatch[]>([]);
  const [isGettingBatch, setIsGettingBatch] = useState(false);
  const [isSubscribing, setIsSubscribing] = useState(false);
  const streamAbortRef = useRef<AbortController | null>(null);
  const reservedBitsForMax = Number.parseInt(streamReservedBits || '0', 10);
  const maxStreamPrefix =
    Number.isInteger(reservedBitsForMax) && reservedBitsForMax >= 0 && reservedBitsForMax <= 16
      ? maxPrefixForReservedBits(reservedBitsForMax)
      : 65535;

  useEffect(() => {
    return () => {
      streamAbortRef.current?.abort();
    };
  }, []);

  const handleGetBatch = async () => {
    if (!client || !batchSequenceNumber.trim()) {
      return;
    }

    setIsGettingBatch(true);
    setBatchResult(null);
    setBatchNotFound(false);
    try {
      const sequenceNumber = BigInt(batchSequenceNumber.trim());
      const result = await client.getBatch(sequenceNumber);
      setBatchResult(result);
      setBatchNotFound(result === null);
      if (result) {
        showNotification('success', 'Log Batch Loaded', `Loaded batch ${sequenceNumber}`);
      } else {
        showNotification('success', 'Log Batch Missing', `Batch ${sequenceNumber} is not retained`);
      }
    } catch (error) {
      showNotification('error', 'Log Batch Failed', `Failed to get batch: ${error}`);
      setBatchResult(null);
      setBatchNotFound(false);
      if (isNetworkError(error)) {
        onConnectionLost();
      }
    } finally {
      setIsGettingBatch(false);
    }
  };

  const handleStartSubscription = () => {
    if (!client) {
      return;
    }

    try {
      const reservedBits = Number.parseInt(streamReservedBits || '0', 10);
      const prefix = Number.parseInt(streamPrefix || '0', 10);

      if (!Number.isInteger(reservedBits) || reservedBits < 0 || reservedBits > 16) {
        throw new Error('Reserved bits must be an integer between 0 and 16');
      }
      const maxPrefix = maxPrefixForReservedBits(reservedBits);
      if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
        throw new Error(`Prefix must be an integer between 0 and ${maxPrefix}`);
      }
      if (!streamPayloadRegex.trim()) {
        throw new Error('Payload regex is required');
      }

      streamAbortRef.current?.abort();
      setStreamEvents([]);
      setIsSubscribing(true);

      const controller = new AbortController();
      streamAbortRef.current = controller;
      const sinceSequenceNumber = parseOptionalBigInt(streamSinceSequenceNumber);
      const selector = {
        reservedBits,
        prefix,
        payloadRegex: streamPayloadRegex.trim(),
      };
      const valueRegex = streamValueRegex.trim();
      const valueFilters = valueRegex
        ? [{ kind: { case: 'regex' as const, value: valueRegex } }]
        : [];

      void (async () => {
        try {
          for await (const batch of client.subscribe(
            {
              selectors: [selector],
              valueFilters,
              sinceSequenceNumber,
            },
            { signal: controller.signal },
          )) {
            setStreamEvents((prev) => [batch, ...prev].slice(0, MAX_LOG_EVENTS));
            onConnectionRestored();
          }
        } catch (error) {
          if (!controller.signal.aborted) {
            showNotification('error', 'Log Subscription Error', String(error));
            if (isNetworkError(error)) {
              onConnectionLost();
            }
          }
        } finally {
          if (streamAbortRef.current === controller) {
            streamAbortRef.current = null;
            setIsSubscribing(false);
          }
        }
      })();

      showNotification(
        'success',
        'Log Subscription Started',
        sinceSequenceNumber !== undefined
          ? `Listening from sequence ${sinceSequenceNumber}`
          : 'Listening for the next matching batch',
      );
    } catch (error) {
      showNotification('error', 'Invalid Log Filter', String(error));
      setIsSubscribing(false);
    }
  };

  const handleStopSubscription = () => {
    if (!streamAbortRef.current) {
      return;
    }
    streamAbortRef.current.abort();
    streamAbortRef.current = null;
    setIsSubscribing(false);
    showNotification('success', 'Log Subscription Stopped', 'Live log subscription stopped');
  };

  return (
    <div className="card fade-in">
      <h2>Log</h2>

      <div className="form-section">
        <h3>Get Batch</h3>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="log-batch-sequence-number">Sequence Number</label>
            <input
              id="log-batch-sequence-number"
              type="number"
              min="0"
              placeholder="e.g. 42"
              value={batchSequenceNumber}
              onChange={(event) => setBatchSequenceNumber(event.target.value)}
            />
          </div>
        </div>
        <button
          className={`btn-primary ${isGettingBatch ? 'loading' : ''}`}
          onClick={handleGetBatch}
          disabled={!client || isGettingBatch || !batchSequenceNumber.trim()}
        >
          {isGettingBatch ? 'Loading...' : 'Get Batch'}
        </button>
        {batchResult && renderBatch(batchResult)}
        {batchNotFound && (
          <div className="result fade-in">
            <h4>Batch Not Retained</h4>
            <p><strong>Sequence:</strong> {batchSequenceNumber}</p>
          </div>
        )}
      </div>

      <div className="form-section">
        <h3>Subscribe</h3>
        <p className="section-note">
          Leave the since-sequence blank to start live from the next write.
        </p>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="log-stream-reserved-bits">Reserved Bits</label>
            <input
              id="log-stream-reserved-bits"
              type="number"
              min="0"
              max="16"
              value={streamReservedBits}
              onChange={(event) => setStreamReservedBits(event.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="log-stream-prefix">Prefix</label>
            <input
              id="log-stream-prefix"
              type="number"
              min="0"
              max={maxStreamPrefix}
              value={streamPrefix}
              onChange={(event) => setStreamPrefix(event.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="log-stream-since-sequence">Since Sequence (optional)</label>
            <input
              id="log-stream-since-sequence"
              type="number"
              min="0"
              placeholder="Replay from retained batch"
              value={streamSinceSequenceNumber}
              onChange={(event) => setStreamSinceSequenceNumber(event.target.value)}
            />
          </div>
        </div>
        <div className="form-row">
          <div className="form-group form-group-wide">
            <label htmlFor="log-stream-payload-regex">Payload Regex (key)</label>
            <input
              id="log-stream-payload-regex"
              type="text"
              placeholder="(?s-u)^orders/.*$"
              value={streamPayloadRegex}
              onChange={(event) => setStreamPayloadRegex(event.target.value)}
            />
          </div>
        </div>
        <div className="form-row">
          <div className="form-group form-group-wide">
            <label htmlFor="log-stream-value-regex">Value Regex (optional)</label>
            <input
              id="log-stream-value-regex"
              type="text"
              placeholder="(?s)^status=ready$"
              value={streamValueRegex}
              onChange={(event) => setStreamValueRegex(event.target.value)}
            />
          </div>
        </div>
        <div className="button-row">
          <button
            className={`btn-primary ${isSubscribing ? 'loading' : ''}`}
            onClick={handleStartSubscription}
            disabled={!client || isSubscribing}
          >
            {isSubscribing ? 'Streaming...' : 'Start Subscription'}
          </button>
          <button
            className="btn-secondary"
            onClick={handleStopSubscription}
            disabled={!isSubscribing}
          >
            Stop
          </button>
          <button
            className="btn-secondary"
            onClick={() => setStreamEvents([])}
            disabled={streamEvents.length === 0}
          >
            Clear Events
          </button>
        </div>

        {streamEvents.length > 0 ? (
          <div className="stream-events">
            {streamEvents.map((batch) => (
              <div key={batch.sequenceNumber.toString()} className="stream-event">
                {renderBatch(batch)}
              </div>
            ))}
          </div>
        ) : (
          <div className="result fade-in">
            <h4>Subscription Feed</h4>
            <p>{isSubscribing ? 'Waiting for matching batches...' : 'No batches received yet.'}</p>
          </div>
        )}
      </div>
    </div>
  );
}
