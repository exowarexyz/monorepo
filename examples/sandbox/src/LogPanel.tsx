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

const textEncoder = new TextEncoder();

// Store keys are raw bytes and many families use control bytes a text input
// cannot express, so a `0x` prefix switches the input to hex.
function parsePrefixInput(input: string): Uint8Array {
  if (input.startsWith('0x') || input.startsWith('0X')) {
    const hex = input.slice(2);
    if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
      throw new Error('Hex prefix must be an even number of hex digits after 0x');
    }
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }
  return textEncoder.encode(input);
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
  const [streamPrefix, setStreamPrefix] = useState('');
  const [streamPayloadRegex, setStreamPayloadRegex] = useState('(?s-u)^.*$');
  const [streamValueRegex, setStreamValueRegex] = useState('');
  const [streamSinceSequenceNumber, setStreamSinceSequenceNumber] = useState('');
  const [streamEvents, setStreamEvents] = useState<StoreBatch[]>([]);
  const [isGettingBatch, setIsGettingBatch] = useState(false);
  const [isSubscribing, setIsSubscribing] = useState(false);
  const streamAbortRef = useRef<AbortController | null>(null);

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
      const prefix = parsePrefixInput(streamPrefix);

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
            <label htmlFor="log-stream-prefix">Prefix (key)</label>
            <input
              id="log-stream-prefix"
              type="text"
              placeholder="e.g. orders/ or 0x01 for binary"
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
