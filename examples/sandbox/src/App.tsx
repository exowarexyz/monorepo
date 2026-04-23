import { useEffect, useRef, useState } from 'react';
import {
  Client,
  type GetResult,
  type QueryResult,
  type QueryResultItem,
  type StoreBatch,
  type StoreClient
} from 'exoware-sdk-ts';
import { Buffer } from 'buffer';
import './App.css';
import { QMDB_URL, QmdbPanel } from './QmdbPanel';
import { SQL_URL, SqlPanel } from './SqlPanel';

const MAX_STREAM_EVENTS = 10;

// Polyfill Buffer for browser environment
declare global {
  interface Window {
    Buffer: typeof Buffer;
  }
}
window.Buffer = Buffer;

// Load environment variables from .env file
const SIMULATOR_URL = import.meta.env.VITE_SIMULATOR_URL;
const TOKEN = import.meta.env.VITE_TOKEN;

interface Notification {
  id: string;
  type: 'success' | 'error';
  title: string;
  message: string;
}

function App() {
  const [storeClient, setStoreClient] = useState<StoreClient | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);

  // Store state
  const [storeKey, setStoreKey] = useState('');
  const [storeValue, setStoreValue] = useState('');
  const [storeGetKey, setStoreGetKey] = useState('');
  const [storeGetValue, setStoreGetValue] = useState<GetResult | null>(null);
  const [keyNotFound, setKeyNotFound] = useState(false);
  const [queryStart, setQueryStart] = useState('');
  const [queryEnd, setQueryEnd] = useState('');
  const [queryLimit, setQueryLimit] = useState('10');
  const [queryResult, setQueryResult] = useState<QueryResult | null>(null);

  // Stream state
  const [batchSequenceNumber, setBatchSequenceNumber] = useState('');
  const [batchResult, setBatchResult] = useState<StoreBatch | null>(null);
  const [batchNotFound, setBatchNotFound] = useState(false);
  const [streamReservedBits, setStreamReservedBits] = useState('0');
  const [streamPrefix, setStreamPrefix] = useState('0');
  const [streamPayloadRegex, setStreamPayloadRegex] = useState('(?s-u)^.*$');
  const [streamValueRegex, setStreamValueRegex] = useState('');
  const [streamSinceSequenceNumber, setStreamSinceSequenceNumber] = useState('');
  const [streamEvents, setStreamEvents] = useState<StoreBatch[]>([]);

  // Loading states
  const [isSettingValue, setIsSettingValue] = useState(false);
  const [isGettingValue, setIsGettingValue] = useState(false);
  const [isQuerying, setIsQuerying] = useState(false);
  const [isGettingBatch, setIsGettingBatch] = useState(false);
  const [isSubscribing, setIsSubscribing] = useState(false);

  const enc = new TextEncoder();
  const streamAbortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    const client = new Client(SIMULATOR_URL, TOKEN);
    const store = client.store();
    setStoreClient(store);

    testConnection(client).then((connected) => {
      if (!connected) {
        setNotifications((prev) => [
          ...prev,
          {
            id: Math.random().toString(36).slice(2, 11),
            type: 'error',
            title: 'Connection Failed',
            message: 'Unable to connect to the simulator backend'
          }
        ]);
      }
    });

    const healthCheckInterval = setInterval(() => {
      void testConnection(client);
    }, 30000);

    return () => {
      clearInterval(healthCheckInterval);
      streamAbortRef.current?.abort();
    };
  }, []);

  const showNotification = (type: 'success' | 'error', title: string, message: string) => {
    const id = Math.random().toString(36).slice(2, 11);
    const notification: Notification = { id, type, title, message };
    setNotifications((prev) => [...prev, notification]);

    setTimeout(() => {
      setNotifications((prev) => prev.filter((n) => n.id !== id));
    }, 5000);
  };

  const removeNotification = (id: string) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  };

  const testConnection = async (client: Client) => {
    try {
      await client.store().query(undefined, undefined, 1);
      setIsConnected(true);
      return true;
    } catch (e) {
      console.error('Backend connection failed:', e);
      setIsConnected(false);
      return false;
    }
  };

  const parseOptionalBigInt = (value: string) => {
    const trimmed = value.trim();
    if (!trimmed) {
      return undefined;
    }
    return BigInt(trimmed);
  };

  const handleSet = async () => {
    if (storeClient && storeKey) {
      setIsSettingValue(true);
      try {
        const sequenceNumber = await storeClient.set(enc.encode(storeKey), Buffer.from(storeValue));
        showNotification('success', 'Success', `Key "${storeKey}" set at sequence ${sequenceNumber}`);
        setStoreKey('');
        setStoreValue('');
      } catch (e) {
        showNotification('error', 'Error', `Failed to set value: ${e}`);
        if (e instanceof Error && (e.message.includes('fetch') || e.message.includes('network'))) {
          setIsConnected(false);
        }
      } finally {
        setIsSettingValue(false);
      }
    }
  };

  const handleGet = async () => {
    if (storeClient && storeGetKey) {
      setIsGettingValue(true);
      setStoreGetValue(null);
      setKeyNotFound(false);
      try {
        const result = await storeClient.get(enc.encode(storeGetKey));
        setStoreGetValue(result);
        setKeyNotFound(result === null);
        showNotification('success', 'Success', `Retrieved value for key "${storeGetKey}"`);
      } catch (e) {
        showNotification('error', 'Error', `Failed to get value: ${e}`);
        setStoreGetValue(null);
        setKeyNotFound(false);
        if (e instanceof Error && (e.message.includes('fetch') || e.message.includes('network'))) {
          setIsConnected(false);
        }
      } finally {
        setIsGettingValue(false);
      }
    }
  };

  const handleQuery = async () => {
    if (storeClient) {
      setIsQuerying(true);
      try {
        const result = await storeClient.query(
          queryStart ? enc.encode(queryStart) : undefined,
          queryEnd ? enc.encode(queryEnd) : undefined,
          queryLimit ? parseInt(queryLimit, 10) : undefined
        );
        setQueryResult(result);
        showNotification('success', 'Success', `Query returned ${result.results.length} results`);
      } catch (e) {
        showNotification('error', 'Error', `Query failed: ${e}`);
      } finally {
        setIsQuerying(false);
      }
    }
  };

  const handleGetBatch = async () => {
    if (!storeClient || !batchSequenceNumber.trim()) {
      return;
    }

    setIsGettingBatch(true);
    setBatchResult(null);
    setBatchNotFound(false);
    try {
      const sequenceNumber = BigInt(batchSequenceNumber.trim());
      const result = await storeClient.getBatch(sequenceNumber);
      setBatchResult(result);
      setBatchNotFound(result === null);
      if (result) {
        showNotification('success', 'Batch Loaded', `Loaded batch ${sequenceNumber}`);
      } else {
        showNotification('success', 'Batch Missing', `Batch ${sequenceNumber} is not retained`);
      }
    } catch (e) {
      showNotification('error', 'Error', `Failed to get batch: ${e}`);
      setBatchResult(null);
      setBatchNotFound(false);
    } finally {
      setIsGettingBatch(false);
    }
  };

  const handleStartSubscription = () => {
    if (!storeClient) {
      return;
    }

    try {
      const reservedBits = Number.parseInt(streamReservedBits || '0', 10);
      const prefix = Number.parseInt(streamPrefix || '0', 10);

      if (!Number.isInteger(reservedBits) || reservedBits < 0 || reservedBits > 255) {
        throw new Error('Reserved bits must be an integer between 0 and 255');
      }
      if (!Number.isInteger(prefix) || prefix < 0 || prefix > 65535) {
        throw new Error('Prefix must be an integer between 0 and 65535');
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
      const matchKey = {
        reservedBits,
        prefix,
        payloadRegex: streamPayloadRegex.trim()
      };
      const valueRegex = streamValueRegex.trim();
      const valueFilters = valueRegex
        ? [{ kind: { case: 'regex' as const, value: valueRegex } }]
        : [];

      void (async () => {
        try {
          for await (const batch of storeClient.subscribe(
            {
              matchKeys: [matchKey],
              valueFilters,
              sinceSequenceNumber,
            },
            { signal: controller.signal },
          )) {
            setStreamEvents((prev) => [batch, ...prev].slice(0, MAX_STREAM_EVENTS));
            setIsConnected(true);
          }
        } catch (e) {
          if (!controller.signal.aborted) {
            showNotification('error', 'Subscription Error', String(e));
            if (e instanceof Error && (e.message.includes('fetch') || e.message.includes('network'))) {
              setIsConnected(false);
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
        'Subscription Started',
        sinceSequenceNumber !== undefined
          ? `Listening from sequence ${sinceSequenceNumber}`
          : 'Listening for the next matching batch'
      );
    } catch (e) {
      showNotification('error', 'Invalid Stream Filter', String(e));
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
    showNotification('success', 'Subscription Stopped', 'Live stream subscription stopped');
  };

  const handleGetKeyChange = (value: string) => {
    setStoreGetKey(value);
    if (storeGetValue || keyNotFound) {
      setStoreGetValue(null);
      setKeyNotFound(false);
    }
  };

  const renderValue = (value: Uint8Array) => {
    try {
      const str = Buffer.from(value).toString('utf-8');
      // eslint-disable-next-line no-control-regex
      if (/^[\x00-\x7F]*$/.test(str)) {
        return str;
      }
    } catch (_e) {
      // ignore
    }
    return `[${Array.from(value).join(', ')}]`;
  };

  const formatKeyPreview = (key: Uint8Array) => {
    try {
      return new TextDecoder('utf-8', { fatal: false }).decode(key);
    } catch {
      return `[${key.byteLength} bytes]`;
    }
  };

  const renderBatch = (batch: StoreBatch) => (
    <div className="result fade-in">
      <h4>Batch {batch.sequenceNumber.toString()}</h4>
      <p><strong>Entries:</strong> {batch.entries.length}</p>
      {batch.entries.length > 0 ? (
        <div className="result-list">
          {batch.entries.map((entry, index) => (
            <div key={`${batch.sequenceNumber}-${index}`} className="result-row">
              <strong>{formatKeyPreview(entry.key)}</strong>
              <span>{renderValue(entry.value)}</span>
            </div>
          ))}
        </div>
      ) : (
        <p>No entries</p>
      )}
    </div>
  );

  return (
    <div className="App">
      {notifications.map((notification) => (
        <div key={notification.id} className={`notification ${notification.type}`}>
          <button
            className="notification-close"
            onClick={() => removeNotification(notification.id)}
          >
            ×
          </button>
          <div className="notification-title">{notification.title}</div>
          <div className="notification-message">{notification.message}</div>
        </div>
      ))}

      <div className="header">
        <div className="header-copy">
          <h1>Exoware API Sandbox</h1>
        </div>
        <div className={`status-indicator ${isConnected ? 'status-connected' : 'status-disconnected'}`}>
          <span>●</span>
          {isConnected ? 'Connected' : 'Disconnected'}
        </div>
      </div>

      <div className="card fade-in">
        <h2>Store Operations</h2>

        <div className="form-section">
          <h3>Set Value</h3>
          <div className="form-row">
            <div className="form-group">
              <label htmlFor="store-key">Key</label>
              <input
                id="store-key"
                type="text"
                placeholder="Enter key"
                value={storeKey}
                onChange={(e) => setStoreKey(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label htmlFor="store-value">Value</label>
              <input
                id="store-value"
                type="text"
                placeholder="Enter value"
                value={storeValue}
                onChange={(e) => setStoreValue(e.target.value)}
              />
            </div>
          </div>
          <button
            className={`btn-primary ${isSettingValue ? 'loading' : ''}`}
            onClick={handleSet}
            disabled={isSettingValue || !storeKey}
          >
            {isSettingValue ? 'Setting...' : 'Set Value'}
          </button>
        </div>

        <div className="form-section">
          <h3>Get Value</h3>
          <div className="form-row">
            <div className="form-group">
              <label htmlFor="get-key">Key</label>
              <input
                id="get-key"
                type="text"
                placeholder="Enter key to retrieve"
                value={storeGetKey}
                onChange={(e) => handleGetKeyChange(e.target.value)}
              />
            </div>
          </div>
          <button
            className={`btn-primary ${isGettingValue ? 'loading' : ''}`}
            onClick={handleGet}
            disabled={isGettingValue || !storeGetKey}
          >
            {isGettingValue ? 'Getting...' : 'Get Value'}
          </button>
          {storeGetValue && (
            <div className="result fade-in">
              <h4>Retrieved Value</h4>
              <p><strong>Key:</strong> {storeGetKey}</p>
              <p><strong>Value:</strong> {renderValue(storeGetValue.value)}</p>
            </div>
          )}
          {keyNotFound && (
            <div className="result fade-in">
              <h4>Not Found</h4>
              <p><strong>Key:</strong> {storeGetKey}</p>
            </div>
          )}
        </div>

        <div className="form-section">
          <h3>Query Range</h3>
          <div className="form-row">
            <div className="form-group">
              <label htmlFor="query-start">Start Key (optional)</label>
              <input
                id="query-start"
                type="text"
                placeholder="Start key"
                value={queryStart}
                onChange={(e) => setQueryStart(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label htmlFor="query-end">End Key (optional)</label>
              <input
                id="query-end"
                type="text"
                placeholder="End key"
                value={queryEnd}
                onChange={(e) => setQueryEnd(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label htmlFor="query-limit">Limit</label>
              <input
                id="query-limit"
                type="number"
                placeholder="10"
                value={queryLimit}
                onChange={(e) => setQueryLimit(e.target.value)}
              />
            </div>
          </div>
          <button
            className={`btn-primary ${isQuerying ? 'loading' : ''}`}
            onClick={handleQuery}
            disabled={isQuerying}
          >
            {isQuerying ? 'Querying...' : 'Query Range'}
          </button>
          {queryResult && (
            <div className="result fade-in">
              <h4>Query Results ({queryResult.results.length} items)</h4>
              {queryResult.results.length > 0 ? (
                <ul>
                  {queryResult.results.map((item: QueryResultItem, i: number) => (
                    <li key={`${i}-${item.key.byteLength}`}>
                      <strong>{formatKeyPreview(item.key)}:</strong> {renderValue(item.value)}
                    </li>
                  ))}
                </ul>
              ) : (
                <p>No results found</p>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="card fade-in">
        <h2>Batch Log &amp; Stream</h2>

        <div className="form-section">
          <h3>Get Batch</h3>
          <div className="form-row">
            <div className="form-group">
              <label htmlFor="batch-sequence-number">Sequence Number</label>
              <input
                id="batch-sequence-number"
                type="number"
                min="0"
                placeholder="e.g. 42"
                value={batchSequenceNumber}
                onChange={(e) => setBatchSequenceNumber(e.target.value)}
              />
            </div>
          </div>
          <button
            className={`btn-primary ${isGettingBatch ? 'loading' : ''}`}
            onClick={handleGetBatch}
            disabled={isGettingBatch || !batchSequenceNumber.trim()}
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
            Subscribe to matching batches from the batch log. Leave the since-sequence blank to
            start live from the next write.
          </p>
          <div className="form-row">
            <div className="form-group">
              <label htmlFor="stream-reserved-bits">Reserved Bits</label>
              <input
                id="stream-reserved-bits"
                type="number"
                min="0"
                max="255"
                value={streamReservedBits}
                onChange={(e) => setStreamReservedBits(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label htmlFor="stream-prefix">Prefix</label>
              <input
                id="stream-prefix"
                type="number"
                min="0"
                max="65535"
                value={streamPrefix}
                onChange={(e) => setStreamPrefix(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label htmlFor="stream-since-sequence">Since Sequence (optional)</label>
              <input
                id="stream-since-sequence"
                type="number"
                min="0"
                placeholder="Replay from retained batch"
                value={streamSinceSequenceNumber}
                onChange={(e) => setStreamSinceSequenceNumber(e.target.value)}
              />
            </div>
          </div>
          <div className="form-row">
            <div className="form-group form-group-wide">
              <label htmlFor="stream-payload-regex">Payload Regex (key)</label>
              <input
                id="stream-payload-regex"
                type="text"
                placeholder="(?s-u)^orders/.*$"
                value={streamPayloadRegex}
                onChange={(e) => setStreamPayloadRegex(e.target.value)}
              />
            </div>
          </div>
          <div className="form-row">
            <div className="form-group form-group-wide">
              <label htmlFor="stream-value-regex">Value Regex (optional)</label>
              <input
                id="stream-value-regex"
                type="text"
                placeholder="(?s)^status=ready$"
                value={streamValueRegex}
                onChange={(e) => setStreamValueRegex(e.target.value)}
              />
            </div>
          </div>
          <div className="button-row">
            <button
              className={`btn-primary ${isSubscribing ? 'loading' : ''}`}
              onClick={handleStartSubscription}
              disabled={isSubscribing}
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

      {QMDB_URL && <QmdbPanel qmdbUrl={QMDB_URL} showNotification={showNotification} />}
      {SQL_URL && <SqlPanel sqlUrl={SQL_URL} showNotification={showNotification} />}
    </div>
  );
}

export default App;
