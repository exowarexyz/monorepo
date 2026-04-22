import { useState, useEffect } from 'react';
import {
  Client,
  type StoreClient,
  type StoreStreamClient,
  type GetResult,
  type QueryResult,
  type QueryResultItem,
  type StreamBatch,
} from 'exoware-sdk-ts';
import { Buffer } from 'buffer';
import {
  ImmutableQmdbClient,
  KeylessQmdbClient,
  OrderedQmdbClient,
  UnorderedQmdbClient,
  qmdbMatchKeysForVariant,
  type QmdbStreamVariant,
  type VerifiedQmdbBatch,
} from '@exoware/qmdb-web';
import './App.css';

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

type VerifiedQmdbOperation = VerifiedQmdbBatch['operations'][number];
type VerifiedStreamClient = {
  streamBatches(since?: bigint): AsyncGenerator<VerifiedQmdbBatch, void, void>;
  free(): void;
};

const MAX_STREAM_BATCHES = 12;

function App() {
  const [, setClient] = useState<Client | null>(null);
  const [storeClient, setStoreClient] = useState<StoreClient | null>(null);
  const [streamClient, setStreamClient] = useState<StoreStreamClient | null>(null);
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
  const [streamVariant, setStreamVariant] = useState<QmdbStreamVariant>('ordered');
  const [streamSinceSequence, setStreamSinceSequence] = useState('');
  const [immutableKeySizeBytes, setImmutableKeySizeBytes] = useState('32');
  const [activeStream, setActiveStream] = useState<{
    variant: QmdbStreamVariant;
    sinceSequenceNumber?: bigint;
    immutableKeySizeBytes?: number;
  } | null>(null);
  const [streamBatches, setStreamBatches] = useState<StreamBatch[]>([]);
  const [verifiedBatches, setVerifiedBatches] = useState<VerifiedQmdbBatch[]>([]);
  const [streamError, setStreamError] = useState<string | null>(null);
  const [verifiedError, setVerifiedError] = useState<string | null>(null);
  const [lastStreamSequence, setLastStreamSequence] = useState<bigint | null>(null);
  const [lastVerifiedWatermark, setLastVerifiedWatermark] = useState<bigint | null>(null);
  const [isStreamConnecting, setIsStreamConnecting] = useState(false);
  const [isStreamLive, setIsStreamLive] = useState(false);
  const [isVerifiedStreamConnecting, setIsVerifiedStreamConnecting] = useState(false);
  const [isVerifiedStreamLive, setIsVerifiedStreamLive] = useState(false);

  // Loading states
  const [isSettingValue, setIsSettingValue] = useState(false);
  const [isGettingValue, setIsGettingValue] = useState(false);
  const [isQuerying, setIsQuerying] = useState(false);

  const enc = new TextEncoder();

  useEffect(() => {
    const c = new Client(SIMULATOR_URL, TOKEN);
    setClient(c);
    setStoreClient(c.store());
    setStreamClient(c.stream());

    // Initial connection test
    testConnection(c).then(connected => {
      if (!connected) {
        setNotifications(prev => [...prev, {
          id: Math.random().toString(36).substr(2, 9),
          type: 'error',
          title: 'Connection Failed',
          message: 'Unable to connect to the simulator backend'
        }]);
      }
    });

    // Periodic connection check every 30 seconds
    const healthCheckInterval = setInterval(() => {
      testConnection(c);
    }, 30000);

    return () => clearInterval(healthCheckInterval);
  }, []);

  const showNotification = (type: 'success' | 'error', title: string, message: string) => {
    const id = Math.random().toString(36).substr(2, 9);
    const notification: Notification = { id, type, title, message };
    setNotifications(prev => [...prev, notification]);

    // Auto-remove after 5 seconds
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 5000);
  };

  const removeNotification = (id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
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

  const createVerifiedStreamClient = (): VerifiedStreamClient | null => {
    if (!storeClient || !streamClient || activeStream === null) {
      return null;
    }

    switch (activeStream.variant) {
      case 'ordered':
        return new OrderedQmdbClient(storeClient, streamClient) as VerifiedStreamClient;
      case 'unordered':
        return new UnorderedQmdbClient(storeClient, streamClient) as VerifiedStreamClient;
      case 'immutable':
        return new ImmutableQmdbClient(
          storeClient,
          streamClient,
          activeStream.immutableKeySizeBytes ?? 32,
        ) as VerifiedStreamClient;
      case 'keyless':
        return new KeylessQmdbClient(storeClient, streamClient) as VerifiedStreamClient;
    }
  };

  useEffect(() => {
    if (!streamClient || activeStream === null) {
      return;
    }

    let cancelled = false;
    const iterator = streamClient.subscribe(
      qmdbMatchKeysForVariant(activeStream.variant),
      activeStream.sinceSequenceNumber,
    );

    setIsStreamConnecting(true);
    setIsStreamLive(false);
    setStreamError(null);

    void (async () => {
      try {
        for await (const batch of iterator) {
          if (cancelled) {
            break;
          }
          setIsStreamConnecting(false);
          setIsStreamLive(true);
          setLastStreamSequence(batch.sequenceNumber);
          setStreamBatches((prev) => [batch, ...prev].slice(0, MAX_STREAM_BATCHES));
        }

        if (!cancelled) {
          setIsStreamConnecting(false);
          setIsStreamLive(false);
        }
      } catch (error) {
        if (cancelled) {
          return;
        }
        const message = error instanceof Error ? error.message : String(error);
        setIsStreamConnecting(false);
        setIsStreamLive(false);
        setStreamError(message);
        showNotification('error', 'Stream Error', message);
      }
    })();

    return () => {
      cancelled = true;
      setIsStreamConnecting(false);
      setIsStreamLive(false);
      void iterator.return?.();
    };
  }, [activeStream, streamClient]);

  useEffect(() => {
    if (!storeClient || !streamClient || activeStream === null) {
      return;
    }

    let cancelled = false;
    const reader = createVerifiedStreamClient();
    let iterator: AsyncGenerator<VerifiedQmdbBatch, void, void> | null = null;
    let readerReleased = false;

    if (reader === null) {
      return;
    }

    const releaseReader = () => {
      if (!readerReleased) {
        readerReleased = true;
        reader.free();
      }
    };

    setIsVerifiedStreamConnecting(true);
    setIsVerifiedStreamLive(false);
    setVerifiedError(null);

    void (async () => {
      try {
        iterator = reader.streamBatches(activeStream.sinceSequenceNumber);
        for await (const batch of iterator) {
          if (cancelled) {
            break;
          }
          setIsVerifiedStreamConnecting(false);
          setIsVerifiedStreamLive(true);
          setLastVerifiedWatermark(batch.watermark);
          setVerifiedBatches((prev) => [batch, ...prev].slice(0, MAX_STREAM_BATCHES));
        }

        if (!cancelled) {
          setIsVerifiedStreamConnecting(false);
          setIsVerifiedStreamLive(false);
        }
      } catch (error) {
        if (cancelled) {
          return;
        }
        const message = error instanceof Error ? error.message : String(error);
        setIsVerifiedStreamConnecting(false);
        setIsVerifiedStreamLive(false);
        setVerifiedError(message);
        showNotification('error', 'Verified Stream Error', message);
      } finally {
        releaseReader();
      }
    })();

    return () => {
      cancelled = true;
      setIsVerifiedStreamConnecting(false);
      setIsVerifiedStreamLive(false);
      void iterator?.return?.();
      releaseReader();
    };
  }, [activeStream, storeClient, streamClient]);

  const handleStartStream = () => {
    if (!streamClient) {
      showNotification('error', 'Error', 'Stream client is not ready');
      return;
    }

    try {
      const trimmed = streamSinceSequence.trim();
      const sinceSequenceNumber = trimmed.length > 0 ? BigInt(trimmed) : undefined;
      const immutableKeySize =
        streamVariant === 'immutable'
          ? Number.parseInt(immutableKeySizeBytes.trim(), 10)
          : undefined;
      if (
        streamVariant === 'immutable' &&
        (!Number.isInteger(immutableKeySize) || immutableKeySize === undefined || immutableKeySize <= 0)
      ) {
        throw new Error('Immutable key size must be a positive integer');
      }
      setStreamBatches([]);
      setVerifiedBatches([]);
      setStreamError(null);
      setVerifiedError(null);
      setLastStreamSequence(null);
      setLastVerifiedWatermark(null);
      setActiveStream({
        variant: streamVariant,
        ...(sinceSequenceNumber !== undefined ? { sinceSequenceNumber } : {}),
        ...(immutableKeySize !== undefined
          ? { immutableKeySizeBytes: immutableKeySize }
          : {}),
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Invalid stream sequence number';
      showNotification('error', 'Invalid Cursor', message);
    }
  };

  const handleStopStream = () => {
    setActiveStream(null);
    setIsStreamConnecting(false);
    setIsStreamLive(false);
    setIsVerifiedStreamConnecting(false);
    setIsVerifiedStreamLive(false);
  };

  const handleSet = async () => {
    if (storeClient && storeKey) {
      setIsSettingValue(true);
      try {
        await storeClient.set(enc.encode(storeKey), Buffer.from(storeValue));
        showNotification('success', 'Success', `Key "${storeKey}" set successfully`);
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
        if (result) {
          setKeyNotFound(false);
        } else {
          setKeyNotFound(true);
        }
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

  const formatHex = (value: Uint8Array) =>
    Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');

  const renderVerifiedOperation = (operation: VerifiedQmdbOperation) => {
    switch (operation.kind) {
      case 'delete':
        return `delete ${formatKeyPreview(operation.key)}`;
      case 'update':
        if ('nextKey' in operation) {
          return `update ${formatKeyPreview(operation.key)} -> ${renderValue(operation.value)} (next ${formatKeyPreview(operation.nextKey)})`;
        }
        return `update ${formatKeyPreview(operation.key)} -> ${renderValue(operation.value)}`;
      case 'set':
        return `set ${formatKeyPreview(operation.key)} -> ${renderValue(operation.value)}`;
      case 'append':
        return `append ${renderValue(operation.value)}`;
      case 'commit':
        return operation.metadata
          ? `commit metadata=${renderValue(operation.metadata)}`
          : 'commit';
      case 'commitFloor':
        return operation.metadata
          ? `commitFloor inactivity=${operation.inactivityFloor.toString()} metadata=${renderValue(operation.metadata)}`
          : `commitFloor inactivity=${operation.inactivityFloor.toString()}`;
    }
  };

  const activeVariant = activeStream?.variant ?? streamVariant;
  const nextResumeSequence =
    lastStreamSequence === null ? null : (lastStreamSequence + 1n).toString();
  const activeImmutableKeySize =
    activeStream?.immutableKeySizeBytes?.toString() ?? immutableKeySizeBytes;

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
        <h1>Exoware API Sandbox</h1>
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
        <h2>QMDB Stream</h2>

        <div className="form-section">
          <h3>Live Subscription</h3>
          <div className="form-row">
            <div className="form-group">
              <label htmlFor="stream-variant">Variant</label>
              <select
                id="stream-variant"
                value={streamVariant}
                onChange={(e) => setStreamVariant(e.target.value as QmdbStreamVariant)}
                disabled={activeStream !== null}
              >
                <option value="ordered">Ordered</option>
                <option value="unordered">Unordered</option>
                <option value="immutable">Immutable</option>
                <option value="keyless">Keyless</option>
              </select>
            </div>
            <div className="form-group">
              <label htmlFor="stream-since-sequence">Since Sequence (optional)</label>
              <input
                id="stream-since-sequence"
                type="text"
                placeholder="Replay from store sequence"
                value={streamSinceSequence}
                onChange={(e) => setStreamSinceSequence(e.target.value)}
                disabled={activeStream !== null}
              />
            </div>
            {streamVariant === 'immutable' && (
              <div className="form-group">
                <label htmlFor="immutable-key-size">Immutable Key Size (bytes)</label>
                <input
                  id="immutable-key-size"
                  type="number"
                  min="1"
                  placeholder="32"
                  value={immutableKeySizeBytes}
                  onChange={(e) => setImmutableKeySizeBytes(e.target.value)}
                  disabled={activeStream !== null}
                />
              </div>
            )}
          </div>
          <div className="form-row">
            <button
              className={`btn-primary ${isStreamConnecting ? 'loading' : ''}`}
              onClick={handleStartStream}
              disabled={activeStream !== null || streamClient === null}
            >
              {isStreamConnecting ? 'Connecting...' : 'Start Stream'}
            </button>
            <button
              className="btn-secondary"
              onClick={handleStopStream}
              disabled={activeStream === null}
            >
              Stop Stream
            </button>
          </div>
          <div className="result fade-in">
            <h4>Stream Status</h4>
            <p><strong>Variant:</strong> {activeVariant}</p>
            <p>
              <strong>Raw Stream:</strong>{' '}
              {isStreamConnecting ? 'connecting' : isStreamLive ? 'live' : activeStream ? 'idle' : 'stopped'}
            </p>
            <p>
              <strong>Verified Stream:</strong>{' '}
              {isVerifiedStreamConnecting
                ? 'connecting'
                : isVerifiedStreamLive
                  ? 'live'
                  : activeStream
                    ? 'idle'
                    : 'stopped'}
            </p>
            <p><strong>Filter Families:</strong> {qmdbMatchKeysForVariant(activeVariant).map((matchKey) => matchKey.prefix).join(', ')}</p>
            {activeVariant === 'immutable' && (
              <p><strong>Immutable Key Size:</strong> {activeImmutableKeySize}</p>
            )}
            {lastStreamSequence !== null && (
              <p><strong>Last Raw Sequence:</strong> {lastStreamSequence.toString()}</p>
            )}
            {nextResumeSequence !== null && (
              <p><strong>Next Resume Cursor:</strong> {nextResumeSequence}</p>
            )}
            {lastVerifiedWatermark !== null && (
              <p><strong>Last Verified Watermark:</strong> {lastVerifiedWatermark.toString()}</p>
            )}
            {streamError && (
              <p><strong>Raw Stream Error:</strong> {streamError}</p>
            )}
            {verifiedError && (
              <p><strong>Verification Error:</strong> {verifiedError}</p>
            )}
          </div>
        </div>

        <div className="form-section">
          <h3>Raw Stream Frames</h3>
          {streamBatches.length > 0 ? (
            streamBatches.map((batch) => (
              <div key={batch.sequenceNumber.toString()} className="result fade-in">
                <h4>Batch {batch.sequenceNumber.toString()}</h4>
                <p><strong>Entries:</strong> {batch.entries.length}</p>
                <ul>
                  {batch.entries.map((entry, index) => (
                    <li key={`${batch.sequenceNumber.toString()}-${index}`}>
                      <strong>key</strong> {formatHex(entry.key)} | <strong>value</strong> {renderValue(entry.value)}
                    </li>
                  ))}
                </ul>
              </div>
            ))
          ) : (
            <div className="result fade-in">
              <p>No stream frames received yet.</p>
            </div>
          )}
        </div>

        <div className="form-section">
          <h3>Verified QMDB Batches (WASM)</h3>
          {verifiedBatches.length > 0 ? (
            verifiedBatches.map((batch, batchIndex) => (
              <div
                key={`verified-${batch.watermark.toString()}-${batch.startLocation.toString()}-${batchIndex}`}
                className="result fade-in"
              >
                <h4>Watermark {batch.watermark.toString()}</h4>
                <p><strong>Start Location:</strong> {batch.startLocation.toString()}</p>
                <p><strong>Operations:</strong> {batch.operations.length}</p>
                <p><strong>Root:</strong> {formatHex(batch.root)}</p>
                {batch.resumeSequenceNumber !== undefined && (
                  <p><strong>Resume Sequence:</strong> {batch.resumeSequenceNumber.toString()}</p>
                )}
                {batch.operations.length > 0 ? (
                  <ul>
                    {batch.operations.map((operation, index) => (
                      <li key={`verified-${batch.watermark.toString()}-${index}`}>
                        {renderVerifiedOperation(operation)}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p>No operations verified for this batch.</p>
                )}
              </div>
            ))
          ) : (
            <div className="result fade-in">
              <p>No verified QMDB batches received yet.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default App
