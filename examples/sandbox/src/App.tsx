import { useState, useEffect } from 'react';
import {
  Client,
  type StoreClient,
  type GetResult,
  type QueryResult,
  type QueryResultItem
} from 'exoware-sdk-ts';
import { Buffer } from 'buffer';
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

function App() {
  const [, setClient] = useState<Client | null>(null);
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

  // Loading states
  const [isSettingValue, setIsSettingValue] = useState(false);
  const [isGettingValue, setIsGettingValue] = useState(false);
  const [isQuerying, setIsQuerying] = useState(false);

  const enc = new TextEncoder();

  useEffect(() => {
    const c = new Client(SIMULATOR_URL, TOKEN);
    setClient(c);
    setStoreClient(c.store());

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
    </div>
  )
}

export default App
