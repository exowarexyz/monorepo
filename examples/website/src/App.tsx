import { useState, useEffect } from 'react';
import {
  Client,
  type StoreClient,
  type StreamClient,
  type Subscription,
  type GetResult,
  type QueryResult,
  type QueryResultItem
} from 'exoware-sdk';
import { Buffer } from 'buffer';
import './App.css';

// Polyfill Buffer for browser environment
declare global {
  interface Window {
    Buffer: typeof Buffer;
  }
}
window.Buffer = Buffer;

const SIMULATOR_URL = 'http://localhost:8080';
const AUTH_TOKEN = 'your-secret-token'; // IMPORTANT: Replace with your actual auth token

interface Notification {
  id: string;
  type: 'success' | 'error';
  title: string;
  message: string;
}

function App() {
  const [, setClient] = useState<Client | null>(null);
  const [storeClient, setStoreClient] = useState<StoreClient | null>(null);
  const [streamClient, setStreamClient] = useState<StreamClient | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);

  // Store state
  const [storeKey, setStoreKey] = useState('');
  const [storeValue, setStoreValue] = useState('');
  const [storeGetKey, setStoreGetKey] = useState('');
  const [storeGetValue, setStoreGetValue] = useState<GetResult | null>(null);
  const [queryStart, setQueryStart] = useState('');
  const [queryEnd, setQueryEnd] = useState('');
  const [queryLimit, setQueryLimit] = useState('10');
  const [queryResult, setQueryResult] = useState<QueryResult | null>(null);

  // Stream state
  const [streamName, setStreamName] = useState('my-stream');
  const [streamPublishData, setStreamPublishData] = useState('hello world');
  const [streamSubscribeName, setStreamSubscribeName] = useState('my-stream');
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [streamMessages, setStreamMessages] = useState<unknown[]>([]);

  // Loading states
  const [isSettingValue, setIsSettingValue] = useState(false);
  const [isGettingValue, setIsGettingValue] = useState(false);
  const [isQuerying, setIsQuerying] = useState(false);
  const [isPublishing, setIsPublishing] = useState(false);
  const [isSubscribing, setIsSubscribing] = useState(false);

  useEffect(() => {
    const c = new Client(SIMULATOR_URL, AUTH_TOKEN);
    setClient(c);
    setStoreClient(c.store());
    setStreamClient(c.stream());
    setIsConnected(true);
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

  const handleSet = async () => {
    if (storeClient && storeKey) {
      setIsSettingValue(true);
      try {
        await storeClient.set(storeKey, Buffer.from(storeValue));
        showNotification('success', 'Success', `Key "${storeKey}" set successfully`);
        setStoreKey('');
        setStoreValue('');
      } catch (e) {
        showNotification('error', 'Error', `Failed to set value: ${e}`);
      } finally {
        setIsSettingValue(false);
      }
    }
  };

  const handleGet = async () => {
    if (storeClient && storeGetKey) {
      setIsGettingValue(true);
      setStoreGetValue(null); // Clear previous result
      try {
        const result = await storeClient.get(storeGetKey);
        setStoreGetValue(result);
        showNotification('success', 'Success', `Retrieved value for key "${storeGetKey}"`);
      } catch (e) {
        showNotification('error', 'Error', `Failed to get value: ${e}`);
        setStoreGetValue(null); // Clear result on error
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
          queryStart || undefined,
          queryEnd || undefined,
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

  const handlePublish = async () => {
    if (streamClient && streamName) {
      setIsPublishing(true);
      try {
        await streamClient.publish(streamName, Buffer.from(streamPublishData));
        showNotification('success', 'Success', `Message published to "${streamName}"`);
      } catch (e) {
        showNotification('error', 'Error', `Failed to publish message: ${e}`);
      } finally {
        setIsPublishing(false);
      }
    }
  };

  const handleSubscribe = async () => {
    if (streamClient && streamSubscribeName && !subscription) {
      setIsSubscribing(true);
      try {
        const sub = await streamClient.subscribe(streamSubscribeName);
        setSubscription(sub);
        setStreamMessages([]);
        showNotification('success', 'Success', `Subscribed to "${streamSubscribeName}"`);

        sub.onMessage((data: unknown) => {
          setStreamMessages((prev) => [...prev, data]);
        });
        sub.onClose((ev: any) => {
          console.log('Subscription closed', ev);
          setSubscription(null);
          showNotification('error', 'Disconnected', 'Subscription was closed');
        });
        sub.onError((err: any) => {
          console.error('Subscription error', err);
          showNotification('error', 'Error', 'Subscription error occurred');
        });

      } catch (e) {
        showNotification('error', 'Error', `Failed to subscribe: ${e}`);
      } finally {
        setIsSubscribing(false);
      }
    }
  };

  const handleUnsubscribe = () => {
    if (subscription) {
      subscription.close();
      setSubscription(null);
      showNotification('success', 'Success', 'Unsubscribed from stream');
    }
  };

  const handleGetKeyChange = (value: string) => {
    setStoreGetKey(value);
    if (storeGetValue) {
      setStoreGetValue(null); // Clear result when key changes
    }
  };

  const renderValue = (value: Uint8Array) => {
    try {
      // Is it a string?
      const str = Buffer.from(value).toString('utf-8');
      // check for weird characters
      // eslint-disable-next-line no-control-regex
      if (/^[\x00-\x7F]*$/.test(str)) {
        return str;
      }
    } catch (_e) {
      // ignore
    }
    return `[${value.join(', ')}]`;
  }

  return (
    <div className="App">
      {/* Notifications */}
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
        <h1>Exoware Simulator</h1>
        <p>Modern interface for store and stream operations</p>
        <div className={`status-indicator ${isConnected ? 'status-connected' : 'status-disconnected'}`}>
          <span>●</span>
          {isConnected ? 'Connected' : 'Disconnected'}
        </div>
      </div>

      <div className="card fade-in">
        <h2>Store Operations</h2>

        <div className="form-section">
          <h3>Set Key-Value Pair</h3>
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
          <h3>Get Value by Key</h3>
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
        </div>

        <div className="form-section">
          <h3>Query Key Range</h3>
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
                  {queryResult.results.map((item: QueryResultItem) => (
                    <li key={item.key}>
                      <strong>{item.key}:</strong> {renderValue(item.value)}
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
        <h2>Stream Operations</h2>

        <div className="form-section">
          <h3>Publish Message</h3>
          <div className="form-row">
            <div className="form-group">
              <label htmlFor="stream-name">Stream Name</label>
              <input
                id="stream-name"
                type="text"
                placeholder="Enter stream name"
                value={streamName}
                onChange={(e) => setStreamName(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label htmlFor="stream-data">Message Data</label>
              <input
                id="stream-data"
                type="text"
                placeholder="Enter message content"
                value={streamPublishData}
                onChange={(e) => setStreamPublishData(e.target.value)}
              />
            </div>
          </div>
          <button
            className={`btn-primary ${isPublishing ? 'loading' : ''}`}
            onClick={handlePublish}
            disabled={isPublishing || !streamName}
          >
            {isPublishing ? 'Publishing...' : 'Publish Message'}
          </button>
        </div>

        <div className="form-section">
          <h3>Subscribe to Stream</h3>
          <div className="form-row">
            <div className="form-group">
              <label htmlFor="subscribe-stream">Stream Name</label>
              <input
                id="subscribe-stream"
                type="text"
                placeholder="Enter stream name to subscribe"
                value={streamSubscribeName}
                onChange={(e) => setStreamSubscribeName(e.target.value)}
              />
            </div>
          </div>
          <div className="form-row">
            {subscription ? (
              <button
                className="btn-danger"
                onClick={handleUnsubscribe}
              >
                Unsubscribe
              </button>
            ) : (
              <button
                className={`btn-primary ${isSubscribing ? 'loading' : ''}`}
                onClick={handleSubscribe}
                disabled={isSubscribing || !streamSubscribeName}
              >
                {isSubscribing ? 'Subscribing...' : 'Subscribe'}
              </button>
            )}
          </div>

          <div className="result">
            <h4>Live Messages ({streamMessages.length})</h4>
            {streamMessages.length > 0 ? (
              <ul>
                {streamMessages.slice(-10).map((msg, i) => (
                  <li key={i}>
                    <strong>#{streamMessages.length - 10 + i + 1}:</strong> {msg instanceof Blob ? 'Blob' : renderValue(msg as Uint8Array)}
                  </li>
                ))}
              </ul>
            ) : (
              <p>{subscription ? 'Waiting for messages...' : 'Not subscribed to any stream'}</p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default App
