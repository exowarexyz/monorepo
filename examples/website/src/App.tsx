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

function App() {
  const [, setClient] = useState<Client | null>(null);
  const [storeClient, setStoreClient] = useState<StoreClient | null>(null);
  const [streamClient, setStreamClient] = useState<StreamClient | null>(null);

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

  useEffect(() => {
    const c = new Client(SIMULATOR_URL, AUTH_TOKEN);
    setClient(c);
    setStoreClient(c.store());
    setStreamClient(c.stream());
  }, []);

  const handleSet = async () => {
    if (storeClient && storeKey) {
      try {
        await storeClient.set(storeKey, Buffer.from(storeValue));
        alert('Value set successfully');
      } catch (e) {
        alert(`Error setting value: ${e}`);
      }
    }
  };

  const handleGet = async () => {
    if (storeClient && storeGetKey) {
      try {
        const result = await storeClient.get(storeGetKey);
        setStoreGetValue(result);
      } catch (e) {
        alert(`Error getting value: ${e}`);
      }
    }
  };

  const handleQuery = async () => {
    if (storeClient) {
      try {
        const result = await storeClient.query(
          queryStart || undefined,
          queryEnd || undefined,
          queryLimit ? parseInt(queryLimit, 10) : undefined
        );
        setQueryResult(result);
      } catch (e) {
        alert(`Error querying: ${e}`);
      }
    }
  };

  const handlePublish = async () => {
    if (streamClient && streamName) {
      try {
        await streamClient.publish(streamName, Buffer.from(streamPublishData));
        alert('Message published');
      } catch (e) {
        alert(`Error publishing message: ${e}`);
      }
    }
  };

  const handleSubscribe = async () => {
    if (streamClient && streamSubscribeName && !subscription) {
      try {
        const sub = await streamClient.subscribe(streamSubscribeName);
        setSubscription(sub);
        setStreamMessages([]);

        sub.onMessage((data: unknown) => {
          setStreamMessages((prev) => [...prev, data]);
        });
        sub.onClose((ev: any) => {
          console.log('Subscription closed', ev);
          setSubscription(null);
        });
        sub.onError((err: any) => {
          console.error('Subscription error', err);
        });

      } catch (e) {
        alert(`Error subscribing: ${e}`);
      }
    }
  };

  const handleUnsubscribe = () => {
    if (subscription) {
      subscription.close();
      setSubscription(null);
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
      <h1>Exoware Simulator UI</h1>

      <div className="card">
        <h2>Store</h2>
        <div className="form-section">
          <h3>Set Value</h3>
          <input type="text" placeholder="Key" value={storeKey} onChange={(e) => setStoreKey(e.target.value)} />
          <input type="text" placeholder="Value" value={storeValue} onChange={(e) => setStoreValue(e.target.value)} />
          <button onClick={handleSet}>Set</button>
        </div>

        <div className="form-section">
          <h3>Get Value</h3>
          <input type="text" placeholder="Key" value={storeGetKey} onChange={(e) => setStoreGetKey(e.target.value)} />
          <button onClick={handleGet}>Get</button>
          {storeGetValue && (
            <div className="result">
              <p><strong>Value:</strong> {renderValue(storeGetValue.value)}</p>
            </div>
          )}
        </div>

        <div className="form-section">
          <h3>Query</h3>
          <input type="text" placeholder="Start Key" value={queryStart} onChange={(e) => setQueryStart(e.target.value)} />
          <input type="text" placeholder="End Key" value={queryEnd} onChange={(e) => setQueryEnd(e.target.value)} />
          <input type="number" placeholder="Limit" value={queryLimit} onChange={(e) => setQueryLimit(e.target.value)} />
          <button onClick={handleQuery}>Query</button>
          {queryResult && (
            <div className="result">
              <h4>Results:</h4>
              <ul>
                {queryResult.results.map((item: QueryResultItem) => (
                  <li key={item.key}><strong>{item.key}:</strong> {renderValue(item.value)}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <h2>Stream</h2>
        <div className="form-section">
          <h3>Publish Message</h3>
          <input type="text" placeholder="Stream Name" value={streamName} onChange={(e) => setStreamName(e.target.value)} />
          <input type="text" placeholder="Data" value={streamPublishData} onChange={(e) => setStreamPublishData(e.target.value)} />
          <button onClick={handlePublish}>Publish</button>
        </div>

        <div className="form-section">
          <h3>Subscribe to Stream</h3>
          <input type="text" placeholder="Stream Name" value={streamSubscribeName} onChange={(e) => setStreamSubscribeName(e.target.value)} />
          {subscription ? (
            <button onClick={handleUnsubscribe}>Unsubscribe</button>
          ) : (
            <button onClick={handleSubscribe}>Subscribe</button>
          )}
          <div className="result">
            <h4>Messages:</h4>
            <ul>
              {streamMessages.map((msg, i) => (
                <li key={i}>{msg instanceof Blob ? 'Blob' : renderValue(msg as Uint8Array)}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}

export default App
