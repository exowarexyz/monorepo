import { useState } from 'react';
import {
  type GetResult,
  type QueryResult,
  type QueryResultItem,
  type StoreClient,
} from '@exowarexyz/sdk';
import { isNetworkError } from './clientErrors';
import { formatBytesValue, formatKeyPreview } from './format';

interface NotificationFn {
  (type: 'success' | 'error', title: string, message: string): void;
}

export function StorePanel({
  client,
  showNotification,
  onConnectionLost,
}: {
  client: StoreClient | null;
  showNotification: NotificationFn;
  onConnectionLost: () => void;
}) {
  const [storeKey, setStoreKey] = useState('');
  const [storeValue, setStoreValue] = useState('');
  const [storeGetKey, setStoreGetKey] = useState('');
  const [storeGetValue, setStoreGetValue] = useState<GetResult | null>(null);
  const [keyNotFound, setKeyNotFound] = useState(false);
  const [queryStart, setQueryStart] = useState('');
  const [queryEnd, setQueryEnd] = useState('');
  const [queryLimit, setQueryLimit] = useState('10');
  const [queryResult, setQueryResult] = useState<QueryResult | null>(null);
  const [isSettingValue, setIsSettingValue] = useState(false);
  const [isGettingValue, setIsGettingValue] = useState(false);
  const [isQuerying, setIsQuerying] = useState(false);

  const enc = new TextEncoder();

  const handleSet = async () => {
    if (!client || !storeKey) {
      return;
    }

    setIsSettingValue(true);
    try {
      const sequenceNumber = await client.set(enc.encode(storeKey), enc.encode(storeValue));
      showNotification('success', 'Store Write', `Key "${storeKey}" set at sequence ${sequenceNumber}`);
      setStoreKey('');
      setStoreValue('');
    } catch (error) {
      showNotification('error', 'Store Write Failed', `Failed to set value: ${error}`);
      if (isNetworkError(error)) {
        onConnectionLost();
      }
    } finally {
      setIsSettingValue(false);
    }
  };

  const handleGet = async () => {
    if (!client || !storeGetKey) {
      return;
    }

    setIsGettingValue(true);
    setStoreGetValue(null);
    setKeyNotFound(false);
    try {
      const result = await client.get(enc.encode(storeGetKey));
      setStoreGetValue(result);
      setKeyNotFound(result === null);
      showNotification('success', 'Store Read', `Read key "${storeGetKey}"`);
    } catch (error) {
      showNotification('error', 'Store Read Failed', `Failed to get value: ${error}`);
      setStoreGetValue(null);
      setKeyNotFound(false);
      if (isNetworkError(error)) {
        onConnectionLost();
      }
    } finally {
      setIsGettingValue(false);
    }
  };

  const handleQuery = async () => {
    if (!client) {
      return;
    }

    setIsQuerying(true);
    try {
      const result = await client.query(
        queryStart ? enc.encode(queryStart) : undefined,
        queryEnd ? enc.encode(queryEnd) : undefined,
        queryLimit ? Number.parseInt(queryLimit, 10) : undefined,
      );
      setQueryResult(result);
      showNotification('success', 'Store Range', `Query returned ${result.results.length} results`);
    } catch (error) {
      showNotification('error', 'Store Range Failed', `Query failed: ${error}`);
      if (isNetworkError(error)) {
        onConnectionLost();
      }
    } finally {
      setIsQuerying(false);
    }
  };

  const handleGetKeyChange = (value: string) => {
    setStoreGetKey(value);
    if (storeGetValue || keyNotFound) {
      setStoreGetValue(null);
      setKeyNotFound(false);
    }
  };

  return (
    <div className="card fade-in">
      <h2>Store</h2>

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
              onChange={(event) => setStoreKey(event.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="store-value">Value</label>
            <input
              id="store-value"
              type="text"
              placeholder="Enter value"
              value={storeValue}
              onChange={(event) => setStoreValue(event.target.value)}
            />
          </div>
        </div>
        <button
          className={`btn-primary ${isSettingValue ? 'loading' : ''}`}
          onClick={handleSet}
          disabled={!client || isSettingValue || !storeKey}
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
              onChange={(event) => handleGetKeyChange(event.target.value)}
            />
          </div>
        </div>
        <button
          className={`btn-primary ${isGettingValue ? 'loading' : ''}`}
          onClick={handleGet}
          disabled={!client || isGettingValue || !storeGetKey}
        >
          {isGettingValue ? 'Getting...' : 'Get Value'}
        </button>
        {storeGetValue && (
          <div className="result fade-in">
            <h4>Retrieved Value</h4>
            <p><strong>Key:</strong> {storeGetKey}</p>
            <p><strong>Value:</strong> {formatBytesValue(storeGetValue.value)}</p>
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
              onChange={(event) => setQueryStart(event.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="query-end">End Key (optional)</label>
            <input
              id="query-end"
              type="text"
              placeholder="End key"
              value={queryEnd}
              onChange={(event) => setQueryEnd(event.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="query-limit">Limit</label>
            <input
              id="query-limit"
              type="number"
              placeholder="10"
              value={queryLimit}
              onChange={(event) => setQueryLimit(event.target.value)}
            />
          </div>
        </div>
        <button
          className={`btn-primary ${isQuerying ? 'loading' : ''}`}
          onClick={handleQuery}
          disabled={!client || isQuerying}
        >
          {isQuerying ? 'Querying...' : 'Query Range'}
        </button>
        {queryResult && (
          <div className="result fade-in">
            <h4>Query Results ({queryResult.results.length} items)</h4>
            {queryResult.results.length > 0 ? (
              <ul>
                {queryResult.results.map((item: QueryResultItem, index: number) => (
                  <li key={`${index}-${item.key.byteLength}`}>
                    <strong>{formatKeyPreview(item.key)}:</strong> {formatBytesValue(item.value)}
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
  );
}
