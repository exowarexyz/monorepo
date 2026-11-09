import { useState } from 'react';
import {
  type GetResult,
  type RangeResult,
  type RangeResultItem,
  type PrefixedStoreClient,
} from '@exowarexyz/sdk';
import { isNetworkError } from './clientErrors';
import { formatBytesValue, formatKeyPreview } from './format';

interface NotificationFn {
  (type: 'success' | 'error', title: string, message: string): void;
}

export function StorePanel({
  store,
  showNotification,
  onConnectionLost,
}: {
  store: PrefixedStoreClient | null;
  showNotification: NotificationFn;
  onConnectionLost: () => void;
}) {
  const [storeKey, setStoreKey] = useState('');
  const [storeValue, setStoreValue] = useState('');
  const [storeGetKey, setStoreGetKey] = useState('');
  const [storeGetValue, setStoreGetValue] = useState<GetResult | null>(null);
  const [keyNotFound, setKeyNotFound] = useState(false);
  const [rangeStart, setRangeStart] = useState('');
  const [rangeEnd, setRangeEnd] = useState('');
  const [rangeLimit, setRangeLimit] = useState('10');
  const [rangeResult, setRangeResult] = useState<RangeResult | null>(null);
  const [isPuttingValue, setIsPuttingValue] = useState(false);
  const [isGettingValue, setIsGettingValue] = useState(false);
  const [isRanging, setIsRanging] = useState(false);

  const enc = new TextEncoder();

  const handlePut = async () => {
    if (!store || !storeKey) {
      return;
    }

    setIsPuttingValue(true);
    try {
      const sequenceNumber = await store.put(enc.encode(storeKey), enc.encode(storeValue));
      showNotification('success', 'Store Write', `Key "${storeKey}" put at sequence ${sequenceNumber}`);
      setStoreKey('');
      setStoreValue('');
    } catch (error) {
      showNotification('error', 'Store Write Failed', `Failed to put value: ${error}`);
      if (isNetworkError(error)) {
        onConnectionLost();
      }
    } finally {
      setIsPuttingValue(false);
    }
  };

  const handleGet = async () => {
    if (!store || !storeGetKey) {
      return;
    }

    setIsGettingValue(true);
    setStoreGetValue(null);
    setKeyNotFound(false);
    try {
      const result = await store.get(enc.encode(storeGetKey));
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

  const handleRange = async () => {
    if (!store) {
      return;
    }

    setIsRanging(true);
    try {
      const result = await store.range(
        rangeStart ? enc.encode(rangeStart) : undefined,
        rangeEnd ? enc.encode(rangeEnd) : undefined,
        rangeLimit ? Number.parseInt(rangeLimit, 10) : undefined,
      );
      setRangeResult(result);
      showNotification('success', 'Store Range', `Range returned ${result.results.length} results`);
    } catch (error) {
      showNotification('error', 'Store Range Failed', `Range failed: ${error}`);
      if (isNetworkError(error)) {
        onConnectionLost();
      }
    } finally {
      setIsRanging(false);
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
        <h3>Put Value</h3>
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
          className={`btn-primary ${isPuttingValue ? 'loading' : ''}`}
          onClick={handlePut}
          disabled={!store || isPuttingValue || !storeKey}
        >
          {isPuttingValue ? 'Putting...' : 'Put Value'}
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
          disabled={!store || isGettingValue || !storeGetKey}
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
        <h3>Range</h3>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="range-start">Start Key (optional)</label>
            <input
              id="range-start"
              type="text"
              placeholder="Start key"
              value={rangeStart}
              onChange={(event) => setRangeStart(event.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="range-end">End Key (optional)</label>
            <input
              id="range-end"
              type="text"
              placeholder="End key"
              value={rangeEnd}
              onChange={(event) => setRangeEnd(event.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="range-limit">Limit</label>
            <input
              id="range-limit"
              type="number"
              placeholder="10"
              value={rangeLimit}
              onChange={(event) => setRangeLimit(event.target.value)}
            />
          </div>
        </div>
        <button
          className={`btn-primary ${isRanging ? 'loading' : ''}`}
          onClick={handleRange}
          disabled={!store || isRanging}
        >
          {isRanging ? 'Reading...' : 'Range'}
        </button>
        {rangeResult && (
          <div className="result fade-in">
            <h4>Range Results ({rangeResult.results.length} items)</h4>
            {rangeResult.results.length > 0 ? (
              <ul>
                {rangeResult.results.map((item: RangeResultItem, index: number) => (
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
