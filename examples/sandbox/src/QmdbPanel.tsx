import { useEffect, useMemo, useRef, useState } from 'react';
import {
  matchExact,
  matchPrefix,
  matchRegex,
  OrderedQmdbClient,
  type OrderedSubscribeProof,
  type VerifiedCurrentKeyValueProof,
  type VerifiedHistoricalMultiProof,
} from '@qmdb-ts';

const QMDB_URL = import.meta.env.VITE_QMDB_URL ?? 'http://127.0.0.1:8081';
const DEFAULT_CURRENT_ROOT = import.meta.env.VITE_QMDB_CURRENT_ROOT ?? '';
const DEFAULT_HISTORICAL_ROOT = import.meta.env.VITE_QMDB_HISTORICAL_ROOT ?? '';
const MAX_EVENTS = 10;

interface NotificationFn {
  (type: 'success' | 'error', title: string, message: string): void;
}

function decodeUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch {
    return '';
  }
}

function formatBytes(bytes: Uint8Array): string {
  const text = decodeUtf8(bytes);
  // eslint-disable-next-line no-control-regex
  if (text && /^[\x20-\x7E]*$/.test(text)) {
    return text;
  }
  return `0x${Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`;
}

function parseHexBytes(value: string): Uint8Array {
  const normalized = value.trim().replace(/^0x/i, '');
  if (!normalized) {
    throw new Error('Root is required');
  }
  if (normalized.length % 2 !== 0) {
    throw new Error('Hex roots must have an even number of characters');
  }
  if (!/^[0-9a-fA-F]+$/.test(normalized)) {
    throw new Error('Root must be hex');
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < normalized.length; index += 2) {
    bytes[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }
  return bytes;
}

function renderOperation(proofOperation: OrderedSubscribeProof['proof']['operations'][number]['operation']) {
  switch (proofOperation.type) {
    case 'update':
      return (
        <>
          <p><strong>Type:</strong> update</p>
          <p><strong>Key:</strong> {formatBytes(proofOperation.key)}</p>
          <p><strong>Value:</strong> {formatBytes(proofOperation.value)}</p>
          <p><strong>Next Key:</strong> {formatBytes(proofOperation.nextKey)}</p>
        </>
      );
    case 'delete':
      return (
        <>
          <p><strong>Type:</strong> delete</p>
          <p><strong>Key:</strong> {formatBytes(proofOperation.key)}</p>
        </>
      );
    case 'commit_floor':
      return (
        <>
          <p><strong>Type:</strong> commit_floor</p>
          {proofOperation.value && (
            <p><strong>Value:</strong> {formatBytes(proofOperation.value)}</p>
          )}
          <p><strong>Floor Location:</strong> {proofOperation.floorLocation.toString()}</p>
        </>
      );
  }
}

export function QmdbPanel({ showNotification }: { showNotification: NotificationFn }) {
  const client = useMemo(() => new OrderedQmdbClient(QMDB_URL), []);
  const subscribeAbortRef = useRef<AbortController | null>(null);

  const [isConnected, setIsConnected] = useState(false);
  const [currentRoot, setCurrentRoot] = useState(DEFAULT_CURRENT_ROOT);
  const [historicalRoot, setHistoricalRoot] = useState(DEFAULT_HISTORICAL_ROOT);

  const [getKey, setGetKey] = useState('alpha');
  const [getProof, setGetProof] = useState<VerifiedCurrentKeyValueProof | null>(null);
  const [isGetting, setIsGetting] = useState(false);

  const [manyKeys, setManyKeys] = useState('alpha,beta');
  const [manyProof, setManyProof] = useState<VerifiedHistoricalMultiProof | null>(null);
  const [isGettingMany, setIsGettingMany] = useState(false);

  const [matcherKind, setMatcherKind] = useState<'exact' | 'prefix' | 'regex'>('prefix');
  const [matcherValue, setMatcherValue] = useState('a');
  const [sinceSequenceNumber, setSinceSequenceNumber] = useState('');
  const [events, setEvents] = useState<OrderedSubscribeProof[]>([]);
  const [isSubscribing, setIsSubscribing] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const response = await fetch(`${QMDB_URL.replace(/\/$/, '')}/health`, {
          signal: controller.signal,
        });
        setIsConnected(response.ok);
      } catch {
        setIsConnected(false);
      }
    })();

    return () => {
      controller.abort();
      subscribeAbortRef.current?.abort();
    };
  }, []);

  const handleGet = async () => {
    setIsGetting(true);
    setGetProof(null);
    try {
      const proof = await client.get(getKey, parseHexBytes(currentRoot));
      setGetProof(proof);
      showNotification('success', 'QMDB Get', `Verified proof for "${getKey}"`);
    } catch (error) {
      showNotification('error', 'QMDB Get Failed', String(error));
    } finally {
      setIsGetting(false);
    }
  };

  const handleGetMany = async () => {
    setIsGettingMany(true);
    setManyProof(null);
    try {
      const keys = manyKeys
        .split(',')
        .map((key) => key.trim())
        .filter(Boolean);
      if (keys.length === 0) {
        throw new Error('At least one key is required');
      }
      const proof = await client.getMany(keys, parseHexBytes(historicalRoot));
      setManyProof(proof);
      showNotification('success', 'QMDB GetMany', `Verified ${proof.operations.length} operations`);
    } catch (error) {
      showNotification('error', 'QMDB GetMany Failed', String(error));
    } finally {
      setIsGettingMany(false);
    }
  };

  const handleStartSubscribe = () => {
    subscribeAbortRef.current?.abort();
    setEvents([]);
    setIsSubscribing(true);

    const controller = new AbortController();
    subscribeAbortRef.current = controller;

    let matcher;
    if (matcherKind === 'exact') {
      matcher = matchExact(matcherValue);
    } else if (matcherKind === 'prefix') {
      matcher = matchPrefix(matcherValue);
    } else {
      matcher = matchRegex(matcherValue);
    }

    void (async () => {
      try {
        const since = sinceSequenceNumber.trim() ? BigInt(sinceSequenceNumber.trim()) : undefined;
        for await (const proof of client.subscribe([matcher], since, {
          signal: controller.signal,
        })) {
          setEvents((previous) => [proof, ...previous].slice(0, MAX_EVENTS));
        }
      } catch (error) {
        if (!controller.signal.aborted) {
          showNotification('error', 'QMDB Subscribe Failed', String(error));
        }
      } finally {
        if (subscribeAbortRef.current === controller) {
          subscribeAbortRef.current = null;
        }
        setIsSubscribing(false);
      }
    })();

    showNotification('success', 'QMDB Subscribe', 'Listening for verified multi-proofs');
  };

  const handleStopSubscribe = () => {
    subscribeAbortRef.current?.abort();
    subscribeAbortRef.current = null;
    setIsSubscribing(false);
  };

  return (
    <div className="card fade-in">
      <h2>Ordered QMDB</h2>

      <div className="form-section">
        <h3>Connection</h3>
        <p className="section-note">
          Proof reads are root-driven. Start the local server with the `qmdb run` binary and
          seed demo data with `qmdb seed-demo` to get roots to paste here.
        </p>
        <p><strong>Server:</strong> {QMDB_URL}</p>
        <p><strong>Status:</strong> {isConnected ? 'Connected' : 'Disconnected'}</p>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="qmdb-current-root">Current Root (hex)</label>
            <input
              id="qmdb-current-root"
              type="text"
              placeholder="0x..."
              value={currentRoot}
              onChange={(event) => setCurrentRoot(event.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="qmdb-historical-root">Historical Root (hex)</label>
            <input
              id="qmdb-historical-root"
              type="text"
              placeholder="0x..."
              value={historicalRoot}
              onChange={(event) => setHistoricalRoot(event.target.value)}
            />
          </div>
        </div>
      </div>

      <div className="form-section">
        <h3>Get Current Proof</h3>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="qmdb-get-key">Key</label>
            <input
              id="qmdb-get-key"
              type="text"
              value={getKey}
              onChange={(event) => setGetKey(event.target.value)}
            />
          </div>
        </div>
        <button
          className={`btn-primary ${isGetting ? 'loading' : ''}`}
          onClick={handleGet}
          disabled={isGetting || !getKey.trim() || !currentRoot.trim()}
        >
          {isGetting ? 'Verifying...' : 'Get Proof'}
        </button>
        {getProof && (
          <div className="result fade-in">
            <h4>Verified Current Proof</h4>
            <p><strong>Location:</strong> {getProof.location.toString()}</p>
            <p><strong>Root:</strong> {formatBytes(getProof.root)}</p>
            {renderOperation(getProof.operation)}
          </div>
        )}
      </div>

      <div className="form-section">
        <h3>Get Historical Multi-Proof</h3>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="qmdb-many-keys">Keys (comma-separated)</label>
            <input
              id="qmdb-many-keys"
              type="text"
              value={manyKeys}
              onChange={(event) => setManyKeys(event.target.value)}
            />
          </div>
        </div>
        <button
          className={`btn-primary ${isGettingMany ? 'loading' : ''}`}
          onClick={handleGetMany}
          disabled={isGettingMany || !manyKeys.trim() || !historicalRoot.trim()}
        >
          {isGettingMany ? 'Verifying...' : 'Get Multi-Proof'}
        </button>
        {manyProof && (
          <div className="result fade-in">
            <h4>Verified Historical Multi-Proof</h4>
            <p><strong>Root:</strong> {formatBytes(manyProof.root)}</p>
            <div className="result-list">
              {manyProof.operations.map((operation, index) => (
                <div key={`${operation.location.toString()}-${index}`} className="result-row-block">
                  <p><strong>Location:</strong> {operation.location.toString()}</p>
                  {renderOperation(operation.operation)}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="form-section">
        <h3>Subscribe</h3>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="qmdb-matcher-kind">Matcher</label>
            <select
              id="qmdb-matcher-kind"
              value={matcherKind}
              onChange={(event) => setMatcherKind(event.target.value as 'exact' | 'prefix' | 'regex')}
            >
              <option value="exact">exact</option>
              <option value="prefix">prefix</option>
              <option value="regex">regex</option>
            </select>
          </div>
          <div className="form-group form-group-wide">
            <label htmlFor="qmdb-matcher-value">Value</label>
            <input
              id="qmdb-matcher-value"
              type="text"
              value={matcherValue}
              onChange={(event) => setMatcherValue(event.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="qmdb-since-sequence">Since Sequence (optional)</label>
            <input
              id="qmdb-since-sequence"
              type="number"
              min="0"
              value={sinceSequenceNumber}
              onChange={(event) => setSinceSequenceNumber(event.target.value)}
            />
          </div>
        </div>
        <div className="button-row">
          <button
            className={`btn-primary ${isSubscribing ? 'loading' : ''}`}
            onClick={handleStartSubscribe}
            disabled={isSubscribing || !matcherValue.trim()}
          >
            {isSubscribing ? 'Listening...' : 'Start Subscribe'}
          </button>
          <button
            className="btn-secondary"
            onClick={handleStopSubscribe}
            disabled={!isSubscribing}
          >
            Stop
          </button>
        </div>
        <div className="result fade-in">
          <h4>Verified Events ({events.length})</h4>
          {events.length === 0 ? (
            <p>No proof events yet</p>
          ) : (
            <div className="result-list">
              {events.map((event, index) => (
                <div
                  key={`${event.resumeSequenceNumber.toString()}-${index}`}
                  className="result-row-block"
                >
                  <p><strong>Resume Sequence:</strong> {event.resumeSequenceNumber.toString()}</p>
                  <p><strong>Operations:</strong> {event.proof.operations.length}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
