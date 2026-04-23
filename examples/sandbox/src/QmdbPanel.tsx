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

export const QMDB_URL = import.meta.env.VITE_QMDB_URL as string | undefined;
const MAX_EVENTS = 10;

function parseHexRoot(value: string): Uint8Array {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error('Expected Root is required');
  }
  const body = trimmed.startsWith('0x') || trimmed.startsWith('0X') ? trimmed.slice(2) : trimmed;
  if (body.length === 0 || body.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(body)) {
    throw new Error('Expected Root must be a hex string (optionally 0x-prefixed)');
  }
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(body.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

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
  if (text && /^[\x20-\x7E]*$/.test(text)) {
    return text;
  }
  return `0x${Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`;
}

function parseTip(value: string): bigint {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error('Tip is required');
  }
  const tip = BigInt(trimmed);
  if (tip < 0n) {
    throw new Error('Tip must be non-negative');
  }
  return tip;
}

function renderOperation(
  proofOperation: OrderedSubscribeProof['proof']['operations'][number]['operation'],
) {
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

export function QmdbPanel({
  qmdbUrl,
  showNotification,
}: {
  qmdbUrl: string;
  showNotification: NotificationFn;
}) {
  const client = useMemo(() => new OrderedQmdbClient(qmdbUrl), [qmdbUrl]);
  const subscribeAbortRef = useRef<AbortController | null>(null);

  const [isConnected, setIsConnected] = useState(false);
  const [tip, setTip] = useState('');
  const [expectedCurrentRoot, setExpectedCurrentRoot] = useState('');
  const [expectedHistoricalRoot, setExpectedHistoricalRoot] = useState('');

  const [getKey, setGetKey] = useState('k-00000000');
  const [getProof, setGetProof] = useState<VerifiedCurrentKeyValueProof | null>(null);
  const [isGetting, setIsGetting] = useState(false);

  const [manyKeys, setManyKeys] = useState('k-00000000,k-00000001');
  const [manyProof, setManyProof] = useState<VerifiedHistoricalMultiProof | null>(null);
  const [isGettingMany, setIsGettingMany] = useState(false);

  const [keyMatcherKind, setKeyMatcherKind] = useState<'exact' | 'prefix' | 'regex' | 'none'>(
    'prefix',
  );
  const [keyMatcherValue, setKeyMatcherValue] = useState('k-');
  const [valueMatcherKind, setValueMatcherKind] = useState<'exact' | 'prefix' | 'regex' | 'none'>(
    'none',
  );
  const [valueMatcherValue, setValueMatcherValue] = useState('');
  const [sinceSequenceNumber, setSinceSequenceNumber] = useState('');
  const [events, setEvents] = useState<OrderedSubscribeProof[]>([]);
  const [isSubscribing, setIsSubscribing] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const response = await fetch(`${qmdbUrl.replace(/\/$/, '')}/health`, {
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
      const proof = await client.get(
        getKey,
        parseTip(tip),
        parseHexRoot(expectedCurrentRoot),
      );
      setGetProof(proof);
      showNotification('success', 'QMDB Get', `Verified proof for "${getKey}" against expected root`);
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
      const proof = await client.getMany(
        keys,
        parseTip(tip),
        parseHexRoot(expectedHistoricalRoot),
      );
      setManyProof(proof);
      showNotification(
        'success',
        'QMDB GetMany',
        `Verified ${proof.operations.length} operations against expected root`,
      );
    } catch (error) {
      showNotification('error', 'QMDB GetMany Failed', String(error));
    } finally {
      setIsGettingMany(false);
    }
  };

  function buildFilter(
    kind: 'exact' | 'prefix' | 'regex' | 'none',
    value: string,
  ): ReturnType<typeof matchExact> | undefined {
    if (kind === 'none') return undefined;
    if (!value.trim()) return undefined;
    if (kind === 'exact') return matchExact(value);
    if (kind === 'prefix') return matchPrefix(value);
    return matchRegex(value);
  }

  const handleStartSubscribe = () => {
    subscribeAbortRef.current?.abort();
    setEvents([]);
    setIsSubscribing(true);

    const controller = new AbortController();
    subscribeAbortRef.current = controller;

    const keyFilter = buildFilter(keyMatcherKind, keyMatcherValue);
    const valueFilter = buildFilter(valueMatcherKind, valueMatcherValue);

    void (async () => {
      try {
        const since = sinceSequenceNumber.trim() ? BigInt(sinceSequenceNumber.trim()) : undefined;
        for await (const proof of client.subscribe(
          {
            keyFilters: keyFilter ? [keyFilter] : [],
            valueFilters: valueFilter ? [valueFilter] : [],
            sinceSequenceNumber: since,
          },
          { signal: controller.signal },
        )) {
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
          Proofs are anchored to roots the writer emits per batch. Run `qmdb run`
          locally and `qmdb seed` to stream fresh tips; each line prints
          `tip=N current_root=0x.. historical_root=0x..`. Get Proof verifies
          against the current root; Get Multi-Proof verifies against the
          historical root.
        </p>
        <p><strong>Server:</strong> {qmdbUrl}</p>
        <p><strong>Status:</strong> {isConnected ? 'Connected' : 'Disconnected'}</p>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="qmdb-tip">Tip (location)</label>
            <input
              id="qmdb-tip"
              type="number"
              min="0"
              placeholder="e.g. 14"
              value={tip}
              onChange={(event) => setTip(event.target.value)}
            />
          </div>
          <div className="form-group form-group-wide">
            <label htmlFor="qmdb-current-root">Expected Current Root (hex)</label>
            <input
              id="qmdb-current-root"
              type="text"
              placeholder="0x..."
              value={expectedCurrentRoot}
              onChange={(event) => setExpectedCurrentRoot(event.target.value)}
            />
          </div>
          <div className="form-group form-group-wide">
            <label htmlFor="qmdb-historical-root">Expected Historical Root (hex)</label>
            <input
              id="qmdb-historical-root"
              type="text"
              placeholder="0x..."
              value={expectedHistoricalRoot}
              onChange={(event) => setExpectedHistoricalRoot(event.target.value)}
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
          disabled={
            isGetting || !getKey.trim() || !tip.trim() || !expectedCurrentRoot.trim()
          }
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
          disabled={
            isGettingMany || !manyKeys.trim() || !tip.trim() || !expectedHistoricalRoot.trim()
          }
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
        <p className="section-note">
          Key and value filters are AND'd: a proof is emitted only when an op satisfies every
          non-empty filter. Pick "none" to leave a side unfiltered.
        </p>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="qmdb-key-kind">Key Matcher</label>
            <select
              id="qmdb-key-kind"
              value={keyMatcherKind}
              onChange={(event) =>
                setKeyMatcherKind(event.target.value as 'exact' | 'prefix' | 'regex' | 'none')
              }
            >
              <option value="none">none</option>
              <option value="exact">exact</option>
              <option value="prefix">prefix</option>
              <option value="regex">regex</option>
            </select>
          </div>
          <div className="form-group form-group-wide">
            <label htmlFor="qmdb-key-value">Key Value</label>
            <input
              id="qmdb-key-value"
              type="text"
              value={keyMatcherValue}
              onChange={(event) => setKeyMatcherValue(event.target.value)}
              disabled={keyMatcherKind === 'none'}
            />
          </div>
        </div>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="qmdb-value-kind">Value Matcher</label>
            <select
              id="qmdb-value-kind"
              value={valueMatcherKind}
              onChange={(event) =>
                setValueMatcherKind(event.target.value as 'exact' | 'prefix' | 'regex' | 'none')
              }
            >
              <option value="none">none</option>
              <option value="exact">exact</option>
              <option value="prefix">prefix</option>
              <option value="regex">regex</option>
            </select>
          </div>
          <div className="form-group form-group-wide">
            <label htmlFor="qmdb-value-value">Value Value</label>
            <input
              id="qmdb-value-value"
              type="text"
              value={valueMatcherValue}
              onChange={(event) => setValueMatcherValue(event.target.value)}
              disabled={valueMatcherKind === 'none'}
            />
          </div>
        </div>
        <div className="form-row">
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
            disabled={isSubscribing}
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
              {events.map((event, index) => {
                const ops = event.proof.operations;
                let locationRange = '(none)';
                if (ops.length > 0) {
                  let minLoc = ops[0].location;
                  let maxLoc = ops[0].location;
                  for (const op of ops) {
                    if (op.location < minLoc) minLoc = op.location;
                    if (op.location > maxLoc) maxLoc = op.location;
                  }
                  locationRange =
                    minLoc === maxLoc
                      ? minLoc.toString()
                      : `${minLoc.toString()}-${maxLoc.toString()}`;
                }
                return (
                  <div
                    key={`${event.resumeSequenceNumber.toString()}-${index}`}
                    className="result-row-block"
                  >
                    <p>
                      <strong>Resume Sequence:</strong> {event.resumeSequenceNumber.toString()}
                      {' · '}
                      <strong>Matched:</strong> {ops.length}
                      {' · '}
                      <strong>Locations:</strong> {locationRange}
                    </p>
                    <p><strong>Historical Root:</strong> {formatBytes(event.proof.root)}</p>
                    {ops.length > 0 && (
                      <div className="result-list">
                        {ops.map((op, opIndex) => (
                          <div
                            key={`${event.resumeSequenceNumber.toString()}-${opIndex}-${op.location.toString()}`}
                            className="result-row-block"
                          >
                            <p><strong>Location:</strong> {op.location.toString()}</p>
                            {renderOperation(op.operation)}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
