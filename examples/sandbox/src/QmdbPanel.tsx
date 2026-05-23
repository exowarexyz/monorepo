import { useEffect, useMemo, useRef, useState } from 'react';
import {
  matchExact,
  matchPrefix,
  matchRegex,
  OrderedQmdbClient,
  type OrderedOperation,
  type OrderedSubscribeProof,
  type VerifiedCurrentKeyLookupProof,
  type VerifiedCurrentKeyRangeProof,
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

function formatProofSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KiB`;
}

function parseNonNegativeBigInt(value: string, label: string): bigint {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`${label} is required`);
  }
  const parsed = BigInt(trimmed);
  if (parsed < 0n) {
    throw new Error(`${label} must be non-negative`);
  }
  return parsed;
}

function parseTip(value: string): bigint {
  return parseNonNegativeBigInt(value, 'Tip');
}

function renderOperation(proofOperation: OrderedOperation) {
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
          <p><strong>Type:</strong> commit</p>
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
  const client = useMemo(
    () => new OrderedQmdbClient(qmdbUrl, { merkleFamily: 'mmb' }),
    [qmdbUrl],
  );
  const subscribeAbortRef = useRef<AbortController | null>(null);

  const [isConnected, setIsConnected] = useState(false);
  const [tip, setTip] = useState('');
  const [expectedCurrentRoot, setExpectedCurrentRoot] = useState('');

  const [getKey, setGetKey] = useState('k-00000000');
  const [getProof, setGetProof] = useState<VerifiedCurrentKeyValueProof | null>(null);
  const [isGetting, setIsGetting] = useState(false);

  const [manyKeys, setManyKeys] = useState('k-00000000,k-00000001');
  const [manyProof, setManyProof] = useState<VerifiedCurrentKeyLookupProof | null>(null);
  const [isGettingMany, setIsGettingMany] = useState(false);

  const [rangeStartKey, setRangeStartKey] = useState('k-00000000');
  const [rangeEndKey, setRangeEndKey] = useState('k-00000010');
  const [rangeLimit, setRangeLimit] = useState('5');
  const [rangeProof, setRangeProof] = useState<VerifiedCurrentKeyRangeProof | null>(null);
  const [isGettingRange, setIsGettingRange] = useState(false);

  const [historyStartLocation, setHistoryStartLocation] = useState('0');
  const [historyMaxLocations, setHistoryMaxLocations] = useState('5');
  const [historyProof, setHistoryProof] = useState<VerifiedHistoricalMultiProof | null>(null);
  const [isGettingHistory, setIsGettingHistory] = useState(false);

  const [keyMatcherKind, setKeyMatcherKind] = useState<'exact' | 'prefix' | 'regex' | 'none'>(
    'none',
  );
  const [keyMatcherValue, setKeyMatcherValue] = useState('');
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
  }, [qmdbUrl]);

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
      showNotification(
        'success',
        'QMDB Get',
        `Verified proof for "${getKey}" against expected root (${formatProofSize(proof.proofSizeBytes)})`,
      );
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
        parseHexRoot(expectedCurrentRoot),
      );
      setManyProof(proof);
      showNotification(
        'success',
        'QMDB GetMany',
        `Verified ${proof.results.length} key results against expected root (${formatProofSize(proof.proofSizeBytes)})`,
      );
    } catch (error) {
      showNotification('error', 'QMDB GetMany Failed', String(error));
    } finally {
      setIsGettingMany(false);
    }
  };

  const handleGetRange = async () => {
    setIsGettingRange(true);
    setRangeProof(null);
    try {
      const limit = Number(rangeLimit);
      if (!Number.isInteger(limit) || limit <= 0) {
        throw new Error('Limit must be a positive integer');
      }
      const endKey = rangeEndKey.trim();
      const proof = await client.getRange(
        {
          startKey: rangeStartKey,
          ...(endKey ? { endKey } : {}),
          limit,
          tip: parseTip(tip),
        },
        parseHexRoot(expectedCurrentRoot),
      );
      setRangeProof(proof);
      showNotification(
        'success',
        'QMDB GetRange',
        `Verified ${proof.entries.length} ordered entries against expected root (${formatProofSize(proof.proofSizeBytes)})`,
      );
    } catch (error) {
      showNotification('error', 'QMDB GetRange Failed', String(error));
    } finally {
      setIsGettingRange(false);
    }
  };

  const handleGetOperationRange = async () => {
    setIsGettingHistory(true);
    setHistoryProof(null);
    try {
      const maxLocations = Number(historyMaxLocations);
      if (!Number.isInteger(maxLocations) || maxLocations <= 0) {
        throw new Error('Max Locations must be a positive integer');
      }
      const proof = await client.getOperationRange(
        {
          tip: parseTip(tip),
          startLocation: parseNonNegativeBigInt(historyStartLocation, 'Start Location'),
          maxLocations,
        },
        parseHexRoot(expectedCurrentRoot),
      );
      setHistoryProof(proof);
      showNotification(
        'success',
        'QMDB Historical Range',
        `Verified ${proof.operations.length} historical operations against expected root (${formatProofSize(proof.proofSizeBytes)})`,
      );
    } catch (error) {
      showNotification('error', 'QMDB Historical Range Failed', String(error));
    } finally {
      setIsGettingHistory(false);
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

    showNotification('success', 'QMDB Subscribe', 'Listening for streamed proofs');
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
          `tip=N root=0x..`. Get Proof, Get Many, Get Range, and historical
          operation ranges verify against that current root. Subscribe streams
          each proof with its tip and included operations.
        </p>
        <p><strong>Server:</strong> {qmdbUrl}</p>
        <p><strong>Merkle Family:</strong> MMB</p>
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
            <label htmlFor="qmdb-current-root">Expected Root (hex)</label>
            <input
              id="qmdb-current-root"
              type="text"
              placeholder="0x..."
              value={expectedCurrentRoot}
              onChange={(event) => setExpectedCurrentRoot(event.target.value)}
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
            <p><strong>Proof Size:</strong> {formatProofSize(getProof.proofSizeBytes)}</p>
            <p><strong>Location:</strong> {getProof.location.toString()}</p>
            {renderOperation(getProof.operation)}
          </div>
        )}
      </div>

      <div className="form-section">
        <h3>Get Many Current Proofs</h3>
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
            isGettingMany || !manyKeys.trim() || !tip.trim() || !expectedCurrentRoot.trim()
          }
        >
          {isGettingMany ? 'Verifying...' : 'Get Many'}
        </button>
        {manyProof && (
          <div className="result fade-in">
            <h4>Verified Current Key Results</h4>
            <p><strong>Proof Size:</strong> {formatProofSize(manyProof.proofSizeBytes)}</p>
            <div className="result-list">
              {manyProof.results.map((result, index) => (
                <div key={`${formatBytes(result.key)}-${index}`} className="result-row-block">
                  <p><strong>Key:</strong> {formatBytes(result.key)}</p>
                  <p><strong>Result:</strong> {result.type}</p>
                  {result.type === 'hit' && (
                    <>
                      <p><strong>Location:</strong> {result.location.toString()}</p>
                      {renderOperation(result.operation)}
                    </>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="form-section">
        <h3>Get Ordered Range</h3>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="qmdb-range-start-key">Start Key</label>
            <input
              id="qmdb-range-start-key"
              type="text"
              value={rangeStartKey}
              onChange={(event) => setRangeStartKey(event.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="qmdb-range-end-key">End Key (optional)</label>
            <input
              id="qmdb-range-end-key"
              type="text"
              value={rangeEndKey}
              onChange={(event) => setRangeEndKey(event.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="qmdb-range-limit">Limit</label>
            <input
              id="qmdb-range-limit"
              type="number"
              min="1"
              value={rangeLimit}
              onChange={(event) => setRangeLimit(event.target.value)}
            />
          </div>
        </div>
        <button
          className={`btn-primary ${isGettingRange ? 'loading' : ''}`}
          onClick={handleGetRange}
          disabled={
            isGettingRange ||
            !rangeStartKey.trim() ||
            !rangeLimit.trim() ||
            !tip.trim() ||
            !expectedCurrentRoot.trim()
          }
        >
          {isGettingRange ? 'Verifying...' : 'Get Range'}
        </button>
        {rangeProof && (
          <div className="result fade-in">
            <h4>Verified Ordered Range</h4>
            <p><strong>Proof Size:</strong> {formatProofSize(rangeProof.proofSizeBytes)}</p>
            <p><strong>Has More:</strong> {rangeProof.hasMore ? 'yes' : 'no'}</p>
            {rangeProof.nextStartKey.length > 0 && (
              <p><strong>Next Start Key:</strong> {formatBytes(rangeProof.nextStartKey)}</p>
            )}
            <div className="result-list">
              {rangeProof.entries.map((entry, index) => (
                <div key={`${formatBytes(entry.key)}-${index}`} className="result-row-block">
                  <p><strong>Key:</strong> {formatBytes(entry.key)}</p>
                  <p><strong>Location:</strong> {entry.location.toString()}</p>
                  {renderOperation(entry.operation)}
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
          <h4>Streamed Events ({events.length})</h4>
          {events.length === 0 ? (
            <p>No proof events yet</p>
          ) : (
            <div className="result-list">
              {events.map((event, index) => {
                const ops = event.proof.operations;
                const counts = ops.reduce(
                  (acc, op) => {
                    if (op.operation.type === 'update') acc.updates += 1;
                    if (op.operation.type === 'delete') acc.deletes += 1;
                    if (op.operation.type === 'commit_floor') acc.commits += 1;
                    return acc;
                  },
                  { updates: 0, deletes: 0, commits: 0 },
                );
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
                      <strong>Tip:</strong> {event.tip.toString()}
                      {' · '}
                      <strong>Matched:</strong> {ops.length}
                      {' · '}
                      <strong>Updates:</strong> {counts.updates}
                      {' · '}
                      <strong>Deletes:</strong> {counts.deletes}
                      {' · '}
                      <strong>Commits:</strong> {counts.commits}
                      {' · '}
                      <strong>Locations:</strong> {locationRange}
                      {' · '}
                      <strong>Proof Size:</strong>{' '}
                      {formatProofSize(event.proof.proofSizeBytes)}
                    </p>
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

      <div className="form-section">
        <h3>Get Historical Operation Range</h3>
        <p className="section-note">
          Fetches a contiguous historical operation proof for the operation log and verifies it
          against the expected root for the selected tip.
        </p>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="qmdb-history-start">Start Location</label>
            <input
              id="qmdb-history-start"
              type="number"
              min="0"
              value={historyStartLocation}
              onChange={(event) => setHistoryStartLocation(event.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="qmdb-history-max">Max Locations</label>
            <input
              id="qmdb-history-max"
              type="number"
              min="1"
              value={historyMaxLocations}
              onChange={(event) => setHistoryMaxLocations(event.target.value)}
            />
          </div>
        </div>
        <button
          className={`btn-primary ${isGettingHistory ? 'loading' : ''}`}
          onClick={handleGetOperationRange}
          disabled={
            isGettingHistory ||
            !historyStartLocation.trim() ||
            !historyMaxLocations.trim() ||
            !tip.trim() ||
            !expectedCurrentRoot.trim()
          }
        >
          {isGettingHistory ? 'Verifying...' : 'Get Historical Range'}
        </button>
        {historyProof && (
          <div className="result fade-in">
            <h4>Verified Historical Operations</h4>
            <p><strong>Proof Size:</strong> {formatProofSize(historyProof.proofSizeBytes)}</p>
            <p><strong>Operations:</strong> {historyProof.operations.length}</p>
            <div className="result-list">
              {historyProof.operations.map((op, index) => (
                <div
                  key={`${op.location.toString()}-${index}`}
                  className="result-row-block"
                >
                  <p><strong>Location:</strong> {op.location.toString()}</p>
                  {renderOperation(op.operation)}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
