import { useEffect, useMemo, useRef, useState } from 'react';
import {
  SimplexClient,
  bytesToHex,
  hexToBytes,
  wasmCertifiedBlockVerifier,
  type CertifiedBlockFrame,
} from '@simplex-ts';

export const SIMPLEX_STORE_URL = (
  import.meta.env.VITE_SIMPLEX_STORE_URL
  || import.meta.env.VITE_SIMULATOR_URL
  || import.meta.env.VITE_SIMPLEX_URL
) as string | undefined;

const MAX_EVENTS = 10;
const DEFAULT_NAMESPACE = import.meta.env.VITE_SIMPLEX_NAMESPACE || '';
const DEFAULT_IDENTITY = import.meta.env.VITE_SIMPLEX_IDENTITY || '';

interface NotificationFn {
  (type: 'success' | 'error', title: string, message: string): void;
}

type KindFilter = 'all' | 'notarized' | 'finalized';

function parseRequiredBigInt(value: string, label: string): bigint {
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

function parseOptionalBigInt(value: string): bigint | undefined {
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }
  const parsed = BigInt(trimmed);
  if (parsed < 0n) {
    throw new Error('Since Sequence must be non-negative');
  }
  return parsed;
}

function formatHex(bytes: Uint8Array, maxChars = 72): string {
  const hex = bytesToHex(bytes);
  if (hex.length <= maxChars) {
    return `0x${hex}`;
  }
  return `0x${hex.slice(0, maxChars - 12)}...${hex.slice(-8)}`;
}

function formatBytesLength(bytes: Uint8Array): string {
  return `${bytes.byteLength.toLocaleString()} bytes`;
}

function requestKind(kind: KindFilter): 'notarized' | 'finalized' | undefined {
  return kind === 'all' ? undefined : kind;
}

function blockDetails(event: CertifiedBlockFrame) {
  return (
    <>
      <p>
        <strong>Sequence:</strong> {event.sequenceNumber.toString()}
        {' · '}
        <strong>Kind:</strong> {event.kind}
        {' · '}
        <strong>Height:</strong> {event.height.toString()}
      </p>
      <p>
        <strong>Epoch:</strong> {event.epoch.toString()}
        {' · '}
        <strong>View:</strong> {event.view.toString()}
      </p>
      <p><strong>Block Digest:</strong> {formatHex(event.blockDigest)}</p>
      <p><strong>Block Key:</strong> {formatHex(event.blockKey)}</p>
      <p>
        <strong>Certificate:</strong> {formatBytesLength(event.encodedCertificate)}
        {' · '}
        <strong>Block:</strong> {formatBytesLength(event.encodedBlock)}
      </p>
    </>
  );
}

export function SimplexPanel({
  storeUrl,
  showNotification,
}: {
  storeUrl: string;
  showNotification: NotificationFn;
}) {
  const client = useMemo(
    () => new SimplexClient(storeUrl),
    [storeUrl],
  );
  const subscribeAbortRef = useRef<AbortController | null>(null);

  const [isConnected, setIsConnected] = useState(false);
  const [identityHex, setIdentityHex] = useState(DEFAULT_IDENTITY);
  const [namespace, setNamespace] = useState(DEFAULT_NAMESPACE);
  const [kind, setKind] = useState<KindFilter>('finalized');
  const [sinceSequenceNumber, setSinceSequenceNumber] = useState('');
  const [events, setEvents] = useState<CertifiedBlockFrame[]>([]);
  const [isSubscribing, setIsSubscribing] = useState(false);
  const [lookupKind, setLookupKind] = useState<'notarized' | 'finalized'>('finalized');
  const [lookupEpoch, setLookupEpoch] = useState('0');
  const [lookupView, setLookupView] = useState('');
  const [lookupHeight, setLookupHeight] = useState('');
  const [lookupResult, setLookupResult] = useState<CertifiedBlockFrame | null>(null);
  const [isLookingUp, setIsLookingUp] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        await client.health();
        if (!controller.signal.aborted) {
          setIsConnected(true);
        }
      } catch {
        if (!controller.signal.aborted) {
          setIsConnected(false);
        }
      }
    })();

    return () => {
      controller.abort();
      subscribeAbortRef.current?.abort();
    };
  }, [client]);

  const buildVerifier = () => {
    const trimmedIdentity = identityHex.trim();
    if (!trimmedIdentity) {
      throw new Error('Committee identity is required');
    }
    const trimmedNamespace = namespace.trim();
    if (!trimmedNamespace) {
      throw new Error('Namespace is required');
    }
    return wasmCertifiedBlockVerifier({
      identity: hexToBytes(trimmedIdentity),
      namespace: trimmedNamespace,
    });
  };

  const handleStartSubscribe = () => {
    try {
      const verifier = buildVerifier();

      subscribeAbortRef.current?.abort();
      setEvents([]);
      setIsSubscribing(true);

      const controller = new AbortController();
      subscribeAbortRef.current = controller;
      const selectedKind = requestKind(kind);
      const since = parseOptionalBigInt(sinceSequenceNumber);

      void (async () => {
        try {
          for await (const block of client.subscribeCertifiedBlocks(
            {
              kind: selectedKind,
              sinceSequenceNumber: since,
            },
            verifier,
            { signal: controller.signal },
          )) {
            setEvents((previous) => [block, ...previous].slice(0, MAX_EVENTS));
          }
        } catch (error) {
          if (!controller.signal.aborted) {
            showNotification('error', 'Simplex Subscribe Failed', String(error));
          }
        } finally {
          if (subscribeAbortRef.current === controller) {
            subscribeAbortRef.current = null;
          }
          setIsSubscribing(false);
        }
      })();

      showNotification(
        'success',
        'Simplex Subscribe',
        selectedKind ? `Streaming verified ${selectedKind} blocks` : 'Streaming verified blocks',
      );
    } catch (error) {
      showNotification('error', 'Simplex Subscribe Failed', String(error));
      setIsSubscribing(false);
    }
  };

  const handleStopSubscribe = () => {
    subscribeAbortRef.current?.abort();
    subscribeAbortRef.current = null;
    setIsSubscribing(false);
  };

  const handleLookupByView = async () => {
    try {
      setIsLookingUp(true);
      const verifier = buildVerifier();
      const epoch = parseRequiredBigInt(lookupEpoch.trim() || '0', 'Epoch');
      const view = parseRequiredBigInt(lookupView, 'View');
      const block = await client.certifiedBlockByView(lookupKind, view, { epoch, verifier });
      setLookupResult(block ?? null);
      showNotification(
        block ? 'success' : 'error',
        'Simplex Lookup',
        block ? `Fetched verified ${lookupKind} block` : 'No block found for that view',
      );
    } catch (error) {
      showNotification('error', 'Simplex Lookup Failed', String(error));
    } finally {
      setIsLookingUp(false);
    }
  };

  const handleLookupFinalizedByHeight = async () => {
    try {
      setIsLookingUp(true);
      const verifier = buildVerifier();
      const epoch = parseRequiredBigInt(lookupEpoch.trim() || '0', 'Epoch');
      const height = parseRequiredBigInt(lookupHeight, 'Height');
      const block = await client.finalizedBlockByHeight(height, { epoch, verifier });
      setLookupResult(block ?? null);
      showNotification(
        block ? 'success' : 'error',
        'Simplex Lookup',
        block ? 'Fetched verified finalized block' : 'No finalized block found for that height',
      );
    } catch (error) {
      showNotification('error', 'Simplex Lookup Failed', String(error));
    } finally {
      setIsLookingUp(false);
    }
  };

  return (
    <div className="card fade-in">
      <h2>Simplex</h2>

      <div className="form-section">
        <h3>Connection</h3>
        <p className="section-note">
          Streams certified block records from Store, fetches each raw block from KV, and verifies
          the notarization or finalization certificate in WASM before showing it.
        </p>
        <p><strong>Store Server:</strong> {storeUrl}</p>
        <p><strong>Status:</strong> {isConnected ? 'Connected' : 'Disconnected'}</p>
      </div>

      <div className="form-section">
        <h3>Subscribe</h3>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="simplex-kind">Kind</label>
            <select
              id="simplex-kind"
              value={kind}
              onChange={(event) => setKind(event.target.value as KindFilter)}
            >
              <option value="finalized">finalized</option>
              <option value="notarized">notarized</option>
              <option value="all">all</option>
            </select>
          </div>
          <div className="form-group">
            <label htmlFor="simplex-since">Since Sequence (optional)</label>
            <input
              id="simplex-since"
              type="number"
              min="0"
              value={sinceSequenceNumber}
              onChange={(event) => setSinceSequenceNumber(event.target.value)}
            />
          </div>
        </div>
        <div className="form-row">
          <div className="form-group form-group-wide">
            <label htmlFor="simplex-identity">Committee Identity (hex)</label>
            <input
              id="simplex-identity"
              type="text"
              placeholder="0x..."
              value={identityHex}
              onChange={(event) => setIdentityHex(event.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="simplex-namespace">Namespace</label>
            <input
              id="simplex-namespace"
              type="text"
              value={namespace}
              onChange={(event) => setNamespace(event.target.value)}
            />
          </div>
        </div>
        <div className="button-row">
          <button
            className={`btn-primary ${isSubscribing ? 'loading' : ''}`}
            onClick={handleStartSubscribe}
            disabled={isSubscribing || !identityHex.trim() || !namespace.trim()}
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
          <button
            className="btn-secondary"
            onClick={() => setEvents([])}
            disabled={events.length === 0}
          >
            Clear Events
          </button>
        </div>

        <div className="form-section">
          <h3>Lookup</h3>
          <div className="form-row">
            <div className="form-group">
              <label htmlFor="simplex-lookup-kind">Kind</label>
              <select
                id="simplex-lookup-kind"
                value={lookupKind}
                onChange={(event) => setLookupKind(event.target.value as 'notarized' | 'finalized')}
              >
                <option value="finalized">finalized</option>
                <option value="notarized">notarized</option>
              </select>
            </div>
            <div className="form-group">
              <label htmlFor="simplex-lookup-epoch">Epoch</label>
              <input
                id="simplex-lookup-epoch"
                type="number"
                min="0"
                value={lookupEpoch}
                onChange={(event) => setLookupEpoch(event.target.value)}
              />
            </div>
          </div>
          <div className="form-row">
            <div className="form-group">
              <label htmlFor="simplex-lookup-view">View</label>
              <input
                id="simplex-lookup-view"
                type="number"
                min="0"
                value={lookupView}
                onChange={(event) => setLookupView(event.target.value)}
              />
            </div>
            <div className="form-group">
              <label htmlFor="simplex-lookup-height">Finalized Height</label>
              <input
                id="simplex-lookup-height"
                type="number"
                min="0"
                value={lookupHeight}
                onChange={(event) => setLookupHeight(event.target.value)}
              />
            </div>
          </div>
          <div className="button-row">
            <button
              className={`btn-secondary ${isLookingUp ? 'loading' : ''}`}
              onClick={() => void handleLookupByView()}
              disabled={isLookingUp || !identityHex.trim() || !namespace.trim() || !lookupView.trim()}
            >
              Get by View
            </button>
            <button
              className={`btn-secondary ${isLookingUp ? 'loading' : ''}`}
              onClick={() => void handleLookupFinalizedByHeight()}
              disabled={isLookingUp || !identityHex.trim() || !namespace.trim() || !lookupHeight.trim()}
            >
              Get Finalized by Height
            </button>
          </div>
          {lookupResult && (
            <div className="result fade-in">
              <h4>Lookup Result</h4>
              <div className="result-row-block">{blockDetails(lookupResult)}</div>
            </div>
          )}
        </div>

        <div className="result fade-in">
          <h4>Verified Blocks ({events.length})</h4>
          {events.length === 0 ? (
            <p>{isSubscribing ? 'Waiting for certified blocks...' : 'No blocks received yet.'}</p>
          ) : (
            <div className="result-list">
              {events.map((event, index) => (
                <div
                  key={`${event.sequenceNumber.toString()}-${event.kind}-${event.view.toString()}-${index}`}
                  className="result-row-block"
                >
                  {blockDetails(event)}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
