import { useEffect, useMemo, useRef, useState } from 'react';
import {
  bytesToHex,
  hexToBytes,
  type CommonwareSimplexHeaderVerification,
  type CommonwareSimplexScheme,
  SimplexClient,
  type CommonwareVerifiedSimplexCertificate,
  type SimplexBlockData,
  type SimplexCertificateVerifier,
  type VerifiedSimplexCertificateStreamEntry,
} from '@simplex-ts';
import { createCommonwareWasmSimplexVerifier } from '@simplex-ts/wasm';

export const SIMPLEX_URL = import.meta.env.VITE_SIMPLEX_URL as string | undefined;
const MAX_EVENTS = 10;
const SIMPLEX_DEMO_SCHEME: CommonwareSimplexScheme = 'bls12381-threshold-vrf-min-sig';
const SIMPLEX_DEMO_NAMESPACE = '_EXOWARE_SIMPLEX_DEMO';
const SIMPLEX_DEMO_VERIFICATION_MATERIAL =
  'a1195547a176e10913080f5f367fe413698890f3b9809e24c2bc4e7928d41d74ef29d81e49fa2ec3c129be87479f666811d200bb29e70093c9cc86946c47d7156b9a0440c08894e00e3702c06642f45dbdfabcbab0763d225a0c66cd3e30bffe';
const SIMPLEX_SCHEMES: CommonwareSimplexScheme[] = [
  'ed25519',
  'secp256r1',
  'bls12381-multisig-min-pk',
  'bls12381-multisig-min-sig',
  'bls12381-threshold-standard-min-pk',
  'bls12381-threshold-standard-min-sig',
  'bls12381-threshold-vrf-min-pk',
  'bls12381-threshold-vrf-min-sig',
];

interface NotificationFn {
  (type: 'success' | 'error', title: string, message: string): void;
}

type VerifiedSimplexEntry = VerifiedSimplexCertificateStreamEntry<
  CommonwareVerifiedSimplexCertificate,
  CommonwareVerifiedSimplexCertificate
>;

interface VerifiedSimplexEvent {
  sequenceNumber: bigint;
  entry: VerifiedSimplexEntry;
}

interface VerifierConfig {
  scheme: CommonwareSimplexScheme;
  namespace: string;
  verificationMaterialHex: string;
}

interface VerifiedFullBlock {
  digestHex: string;
  block: SimplexBlockData;
}

const READ_CERTIFICATE_IDS = ['notarization', 'latest', 'view', 'height'] as const;
type ReadCertificateId = typeof READ_CERTIFICATE_IDS[number];
type ReadCertificates = Record<ReadCertificateId, CommonwareVerifiedSimplexCertificate | null>;

function renderBytes(value: Uint8Array): string {
  const hex = bytesToHex(value);
  return hex.length > 160 ? `${hex.slice(0, 160)}...` : hex;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

async function verifyDemoHeader({
  payload,
  header,
}: CommonwareSimplexHeaderVerification): Promise<boolean> {
  return bytesEqual(payload, await sha256(header));
}

async function verifyDemoBlock(header: Uint8Array, body: Uint8Array): Promise<boolean> {
  if (header.byteLength < 32) {
    return false;
  }
  return bytesEqual(header.slice(header.byteLength - 32), await sha256(body));
}

function renderCertificate(value: CommonwareVerifiedSimplexCertificate): string {
  return [
    `scheme ${value.scheme}`,
    `view ${value.view.toString()}`,
    `parent ${value.parent.toString()}`,
    `payload ${renderBytes(value.payload)}`,
    `certificate ${renderBytes(value.certificate)}`,
    `header ${renderBytes(value.header)}`,
  ].join('\n');
}

function emptyReadCertificates(): ReadCertificates {
  return {
    notarization: null,
    latest: null,
    view: null,
    height: null,
  };
}

function keepReadVerifiedFullBlocks(
  previous: Record<string, VerifiedFullBlock>,
): Record<string, VerifiedFullBlock> {
  const next: Record<string, VerifiedFullBlock> = {};
  for (const id of READ_CERTIFICATE_IDS) {
    const block = previous[id];
    if (block) {
      next[id] = block;
    }
  }
  return next;
}

function streamEventId({ sequenceNumber, entry }: VerifiedSimplexEvent): string {
  return `${sequenceNumber.toString()}-${bytesToHex(entry.key)}`;
}

export function SimplexPanel({
  simplexUrl,
  showNotification,
}: {
  simplexUrl: string;
  showNotification: NotificationFn;
}) {
  const subscribeAbortRef = useRef<AbortController | null>(null);
  const showNotificationRef = useRef(showNotification);
  const readCertificatesRef = useRef<ReadCertificates>(emptyReadCertificates());
  const streamCertificatesRef = useRef<Record<string, CommonwareVerifiedSimplexCertificate>>({});
  const [scheme, setScheme] = useState<CommonwareSimplexScheme>(SIMPLEX_DEMO_SCHEME);
  const [namespace, setNamespace] = useState(SIMPLEX_DEMO_NAMESPACE);
  const [verificationMaterialHex, setVerificationMaterialHex] = useState(
    SIMPLEX_DEMO_VERIFICATION_MATERIAL,
  );
  const [appliedVerifierConfig, setAppliedVerifierConfig] = useState<VerifierConfig>({
    scheme: SIMPLEX_DEMO_SCHEME,
    namespace: SIMPLEX_DEMO_NAMESPACE,
    verificationMaterialHex: SIMPLEX_DEMO_VERIFICATION_MATERIAL,
  });
  const [verifier, setVerifier] = useState<
    SimplexCertificateVerifier<
      CommonwareVerifiedSimplexCertificate,
      CommonwareVerifiedSimplexCertificate
    >
  >();
  const [verifierStatus, setVerifierStatus] = useState<'loading' | 'ready' | 'error'>('loading');
  const client = useMemo(
    () =>
      new SimplexClient<
        CommonwareVerifiedSimplexCertificate,
        CommonwareVerifiedSimplexCertificate
      >(simplexUrl, verifier ? { verifier } : {}),
    [simplexUrl, verifier],
  );

  const [isConnected, setIsConnected] = useState(false);
  const [isReadingBlock, setIsReadingBlock] = useState(false);
  const [isReadingNotarization, setIsReadingNotarization] = useState(false);
  const [isReadingLatest, setIsReadingLatest] = useState(false);
  const [isReadingViewFinalization, setIsReadingViewFinalization] = useState(false);
  const [isReadingHeightFinalization, setIsReadingHeightFinalization] = useState(false);
  const [isSubscribing, setIsSubscribing] = useState(false);
  const [verifyingFullBlockId, setVerifyingFullBlockId] = useState<string | null>(null);
  const [notarizationView, setNotarizationView] = useState('');
  const [finalizationIndex, setFinalizationIndex] = useState('');
  const [sinceSequenceNumber, setSinceSequenceNumber] = useState('');
  const [streamEvents, setStreamEvents] = useState<VerifiedSimplexEvent[]>([]);
  const [verifiedFullBlocks, setVerifiedFullBlocks] = useState<Record<string, VerifiedFullBlock>>(
    {},
  );

  const [blockReadDigestHex, setBlockReadDigestHex] = useState('');
  const [headerReadResult, setHeaderReadResult] = useState<Uint8Array | null>(null);
  const [blockReadResult, setBlockReadResult] = useState<SimplexBlockData | null>(null);

  const [notarization, setNotarization] =
    useState<CommonwareVerifiedSimplexCertificate | null>(null);
  const [notarizationMissing, setNotarizationMissing] = useState(false);
  const [latestFinalization, setLatestFinalization] =
    useState<CommonwareVerifiedSimplexCertificate | null>(null);
  const [latestFinalizationMissing, setLatestFinalizationMissing] = useState(false);
  const [viewFinalization, setViewFinalization] =
    useState<CommonwareVerifiedSimplexCertificate | null>(null);
  const [viewFinalizationMissing, setViewFinalizationMissing] = useState(false);
  const [heightFinalization, setHeightFinalization] =
    useState<CommonwareVerifiedSimplexCertificate | null>(null);
  const [heightFinalizationMissing, setHeightFinalizationMissing] = useState(false);

  const setReadCertificateRef = (
    id: ReadCertificateId,
    certificate: CommonwareVerifiedSimplexCertificate | null,
  ) => {
    readCertificatesRef.current = {
      ...readCertificatesRef.current,
      [id]: certificate,
    };
  };

  useEffect(() => {
    showNotificationRef.current = showNotification;
  }, [showNotification]);

  useEffect(() => {
    streamCertificatesRef.current = Object.fromEntries(
      streamEvents.map((event) => [streamEventId(event), event.entry.certificate]),
    );
  }, [streamEvents]);

  useEffect(() => {
    let active = true;
    setVerifierStatus('loading');
    void (async () => {
      try {
        const nextVerifier = await createCommonwareWasmSimplexVerifier({
          scheme: appliedVerifierConfig.scheme,
          namespace: new TextEncoder().encode(appliedVerifierConfig.namespace),
          verificationMaterial: hexToBytes(appliedVerifierConfig.verificationMaterialHex),
          verifyHeader: verifyDemoHeader,
        });
        if (active) {
          setVerifier(nextVerifier);
          setVerifierStatus('ready');
        }
      } catch (error) {
        if (active) {
          setVerifier(undefined);
          setVerifierStatus('error');
          showNotificationRef.current('error', 'Simplex Verifier Failed', String(error));
        }
      }
    })();
    return () => {
      active = false;
    };
  }, [appliedVerifierConfig]);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const response = await fetch(`${simplexUrl.replace(/\/$/, '')}/health`, {
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
  }, [simplexUrl]);

  const applyVerifier = () => {
    try {
      hexToBytes(verificationMaterialHex);
      subscribeAbortRef.current?.abort();
      subscribeAbortRef.current = null;
      readCertificatesRef.current = emptyReadCertificates();
      streamCertificatesRef.current = {};
      setIsSubscribing(false);
      setNotarization(null);
      setNotarizationMissing(false);
      setLatestFinalization(null);
      setLatestFinalizationMissing(false);
      setViewFinalization(null);
      setViewFinalizationMissing(false);
      setHeightFinalization(null);
      setHeightFinalizationMissing(false);
      setStreamEvents([]);
      setVerifiedFullBlocks({});
      setAppliedVerifierConfig({
        scheme,
        namespace,
        verificationMaterialHex,
      });
      showNotification('success', 'Simplex Verifier', `Using ${scheme}`);
    } catch (error) {
      showNotification('error', 'Simplex Verifier Failed', String(error));
    }
  };

  const readBlock = async () => {
    setIsReadingBlock(true);
    setHeaderReadResult(null);
    setBlockReadResult(null);
    try {
      const block = await client.getBlock(hexToBytes(blockReadDigestHex));
      setBlockReadResult(block);
      showNotification(
        'success',
        block ? 'Simplex Block Loaded' : 'Simplex Block Missing',
        block
          ? `${block.header.byteLength} header bytes, ${block.body.byteLength} body bytes`
          : 'No block for that digest',
      );
    } catch (error) {
      showNotification('error', 'Simplex Block Read Failed', String(error));
    } finally {
      setIsReadingBlock(false);
    }
  };

  const readHeader = async () => {
    setIsReadingBlock(true);
    setHeaderReadResult(null);
    setBlockReadResult(null);
    try {
      const header = await client.getHeader(hexToBytes(blockReadDigestHex));
      setHeaderReadResult(header);
      showNotification(
        'success',
        header ? 'Simplex Header Loaded' : 'Simplex Header Missing',
        header ? `${header.byteLength} bytes` : 'No header bytes for that digest',
      );
    } catch (error) {
      showNotification('error', 'Simplex Header Read Failed', String(error));
    } finally {
      setIsReadingBlock(false);
    }
  };

  const readNotarizationByView = async () => {
    setIsReadingNotarization(true);
    setReadCertificateRef('notarization', null);
    setNotarization(null);
    setNotarizationMissing(false);
    setVerifiedFullBlocks((previous) => {
      const next = { ...previous };
      delete next.notarization;
      return next;
    });
    try {
      const view = notarizationView.trim();
      if (!/^\d+$/.test(view)) {
        throw new Error('Notarization view must be a non-negative integer');
      }
      const nextNotarization = await client.getNotarization(view);
      setReadCertificateRef('notarization', nextNotarization);
      setNotarization(nextNotarization);
      setNotarizationMissing(nextNotarization === null);
      showNotification(
        'success',
        nextNotarization ? 'Simplex Notarization Loaded' : 'Simplex Notarization Missing',
        nextNotarization
          ? `view ${nextNotarization.view.toString()}`
          : `No notarized certificate at view ${view}`,
      );
    } catch (error) {
      showNotification('error', 'Simplex Notarization Read Failed', String(error));
    } finally {
      setIsReadingNotarization(false);
    }
  };

  const readLatestFinalization = async () => {
    setIsReadingLatest(true);
    setReadCertificateRef('latest', null);
    setLatestFinalization(null);
    setLatestFinalizationMissing(false);
    setVerifiedFullBlocks((previous) => {
      const next = { ...previous };
      delete next.latest;
      return next;
    });
    try {
      const finalization = await client.latestFinalization();
      setReadCertificateRef('latest', finalization);
      setLatestFinalization(finalization);
      setLatestFinalizationMissing(finalization === null);
      showNotification(
        'success',
        finalization ? 'Simplex Finalization Loaded' : 'Simplex Finalization Missing',
        finalization ? `view ${finalization.view.toString()}` : 'No finalized height index yet',
      );
    } catch (error) {
      showNotification('error', 'Simplex Finalization Read Failed', String(error));
    } finally {
      setIsReadingLatest(false);
    }
  };

  const readFinalizationIndex = (label: 'view' | 'height') => {
    const value = finalizationIndex.trim();
    if (!/^\d+$/.test(value)) {
      throw new Error(`Finalization ${label} must be a non-negative integer`);
    }
    return value;
  };

  const readViewFinalization = async () => {
    setIsReadingViewFinalization(true);
    setReadCertificateRef('view', null);
    setViewFinalization(null);
    setViewFinalizationMissing(false);
    setVerifiedFullBlocks((previous) => {
      const next = { ...previous };
      delete next.view;
      return next;
    });
    try {
      const view = readFinalizationIndex('view');
      const finalization = await client.getFinalizationByView(view);
      setReadCertificateRef('view', finalization);
      setViewFinalization(finalization);
      setViewFinalizationMissing(finalization === null);
      showNotification(
        'success',
        finalization ? 'Simplex Finalization Loaded' : 'Simplex Finalization Missing',
        finalization
          ? `view ${finalization.view.toString()}`
          : `No finalized certificate at view ${view}`,
      );
    } catch (error) {
      showNotification('error', 'Simplex Finalization Read Failed', String(error));
    } finally {
      setIsReadingViewFinalization(false);
    }
  };

  const readHeightFinalization = async () => {
    setIsReadingHeightFinalization(true);
    setReadCertificateRef('height', null);
    setHeightFinalization(null);
    setHeightFinalizationMissing(false);
    setVerifiedFullBlocks((previous) => {
      const next = { ...previous };
      delete next.height;
      return next;
    });
    try {
      const height = readFinalizationIndex('height');
      const finalization = await client.getFinalizationByHeight(height);
      setReadCertificateRef('height', finalization);
      setHeightFinalization(finalization);
      setHeightFinalizationMissing(finalization === null);
      showNotification(
        'success',
        finalization ? 'Simplex Finalization Loaded' : 'Simplex Finalization Missing',
        finalization
          ? `height ${height}, view ${finalization.view.toString()}`
          : `No finalized certificate at height ${height}`,
      );
    } catch (error) {
      showNotification('error', 'Simplex Finalization Read Failed', String(error));
    } finally {
      setIsReadingHeightFinalization(false);
    }
  };

  const verifyFullBlock = async (
    id: string,
    certificate: CommonwareVerifiedSimplexCertificate,
  ) => {
    setVerifyingFullBlockId(id);
    setVerifiedFullBlocks((previous) => {
      const next = { ...previous };
      delete next[id];
      return next;
    });
    try {
      const block = await client.getBlock(certificate.payload);
      if (!block) {
        throw new Error(`No full block for digest ${bytesToHex(certificate.payload)}`);
      }
      if (!bytesEqual(block.header, certificate.header)) {
        throw new Error('Fetched block header does not match the certified header');
      }
      if (!(await verifyDemoBlock(block.header, block.body))) {
        throw new Error('Fetched block body does not match the demo header commitment');
      }
      setVerifiedFullBlocks((previous) => ({
        ...previous,
        [id]: {
          digestHex: bytesToHex(certificate.payload),
          block,
        },
      }));
      showNotification(
        'success',
        'Simplex Full Block Verified',
        `${block.header.byteLength} header bytes, ${block.body.byteLength} body bytes`,
      );
    } catch (error) {
      showNotification('error', 'Simplex Full Block Verify Failed', String(error));
    } finally {
      setVerifyingFullBlockId(null);
    }
  };

  const verifyReadFullBlock = async (id: ReadCertificateId) => {
    const certificate = readCertificatesRef.current[id];
    if (!certificate) {
      showNotification('error', 'Simplex Full Block Verify Failed', 'No verified certificate loaded');
      return;
    }
    await verifyFullBlock(id, certificate);
  };

  const verifyStreamFullBlock = async (id: string) => {
    const certificate = streamCertificatesRef.current[id];
    if (!certificate) {
      showNotification('error', 'Simplex Full Block Verify Failed', 'No streamed certificate loaded');
      return;
    }
    await verifyFullBlock(id, certificate);
  };

  const startSubscribe = () => {
    subscribeAbortRef.current?.abort();
    streamCertificatesRef.current = {};
    setStreamEvents([]);
    setVerifiedFullBlocks(keepReadVerifiedFullBlocks);
    setIsSubscribing(true);

    const controller = new AbortController();
    subscribeAbortRef.current = controller;

    void (async () => {
      try {
        const since = sinceSequenceNumber.trim()
          ? BigInt(sinceSequenceNumber.trim())
          : undefined;
        for await (const batch of client.subscribeCertificates(
          {
            includeFinalizedByHeight: true,
            sinceSequenceNumber: since,
          },
          { signal: controller.signal },
        )) {
          const events = batch.entries.map((entry) => ({
            sequenceNumber: batch.sequenceNumber,
            entry,
          }));
          setStreamEvents((previous) => [...events, ...previous].slice(0, MAX_EVENTS));
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

    showNotification('success', 'Simplex Subscribe', 'Listening for verified certificates');
  };

  const stopSubscribe = () => {
    subscribeAbortRef.current?.abort();
    subscribeAbortRef.current = null;
    setIsSubscribing(false);
  };

  return (
    <div className="card fade-in">
      <h2>Simplex</h2>

      <div className="form-section">
        <h3>Connection</h3>
        <p className="section-note">
          Run `simplex seed` and paste its verifier material here. Fetched and
          streamed certificates are verified before display.
        </p>
        <p><strong>Store:</strong> {simplexUrl}</p>
        <p><strong>Status:</strong> {isConnected ? 'Connected' : 'Disconnected'}</p>
        <p><strong>Verifier:</strong> {verifierStatus}</p>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="simplex-verifier-scheme">Scheme</label>
            <select
              id="simplex-verifier-scheme"
              value={scheme}
              onChange={(event) => setScheme(event.target.value as CommonwareSimplexScheme)}
            >
              {SIMPLEX_SCHEMES.map((item) => (
                <option key={item} value={item}>{item}</option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label htmlFor="simplex-verifier-namespace">Namespace</label>
            <input
              id="simplex-verifier-namespace"
              type="text"
              value={namespace}
              onChange={(event) => setNamespace(event.target.value)}
            />
          </div>
        </div>
        <div className="form-row">
          <div className="form-group form-group-wide">
            <label htmlFor="simplex-verifier-material">Verification Material Hex</label>
            <textarea
              id="simplex-verifier-material"
              value={verificationMaterialHex}
              onChange={(event) => setVerificationMaterialHex(event.target.value)}
            />
          </div>
        </div>
        <button className="btn-secondary" onClick={applyVerifier}>
          Apply Verifier
        </button>
      </div>

      <div className="form-section">
        <h3>Read</h3>
        <div className="form-row">
          <div className="form-group form-group-wide">
            <label htmlFor="simplex-read-block-digest">Block Digest Hex</label>
            <input
              id="simplex-read-block-digest"
              type="text"
              value={blockReadDigestHex}
              onChange={(event) => setBlockReadDigestHex(event.target.value)}
            />
          </div>
        </div>
        <div className="button-row">
          <button
            className={`btn-primary ${isReadingBlock ? 'loading' : ''}`}
            onClick={readHeader}
            disabled={isReadingBlock || !blockReadDigestHex.trim()}
          >
            {isReadingBlock ? 'Loading...' : 'Get Header'}
          </button>
          <button
            className={`btn-primary ${isReadingBlock ? 'loading' : ''}`}
            onClick={readBlock}
            disabled={isReadingBlock || !blockReadDigestHex.trim()}
          >
            {isReadingBlock ? 'Loading...' : 'Get Full Block'}
          </button>
        </div>
        <div className="form-row">
          <div className="form-group form-group-wide">
            <label htmlFor="simplex-notarization-view">Notarization View</label>
            <input
              id="simplex-notarization-view"
              type="number"
              min="0"
              value={notarizationView}
              onChange={(event) => setNotarizationView(event.target.value)}
            />
          </div>
        </div>
        <div className="button-row">
          <button
            className={`btn-primary ${isReadingNotarization ? 'loading' : ''}`}
            onClick={readNotarizationByView}
            disabled={
              isReadingNotarization
              || verifierStatus !== 'ready'
              || !notarizationView.trim()
            }
          >
            {isReadingNotarization ? 'Loading...' : 'By View'}
          </button>
        </div>
        <div className="form-row">
          <div className="form-group form-group-wide">
            <label htmlFor="simplex-finalization-index">Finalization View or Height</label>
            <input
              id="simplex-finalization-index"
              type="number"
              min="0"
              value={finalizationIndex}
              onChange={(event) => setFinalizationIndex(event.target.value)}
            />
          </div>
        </div>
        <div className="button-row">
          <button
            className={`btn-primary ${isReadingViewFinalization ? 'loading' : ''}`}
            onClick={readViewFinalization}
            disabled={
              isReadingViewFinalization
              || verifierStatus !== 'ready'
              || !finalizationIndex.trim()
            }
          >
            {isReadingViewFinalization ? 'Loading...' : 'By View'}
          </button>
          <button
            className={`btn-primary ${isReadingHeightFinalization ? 'loading' : ''}`}
            onClick={readHeightFinalization}
            disabled={
              isReadingHeightFinalization
              || verifierStatus !== 'ready'
              || !finalizationIndex.trim()
            }
          >
            {isReadingHeightFinalization ? 'Loading...' : 'By Height'}
          </button>
          <button
            className={`btn-secondary ${isReadingLatest ? 'loading' : ''}`}
            onClick={readLatestFinalization}
            disabled={isReadingLatest || verifierStatus !== 'ready'}
          >
            {isReadingLatest ? 'Loading...' : 'Latest'}
          </button>
        </div>
        {headerReadResult && (
          <div className="result fade-in">
            <h4>Header</h4>
            <p>{renderBytes(headerReadResult)}</p>
          </div>
        )}
        {blockReadResult && (
          <div className="result fade-in">
            <h4>Block</h4>
            <pre>{[
              `header ${renderBytes(blockReadResult.header)}`,
              `body ${renderBytes(blockReadResult.body)}`,
            ].join('\n')}</pre>
          </div>
        )}
        {notarization && (
          <div className="result fade-in">
            <div className="result-title-row">
              <h4>Notarization By View</h4>
              <button
                className={`btn-secondary btn-compact ${
                  verifyingFullBlockId === 'notarization' ? 'loading' : ''
                }`}
                onClick={() => void verifyReadFullBlock('notarization')}
                disabled={verifyingFullBlockId !== null}
              >
                {verifyingFullBlockId === 'notarization'
                  ? 'Verifying...'
                  : 'Verify Full Block'}
              </button>
            </div>
            <pre>{renderCertificate(notarization)}</pre>
            {verifiedFullBlocks.notarization && (
              <div className="result-detail">
                <p><strong>Digest:</strong> {verifiedFullBlocks.notarization.digestHex}</p>
                <pre>{[
                  `header ${renderBytes(verifiedFullBlocks.notarization.block.header)}`,
                  `body ${renderBytes(verifiedFullBlocks.notarization.block.body)}`,
                ].join('\n')}</pre>
              </div>
            )}
          </div>
        )}
        {notarizationMissing && (
          <div className="result fade-in">
            <h4>No Notarization</h4>
            <p>No notarized certificate is stored at view {notarizationView.trim()}.</p>
          </div>
        )}
        {latestFinalization && (
          <div className="result fade-in">
            <div className="result-title-row">
              <h4>Latest Finalization</h4>
              <button
                className={`btn-secondary btn-compact ${
                  verifyingFullBlockId === 'latest' ? 'loading' : ''
                }`}
                onClick={() => void verifyReadFullBlock('latest')}
                disabled={verifyingFullBlockId !== null}
              >
                {verifyingFullBlockId === 'latest' ? 'Verifying...' : 'Verify Full Block'}
              </button>
            </div>
            <pre>{renderCertificate(latestFinalization)}</pre>
            {verifiedFullBlocks.latest && (
              <div className="result-detail">
                <p><strong>Digest:</strong> {verifiedFullBlocks.latest.digestHex}</p>
                <pre>{[
                  `header ${renderBytes(verifiedFullBlocks.latest.block.header)}`,
                  `body ${renderBytes(verifiedFullBlocks.latest.block.body)}`,
                ].join('\n')}</pre>
              </div>
            )}
          </div>
        )}
        {latestFinalizationMissing && (
          <div className="result fade-in">
            <h4>No Finalization</h4>
            <p>No finalized height index is stored.</p>
          </div>
        )}
        {viewFinalization && (
          <div className="result fade-in">
            <div className="result-title-row">
              <h4>Finalization By View</h4>
              <button
                className={`btn-secondary btn-compact ${
                  verifyingFullBlockId === 'view' ? 'loading' : ''
                }`}
                onClick={() => void verifyReadFullBlock('view')}
                disabled={verifyingFullBlockId !== null}
              >
                {verifyingFullBlockId === 'view' ? 'Verifying...' : 'Verify Full Block'}
              </button>
            </div>
            <pre>{renderCertificate(viewFinalization)}</pre>
            {verifiedFullBlocks.view && (
              <div className="result-detail">
                <p><strong>Digest:</strong> {verifiedFullBlocks.view.digestHex}</p>
                <pre>{[
                  `header ${renderBytes(verifiedFullBlocks.view.block.header)}`,
                  `body ${renderBytes(verifiedFullBlocks.view.block.body)}`,
                ].join('\n')}</pre>
              </div>
            )}
          </div>
        )}
        {viewFinalizationMissing && (
          <div className="result fade-in">
            <h4>No Finalization</h4>
            <p>No finalized certificate is stored at view {finalizationIndex.trim()}.</p>
          </div>
        )}
        {heightFinalization && (
          <div className="result fade-in">
            <div className="result-title-row">
              <h4>Finalization By Height</h4>
              <button
                className={`btn-secondary btn-compact ${
                  verifyingFullBlockId === 'height' ? 'loading' : ''
                }`}
                onClick={() => void verifyReadFullBlock('height')}
                disabled={verifyingFullBlockId !== null}
              >
                {verifyingFullBlockId === 'height' ? 'Verifying...' : 'Verify Full Block'}
              </button>
            </div>
            <pre>{renderCertificate(heightFinalization)}</pre>
            {verifiedFullBlocks.height && (
              <div className="result-detail">
                <p><strong>Digest:</strong> {verifiedFullBlocks.height.digestHex}</p>
                <pre>{[
                  `header ${renderBytes(verifiedFullBlocks.height.block.header)}`,
                  `body ${renderBytes(verifiedFullBlocks.height.block.body)}`,
                ].join('\n')}</pre>
              </div>
            )}
          </div>
        )}
        {heightFinalizationMissing && (
          <div className="result fade-in">
            <h4>No Finalization</h4>
            <p>No finalized certificate is stored at height {finalizationIndex.trim()}.</p>
          </div>
        )}
      </div>

      <div className="form-section">
        <h3>Subscribe</h3>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="simplex-since-sequence">Since Sequence</label>
            <input
              id="simplex-since-sequence"
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
            onClick={startSubscribe}
            disabled={isSubscribing || verifierStatus !== 'ready'}
          >
            {isSubscribing ? 'Listening...' : 'Start Subscribe'}
          </button>
          <button
            className="btn-secondary"
            onClick={stopSubscribe}
            disabled={!isSubscribing}
          >
            Stop Subscribe
          </button>
          <button
            className="btn-secondary"
            onClick={() => {
              streamCertificatesRef.current = {};
              setStreamEvents([]);
              setVerifiedFullBlocks(keepReadVerifiedFullBlocks);
            }}
            disabled={streamEvents.length === 0}
          >
            Clear
          </button>
        </div>
        <div className="result fade-in">
          <h4>Verified Certificates ({streamEvents.length})</h4>
          {streamEvents.length === 0 ? (
            <p>No certificate events yet</p>
          ) : (
            <div className="result-list">
              {streamEvents.map(({ sequenceNumber, entry }) => {
                const eventId = streamEventId({ sequenceNumber, entry });
                const title =
                  entry.type === 'notarization'
                    ? `notarization view ${entry.view.toString()}`
                    : `finalization ${entry.index} ${
                        entry.index === 'view'
                          ? entry.view.toString()
                          : entry.height.toString()
                      }`;
                return (
                  <div
                    key={eventId}
                    className="result-row-block"
                  >
                    <div className="result-title-row">
                      <div className="result-meta">
                        <p><strong>Sequence:</strong> {sequenceNumber.toString()}</p>
                        <p><strong>Entry:</strong> {title}</p>
                      </div>
                      <button
                        className={`btn-secondary btn-compact ${
                          verifyingFullBlockId === eventId ? 'loading' : ''
                        }`}
                        onClick={() => void verifyStreamFullBlock(eventId)}
                        disabled={verifyingFullBlockId !== null}
                      >
                        {verifyingFullBlockId === eventId
                          ? 'Verifying...'
                          : 'Verify Full Block'}
                      </button>
                    </div>
                    <pre>{renderCertificate(entry.certificate)}</pre>
                    {verifiedFullBlocks[eventId] && (
                      <div className="result-detail">
                        <p><strong>Digest:</strong> {verifiedFullBlocks[eventId].digestHex}</p>
                        <pre>{[
                          `header ${renderBytes(verifiedFullBlocks[eventId].block.header)}`,
                          `body ${renderBytes(verifiedFullBlocks[eventId].block.body)}`,
                        ].join('\n')}</pre>
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
