import { useEffect, useMemo, useRef, useState } from 'react';
import {
  bytesToHex,
  hexToBytes,
  type CommonwareSimplexBlockVerification,
  type CommonwareSimplexHeaderVerification,
  type CommonwareSimplexScheme,
  SimplexClient,
  type CommonwareVerifiedSimplexCertificate,
  type SimplexBlockData,
  type SimplexCertificateVerifier,
  type SimplexUploadReceipt,
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

function formatSequence(receipt: SimplexUploadReceipt): string {
  return receipt.storeSequenceNumber.toString();
}

function parseOptionalHex(value: string): Uint8Array | undefined {
  const trimmed = value.trim();
  return trimmed ? hexToBytes(trimmed) : undefined;
}

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

async function verifyDemoBlock({
  header,
  body,
}: CommonwareSimplexBlockVerification): Promise<boolean> {
  if (header.byteLength < 32) {
    return false;
  }
  return bytesEqual(header.slice(header.byteLength - 32), await sha256(body));
}

async function verifyDemoHeader({
  payload,
  header,
}: CommonwareSimplexHeaderVerification): Promise<boolean> {
  return bytesEqual(payload, await sha256(header));
}

function renderCertificate(value: CommonwareVerifiedSimplexCertificate): string {
  return [
    `scheme ${value.scheme}`,
    `view ${value.view.toString()}`,
    `parent ${value.parent.toString()}`,
    `payload ${renderBytes(value.payload)}`,
    `certificate ${renderBytes(value.certificate)}`,
    `header ${renderBytes(value.header)}`,
    `body ${renderBytes(value.body)}`,
  ].join('\n');
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
  const [isUploadingBlock, setIsUploadingBlock] = useState(false);
  const [isUploadingCertificate, setIsUploadingCertificate] = useState(false);
  const [isReadingBlock, setIsReadingBlock] = useState(false);
  const [isReadingLatest, setIsReadingLatest] = useState(false);
  const [isSubscribing, setIsSubscribing] = useState(false);
  const [sinceSequenceNumber, setSinceSequenceNumber] = useState('');
  const [streamEvents, setStreamEvents] = useState<VerifiedSimplexEvent[]>([]);

  const [blockDigestHex, setBlockDigestHex] = useState('');
  const [blockHeaderHex, setBlockHeaderHex] = useState('');
  const [blockBodyHex, setBlockBodyHex] = useState('');
  const [blockReadDigestHex, setBlockReadDigestHex] = useState('');
  const [headerReadResult, setHeaderReadResult] = useState<Uint8Array | null>(null);
  const [blockReadResult, setBlockReadResult] = useState<SimplexBlockData | null>(null);

  const [certificateKind, setCertificateKind] = useState<'notarization' | 'finalization'>(
    'finalization',
  );
  const [certificateView, setCertificateView] = useState('');
  const [certificateHeight, setCertificateHeight] = useState('');
  const [certificateHex, setCertificateHex] = useState('');
  const [certificateBlockDigestHex, setCertificateBlockDigestHex] = useState('');
  const [certificateHeaderHex, setCertificateHeaderHex] = useState('');
  const [certificateBodyHex, setCertificateBodyHex] = useState('');
  const [latestFinalization, setLatestFinalization] =
    useState<CommonwareVerifiedSimplexCertificate | null>(null);
  const [latestFinalizationMissing, setLatestFinalizationMissing] = useState(false);

  useEffect(() => {
    showNotificationRef.current = showNotification;
  }, [showNotification]);

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
          verifyBlock: verifyDemoBlock,
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
      setIsSubscribing(false);
      setLatestFinalization(null);
      setLatestFinalizationMissing(false);
      setStreamEvents([]);
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

  const uploadBlock = async () => {
    setIsUploadingBlock(true);
    try {
      const receipt = await client.uploadBlock({
        digest: hexToBytes(blockDigestHex),
        header: hexToBytes(blockHeaderHex),
        body: parseOptionalHex(blockBodyHex),
      });
      showNotification('success', 'Simplex Block', `Stored at sequence ${formatSequence(receipt)}`);
      setBlockHeaderHex('');
      setBlockBodyHex('');
    } catch (error) {
      showNotification('error', 'Simplex Block Failed', String(error));
    } finally {
      setIsUploadingBlock(false);
    }
  };

  const uploadCertificate = async () => {
    setIsUploadingCertificate(true);
    try {
      const header = parseOptionalHex(certificateHeaderHex);
      const body = parseOptionalHex(certificateBodyHex);
      const digest = parseOptionalHex(certificateBlockDigestHex);
      if ((header && !digest) || (!header && digest) || (body && (!header || !digest))) {
        throw new Error('Header bytes and digest must be provided together');
      }
      let receipt: SimplexUploadReceipt;
      if (certificateKind === 'notarization') {
        receipt = await client.uploadNotarization({
          view: certificateView,
          notarized: hexToBytes(certificateHex),
          ...(header && digest ? { header, digest, body } : {}),
        });
      } else {
        receipt = await client.uploadFinalization({
          view: certificateView,
          height: certificateHeight,
          finalized: hexToBytes(certificateHex),
          ...(header && digest ? { header, digest, body } : {}),
        });
      }
      showNotification(
        'success',
        'Simplex Certificate',
        `Stored at sequence ${formatSequence(receipt)}`,
      );
      setCertificateHex('');
    } catch (error) {
      showNotification('error', 'Simplex Certificate Failed', String(error));
    } finally {
      setIsUploadingCertificate(false);
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

  const readLatestFinalization = async () => {
    setIsReadingLatest(true);
    setLatestFinalization(null);
    setLatestFinalizationMissing(false);
    try {
      const finalization = await client.latestFinalization();
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

  const startSubscribe = () => {
    subscribeAbortRef.current?.abort();
    setStreamEvents([]);
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
        <h3>Upload Block</h3>
        <div className="form-row">
          <div className="form-group form-group-wide">
            <label htmlFor="simplex-block-digest">Digest Hex</label>
            <input
              id="simplex-block-digest"
              type="text"
              value={blockDigestHex}
              onChange={(event) => setBlockDigestHex(event.target.value)}
            />
          </div>
        </div>
        <div className="form-row">
          <div className="form-group form-group-wide">
            <label htmlFor="simplex-block-bytes">Header Hex</label>
            <textarea
              id="simplex-block-bytes"
              value={blockHeaderHex}
              onChange={(event) => setBlockHeaderHex(event.target.value)}
            />
          </div>
        </div>
        <div className="form-row">
          <div className="form-group form-group-wide">
            <label htmlFor="simplex-block-body">Body Hex</label>
            <textarea
              id="simplex-block-body"
              value={blockBodyHex}
              onChange={(event) => setBlockBodyHex(event.target.value)}
            />
          </div>
        </div>
        <button
          className={`btn-primary ${isUploadingBlock ? 'loading' : ''}`}
          onClick={uploadBlock}
          disabled={isUploadingBlock || !blockDigestHex.trim() || !blockHeaderHex.trim()}
        >
          {isUploadingBlock ? 'Uploading...' : 'Upload Block'}
        </button>
      </div>

      <div className="form-section">
        <h3>Upload Certificate</h3>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="simplex-certificate-kind">Kind</label>
            <select
              id="simplex-certificate-kind"
              value={certificateKind}
              onChange={(event) =>
                setCertificateKind(event.target.value as 'notarization' | 'finalization')
              }
            >
              <option value="notarization">notarization</option>
              <option value="finalization">finalization</option>
            </select>
          </div>
          <div className="form-group">
            <label htmlFor="simplex-certificate-view">View</label>
            <input
              id="simplex-certificate-view"
              type="number"
              min="0"
              value={certificateView}
              onChange={(event) => setCertificateView(event.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="simplex-certificate-height">Height</label>
            <input
              id="simplex-certificate-height"
              type="number"
              min="0"
              value={certificateHeight}
              onChange={(event) => setCertificateHeight(event.target.value)}
              disabled={certificateKind !== 'finalization'}
            />
          </div>
        </div>
        <div className="form-row">
          <div className="form-group form-group-wide">
            <label htmlFor="simplex-certificate-bytes">Certificate Record Hex</label>
            <textarea
              id="simplex-certificate-bytes"
              value={certificateHex}
              onChange={(event) => setCertificateHex(event.target.value)}
            />
          </div>
        </div>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="simplex-certificate-block-digest">Block Digest Hex</label>
            <input
              id="simplex-certificate-block-digest"
              type="text"
              value={certificateBlockDigestHex}
              onChange={(event) => setCertificateBlockDigestHex(event.target.value)}
            />
          </div>
          <div className="form-group form-group-wide">
            <label htmlFor="simplex-certificate-block">Header Hex</label>
            <textarea
              id="simplex-certificate-block"
              value={certificateHeaderHex}
              onChange={(event) => setCertificateHeaderHex(event.target.value)}
            />
          </div>
          <div className="form-group form-group-wide">
            <label htmlFor="simplex-certificate-body">Body Hex</label>
            <textarea
              id="simplex-certificate-body"
              value={certificateBodyHex}
              onChange={(event) => setCertificateBodyHex(event.target.value)}
            />
          </div>
        </div>
        <button
          className={`btn-primary ${isUploadingCertificate ? 'loading' : ''}`}
          onClick={uploadCertificate}
          disabled={
            isUploadingCertificate ||
            !certificateView.trim() ||
            !certificateHex.trim() ||
            (certificateKind === 'finalization' && !certificateHeight.trim())
          }
        >
          {isUploadingCertificate ? 'Uploading...' : 'Upload Certificate'}
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
          <button
            className={`btn-secondary ${isReadingLatest ? 'loading' : ''}`}
            onClick={readLatestFinalization}
            disabled={isReadingLatest || verifierStatus !== 'ready'}
          >
            {isReadingLatest ? 'Loading...' : 'Latest Finalization'}
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
        {latestFinalization && (
          <div className="result fade-in">
            <h4>Latest Finalization</h4>
            <pre>{renderCertificate(latestFinalization)}</pre>
          </div>
        )}
        {latestFinalizationMissing && (
          <div className="result fade-in">
            <h4>No Finalization</h4>
            <p>No finalized height index is stored.</p>
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
            onClick={() => setStreamEvents([])}
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
              {streamEvents.map(({ sequenceNumber, entry }, index) => {
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
                    key={`${sequenceNumber.toString()}-${index}`}
                    className="result-row-block"
                  >
                    <p><strong>Sequence:</strong> {sequenceNumber.toString()}</p>
                    <p><strong>Entry:</strong> {title}</p>
                    <pre>{renderCertificate(entry.certificate)}</pre>
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
