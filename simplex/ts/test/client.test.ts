import assert from 'node:assert/strict';
import test from 'node:test';
import { Client, StoreWriteBatch } from '@exowarexyz/sdk';
import {
  SimplexClient,
  SimplexRecordKind,
  createCommonwareSimplexVerifier,
  createWasmSimplexVerifier,
  blockByDigestKey,
  bytesToHex,
  finalizationByViewKey,
  finalizedByHeightKey,
  hexToBytes,
  notarizationByViewKey,
  rangeForKind,
  type SimplexCertificateVerifier,
} from '../src/index.js';

test('hex helpers round trip optional 0x prefix', () => {
  assert.deepEqual(Array.from(hexToBytes('0x000102ff')), [0, 1, 2, 255]);
  assert.equal(bytesToHex(new Uint8Array([0, 1, 2, 255])), '000102ff');
  assert.throws(() => hexToBytes('abc'), /even-length/);
});

test('simplex keys match the Rust key layout', () => {
  assert.equal(bytesToHex(blockByDigestKey('aabbcc')), '0010aabbcc');
  assert.equal(bytesToHex(finalizedByHeightKey(258n)), '00310000000000000102');
  const range = rangeForKind(SimplexRecordKind.FinalizedByHeight);
  assert.equal(bytesToHex(range.start), '0031');
  assert.equal(bytesToHex(range.end), '0032');
});

test('stages block and finalization rows into one StoreWriteBatch', () => {
  const store = new Client('http://127.0.0.1:1').store();
  const simplex = new SimplexClient(store);
  const upload = simplex.prepareFinalization({
    view: 7,
    height: 11,
    digest: 'd0',
    block: 'b0',
    finalized: 'f1',
  });
  assert.deepEqual(upload.summary, {
    blocks: 1,
    notarizations: 0,
    finalizations: 1,
    finalizedHeightIndexes: 1,
  });

  const batch = simplex.stageUpload(upload, new StoreWriteBatch());
  assert.equal(batch.length, 3);
  assert.deepEqual(
    batch.entries().map((entry) => bytesToHex(entry.key)),
    ['0010d0', '00300000000000000007', '0031000000000000000b'],
  );
});

test('certificate getters require and apply a verifier', async () => {
  const store = new Client('http://127.0.0.1:1').store();
  const rows = new Map<string, Uint8Array>([
    [bytesToHex(notarizationByViewKey(3)), new Uint8Array([0xa3])],
    [bytesToHex(finalizationByViewKey(4)), new Uint8Array([0xf4])],
  ]);
  store.get = async (key: Uint8Array) => {
    const value = rows.get(bytesToHex(key));
    return value ? { value } : null;
  };

  await assert.rejects(
    () => new SimplexClient(store).getNotarization(3),
    /requires a configured verifier/,
  );

  const verifier: SimplexCertificateVerifier<{ view: bigint }, { index: string }> = {
    verifyNotarization: (bytes, context) =>
      bytes[0] === 0xa3 ? { view: context.view } : null,
    verifyFinalization: (bytes, context) =>
      bytes[0] === 0xf4 ? { index: context.index } : null,
  };
  const simplex = new SimplexClient(store, { verifier });

  assert.deepEqual(await simplex.getNotarization(3), { view: 3n });
  assert.deepEqual(await simplex.getFinalizationByView(4), { index: 'view' });
  assert.deepEqual(await simplex.getNotarizationRaw(3), new Uint8Array([0xa3]));
});

test('WASM verifier adapter passes opaque bytes and configured key', () => {
  const verifier = createWasmSimplexVerifier(
    {
      parse_notarized: (key, bytes) => ({
        key: bytesToHex(key),
        bytes: bytesToHex(bytes),
      }),
      parse_finalized: (key, bytes) => ({
        key: bytesToHex(key),
        bytes: bytesToHex(bytes),
      }),
    },
    '0xabcd',
  );

  assert.deepEqual(
    verifier.verifyNotarization(new Uint8Array([1, 2]), {
      kind: 'notarization',
      source: 'get',
      key: notarizationByViewKey(1),
      value: new Uint8Array([1, 2]),
      view: 1n,
    }),
    { key: 'abcd', bytes: '0102' },
  );
});

test('Commonware WASM verifier adapter is scheme-parameterized', async () => {
  const verifier = createCommonwareSimplexVerifier(
    {
      verify_notarized_commonware: (scheme, namespace, material, bytes) => ({
        scheme,
        view: 11n,
        parent: 10n,
        payload: namespace,
        certificate: material,
        block: bytes,
      }),
      verify_finalized_commonware: (scheme, namespace, material, bytes) => ({
        scheme,
        view: '12',
        parent: 11,
        payload: Array.from(namespace),
        certificate: Array.from(material),
        block: Array.from(bytes),
      }),
    },
    {
      scheme: 'bls12381-threshold-vrf-min-sig',
      namespace: '0a',
      verificationMaterial: '0b',
    },
  );

  assert.deepEqual(
    await verifier.verifyNotarization(new Uint8Array([0xc0]), {
      kind: 'notarization',
      source: 'get',
      key: notarizationByViewKey(11),
      value: new Uint8Array([0xc0]),
      view: 11n,
    }),
    {
      scheme: 'bls12381-threshold-vrf-min-sig',
      view: 11n,
      parent: 10n,
      payload: new Uint8Array([0x0a]),
      certificate: new Uint8Array([0x0b]),
      block: new Uint8Array([0xc0]),
    },
  );

  assert.deepEqual(
    await verifier.verifyFinalization(new Uint8Array([0xd0]), {
      kind: 'finalization',
      index: 'view',
      source: 'get',
      key: finalizationByViewKey(12),
      value: new Uint8Array([0xd0]),
      view: 12n,
    }),
    {
      scheme: 'bls12381-threshold-vrf-min-sig',
      view: 12n,
      parent: 11n,
      payload: new Uint8Array([0x0a]),
      certificate: new Uint8Array([0x0b]),
      block: new Uint8Array([0xd0]),
    },
  );
});

test('streams and verifies certificate entries', async () => {
  const store = new Client('http://127.0.0.1:1').store();
  let capturedFilters: unknown;
  store.subscribe = async function* (filters) {
    capturedFilters = filters;
    yield {
      sequenceNumber: 12n,
      entries: [
        {
          key: notarizationByViewKey(7),
          value: new Uint8Array([0x70]),
        },
        {
          key: finalizationByViewKey(8),
          value: new Uint8Array([0x80]),
        },
        {
          key: finalizedByHeightKey(9),
          value: new Uint8Array([0x90]),
        },
      ],
    };
  };

  const verifier: SimplexCertificateVerifier<{ view: bigint }, { marker: number }> = {
    verifyNotarization: (bytes, context) =>
      bytes[0] === 0x70 ? { view: context.view } : null,
    verifyFinalization: (bytes) => ({ marker: bytes[0] }),
  };
  const simplex = new SimplexClient(store, { verifier });

  const batches = [];
  for await (const batch of simplex.subscribeCertificates({
    includeFinalizedByHeight: true,
    sinceSequenceNumber: 10n,
  })) {
    batches.push(batch);
  }

  assert.deepEqual(capturedFilters, {
    matchKeys: [
      { reservedBits: 16, prefix: 0x0020, payloadRegex: '(?s-u).*' },
      { reservedBits: 16, prefix: 0x0030, payloadRegex: '(?s-u).*' },
      { reservedBits: 16, prefix: 0x0031, payloadRegex: '(?s-u).*' },
    ],
    sinceSequenceNumber: 10n,
  });
  assert.equal(batches.length, 1);
  assert.deepEqual(
    batches[0].entries.map((entry) => entry.certificate),
    [{ view: 7n }, { marker: 0x80 }, { marker: 0x90 }],
  );
});
