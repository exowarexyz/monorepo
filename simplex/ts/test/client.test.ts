import assert from 'node:assert/strict';
import test from 'node:test';
import { Client, StoreWriteBatch } from '@exowarexyz/sdk';
import {
  SimplexClient,
  SimplexRecordKind,
  headerByDigestKey,
  createSimplexVerifier,
  createWasmSimplexBlockVerifier,
  createWasmSimplexHeaderVerifier,
  blockByDigestKey,
  bytesToHex,
  decodeSimplexBlockData,
  encodeSimplexBlockData,
  finalizedByHeightKey,
  hexToBytes,
  normalizeU64,
  notarizationByRoundKey,
  finalizationByRoundKey,
  rangeForKind,
  type SimplexCertificateVerifier,
} from '../src/index.js';

test('hex helpers round trip optional 0x prefix', () => {
  assert.deepEqual(Array.from(hexToBytes('0x000102ff')), [0, 1, 2, 255]);
  assert.equal(bytesToHex(new Uint8Array([0, 1, 2, 255])), '000102ff');
  assert.throws(() => hexToBytes('abc'), /even-length/);
});

test('simplex keys match the Rust key layout', () => {
  // simplex/rs/src/keys.rs::tests::key_layout asserts the same bytes
  const digest = 'ab'.repeat(32);
  assert.equal(bytesToHex(headerByDigestKey(digest)), `01${digest}`);
  assert.equal(bytesToHex(blockByDigestKey(digest)), `02${digest}`);
  assert.equal(bytesToHex(notarizationByRoundKey(0x100000000n, 7)), '0300000001000000000000000000000007');
  assert.equal(bytesToHex(finalizationByRoundKey(0x100000000n, 7)), '0400000001000000000000000000000007');
  assert.equal(bytesToHex(finalizedByHeightKey(258n)), '050000000000000102');
  const range = rangeForKind(SimplexRecordKind.FinalizedByHeight);
  assert.equal(bytesToHex(range.start), '05');
  assert.equal(bytesToHex(range.end), '06');
});

test('u64 helper rejects unsafe JavaScript numbers', () => {
  assert.equal(normalizeU64(Number.MAX_SAFE_INTEGER).toString(), '9007199254740991');
  assert.throws(() => normalizeU64(Number.MAX_SAFE_INTEGER + 1), /safe integer/);
});

test('stages block and finalization rows into one StoreWriteBatch', () => {
  const store = new Client('http://127.0.0.1:1').store();
  const simplex = new SimplexClient(store);
  assert.deepEqual(simplex.prepareHeader({ digest: 'c0', header: 'a0' }), {
    entries: [{ key: headerByDigestKey('c0'), value: new Uint8Array([0xa0]) }],
    summary: {
      headers: 1,
      blocks: 0,
      notarizations: 0,
      finalizations: 0,
      finalizedHeightIndexes: 0,
    },
  });

  const block = simplex.prepareBlock({ digest: 'd0', header: 'b0', body: 'c0c1' });
  const finalization = simplex.prepareFinalization({
    epoch: 0,
    view: 7,
    height: 11,
    finalized: 'f1',
  });
  assert.deepEqual(block.summary, {
    headers: 1,
    blocks: 1,
    notarizations: 0,
    finalizations: 0,
    finalizedHeightIndexes: 0,
  });
  assert.deepEqual(finalization.summary, {
    headers: 0,
    blocks: 0,
    notarizations: 0,
    finalizations: 1,
    finalizedHeightIndexes: 1,
  });

  const batch = simplex.stageUpload(block, new StoreWriteBatch());
  simplex.stageUpload(finalization, batch);
  assert.equal(batch.length, 4);
  assert.deepEqual(
    batch.entries().map((entry) => bytesToHex(entry.key)),
    ['01d0', '02d0', '0400000000000000000000000000000007', '05000000000000000b'],
  );
  assert.deepEqual(decodeSimplexBlockData(batch.entries()[1].value), {
    header: new Uint8Array([0xb0]),
    body: new Uint8Array([0xc0, 0xc1]),
  });
});

test('streams header and full block data separately', async () => {
  const store = new Client('http://127.0.0.1:1').store();
  const full = encodeSimplexBlockData('aa', 'bbcc');
  store.subscribe = async function* () {
    yield {
      sequenceNumber: 4n,
      entries: [
        { key: headerByDigestKey('01'), value: new Uint8Array([0xaa]) },
        { key: blockByDigestKey('01'), value: full },
      ],
    };
  };

  const simplex = new SimplexClient(store);
  const headerBatches = [];
  for await (const batch of simplex.subscribeHeaders()) {
    headerBatches.push(batch);
  }
  assert.deepEqual(headerBatches[0].entries, [
    {
      type: 'header',
      key: headerByDigestKey('01'),
      digest: new Uint8Array([0x01]),
      header: new Uint8Array([0xaa]),
    },
  ]);

  const blockBatches = [];
  for await (const batch of simplex.subscribeBlocks()) {
    blockBatches.push(batch);
  }
  assert.deepEqual(blockBatches[0].entries, [
    {
      type: 'block',
      key: blockByDigestKey('01'),
      digest: new Uint8Array([0x01]),
      raw: full,
      header: new Uint8Array([0xaa]),
      body: new Uint8Array([0xbb, 0xcc]),
    },
  ]);
});

test('certificate getters require and apply a verifier', async () => {
  const store = new Client('http://127.0.0.1:1').store();
  const rows = new Map<string, Uint8Array>([
    [bytesToHex(notarizationByRoundKey(0, 3)), new Uint8Array([0xa3])],
    [bytesToHex(finalizationByRoundKey(0, 4)), new Uint8Array([0xf4])],
  ]);
  store.get = async (key: Uint8Array) => {
    const value = rows.get(bytesToHex(key));
    return value ? { value } : null;
  };

  await assert.rejects(
    () => new SimplexClient(store).getNotarizationByRound(0, 3),
    /requires a configured verifier/,
  );

  const verifier: SimplexCertificateVerifier<{ view: bigint }, { index: string }> = {
    verifyNotarization: (bytes, context) =>
      bytes[0] === 0xa3 ? { view: context.view } : null,
    verifyFinalization: (bytes, context) =>
      bytes[0] === 0xf4 ? { index: context.index } : null,
  };
  const simplex = new SimplexClient(store, { verifier });

  assert.deepEqual(await simplex.getNotarizationByRound(0, 3), { view: 3n });
  assert.deepEqual(await simplex.getFinalizationByRound(0, 4), { index: 'round' });
  assert.deepEqual(await simplex.getNotarizationByRoundRaw(0, 3), new Uint8Array([0xa3]));
});

test('WASM header verifier adapter passes payload and header', () => {
  const calls: string[] = [];
  const verifyHeader = createWasmSimplexHeaderVerifier({
    verify_header: (payload, header) => {
      calls.push([bytesToHex(payload), bytesToHex(header)].join(':'));
      return bytesToHex(payload) === 'aa' && bytesToHex(header) === 'bb';
    },
  });

  assert.equal(
    verifyHeader({
      certificate: {
        scheme: 'ed25519',
        epoch: 0n,
        view: 1n,
        parent: 0n,
        payload: new Uint8Array([0xaa]),
        certificate: new Uint8Array([0xcc]),
        header: new Uint8Array([0xbb]),
      },
      context: {
        kind: 'notarization',
        source: 'get',
        key: notarizationByRoundKey(0, 1),
        value: new Uint8Array([0xee]),
        epoch: 0n,
        view: 1n,
      },
      raw: new Uint8Array([0xee]),
      payload: new Uint8Array([0xaa]),
      header: new Uint8Array([0xbb]),
    }),
    true,
  );
  assert.deepEqual(calls, ['aa:bb']);
  assert.throws(() => createWasmSimplexHeaderVerifier({} as never), /missing verify_header/);
});

test('WASM block verifier adapter passes payload, header, and body', () => {
  const calls: string[] = [];
  const verifyBlock = createWasmSimplexBlockVerifier({
    verify_block: (payload, header, body) => {
      calls.push([bytesToHex(payload), bytesToHex(header), bytesToHex(body)].join(':'));
      return bytesToHex(payload) === 'aa' && bytesToHex(header) === 'bb';
    },
  });

  assert.equal(
    verifyBlock({
      certificate: {
        scheme: 'ed25519',
        epoch: 0n,
        view: 1n,
        parent: 0n,
        payload: new Uint8Array([0xaa]),
        certificate: new Uint8Array([0xcc]),
        header: new Uint8Array([0xbb]),
      },
      context: {
        kind: 'notarization',
        source: 'get',
        key: notarizationByRoundKey(0, 1),
        value: new Uint8Array([0xee]),
        epoch: 0n,
        view: 1n,
      },
      raw: new Uint8Array([0xee]),
      payload: new Uint8Array([0xaa]),
      header: new Uint8Array([0xbb]),
      body: new Uint8Array([0xdd]),
    }),
    true,
  );
  assert.deepEqual(calls, ['aa:bb:dd']);
  assert.throws(() => createWasmSimplexBlockVerifier({} as never), /missing verify_block/);
});

test('Simplex WASM verifier adapter is scheme-parameterized', async () => {
  const headerVerifications: string[] = [];
  const verifier = createSimplexVerifier(
    {
      verify_notarized_payload: (payload, identity, _scheme, namespace, material, bytes) => ({
        epoch: 0n,
        view: 11n,
        parent: 10n,
        payload: payload === 'sha256' ? namespace : new Uint8Array(),
        certificate: material,
        header: bytes,
      }),
      verify_finalized_payload: (payload, identity, _scheme, namespace, material, bytes) => ({
        epoch: 0n,
        view: 12n,
        parent: 11n,
        payload: payload === 'sha256' ? Array.from(namespace) : [],
        certificate: Array.from(material),
        header: Array.from(bytes),
      }),
    },
    {
      scheme: 'bls12381-threshold-vrf-min-sig',
      payload: 'sha256',
      identity: 'ed25519',
      namespace: '0a',
      verificationMaterial: '0b',
      verifyHeader: ({ payload, header, raw, context }) => {
        headerVerifications.push(
          [
            context.kind,
            bytesToHex(payload),
            bytesToHex(header),
            bytesToHex(raw),
          ].join(':'),
        );
        return true;
      },
    },
  );

  assert.deepEqual(
    await verifier.verifyNotarization(new Uint8Array([0xc0]), {
      kind: 'notarization',
      source: 'get',
      key: notarizationByRoundKey(0, 11),
      value: new Uint8Array([0xc0]),
      epoch: 0n,
      view: 11n,
    }),
    {
      scheme: 'bls12381-threshold-vrf-min-sig',
      epoch: 0n,
      view: 11n,
      parent: 10n,
      payload: new Uint8Array([0x0a]),
      certificate: new Uint8Array([0x0b]),
      header: new Uint8Array([0xc0]),
    },
  );

  assert.deepEqual(
    await verifier.verifyFinalization(new Uint8Array([0xd0]), {
      kind: 'finalization',
      index: 'round',
      source: 'get',
      key: finalizationByRoundKey(0, 12),
      value: new Uint8Array([0xd0]),
      epoch: 0n,
      view: 12n,
    }),
    {
      scheme: 'bls12381-threshold-vrf-min-sig',
      epoch: 0n,
      view: 12n,
      parent: 11n,
      payload: new Uint8Array([0x0a]),
      certificate: new Uint8Array([0x0b]),
      header: new Uint8Array([0xd0]),
    },
  );
  assert.deepEqual(headerVerifications, [
    'notarization:0a:c0:c0',
    'finalization:0a:d0:d0',
  ]);
});

test('Simplex WASM verifier adapter supports coding commitment payloads', async () => {
  const calls: string[] = [];
  const verifier = createSimplexVerifier(
    {
      verify_notarized_payload: (payload, identity, scheme, namespace, material, bytes) => {
        calls.push(`notarized:${payload}:${identity}:${scheme}:${bytesToHex(bytes)}`);
        return {
          epoch: 0n,
          view: 3n,
          parent: 2n,
          payload: namespace,
          certificate: material,
          header: bytes,
        };
      },
      verify_finalized_payload: (payload, identity, scheme, namespace, material, bytes) => {
        calls.push(`finalized:${payload}:${identity}:${scheme}:${bytesToHex(bytes)}`);
        return {
          epoch: 0n,
          view: 4n,
          parent: 3n,
          payload: namespace,
          certificate: material,
          header: bytes,
        };
      },
    },
    {
      scheme: 'bls12381-threshold-standard-min-sig',
      payload: 'coding-commitment',
      identity: 'ed25519',
      namespace: 'aa',
      verificationMaterial: 'bb',
    },
  );

  await verifier.verifyNotarization(new Uint8Array([0xc1]), {
    kind: 'notarization',
    source: 'get',
    key: notarizationByRoundKey(0, 3),
    value: new Uint8Array([0xc1]),
    epoch: 0n,
    view: 3n,
  });
  await verifier.verifyFinalization(new Uint8Array([0xd1]), {
    kind: 'finalization',
    index: 'round',
    source: 'get',
    key: finalizationByRoundKey(0, 4),
    value: new Uint8Array([0xd1]),
    epoch: 0n,
    view: 4n,
  });

  assert.deepEqual(calls, [
    'notarized:coding-commitment:ed25519:bls12381-threshold-standard-min-sig:c1',
    'finalized:coding-commitment:ed25519:bls12381-threshold-standard-min-sig:d1',
  ]);
});

test('Simplex WASM verifier adapter passes non-SHA payloads through', async () => {
  const calls: string[] = [];
  const verifier = createSimplexVerifier(
    {
      verify_notarized_payload: (payload, identity, scheme, namespace, material, bytes) => {
        calls.push(`notarized:${payload}:${identity}:${scheme}:${bytesToHex(bytes)}`);
        return {
          epoch: 0n,
          view: 5n,
          parent: 4n,
          payload: namespace,
          certificate: material,
          header: bytes,
        };
      },
      verify_finalized_payload: (payload, identity, scheme, namespace, material, bytes) => {
        calls.push(`finalized:${payload}:${identity}:${scheme}:${bytesToHex(bytes)}`);
        return {
          epoch: 0n,
          view: 6n,
          parent: 5n,
          payload: namespace,
          certificate: material,
          header: bytes,
        };
      },
    },
    {
      scheme: 'ed25519',
      payload: 'blake3',
      identity: 'ed25519',
      namespace: '01',
      verificationMaterial: '02',
    },
  );

  await verifier.verifyNotarization(new Uint8Array([0xa1]), {
    kind: 'notarization',
    source: 'get',
    key: notarizationByRoundKey(0, 5),
    value: new Uint8Array([0xa1]),
    epoch: 0n,
    view: 5n,
  });
  await verifier.verifyFinalization(new Uint8Array([0xb1]), {
    kind: 'finalization',
    index: 'round',
    source: 'get',
    key: finalizationByRoundKey(0, 6),
    value: new Uint8Array([0xb1]),
    epoch: 0n,
    view: 6n,
  });

  assert.deepEqual(calls, [
    'notarized:blake3:ed25519:ed25519:a1',
    'finalized:blake3:ed25519:ed25519:b1',
  ]);
});

test('Simplex WASM verifier adapter rejects failed header verification', async () => {
  const verifier = createSimplexVerifier(
    {
      verify_notarized_payload: () => ({
        scheme: 'ed25519',
        epoch: 0n,
        view: 1n,
        parent: 0n,
        payload: [0x01],
        certificate: [0x02],
        header: [0x03],
      }),
      verify_finalized_payload: () => null,
    },
    {
      scheme: 'ed25519',
      payload: 'sha256',
      identity: 'ed25519',
      namespace: '',
      verificationMaterial: '',
      verifyHeader: () => false,
    },
  );

  assert.equal(
    await verifier.verifyNotarization(new Uint8Array([0xc0]), {
      kind: 'notarization',
      source: 'get',
      key: notarizationByRoundKey(0, 1),
      value: new Uint8Array([0xc0]),
      epoch: 0n,
      view: 1n,
    }),
    null,
  );
});

test('Simplex WASM verifier adapter propagates verifier errors', async () => {
  const verifier = createSimplexVerifier(
    {
      verify_notarized_payload: () => {
        throw new Error('failed to decode notarized artifact: bad bytes');
      },
      verify_finalized_payload: () => {
        throw new Error('finalization certificate verification failed');
      },
    },
    {
      scheme: 'ed25519',
      payload: 'sha256',
      identity: 'ed25519',
      namespace: '',
      verificationMaterial: '',
    },
  );

  await assert.rejects(
    async () => verifier.verifyNotarization(new Uint8Array([0xc0]), {
      kind: 'notarization',
      source: 'get',
      key: notarizationByRoundKey(0, 1),
      value: new Uint8Array([0xc0]),
      epoch: 0n,
      view: 1n,
    }),
    /failed to decode notarized artifact: bad bytes/,
  );

  await assert.rejects(
    async () => verifier.verifyFinalization(new Uint8Array([0xd0]), {
      kind: 'finalization',
      index: 'round',
      source: 'get',
      key: finalizationByRoundKey(0, 2),
      value: new Uint8Array([0xd0]),
      epoch: 0n,
      view: 2n,
    }),
    /finalization certificate verification failed/,
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
          key: notarizationByRoundKey(0, 7),
          value: new Uint8Array([0x70]),
        },
        {
          key: finalizationByRoundKey(0, 8),
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
    selectors: [
      { prefix: rangeForKind(SimplexRecordKind.NotarizationByRound).start, payloadRegex: '(?s-u).*' },
      { prefix: rangeForKind(SimplexRecordKind.FinalizationByRound).start, payloadRegex: '(?s-u).*' },
      { prefix: rangeForKind(SimplexRecordKind.FinalizedByHeight).start, payloadRegex: '(?s-u).*' },
    ],
    sinceSequenceNumber: 10n,
  });
  assert.equal(batches.length, 1);
  assert.deepEqual(
    batches[0].entries.map((entry) => entry.certificate),
    [{ view: 7n }, { marker: 0x80 }, { marker: 0x90 }],
  );
});

test('round getters and streams distinguish epochs at the same view', async () => {
  const store = new Client('http://127.0.0.1:1').store();
  const entries = [2, 3].flatMap((epoch) => [
    { key: notarizationByRoundKey(epoch, 7), value: new Uint8Array([epoch]) },
    { key: finalizationByRoundKey(epoch, 7), value: new Uint8Array([epoch]) },
  ]);
  const rows = new Map(entries.map(({ key, value }) => [bytesToHex(key), value]));
  const requestedKeys: string[] = [];
  store.get = async (key) => {
    requestedKeys.push(bytesToHex(key));
    const value = rows.get(bytesToHex(key));
    return value ? { value } : null;
  };
  const certificate = (bytes: Uint8Array) => ({
    scheme: 'ed25519', epoch: BigInt(bytes[0]), view: 7n, parent: 6n,
    payload: [], certificate: [], header: [],
  });
  const verifier = createSimplexVerifier({
    verify_notarized_payload: (_payload, _identity, _scheme, _namespace, _material, bytes) => certificate(bytes),
    verify_finalized_payload: (_payload, _identity, _scheme, _namespace, _material, bytes) => certificate(bytes),
  }, { scheme: 'ed25519', payload: 'sha256', identity: 'ed25519', namespace: '', verificationMaterial: '' });
  const simplex = new SimplexClient(store, { verifier });
  for (const epoch of [2, 3]) {
    assert.equal((await simplex.getNotarizationByRound(epoch, 7))?.epoch, BigInt(epoch));
    assert.equal((await simplex.getFinalizationByRound(epoch, 7))?.epoch, BigInt(epoch));
    assert.deepEqual(await simplex.getNotarizationByRoundRaw(epoch, 7), new Uint8Array([epoch]));
    assert.deepEqual(await simplex.getFinalizationByRoundRaw(epoch, 7), new Uint8Array([epoch]));
  }

  requestedKeys.length = 0;
  assert.equal(await simplex.getNotarizationByRound(4, 7), null);
  assert.equal(await simplex.getFinalizationByRound(4, 7), null);
  assert.deepEqual(requestedKeys, [
    bytesToHex(notarizationByRoundKey(4, 7)),
    bytesToHex(finalizationByRoundKey(4, 7)),
  ]);

  store.subscribe = async function* () {
    yield { sequenceNumber: 12n, entries };
  };
  const rounds = [];
  for await (const batch of simplex.subscribeCertificates()) {
    for (const entry of batch.entries) {
      assert.ok('epoch' in entry);
      assert.equal(entry.certificate.epoch, entry.epoch);
      rounds.push([entry.type, entry.certificate.epoch, entry.certificate.view]);
    }
  }
  assert.deepEqual(rounds, [
    ['notarization', 2n, 7n],
    ['finalization', 2n, 7n],
    ['notarization', 3n, 7n],
    ['finalization', 3n, 7n],
  ]);
});

test('built-in certificate verification binds epoch and view to the request', async () => {
  const certificate = { scheme: 'ed25519', epoch: 2n, view: 7n, parent: 6n, payload: [], certificate: [], header: [] };
  const verifier = createSimplexVerifier({ verify_notarized_payload: () => certificate, verify_finalized_payload: () => certificate },
    { scheme: 'ed25519', payload: 'sha256', identity: 'ed25519', namespace: '', verificationMaterial: '' });
  const context = { kind: 'notarization' as const, source: 'get' as const, key: notarizationByRoundKey(2, 7), value: new Uint8Array(), epoch: 2n, view: 7n };
  assert.ok(await verifier.verifyNotarization(new Uint8Array(), context));
  assert.equal(await verifier.verifyNotarization(new Uint8Array(), { ...context, view: 8n }), null);
  assert.equal(await verifier.verifyNotarization(new Uint8Array(), { ...context, epoch: 3n }), null);
  assert.notDeepEqual(notarizationByRoundKey(2, 7), notarizationByRoundKey(3, 7));

  // The bundled WASM emits u64 fields as BigInt, so nothing else is accepted
  const numeric = createSimplexVerifier({ verify_notarized_payload: () => ({ ...certificate, epoch: 2 }), verify_finalized_payload: () => certificate },
    { scheme: 'ed25519', payload: 'sha256', identity: 'ed25519', namespace: '', verificationMaterial: '' });
  await assert.rejects(async () => numeric.verifyNotarization(new Uint8Array(), context), /invalid epoch/);
});

test('latest finalization passes the indexed height to the verifier', async () => {
  const store = new Client('http://127.0.0.1:1').store();
  store.query = async () => ({
    results: [{ key: finalizedByHeightKey(11), value: new Uint8Array([0xb0]) }],
  });
  const verifier: SimplexCertificateVerifier<unknown, { height: bigint }> = {
    verifyNotarization: () => null,
    verifyFinalization: (bytes, context) => {
      assert.equal(bytes[0], 0xb0);
      assert.equal(context.kind, 'finalization');
      assert.equal(context.index, 'latest');
      return context.index === 'latest' ? { height: context.height } : null;
    },
  };
  const simplex = new SimplexClient(store, { verifier });
  assert.deepEqual(await simplex.latestFinalization(), { height: 11n });
  assert.deepEqual(await simplex.latestFinalizationRaw(), new Uint8Array([0xb0]));
});

test('certificate streams reject round keys of the wrong width', async () => {
  const store = new Client('http://127.0.0.1:1').store();
  store.subscribe = async function* () {
    yield {
      sequenceNumber: 1n,
      entries: [{ key: notarizationByRoundKey(0, 7).slice(0, 16), value: new Uint8Array([0x70]) }],
    };
  };
  const verifier: SimplexCertificateVerifier = {
    verifyNotarization: () => null,
    verifyFinalization: () => null,
  };
  const simplex = new SimplexClient(store, { verifier });
  await assert.rejects(async () => {
    for await (const batch of simplex.subscribeCertificates()) {
      assert.fail(`decoded a malformed key: ${batch.entries.length}`);
    }
  }, /invalid simplex round key length/);
});
