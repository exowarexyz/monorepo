import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fromBinary, toBinary } from '@bufbuild/protobuf';
import { initQmdbWasm, QmdbProofVerifier } from '../dist/index.js';
import {
  HistoricalMultiProofSchema,
  HistoricalOperationRangeProofSchema,
} from '../dist/generated/proto/qmdb/v1/proof_pb.js';

const bytes = (hex) => Buffer.from(hex, 'hex');
const wasm = readFileSync(new URL('../dist/generated/wasm/exoware_qmdb_wasm_bg.wasm', import.meta.url));
const fixture = (path) => readFileSync(new URL(`fixtures/${path}.txt`, import.meta.url), 'utf8').trim().split('\n');
const flip = (value) => { const copy = Buffer.from(value); copy[0] ^= 1; return copy; };

function rangeFixture(name) {
  const [root, window, proof] = fixture(`variants/${name}`);
  const [tip, startLocation, maxLocations] = window.split(' ');
  return {
    root: bytes(root), proof: bytes(proof),
    request: { tip: BigInt(tip), startLocation: BigInt(startLocation), maxLocations: Number(maxLocations) },
  };
}

function multiFixture(name) {
  const [root, request, proof, ...operations] = fixture(`operations/${name}`);
  const [tip, locations] = request.split(' ');
  return { root: bytes(root), proof: bytes(proof), tip: BigInt(tip), locations: locations.split(',').map(BigInt), operations: operations.map(bytes) };
}

test('public verifier initializes from supplied WASM and verifies without transport', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', () => { throw new Error('unexpected transport'); });
  const first = initQmdbWasm(wasm);
  assert.equal(first, initQmdbWasm());
  await first;
  const data = rangeFixture('any_unordered_fixed_fixed_keys_fixed_values_mmr');
  const verifier = new QmdbProofVerifier();
  const verified = await verifier.verifyFixedUnorderedUpdate(data.proof, data.request, data.root, data.request.startLocation + 1n, Buffer.alloc(32, 0x11), 32);
  assert.deepEqual(Buffer.from(verified.root), data.root);
  assert.equal(verified.location, data.request.startLocation + 1n);
  assert.equal(verified.proofSizeBytes, data.proof.length);
  assert.equal(verified.value.length, 32);
  assert.equal(fetch.mock.callCount(), 0);
});

for (const merkleFamily of ['mmr', 'mmb']) {
  test(`raw range verifier binds account context (${merkleFamily})`, async () => {
    await initQmdbWasm(wasm);
    const { proof, root, request } = rangeFixture(`any_unordered_fixed_fixed_keys_fixed_values_${merkleFamily}`);
    const verifier = new QmdbProofVerifier({ merkleFamily });
    const key = Buffer.alloc(32, 0x11);
    const location = request.startLocation + 1n;
    const verify = (p = proof, r = request, expectedRoot = root, loc = location, k = key, size = 32) =>
      verifier.verifyFixedUnorderedUpdate(p, r, expectedRoot, loc, k, size);
    const verified = await verify();
    assert.equal(verified.location, location);
    const raw = await verifier.verifyOperationRange(proof, request, root);
    assert.deepEqual(Buffer.from(verified.value), Buffer.from(raw.operations[1].encodedOperation.subarray(33, 65)));
    await assert.rejects(verify(proof, request, flip(root)));
    await assert.rejects(verify(proof, { ...request, tip: request.tip + 1n }));
    await assert.rejects(verify(proof, { ...request, startLocation: request.startLocation + 1n }));
    await assert.rejects(verify(proof, { ...request, maxLocations: 1 }));
    await assert.rejects(verify(proof, request, root, request.tip + 1n));
    await assert.rejects(verify(proof, request, root, location, flip(key)));
    await assert.rejects(verify(proof, request, root, location, key, 31));
    await assert.rejects(verify(proof.subarray(0, proof.length - 1)));
    const changed = fromBinary(HistoricalOperationRangeProofSchema, proof);
    changed.encodedOperations[1] = flip(changed.encodedOperations[1]);
    await assert.rejects(verify(toBinary(HistoricalOperationRangeProofSchema, changed)));
  });
}

test('keyless multiproof binds values to exact locations and tip', async () => {
  await initQmdbWasm(wasm);
  const data = multiFixture('keyless_fixed_full_fixed_values_mmr');
  const verifier = new QmdbProofVerifier();
  const expected = data.locations.map((location, i) => ({ location, value: data.operations[i].subarray(1, 17) }));
  const verify = (proof = data.proof, request = { tip: data.tip }, root = data.root, values = expected) =>
    verifier.verifyFixedKeylessAppendMany(proof, request, root, values);
  const verified = await verify(data.proof, { tip: data.tip }, data.root, [...expected].reverse());
  assert.deepEqual(verified.operations.map(({ location }) => location), data.locations);
  assert.deepEqual(verified.operations.map(({ value }) => Buffer.from(value)), expected.map(({ value }) => Buffer.from(value)));
  assert.equal(verified.proofSizeBytes, data.proof.length);
  await assert.rejects(verify(data.proof, { tip: data.tip + 1n }));
  await assert.rejects(verify(data.proof, { tip: data.tip }, flip(data.root)));
  await assert.rejects(verify(data.proof, { tip: data.tip }, data.root, expected.slice(1)));
  await assert.rejects(verify(data.proof, { tip: data.tip }, data.root, expected.map((entry, i) => ({ ...entry, value: expected[expected.length - 1 - i].value }))));
  await assert.rejects(verify(data.proof.subarray(0, data.proof.length - 1)));
  const changed = fromBinary(HistoricalMultiProofSchema, data.proof);
  changed.operations[0].encodedOperation = flip(changed.operations[0].encodedOperation);
  await assert.rejects(verify(toBinary(HistoricalMultiProofSchema, changed)));
});

test('raw multiproof uses canonical current root and exact locations', async () => {
  await initQmdbWasm(wasm);
  const data = multiFixture('current_unordered_variable_variable_keys_variable_values_mmr');
  const verifier = new QmdbProofVerifier();
  const request = { tip: data.tip, locations: data.locations };
  const verified = await verifier.verifyOperations(data.proof, request, data.root);
  assert.deepEqual(verified.operations.map(({ encodedOperation }) => Buffer.from(encodedOperation)), data.operations);
  const proof = fromBinary(HistoricalMultiProofSchema, data.proof);
  assert.ok(proof.opsRootWitness.length > 0);
  await assert.rejects(verifier.verifyOperations(data.proof, request, proof.opsRoot));
  proof.opsRootWitness = new Uint8Array();
  await assert.rejects(verifier.verifyOperations(toBinary(HistoricalMultiProofSchema, proof), request, data.root));
  await assert.rejects(verifier.verifyOperations(data.proof, { ...request, locations: data.locations.slice(1) }, data.root));
});

test('public verifier rejects invalid location domains and numeric narrowing', async () => {
  const verifier = new QmdbProofVerifier();
  const proof = new Uint8Array();
  for (const request of [
    { tip: 10n, locations: [] },
    { tip: 10n, locations: [1n, 1n] },
    { tip: 10n, locations: [2n, 1n] },
    { tip: 10n, locations: [11n] },
    { tip: 10n, locations: [-1n] },
    { tip: (1n << 64n) - 1n, locations: [0n] },
    { tip: 2000n, locations: Array.from({ length: 1025 }, (_, i) => BigInt(i)) },
  ]) {
    await assert.rejects(verifier.verifyOperations(proof, request, ''), /location|ascending|tip/);
  }
  await assert.rejects(verifier.verifyFixedKeylessAppendMany(proof, { tip: 10n }, '', [{ location: 1n, value: 'a' }, { location: 2n, value: 'bb' }]), /equal in size/);
  await assert.rejects(verifier.verifyFixedUnorderedUpdate(proof, { tip: 1n, startLocation: 0n, maxLocations: 1 }, '', 0n, '', 2 ** 32), /32-bit/);
  assert.throws(() => new QmdbProofVerifier({ hashFamily: 'unknown' }), /hash family/);
  assert.throws(() => new QmdbProofVerifier({ merkleFamily: 'unknown' }), /Merkle family/);
});
