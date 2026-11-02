import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fromBinary, toBinary } from '@bufbuild/protobuf';
import { initQmdbWasm, QmdbProofVerifier } from '../dist/index.js';
import {
  OperationMultiProofSchema,
  OperationRangeProofSchema,
} from '../dist/generated/proto/qmdb/v1/proof_pb.js';

const bytes = (hex) => Buffer.from(hex, 'hex');
const wasm = readFileSync(new URL('../dist/generated/wasm/exoware_qmdb_wasm_bg.wasm', import.meta.url));
const fixture = (path) => readFileSync(new URL(`fixtures/${path}.txt`, import.meta.url), 'utf8').trim().split('\n');
const flip = (value) => { const copy = Buffer.from(value); copy[0] ^= 1; return copy; };

// A range fixture has three lines: the hex root, the `tip startLocation maxLocations` window, and
// the hex proof.
function rangeFixture(name) {
  const [root, window, proof] = fixture(`variants/${name}`);
  const [tip, startLocation, maxLocations] = window.split(' ');
  return {
    root: bytes(root), proof: bytes(proof),
    request: { tip: BigInt(tip), startLocation: BigInt(startLocation), maxLocations: Number(maxLocations) },
  };
}

// A multi-proof fixture has the hex root, a `tip locations` line with comma-separated locations,
// the hex proof, and one hex encoded operation per location.
function multiFixture(name) {
  const [root, request, proof, ...operations] = fixture(`operations/${name}`);
  const [tip, locations] = request.split(' ');
  return { root: bytes(root), proof: bytes(proof), tip: BigInt(tip), locations: locations.split(',').map(BigInt), operations: operations.map(bytes) };
}

test('public verifier initializes from supplied WASM and verifies without transport', async (t) => {
  // Any network access fails the test, so verification must rely only on the supplied bytes.
  const fetch = t.mock.method(globalThis, 'fetch', () => { throw new Error('unexpected transport'); });

  // Later initialization calls share the first call's promise.
  const first = initQmdbWasm(wasm);
  assert.equal(first, initQmdbWasm());
  await first;

  // A fixed unordered update verifies from raw proof bytes and reports their length.
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
    // `verify` changes one argument at a time from a valid baseline.
    await initQmdbWasm(wasm);
    const { proof, root, request } = rangeFixture(`any_unordered_fixed_fixed_keys_fixed_values_${merkleFamily}`);
    const verifier = new QmdbProofVerifier({ merkleFamily });
    const key = Buffer.alloc(32, 0x11);
    const location = request.startLocation + 1n;
    const verify = (p = proof, r = request, expectedRoot = root, loc = location, k = key, size = 32) =>
      verifier.verifyFixedUnorderedUpdate(p, r, expectedRoot, loc, k, size);

    // The baseline verifies, and its value matches the value bytes of the raw operation.
    const verified = await verify();
    assert.equal(verified.location, location);
    const raw = await verifier.verifyOperationRange(proof, request, root);
    assert.deepEqual(Buffer.from(verified.value), Buffer.from(raw.operations[1].encodedOperation.subarray(33, 65)));

    // A different root, window, location, key, or value size is rejected, as is a truncated
    // proof or an altered operation.
    await assert.rejects(verify(proof, request, flip(root)));
    await assert.rejects(verify(proof, { ...request, tip: request.tip + 1n }));
    await assert.rejects(verify(proof, { ...request, startLocation: request.startLocation + 1n }));
    await assert.rejects(verify(proof, { ...request, maxLocations: 1 }));
    await assert.rejects(verify(proof, request, root, request.tip + 1n));
    await assert.rejects(verify(proof, request, root, location, flip(key)));
    await assert.rejects(verify(proof, request, root, location, key, 31));
    await assert.rejects(verify(proof.subarray(0, proof.length - 1)));
    const changed = fromBinary(OperationRangeProofSchema, proof);
    changed.encodedOperations[1] = flip(changed.encodedOperations[1]);
    await assert.rejects(verify(toBinary(OperationRangeProofSchema, changed)));
  });
}

test('keyless multiproof binds values to exact locations and tip', async () => {
  // Each fixture append carries its 16-byte value right after the context tag.
  await initQmdbWasm(wasm);
  const data = multiFixture('keyless_fixed_full_fixed_values_mmr');
  const verifier = new QmdbProofVerifier();
  const expected = data.locations.map((location, i) => ({ location, value: data.operations[i].subarray(1, 17) }));
  const verify = (proof = data.proof, request = { tip: data.tip }, root = data.root, values = expected) =>
    verifier.verifyFixedKeylessAppendMany(proof, request, root, values);

  // Expectations in any order verify and return in ascending location order.
  const verified = await verify(data.proof, { tip: data.tip }, data.root, [...expected].reverse());
  assert.deepEqual(verified.operations.map(({ location }) => location), data.locations);
  assert.deepEqual(verified.operations.map(({ value }) => Buffer.from(value)), expected.map(({ value }) => Buffer.from(value)));
  assert.equal(verified.proofSizeBytes, data.proof.length);

  // A different tip or root, a missing expectation, swapped values, a truncated proof, or an
  // altered operation is rejected.
  await assert.rejects(verify(data.proof, { tip: data.tip + 1n }));
  await assert.rejects(verify(data.proof, { tip: data.tip }, flip(data.root)));
  await assert.rejects(verify(data.proof, { tip: data.tip }, data.root, expected.slice(1)));
  await assert.rejects(verify(data.proof, { tip: data.tip }, data.root, expected.map((entry, i) => ({ ...entry, value: expected[expected.length - 1 - i].value }))));
  await assert.rejects(verify(data.proof.subarray(0, data.proof.length - 1)));
  const changed = fromBinary(OperationMultiProofSchema, data.proof);
  changed.operations[0].encodedOperation = flip(changed.operations[0].encodedOperation);
  await assert.rejects(verify(toBinary(OperationMultiProofSchema, changed)));
});

test('standalone multiproof verification accepts more than 1024 locations', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', () => { throw new Error('unexpected transport'); });
  await initQmdbWasm(wasm);
  const data = multiFixture('keyless_large_mmr');
  const verifier = new QmdbProofVerifier();
  const request = { tip: data.tip, locations: data.locations };
  assert.equal(data.locations.length, 1025);

  const raw = await verifier.verifyOperations(data.proof, request, data.root);
  assert.deepEqual(raw.operations.map(({ location }) => location), data.locations);
  assert.deepEqual(raw.operations.map(({ encodedOperation }) => Buffer.from(encodedOperation)), data.operations);

  const expected = data.locations.map((location, i) => ({ location, value: data.operations[i].subarray(1, 17) }));
  const fixed = await verifier.verifyFixedKeylessAppendMany(data.proof, { tip: data.tip }, data.root, expected);
  assert.deepEqual(fixed.operations.map(({ location }) => location), data.locations);
  assert.deepEqual(fixed.operations.map(({ value }) => Buffer.from(value)), expected.map(({ value }) => value));
  assert.equal(fetch.mock.callCount(), 0);
});

test('raw multiproof uses canonical current root and exact locations', async () => {
  // The proof verifies against the current root, which its ops-root witness binds to the
  // operations root.
  await initQmdbWasm(wasm);
  const data = multiFixture('current_unordered_variable_variable_keys_variable_values_mmr');
  const verifier = new QmdbProofVerifier();
  const request = { tip: data.tip, locations: data.locations };
  const verified = await verifier.verifyOperations(data.proof, request, data.root);
  assert.deepEqual(verified.operations.map(({ encodedOperation }) => Buffer.from(encodedOperation)), data.operations);

  // The bare operations root, a proof without its witness, and a different location set are
  // rejected.
  const proof = fromBinary(OperationMultiProofSchema, data.proof);
  assert.ok(proof.opsRootWitness.length > 0);
  await assert.rejects(verifier.verifyOperations(data.proof, request, proof.opsRoot));
  proof.opsRootWitness = new Uint8Array();
  await assert.rejects(verifier.verifyOperations(toBinary(OperationMultiProofSchema, proof), request, data.root));
  await assert.rejects(verifier.verifyOperations(data.proof, { ...request, locations: data.locations.slice(1) }, data.root));
});

test('public verifier rejects invalid location domains and numeric narrowing', async () => {
  // Empty, duplicate, descending, above-tip, negative, and tip-overflowing location sets fail
  // request validation.
  const verifier = new QmdbProofVerifier();
  const proof = new Uint8Array();
  for (const request of [
    { tip: 10n, locations: [] },
    { tip: 10n, locations: [1n, 1n] },
    { tip: 10n, locations: [2n, 1n] },
    { tip: 10n, locations: [11n] },
    { tip: 10n, locations: [-1n] },
    { tip: (1n << 64n) - 1n, locations: [0n] },
  ]) {
    await assert.rejects(verifier.verifyOperations(proof, request, ''), /location|ascending|tip/);
  }

  // Unequal expectation sizes, a value size above 32 bits, and unknown families are rejected.
  await assert.rejects(verifier.verifyFixedKeylessAppendMany(proof, { tip: 10n }, '', [{ location: 1n, value: 'a' }, { location: 2n, value: 'bb' }]), /equal in size/);
  await assert.rejects(verifier.verifyFixedUnorderedUpdate(proof, { tip: 1n, startLocation: 0n, maxLocations: 1 }, '', 0n, '', 2 ** 32), /32-bit/);
  assert.throws(() => new QmdbProofVerifier({ hashFamily: 'unknown' }), /hash family/);
  assert.throws(() => new QmdbProofVerifier({ merkleFamily: 'unknown' }), /Merkle family/);
});
