import assert from 'node:assert/strict';
import test from 'node:test';
import { create, fromBinary, fromJsonString, toJsonString } from '@bufbuild/protobuf';
import {
  GetOperationRangeRequestSchema,
  GetOperationRangeResponseSchema,
  GetOperationsRequestSchema,
  GetOperationsResponseSchema,
} from '../dist/generated/proto/qmdb/v1/operation_log_pb.js';
import { HistoricalMultiProofSchema, HistoricalOperationRangeProofSchema } from '../dist/generated/proto/qmdb/v1/proof_pb.js';
import { readFileSync } from 'node:fs';
import { OrderedQmdbClient, QmdbOperationLogClient } from '../dist/client.js';
import { initSync, verify_historical_raw_operation_range_proof } from '../dist/generated/wasm/exoware_qmdb_wasm.js';

test('test_size_arguments_reject_narrowing_before_initialization', async () => {
  for (const currentChunkSize of [0, -1, 1.5, 2 ** 32, Number.MAX_SAFE_INTEGER]) {
    assert.throws(() => new OrderedQmdbClient('http://127.0.0.1:1', { currentChunkSize }), /32-bit/);
  }
  const client = new QmdbOperationLogClient('http://127.0.0.1:1');
  const request = { tip: 2n, startLocation: 1n, maxLocations: 1 };
  await assert.rejects(client.getFixedUnorderedUpdate(request, '', 1n, '', 2 ** 32), /32-bit/);
  await assert.rejects(client.getFixedKeylessAppend(request, '', 1n << 64n, ''), /64-bit/);
  const ordered = new OrderedQmdbClient('http://127.0.0.1:1');
  await assert.rejects(ordered.getRange({ startKey: '', limit: 0, tip: 1n }, ''), /32-bit/);
});

test('test_operation_windows_reject_invalid_bounds_before_initialization', async () => {
  const clients = [new QmdbOperationLogClient('http://127.0.0.1:1'), new OrderedQmdbClient('http://127.0.0.1:1')];
  const valid = { tip: (1n << 53n) + 2n, startLocation: (1n << 53n) + 1n, maxLocations: 1 };
  for (const client of clients) {
    for (const request of [
      { ...valid, maxLocations: 2 ** 32 },
      { ...valid, maxLocations: 0 },
      { ...valid, startLocation: -1n },
      { ...valid, tip: 1n << 64n },
      { ...valid, minSequenceNumber: -1n },
      { ...valid, minSequenceNumber: 1n << 64n },
      { ...valid, startLocation: valid.tip + 1n },
    ]) {
      await assert.rejects(client.getOperationRange(request, ''), /32-bit|64-bit|window/);
    }
  }
});

test('test_keyless_variable_variable_values_large_locations', () => {
  initSync({ module: readFileSync(new URL('../dist/generated/wasm/exoware_qmdb_wasm_bg.wasm', import.meta.url)) });
  for (const family of ['mmr', 'mmb']) {
    for (const start of [(1n << 32n) - 2n, (1n << 53n) + 1n]) {
      // Rust's e2e_keyless_large_locations checks these fixtures against a trusted pruned frontier
      const [rootHex, proofHex] = readFileSync(new URL(`fixtures/keyless_variable_variable_values_${family}_start_${start}.txt`, import.meta.url), 'utf8').trim().split('\n');
      const root = Buffer.from(rootHex, 'hex');
      const proof = Buffer.from(proofHex, 'hex');
      const verified = verify_historical_raw_operation_range_proof(proof, root, family, 'sha256', start + 2n, start, 10);
      assert.deepEqual(Array.from(verified.root), Array.from(root));
      assert.deepEqual(verified.operations.map((operation) => operation.location), [start, start + 1n, start + 2n]);
      assert.ok(verified.operations.every((operation) => operation.encodedOperation.length > 0));
      assert.throws(() => verify_historical_raw_operation_range_proof(proof, root, family, 'sha256', start + 2n, start + 1n, 10), /request/);
    }
  }
});

const readFloorCases = [
  {
    name: 'raw',
    fixture: 'any_unordered_variable_variable_keys_variable_values',
    Client: QmdbOperationLogClient,
    read: (client, request, root, options) => client.getOperationRange(request, root, options),
  },
  {
    name: 'ordered',
    fixture: 'any_ordered_variable_variable_keys_variable_values',
    Client: OrderedQmdbClient,
    read: (client, request, root, options) => client.getOperationRange(request, root, options),
  },
  {
    name: 'fixed_keyless',
    fixture: 'keyless_fixed_full_fixed_values',
    Client: QmdbOperationLogClient,
    read: (client, request, root, options) => client.getFixedKeylessAppend(
      request, root, request.startLocation, Buffer.alloc(16, 8), options,
    ),
  },
  {
    name: 'fixed_unordered',
    fixture: 'any_unordered_fixed_fixed_keys_fixed_values',
    Client: QmdbOperationLogClient,
    read: (client, request, root, options) => client.getFixedUnorderedUpdate(
      request, root, request.startLocation + 1n, Buffer.alloc(32, 0x11), 32, options,
    ),
  },
];

for (const { name, fixture, Client, read } of readFloorCases) {
  for (const merkleFamily of ['mmr', 'mmb']) {
    test(`test_${name}_${merkleFamily}_read_floor_and_verified_proof`, async (t) => {
      initSync({ module: readFileSync(new URL('../dist/generated/wasm/exoware_qmdb_wasm_bg.wasm', import.meta.url)) });
      const [rootHex, window, proofHex] = readFileSync(
        new URL(`fixtures/variants/${fixture}_${merkleFamily}.txt`, import.meta.url), 'utf8',
      ).trim().split('\n');
      const [tip, startLocation, maxLocations] = window.split(' ');
      const root = Buffer.from(rootHex, 'hex');
      const minSequenceNumber = (1n << 53n) + 100n;
      const request = {
        tip: BigInt(tip),
        startLocation: BigInt(startLocation),
        maxLocations: Number(maxLocations),
        minSequenceNumber,
      };
      const response = create(GetOperationRangeResponseSchema, {
        proof: fromBinary(HistoricalOperationRangeProofSchema, Buffer.from(proofHex, 'hex')),
      });
      t.mock.method(globalThis, 'fetch', async (input, init) => {
        const sent = new Request(input, init);
        const bytes = new Uint8Array(await sent.arrayBuffer());
        const decoded = sent.headers.get('content-type') === 'application/proto'
          ? fromBinary(GetOperationRangeRequestSchema, bytes)
          : fromJsonString(GetOperationRangeRequestSchema, new TextDecoder().decode(bytes));
        assert.equal(decoded.minSequenceNumber, request.minSequenceNumber);
        assert.equal(sent.headers.get('x-test-floor'), 'forwarded');
        assert.ok(Number(sent.headers.get('connect-timeout-ms')) > 0);
        return new Response(toJsonString(GetOperationRangeResponseSchema, response), {
          headers: { 'content-type': 'application/json' },
        });
      });
      const client = new Client('http://qmdb.test', { merkleFamily });
      const options = { timeoutMs: 1000, headers: { 'x-test-floor': 'forwarded' } };
      for (const minimum of [undefined, 0n, minSequenceNumber]) {
        request.minSequenceNumber = minimum;
        const proof = await read(client, request, root, options);
        assert.deepEqual(Buffer.from(proof.root), root);
      }

      const wrongRoot = Buffer.from(root);
      wrongRoot[0] ^= 1;
      await assert.rejects(read(client, request, wrongRoot, options));
    });
  }
}

test('test_operations_requests_reject_invalid_locations_before_dispatch', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => {
    throw new Error('request must not be sent');
  });
  const client = new QmdbOperationLogClient('http://127.0.0.1:1');
  for (const request of [
    { tip: 10n, locations: [] },
    { tip: 10n, locations: [2n, 1n] },
    { tip: 10n, locations: [1n, 1n] },
    { tip: 10n, locations: [0n, 11n] },
    { tip: 10n, locations: [-1n] },
    { tip: 1n << 64n, locations: [0n] },
    { tip: 10n, locations: [0n], minSequenceNumber: -1n },
    { tip: 2000n, locations: Array.from({ length: 1025 }, (_, index) => BigInt(index)) },
  ]) {
    await assert.rejects(client.getOperations(request, ''), /locations|location|64-bit|ascending|tip/);
  }
  await assert.rejects(
    client.getFixedKeylessAppendMany({ tip: 10n }, '', [{ location: 1n, value: 'a' }, { location: 2n, value: 'bb' }]),
    /equal in size/,
  );
  await assert.rejects(
    client.getFixedUnorderedUpdateMany({ tip: 10n }, '', [{ location: 1n, key: 'a' }, { location: 1n, key: 'b' }], 8),
    /ascending/,
  );
  assert.equal(fetch.mock.callCount(), 0);
});

function operationsFixture(name) {
  const [rootHex, request, proofHex, ...operationHex] = readFileSync(
    new URL(`fixtures/operations/${name}.txt`, import.meta.url), 'utf8',
  ).trim().split('\n');
  const [tip, locations] = request.split(' ');
  return {
    root: Buffer.from(rootHex, 'hex'),
    tip: BigInt(tip),
    locations: locations.split(',').map(BigInt),
    proof: fromBinary(HistoricalMultiProofSchema, Buffer.from(proofHex, 'hex')),
    operations: operationHex.map((hex) => Buffer.from(hex, 'hex')),
  };
}

// Serves the fixture proof, checking the forwarded request unless `checkRequest` is false.
function mockOperationsService(t, fixture, minSequenceNumber, checkRequest = true) {
  const response = create(GetOperationsResponseSchema, { proof: fixture.proof });
  return t.mock.method(globalThis, 'fetch', async (input, init) => {
    const sent = new Request(input, init);
    assert.ok(sent.url.endsWith('/qmdb.v1.OperationLogService/GetOperations'));
    if (!checkRequest) {
      return new Response(toJsonString(GetOperationsResponseSchema, response), {
        headers: { 'content-type': 'application/json' },
      });
    }
    const bytes = new Uint8Array(await sent.arrayBuffer());
    const decoded = sent.headers.get('content-type') === 'application/proto'
      ? fromBinary(GetOperationsRequestSchema, bytes)
      : fromJsonString(GetOperationsRequestSchema, new TextDecoder().decode(bytes));
    assert.equal(decoded.tip, fixture.tip);
    assert.deepEqual(decoded.locations, fixture.locations);
    assert.equal(decoded.minSequenceNumber, minSequenceNumber);
    return new Response(toJsonString(GetOperationsResponseSchema, response), {
      headers: { 'content-type': 'application/json' },
    });
  });
}

const initWasm = () =>
  initSync({ module: readFileSync(new URL('../dist/generated/wasm/exoware_qmdb_wasm_bg.wasm', import.meta.url)) });

for (const [fixtureName, merkleFamily, current] of [
  ['any_unordered_variable_variable_keys_variable_values_mmr', 'mmr', false],
  ['any_unordered_variable_variable_keys_variable_values_mmb', 'mmb', false],
  ['current_unordered_variable_variable_keys_variable_values_mmr', 'mmr', true],
]) {
  test(`test_operations_client_verifies_${fixtureName}`, async (t) => {
    initWasm();
    const fixture = operationsFixture(fixtureName);
    const minSequenceNumber = (1n << 53n) + 100n;
    mockOperationsService(t, fixture, minSequenceNumber);
    const client = new QmdbOperationLogClient('http://qmdb.test', { merkleFamily });
    const request = { tip: fixture.tip, locations: fixture.locations, minSequenceNumber };

    const verified = await client.getOperations(request, fixture.root);
    // A current endpoint's witness binds the proven operation-log root to the trusted root.
    assert.deepEqual(Buffer.from(verified.root), fixture.root);
    assert.equal(fixture.proof.opsRootWitness.length > 0, current);
    assert.deepEqual(verified.operations.map(({ location }) => location), fixture.locations);
    assert.deepEqual(verified.operations.map(({ encodedOperation }) => Buffer.from(encodedOperation)), fixture.operations);
    assert.ok(verified.proofSizeBytes > 0);

    const wrongRoot = Buffer.from(fixture.root);
    wrongRoot[0] ^= 1;
    await assert.rejects(client.getOperations(request, wrongRoot));

    // A proof for other locations than requested is rejected.
    // The transport captures `fetch` at construction, so use a fresh client.
    t.mock.restoreAll();
    mockOperationsService(t, fixture, undefined, false);
    const mismatched = new QmdbOperationLogClient('http://qmdb.test', { merkleFamily });
    await assert.rejects(mismatched.getOperations({ ...request, locations: fixture.locations.slice(1) }, fixture.root), /locations/);
  });
}

test('test_fixed_keyless_append_many_verifies_values', async (t) => {
  initWasm();
  const fixture = operationsFixture('keyless_fixed_full_fixed_values_mmr');
  mockOperationsService(t, fixture, undefined);
  const client = new QmdbOperationLogClient('http://qmdb.test');
  // Fixed keyless appends encode a context byte followed by the value.
  const values = fixture.operations.map((operation) => operation.subarray(1, 17));
  const expected = fixture.locations.map((location, index) => ({ location, value: values[index] }));

  // Expectations are sorted by location before the request is sent.
  const verified = await client.getFixedKeylessAppendMany({ tip: fixture.tip }, fixture.root, [...expected].reverse());
  assert.deepEqual(verified.operations.map(({ location }) => location), fixture.locations);
  assert.deepEqual(verified.operations.map(({ value }) => Buffer.from(value)), values.map((value) => Buffer.from(value)));

  const wrong = expected.map(({ location, value }) => ({ location, value: Buffer.from(value).fill(0xff) }));
  await assert.rejects(client.getFixedKeylessAppendMany({ tip: fixture.tip }, fixture.root, wrong), /does not match expected value/);
});

test('test_fixed_unordered_update_many_verifies_keys', async (t) => {
  initWasm();
  const fixture = operationsFixture('any_unordered_fixed_fixed_keys_fixed_values_mmr');
  mockOperationsService(t, fixture, undefined);
  const client = new QmdbOperationLogClient('http://qmdb.test');
  // Fixed unordered updates encode a context byte, the 32-byte key, then the 32-byte value.
  const keys = fixture.operations.map((operation) => operation.subarray(1, 33));
  const expected = fixture.locations.map((location, index) => ({ location, key: keys[index] }));

  const verified = await client.getFixedUnorderedUpdateMany({ tip: fixture.tip }, fixture.root, expected, 32);
  assert.deepEqual(verified.operations.map(({ location }) => location), fixture.locations);
  assert.deepEqual(verified.operations.map(({ key }) => Buffer.from(key)), keys.map((key) => Buffer.from(key)));
  assert.deepEqual(
    verified.operations.map(({ value }) => Buffer.from(value)),
    fixture.operations.map((operation) => Buffer.from(operation.subarray(33, 65))),
  );

  const swapped = expected.map(({ location }, index) => ({ location, key: keys[1 - index] }));
  await assert.rejects(client.getFixedUnorderedUpdateMany({ tip: fixture.tip }, fixture.root, swapped, 32), /key does not match/);
});
