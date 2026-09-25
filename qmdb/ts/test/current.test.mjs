import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { create, fromBinary, fromJsonString, toBinary, toJsonString } from '@bufbuild/protobuf';
import { GetRequestSchema, GetResponseSchema, GetManyRequestSchema, GetManyResponseSchema } from '../dist/generated/proto/qmdb/v1/key_lookup_pb.js';
import { GetRangeRequestSchema, GetRangeResponseSchema } from '../dist/generated/proto/qmdb/v1/key_range_pb.js';
import { GetCurrentOperationRangeRequestSchema, GetCurrentOperationRangeResponseSchema } from '../dist/generated/proto/qmdb/v1/current_operation_pb.js';
import { SubscribeRequestSchema, SubscribeResponseSchema } from '../dist/generated/proto/qmdb/v1/operation_log_pb.js';
import { CurrentKeyValueProofSchema, CurrentOperationRangeProofSchema, HistoricalMultiProofSchema } from '../dist/generated/proto/qmdb/v1/proof_pb.js';
import { OrderedQmdbClient } from '../dist/client.js';
import {
  decode_historical_multi_proof_operations, encode_vec_key, initSync, verify_current_key_value_proof,
  verify_get_many_response, verify_get_range_response,
} from '../dist/generated/wasm/exoware_qmdb_wasm.js';

initSync({ module: readFileSync(new URL('../dist/generated/wasm/exoware_qmdb_wasm_bg.wasm', import.meta.url)) });

function fixture(family, suffix, requestSchema, responseSchema) {
  const name = `current_ordered_variable_variable_keys_variable_values_${family}_${suffix}`;
  const [root, chunkSize, request, response, ...expected] = readFileSync(new URL(`fixtures/current/${name}.txt`, import.meta.url), 'utf8').trim().split('\n');
  const responseBytes = Buffer.from(response, 'hex');
  return {
    root: Buffer.from(root, 'hex'), chunkSize: Number(chunkSize), family,
    request: fromBinary(requestSchema, Buffer.from(request, 'hex')),
    response: fromBinary(responseSchema, responseBytes), responseBytes, expected,
  };
}

function assertHit(actual, expected) {
  const [key, value, location] = expected.split(' ');
  assert.equal(typeof actual.location, 'bigint');
  assert.equal(actual.location, BigInt(location));
  assert.equal(actual.operation.type, 'update');
  assert.equal(Buffer.from(actual.operation.key).toString('hex'), key);
  assert.equal(Buffer.from(actual.operation.value).toString('hex'), value);
}

function verifyRange(f, response = f.responseBytes, root = f.root, start = f.request.startKey) {
  return verify_get_range_response(response, root, f.family, 'sha256', f.chunkSize,
    start, f.request.endKey ?? new Uint8Array(), f.request.endKey !== undefined, f.request.limit);
}

function assertRange(actual, expected) {
  const [next, ...rows] = expected;
  assert.equal(actual.nextStartKey === null ? '-' : Buffer.from(actual.nextStartKey).toString('hex'), next);
  assert.equal(actual.entries.length, rows.length);
  actual.entries.forEach((entry, index) => {
    assertHit(entry, rows[index]);
    assert.deepEqual(entry.key, entry.operation.key);
  });
}

function decodeFixtureKey(key) {
  const decoded = key.subarray(1);
  assert.deepEqual(Buffer.from(encode_vec_key(decoded)), Buffer.from(key));
  return decoded;
}

function decodeRequest(schema, body, contentType) {
  return contentType === 'application/proto'
    ? fromBinary(schema, body)
    : fromJsonString(schema, new TextDecoder().decode(body));
}

async function requestBody(request) {
  return new Uint8Array(await request.arrayBuffer());
}

function rpcResponse(request, schema, message) {
  if (request.headers.get('content-type') === 'application/proto') {
    return new Response(toBinary(schema, message), {
      headers: { 'content-type': 'application/proto' },
    });
  }
  return new Response(toJsonString(schema, message), {
    headers: { 'content-type': 'application/json' },
  });
}

for (const family of ['mmr', 'mmb']) {
  test(`test_current_ordered_variable_variable_keys_variable_values_${family}_browser_queries`, () => {
    // Native matrix cases bind these wire responses to their Commonware source state
    const get = fixture(family, 'get', GetRequestSchema, GetResponseSchema);
    const proof = toBinary(CurrentKeyValueProofSchema, get.response.proof);
    const verifyGet = (root, key) => verify_current_key_value_proof(proof, root, family, 'sha256', get.chunkSize, key);
    assertHit(verifyGet(get.root, get.request.key), get.expected[0]);
    const wrongRoot = Buffer.from(get.root);
    wrongRoot[0] ^= 1;
    assert.throws(() => verifyGet(wrongRoot, get.request.key));
    assert.throws(() => verifyGet(get.root, encode_vec_key(new Uint8Array([255]))));

    const many = fixture(family, 'get_many', GetManyRequestSchema, GetManyResponseSchema);
    const verifyMany = (response = many.responseBytes, root = many.root) => verify_get_many_response(response, root, family, 'sha256', many.chunkSize, many.request.keys);
    const results = verifyMany().results;
    assert.equal(results.length, many.expected.length);
    assert.deepEqual(results.map((result) => result.type), ['hit', 'miss', 'hit']);
    results.forEach((result, index) => {
      const [key, value] = many.expected[index].split(' ');
      assert.equal(Buffer.from(result.key).toString('hex'), key);
      if (value !== '-') assertHit(result, many.expected[index]);
    });
    assert.throws(() => verifyMany(many.responseBytes, wrongRoot));
    const [hit, miss, otherHit] = many.response.results;
    for (const results of [
      [hit, miss], [hit, miss, otherHit, hit], [hit, miss, hit],
      [miss, miss, otherHit], [otherHit, miss, hit],
    ]) {
      assert.throws(() => verifyMany(toBinary(GetManyResponseSchema, { ...many.response, results })));
    }
    assert.throws(() => verify_get_many_response(many.responseBytes, many.root, family,
      'sha256', many.chunkSize, [many.request.keys[0], many.request.keys[0], many.request.keys[2]]));

    const subscribe = fixture(family, 'subscribe', SubscribeRequestSchema, SubscribeResponseSchema);
    const decoded = decode_historical_multi_proof_operations(
      toBinary(HistoricalMultiProofSchema, subscribe.response.proof), family, 'sha256');
    assert.equal(typeof decoded.tip, 'bigint');
    assert.equal(decoded.tip, BigInt(subscribe.expected[0]));
    assert.deepEqual(Buffer.from(decoded.root), subscribe.root);
    assert.equal(decoded.operations.length, subscribe.expected.length - 1);
    decoded.operations.forEach((entry, index) => {
      assert.ok(entry.location < decoded.tip);
      assertHit(entry, subscribe.expected[index + 1]);
    });

    const first = fixture(family, 'range_first', GetRangeRequestSchema, GetRangeResponseSchema);
    const last = fixture(family, 'range_last', GetRangeRequestSchema, GetRangeResponseSchema);
    const empty = fixture(family, 'range_empty', GetRangeRequestSchema, GetRangeResponseSchema);
    const page = verifyRange(first);
    assertRange(page, first.expected);
    assert.ok(page.nextStartKey !== null);
    const continuation = encode_vec_key(page.nextStartKey);
    assert.deepEqual(Buffer.from(continuation), Buffer.from(last.request.startKey));
    assertRange(verifyRange(last, last.responseBytes, last.root, continuation), last.expected);
    assertRange(verifyRange(empty), empty.expected);
    assert.throws(() => verifyRange(first, first.responseBytes, wrongRoot));
    first.response.startProof = undefined;
    assert.throws(() => verifyRange(first, toBinary(GetRangeResponseSchema, first.response)));
  });

  test(`test_current_${family}_clients_forward_read_floor_and_verify_proofs`, async (t) => {
    const get = fixture(family, 'get', GetRequestSchema, GetResponseSchema);
    const many = fixture(family, 'get_many', GetManyRequestSchema, GetManyResponseSchema);
    const range = fixture(family, 'range_first', GetRangeRequestSchema, GetRangeResponseSchema);
    const currentOperationResponse = create(GetCurrentOperationRangeResponseSchema, {
      proof: create(CurrentOperationRangeProofSchema, {}),
    });
    const large = (1n << 53n) + 100n;
    let abortFetch = false;
    let fetchSignal;
    let markFetchStarted;
    const fetchStarted = new Promise((resolve) => {
      markFetchStarted = resolve;
    });
    const forwarded = [];

    t.mock.method(globalThis, 'fetch', async (input, init) => {
      const request = new Request(input, init);
      const body = await requestBody(request);
      const path = new URL(request.url).pathname;
      let cases;
      if (path.endsWith('/GetMany')) {
        cases = [GetManyRequestSchema, GetManyResponseSchema, many.response];
      } else if (path.endsWith('/GetRange')) {
        cases = [GetRangeRequestSchema, GetRangeResponseSchema, range.response];
      } else if (path.endsWith('/GetCurrentOperationRange')) {
        cases = [GetCurrentOperationRangeRequestSchema, GetCurrentOperationRangeResponseSchema, currentOperationResponse];
      } else if (path.endsWith('/Get')) {
        cases = [GetRequestSchema, GetResponseSchema, get.response];
      } else {
        throw new Error(`unexpected QMDB RPC path ${path}`);
      }
      const decoded = decodeRequest(cases[0], body, request.headers.get('content-type'));
      forwarded.push({
        path,
        minSequenceNumber: decoded.minSequenceNumber,
        testHeader: request.headers.get('x-test-floor'),
        timeoutMs: Number(request.headers.get('connect-timeout-ms')),
      });
      if (abortFetch) {
        fetchSignal = init.signal;
        markFetchStarted();
        return new Promise((resolve, reject) => {
          init.signal.addEventListener('abort', () => reject(init.signal.reason), { once: true });
        });
      }
      return rpcResponse(request, cases[1], cases[2]);
    });

    function assertForwarded(method, minSequenceNumber) {
      const request = forwarded.shift();
      assert.ok(request.path.endsWith(`/${method}`));
      assert.equal(request.minSequenceNumber, minSequenceNumber);
      assert.equal(request.testHeader, 'forwarded');
      assert.ok(request.timeoutMs > 0);
    }

    const client = new OrderedQmdbClient('http://qmdb.test', {
      merkleFamily: family,
      currentChunkSize: get.chunkSize,
    });
    const options = {
      headers: { 'x-test-floor': 'forwarded' },
      timeoutMs: 1000,
    };
    const getKey = Buffer.from(get.expected[0].split(' ')[0], 'hex');
    const manyKeys = many.expected.map((row) => Buffer.from(row.split(' ')[0], 'hex'));
    const rangeRequest = {
      startKey: decodeFixtureKey(range.request.startKey),
      ...(range.request.endKey === undefined
        ? {}
        : { endKey: decodeFixtureKey(range.request.endKey) }),
      limit: range.request.limit,
      tip: range.request.tip,
    };

    for (const minimum of [undefined, 0n, large]) {
      const one = await client.get(getKey, get.request.tip, get.root, minimum, options);
      assertHit(one, get.expected[0]);
      assertForwarded('Get', minimum);

      const lookup = await client.getMany(manyKeys, many.request.tip, many.root, minimum, options);
      assert.deepEqual(lookup.results.map((result) => result.type), ['hit', 'miss', 'hit']);
      assertForwarded('GetMany', minimum);

      const page = await client.getRange(
        { ...rangeRequest, minSequenceNumber: minimum },
        range.root,
        options,
      );
      assertRange(page, range.expected);
      assertForwarded('GetRange', minimum);

      await assert.rejects(client.getCurrentOperationRange({
        tip: range.request.tip,
        startLocation: 0n,
        maxLocations: 1,
        minSequenceNumber: minimum,
      }, range.root, options), /current operation range proof has no operations/);
      assertForwarded('GetCurrentOperationRange', minimum);
    }

    abortFetch = true;
    const controller = new AbortController();
    const aborted = client.get(
      getKey,
      get.request.tip,
      get.root,
      undefined,
      {
        headers: { 'x-test-floor': 'forwarded' },
        signal: controller.signal,
        timeoutMs: 1000,
      },
    );
    await fetchStarted;
    controller.abort();
    await assert.rejects(aborted);
    assertForwarded('Get', undefined);
    assert.equal(fetchSignal.aborted, true);
    assert.equal(forwarded.length, 0);
  });
}

test('test_current_clients_reject_invalid_read_floors_before_dispatch', async (t) => {
  let requests = 0;
  t.mock.method(globalThis, 'fetch', async () => {
    requests += 1;
    throw new Error('unexpected request');
  });
  const client = new OrderedQmdbClient('http://qmdb.test');
  for (const minimum of [-1n, 1n << 64n, 1]) {
    await assert.rejects(client.get('', 1n, '', minimum), /64-bit/);
    await assert.rejects(client.getMany([''], 1n, '', minimum), /64-bit/);
    await assert.rejects(client.getRange({
      startKey: '', limit: 1, tip: 1n, minSequenceNumber: minimum,
    }, ''), /64-bit/);
    await assert.rejects(client.getCurrentOperationRange({
      tip: 1n, startLocation: 0n, maxLocations: 1, minSequenceNumber: minimum,
    }, ''), /64-bit/);
  }
  assert.equal(requests, 0);
});
