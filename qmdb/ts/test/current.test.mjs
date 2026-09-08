import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fromBinary, toBinary } from '@bufbuild/protobuf';
import { GetRequestSchema, GetResponseSchema, GetManyRequestSchema, GetManyResponseSchema } from '../dist/generated/proto/qmdb/v1/key_lookup_pb.js';
import { GetRangeRequestSchema, GetRangeResponseSchema } from '../dist/generated/proto/qmdb/v1/key_range_pb.js';
import { SubscribeRequestSchema, SubscribeResponseSchema } from '../dist/generated/proto/qmdb/v1/operation_log_pb.js';
import { CurrentKeyValueProofSchema, HistoricalMultiProofSchema } from '../dist/generated/proto/qmdb/v1/proof_pb.js';
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
}
