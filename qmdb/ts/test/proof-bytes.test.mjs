import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { GetCurrentOperationRangeResponseSchema } from '../dist/generated/proto/qmdb/v1/current_operation_pb.js';
import { GetManyResponseSchema, GetRequestSchema, GetResponseSchema } from '../dist/generated/proto/qmdb/v1/key_lookup_pb.js';
import { GetRangeRequestSchema, GetRangeResponseSchema } from '../dist/generated/proto/qmdb/v1/key_range_pb.js';
import {
  GetOperationRangeResponseSchema,
  GetOperationsResponseSchema,
  SubscribeResponseSchema,
} from '../dist/generated/proto/qmdb/v1/operation_log_pb.js';
import {
  CurrentKeyExclusionProofSchema,
  CurrentKeyValueProofSchema,
  CurrentOperationRangeProofSchema,
  HistoricalMultiProofSchema,
  HistoricalOperationRangeProofSchema,
} from '../dist/generated/proto/qmdb/v1/proof_pb.js';
import { OrderedQmdbClient, QmdbOperationLogClient } from '../dist/client.js';
import {
  ProofBytesCurrentOperationService,
  ProofBytesKeyLookupService,
  ProofBytesOperationLogService,
  ProofBytesOrderedKeyRangeService,
} from '../dist/proof-bytes.js';
import { initSync } from '../dist/generated/wasm/exoware_qmdb_wasm.js';

// Load wasm up front, so the mocked fetch below only sees RPCs.
initSync({ module: readFileSync(new URL('../dist/generated/wasm/exoware_qmdb_wasm_bg.wasm', import.meta.url)) });

const families = ['mmr', 'mmb'];

// A request and response as the Rust server encoded them, with the root and
// chunk size to verify against.
function fixture(family, suffix) {
  const name = `current_ordered_variable_variable_keys_variable_values_${family}_${suffix}`;
  const [root, chunkSize, request, response] = readFileSync(new URL(`fixtures/current/${name}.txt`, import.meta.url), 'utf8').trim().split('\n');
  const bytes = (hex) => new Uint8Array(Buffer.from(hex, 'hex'));
  return { root: bytes(root), chunkSize: Number(chunkSize), request: bytes(request), response: bytes(response) };
}

function assertViewOf(view, wire) {
  assert.ok(view instanceof Uint8Array);
  assert.ok(view.length > 0);
  assert.equal(view.buffer, wire.buffer, 'expected a view into the response, not a copy');
}

const fill = (length, seed) => Uint8Array.from({ length }, (_, i) => (i + seed) & 0xff);

test('test_proof_bytes_proof_fields_are_views_of_the_encoded_proof', () => {
  const cases = [
    [ProofBytesOperationLogService.method.getOperationRange.output, GetOperationRangeResponseSchema,
      HistoricalOperationRangeProofSchema, { proof: fill(40, 1), encodedOperations: [fill(9, 2)], startLocation: 3n }],
    [ProofBytesOperationLogService.method.getOperations.output, GetOperationsResponseSchema,
      HistoricalMultiProofSchema, { proof: fill(40, 1), operations: [{ location: 4n, encodedOperation: fill(9, 2) }] }],
    [ProofBytesOperationLogService.method.subscribe.output, SubscribeResponseSchema,
      HistoricalMultiProofSchema, { proof: fill(40, 1), opsRoot: fill(32, 5) }],
    [ProofBytesKeyLookupService.method.get.output, GetResponseSchema,
      CurrentKeyValueProofSchema, { proof: fill(40, 1), encodedOperation: fill(9, 2) }],
    [ProofBytesCurrentOperationService.method.getCurrentOperationRange.output, GetCurrentOperationRangeResponseSchema,
      CurrentOperationRangeProofSchema, { proof: fill(40, 1), encodedOperations: [fill(9, 2)], chunks: [fill(32, 3)] }],
  ];
  for (const [output, schema, proofSchema, proofInit] of cases) {
    const proof = create(proofSchema, proofInit);
    const wire = toBinary(schema, create(schema, { proof }));
    const [part, ...rest] = fromBinary(output, wire).proof;
    assert.equal(rest.length, 0, output.typeName);
    assertViewOf(part, wire);
    assert.deepEqual(part, toBinary(proofSchema, proof), output.typeName);
  }
});

test('test_proof_bytes_proof_fields_match_server_fixtures', () => {
  const cases = [
    ['get', ProofBytesKeyLookupService.method.get.output, GetResponseSchema, CurrentKeyValueProofSchema],
    ['subscribe', ProofBytesOperationLogService.method.subscribe.output, SubscribeResponseSchema, HistoricalMultiProofSchema],
  ];
  for (const family of families) {
    for (const [suffix, output, schema, proofSchema] of cases) {
      const wire = fixture(family, suffix).response;
      const [part, ...rest] = fromBinary(output, wire).proof;
      assert.equal(rest.length, 0, `${family} ${suffix}`);
      assertViewOf(part, wire);
      assert.deepEqual(part, toBinary(proofSchema, fromBinary(schema, wire).proof), `${family} ${suffix}`);
    }
  }
});

test('test_proof_bytes_get_many_and_get_range_reencode_to_the_received_bytes', () => {
  const manyOutput = ProofBytesKeyLookupService.method.getMany.output;
  const rangeOutput = ProofBytesOrderedKeyRangeService.method.getRange.output;
  for (const family of families) {
    const many = fixture(family, 'get_many').response;
    const decoded = fromBinary(manyOutput, many);
    assert.equal(decoded.results.length, fromBinary(GetManyResponseSchema, many).results.length);
    decoded.results.forEach((result) => assertViewOf(result, many));
    assert.deepEqual(toBinary(manyOutput, decoded), many, family);

    for (const suffix of ['range_first', 'range_last', 'range_empty']) {
      const wire = fixture(family, suffix).response;
      const asBytes = fromBinary(rangeOutput, wire);
      const asMessages = fromBinary(GetRangeResponseSchema, wire);
      assert.equal(asBytes.entries.length, asMessages.entries.length);
      assert.equal(asBytes.startProof.length, asMessages.startProof === undefined ? 0 : 1, `${family} ${suffix}`);
      assert.deepEqual(toBinary(rangeOutput, asBytes), wire, `${family} ${suffix}`);
    }
  }
});

test('test_proof_bytes_get_range_keeps_start_proof_presence', () => {
  const output = ProofBytesOrderedKeyRangeService.method.getRange.output;
  const entries = [create(CurrentKeyValueProofSchema, { proof: fill(40, 1), encodedOperation: fill(9, 2) })];
  const absent = toBinary(GetRangeResponseSchema, create(GetRangeResponseSchema, { entries }));
  assert.deepEqual(fromBinary(output, absent).startProof, []);

  // An empty start proof is still a start proof, and must survive the round trip.
  const empty = toBinary(GetRangeResponseSchema, create(GetRangeResponseSchema, {
    entries,
    startProof: create(CurrentKeyExclusionProofSchema, {}),
  }));
  assert.notDeepEqual(empty, absent);
  const decoded = fromBinary(output, empty);
  assert.deepEqual(decoded.startProof, [new Uint8Array()]);
  assert.deepEqual(toBinary(output, decoded), empty);
});

test('test_proof_bytes_split_proofs_join_like_protobuf_merges_them', () => {
  const output = ProofBytesKeyLookupService.method.get.output;
  const first = create(CurrentKeyValueProofSchema, { proof: fill(40, 1) });
  const second = create(CurrentKeyValueProofSchema, { encodedOperation: fill(9, 2) });
  // Two occurrences of the proof field, which protobuf parses as one merged proof.
  const wire = new Uint8Array([
    ...toBinary(GetResponseSchema, create(GetResponseSchema, { proof: first })),
    ...toBinary(GetResponseSchema, create(GetResponseSchema, { proof: second })),
  ]);
  const parts = fromBinary(output, wire).proof;
  assert.equal(parts.length, 2);
  const joined = new Uint8Array(Buffer.concat(parts));
  assert.deepEqual(
    fromBinary(CurrentKeyValueProofSchema, joined),
    fromBinary(GetResponseSchema, wire).proof,
  );
});

test('test_clients_join_proofs_split_across_occurrences', async (t) => {
  let body;
  t.mock.method(globalThis, 'fetch', async () => new Response(body, { headers: { 'content-type': 'application/proto' } }));
  const occurrence = (init) => toBinary(GetResponseSchema, create(GetResponseSchema, {
    proof: create(CurrentKeyValueProofSchema, init),
  }));
  for (const family of families) {
    const get = fixture(family, 'get');
    const { key, tip } = fromBinary(GetRequestSchema, get.request);
    const client = new OrderedQmdbClient('http://qmdb.test', { merkleFamily: family, currentChunkSize: get.chunkSize });
    const whole = fromBinary(GetResponseSchema, get.response).proof;
    // The server's proof split in two, and whole but followed by an empty
    // occurrence. Protobuf merges each into the server's proof.
    for (const parts of [[{ proof: whole.proof }, { encodedOperation: whole.encodedOperation }], [whole, {}]]) {
      body = new Uint8Array(parts.flatMap((init) => [...occurrence(init)]));
      const verified = await client.get(key.subarray(1), tip, get.root);
      assert.equal(verified.proofSizeBytes, toBinary(CurrentKeyValueProofSchema, whole).length, family);
    }

    // A whole start proof followed by an empty occurrence.
    const range = fixture(family, 'range_first');
    const request = fromBinary(GetRangeRequestSchema, range.request);
    body = new Uint8Array([...range.response, 0x12, 0x00]);
    await client.getRange({
      startKey: request.startKey.subarray(1),
      endKey: request.endKey?.subarray(1),
      limit: request.limit,
      tip: request.tip,
    }, range.root);
  }
});

test('test_clients_use_binary_even_when_json_is_requested', async (t) => {
  const contentTypes = [];
  t.mock.method(globalThis, 'fetch', async (input, init) => {
    contentTypes.push(new Request(input, init).headers.get('content-type'));
    // An empty response, which fails fast as a missing proof.
    return new Response(new Uint8Array(), { headers: { 'content-type': 'application/proto' } });
  });
  const root = new Uint8Array(32);
  const ordered = new OrderedQmdbClient('http://qmdb.test', { useBinaryFormat: false });
  await assert.rejects(ordered.get('a', 1n, root), /get response missing proof/);
  const log = new QmdbOperationLogClient('http://qmdb.test', { useBinaryFormat: false });
  await assert.rejects(
    log.getOperationRange({ tip: 1n, startLocation: 0n, maxLocations: 1 }, root),
    /getOperationRange response missing proof/,
  );
  assert.deepEqual(contentTypes, ['application/proto', 'application/proto']);
});

test('test_clients_report_missing_proofs', async (t) => {
  t.mock.method(globalThis, 'fetch', async (input) => {
    if (String(input).endsWith('/Subscribe')) {
      // One empty frame, then Connect's end-of-stream frame.
      const end = new TextEncoder().encode('{}');
      const body = new Uint8Array([0, 0, 0, 0, 0, 2, 0, 0, 0, end.length, ...end]);
      return new Response(body, { headers: { 'content-type': 'application/connect+proto' } });
    }
    return new Response(new Uint8Array(), { headers: { 'content-type': 'application/proto' } });
  });
  const ordered = new OrderedQmdbClient('http://qmdb.test');
  const log = new QmdbOperationLogClient('http://qmdb.test');
  const range = { tip: 1n, startLocation: 0n, maxLocations: 1 };
  const root = new Uint8Array(32);
  await assert.rejects(ordered.get('a', 1n, root), /qmdb get response missing proof/);
  await assert.rejects(ordered.getCurrentOperationRange(range, root), /getCurrentOperationRange response missing proof/);
  await assert.rejects(ordered.getOperationRange(range, root), /getOperationRange response missing proof/);
  await assert.rejects(log.getOperations({ tip: 1n, locations: [0n] }, root), /getOperations response missing proof/);
  await assert.rejects(
    (async () => { for await (const _ of ordered.subscribe({})) { /* first frame throws */ } })(),
    /subscribe response missing proof/,
  );
});
