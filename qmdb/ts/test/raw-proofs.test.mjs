import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { GetCurrentOperationRangeResponseSchema } from '../dist/generated/proto/qmdb/v1/current_operation_pb.js';
import { GetManyResponseSchema, GetResponseSchema } from '../dist/generated/proto/qmdb/v1/key_lookup_pb.js';
import { GetRangeResponseSchema } from '../dist/generated/proto/qmdb/v1/key_range_pb.js';
import {
  GetOperationRangeResponseSchema,
  GetOperationsResponseSchema,
  SubscribeResponseSchema,
} from '../dist/generated/proto/qmdb/v1/operation_log_pb.js';
import {
  CurrentKeyExclusionProofSchema,
  CurrentKeyLookupResultSchema,
  CurrentKeyValueProofSchema,
  CurrentOperationRangeProofSchema,
  HistoricalMultiProofSchema,
  HistoricalOperationRangeProofSchema,
} from '../dist/generated/proto/qmdb/v1/proof_pb.js';
import { OrderedQmdbClient, QmdbOperationLogClient } from '../dist/client.js';
import {
  RawCurrentOperationService,
  RawKeyLookupService,
  RawOperationLogService,
  RawOrderedKeyRangeService,
} from '../dist/raw-proofs.js';
import { initSync } from '../dist/generated/wasm/exoware_qmdb_wasm.js';

// Load wasm up front, so the mocked fetch below only sees RPCs.
initSync({ module: readFileSync(new URL('../dist/generated/wasm/exoware_qmdb_wasm_bg.wasm', import.meta.url)) });

// Responses as the Rust server encoded them.
function fixtureResponse(suffix) {
  const name = `current_ordered_variable_variable_keys_variable_values_mmr_${suffix}`;
  const lines = readFileSync(new URL(`fixtures/current/${name}.txt`, import.meta.url), 'utf8').trim().split('\n');
  return new Uint8Array(Buffer.from(lines[3], 'hex'));
}

function assertViewOf(view, wire) {
  assert.ok(view instanceof Uint8Array);
  assert.ok(view.length > 0);
  assert.equal(view.buffer, wire.buffer, 'expected a view into the response, not a copy');
}

const fill = (length, seed) => Uint8Array.from({ length }, (_, i) => (i + seed) & 0xff);

test('test_raw_proof_fields_are_views_of_the_encoded_proof', () => {
  const cases = [
    [RawOperationLogService.method.getOperationRange.output, GetOperationRangeResponseSchema,
      HistoricalOperationRangeProofSchema, { proof: fill(40, 1), encodedOperations: [fill(9, 2)], startLocation: 3n }],
    [RawOperationLogService.method.getOperations.output, GetOperationsResponseSchema,
      HistoricalMultiProofSchema, { proof: fill(40, 1), operations: [{ location: 4n, encodedOperation: fill(9, 2) }] }],
    [RawOperationLogService.method.subscribe.output, SubscribeResponseSchema,
      HistoricalMultiProofSchema, { proof: fill(40, 1), opsRoot: fill(32, 5) }],
    [RawKeyLookupService.method.get.output, GetResponseSchema,
      CurrentKeyValueProofSchema, { proof: fill(40, 1), encodedOperation: fill(9, 2) }],
    [RawCurrentOperationService.method.getCurrentOperationRange.output, GetCurrentOperationRangeResponseSchema,
      CurrentOperationRangeProofSchema, { proof: fill(40, 1), encodedOperations: [fill(9, 2)], chunks: [fill(32, 3)] }],
  ];
  for (const [raw, schema, proofSchema, proofInit] of cases) {
    const proof = create(proofSchema, proofInit);
    const wire = toBinary(schema, create(schema, { proof }));
    const decoded = fromBinary(raw, wire);
    assertViewOf(decoded.proof, wire);
    assert.deepEqual(decoded.proof, toBinary(proofSchema, proof), raw.typeName);
  }
});

test('test_raw_get_many_and_get_range_reencode_to_the_received_bytes', () => {
  const many = fixtureResponse('get_many');
  const rawMany = fromBinary(RawKeyLookupService.method.getMany.output, many);
  assert.equal(rawMany.results.length, fromBinary(GetManyResponseSchema, many).results.length);
  rawMany.results.forEach((result) => assertViewOf(result, many));
  assert.deepEqual(toBinary(RawKeyLookupService.method.getMany.output, rawMany), many);

  const rangeOutput = RawOrderedKeyRangeService.method.getRange.output;
  for (const suffix of ['range_first', 'range_last', 'range_empty']) {
    const wire = fixtureResponse(suffix);
    const raw = fromBinary(rangeOutput, wire);
    const decoded = fromBinary(GetRangeResponseSchema, wire);
    assert.equal(raw.entries.length, decoded.entries.length);
    assert.equal(raw.startProof === undefined, decoded.startProof === undefined, suffix);
    assert.deepEqual(toBinary(rangeOutput, raw), wire, suffix);
  }
});

test('test_raw_get_range_keeps_start_proof_presence', () => {
  const output = RawOrderedKeyRangeService.method.getRange.output;
  const entries = [create(CurrentKeyValueProofSchema, { proof: fill(40, 1), encodedOperation: fill(9, 2) })];
  const absent = toBinary(GetRangeResponseSchema, create(GetRangeResponseSchema, { entries }));
  assert.equal(fromBinary(output, absent).startProof, undefined);

  // An empty start proof is still a start proof, and must survive the round trip.
  const empty = toBinary(GetRangeResponseSchema, create(GetRangeResponseSchema, {
    entries,
    startProof: create(CurrentKeyExclusionProofSchema, {}),
  }));
  assert.notDeepEqual(empty, absent);
  const raw = fromBinary(output, empty);
  assert.deepEqual(raw.startProof, new Uint8Array());
  assert.deepEqual(toBinary(output, raw), empty);
  assert.notEqual(fromBinary(GetRangeResponseSchema, toBinary(output, raw)).startProof, undefined);
});

test('test_clients_use_binary_even_when_json_is_requested', async (t) => {
  const contentTypes = [];
  t.mock.method(globalThis, 'fetch', async (input, init) => {
    const request = new Request(input, init);
    contentTypes.push(request.headers.get('content-type'));
    const response = create(GetManyResponseSchema, {
      results: [create(CurrentKeyLookupResultSchema, {})],
    });
    return new Response(toBinary(GetManyResponseSchema, response), {
      headers: { 'content-type': 'application/proto' },
    });
  });
  const ordered = new OrderedQmdbClient('http://qmdb.test', { useBinaryFormat: false });
  await assert.rejects(ordered.getMany(['a'], 1n, new Uint8Array(32)));
  const log = new QmdbOperationLogClient('http://qmdb.test', { useBinaryFormat: false });
  await assert.rejects(log.getOperationRange({ tip: 1n, startLocation: 0n, maxLocations: 1 }, new Uint8Array(32)));
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
  const window = { tip: 1n, startLocation: 0n, maxLocations: 1 };
  const root = new Uint8Array(32);
  await assert.rejects(ordered.get('a', 1n, root), /qmdb get response missing proof/);
  await assert.rejects(ordered.getCurrentOperationRange(window, root), /getCurrentOperationRange response missing proof/);
  await assert.rejects(ordered.getOperationRange(window, root), /getOperationRange response missing proof/);
  await assert.rejects(log.getOperations({ tip: 1n, locations: [0n] }, root), /getOperations response missing proof/);
  await assert.rejects(
    (async () => { for await (const _ of ordered.subscribe({})) { /* first frame throws */ } })(),
    /subscribe response missing proof/,
  );
});
