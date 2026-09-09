import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import test from 'node:test';
import { fromBinary, toBinary } from '@bufbuild/protobuf';
import { HistoricalOperationRangeProofSchema } from '../dist/generated/proto/qmdb/v1/proof_pb.js';
import { initSync, verify_historical_raw_operation_range_proof } from '../dist/generated/wasm/exoware_qmdb_wasm.js';

const families = ['mmr', 'mmb'];
const shapes = [
  ['fixed', 'fixed', 'fixed'],
  ['variable', 'fixed', 'fixed'],
  ['variable', 'fixed', 'variable'],
  ['variable', 'variable', 'fixed'],
  ['variable', 'variable', 'variable'],
];
const cases = [];
for (const state of ['any', 'current']) {
  for (const ordering of ['ordered', 'unordered']) {
    for (const [encoding, key, value] of shapes) {
      for (const family of families) {
        cases.push(`${state}_${ordering}_${encoding}_${key}_keys_${value}_values_${family}`);
      }
    }
  }
}
for (const [encoding, key, value] of shapes) {
  for (const construction of ['full', 'compact']) {
    for (const family of families) {
      cases.push(`immutable_${encoding}_${construction}_${key}_keys_${value}_values_${family}`);
    }
  }
}
for (const [encoding, value] of [['fixed', 'fixed'], ['variable', 'fixed'], ['variable', 'variable']]) {
  for (const construction of ['full', 'compact']) {
    for (const family of families) {
      cases.push(`keyless_${encoding}_${construction}_${value}_values_${family}`);
    }
  }
}
cases.sort();

const fixtures = new URL('fixtures/variants/', import.meta.url);
initSync({ module: readFileSync(new URL('../dist/generated/wasm/exoware_qmdb_wasm_bg.wasm', import.meta.url)) });

test('test_commonware_variant_fixture_matrix', () => {
  assert.equal(cases.length, 72);
  assert.equal(new Set(cases).size, cases.length);
  assert.deepEqual(readdirSync(fixtures).sort(), cases.map((name) => `${name}.txt`));
});

for (const name of cases) {
  test(`test_${name}`, () => {
    // The native matrix checks these proof bytes against its actual Commonware source
    const [rootHex, request, proofHex, ...operationHex] = readFileSync(new URL(`${name}.txt`, fixtures), 'utf8').trim().split('\n');
    const [tipText, startText, maxText] = request.split(' ');
    const tip = BigInt(tipText);
    const start = BigInt(startText);
    const max = Number(maxText);
    const root = Buffer.from(rootHex, 'hex');
    const proof = Buffer.from(proofHex, 'hex');
    const family = name.endsWith('_mmr') ? 'mmr' : 'mmb';
    assert.ok(start > 0n);
    assert.ok(operationHex.length > 0);
    assert.equal(start + BigInt(operationHex.length), tip + 1n);

    const wire = fromBinary(HistoricalOperationRangeProofSchema, proof);
    assert.ok(wire.pinnedNodes.length > 0);
    assert.equal(wire.opsRootWitness.length > 0, name.startsWith('current_'));
    const verified = verify_historical_raw_operation_range_proof(proof, root, family, 'sha256', tip, start, max);
    assert.deepEqual(Buffer.from(verified.root), root);
    assert.deepEqual(verified.operations.map((operation) => operation.location), operationHex.map((_, offset) => start + BigInt(offset)));
    assert.deepEqual(verified.operations.map((operation) => Buffer.from(operation.encodedOperation).toString('hex')), operationHex);

    const wrongRoot = Buffer.from(root);
    wrongRoot[0] ^= 1;
    assert.throws(() => verify_historical_raw_operation_range_proof(proof, wrongRoot, family, 'sha256', tip, start, max));
    assert.throws(() => verify_historical_raw_operation_range_proof(proof, root, family, 'sha256', tip + 1n, start, max));
    assert.throws(() => verify_historical_raw_operation_range_proof(proof, root, family, 'sha256', tip, start + 1n, max));

    wire.encodedOperations[0][0] ^= 1;
    const tamperedProof = toBinary(HistoricalOperationRangeProofSchema, wire);
    assert.throws(() => verify_historical_raw_operation_range_proof(tamperedProof, root, family, 'sha256', tip, start, max));
  });
}
