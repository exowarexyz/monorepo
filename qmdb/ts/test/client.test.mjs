import assert from 'node:assert/strict';
import test from 'node:test';
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
