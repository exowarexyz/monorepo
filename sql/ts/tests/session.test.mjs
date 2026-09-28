import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { SqlClient } from '../dist/index.js';
import { QueryRequestSchema, QueryResponseSchema } from '../dist/generated/proto/sql/v1/query_pb.js';

const results = await readFile(new URL('fixtures/empty.arrow', import.meta.url));
const options = { token: '' };

function response(sequenceNumber, payload = results) {
  return new Response(toBinary(QueryResponseSchema, create(QueryResponseSchema, {
    results: payload,
    ...(sequenceNumber === undefined ? {} : { sequenceNumber }),
  })), { headers: { 'content-type': 'application/proto' } });
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

test('default SQL client advances across queries and preserves absent versus zero', async (t) => {
  const observed = [undefined, 0n, 7n, undefined];
  const floors = [];
  t.mock.method(globalThis, 'fetch', async (_input, init) => {
    floors.push(fromBinary(QueryRequestSchema, init.body).minSequenceNumber);
    return response(observed.shift());
  });
  const client = new SqlClient('http://sql.test', options);
  assert.equal(client.minSequenceNumber(), undefined);
  await client.query('SELECT 1');
  assert.equal(client.evaluatedSequence(), undefined);
  await client.query('SELECT * FROM empty_table');
  assert.equal(client.minSequenceNumber(), 0n);
  await client.query('SELECT * FROM empty_table');
  assert.equal(client.evaluatedSequence(), 7n);
  await client.query('SELECT 1');
  assert.equal(client.evaluatedSequence(), 7n);
  assert.deepEqual(floors, [undefined, undefined, 0n, 7n]);
});

test('fixed policy records observations without raising its minimum', async (t) => {
  const floors = [];
  t.mock.method(globalThis, 'fetch', async (_input, init) => {
    floors.push(fromBinary(QueryRequestSchema, init.body).minSequenceNumber);
    return response(20n);
  });
  for (const floor of [undefined, 0n, 5n]) {
    const client = SqlClient.fixed('http://sql.test', floor, options);
    await client.query('SELECT * FROM items');
    await client.query('SELECT * FROM items');
    assert.equal(client.evaluatedSequence(), 20n);
    assert.equal(client.minSequenceNumber(), floor);
  }
  assert.deepEqual(floors, [undefined, undefined, 0n, 0n, 5n, 5n]);
});

test('explicit per-query minimum strengthens only that request when no read occurs', async (t) => {
  const floors = [];
  t.mock.method(globalThis, 'fetch', async (_input, init) => {
    floors.push(fromBinary(QueryRequestSchema, init.body).minSequenceNumber);
    return response(undefined);
  });
  const client = SqlClient.monotonic('http://sql.test', 5n, options);
  await client.query('SELECT 1', 30n);
  await client.query('SELECT 1', 0n);
  assert.deepEqual(floors, [30n, 5n]);
  assert.equal(client.minSequenceNumber(), 5n);
  assert.equal(client.evaluatedSequence(), undefined);
});

for (const initialFloor of [undefined, 0n]) {
  test(`concurrent queries retain floor ${initialFloor} and late responses cannot lower observations`, { timeout: 10000 }, async (t) => {
    const started = [deferred(), deferred()];
    const replies = [deferred(), deferred()];
    const floors = [];
    t.mock.method(globalThis, 'fetch', async (_input, init) => {
      const index = floors.length;
      floors.push(fromBinary(QueryRequestSchema, init.body).minSequenceNumber);
      if (index < 2) {
        started[index].resolve();
        return replies[index].promise;
      }
      return response(20n);
    });
    const client = SqlClient.monotonic('http://sql.test', initialFloor, options);
    const first = client.query('SELECT * FROM items');
    const second = client.query('SELECT * FROM items');
    await Promise.all(started.map((event) => event.promise));
    replies[1].resolve(response(20n));
    await second;
    replies[0].resolve(response(10n));
    const older = await first;
    assert.equal(older.sequenceNumber, 10n);
    assert.equal(client.evaluatedSequence(), 20n);
    await client.query('SELECT * FROM items');
    assert.deepEqual(floors, [initialFloor, initialFloor, 20n]);
  });
}

test('an unseeded query can be cancelled independently of another pending query', { timeout: 10000 }, async (t) => {
  const started = deferred();
  const reply = deferred();
  const secondStarted = deferred();
  const floors = [];
  t.mock.method(globalThis, 'fetch', async (_input, init) => {
    floors.push(fromBinary(QueryRequestSchema, init.body).minSequenceNumber);
    if (floors.length === 1) {
      started.resolve();
      return reply.promise;
    }
    return new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(init.signal.reason), { once: true });
      secondStarted.resolve();
    });
  });
  const client = new SqlClient('http://sql.test', options);
  const first = client.query('SELECT * FROM items');
  await started.promise;
  const abort = new AbortController();
  const second = client.query('SELECT * FROM items', undefined, { signal: abort.signal });
  const rejected = assert.rejects(second, /cancel|abort/i);
  await secondStarted.promise;
  abort.abort();
  await rejected;
  assert.equal(client.evaluatedSequence(), undefined);
  reply.resolve(response(8n));
  await first;
  assert.deepEqual(floors, [undefined, undefined]);
});

test('successful Store observation survives Arrow decoding failure', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => response(9n, new Uint8Array()));
  const client = new SqlClient('http://sql.test', options);
  await assert.rejects(client.query('SELECT * FROM items'));
  assert.equal(client.evaluatedSequence(), 9n);
});

test('rejected queries do not observe and later queries can establish a floor', async (t) => {
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async () => {
    if (calls++ === 0) {
      return new Response(JSON.stringify({ code: 'invalid_argument', message: 'bad SQL' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      });
    }
    return response(0n);
  });
  const client = new SqlClient('http://sql.test', options);
  await assert.rejects(client.query('invalid'));
  assert.equal(client.evaluatedSequence(), undefined);
  await client.query('SELECT * FROM items');
  assert.equal(client.minSequenceNumber(), 0n);
});

test('invalid minimums fail before sending a query', async (t) => {
  t.mock.method(globalThis, 'fetch', () => { throw new Error('must not send'); });
  for (const invalid of [-1n, 1n << 64n, 0, null]) {
    assert.throws(() => SqlClient.fixed('http://sql.test', invalid, options), /bigint|u64/);
    assert.throws(() => SqlClient.monotonic('http://sql.test', invalid, options), /bigint|u64/);
    const client = new SqlClient('http://sql.test', options);
    await assert.rejects(client.query('SELECT 1', invalid), /bigint|u64/);
  }
});
