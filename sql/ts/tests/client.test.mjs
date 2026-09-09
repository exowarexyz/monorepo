import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { encodeEnvelopes } from '@connectrpc/connect/protocol';
import { DataType, SqlClient, Table, TimeUnit } from '../dist/index.js';
import { QueryRequestSchema, QueryResponseSchema } from '../dist/generated/proto/sql/v1/query_pb.js';
import { SubscribeResponseSchema } from '../dist/generated/proto/sql/v1/stream_pb.js';

const fixture = (name) => readFile(new URL(`fixtures/${name}.arrow`, import.meta.url));

function clientFor(t, body, streaming = false) {
  t.mock.method(globalThis, 'fetch', async (_input, init) => {
    const contentType = streaming ? 'application/connect+proto' : 'application/proto';
    assert.equal(new Headers(init.headers).get('content-type'), contentType);
    return new Response(body, { headers: { 'content-type': contentType } });
  });
  return new SqlClient('http://sql.test', { token: '' });
}

async function queryFixture(t, name) {
  const sequenceNumber = 9007199254740993n;
  const body = toBinary(QueryResponseSchema, create(QueryResponseSchema, { sequenceNumber, results: await fixture(name) }));
  const response = await clientFor(t, body).query('SELECT fixture');
  assert.equal(response.sequenceNumber, sequenceNumber);
  return response;
}

test('Rust SQL results retain computed types and exact column buffers', async (t) => {
  const { table } = await queryFixture(t, 'computed');
  assert.ok(table instanceof Table);
  assert.equal(table.numRows, 1);
  const column = (name) => table.getChild(name);
  for (const [name, unit, value] of [
    ['seconds', TimeUnit.SECOND, 1n],
    ['milliseconds', TimeUnit.MILLISECOND, 1n],
    ['microseconds', TimeUnit.MICROSECOND, 1n],
    ['nanoseconds', TimeUnit.NANOSECOND, 1735689600123456789n],
    ['zoned', TimeUnit.NANOSECOND, 1735689600123456789n],
  ]) {
    assert.equal(column(name).type.unit, unit);
    assert.equal(column(name).toArray()[0], value);
  }
  assert.equal(column('zoned').type.timezone, 'UTC');
  assert.equal(column('decimal_integer').type.scale, 0);
  assert.equal(column('decimal_fraction').type.scale, 2);
  assert.equal(String(column('decimal_integer').get(0)), '1');
  assert.equal(String(column('decimal_fraction').get(0)), '1');
  assert.equal(column('tiny').get(0), -7);
  assert.equal(column('small').get(0), -300);
  assert.equal(column('nested').get(0).value, 42n);
  assert.equal(column('nested').get(0).missing, null);
  assert.ok(DataType.isMap(column('mapping').type));
  assert.ok(DataType.isInterval(column('duration').type));
  assert.equal(column('date32_far').data[0].values[0], 100000001);
  assert.equal(column('date32_negative').data[0].values[0], -100000001);
  assert.equal(column('date64_far').data[0].values[0], 8640000086400000n);
  assert.equal(column('seconds_extreme').toArray()[0], 9223372036854775807n);
});

test('Rust batch layouts preserve nulls, views, nested values, and wide decimals', async (t) => {
  const { table } = await queryFixture(t, 'layouts');
  const column = (name) => table.getChild(name);
  assert.equal(table.numRows, 3);
  assert.equal(column('dates').data[0].values[0], 9223372036828800000n);
  assert.equal(column('dates').isValid(1), false);
  assert.equal(column('dates').data[1].values[1], -9223372036828800000n);
  assert.deepEqual([...column('binary0').get(0)], []);
  assert.equal(column('binary0').get(1), null);
  assert.deepEqual([...column('binary300').get(2)], Array(300).fill(9));
  assert.equal(column('binary300').get(1), null);
  assert.equal(column('text_view').get(1), 'this value lives outside the inline view');
  assert.equal(column('text_view').get(2), null);
  assert.equal(new TextDecoder().decode(column('binary_view').get(1)), 'this binary value also exceeds twelve bytes');
  assert.deepEqual([...column('large_list').get(0)], [1n, null]);
  assert.equal(column('large_list').get(1), null);
  assert.deepEqual([...column('large_list').get(2)], []);
  assert.equal(column('decimal256').type.bitWidth, 256);
  assert.equal(column('decimal256').type.scale, 2);
  assert.deepEqual([...column('decimal256').get(0)], [4294954951, ...Array(7).fill(4294967295)]);
  assert.deepEqual([...column('decimal256').get(2)], [1, 2097152, ...Array(6).fill(0)]);
  assert.deepEqual([...column('all_null')], [null, null, null]);
});

test('empty results retain schema and zero-column results retain row count', async (t) => {
  const { table: empty } = await queryFixture(t, 'empty');
  assert.equal(empty.numRows, 0);
  assert.equal(empty.getChild('decimal_fraction').type.scale, 2);
  const { table: zero } = await queryFixture(t, 'zero_columns');
  assert.equal(zero.numCols, 0);
  assert.equal(zero.numRows, 3);
});

test('duplicate column names retain distinct positional types', async (t) => {
  const { table } = await queryFixture(t, 'duplicates');
  assert.deepEqual(table.schema.fields.map((field) => field.name), ['id', 'id']);
  assert.deepEqual(table.schema.fields.map((field) => field.type.toString()), ['Int64', 'Utf8']);
  assert.equal(table.getChildAt(0).get(0), 1n);
  assert.equal(table.getChildAt(1).get(0), 'two');
});

test('queries forward optional sequence floors and call options', async (t) => {
  const results = await fixture('empty');
  for (const minSequenceNumber of [undefined, 0n, 9007199254740993n]) {
    await t.test(String(minSequenceNumber), async (t) => {
      const sequenceNumber = minSequenceNumber ?? 0n;
      const body = toBinary(QueryResponseSchema, create(QueryResponseSchema, { sequenceNumber, results }));
      t.mock.method(globalThis, 'fetch', async (_input, init) => {
        const request = fromBinary(QueryRequestSchema, init.body);
        assert.equal(request.sql, 'SELECT fixture');
        assert.equal(request.minSequenceNumber, minSequenceNumber);
        assert.equal(new Headers(init.headers).get('x-query-test'), 'forwarded');
        return new Response(body, { headers: { 'content-type': 'application/proto' } });
      });

      const client = new SqlClient('http://sql.test', { token: '' });
      const response = await client.query('SELECT fixture', minSequenceNumber, {
        headers: { 'x-query-test': 'forwarded' },
      });
      assert.equal(response.sequenceNumber, sequenceNumber);
      assert.equal(response.table.numRows, 0);
    });
  }
});

test('subscription frames decode independently and retain their sequence', async (t) => {
  const results = await fixture('subscription');
  const envelopes = [42n, 43n].map((sequenceNumber) => ({
    flags: 0,
    data: toBinary(SubscribeResponseSchema, create(SubscribeResponseSchema, { sequenceNumber, results })),
  }));
  envelopes.push({ flags: 2, data: new TextEncoder().encode('{}') });
  const frames = [];
  for await (const frame of clientFor(t, encodeEnvelopes(...envelopes), true).subscribe({ table: 'orders' })) {
    frames.push(frame);
  }
  assert.deepEqual(frames.map((frame) => frame.sequenceNumber), [42n, 43n]);
  for (const frame of frames) assert.deepEqual([...frame.table.getChild('id')], [2n, 3n]);
});

test('missing or malformed IPC rejects the query', async (t) => {
  for (const results of [new Uint8Array(), new Uint8Array([1, 2, 3, 4]), (await fixture('computed')).subarray(0, 20)]) {
    const body = toBinary(QueryResponseSchema, create(QueryResponseSchema, { results }));
    await assert.rejects(clientFor(t, body).query('SELECT fixture'));
  }
});
