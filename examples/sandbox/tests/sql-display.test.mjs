import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

for (const [name, expected] of [
  ['layouts', [
    '-123.45', '90071992547409.93', 'NULL',
    '<strong>large_list:</strong> [1, NULL]',
    '9223372036828800000 millisecond since epoch',
    '-9223372036828800000 millisecond since epoch',
  ]],
  ['computed', [
    '0.01', '-12345.00', '1735689600123456789 nanosecond since epoch (UTC)',
    '100000001 day since epoch', '-100000001 day since epoch',
    '8640000086400000 millisecond since epoch',
    '9223372036854775807 second since epoch (no timezone)',
  ]],
]) {
  test(`SQL ${name} cells display exact temporal and signed decimal values`, async () => {
    const server = await createServer({ server: { middlewareMode: true } });
    try {
      const { ArrowRows } = await server.ssrLoadModule('/src/SqlPanel.tsx');
      const { RecordBatchReader, Table } = await server.ssrLoadModule('../../sql/ts/node_modules/apache-arrow/Arrow.node.mjs');
      const bytes = await readFile(new URL(`../../../sql/ts/tests/fixtures/${name}.arrow`, import.meta.url));
      const table = new Table(RecordBatchReader.from(bytes));
      const html = renderToStaticMarkup(createElement(ArrowRows, { table }));
      for (const value of expected) assert.ok(html.includes(value), `${name}: missing ${value}`);
    } finally {
      await server.close();
    }
  });
}

test('SQL temporal lists preserve exact values and nulls in sliced vectors', async () => {
  const server = await createServer({ server: { middlewareMode: true } });
  try {
    const { ArrowRows } = await server.ssrLoadModule('/src/SqlPanel.tsx');
    const { DateMillisecond, Field, List, Map_: ArrowMap, Struct, Table, TimestampSecond, TimestampNanosecond, Utf8, makeData, makeVector, vectorFromArray } =
      await server.ssrLoadModule('../../sql/ts/node_modules/apache-arrow/Arrow.node.mjs');
    for (const [type, value, expected] of [
      [new TimestampSecond(), 9223372036854775807n, '9223372036854775807 second since epoch (no timezone)'],
      [new TimestampNanosecond('UTC'), 1735689600123456789n, '1735689600123456789 nanosecond since epoch (UTC)'],
      [new DateMillisecond(), 9223372036828800000n, '9223372036828800000 millisecond since epoch'],
    ]) {
      const child = makeData({
        type,
        length: 4,
        data: new BigInt64Array([0n, value, 0n, -value]),
        nullBitmap: new Uint8Array([0b1011]),
        nullCount: 1,
      });
      const times = makeVector(makeData({
        type: new List(new Field('item', type, true)),
        length: 2,
        valueOffsets: new Int32Array([0, 1, 4]),
        child,
      })).slice(1, 2);
      const table = new Table({ times });
      const html = renderToStaticMarkup(createElement(ArrowRows, { table }));
      assert.ok(html.includes(`[${expected}, NULL, -${expected}]`), html);

      const structure = makeVector(makeData({
        type: new Struct([new Field('value', type, true)]),
        length: 3,
        children: [child.slice(1, 3)],
      }));
      const entries = makeData({
        type: new Struct([new Field('key', new Utf8(), false), new Field('value', type, true)]),
        length: 3,
        children: [vectorFromArray(['first', 'missing', 'last'], new Utf8()).data[0], child.slice(1, 3)],
      });
      const mapping = makeVector(makeData({
        type: new ArrowMap(new Field('entries', entries.type, false)),
        length: 1,
        valueOffsets: new Int32Array([0, 3]),
        child: entries,
      }));
      for (const values of [structure.slice(0, 1).concat(structure.slice(1, 3)), mapping]) {
        const html = renderToStaticMarkup(createElement(ArrowRows, { table: new Table({ values }) }));
        for (const value of [expected, `-${expected}`, 'value: NULL']) assert.ok(html.includes(value), html);
      }
    }
  } finally {
    await server.close();
  }
});
