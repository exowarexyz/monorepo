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
