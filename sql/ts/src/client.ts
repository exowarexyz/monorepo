import { create } from '@bufbuild/protobuf';
import { createClient, type CallOptions, type Client as ConnectClient } from '@connectrpc/connect';
import {
  createTransport,
  SqlService,
  SqlQueryRequestSchema,
  SqlSubscribeRequestSchema,
  type ClientOptions as SdkClientOptions,
  type SqlCell,
  type SqlQueryResponse,
  type SqlRow,
  type SqlSubscribeResponse,
} from 'exoware-sdk-ts';

export type SqlClientOptions = SdkClientOptions;

/**
 * Typed view of a single row cell. `null` means the server emitted an empty
 * `kind` oneof (SQL NULL).
 */
export type CellValue = bigint | number | boolean | string | Uint8Array | null;

export interface DecodedRow {
  /** Column → value. Columns are in the same order as the `columns` array. */
  values: Record<string, CellValue>;
  /** Parallel array of values for positional access. */
  cells: CellValue[];
}

export interface DecodedQueryResult {
  columns: string[];
  rows: DecodedRow[];
}

export interface DecodedSubscribeFrame {
  sequenceNumber: bigint;
  columns: string[];
  rows: DecodedRow[];
}

function cellToValue(cell: SqlCell): CellValue {
  switch (cell.kind.case) {
    case 'int64Value':
      return cell.kind.value;
    case 'float64Value':
      return cell.kind.value;
    case 'booleanValue':
      return cell.kind.value;
    case 'utf8Value':
      return cell.kind.value;
    case 'bytesValue':
      return cell.kind.value;
    default:
      return null;
  }
}

function decodeRow(row: SqlRow, columns: string[]): DecodedRow {
  const cells = row.cells.map(cellToValue);
  const values: Record<string, CellValue> = {};
  columns.forEach((column, index) => {
    values[column] = cells[index] ?? null;
  });
  return { values, cells };
}

function decodeQuery(response: SqlQueryResponse): DecodedQueryResult {
  const columns = response.column;
  return {
    columns,
    rows: response.rows.map((row) => decodeRow(row, columns)),
  };
}

function decodeSubscribe(response: SqlSubscribeResponse): DecodedSubscribeFrame {
  const columns = response.column;
  return {
    sequenceNumber: response.sequenceNumber,
    columns,
    rows: response.rows.map((row) => decodeRow(row, columns)),
  };
}

/**
 * Thin wrapper around the `store.sql.v1.Service` Connect client.
 *
 * `subscribe` re-runs the server-side predicate on every ingest batch that
 * touches the named table and yields one frame per batch of matching rows.
 * `query` runs an arbitrary SQL statement against the server's session and
 * returns rows as typed cells.
 */
export class SqlClient {
  private readonly rpc: ConnectClient<typeof SqlService>;

  constructor(baseUrl: string, options: SqlClientOptions = {}) {
    const transport = createTransport(baseUrl, options);
    this.rpc = createClient(SqlService, transport);
  }

  async query(sql: string, options?: CallOptions): Promise<DecodedQueryResult> {
    const response = await this.rpc.query(
      create(SqlQueryRequestSchema, { sql }),
      options,
    );
    return decodeQuery(response);
  }

  async *subscribe(
    request: {
      table: string;
      whereSql?: string;
      sinceSequenceNumber?: bigint;
    },
    options?: CallOptions,
  ): AsyncIterable<DecodedSubscribeFrame> {
    const stream = this.rpc.subscribe(
      create(SqlSubscribeRequestSchema, {
        table: request.table,
        whereSql: request.whereSql ?? '',
        ...(request.sinceSequenceNumber !== undefined
          ? { sinceSequenceNumber: request.sinceSequenceNumber }
          : {}),
      }),
      options,
    );
    for await (const frame of stream) {
      yield decodeSubscribe(frame);
    }
  }
}
