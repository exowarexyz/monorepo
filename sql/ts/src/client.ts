import { RecordBatchReader, Table } from 'apache-arrow';
import { create } from '@bufbuild/protobuf';
import { createClient, type CallOptions, type Client as ConnectClient } from '@connectrpc/connect';
import {
  createTransport,
  type ClientOptions as SdkClientOptions,
} from '@exowarexyz/sdk';
import {
  QueryRequestSchema as SqlQueryRequestSchema,
  type QueryResponse as SqlQueryResponse,
} from './generated/proto/sql/v1/query_pb.js';
import {
  IndexLayout as SqlIndexLayout,
  TablesRequestSchema as SqlTablesRequestSchema,
  type Column as SqlColumn,
  type Index as SqlIndex,
  type Table as SqlTable,
} from './generated/proto/sql/v1/schema_pb.js';
import { Service as SqlService } from './generated/proto/sql/v1/service_pb.js';
import {
  SubscribeRequestSchema as SqlSubscribeRequestSchema,
  type SubscribeResponse as SqlSubscribeResponse,
} from './generated/proto/sql/v1/stream_pb.js';
export type SqlClientOptions = SdkClientOptions;

export interface DecodedQueryResult {
  sequenceNumber: bigint;
  table: Table;
}

export interface DecodedSubscribeFrame {
  sequenceNumber: bigint;
  table: Table;
}

export interface DecodedColumn {
  name: string;
  /** Arrow DataType debug string, e.g. `Int64`, `Utf8`, `Decimal128(38, 10)`. */
  dataType: string;
  nullable: boolean;
}

export type DecodedIndexLayout = 'lexicographic' | 'zorder';

export interface DecodedIndex {
  name: string;
  layout: DecodedIndexLayout;
  /** Names of columns in key order. */
  keyColumns: string[];
  /** Names of columns included in the index payload ("covered"). */
  coverColumns: string[];
}

export interface DecodedTable {
  name: string;
  columns: DecodedColumn[];
  /** Names of primary-key columns in key-sort order. */
  primaryKeyColumns: string[];
  indexes: DecodedIndex[];
}

function decodeTableStream(bytes: Uint8Array): Table {
  const reader = RecordBatchReader.from(bytes).open();
  if (!reader.schema) {
    throw new Error('SQL response is missing its Arrow schema');
  }

  // Arrow 21.2 merges duplicate field names when rebuilding batch schemas
  const schema = reader.schema;
  const batches = reader.readAll().map((batch) => Object.assign(batch, { schema }));
  return new Table(schema, batches);
}

function decodeQuery(response: SqlQueryResponse): DecodedQueryResult {
  return {
    sequenceNumber: response.sequenceNumber,
    table: decodeTableStream(response.results),
  };
}

function decodeSubscribe(response: SqlSubscribeResponse): DecodedSubscribeFrame {
  return {
    sequenceNumber: response.sequenceNumber,
    table: decodeTableStream(response.results),
  };
}

function decodeLayout(layout: SqlIndexLayout): DecodedIndexLayout {
  return layout === SqlIndexLayout.Z_ORDER ? 'zorder' : 'lexicographic';
}

function decodeColumn(column: SqlColumn): DecodedColumn {
  return {
    name: column.name,
    dataType: column.dataType,
    nullable: column.nullable,
  };
}

function decodeIndex(index: SqlIndex, columnNames: string[]): DecodedIndex {
  const lookup = (idx: number) => columnNames[idx] ?? `#${idx}`;
  return {
    name: index.name,
    layout: decodeLayout(index.layout),
    keyColumns: index.keyColumns.map(lookup),
    coverColumns: index.coverColumns.map(lookup),
  };
}

function decodeTable(table: SqlTable): DecodedTable {
  const columns = table.columns.map(decodeColumn);
  const columnNames = columns.map((c) => c.name);
  const lookup = (idx: number) => columnNames[idx] ?? `#${idx}`;
  return {
    name: table.name,
    columns,
    primaryKeyColumns: table.primaryKeyColumns.map(lookup),
    indexes: table.indexes.map((index) => decodeIndex(index, columnNames)),
  };
}

/**
 * Thin wrapper around the `sql.v1.Service` Connect client.
 *
 * `subscribe` evaluates a compiled scalar predicate on every ingest batch
 * that touches the named table and yields one frame per batch of matching rows.
 * `query` runs an arbitrary SQL statement against the server's session and
 * returns the observed Store sequence and a native Arrow Table with its result
 * schema and column buffers.
 */
export class SqlClient {
  private readonly rpc: ConnectClient<typeof SqlService>;

  constructor(baseUrl: string, options: SqlClientOptions = {}) {
    const transport = createTransport(baseUrl, { useBinaryFormat: true, ...options });
    this.rpc = createClient(SqlService, transport);
  }

  async query(
    sql: string,
    minSequenceNumber?: bigint,
    options?: CallOptions,
  ): Promise<DecodedQueryResult> {
    const response = await this.rpc.query(
      create(SqlQueryRequestSchema, {
        sql,
        ...(minSequenceNumber !== undefined ? { minSequenceNumber } : {}),
      }),
      options,
    );
    return decodeQuery(response);
  }

  async tables(options?: CallOptions): Promise<DecodedTable[]> {
    const response = await this.rpc.tables(
      create(SqlTablesRequestSchema, {}),
      options,
    );
    return response.tables.map(decodeTable);
  }

  async *subscribe(
    request: {
      table: string;
      /**
       * Scalar SQL boolean expression over the table's columns, without WHERE.
       * Empty emits every row. Subqueries, aggregates, window functions, and
       * row-expanding expressions are unsupported. Stable time functions use
       * the subscription start time. Volatile functions run for each batch.
       */
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
