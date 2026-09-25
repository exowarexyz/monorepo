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

function minimumSequence(value?: bigint): bigint | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'bigint') throw new TypeError('minimum sequence number must be a bigint');
  if (value < 0n || value > (1n << 64n) - 1n) {
    throw new RangeError('minimum sequence number must fit in u64');
  }
  return value;
}

function maxSequence(left?: bigint, right?: bigint): bigint | undefined {
  if (left === undefined) return right;
  if (right === undefined) return left;
  return left > right ? left : right;
}

export interface DecodedQueryResult {
  sequenceNumber: bigint | undefined;
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

function decodeQueryResult(response: SqlQueryResponse): DecodedQueryResult {
  return {
    sequenceNumber: response.sequenceNumber,
    table: decodeTableStream(response.results),
  };
}

function decodeSubscribeFrame(response: SqlSubscribeResponse): DecodedSubscribeFrame {
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
 * SQL client with a fixed or monotonic minimum Store sequence across queries.
 *
 * `subscribe` evaluates a compiled scalar predicate on every ingest batch
 * that touches the named table and yields one frame per batch of matching rows.
 * `query` runs an arbitrary SQL statement against the server's session and
 * returns the optional observed Store sequence and a native Arrow Table.
 * Subscriptions retain their own resume cursor and do not advance query observations.
 */
export class SqlClient {
  private readonly rpc: ConnectClient<typeof SqlService>;
  private policy: 'fixed' | 'monotonic' = 'monotonic';
  private configuredFloor: bigint | undefined;
  private observedSequence: bigint | undefined;

  /** Create a monotonic client with no initial minimum. */
  constructor(baseUrl: string, options: SqlClientOptions = {}) {
    const transport = createTransport(baseUrl, { useBinaryFormat: true, ...options });
    this.rpc = createClient(SqlService, transport);
  }

  /** Create a client whose minimum advances to its highest observed sequence. */
  static monotonic(
    baseUrl: string,
    initialFloor?: bigint,
    options: SqlClientOptions = {},
  ): SqlClient {
    const floor = minimumSequence(initialFloor);
    const client = new SqlClient(baseUrl, options);
    client.configuredFloor = floor;
    return client;
  }

  /** Create a client whose configured minimum stays fixed across queries. */
  static fixed(
    baseUrl: string,
    floor?: bigint,
    options: SqlClientOptions = {},
  ): SqlClient {
    const client = SqlClient.monotonic(baseUrl, floor, options);
    client.policy = 'fixed';
    return client;
  }

  minSequenceNumber(): bigint | undefined {
    return this.policy === 'fixed'
      ? this.configuredFloor
      : maxSequence(this.configuredFloor, this.observedSequence);
  }

  evaluatedSequence(): bigint | undefined {
    return this.observedSequence;
  }

  /** An explicit minimum can strengthen this query without changing the configured floor. */
  async query(
    sql: string,
    minSequenceNumber?: bigint,
    options?: CallOptions,
  ): Promise<DecodedQueryResult> {
    const requested = minimumSequence(minSequenceNumber);
    const floor = maxSequence(this.minSequenceNumber(), requested);
    const response = await this.rpc.query(
      create(SqlQueryRequestSchema, {
        sql,
        ...(floor !== undefined ? { minSequenceNumber: floor } : {}),
      }),
      options,
    );
    this.observedSequence = maxSequence(this.observedSequence, response.sequenceNumber);
    return decodeQueryResult(response);
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
      yield decodeSubscribeFrame(frame);
    }
  }
}
