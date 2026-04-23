import { useEffect, useMemo, useRef, useState } from 'react';
import {
  SqlClient,
  type CellValue,
  type DecodedQueryResult,
  type DecodedSubscribeFrame,
} from '@sql-ts';

export const SQL_URL = import.meta.env.VITE_SQL_URL as string | undefined;
const MAX_EVENTS = 10;
const DEFAULT_TABLE = 'orders_kv';
const DEFAULT_WHERE = "region = 'us-east' AND amount_cents >= 2000";
const DEFAULT_QUERY = `SELECT region, COUNT(*) AS order_count, SUM(amount_cents) AS total_cents
FROM ${DEFAULT_TABLE}
GROUP BY region`;

interface NotificationFn {
  (type: 'success' | 'error', title: string, message: string): void;
}

function formatCell(value: CellValue): string {
  if (value === null) return 'NULL';
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Uint8Array) {
    return `0x${Array.from(value)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('')}`;
  }
  if (typeof value === 'string') return value;
  return String(value);
}

export function SqlPanel({
  sqlUrl,
  showNotification,
}: {
  sqlUrl: string;
  showNotification: NotificationFn;
}) {
  const client = useMemo(() => new SqlClient(sqlUrl), [sqlUrl]);
  const subscribeAbortRef = useRef<AbortController | null>(null);

  const [isConnected, setIsConnected] = useState(false);
  const [table, setTable] = useState(DEFAULT_TABLE);
  const [whereSql, setWhereSql] = useState(DEFAULT_WHERE);
  const [sinceSequenceNumber, setSinceSequenceNumber] = useState('');
  const [events, setEvents] = useState<DecodedSubscribeFrame[]>([]);
  const [isSubscribing, setIsSubscribing] = useState(false);

  const [querySql, setQuerySql] = useState(DEFAULT_QUERY);
  const [queryResult, setQueryResult] = useState<DecodedQueryResult | null>(null);
  const [isQuerying, setIsQuerying] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const response = await fetch(`${sqlUrl.replace(/\/$/, '')}/health`, {
          signal: controller.signal,
        });
        setIsConnected(response.ok);
      } catch {
        setIsConnected(false);
      }
    })();

    return () => {
      controller.abort();
      subscribeAbortRef.current?.abort();
    };
  }, [sqlUrl]);

  const handleQuery = async () => {
    setIsQuerying(true);
    setQueryResult(null);
    try {
      const result = await client.query(querySql);
      setQueryResult(result);
      showNotification('success', 'SQL Query', `Returned ${result.rows.length} rows`);
    } catch (error) {
      showNotification('error', 'SQL Query Failed', String(error));
    } finally {
      setIsQuerying(false);
    }
  };

  const handleStartSubscribe = () => {
    subscribeAbortRef.current?.abort();
    setEvents([]);
    setIsSubscribing(true);

    const controller = new AbortController();
    subscribeAbortRef.current = controller;
    const since = sinceSequenceNumber.trim() ? BigInt(sinceSequenceNumber.trim()) : undefined;

    void (async () => {
      try {
        for await (const frame of client.subscribe(
          {
            table: table.trim(),
            whereSql: whereSql.trim(),
            sinceSequenceNumber: since,
          },
          { signal: controller.signal },
        )) {
          setEvents((previous) => [frame, ...previous].slice(0, MAX_EVENTS));
        }
      } catch (error) {
        if (!controller.signal.aborted) {
          showNotification('error', 'SQL Subscribe Failed', String(error));
        }
      } finally {
        if (subscribeAbortRef.current === controller) {
          subscribeAbortRef.current = null;
        }
        setIsSubscribing(false);
      }
    })();

    showNotification(
      'success',
      'SQL Subscribe',
      whereSql.trim()
        ? `Streaming rows where ${whereSql.trim()}`
        : 'Streaming every decoded row',
    );
  };

  const handleStopSubscribe = () => {
    subscribeAbortRef.current?.abort();
    subscribeAbortRef.current = null;
    setIsSubscribing(false);
  };

  return (
    <div className="card fade-in">
      <h2>SQL</h2>

      <div className="form-section">
        <h3>Connection</h3>
        <p className="section-note">
          Run `sql run` to serve `store.sql.v1` and `sql seed` to insert rows
          into <code>{DEFAULT_TABLE}</code> every few seconds. Subscribe re-runs the
          SQL WHERE predicate against every ingested batch; matching rows come
          back per-batch.
        </p>
        <p><strong>Server:</strong> {sqlUrl}</p>
        <p><strong>Status:</strong> {isConnected ? 'Connected' : 'Disconnected'}</p>
      </div>

      <div className="form-section">
        <h3>Query</h3>
        <div className="form-row">
          <div className="form-group form-group-wide">
            <label htmlFor="sql-query">SQL</label>
            <textarea
              id="sql-query"
              rows={4}
              value={querySql}
              onChange={(event) => setQuerySql(event.target.value)}
            />
          </div>
        </div>
        <button
          className={`btn-primary ${isQuerying ? 'loading' : ''}`}
          onClick={handleQuery}
          disabled={isQuerying || !querySql.trim()}
        >
          {isQuerying ? 'Running...' : 'Run Query'}
        </button>
        {queryResult && (
          <div className="result fade-in">
            <h4>Rows ({queryResult.rows.length})</h4>
            {queryResult.rows.length === 0 ? (
              <p>No rows returned</p>
            ) : (
              <div className="result-list">
                {queryResult.rows.map((row, index) => (
                  <div key={index} className="result-row-block">
                    {queryResult.columns.map((column) => (
                      <p key={column}>
                        <strong>{column}:</strong> {formatCell(row.values[column])}
                      </p>
                    ))}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="form-section">
        <h3>Subscribe</h3>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="sql-table">Table</label>
            <input
              id="sql-table"
              type="text"
              value={table}
              onChange={(event) => setTable(event.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="sql-since">Since Sequence (optional)</label>
            <input
              id="sql-since"
              type="number"
              min="0"
              value={sinceSequenceNumber}
              onChange={(event) => setSinceSequenceNumber(event.target.value)}
            />
          </div>
        </div>
        <div className="form-row">
          <div className="form-group form-group-wide">
            <label htmlFor="sql-where">WHERE predicate</label>
            <input
              id="sql-where"
              type="text"
              placeholder="e.g. region = 'us-east' AND amount_cents >= 2000"
              value={whereSql}
              onChange={(event) => setWhereSql(event.target.value)}
            />
          </div>
        </div>
        <div className="button-row">
          <button
            className={`btn-primary ${isSubscribing ? 'loading' : ''}`}
            onClick={handleStartSubscribe}
            disabled={isSubscribing || !table.trim()}
          >
            {isSubscribing ? 'Listening...' : 'Start Subscribe'}
          </button>
          <button
            className="btn-secondary"
            onClick={handleStopSubscribe}
            disabled={!isSubscribing}
          >
            Stop
          </button>
          <button
            className="btn-secondary"
            onClick={() => setEvents([])}
            disabled={events.length === 0}
          >
            Clear Events
          </button>
        </div>
        <div className="result fade-in">
          <h4>Per-Batch Matches ({events.length})</h4>
          {events.length === 0 ? (
            <p>{isSubscribing ? 'Waiting for matching batches...' : 'No matches yet.'}</p>
          ) : (
            <div className="result-list">
              {events.map((frame) => (
                <div
                  key={frame.sequenceNumber.toString()}
                  className="result-row-block"
                >
                  <p>
                    <strong>Sequence:</strong> {frame.sequenceNumber.toString()}
                    {' · '}
                    <strong>Rows:</strong> {frame.rows.length}
                  </p>
                  {frame.rows.map((row, index) => (
                    <div
                      key={index}
                      className="result-row-block"
                    >
                      {frame.columns.map((column) => (
                        <p key={column}>
                          <strong>{column}:</strong> {formatCell(row.values[column])}
                        </p>
                      ))}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
