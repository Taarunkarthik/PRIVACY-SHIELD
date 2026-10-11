import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { ArrowRight, Braces, ChevronRight, Database, KeyRound, Layers3, Link2, RefreshCw, Search, Table2, Waypoints } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { useAuth } from '../api/auth';
import { connectionError, defaultConnectionId, discoveryScope } from '../api/connections';
import type { Connection, ConnectionPage, SchemaSnapshot, SchemaTable } from '../api/connections';

const tableKey = (table: Pick<SchemaTable, 'schema' | 'name'>) => JSON.stringify([table.schema, table.name]);
const tableLabel = (table: SchemaTable) => `${table.schema}.${table.name}`;

export function SchemaExplorer() {
  const { user } = useAuth();
  const canDiscover = user?.role === 'ADMIN' || user?.role === 'ANALYST';
  const [params, setParams] = useSearchParams();
  const [connections, setConnections] = useState<Connection[]>([]);
  const [connectionsLoading, setConnectionsLoading] = useState(true);
  const [connectionsError, setConnectionsError] = useState('');
  const [snapshot, setSnapshot] = useState<SchemaSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [selectedTable, setSelectedTable] = useState('');
  const [tableFilter, setTableFilter] = useState('');
  const [columnFilter, setColumnFilter] = useState('');
  const [schemas, setSchemas] = useState('');
  const [discovering, setDiscovering] = useState(false);
  const connectionId = params.get('connection') || defaultConnectionId(connections);
  const selectedConnection = connections.find((item) => item.id === connectionId);

  useEffect(() => {
    const controller = new AbortController();
    setConnectionsLoading(true);
    setConnectionsError('');
    async function loadConnections() {
      const first = await api<ConnectionPage>('/connections?page=1&page_size=100', { signal: controller.signal });
      const all = [...first.items];
      for (let page = 2; page <= Math.ceil(first.total / 100); page++) {
        const next = await api<ConnectionPage>(`/connections?page=${page}&page_size=100`, { signal: controller.signal });
        all.push(...next.items);
      }
      if (!controller.signal.aborted) setConnections(all);
    }
    loadConnections().catch((reason: unknown) => { if (!controller.signal.aborted) setConnectionsError(connectionError(reason)); })
      .finally(() => { if (!controller.signal.aborted) setConnectionsLoading(false); });
    return () => controller.abort();
  }, [refresh]);

  useEffect(() => {
    if (!selectedConnection) { setSnapshot(null); return; }
    const controller = new AbortController();
    setLoading(true);
    setError('');
    setSnapshot(null);
    setSelectedTable('');
    setTableFilter('');
    setColumnFilter('');
    api<SchemaSnapshot>(`/connections/${encodeURIComponent(connectionId)}/schema`, { signal: controller.signal })
      .then((result) => { if (!controller.signal.aborted) setSnapshot(result); })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted && !(reason instanceof ApiError && reason.status === 404)) setError(connectionError(reason));
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
    // Changes to connection identity or refresh reload the immutable saved snapshot.
  }, [connectionId, Boolean(selectedConnection), refresh]);

  async function discover() {
    if (!user || !selectedConnection?.is_active || discovering) return;
    setDiscovering(true);
    setError('');
    try {
      const result = await api<SchemaSnapshot>(`/connections/${encodeURIComponent(connectionId)}/discover`, {
        method: 'POST', csrfToken: user.csrf_token, body: JSON.stringify(discoveryScope(schemas)),
      });
      setSnapshot(result);
      setSelectedTable('');
      setTableFilter('');
      setColumnFilter('');
    } catch (reason) { setError(connectionError(reason)); }
    finally { setDiscovering(false); }
  }

  const tables = snapshot?.catalog.tables ?? [];
  const visibleTables = tables.filter((table) => tableLabel(table).toLowerCase().includes(tableFilter.toLowerCase()));
  const table = tables.find((item) => tableKey(item) === selectedTable) ?? visibleTables[0];
  const columns = table?.columns.filter((column) => `${column.name} ${column.data_type}`.toLowerCase().includes(columnFilter.toLowerCase())) ?? [];
  const selectTable = (value: string) => { setSelectedTable(value); setColumnFilter(''); };

  return <div className="page-content schema-page">
    <div className="page-heading"><div><h1>Schema Explorer<span className="heading-dot">.</span></h1><p className="page-description">Explore columns, keys, and relationships without viewing source records.</p></div><div className="heading-actions"><button className="button secondary" disabled={connectionsLoading || loading || discovering} onClick={() => setRefresh((value) => value + 1)}><RefreshCw size={15} /> Refresh</button>{selectedConnection && <Link className="button primary" to={`/scans?connection=${encodeURIComponent(connectionId)}`}>View scans <ArrowRight size={14} /></Link>}</div></div>
    <section className="panel schema-controls"><div className="form-field"><label htmlFor="schema-connection">Database connection</label><select id="schema-connection" value={selectedConnection ? connectionId : ''} onChange={(event) => { setParams({ connection: event.target.value }); setSchemas(''); }} disabled={connectionsLoading || discovering}><option value="" disabled>{connectionsLoading ? 'Loading connections…' : connections.length ? 'Choose a connection' : 'No connections saved'}</option>{connections.map((item) => <option key={item.id} value={item.id}>{item.name}{item.is_active ? '' : ' (inactive)'}</option>)}</select></div>{canDiscover && <><div className="form-field"><label htmlFor="discovery-schemas">Schemas to inspect <span>Optional</span></label><input id="discovery-schemas" value={schemas} onChange={(event) => setSchemas(event.target.value)} placeholder="Default: enterprise/public, or enter schema names" disabled={discovering} maxLength={1000} /></div><button className="button primary" onClick={discover} disabled={!selectedConnection?.is_active || discovering || loading}><Waypoints size={16} />{discovering ? 'Discovering…' : 'Discover schema'}</button></>}</section>
    {(error || connectionsError) && <div className="error-box" role="alert">{connectionsError || error}</div>}
    {connectionsLoading || loading ? <section className="panel data-empty" role="status"><div className="loading-ring" /><p>Loading discovered schema…</p></section> : !selectedConnection ? <section className="panel data-empty"><Database size={35} strokeWidth={1.3} /><h2>{connections.length ? 'Choose a saved connection' : 'Connect a database to begin'}</h2><p>{connections.length ? 'Select a database above to view its latest discovered schema.' : 'Your workspace needs an authorized connection before it can explore database structure.'}</p><Link to="/connections" className="button secondary">View connections <ArrowRight size={15} /></Link></section> : !snapshot ? <section className="panel data-empty"><Waypoints size={38} strokeWidth={1.2} /><h2>{error ? 'Schema could not be loaded' : 'No schema discovered yet'}</h2><p>{error ? 'Refresh or discover the schema again when the connection is available.' : canDiscover && selectedConnection.is_active ? 'Choose Discover schema to map the tables available to this connection.' : 'An administrator or analyst can discover this connection’s accessible schemas.'}</p>{!selectedConnection.is_active && <span className="pill">Connection is inactive</span>}</section> : <>
      <div className="schema-summary"><span><Layers3 size={15} /><strong>{snapshot.catalog.schemas.length}</strong> schemas</span><span><Table2 size={15} /><strong>{tables.length}</strong> tables</span><span><Braces size={15} /><strong>{tables.reduce((count, item) => count + item.columns.length, 0)}</strong> columns</span><p>Discovered {new Date(snapshot.discovered_at).toLocaleString()}</p></div>
      {!tables.length ? <section className="panel data-empty"><Database size={35} /><h2>No accessible tables found</h2><p>Check the selected schemas and scanner permissions, then discover again.</p></section> : <div className="schema-workspace">
        <aside className="panel schema-table-list" aria-label="Discovered tables"><div className="table-list-heading"><h2>Tables <span className="count-badge">{tables.length}</span></h2><div className="search-field"><Search size={15} /><input aria-label="Find tables" value={tableFilter} onChange={(event) => { setTableFilter(event.target.value); setSelectedTable(''); setColumnFilter(''); }} placeholder="Find a table…" /></div></div>{snapshot.catalog.schemas.map((schema) => { const inSchema = visibleTables.filter((item) => item.schema === schema); return inSchema.length ? <div className="schema-group" key={schema}><p><Database size={13} />{schema}<span>{inSchema.length}</span></p>{inSchema.map((item) => <button className={`table-select ${table && tableKey(table) === tableKey(item) ? 'selected' : ''}`} key={tableKey(item)} onClick={() => selectTable(tableKey(item))} aria-pressed={Boolean(table && tableKey(table) === tableKey(item))}><Table2 size={14} /><span>{item.name}</span><ChevronRight size={13} /></button>)}</div> : null; })}{!visibleTables.length && <p className="list-empty">No matching tables.</p>}</aside>
        {table ? <section className="panel table-details" aria-label={`Table ${tableLabel(table)}`}><div className="table-detail-heading"><div><p className="table-schema">{table.schema}</p><h2><Table2 size={21} />{table.name}</h2><p>{table.columns.length} columns <span>·</span> {table.row_estimate >= 0 ? `Approximately ${Math.round(table.row_estimate).toLocaleString()} rows` : 'Row estimate unavailable'}</p></div>{table.rls_enabled && <span className="pill">Row security enabled</span>}</div>
          <div className="column-toolbar"><h3>Columns</h3><div className="search-field"><Search size={14} /><input aria-label="Find columns" placeholder="Filter columns or types…" value={columnFilter} onChange={(event) => setColumnFilter(event.target.value)} /></div></div>
          <div className="table-scroll"><table className="columns-table"><thead><tr><th scope="col">Column</th><th scope="col">Data type</th><th scope="col">Nullable</th><th scope="col">Properties</th></tr></thead><tbody>{columns.map((column) => <tr key={column.name}><th scope="row"><span className="column-ordinal">{column.ordinal}</span>{column.name}</th><td><code>{column.data_type}</code></td><td>{column.nullable ? 'Yes' : 'No'}</td><td><div className="column-badges">{column.is_primary_key && <span className="pill key-pill"><KeyRound size={12} /> Primary key</span>}{column.is_jsonb && <span className="pill json-pill"><Braces size={12} /> JSONB</span>}{!column.is_primary_key && !column.is_jsonb && <span className="muted">—</span>}</div></td></tr>)}</tbody></table></div>{!columns.length && <p className="list-empty">No matching columns.</p>}
          <div className="key-summary"><KeyRound size={15} /><div><strong>{table.primary_key.length > 1 ? 'Composite primary key' : 'Primary key'}</strong><p>{table.primary_key.length ? table.primary_key.join(' + ') : 'No primary key defined'}</p></div></div>
          <div className="relationship-section"><h3><Link2 size={17} /> Foreign-key relationships <span className="count-badge">{table.foreign_keys.length}</span></h3>{table.foreign_keys.length ? table.foreign_keys.map((key) => <article className="relationship" key={key.name}><div className="relationship-name"><strong>{key.name}</strong>{key.columns.length > 1 && <span className="pill small">Composite foreign key</span>}</div><div className="relationship-mapping"><code>{key.columns.join(', ')}</code><ArrowRight size={15} /><div>{tables.some((item) => item.schema === key.referenced_schema && item.name === key.referenced_table) ? <button className="text-link" onClick={() => { setTableFilter(''); selectTable(tableKey({ schema: key.referenced_schema, name: key.referenced_table })); }}>{key.referenced_schema}.{key.referenced_table}</button> : <strong>{key.referenced_schema}.{key.referenced_table}</strong>}<code>({key.referenced_columns.join(', ')})</code></div></div></article>) : <p className="relationship-empty">No foreign keys defined for this table.</p>}</div>
          <p className="schema-footnote">Row counts are database estimates, not exact counts. This view contains schema metadata only.</p>
        </section> : <section className="panel data-empty"><Search size={30} /><h3>No matching tables</h3><p>Try another table name or clear the filter.</p><button className="button secondary" onClick={() => setTableFilter('')}>Clear filter</button></section>}
      </div>}
    </>}
  </div>;
}
