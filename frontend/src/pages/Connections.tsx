import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { ArrowRight, CheckCircle2, ChevronLeft, ChevronRight, Database, Pencil, PlugZap, Plus, RefreshCw, Search, Waypoints } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../api/auth';
import { connectionError, discoveryScope } from '../api/connections';
import type { Connection, ConnectionCheck, ConnectionPage, SchemaSnapshot } from '../api/connections';
import { ConnectionForm } from '../components/ConnectionForm';

export function Connections() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const isAdmin = user?.role === 'ADMIN';
  const canDiscover = isAdmin || user?.role === 'ANALYST';
  const [data, setData] = useState<ConnectionPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [filter, setFilter] = useState('');
  const [schemas, setSchemas] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [editing, setEditing] = useState<Connection | 'new' | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError('');
    api<ConnectionPage>(`/connections?page=${page}&page_size=20`, { signal: controller.signal })
      .then((result) => { if (!controller.signal.aborted) setData(result); })
      .catch((reason: unknown) => { if (!controller.signal.aborted) { setData(null); setError(connectionError(reason)); } })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [page, revision]);

  async function runAction(connection: Connection, action: 'test' | 'discover') {
    if (!user || !connection.is_active || busy) return;
    setBusy(`${connection.id}:${action}`);
    setError('');
    setNotice('');
    try {
      const result = await api<ConnectionCheck | SchemaSnapshot>(`/connections/${encodeURIComponent(connection.id)}/${action}`, {
        method: 'POST', csrfToken: user.csrf_token, body: JSON.stringify(discoveryScope(schemas)),
      });
      if (action === 'test') {
        const check = result as ConnectionCheck;
        setNotice(`${connection.name} is reachable. ${check.table_count} accessible ${check.table_count === 1 ? 'table' : 'tables'} in ${check.schemas.length} ${check.schemas.length === 1 ? 'schema' : 'schemas'}.`);
      } else navigate(`/schema?connection=${encodeURIComponent(connection.id)}`);
    } catch (reason) { setError(connectionError(reason)); }
    finally { setBusy(null); }
  }

  const visible = data?.items.filter((item) => `${item.name} ${item.host} ${item.database_name}`.toLowerCase().includes(filter.toLowerCase())) ?? [];
  return <div className="page-content connections-page">
    <div className="page-heading"><div><h1>Connections<span className="heading-dot">.</span></h1><p className="page-description">Connect authorized databases and discover their structure.</p></div><div className="heading-actions"><button className="button secondary" aria-label="Refresh connections" disabled={loading || Boolean(busy)} onClick={() => setRevision((value) => value + 1)}><RefreshCw size={15} className={loading ? 'spin' : ''} /></button>{isAdmin && <button className="button primary" onClick={() => { setEditing('new'); setNotice(''); }} disabled={Boolean(busy) || Boolean(editing)}><Plus size={16} /> Add database</button>}</div></div>
    {editing && isAdmin && <ConnectionForm key={editing === 'new' ? 'new' : editing.id} connection={editing === 'new' ? undefined : editing} onCancel={() => setEditing(null)} onSaved={() => { setEditing(null); setPage(1); setFilter(''); setNotice('Connection saved. Test access or discover its schema when you are ready.'); setRevision((value) => value + 1); }} />}
    {notice && <div className="success-box" role="status"><CheckCircle2 size={17} /><span>{notice}</span></div>}
    {error && <div className="error-box" role="alert">{error}<button className="text-button" onClick={() => setRevision((value) => value + 1)}>Refresh connections</button></div>}
    <section className="panel connections-panel" aria-label="Saved database connections">
      <div className="panel-heading"><div><h2>Database connections <span className="count-badge">{data?.total ?? '—'}</span></h2><p>{isAdmin ? 'Keep credentials current and inspect accessible schemas.' : canDiscover ? 'Discover schemas using the saved, authorized connections.' : 'Browse saved connections and their discovered schemas.'}</p></div><div className="search-field"><Search size={15} /><input aria-label="Find connections on this page" placeholder="Find on this page…" value={filter} onChange={(event) => setFilter(event.target.value)} /></div></div>
      {canDiscover && <div className="schema-scope"><label htmlFor="connection-schemas">Schemas to inspect <span>Optional</span></label><input id="connection-schemas" value={schemas} onChange={(event) => setSchemas(event.target.value)} placeholder="Default: enterprise/public, or enter names separated by commas" disabled={Boolean(busy)} maxLength={1000} /><p>Leave blank for enterprise/public where accessible. Discovery reads structure, not source records.</p></div>}
      {loading ? <div className="data-empty" role="status"><div className="loading-ring" /><p>Loading database connections…</p></div> : !data ? <div className="data-empty"><Database size={31} strokeWidth={1.4} /><h3>Connections are unavailable</h3><p>Refresh to try again.</p></div> : !data.total ? <div className="data-empty"><Database size={36} strokeWidth={1.3} /><h3>Add your first database</h3><p>{isAdmin ? 'Register a database with read-only scanner credentials to start discovering its schema.' : 'An administrator can register an authorized database for your workspace.'}</p>{isAdmin && !editing && <button className="button secondary" onClick={() => setEditing('new')}><Plus size={15} /> Add database</button>}</div> : !visible.length ? <div className="data-empty"><Search size={30} strokeWidth={1.3} /><h3>No matching connections on this page</h3><button className="text-link" onClick={() => setFilter('')}>Clear filter</button></div> : <div className="connection-list">{visible.map((connection) => <article className="connection-card" key={connection.id} aria-label={`Connection ${connection.name}`}><div className="connection-card-main"><span className="connection-card-icon"><Database size={23} strokeWidth={1.5} /></span><div><h3>{connection.name}<span className={`pill small ${connection.is_active ? 'active-status' : ''}`}>{connection.is_active ? 'Active' : 'Inactive'}</span></h3><p className="connection-address">{connection.host}:{connection.port} <span>/</span> {connection.database_name}</p><div className="connection-metadata"><span>PostgreSQL</span><span>TLS {connection.ssl_mode === 'disable' ? 'disabled' : connection.ssl_mode}</span><span>Scanner: {connection.scanner_username}</span></div></div>{isAdmin && <button className="icon-button edit-connection" aria-label={`Edit ${connection.name}`} onClick={() => setEditing(connection)} disabled={Boolean(busy) || Boolean(editing)}><Pencil size={16} /></button>}</div><div className="connection-card-actions"><Link className="text-link" to={`/schema?connection=${encodeURIComponent(connection.id)}`}>Explore schema <ArrowRight size={14} /></Link><div>{isAdmin && <button className="button secondary" disabled={!connection.is_active || Boolean(busy) || Boolean(editing)} onClick={() => runAction(connection, 'test')}><PlugZap size={14} />{busy === `${connection.id}:test` ? 'Testing…' : 'Test connection'}</button>}{canDiscover && <button className="button primary" disabled={!connection.is_active || Boolean(busy) || Boolean(editing)} onClick={() => runAction(connection, 'discover')}><Waypoints size={14} />{busy === `${connection.id}:discover` ? 'Discovering…' : 'Discover schema'}</button>}</div></div></article>)}</div>}
      {data && data.total > 20 && <div className="pagination"><span>Page {page} of {Math.ceil(data.total / 20)}</span><div><button className="button secondary" disabled={page === 1 || loading} onClick={() => { setPage(page - 1); setFilter(''); }}><ChevronLeft size={14} /> Previous</button><button className="button secondary" disabled={page * 20 >= data.total || loading} onClick={() => { setPage(page + 1); setFilter(''); }}>Next <ChevronRight size={14} /></button></div></div>}
    </section>
  </div>;
}
