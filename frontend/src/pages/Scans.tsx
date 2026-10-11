import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router';
import { AlertTriangle, ArrowRight, ChevronLeft, ChevronRight, Clock3, Database, Play, RefreshCw, ScanLine } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { useAuth } from '../api/auth';
import type { Connection, ConnectionPage, SchemaSnapshot } from '../api/connections';
import { activeScan, activeScanPage, failureMessage, scanError, statusLabel } from '../api/scans';
import type { ScanJob, ScanPage } from '../api/scans';
import { usePollingResource } from '../api/usePollingResource';
import { ScanFindings } from '../components/ScanFindings';

export function Scans() {
  const { user } = useAuth();
  const canScan = user?.role === 'ADMIN' || user?.role === 'ANALYST';
  const [params, setParams] = useSearchParams();
  const [connections, setConnections] = useState<Connection[]>([]);
  const [connectionsLoading, setConnectionsLoading] = useState(true);
  const [connectionError, setConnectionError] = useState('');
  const [snapshot, setSnapshot] = useState<{ connectionId: string; value: SchemaSnapshot } | null>(null);
  const [snapshotLoading, setSnapshotLoading] = useState(false);
  const [snapshotError, setSnapshotError] = useState('');
  const [sampleLimit, setSampleLimit] = useState('1000');
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState('');
  const [revision, setRevision] = useState(0);
  const [historyPage, setHistoryPage] = useState(1);
  const connectionId = params.get('connection') || connections.find((item) => item.is_active)?.id || connections[0]?.id || '';
  const connection = connections.find((item) => item.id === connectionId);
  const history = usePollingResource<ScanPage>(connection ? `/scans?connection_id=${encodeURIComponent(connectionId)}&page=${historyPage}&page_size=10` : null, revision, activeScanPage);
  const selectedId = params.get('job') || history.data?.items[0]?.id || '';
  const selected = usePollingResource<ScanJob>(connection && selectedId ? `/scans/${encodeURIComponent(selectedId)}` : null, revision, activeScan);
  const job = selected.data?.connection_id === connectionId ? selected.data : null;
  const readySnapshot = snapshot?.connectionId === connectionId ? snapshot.value : null;

  useEffect(() => {
    const controller = new AbortController();
    setConnectionsLoading(true);
    setConnectionError('');
    async function loadConnections() {
      const first = await api<ConnectionPage>('/connections?page=1&page_size=100', { signal: controller.signal });
      const all = [...first.items];
      for (let page = 2; page <= Math.ceil(first.total / 100); page++) {
        const next = await api<ConnectionPage>(`/connections?page=${page}&page_size=100`, { signal: controller.signal });
        all.push(...next.items);
      }
      if (!controller.signal.aborted) setConnections(all);
    }
    loadConnections().catch((reason: unknown) => { if (!controller.signal.aborted) setConnectionError(scanError(reason)); })
      .finally(() => { if (!controller.signal.aborted) setConnectionsLoading(false); });
    return () => controller.abort();
  }, [revision]);

  useEffect(() => {
    if (!connection) { setSnapshot(null); return; }
    const controller = new AbortController();
    setSnapshot(null);
    setSnapshotError('');
    setSnapshotLoading(true);
    api<SchemaSnapshot>(`/connections/${encodeURIComponent(connectionId)}/schema`, { signal: controller.signal })
      .then((value) => { if (!controller.signal.aborted) setSnapshot({ connectionId, value }); })
      .catch((reason: unknown) => { if (!controller.signal.aborted && !(reason instanceof ApiError && reason.status === 404)) setSnapshotError(scanError(reason)); })
      .finally(() => { if (!controller.signal.aborted) setSnapshotLoading(false); });
    return () => controller.abort();
  }, [connectionId, Boolean(connection), revision]);

  async function launch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!user || !canScan || !connection?.is_active || !readySnapshot || launching) return;
    const limit = Number(sampleLimit);
    if (!Number.isInteger(limit) || limit < 1 || limit > 10000) { setLaunchError('Choose a whole-number sample limit from 1 to 10,000.'); return; }
    setLaunching(true);
    setLaunchError('');
    try {
      const created = await api<ScanJob>('/scans', { method: 'POST', csrfToken: user.csrf_token, body: JSON.stringify({ connection_id: connectionId, snapshot_id: readySnapshot.snapshot_id, sample_limit: limit }) });
      setParams({ connection: connectionId, job: created.id });
      setHistoryPage(1);
      setRevision((value) => value + 1);
    } catch (reason) { setLaunchError(scanError(reason)); }
    finally { setLaunching(false); }
  }

  return <div className="page-content scans-page">
    <div className="page-heading"><div><h1>Scan Results<span className="heading-dot">.</span></h1><p className="page-description">Run bounded samples and review personal-data candidates.</p></div><button className="button secondary" onClick={() => setRevision((value) => value + 1)} disabled={launching || connectionsLoading}><RefreshCw size={15} /> Refresh</button></div>
    <form className="panel scan-launch" onSubmit={launch} aria-label="Launch a scan"><div className="scan-launch-fields"><div className="form-field"><label htmlFor="scan-connection">Database connection</label><select id="scan-connection" value={connection ? connectionId : ''} disabled={connectionsLoading || launching} onChange={(event) => { setParams({ connection: event.target.value }); setHistoryPage(1); setLaunchError(''); }}><option value="" disabled>{connectionsLoading ? 'Loading connections…' : connections.length ? 'Choose a connection' : 'No connections saved'}</option>{connections.map((item) => <option key={item.id} value={item.id}>{item.name}{item.is_active ? '' : ' (inactive)'}</option>)}</select></div>{canScan && <><div className="form-field sample-limit"><label htmlFor="sample-limit">Rows per table <span>Maximum 10,000</span></label><input id="sample-limit" type="number" min={1} max={10000} step={1} value={sampleLimit} onChange={(event) => setSampleLimit(event.target.value)} required disabled={launching} /></div><button className="button primary" type="submit" disabled={launching || snapshotLoading || !connection?.is_active || !readySnapshot || !readySnapshot.catalog.tables.length}><Play size={15} />{launching ? 'Starting…' : 'Start scan'}</button></>}</div>
      <div className="scan-launch-note"><ScanLine size={15} /><p>{snapshotLoading ? 'Loading the latest discovered schema…' : readySnapshot ? `${readySnapshot.catalog.tables.length} tables in the latest saved schema. Scans continue in the background after you leave this page.` : connection ? 'Discover this database’s schema before starting a scan.' : 'Choose an authorized database connection to begin.'}</p>{connection && <Link className="text-link" to={`/schema?connection=${encodeURIComponent(connectionId)}`}>View schema <ArrowRight size={13} /></Link>}</div>
      {!canScan && <p className="role-note">Your account can review scans. An administrator or analyst can start one.</p>}
      {connection && !connection.is_active && <p className="role-note">This connection is inactive. Saved scan history remains available.</p>}
    </form>
    {(connectionError || snapshotError || launchError) && <div className="error-box" role="alert">{connectionError || snapshotError || launchError}</div>}
    <div className="sample-notice"><AlertTriangle size={16} /><p>These are sampled findings, not a complete inventory of personal data. PAN and Aadhaar detections identify candidates, not verified identities.</p></div>
    {!connectionsLoading && !connection ? <section className="panel data-empty"><Database size={34} strokeWidth={1.3} /><h2>{connections.length ? 'Choose a connection' : 'Connect a database to start scanning'}</h2><p>Scans use a saved schema and read-only scanner access.</p><Link to="/connections" className="button secondary">View connections <ArrowRight size={14} /></Link></section> : connection && <>
      <section className="panel scan-history" aria-label="Scan history"><div className="panel-heading"><div><h2>Scan history <span className="count-badge">{history.data?.total ?? '—'}</span></h2><p>Saved jobs for {connection.name}. Active jobs update every few seconds.</p></div><Clock3 size={19} className="muted" /></div>
        {history.error && <div className="error-box findings-error" role="alert">{history.error} Automatic updates have stopped.<button className="text-button" onClick={() => setRevision((value) => value + 1)}>Retry scan history</button></div>}
        {history.loading && !history.data ? <div className="data-empty" role="status"><div className="loading-ring" /><p>Loading scan history…</p></div> : history.data && !history.data.total ? <div className="data-empty"><ScanLine size={34} strokeWidth={1.3} /><h3>No scans for this connection yet</h3><p>{canScan ? 'Choose a sample limit and start a scan when the schema is ready.' : 'Completed scans will appear here after an administrator or analyst starts one.'}</p></div> : <div className="scan-job-list">{history.data?.items.map((item) => <button type="button" className={`scan-job-row ${selectedId === item.id ? 'selected' : ''}`} key={item.id} onClick={() => setParams({ connection: connectionId, job: item.id })} aria-pressed={selectedId === item.id}><span className="job-list-icon"><ScanLine size={17} /></span><span className="job-list-date"><strong>{new Date(item.created_at).toLocaleString()}</strong><small>{item.sample_limit.toLocaleString()} rows per table · Scan {item.id.slice(0, 8)}</small></span><span className={`pill scan-status status-${item.status.toLowerCase()}`}>{statusLabel[item.status]}</span>{activeScan(item) && <span className="history-progress">{item.progress}%</span>}<ChevronRight size={15} /></button>)}</div>}
        {history.data && history.data.total > 10 && <div className="pagination"><span>Page {historyPage} of {Math.ceil(history.data.total / 10)}</span><div><button className="button secondary" disabled={historyPage === 1 || history.loading} onClick={() => setHistoryPage(historyPage - 1)}><ChevronLeft size={13} /> Previous</button><button className="button secondary" disabled={historyPage * 10 >= history.data.total || history.loading} onClick={() => setHistoryPage(historyPage + 1)}>Next <ChevronRight size={13} /></button></div></div>}
      </section>
      {selected.error && <div className="error-box" role="alert">{selected.error} Automatic status updates have stopped.<button className="text-button" onClick={() => setRevision((value) => value + 1)}>Retry scan status</button></div>}
      {selectedId && selected.loading && !job && <section className="panel data-empty" role="status"><div className="loading-ring" /><p>Loading selected scan…</p></section>}
      {job && <section className="panel selected-scan" aria-label="Selected scan status"><div className="panel-heading"><div><h2>Scan {job.id.slice(0, 8)}</h2><p>{job.sample_limit.toLocaleString()} rows per table · Created {new Date(job.created_at).toLocaleString()}</p></div><span className={`pill scan-status status-${job.status.toLowerCase()}`}>{statusLabel[job.status]}</span></div>
        {activeScan(job) ? <div className="scan-progress"><div><span>{job.status === 'QUEUED' ? 'Waiting for a scanning worker' : 'Reading bounded samples and detecting candidates'}</span><strong>{job.progress}%</strong></div><progress aria-label="Scan progress" max={100} value={job.progress} /><p>Findings appear after the entire scan completes. You can return to this saved job later.</p></div> : job.status === 'COMPLETED' ? <div className="scan-complete-note"><p>The scan completed. Review the sampled findings and any coverage limitations below.</p><Link className="text-link" to={`/classifications?scan=${encodeURIComponent(job.id)}`}>Review with AI <ArrowRight size={13} /></Link></div> : <div className="scan-failure-note"><AlertTriangle size={19} /><div><strong>{job.status === 'CANCELLED' ? 'Scan cancelled' : 'Scan incomplete'}</strong><p>{job.status === 'CANCELLED' ? 'This scan was cancelled before completion.' : failureMessage(job.error_code)}</p><p>No partial findings were published. This outcome does not establish that your data has no personal information.</p></div></div>}
      </section>}
      {job?.status === 'COMPLETED' && <ScanFindings key={job.id} jobId={job.id} />}
    </>}
  </div>;
}
