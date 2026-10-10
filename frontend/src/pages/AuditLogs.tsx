import { useEffect, useState } from 'react';
import { ChevronLeft, ChevronRight, FileClock, RefreshCw } from 'lucide-react';
import { api, ApiError } from '../api/client';
import type { AuditEventPage } from '../api/policies';

export function AuditLogs() {
  const [events, setEvents] = useState<AuditEventPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [eventType, setEventType] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError('');
    const query = eventType ? `?event_type=${encodeURIComponent(eventType)}&page=${page}&page_size=50` : `?page=${page}&page_size=50`;
    api<AuditEventPage>(`/audit-events${query}`, { signal: controller.signal })
      .then((v) => { if (!controller.signal.aborted) setEvents(v); })
      .catch((r: unknown) => { if (!controller.signal.aborted) setError(r instanceof ApiError ? r.message : 'Could not load audit events.'); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [page, revision, eventType]);

  return <div className="page-content audit-page">
    <div className="page-heading">
      <div><p className="eyebrow">A CLEAR RECORD</p><h1>Audit Logs<span className="heading-dot">.</span></h1><p className="page-description">Review the history of discovery, policy decisions, and protection deployments.</p></div>
      <button className="button secondary" onClick={() => setRevision((v) => v + 1)} disabled={loading}><RefreshCw size={15} /> Refresh</button>
    </div>
    <div className="audit-filters">
      <div className="form-field"><label htmlFor="audit-event-type">Event type</label>
        <select id="audit-event-type" value={eventType} onChange={(e) => { setEventType(e.target.value); setPage(1); }}>
          <option value="">All events</option>
          <option value="POLICY_CREATED">Policy created</option>
          <option value="POLICY_SUBMITTED">Policy submitted</option>
          <option value="POLICY_APPROVED">Policy approved</option>
          <option value="POLICY_REJECTED">Policy rejected</option>
          <option value="DEPLOYMENT_QUEUED">Deployment queued</option>
          <option value="DEPLOYMENT_COMPLETED">Deployment completed</option>
          <option value="DEPLOYMENT_FAILED">Deployment failed</option>
          <option value="SCAN_QUEUED">Scan queued</option>
          <option value="SCAN_COMPLETED">Scan completed</option>
          <option value="SCAN_FAILED">Scan failed</option>
          <option value="CLASSIFICATION_QUEUED">Classification queued</option>
          <option value="CLASSIFICATION_COMPLETED">Classification completed</option>
          <option value="CONNECTION_CREATED">Connection created</option>
          <option value="SCHEMA_DISCOVERED">Schema discovered</option>
        </select>
      </div>
    </div>
    {error && <div className="error-box" role="alert">{error}</div>}
    <section className="panel" aria-label="Audit events">
      <div className="panel-heading"><div><h2>Activity timeline <span className="count-badge">{events?.total ?? '—'}</span></h2><p> chronological record of workspace activity.</p></div><FileClock size={19} className="muted" /></div>
      {loading && !events ? <div className="data-empty" role="status"><div className="loading-ring" /><p>Loading audit events…</p></div>
        : events && !events.total ? <div className="data-empty"><FileClock size={34} strokeWidth={1.3} /><h3>No events found</h3><p>Activity will appear here as you use the workspace.</p></div>
        : <div className="audit-timeline">{events?.items.map((item) => (
          <div className="audit-event" key={item.id}>
            <span className="audit-event-dot" />
            <div className="audit-event-content">
              <strong>{item.event_type.replace(/_/g, ' ')}</strong>
              <span className="audit-event-meta">
                {item.subject_type}{item.subject_id ? ` ${item.subject_id.slice(0, 8)}` : ''} · {new Date(item.created_at).toLocaleString()}
              </span>
            </div>
          </div>))}</div>}
      {events && events.total > 50 && <div className="pagination"><span>Page {page} of {Math.ceil(events.total / 50)}</span><div><button className="button secondary" disabled={page === 1 || loading} onClick={() => setPage(page - 1)}><ChevronLeft size={13} /> Previous</button><button className="button secondary" disabled={page * 50 >= events.total || loading} onClick={() => setPage(page + 1)}>Next <ChevronRight size={13} /></button></div></div>}
    </section>
  </div>;
}
