import { useEffect, useRef, useState } from 'react';
import { Check, ChevronLeft, ChevronRight, Copy, FileClock, RefreshCw, ShieldCheck, X } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { useAuth } from '../api/auth';
import { can } from '../api/permissions';
import { auditChainReasonText, shortHash } from '../api/auditChain';
import type { AuditChainVerification } from '../api/auditChain';
import type { AuditEventPage } from '../api/policies';

const SUBJECT_TYPES: Array<{ value: string; label: string }> = [
  { value: 'session', label: 'Session' },
  { value: 'user', label: 'User' },
  { value: 'database_connection', label: 'Database connection' },
  { value: 'schema_snapshot', label: 'Schema snapshot' },
  { value: 'scan_job', label: 'Scan job' },
  { value: 'classification_job', label: 'Classification job' },
  { value: 'masking_policy', label: 'Masking policy' },
  { value: 'policy_deployment', label: 'Policy deployment' },
];

// Backends that predate the newer filters simply ignore the extra query parameters.
function toIso(value: string) {
  if (!value) return '';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? '' : parsed.toISOString();
}

// The status icon shares a flex row with wrapping text; this keeps it from being squeezed.
const ICON = { flexShrink: 0 };

// Recomputes the hash chain on request only: it reads the whole log, so it never runs on page load.
function LogIntegrity() {
  const { user } = useAuth();
  const canVerify = can(user, 'audit.verify');
  const [result, setResult] = useState<AuditChainVerification | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState<'copied' | 'manual' | ''>('');
  const request = useRef<AbortController | null>(null);

  useEffect(() => () => request.current?.abort(), []);

  async function verify() {
    const controller = new AbortController();
    request.current?.abort();
    request.current = controller;
    setVerifying(true);
    setError('');
    setCopied('');
    try {
      const value = await api<AuditChainVerification>('/audit-events/verify', { signal: controller.signal });
      if (!controller.signal.aborted) setResult(value);
    } catch (reason) {
      if (controller.signal.aborted) return;
      // A stale "intact" must not stay on screen after a check that did not complete.
      setResult(null);
      setError(reason instanceof ApiError && reason.status === 403
        ? 'Only an administrator or auditor can verify the log.'
        : reason instanceof ApiError && reason.status === 429
        ? 'Another verification is still running. Try again in a few seconds.'
        : 'The log could not be verified. Nothing is known about its integrity until a check completes.');
    } finally {
      if (!controller.signal.aborted) setVerifying(false);
    }
  }

  async function copyHead(hash: string) {
    try {
      await navigator.clipboard.writeText(hash);
      setCopied('copied');
    } catch {
      // Without clipboard access the full value is shown so it can be selected by hand.
      setCopied('manual');
    }
  }

  const broken = result?.status === 'BROKEN';
  return <>
    {error && <div className="error-box" role="alert">{error}</div>}
    <section className="panel settings-panel" aria-label="Log integrity">
      <div className="panel-heading">
        <div>
          <h2>Log integrity {result && <span className={`pill small ${broken ? 'status-rejected' : 'status-approved'}`}>{broken ? 'Broken' : 'Intact'}</span>}</h2>
          <p>{canVerify
            ? 'Each audit event is sealed into a hash chain. Verifying recomputes every hash from the stored events.'
            : 'An administrator or auditor can verify that sealed audit events have not been changed.'}</p>
        </div>
        {canVerify && <button className="button secondary" onClick={verify} disabled={verifying}><ShieldCheck size={15} style={ICON} /> {verifying ? 'Verifying…' : 'Verify log integrity'}</button>}
      </div>
      {result && <ul className="access-facts" aria-label="Verification result">
        {broken
          ? <li className="access-bad"><X size={14} style={ICON} /><span role="alert">Broken at position {result.broken_index?.toLocaleString()}. {result.reason ? auditChainReasonText[result.reason] : ''} Entries before this position still verify. Entries from it onward cannot be relied on.</span></li>
          : <li className="access-ok"><Check size={14} style={ICON} /><span role="status">{result.sealed
            ? 'Intact. Every sealed event still matches the hash recorded when it was sealed.'
            : 'Intact. No events have been sealed yet.'}</span></li>}
        <li><span>Sealed events: <strong>{result.sealed.toLocaleString()}</strong></span></li>
        <li><span>Not yet sealed: <strong>{result.pending.toLocaleString()}</strong>{result.pending > 0 && ' (recorded moments ago, sealed automatically, and not covered by this check)'}</span></li>
        {result.head_hash && <li>
          <span>Head of the chain: position <strong>{result.head_index.toLocaleString()}</strong>, hash <code title={result.head_hash}>{copied === 'manual' ? result.head_hash : shortHash(result.head_hash)}</code> <button type="button" className="text-link" onClick={() => copyHead(result.head_hash ?? '')}><Copy size={12} /> {copied === 'copied' ? 'Copied' : 'Copy head hash'}</button></span>
        </li>}
        {result.head_hash && <li className="muted"><span>Keep the head position and hash somewhere outside this system. Removal of the newest entries, or a chain rebuilt after a change, can only be detected by comparing against a saved head.</span></li>}
        <li className="muted"><span>Checked {new Date(result.verified_at).toLocaleString()}</span></li>
      </ul>}
    </section>
  </>;
}

export function AuditLogs() {
  const [events, setEvents] = useState<AuditEventPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [eventType, setEventType] = useState('');
  const [subjectType, setSubjectType] = useState('');
  const [since, setSince] = useState('');
  const [until, setUntil] = useState('');

  const rangeInvalid = Boolean(since && until && new Date(since) > new Date(until));

  useEffect(() => {
    if (rangeInvalid) {
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    setError('');
    const search = new URLSearchParams();
    if (eventType) search.set('event_type', eventType);
    if (subjectType) search.set('subject_type', subjectType);
    const sinceIso = toIso(since);
    const untilIso = toIso(until);
    if (sinceIso) search.set('since', sinceIso);
    if (untilIso) search.set('until', untilIso);
    search.set('page', String(page));
    search.set('page_size', '50');
    api<AuditEventPage>(`/audit-events?${search.toString()}`, { signal: controller.signal })
      .then((v) => { if (!controller.signal.aborted) setEvents(v); })
      .catch((r: unknown) => { if (!controller.signal.aborted) setError(r instanceof ApiError ? r.message : 'Could not load audit events.'); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [page, revision, eventType, subjectType, since, until, rangeInvalid]);

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
          <option value="USER_CREATED_AS_ADMIN">Administrator created</option>
          <option value="USER_CREATED_AS_ANALYST">Analyst created</option>
          <option value="USER_CREATED_AS_AUDITOR">Auditor created</option>
          <option value="USER_ROLE_SET_ADMIN">Role set to administrator</option>
          <option value="USER_ROLE_SET_ANALYST">Role set to analyst</option>
          <option value="USER_ROLE_SET_AUDITOR">Role set to auditor</option>
          <option value="USER_DEACTIVATED">User deactivated</option>
          <option value="USER_REACTIVATED">User reactivated</option>
          <option value="USER_PASSWORD_RESET">User password reset</option>
        </select>
      </div>
      <div className="form-field"><label htmlFor="audit-subject-type">Subject</label>
        <select id="audit-subject-type" value={subjectType} onChange={(e) => { setSubjectType(e.target.value); setPage(1); }}>
          <option value="">All subjects</option>
          {SUBJECT_TYPES.map((subject) => <option key={subject.value} value={subject.value}>{subject.label}</option>)}
        </select>
      </div>
      <div className="form-field"><label htmlFor="audit-since">From</label>
        <input id="audit-since" type="datetime-local" value={since} onChange={(e) => { setSince(e.target.value); setPage(1); }} />
      </div>
      <div className="form-field"><label htmlFor="audit-until">To</label>
        <input id="audit-until" type="datetime-local" value={until} onChange={(e) => { setUntil(e.target.value); setPage(1); }} />
      </div>
    </div>
    {(error || rangeInvalid) && <div className="error-box" role="alert">{rangeInvalid ? 'Choose a start time that is earlier than the end time.' : error}</div>}
    <LogIntegrity />
    <section className="panel" aria-label="Audit events">
      <div className="panel-heading"><div><h2>Activity timeline <span className="count-badge">{events?.total ?? '—'}</span></h2><p>A chronological record of workspace activity.</p></div><FileClock size={19} className="muted" /></div>
      {rangeInvalid ? <div className="data-empty"><FileClock size={34} strokeWidth={1.3} /><h3>Adjust the time window</h3><p>The start of the window must be earlier than the end.</p></div>
        : loading && !events ? <div className="data-empty" role="status"><div className="loading-ring" /><p>Loading audit events…</p></div>
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
