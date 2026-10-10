import { useEffect, useState } from 'react';
import { Check, ChevronLeft, ChevronRight, CircleCheck, RefreshCw, X } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { useAuth } from '../api/auth';
import type { PolicyPage } from '../api/policies';
import { policyStatusLabel } from '../api/policies';

export function Approvals() {
  const { user } = useAuth();
  const canApprove = user?.role === 'ADMIN';
  const [policies, setPolicies] = useState<PolicyPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [actionError, setActionError] = useState('');
  const [actionLoading, setActionLoading] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError('');
    api<PolicyPage>(`/policies?status=PENDING_APPROVAL&page=${page}&page_size=20`, { signal: controller.signal })
      .then((v) => { if (!controller.signal.aborted) setPolicies(v); })
      .catch((r: unknown) => { if (!controller.signal.aborted) setError(r instanceof ApiError ? r.message : 'Could not load approvals.'); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [page, revision]);

  async function approve(id: string) {
    setActionLoading(id); setActionError('');
    try {
      await api(`/policies/${encodeURIComponent(id)}/approve`, { method: 'POST', csrfToken: user!.csrf_token });
      setRevision((v) => v + 1);
    } catch (r) { setActionError(r instanceof ApiError ? r.message : 'Could not approve policy.'); }
    finally { setActionLoading(''); }
  }

  async function reject(id: string) {
    setActionLoading(id); setActionError('');
    try {
      await api(`/policies/${encodeURIComponent(id)}/reject`, { method: 'POST', csrfToken: user!.csrf_token });
      setRevision((v) => v + 1);
    } catch (r) { setActionError(r instanceof ApiError ? r.message : 'Could not reject policy.'); }
    finally { setActionLoading(''); }
  }

  return <div className="page-content approvals-page">
    <div className="page-heading">
      <div><p className="eyebrow">HUMAN REVIEW, ALWAYS</p><h1>Approval Queue<span className="heading-dot">.</span></h1><p className="page-description">Review and decide on submitted masking policies before deployment.</p></div>
      <button className="button secondary" onClick={() => setRevision((v) => v + 1)} disabled={loading}><RefreshCw size={15} /> Refresh</button>
    </div>
    {(!canApprove) && <p className="role-note">Your account can review pending policies. An administrator can approve or reject them.</p>}
    {(error || actionError) && <div className="error-box" role="alert">{error || actionError}</div>}
    <section className="panel" aria-label="Pending approvals">
      <div className="panel-heading"><div><h2>Pending approval <span className="count-badge">{policies?.total ?? '—'}</span></h2><p>Policies waiting for an administrator decision.</p></div><CircleCheck size={19} className="muted" /></div>
      {loading && !policies ? <div className="data-empty" role="status"><div className="loading-ring" /><p>Loading approvals…</p></div>
        : policies && !policies.total ? <div className="data-empty"><CircleCheck size={34} strokeWidth={1.3} /><h3>No pending approvals</h3><p>All submitted policies have been reviewed.</p></div>
        : <div className="policy-items">{policies?.items.map((item) => (
          <div className="policy-row approval-row" key={item.id}>
            <span className="policy-icon"><CircleCheck size={17} /></span>
            <span className="policy-info">
              <strong>{item.schema_name}.{item.table_name} <span className="count-badge">v{item.version}</span></strong>
              <small>{item.rules.length} rules · {policyStatusLabel[item.status]} · {new Date(item.created_at).toLocaleString()}</small>
            </span>
            <span className={`pill policy-status status-pending-approval`}>{policyStatusLabel[item.status]}</span>
            {canApprove && <div className="approval-actions">
              <button className="button primary small" disabled={actionLoading === item.id} onClick={() => approve(item.id)}><Check size={14} />{actionLoading === item.id ? '…' : 'Approve'}</button>
              <button className="button danger small" disabled={actionLoading === item.id} onClick={() => reject(item.id)}><X size={14} />{actionLoading === item.id ? '…' : 'Reject'}</button>
            </div>}
          </div>))}</div>}
      {policies && policies.total > 20 && <div className="pagination"><span>Page {page} of {Math.ceil(policies.total / 20)}</span><div><button className="button secondary" disabled={page === 1 || loading} onClick={() => setPage(page - 1)}><ChevronLeft size={13} /> Previous</button><button className="button secondary" disabled={page * 20 >= policies.total || loading} onClick={() => setPage(page + 1)}>Next <ChevronRight size={13} /></button></div></div>}
    </section>
    {canApprove && policies && policies.total > 0 && <section className="panel approval-info">
      <h3>Approval guidelines</h3>
      <ul>
        <li>Review each column's protection action before approving.</li>
        <li>Approved policies require a separate deployment step.</li>
        <li>Rejected policies return to draft and can be resubmitted with a new version.</li>
        <li>All decisions are recorded in the audit log.</li>
      </ul>
    </section>}
  </div>;
}
