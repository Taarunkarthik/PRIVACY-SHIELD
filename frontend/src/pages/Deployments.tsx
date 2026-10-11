import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { Check, ChevronLeft, ChevronRight, FileClock, Play, RefreshCw, X } from 'lucide-react';
import { api, ApiError } from '../api/client';
import type { DeploymentPage } from '../api/policies';
import { deploymentStatusLabel } from '../api/policies';

export function Deployments() {
  const [deployments, setDeployments] = useState<DeploymentPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError('');
    api<DeploymentPage>(`/deployments?page=${page}&page_size=20`, { signal: controller.signal })
      .then((v) => { if (!controller.signal.aborted) setDeployments(v); })
      .catch((r: unknown) => { if (!controller.signal.aborted) setError(r instanceof ApiError ? r.message : 'Could not load deployments.'); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [page, revision]);

  return <div className="page-content deployments-page">
    <div className="page-heading">
      <div><h1>Deployments<span className="heading-dot">.</span></h1><p className="page-description">Track policy deployments and their outcomes.</p></div>
      <button className="button secondary" onClick={() => setRevision((v) => v + 1)} disabled={loading}><RefreshCw size={15} /> Refresh</button>
    </div>
    {error && <div className="error-box" role="alert">{error}</div>}
    <section className="panel" aria-label="Deployments">
      <div className="panel-heading"><div><h2>Deployment history <span className="count-badge">{deployments?.total ?? '—'}</span></h2><p>All policy deployment attempts and their status.</p></div><FileClock size={19} className="muted" /></div>
      {loading && !deployments ? <div className="data-empty" role="status"><div className="loading-ring" /><p>Loading deployments…</p></div>
        : deployments && !deployments.total ? <div className="data-empty"><Play size={34} strokeWidth={1.3} /><h3>No deployments yet</h3><p>Approved policies will appear here after deployment.</p><Link to="/policies" className="button secondary">View policies</Link></div>
        : <div className="deployment-list">{deployments?.items.map((item) => (
          <div className="deployment-row" key={item.id}>
            <span className="deployment-icon">{item.status === 'COMPLETED' ? <Check size={17} /> : item.status === 'FAILED' ? <X size={17} /> : <Play size={17} />}</span>
            <span className="deployment-info">
              <strong>Deployment {item.id.slice(0, 8)}</strong>
              <small>Policy {item.policy_id.slice(0, 8)} · {new Date(item.created_at).toLocaleString()}{item.finished_at ? ` · Finished ${new Date(item.finished_at).toLocaleString()}` : ''}</small>
            </span>
            <span className={`pill deployment-status status-${item.status.toLowerCase()}`}>{deploymentStatusLabel[item.status]}</span>
            {item.target_receipt && <span className="deployment-receipt"><Check size={13} /> Receipt</span>}
            {item.error_code && <span className="deployment-error">{item.error_code}</span>}
          </div>))}</div>}
      {deployments && deployments.total > 20 && <div className="pagination"><span>Page {page} of {Math.ceil(deployments.total / 20)}</span><div><button className="button secondary" disabled={page === 1 || loading} onClick={() => setPage(page - 1)}><ChevronLeft size={13} /> Previous</button><button className="button secondary" disabled={page * 20 >= deployments.total || loading} onClick={() => setPage(page + 1)}>Next <ChevronRight size={13} /></button></div></div>}
    </section>
  </div>;
}
