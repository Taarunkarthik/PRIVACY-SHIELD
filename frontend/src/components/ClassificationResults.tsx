import { useState } from 'react';
import { Link } from 'react-router';
import { ArrowRight, Bot, ChevronLeft, ChevronRight, ShieldCheck } from 'lucide-react';
import { classificationCategory, classificationError, recommendationLabels, riskLabels } from '../api/classifications';
import type { ClassificationPage } from '../api/classifications';
import { usePollingResource } from '../api/usePollingResource';

export function ClassificationResults({ jobId }: { jobId: string }) {
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const decisions = usePollingResource<ClassificationPage>(`/classifications?job_id=${encodeURIComponent(jobId)}&page=${page}&page_size=20`, revision, undefined, classificationError);
  return <section className="panel scan-findings" aria-label="AI recommendations">
    <div className="panel-heading"><div><h2>AI recommendations <span className="count-badge">{decisions.data?.total ?? '—'}</span></h2><p>Accepted advisory responses. Review each recommendation before defining protection.</p></div><Bot size={21} className="muted" /></div>
    {decisions.error && <div className="error-box findings-error" role="alert">{decisions.error}<button className="text-button" onClick={() => setRevision((value) => value + 1)}>Retry recommendations</button></div>}
    {decisions.loading && !decisions.data ? <div className="data-empty" role="status"><div className="loading-ring" /><p>Loading recommendations…</p></div> : decisions.data && !decisions.data.total ? <div className="data-empty"><Bot size={32} /><h3>No accepted recommendations</h3><p>Use the original scan findings for manual review. No protection has been applied.</p></div> : <div className="finding-list">{decisions.data?.items.map((item) => <article className="finding-card recommendation-card" key={item.id} aria-label={`Recommendation ${item.schema_name}.${item.table_name}.${item.column_name}${item.json_path}`}>
      <div className="finding-heading"><div><p>{item.schema_name}.{item.table_name}</p><h3>{item.column_name}{item.json_path && <code>{item.json_path}</code>}</h3></div><span className={`pill risk-${item.risk.toLowerCase()}`}>{riskLabels[item.risk] ?? 'Unspecified'} risk</span></div>
      <div className="recommendation-summary"><span className="category-chip">{classificationCategory(item.category)}</span><span><strong>{Math.round(item.confidence * 100)}%</strong> AI score</span></div>
      <p className="recommendation-reason">{item.reason}</p>
      <div className="recommendation-action"><ShieldCheck size={17} /><div><small>Suggested protection</small><strong>{recommendationLabels[item.recommendation] ?? 'Manual review'}</strong></div><span className="pill">Requires approval</span></div>
      <div className="recommendation-meta"><span>Model <strong>{item.model}</strong></span><span>Prompt <strong>{item.prompt_version}</strong></span><time dateTime={item.created_at}>{new Date(item.created_at).toLocaleString()}</time></div>
    </article>)}</div>}
    {decisions.data && decisions.data.total > 20 && <div className="pagination"><span>Page {page} of {Math.ceil(decisions.data.total / 20)}</span><div><button className="button secondary" disabled={page === 1 || decisions.loading} onClick={() => setPage(page - 1)}><ChevronLeft size={14} /> Previous</button><button className="button secondary" disabled={page * 20 >= decisions.data.total || decisions.loading} onClick={() => setPage(page + 1)}>Next <ChevronRight size={14} /></button></div></div>}
    <div className="schema-footnote"><p>AI scores are heuristic signals, not probabilities or identity verification. Recommendations do not alter source data. A policy needs human approval before a separate deployment action.</p><Link className="text-link" to="/policies">View masking workspace <ArrowRight size={13} /></Link></div>
  </section>;
}
