import { useState } from 'react';
import { AlertTriangle, ChevronLeft, ChevronRight, Fingerprint, Search } from 'lucide-react';
import { categoryLabel, coverageLimits } from '../api/scans';
import type { ResultPage } from '../api/scans';
import { usePollingResource } from '../api/usePollingResource';

export function ScanFindings({ jobId }: { jobId: string }) {
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [filter, setFilter] = useState('');
  const results = usePollingResource<ResultPage>(`/scans/${encodeURIComponent(jobId)}/results?page=${page}&page_size=20`, revision);
  const visible = results.data?.items.filter((item) => `${item.schema_name}.${item.table_name}.${item.column_name}${item.json_path}`.toLowerCase().includes(filter.toLowerCase())) ?? [];

  return <section className="panel scan-findings" aria-label="Sampled scan findings">
    <div className="panel-heading"><div><h2>Sampled findings <span className="count-badge">{results.data?.total ?? '—'}</span></h2><p>Column and JSON-path records, including samples with no matches.</p></div><div className="search-field"><Search size={15} /><input aria-label="Find results on this page" placeholder="Find on this page…" value={filter} onChange={(event) => setFilter(event.target.value)} /></div></div>
    {results.error && <div className="error-box findings-error" role="alert">{results.error}<button className="text-button" onClick={() => setRevision((value) => value + 1)}>Retry findings</button></div>}
    {results.loading && !results.data ? <div className="data-empty" role="status"><div className="loading-ring" /><p>Loading sampled findings…</p></div> : results.data && !results.data.total ? <div className="data-empty"><Fingerprint size={35} strokeWidth={1.3} /><h3>No sampled column records</h3><p>The scan produced no result records. This does not establish that the database contains no personal data.</p></div> : results.data && !visible.length ? <div className="data-empty"><Search size={29} /><h3>No matching records on this page</h3><button className="text-link" onClick={() => setFilter('')}>Clear filter</button></div> : <div className="finding-list">{visible.map((item) => {
      const coverage = item.sanitized_evidence?.coverage;
      const limits = coverageLimits(coverage);
      return <article className="finding-card" key={item.id} aria-label={`Finding ${item.schema_name}.${item.table_name}.${item.column_name}${item.json_path}`}>
        <div className="finding-heading"><div><p>{item.schema_name}.{item.table_name}</p><h3>{item.column_name}{item.json_path && <code>{item.json_path}</code>}</h3></div><span className={`pill ${item.matching_rows > 0 ? 'candidate-status' : ''}`}>{coverage?.unsupported_type ? 'Not assessed' : item.matching_rows > 0 ? 'Candidates detected' : 'No matches in this sample'}</span></div>
        <div className="finding-metrics"><span><strong>{item.matching_rows.toLocaleString()}</strong> matching rows</span><span><strong>{item.sampled_rows.toLocaleString()}</strong> sampled rows</span><span><strong>{item.matching_rows ? `${Math.round(item.confidence * 100)}%` : '—'}</strong> max detector score</span></div>
        {Object.keys(item.category_counts).length > 0 && <div className="finding-categories">{Object.entries(item.category_counts).map(([category, count]) => <span className="category-chip" key={category}>{categoryLabel(category)} <b>{count.toLocaleString()}</b></span>)}</div>}
        <details className={`coverage-details ${limits.length ? 'coverage-limited' : ''}`}><summary>{limits.length > 0 && <AlertTriangle size={13} />} {limits.length ? 'Coverage limitations' : 'Sample coverage & evidence'}</summary><div>{limits.length > 0 && <ul>{limits.map((limit) => <li key={limit}>{limit}</li>)}</ul>}{coverage && <p>Up to {coverage.sample_limit.toLocaleString()} rows per table; each value is bounded to {coverage.max_cell_chars.toLocaleString()} characters and {coverage.max_cell_bytes.toLocaleString()} bytes.</p>}<p>Evidence: {item.sanitized_evidence?.labels?.length ? [...new Set(item.sanitized_evidence.labels.map(categoryLabel))].join(', ') : 'No detection labels recorded for this sample.'} No raw values are shown.</p></div></details>
      </article>;
    })}</div>}
    {results.data && results.data.total > 20 && <div className="pagination"><span>Page {page} of {Math.ceil(results.data.total / 20)}</span><div><button className="button secondary" disabled={page === 1 || results.loading} onClick={() => { setPage(page - 1); setFilter(''); }}><ChevronLeft size={14} /> Previous</button><button className="button secondary" disabled={page * 20 >= results.data.total || results.loading} onClick={() => { setPage(page + 1); setFilter(''); }}>Next <ChevronRight size={14} /></button></div></div>}
    <p className="schema-footnote">Category counts can overlap. Detector scores are heuristic candidate signals. A sampled result cannot prove that other rows or values contain no personal data. PAN and Aadhaar detections are candidates, not verified identities.</p>
  </section>;
}
