import { useState } from 'react';
import { ChevronLeft, ChevronRight, Search } from 'lucide-react';
import type { ResultPage } from '../api/scans';
import { usePollingResource } from '../api/usePollingResource';

export function ClassificationSelection({ scanId, selected, onChange, disabled }: { scanId: string; selected: string[]; onChange: (ids: string[]) => void; disabled: boolean }) {
  const [page, setPage] = useState(1);
  const [filter, setFilter] = useState('');
  const [revision, setRevision] = useState(0);
  const results = usePollingResource<ResultPage>(`/scans/${encodeURIComponent(scanId)}/results?page=${page}&page_size=20`, revision);
  const visible = results.data?.items.filter((item) => `${item.schema_name}.${item.table_name}.${item.column_name}${item.json_path}`.toLowerCase().includes(filter.toLowerCase())) ?? [];
  return <section className="classification-selection" aria-label="Choose findings">
    <div className="selection-heading"><p><strong>{selected.length} of 50</strong> findings selected across pages</p><button type="button" className="text-button" disabled={disabled || !selected.length} onClick={() => onChange([])}>Clear selection</button></div>
    <div className="search-field"><Search size={14} /><input aria-label="Find columns on this page" placeholder="Find on this page…" value={filter} onChange={(event) => setFilter(event.target.value)} /></div>
    {results.error && <div className="error-box" role="alert">{results.error}<button type="button" className="text-button" onClick={() => setRevision((value) => value + 1)}>Retry columns</button></div>}
    {results.loading && !results.data ? <p className="list-empty" role="status">Loading scan findings…</p> : results.data && !visible.length ? <p className="list-empty">No findings on this page match your filter.</p> : <div className="selection-list">{visible.map((item) => <label className="selection-item" key={item.id}><input type="checkbox" checked={selected.includes(item.id)} disabled={disabled || (!selected.includes(item.id) && selected.length >= 50)} onChange={(event) => onChange(event.target.checked ? [...selected, item.id] : selected.filter((id) => id !== item.id))} /><span><strong>{item.schema_name}.{item.table_name}.{item.column_name}</strong>{item.json_path && <code>{item.json_path}</code>}<small>{item.matching_rows} matching / {item.sampled_rows} sampled rows{item.sanitized_evidence.coverage.unsupported_type ? ' · Not assessed' : ''}</small></span></label>)}</div>}
    {results.data && results.data.total > 20 && <div className="pagination"><span>Page {page} of {Math.ceil(results.data.total / 20)}</span><div><button type="button" className="button secondary" disabled={page === 1 || results.loading || disabled} onClick={() => { setPage(page - 1); setFilter(''); }}><ChevronLeft size={13} /> Previous</button><button type="button" className="button secondary" disabled={page * 20 >= results.data.total || results.loading || disabled} onClick={() => { setPage(page + 1); setFilter(''); }}>Next <ChevronRight size={13} /></button></div></div>}
  </section>;
}
