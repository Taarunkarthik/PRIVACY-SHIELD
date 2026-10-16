import { useState } from 'react';
import type { FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router';
import { AlertTriangle, ArrowRight, Bot, ChevronLeft, ChevronRight, RefreshCw, Sparkles } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../api/auth';
import { can, isReadOnly, roleLabel } from '../api/permissions';
import type { ScanJob, ScanPage } from '../api/scans';
import { activeClassification, activeClassificationPage, classificationError, classificationFailure, classificationStatus, launchError as describeLaunchError, nothingForModel, summarySentences } from '../api/classifications';
import type { ClassificationJob, ClassificationJobPage, ClassificationSummary } from '../api/classifications';
import { usePollingResource } from '../api/usePollingResource';
import { ClassificationResults } from '../components/ClassificationResults';
import { ClassificationSelection } from '../components/ClassificationSelection';

export function Classifications() {
  const { user } = useAuth();
  const readOnly = isReadOnly(user);
  const canClassify = can(user, 'classify.run');
  const [params, setParams] = useSearchParams();
  const [revision, setRevision] = useState(0);
  const [scanPage, setScanPage] = useState(1);
  const [historyPage, setHistoryPage] = useState(1);
  const [selectionMode, setSelectionMode] = useState<'default' | 'custom'>('default');
  const [selection, setSelection] = useState<{ scanId: string; ids: string[] }>({ scanId: '', ids: [] });
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState('');
  const scans = usePollingResource<ScanPage>(`/scans?status=COMPLETED&page=${scanPage}&page_size=50`, revision);
  const scanId = params.get('scan') || scans.data?.items[0]?.id || '';
  const scanResource = usePollingResource<ScanJob>(scanId ? `/scans/${encodeURIComponent(scanId)}` : null, revision);
  const scan = scanResource.data;
  const completedScan = scan?.status === 'COMPLETED' ? scan : null;
  const selectedIds = selection.scanId === scanId ? selection.ids : [];
  // Counts behind the default selection: columns the detectors decided are skipped, the rest go to the model.
  const summary = usePollingResource<ClassificationSummary>(completedScan && canClassify ? `/scans/${encodeURIComponent(scanId)}/classification-summary` : null, revision, undefined, classificationError).data;
  const nothingToSend = selectionMode === 'default' && summary?.will_classify === 0;
  const history = usePollingResource<ClassificationJobPage>(completedScan ? `/classification-jobs?scan_id=${encodeURIComponent(scanId)}&page=${historyPage}&page_size=10` : null, revision, activeClassificationPage, classificationError);
  const selectedJobId = params.get('job') || history.data?.items[0]?.id || '';
  const selected = usePollingResource<ClassificationJob>(completedScan && selectedJobId ? `/classification-jobs/${encodeURIComponent(selectedJobId)}` : null, revision, activeClassification, classificationError);
  const job = selected.data?.scan_id === scanId ? selected.data : null;
  const scanLink = scan ? `/scans?connection=${encodeURIComponent(scan.connection_id)}&job=${encodeURIComponent(scan.id)}` : '/scans';

  async function launch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!user || !canClassify || !completedScan || launching) return;
    if (selectionMode === 'custom' && (!selectedIds.length || selectedIds.length > 50)) { setLaunchError('Choose between 1 and 50 findings, or use the default whole-column selection.'); return; }
    if (nothingToSend) { setLaunchError(nothingForModel(summary)); return; }
    setLaunching(true);
    setLaunchError('');
    try {
      const created = await api<ClassificationJob>(`/scans/${encodeURIComponent(scanId)}/classify`, { method: 'POST', csrfToken: user.csrf_token, body: JSON.stringify(selectionMode === 'custom' ? { result_ids: selectedIds } : {}) });
      setParams({ scan: scanId, job: created.id });
      setHistoryPage(1);
      setRevision((value) => value + 1);
    } catch (reason) { setLaunchError(describeLaunchError(reason, selectionMode, summary)); }
    finally { setLaunching(false); }
  }

  return <div className="page-content classification-page">
    <div className="page-heading"><div><p className="eyebrow">CONTEXT FOR EVERY FINDING</p><h1>AI Classification<span className="heading-dot">.</span></h1><p className="page-description">Review advisory classifications and choose what deserves protection.</p></div><button className="button secondary" onClick={() => setRevision((value) => value + 1)} disabled={launching || scans.loading}><RefreshCw size={15} /> Refresh</button></div>
    {readOnly && user && <p className="readonly-note">Read-only for your {roleLabel[user.role]} role: you can review AI classifications, but cannot request them.</p>}
    <div className="sample-notice"><Sparkles size={17} /><p>AI reviews metadata and sanitized detection evidence. Recommendations need human review and do not apply protection or change source records.</p></div>
    <form className="panel scan-launch" aria-label="Request AI classification" onSubmit={launch}>
      <div className="form-field"><label htmlFor="classification-scan">Completed scan</label><select id="classification-scan" value={scanId} disabled={scans.loading || launching} onChange={(event) => { setParams({ scan: event.target.value }); setHistoryPage(1); setSelectionMode('default'); setSelection({ scanId: event.target.value, ids: [] }); setLaunchError(''); }}>
        <option value="" disabled>{scans.loading ? 'Loading completed scans…' : scans.data?.items.length ? 'Choose a completed scan' : 'No completed scans available'}</option>
        {scan && !scans.data?.items.some((item) => item.id === scan.id) && <option value={scan.id}>Scan {scan.id.slice(0, 8)} · {new Date(scan.created_at).toLocaleString()}</option>}
        {scans.data?.items.map((item) => <option key={item.id} value={item.id}>Scan {item.id.slice(0, 8)} · {new Date(item.created_at).toLocaleString()} · {item.sample_limit.toLocaleString()} rows per table</option>)}
      </select></div>
      {scans.data && scans.data.total > 50 && <div className="pagination scan-choice-pages"><span>Completed scans page {scanPage} of {Math.ceil(scans.data.total / 50)}</span><div><button type="button" className="button secondary" disabled={scanPage === 1 || launching || scans.loading} onClick={() => setScanPage(scanPage - 1)}><ChevronLeft size={13} /> Previous</button><button type="button" className="button secondary" disabled={scanPage * 50 >= scans.data.total || launching || scans.loading} onClick={() => setScanPage(scanPage + 1)}>Next <ChevronRight size={13} /></button></div></div>}
      {completedScan && canClassify && <>
        <fieldset className="classification-mode" disabled={launching}><legend>Choose evidence to classify</legend><label><input type="radio" name="classification-mode" checked={selectionMode === 'default'} onChange={() => { setSelectionMode('default'); setLaunchError(''); }} /><span>Whole columns <small>Up to 50 whole columns the detectors did not settle, including samples with no matches.</small></span></label><label><input type="radio" name="classification-mode" checked={selectionMode === 'custom'} onChange={() => { setSelectionMode('custom'); setLaunchError(''); }} /><span>Choose findings <small>Select specific columns or JSON paths, up to 50 per job.</small></span></label></fieldset>
        {selectionMode === 'custom' && <ClassificationSelection key={scanId} scanId={scanId} selected={selectedIds} onChange={(ids) => setSelection({ scanId, ids })} disabled={launching} />}
        {selectionMode === 'default' && summary && <p className="role-note" role="status" aria-label="What will be classified">{summarySentences(summary).join(' ')}</p>}
        <div className="classification-launch-action"><p>Each finding is reviewed separately. Large selections can take several minutes.</p><button type="submit" className="button primary" disabled={launching || (selectionMode === 'custom' && !selectedIds.length) || nothingToSend}><Bot size={16} />{launching ? 'Starting…' : 'Request classification'}</button></div>
      </>}
      {!canClassify && <p className="role-note">Your account can review recommendations. An administrator or analyst can request classification.</p>}
      {scan && !completedScan && <p className="role-note">This scan has not completed. Classification requires completed scan findings.</p>}
      <div className="scan-launch-note"><Bot size={15} /><p>Scan findings stay available when AI is unavailable or a response fails validation.</p><Link to={scanLink} className="text-link">Review scan findings <ArrowRight size={13} /></Link></div>
    </form>
    {(scans.error || scanResource.error || launchError) && <div className="error-box" role="alert">{scans.error || scanResource.error || launchError}</div>}
    {!scans.loading && !scanId && <section className="panel data-empty"><Bot size={35} strokeWidth={1.3} /><h2>Start with a completed scan</h2><p>AI classification uses saved scan findings. Run a bounded scan first, then return to request recommendations.</p><Link to="/scans" className="button secondary">View scans <ArrowRight size={14} /></Link></section>}
    {completedScan && <>
      <section className="panel scan-history" aria-label="Classification history"><div className="panel-heading"><div><h2>Classification history <span className="count-badge">{history.data?.total ?? '—'}</span></h2><p>Saved jobs for scan {scanId.slice(0, 8)}. Active jobs update every few seconds.</p></div><Bot size={20} className="muted" /></div>
        {history.error && <div className="error-box findings-error" role="alert">{history.error} Automatic updates have stopped.<button className="text-button" onClick={() => setRevision((value) => value + 1)}>Retry classification history</button></div>}
        {history.loading && !history.data ? <div className="data-empty" role="status"><div className="loading-ring" /><p>Loading classification jobs…</p></div> : history.data && !history.data.total ? <div className="data-empty"><Bot size={30} /><h3>No recommendations requested yet</h3><p>Choose a few findings to request advisory classifications.</p></div> : <div className="scan-job-list">{history.data?.items.map((item) => <button type="button" className={`scan-job-row ${selectedJobId === item.id ? 'selected' : ''}`} key={item.id} aria-pressed={selectedJobId === item.id} onClick={() => setParams({ scan: scanId, job: item.id })}><span className="job-list-icon"><Bot size={17} /></span><span className="job-list-date"><strong>{new Date(item.created_at).toLocaleString()}</strong><small>{item.total_results} findings · Job {item.id.slice(0, 8)}</small></span><span className={`pill scan-status status-${item.status.toLowerCase()}`}>{classificationStatus[item.status]}</span>{activeClassification(item) && <span className="history-progress">{item.progress}%</span>}<ChevronRight size={15} /></button>)}</div>}
        {history.data && history.data.total > 10 && <div className="pagination"><span>Page {historyPage} of {Math.ceil(history.data.total / 10)}</span><div><button className="button secondary" disabled={historyPage === 1 || history.loading} onClick={() => setHistoryPage(historyPage - 1)}><ChevronLeft size={13} /> Previous</button><button className="button secondary" disabled={historyPage * 10 >= history.data.total || history.loading} onClick={() => setHistoryPage(historyPage + 1)}>Next <ChevronRight size={13} /></button></div></div>}
      </section>
      {selected.error && <div className="error-box" role="alert">{selected.error} Automatic status updates have stopped.<button className="text-button" onClick={() => setRevision((value) => value + 1)}>Retry classification status</button></div>}
      {selectedJobId && selected.loading && !job && <section className="panel data-empty" role="status"><div className="loading-ring" /><p>Loading selected classification…</p></section>}
      {job && <section className="panel selected-scan" aria-label="Selected classification status"><div className="panel-heading"><div><h2>Classification {job.id.slice(0, 8)}</h2><p>{job.total_results} findings · {job.model} · Prompt {job.prompt_version}</p></div><span className={`pill scan-status status-${job.status.toLowerCase()}`}>{classificationStatus[job.status]}</span></div>
        {activeClassification(job) ? <div className="scan-progress"><div><span>{job.status === 'QUEUED' ? 'Waiting for AI classification' : 'Reviewing sanitized evidence'}</span><strong>{job.progress}%</strong></div><progress aria-label="Classification progress" max={100} value={job.progress} /><p>{job.completed_results} accepted, {job.failed_results} unavailable so far. This saved job continues after you leave the page.</p></div> : job.status === 'COMPLETED' ? <p className="scan-complete-note">{job.completed_results} recommendations accepted. Review their reasoning and limitations before deciding on protection.</p> : <div className="scan-failure-note"><AlertTriangle size={19} /><div><strong>{job.status === 'PARTIAL' ? 'Some findings still need manual review' : 'AI recommendations unavailable'}</strong><p>{classificationFailure(job.error_code)} {job.completed_results} accepted; {job.failed_results} unavailable.</p><p>{job.status === 'PARTIAL' ? 'Only accepted recommendations are shown below.' : 'No recommendations from this job were accepted.'} Missing recommendations do not indicate low risk.</p><Link className="text-link" to={scanLink}>Review original scan findings <ArrowRight size={13} /></Link></div></div>}
      </section>}
      {job && (job.status === 'COMPLETED' || job.status === 'PARTIAL') && <ClassificationResults key={job.id} jobId={job.id} />}
    </>}
  </div>;
}
