import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { ArrowRight, ArrowUpRight, Check, ChevronRight, CircleCheck, Database, Fingerprint, Layers3, LockKeyhole, RefreshCw, ScanLine, ShieldCheck, Sparkles } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { api } from '../api/client';
import type { DashboardSummary } from '../api/client';

const stats = [
  { key: 'databases', title: 'Connected databases', icon: Database, detail: 'Authorized data sources', className: 'teal' },
  { key: 'tables', title: 'Discovered tables', icon: Layers3, detail: 'Across your databases', className: 'blue' },
  { key: 'sensitive_columns', title: 'Sensitive columns', icon: Fingerprint, detail: 'Identified in sampled findings', className: 'amber' },
  { key: 'deployed_policies', title: 'Deployed policies', icon: ShieldCheck, detail: 'Approved protections in place', className: 'purple' },
] as const;

export function Dashboard() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  const [updated, setUpdated] = useState<Date | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError('');
    api<DashboardSummary>('/dashboard/summary', { signal: controller.signal })
      .then((result) => { setSummary(result); setUpdated(new Date()); })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : 'Unable to load workspace totals.');
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [revision]);

  const hasRecords = summary && Object.values(summary).some((value) => value > 0);
  const chartData = summary ? [
    { name: 'Databases', count: summary.databases },
    { name: 'Tables', count: summary.tables },
    { name: 'Findings', count: summary.sensitive_columns },
    { name: 'Policies', count: summary.deployed_policies },
  ] : [];

  return <div className="page-content dashboard">
    <div className="page-heading"><div><p className="eyebrow">YOUR PRIVACY COMMAND CENTER</p><h1>Workspace overview<span className="heading-dot">.</span></h1><p className="page-description">A clear view of your data and the protections around it.</p></div><button className="button secondary refresh-button" onClick={() => setRevision((value) => value + 1)} disabled={loading}><RefreshCw size={15} className={loading ? 'spin' : ''} />{loading ? 'Refreshing…' : 'Refresh'}</button></div>
    {error && <div className="error-box" role="alert">{error}{summary && ' The totals below are from the last successful refresh.'}<button className="text-button" onClick={() => setRevision((value) => value + 1)}>Try again</button></div>}
    <section className="welcome-banner"><div className="welcome-icon"><ShieldCheck size={30} strokeWidth={1.5} /></div><div><span className="eyebrow">DISCOVER WITH CONFIDENCE</span><h2>Your data landscape is ready to explore.</h2><p>Connect a database and explore its schema. Scanning and reviewed protections are coming next.</p></div><span className="banner-pill"><Check size={13} /> Discovery available</span></section>
    <section className="stats-grid" aria-label="Workspace statistics" aria-busy={loading}>
      {stats.map(({ key, title, icon: Icon, detail, className }) => <article className="stat-card panel" key={key}><div className="stat-top"><span className={`stat-icon ${className}`}><Icon size={19} strokeWidth={1.8} /></span><span className="stat-label">{title}</span></div><p className={`stat-number ${loading && !summary ? 'skeleton' : ''}`}>{summary ? summary[key].toLocaleString() : loading ? '\u00a0' : '—'}</p><p className="stat-detail">{detail}</p></article>)}
    </section>
    <div className="dashboard-grid">
      <section className="panel inventory-panel"><div className="panel-heading"><div><h2>Data landscape</h2><p>Your recorded inventory at a glance</p></div><span className="pill small">Workspace totals</span></div>
        {loading && !summary ? <div className="chart-empty" role="status"><div className="loading-ring" /><p>Loading your workspace…</p></div> : !summary ? <div className="chart-empty"><Database size={36} strokeWidth={1.2} /><h3>Workspace totals unavailable</h3><p>Refresh to try loading them again.</p></div> : hasRecords ? <div className="inventory-chart" aria-label="Database, table, finding, and deployed policy counts"><ResponsiveContainer width="100%" height={238}><BarChart data={chartData} margin={{ top: 15, right: 20, bottom: 0, left: -20 }}><CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e5ebeb" /><XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fontSize: 12, fill: '#687d83' }} /><YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fontSize: 12, fill: '#687d83' }} /><Tooltip cursor={{ fill: '#f0f7f5' }} /><Bar dataKey="count" name="Records" fill="#138673" radius={[5, 5, 0, 0]} maxBarSize={48} /></BarChart></ResponsiveContainer></div> : <div className="chart-empty"><div className="empty-database-art" aria-hidden="true"><Database size={36} strokeWidth={1.3} /><span className="art-dot a" /><span className="art-dot b" /><span className="art-line" /></div><h3>Your data landscape starts here</h3><p>No databases have been registered yet.<br />Add a connection to discover its tables and relationships.</p><Link to="/connections" className="text-link">Explore connections <ArrowRight size={15} /></Link></div>}
        <div className="inventory-footer"><LockKeyhole size={14} /><p>Source records stay in your database.</p></div>
      </section>
      <section className="panel review-panel"><div className="panel-heading"><div><h2>Review & activity</h2><p>Stay close to your privacy workflow</p></div><CircleCheck size={20} className="muted" /></div><Link className="activity-row" to="/approvals"><span className="activity-icon amber"><CircleCheck size={20} /></span><span><strong>Pending approvals</strong><small>Policies awaiting a decision</small></span><b>{summary?.pending_approvals.toLocaleString() ?? '—'}</b><ChevronRight size={16} /></Link><Link className="activity-row" to="/scans"><span className="activity-icon blue"><ScanLine size={20} /></span><span><strong>Scan jobs</strong><small>Total discovery scans</small></span><b>{summary?.scan_jobs.toLocaleString() ?? '—'}</b><ChevronRight size={16} /></Link><div className="review-note"><span className="small-check"><Check size={14} /></span><div><strong>People stay in control</strong><p>Policies will require an explicit approval before a separate deployment action.</p></div></div><Link to="/audit" className="panel-bottom-link">View audit workspace <ArrowUpRight size={15} /></Link></section>
    </div>
    <section className="panel journey-panel"><div className="panel-heading"><div><h2>From visibility to protection</h2><p>Your path from discovery to protection</p></div><Sparkles size={20} className="muted" /></div><div className="journey-grid">{[
      { number: '01', title: 'Connect & discover', text: 'Map your tables, columns, and relationships.', to: '/schema', icon: Database },
      { number: '02', title: 'Find & understand', text: 'Identify personal data and review recommendations.', to: '/scans', icon: ScanLine },
      { number: '03', title: 'Review & protect', text: 'Preview, approve, and deploy masking policies.', to: '/policies', icon: ShieldCheck },
    ].map(({ number, title, text, to, icon: Icon }) => <Link className="journey-step" to={to} key={number}><span className="journey-number">{number}</span><div><div className="journey-title"><Icon size={17} /><h3>{title}</h3></div><p>{text}</p><span className="journey-state">{number === '01' ? 'Available now' : 'Planned capability'} <ArrowUpRight size={12} /></span></div></Link>)}</div></section>
    <p className="updated-caption" role="status">{loading ? 'Refreshing workspace totals…' : updated ? `Last refreshed ${updated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} · Counts reflect saved workspace records` : 'No workspace totals loaded'}</p>
  </div>;
}
