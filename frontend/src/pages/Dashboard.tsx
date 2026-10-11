import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { ArrowRight, ArrowUpRight, Check, ChevronRight, CircleCheck, Database, Fingerprint, Layers3, LockKeyhole, RefreshCw, ScanLine, ShieldCheck, Sparkles } from 'lucide-react';
import { Bar, BarChart, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { api } from '../api/client';
import type { DashboardInsights, DashboardSummary } from '../api/client';
import { classificationCategory, riskLabels } from '../api/classifications';
import type { Risk } from '../api/classifications';
import { policyStatusLabel } from '../api/policies';
import type { PolicyStatus } from '../api/policies';

const stats = [
  { key: 'databases', title: 'Connected databases', icon: Database, detail: 'Authorized data sources', className: 'teal' },
  { key: 'tables', title: 'Discovered tables', icon: Layers3, detail: 'Across your databases', className: 'blue' },
  { key: 'sensitive_columns', title: 'Sensitive columns', icon: Fingerprint, detail: 'Identified in sampled findings', className: 'amber' },
  { key: 'deployed_policies', title: 'Deployed policies', icon: ShieldCheck, detail: 'Approved protections in place', className: 'purple' },
] as const;

const journey = [
  { number: '01', title: 'Connect & discover', text: 'Map your tables, columns, and relationships.', to: '/schema', icon: Database },
  { number: '02', title: 'Find & understand', text: 'Review sampled findings and advisory AI recommendations.', to: '/classifications', icon: ScanLine },
  { number: '03', title: 'Review & protect', text: 'Preview, approve, and deploy masking policies.', to: '/policies', icon: ShieldCheck },
];

/** "POLICY_APPROVED" -> "Policy approved". */
function eventLabel(eventType: string) {
  const words = eventType.toLowerCase().replace(/_/g, ' ');
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function timeAgo(iso: string) {
  const seconds = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
}

const BAR_COLOR = '#0f8a74';
const BAR_ROW_HEIGHT = 30;

/**
 * One series of horizontal bars on a shared zero baseline, with the value at
 * each bar's end and a tooltip on hover. The same numbers are also rendered as
 * a list for screen readers, so the chart is never the only way to read them.
 */
function BarList({ label, unit, rows }: { label: string; unit: string; rows: Array<{ key: string; name: string; value: number }> }) {
  return <div className="bar-chart">
    <div aria-hidden="true">
      <ResponsiveContainer width="100%" height={rows.length * BAR_ROW_HEIGHT + 6}>
        <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 40, bottom: 0, left: 0 }}>
          <XAxis type="number" hide domain={[0, 'dataMax']} allowDecimals={false} />
          <YAxis type="category" dataKey="name" width={132} axisLine={{ stroke: '#cfdad8' }} tickLine={false} tick={{ fontSize: 11, fill: '#48616a' }} />
          <Tooltip cursor={{ fill: '#f0f7f5' }} formatter={(value) => [Number(value).toLocaleString(), unit]} contentStyle={{ fontSize: 11, borderRadius: 6, borderColor: '#dfe9e4' }} />
          <Bar dataKey="value" fill={BAR_COLOR} radius={[0, 4, 4, 0]} barSize={14} minPointSize={2} isAnimationActive={false}>
            <LabelList dataKey="value" position="right" style={{ fontSize: 11, fontWeight: 600, fill: '#233c43' }} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
    <ul className="sr-only" aria-label={label}>
      {rows.map((row) => <li key={row.key}><span>{row.name}</span><span>{row.value.toLocaleString()}</span></li>)}
    </ul>
  </div>;
}

export function Dashboard() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [insights, setInsights] = useState<DashboardInsights | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  const [updated, setUpdated] = useState<Date | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError('');
    api<DashboardSummary>('/dashboard/summary', { signal: controller.signal })
      .then((result) => {
        setSummary(result);
        setUpdated(new Date());
        // The breakdowns are requested only after the totals have loaded, and a
        // failure leaves the totals on screen with the breakdown panels empty.
        return api<DashboardInsights>('/dashboard/insights', { signal: controller.signal })
          .then((value) => { if (!controller.signal.aborted) setInsights(value); })
          .catch(() => { if (!controller.signal.aborted) setInsights(null); });
      })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : 'Unable to load workspace totals.');
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [revision]);

  const hasRecords = summary && Object.values(summary).some((value) => value > 0);
  const sensitive = insights?.coverage.sensitive_columns ?? 0;
  const covered = insights?.coverage.protected_columns ?? 0;
  const coveragePercent = sensitive ? Math.round((covered / sensitive) * 100) : 0;
  const policyTotal = insights?.policy_status.reduce((total, item) => total + item.policies, 0) ?? 0;
  const refresh = () => setRevision((value) => value + 1);

  return <div className="page-content dashboard">
    <div className="page-heading">
      <div><p className="eyebrow">YOUR PRIVACY COMMAND CENTER</p><h1>Workspace overview<span className="heading-dot">.</span></h1><p className="page-description">A clear view of your data and the protections around it.</p></div>
      <button className="button secondary refresh-button" onClick={refresh} disabled={loading}><RefreshCw size={15} className={loading ? 'spin' : ''} />{loading ? 'Refreshing…' : 'Refresh'}</button>
    </div>
    {error && <div className="error-box" role="alert">{error}{summary && ' The totals below are from the last successful refresh.'}<button className="text-button" onClick={refresh}>Try again</button></div>}

    <section className="welcome-banner">
      <div className="welcome-icon"><ShieldCheck size={30} strokeWidth={1.5} /></div>
      <div><span className="eyebrow">DISCOVER, DECIDE, PROTECT</span><h2>From a database connection to a masked view.</h2><p>Explore your schema, scan bounded samples, review advisory AI recommendations, then approve and deploy masking policies.</p></div>
      <span className="banner-pill"><Check size={13} /> Source data is never modified</span>
    </section>

    <section className="stats-grid" aria-label="Workspace statistics" aria-busy={loading}>
      {stats.map(({ key, title, icon: Icon, detail, className }) => (
        <article className="stat-card panel" key={key}>
          <div className="stat-top"><span className={`stat-icon ${className}`}><Icon size={19} strokeWidth={1.8} /></span><span className="stat-label">{title}</span></div>
          <p className={`stat-number ${loading && !summary ? 'skeleton' : ''}`}>{summary ? summary[key].toLocaleString() : loading ? ' ' : '—'}</p>
          <p className="stat-detail">{detail}</p>
        </article>
      ))}
    </section>

    <div className="dashboard-grid">
      <section className="panel inventory-panel" aria-label="Sensitive data by category">
        <div className="panel-heading"><div><h2>Sensitive data by category</h2><p>Columns with findings in the latest scan of each database</p></div><span className="pill small">Columns</span></div>
        {loading && !summary ? <div className="chart-empty" role="status"><div className="loading-ring" /><p>Loading your workspace…</p></div>
          : !summary ? <div className="chart-empty"><Database size={36} strokeWidth={1.2} /><h3>Workspace totals unavailable</h3><p>Refresh to try loading them again.</p></div>
          : !hasRecords ? <div className="chart-empty"><div className="empty-database-art" aria-hidden="true"><Database size={36} strokeWidth={1.3} /><span className="art-dot a" /><span className="art-dot b" /><span className="art-line" /></div><h3>Your data landscape starts here</h3><p>No databases have been registered yet.<br />Add a connection to discover its tables and relationships.</p><Link to="/connections" className="text-link">Explore connections <ArrowRight size={15} /></Link></div>
          : insights && insights.categories.length ? <BarList label="Sensitive columns by category" unit="columns" rows={insights.categories.map((item) => ({ key: item.category, name: classificationCategory(item.category), value: item.columns }))} />
          : <div className="chart-empty"><ScanLine size={36} strokeWidth={1.2} /><h3>No scan findings yet</h3><p>Run a scan to see which kinds of personal data your tables hold.</p><Link to="/scans" className="text-link">Go to scans <ArrowRight size={15} /></Link></div>}
        <div className="inventory-footer"><LockKeyhole size={14} /><p>Counts come from bounded samples. Source records stay in your database.</p></div>
      </section>

      <section className="panel review-panel" aria-label="Risk and protection">
        <div className="panel-heading"><div><h2>Risk and protection</h2><p>How sensitive the findings are, and how many are masked</p></div><ShieldCheck size={20} className="muted" /></div>
        {insights && sensitive > 0 ? <>
          <BarList label="Sensitive columns by risk level" unit="columns" rows={insights.risks.map((item) => ({ key: item.risk, name: riskLabels[item.risk as Risk], value: item.columns }))} />
          <p className="chart-note">{insights.risks_from_ai === 0 ? 'Risk level is assigned from the detected category.' : `Risk level comes from AI classification for ${insights.risks_from_ai} of ${sensitive} columns, and from the detected category for the rest.`}</p>
          <div className="coverage">
            <div className="coverage-figure"><strong>{covered.toLocaleString()} of {sensitive.toLocaleString()}</strong><span>sensitive columns are masked by a deployed policy</span></div>
            <div className="coverage-track" role="meter" aria-label="Sensitive columns masked by a deployed policy" aria-valuemin={0} aria-valuemax={sensitive} aria-valuenow={covered} aria-valuetext={`${covered} of ${sensitive} columns, ${coveragePercent}%`}><span style={{ width: `${coveragePercent}%` }} /></div>
          </div>
        </> : <p className="chart-note quiet">Risk levels and protection coverage appear after the first completed scan.</p>}
      </section>
    </div>

    <div className="dashboard-grid">
      <section className="panel" aria-label="Policy pipeline">
        <div className="panel-heading"><div><h2>Policy pipeline</h2><p>{policyTotal.toLocaleString()} masking {policyTotal === 1 ? 'policy version' : 'policy versions'} by lifecycle state</p></div><CircleCheck size={20} className="muted" /></div>
        <dl className="status-row">
          {(insights?.policy_status ?? []).map((item) => (
            <div key={item.status}><dt>{policyStatusLabel[item.status as PolicyStatus] ?? item.status}</dt><dd>{item.policies.toLocaleString()}</dd></div>
          ))}
        </dl>
        <Link className="activity-row" to="/approvals"><span className="activity-icon amber"><CircleCheck size={20} /></span><span><strong>Pending approvals</strong><small>Policies awaiting a decision</small></span><b>{summary?.pending_approvals.toLocaleString() ?? '—'}</b><ChevronRight size={16} /></Link>
        <Link className="activity-row" to="/scans"><span className="activity-icon blue"><ScanLine size={20} /></span><span><strong>Scan jobs</strong><small>Total discovery scans</small></span><b>{summary?.scan_jobs.toLocaleString() ?? '—'}</b><ChevronRight size={16} /></Link>
        <div className="review-note"><span className="small-check"><Check size={14} /></span><div><strong>People stay in control</strong><p>A policy needs an explicit approval, then a separate deployment action.</p></div></div>
      </section>

      <section className="panel review-panel" aria-label="Recent activity">
        <div className="panel-heading"><div><h2>Recent activity</h2><p>Latest entries in the audit trail</p></div><Sparkles size={20} className="muted" /></div>
        {insights && insights.recent_activity.length
          ? <ol className="event-list">{insights.recent_activity.map((event, index) => (
            <li key={`${event.created_at}-${index}`}><span className="event-dot" aria-hidden="true" /><span>{eventLabel(event.event_type)}</span><time dateTime={event.created_at}>{timeAgo(event.created_at)}</time></li>
          ))}</ol>
          : <p className="chart-note quiet">Audit events will appear here as people use the workspace.</p>}
        <Link to="/audit" className="panel-bottom-link">View audit workspace <ArrowUpRight size={15} /></Link>
      </section>
    </div>

    <section className="panel journey-panel">
      <div className="panel-heading"><div><h2>From visibility to protection</h2><p>Your path from discovery to protection</p></div><Sparkles size={20} className="muted" /></div>
      <div className="journey-grid">{journey.map(({ number, title, text, to, icon: Icon }) => (
        <Link className="journey-step" to={to} key={number}>
          <span className="journey-number">{number}</span>
          <div><div className="journey-title"><Icon size={17} /><h3>{title}</h3></div><p>{text}</p><span className="journey-state">Available now <ArrowUpRight size={12} /></span></div>
        </Link>
      ))}</div>
    </section>
    <p className="updated-caption" role="status">{loading ? 'Refreshing workspace totals…' : updated ? `Last refreshed ${updated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} · Counts reflect saved workspace records` : 'No workspace totals loaded'}</p>
  </div>;
}
