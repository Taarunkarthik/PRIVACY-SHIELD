import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { ArrowRight, ArrowUpRight, ChevronRight, CircleCheck, Database, Fingerprint, Layers3, RefreshCw, ScanLine, ShieldCheck } from 'lucide-react';
import { Bar, BarChart, Cell, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { api } from '../api/client';
import type { DashboardInsights, DashboardSummary } from '../api/client';
import { useAuth } from '../api/auth';
import { can, isReadOnly, roleBlurb, roleCapabilities, roleLabel } from '../api/permissions';
import { classificationCategory, riskLabels } from '../api/classifications';
import type { Risk } from '../api/classifications';
import { policyStatusLabel } from '../api/policies';
import type { PolicyStatus } from '../api/policies';
import { CountUp } from '../components/CountUp';
import { chart } from '../theme/chart';

// The tone ties a total to the product's two meanings: amber for what was
// found exposed, mint for what is protected.
const stats = [
  { key: 'databases', title: 'Connected databases', icon: Database, detail: 'Authorized data sources', tone: 'neutral' },
  { key: 'tables', title: 'Discovered tables', icon: Layers3, detail: 'Across your databases', tone: 'neutral' },
  { key: 'sensitive_columns', title: 'Sensitive columns', icon: Fingerprint, detail: 'Identified in sampled findings', tone: 'exposed' },
  { key: 'deployed_policies', title: 'Deployed policies', icon: ShieldCheck, detail: 'Approved protections in place', tone: 'masked' },
] as const;

const statusTone: Record<string, string> = {
  DRAFT: 'neutral', PENDING_APPROVAL: 'exposed', APPROVED: 'progress', DEPLOYED: 'masked', REJECTED: 'refused', FAILED: 'refused',
};

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

const BAR_ROW_HEIGHT = 26;

/* A "this is allowed" mark: a small tick drawn in the current colour so the
 * CSS owns the colour (mint) and this stays a plain inline SVG. */
function AllowedMark() {
  return <svg className="cap-mark" viewBox="0 0 16 16" width="13" height="13" aria-hidden="true" focusable="false"><path d="M3.4 8.5l3 3 6.2-6.9" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" /></svg>;
}

interface BarRow { key: string; name: string; value: number; fill?: string }

/**
 * One series of horizontal bars on a shared zero baseline, with the value at
 * each bar's end and a tooltip on hover. The same numbers are also rendered as
 * a list for screen readers, so the chart is never the only way to read them.
 * Labels and values use text colours; only the bars carry the series colour.
 */
function BarList({ label, unit, rows, labelWidth }: { label: string; unit: string; rows: BarRow[]; labelWidth: number }) {
  return <div className="bar-chart">
    <div aria-hidden="true">
      <ResponsiveContainer width="100%" height={rows.length * BAR_ROW_HEIGHT + 6}>
        <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 40, bottom: 0, left: 0 }}>
          <XAxis type="number" hide domain={[0, 'dataMax']} allowDecimals={false} />
          <YAxis type="category" dataKey="name" width={labelWidth} axisLine={{ stroke: chart.axis }} tickLine={false} tick={{ fontSize: 13, fill: chart.textMuted }} />
          <Tooltip cursor={{ fill: chart.hover }} formatter={(value) => [Number(value).toLocaleString(), unit]} contentStyle={{ fontSize: 13, borderRadius: 6, background: chart.tooltip.background, borderColor: chart.tooltip.border }} itemStyle={{ color: chart.text }} labelStyle={{ color: chart.textMuted }} />
          <Bar dataKey="value" fill={chart.exposed} radius={[0, 4, 4, 0]} barSize={14} minPointSize={2} isAnimationActive={false}>
            {rows.map((row) => <Cell key={row.key} fill={row.fill ?? chart.exposed} />)}
            <LabelList dataKey="value" position="right" style={{ fontSize: 13, fontWeight: 600, fill: chart.text }} />
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
  const { user } = useAuth();
  const role = user?.role;
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [insights, setInsights] = useState<DashboardInsights | null>(null);
  const [insightsFailed, setInsightsFailed] = useState(false);
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
          .then((value) => { if (!controller.signal.aborted) { setInsights(value); setInsightsFailed(false); } })
          .catch(() => { if (!controller.signal.aborted) { setInsights(null); setInsightsFailed(true); } });
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
  // Shown in a breakdown panel while its numbers are loading or could not be
  // loaded, so an empty panel is never mistaken for "nothing found".
  const breakdownPending = !insights && <p className="chart-note quiet" role="status">{insightsFailed ? 'This breakdown could not be loaded. Refresh to try again.' : 'Loading the breakdown…'}</p>;

  return <div className="page-content dashboard">
    <div className="page-heading">
      <div><h1>Workspace overview<span className="heading-dot">.</span></h1><p className="page-description">A clear view of your data and the protections around it.</p>{role && <p className="role-line">{roleLabel[role]} · {roleBlurb[role]}</p>}</div>
      <div className="heading-actions">
        <p className="updated-caption" role="status">{loading ? 'Refreshing workspace totals…' : updated ? `Last refreshed ${updated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : 'No workspace totals loaded'}</p>
        <button className="button secondary refresh-button" onClick={refresh} disabled={loading}><RefreshCw size={15} className={loading ? 'spin' : ''} />{loading ? 'Refreshing…' : 'Refresh'}</button>
      </div>
    </div>
    {role && isReadOnly(user) && <p className="readonly-note">Read-only for your {roleLabel[role]} role: you can inspect coverage and the audit trail, but nothing here can be changed.</p>}
    {role && <ul className="cap-strip" aria-label="What your role can do">
      {roleCapabilities[role].may.map((item) => <li key={item} className="cap-item yes"><AllowedMark /><span>{item}</span></li>)}
      {roleCapabilities[role].mayNot.map((item) => <li key={item} className="cap-item no"><span className="cap-mark" aria-hidden="true">·</span><span>{item}</span></li>)}
    </ul>}
    {error && <div className="error-box" role="alert">{error}{summary && ' The totals below are from the last successful refresh.'}<button className="text-button" onClick={refresh}>Try again</button></div>}

    <section className="stats-grid" aria-label="Workspace statistics" aria-busy={loading}>
      {stats.map(({ key, title, icon: Icon, detail, tone }) => (
        <article className={`stat-card panel tone-${tone}`} key={key}>
          <div className="stat-top"><span className="stat-icon"><Icon size={18} strokeWidth={1.8} /></span><span className="stat-label">{title}</span></div>
          <p className={`stat-number ${loading && !summary ? 'skeleton' : ''}`}>{summary ? <CountUp value={summary[key]} /> : loading ? ' ' : '—'}</p>
          <p className="stat-detail">{detail}</p>
        </article>
      ))}
    </section>

    <div className="dashboard-grid">
      <section className="panel inventory-panel" aria-label="Sensitive data by category">
        <div className="panel-heading"><div><h2>Sensitive data by category</h2><p>Columns with findings in the latest scan of each database</p></div></div>
        {loading && !summary ? <div className="chart-empty" role="status"><div className="loading-ring" /><p>Loading your workspace…</p></div>
          : !summary ? <div className="chart-empty"><Database size={36} strokeWidth={1.2} /><h3>Workspace totals unavailable</h3><p>Refresh to try loading them again.</p></div>
          : !hasRecords ? <div className="chart-empty"><Database size={36} strokeWidth={1.2} /><h3>Your data landscape starts here</h3><p>No databases have been registered yet.<br />Add a connection to discover its tables and relationships.</p><Link to="/connections" className="text-link">Explore connections <ArrowRight size={15} /></Link></div>
          : !insights ? <div className="chart-empty">{breakdownPending}</div>
          : insights.categories.length ? <BarList label="Sensitive columns by category" unit="columns" labelWidth={172} rows={insights.categories.map((item) => ({ key: item.category, name: classificationCategory(item.category), value: item.columns }))} />
          : <div className="chart-empty"><ScanLine size={36} strokeWidth={1.2} /><h3>No scan findings yet</h3><p>Run a scan to see which kinds of personal data your tables hold.</p><Link to="/scans" className="text-link">Go to scans <ArrowRight size={15} /></Link></div>}
        <p className="panel-footnote">Counts come from bounded samples. Source records stay in your database.</p>
      </section>

      <section className="panel review-panel" aria-label="Risk and protection">
        <div className="panel-heading"><div><h2>Risk and protection</h2><p>How sensitive the findings are, and how many are masked</p></div></div>
        {!insights ? breakdownPending : sensitive > 0 ? <>
          <div className="coverage">
            <div className="coverage-figure"><strong>{covered.toLocaleString()} of {sensitive.toLocaleString()}</strong><span>sensitive columns are masked by a deployed policy</span></div>
            <div className="coverage-track" role="meter" aria-label="Sensitive columns masked by a deployed policy" aria-valuemin={0} aria-valuemax={sensitive} aria-valuenow={covered} aria-valuetext={`${covered} of ${sensitive} columns, ${coveragePercent}%`}>
              {covered > 0 && <span className="coverage-masked" style={{ flexGrow: covered }} />}
              {sensitive > covered && <span className="coverage-exposed" style={{ flexGrow: sensitive - covered }} />}
            </div>
            <ul className="coverage-key">
              <li><span className="key-dot masked" aria-hidden="true" />{covered.toLocaleString()} masked</li>
              <li><span className="key-dot exposed" aria-hidden="true" />{(sensitive - covered).toLocaleString()} still exposed</li>
            </ul>
          </div>
          <BarList label="Sensitive columns by risk level" unit="columns" labelWidth={84} rows={insights.risks.map((item) => ({ key: item.risk, name: riskLabels[item.risk as Risk], value: item.columns, fill: chart.risk[item.risk] }))} />
          <p className="chart-note">A column takes the highest risk level among the categories detected in it.{insights.risks_from_ai > 0 && ` An AI classification was also weighed for ${insights.risks_from_ai} of ${sensitive} columns and can only raise the level.`}</p>
        </> : <p className="chart-note quiet">Risk levels and protection coverage appear after the first completed scan.</p>}
      </section>

      <section className="panel pipeline-panel" aria-label="Policy pipeline">
        <div className="panel-heading"><div><h2>Policy pipeline</h2><p>{insights ? `${policyTotal.toLocaleString()} masking ${policyTotal === 1 ? 'policy version' : 'policy versions'} by lifecycle state` : 'Masking policy versions by lifecycle state'}</p></div></div>
        {!insights ? breakdownPending : <dl className="status-row">
          {insights.policy_status.map((item) => (
            <div key={item.status}><dt><span className={`key-dot ${statusTone[item.status] ?? 'neutral'}`} aria-hidden="true" />{policyStatusLabel[item.status as PolicyStatus] ?? item.status}</dt><dd>{item.policies.toLocaleString()}</dd></div>
          ))}
        </dl>}
        {role === 'ANALYST' && <p className="chart-note quiet">You can create and submit policies for approval; an administrator gives the decision and deploys them.</p>}
        <div className="pipeline-links">
          {can(user, 'policy.approve') && <Link className="activity-row" to="/approvals"><span className="activity-icon tone-exposed"><CircleCheck size={18} /></span><span><strong>Pending approvals</strong><small>Policies awaiting a decision</small></span><b>{summary?.pending_approvals.toLocaleString() ?? '—'}</b><ChevronRight size={16} /></Link>}
          <Link className="activity-row" to="/scans"><span className="activity-icon tone-neutral"><ScanLine size={18} /></span><span><strong>Scan jobs</strong><small>Total discovery scans</small></span><b>{summary?.scan_jobs.toLocaleString() ?? '—'}</b><ChevronRight size={16} /></Link>
        </div>
        <p className="panel-footnote">A policy needs an explicit approval, then a separate deployment action.</p>
      </section>

      <section className="panel activity-panel" aria-label="Recent activity">
        <div className="panel-heading"><div><h2>Recent activity</h2><p>Latest entries in the audit trail</p></div><Link to="/audit" className="text-link">View audit workspace <ArrowUpRight size={15} /></Link></div>
        {!insights ? breakdownPending : insights.recent_activity.length
          ? <ol className="event-list">{insights.recent_activity.map((event, index) => (
            <li key={`${event.created_at}-${index}`}><span className="event-dot" aria-hidden="true" /><span>{eventLabel(event.event_type)}</span><time dateTime={event.created_at}>{timeAgo(event.created_at)}</time></li>
          ))}</ol>
          : <p className="chart-note quiet">Audit events will appear here as people use the workspace.</p>}
      </section>
    </div>
  </div>;
}
