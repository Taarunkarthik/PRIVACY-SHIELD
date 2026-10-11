import { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { ArrowRight, Check, ChevronLeft, ChevronRight, Copy, FileClock, Play, Plus, RefreshCw, Send, ShieldCheck, Sparkles, X } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { useAuth } from '../api/auth';
import { defaultConnectionId } from '../api/connections';
import type { Connection, SchemaSnapshot } from '../api/connections';
import { classificationCategory } from '../api/classifications';
import type { Audience, Policy, PolicyPage, PolicyPreview, PolicyAction, PolicyRule, PolicySamples, PolicySuggestions, ProtectedOutput, RuleSuggestion } from '../api/policies';
import { actionHint, actionLabel, AUDIENCES, audienceLabel, audienceRole, policyAudiences, policyStatusLabel } from '../api/policies';
import { MaskReveal } from '../components/MaskReveal';

const ACTIONS: PolicyAction[] = ['KEEP', 'MASK_EMAIL', 'MASK_PHONE', 'MASK_ID', 'PARTIAL', 'REDACT', 'PSEUDONYMIZE', 'NULLIFY', 'RESTRICT'];
// The pseudonym key domain provisioned on the bundled demonstration target.
const DEFAULT_PSEUDONYM_DOMAIN = 'demo';
// The API accepts at most this many rules for each audience of one policy.
const MAX_RULES = 200;

// General readers are the default audience, so requests for them carry no parameter.
const audienceQuery = (audience: Audience) => (audience === 'reader' ? '' : `?audience=${audience}`);

// What the right-hand side shows for the selected policy.
type PolicyView = 'rules' | 'preview' | 'output';

export function Policies() {
  const { user } = useAuth();
  const canManage = user?.role === 'ADMIN' || user?.role === 'ANALYST';
  const canApprove = user?.role === 'ADMIN';
  const [params, setParams] = useSearchParams();
  const [connections, setConnections] = useState<Connection[]>([]);
  const [connectionsLoading, setConnectionsLoading] = useState(true);
  const [connectionError, setConnectionError] = useState('');
  const [policies, setPolicies] = useState<PolicyPage | null>(null);
  const [policiesLoading, setPoliciesLoading] = useState(true);
  const [policiesError, setPoliciesError] = useState('');
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [showCreate, setShowCreate] = useState(false);
  const [actionError, setActionError] = useState('');
  const [previewError, setPreviewError] = useState('');
  const [actionLoading, setActionLoading] = useState('');
  const [preview, setPreview] = useState<PolicyPreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [samples, setSamples] = useState<PolicySamples | null>(null);
  const previewRequest = useRef(0);
  const previewKey = useRef('');
  const [output, setOutput] = useState<ProtectedOutput | null>(null);
  const [outputLoading, setOutputLoading] = useState(false);
  const outputRequest = useRef(0);
  const outputKey = useRef('');
  const [view, setView] = useState<PolicyView>('rules');
  const [audience, setAudience] = useState<Audience>('reader');
  const connectionId = params.get('connection') || defaultConnectionId(connections);
  const connection = connections.find((c) => c.id === connectionId);
  const selectedId = params.get('policy') || policies?.items[0]?.id || '';
  const selected = policies?.items.find((p) => p.id === selectedId) || null;
  // Read by responses that arrive late: a failure for a policy that is no
  // longer selected must not be reported against the one that is.
  const selectedNow = useRef(selectedId);
  selectedNow.current = selectedId;
  // The audiences this policy has a view for, and the one on screen.
  const audiences = selected ? policyAudiences(selected) : AUDIENCES.slice(0, 1);
  const shownAudience: Audience = audiences.includes(audience) ? audience : 'reader';

  useEffect(() => {
    const controller = new AbortController();
    setConnectionsLoading(true);
    setConnectionError('');
    async function load() {
      const first = await api<ConnectionPage>('/connections?page=1&page_size=100', { signal: controller.signal });
      const all = [...first.items];
      for (let p = 2; p <= Math.ceil(first.total / 100); p++) {
        const next = await api<ConnectionPage>(`/connections?page=${p}&page_size=100`, { signal: controller.signal });
        all.push(...next.items);
      }
      if (!controller.signal.aborted) setConnections(all);
    }
    load().catch((r: unknown) => { if (!controller.signal.aborted) setConnectionError(r instanceof ApiError ? r.message : 'Could not load connections.'); })
      .finally(() => { if (!controller.signal.aborted) setConnectionsLoading(false); });
    return () => controller.abort();
  }, [revision]);

  useEffect(() => {
    if (!connectionId) { setPolicies(null); setPoliciesLoading(false); return; }
    const controller = new AbortController();
    setPoliciesLoading(true);
    setPoliciesError('');
    api<PolicyPage>(`/policies?connection_id=${encodeURIComponent(connectionId)}&page=${page}&page_size=10`, { signal: controller.signal })
      .then((v) => { if (!controller.signal.aborted) setPolicies(v); })
      .catch((r: unknown) => { if (!controller.signal.aborted) setPoliciesError(r instanceof ApiError ? r.message : 'Could not load policies.'); })
      .finally(() => { if (!controller.signal.aborted) setPoliciesLoading(false); });
    return () => controller.abort();
  }, [connectionId, page, revision]);

  // Another policy is selected (a click, a newly created policy, Back or Forward):
  // start on its rules, for general readers, without the previous policy's messages.
  useEffect(() => {
    setView('rules');
    setAudience('reader');
    setActionError('');
    setPreviewError('');
  }, [selectedId]);

  async function submitPolicy(id: string) {
    setActionLoading(id); setActionError('');
    try {
      await api(`/policies/${encodeURIComponent(id)}/submit`, { method: 'POST', csrfToken: user!.csrf_token });
      setRevision((v) => v + 1);
    } catch (r) { setActionError(r instanceof ApiError ? r.message : 'Could not submit policy.'); }
    finally { setActionLoading(''); }
  }

  async function approvePolicy(id: string) {
    setActionLoading(id); setActionError('');
    try {
      await api(`/policies/${encodeURIComponent(id)}/approve`, { method: 'POST', csrfToken: user!.csrf_token });
      setRevision((v) => v + 1);
    } catch (r) { setActionError(r instanceof ApiError ? r.message : 'Could not approve policy.'); }
    finally { setActionLoading(''); }
  }

  async function rejectPolicy(id: string) {
    setActionLoading(id); setActionError('');
    try {
      await api(`/policies/${encodeURIComponent(id)}/reject`, { method: 'POST', csrfToken: user!.csrf_token });
      setRevision((v) => v + 1);
    } catch (r) { setActionError(r instanceof ApiError ? r.message : 'Could not reject policy.'); }
    finally { setActionLoading(''); }
  }

  async function deployPolicy(id: string) {
    setActionLoading(id); setActionError('');
    try {
      await api(`/policies/${encodeURIComponent(id)}/deploy`, { method: 'POST', csrfToken: user!.csrf_token, body: '{}' });
      setRevision((v) => v + 1);
    } catch (r) { setActionError(r instanceof ApiError ? r.message : 'Could not deploy policy.'); }
    finally { setActionLoading(''); }
  }

  async function loadPreview(id: string, forAudience: Audience) {
    // Each request supersedes the last one, so a slow earlier response cannot
    // overwrite the preview that was asked for most recently.
    const request = ++previewRequest.current;
    const current = () => request === previewRequest.current;
    previewKey.current = `${id}:${forAudience}`;
    const query = audienceQuery(forAudience);
    setPreviewLoading(true); setPreviewError(''); setPreview(null); setSamples(null);
    try {
      const v = await api<PolicyPreview>(`/policies/${encodeURIComponent(id)}/preview${query}`);
      if (!current()) return;
      setPreview(v);
      // The before/after illustration is optional: it needs the target database,
      // so the compiled preview is shown even when the illustration is unavailable.
      api<PolicySamples>(`/policies/${encodeURIComponent(id)}/preview/samples${query}`)
        .then((value) => { if (current()) setSamples(value); })
        .catch(() => { if (current()) setSamples({ policy_id: id, status: 'UNAVAILABLE', source: 'FABRICATED', audience: forAudience, columns: [], before: [], after: [] }); });
    } catch (r) { if (current() && selectedNow.current === id) setPreviewError(r instanceof ApiError ? r.message : 'Could not load preview.'); }
    finally { if (current()) setPreviewLoading(false); }
  }

  async function loadOutput(id: string, forAudience: Audience) {
    const request = ++outputRequest.current;
    const current = () => request === outputRequest.current;
    outputKey.current = `${id}:${forAudience}`;
    setOutputLoading(true); setActionError(''); setOutput(null);
    try {
      const value = await api<ProtectedOutput>(`/policies/${encodeURIComponent(id)}/protected-output${audienceQuery(forAudience)}`);
      if (current()) setOutput(value);
    } catch (r) {
      if (current() && selectedNow.current === id) setActionError(r instanceof ApiError && r.status === 409
        ? 'Protected output is not available for this version. A newer version may have replaced it, or its connection or schema may have changed.'
        : r instanceof ApiError ? r.message : 'Could not load the protected output.');
    }
    finally { if (current()) setOutputLoading(false); }
  }

  // A preview or output belongs to one policy and one audience; hide it when another is chosen.
  const shownPreview = preview && preview.policy_id === selectedId && (preview.audience ?? 'reader') === shownAudience ? preview : null;
  const ownSamples = shownPreview && samples?.policy_id === selectedId && (samples.audience ?? 'reader') === shownAudience ? samples : null;
  const shownSamples = ownSamples?.status === 'OK' ? ownSamples : null;
  const hasPseudonym = Boolean(shownSamples?.columns.some((col) => col.action === 'PSEUDONYMIZE'));
  const shownOutput = output && output.policy_id === selectedId && (output.audience ?? 'reader') === shownAudience ? output : null;
  // Rows through the deployed view are for administrators, and exist only once a policy is deployed.
  const canSeeOutput = canApprove && selected?.status === 'DEPLOYED';
  const shownView: PolicyView = view === 'output' && !canSeeOutput ? 'rules' : view;

  // Policies belong to one database. Changing it starts that database's list from
  // its first page, with no policy carried over from the previous one.
  function chooseConnection(id: string) {
    if (id === connectionId) return;
    setPage(1);
    setPolicies(null);
    setParams({ connection: id });
  }

  function selectPolicy(id: string) {
    // Reset together with the selection, so no frame shows the old tab for the
    // new policy. The effect above covers the routes that do not pass through here.
    setView('rules');
    setAudience('reader');
    setParams({ connection: connectionId, policy: id });
  }

  // Opening a tab loads what it shows, unless that is already on screen or on its way.
  function openPreview(id: string) {
    setView('preview');
    const pending = previewLoading && previewKey.current === `${id}:${shownAudience}`;
    if (!shownPreview && !pending) void loadPreview(id, shownAudience);
  }

  function openOutput(id: string) {
    setView('output');
    const pending = outputLoading && outputKey.current === `${id}:${shownAudience}`;
    if (!shownOutput && !pending) void loadOutput(id, shownAudience);
  }

  // Switching audience reloads the view on screen for that audience's role.
  function chooseAudience(id: string, next: Audience) {
    if (next === shownAudience) return;
    setAudience(next);
    if (shownView === 'preview') void loadPreview(id, next);
    if (shownView === 'output') void loadOutput(id, next);
  }

  return <div className="page-content policies-page">
    <div className="page-heading">
      <div><h1>Masking Policies<span className="heading-dot">.</span></h1><p className="page-description">Create, preview, approve, and deploy data protection policies.</p></div>
      <div className="heading-actions">
        {canManage && connection && <button className="button primary" onClick={() => setShowCreate(true)}><Plus size={15} /> New policy</button>}
        <Link className="button secondary" to="/deployments"><FileClock size={15} /> Deployments</Link>
        <button className="button secondary" onClick={() => setRevision((v) => v + 1)} disabled={policiesLoading || connectionsLoading}><RefreshCw size={15} /> Refresh</button>
      </div>
    </div>

    {(connectionError || policiesError || actionError || previewError) && <div className="error-box" role="alert">{connectionError || policiesError || actionError || previewError}</div>}

    {!connectionsLoading && !connection && <section className="panel data-empty"><ShieldCheck size={34} strokeWidth={1.3} /><h2>No connections available</h2><p>Connect a database to start creating masking policies.</p><Link to="/connections" className="button secondary">View connections <ArrowRight size={14} /></Link></section>}

    {connection && <div className={`policy-workbench ${selected ? '' : 'no-selection'}`}>
      <section className="panel policy-list" aria-label="Policies">
        <div className="panel-heading"><div><h2>Policies <span className="count-badge">{policies?.total ?? '—'}</span></h2><p>Protection policies for {connection.name}.</p></div></div>
        {connections.length > 1 && <div className="form-field policy-connection">
          <label htmlFor="policy-connection">Database connection</label>
          <select id="policy-connection" value={connectionId} onChange={(e) => chooseConnection(e.target.value)} disabled={Boolean(actionLoading)}>
            {connections.map((item) => <option key={item.id} value={item.id}>{item.name}{item.is_active ? '' : ' (inactive)'}</option>)}
          </select>
        </div>}
        {policiesLoading && !policies ? <div className="data-empty" role="status"><div className="loading-ring" /><p>Loading policies…</p></div>
          : policies && !policies.total ? <div className="data-empty"><ShieldCheck size={34} strokeWidth={1.3} /><h3>No policies yet</h3><p>{canManage ? 'Create your first masking policy to protect sensitive data.' : 'Policies will appear here once an administrator or analyst creates one.'}</p></div>
          : <div className="policy-items">{policies?.items.map((item) => (
            <button type="button" className={`policy-row ${selectedId === item.id ? 'selected' : ''}`} key={item.id} onClick={() => selectPolicy(item.id)} aria-pressed={selectedId === item.id}>
              <span className="policy-info"><strong>{item.schema_name}.{item.table_name}</strong><small>v{item.version} · {item.rules.length} rules · {new Date(item.created_at).toLocaleDateString()}</small></span>
              <span className={`pill policy-status status-${item.status.toLowerCase().replace('_', '-')}`}>{policyStatusLabel[item.status]}</span>
              <ChevronRight size={15} />
            </button>))}</div>}
        {policies && policies.total > 10 && <div className="pagination"><span>Page {page} of {Math.ceil(policies.total / 10)}</span><div><button className="button secondary" disabled={page === 1 || policiesLoading} onClick={() => setPage(page - 1)}><ChevronLeft size={13} /> Previous</button><button className="button secondary" disabled={page * 10 >= policies.total || policiesLoading} onClick={() => setPage(page + 1)}>Next <ChevronRight size={13} /></button></div></div>}
      </section>

      {selected && <section className="panel policy-detail" aria-label="Selected policy">
        <div className="panel-heading">
          <div><h2>{selected.schema_name}.{selected.table_name} <span className="count-badge">v{selected.version}</span></h2><p>Created {new Date(selected.created_at).toLocaleString()}</p></div>
          <span className={`pill policy-status status-${selected.status.toLowerCase().replace('_', '-')}`}>{policyStatusLabel[selected.status]}</span>
        </div>

        <div className="policy-toolbar">
          {/* Toggle buttons rather than ARIA tabs: each keeps a plain button role and name. */}
          <div className="policy-tabs" role="group" aria-label="Policy views">
            <button type="button" className="policy-tab" aria-pressed={shownView === 'rules'} onClick={() => setView('rules')}>Rules <span className="count-badge">{selected.rules.length}</span></button>
            <button type="button" className="policy-tab" aria-pressed={shownView === 'preview'} onClick={() => openPreview(selected.id)}>Preview</button>
            {canSeeOutput && <button type="button" className="policy-tab" aria-pressed={shownView === 'output'} aria-label="View protected output" onClick={() => openOutput(selected.id)}>Protected output</button>}
          </div>
          <div className="policy-actions">
            {canManage && selected.status === 'DRAFT' && <button className="button primary" disabled={actionLoading === selected.id} onClick={() => submitPolicy(selected.id)}><Send size={15} />{actionLoading === selected.id ? 'Submitting…' : 'Submit for approval'}</button>}
            {canApprove && selected.status === 'PENDING_APPROVAL' && <>
              <button className="button primary" disabled={actionLoading === selected.id} onClick={() => approvePolicy(selected.id)}><Check size={15} />{actionLoading === selected.id ? 'Approving…' : 'Approve'}</button>
              <button className="button danger" disabled={actionLoading === selected.id} onClick={() => rejectPolicy(selected.id)}><X size={15} />{actionLoading === selected.id ? 'Rejecting…' : 'Reject'}</button>
            </>}
            {canApprove && (selected.status === 'APPROVED' || selected.status === 'FAILED') && <button className="button primary" disabled={actionLoading === selected.id} onClick={() => deployPolicy(selected.id)}><Play size={15} />{actionLoading === selected.id ? 'Deploying…' : 'Deploy'}</button>}
          </div>
        </div>

        {shownView === 'rules' && <div className="policy-rules">
          <h3>Protection rules</h3>
          {audiences.length === 1
            ? <div className="rules-table">
              <div className="rules-header"><span>Column</span><span>Action</span><span>Domain</span></div>
              {selected.rules.map((rule) => (
                <div className="rules-row" key={rule.column_name}>
                  <span className="rule-column">{rule.column_name}</span>
                  <span><span className={`pill action-${rule.action.toLowerCase().replace('_', '-')}`}>{actionLabel[rule.action]}</span></span>
                  <span className="rule-domain">{rule.pseudonym_domain || '—'}</span>
                </div>
              ))}
            </div>
            : <AudienceRules rules={selected.rules} audiences={audiences} />}
        </div>}

        {shownView !== 'rules' && audiences.length > 1 && <AudienceSwitch
          label="Audience"
          audiences={audiences}
          value={shownAudience}
          onChange={(next) => chooseAudience(selected.id, next)}
          detail={(item) => audienceRole[item]}
        />}

        {shownView === 'preview' && (shownPreview ? <section className="policy-preview" aria-label="Policy preview">
          <div className="view-heading"><h3>Preview: {shownPreview.view_schema}.{shownPreview.view_name}</h3><p>Security-barrier view with {shownPreview.columns.length} columns.</p></div>
          {shownSamples
            ? <><p className="masking-note" id="masking-preview-note">Each example value is run through the policy's real masking expression in PostgreSQL. The examples are invented: no rows are read from your database.{hasPseudonym && ' A pseudonym shown here is a stand-in of the same shape; real tokens are made with a secret key kept in the target database.'}</p>
            <div className="table-scroll">
              <table className="columns-table masking-table masking-preview" aria-describedby="masking-preview-note">
                <thead><tr><th scope="col">Column</th><th scope="col">Action</th><th scope="col">Example value</th><th scope="col">After masking</th></tr></thead>
                <tbody>{shownSamples.columns.map((col, index) => {
                  const before = shownSamples.before[0]?.[index] ?? null;
                  const after = shownSamples.after[0]?.[index] ?? null;
                  return <tr className="preview-column" key={col.name}>
                    <th scope="row">{col.name}<small className="masking-type">{col.data_type}</small></th>
                    <td><span className={`pill action-${col.action.toLowerCase().replace('_', '-')}`}>{actionLabel[col.action]}</span></td>
                    <td><MaskedCell value={before} exposed={before !== after} /></td>
                    <td>{after !== null && before !== after ? <MaskReveal from={before} to={after} /> : <MaskedCell value={after} />}</td>
                  </tr>;
                })}</tbody>
              </table>
            </div></>
            : <div className="preview-columns">
              {ownSamples?.status === 'UNAVAILABLE' && <p className="rules-editor-note">Example values are not available right now because the target database could not be used. The compiled plan below is unaffected.</p>}
              {shownPreview.columns.map((col) => (
                <div className="preview-column" key={col.name}>
                  <span className="preview-col-name">{col.name}</span>
                  <span className="preview-col-type">{col.data_type}</span>
                  <span className={`pill action-${col.action.toLowerCase().replace('_', '-')}`}>{actionLabel[col.action]}</span>
                </div>
              ))}
            </div>}
          <details className="preview-sql"><summary>View SQL</summary><pre>{shownPreview.sql}</pre></details>
        </section> : <div className="data-empty view-pending" role="status">{previewLoading ? <><div className="loading-ring" /><p>Compiling the preview…</p></> : <p>The preview could not be loaded. Choose Preview to try again.</p>}</div>)}

        {shownView === 'output' && (shownOutput ? <section className="policy-preview" aria-label="Protected output">
          <div className="view-heading"><h3>Protected output: {shownOutput.view_schema}.{shownOutput.view_name}</h3><p>The first {shownOutput.rows.length} rows as the <code>{shownOutput.access.reader_role}</code> role sees them through the deployed view.</p></div>
          <ul className="access-facts">
            <li className={shownOutput.access.reader_can_read_view ? 'access-ok' : 'access-bad'}>{shownOutput.access.reader_can_read_view ? <Check size={15} /> : <X size={15} />}<span><code>{shownOutput.access.reader_role}</code> {shownOutput.access.reader_can_read_view ? 'can read' : 'cannot read'} the masked view</span></li>
            <li className={shownOutput.access.reader_can_read_source ? 'access-bad' : 'access-ok'}>{shownOutput.access.reader_can_read_source ? <X size={15} /> : <Check size={15} />}<span><code>{shownOutput.access.reader_role}</code> {shownOutput.access.reader_can_read_source ? 'can still read' : 'cannot read'} the source table {shownOutput.source_schema}.{shownOutput.source_table}</span></li>
          </ul>
          <div className="table-scroll">
            <table className="columns-table masking-table masking-output">
              <thead><tr>{shownOutput.columns.map((col) => <th scope="col" key={col.name}>{col.name}<small className="masking-type">{actionLabel[col.action]}</small></th>)}</tr></thead>
              <tbody>{shownOutput.rows.map((row, rowIndex) => (
                <tr key={rowIndex}>{row.map((value, index) => <td key={shownOutput.columns[index].name}><MaskedCell value={value} changed={shownOutput.columns[index].action !== 'KEEP'} /></td>)}</tr>
              ))}</tbody>
            </table>
          </div>
          {!shownOutput.rows.length && <p className="masking-empty">The source table has no rows yet.</p>}
        </section> : <div className="data-empty view-pending" role="status">{outputLoading ? <><div className="loading-ring" /><p>Reading through the deployed view…</p></> : <p>The protected output could not be loaded. Choose Protected output to try again.</p>}</div>)}
      </section>}
    </div>}

    {showCreate && <CreatePolicyDialog connectionId={connectionId} onClose={() => setShowCreate(false)} onCreated={(id) => { setShowCreate(false); selectPolicy(id); setRevision((v) => v + 1); }} />}
  </div>;
}

/** One value in a before/after table: amber while it is still exposed, mint once a mask has changed it. */
function MaskedCell({ value, changed = false, exposed = false }: { value: string | null; changed?: boolean; exposed?: boolean }) {
  if (value === null) return <span className="masked-null">NULL</span>;
  return <code className={changed ? 'masked-value' : exposed ? 'exposed-value' : undefined}>{value}</code>;
}

function emptyAudienceMap<T>(): Record<Audience, Record<string, T>> {
  return { reader: {}, support: {}, analyst: {} };
}

/** Chooses which audience a view or an editor is showing. Toggle buttons, like the view switcher. */
function AudienceSwitch({ label, audiences, value, onChange, detail }: { label: string; audiences: Audience[]; value: Audience; onChange: (audience: Audience) => void; detail: (audience: Audience) => string }) {
  return <div className="audience-switch" role="group" aria-label={label}>
    <span className="audience-switch-label">{label}</span>
    {audiences.map((item) => (
      <button type="button" className="audience-option" key={item} aria-pressed={value === item} onClick={() => onChange(item)}>
        <strong>{audienceLabel[item]}</strong><small>{detail(item)}</small>
      </button>
    ))}
  </div>;
}

/** The rules of a policy that masks one table differently for several audiences, side by side. */
function AudienceRules({ rules, audiences }: { rules: PolicyRule[]; audiences: Audience[] }) {
  const columns = [...new Set(rules.map((rule) => rule.column_name))];
  const ruleFor = (column: string, audience: Audience) => rules.find((rule) => rule.column_name === column && (rule.audience ?? 'reader') === audience);
  return <>
    <p className="rules-editor-note">Each audience reads its own masked view through its own database role. A column without a rule for an audience is NULL in that audience's view.</p>
    <div className="table-scroll">
      <table className="columns-table masking-table audience-matrix">
        <thead><tr><th scope="col">Column</th>{audiences.map((item) => <th scope="col" key={item}>{audienceLabel[item]}<small className="masking-type">{audienceRole[item]}</small></th>)}</tr></thead>
        <tbody>{columns.map((column) => (
          <tr key={column}>
            <th scope="row">{column}</th>
            {audiences.map((item) => {
              const rule = ruleFor(column, item);
              return <td key={item}>{rule
                ? <><span className={`pill action-${rule.action.toLowerCase().replace('_', '-')}`}>{actionLabel[rule.action]}</span>{rule.pseudonym_domain && <small className="masking-type">key domain {rule.pseudonym_domain}</small>}</>
                : <span className="masked-null">NULL</span>}</td>;
            })}
          </tr>
        ))}</tbody>
      </table>
    </div>
  </>;
}

function suggestionNote(suggestion: RuleSuggestion | undefined): string {
  if (!suggestion || suggestion.source === 'NOT_SCANNED') return 'Not scanned yet';
  if (suggestion.source === 'NO_FINDINGS') {
    return suggestion.action
      ? `Nothing found in ${suggestion.sampled_rows.toLocaleString()} sampled rows`
      : 'Could not be read in full, so there is no suggestion';
  }
  const category = classificationCategory(suggestion.category ?? '');
  return suggestion.source === 'AI'
    ? `${category} (AI suggestion)`
    : `${category} in ${suggestion.matching_rows.toLocaleString()} of ${suggestion.sampled_rows.toLocaleString()} sampled rows`;
}

function CreatePolicyDialog({ connectionId, onClose, onCreated }: { connectionId: string; onClose: () => void; onCreated: (id: string) => void }) {
  const { user } = useAuth();
  const [snapshot, setSnapshot] = useState<SchemaSnapshot | null>(null);
  const [snapshotLoading, setSnapshotLoading] = useState(true);
  const [selectedTable, setSelectedTable] = useState('');
  // One set of rules per audience; the editor shows one audience at a time.
  const [allRules, setAllRules] = useState<Record<Audience, Record<string, PolicyAction>>>(emptyAudienceMap);
  const [allDomains, setAllDomains] = useState<Record<Audience, Record<string, string>>>(emptyAudienceMap);
  const [editing, setEditing] = useState<Audience>('reader');
  const rules = allRules[editing];
  const domains = allDomains[editing];
  const [suggestions, setSuggestions] = useState<PolicySuggestions | null>(null);
  const [loading, setLoading] = useState(false);
  // Shown inside the dialog: a message on the page behind it would be hidden.
  const [error, setError] = useState('');

  // Escape closes the dialog wherever focus is. A button that removes itself when
  // used (applying suggestions, say) leaves focus on the page, outside the dialog.
  // Not while a create is on its way: its outcome is reported in this dialog.
  // And not from a dropdown, where Escape means "close the list" (some browsers
  // pass that key press on to the page).
  const close = useRef(onClose);
  close.current = onClose;
  const busy = useRef(false);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || event.defaultPrevented || event.isComposing || busy.current) return;
      if (event.target instanceof HTMLSelectElement) return;
      close.current();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    setSnapshotLoading(true);
    api<SchemaSnapshot>(`/connections/${encodeURIComponent(connectionId)}/schema`, { signal: controller.signal })
      .then((v) => { if (!controller.signal.aborted) setSnapshot(v); })
      .catch(() => {})
      .finally(() => { if (!controller.signal.aborted) setSnapshotLoading(false); });
    return () => controller.abort();
  }, [connectionId]);

  const tableKey = (t: { schema: string; name: string }) => `${t.schema}.${t.name}`;
  const table = snapshot?.catalog.tables.find((t) => tableKey(t) === selectedTable);
  const tableSchema = table?.schema;
  const tableName = table?.name;
  const snapshotId = snapshot?.snapshot_id;

  useEffect(() => {
    setSuggestions(null);
    if (!tableSchema || !tableName || !snapshotId) return;
    const controller = new AbortController();
    const query = new URLSearchParams({ connection_id: connectionId, snapshot_id: snapshotId, schema_name: tableSchema, table_name: tableName });
    // Suggestions are a convenience; the editor works without them.
    api<PolicySuggestions>(`/policies/suggestions?${query}`, { signal: controller.signal })
      .then((v) => { if (!controller.signal.aborted) setSuggestions(v); })
      .catch(() => {});
    return () => controller.abort();
  }, [connectionId, snapshotId, tableSchema, tableName]);

  const byColumn = new Map((suggestions?.columns ?? []).map((item) => [item.column_name, item]));
  const suggested = (suggestions?.columns ?? []).filter((item) => item.action);

  function setRule(column: string, action: PolicyAction | '') {
    setAllRules((prev) => {
      const next = { ...prev[editing] };
      if (action) next[column] = action;
      else delete next[column];
      return { ...prev, [editing]: next };
    });
    // A key domain belongs to a pseudonym rule. Left behind, it would win over
    // the general reader's domain when those rules are copied in later.
    if (action !== 'PSEUDONYMIZE') {
      setAllDomains((prev) => {
        if (!(column in prev[editing])) return prev;
        const next = { ...prev[editing] };
        delete next[column];
        return { ...prev, [editing]: next };
      });
    }
  }

  // Suggestions are made for general readers. They fill only the columns still
  // without a rule, so a choice already made by hand is never overwritten.
  const pending = editing === 'reader' ? suggested.filter((item) => !rules[item.column_name]) : [];
  function applySuggestions() {
    setAllRules((prev) => ({ ...prev, reader: { ...Object.fromEntries(pending.map((item) => [item.column_name, item.action as PolicyAction])), ...prev.reader } }));
  }

  // Another audience can start from the general reader rules and be loosened from there.
  const copyable = editing === 'reader' ? [] : Object.keys(allRules.reader).filter((column) => !rules[column]);
  function copyReaderRules() {
    setAllRules((prev) => ({ ...prev, [editing]: { ...prev.reader, ...prev[editing] } }));
    setAllDomains((prev) => ({ ...prev, [editing]: { ...prev.reader, ...prev[editing] } }));
  }

  const counts = Object.fromEntries(AUDIENCES.map((item) => [item, Object.keys(allRules[item]).length])) as Record<Audience, number>;
  const ruleCount = AUDIENCES.reduce((total, item) => total + counts[item], 0);
  const overLimit = AUDIENCES.find((item) => counts[item] > MAX_RULES);

  async function create() {
    if (!table || !user) return;
    setLoading(true);
    busy.current = true;
    setError('');
    try {
      const created = await api<Policy>('/policies', {
        method: 'POST',
        csrfToken: user.csrf_token,
        body: JSON.stringify({
          connection_id: connectionId,
          schema_name: table.schema,
          table_name: table.name,
          snapshot_id: snapshot!.snapshot_id,
          rules: AUDIENCES.flatMap((audience) => Object.entries(allRules[audience]).map(([column_name, action]) => ({
            column_name,
            action,
            // General readers are the default, so their rules are sent as before.
            ...(audience === 'reader' ? {} : { audience }),
            ...(action === 'PSEUDONYMIZE' ? { pseudonym_domain: (allDomains[audience][column_name] ?? DEFAULT_PSEUDONYM_DOMAIN).trim() || DEFAULT_PSEUDONYM_DOMAIN } : {}),
            ...(audience === 'reader' && byColumn.get(column_name)?.classification_id ? { classification_id: byColumn.get(column_name)!.classification_id } : {}),
          }))),
        }),
      });
      onCreated(created.id);
    } catch (r) { setError(r instanceof ApiError ? r.message : 'Could not create policy.'); }
    finally { setLoading(false); busy.current = false; }
  }

  return <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Create policy">
    <div className="modal-panel wide">
      <div className="modal-header"><h2>New masking policy</h2><button className="text-button" onClick={onClose} disabled={loading}>Cancel</button></div>
      {snapshotLoading ? <div className="data-empty" role="status"><div className="loading-ring" /><p>Loading schema…</p></div>
        : !snapshot ? <div className="data-empty"><p>No schema snapshot found. Discover the schema first.</p></div>
        : <>
          <div className="form-field"><label htmlFor="policy-table">Table</label>
            <select id="policy-table" autoFocus value={selectedTable} onChange={(e) => { setSelectedTable(e.target.value); setAllRules(emptyAudienceMap()); setAllDomains(emptyAudienceMap()); setEditing('reader'); }}>
              <option value="">Choose a table</option>
              {snapshot.catalog.tables.map((t) => <option key={tableKey(t)} value={tableKey(t)}>{t.schema}.{t.name}</option>)}
            </select>
          </div>
          {table && <div className="rules-editor">
            <AudienceSwitch
              label="Rules for"
              audiences={AUDIENCES}
              value={editing}
              onChange={setEditing}
              detail={(item) => counts[item] ? `${counts[item]} ${counts[item] === 1 ? 'rule' : 'rules'}` : item === 'reader' ? 'all NULL' : 'no view'}
            />
            <div className="suggestion-bar">
              <p className="rules-editor-note">{editing === 'reader'
                ? 'Choose what the reader role sees in each column. A column with no rule is returned as NULL.'
                : <>{audienceLabel[editing]} read their own view through the <code>{audienceRole[editing]}</code> role. It is created only if you add at least one rule here, and it never changes what general readers see. A column with no rule is returned as NULL.</>}</p>
              {pending.length > 0 && <button type="button" className="button secondary" onClick={applySuggestions}><Sparkles size={14} /> Apply {pending.length} {pending.length === 1 ? 'suggestion' : 'suggestions'}</button>}
              {copyable.length > 0 && <button type="button" className="button secondary" onClick={copyReaderRules}><Copy size={14} /> Start from the general reader rules</button>}
            </div>
            {suggestions && !suggestions.scan_id && <p className="rules-editor-note">No completed scan for this connection yet, so there are no suggestions. Run a scan to get them.</p>}
            <div className="rules-editor-list">
              {table.columns.map((col) => {
                const suggestion = byColumn.get(col.name);
                const action = rules[col.name] ?? '';
                return <div className="rules-editor-row" key={col.name}>
                  <span className="rules-editor-col">{col.name} <small>{col.data_type}</small></span>
                  <span className="rules-editor-evidence">
                    {suggestions ? suggestionNote(suggestion) : ''}
                    {suggestion?.action && <small>Suggested: {actionLabel[suggestion.action]}</small>}
                  </span>
                  <span className="rules-editor-choice">
                    <select aria-label={`Action for ${col.name}`} value={action} onChange={(e) => setRule(col.name, e.target.value as PolicyAction | '')}>
                      <option value="">No rule (NULL)</option>
                      {ACTIONS.map((item) => <option key={item} value={item}>{actionLabel[item]}</option>)}
                    </select>
                    {action === 'PSEUDONYMIZE'
                      ? <input aria-label={`Pseudonym key domain for ${col.name}`} value={domains[col.name] ?? DEFAULT_PSEUDONYM_DOMAIN} maxLength={60} onChange={(e) => setAllDomains((prev) => ({ ...prev, [editing]: { ...prev[editing], [col.name]: e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, '') } }))} />
                      : <small>{action ? actionHint[action] : 'Returned as NULL'}</small>}
                  </span>
                </div>;
              })}
            </div>
          </div>}
          {error && <div className="error-box modal-error" role="alert">{error}</div>}
          <div className="modal-actions">
            <button className="button secondary" onClick={onClose} disabled={loading}>Cancel</button>
            {overLimit && <p className="rules-editor-note" role="alert">A policy can hold at most {MAX_RULES} rules for each audience. Remove {counts[overLimit] - MAX_RULES} of the rules for {audienceLabel[overLimit].toLowerCase()} to continue; columns without a rule are returned as NULL.</p>}
            <button className="button primary" disabled={!table || loading || ruleCount === 0 || Boolean(overLimit)} onClick={create}>{loading ? 'Creating…' : 'Create policy'}</button>
          </div>
        </>}
    </div>
  </div>;
}

interface ConnectionPage { items: Connection[]; total: number; page: number; page_size: number }
