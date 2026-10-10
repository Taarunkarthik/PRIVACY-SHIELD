import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { KeyRound, Plus, RefreshCw, Save, Settings2, ShieldCheck, Trash2 } from 'lucide-react';
import { ApiError } from '../api/client';
import { useAuth } from '../api/auth';
import {
  getSettings,
  updateSettings,
  patternCategories,
  patternCategoryLabel,
  PATTERN_LIMIT,
  PATTERN_NAME_LIMIT,
  PATTERN_REGEX_LIMIT,
  WORKSPACE_NAME_LIMIT,
  MIN_RETENTION_DAYS,
  MAX_RETENTION_DAYS,
} from '../api/settings';
import type { DetectionPattern, WorkspaceSettings } from '../api/settings';

function newPatternId() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  return `pattern-${Date.now().toString(36)}-${Math.random().toString(16).slice(2)}`;
}

// Server exceptions are never rendered; map statuses to bounded, workspace-safe copy.
function settingsError(reason: unknown, kind: 'workspace' | 'pattern') {
  if (reason instanceof ApiError) {
    if (reason.status === 403) return 'Only administrators can change workspace settings.';
    if (reason.status === 422) {
      return kind === 'pattern'
        ? 'Check the pattern name, category, and regular expression, then try again.'
        : 'Check the workspace name and retention period, then try again.';
    }
    return reason.message;
  }
  return 'The change could not be saved. Please try again.';
}

export function Settings() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'ADMIN';
  const [settings, setSettings] = useState<WorkspaceSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [revision, setRevision] = useState(0);

  const [workspaceName, setWorkspaceName] = useState('');
  const [retentionDays, setRetentionDays] = useState(String(MIN_RETENTION_DAYS));
  const [savingWorkspace, setSavingWorkspace] = useState(false);
  const [workspaceError, setWorkspaceError] = useState('');
  const [workspaceSaved, setWorkspaceSaved] = useState(false);

  const [patternName, setPatternName] = useState('');
  const [patternCategory, setPatternCategory] = useState<string>(patternCategories[0]);
  const [patternRegex, setPatternRegex] = useState('');
  const [patternEnabled, setPatternEnabled] = useState(true);
  const [patternError, setPatternError] = useState('');
  const [patternBusy, setPatternBusy] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setLoadError('');
    getSettings(controller.signal)
      .then((value) => {
        if (controller.signal.aborted) return;
        setSettings(value);
        setWorkspaceName(value.workspace_name);
        setRetentionDays(String(value.retention_days));
      })
      .catch((reason: unknown) => {
        if (controller.signal.aborted) return;
        setLoadError(reason instanceof ApiError ? reason.message : 'Could not load workspace settings.');
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [revision]);

  function applySettings(value: WorkspaceSettings) {
    setSettings(value);
    setWorkspaceName(value.workspace_name);
    setRetentionDays(String(value.retention_days));
  }

  async function saveWorkspace(event: FormEvent) {
    event.preventDefault();
    if (!user) return;
    const name = workspaceName.trim();
    const days = Number(retentionDays);
    if (!name) { setWorkspaceError('Enter a workspace name.'); setWorkspaceSaved(false); return; }
    if (name.length > WORKSPACE_NAME_LIMIT) { setWorkspaceError(`Workspace names are limited to ${WORKSPACE_NAME_LIMIT} characters.`); setWorkspaceSaved(false); return; }
    if (!Number.isInteger(days) || days < MIN_RETENTION_DAYS || days > MAX_RETENTION_DAYS) {
      setWorkspaceError(`Retention must be a whole number between ${MIN_RETENTION_DAYS} and ${MAX_RETENTION_DAYS} days.`);
      setWorkspaceSaved(false);
      return;
    }
    setSavingWorkspace(true);
    setWorkspaceError('');
    setWorkspaceSaved(false);
    try {
      applySettings(await updateSettings({ workspace_name: name, retention_days: days }, user.csrf_token));
      setWorkspaceSaved(true);
    } catch (reason) {
      setWorkspaceError(settingsError(reason, 'workspace'));
    } finally {
      setSavingWorkspace(false);
    }
  }

  async function persistPatterns(next: DetectionPattern[], busyKey: string) {
    if (!user) return false;
    setPatternBusy(busyKey);
    setPatternError('');
    try {
      const updated = await updateSettings({ custom_patterns: next }, user.csrf_token);
      setSettings(updated);
      return true;
    } catch (reason) {
      setPatternError(settingsError(reason, 'pattern'));
      return false;
    } finally {
      setPatternBusy('');
    }
  }

  async function addPattern(event: FormEvent) {
    event.preventDefault();
    const name = patternName.trim();
    const regex = patternRegex.trim();
    if (!name) { setPatternError('Enter a pattern name.'); return; }
    if (name.length > PATTERN_NAME_LIMIT) { setPatternError(`Pattern names are limited to ${PATTERN_NAME_LIMIT} characters.`); return; }
    if (!regex) { setPatternError('Enter a regular expression.'); return; }
    if (regex.length > PATTERN_REGEX_LIMIT) { setPatternError(`Regular expressions are limited to ${PATTERN_REGEX_LIMIT} characters.`); return; }
    try { new RegExp(regex); }
    catch { setPatternError('Enter a valid regular expression.'); return; }
    const patterns = settings?.custom_patterns ?? [];
    if (patterns.length >= PATTERN_LIMIT) { setPatternError(`You can keep up to ${PATTERN_LIMIT} custom patterns.`); return; }
    const created: DetectionPattern = { id: newPatternId(), name, category: patternCategory, regex, enabled: patternEnabled };
    if (await persistPatterns([...patterns, created], 'add')) {
      setPatternName('');
      setPatternCategory(patternCategories[0]);
      setPatternRegex('');
      setPatternEnabled(true);
    }
  }

  async function togglePattern(pattern: DetectionPattern) {
    const patterns = settings?.custom_patterns ?? [];
    await persistPatterns(patterns.map((item) => (item.id === pattern.id ? { ...item, enabled: !item.enabled } : item)), pattern.id);
  }

  async function removePattern(pattern: DetectionPattern) {
    const patterns = settings?.custom_patterns ?? [];
    await persistPatterns(patterns.filter((item) => item.id !== pattern.id), pattern.id);
  }

  const patterns = settings?.custom_patterns ?? [];

  return <div className="page-content settings-page">
    <div className="page-heading">
      <div><p className="eyebrow">YOUR WORKSPACE</p><h1>Settings<span className="heading-dot">.</span></h1><p className="page-description">Manage workspace identity, data retention, and custom detection patterns.</p></div>
      <button className="button secondary" onClick={() => setRevision((value) => value + 1)} disabled={loading}><RefreshCw size={15} /> Refresh</button>
    </div>

    {loadError && <div className="error-box" role="alert">{loadError}</div>}

    {loading && !settings && <section className="panel data-empty" role="status"><div className="loading-ring" /><p>Loading workspace settings…</p></section>}

    {!loading && !settings && <section className="panel data-empty">
      <Settings2 size={34} strokeWidth={1.3} />
      <h2>Workspace settings unavailable</h2>
      <p>The settings could not be loaded. Try again when the workspace is reachable.</p>
      <button className="button secondary" onClick={() => setRevision((value) => value + 1)}><RefreshCw size={14} /> Try again</button>
    </section>}

    {settings && <>
      <section className="panel settings-panel" aria-label="Workspace settings">
        <div className="panel-heading"><div><h2>Workspace</h2><p>Identity and data retention for this workspace.</p></div><Settings2 size={19} className="muted" /></div>
        {isAdmin ? <form className="settings-form" onSubmit={saveWorkspace} noValidate>
          <div className="form-grid">
            <div className="form-field"><label htmlFor="workspace-name">Workspace name</label><input id="workspace-name" value={workspaceName} maxLength={WORKSPACE_NAME_LIMIT} onChange={(event) => { setWorkspaceName(event.target.value); setWorkspaceSaved(false); }} /></div>
            <div className="form-field"><label htmlFor="retention-days">Retention period <span>days</span></label><input id="retention-days" type="number" min={MIN_RETENTION_DAYS} max={MAX_RETENTION_DAYS} value={retentionDays} onChange={(event) => { setRetentionDays(event.target.value); setWorkspaceSaved(false); }} /></div>
          </div>
          {workspaceError && <p className="form-note error" role="alert">{workspaceError}</p>}
          {workspaceSaved && <p className="form-note success" role="status">Workspace settings saved.</p>}
          <div className="form-actions"><p><ShieldCheck size={14} /> Changes are recorded in the audit log.</p><div><button className="button primary" type="submit" disabled={savingWorkspace}><Save size={15} />{savingWorkspace ? 'Saving…' : 'Save changes'}</button></div></div>
        </form>
        : <dl className="settings-readonly">
          <div><dt>Workspace name</dt><dd>{settings.workspace_name}</dd></div>
          <div><dt>Retention period</dt><dd>{settings.retention_days} days</dd></div>
        </dl>}
      </section>

      <section className="panel settings-panel" aria-label="Custom detection patterns">
        <div className="panel-heading"><div><h2>Custom detection patterns <span className="count-badge">{patterns.length}</span></h2><p>Bounded regular expressions that supplement built-in detection.</p></div><KeyRound size={19} className="muted" /></div>
        {!isAdmin && <p className="role-note">Only administrators can change workspace settings. These patterns apply to detection across the workspace.</p>}
        {patterns.length === 0
          ? <div className="data-empty"><KeyRound size={34} strokeWidth={1.3} /><h3>No custom patterns</h3><p>{isAdmin ? 'Add a pattern to flag organisation-specific sensitive data.' : 'Custom patterns added by an administrator will appear here.'}</p></div>
          : <div className="pattern-list">{patterns.map((pattern) => (
            <div className="pattern-row" key={pattern.id}>
              <span className="pattern-icon"><KeyRound size={16} /></span>
              <div className="pattern-info">
                <strong>{pattern.name}</strong>
                <code>{pattern.regex}</code>
                <span className="pattern-meta">{patternCategoryLabel(pattern.category)} · {pattern.enabled ? 'Enabled' : 'Disabled'}</span>
              </div>
              <span className={`pill pattern-state ${pattern.enabled ? 'state-enabled' : 'state-disabled'}`}>{pattern.enabled ? 'Enabled' : 'Disabled'}</span>
              {isAdmin && <div className="pattern-actions">
                <button className="button secondary small" type="button" disabled={patternBusy === pattern.id} onClick={() => togglePattern(pattern)}>{pattern.enabled ? 'Disable' : 'Enable'}</button>
                <button className="button danger small" type="button" disabled={patternBusy === pattern.id} onClick={() => removePattern(pattern)}><Trash2 size={13} /> Delete</button>
              </div>}
            </div>
          ))}</div>}

        {isAdmin && <form className="pattern-form" onSubmit={addPattern}>
          <div className="form-grid">
            <div className="form-field"><label htmlFor="pattern-name">Pattern name</label><input id="pattern-name" value={patternName} maxLength={PATTERN_NAME_LIMIT} onChange={(event) => setPatternName(event.target.value)} /></div>
            <div className="form-field"><label htmlFor="pattern-category">Category</label><select id="pattern-category" value={patternCategory} onChange={(event) => setPatternCategory(event.target.value)}>{patternCategories.map((value) => <option key={value} value={value}>{patternCategoryLabel(value)}</option>)}</select></div>
            <div className="form-field span-two"><label htmlFor="pattern-regex">Regular expression</label><input id="pattern-regex" value={patternRegex} maxLength={PATTERN_REGEX_LIMIT} placeholder="\\b[A-Z]{5}[0-9]{4}[A-Z]\\b" onChange={(event) => setPatternRegex(event.target.value)} /></div>
          </div>
          <label className="checkbox-field"><input type="checkbox" checked={patternEnabled} onChange={(event) => setPatternEnabled(event.target.checked)} /><span>Enable this pattern<small>Disabled patterns are stored but not applied during detection.</small></span></label>
          {patternError && <p className="form-note error" role="alert">{patternError}</p>}
          <div className="form-actions"><p><KeyRound size={14} /> Try the expression on synthetic data before relying on it.</p><div><button className="button primary" type="submit" disabled={patternBusy === 'add' || patterns.length >= PATTERN_LIMIT}><Plus size={15} />{patternBusy === 'add' ? 'Adding…' : 'Add pattern'}</button></div></div>
        </form>}
      </section>

      <section className="panel account-summary">
        <div><p className="eyebrow">SIGNED-IN ACCOUNT</p><h2>{user?.email}</h2></div><span className="pill">{user?.role}</span>
      </section>
    </>}
  </div>;
}
