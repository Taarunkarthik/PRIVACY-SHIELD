import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { Eye, EyeOff, KeyRound, RefreshCw, UserCheck, UserCog, UserPlus, UserX, Users as UsersIcon } from 'lucide-react';
import { ApiError } from '../api/client';
import { useAuth } from '../api/auth';
import { changeAccount, createAccount, listAccounts, MAX_PASSWORD, MIN_PASSWORD, PAGE_SIZE, ROLES, roleLabel, roleSummary } from '../api/users';
import type { Account, AccountChange, AccountPage, Role } from '../api/users';

// The server never says why in words that are safe to show, so each refusal is explained here.
function createError(reason: unknown): string {
  if (!(reason instanceof ApiError)) return 'The account could not be created.';
  if (reason.status === 409) return 'An account with this email address already exists.';
  if (reason.status === 422) return `Check the email address, and use a password of ${MIN_PASSWORD} to ${MAX_PASSWORD} characters.`;
  return reason.message;
}

function changeError(reason: unknown): string {
  if (!(reason instanceof ApiError)) return 'The change could not be saved.';
  if (reason.status === 409) return 'That change would remove your own access or the last administrator, so it was not made.';
  if (reason.status === 404) return 'That account no longer exists. Refresh the list.';
  if (reason.status === 422) return `Use a password of ${MIN_PASSWORD} to ${MAX_PASSWORD} characters.`;
  return reason.message;
}

export function Users() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'ADMIN';
  const [accounts, setAccounts] = useState<AccountPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  // Accounts with a change on its way; more than one can be in flight at once.
  const [saving, setSaving] = useState<ReadonlySet<string>>(new Set());
  const [adding, setAdding] = useState(false);
  const [resetting, setResetting] = useState<Account | null>(null);
  const [changingRole, setChangingRole] = useState<Account | null>(null);

  // Opening a dialog starts a new action: earlier messages no longer describe the page.
  function open(action: () => void) {
    setError('');
    setNotice('');
    action();
  }

  function replace(saved: Account) {
    setAccounts((current) => current && { ...current, items: current.items.map((item) => (item.id === saved.id ? saved : item)) });
  }

  useEffect(() => {
    if (!isAdmin) { setLoading(false); return; }
    const controller = new AbortController();
    setLoading(true);
    listAccounts(page, controller.signal)
      .then((value) => { if (!controller.signal.aborted) { setAccounts(value); setError(''); } })
      .catch((reason: unknown) => { if (!controller.signal.aborted) setError(reason instanceof ApiError ? reason.message : 'Accounts could not be loaded.'); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [isAdmin, page, revision]);

  async function change(account: Account, update: AccountChange, done: string) {
    if (!user) return;
    setSaving((current) => new Set(current).add(account.id)); setError(''); setNotice('');
    try {
      replace(await changeAccount(account.id, update, user.csrf_token));
      setNotice(done);
    } catch (reason) { setError(changeError(reason)); }
    finally { setSaving((current) => { const next = new Set(current); next.delete(account.id); return next; }); }
  }

  if (!isAdmin) {
    return <div className="page-content"><section className="panel data-empty"><UsersIcon size={34} strokeWidth={1.3} /><h1>Accounts are managed by administrators</h1><p>Ask an administrator if you need a different role or a new password.</p></section></div>;
  }

  return <div className="page-content users-page">
    <div className="page-heading">
      <div><h1>Users<span className="heading-dot">.</span></h1><p className="page-description">The people who can sign in to this workspace, and what each may do.</p></div>
      <div className="heading-actions">
        <button className="button primary" onClick={() => open(() => setAdding(true))}><UserPlus size={15} /> Add user</button>
        <button className="button secondary" onClick={() => setRevision((value) => value + 1)} disabled={loading}><RefreshCw size={15} /> Refresh</button>
      </div>
    </div>

    {error && <div className="error-box" role="alert">{error}</div>}
    {notice && <div className="success-box" role="status">{notice}</div>}

    <section className="panel" aria-label="Accounts">
      <div className="panel-heading"><div><h2>Accounts <span className="count-badge">{accounts?.total ?? '—'}</span></h2><p>A change of role applies from the person's next request. Deactivating an account signs it out.</p></div></div>
      {loading && !accounts ? <div className="data-empty" role="status"><div className="loading-ring" /><p>Loading accounts…</p></div>
        : <div className="table-scroll">
          <table className="columns-table accounts-table">
            <thead><tr><th scope="col">Email</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Added</th><th scope="col" aria-label="Actions" /></tr></thead>
            <tbody>{accounts?.items.map((account) => {
              const own = account.id === user?.id;
              const busy = saving.has(account.id);
              return <tr key={account.id} className={account.is_active ? undefined : 'account-inactive'}>
                <th scope="row">{account.email}{own && <span className="pill small you-pill">You</span>}</th>
                <td>{roleLabel[account.role]}</td>
                <td><span className={`pill ${account.is_active ? 'status-deployed' : 'status-draft'}`}>{account.is_active ? 'Active' : 'Deactivated'}</span></td>
                <td>{new Date(account.created_at).toLocaleDateString()}</td>
                <td>
                  <div className="account-actions">
                    {/* A role is changed in a dialog with an explicit Save, never by moving through a list. */}
                    {!own && <button className="button secondary" disabled={busy} aria-label={`Change role of ${account.email}`} onClick={() => open(() => setChangingRole(account))}><UserCog size={14} /> Change role</button>}
                    <button className="button secondary" disabled={busy} aria-label={`Reset password for ${account.email}`} onClick={() => open(() => setResetting(account))}><KeyRound size={14} /> Reset password</button>
                    {!own && (account.is_active
                      ? <button className="button danger" disabled={busy} aria-label={`Deactivate ${account.email}`} onClick={() => void change(account, { is_active: false }, `${account.email} was deactivated and signed out.`)}><UserX size={14} /> Deactivate</button>
                      : <button className="button secondary" disabled={busy} aria-label={`Reactivate ${account.email}`} onClick={() => void change(account, { is_active: true }, `${account.email} can sign in again.`)}><UserCheck size={14} /> Reactivate</button>)}
                  </div>
                </td>
              </tr>;
            })}</tbody>
          </table>
        </div>}
      {accounts && accounts.total > PAGE_SIZE && <div className="pagination"><span>Page {page} of {Math.ceil(accounts.total / PAGE_SIZE)}</span><div><button className="button secondary" disabled={page === 1 || loading} onClick={() => setPage(page - 1)}>Previous</button><button className="button secondary" disabled={page * PAGE_SIZE >= accounts.total || loading} onClick={() => setPage(page + 1)}>Next</button></div></div>}
    </section>

    <section className="panel" aria-label="Roles">
      <div className="panel-heading"><div><h2>What each role can do</h2><p>The server checks the role on every request; hiding a button is not what enforces it.</p></div></div>
      <dl className="role-guide">{ROLES.map((role) => <div key={role}><dt>{roleLabel[role]}</dt><dd>{roleSummary[role]}</dd></div>)}</dl>
    </section>

    {adding && <AccountDialog
      mode="add"
      title="Add user"
      label="Add user"
      submitLabel="Create account"
      onClose={() => setAdding(false)}
      explain={createError}
      onSubmit={async ({ email, role, password }) => {
        const created = await createAccount({ email, role, password }, user!.csrf_token);
        setAdding(false);
        setNotice(`${created.email} was added as ${roleLabel[created.role].toLowerCase()}. Give them the password privately; it is not shown again.`);
        setRevision((value) => value + 1);
      }}
    />}

    {changingRole && <AccountDialog
      mode="role"
      title={`Change role of ${changingRole.email}`}
      label="Change role"
      submitLabel="Save role"
      account={changingRole}
      onClose={() => setChangingRole(null)}
      explain={changeError}
      onSubmit={async ({ role }) => {
        const saved = await changeAccount(changingRole.id, { role }, user!.csrf_token);
        replace(saved);
        setChangingRole(null);
        setNotice(`${saved.email} is now ${roleLabel[saved.role].toLowerCase()}.`);
      }}
    />}

    {resetting && <AccountDialog
      mode="password"
      title={`Reset password for ${resetting.email}`}
      label="Reset password"
      submitLabel="Set new password"
      account={resetting}
      onClose={() => setResetting(null)}
      explain={changeError}
      onSubmit={async ({ password }) => {
        await changeAccount(resetting.id, { password }, user!.csrf_token);
        const own = resetting.id === user?.id;
        setResetting(null);
        setNotice(own ? 'Your password was changed. Your other sessions were signed out.' : `${resetting.email} has a new password and was signed out everywhere.`);
      }}
    />}
  </div>;
}

type AccountForm = { email: string; role: Role; password: string };

/** One dialog for the three things that need a form: a new account, a new role, a new password. */
function AccountDialog({ mode, title, label, submitLabel, account, onClose, onSubmit, explain }: {
  mode: 'add' | 'role' | 'password'; title: string; label: string; submitLabel: string; account?: Account;
  onClose: () => void; onSubmit: (form: AccountForm) => Promise<void>; explain: (reason: unknown) => string;
}) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<Role>(account?.role ?? 'ANALYST');
  const [password, setPassword] = useState('');
  const [visible, setVisible] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const asksPassword = mode !== 'role';
  const asksRole = mode !== 'password';

  // Escape closes the dialog unless a request is on its way or a list is open.
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

  const tooShort = password.length > 0 && password.length < MIN_PASSWORD;
  const unchanged = mode === 'role' && role === account?.role;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (asksPassword && password.length < MIN_PASSWORD) { setError(`Use a password of ${MIN_PASSWORD} to ${MAX_PASSWORD} characters.`); return; }
    setSaving(true); busy.current = true; setError('');
    try { await onSubmit({ email: email.trim(), role, password }); }
    catch (reason) { setError(explain(reason)); }
    finally { setSaving(false); busy.current = false; }
  }

  return <div className="modal-overlay" role="dialog" aria-modal="true" aria-label={label}>
    <form className="modal-panel account-form" onSubmit={submit}>
      <div className="modal-header"><h2>{title}</h2><button type="button" className="text-button" onClick={onClose} disabled={saving}>Cancel</button></div>
      {mode === 'add' && <div className="form-field"><label htmlFor="account-email">Email address</label>
        <input id="account-email" type="email" autoFocus required maxLength={254} autoComplete="off" value={email} onChange={(event) => setEmail(event.target.value)} disabled={saving} placeholder="person@organization.com" />
      </div>}
      {asksRole && <div className="form-field"><label htmlFor="account-role">Role</label>
        <select id="account-role" autoFocus={mode === 'role'} value={role} onChange={(event) => setRole(event.target.value as Role)} disabled={saving} aria-describedby="account-role-hint">
          {ROLES.map((item) => <option key={item} value={item}>{roleLabel[item]}</option>)}
        </select>
        <small id="account-role-hint" className="field-hint">{roleSummary[role]}</small>
      </div>}
      {asksPassword && <div className="form-field"><label htmlFor="account-password">{mode === 'password' ? 'New password' : 'Password'}</label>
        <div className="password-field account-password">
          <input id="account-password" type={visible ? 'text' : 'password'} autoFocus={mode === 'password'} required minLength={MIN_PASSWORD} maxLength={MAX_PASSWORD} autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} disabled={saving} aria-describedby="account-password-hint" />
          <button type="button" className="password-toggle" onClick={() => setVisible(!visible)} aria-label={visible ? 'Hide password' : 'Show password'} aria-pressed={visible} disabled={saving}>{visible ? <EyeOff size={18} /> : <Eye size={18} />}</button>
        </div>
        <small id="account-password-hint" className="field-hint">{tooShort ? `${MIN_PASSWORD - password.length} more ${MIN_PASSWORD - password.length === 1 ? 'character' : 'characters'} needed.` : `${MIN_PASSWORD} to ${MAX_PASSWORD} characters. Pass it on privately: it cannot be shown again.`}</small>
      </div>}
      {error && <div className="error-box modal-error" role="alert">{error}</div>}
      <div className="modal-actions">
        <button type="button" className="button secondary" onClick={onClose} disabled={saving}>Cancel</button>
        <button type="submit" className="button primary" disabled={saving || unchanged}>{saving ? 'Saving…' : submitLabel}</button>
      </div>
    </form>
  </div>;
}
