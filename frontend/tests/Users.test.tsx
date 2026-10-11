import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../src/App';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const me = { id: 'user-admin', email: 'admin@example.test', role: 'ADMIN', is_active: true, created_at: '2026-10-01T00:00:00Z' };
const analyst = { id: 'user-analyst', email: 'analyst@example.test', role: 'ANALYST', is_active: true, created_at: '2026-10-02T00:00:00Z' };
const former = { id: 'user-former', email: 'former@example.test', role: 'AUDITOR', is_active: false, created_at: '2026-10-03T00:00:00Z' };

function server({ role = 'ADMIN', createStatus = 201 } = {}) {
  let accounts = [me, analyst, former];
  const fetchMock = vi.fn(async (url: RequestInfo | URL, options?: RequestInit) => {
    const path = String(url);
    const method = options?.method ?? 'GET';
    if (path.endsWith('/auth/me')) return json({ id: me.id, email: me.email, role, csrf_token: 'csrf-users' });
    if (path.includes('/users?')) return json({ items: accounts, total: accounts.length, page: 1, page_size: 50 });
    if (path.endsWith('/users') && method === 'POST') {
      if (createStatus !== 201) return json({ detail: 'EMAIL_IN_USE' }, createStatus);
      const sent = JSON.parse(String(options?.body));
      const created = { id: 'user-new', email: sent.email, role: sent.role, is_active: true, created_at: '2026-10-11T00:00:00Z' };
      accounts = [...accounts, created];
      return json(created, 201);
    }
    const match = path.match(/\/users\/([^/?]+)$/);
    if (match && method === 'PATCH') {
      const sent = JSON.parse(String(options?.body));
      const current = accounts.find((item) => item.id === match[1])!;
      const saved = { ...current, ...(sent.role ? { role: sent.role } : {}), ...(sent.is_active === undefined ? {} : { is_active: sent.is_active }) };
      accounts = accounts.map((item) => (item.id === saved.id ? saved : item));
      return json(saved);
    }
    // Other pages a test may pass through.
    if (path.includes('/dashboard/')) return json({ detail: 'not-used' }, 500);
    throw new Error(`Unexpected test endpoint ${method} ${path}`);
  });
  vi.stubGlobal('fetch', fetchMock);
  window.history.replaceState({}, '', '/users');
  return fetchMock;
}

const sent = (fetchMock: ReturnType<typeof server>, method: string, suffix: string) =>
  fetchMock.mock.calls.filter(([path, options]) => String(path).endsWith(suffix) && (options?.method ?? 'GET') === method);

describe('account management', () => {
  it('lists accounts and protects the administrator from removing their own access', async () => {
    server();
    render(<App />);
    const table = await screen.findByRole('table');
    const own = within(table).getByRole('row', { name: /admin@example\.test/ });
    expect(within(own).getByText('You')).toBeInTheDocument();
    expect(within(own).getByText('Administrator')).toBeInTheDocument();
    expect(within(own).queryByRole('button', { name: /Change role/ })).not.toBeInTheDocument();
    expect(within(own).queryByRole('button', { name: /Deactivate/ })).not.toBeInTheDocument();
    // Changing their own password is allowed.
    expect(within(own).getByRole('button', { name: 'Reset password for admin@example.test' })).toBeEnabled();

    const other = within(table).getByRole('row', { name: /analyst@example\.test/ });
    expect(within(other).getByText('Active')).toBeInTheDocument();
    expect(within(other).getByRole('button', { name: 'Change role of analyst@example.test' })).toBeEnabled();
    // No role is changed by moving through a list in the table.
    expect(within(table).queryByRole('combobox')).not.toBeInTheDocument();
    const inactive = within(table).getByRole('row', { name: /former@example\.test/ });
    expect(within(inactive).getByText('Deactivated')).toBeInTheDocument();
    expect(within(inactive).getByRole('button', { name: 'Reactivate former@example.test' })).toBeInTheDocument();
    // The role guide says what the server enforces.
    expect(screen.getByText(/Cannot approve or deploy/)).toBeInTheDocument();
  });

  it('adds an account with its role and never repeats the password', async () => {
    const fetchMock = server();
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByRole('button', { name: 'Add user' }));
    const dialog = screen.getByRole('dialog', { name: 'Add user' });
    await visitor.type(within(dialog).getByLabelText('Email address'), 'new.person@example.test');
    await visitor.selectOptions(within(dialog).getByLabelText('Role'), 'AUDITOR');
    expect(within(dialog).getByText(/Read-only/)).toBeInTheDocument();

    // Too short: explained before anything is sent.
    await visitor.type(within(dialog).getByLabelText('Password'), 'short');
    expect(within(dialog).getByText('7 more characters needed.')).toBeInTheDocument();
    await visitor.type(within(dialog).getByLabelText('Password'), '-but-now-long-enough');
    await visitor.click(within(dialog).getByRole('button', { name: 'Create account' }));

    const notice = await screen.findByRole('status');
    expect(notice).toHaveTextContent('new.person@example.test was added as auditor');
    expect(document.body).not.toHaveTextContent('short-but-now-long-enough');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    const [[, options]] = sent(fetchMock, 'POST', '/users');
    expect(JSON.parse(String(options?.body))).toEqual({ email: 'new.person@example.test', role: 'AUDITOR', password: 'short-but-now-long-enough' });
    expect(new Headers(options?.headers).get('X-CSRF-Token')).toBe('csrf-users');
    expect(await screen.findByRole('row', { name: /new\.person@example\.test/ })).toBeInTheDocument();
  });

  it('explains a refused create inside the dialog and keeps what was typed', async () => {
    server({ createStatus: 409 });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByRole('button', { name: 'Add user' }));
    const dialog = screen.getByRole('dialog', { name: 'Add user' });
    await visitor.type(within(dialog).getByLabelText('Email address'), 'analyst@example.test');
    await visitor.type(within(dialog).getByLabelText('Password'), 'a-long-enough-password');
    await visitor.click(within(dialog).getByRole('button', { name: 'Create account' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('An account with this email address already exists.');
    expect(within(dialog).getByLabelText('Email address')).toHaveValue('analyst@example.test');
    expect(document.body).not.toHaveTextContent('EMAIL_IN_USE');
  });

  it('changes a role, deactivates and reactivates with one request each', async () => {
    const fetchMock = server();
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByRole('button', { name: 'Change role of analyst@example.test' }));
    const dialog = screen.getByRole('dialog', { name: 'Change role' });
    // Nothing is sent until the role differs and Save is chosen.
    expect(within(dialog).getByLabelText('Role')).toHaveValue('ANALYST');
    expect(within(dialog).getByRole('button', { name: 'Save role' })).toBeDisabled();
    await visitor.selectOptions(within(dialog).getByLabelText('Role'), 'ADMIN');
    expect(within(dialog).getByText(/managing accounts/)).toBeInTheDocument();
    await visitor.selectOptions(within(dialog).getByLabelText('Role'), 'AUDITOR');
    expect(sent(fetchMock, 'PATCH', '/users/user-analyst')).toHaveLength(0);
    await visitor.click(within(dialog).getByRole('button', { name: 'Save role' }));
    expect(await screen.findByRole('status')).toHaveTextContent('analyst@example.test is now auditor.');
    expect(within(screen.getByRole('row', { name: /analyst@example\.test/ })).getByText('Auditor')).toBeInTheDocument();
    await visitor.click(screen.getByRole('button', { name: 'Deactivate analyst@example.test' }));
    expect(await screen.findByRole('status')).toHaveTextContent('was deactivated and signed out');
    await visitor.click(await screen.findByRole('button', { name: 'Reactivate analyst@example.test' }));
    expect(await screen.findByRole('status')).toHaveTextContent('can sign in again');
    const bodies = sent(fetchMock, 'PATCH', '/users/user-analyst').map(([, options]) => JSON.parse(String(options?.body)));
    expect(bodies).toEqual([{ role: 'AUDITOR' }, { is_active: false }, { is_active: true }]);
  });

  it('sets a new password for someone without showing it afterwards', async () => {
    const fetchMock = server();
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    const row = await screen.findByRole('row', { name: /analyst@example\.test/ });
    await visitor.click(within(row).getByRole('button', { name: 'Reset password for analyst@example.test' }));
    const dialog = screen.getByRole('dialog', { name: 'Reset password' });
    // Only a password is asked for: the account is already chosen.
    expect(within(dialog).queryByLabelText('Email address')).not.toBeInTheDocument();
    expect(within(dialog).queryByLabelText('Role')).not.toBeInTheDocument();
    const field = within(dialog).getByLabelText('New password');
    expect(field).toHaveAttribute('type', 'password');
    await visitor.type(field, 'replacement-password-1');
    await visitor.click(within(dialog).getByRole('button', { name: 'Show password' }));
    expect(field).toHaveAttribute('type', 'text');
    await visitor.click(within(dialog).getByRole('button', { name: 'Set new password' }));
    expect(await screen.findByRole('status')).toHaveTextContent('analyst@example.test has a new password and was signed out everywhere.');
    expect(document.body).not.toHaveTextContent('replacement-password-1');
    const [[, options]] = sent(fetchMock, 'PATCH', '/users/user-analyst');
    expect(JSON.parse(String(options?.body))).toEqual({ password: 'replacement-password-1' });
  });

  it('clears an earlier refusal when a new action starts', async () => {
    const fetchMock = server();
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    // The next change is refused, as it would be for the last administrator.
    await screen.findByRole('table');
    fetchMock.mockImplementationOnce(async () => json({ detail: 'LAST_ADMIN' }, 409));
    await visitor.click(screen.getByRole('button', { name: 'Deactivate analyst@example.test' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('was not made');
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    // The account is shown as it still is.
    expect(screen.getByRole('button', { name: 'Deactivate analyst@example.test' })).toBeEnabled();
    await visitor.click(screen.getByRole('button', { name: 'Reset password for analyst@example.test' }));
    expect(screen.queryByText(/was not made/)).not.toBeInTheDocument();
  });

  it.each(['ANALYST', 'AUDITOR'])('keeps accounts out of reach of an %s', async (role) => {
    const fetchMock = server({ role });
    render(<App />);
    expect(await screen.findByText('Accounts are managed by administrators')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Users' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add user' })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([path]) => String(path).includes('/users'))).toBe(false);
  });

  it('offers the page to administrators in the navigation', async () => {
    server();
    render(<App />);
    expect(await screen.findByRole('link', { name: 'Users' })).toHaveAttribute('href', '/users');
  });
});
