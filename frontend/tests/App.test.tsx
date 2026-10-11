import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../src/App';
import { SESSION_EXPIRED } from '../src/api/client';

const user = { id: 'test-user', email: 'admin@example.test', role: 'ADMIN', csrf_token: 'test-only-csrf-value' };
const totals = { databases: 0, tables: 0, sensitive_columns: 0, pending_approvals: 0, deployed_policies: 0, scan_jobs: 0 };
const insights = {
  categories: [], risks: [], risks_from_ai: 0, policy_status: [],
  coverage: { sensitive_columns: 0, protected_columns: 0 }, recent_activity: [],
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

function mockApi(initiallySignedIn = false) {
  let signedIn = initiallySignedIn;
  const fetchMock = vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
    const path = String(input);
    if (path === '/api/v1/auth/me') return signedIn ? json(user) : json({ detail: 'Unauthorized' }, 401);
    if (path === '/api/v1/auth/login') { signedIn = true; return json(user); }
    if (path === '/api/v1/auth/logout') {
      if (new Headers(options?.headers).get('X-CSRF-Token') !== user.csrf_token) return json({}, 403);
      signedIn = false;
      return new Response(null, { status: 204 });
    }
    if (path === '/api/v1/dashboard/summary') return json(totals);
    if (path === '/api/v1/dashboard/insights') return json(insights);
    if (path.startsWith('/api/v1/policies')) return json({ items: [], total: 0, page: 1, page_size: 20 });
    if (path.startsWith('/api/v1/connections')) return json({ items: [], total: 0, page: 1, page_size: 100 });
    if (path.startsWith('/api/v1/audit-events')) return json({ items: [], total: 0, page: 1, page_size: 50 });
    if (path.startsWith('/api/v1/settings')) return json({ workspace_name: 'Privacy workspace', retention_days: 30, custom_patterns: [] });
    if (path.startsWith('/api/v1/deployments')) return json({ items: [], total: 0, page: 1, page_size: 20 });
    throw new Error(`Unexpected test endpoint: ${path}`);
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

describe('workspace sessions', () => {
  it('signs in using the API and keeps credentials and CSRF out of browser storage', async () => {
    const fetchMock = mockApi();
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.type(await screen.findByLabelText('Email address'), 'ADMIN@example.test');
    await visitor.type(screen.getByLabelText('Password'), 'not-a-real-password');
    await visitor.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('heading', { name: 'Workspace overview.' })).toBeInTheDocument();
    expect(await screen.findByText('Your data landscape starts here')).toBeInTheDocument();
    const loginCall = fetchMock.mock.calls.find(([path]) => path === '/api/v1/auth/login');
    expect(JSON.parse(String(loginCall?.[1]?.body))).toEqual({ email: user.email, password: 'not-a-real-password' });
    expect(loginCall?.[1]?.credentials).toBe('same-origin');
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(screen.queryByLabelText('Password')).not.toBeInTheDocument();
  });

  it('clears a rejected password and never exposes backend exception details', async () => {
    const fetchMock = mockApi();
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.type(await screen.findByLabelText('Email address'), user.email);
    await visitor.type(screen.getByLabelText('Password'), 'incorrect-password');
    fetchMock.mockResolvedValueOnce(json({ detail: 'secret-postgres-connection-string' }, 401));
    await visitor.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The email or password is incorrect.');
    expect(screen.getByLabelText('Password')).toHaveValue('');
    expect(screen.queryByText(/secret-postgres/)).not.toBeInTheDocument();
  });

  it('restores the server session and signs out with a CSRF-protected request', async () => {
    const fetchMock = mockApi(true);
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByRole('button', { name: 'Sign out' }));
    expect(await screen.findByRole('heading', { name: 'Sign in to PrivacyShield' })).toBeInTheDocument();
    const logoutCall = fetchMock.mock.calls.find(([path]) => path === '/api/v1/auth/logout');
    expect(logoutCall?.[1]?.method).toBe('POST');
    expect(new Headers(logoutCall?.[1]?.headers).get('X-CSRF-Token')).toBe(user.csrf_token);
  });

  it('returns to an empty sign-in form when an authenticated API request expires', async () => {
    const fetchMock = mockApi(true);
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await screen.findByText('Your data landscape starts here');
    fetchMock.mockResolvedValueOnce(json({}, 401));
    await visitor.click(screen.getByRole('button', { name: 'Refresh' }));
    expect(await screen.findByText('Your session has expired. Please sign in again.')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toHaveValue('');
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument();
    expect(localStorage.length).toBe(0);
  });

  it('does not pretend sign-out succeeded when the network fails', async () => {
    const fetchMock = mockApi(true);
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await screen.findByText('Your data landscape starts here');
    fetchMock.mockRejectedValueOnce(new TypeError('offline'));
    await visitor.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The workspace could not be reached.');
    expect(screen.getByRole('navigation')).toBeInTheDocument();
  });

  it('restores a connection after an initial network failure', async () => {
    const fetchMock = mockApi(true);
    fetchMock.mockRejectedValueOnce(new TypeError('offline'));
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByRole('button', { name: 'Try connection again' }));
    expect(await screen.findByRole('heading', { name: 'Workspace overview.' })).toBeInTheDocument();
  });
});

describe('dashboard and navigation', () => {
  it('shows an administrator all ten routes and labels unimplemented features honestly', async () => {
    mockApi(true);
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    const nav = await screen.findByRole('navigation', { name: 'Main navigation' });
    // Nine pages for everyone, plus Users for administrators (covered in Users.test.tsx).
    expect(nav.querySelectorAll('a')).toHaveLength(10);
    await visitor.click(screen.getByRole('link', { name: 'Masking Policies' }));
    expect(await screen.findByRole('heading', { name: /Masking Policies/ })).toBeInTheDocument();
    expect(screen.getByText(/Create, preview, approve, and deploy/)).toBeInTheDocument();
  });

  it('distinguishes missing metrics from an empty workspace after a dashboard failure', async () => {
    const fetchMock = mockApi(true);
    fetchMock.mockResolvedValueOnce(json(user)).mockResolvedValueOnce(json({}, 500));
    render(<App />);
    expect(await screen.findByRole('alert')).toHaveTextContent('This request could not be completed.');
    expect(await screen.findByText('Workspace totals unavailable')).toBeInTheDocument();
    expect(screen.queryByText('Your data landscape starts here')).not.toBeInTheDocument();
  });

  it('preserves the selected page after reauthentication without retaining its session', async () => {
    mockApi(true);
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByRole('link', { name: 'Settings' }));
    await act(async () => window.dispatchEvent(new Event(SESSION_EXPIRED)));
    await visitor.type(screen.getByLabelText('Email address'), user.email);
    await visitor.type(screen.getByLabelText('Password'), 'not-a-real-password');
    await visitor.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Settings.' })).toBeInTheDocument());
  });

  it('breaks the findings down by category and risk, with protection coverage', async () => {
    const fetchMock = mockApi(true);
    const populated = { databases: 1, tables: 4, sensitive_columns: 9, pending_approvals: 1, deployed_policies: 1, scan_jobs: 2 };
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path === '/api/v1/auth/me') return json(user);
      if (path === '/api/v1/dashboard/summary') return json(populated);
      if (path === '/api/v1/dashboard/insights') return json({
        categories: [{ category: 'EMAIL_ADDRESS', columns: 3 }, { category: 'AADHAAR_CANDIDATE', columns: 1 }],
        risks: [{ risk: 'CRITICAL', columns: 2 }, { risk: 'HIGH', columns: 5 }, { risk: 'MEDIUM', columns: 2 }],
        risks_from_ai: 0,
        policy_status: [{ status: 'DRAFT', policies: 1 }, { status: 'DEPLOYED', policies: 1 }],
        coverage: { sensitive_columns: 9, protected_columns: 6 },
        recent_activity: [{ event_type: 'POLICY_APPROVED', subject_type: 'masking_policy', created_at: new Date().toISOString() }],
      });
      throw new Error(`Unexpected test endpoint: ${path}`);
    });
    render(<App />);

    const categories = await screen.findByRole('list', { name: 'Sensitive columns by category' });
    expect(categories).toHaveTextContent('Email address3');
    expect(categories).toHaveTextContent('Aadhaar candidate1');
    const risks = screen.getByRole('list', { name: 'Sensitive columns by risk level' });
    expect(risks).toHaveTextContent('Critical2');
    expect(risks).toHaveTextContent('Medium2');
    expect(screen.getByText('6 of 9')).toBeInTheDocument();
    expect(screen.getByRole('meter', { name: 'Sensitive columns masked by a deployed policy' })).toHaveAttribute('aria-valuenow', '6');
    expect(screen.getByText('A column takes the highest risk level among the categories detected in it.')).toBeInTheDocument();
    expect(screen.getByText('Policy approved')).toBeInTheDocument();
    // The three-step journey panel is gone from the overview, and nothing is labelled as planned.
    expect(screen.queryByText(/Available now/)).not.toBeInTheDocument();
    expect(screen.queryByText('From visibility to protection')).not.toBeInTheDocument();
    expect(screen.queryByText(/Planned capability/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Masking policies are next/)).not.toBeInTheDocument();
  });

  it('says so when the breakdowns fail to load instead of showing them as empty', async () => {
    const fetchMock = mockApi(true);
    const populated = { databases: 1, tables: 4, sensitive_columns: 9, pending_approvals: 0, deployed_policies: 1, scan_jobs: 2 };
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path === '/api/v1/auth/me') return json(user);
      if (path === '/api/v1/dashboard/summary') return json(populated);
      return json({}, 500);
    });
    render(<App />);
    expect(await screen.findAllByText('This breakdown could not be loaded. Refresh to try again.')).toHaveLength(4);
    // The totals are still shown, and nothing claims there are no findings.
    expect(screen.getByText('9')).toBeInTheDocument();
    expect(screen.queryByText('No scan findings yet')).not.toBeInTheDocument();
  });
});
