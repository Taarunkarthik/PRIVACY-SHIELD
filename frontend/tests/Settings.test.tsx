import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../src/App';
import type { WorkspaceSettings } from '../src/api/settings';
import { PATTERN_LIMIT } from '../src/api/settings';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const emptySettings: WorkspaceSettings = { workspace_name: 'Privacy workspace', retention_days: 30, custom_patterns: [] };

function pattern(index: number) {
  return { id: `pattern-${index}`, name: `Pattern ${index}`, category: 'EMAIL_ADDRESS', regex: `p${index}`, enabled: true };
}

function server({ role = 'ADMIN', initial = emptySettings, failPatch = 0 }: { role?: 'ADMIN' | 'ANALYST' | 'AUDITOR'; initial?: WorkspaceSettings; failPatch?: number } = {}) {
  let settings = initial;
  const fetchMock = vi.fn(async (url: RequestInfo | URL, options?: RequestInit) => {
    const path = String(url);
    const method = options?.method ?? 'GET';
    if (path.endsWith('/auth/me')) return json({ id: 'user-1', email: 'admin@example.test', role, csrf_token: 'csrf-settings' });
    if (path.endsWith('/settings') && method === 'PATCH') {
      if (failPatch) return json({ detail: 'postgres://secret-connection-string' }, failPatch);
      const body = JSON.parse(String(options?.body));
      settings = { ...settings, ...body };
      return json(settings);
    }
    if (path.endsWith('/settings')) return json(settings);
    throw new Error(`Unexpected test endpoint ${path}`);
  });
  vi.stubGlobal('fetch', fetchMock);
  window.history.replaceState({}, '', '/settings');
  return fetchMock;
}

function patches(fetchMock: ReturnType<typeof server>) {
  return fetchMock.mock.calls.filter(([path, options]) => String(path).endsWith('/settings') && options?.method === 'PATCH');
}

describe('workspace settings', () => {
  it('lets an administrator rename the workspace and change retention with CSRF', async () => {
    const fetchMock = server();
    const visitor = userEvent.setup({ delay: null });
    render(<App />);

    const name = await screen.findByLabelText('Workspace name');
    expect(name).toHaveValue('Privacy workspace');
    await visitor.clear(name);
    await visitor.type(name, 'Acme analytics');
    const retention = screen.getByLabelText(/Retention period/);
    await visitor.clear(retention);
    await visitor.type(retention, '90');

    await visitor.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Workspace settings saved.');

    const [path, options] = patches(fetchMock).at(-1) ?? [];
    expect(path).toBe('/api/v1/settings');
    expect(new Headers(options?.headers).get('X-CSRF-Token')).toBe('csrf-settings');
    expect(JSON.parse(String(options?.body))).toEqual({ workspace_name: 'Acme analytics', retention_days: 90 });
  });

  it('adds, toggles, and deletes a custom detection pattern', async () => {
    const fetchMock = server();
    const visitor = userEvent.setup({ delay: null });
    render(<App />);

    const patterns = await screen.findByRole('region', { name: 'Custom detection patterns' });
    await visitor.type(within(patterns).getByLabelText('Pattern name'), 'Employee badge');
    await visitor.selectOptions(within(patterns).getByLabelText('Category'), 'CREDIT_CARD');
    fireEvent.change(within(patterns).getByLabelText('Regular expression'), { target: { value: '\\b[0-9]{6}\\b' } });
    await visitor.click(within(patterns).getByRole('button', { name: 'Add pattern' }));

    expect(await within(patterns).findByText('Employee badge')).toBeInTheDocument();
    const added = JSON.parse(String(patches(fetchMock).at(-1)?.[1]?.body));
    expect(added.custom_patterns).toHaveLength(1);
    expect(added.custom_patterns[0]).toMatchObject({ name: 'Employee badge', category: 'CREDIT_CARD', regex: '\\b[0-9]{6}\\b', enabled: true });

    await visitor.click(within(patterns).getByRole('button', { name: 'Disable' }));
    expect(await within(patterns).findByText('Disabled')).toBeInTheDocument();

    await visitor.click(within(patterns).getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(within(patterns).queryByText('Employee badge')).not.toBeInTheDocument());
    expect(JSON.parse(String(patches(fetchMock).at(-1)?.[1]?.body)).custom_patterns).toEqual([]);
  });

  it('validates pattern input before sending a request', async () => {
    const fetchMock = server();
    const visitor = userEvent.setup({ delay: null });
    render(<App />);

    const patterns = await screen.findByRole('region', { name: 'Custom detection patterns' });
    await visitor.click(within(patterns).getByRole('button', { name: 'Add pattern' }));
    expect(within(patterns).getByRole('alert')).toHaveTextContent('Enter a pattern name.');

    await visitor.type(within(patterns).getByLabelText('Pattern name'), 'Unbounded');
    fireEvent.change(within(patterns).getByLabelText('Regular expression'), { target: { value: '[' } });
    await visitor.click(within(patterns).getByRole('button', { name: 'Add pattern' }));
    expect(within(patterns).getByRole('alert')).toHaveTextContent('Enter a valid regular expression.');
    expect(patches(fetchMock)).toHaveLength(0);
    expect(within(patterns).getByLabelText('Pattern name')).toHaveAttribute('maxlength', '60');
  });

  it('caps the number of custom patterns at the server limit', async () => {
    server({ initial: { ...emptySettings, custom_patterns: Array.from({ length: PATTERN_LIMIT }, (_, index) => pattern(index)) } });
    render(<App />);
    const patterns = await screen.findByRole('region', { name: 'Custom detection patterns' });
    expect(within(patterns).getByRole('button', { name: 'Add pattern' })).toBeDisabled();
  });

  it('shows a read-only view for non-administrators', async () => {
    server({ role: 'ANALYST', initial: { ...emptySettings, custom_patterns: [pattern(1)] } });
    render(<App />);

    const workspace = await screen.findByRole('region', { name: 'Workspace settings' });
    expect(within(workspace).getByText('Privacy workspace')).toBeInTheDocument();
    expect(within(workspace).getByText('30 days')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save changes' })).not.toBeInTheDocument();

    const patterns = screen.getByRole('region', { name: 'Custom detection patterns' });
    expect(within(patterns).queryByRole('button', { name: 'Add pattern' })).not.toBeInTheDocument();
    expect(within(patterns).queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
  });

  it('never renders backend exception text on a failed update', async () => {
    server({ failPatch: 422 });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);

    const name = await screen.findByLabelText('Workspace name');
    await visitor.clear(name);
    await visitor.type(name, 'Renamed');
    await visitor.click(screen.getByRole('button', { name: 'Save changes' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Check the workspace name and retention period, then try again.');
    expect(screen.queryByText(/secret-connection-string/)).not.toBeInTheDocument();
  });

  it('blocks an out-of-range retention value without a request', async () => {
    const fetchMock = server();
    const visitor = userEvent.setup({ delay: null });
    render(<App />);

    const retention = await screen.findByLabelText(/Retention period/);
    fireEvent.change(retention, { target: { value: '0' } });
    await visitor.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Retention must be a whole number between 1 and 3650 days.');
    expect(patches(fetchMock)).toHaveLength(0);
  });
});
