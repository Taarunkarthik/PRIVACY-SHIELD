import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../src/App';
import type { Connection, SchemaSnapshot } from '../src/api/connections';

const connection: Connection = { id: 'db-fixture', name: 'Synthetic enterprise', host: 'target-db', port: 5432, database_name: 'enterprise_demo', ssl_mode: 'disable', scanner_username: 'ps_scanner', deployer_username: null, is_active: true, created_at: '2026-10-09T10:00:00Z' };
const snapshot: SchemaSnapshot = { snapshot_id: 'snapshot-fixture', discovered_at: '2026-10-09T10:10:00Z', fingerprint: 'fixture-fingerprint', catalog: { schemas: ['enterprise'], tables: [
  { schema: 'enterprise', name: 'customers', oid: 1, row_estimate: 40, rls_enabled: false, columns: [
    { name: 'tenant_id', data_type: 'integer', udt_name: 'int4', nullable: false, ordinal: 1, is_primary_key: true, is_jsonb: false },
    { name: 'customer_id', data_type: 'uuid', udt_name: 'uuid', nullable: false, ordinal: 2, is_primary_key: true, is_jsonb: false },
    { name: 'profile', data_type: 'jsonb', udt_name: 'jsonb', nullable: true, ordinal: 3, is_primary_key: false, is_jsonb: true },
  ], primary_key: ['tenant_id', 'customer_id'], foreign_keys: [] },
  { schema: 'enterprise', name: 'accounts', oid: 2, row_estimate: 50, rls_enabled: true, columns: [
    { name: 'account_id', data_type: 'uuid', udt_name: 'uuid', nullable: false, ordinal: 1, is_primary_key: true, is_jsonb: false },
  ], primary_key: ['account_id'], foreign_keys: [{ name: 'accounts_customer_fk', columns: ['tenant_id', 'customer_id'], referenced_schema: 'enterprise', referenced_table: 'customers', referenced_columns: ['tenant_id', 'customer_id'] }] },
] } };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

async function fill(visitor: ReturnType<typeof userEvent.setup>, element: HTMLElement, value: string) {
  await visitor.click(element);
  await visitor.clear(element);
  await visitor.paste(value);
}

function server({ role = 'ADMIN', items = [connection], noSchema = false, saveStatus = 201, schema = snapshot }: { role?: 'ADMIN' | 'ANALYST' | 'AUDITOR'; items?: Connection[]; noSchema?: boolean; saveStatus?: number; schema?: SchemaSnapshot } = {}) {
  let saved = [...items];
  const fetchMock = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    const path = String(url);
    if (path.endsWith('/auth/me')) return json({ id: 'user', email: 'admin@example.test', role, csrf_token: 'csrf-fixture' });
    if (path.includes('/connections?')) return json({ items: saved, total: saved.length, page: 1, page_size: path.includes('100') ? 100 : 20 });
    if (path === '/api/v1/connections' && init?.method === 'POST') {
      if (saveStatus !== 201) return json({ detail: 'A backend exception containing should-never-render-secret' }, saveStatus);
      saved = [connection]; return json(connection, 201);
    }
    if (path.endsWith('/connections/db-fixture') && init?.method === 'PATCH') return json(connection);
    if (path.endsWith('/test')) return json({ status: 'ok', schemas: ['enterprise'], table_count: 2 });
    if (path.endsWith('/discover')) return json(schema);
    if (path.endsWith('/schema')) return noSchema ? json({}, 404) : json(schema);
    throw new Error(`Unexpected fixture endpoint ${path}`);
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

describe('connection management', () => {
  it('saves write-only credentials with CSRF and removes password fields on success', async () => {
    window.history.replaceState({}, '', '/connections');
    const fetchMock = server({ items: [] });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click((await screen.findAllByRole('button', { name: 'Add database' }))[0]);
    await fill(visitor, screen.getByLabelText('Connection name'), 'Synthetic enterprise');
    expect(screen.getByLabelText('Scanner password')).toHaveValue('');
    await fill(visitor, screen.getByLabelText('Scanner password'), 'synthetic-test-password');
    await visitor.click(screen.getByRole('button', { name: 'Save connection' }));
    expect(await screen.findByRole('article', { name: 'Connection Synthetic enterprise' })).toBeInTheDocument();
    const saved = fetchMock.mock.calls.find(([path, request]) => path === '/api/v1/connections' && request?.method === 'POST');
    expect(JSON.parse(String(saved?.[1]?.body))).toMatchObject({ host: 'target-db', database_name: 'enterprise_demo', ssl_mode: 'disable', scanner_password: 'synthetic-test-password' });
    expect(new Headers(saved?.[1]?.headers).get('X-CSRF-Token')).toBe('csrf-fixture');
    expect(screen.queryByLabelText('Scanner password')).not.toBeInTheDocument();
    expect(localStorage.length + sessionStorage.length).toBe(0);
    expect(document.body).not.toHaveTextContent('synthetic-test-password');
  });

  it('clears all submitted passwords after a failed save and hides backend exception details', async () => {
    window.history.replaceState({}, '', '/connections');
    server({ items: [], saveStatus: 502 });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click((await screen.findAllByRole('button', { name: 'Add database' }))[0]);
    await fill(visitor, screen.getByLabelText('Connection name'), 'Private source');
    await fill(visitor, screen.getByLabelText('Scanner password'), 'synthetic-test-password');
    await visitor.click(screen.getByRole('checkbox', { name: /Add deployment credentials/ }));
    await fill(visitor, screen.getByLabelText('Deployment username'), 'deployer_fixture');
    await fill(visitor, screen.getByLabelText('Deployment password'), 'synthetic-deployer-password');
    await visitor.click(screen.getByRole('button', { name: 'Save connection' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Password fields have been cleared.');
    expect(screen.getByLabelText('Scanner password')).toHaveValue('');
    expect(screen.getByLabelText('Deployment password')).toHaveValue('');
    expect(screen.getByLabelText('Connection name')).toHaveValue('Private source');
    expect(document.body).not.toHaveTextContent('should-never-render-secret');
  });

  it('shows connection records to auditors without credential or discovery actions', async () => {
    window.history.replaceState({}, '', '/connections');
    server({ role: 'AUDITOR' });
    render(<App />);
    await screen.findByRole('article', { name: 'Connection Synthetic enterprise' });
    expect(screen.queryByRole('button', { name: 'Add database' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Edit Synthetic/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Test connection' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Discover schema' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Explore schema' })).toHaveAttribute('href', '/schema?connection=db-fixture');
  });

  it('lets analysts discover structure and opens the returned connection in the explorer', async () => {
    window.history.replaceState({}, '', '/connections');
    const fetchMock = server({ role: 'ANALYST' });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await fill(visitor, await screen.findByLabelText(/Schemas to inspect/), 'enterprise, enterprise');
    await visitor.click(await screen.findByRole('button', { name: 'Discover schema' }));
    expect(await screen.findByRole('heading', { name: 'Schema Explorer.' })).toBeInTheDocument();
    expect(await screen.findByText('Composite primary key')).toBeInTheDocument();
    const request = fetchMock.mock.calls.find(([path]) => String(path).endsWith('/discover'));
    expect(JSON.parse(String(request?.[1]?.body))).toEqual({ schemas: ['enterprise'] });
    expect(new Headers(request?.[1]?.headers).get('X-CSRF-Token')).toBe('csrf-fixture');
  });

  it('edits metadata without sending blank credential values and preserves inactive records', async () => {
    window.history.replaceState({}, '', '/connections');
    const fetchMock = server();
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByRole('button', { name: 'Edit Synthetic enterprise' }));
    await visitor.click(screen.getByRole('checkbox', { name: /Connection is active/ }));
    await visitor.click(screen.getByRole('button', { name: 'Save connection' }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([, options]) => options?.method === 'PATCH')).toBe(true));
    const request = fetchMock.mock.calls.find(([, options]) => options?.method === 'PATCH');
    const body = JSON.parse(String(request?.[1]?.body));
    expect(body.is_active).toBe(false);
    expect(body).not.toHaveProperty('scanner_password');
    expect(body).not.toHaveProperty('deployer_password');
  });
});

describe('schema explorer', () => {
  it('keeps quoted schema and table names containing dots distinct', async () => {
    window.history.replaceState({}, '', '/schema?connection=db-fixture');
    const schema: SchemaSnapshot = { ...snapshot, catalog: { schemas: ['a.b', 'a'], tables: [
      { ...snapshot.catalog.tables[0], schema: 'a.b', name: 'c', columns: [{ ...snapshot.catalog.tables[0].columns[0], name: 'first_column' }] },
      { ...snapshot.catalog.tables[0], schema: 'a', name: 'b.c', columns: [{ ...snapshot.catalog.tables[0].columns[0], name: 'second_column' }] },
    ] } };
    server({ schema });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByRole('button', { name: 'b.c' }));
    expect(screen.getByRole('rowheader', { name: /second_column/ })).toBeInTheDocument();
    expect(screen.queryByRole('rowheader', { name: /first_column/ })).not.toBeInTheDocument();
  });
  it('shows composite primary and foreign keys as grouped relationships and filters columns', async () => {
    window.history.replaceState({}, '', '/schema?connection=db-fixture');
    server();
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    expect(await screen.findByText('Composite primary key')).toBeInTheDocument();
    expect(screen.getByText('tenant_id + customer_id')).toBeInTheDocument();
    expect(screen.getByText(/Approximately 40 rows/)).toBeInTheDocument();
    const columnsTable = screen.getByRole('table');
    expect(within(columnsTable).getByText('JSONB')).toBeInTheDocument();
    await fill(visitor, screen.getByLabelText('Find columns'), 'profile');
    expect(within(columnsTable).getAllByRole('row')).toHaveLength(2);
    await visitor.click(screen.getByRole('button', { name: 'accounts' }));
    expect(screen.getByText('Composite foreign key')).toBeInTheDocument();
    expect(screen.getByText('accounts_customer_fk')).toBeInTheDocument();
    expect(screen.getByText('Row security enabled')).toBeInTheDocument();
    await visitor.click(screen.getByRole('button', { name: 'enterprise.customers' }));
    expect(screen.getByText('Composite primary key')).toBeInTheDocument();
  });

  it('treats an undiscovered schema as an empty state and lets an analyst discover it', async () => {
    window.history.replaceState({}, '', '/schema?connection=db-fixture');
    const fetchMock = server({ role: 'ANALYST', noSchema: true });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    expect(await screen.findByRole('heading', { name: 'No schema discovered yet' })).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    await visitor.click(screen.getByRole('button', { name: 'Discover schema' }));
    expect(await screen.findByText('Composite primary key')).toBeInTheDocument();
    const request = fetchMock.mock.calls.find(([path]) => String(path).endsWith('/discover'));
    expect(JSON.parse(String(request?.[1]?.body))).toEqual({});
  });

  it('keeps inactive snapshots readable while disabling new discovery', async () => {
    window.history.replaceState({}, '', '/schema?connection=db-fixture');
    server({ items: [{ ...connection, is_active: false }] });
    render(<App />);
    expect(await screen.findByText('Composite primary key')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Discover schema' })).toBeDisabled();
  });
});
