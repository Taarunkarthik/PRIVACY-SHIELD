import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../src/App';

const connection = {
  id: 'db-1', name: 'Demo enterprise', host: 'target-db', port: 5432,
  database_name: 'enterprise_demo', ssl_mode: 'disable', scanner_username: 'ps_scanner',
  deployer_username: 'ps_deployer', is_active: true, created_at: '2026-10-10T00:00:00Z',
};

const rules = [
  { policy_id: 'policy-1', column_name: 'id', action: 'KEEP', pseudonym_domain: null, classification_id: null },
  { policy_id: 'policy-1', column_name: 'email', action: 'REDACT', pseudonym_domain: null, classification_id: null },
  { policy_id: 'policy-1', column_name: 'phone', action: 'NULLIFY', pseudonym_domain: null, classification_id: null },
];

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

function server({ role = 'ADMIN', status = 'DRAFT' } = {}) {
  let current = status;
  const fetchMock = vi.fn(async (url: RequestInfo | URL, options?: RequestInit) => {
    const path = String(url);
    const method = options?.method ?? 'GET';
    if (path.endsWith('/auth/me')) return json({ id: 'user-1', email: 'admin@example.test', role, csrf_token: 'csrf-policy' });
    if (path.includes('/connections?')) return json({ items: [connection], total: 1, page: 1, page_size: 100 });
    if (path.endsWith('/policies/policy-1/preview')) return json({
      policy_id: 'policy-1', schema_name: 'enterprise', table_name: 'customers',
      view_schema: 'privacyshield_masked', view_name: 'customers_abc123',
      columns: [
        { name: 'id', data_type: 'bigint', action: 'KEEP', pseudonym_domain: null, source_column: 'id' },
        { name: 'email', data_type: 'text', action: 'REDACT', pseudonym_domain: null, source_column: 'email' },
      ],
      sql: 'CREATE OR REPLACE VIEW "privacyshield_masked"."customers_abc123" WITH (security_barrier = true) AS',
    });
    if (path.endsWith('/policies/policy-1/submit') && method === 'POST') { current = 'PENDING_APPROVAL'; return json(policy()); }
    if (path.endsWith('/policies/policy-1/approve') && method === 'POST') { current = 'APPROVED'; return json(policy()); }
    if (path.endsWith('/policies/policy-1/reject') && method === 'POST') { current = 'REJECTED'; return json(policy()); }
    if (path.endsWith('/policies/policy-1/deploy') && method === 'POST') return json({ id: 'deploy-1', policy_id: 'policy-1', requested_by: 'user-1', idempotency_key: 'key-1', status: 'QUEUED', target_receipt: null, finished_at: null, error_code: null, created_at: '2026-10-10T00:00:00Z' }, 202);
    if (path.includes('/policies?')) return json({ items: [policy()], total: 1, page: 1, page_size: 10 });
    throw new Error(`Unexpected test endpoint ${path}`);
  });
  function policy() {
    return {
      id: 'policy-1', connection_id: 'db-1', schema_name: 'enterprise', table_name: 'customers',
      version: 1, status: current, schema_fingerprint: 'fingerprint-1',
      compiled_plan_fingerprint: current === 'APPROVED' ? 'plan-hash' : null,
      created_by: 'user-1', created_at: '2026-10-10T00:00:00Z', rules,
    };
  }
  vi.stubGlobal('fetch', fetchMock);
  window.history.replaceState({}, '', '/policies?connection=db-1&policy=policy-1');
  return fetchMock;
}

describe('masking policy workflow', () => {
  it('lets an administrator submit, approve, then deploy a policy with CSRF', async () => {
    const fetchMock = server();
    const visitor = userEvent.setup({ delay: null });
    render(<App />);

    const list = await screen.findByRole('region', { name: 'Policies' });
    expect(within(list).getByText('Draft')).toBeInTheDocument();

    await visitor.click(await screen.findByRole('button', { name: 'Submit for approval' }));
    expect(await screen.findByRole('button', { name: 'Approve' })).toBeInTheDocument();

    await visitor.click(screen.getByRole('button', { name: 'Approve' }));
    const deployButton = await screen.findByRole('button', { name: 'Deploy' });

    await visitor.click(deployButton);
    const posted = fetchMock.mock.calls.find(([path, options]) => String(path).endsWith('/deploy') && options?.method === 'POST');
    expect(new Headers(posted?.[1]?.headers).get('X-CSRF-Token')).toBe('csrf-policy');
  });

  it('shows the compiled view preview without exposing source values', async () => {
    server({ status: 'APPROVED' });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByRole('button', { name: 'Preview' }));
    expect(await screen.findByText('Preview: privacyshield_masked.customers_abc123')).toBeInTheDocument();
    expect(screen.getByText(/security_barrier = true/)).toBeInTheDocument();
  });

  it('does not offer approval to analysts', async () => {
    server({ role: 'ANALYST', status: 'PENDING_APPROVAL' });
    render(<App />);
    const list = await screen.findByRole('region', { name: 'Policies' });
    expect(within(list).getByText('Pending approval')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Deploy' })).not.toBeInTheDocument();
  });

  it('lets auditors review policies read-only', async () => {
    server({ role: 'AUDITOR', status: 'DEPLOYED' });
    render(<App />);
    const list = await screen.findByRole('region', { name: 'Policies' });
    expect(within(list).getByText('Deployed')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Submit for approval' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'New policy' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Preview' })).toBeInTheDocument();
  });
});
