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

const snapshot = {
  snapshot_id: 'snapshot-1', discovered_at: '2026-10-10T00:00:00Z', fingerprint: 'fingerprint-1',
  catalog: { schemas: ['enterprise'], tables: [{
    schema: 'enterprise', name: 'customers', oid: 1, row_estimate: 100, rls_enabled: false,
    primary_key: ['id'], foreign_keys: [],
    columns: [
      { name: 'id', data_type: 'bigint', udt_name: 'int8', nullable: false, ordinal: 1, is_primary_key: true, is_jsonb: false },
      { name: 'email', data_type: 'text', udt_name: 'text', nullable: false, ordinal: 2, is_primary_key: false, is_jsonb: false },
      { name: 'notes', data_type: 'text', udt_name: 'text', nullable: true, ordinal: 3, is_primary_key: false, is_jsonb: false },
    ],
  }] },
};

const suggestion = (column_name: string, extra: object) => ({
  column_name, data_type: 'text', source: 'NOT_SCANNED', action: null, category: null, confidence: null,
  sampled_rows: 0, matching_rows: 0, classification_id: null, ai_recommendation: null, ai_risk: null, ...extra,
});

function server({ role = 'ADMIN', status = 'DRAFT', samples = false } = {}) {
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
    if (samples && path.endsWith('/policies/policy-1/preview/samples')) return json({
      policy_id: 'policy-1', status: 'OK', source: 'FABRICATED',
      columns: [
        { name: 'id', data_type: 'bigint', action: 'KEEP' },
        { name: 'email', data_type: 'text', action: 'MASK_EMAIL' },
        { name: 'phone', data_type: 'text', action: 'NULLIFY' },
      ],
      before: [['1001', 'priya.sharma@example.com', '+91 98765 43210']],
      after: [['1001', 'p***@example.com', null]],
    });
    if (path.endsWith('/policies/policy-1/protected-output')) return json({
      policy_id: 'policy-1', view_schema: 'privacyshield_masked', view_name: 'customers_abc123',
      source_schema: 'enterprise', source_table: 'customers',
      columns: [{ name: 'id', data_type: 'bigint', action: 'KEEP' }, { name: 'email', data_type: 'text', action: 'MASK_EMAIL' }],
      rows: [['1', 'c***@example.com'], ['2', 'c***@example.com']], row_limit: 5,
      access: { reader_role: 'ps_reader', reader_can_read_view: true, reader_can_read_source: false },
    });
    if (path.endsWith('/connections/db-1/schema')) return json(snapshot);
    if (path.includes('/policies/suggestions?')) return json({
      connection_id: 'db-1', schema_name: 'enterprise', table_name: 'customers', scan_id: 'scan-1', scanned_at: '2026-10-10T00:00:00Z',
      columns: [
        suggestion('id', { data_type: 'bigint', source: 'NO_FINDINGS', action: 'KEEP', sampled_rows: 50 }),
        suggestion('email', { source: 'DETECTOR', action: 'MASK_EMAIL', category: 'EMAIL_ADDRESS', confidence: 1, sampled_rows: 50, matching_rows: 50, classification_id: 'class-1' }),
        suggestion('notes', {}),
      ],
    });
    if (path.endsWith('/policies') && method === 'POST') return json(policy(), 201);
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

  it('shows example values before and after masking, labelled as invented', async () => {
    server({ status: 'APPROVED', samples: true });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByRole('button', { name: 'Preview' }));
    const preview = await screen.findByRole('region', { name: 'Policy preview' });
    expect(await within(preview).findByText('priya.sharma@example.com')).toBeInTheDocument();
    expect(within(preview).getByText('p***@example.com')).toBeInTheDocument();
    expect(within(preview).getByText(/no rows are read from your database/i)).toBeInTheDocument();
    // A nullified column shows NULL after masking, not its example value twice.
    const phone = within(preview).getByRole('row', { name: /phone/ });
    expect(within(phone).getByText('+91 98765 43210')).toBeInTheDocument();
    expect(within(phone).getByText('NULL')).toBeInTheDocument();
  });

  it('shows an administrator the deployed output and what the reader role can access', async () => {
    server({ status: 'DEPLOYED' });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByRole('button', { name: 'View protected output' }));
    const output = await screen.findByRole('region', { name: 'Protected output' });
    expect(within(output).getAllByText('c***@example.com')).toHaveLength(2);
    expect(within(output).getByText(/can read the masked view/)).toBeInTheDocument();
    expect(within(output).getByText(/cannot read the source table enterprise\.customers/)).toBeInTheDocument();
  });

  it('applies scan suggestions to a new policy and submits them with lineage', async () => {
    const fetchMock = server();
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByRole('button', { name: 'New policy' }));
    const dialog = await screen.findByRole('dialog', { name: 'Create policy' });
    await visitor.selectOptions(await within(dialog).findByLabelText('Table'), 'enterprise.customers');
    expect(await within(dialog).findByText('Email address in 50 of 50 sampled rows')).toBeInTheDocument();
    expect(within(dialog).getByText('Not scanned yet')).toBeInTheDocument();

    await visitor.click(within(dialog).getByRole('button', { name: 'Apply 2 suggestions' }));
    expect(within(dialog).getByLabelText('Action for email')).toHaveValue('MASK_EMAIL');
    expect(within(dialog).getByLabelText('Action for id')).toHaveValue('KEEP');
    // A column without evidence gets no rule, so it stays NULL unless chosen.
    expect(within(dialog).getByLabelText('Action for notes')).toHaveValue('');

    await visitor.selectOptions(within(dialog).getByLabelText('Action for notes'), 'PSEUDONYMIZE');
    expect(within(dialog).getByLabelText('Pseudonym key domain for notes')).toHaveValue('demo');

    await visitor.click(within(dialog).getByRole('button', { name: 'Create policy' }));
    const posted = fetchMock.mock.calls.find(([path, options]) => String(path).endsWith('/policies') && options?.method === 'POST');
    expect(JSON.parse(String(posted?.[1]?.body))).toEqual({
      connection_id: 'db-1', schema_name: 'enterprise', table_name: 'customers', snapshot_id: 'snapshot-1',
      rules: [
        { column_name: 'id', action: 'KEEP' },
        { column_name: 'email', action: 'MASK_EMAIL', classification_id: 'class-1' },
        { column_name: 'notes', action: 'PSEUDONYMIZE', pseudonym_domain: 'demo' },
      ],
    });
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
    // Rows through the deployed view are for administrators only.
    expect(screen.queryByRole('button', { name: 'View protected output' })).not.toBeInTheDocument();
  });
});
