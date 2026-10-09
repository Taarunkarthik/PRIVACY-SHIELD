import { act, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../src/App';
import { activeScan } from '../src/api/scans';
import type { ScanJob, ScanResult } from '../src/api/scans';
import { usePollingResource } from '../src/api/usePollingResource';

const connection = { id: 'db-scan', name: 'Scan fixture', host: 'target-db', port: 5432, database_name: 'enterprise_demo', ssl_mode: 'disable', scanner_username: 'ps_scanner', deployer_username: null, is_active: true, created_at: '2026-10-09T10:00:00Z' };
const job: ScanJob = { id: 'scan-fixture', connection_id: connection.id, snapshot_id: 'snapshot-scan', status: 'COMPLETED', sample_limit: 1000, progress: 100, created_at: '2026-10-09T10:00:00Z', started_at: '2026-10-09T10:00:01Z', finished_at: '2026-10-09T10:01:00Z', error_code: null };
const result: ScanResult = { id: 'result-fixture', scan_job_id: job.id, schema_name: 'enterprise', table_name: 'customers', column_name: 'profile', json_path: '$.contact.email', sampled_rows: 100, matching_rows: 4, confidence: .9, category_counts: { EMAIL_ADDRESS: 3, PAN_CANDIDATE: 1 }, sanitized_evidence: { labels: ['EMAIL_ADDRESS', 'PAN_CANDIDATE'], coverage: { mode: 'bounded_sample', sample_limit: 1000, max_cell_chars: 4096, max_cell_bytes: 16384, values_truncated: 2, values_skipped: 1, json_truncated: 1, path_limit_reached: 0, unsupported_type: false } }, created_at: '2026-10-09T10:01:00Z' };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

function server({ role = 'ADMIN', status = 'COMPLETED', noJobs = false, noSchema = false, findings = [result] }: { role?: 'ADMIN' | 'ANALYST' | 'AUDITOR'; status?: ScanJob['status']; noJobs?: boolean; noSchema?: boolean; findings?: ScanResult[] } = {}) {
  let storedJob = { ...job, status, progress: status === 'COMPLETED' ? 100 : 40, error_code: status === 'FAILED' ? 'SCHEMA_DRIFT' : null };
  let items = noJobs ? [] : [storedJob];
  const fetchMock = vi.fn(async (url: RequestInfo | URL, options?: RequestInit) => {
    const path = String(url);
    if (path.endsWith('/auth/me')) return json({ id: 'user-scan', email: 'admin@example.test', role, csrf_token: 'csrf-scan' });
    if (path.includes('/connections?')) return json({ items: [connection], total: 1, page: 1, page_size: 100 });
    if (path.endsWith('/schema')) return noSchema ? json({}, 404) : json({ snapshot_id: job.snapshot_id, discovered_at: job.created_at, fingerprint: 'fixture', catalog: { schemas: ['enterprise'], tables: [{ schema: 'enterprise', name: 'customers', columns: [] }] } });
    if (path === '/api/v1/scans' && options?.method === 'POST') { storedJob = { ...storedJob, status: 'QUEUED', progress: 0 }; items = [storedJob]; return json(storedJob, 202); }
    if (path.includes('/scans?')) return json({ items, total: items.length, page: 1, page_size: 10 });
    if (path.endsWith(`/scans/${job.id}`)) return json(storedJob);
    if (path.includes('/results?')) return json({ items: findings, total: findings.length, page: 1, page_size: 20 });
    throw new Error(`Unexpected test endpoint ${path}`);
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

describe('sampled scan workflow', () => {
  it('launches an analyst scan with the latest snapshot, bounded limit, and CSRF', async () => {
    window.history.replaceState({}, '', '/scans');
    const fetchMock = server({ role: 'ANALYST', noJobs: true });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Start scan' })).toBeEnabled());
    expect(screen.getByLabelText(/Rows per table/)).toHaveValue(1000);
    await visitor.click(screen.getByRole('button', { name: 'Start scan' }));
    expect(await screen.findByText('Waiting for a scanning worker')).toBeInTheDocument();
    const created = fetchMock.mock.calls.find(([path, options]) => path === '/api/v1/scans' && options?.method === 'POST');
    expect(JSON.parse(String(created?.[1]?.body))).toEqual({ connection_id: connection.id, snapshot_id: job.snapshot_id, sample_limit: 1000 });
    expect(new Headers(created?.[1]?.headers).get('X-CSRF-Token')).toBe('csrf-scan');
    expect(fetchMock.mock.calls.some(([path]) => String(path).includes('/results?'))).toBe(false);
  });

  it('blocks excessive samples before making a scan request', async () => {
    window.history.replaceState({}, '', '/scans');
    const fetchMock = server({ noJobs: true });
    render(<App />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Start scan' })).toBeEnabled());
    fireEvent.change(screen.getByLabelText(/Rows per table/), { target: { value: '10001' } });
    fireEvent.submit(screen.getByRole('form', { name: 'Launch a scan' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('1 to 10,000');
    expect(fetchMock.mock.calls.some(([path, options]) => path === '/api/v1/scans' && options?.method === 'POST')).toBe(false);
  });

  it('allows auditors to review completed findings but not launch scans', async () => {
    window.history.replaceState({}, '', '/scans');
    server({ role: 'AUDITOR' });
    render(<App />);
    expect(await screen.findByRole('region', { name: 'Sampled scan findings' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Start scan' })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/Rows per table/)).not.toBeInTheDocument();
    expect(await screen.findByText(/PAN candidate/, { selector: '.category-chip' })).toBeInTheDocument();
  });

  it('requires discovery before a new scan', async () => {
    window.history.replaceState({}, '', '/scans');
    server({ noSchema: true, noJobs: true });
    render(<App />);
    expect(await screen.findByText('Discover this database’s schema before starting a scan.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start scan' })).toBeDisabled();
  });

  it('shows truncation and safe category labels without rendering unexpected evidence values', async () => {
    window.history.replaceState({}, '', '/scans');
    const poisoned = { ...result, sanitized_evidence: { ...result.sanitized_evidence, unexpected_raw_value: 'customer-private-value@example.test' } };
    server({ findings: [poisoned] });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByText('Coverage limitations', { selector: 'summary' }));
    expect(screen.getByText('2 values truncated')).toBeVisible();
    expect(screen.getByText('1 values skipped')).toBeVisible();
    expect(document.body).not.toHaveTextContent('customer-private-value@example.test');
    expect(screen.getByText('$.contact.email')).toBeInTheDocument();
    expect(screen.getAllByText(/not verified identities/).length).toBeGreaterThan(0);
  });

  it('does not request or imply clean findings when a job fails', async () => {
    window.history.replaceState({}, '', '/scans');
    const fetchMock = server({ status: 'FAILED' });
    render(<App />);
    expect(await screen.findByText('Scan incomplete')).toBeInTheDocument();
    expect(screen.getByText(/schema changed after discovery/)).toBeInTheDocument();
    expect(screen.getByText(/No partial findings were published/)).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Sampled scan findings' })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([path]) => String(path).includes('/results?'))).toBe(false);
  });

  it('labels unsupported column types as unassessed rather than a clean sample', async () => {
    window.history.replaceState({}, '', '/scans');
    server({ findings: [{ ...result, matching_rows: 0, confidence: 0, category_counts: {}, sanitized_evidence: { labels: [], coverage: { ...result.sanitized_evidence.coverage, unsupported_type: true } } }] });
    render(<App />);
    expect(await screen.findByText('Not assessed')).toBeInTheDocument();
    expect(screen.queryByText('No matches in this sample')).not.toBeInTheDocument();
  });
});

describe('durable scan polling', () => {
  it('polls active jobs and stops when completed, then cancels requests on unmount', async () => {
    vi.useFakeTimers();
    try {
      const fetchMock = vi.fn().mockResolvedValueOnce(json({ ...job, status: 'QUEUED', progress: 0 }))
        .mockResolvedValueOnce(json({ ...job, status: 'RUNNING', progress: 50 }))
        .mockResolvedValueOnce(json(job));
      vi.stubGlobal('fetch', fetchMock);
      const { result: resource, unmount } = renderHook(() => usePollingResource<ScanJob>('/scans/scan-fixture', 0, activeScan));
      await act(async () => { await vi.advanceTimersByTimeAsync(0); });
      expect(resource.current.data?.status).toBe('QUEUED');
      await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
      expect(resource.current.data?.progress).toBe(50);
      await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
      expect(resource.current.data?.status).toBe('COMPLETED');
      await act(async () => { await vi.advanceTimersByTimeAsync(9000); });
      expect(fetchMock).toHaveBeenCalledTimes(3);
      const signal = (fetchMock.mock.calls[0][1] as RequestInit).signal;
      unmount();
      expect(signal?.aborted).toBe(true);
    } finally { vi.useRealTimers(); }
  });

  it('stops automatic polling on a network error and clears pending timers on unmount', async () => {
    vi.useFakeTimers();
    try {
      const fetchMock = vi.fn().mockResolvedValueOnce(json({ ...job, status: 'RUNNING' })).mockRejectedValueOnce(new TypeError('offline'));
      vi.stubGlobal('fetch', fetchMock);
      const { result: resource, unmount } = renderHook(() => usePollingResource<ScanJob>('/scans/scan-fixture', 0, activeScan));
      await act(async () => { await vi.advanceTimersByTimeAsync(0); });
      await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
      expect(resource.current.error).toContain('could not be reached');
      await act(async () => { await vi.advanceTimersByTimeAsync(9000); });
      expect(fetchMock).toHaveBeenCalledTimes(2);
      unmount();
    } finally { vi.useRealTimers(); }
  });
});
