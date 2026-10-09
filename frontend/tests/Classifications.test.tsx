import { act, render, renderHook, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../src/App';
import { activeClassification, classificationError } from '../src/api/classifications';
import type { Classification, ClassificationJob } from '../src/api/classifications';
import { usePollingResource } from '../src/api/usePollingResource';

const scan = { id: 'scan-ai', connection_id: 'database-ai', snapshot_id: 'snapshot-ai', status: 'COMPLETED', sample_limit: 100, progress: 100, created_at: '2026-10-10T01:00:00Z', started_at: null, finished_at: null, error_code: null };
const job: ClassificationJob = { id: 'classification-job', scan_id: scan.id, status: 'COMPLETED', progress: 100, total_results: 1, completed_results: 1, failed_results: 0, model: 'qwen2.5:1.5b', prompt_version: 'v1', error_code: null, created_at: scan.created_at, started_at: null, finished_at: null };
const decision: Classification = { id: 'decision-ai', job_id: job.id, scan_result_id: 'finding-email', scan_id: scan.id, schema_name: 'enterprise', table_name: 'customers', column_name: 'email', json_path: '', category: 'EMAIL_ADDRESS', risk: 'HIGH', recommendation: 'REDACT', confidence: .85, reason: 'Email metadata and detector labels suggest a personal contact identifier.', model: job.model, prompt_version: job.prompt_version, requires_approval: true, created_at: scan.created_at };
const finding = { id: 'finding-email', schema_name: 'enterprise', table_name: 'customers', column_name: 'email', json_path: '', sampled_rows: 100, matching_rows: 100, sanitized_evidence: { coverage: { unsupported_type: false } } };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

function server({ role = 'ADMIN', status = 'COMPLETED', noJobs = false, postStatus = 202, noScans = false }: { role?: 'ADMIN' | 'ANALYST' | 'AUDITOR'; status?: ClassificationJob['status']; noJobs?: boolean; postStatus?: number; noScans?: boolean } = {}) {
  let storedJob = { ...job, status, failed_results: status === 'FAILED' || status === 'PARTIAL' ? 1 : 0, completed_results: status === 'FAILED' ? 0 : 1, total_results: status === 'PARTIAL' ? 2 : 1, error_code: status === 'FAILED' || status === 'PARTIAL' ? 'AI_INVALID_RESPONSE' : null };
  let items = noJobs ? [] : [storedJob];
  const fetchMock = vi.fn(async (url: RequestInfo | URL, options?: RequestInit) => {
    const path = String(url);
    if (path.endsWith('/auth/me')) return json({ id: 'user-ai', email: 'analyst@example.test', role, csrf_token: 'csrf-ai' });
    if (path.includes('/scans?')) return json({ items: noScans ? [] : [scan], total: noScans ? 0 : 1, page: 1, page_size: 50 });
    if (path.endsWith(`/scans/${scan.id}`)) return json(scan);
    if (path.includes('/results?')) return json({ items: [finding], total: 1, page: 1, page_size: 20 });
    if (path.endsWith('/classify') && options?.method === 'POST') { storedJob = { ...storedJob, status: 'QUEUED', progress: 0, completed_results: 0 }; items = [storedJob]; return json(postStatus === 202 ? storedJob : { detail: 'private-backend-error' }, postStatus); }
    if (path.includes('/classification-jobs?')) return json({ items, total: items.length, page: 1, page_size: 10 });
    if (path.endsWith(`/classification-jobs/${job.id}`)) return json(storedJob);
    if (path.includes('/classifications?')) return json({ items: [{ ...decision, unexpected_raw_value: 'secret@example.test' }], total: 1, page: 1, page_size: 20 });
    throw new Error(`Unexpected test endpoint ${path}`);
  });
  vi.stubGlobal('fetch', fetchMock);
  window.history.replaceState({}, '', '/classifications');
  return fetchMock;
}

describe('advisory AI classification', () => {
  it('lets an analyst select a finding and requests classification with CSRF', async () => {
    const fetchMock = server({ role: 'ANALYST', noJobs: true });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByRole('radio', { name: /Choose findings/ }));
    expect(screen.getByRole('button', { name: 'Request classification' })).toBeDisabled();
    await visitor.click(await screen.findByRole('checkbox', { name: /enterprise.customers.email/ }));
    await visitor.click(screen.getByRole('button', { name: 'Request classification' }));
    expect(await screen.findByText('Waiting for AI classification')).toBeInTheDocument();
    const posted = fetchMock.mock.calls.find(([path, options]) => String(path).endsWith('/classify') && options?.method === 'POST');
    expect(JSON.parse(String(posted?.[1]?.body))).toEqual({ result_ids: ['finding-email'] });
    expect(new Headers(posted?.[1]?.headers).get('X-CSRF-Token')).toBe('csrf-ai');
    expect(fetchMock.mock.calls.some(([path]) => String(path).includes('status=COMPLETED'))).toBe(true);
  });

  it('uses the bounded whole-column default without inventing a selection', async () => {
    const fetchMock = server({ noJobs: true });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByRole('button', { name: 'Request classification' }));
    const posted = fetchMock.mock.calls.find(([path, options]) => String(path).endsWith('/classify') && options?.method === 'POST');
    expect(JSON.parse(String(posted?.[1]?.body))).toEqual({});
    expect(fetchMock.mock.calls.some(([path]) => String(path).includes('/results?'))).toBe(false);
  });

  it('lets auditors review risk, explanation, provenance, and approval requirements only', async () => {
    server({ role: 'AUDITOR' });
    render(<App />);
    expect(await screen.findByText('High risk')).toBeInTheDocument();
    expect(screen.getByText(decision.reason)).toBeInTheDocument();
    expect(screen.getByText('Redact')).toBeInTheDocument();
    expect(screen.getByText('Requires approval')).toBeInTheDocument();
    expect(screen.getByText(/AI scores are heuristic signals/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Request classification' })).not.toBeInTheDocument();
    expect(screen.queryByRole('radio')).not.toBeInTheDocument();
    expect(document.body).not.toHaveTextContent('secret@example.test');
  });

  it('shows accepted partial results with explicit unavailable counts and manual review', async () => {
    server({ status: 'PARTIAL' });
    render(<App />);
    expect(await screen.findByText('Some findings still need manual review')).toBeInTheDocument();
    expect(screen.getByText(/1 accepted; 1 unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/Missing recommendations do not indicate low risk/)).toBeInTheDocument();
    expect(await screen.findByRole('region', { name: 'AI recommendations' })).toBeInTheDocument();
  });

  it('does not render recommendations after invalid AI output fails the job', async () => {
    const fetchMock = server({ status: 'FAILED' });
    render(<App />);
    expect(await screen.findByText('AI recommendations unavailable')).toBeInTheDocument();
    expect(screen.getByText(/did not pass validation/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Review original scan findings' })).toHaveAttribute('href', '/scans?connection=database-ai&job=scan-ai');
    expect(screen.queryByRole('region', { name: 'AI recommendations' })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([path]) => String(path).includes('/classifications?'))).toBe(false);
  });

  it('explains an outage without rendering backend details or fabricating decisions', async () => {
    server({ postStatus: 503, noJobs: true });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    await visitor.click(await screen.findByRole('button', { name: 'Request classification' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('scan findings remain available for manual review');
    expect(document.body).not.toHaveTextContent('private-backend-error');
    expect(screen.queryByRole('region', { name: 'AI recommendations' })).not.toBeInTheDocument();
  });

  it('offers a scan first when no completed scan exists', async () => {
    server({ noScans: true });
    render(<App />);
    expect(await screen.findByText('Start with a completed scan')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Request classification' })).not.toBeInTheDocument();
  });
});

it('stops classification polling on a partial terminal outcome', async () => {
  vi.useFakeTimers();
  try {
    const fetchMock = vi.fn().mockResolvedValueOnce(json({ ...job, status: 'RUNNING', progress: 50 })).mockResolvedValueOnce(json({ ...job, status: 'PARTIAL', failed_results: 1 }));
    vi.stubGlobal('fetch', fetchMock);
    const { result, unmount } = renderHook(() => usePollingResource<ClassificationJob>('/classification-jobs/job', 0, activeClassification, classificationError));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(result.current.data?.status).toBe('PARTIAL');
    await act(async () => { await vi.advanceTimersByTimeAsync(9000); });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    unmount();
  } finally { vi.useRealTimers(); }
});
