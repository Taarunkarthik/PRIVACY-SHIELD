import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../src/App';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const event = {
  id: 'event-1', actor_id: 'user-1', event_type: 'POLICY_APPROVED', subject_type: 'masking_policy',
  subject_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', correlation_id: 'corr-1', details: {}, created_at: '2026-10-01T09:00:00Z',
};

function server({ items = [event], ignoresFilters = false } = {}) {
  const fetchMock = vi.fn(async (url: RequestInfo | URL) => {
    const path = String(url);
    if (path.endsWith('/auth/me')) return json({ id: 'user-1', email: 'auditor@example.test', role: 'AUDITOR', csrf_token: 'csrf-audit' });
    if (path.includes('/audit-events')) {
      const parsed = new URL(path, 'http://local');
      const filtered = ignoresFilters ? items : items.filter((item) =>
        (!parsed.searchParams.get('subject_type') || item.subject_type === parsed.searchParams.get('subject_type'))
        && (!parsed.searchParams.get('event_type') || item.event_type === parsed.searchParams.get('event_type')));
      return json({ items: filtered, total: filtered.length, page: 1, page_size: 50 });
    }
    throw new Error(`Unexpected test endpoint ${path}`);
  });
  vi.stubGlobal('fetch', fetchMock);
  window.history.replaceState({}, '', '/audit');
  return fetchMock;
}

function auditCalls(fetchMock: ReturnType<typeof server>) {
  return fetchMock.mock.calls.map(([url]) => String(url)).filter((url) => url.includes('/audit-events'));
}

function lastParams(fetchMock: ReturnType<typeof server>) {
  return new URL(auditCalls(fetchMock).at(-1) ?? '', 'http://local').searchParams;
}

describe('audit timeline filters', () => {
  it('sends the subject type and time window and keeps the event-type filter', async () => {
    const fetchMock = server();
    const visitor = userEvent.setup({ delay: null });
    render(<App />);

    expect(await screen.findByText('POLICY APPROVED')).toBeInTheDocument();

    await visitor.selectOptions(screen.getByLabelText('Subject'), 'masking_policy');
    await waitFor(() => expect(lastParams(fetchMock).get('subject_type')).toBe('masking_policy'));

    await visitor.selectOptions(screen.getByLabelText('Event type'), 'POLICY_APPROVED');
    fireEvent.change(screen.getByLabelText('From'), { target: { value: '2026-10-01T10:00' } });
    fireEvent.change(screen.getByLabelText('To'), { target: { value: '2026-10-02T10:00' } });

    await waitFor(() => {
      const params = lastParams(fetchMock);
      expect(params.get('event_type')).toBe('POLICY_APPROVED');
      expect(params.get('subject_type')).toBe('masking_policy');
      expect(params.get('since')).toBe(new Date('2026-10-01T10:00').toISOString());
      expect(params.get('until')).toBe(new Date('2026-10-02T10:00').toISOString());
      expect(params.get('page')).toBe('1');
    });
  });

  it('degrades gracefully when the backend ignores the newer filters', async () => {
    server({ ignoresFilters: true });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);

    expect(await screen.findByText('POLICY APPROVED')).toBeInTheDocument();
    await visitor.selectOptions(screen.getByLabelText('Subject'), 'scan_job');
    expect(await screen.findByText('POLICY APPROVED')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('rejects an inverted time window without another request', async () => {
    const fetchMock = server();
    render(<App />);
    expect(await screen.findByText('POLICY APPROVED')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('From'), { target: { value: '2026-10-03T10:00' } });
    fireEvent.change(screen.getByLabelText('To'), { target: { value: '2026-10-01T10:00' } });

    expect(await screen.findByRole('alert')).toHaveTextContent('Choose a start time that is earlier than the end time.');
    const callsBefore = auditCalls(fetchMock).length;
    fireEvent.change(screen.getByLabelText('From'), { target: { value: '2026-10-04T10:00' } });
    expect(auditCalls(fetchMock).length).toBe(callsBefore);
  });
});
