import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../src/App';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const event = {
  id: 'event-1', actor_id: 'user-1', event_type: 'POLICY_APPROVED', subject_type: 'masking_policy',
  subject_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', correlation_id: 'corr-1', details: {}, created_at: '2026-10-01T09:00:00Z',
};

type ServerOptions = { items?: Array<typeof event>; ignoresFilters?: boolean; role?: string; verify?: () => Response };

function server({ items = [event], ignoresFilters = false, role = 'AUDITOR', verify }: ServerOptions = {}) {
  const fetchMock = vi.fn(async (url: RequestInfo | URL) => {
    const path = String(url);
    if (path.endsWith('/auth/me')) return json({ id: 'user-1', email: 'auditor@example.test', role, csrf_token: 'csrf-audit' });
    if (path.includes('/audit-events/verify')) {
      if (!verify) throw new Error('Integrity verification was requested unexpectedly');
      return verify();
    }
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
  return fetchMock.mock.calls.map(([url]) => String(url)).filter((url) => url.includes('/audit-events') && !url.includes('/verify'));
}

function verifyCalls(fetchMock: ReturnType<typeof server>) {
  return fetchMock.mock.calls.map(([url]) => String(url)).filter((url) => url.includes('/audit-events/verify'));
}

const headHash = '9df800e54ab7bd0e38072530cea98ef5a90e1d350b25724dc7b54c0f349fc043';
const intact = {
  status: 'INTACT', sealed: 128, pending: 2, head_index: 128, head_hash: headHash,
  broken_index: null, reason: null, anchor_status: null, verified_at: '2026-10-01T09:00:00Z',
};

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

describe('audit log integrity', () => {
  it('verifies only on request and shows an intact chain with a copyable head hash', async () => {
    const fetchMock = server({ verify: () => json(intact) });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);

    expect(await screen.findByText('POLICY APPROVED')).toBeInTheDocument();
    const integrity = within(screen.getByRole('region', { name: 'Log integrity' }));
    expect(verifyCalls(fetchMock)).toHaveLength(0);
    expect(integrity.queryByRole('status')).not.toBeInTheDocument();

    await visitor.click(integrity.getByRole('button', { name: 'Verify log integrity' }));

    expect(await integrity.findByRole('status')).toHaveTextContent('Intact. Every sealed event still matches the hash recorded when it was sealed.');
    expect(verifyCalls(fetchMock)).toEqual(['/api/v1/audit-events/verify']);
    expect(integrity.getByText('Intact')).toHaveClass('pill');
    expect(integrity.getByText(/Sealed events:/)).toHaveTextContent('Sealed events: 128');
    expect(integrity.getByText(/Not yet sealed:/)).toHaveTextContent('Not yet sealed: 2 (recorded moments ago, sealed automatically, and not covered by this check)');
    expect(integrity.getByText(/Head of the chain:/)).toHaveTextContent('position 128, hash 9df800e54ab7…349fc043');
    expect(integrity.queryByText(headHash)).not.toBeInTheDocument();
    expect(integrity.getByTitle(headHash)).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();

    await visitor.click(integrity.getByRole('button', { name: 'Copy head hash' }));
    expect(await integrity.findByRole('button', { name: 'Copied' })).toBeInTheDocument();
    expect(await window.navigator.clipboard.readText()).toBe(headHash);
  });

  it('shows the full head hash when the clipboard is unavailable', async () => {
    server({ verify: () => json(intact) });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    const integrity = within(await screen.findByRole('region', { name: 'Log integrity' }));
    await visitor.click(await integrity.findByRole('button', { name: 'Verify log integrity' }));
    await integrity.findByRole('status');

    vi.spyOn(window.navigator.clipboard, 'writeText').mockRejectedValue(new Error('denied'));
    await visitor.click(integrity.getByRole('button', { name: 'Copy head hash' }));
    expect(await integrity.findByText(headHash)).toBeInTheDocument();
  });

  it('reports a broken chain with its position and a plain-language reason', async () => {
    server({ verify: () => json({ ...intact, status: 'BROKEN', pending: 0, broken_index: 57, reason: 'HASH_MISMATCH' }) });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    const integrity = within(await screen.findByRole('region', { name: 'Log integrity' }));
    await visitor.click(await integrity.findByRole('button', { name: 'Verify log integrity' }));

    const alert = await integrity.findByRole('alert');
    expect(alert).toHaveTextContent('Broken at position 57.');
    expect(alert).toHaveTextContent('The audit event at this position, or the hash recorded for it, was changed after the event was sealed.');
    expect(alert).not.toHaveTextContent('HASH_MISMATCH');
    expect(integrity.getByText('Broken')).toHaveClass('pill');
    expect(integrity.queryByRole('status')).not.toBeInTheDocument();
    expect(integrity.getByText(/Sealed events:/)).toHaveTextContent('Sealed events: 128');
    expect(integrity.getByText(/Not yet sealed:/)).toHaveTextContent('Not yet sealed: 0');
  });

  it.each([
    ['LINK_MISMATCH', 'This entry no longer follows from the one before it.'],
    ['INDEX_GAP', 'The entry at this position is missing.'],
    ['MISSING_EVENT', 'The audit event that was sealed at this position no longer exists.'],
  ])('explains %s in plain language', async (reason, text) => {
    server({ verify: () => json({ ...intact, status: 'BROKEN', broken_index: 3, reason }) });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    const integrity = within(await screen.findByRole('region', { name: 'Log integrity' }));
    await visitor.click(await integrity.findByRole('button', { name: 'Verify log integrity' }));
    expect(await integrity.findByRole('alert')).toHaveTextContent(`Broken at position 3. ${text}`);
  });

  it('says that nothing is known when the request fails, and clears an earlier result', async () => {
    let fail = false;
    server({ verify: () => (fail ? json({ detail: 'Database temporarily unavailable' }, 503) : json(intact)) });
    const visitor = userEvent.setup({ delay: null });
    render(<App />);
    const integrity = within(await screen.findByRole('region', { name: 'Log integrity' }));
    const button = await integrity.findByRole('button', { name: 'Verify log integrity' });
    await visitor.click(button);
    await integrity.findByRole('status');

    fail = true;
    await visitor.click(button);
    expect(await screen.findByRole('alert')).toHaveTextContent('The log could not be verified. Nothing is known about its integrity until a check completes.');
    expect(integrity.queryByRole('status')).not.toBeInTheDocument();
    expect(integrity.queryByText('Intact')).not.toBeInTheDocument();
    expect(screen.queryByText(/Database temporarily unavailable/)).not.toBeInTheDocument();
    expect(integrity.getByRole('button', { name: 'Verify log integrity' })).toBeEnabled();
  });

  it('offers no verification to an analyst', async () => {
    const fetchMock = server({ role: 'ANALYST' });
    render(<App />);
    expect(await screen.findByText('POLICY APPROVED')).toBeInTheDocument();
    const integrity = within(screen.getByRole('region', { name: 'Log integrity' }));
    expect(integrity.queryByRole('button', { name: 'Verify log integrity' })).not.toBeInTheDocument();
    expect(integrity.getByText('An administrator or auditor can verify that sealed audit events have not been changed.')).toBeInTheDocument();
    expect(verifyCalls(fetchMock)).toHaveLength(0);
  });
});
