import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ErrorBoundary } from '../src/components/ErrorBoundary';

/** A page that fails on its first render, the way a bad data shape or hook would. */
function BrokenPage(): never {
  throw new Error('unexpected render failure');
}

describe('error boundary', () => {
  // React reports a caught render error on the console; keep the run clean.
  beforeEach(() => { vi.spyOn(console, 'error').mockImplementation(() => {}); });

  it('shows a recovery panel instead of a blank screen when a page throws', () => {
    render(<ErrorBoundary><BrokenPage /></ErrorBoundary>);
    expect(screen.getByRole('alert')).toHaveTextContent('Something went wrong');
    expect(screen.getByRole('button', { name: 'Reload the workspace' })).toBeInTheDocument();
    // The failure is not exposed to the user.
    expect(screen.queryByText(/unexpected render failure/)).not.toBeInTheDocument();
  });

  it('renders its children untouched while nothing has failed', () => {
    render(<ErrorBoundary><p>Workspace overview.</p></ErrorBoundary>);
    expect(screen.getByText('Workspace overview.')).toBeInTheDocument();
    expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument();
  });

  it('reports the failure to the console for diagnostics', () => {
    const errors = vi.spyOn(console, 'error');
    render(<ErrorBoundary><BrokenPage /></ErrorBoundary>);
    expect(errors).toHaveBeenCalled();
  });
});
