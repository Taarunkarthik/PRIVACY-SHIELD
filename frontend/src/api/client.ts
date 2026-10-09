export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

export const SESSION_EXPIRED = 'privacyshield:session-expired';

type RequestOptions = RequestInit & { csrfToken?: string; signal?: AbortSignal };

export async function api<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { csrfToken, ...requestOptions } = options;
  const headers = new Headers(requestOptions.headers);
  headers.set('Accept', 'application/json');
  if (requestOptions.body) headers.set('Content-Type', 'application/json');
  if (csrfToken) headers.set('X-CSRF-Token', csrfToken);
  let response: Response;
  try {
    response = await fetch(`/api/v1${path}`, { ...requestOptions, headers, credentials: 'same-origin' });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ApiError(0, 'The workspace could not be reached. Check your connection and try again.');
  }
  if (!response.ok) {
    if (response.status === 401 && path !== '/auth/login') {
      window.dispatchEvent(new Event(SESSION_EXPIRED));
    }
    // Never render backend exception text, which can include connection secrets or source values.
    const message = response.status === 401
      ? (path === '/auth/login' ? 'The email or password is incorrect.' : 'Your session has expired. Please sign in again.')
      : response.status === 403 ? 'You do not have permission to perform this action.'
      : response.status === 429 ? 'Too many attempts. Wait a moment and try again.'
      : 'This request could not be completed. Please try again.';
    throw new ApiError(response.status, message);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export type User = { id: string; email: string; role: 'ADMIN' | 'ANALYST' | 'AUDITOR'; csrf_token: string };
export type DashboardSummary = {
  databases: number;
  tables: number;
  sensitive_columns: number;
  pending_approvals: number;
  deployed_policies: number;
  scan_jobs: number;
};
