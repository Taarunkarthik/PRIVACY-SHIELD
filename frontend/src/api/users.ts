import { api } from './client';

export type Role = 'ADMIN' | 'ANALYST' | 'AUDITOR';
export const ROLES: Role[] = ['ADMIN', 'ANALYST', 'AUDITOR'];

export interface Account {
  id: string;
  email: string;
  role: Role;
  is_active: boolean;
  created_at: string;
}

export interface AccountPage { items: Account[]; total: number; page: number; page_size: number }

export type AccountChange = Partial<{ role: Role; is_active: boolean; password: string }>;

// The bounds the server enforces, mirrored so a person hears about them before a request.
export const MIN_PASSWORD = 12;
export const MAX_PASSWORD = 128;
export const PAGE_SIZE = 50;

export const roleLabel: Record<Role, string> = {
  ADMIN: 'Administrator',
  ANALYST: 'Analyst',
  AUDITOR: 'Auditor',
};

/** What each role may do, in the words shown where a role is chosen. */
export const roleSummary: Record<Role, string> = {
  ADMIN: 'Everything, including approving and deploying policies and managing accounts.',
  ANALYST: 'Runs scans and classification, writes and submits policies. Cannot approve or deploy.',
  AUDITOR: 'Read-only. Reviews policies and the audit log, and can verify its integrity.',
};

export function listAccounts(page: number, signal?: AbortSignal) {
  return api<AccountPage>(`/users?page=${page}&page_size=${PAGE_SIZE}`, { signal });
}

export function createAccount(account: { email: string; role: Role; password: string }, csrfToken: string) {
  return api<Account>('/users', { method: 'POST', csrfToken, body: JSON.stringify(account) });
}

export function changeAccount(id: string, change: AccountChange, csrfToken: string) {
  return api<Account>(`/users/${encodeURIComponent(id)}`, { method: 'PATCH', csrfToken, body: JSON.stringify(change) });
}
