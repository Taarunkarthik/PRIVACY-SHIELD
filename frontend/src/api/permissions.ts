import type { User } from './client';

export type Role = User['role'];

/**
 * One place for what each role may do. The server refuses everything else
 * regardless of what the UI shows, so this only decides what to offer, hide,
 * or show as read-only. It mirrors the API's `require_roles(...)` guards.
 */
export type Capability =
  | 'manage.users'
  | 'manage.settings'
  | 'connection.manage'
  | 'scan.run'
  | 'classify.run'
  | 'policy.create'
  | 'policy.approve'
  | 'policy.deploy'
  | 'audit.view'
  | 'audit.verify';

const ANALYST: Capability[] = [
  'connection.manage',
  'scan.run',
  'classify.run',
  'policy.create',
  'audit.view',
];

const AUDITOR: Capability[] = ['audit.view', 'audit.verify'];

const MATRIX: Record<Role, Capability[]> = {
  ADMIN: [
    'manage.users',
    'manage.settings',
    'connection.manage',
    'scan.run',
    'classify.run',
    'policy.create',
    'policy.approve',
    'policy.deploy',
    'audit.view',
    'audit.verify',
  ],
  ANALYST,
  AUDITOR,
};

export const roleLabel: Record<Role, string> = {
  ADMIN: 'Administrator',
  ANALYST: 'Analyst',
  AUDITOR: 'Auditor',
};

export function can(user: { role: Role } | null | undefined, capability: Capability): boolean {
  return Boolean(user && MATRIX[user.role].includes(capability));
}

/** Auditors see everything but change nothing. */
export function isReadOnly(user: { role: Role } | null | undefined): boolean {
  return user?.role === 'AUDITOR';
}

/** A short, plain description of the role's remit for the Overview heading. */
export const roleBlurb: Record<Role, string> = {
  ADMIN: 'Every capability: run the workflow, approve and deploy, manage people and settings.',
  ANALYST: 'Run scans and classifications, and create and submit masking policies for approval.',
  AUDITOR: 'Read-only oversight of coverage and the audit trail. Nothing here can be changed.',
};

/** Two short lists for the at-a-glance capability strip. */
export const roleCapabilities: Record<Role, { may: string[]; mayNot: string[] }> = {
  ADMIN: {
    may: ['Approve & deploy policies', 'Run scans & classifications', 'Manage users & settings'],
    mayNot: ['Modify source data', 'Bypass the audit trail'],
  },
  ANALYST: {
    may: ['Run scans & classifications', 'Create & submit policies'],
    mayNot: ['Approve or deploy', 'Manage users or settings'],
  },
  AUDITOR: {
    may: ['View policies, scans & audit', 'Verify the audit chain'],
    mayNot: ['Run scans or classifications', 'Approve or deploy'],
  },
};
